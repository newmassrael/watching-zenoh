// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over a byte stream (TCP), written once for every stack that has BSD-style
//! sockets under a cooperative loop, as `udp_link` is for datagrams.
//!
//! A platform supplies a [`StreamDial`], which opens a connection, and the [`StreamSocket`] it
//! yields: write, wait, read what is queued. Everything above the socket is here:
//! [`StreamDriver`] is the session's outbound [`BoxedLinkDriver`] and the drive loop's
//! [`SessionDatagramLink`] over one connection.
//!
//! ## The framing
//!
//! A stream keeps no message boundaries, so zenoh writes every batch behind its length, a
//! little-endian `u16` counted inside the batch size ([`STREAM_BATCH_LENGTH_BYTES`]). The receive
//! gathers what the socket has into the driver's buffer and hands the session one whole batch at a
//! time, where the buffer holds it, and leaves it there until the next receive; the bytes of the
//! next batch, however the stream cut them, stay behind it, and are moved to the front of the
//! buffer only when the stream must be read for the rest of one.
//! The send writes the length into the headroom the driver asked the session to leave in front of
//! the frame, so length and batch leave in one write from the slot the session encoded into.
//! That is [`LengthPrefix`]; a protocol that frames its messages itself (a WebSocket) runs the
//! same driver under a [`StreamFraming`] of its own.
//!
//! ## What the stream does not take
//!
//! With `tx-stream-owed` (on in a build that names nothing) a send never waits for its stream:
//! the part of a frame the stream did not take is owed in the frame's slot and written by the
//! next step that finds the stream room, and a question of room waits for the stream within the
//! message's own wait, as zenoh's queue does. Without it, the zenoh-pico preset's build, a send
//! writes its frame whole, waiting for the stream whenever it takes nothing, as zenoh-pico's link
//! write does, and the link has room whenever it has a slot.
//!
//! ## The end of the stream
//!
//! A datagram link has no connection to lose; this one does. A stream the peer closed, a read
//! that failed, or a length the buffer cannot hold (a batch larger than the one negotiated: the
//! tokio stream reader reads that as the peer's end too) ends the link: the receive stops and
//! [`SessionDatagramLink::lost`] says so, after everything that arrived before the end has been
//! handed over, and the loop tells the session.

use core::cell::{Cell, RefCell};
use core::ffi::c_int;
use core::fmt::Debug;
use core::mem::MaybeUninit;
use core::net::SocketAddr;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEnds, LinkRoom, LinkSendOutcome, LostCause, RoomAnswer,
    RoomWait, TxSlot, TxSlotGrant, DEFAULT_LINK_MTU, SESSION_TX_SLOTS, STREAM_BATCH_LENGTH_BYTES,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

use crate::atomic::{AtomicU8, Ordering};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::{RxStore, TxStore};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::WaitOn;
use crate::session_drive::{LinkOpenError, LinkProto, SessionDatagramLink};
use crate::udp_link::{ends_fit, SERVICE_WAIT_MS};

/// The receive buffer of a link that takes the largest batch zenoh can negotiate: its length and
/// the batch behind it.
pub const STREAM_RX_CAPACITY: usize = u16::MAX as usize + STREAM_BATCH_LENGTH_BYTES;

/// One connected byte stream, IPv4 or IPv6: a platform's TCP socket, or a channel over one. Only the one
/// thread that drives the link touches it. How the stream came to be connected is a
/// [`StreamDial`]'s to say, so a stream that needs more than an address to open (a secure channel
/// needs its identity and its peer's) is a stream like any other here.
pub trait StreamSocket: Sized {
    /// Why a call failed, as the platform reports it. `Copy`, because the driver keeps the last
    /// failure for the deploy to report.
    type Error: Copy + Debug;

    /// The link a stack holds over this stream: [`StreamDriver`] over it, for every stream there
    /// is one of. [`NoStream`] names itself, a link there is none of, so the case a stack keeps
    /// for a protocol it does not carry holds nothing and no code serves it.
    type Link<B: RxStore + 'static, X: TxStore + 'static>: StreamLink<Self, B, X>
    where
        Self: 'static;

    /// The two ends of the connection, in the form the kind of link it is names them
    /// ([`StreamEnds`]): a connection over IP by its protocol and its two addresses and ports, a
    /// secure channel over one by the connection's addresses under its own protocol, a link over
    /// named FIFOs by the two FIFOs. What the link reports of its ends and of itself is read off
    /// them, and whether the rows of the build name them.
    fn ends(&self) -> StreamEnds<'_>;

    /// Whether [`Self::write`] returns without waiting for the stream to take its bytes, as a
    /// non-blocking write does. A link over such a stream is not asked for room before every
    /// frame: a write taken whole says the stream had room, and only one it did not take whole
    /// makes the next frame ask ([`Self::wait_writable`]). A stream whose write waits is asked
    /// before every frame, its write saying nothing of the room left.
    const WRITES_NOW: bool = false;

    /// Write `bytes`, in order, as far as the stream takes them: how many it took. A stream that
    /// writes without waiting ([`Self::WRITES_NOW`]) takes what it has room for now, `0` when
    /// it has none and fewer than all when it has some; one that does not returns once it has
    /// taken them all.
    fn write(&self, bytes: &[u8]) -> Result<usize, Self::Error>;

    /// Write every byte of `bytes`, waiting for room whenever the stream takes none: for a writer
    /// that has nowhere to keep what a write leaves (a secure channel's records over the stream),
    /// and for each frame of a link built without `tx-stream-owed`. A link built with it keeps the
    /// rest of a frame itself and never waits here.
    fn write_all(&self, bytes: &[u8]) -> Result<(), Self::Error> {
        let mut rest = bytes;
        while !rest.is_empty() {
            let taken = self.write(rest)?;
            if taken == 0 {
                self.wait_writable(SERVICE_WAIT_US);
            }
            rest = rest.get(taken..).unwrap_or_default();
        }
        Ok(())
    }

    /// Block until bytes are queued or `timeout_ms` has passed, and return at once when some
    /// already are. A failed wait is the same as a quiet socket here: the read that follows
    /// reports the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Wait up to `timeout_us` microseconds for the stack to take more bytes: whether it will (or
    /// the stream has failed, which the write that follows reports) or still would not when the
    /// time is up, and how long the wait took in microseconds. This is the link's room: zenoh's
    /// queue that has no batch for a message within its deadline, here a stream whose peer has
    /// not read what it was sent. The time is what a question of the link's room reports it
    /// spent, so a sender that keeps one deadline across several questions keeps the right one;
    /// a stream with no clock counts room found as found at once and none as the whole wait.
    ///
    /// A stream that cannot tell answers room at once, and a send to it waits in the write.
    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        let _ = timeout_us;
        (true, 0)
    }

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes, `Ok(Some(0))`
    /// when the peer has closed the stream, `Ok(None)` when nothing is queued.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Whether a connection begun without waiting ([`StreamDial::dial_started`]) has been made:
    /// `Ok(true)` once it carries bytes, `Ok(false)` while it is still being made, the failure once
    /// the other end or the stack refused it. Asked without waiting. Once made, the stream is read
    /// and written as a dialled one is and names its two ends as they are. A stream whose dial
    /// waited is made from the start.
    fn connected(&mut self) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// End the connection in both directions. The peer reads the end of the stream.
    fn shutdown(&self);

    /// The zid of the key the peer proved when the stream was opened, for a stream that is a
    /// secure channel (decision D1); `None` for a plain connection, which proves nobody.
    fn peer_credential_zid(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        None
    }

    /// What a thread other than the link's waits on for this stream's input
    /// ([`SessionDatagramLink::input_wait`]); `None` when the platform gives none (a secure
    /// channel holds bytes of its own the socket's wait would not see), and then a link over the
    /// stream waits in its own loop whatever it was asked.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// What a thread other than the link's waits on for room on this stream
    /// ([`SessionDatagramLink::room_wait`]): the stream's own handle, a value a wait copies;
    /// `None` when the platform gives none, and then a sender that finds the session held waits
    /// for it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// How a stack opens the connected streams its `tcp/` links run over: a value the stack holds,
/// so whatever a dial needs besides the address (a secure channel's identity, its context
/// table) is the dial's, and the stack and the link stay written once.
pub trait StreamDial {
    /// The stream a dial yields.
    type Stream: StreamSocket;

    /// Connect to `to`, over a socket of its family, blocking until the stream can carry a
    /// session or the dial has failed: [`LinkOpenError::Refused`] when the other end did not take
    /// it, [`LinkOpenError::Exhausted`] when the platform had no socket to give,
    /// [`LinkOpenError::Unsupported`] when it has no socket of that family at all.
    fn dial(&self, to: SocketAddr) -> Result<Self::Stream, LinkOpenError>;

    /// Begin a connection to `to` without waiting for it to be made: the stream, whose
    /// [`StreamSocket::connected`] tells when it is, so whoever holds a session is not held by
    /// a connect the other end is slow to answer or to refuse. A dial that cannot begin one
    /// without waiting makes it here, as [`Self::dial`] does, and its stream is made from the start.
    fn dial_started(&self, to: SocketAddr) -> Result<Self::Stream, LinkOpenError> {
        self.dial(to)
    }

    /// Whether the dial opens streams at all. A stack asks before it claims any buffer, so a
    /// protocol it does not carry is [`LinkOpenError::Unsupported`] (permanent) and never
    /// [`LinkOpenError::Exhausted`] (retried) when its tables happen to be full.
    const CARRIED: bool = true;

    /// Whether the dial connects to an IPv6 end: `false` on a stack built without IPv6, whose
    /// dial of one is [`LinkOpenError::Unsupported`]. The datagram twin is
    /// `DatagramSocket::IPV6`, and a stack's own answer is the union of its protocols'.
    const IPV6: bool = true;

    /// Listen on `at` (port 0: the platform picks one, read back with [`StreamListen::local`])
    /// for the connections of the protocol this dial opens. A stack that listens overrides it;
    /// the answer of one that does not is [`LinkOpenError::Unsupported`], as a dial it does not
    /// carry is. Boxed, so a stack names the listener it opens here and nowhere above, and one
    /// that never listens links none.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn listen(
        &self,
        at: SocketAddr,
    ) -> Result<alloc::boxed::Box<dyn StreamListen<Stream = Self::Stream>>, LinkOpenError> {
        let _ = at;
        Err(LinkOpenError::Unsupported)
    }
}

/// How a stack takes the connections that arrive on a port it listens on: the other half of
/// [`StreamDial`], and for the same reason a value the stack holds. What it yields is a
/// [`StreamSocket`] like a dial's, because a connection is the same thing from either end: the
/// [`StreamDriver`] over it has no binding to make, since "the peer is the other end of the
/// connection", so nothing above the socket knows which end opened it.
pub trait StreamListen {
    /// The stream an accept yields.
    type Stream: StreamSocket;

    /// The address and port the listener is bound to.
    fn local(&self) -> SocketAddr;

    /// The connection waiting on the listener, taken without blocking: `Ok(None)` when none waits
    /// (or when the one that did gave up before it was taken, which leaves nothing to take).
    /// [`LinkOpenError::Exhausted`] when the platform had no descriptor to give it: the
    /// connection stays queued and the next call tries again. [`LinkOpenError::Unsupported`]
    /// when the listener itself is broken, which no later call mends.
    fn accept(&self) -> Result<Option<Self::Stream>, LinkOpenError>;

    /// What a thread other than the one that accepts waits on for a connection
    /// ([`StreamSocket::input_wait`] is the stream's): ready when a connection is queued.
    /// `None` when the platform gives none, and then the owner looks for a connection at a pace
    /// of its own.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// A boxed listener is a listener, so a provider that wraps the one a [`StreamDial::listen`] hands
/// back (a secure channel's handshake runs between the accept and the link) names it by trait and
/// not by the platform's own type.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<L: StreamListen + ?Sized> StreamListen for alloc::boxed::Box<L> {
    type Stream = L::Stream;

    fn local(&self) -> SocketAddr {
        (**self).local()
    }

    fn accept(&self) -> Result<Option<Self::Stream>, LinkOpenError> {
        (**self).accept()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        (**self).input_wait()
    }
}

/// What a stack makes of a connected stream and holds as one of its links
/// ([`StreamSocket::Link`]).
pub trait StreamLink<S, B, X>: BoxedLinkDriver + SessionDatagramLink + Sized {
    /// The link over the connected `socket`, receiving into `rx` and building its frames in `tx`.
    fn over(socket: S, rx: B, tx: X) -> Self;

    /// Have the link's owner wait on it, where the link lies ([`StreamDriver::wait_by_owner`]).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn wait_by_owner(&mut self);
}

/// Whether a stream link over `stream` names both its ends in the rows of the build
/// ([`StreamEnds::fit`]), asked of the stream before a link is made over it.
pub fn stream_ends_fit<S: StreamSocket>(stream: &S) -> bool {
    stream.ends().fit()
}

/// The two ends of a connected stream, each kind of link in the form its locators take: the
/// branches of [`Locator`](crate::session_drive::Locator) a stream link can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnds<'a> {
    /// A connection over IP: the protocol the link speaks over it (`tcp/`, or `tls/` for a
    /// secure channel), this end's address and port, then the peer's.
    Ip {
        /// The protocol the link speaks.
        proto: LinkProto,
        /// This end's address and port.
        local: SocketAddr,
        /// The other end's.
        peer: SocketAddr,
    },
    /// A link over a pair of named FIFOs: the FIFO this end reads, then the one it writes, as
    /// upstream names a unixpipe link's two ends
    /// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `dedicated_donlink_path`).
    #[cfg(feature = "unixpipe")]
    Unixpipe {
        /// The FIFO this end reads.
        local: &'a str,
        /// The FIFO this end writes.
        peer: &'a str,
    },
    /// No value: it holds the lifetime of the branches a build without them does not carry.
    #[cfg(not(feature = "unixpipe"))]
    #[doc(hidden)]
    Never(core::convert::Infallible, core::marker::PhantomData<&'a ()>),
}

impl<'a> StreamEnds<'a> {
    /// The ends as the link reports them, lent as they are: a reader that reports the link
    /// writes its locators.
    pub fn link_ends(self) -> LinkEnds<'a> {
        match self {
            Self::Ip { proto, local, peer } => LinkEnds::ip(proto.kind(), local, peer),
            #[cfg(feature = "unixpipe")]
            Self::Unixpipe { local, peer } => {
                LinkEnds::named(wz_session_core::link::LinkKind::Unixpipe, local, peer)
            }
            #[cfg(not(feature = "unixpipe"))]
            Self::Never(never, _) => match never {},
        }
    }

    /// Whether the rows of the build name both ends: an IP end as [`ends_fit`] asks, a FIFO by
    /// the length of its locator, `unixpipe/` and its path.
    pub fn fit(self) -> bool {
        match self {
            Self::Ip { proto, local, peer } => ends_fit(proto, local, peer),
            #[cfg(feature = "unixpipe")]
            Self::Unixpipe { local, peer } => [local, peer].into_iter().all(|path| {
                wz_session_core::locator_grammar::UNIXPIPE_SCHEME
                    .len()
                    .saturating_add(1)
                    .saturating_add(path.len())
                    <= wz_session_core::caps::MAX_LOCATOR_LEN
            }),
            #[cfg(not(feature = "unixpipe"))]
            Self::Never(never, _) => match never {},
        }
    }

    /// This end's address and port and the peer's, for a connection over IP; `None` for ends of
    /// another kind.
    pub fn ip(self) -> Option<(SocketAddr, SocketAddr)> {
        match self {
            Self::Ip { local, peer, .. } => Some((local, peer)),
            #[cfg(feature = "unixpipe")]
            Self::Unixpipe { .. } => None,
            #[cfg(not(feature = "unixpipe"))]
            Self::Never(never, _) => match never {},
        }
    }

    /// The ends of a secure channel that speaks `proto` over a connection with these ends: an IP
    /// connection's two addresses under the channel's protocol; ends of another kind as they are.
    pub fn speaking(self, proto: LinkProto) -> Self {
        match self {
            Self::Ip { local, peer, .. } => Self::Ip { proto, local, peer },
            #[cfg(feature = "unixpipe")]
            unixpipe @ Self::Unixpipe { .. } => unixpipe,
            #[cfg(not(feature = "unixpipe"))]
            Self::Never(never, _) => match never {},
        }
    }

    /// What a link over the stream reports of itself to a connectivity plane: its kind, which
    /// says whether it is streamed and how reliable.
    #[cfg(feature = "alloc")]
    pub fn subject(self) -> &'static wz_session_core::link::LinkSubject {
        match self {
            Self::Ip { proto, .. } => proto.subject(),
            #[cfg(feature = "unixpipe")]
            Self::Unixpipe { .. } => {
                use wz_session_core::link::{LinkKind, LinkSubject};
                static UNIXPIPE: LinkSubject = LinkSubject {
                    kind: Some(LinkKind::Unixpipe),
                    ..LinkSubject::UNKNOWN
                };
                &UNIXPIPE
            }
            #[cfg(not(feature = "unixpipe"))]
            Self::Never(never, _) => match never {},
        }
    }
}

/// The link a stack holds over the connected `socket` ([`StreamSocket::Link`]).
pub fn link_over<S, B, X>(socket: S, rx: B, tx: X) -> S::Link<B, X>
where
    S: StreamSocket + 'static,
    B: RxStore + 'static,
    X: TxStore + 'static,
{
    <S::Link<B, X> as StreamLink<S, B, X>>::over(socket, rx, tx)
}

/// The dial of a stream protocol a stack does not carry: an image with no secure channel names
/// it for `tls/`, and every dial is [`LinkOpenError::Unsupported`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDial;

/// The stream [`NoDial`] would yield: there is none.
#[derive(Debug)]
pub enum NoStream {}

impl StreamSocket for NoStream {
    type Error = core::convert::Infallible;

    type Link<B: RxStore + 'static, X: TxStore + 'static>
        = NoStream
    where
        Self: 'static;

    fn ends(&self) -> StreamEnds<'_> {
        match *self {}
    }

    fn write(&self, _bytes: &[u8]) -> Result<usize, Self::Error> {
        match *self {}
    }

    fn wait_readable(&self, _timeout_ms: c_int) {
        match *self {}
    }

    fn try_read(&self, _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match *self {}
    }

    fn shutdown(&self) {
        match *self {}
    }
}

// A link over a stream there is none of is no value either: every call is a match of nothing.
impl<B, X> StreamLink<NoStream, B, X> for NoStream {
    fn over(socket: NoStream, _rx: B, _tx: X) -> Self {
        socket
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn wait_by_owner(&mut self) {
        match *self {}
    }
}

impl BoxedLinkDriver for NoStream {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        match *self {}
    }

    fn wait_for_room(&self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        match *self {}
    }

    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        match *self {}
    }

    fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
        match *self {}
    }

    fn tx_slot_send(
        &self,
        _slot: TxSlot,
        _start: usize,
        _len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        match *self {}
    }

    fn tx_slot_abort(&self, _slot: TxSlot) {
        match *self {}
    }

    fn open_blocking(&self) {
        match *self {}
    }

    fn close_blocking(&self) {
        match *self {}
    }

    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        match *self {}
    }

    fn peer_credential_zid(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        match *self {}
    }

    fn batch_length_prefixed(&self) -> bool {
        match *self {}
    }

    fn link_mtu(&self) -> usize {
        match *self {}
    }

    fn link_rx_capacity(&self) -> usize {
        match *self {}
    }
}

impl SessionDatagramLink for NoStream {
    fn service(&self) {
        match *self {}
    }

    fn service_within(&self, _max_wait_ms: u64) {
        match *self {}
    }

    fn uses_wake_budget(&self) -> bool {
        match *self {}
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        match *self {}
    }

    fn recv_with(&self, _f: &mut dyn FnMut(&[u8])) -> bool {
        match *self {}
    }

    fn lost(&self) -> Option<LostCause> {
        match *self {}
    }

    fn holds_input(&self) -> bool {
        match *self {}
    }

    fn owes_write(&self) -> bool {
        match *self {}
    }

    fn takes_input(&self) -> bool {
        match *self {}
    }

    fn keeps_input(&self) -> bool {
        match *self {}
    }

    fn keep(&self) {
        match *self {}
    }

    fn lends_until_next_receive(&self) -> bool {
        match *self {}
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        match *self {}
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        match *self {}
    }
}

impl StreamDial for NoDial {
    type Stream = NoStream;

    const CARRIED: bool = false;

    fn dial(&self, _to: SocketAddr) -> Result<NoStream, LinkOpenError> {
        Err(LinkOpenError::Unsupported)
    }
}

/// What the front of a receive buffer holds, as the framing reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Front {
    /// Not yet a whole unit of the framing: some of it is still to come.
    Partial,
    /// A whole batch of `len` bytes, `at` bytes into what was read, in a unit of the framing that
    /// ends `used` bytes in.
    Batch {
        /// Where the batch starts.
        at: usize,
        /// The bytes of the batch.
        len: usize,
        /// Where the unit that carried it ends, and the next one starts.
        used: usize,
    },
    /// A whole unit of this many bytes that carries no batch: passed over.
    Skip(usize),
    /// A unit that does not fit a buffer of this capacity.
    TooLong,
    /// The peer ended the link inside the framing.
    Closed,
}

/// How batches lie on a stream: what a receive finds at the front of the bytes it read, and what
/// a send writes in front of a batch. zenoh's own framing is [`LengthPrefix`]; a protocol that
/// frames its messages itself (a WebSocket) brings its own, and the link over it is the same
/// driver, its writes, its waits and its owed frames, with the framing alone changed.
pub trait StreamFraming {
    /// The room a send asks the session to leave in front of a batch.
    const HEADROOM: usize;

    /// Whether the batch is counted with a length the session leaves room for
    /// ([`BoxedLinkDriver::batch_length_prefixed`]).
    const LENGTH_PREFIXED: bool;

    /// Read the unit at the front of `held`, the bytes a buffer of `capacity` bytes read. With
    /// `consume` the unit is the receive's to hand over, and the framing may change its bytes
    /// where they lie (unmask them, join the parts of a message); without it the receive only asks
    /// whether a whole unit is there, and nothing changes.
    ///
    /// A front that answers [`Front::Partial`] changes nothing, and answers so again until bytes
    /// are added behind it: a receive that found the part of a batch reads the stream for the
    /// rest without asking again.
    fn front(&self, held: &mut [u8], capacity: usize, consume: bool) -> Front;

    /// The batch the last consuming [`Self::front`] answered has been passed over: the bytes
    /// behind it are the next unit's.
    fn passed(&self) {}

    /// Seal a batch for the stream where it lies. `bytes` is the slot from its first byte to the
    /// batch's last: the batch is `bytes[start..]` and the headroom in front of it is the
    /// framing's room. What goes in front of the batch is written into that room, the batch's
    /// bytes are changed as the framing changes them (a client's WebSocket masks them), and the
    /// answer is where the bytes to write start. `None` when no unit carries a batch that long or
    /// the room in front of it is too short; the caller gives the slot back.
    ///
    /// The framing's own: a framing that writes a length alone carries no masking branch and no
    /// head of a variable length.
    fn seal(&self, bytes: &mut [u8], start: usize) -> Option<usize>;

    /// The ends a link over a stream with `ends` reports, which name the kind of link it is: the
    /// stream's own ([`StreamEnds::link_ends`]), unless the framing makes the link a kind of its
    /// own over them.
    fn link_ends(ends: StreamEnds<'_>) -> LinkEnds<'_> {
        ends.link_ends()
    }

    /// What such a link reports of itself ([`StreamEnds::subject`]).
    #[cfg(feature = "alloc")]
    fn subject(ends: StreamEnds<'_>) -> &'static wz_session_core::link::LinkSubject {
        ends.subject()
    }

    /// The largest batch a slot of `slot_len` bytes carries.
    fn mtu(slot_len: usize) -> usize {
        slot_len
    }

    /// The largest batch a receive buffer of `rx_len` bytes takes.
    fn rx_capacity(rx_len: usize) -> usize {
        rx_len
    }

    /// Whether the framing has a unit of its own to write (an answer to the peer).
    fn owes_control(&self) -> bool {
        false
    }

    /// Write what the framing owes, as far as `socket` takes it: `true` once nothing is owed.
    /// Called only between frames, so its bytes never land inside one.
    fn write_control<S: StreamSocket>(&self, socket: &S) -> Result<bool, S::Error> {
        let _ = socket;
        Ok(true)
    }

    /// The link is closing: what the framing writes before the stream ends.
    fn closing(&self) {}
}

/// zenoh's framing of a stream: every batch behind its length, a little-endian `u16`
/// ([`STREAM_BATCH_LENGTH_BYTES`]), an empty batch passed over.
#[derive(Debug, Clone, Copy, Default)]
pub struct LengthPrefix;

impl StreamFraming for LengthPrefix {
    const HEADROOM: usize = STREAM_BATCH_LENGTH_BYTES;
    const LENGTH_PREFIXED: bool = true;
    fn front(&self, held: &mut [u8], capacity: usize, _consume: bool) -> Front {
        front(held, capacity)
    }

    fn seal(&self, bytes: &mut [u8], start: usize) -> Option<usize> {
        let length = u16::try_from(bytes.len().checked_sub(start)?).ok()?;
        let from = start.checked_sub(STREAM_BATCH_LENGTH_BYTES)?;
        bytes
            .get_mut(from..start)?
            .copy_from_slice(&length.to_le_bytes());
        Some(from)
    }
}

/// The most frames a stream link owes its stream at once: one for each slot its book can lend.
#[cfg(feature = "tx-stream-owed")]
const OWED: usize = crate::link_storage::LENT_SLOTS;

/// How long a service turn waits for room to write, in microseconds.
const SERVICE_WAIT_US: u64 = SERVICE_WAIT_MS as u64 * 1_000;

/// What a stream link owes its stream: bytes `from .. end` of a slot of the link's, held out of
/// its pool until they are written. The rest of a frame the stream took only in part, or a frame
/// handed over behind one ([`StreamDriver::write_owed`]). Every frame a stream link writes lies in
/// a slot it lent, a frame handed over as bytes included (`copied_send`), so what it owes is never
/// kept anywhere else, and only the oldest is ever written in part.
#[cfg(feature = "tx-stream-owed")]
#[derive(Clone, Copy)]
struct Owed {
    slot: TxSlot,
    from: usize,
    end: usize,
}

/// The frames a stream link owes, oldest first, in a ring of [`OWED`] places. Only the `len`
/// places from `head` on hold a frame, each written by its push and read once by its pop, so the
/// ring is made without writing a place: a link made in its cell writes none of them. Each frame
/// holds a slot of its own, and a link lends at most [`OWED`], so the ring is never full.
#[cfg(feature = "tx-stream-owed")]
struct OwedQueue {
    places: [MaybeUninit<Owed>; OWED],
    head: usize,
    len: usize,
}

#[cfg(feature = "tx-stream-owed")]
impl OwedQueue {
    const fn new() -> Self {
        Self {
            places: [const { MaybeUninit::uninit() }; OWED],
            head: 0,
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Put `owed` last; handed back when every place is taken.
    fn push(&mut self, owed: Owed) -> Result<(), Owed> {
        if self.len == OWED {
            return Err(owed);
        }
        // `head` is a place of the ring and `len` below its places, so neither sum wraps.
        let Some(place) = self.places.get_mut(self.head.wrapping_add(self.len) % OWED) else {
            return Err(owed);
        };
        place.write(owed);
        self.len = self.len.wrapping_add(1);
        Ok(())
    }

    /// The oldest, still owed.
    fn front_mut(&mut self) -> Option<&mut Owed> {
        if self.len == 0 {
            return None;
        }
        let place = self.places.get_mut(self.head)?;
        // SAFETY: the ring holds a frame, and the oldest lies at `head`, written by its push and
        // not yet read by a pop.
        Some(unsafe { place.assume_init_mut() })
    }

    /// Take the oldest out.
    fn pop(&mut self) -> Option<Owed> {
        if self.len == 0 {
            return None;
        }
        let place = self.places.get(self.head)?;
        // SAFETY: as in `front_mut`; `head` moves past the place below, so nothing reads it again
        // before a push writes it.
        let owed = unsafe { place.assume_init_read() };
        // A place of the ring, and a length of one or more, checked above.
        self.head = self.head.wrapping_add(1) % OWED;
        self.len = self.len.wrapping_sub(1);
        Some(owed)
    }
}

/// Read the front of `held`, the bytes a buffer of `capacity` bytes holds.
fn front(held: &[u8], capacity: usize) -> Front {
    let Some(&prefix) = held.first_chunk::<STREAM_BATCH_LENGTH_BYTES>() else {
        return Front::Partial;
    };
    let len = usize::from(u16::from_le_bytes(prefix));
    let whole = len.saturating_add(STREAM_BATCH_LENGTH_BYTES);
    if whole > capacity {
        Front::TooLong
    } else if held.len() < whole {
        Front::Partial
    } else if len == 0 {
        Front::Skip(whole)
    } else {
        Front::Batch {
            at: STREAM_BATCH_LENGTH_BYTES,
            len,
            used: whole,
        }
    }
}

/// The session's link over one connected stream socket `S`, with its receive buffer in `B` and
/// its outbound frames built in `T`: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the
/// image's byte tables on the fixed one ([`FixedStreamDriver`]).
///
/// The peer is the other end of the connection, so the link has no binding to make: what arrives
/// is the peer's. The receive buffer bounds the batch the link takes, and so the batch the session
/// advertises ([`BoxedLinkDriver::link_rx_capacity`]).
pub struct StreamDriver<S: StreamSocket, B: RxStore, T: TxStore, F: StreamFraming = LengthPrefix> {
    socket: S,
    /// How batches lie on the stream.
    framing: F,
    /// What the link's receive keeps ([`RxHalf`]).
    rx: RxHalf<B>,
    /// What the link's sends keep ([`TxHalf`]).
    tx: TxHalf<T>,
    /// Why the link is gone, once it is: written by a receive that reads the stream's end or fails
    /// a read, and by a send that fails a write, and read by both, which may be two threads.
    lost: Lost,
    /// The failure the socket reported first, kept for the deploy to report.
    error: FirstError<S::Error>,
    /// Whether the link's owner waits on its stream ([`Self::waited_by_owner`]), so its loop does
    /// not.
    owner_waits: bool,
}

/// The half of a [`StreamDriver`] a receive reaches: the buffer the stream is read into and what
/// of it was handed to the session. Nothing that sends reaches it, so a receive that holds it lends
/// a batch from it while a send runs beside the lend; the one way the receive reaches the send half
/// is the write of what the link owes before it answers the peer's end inside the framing.
struct RxHalf<B> {
    buf: RefCell<B>,
    /// The length of `buf`: a batch's length and the batch behind it.
    len: usize,
    /// How many bytes at the front of `buf` were received.
    held: Cell<usize>,
    /// How many of those bytes the session was handed already: the batch the last receive lent,
    /// which lies where it is until the next receive, and the empty batches before it. The next
    /// receive starts behind them, and moves what follows them to the front only when it must
    /// read the stream for the rest of a batch.
    spent: Cell<usize>,
    /// What lies behind the spent bytes, as the last receive left the buffer: a whole batch, which
    /// the next receive hands over without a read, or the part of one, for which it reads the
    /// stream without reading the front again. Kept apart from the buffer so that asking it does
    /// not touch the bytes a lent batch may still be read from.
    behind: Cell<Behind>,
    /// The bytes the receive moved within its buffer, which the tests count.
    #[cfg(test)]
    moved: Cell<usize>,
    /// How many times the receive read the front of its buffer, which the tests count.
    #[cfg(test)]
    fronts: Cell<usize>,
    /// How many times the receive moved bytes within its buffer, which the tests count.
    #[cfg(test)]
    moves: Cell<usize>,
    /// Whether the session asked, while a batch is lent, to keep it
    /// ([`SessionDatagramLink::keep`]): it then stays at the front, lent again by the next receive.
    keeping: Cell<bool>,
    /// The batches the copying receive let go of for want of heap room, until the loop takes them.
    #[cfg(feature = "alloc")]
    drops: crate::link_storage::RxDrops,
}

/// What a receive found behind the bytes it spent, for the next receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Behind {
    /// Not read, or read as what no receive goes on from (a length past the buffer, the peer's
    /// end inside the framing): the next receive reads the front.
    Unread,
    /// The part of a batch, or nothing: the next receive reads the stream for the rest before it
    /// reads the front, which answers the same until bytes are added behind it.
    Part,
    /// A whole batch, an empty one included: the next receive hands it over with no read.
    Whole,
}

use tx_half::{TxHalf, TxHold};

/// The half of a [`StreamDriver`] a send reaches, apart in a module of its own so that what it
/// keeps is reached only through a hold of it ([`TxHold`]).
mod tx_half {
    #[cfg(feature = "tx-stream-owed")]
    use core::cell::{Cell, RefCell};

    use wz_session_core::link::TxSlot;

    #[cfg(feature = "tx-stream-owed")]
    use super::OwedQueue;
    use crate::atomic::{AtomicBool, Ordering};
    use crate::link_storage::{TxLender, TxStore};

    /// The memory the session encodes its frames into and what of it the stream still owes. A
    /// send, a question of room and a service's write reach it, and a receive reaches it to write
    /// what is owed before the peer's end. A session whose read steps its link on one thread while
    /// another sends on it reaches it from both, so each reach holds it first: the read only by a
    /// try, which leaves what is owed to the send that holds it, and a send by waiting for the
    /// holder. With `tx-stream-owed` no holder waits inside its hold; without it a send holds it
    /// while it writes its frame whole, as zenoh-pico's send holds its transmit lock.
    pub(super) struct TxHalf<T: TxStore> {
        /// Whether a [`TxHold`] of the half stands.
        held: AtomicBool,
        /// The memory the session encodes its frames into, and which of it is out.
        lender: TxLender<T>,
        /// Whether the stream took the last write whole without waiting
        /// ([`super::StreamSocket::WRITES_NOW`]): the next frame is then not preceded by a
        /// question of its room, the write itself being the question. `false` before the first
        /// write and for a stream that cannot write without waiting, which is asked every time.
        #[cfg(feature = "tx-stream-owed")]
        room_known: Cell<bool>,
        /// What the link owes the stream, oldest first: the rest of a frame the stream took in
        /// part, and the frames handed over behind it. Written by the next step that finds the
        /// stream room (a send, a question of room, the loop's service), never by waiting inside a
        /// call.
        #[cfg(feature = "tx-stream-owed")]
        owed: RefCell<OwedQueue>,
    }

    impl<T: TxStore> TxHalf<T> {
        /// The half of a link whose frames are built in `tx`, nothing lent and nothing owed.
        pub(super) fn new(tx: T) -> Self {
            Self {
                held: AtomicBool::new(false),
                lender: TxLender::new(tx),
                #[cfg(feature = "tx-stream-owed")]
                room_known: Cell::new(false),
                #[cfg(feature = "tx-stream-owed")]
                owed: RefCell::new(OwedQueue::new()),
            }
        }

        /// The half, held, when no other holder has it now.
        pub(super) fn try_hold(&self) -> Option<TxHold<'_, T>> {
            self.held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()
                .map(|_| TxHold { half: self })
        }

        /// The half, held, once a holder that has it now lets go: with `tx-stream-owed` no holder
        /// waits for its stream while it holds the half, so this waits for writes that do not
        /// wait; without it this waits for a send to write its frame whole. No reach of the half
        /// is made from inside another's hold on the same thread: each step under a hold is
        /// handed that hold.
        pub(super) fn hold(&self) -> TxHold<'_, T> {
            loop {
                if let Some(held) = self.try_hold() {
                    return held;
                }
                core::hint::spin_loop();
            }
        }

        /// Whether there is storage to lend: a fact of the store, which no hold changes.
        pub(super) fn lends(&self) -> bool {
            self.lender.lends()
        }

        /// The length of every slot.
        pub(super) fn slot_len(&self) -> usize {
            self.lender.slot_len()
        }

        /// How many slots the link lends.
        pub(super) fn slots(&self) -> usize {
            self.lender.slots()
        }

        /// The first byte of `slot` and its whole length, for the holder of its grant to write.
        pub(super) fn storage(&self, slot: TxSlot) -> (*mut u8, usize) {
            self.lender.storage(slot)
        }

        /// Whether a slot the link holds may stay held past the call that holds it.
        #[cfg(feature = "session-unicast-accept")]
        pub(super) fn spare(&self) -> bool {
            self.lender.spare()
        }

        /// Whether the store has the memory for a slot now, as far as a pool goes
        /// ([`TxLender::claimable`]).
        #[cfg(any(feature = "tx-stream-owed", feature = "session-unicast-accept"))]
        pub(super) fn claimable(&self) -> bool {
            self.lender.claimable()
        }
    }

    /// A hold of a link's [`TxHalf`], the one way to what it keeps: the book of its slots, what
    /// the stream owes and what the last write said of the room. Let go of as it drops.
    pub(super) struct TxHold<'a, T: TxStore> {
        half: &'a TxHalf<T>,
    }

    impl<T: TxStore> TxHold<'_, T> {
        /// The book of the link's slots.
        pub(super) fn lender(&self) -> &TxLender<T> {
            &self.half.lender
        }

        /// Whether the stream took the last write whole without waiting.
        #[cfg(feature = "tx-stream-owed")]
        pub(super) fn room_known(&self) -> &Cell<bool> {
            &self.half.room_known
        }

        /// What the link owes the stream.
        #[cfg(feature = "tx-stream-owed")]
        pub(super) fn owed(&self) -> &RefCell<OwedQueue> {
            &self.half.owed
        }
    }

    impl<T: TxStore> Drop for TxHold<'_, T> {
        fn drop(&mut self) {
            self.half.held.store(false, Ordering::Release);
        }
    }
}

/// Why a link is gone, once it is, in one byte that the first end writes and every reach reads,
/// on whichever thread: `0` while the link stands, the cause's code ([`lost_code`]) after.
struct Lost(AtomicU8);

impl Lost {
    /// A link that stands.
    const fn standing() -> Self {
        Self(AtomicU8::new(0))
    }

    /// Why the link is gone; `None` while it stands.
    fn get(&self) -> Option<LostCause> {
        lost_cause(self.0.load(Ordering::Acquire))
    }

    /// The link is gone for `cause`, unless it is gone already: the first cause is kept.
    fn end(&self, cause: LostCause) {
        let _ = self
            .0
            .compare_exchange(0, lost_code(cause), Ordering::AcqRel, Ordering::Acquire);
    }
}

/// The code [`Lost`] keeps `cause` by: never `0`, which is a link that stands.
const fn lost_code(cause: LostCause) -> u8 {
    match cause {
        LostCause::PeerClosed => 1,
        LostCause::Timeout => 2,
        LostCause::OsError => 3,
        LostCause::CertificateExpired => 4,
        LostCause::UnknownPriority => 5,
        LostCause::ReliableGap => 6,
    }
}

/// The cause [`lost_code`] keeps as `code`; `None` for `0`, a link that stands.
const fn lost_cause(code: u8) -> Option<LostCause> {
    match code {
        1 => Some(LostCause::PeerClosed),
        2 => Some(LostCause::Timeout),
        3 => Some(LostCause::OsError),
        4 => Some(LostCause::CertificateExpired),
        5 => Some(LostCause::UnknownPriority),
        6 => Some(LostCause::ReliableGap),
        _ => None,
    }
}

/// A [`FirstError`] that holds no failure.
const NO_ERROR: u8 = 0;
/// A [`FirstError`] whose one writer is writing its failure.
const WRITING_ERROR: u8 = 1;
/// A [`FirstError`] that holds its failure.
const HELD_ERROR: u8 = 2;

/// The first failure a link's socket reported, written once by whichever reach met it (a receive
/// or a send, which may be two threads) and read once it is whole.
struct FirstError<E> {
    state: AtomicU8,
    error: core::cell::UnsafeCell<MaybeUninit<E>>,
}

impl<E: Copy> FirstError<E> {
    /// No failure yet.
    const fn none() -> Self {
        Self {
            state: AtomicU8::new(NO_ERROR),
            error: core::cell::UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Keep `error`, unless a failure is kept already.
    fn set(&self, error: E) {
        if self
            .state
            .compare_exchange(
                NO_ERROR,
                WRITING_ERROR,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // SAFETY: the exchange made this call the one writer, and no reader reads the failure
            // before the store below says it is whole.
            unsafe { (*self.error.get()).write(error) };
            self.state.store(HELD_ERROR, Ordering::Release);
        }
    }

    /// The failure kept, once it is whole.
    fn get(&self) -> Option<E> {
        if self.state.load(Ordering::Acquire) != HELD_ERROR {
            return None;
        }
        // SAFETY: the state says the one write of the failure ended before it was stored, and
        // nothing writes the failure again.
        Some(unsafe { (*self.error.get()).assume_init() })
    }
}

/// The fixed-memory profile's driver: its receive buffer and the buffer its frames are built in
/// are each lent by a table the image declares.
pub type FixedStreamDriver<S> =
    StreamDriver<S, wz_session_core::byte_cells::ByteBuf, wz_session_core::byte_cells::ByteBuf>;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S: StreamSocket> StreamDriver<S, Vec<u8>, HeapTx> {
    /// The link over `socket`, receiving a batch of up to `rx_capacity` bytes with its length (the
    /// largest zenoh negotiates is [`STREAM_RX_CAPACITY`]) and encoding into the slots of `tx`.
    pub fn with_buffers(socket: S, rx_capacity: usize, tx: HeapTx) -> Self {
        Self::over(socket, vec![0u8; rx_capacity], tx)
    }
}

impl<S: StreamSocket, B: RxStore, T: TxStore> StreamDriver<S, B, T> {
    /// The link over the connected `socket`, receiving into `rx_buf` and building its frames in
    /// `tx`.
    pub fn over(socket: S, rx_buf: B, tx: T) -> Self {
        Self::framed(socket, rx_buf, 0, tx, LengthPrefix)
    }
}

impl<S: StreamSocket, B: RxStore, T: TxStore, F: StreamFraming> StreamDriver<S, B, T, F> {
    /// The link over the connected `socket`, its batches framed by `framing`, receiving into
    /// `rx_buf`, whose first `held` bytes were read off the stream already (what followed a
    /// handshake the link's maker ran in it), and building its frames in `tx`.
    pub fn framed(socket: S, mut rx_buf: B, held: usize, tx: T, framing: F) -> Self {
        let rx_len = rx_buf.capacity();
        Self {
            socket,
            framing,
            rx: RxHalf {
                buf: RefCell::new(rx_buf),
                len: rx_len,
                held: Cell::new(held.min(rx_len)),
                spent: Cell::new(0),
                behind: Cell::new(Behind::Unread),
                #[cfg(test)]
                moved: Cell::new(0),
                #[cfg(test)]
                fronts: Cell::new(0),
                #[cfg(test)]
                moves: Cell::new(0),
                keeping: Cell::new(false),
                #[cfg(feature = "alloc")]
                drops: crate::link_storage::RxDrops::new(),
            },
            tx: TxHalf::new(tx),
            lost: Lost::standing(),
            error: FirstError::none(),
            owner_waits: false,
        }
    }

    /// The same link, waited on by its owner when its stream can be
    /// ([`SessionDatagramLink::input_wait`]): its loop then reads what is queued and does not
    /// wait, and its owner waits on the stream with nothing of the session held. A stream that
    /// gives no such wait keeps the link waiting in its loop.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.wait_by_owner();
        self
    }

    /// [`Self::waited_by_owner`] where the link lies: a stack that makes a link sets it there,
    /// so the link is not moved through a second value of its whole size.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub fn wait_by_owner(&mut self) {
        self.owner_waits = self.socket.input_wait().is_some();
    }

    /// The failure the socket reported first, the one that ended the link, if it has failed.
    pub fn error(&self) -> Option<S::Error> {
        self.error.get()
    }

    /// The link is gone, for `cause`; the first cause is the one kept.
    fn end(&self, cause: LostCause) {
        self.lost.end(cause);
    }

    /// Whether a whole batch lies in the buffer for the next receive, which then needs no read.
    fn batch_held(&self) -> bool {
        self.rx.behind.get() == Behind::Whole
    }

    /// Hand the next whole batch to `f` where the buffer holds it, reading the socket until there
    /// is one or nothing more is queued; `false` when there is none. An empty batch is passed
    /// over. The batch stays where it lies after `f` returns, until the next receive: the bytes
    /// behind it are moved to the front only when the stream must be read for the rest of a batch,
    /// as zenoh-pico compacts its buffer only before such a read
    /// (`vendor/zenoh-pico/src/transport/unicast/read.c` @
    /// `_z_zbuf_set_rpos(&ztu->_common._zbuf, _z_zbuf_get_rpos(&ztu->_common._zbuf) - _Z_MSG_LEN_ENC_SIZE);`).
    fn receive(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.lost.get().is_some() {
            return false;
        }
        // A receive from inside `f` finds the buffer lent and reads nothing.
        let Ok(mut buf) = self.rx.buf.try_borrow_mut() else {
            return false;
        };
        // A link of a pool that holds no buffer and finds none free reads nothing: what its peer
        // sent waits in the stack (`SessionDatagramLink::waits_for_buffer`).
        let Some(bytes) = buf.bytes() else {
            return false;
        };
        let mut start = self.rx.spent.get();
        let mut held = self.rx.held.get();
        // Once a batch is lent, the front is read once more and only to say what lies behind it
        // for the next receive (`behind`): one reading of the front serves both. The part of a
        // batch the last receive found there is what a reading would find again, nothing having
        // been read since, so this receive reads the stream for the rest first.
        let mut lent = false;
        let mut part_known = self.rx.behind.get() == Behind::Part;
        let behind = loop {
            // `start` and `held` are places of the buffer, `start` the earlier, and a batch `front`
            // answered lies whole between them: the sums below stay inside it.
            let unit = if core::mem::take(&mut part_known) {
                Front::Partial
            } else {
                #[cfg(test)]
                self.rx.fronts.set(self.rx.fronts.get() + 1);
                self.framing.front(
                    bytes.get_mut(start..held).unwrap_or_default(),
                    self.rx.len,
                    !lent,
                )
            };
            match unit {
                Front::Batch { .. } | Front::Skip(_) if lent => break Behind::Whole,
                Front::Partial if lent => break Behind::Part,
                _ if lent => break Behind::Unread,
                Front::Skip(used) => start = start.wrapping_add(used),
                Front::Batch { at, len, used } => {
                    let body = start.wrapping_add(at);
                    let end = body.wrapping_add(len);
                    self.rx.keeping.set(false);
                    f(bytes.get(body..end).unwrap_or_default());
                    // A batch kept is lent again by the next receive; one let go is passed over
                    // there.
                    if !self.rx.keeping.replace(false) {
                        start = start.wrapping_add(used);
                        self.framing.passed();
                    }
                    lent = true;
                }
                Front::TooLong => {
                    self.end(LostCause::PeerClosed);
                    break Behind::Unread;
                }
                // The peer's end inside the framing is answered as the framing answers it, with
                // what the link owes written first, and the link ends.
                // A send that holds the send half now writes what is owed itself.
                Front::Closed => {
                    if let Some(tx) = self.tx.try_hold() {
                        self.write_owed(&tx);
                    }
                    self.end(LostCause::PeerClosed);
                    break Behind::Unread;
                }
                Front::Partial => {
                    // Nothing before the part of a batch is lent any more: it moves to the front,
                    // so the rest is read behind it and the whole batch fits where it lies.
                    if start > 0 {
                        // A buffer handed over whole has nothing behind its spent bytes, and
                        // starts over at its front with no move: what a stream that cuts its
                        // batches where they end finds at every read.
                        if start < held {
                            // `start < part.len()` is the one check `copy_within` makes of a
                            // range from `start` to a front it moves to, so it is decided here.
                            if let Some(part) = bytes.get_mut(..held) {
                                part.copy_within(start.., 0);
                            }
                            #[cfg(test)]
                            self.rx.moves.set(self.rx.moves.get() + 1);
                        }
                        #[cfg(test)]
                        self.rx.moved.set(self.rx.moved.get() + (held - start));
                        held = held.wrapping_sub(start);
                        start = 0;
                    }
                    match self
                        .socket
                        .try_read(bytes.get_mut(held..).unwrap_or_default())
                    {
                        Ok(Some(0)) => {
                            self.end(LostCause::PeerClosed);
                            break Behind::Unread;
                        }
                        // A read fills at most the room after `held`.
                        Ok(Some(n)) => held = held.wrapping_add(n),
                        // Nothing was added to the part of a batch the front found.
                        Ok(None) => break Behind::Part,
                        Err(e) => {
                            self.error.set(e);
                            self.end(LostCause::OsError);
                            break Behind::Unread;
                        }
                    }
                }
            }
        };
        self.rx.spent.set(start);
        self.rx.held.set(held);
        self.rx.behind.set(behind);
        // Nothing of the link's own is left in the buffer, no part of a batch and no batch kept:
        // a pooled buffer goes back for any link to read into. The facts of a part of a batch are
        // this link's (`held`, `spent`), so its buffer stays its own while one is there.
        if B::POOLED && start == held {
            self.rx.spent.set(0);
            self.rx.held.set(0);
            buf.idle();
        }
        lent
    }

    /// Whether the link owes the stream anything (a frame or the rest of one, or a unit of the
    /// framing's own). A send half another holder has now may be writing what is owed, and is
    /// answered as owing: a question that waits for nothing never takes for paid a debt a send
    /// beside it is paying.
    fn owes(&self) -> bool {
        match self.tx.try_hold() {
            Some(tx) => self.owes_held(&tx),
            None => true,
        }
    }

    /// [`Self::owes`], under `tx`, the hold of the send half.
    #[cfg(feature = "tx-stream-owed")]
    fn owes_held(&self, tx: &TxHold<'_, T>) -> bool {
        // A queue being written owes what it held when the write began.
        !tx.owed().try_borrow().is_ok_and(|owed| owed.is_empty()) || self.framing.owes_control()
    }

    /// [`Self::owes`] of a link whose send writes each frame whole: it owes no frame between
    /// calls, so what it owes is the framing's own units alone.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn owes_held(&self, _tx: &TxHold<'_, T>) -> bool {
        self.framing.owes_control()
    }

    /// Write the framing's own units, once no frame is owed before them: `true` once nothing
    /// of them is left (or the stream failed, which ends the link).
    fn write_control(&self, tx: &TxHold<'_, T>) -> bool {
        match self.framing.write_control(&self.socket) {
            Ok(done) => done,
            Err(e) => {
                self.fail(tx, e);
                true
            }
        }
    }

    /// Write what the link owes the stream, oldest first, without waiting: `true` once nothing is
    /// owed (or the link has ended, which gives back whatever it held), `false` when the stream
    /// took less than all of it, the rest still owed for the next step that finds it room.
    #[cfg(feature = "tx-stream-owed")]
    fn write_owed(&self, tx: &TxHold<'_, T>) -> bool {
        loop {
            if self.lost.get().is_some() {
                self.drop_owed(tx);
                return true;
            }
            // A queue already being written is left to that write, which owes the rest.
            let Ok(mut owed) = tx.owed().try_borrow_mut() else {
                return false;
            };
            let Some(front) = owed.front_mut() else {
                drop(owed);
                return self.write_control(tx);
            };
            // SAFETY: the slot is held by the link, out of its pool until the pop below or
            // `drop_owed` gives it back, so nothing writes it.
            let rest = unsafe { tx.lender().held(front.slot, front.from, front.end) };
            let want = rest.len();
            match self.socket.write(rest) {
                Ok(taken) if taken < want => {
                    front.from = front.from.saturating_add(taken);
                    return false;
                }
                Ok(_) => {
                    if let Some(done) = owed.pop() {
                        tx.lender().release(done.slot);
                    }
                }
                Err(e) => {
                    drop(owed);
                    self.fail(tx, e);
                    return true;
                }
            }
        }
    }

    /// Give back everything the link holds for the stream: the link has ended, and nothing it
    /// owed will be written. Out of line: every way a link ends comes here, and the loop that
    /// gives back slots is one body for all of them.
    #[cfg(feature = "tx-stream-owed")]
    #[inline(never)]
    fn drop_owed(&self, tx: &TxHold<'_, T>) {
        // No caller holds the queue across this call (`write_owed` lets it go before it fails),
        // so the queue is free here; a holder up the stack would keep its slots to release.
        if let Ok(mut owed) = tx.owed().try_borrow_mut() {
            while let Some(done) = owed.pop() {
                tx.lender().release(done.slot);
            }
        }
        tx.room_known().set(false);
    }

    /// [`Self::write_owed`] of a link whose send writes each frame whole: the framing's own units
    /// are all it can owe, written as far as the stream takes them without waiting.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn write_owed(&self, tx: &TxHold<'_, T>) -> bool {
        if self.lost.get().is_some() {
            return true;
        }
        self.write_control(tx)
    }

    /// [`Self::drop_owed`] of a link whose send writes each frame whole: it holds no frame for the
    /// stream once a send returns, so an end has nothing to give back.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn drop_owed(&self, _tx: &TxHold<'_, T>) {}

    /// The stream failed a write with `error`: the link ends, REPORTED and not swallowed.
    fn fail(&self, tx: &TxHold<'_, T>, error: S::Error) {
        self.error.set(error);
        self.end(LostCause::OsError);
        self.drop_owed(tx);
    }

    /// Write the frame `from .. end` of `slot`, which the session handed over, prefix included.
    /// A stream that writes without waiting ([`StreamSocket::WRITES_NOW`]) tries it: taken whole,
    /// it says the stream had room, the slot goes back, and the next frame asks nothing; taken in
    /// part or not at all, the rest is owed in the slot and the next frame asks the stream for
    /// room. Behind something already owed it is owed whole, so frames leave in the order they
    /// were handed over. Nothing waits here; a stream that cannot try is written by waiting.
    #[cfg(feature = "tx-stream-owed")]
    fn send(&self, tx: &TxHold<'_, T>, slot: TxSlot, from: usize, end: usize) -> LinkSendOutcome {
        // Where the rest that is owed starts, and how much of the frame the stream took: the frame
        // is owed from one place, whether it waits whole or the stream took part of it.
        let (from, taken) = if self.lost.get().is_none() && !self.write_owed(tx) {
            (from, 0)
        } else {
            if self.lost.get().is_some() {
                tx.lender().release(slot);
                return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
            }
            // SAFETY: the session handed the slot over and the link holds it: nothing writes it.
            let frame = unsafe { tx.lender().held(slot, from, end) };
            match self.socket.write(frame) {
                Ok(taken) if taken >= frame.len() => {
                    tx.lender().release(slot);
                    // A write that waited took the frame whole and says nothing of the room left.
                    tx.room_known().set(S::WRITES_NOW);
                    return LinkSendOutcome::Sent;
                }
                Ok(taken) => {
                    tx.room_known().set(false);
                    (from.saturating_add(taken), taken)
                }
                Err(e) => {
                    tx.lender().release(slot);
                    self.fail(tx, e);
                    return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
                }
            }
        };
        self.owe(tx, Owed { slot, from, end }, taken)
    }

    /// Write the frame `from .. end` of `slot`, which the session handed over, prefix included,
    /// whole: the send waits for the stream whenever it takes nothing, as zenoh-pico's link write
    /// waits in its socket's send (`vendor/zenoh-pico/src/link/link.c` @
    /// `z_result_t _z_link_send_wbuf(`), and the slot goes back once the frame has left or the
    /// stream has failed. A link that has ended writes nothing and gives the slot back.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn send(&self, tx: &TxHold<'_, T>, slot: TxSlot, from: usize, end: usize) -> LinkSendOutcome {
        let written = if self.lost.get().is_some() {
            None
        } else {
            // SAFETY: the session handed the slot over and the link holds it until the release
            // below, after the last read of the frame: nothing writes it meanwhile.
            let frame = unsafe { tx.lender().held(slot, from, end) };
            Some(self.write_whole(frame))
        };
        tx.lender().release(slot);
        match written {
            Some(Ok(())) => LinkSendOutcome::Sent,
            Some(Err(e)) => {
                self.fail(tx, e);
                LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
            }
            None => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    /// Write what the framing owes and then `frame`, every byte, waiting for the stream whenever
    /// it takes none: the framing's units go between frames, never inside one.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn write_whole(&self, frame: &[u8]) -> Result<(), S::Error> {
        while !self.framing.write_control(&self.socket)? {
            self.socket.wait_writable(SERVICE_WAIT_US);
        }
        self.socket.write_all(frame)
    }

    /// Put `owed` behind what is owed already. `skip` is how much of its frame the stream has
    /// taken: none for a frame that waits whole behind another.
    #[cfg(feature = "tx-stream-owed")]
    fn owe(&self, tx: &TxHold<'_, T>, owed: Owed, skip: usize) -> LinkSendOutcome {
        // A queue being written takes nothing more until the write ends: the frame is refused.
        let refused = match tx.owed().try_borrow_mut() {
            Ok(mut queue) => queue.push(owed),
            Err(_) => Err(owed),
        };
        match refused {
            Ok(()) => LinkSendOutcome::Sent,
            Err(owed) => {
                tx.lender().release(owed.slot);
                self.cannot_owe(tx, skip)
            }
        }
    }

    /// The link has nowhere to keep a frame it owes. One of which nothing was written is refused,
    /// as a frame the link lends no slot for is. One already begun on the stream cannot be: the
    /// stream's framing is lost with its rest, so the link ends.
    #[cfg(feature = "tx-stream-owed")]
    fn cannot_owe(&self, tx: &TxHold<'_, T>, skip: usize) -> LinkSendOutcome {
        if skip == 0 {
            return LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot);
        }
        self.end(LostCause::OsError);
        self.drop_owed(tx);
        LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
    }
}

impl<S, B, T, F> BoxedLinkDriver for StreamDriver<S, B, T, F>
where
    S: StreamSocket + 'static,
    B: RxStore + 'static,
    T: TxStore + 'static,
    F: StreamFraming + 'static,
{
    // The bytes are copied into a slot the link lends and sent as one, so a frame handed over as
    // bytes takes the steps of a lent one, and the stream's answer to it is a lent frame's.
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        let sent = crate::link_storage::copied_send(self, bytes, reliability, Priority::DEFAULT);
        // A link that owes its stream nothing has every slot out with the session, which holds one
        // for each of its conduits at most: one that lends the slots its session needs has one
        // more for this frame.
        debug_assert!(
            sent != LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
                || self.owes()
                || self.tx.slots() < SESSION_TX_SLOTS,
            "a stream link that lends its session's slots and owes nothing had none for a frame"
        );
        sent
    }

    // The room is the stream's: the session asks before it builds a frame, and a stream that
    // will not take more bytes within the wait has none, as zenoh's queue has no batch for a
    // message by its deadline (`io/zenoh-transport/src/common/pipeline.rs` @
    // `// Wait for an available batch until deadline`). A droppable message is then dropped and a
    // blocking one closes the session, which is the session's decision and not the link's. The
    // answer carries the time the stream's wait measured (`StreamSocket::wait_writable`),
    // so a sender that keeps one deadline across several questions spends what was spent. A link
    // that has ended answers room, so the send that follows reports the end.
    // A stream that took the last write whole without waiting is not asked: the next write is
    // tried first, and one it does not take whole makes the frame after it ask again
    // (`send`). A link that still owes the stream part of a frame has room once that is
    // written: the wait for the stream to take bytes is what lets it be, within the message's wait.
    // Out of line where the link is reached through its table, which the session asks through the
    // entry the trait derives from this one (`wait_for_room_for`): two entries, one body.
    #[cfg(feature = "tx-stream-owed")]
    #[cfg_attr(all(feature = "alloc", not(feature = "session-slot")), inline(never))]
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        let wait_us = wait.wait_us();
        // The send half is held for each write and let go of before any wait for the stream, so a
        // service beside this question is never held up by its wait.
        let owed_written = self.write_owed(&self.tx.hold());
        if self.lost.get().is_some() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        // A link of a pool whose every slot another link holds for a frame its stream has not
        // finished has no slot for the next frame until that link's step writes it. It does not
        // wait for that under the session's lock, where that step cannot run: it is congested now,
        // and a droppable message is dropped at once, as zenoh-pico drops one that finds its
        // transmit lock held (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
        // `return _z_mutex_try_lock(&ztc->_mutex_tx);`).
        if owed_written && !self.tx.claimable() {
            return RoomAnswer::at_once(LinkRoom::Congested);
        }
        if !owed_written {
            let (room, waited_us) = self.socket.wait_writable(wait_us);
            let room = if room && self.write_owed(&self.tx.hold()) {
                LinkRoom::Free
            } else {
                LinkRoom::Congested
            };
            return RoomAnswer { room, waited_us };
        }
        if self.tx.hold().room_known().get() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let (room, waited_us) = self.socket.wait_writable(wait_us);
        RoomAnswer {
            room: if room {
                LinkRoom::Free
            } else {
                LinkRoom::Congested
            },
            waited_us,
        }
    }

    // The session encodes a batch straight into the driver's own storage behind the room its
    // length takes, and the length is written there at the send: length and batch are one write
    // from the slot, and no buffer is allocated for either.
    //
    // A frame the stream has not taken whole keeps its slot until it is written. A link lent one
    // slot, as zenoh-pico keeps one write buffer, finds it held by the batch it has just sent
    // whenever a message follows it (a Close after the drain of the open batch); so a link with no
    // slot free writes what it owes first, as far as the stream takes it without waiting, and lends
    // the slot that frees. One the stream frees none for is refused, as before.
    #[cfg(feature = "tx-stream-owed")]
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        let tx = self.tx.hold();
        if let Some(grant) = tx.lender().acquire(F::HEADROOM) {
            return Some(grant);
        }
        if self.owes_held(&tx) && self.write_owed(&tx) {
            return tx.lender().acquire(F::HEADROOM);
        }
        None
    }

    // A link whose send writes each frame whole waits for its stream inside the send, as
    // zenoh-pico's does, so the stream is not asked here. What keeps a message from the link is
    // the send half another send holds while it writes, as zenoh-pico's transmit lock is: a
    // droppable message only tries it and is congested at once while it is held
    // (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
    // `return _z_mutex_try_lock(&ztc->_mutex_tx);`), and one that may not be dropped waits for it
    // (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
    // `_z_mutex_lock(&ztc->_mutex_tx);`). A slot the session holds does not: its open batch takes
    // the message, or is sent first and the slot lent again, as zenoh-pico's one write buffer
    // held by a batch takes the next message or is flushed for it. So the link has room while its
    // store has the memory for a slot (`claimable`), and is congested at once only while a pool
    // its session's links share has none. A link that has ended answers room, so the send that
    // follows reports the end.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[cfg_attr(all(feature = "alloc", not(feature = "session-slot")), inline(never))]
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        if self.lost.get().is_some() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let tx = if wait.is_droppable() {
            self.tx.try_hold()
        } else {
            Some(self.tx.hold())
        };
        if tx.is_some_and(|held| held.lender().claimable()) {
            RoomAnswer::at_once(LinkRoom::Free)
        } else {
            RoomAnswer::at_once(LinkRoom::Congested)
        }
    }

    // The link keeps no slot past the send that wrote its frame, so one that finds none free has
    // every slot with the session, and no write of its own here would give one back.
    #[cfg(not(feature = "tx-stream-owed"))]
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        self.tx.hold().lender().acquire(F::HEADROOM)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.tx.storage(slot)
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        // The framing seals the batch in the slot: its head written into the headroom and, for a
        // framing that masks, the batch masked where it lies.
        let tx = self.tx.hold();
        match tx
            .lender()
            .seal(slot, start, len, |bytes, at| self.framing.seal(bytes, at))
        {
            Some((from, end)) => self.send(&tx, slot, from, end),
            None => {
                tx.lender().release(slot);
                LinkSendOutcome::Dropped(LinkDropCause::Oversize)
            }
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.hold().lender().release(slot);
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_spare(&self) -> bool {
        self.tx.spare()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_claimable(&self) -> bool {
        self.tx.claimable()
    }

    fn open_blocking(&self) {}

    // The session's Close frame has been handed over; the stream ends behind it, and the peer
    // reads the end. What the link still owes is tried once more, without waiting, and what the
    // stream does not take then is not written: the peer reads a frame cut short by the end of
    // the stream, which it takes as the end.
    fn close_blocking(&self) {
        let tx = self.tx.hold();
        self.framing.closing();
        self.write_owed(&tx);
        self.socket.shutdown();
        self.end(LostCause::PeerClosed);
        self.drop_owed(&tx);
    }

    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        Some(F::link_ends(self.socket.ends()))
    }

    #[cfg(feature = "alloc")]
    fn link_subject(&self) -> Option<&wz_session_core::link::LinkSubject> {
        Some(F::subject(self.socket.ends()))
    }

    fn peer_credential_zid(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        self.socket.peer_credential_zid()
    }

    fn batch_length_prefixed(&self) -> bool {
        F::LENGTH_PREFIXED
    }

    // A driver whose frame storage is declared is bounded by it: the batch it sends is at most a
    // slot. A batch is counted with its length, as the session's budget counts it (it takes the
    // length's room out of the batch itself, `batch_envelope_bytes`), so the bound is the whole
    // slot. One that lends nothing builds no frame in its storage and takes any batch the session
    // hands it.
    fn link_mtu(&self) -> usize {
        if self.tx.lends() {
            F::mtu(self.tx.slot_len())
        } else {
            DEFAULT_LINK_MTU
        }
    }

    // The receive buffer bounds the batch whatever the send side lends: a batch is counted with
    // its length, and the buffer holds both.
    fn link_rx_capacity(&self) -> usize {
        F::rx_capacity(self.rx.len).min(DEFAULT_LINK_MTU)
    }
}

impl<S, B, T, F> SessionDatagramLink for StreamDriver<S, B, T, F>
where
    S: StreamSocket + 'static,
    B: RxStore + 'static,
    T: TxStore + 'static,
    F: StreamFraming + 'static,
{
    fn service(&self) {
        // What the link owes the stream is written as far as the stream takes it, every step, unless
        // a send holds the send half now: that send writes it, and the read does not wait for it.
        if let Some(tx) = self.tx.try_hold() {
            if self.owes_held(&tx) {
                self.write_owed(&tx);
            }
        }
        // A whole batch already held (the last read brought two) is read without waiting, and a
        // link its owner waits on does not wait here. A link that still owes the stream waits its
        // tick for room instead of for input, and writes on when it has some.
        if self.lost.get().is_none() && !self.batch_held() && !self.owner_waits {
            if !self.owes() {
                self.socket.wait_readable(SERVICE_WAIT_MS);
            } else if self.socket.wait_writable(SERVICE_WAIT_US).0 {
                if let Some(tx) = self.tx.try_hold() {
                    self.write_owed(&tx);
                }
            }
        }
    }

    fn holds_input(&self) -> bool {
        self.batch_held()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        self.rx.buf.try_borrow().is_ok_and(|buf| buf.starved())
    }

    fn owes_write(&self) -> bool {
        self.owes()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        if let Some(tx) = self.tx.try_hold() {
            if self.owes_held(&tx) {
                self.write_owed(&tx);
            }
        }
    }

    // A batch lies in the link's own receive buffer until the link moves what follows it to the
    // front: a batch kept is left where it lies, and costs no copy.
    fn keeps_input(&self) -> bool {
        true
    }

    fn keep(&self) {
        self.rx.keeping.set(true);
    }

    // The receive buffer is written by a receive alone (`receive`: its read of the stream and the
    // move to the front before it), never by a service, which waits and writes what is owed, so
    // what a receive lent lies there until the link is next asked to receive.
    fn lends_until_next_receive(&self) -> bool {
        true
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        if self.owner_waits {
            self.socket.input_wait()
        } else {
            None
        }
    }

    // Whoever waits for input, room is the socket's alone: the driver queues nothing of its own
    // ahead of it (`wait_for_room` asks the socket too, unless the last write already said the
    // stream had room), so a wait on the socket from outside answers what the session's own wait
    // would.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        self.socket.room_wait()
    }

    // The batch the lending receive hands over, copied out.
    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        crate::link_storage::copied_receive(self, &self.rx.drops)
    }

    #[cfg(feature = "alloc")]
    fn take_rx_dropped(&self) -> usize {
        self.rx.drops.take()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.receive(f)
    }

    fn lost(&self) -> Option<LostCause> {
        self.lost.get()
    }
}

impl<S, B, X> StreamLink<S, B, X> for StreamDriver<S, B, X>
where
    S: StreamSocket + 'static,
    B: RxStore + 'static,
    X: TxStore + 'static,
{
    fn over(socket: S, rx: B, tx: X) -> Self {
        StreamDriver::over(socket, rx, tx)
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn wait_by_owner(&mut self) {
        StreamDriver::wait_by_owner(self);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::UnsafeCell;
    use std::collections::VecDeque;
    use std::vec::Vec;
    use wz_session_core::link::LinkEndsText;

    /// A secure channel reports the connection's two addresses under its own protocol, which a
    /// row names as it names any IP end. Turned red by ends that keep the connection's protocol,
    /// or lose an address.
    #[test]
    fn a_channel_reports_the_connections_ends_under_its_own_protocol() {
        let local = SocketAddr::from(([10, 0, 0, 2], 40_000));
        let peer = SocketAddr::from(([10, 0, 0, 1], 7447));
        let tcp = StreamEnds::Ip {
            proto: LinkProto::Tcp,
            local,
            peer,
        };
        let tls = tcp.speaking(LinkProto::Tls);
        assert_eq!(
            tls,
            StreamEnds::Ip {
                proto: LinkProto::Tls,
                local,
                peer
            }
        );
        assert_eq!(tls.ip(), Some((local, peer)));
        assert!(tls.fit());
        #[cfg(feature = "alloc")]
        assert_eq!(
            tls.subject().kind,
            Some(wz_session_core::link::LinkKind::Tls)
        );
    }

    /// The ends of a link over named FIFOs are its two FIFOs, of no IP, kept as they are under a
    /// channel, and named in a row while `unixpipe/` and the path fit it. Turned red by a bound
    /// that counts the path alone, or ends reported as another kind.
    #[cfg(feature = "unixpipe")]
    #[test]
    fn the_ends_of_a_fifo_link_are_its_two_fifos() {
        let row = wz_session_core::caps::MAX_LOCATOR_LEN - "unixpipe/".len();
        let longest = "a".repeat(row);
        let ends = StreamEnds::Unixpipe {
            local: &longest,
            peer: "/tmp/p_downlink7",
        };
        assert!(ends.fit());
        assert_eq!(ends.ip(), None);
        assert_eq!(ends.speaking(LinkProto::Tls), ends);
        #[cfg(feature = "alloc")]
        assert_eq!(
            ends.subject().kind,
            Some(wz_session_core::link::LinkKind::Unixpipe)
        );
        let past = "a".repeat(row + 1);
        let ends = StreamEnds::Unixpipe {
            local: "/tmp/p_uplink7",
            peer: &past,
        };
        assert!(!ends.fit());
    }

    /// The ring of what a link owes keeps its frames oldest first across its end, refuses one past
    /// its places and hands it back, and lends its oldest where it lies. Turned red by a ring that
    /// reads a place no push wrote, or loses the order once it wraps.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn the_owed_ring_keeps_its_frames_in_order_across_its_end() {
        let owed = |n: u32| Owed {
            slot: TxSlot(n),
            from: 0,
            end: 0,
        };
        let slot_of = |owed: &Owed| Some(owed.slot.0);
        let mut ring = OwedQueue::new();
        assert!(ring.is_empty());
        assert!(ring.front_mut().is_none());
        assert!(ring.pop().is_none());
        // Some frames in and out first, so the full ring lies across its end.
        for n in 0..3 {
            assert!(ring.push(owed(n)).is_ok());
        }
        for n in 0..3 {
            assert_eq!(ring.pop().as_ref().and_then(slot_of), Some(n));
        }
        let places = u32::try_from(OWED).expect("a ring of a few places");
        for n in 10..10 + places {
            assert!(ring.push(owed(n)).is_ok(), "frame {n} has a place");
        }
        let refused = ring.push(owed(99)).err();
        assert_eq!(
            refused.as_ref().and_then(slot_of),
            Some(99),
            "one past the places comes back"
        );
        if let Some(front) = ring.front_mut() {
            front.from = 5;
        }
        let first = ring.pop().expect("the oldest");
        assert_eq!(
            (slot_of(&first), first.from),
            (Some(10), 5),
            "the oldest was lent where it lies"
        );
        for n in 11..10 + places {
            assert_eq!(ring.pop().as_ref().and_then(slot_of), Some(n));
        }
        assert!(ring.is_empty());
    }

    /// What the test hands the driver to read, in the pieces the stream cuts it into, and what
    /// the driver wrote, one entry per write. A pipe that `TRIES` writes without waiting
    /// ([`StreamSocket::WRITES_NOW`]); one that does not is asked for room before every frame.
    #[derive(Default)]
    struct Pipe<const TRIES: bool = false> {
        pieces: RefCell<VecDeque<Vec<u8>>>,
        /// After the pieces: the peer closed the stream.
        ends: Cell<bool>,
        /// The next read fails.
        fails: Cell<bool>,
        writes: RefCell<Vec<Vec<u8>>>,
        reads: Cell<u32>,
        waits: Cell<u32>,
        shut: Cell<bool>,
        /// The connection's two ends, local then peer; `None` is an IPv4 pair.
        ends_at: Option<(SocketAddr, SocketAddr)>,
        /// The peer reads nothing: the stream takes no more bytes, however long it is waited on.
        full: Cell<bool>,
        /// Each wait for the stream to take bytes, in microseconds.
        room_waits: RefCell<Vec<u64>>,
        /// How many bytes the writes that do not wait take before the stream would block; `None`
        /// takes them all.
        takes: Cell<Option<usize>>,
        /// The writes made by waiting, by a pipe that does not try.
        waited_writes: Cell<u32>,
        /// The next write that does not wait fails.
        write_fails: Cell<bool>,
        /// How long a wait for room says it took, in microseconds; `None` answers as a stream
        /// with no clock does.
        room_took_us: Cell<Option<u64>>,
        /// What the next wait for room leaves the writes that do not wait taking, the peer having
        /// read meanwhile; `None` leaves them as they were.
        room_after_wait: Cell<Option<usize>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Broken;

    impl<const TRIES: bool> StreamSocket for Pipe<TRIES> {
        type Error = Broken;

        type Link<B: RxStore + 'static, X: crate::link_storage::TxStore + 'static>
            = crate::stream_link::StreamDriver<Self, B, X>
        where
            Self: 'static;

        const WRITES_NOW: bool = TRIES;

        fn ends(&self) -> StreamEnds<'_> {
            let (local, peer) = self.ends_at.unwrap_or((
                SocketAddr::from(([10, 0, 0, 2], 40_000)),
                SocketAddr::from(([10, 0, 0, 1], 7447)),
            ));
            StreamEnds::Ip {
                proto: LinkProto::Tcp,
                local,
                peer,
            }
        }

        fn write(&self, bytes: &[u8]) -> Result<usize, Broken> {
            if !TRIES {
                self.waited_writes.set(self.waited_writes.get() + 1);
                self.writes.borrow_mut().push(bytes.to_vec());
                return Ok(bytes.len());
            }
            if self.write_fails.get() {
                return Err(Broken);
            }
            let taken = if self.full.get() {
                0
            } else {
                self.takes
                    .get()
                    .map_or(bytes.len(), |left| left.min(bytes.len()))
            };
            if let Some(left) = self.takes.get() {
                self.takes.set(Some(left - taken));
            }
            if taken > 0 {
                self.writes.borrow_mut().push(bytes[..taken].to_vec());
            }
            Ok(taken)
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
        }

        fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
            self.room_waits.borrow_mut().push(timeout_us);
            if let Some(takes) = self.room_after_wait.take() {
                self.takes.set(Some(takes));
            }
            let room = !self.full.get() && self.takes.get() != Some(0);
            let took = self
                .room_took_us
                .get()
                .unwrap_or(if room { 0 } else { timeout_us });
            (room, took)
        }

        fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Broken> {
            self.reads.set(self.reads.get() + 1);
            if self.fails.get() {
                return Err(Broken);
            }
            let mut pieces = self.pieces.borrow_mut();
            let Some(piece) = pieces.front_mut() else {
                return Ok(if self.ends.get() { Some(0) } else { None });
            };
            let n = piece.len().min(buf.len());
            buf[..n].copy_from_slice(&piece[..n]);
            piece.drain(..n);
            if piece.is_empty() {
                pieces.pop_front();
            }
            Ok(Some(n))
        }

        fn shutdown(&self) {
            self.shut.set(true);
        }

        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        fn room_wait(&self) -> Option<WaitOn> {
            Some(WaitOn::Socket(PIPE_HANDLE))
        }
    }

    /// The handle a pipe names for a wait on its room: a socket of no platform, which only the
    /// tests compare.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    const PIPE_HANDLE: usize = 7;

    /// A link names its socket's handle for a wait on its room whether or not its owner waits for
    /// its input (none does here), and names nothing for its input then. Turned red by a link
    /// whose room wait follows its owner's wait for input, or that names a handle for its input
    /// while its own loop waits for it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_link_names_its_sockets_room_whether_or_not_its_owner_waits() {
        let link = link();
        assert_eq!(link.room_wait(), Some(WaitOn::Socket(PIPE_HANDLE)));
        assert_eq!(link.input_wait(), None, "its own loop waits for its input");
    }

    /// Two slots of 32 bytes, for any profile.
    struct Slots(UnsafeCell<[u8; 64]>);

    impl TxStore for Slots {
        fn slots(&self) -> usize {
            2
        }

        fn slot_len(&self) -> usize {
            32
        }

        fn slot_base(&self, slot: usize) -> *mut u8 {
            self.0.get().cast::<u8>().wrapping_add(slot * 32)
        }
    }

    type Link = StreamDriver<Pipe, [u8; 34], Slots>;

    /// A link whose buffer takes a batch of 32 bytes behind its length.
    fn link() -> Link {
        StreamDriver::over(Pipe::default(), [0u8; 34], Slots(UnsafeCell::new([0; 64])))
    }

    /// A write that must have every byte taken waits for room whenever the stream takes none, and
    /// writes on from where the stream stopped once it has some: nothing it took is written again.
    /// A stream that takes it all is never asked. Turned red (a write that never ends) by
    /// `write_all` writing again without waiting after a write that took nothing.
    #[test]
    fn a_write_of_every_byte_waits_for_room_only_when_the_stream_took_none() {
        let pipe = Pipe::<true>::default();
        pipe.write_all(b"hi").expect("CONTROL: a stream with room");
        assert!(pipe.room_waits.borrow().is_empty(), "CONTROL: not asked");
        pipe.takes.set(Some(2));
        pipe.room_after_wait.set(Some(8));
        pipe.write_all(b"hello").expect("written whole");
        assert_eq!(
            *pipe.writes.borrow(),
            [b"hi".to_vec(), b"he".to_vec(), b"llo".to_vec()]
        );
        assert_eq!(*pipe.room_waits.borrow(), [SERVICE_WAIT_US]);
        pipe.write_fails.set(true);
        assert_eq!(
            pipe.write_all(b"late"),
            Err(Broken),
            "a failure is reported"
        );
    }

    /// A link of [`Link`]'s buffers over a stream that writes without waiting.
    type Trying = StreamDriver<Pipe<true>, [u8; 34], Slots>;

    /// A link as [`link`] makes one, over a stream that writes without waiting.
    fn trying() -> Trying {
        StreamDriver::over(Pipe::default(), [0u8; 34], Slots(UnsafeCell::new([0; 64])))
    }

    fn batch(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn queue<B: RxStore>(link: &StreamDriver<Pipe, B, Slots>, piece: &[u8]) {
        link.socket.pieces.borrow_mut().push_back(piece.to_vec());
    }

    fn received<B: RxStore + 'static>(link: &StreamDriver<Pipe, B, Slots>) -> Option<Vec<u8>> {
        let mut got = None;
        link.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
        got
    }

    /// A link that reads into a pool of receive buffers its session's links share.
    #[cfg(feature = "session-unicast-accept")]
    type Pooled = StreamDriver<Pipe, crate::link_storage::PooledRx, Slots>;

    /// A pool of `buffers` receive buffers of 34 bytes, lent from an arena of its own that the test
    /// process leaks, as a session's arena lends its links' pool.
    #[cfg(feature = "session-unicast-accept")]
    fn pool(buffers: usize) -> wz_session_core::byte_cells::LentByteCells {
        use wz_session_core::bounded::{Arena, ARENA_ALIGN};

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let bytes = Arena::byte_cells_bytes(34, buffers).expect("a test's pool fits");
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every buffer.
        let mut arena = unsafe {
            Arena::over(
                core::ptr::NonNull::from(region).cast::<u8>(),
                blocks * ARENA_ALIGN,
            )
        };
        arena
            .lend_byte_cells(34, buffers)
            .expect("the arena holds the pool")
    }

    #[cfg(feature = "session-unicast-accept")]
    fn pooled(pool: wz_session_core::byte_cells::LentByteCells) -> Pooled {
        StreamDriver::over(
            Pipe::default(),
            crate::link_storage::PooledRx::of(pool),
            Slots(UnsafeCell::new([0; 64])),
        )
    }

    /// Two stream links over one pool, each sent its batch in parts that alternate with the
    /// other's, the length cut in two as well: each hands over its own batch whole, never a byte
    /// of the other's, because a link keeps the buffer that holds its part of a batch and the
    /// other reads into another. Once both are handed over neither holds a buffer. Then byte by
    /// byte, alternating, the same holds at every step.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn two_stream_links_over_one_pool_each_keep_their_part_of_a_batch() {
        let pool = pool(2);
        let (a, b) = (pooled(pool), pooled(pool));
        let (to_a, to_b) = (
            batch(b"to a, all of it here"),
            batch(b"and to b, another one"),
        );
        queue(&a, &to_a[..1]);
        assert_eq!(received(&a), None, "half a length");
        queue(&b, &to_b[..5]);
        assert_eq!(received(&b), None, "a length and part of a batch");
        assert_eq!(pool.in_use(), 2, "each link holds the buffer of its part");
        queue(&a, &to_a[1..9]);
        assert_eq!(received(&a), None, "still part of a batch");
        queue(&b, &to_b[5..]);
        assert_eq!(received(&b).as_deref(), Some(&to_b[2..]));
        assert_eq!(pool.in_use(), 1, "b holds nothing of its own now");
        queue(&a, &to_a[9..]);
        assert_eq!(received(&a).as_deref(), Some(&to_a[2..]));
        assert_eq!(pool.in_use(), 0);
        assert!(!a.waits_for_buffer() && !b.waits_for_buffer());

        let mut got: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        for at in 0..to_a.len().max(to_b.len()) {
            for (link, wire, into) in [(&a, &to_a, 0), (&b, &to_b, 1)] {
                if let Some(byte) = wire.get(at) {
                    queue(link, &[*byte]);
                }
                if let Some(whole) = received(link) {
                    got[into].push(whole);
                }
                assert!(pool.in_use() <= 2);
            }
        }
        assert_eq!(
            got,
            [std::vec![to_a[2..].to_vec()], std::vec![to_b[2..].to_vec()]]
        );
        assert_eq!(pool.in_use(), 0);
    }

    /// Over a pool of one buffer, a link whose part of a batch holds it leaves the other link
    /// reading nothing: the other's batch stays in its stream, whole, and the link says it waits
    /// for a buffer; once the first batch is handed over the buffer is free, the other no longer
    /// waits, and its batch is read whole. A batch a link was asked to keep holds the buffer too,
    /// until it is lent again and let go.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn a_link_that_finds_the_pool_dry_reads_nothing_and_loses_nothing() {
        let pool = pool(1);
        let (a, b) = (pooled(pool), pooled(pool));
        let (to_a, to_b) = (batch(b"first"), batch(b"second"));
        queue(&a, &to_a[..4]);
        assert_eq!(received(&a), None);
        queue(&b, &to_b);
        assert_eq!(received(&b), None, "no buffer to read into");
        assert!(b.waits_for_buffer());
        assert_eq!(
            b.socket.pieces.borrow().len(),
            1,
            "the batch waits in the stream, unread"
        );
        queue(&a, &to_a[4..]);
        assert_eq!(received(&a).as_deref(), Some(&b"first"[..]));
        assert!(!b.waits_for_buffer(), "the buffer is free");
        assert_eq!(received(&b).as_deref(), Some(&b"second"[..]));
        assert_eq!(pool.in_use(), 0);

        queue(&a, &batch(b"kept"));
        assert!(a.recv_with(&mut |_| a.keep()));
        assert_eq!(pool.in_use(), 1, "a kept batch holds the buffer");
        queue(&b, &batch(b"waits"));
        assert_eq!(received(&b), None);
        assert_eq!(received(&a).as_deref(), Some(&b"kept"[..]), "lent again");
        assert_eq!(pool.in_use(), 0, "and let go");
        assert_eq!(received(&b).as_deref(), Some(&b"waits"[..]));
    }

    /// A receive asked from inside the lend finds the buffer lent and reads nothing, and the batch
    /// behind waits for the next receive. Turned red by a receive that borrows its buffer with
    /// `borrow_mut`, which panics there.
    #[test]
    fn a_receive_from_inside_the_lend_reads_nothing() {
        let link = link();
        let mut wire = batch(b"one");
        wire.extend(batch(b"two"));
        queue(&link, &wire);
        let mut inner = None;
        assert!(link.recv_with(&mut |_| inner = Some(received(&link))));
        assert_eq!(inner, Some(None), "the inner receive reads nothing");
        assert_eq!(received(&link).as_deref(), Some(&b"two"[..]));
    }

    /// A batch the session asks the link to keep, from inside the lend, is lent again whole by the
    /// next receive, before the batch behind it and with no read of the stream; one not kept is
    /// let go, and the next receive hands the batch behind it.
    #[test]
    fn a_kept_batch_is_lent_again_before_the_next() {
        let link = link();
        assert!(link.keeps_input());
        let mut wire = batch(b"one");
        wire.extend(batch(b"two"));
        queue(&link, &wire);
        let mut got = None;
        assert!(link.recv_with(&mut |bytes| {
            got = Some(bytes.to_vec());
            link.keep();
        }));
        assert_eq!(got.as_deref(), Some(&b"one"[..]));
        let reads = link.socket.reads.get();
        assert_eq!(
            received(&link).as_deref(),
            Some(&b"one"[..]),
            "kept: lent again"
        );
        assert_eq!(
            link.socket.reads.get(),
            reads,
            "from the buffer, with no read"
        );
        assert_eq!(
            received(&link).as_deref(),
            Some(&b"two"[..]),
            "let go: the next"
        );
        assert_eq!(received(&link), None);
    }

    /// A batch a receive lent lies where it was lent until the next receive, whatever is asked of
    /// the link meanwhile (a service, whether it holds input), which is what lets its owner hand
    /// the batch's records to their callbacks there; the batch behind it is lent where the stream
    /// put it, and only the part of a batch the buffer holds when the stream must be read again is
    /// moved: 3 bytes for the three batches here, where moving what followed each batch at once
    /// moved 11.
    #[test]
    fn a_lent_batch_lies_where_it_was_lent_until_the_next_receive() {
        let link = link();
        assert!(link.lends_until_next_receive());
        let mut wire = batch(b"one");
        wire.extend(batch(b"two"));
        wire.extend(&batch(b"three")[..3]);
        queue(&link, &wire);
        let mut first: *const u8 = core::ptr::null();
        assert!(link.recv_with(&mut |bytes| first = bytes.as_ptr()));
        link.service();
        assert!(link.holds_input(), "the second batch lies behind the first");
        // SAFETY: the pointer is into the link's own buffer, which lives as long as `link`, and
        // nothing borrows the buffer now.
        let lent = unsafe { core::slice::from_raw_parts(first, 3) };
        assert_eq!(lent, b"one", "still where it was lent");
        let mut second: *const u8 = core::ptr::null();
        assert!(link.recv_with(&mut |bytes| second = bytes.as_ptr()));
        assert_eq!(
            second,
            first.wrapping_add(3 + STREAM_BATCH_LENGTH_BYTES),
            "the batch behind it is lent where the stream put it"
        );
        assert_eq!(link.rx.moved.get(), 0, "nothing moved yet");
        assert!(!link.holds_input(), "part of a batch is not one");
        queue(&link, &batch(b"three")[3..]);
        assert_eq!(received(&link).as_deref(), Some(&b"three"[..]));
        assert_eq!(
            link.rx.moved.get(),
            3,
            "the part of the third batch, moved once before the read"
        );
        assert_eq!(link.rx.moves.get(), 1, "in one move");
    }

    /// A receive that finds every byte its buffer holds handed over already starts the buffer over
    /// at its front and moves nothing: the next batch is read and lent where the one before it
    /// was. Turned red by a move of the empty rest before the read.
    #[test]
    fn a_buffer_handed_over_whole_starts_over_with_no_move() {
        let link = link();
        queue(&link, &batch(b"one"));
        let mut first: *const u8 = core::ptr::null();
        assert!(link.recv_with(&mut |bytes| first = bytes.as_ptr()));
        queue(&link, &batch(b"two"));
        let mut second: *const u8 = core::ptr::null();
        let mut got = None;
        assert!(link.recv_with(&mut |bytes| {
            second = bytes.as_ptr();
            got = Some(bytes.to_vec());
        }));
        assert_eq!(got.as_deref(), Some(&b"two"[..]));
        assert_eq!(second, first, "read and lent at the front again");
        assert_eq!(link.rx.moves.get(), 0, "nothing was left to move");
        assert_eq!(link.rx.moved.get(), 0);
    }

    /// A receive says whether a whole batch lies behind what it lent, from the one reading of the
    /// front that follows the lend: an empty batch is one (the next receive passes it over), a
    /// batch kept is one (lent again), and a length past the buffer is none, the link ending at
    /// the receive that reads that length and not at the one before it.
    #[test]
    fn a_receive_says_whether_a_whole_batch_lies_behind_what_it_lent() {
        let empty = link();
        let mut wire = batch(b"one");
        wire.extend(batch(b""));
        queue(&empty, &wire);
        assert_eq!(received(&empty).as_deref(), Some(&b"one"[..]));
        assert!(empty.holds_input(), "an empty batch is a whole one");
        assert_eq!(received(&empty), None, "passed over, and nothing behind it");
        assert!(!empty.holds_input());

        let kept = link();
        queue(&kept, &batch(b"two"));
        assert!(kept.recv_with(&mut |_| kept.keep()));
        assert!(kept.holds_input(), "the batch kept is lent again");

        let long = link();
        let mut wire = batch(b"one");
        wire.extend([0xff, 0x00]);
        queue(&long, &wire);
        assert_eq!(received(&long).as_deref(), Some(&b"one"[..]));
        assert!(!long.holds_input(), "a length past the buffer is no batch");
        assert_eq!(
            long.lost(),
            None,
            "not ended by the receive that lent a batch"
        );
        assert_eq!(received(&long), None);
        assert_eq!(long.lost(), Some(LostCause::PeerClosed));
    }

    /// A receive reads the front of its buffer once for the batch it lends and once for what lies
    /// behind it, and the part of a batch found there is not read again before the stream is: the
    /// next receive reads the stream first. Turned red by a receive that reads again a front it
    /// found to be the part of a batch, before reading the stream.
    #[test]
    fn a_receive_does_not_read_again_the_part_of_a_batch_it_found() {
        let link = link();
        queue(&link, &batch(b"one"));
        assert_eq!(received(&link).as_deref(), Some(&b"one"[..]));
        let first = link.rx.fronts.get();
        assert_eq!(first, 3, "a front never read, the batch, and behind it");
        queue(&link, &batch(b"two"));
        assert_eq!(received(&link).as_deref(), Some(&b"two"[..]));
        assert_eq!(link.rx.fronts.get(), first + 2, "the batch, and behind it");
        let reads = link.socket.reads.get();
        assert_eq!(received(&link), None, "nothing more was sent");
        assert_eq!(
            link.rx.fronts.get(),
            first + 2,
            "no front is read when the stream brings nothing"
        );
        assert_eq!(link.socket.reads.get(), reads + 1, "the stream is read");
        queue(&link, &batch(b"three")[..3]);
        assert_eq!(received(&link), None, "part of a batch");
        queue(&link, &batch(b"three")[3..]);
        assert_eq!(
            received(&link).as_deref(),
            Some(&b"three"[..]),
            "the part the front found is read on from where it lies"
        );
    }

    #[test]
    fn the_front_of_a_buffer_is_read_as_the_framing_says() {
        assert_eq!(front(&[], 10), Front::Partial);
        assert_eq!(front(&[3], 10), Front::Partial, "half a length");
        assert_eq!(
            front(&[3, 0, 1, 2], 10),
            Front::Partial,
            "two of three bytes"
        );
        assert_eq!(
            front(&[3, 0, 1, 2, 3, 9], 10),
            Front::Batch {
                at: 2,
                len: 3,
                used: 5
            }
        );
        assert_eq!(front(&[0, 0, 7], 10), Front::Skip(2), "an empty batch");
        assert_eq!(
            front(&[8, 0], 10),
            Front::Partial,
            "a batch that fits, exactly"
        );
        assert_eq!(front(&[9, 0], 10), Front::TooLong);
        assert_eq!(
            front(&[0, 1], 300),
            Front::Partial,
            "the length is little-endian"
        );
    }

    #[test]
    fn a_batch_the_stream_cut_anywhere_is_handed_over_whole() {
        let link = link();
        let wire = batch(b"hello");
        queue(&link, &wire[..1]);
        assert_eq!(received(&link), None, "half the length");
        queue(&link, &wire[1..4]);
        assert_eq!(received(&link), None, "the length and two bytes");
        queue(&link, &wire[4..]);
        assert_eq!(received(&link).as_deref(), Some(&b"hello"[..]));
        assert_eq!(received(&link), None);
        assert_eq!(link.lost(), None);
    }

    #[test]
    fn two_batches_of_one_read_are_two_receives_and_the_second_needs_no_read_or_wait() {
        let link = link();
        let mut wire = batch(b"one");
        wire.extend(batch(b"two"));
        wire.extend(&batch(b"three")[..3]);
        queue(&link, &wire);
        assert_eq!(received(&link).as_deref(), Some(&b"one"[..]));
        let reads = link.socket.reads.get();
        link.service();
        assert_eq!(
            link.socket.waits.get(),
            0,
            "a held batch is read without waiting"
        );
        assert_eq!(received(&link).as_deref(), Some(&b"two"[..]));
        assert_eq!(link.socket.reads.get(), reads, "and without a read");
        link.service();
        assert_eq!(link.socket.waits.get(), 1, "part of a batch is not one");
        queue(&link, &batch(b"three")[3..]);
        assert_eq!(received(&link).as_deref(), Some(&b"three"[..]));
    }

    /// The copying receive hands over the batch the lending one would, past an empty batch, and
    /// nothing while only part of the next is held. Turned red by a copy that takes the length
    /// with the batch, or hands a batch over twice.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_copying_receive_hands_over_what_the_lending_one_would() {
        let link = link();
        let mut wire = batch(b"");
        wire.extend(batch(b"one"));
        wire.extend(batch(b"two"));
        wire.extend(&batch(b"three")[..3]);
        queue(&link, &wire);
        let one = link.try_recv().expect("the first batch");
        assert_eq!(&one.bytes[..], b"one");
        assert_eq!(received(&link).as_deref(), Some(&b"two"[..]));
        assert!(link.try_recv().is_none(), "part of a batch is not one");
        queue(&link, &batch(b"three")[3..]);
        let three = link.try_recv().expect("the rest of the batch");
        assert_eq!(&three.bytes[..], b"three");
    }

    #[test]
    fn an_empty_batch_is_passed_over() {
        let link = link();
        let mut wire = batch(b"");
        wire.extend(batch(b"x"));
        queue(&link, &wire);
        assert_eq!(received(&link).as_deref(), Some(&b"x"[..]));
    }

    /// The driver cuts a stream into batches in its own buffer, in place, and the shared window
    /// (`wz_session_core::stream_window`) cuts the bytes a reader was handed: two designs for two
    /// kinds of reader, and one rule. This holds them to it: however the stream is cut into
    /// reads, the batches they hand over are the same, the empty one passed over by both. The
    /// population is every pair `0 <= i <= j <= L` of cuts (at most three reads), its size asserted
    /// so an enumerator that produced nothing would not leave the test green.
    #[test]
    fn every_chunking_of_a_wire_frames_the_way_the_shared_window_does() {
        use wz_session_core::stream_window::{FixedCarry, RxWindow};

        let mut wire = Vec::new();
        for payload in [&b"abc"[..], b"", b"z", b"hello"] {
            wire.extend(batch(payload));
        }
        let len = wire.len();
        let mut chunkings = 0usize;
        for i in 0..=len {
            for j in i..=len {
                let cuts = [i, j, len];

                let mut window = RxWindow::<FixedCarry<32>>::new();
                let mut expected: Vec<Vec<u8>> = Vec::new();
                let mut prev = 0usize;
                for &cut in &cuts {
                    window
                        .push(&wire[prev..cut], 2, &mut |f: &[u8]| {
                            expected.push(f.to_vec())
                        })
                        .expect("no oversize prefix");
                    prev = cut;
                }

                let link = link();
                let mut got: Vec<Vec<u8>> = Vec::new();
                let mut prev = 0usize;
                for &cut in &cuts {
                    if cut > prev {
                        queue(&link, &wire[prev..cut]);
                    }
                    prev = cut;
                    while let Some(frame) = received(&link) {
                        got.push(frame);
                    }
                }
                assert_eq!(got, expected, "delivered as [0..{i}, {i}..{j}, {j}..{len}]");
                assert_eq!(got.len(), 3, "the empty batch is passed over by both");
                chunkings += 1;
            }
        }
        assert_eq!(chunkings, (len + 1) * (len + 2) / 2);
    }

    #[test]
    fn the_end_of_the_stream_ends_the_link_after_what_came_before_it() {
        let link = link();
        queue(&link, &batch(b"last"));
        link.socket.ends.set(true);
        assert_eq!(link.lost(), None);
        assert_eq!(received(&link).as_deref(), Some(&b"last"[..]));
        assert_eq!(received(&link), None);
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
        let waits = link.socket.waits.get();
        link.service();
        assert_eq!(
            link.socket.waits.get(),
            waits,
            "a link that is gone does not wait"
        );
        assert_eq!(
            link.send_blocking(b"late", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        );
    }

    #[test]
    fn a_length_the_buffer_cannot_hold_ends_the_link() {
        let link = link();
        queue(&link, &batch(&[7u8; 33]));
        assert_eq!(received(&link), None);
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
    }

    #[test]
    fn a_failed_read_ends_the_link_and_is_kept() {
        let link = link();
        link.socket.fails.set(true);
        assert_eq!(received(&link), None);
        assert_eq!(link.lost(), Some(LostCause::OsError));
        assert_eq!(link.error(), Some(Broken));
    }

    /// A link keeps the failure its socket reported first, whichever reach meets a second, and
    /// reads none before one is written. Turned red by a `FirstError::set` that writes over the
    /// failure it holds.
    #[test]
    fn a_link_keeps_the_first_failure_its_socket_reported() {
        let kept = FirstError::<u8>::none();
        assert_eq!(kept.get(), None);
        kept.set(1);
        kept.set(2);
        assert_eq!(kept.get(), Some(1));
    }

    /// Every cause of a link's loss reads back as itself, and the first end is the one kept.
    /// Turned red by a code `lost_cause` does not read back as `lost_code` wrote it, or by an end
    /// that writes over the cause kept.
    #[test]
    fn every_cause_of_a_loss_reads_back_and_the_first_is_kept() {
        for cause in [
            LostCause::PeerClosed,
            LostCause::Timeout,
            LostCause::OsError,
            LostCause::CertificateExpired,
            LostCause::UnknownPriority,
            LostCause::ReliableGap,
        ] {
            let lost = Lost::standing();
            assert_eq!(lost.get(), None, "CONTROL: a link that stands");
            lost.end(cause);
            let later = if cause == LostCause::OsError {
                LostCause::PeerClosed
            } else {
                LostCause::OsError
            };
            lost.end(later);
            assert_eq!(lost.get(), Some(cause));
        }
    }

    /// The send half is reached by one holder at a time: a service that finds it held by a send
    /// writes nothing of what is owed, and answers that the link owes, so the read never takes a
    /// debt for paid that the send beside it is paying; once the hold goes, the next service
    /// writes it. Turned red by a service that writes what is owed without holding the half
    /// (`StreamDriver::service` past a `TxHalf::try_hold` that found it held), or by `owes`
    /// reading the queue another holder has.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_service_beside_a_held_send_half_writes_nothing_of_what_is_owed() {
        let link = trying();
        assert_eq!(send_lent(&link, b"slow!", Some(3)), LinkSendOutcome::Sent);
        assert!(link.owes(), "CONTROL: the rest is owed");
        link.socket.takes.set(None);
        let written = link.socket.writes.borrow().len();
        {
            let _send = link.tx.hold();
            assert!(link.tx.try_hold().is_none(), "one holder at a time");
            link.service();
            assert_eq!(
                link.socket.writes.borrow().len(),
                written,
                "nothing is written under another's hold"
            );
            assert!(link.owes(), "a held half answers as owing");
        }
        link.service();
        assert!(!link.owes());
        assert_eq!(link.socket.writes.borrow().concat(), batch(b"slow!"));
    }

    #[test]
    fn a_send_is_the_length_and_the_bytes_in_one_write() {
        let link = link();
        assert_eq!(
            link.send_blocking(b"abc", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(link.socket.writes.borrow().as_slice(), &[batch(b"abc")]);
        let past = std::vec![0u8; u16::MAX as usize + 1];
        assert_eq!(
            link.send_blocking(&past, Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert_eq!(link.socket.writes.borrow().len(), 1);
    }

    #[test]
    fn a_lent_slot_leaves_the_length_room_and_goes_out_framed_in_one_write() {
        let link = link();
        let grant = link.tx_slot_acquire(10, Priority::Data).expect("a slot");
        assert_eq!(grant.headroom, STREAM_BATCH_LENGTH_BYTES);
        let (base, capacity) = link.tx_slot_storage(grant.slot);
        assert_eq!(capacity, 32);
        // SAFETY: the slot was granted to this test alone and is 32 bytes long.
        let slot = unsafe { core::slice::from_raw_parts_mut(base, capacity) };
        slot[2..5].copy_from_slice(b"xyz");
        assert_eq!(
            link.tx_slot_send(grant.slot, 2, 3, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Sent
        );
        assert_eq!(link.socket.writes.borrow().as_slice(), &[batch(b"xyz")]);
        let again = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("the slot is back");
        let other = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("a second slot");
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_none(),
            "both out"
        );
        link.tx_slot_abort(again.slot);
        assert_eq!(
            link.tx_slot_send(other.slot, 2, 31, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize),
            "past the slot"
        );
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_some(),
            "and back anyway"
        );
    }

    /// zenoh's framing seals a batch with its length, little-endian, in the room just in front of
    /// it, and touches nothing else; a batch with no room for the length, or past a `u16`, is
    /// refused with its bytes as they were. Turned red by a length written big-endian, or by a
    /// seal that writes past the room it was given.
    #[test]
    fn the_length_framing_seals_a_batch_with_its_length_in_the_room_in_front() {
        let mut slot = [0xAAu8; 8];
        slot[2..5].copy_from_slice(b"xyz");
        assert_eq!(LengthPrefix.seal(&mut slot[..5], 2), Some(0));
        assert_eq!(&slot[..5], &[3, 0, b'x', b'y', b'z']);
        assert_eq!(&slot[5..], &[0xAA; 3], "nothing past the batch is touched");

        let mut short = [0u8, b'a', b'b'];
        assert_eq!(LengthPrefix.seal(&mut short, 1), None);
        assert_eq!(short, [0, b'a', b'b']);
        assert_eq!(
            LengthPrefix.seal(&mut [0u8; 4], 5),
            None,
            "a start past the bytes"
        );

        let longest = STREAM_BATCH_LENGTH_BYTES + u16::MAX as usize;
        let mut bytes = std::vec![0u8; longest];
        assert_eq!(
            LengthPrefix.seal(&mut bytes, STREAM_BATCH_LENGTH_BYTES),
            Some(0)
        );
        assert_eq!(&bytes[..2], &[0xFF, 0xFF]);
        let mut past = std::vec![0u8; longest + 1];
        assert_eq!(
            LengthPrefix.seal(&mut past, STREAM_BATCH_LENGTH_BYTES),
            None
        );
        assert_eq!(&past[..2], &[0, 0]);
    }

    #[test]
    fn the_link_states_its_ends_its_framing_and_its_bounds() {
        let link = link();
        let ends = link.link_endpoints().expect("known from the connection");
        assert_eq!(ends.src.as_str(), "tcp/10.0.0.2:40000");
        assert_eq!(ends.dst.as_str(), "tcp/10.0.0.1:7447");
        assert!(link.batch_length_prefixed());
        assert_eq!(link.link_rx_capacity(), 34);
        assert_eq!(
            link.link_mtu(),
            32,
            "a whole slot: the length is counted in the batch"
        );
    }

    /// A connection between IPv6 ends names them in zenoh's bracketed text, with the scope of a
    /// link-local end.
    #[test]
    fn an_ipv6_connection_names_its_ends_in_brackets() {
        use core::net::{Ipv6Addr, SocketAddrV6};
        let pipe: Pipe = Pipe {
            ends_at: Some((
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    40_000,
                    0,
                    2,
                )),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
            )),
            ..Pipe::default()
        };
        let link = StreamDriver::over(pipe, [0u8; 34], Slots(UnsafeCell::new([0; 64])));
        let ends = link.link_endpoints().expect("known from the connection");
        assert_eq!(ends.src.as_str(), "tcp/[fe80::2%2]:40000");
        assert_eq!(ends.dst.as_str(), "tcp/[::1]:7447");
    }

    #[test]
    fn a_closed_link_shuts_the_stream_and_is_gone() {
        let link = link();
        link.close_blocking();
        assert!(link.socket.shut.get());
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
    }

    /// The stream is the link's room: one that takes bytes within the wait has room, one that
    /// does not has none, asked for exactly the message's wait, and a link that has ended has
    /// room at once, so the send that follows reports the end.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_stream_that_takes_no_bytes_within_the_wait_has_no_room() {
        let link = link();
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free)
        );
        link.socket.full.set(true);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: 1_000
            }
        );
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 5_000_000 }),
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: 5_000_000
            }
        );
        assert_eq!(*link.socket.room_waits.borrow(), [1_000, 1_000, 5_000_000]);
        link.end(LostCause::PeerClosed);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 5_000_000 }),
            RoomAnswer::at_once(LinkRoom::Free)
        );
        assert_eq!(
            link.socket.room_waits.borrow().len(),
            3,
            "an ended link waits for nothing"
        );
    }

    /// The time a question of room reports is the time the stream's wait measured, room or none:
    /// a sender that keeps one deadline across several questions spends what was spent, not the
    /// whole wait nor none of it.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_question_of_room_reports_the_wait_the_stream_measured() {
        let link = link();
        link.socket.room_took_us.set(Some(370));
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer {
                room: LinkRoom::Free,
                waited_us: 370
            },
            "room found after 370 us"
        );
        link.socket.full.set(true);
        link.socket.room_took_us.set(Some(990));
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 }),
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: 990
            },
            "none, after the 990 us the wait measured"
        );
    }

    /// A stream that writes without waiting is asked for room before the first frame only, while it
    /// takes each write whole: the write is the question, as a non-blocking write is. CONTROL: a
    /// stream that cannot write without waiting is asked before every frame.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_stream_that_takes_each_write_whole_is_asked_for_room_once() {
        fn frames<const TRIES: bool>(link: &StreamDriver<Pipe<TRIES>, [u8; 34], Slots>) {
            for _ in 0..3 {
                assert_eq!(
                    link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
                    RoomAnswer::at_once(LinkRoom::Free)
                );
                assert_eq!(
                    link.send_blocking(b"frame", Reliability::Reliable),
                    LinkSendOutcome::Sent
                );
            }
        }

        let control = link();
        frames(&control);
        assert_eq!(
            control.socket.room_waits.borrow().len(),
            3,
            "CONTROL: asked before every frame"
        );

        let link = trying();
        frames(&link);
        assert_eq!(
            link.socket.room_waits.borrow().len(),
            1,
            "asked before the first frame only"
        );
        assert_eq!(
            *link.socket.writes.borrow(),
            [batch(b"frame"), batch(b"frame"), batch(b"frame")]
        );
    }

    /// A stream that takes half a frame and then would block leaves the call at once: the frame is
    /// handed over, its rest is the link's to finish, nothing is written by waiting, and the
    /// question of room says there is none while the rest is owed. A frame handed over meanwhile
    /// waits behind it. The next step that finds the stream room writes the rest, then that frame,
    /// in order; a write taken whole after that makes the question of room unneeded again.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_frame_taken_half_is_finished_by_the_next_step_before_any_new_frame() {
        let link = trying();
        let frame = batch(b"twelve bytes");
        let half = frame.len() / 2;
        link.socket.takes.set(Some(half));
        assert_eq!(
            link.send_blocking(b"twelve bytes", Reliability::Reliable),
            LinkSendOutcome::Sent,
            "handed over: the rest is the link's"
        );
        assert_eq!(*link.socket.writes.borrow(), [frame[..half].to_vec()]);
        assert_eq!(
            link.socket.waited_writes.get(),
            0,
            "nothing waited for the rest"
        );
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: 1_000
            },
            "no room while the rest is owed and the stream takes nothing"
        );
        assert_eq!(
            link.send_blocking(b"next", Reliability::Reliable),
            LinkSendOutcome::Sent,
            "a frame handed over now waits behind the rest"
        );
        assert_eq!(link.socket.writes.borrow().len(), 1, "nothing more written");
        assert!(
            link.owes_write(),
            "the owner's wait is told to wake on room"
        );

        link.socket.takes.set(None);
        link.service();
        assert!(
            !link.owes_write(),
            "and, nothing owed, on input alone again"
        );
        assert_eq!(
            link.socket.writes.borrow().concat(),
            [frame, batch(b"next")].concat(),
            "the rest first, then the frame behind it"
        );
        assert_eq!(link.socket.waited_writes.get(), 0);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free)
        );
        assert_eq!(
            link.send_blocking(b"whole", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free)
        );
        assert_eq!(
            *link.socket.room_waits.borrow(),
            [1_000, 1_000],
            "asked while owing and once after; a write taken whole again: not asked"
        );
    }

    /// A lent frame the stream takes only in part keeps its slot out of the pool until the rest is
    /// written, so the session cannot be lent it again and write over the bytes still owed; once
    /// the stream has taken them the slot is back.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_lent_frame_keeps_its_slot_until_the_stream_has_taken_it_all() {
        let link = trying();
        let grant = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a free slot");
        let (base, _) = link.tx_slot_storage(grant.slot);
        // SAFETY: the slot was just granted to this test, 32 bytes long, and five bytes past its
        // headroom are inside it.
        unsafe { core::ptr::copy_nonoverlapping(b"lent!".as_ptr(), base.add(grant.headroom), 5) };
        link.socket.takes.set(Some(3));
        assert_eq!(
            link.tx_slot_send(
                grant.slot,
                grant.headroom,
                5,
                Reliability::Reliable,
                Priority::DEFAULT
            ),
            LinkSendOutcome::Sent
        );
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_some(),
            "CONTROL: the other slot is free"
        );
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_none(),
            "the owed frame's slot is still held"
        );
        link.socket.takes.set(None);
        link.service();
        assert_eq!(link.socket.writes.borrow().concat(), batch(b"lent!"));
        assert_eq!(link.socket.waited_writes.get(), 0);
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_some(),
            "written, the slot is back"
        );
    }

    /// Links of a pool of `slots` outbound slots of 32 bytes with `places` places, and the tables.
    #[cfg(feature = "session-unicast-accept")]
    fn pooled_tx_links(
        places: usize,
        slots: usize,
    ) -> (
        crate::link_storage::LinkTables,
        std::vec::Vec<StreamDriver<Pipe<true>, [u8; 34], crate::link_storage::LinkTx>>,
    ) {
        use wz_session_core::bounded::{Arena, ARENA_ALIGN};

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let bytes = [(34, 1), (32, slots), (0, places)]
            .iter()
            .map(|&(size, count)| Arena::byte_cells_bytes(size, count).expect("fits"))
            .sum::<usize>();
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every buffer.
        let mut arena = unsafe {
            Arena::over(
                core::ptr::NonNull::from(region).cast::<u8>(),
                blocks * ARENA_ALIGN,
            )
        };
        let rx = arena.lend_byte_cells(34, 1).expect("the receive pool");
        let tx = arena.lend_byte_cells(32, slots).expect("the slot pool");
        let at = arena.lend_byte_cells(0, places).expect("the places");
        let tables = crate::link_storage::LinkTables::pooled(rx, tx, at);
        let links = (0..places)
            .map(|_| {
                let (_, tx) = tables.claim().expect("a place");
                StreamDriver::over(Pipe::<true>::default(), [0u8; 34], tx)
            })
            .collect();
        (tables, links)
    }

    /// Hand `link` a frame of `bytes` in a slot it lends, the stream taking `takes` of it.
    fn send_lent<T: TxStore + 'static>(
        link: &StreamDriver<Pipe<true>, [u8; 34], T>,
        bytes: &[u8],
        takes: Option<usize>,
    ) -> LinkSendOutcome {
        let grant = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a free slot");
        let (base, _) = link.tx_slot_storage(grant.slot);
        // SAFETY: the slot was just granted to this test, 32 bytes long, and the frame past its
        // headroom is inside it.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(grant.headroom), bytes.len())
        };
        link.socket.takes.set(takes);
        link.tx_slot_send(
            grant.slot,
            grant.headroom,
            bytes.len(),
            Reliability::Reliable,
            Priority::DEFAULT,
        )
    }

    /// A link of a pool whose stream takes a frame only in part keeps its slot, as a link of its
    /// own slots does, and writes nothing more until the stream has room: it does not wait. The other
    /// links go on meanwhile through the slots left, each frame written whole, and once the slow
    /// stream takes the rest the slot is back.
    #[cfg(feature = "session-unicast-accept")]
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_slow_stream_keeps_its_slot_and_the_other_links_go_on() {
        let (tables, links) = pooled_tx_links(3, 2);
        assert_eq!(
            send_lent(&links[0], b"slow!", Some(3)),
            LinkSendOutcome::Sent
        );
        assert!(links[0].owes(), "the rest is owed");
        assert_eq!(links[0].socket.waited_writes.get(), 0, "and nothing waited");
        assert_eq!(tables.tx_in_use(), 1);
        for round in 0..3u8 {
            for link in &links[1..] {
                assert_eq!(
                    send_lent(link, &[b'a' + round; 4], None),
                    LinkSendOutcome::Sent
                );
                assert_eq!(tables.tx_in_use(), 1, "the slot is back after each send");
            }
        }
        for link in &links[1..] {
            assert_eq!(link.socket.writes.borrow().len(), 3, "every frame, whole");
            assert_eq!(link.socket.waited_writes.get(), 0);
        }
        assert!(links[0].owes(), "the slow stream still owes");
        links[0].socket.takes.set(None);
        links[0].service();
        assert!(!links[0].owes());
        assert_eq!(links[0].socket.writes.borrow().concat(), batch(b"slow!"));
        assert_eq!(tables.tx_in_use(), 0, "written, its slot is back");
    }

    /// A link of a pool whose every slot another link holds for a frame its stream has not
    /// finished is congested at once, whatever the message may wait, and waits on no stream: the
    /// step that frees the slot is the other link's. Once that link's stream takes the rest, the
    /// link has room and sends.
    #[cfg(feature = "session-unicast-accept")]
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_link_that_finds_every_slot_held_is_congested_at_once_and_waits_for_none() {
        let (tables, links) = pooled_tx_links(2, 1);
        assert_eq!(
            send_lent(&links[0], b"held", Some(2)),
            LinkSendOutcome::Sent
        );
        assert_eq!(tables.tx_in_use(), 1);
        for wait in [
            RoomWait::Drop { wait_us: 1_000 },
            RoomWait::Block { wait_us: 1_000_000 },
        ] {
            assert_eq!(
                links[1].wait_for_room(Priority::DEFAULT, wait),
                RoomAnswer::at_once(LinkRoom::Congested)
            );
        }
        assert!(links[1].socket.room_waits.borrow().is_empty(), "no wait");
        assert!(links[1].tx_slot_acquire(16, Priority::DEFAULT).is_none());
        links[0].socket.takes.set(None);
        links[0].service();
        assert_eq!(tables.tx_in_use(), 0);
        assert_eq!(
            links[1]
                .wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 })
                .room,
            LinkRoom::Free
        );
        assert_eq!(send_lent(&links[1], b"after", None), LinkSendOutcome::Sent);
    }

    /// A link of a pool whose open batch frame would take the last free slot says so
    /// (`tx_slot_spare`), and one with a slot free besides, or with a slot for every link, says
    /// it may keep it.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn a_link_says_whether_the_slot_it_holds_leaves_one_spare() {
        let (tables, links) = pooled_tx_links(3, 2);
        let first = links[0]
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a slot");
        assert!(links[0].tx_slot_spare(), "another is free");
        let second = links[1]
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a slot");
        assert!(!links[1].tx_slot_spare(), "it holds the last");
        assert!(links[2].tx_slot_acquire(16, Priority::DEFAULT).is_none());
        links[0].tx_slot_abort(first.slot);
        links[1].tx_slot_abort(second.slot);
        assert_eq!(tables.tx_in_use(), 0);
        let own = link();
        let _held = own.tx_slot_acquire(16, Priority::DEFAULT).expect("a slot");
        assert!(own.tx_slot_spare(), "slots of its own: always");
    }

    /// A link whose every slot is out, one of them held by a frame the stream took only part of,
    /// writes what it owes when it is asked for a slot and lends the one that frees, with no step
    /// between: one slot serves the frame after a batch the stream has not finished. While the
    /// stream takes nothing, nothing is freed and the ask is refused.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_slot_asked_while_a_frame_is_owed_is_lent_once_the_stream_takes_it() {
        let link = trying();
        let grant = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a free slot");
        let (base, _) = link.tx_slot_storage(grant.slot);
        // SAFETY: the slot was just granted to this test, 32 bytes long, and five bytes past its
        // headroom are inside it.
        unsafe { core::ptr::copy_nonoverlapping(b"owed!".as_ptr(), base.add(grant.headroom), 5) };
        link.socket.takes.set(Some(3));
        assert_eq!(
            link.tx_slot_send(
                grant.slot,
                grant.headroom,
                5,
                Reliability::Reliable,
                Priority::DEFAULT
            ),
            LinkSendOutcome::Sent
        );
        let other = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the other slot is free");
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_none(),
            "the stream takes nothing, so the owed frame keeps its slot"
        );
        link.socket.takes.set(None);
        let freed = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the owed frame is written and its slot lent");
        assert_eq!(freed.slot, grant.slot);
        assert_eq!(link.socket.writes.borrow().concat(), batch(b"owed!"));
        assert_eq!(
            link.socket.waited_writes.get(),
            0,
            "written without waiting"
        );
        link.tx_slot_abort(other.slot);
        link.tx_slot_abort(freed.slot);
    }

    /// A link that has ended refuses a frame of either kind as gone, writes nothing, and gives
    /// back the slot a lent one lay in. Turned red by a send on an ended link that keeps the slot
    /// (the release skipped before the refusal) or that writes.
    #[test]
    fn an_ended_link_refuses_either_kind_of_frame_and_gives_back_its_slot() {
        let link = trying();
        let grant = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a free slot");
        link.end(LostCause::PeerClosed);
        assert_eq!(
            link.tx_slot_send(
                grant.slot,
                grant.headroom,
                5,
                Reliability::Reliable,
                Priority::DEFAULT
            ),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        );
        assert_eq!(
            link.send_blocking(b"late", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        );
        assert!(link.socket.writes.borrow().is_empty(), "nothing written");
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the refused frame's slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// A stream that fails a write while the link owes it two frames ends the link with the
    /// failure kept, and every slot those frames held goes back. Turned red by a failed write that
    /// leaves the owed frames' slots held (`drop_owed` not reached from `fail`).
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_failed_write_ends_the_link_and_gives_back_every_slot_it_owed() {
        let link = trying();
        assert_eq!(send_lent(&link, b"first", Some(3)), LinkSendOutcome::Sent);
        assert_eq!(send_lent(&link, b"other", Some(0)), LinkSendOutcome::Sent);
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_none(),
            "CONTROL: both slots are held for what is owed"
        );
        link.socket.write_fails.set(true);
        link.service();
        assert_eq!(link.lost(), Some(LostCause::OsError));
        assert_eq!(link.error(), Some(Broken));
        assert!(!link.owes(), "nothing is owed by a link that has ended");
        assert_eq!(
            link.socket.writes.borrow().concat(),
            batch(b"first")[..3].to_vec(),
            "only what the stream took before it failed"
        );
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// A link closed while it owes the stream tries what it owes once more without waiting,
    /// writes as much as the stream takes then, in order, and gives back the slots of what the
    /// stream did not take. Turned red by a close that waits for the stream, writes the second
    /// frame ahead of the rest of the first, or keeps a slot held.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_link_closed_while_it_owes_writes_what_the_stream_takes_and_gives_back_the_rest() {
        let link = trying();
        assert_eq!(send_lent(&link, b"first", Some(3)), LinkSendOutcome::Sent);
        assert_eq!(send_lent(&link, b"other", Some(0)), LinkSendOutcome::Sent);
        let rest = batch(b"first").len() - 3;
        link.socket.takes.set(Some(rest));
        link.close_blocking();
        assert_eq!(link.socket.writes.borrow().concat(), batch(b"first"));
        assert_eq!(link.socket.waited_writes.get(), 0, "nothing waited");
        assert!(link.socket.shut.get());
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
        assert!(!link.owes());
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// A frame the session hands over as bytes is copied into a slot the link lends and sent from
    /// there: while every slot is out (one with the session, one held by a frame the stream took in
    /// part, and the stream takes none of what is owed) it is refused as a frame the link lends no
    /// slot for, nothing of it written, and the link goes on. Once the stream takes what is owed,
    /// the slot that frees is lent to the next frame of bytes, written behind the rest. Turned red
    /// by a frame of bytes kept anywhere but a slot, written ahead of the rest owed, or refused in a
    /// way that ends the link.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_frame_handed_as_bytes_is_sent_from_a_slot_or_refused_when_none_is_free() {
        let link = trying();
        let held = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the session holds one slot");
        assert_eq!(send_lent(&link, b"first", Some(3)), LinkSendOutcome::Sent);
        assert_eq!(
            link.send_blocking(b"next", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot),
            "nowhere to copy it"
        );
        assert_eq!(link.lost(), None);
        assert_eq!(
            link.socket.writes.borrow().concat(),
            batch(b"first")[..3].to_vec()
        );
        link.socket.takes.set(None);
        assert_eq!(
            link.send_blocking(b"next", Reliability::Reliable),
            LinkSendOutcome::Sent,
            "the rest owed is written first, and its slot lent"
        );
        assert!(!link.owes());
        assert_eq!(
            link.socket.writes.borrow().concat(),
            [batch(b"first"), batch(b"next")].concat(),
            "the rest first, then the frame of bytes"
        );
        link.tx_slot_abort(held.slot);
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the copy's slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// [`OWED`] slots of 32 bytes: as many as a link's book lends.
    #[cfg(feature = "tx-stream-owed")]
    struct EverySlot(UnsafeCell<[u8; OWED * 32]>);

    #[cfg(feature = "tx-stream-owed")]
    impl TxStore for EverySlot {
        fn slots(&self) -> usize {
            OWED
        }

        fn slot_len(&self) -> usize {
            32
        }

        fn slot_base(&self, slot: usize) -> *mut u8 {
            self.0.get().cast::<u8>().wrapping_add(slot * 32)
        }
    }

    /// A link owes at most [`OWED`] frames, one in each slot it lends: with every slot owed, a
    /// frame handed over as bytes is refused as one it lends no slot for, the link goes on, and it
    /// writes the frames it owes in the order they came. Turned red by a ring shorter than the
    /// slots a link lends, by a refusal that ends the link, or by owed frames written out of order.
    #[cfg(feature = "tx-stream-owed")]
    #[test]
    fn a_link_whose_every_slot_is_owed_refuses_the_next_frame_and_goes_on() {
        let link = StreamDriver::over(
            Pipe::<true>::default(),
            [0u8; 34],
            EverySlot(UnsafeCell::new([0; OWED * 32])),
        );
        link.socket.takes.set(Some(3));
        assert_eq!(
            link.send_blocking(b"first", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let behind: Vec<Vec<u8>> = (b'a'..).take(OWED - 1).map(|c| std::vec![c; 2]).collect();
        for frame in &behind {
            assert_eq!(
                link.send_blocking(frame, Reliability::Reliable),
                LinkSendOutcome::Sent
            );
        }
        assert_eq!(
            link.send_blocking(b"one too many", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        assert_eq!(link.lost(), None);
        link.socket.takes.set(None);
        link.service();
        assert!(!link.owes());
        let mut expected = batch(b"first");
        for frame in &behind {
            expected.extend_from_slice(&batch(frame));
        }
        assert_eq!(link.socket.writes.borrow().concat(), expected);
    }

    /// Without `tx-stream-owed` a send writes its frame whole before it returns: a stream that
    /// takes part of it and then nothing is waited on until it takes the rest, nothing is owed
    /// once the call returns, and the frame's slot is back. Turned red by a send that leaves the
    /// rest owed (the owed form's `send`), or keeps the slot past the write.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_send_without_owed_frames_waits_until_the_stream_took_the_whole_frame() {
        let link = trying();
        link.socket.room_after_wait.set(Some(64));
        assert_eq!(send_lent(&link, b"slow!", Some(3)), LinkSendOutcome::Sent);
        let frame = batch(b"slow!");
        assert_eq!(
            *link.socket.writes.borrow(),
            [frame[..3].to_vec(), frame[3..].to_vec()],
            "the part the stream took, then the rest once it had room"
        );
        assert_eq!(
            *link.socket.room_waits.borrow(),
            [SERVICE_WAIT_US],
            "one wait, when the stream took nothing"
        );
        assert!(!link.owes(), "nothing is owed once the send returns");
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the frame's slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// Without `tx-stream-owed` the stream is not asked for room: a link has room at once however
    /// full its stream is, also while every slot is with the session, whose open batches take the
    /// message or are sent first and the slot lent again, and has room once it has ended, so the
    /// send that follows reports the end. Turned red by a question of room that waits for the
    /// stream (the owed form's `wait_for_room`), or one that counts the slots the session holds
    /// (the book read in place of `claimable`), which answers congested below.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_link_without_owed_frames_has_room_whatever_slots_its_session_holds() {
        let link = trying();
        link.socket.full.set(true);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free)
        );
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("a free slot");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the other");
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 5_000_000 }),
            RoomAnswer::at_once(LinkRoom::Free),
            "every slot is with the session, which settles its own"
        );
        link.end(LostCause::PeerClosed);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free),
            "an ended link has room, for its send to report the end"
        );
        assert!(
            link.socket.room_waits.borrow().is_empty(),
            "the stream was never asked"
        );
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// Without `tx-stream-owed` a droppable message does not wait for a send that holds the send
    /// half while it writes its frame whole: it is congested at once, the stream not asked, and
    /// has room once that send lets go. Turned red by a question that answers without trying the
    /// half (the store's `claimable` alone answers room here); one that waits for the half
    /// whatever its message (`hold` in place of `try_hold`) never returns here.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_droppable_question_without_owed_frames_does_not_wait_for_a_send_under_way() {
        let link = trying();
        let under_way = link.tx.hold();
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Congested),
            "a send holds the half"
        );
        drop(under_way);
        assert_eq!(
            link.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free),
            "the send let go"
        );
        assert!(
            link.socket.room_waits.borrow().is_empty(),
            "the stream was never asked"
        );
    }

    /// Without `tx-stream-owed` a link lent one slot, as the pico ABI lends its links one
    /// (`LINK_TX_SLOTS`), has room while its session's open batch holds that slot: the message
    /// joins the batch, or sends it and takes the slot again, as zenoh-pico appends to the batch
    /// its one write buffer holds or flushes it first. Turned red by a question that counts the
    /// slot the session holds (the book read in place of `claimable`), which answers congested
    /// and has the session drop a blocking message and settle its expiry.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_link_whose_one_slot_holds_its_sessions_open_batch_has_room_without_owed_frames() {
        struct OneSlot(UnsafeCell<[u8; 32]>);

        impl TxStore for OneSlot {
            fn slots(&self) -> usize {
                1
            }

            fn slot_len(&self) -> usize {
                32
            }

            fn slot_base(&self, _slot: usize) -> *mut u8 {
                self.0.get().cast::<u8>()
            }
        }

        let link: StreamDriver<Pipe<true>, [u8; 34], OneSlot> = StreamDriver::over(
            Pipe::default(),
            [0u8; 34],
            OneSlot(UnsafeCell::new([0; 32])),
        );
        let open = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the one slot, for the session's open batch");
        assert!(
            link.tx_slot_acquire(16, Priority::DEFAULT).is_none(),
            "CONTROL: the open batch holds the link's one slot"
        );
        for wait in [
            RoomWait::Block { wait_us: 5_000_000 },
            RoomWait::Drop { wait_us: 1_000 },
        ] {
            assert_eq!(
                link.wait_for_room(Priority::DEFAULT, wait),
                RoomAnswer::at_once(LinkRoom::Free),
                "{wait:?}"
            );
        }
        assert!(
            link.socket.room_waits.borrow().is_empty(),
            "the stream was never asked"
        );
        link.tx_slot_abort(open.slot);
    }

    /// Without `tx-stream-owed` a link of a pool whose one slot another link holds is congested at
    /// once, whatever the message may wait, and has room once the slot is back: the pool is the
    /// session's other links', which no step of this one frees. Turned red by a question that does
    /// not ask its store (`claimable`) under the hold, which answers room below.
    #[cfg(feature = "session-unicast-accept")]
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_link_of_a_pool_with_no_slot_left_is_congested_at_once_without_owed_frames() {
        let (tables, links) = pooled_tx_links(2, 1);
        let held = links[0]
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the pool's one slot");
        assert_eq!(tables.tx_in_use(), 1);
        for wait in [
            RoomWait::Drop { wait_us: 1_000 },
            RoomWait::Block { wait_us: 1_000_000 },
        ] {
            assert_eq!(
                links[1].wait_for_room(Priority::DEFAULT, wait),
                RoomAnswer::at_once(LinkRoom::Congested),
                "{wait:?}"
            );
        }
        links[0].tx_slot_abort(held.slot);
        assert_eq!(
            links[1].wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 }),
            RoomAnswer::at_once(LinkRoom::Free),
            "the slot is back in the pool"
        );
        assert!(
            links[1].socket.room_waits.borrow().is_empty(),
            "the stream was never asked"
        );
    }

    /// Without `tx-stream-owed` a write the stream fails ends the link with the failure kept, and
    /// the frame's slot goes back with it. Turned red by a failed write that keeps the slot (the
    /// release skipped on the error), or that is not reported.
    #[cfg(not(feature = "tx-stream-owed"))]
    #[test]
    fn a_failed_write_without_owed_frames_ends_the_link_and_gives_back_its_slot() {
        let link = trying();
        link.socket.write_fails.set(true);
        assert_eq!(
            send_lent(&link, b"lost", None),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        );
        assert_eq!(link.lost(), Some(LostCause::OsError));
        assert_eq!(link.error(), Some(Broken));
        assert!(link.socket.writes.borrow().is_empty(), "nothing written");
        let one = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("the frame's slot is back");
        let two = link
            .tx_slot_acquire(16, Priority::DEFAULT)
            .expect("and the other");
        link.tx_slot_abort(one.slot);
        link.tx_slot_abort(two.slot);
    }

    /// A session of this engine over the stream link, and what a droppable and a blocking message
    /// do when the stream takes no more bytes: the same decisions the tokio engine's session makes
    /// over its writer's queue. Built where the session sends a Push: `switchboard` is the feature
    /// of this crate that brings the session core's Push codec into its build.
    #[cfg(all(
        feature = "switchboard",
        feature = "alloc",
        not(feature = "session-slot")
    ))]
    mod session_room {
        extern crate std;

        use std::vec::Vec;
        use wz_session_core::qos::CongestionControl;
        use wz_session_core::qos::Priority;
        use wz_session_core::sample::QosLevel;
        use wz_session_core::session_init_params::{SessionInitParams, TxQueueConf};
        use wz_session_core::signing_key::SigningKey;

        use super::Pipe;
        use crate::link_storage::HeapTx;
        use crate::session_runtime::new_session_actions;
        use crate::stream_link::{StreamDriver, STREAM_RX_CAPACITY};
        use crate::time::{ClockSource, CoopTime};
        use crate::CoopRuntime;

        /// The session's waits, each of its own so an ask names the one it spent.
        const DROP_WAIT_US: u64 = 1_234;
        const CLOSE_WAIT_US: u64 = 4_242;

        #[derive(Clone, Copy)]
        struct Stopped;

        impl ClockSource for Stopped {
            fn now_us(&self) -> u64 {
                1_000_000
            }
        }

        type Heap = StreamDriver<Pipe, Vec<u8>, HeapTx>;

        /// A session whose frames each leave at once (no batch window), with the waits above.
        fn params() -> SessionInitParams {
            SessionInitParams {
                whatami: wz_session_core::WhatAmI::Peer,
                zid: [0x0A, 0x0B, 0x0C, 0x0D].into(),
                seq_num_res: wz_session_core::policy::SnResolution::Bits32,
                req_id_res: 2,
                batch_size: 1024,
                lease_ms: 10_000,
                keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
                initial_sn: 0,
                cookie: std::vec![0u8; 16],
                tx_queue: TxQueueConf {
                    wait_before_drop_us: DROP_WAIT_US,
                    wait_before_close_us: CLOSE_WAIT_US,
                    batching: false,
                    ..TxQueueConf::of_snapshot(
                        &wz_session_core::policy::SessionPolicy::defaults(),
                        &wz_session_core::limits::SessionLimits::BUILD,
                    )
                },
                link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
                policy: wz_session_core::policy::SessionPolicy::defaults(),
                limits: wz_session_core::limits::SessionLimits::BUILD,
                cookie_signing_key: SigningKey::new(std::vec![7u8; 32])
                    .expect(">=32-byte key")
                    .into(),
                region: None,
            }
        }

        fn link() -> crate::link_cells::CellRc<Heap> {
            crate::link_cells::CellRc::try_boxed(StreamDriver::with_buffers(
                Pipe::<false>::default(),
                STREAM_RX_CAPACITY,
                HeapTx::new(4, 2048),
            ))
            .expect("the heap has room")
        }

        /// A session over `sink`, established as one that completed its handshake stands
        /// (`SessionLinkActions::enter_established`): a data send before establishment is
        /// refused before it asks the stream for room, and each case here is about that ask.
        fn established(
            sink: crate::link_cells::CellRc<dyn wz_session_core::link::BoxedLinkDriver>,
            runtime: &CoopRuntime<Stopped>,
        ) -> crate::session_runtime::SessionHandle<Stopped> {
            let actions = new_session_actions(sink, params(), CoopTime::new(runtime))
                .expect("the heap has room");
            actions.enter_established();
            actions
        }

        /// A droppable message on a stream that takes no more bytes waits its
        /// `wait_before_drop` for them, is dropped, closes nothing and reaches nothing; once the
        /// stream takes bytes again the next message is written.
        #[cfg(feature = "tx-stream-owed")]
        #[test]
        fn a_droppable_message_on_a_full_stream_is_dropped_within_its_own_wait() {
            let runtime = CoopRuntime::try_new(Stopped).expect("the heap has room");
            let link = link();
            let sink = link.clone().into_sink();
            let actions = established(sink, &runtime);
            link.socket.full.set(true);
            actions
                .send_push_literal_qos("home/drop", b"D", true, Priority::DEFAULT)
                .expect("a congestion drop is not the caller's error");
            assert_eq!(
                *link.socket.room_waits.borrow(),
                [DROP_WAIT_US],
                "the message waited `wait_before_drop` for the stream"
            );
            assert!(
                link.socket.writes.borrow().is_empty(),
                "nothing reached the stream"
            );
            assert!(
                !actions.take_congestion_close(),
                "dropping a droppable message closes nothing"
            );
            link.socket.full.set(false);
            actions
                .send_push_literal_qos("home/next", b"N", true, Priority::DEFAULT)
                .expect("a stream that takes bytes is written");
            assert_eq!(link.socket.writes.borrow().len(), 1);
        }

        /// A blocking message on a stream that takes no more bytes waits its `wait_before_close`
        /// for them and then has its session closed, as zenoh closes a transport a blocking
        /// message found no room on; nothing reached the stream.
        ///
        /// The session reads a message's congestion control off the message's own QoS, as
        /// upstream does, so the Push here carries `Block` in its QoS extension. A session built
        /// without `pubsub-qos` writes no QoS on the Pushes it publishes, every one of which is
        /// then droppable, but it still honours the QoS of a Push that carries one; asking for
        /// `Block` through the publish metadata would hold this test to that feature.
        #[cfg(feature = "tx-stream-owed")]
        #[test]
        fn a_blocking_message_on_a_full_stream_closes_the_session_after_its_wait() {
            let runtime = CoopRuntime::try_new(Stopped).expect("the heap has room");
            let link = link();
            let sink = link.clone().into_sink();
            let actions = established(sink, &runtime);
            link.socket.full.set(true);
            let mut push = wz_session_core::push_build::build_push_literal("home/block", b"B")
                .expect("a literal Put encodes");
            wz_session_core::declare_ext_qos::set_push_qos(
                &mut push,
                QosLevel::DEFAULT.with_congestion(CongestionControl::Block),
            )
            .expect("a message's extension chain takes its QoS");
            let _ = actions.send_network_message_qos(
                wz_session_core::network_message::NetworkMessage::Push(alloc::boxed::Box::new(
                    push,
                )),
                true,
                false,
                Priority::DEFAULT,
            );
            assert_eq!(
                *link.socket.room_waits.borrow(),
                [CLOSE_WAIT_US],
                "the message waited `wait_before_close` for the stream"
            );
            assert!(
                link.socket.writes.borrow().is_empty(),
                "nothing reached the stream"
            );
            assert!(
                actions.take_congestion_close(),
                "the session's close is staged for its loop"
            );
        }

        /// Without `tx-stream-owed` a droppable message is not dropped for want of room on its
        /// stream: the stream is not asked for room, and the message is written by a send that
        /// waits for the stream, as zenoh-pico's dropping send writes once it holds its transmit
        /// lock. Nothing closes. Turned red by a session whose link asks the stream for room (the
        /// owed form's question), or that drops the message.
        #[cfg(not(feature = "tx-stream-owed"))]
        #[test]
        fn a_droppable_message_on_a_full_stream_is_written_by_a_send_that_waits() {
            let runtime = CoopRuntime::try_new(Stopped).expect("the heap has room");
            let link = link();
            let sink = link.clone().into_sink();
            let actions = established(sink, &runtime);
            link.socket.full.set(true);
            actions
                .send_push_literal_qos("home/drop", b"D", true, Priority::DEFAULT)
                .expect("the message is sent");
            assert!(
                link.socket.room_waits.borrow().is_empty(),
                "the stream was not asked for room"
            );
            assert_eq!(
                link.socket.writes.borrow().len(),
                1,
                "the message reached the stream"
            );
            assert!(!actions.take_congestion_close(), "nothing closes");
        }

        /// Without `tx-stream-owed` a blocking message waits for its stream in the send and never
        /// finds the link without room, so its session is not closed for congestion. Turned red by
        /// a link that answers a question of room from the stream (the owed form's), which closes
        /// the session after the message's wait.
        #[cfg(not(feature = "tx-stream-owed"))]
        #[test]
        fn a_blocking_message_on_a_full_stream_is_written_and_closes_nothing() {
            let runtime = CoopRuntime::try_new(Stopped).expect("the heap has room");
            let link = link();
            let sink = link.clone().into_sink();
            let actions = established(sink, &runtime);
            link.socket.full.set(true);
            let mut push = wz_session_core::push_build::build_push_literal("home/block", b"B")
                .expect("a literal Put encodes");
            wz_session_core::declare_ext_qos::set_push_qos(
                &mut push,
                QosLevel::DEFAULT.with_congestion(CongestionControl::Block),
            )
            .expect("a message's extension chain takes its QoS");
            actions
                .send_network_message_qos(
                    wz_session_core::network_message::NetworkMessage::Push(alloc::boxed::Box::new(
                        push,
                    )),
                    true,
                    false,
                    Priority::DEFAULT,
                )
                .expect("the message is sent");
            assert!(
                link.socket.room_waits.borrow().is_empty(),
                "the stream was not asked for room"
            );
            assert_eq!(
                link.socket.writes.borrow().len(),
                1,
                "the message reached the stream"
            );
            assert!(!actions.take_congestion_close(), "nothing closes");
        }

        /// Two conduits alternate reliable messages in one window over a stream link that holds
        /// the slots its session needs (`HeapTx::for_link`): every message reaches the stream
        /// once, each conduit's in the order it was sent, as before the link sent its bytes
        /// through its slots. Turned red by a link that holds fewer slots than its session needs
        /// (`HeapTx::for_link` without its `max`), whose frames are refused for want of one.
        #[cfg(all(feature = "transport-qos", feature = "transport-batching"))]
        #[test]
        fn two_conduits_alternating_on_a_stream_lose_no_message() {
            use wz_session_core::link::STREAM_BATCH_LENGTH_BYTES;
            let runtime = CoopRuntime::try_new(Stopped).expect("the heap has room");
            let link = crate::link_cells::CellRc::try_boxed(StreamDriver::with_buffers(
                Pipe::<false>::default(),
                STREAM_RX_CAPACITY,
                HeapTx::for_link(0, 0, 1024 + STREAM_BATCH_LENGTH_BYTES),
            ))
            .expect("the heap has room");
            let sink = link.clone().into_sink();
            let actions = new_session_actions(sink, params(), CoopTime::new(&runtime))
                .expect("the heap has room");
            assert!(
                actions.set_qos_offer(true),
                "the session carries a conduit for each priority"
            );
            // Established after its offer is set, as a handshake settles the offer first: a data
            // send before establishment is refused.
            actions.enter_established();
            let payloads: Vec<Vec<u8>> = (0..6u8).map(|n| std::vec![0xE0 | n; 4]).collect();
            actions.batch_start().expect("a window opens");
            for (n, payload) in payloads.iter().enumerate() {
                let priority = if n % 2 == 0 {
                    Priority::Data
                } else {
                    Priority::DataHigh
                };
                actions
                    .send_push_literal_qos("home/two", payload, true, priority)
                    .expect("a push");
            }
            actions.batch_stop().expect("the window closes");
            let wire = link.socket.writes.borrow().concat();
            let at = |payload: &[u8]| {
                wire.windows(payload.len())
                    .position(|bytes| bytes == payload)
            };
            for payload in &payloads {
                assert_eq!(
                    wire.windows(payload.len())
                        .filter(|bytes| *bytes == payload.as_slice())
                        .count(),
                    1,
                    "{payload:?} reaches the stream once"
                );
            }
            for lane in 0..2 {
                let order: Vec<usize> = payloads
                    .iter()
                    .skip(lane)
                    .step_by(2)
                    .filter_map(|payload| at(payload.as_slice()))
                    .collect();
                assert_eq!(order.len(), 3, "conduit {lane} sent all three");
                assert!(
                    order.windows(2).all(|pair| pair[0] < pair[1]),
                    "conduit {lane} leaves in the order it was sent: {order:?}"
                );
            }
        }
    }
}
