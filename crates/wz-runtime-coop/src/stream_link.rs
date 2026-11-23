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
use core::net::SocketAddr;

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
use alloc::sync::Arc;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkRoom, LinkSendOutcome, LostCause,
    RoomAnswer, RoomWait, TxSlot, TxSlotGrant, DEFAULT_LINK_MTU, STREAM_BATCH_LENGTH_BYTES,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::{RxStore, TxLender, TxStore};
use crate::session_drive::{LinkOpenError, LinkProto, SessionDatagramLink};
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
use crate::session_drive::{LinkRead, OwnerRead, ReadWaited, RxLease};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::{LinkReadiness, LinkWritability};
use crate::udp_link::{link_endpoints, SERVICE_WAIT_MS};

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

    /// The protocol the stream is, which the link's two ends are named by: a plain connection
    /// is `tcp/`, a secure channel over one `tls/`.
    const PROTO: LinkProto = LinkProto::Tcp;

    /// The link a stack holds over this stream: [`StreamDriver`] over it, for every stream there
    /// is one of. [`NoStream`] names itself, a link there is none of, so the case a stack keeps
    /// for a protocol it does not carry holds nothing and no code serves it.
    type Link<B: RxStore + 'static, X: TxStore + 'static>: StreamLink<Self, B, X>
    where
        Self: 'static;

    /// The address and port this end of the connection is bound to.
    fn local(&self) -> SocketAddr;

    /// The address and port of the other end.
    fn peer(&self) -> SocketAddr;

    /// Write every byte of `parts`, in order, as one write where the stack allows (a length and
    /// the batch behind it leave together), blocking until the stack has taken them all.
    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), Self::Error>;

    /// Block until bytes are queued or `timeout_ms` has passed, and return at once when some
    /// already are. A failed wait is the same as a quiet socket here: the read that follows
    /// reports the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Wait up to `timeout_us` microseconds for the stack to take more bytes: `true` once it
    /// will (or the stream has failed, which the write that follows reports), `false` when it
    /// still would not when the time is up. This is the link's room: zenoh's queue that has no
    /// batch for a message within its deadline, here a stream whose peer has not read what it
    /// was sent.
    ///
    /// A stream that cannot tell answers `true` at once, and a send to it waits in the write.
    fn wait_writable(&self, timeout_us: u64) -> bool {
        let _ = timeout_us;
        true
    }

    /// [`Self::wait_writable`], with how long the wait took in microseconds: what a question of
    /// the link's room reports it spent, so a sender that keeps one deadline across several
    /// questions keeps the right one. A stream with a clock overrides it; the provided form has
    /// none, and counts room found as found at once and none as the whole wait.
    fn wait_writable_timed(&self, timeout_us: u64) -> (bool, u64) {
        let room = self.wait_writable(timeout_us);
        (room, if room { 0 } else { timeout_us })
    }

    /// Write what the stack takes of `parts` now, in order, without waiting: `Some(Ok(n))` for the
    /// `n` bytes it took (`0` when it would take none, and fewer than all when it took some), the
    /// failure, or `None` from a stream that cannot write without waiting (the default).
    ///
    /// A stream that can is not asked for room before every frame ([`Self::wait_writable`]): the
    /// write is tried first, as a non-blocking write is, and the stream is asked only after a write
    /// it did not take whole, until one goes through whole again. What a write leaves is the
    /// link's to write, before anything after it, when the stream next has room: no call waits
    /// for it.
    fn send_parts_now(&self, parts: &[&[u8]]) -> Option<Result<usize, Self::Error>> {
        let _ = parts;
        None
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

    /// A wait for this stream that a thread other than the link's can make
    /// ([`SessionDatagramLink::readiness`]); `None` when the platform gives none (a secure
    /// channel holds bytes of its own the socket's wait would not see), and then a link over the
    /// stream waits in its own loop whatever it was asked.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        None
    }

    /// [`Self::wait_writable`] made by a thread other than the link's
    /// ([`SessionDatagramLink::writability`]), on a handle of its own that outlives the stream
    /// safely; `None` when the platform gives none, and then a sender that finds the session held
    /// waits for it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        None
    }

    /// A read of this stream that a thread other than the link's makes, waiting in the read
    /// itself ([`SessionDatagramLink::lend_rx`]), on a handle of its own that outlives the stream
    /// safely, as [`Self::readiness`]'s does. `None` when the platform gives none (a stream whose
    /// write must not wait keeps a read that cannot either), and then the owner waits on the
    /// stream's readiness and the link reads after.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn reader(&self) -> Option<alloc::boxed::Box<dyn LinkRead>> {
        None
    }

    /// The failure a read of [`Self::reader`]'s answered with the platform's `code`, as this
    /// stream reports one; `None` from a stream that names none, and the link then ends with no
    /// failure kept.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn read_failure(code: i32) -> Option<Self::Error> {
        let _ = code;
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

    /// A wait for a connection that a thread other than the one that accepts can make
    /// ([`StreamSocket::readiness`] is the stream's): ready when a connection is queued.
    /// `None` when the platform gives none, and then the owner looks for a connection at a pace
    /// of its own.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
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

    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        (**self).readiness()
    }
}

/// What a stack makes of a connected stream and holds as one of its links
/// ([`StreamSocket::Link`]).
pub trait StreamLink<S, B, X>: BoxedLinkDriver + SessionDatagramLink + Sized {
    /// The link over the connected `socket`, receiving into `rx` and building its frames in `tx`.
    fn over(socket: S, rx: B, tx: X) -> Self;

    /// The same link, waited on by its owner ([`StreamDriver::waited_by_owner`]).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn waited_by_owner(self) -> Self;
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

    fn local(&self) -> SocketAddr {
        match *self {}
    }

    fn peer(&self) -> SocketAddr {
        match *self {}
    }

    fn send_parts(&self, _parts: &[&[u8]]) -> Result<(), Self::Error> {
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
    fn waited_by_owner(self) -> Self {
        self
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

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
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
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        match *self {}
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        match *self {}
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn lend_rx(&self) -> Option<RxLease> {
        match *self {}
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn land_rx(&self, _lease: RxLease) {
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
enum Front {
    /// Not yet a whole batch: its length, or some of the batch, is still to come.
    Partial,
    /// A whole batch of this many bytes behind its length.
    Batch(usize),
    /// A length whose batch, behind it, does not fit a buffer of this capacity.
    TooLong,
}

/// The most frames a stream link owes its stream at once: one for each slot its book can lend.
const OWED: usize = u8::BITS as usize;

/// What a stream link owes its stream: the rest of a frame the stream took only in part, or a
/// frame handed over behind one ([`StreamDriver::write_owed`]).
enum Owed {
    /// Bytes `from .. end` of a slot of the link's, held out of its pool until they are written.
    Slot {
        slot: TxSlot,
        from: usize,
        end: usize,
    },
    /// A frame the session handed over as bytes, on a link with no slot free to keep it in:
    /// written from `from` on.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    Bytes { bytes: Vec<u8>, from: usize },
}

impl Owed {
    /// The slot the link holds for this, given back once it is written.
    fn held_slot(&self) -> Option<TxSlot> {
        match self {
            Self::Slot { slot, .. } => Some(*slot),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Self::Bytes { .. } => None,
        }
    }

    /// `taken` more bytes of it were written.
    fn advance(&mut self, taken: usize) {
        match self {
            Self::Slot { from, .. } => *from += taken,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            Self::Bytes { from, .. } => *from += taken,
        }
    }
}

/// The frames a stream link owes, oldest first, in a ring of [`OWED`] places.
struct OwedQueue {
    places: [Option<Owed>; OWED],
    head: usize,
    len: usize,
}

impl OwedQueue {
    const fn new() -> Self {
        Self {
            places: [const { None }; OWED],
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
        self.places[(self.head + self.len) % OWED] = Some(owed);
        self.len += 1;
        Ok(())
    }

    /// The oldest, still owed.
    fn front_mut(&mut self) -> Option<&mut Owed> {
        if self.len == 0 {
            return None;
        }
        self.places[self.head].as_mut()
    }

    /// Take the oldest out.
    fn pop(&mut self) -> Option<Owed> {
        if self.len == 0 {
            return None;
        }
        let owed = self.places[self.head].take();
        self.head = (self.head + 1) % OWED;
        self.len -= 1;
        owed
    }
}

/// Copy what `parts` hold after their first `skip` bytes into `out`, which is that long.
fn copy_rest(parts: &[&[u8]], skip: usize, out: &mut [u8]) {
    let mut skip = skip;
    let mut at = 0;
    for &part in parts {
        if skip >= part.len() {
            skip -= part.len();
            continue;
        }
        let rest = &part[skip..];
        skip = 0;
        out[at..at + rest.len()].copy_from_slice(rest);
        at += rest.len();
    }
}

/// What a link with no slot free keeps of `parts` after their first `skip` bytes (`len` of
/// them): a copy on the heap.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
fn owed_bytes(parts: &[&[u8]], skip: usize, len: usize) -> Option<Owed> {
    let mut bytes = vec![0u8; len];
    copy_rest(parts, skip, &mut bytes);
    Some(Owed::Bytes { bytes, from: 0 })
}

/// A build with no heap keeps what it owes in its slots alone.
#[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
fn owed_bytes(_parts: &[&[u8]], _skip: usize, _len: usize) -> Option<Owed> {
    None
}

/// Read the front of `held`, the bytes a buffer of `capacity` bytes holds.
fn front(held: &[u8], capacity: usize) -> Front {
    let Some(prefix) = held.get(..STREAM_BATCH_LENGTH_BYTES) else {
        return Front::Partial;
    };
    let len = u16::from_le_bytes([prefix[0], prefix[1]]) as usize;
    if STREAM_BATCH_LENGTH_BYTES + len > capacity {
        Front::TooLong
    } else if held.len() >= STREAM_BATCH_LENGTH_BYTES + len {
        Front::Batch(len)
    } else {
        Front::Partial
    }
}

/// The session's link over one connected stream socket `S`, with its receive buffer in `B` and
/// its outbound frames built in `T`: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the
/// image's byte tables on the fixed one ([`FixedStreamDriver`]).
///
/// The peer is the other end of the connection, so the link has no binding to make: what arrives
/// is the peer's. The receive buffer bounds the batch the link takes, and so the batch the session
/// advertises ([`BoxedLinkDriver::link_rx_capacity`]).
pub struct StreamDriver<S: StreamSocket, B: RxStore, T: TxStore> {
    socket: S,
    /// The link's two ends, `tcp/<ip>:<port>` each, known from the connection.
    endpoints: LinkEndpoints,
    rx_buf: RefCell<B>,
    /// The length of `rx_buf`: a batch's length and the batch behind it.
    rx_len: usize,
    /// How many bytes at the front of `rx_buf` were received.
    held: Cell<usize>,
    /// How many of those bytes the session was handed already: the batch the last receive lent,
    /// which lies where it is until the next receive, and the empty batches before it. The next
    /// receive starts behind them, and moves what follows them to the front only when it must
    /// read the stream for the rest of a batch.
    spent: Cell<usize>,
    /// Whether a whole batch lies behind the spent bytes, as the last receive left the buffer: what
    /// the next receive hands over without a read. Kept apart from the buffer so that asking it
    /// does not touch the bytes a lent batch may still be read from.
    ready: Cell<bool>,
    /// The bytes the receive moved within its buffer, which the tests count.
    #[cfg(test)]
    moved: Cell<usize>,
    /// Whether the session asked, while a batch is lent, to keep it
    /// ([`SessionDatagramLink::keep`]): it then stays at the front, lent again by the next receive.
    keeping: Cell<bool>,
    /// The memory the session encodes its frames into, and which of it is out.
    tx: TxLender<T>,
    /// Why the link is gone, once it is.
    lost: Cell<Option<LostCause>>,
    /// The last failure the socket reported, kept for the deploy to report.
    error: Cell<Option<S::Error>>,
    /// Whether the link's owner waits on its stream ([`Self::waited_by_owner`]), so its loop does
    /// not.
    owner_waits: bool,
    /// The read its owner makes into the buffer with nothing of the session held, waiting in the
    /// read, when the stream gives one ([`SessionDatagramLink::lend_rx`]).
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    owner_read: Option<Arc<OwnerRead>>,
    /// Whether the free part of the buffer is lent to that read now: the receive then reads
    /// nothing and leaves the buffer alone until the lease is landed.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    rx_lent: Cell<bool>,
    /// Whether the stream took the last write whole without waiting
    /// ([`StreamSocket::send_parts_now`]): the next frame is then not preceded by a question of
    /// its room, the write itself being the question. `false` before the first write and for a
    /// stream that cannot write without waiting, which is asked every time.
    room_known: Cell<bool>,
    /// What the link owes the stream, oldest first: the rest of a frame the stream took in part,
    /// and the frames handed over behind it. Written by the next step that finds the stream room
    /// (a send, a question of room, the loop's service), never by waiting inside a call.
    owed: RefCell<OwedQueue>,
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
    pub fn over(socket: S, mut rx_buf: B, tx: T) -> Self {
        let rx_len = rx_buf.capacity();
        Self {
            endpoints: link_endpoints(S::PROTO, socket.local(), socket.peer()),
            socket,
            rx_buf: RefCell::new(rx_buf),
            rx_len,
            held: Cell::new(0),
            spent: Cell::new(0),
            ready: Cell::new(false),
            #[cfg(test)]
            moved: Cell::new(0),
            keeping: Cell::new(false),
            tx: TxLender::new(tx),
            lost: Cell::new(None),
            error: Cell::new(None),
            owner_waits: false,
            #[cfg(all(
                feature = "alloc",
                not(feature = "session-slot"),
                target_has_atomic = "ptr"
            ))]
            owner_read: None,
            #[cfg(all(
                feature = "alloc",
                not(feature = "session-slot"),
                target_has_atomic = "ptr"
            ))]
            rx_lent: Cell::new(false),
            room_known: Cell::new(false),
            owed: RefCell::new(OwedQueue::new()),
        }
    }

    /// The same link, waited on by its owner when its stream can be
    /// ([`SessionDatagramLink::readiness`]): its loop then reads what is queued and does not
    /// wait, and its owner waits on the stream with nothing of the session held. A stream that
    /// gives no such wait keeps the link waiting in its loop. One that also gives a read made from
    /// outside ([`StreamSocket::reader`]) lends its owner the buffer to wait in that read
    /// ([`SessionDatagramLink::lend_rx`]).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.owner_waits = self.socket.readiness().is_some();
        #[cfg(target_has_atomic = "ptr")]
        if self.owner_waits {
            self.owner_read = self.socket.reader().map(OwnerRead::new);
        }
        self
    }

    /// The most recent failure the socket reported, if it has failed.
    pub fn error(&self) -> Option<S::Error> {
        self.error.get()
    }

    /// The link is gone, for `cause`; the first cause is the one kept.
    fn end(&self, cause: LostCause) {
        if self.lost.get().is_none() {
            self.lost.set(Some(cause));
        }
    }

    /// Whether a whole batch lies in the buffer for the next receive, which then needs no read.
    fn batch_held(&self) -> bool {
        self.ready.get()
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
        // The free part of the buffer is the owner's read's until its lease is landed.
        #[cfg(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        ))]
        if self.rx_lent.get() {
            return false;
        }
        let mut buf = self.rx_buf.borrow_mut();
        // A link of a pool that holds no buffer and finds none free reads nothing: what its peer
        // sent waits in the stack (`SessionDatagramLink::waits_for_buffer`).
        let Some(bytes) = buf.bytes() else {
            return false;
        };
        let mut start = self.spent.get();
        let mut held = self.held.get();
        let lent = loop {
            match front(&bytes[start..held], self.rx_len) {
                Front::Batch(0) => start += STREAM_BATCH_LENGTH_BYTES,
                Front::Batch(len) => {
                    let end = start + STREAM_BATCH_LENGTH_BYTES + len;
                    self.keeping.set(false);
                    f(&bytes[start + STREAM_BATCH_LENGTH_BYTES..end]);
                    // A batch kept is lent again by the next receive; one let go is passed over
                    // there.
                    if !self.keeping.replace(false) {
                        start = end;
                    }
                    break true;
                }
                Front::TooLong => {
                    self.end(LostCause::PeerClosed);
                    break false;
                }
                Front::Partial => {
                    // Nothing before the part of a batch is lent any more: it moves to the front,
                    // so the rest is read behind it and the whole batch fits where it lies.
                    if start > 0 {
                        bytes.copy_within(start..held, 0);
                        #[cfg(test)]
                        self.moved.set(self.moved.get() + (held - start));
                        held -= start;
                        start = 0;
                    }
                    match self.socket.try_read(&mut bytes[held..]) {
                        Ok(Some(0)) => {
                            self.end(LostCause::PeerClosed);
                            break false;
                        }
                        Ok(Some(n)) => held += n,
                        Ok(None) => break false,
                        Err(e) => {
                            self.error.set(Some(e));
                            self.end(LostCause::OsError);
                            break false;
                        }
                    }
                }
            }
        };
        self.spent.set(start);
        self.held.set(held);
        self.ready.set(matches!(
            front(&bytes[start..held], self.rx_len),
            Front::Batch(_)
        ));
        // Nothing of the link's own is left in the buffer, no part of a batch and no batch kept:
        // a pooled buffer goes back for any link to read into. The facts of a part of a batch are
        // this link's (`held`, `spent`), so its buffer stays its own while one is there.
        if B::POOLED && start == held {
            self.spent.set(0);
            self.held.set(0);
            buf.idle();
        }
        lent
    }

    /// Whether the link owes the stream anything ([`Owed`]).
    fn owes(&self) -> bool {
        !self.owed.borrow().is_empty()
    }

    /// Write what the link owes the stream, oldest first, without waiting: `true` once nothing is
    /// owed (or the link has ended, which gives back whatever it held), `false` when the stream
    /// took less than all of it, the rest still owed for the next step that finds it room.
    fn write_owed(&self) -> bool {
        loop {
            if self.lost.get().is_some() {
                self.drop_owed();
                return true;
            }
            let mut owed = self.owed.borrow_mut();
            let Some(front) = owed.front_mut() else {
                return true;
            };
            let rest: &[u8] = match &*front {
                // SAFETY: the slot is held by the link (`Owed::Slot`), out of its pool until the
                // pop below or `drop_owed` gives it back, so nothing writes it.
                Owed::Slot { slot, from, end } => unsafe { self.tx.held(*slot, *from, *end) },
                #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
                Owed::Bytes { bytes, from } => &bytes[*from..],
            };
            let want = rest.len();
            let written = match self.socket.send_parts_now(&[rest]) {
                Some(Ok(taken)) => Ok(taken),
                Some(Err(e)) => Err(e),
                // Not reached: only a stream that writes without waiting comes to owe anything.
                None => self.socket.send_parts(&[rest]).map(|()| want),
            };
            match written {
                Ok(taken) if taken < want => {
                    front.advance(taken);
                    return false;
                }
                Ok(_) => {
                    if let Some(slot) = owed.pop().and_then(|done| done.held_slot()) {
                        self.tx.release(slot);
                    }
                }
                Err(e) => {
                    drop(owed);
                    self.fail(e);
                    return true;
                }
            }
        }
    }

    /// Give back everything the link holds for the stream: the link has ended, and nothing it
    /// owed will be written.
    fn drop_owed(&self) {
        let mut owed = self.owed.borrow_mut();
        while let Some(done) = owed.pop() {
            if let Some(slot) = done.held_slot() {
                self.tx.release(slot);
            }
        }
        self.room_known.set(false);
    }

    /// The stream failed a write with `error`: the link ends, REPORTED and not swallowed.
    fn fail(&self, error: S::Error) {
        self.error.set(Some(error));
        self.end(LostCause::OsError);
        self.drop_owed();
    }

    /// Write bytes `from .. end` of `slot`, a frame the session handed over, prefix included. The
    /// write is tried without waiting ([`StreamSocket::send_parts_now`]): taken whole, it says the
    /// stream had room, the slot goes back, and the next frame asks nothing; taken in part or not
    /// at all, the rest is owed, the slot held until it is written, and the next frame asks the
    /// stream for room. Behind something already owed it is owed whole, so frames leave in the
    /// order they were handed over. Nothing waits here; a stream that cannot try is written by
    /// waiting, as it always was.
    fn send_slot(&self, slot: TxSlot, from: usize, end: usize) -> LinkSendOutcome {
        if self.lost.get().is_some() {
            self.tx.release(slot);
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        if !self.write_owed() {
            return self.owe(Owed::Slot { slot, from, end }, 0);
        }
        if self.lost.get().is_some() {
            self.tx.release(slot);
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        // SAFETY: the session handed the slot over and the link holds it: nothing writes it.
        let frame = unsafe { self.tx.held(slot, from, end) };
        match self.socket.send_parts_now(&[frame]) {
            None => {
                let written = self.socket.send_parts(&[frame]);
                self.tx.release(slot);
                self.written(written)
            }
            Some(Ok(taken)) if taken >= frame.len() => {
                self.tx.release(slot);
                self.room_known.set(true);
                LinkSendOutcome::Sent
            }
            Some(Ok(taken)) => {
                self.room_known.set(false);
                self.owe(
                    Owed::Slot {
                        slot,
                        from: from + taken,
                        end,
                    },
                    taken,
                )
            }
            Some(Err(e)) => {
                self.tx.release(slot);
                self.written(Err(e))
            }
        }
    }

    /// Write a frame the session handed over as bytes (`parts`: its length and the batch), as
    /// [`Self::send_slot`] does; what is owed of it is copied into a slot of the link's, or onto
    /// the heap where the link lends none.
    fn send_bytes(&self, parts: &[&[u8]]) -> LinkSendOutcome {
        if self.lost.get().is_some() {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        if !self.write_owed() {
            return self.owe_copy(parts, 0);
        }
        if self.lost.get().is_some() {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        let whole: usize = parts.iter().map(|part| part.len()).sum();
        match self.socket.send_parts_now(parts) {
            None => self.written(self.socket.send_parts(parts)),
            Some(Ok(taken)) if taken >= whole => {
                self.room_known.set(true);
                LinkSendOutcome::Sent
            }
            Some(Ok(taken)) => {
                self.room_known.set(false);
                self.owe_copy(parts, taken)
            }
            Some(Err(e)) => self.written(Err(e)),
        }
    }

    /// The outcome of a write that waited, or failed.
    fn written(&self, written: Result<(), S::Error>) -> LinkSendOutcome {
        match written {
            Ok(()) => LinkSendOutcome::Sent,
            Err(e) => {
                self.fail(e);
                LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
            }
        }
    }

    /// Keep what the stream has not taken of `parts` (all after their first `skip` bytes) to
    /// write before anything after it.
    fn owe_copy(&self, parts: &[&[u8]], skip: usize) -> LinkSendOutcome {
        let len = parts
            .iter()
            .map(|part| part.len())
            .sum::<usize>()
            .saturating_sub(skip);
        let owed = match self.tx.hold_filled(len, |out| copy_rest(parts, skip, out)) {
            Some(slot) => Some(Owed::Slot {
                slot,
                from: 0,
                end: len,
            }),
            None => owed_bytes(parts, skip, len),
        };
        match owed {
            Some(owed) => self.owe(owed, skip),
            None => self.cannot_owe(skip),
        }
    }

    /// Put `owed` behind what is owed already. `skip` is how much of its frame the stream has
    /// taken: none for a frame that waits whole behind another.
    fn owe(&self, owed: Owed, skip: usize) -> LinkSendOutcome {
        let refused = self.owed.borrow_mut().push(owed);
        match refused {
            Ok(()) => LinkSendOutcome::Sent,
            Err(owed) => {
                if let Some(slot) = owed.held_slot() {
                    self.tx.release(slot);
                }
                self.cannot_owe(skip)
            }
        }
    }

    /// The link has nowhere to keep a frame it owes. One of which nothing was written is refused,
    /// as a frame the link lends no slot for is. One already begun on the stream cannot be: the
    /// stream's framing is lost with its rest, so the link ends.
    fn cannot_owe(&self, skip: usize) -> LinkSendOutcome {
        if skip == 0 {
            return LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot);
        }
        self.end(LostCause::OsError);
        self.drop_owed();
        LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
    }
}

impl<S: StreamSocket + 'static, B: RxStore + 'static, T: TxStore + 'static> BoxedLinkDriver
    for StreamDriver<S, B, T>
{
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        let Ok(len) = u16::try_from(bytes.len()) else {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        self.send_bytes(&[&len.to_le_bytes()[..], bytes])
    }

    // The room is the stream's: the session asks before it builds a frame, and a stream that
    // will not take more bytes within the wait has none, as zenoh's queue has no batch for a
    // message by its deadline (`io/zenoh-transport/src/common/pipeline.rs` @
    // `// Wait for an available batch until deadline`). A droppable message is then dropped and a
    // blocking one closes the session, which is the session's decision and not the link's. The
    // answer carries the time the stream's wait measured (`StreamSocket::wait_writable_timed`),
    // so a sender that keeps one deadline across several questions spends what was spent. A link
    // that has ended answers room, so the send that follows reports the end.
    // A stream that took the last write whole without waiting is not asked: the next write is
    // tried first, and one it does not take whole makes the frame after it ask again
    // (`send_slot`). A link that still owes the stream part of a frame has room once that is
    // written: the wait for the stream to take bytes is what lets it be, within the message's wait.
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        let wait_us = wait.wait_us();
        let owed_written = self.write_owed();
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
            let (room, waited_us) = self.socket.wait_writable_timed(wait_us);
            let room = if room && self.write_owed() {
                LinkRoom::Free
            } else {
                LinkRoom::Congested
            };
            return RoomAnswer { room, waited_us };
        }
        if self.room_known.get() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let (room, waited_us) = self.socket.wait_writable_timed(wait_us);
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
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        if let Some(grant) = self.tx.acquire(STREAM_BATCH_LENGTH_BYTES) {
            return Some(grant);
        }
        if self.owes() && self.write_owed() {
            return self.tx.acquire(STREAM_BATCH_LENGTH_BYTES);
        }
        None
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
        let Ok(length) = u16::try_from(len) else {
            self.tx.release(slot);
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        match self
            .tx
            .frame_prefixed(slot, start, len, &length.to_le_bytes())
        {
            Some((from, end)) => self.send_slot(slot, from, end),
            None => {
                self.tx.release(slot);
                LinkSendOutcome::Dropped(LinkDropCause::Oversize)
            }
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
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
        self.write_owed();
        self.socket.shutdown();
        self.end(LostCause::PeerClosed);
        self.drop_owed();
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        Some(&self.endpoints)
    }

    #[cfg(feature = "alloc")]
    fn link_subject(&self) -> Option<&wz_session_core::link::LinkSubject> {
        Some(S::PROTO.subject())
    }

    fn peer_credential_zid(&self) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
        self.socket.peer_credential_zid()
    }

    fn batch_length_prefixed(&self) -> bool {
        true
    }

    // A driver whose frame storage is declared is bounded by it: the batch it sends is at most a
    // slot. A batch is counted with its length, as the session's budget counts it (it takes the
    // length's room out of the batch itself, `batch_envelope_bytes`), so the bound is the whole
    // slot. One that lends nothing builds no frame in its storage and takes any batch the session
    // hands it.
    fn link_mtu(&self) -> usize {
        if self.tx.lends() {
            self.tx.slot_len()
        } else {
            DEFAULT_LINK_MTU
        }
    }

    // The receive buffer bounds the batch whatever the send side lends: a batch is counted with
    // its length, and the buffer holds both.
    fn link_rx_capacity(&self) -> usize {
        self.rx_len.min(DEFAULT_LINK_MTU)
    }
}

impl<S: StreamSocket + 'static, B: RxStore + 'static, T: TxStore + 'static> SessionDatagramLink
    for StreamDriver<S, B, T>
{
    fn service(&self) {
        // What the link owes the stream is written as far as the stream takes it, every step.
        if self.owes() {
            self.write_owed();
        }
        // A whole batch already held (the last read brought two) is read without waiting, and a
        // link its owner waits on does not wait here. A link that still owes the stream waits its
        // tick for room instead of for input, and writes on when it has some.
        if self.lost.get().is_none() && !self.batch_held() && !self.owner_waits {
            if !self.owes() {
                self.socket.wait_readable(SERVICE_WAIT_MS);
            } else if self.socket.wait_writable(SERVICE_WAIT_MS as u64 * 1_000) {
                self.write_owed();
            }
        }
    }

    fn holds_input(&self) -> bool {
        self.batch_held()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        self.rx_buf.try_borrow().is_ok_and(|buf| buf.starved())
    }

    fn owes_write(&self) -> bool {
        self.owes()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        if self.owes() {
            self.write_owed();
        }
    }

    // A batch lies in the link's own receive buffer until the link moves what follows it to the
    // front: a batch kept is left where it lies, and costs no copy.
    fn keeps_input(&self) -> bool {
        true
    }

    fn keep(&self) {
        self.keeping.set(true);
    }

    // The receive buffer is written by a receive alone (`receive`: its read of the stream and the
    // move to the front before it), never by a service, which waits and writes what is owed, so
    // what a receive lent lies there until the link is next asked to receive.
    fn lends_until_next_receive(&self) -> bool {
        true
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        if self.owner_waits {
            self.socket.readiness()
        } else {
            None
        }
    }

    // Whoever waits for input, room is the socket's alone: the driver queues nothing of its own
    // ahead of it (`wait_for_room` asks the socket too, unless the last write already said the
    // stream had room), so a wait on the socket from outside answers what the session's own wait
    // would.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        self.socket.writability()
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn lend_rx(&self) -> Option<RxLease> {
        let owner = self.owner_read.as_ref()?;
        if self.lost.get().is_some() || self.rx_lent.get() || self.batch_held() {
            return None;
        }
        let mut buf = self.rx_buf.try_borrow_mut().ok()?;
        let bytes = buf.bytes()?;
        let (start, mut held) = (self.spent.get(), self.held.get());
        // Nothing before what is left of a batch is lent any more (asked where a receive could
        // be): it moves to the front, as a receive moves it, and the read lands behind it.
        if start > 0 {
            bytes.copy_within(start..held, 0);
            #[cfg(test)]
            self.moved.set(self.moved.get() + (held - start));
            held -= start;
            self.spent.set(0);
            self.held.set(held);
        }
        let free = bytes.get_mut(held..).filter(|free| !free.is_empty())?;
        self.rx_lent.set(true);
        // SAFETY: the free part of the buffer is the lease's read's alone until it is landed: the
        // receive reads nothing while `rx_lent` is set, nothing else writes the buffer, and the
        // link does not let the buffer go before the read has ended (`Drop`).
        Some(unsafe { owner.lend(free.as_mut_ptr(), free.len()) })
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn land_rx(&self, lease: RxLease) {
        let Some(owner) = self.owner_read.as_ref() else {
            return;
        };
        if !self.rx_lent.get() || !owner.lent(&lease) {
            return;
        }
        self.rx_lent.set(false);
        match lease.waited() {
            ReadWaited::Read(n) => {
                let held = (self.held.get() + n).min(self.rx_len);
                self.held.set(held);
                let mut buf = self.rx_buf.borrow_mut();
                // The lease was lent from the buffer the link holds, which it holds still.
                if let Some(bytes) = buf.bytes() {
                    self.ready.set(matches!(
                        front(&bytes[self.spent.get()..held], self.rx_len),
                        Front::Batch(_)
                    ));
                }
            }
            ReadWaited::Quiet => {
                // A read that brought nothing leaves a buffer that holds nothing of the link's
                // own to its pool.
                if B::POOLED && self.held.get() == self.spent.get() {
                    self.rx_buf.borrow_mut().idle();
                }
            }
            ReadWaited::Ended => self.end(LostCause::PeerClosed),
            ReadWaited::Failed(code) => {
                if let Some(error) = S::read_failure(code) {
                    self.error.set(Some(error));
                }
                self.end(LostCause::OsError);
            }
        }
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        let mut frame = None;
        self.receive(&mut |batch| frame = Some(RxFrame::new(batch.to_vec())));
        frame
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.receive(f)
    }

    fn lost(&self) -> Option<LostCause> {
        self.lost.get()
    }
}

/// A buffer lent to the owner's read is not let go of under it: the stream is shut, which ends a
/// read waiting on it at once, and the read is waited out before the buffer goes.
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
    fn waited_by_owner(self) -> Self {
        StreamDriver::waited_by_owner(self)
    }
}

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
impl<S: StreamSocket, B: RxStore, T: TxStore> Drop for StreamDriver<S, B, T> {
    fn drop(&mut self) {
        if let (Some(owner), true) = (&self.owner_read, self.rx_lent.get()) {
            self.socket.shutdown();
            owner.wait_out();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::UnsafeCell;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// What the test hands the driver to read, in the pieces the stream cuts it into, and what
    /// the driver wrote, one entry per write.
    #[derive(Default)]
    struct Pipe {
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
        /// The stream writes without waiting (`send_parts_now`); a pipe that does not is asked for
        /// room before every frame.
        tries: Cell<bool>,
        /// How many bytes the writes that do not wait take before the stream would block; `None`
        /// takes them all.
        takes: Cell<Option<usize>>,
        /// The writes made by waiting (`send_parts`).
        waited_writes: Cell<u32>,
        /// How long a wait for room says it took, in microseconds; `None` answers as a stream
        /// with no clock does.
        room_took_us: Cell<Option<u64>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Broken;

    impl StreamSocket for Pipe {
        type Error = Broken;

        type Link<B: RxStore + 'static, X: crate::link_storage::TxStore + 'static>
            = crate::stream_link::StreamDriver<Self, B, X>
        where
            Self: 'static;

        fn local(&self) -> SocketAddr {
            self.ends_at
                .map_or(SocketAddr::from(([10, 0, 0, 2], 40_000)), |(local, _)| {
                    local
                })
        }

        fn peer(&self) -> SocketAddr {
            self.ends_at
                .map_or(SocketAddr::from(([10, 0, 0, 1], 7447)), |(_, peer)| peer)
        }

        fn send_parts(&self, parts: &[&[u8]]) -> Result<(), Broken> {
            self.waited_writes.set(self.waited_writes.get() + 1);
            self.writes.borrow_mut().push(parts.concat());
            Ok(())
        }

        fn send_parts_now(&self, parts: &[&[u8]]) -> Option<Result<usize, Broken>> {
            if !self.tries.get() {
                return None;
            }
            let all = parts.concat();
            let taken = if self.full.get() {
                0
            } else {
                self.takes
                    .get()
                    .map_or(all.len(), |left| left.min(all.len()))
            };
            if let Some(left) = self.takes.get() {
                self.takes.set(Some(left - taken));
            }
            if taken > 0 {
                self.writes.borrow_mut().push(all[..taken].to_vec());
            }
            Some(Ok(taken))
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
        }

        fn wait_writable(&self, timeout_us: u64) -> bool {
            self.room_waits.borrow_mut().push(timeout_us);
            !self.full.get() && self.takes.get() != Some(0)
        }

        fn wait_writable_timed(&self, timeout_us: u64) -> (bool, u64) {
            let room = self.wait_writable(timeout_us);
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
        fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
            Some(alloc::boxed::Box::new(Room(!self.full.get())))
        }

        #[cfg(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        ))]
        fn read_failure(_code: i32) -> Option<Broken> {
            Some(Broken)
        }
    }

    /// The pipe's room when its wait was handed out, as a wait from outside answers it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    struct Room(bool);

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    impl LinkWritability for Room {
        fn wait_writable(&self, _timeout_us: u64) -> bool {
            self.0
        }
    }

    /// A link hands out its socket's wait for room whether or not its owner waits for its input
    /// (none does here): a sender that finds the session held asks it from outside, and it
    /// answers as the socket does.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_link_hands_out_its_sockets_wait_for_room() {
        let free = link();
        let wait = free.writability().expect("the socket's wait for room");
        assert!(wait.wait_writable(1_000), "a stream that takes bytes");

        let full = link();
        full.socket.full.set(true);
        let wait = full.writability().expect("the socket's wait for room");
        assert!(
            !wait.wait_writable(1_000),
            "a stream whose peer reads nothing"
        );
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
        assert_eq!(link.moved.get(), 0, "nothing moved yet");
        assert!(!link.holds_input(), "part of a batch is not one");
        queue(&link, &batch(b"three")[3..]);
        assert_eq!(received(&link).as_deref(), Some(&b"three"[..]));
        assert_eq!(
            link.moved.get(),
            3,
            "the part of the third batch, moved once before the read"
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
        assert_eq!(front(&[3, 0, 1, 2, 3, 9], 10), Front::Batch(3));
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
        let pipe = Pipe {
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
    #[test]
    fn a_stream_that_takes_each_write_whole_is_asked_for_room_once() {
        let frames = |link: &Link| {
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
        };
        let control = link();
        frames(&control);
        assert_eq!(
            control.socket.room_waits.borrow().len(),
            3,
            "CONTROL: asked before every frame"
        );

        let link = link();
        link.socket.tries.set(true);
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
    #[test]
    fn a_frame_taken_half_is_finished_by_the_next_step_before_any_new_frame() {
        let link = link();
        link.socket.tries.set(true);
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
    #[test]
    fn a_lent_frame_keeps_its_slot_until_the_stream_has_taken_it_all() {
        let link = link();
        link.socket.tries.set(true);
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
        std::vec::Vec<StreamDriver<Pipe, [u8; 34], crate::link_storage::LinkTx>>,
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
                let link = StreamDriver::over(Pipe::default(), [0u8; 34], tx);
                link.socket.tries.set(true);
                link
            })
            .collect();
        (tables, links)
    }

    /// Hand `link` a frame of `bytes` in a slot it lends, the stream taking `takes` of it.
    #[cfg(feature = "session-unicast-accept")]
    fn send_lent<T: TxStore + 'static>(
        link: &StreamDriver<Pipe, [u8; 34], T>,
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
    #[test]
    fn a_slot_asked_while_a_frame_is_owed_is_lent_once_the_stream_takes_it() {
        let link = link();
        link.socket.tries.set(true);
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
                seq_num_res: 2,
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
                cookie_signing_key: SigningKey::new(std::vec![7u8; 32]).expect(">=32-byte key"),
            }
        }

        fn link() -> crate::link_cells::CellRc<Heap> {
            crate::link_cells::CellRc::boxed(StreamDriver::with_buffers(
                Pipe::default(),
                STREAM_RX_CAPACITY,
                HeapTx::new(4, 2048),
            ))
        }

        /// A droppable message on a stream that takes no more bytes waits its
        /// `wait_before_drop` for them, is dropped, closes nothing and reaches nothing; once the
        /// stream takes bytes again the next message is written.
        #[test]
        fn a_droppable_message_on_a_full_stream_is_dropped_within_its_own_wait() {
            let runtime = CoopRuntime::new(Stopped);
            let link = link();
            let sink = link.clone().into_sink();
            let actions = new_session_actions(sink, params(), CoopTime::new(&runtime));
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
        #[test]
        fn a_blocking_message_on_a_full_stream_closes_the_session_after_its_wait() {
            let runtime = CoopRuntime::new(Stopped);
            let link = link();
            let sink = link.clone().into_sink();
            let actions = new_session_actions(sink, params(), CoopTime::new(&runtime));
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
    }

    /// One answer of the owner's read of a test link a read: bytes, the end of the stream, a
    /// failure. A read that finds none is quiet.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    enum Answer {
        Bytes(Vec<u8>),
        Ended,
        Failed(i32),
    }

    /// The answers the owner's read of a test link gives, in order, and how many reads were made.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[derive(Default)]
    struct Feed {
        answers: std::sync::Mutex<VecDeque<Answer>>,
        reads: core::sync::atomic::AtomicUsize,
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    impl Feed {
        fn answer(&self, answer: Answer) {
            self.answers.lock().unwrap().push_back(answer);
        }

        fn reads(&self) -> usize {
            self.reads.load(core::sync::atomic::Ordering::SeqCst)
        }
    }

    /// The owner's read of a test link, over the feed the test holds.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    struct Fed(Arc<Feed>);

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    impl LinkRead for Fed {
        fn read_waiting(&self, buf: &mut [u8], _timeout_ms: u32) -> ReadWaited {
            self.0
                .reads
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            match self.0.answers.lock().unwrap().pop_front() {
                None => ReadWaited::Quiet,
                Some(Answer::Ended) => ReadWaited::Ended,
                Some(Answer::Failed(code)) => ReadWaited::Failed(code),
                Some(Answer::Bytes(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    ReadWaited::Read(bytes.len())
                }
            }
        }
    }

    /// A test link whose owner reads it, and the feed of that read.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn owned_link() -> (Link, Arc<Feed>) {
        let feed = Arc::new(Feed::default());
        let mut link = link();
        link.owner_read = Some(OwnerRead::new(alloc::boxed::Box::new(Fed(feed.clone()))));
        (link, feed)
    }

    /// Lend `link`'s buffer to its owner, make the read and land what it brought.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn owner_reads(link: &Link) {
        let mut lease = link.lend_rx().expect("the buffer is lent");
        lease.read(100);
        link.land_rx(lease);
    }

    /// The owner's read takes a batch into the link's buffer, and the receive after it hands the
    /// batch over from there with no read of the stream of its own: one read a batch, where a wait
    /// for the stream to be readable and the receive's read were two. The CONTROL is the link's
    /// own read of the stream, which the same batch costs a link its owner does not read for.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn a_batch_the_owner_read_is_handed_over_with_no_read_of_the_links_own() {
        let (link, feed) = owned_link();
        feed.answer(Answer::Bytes(batch(b"ping")));
        owner_reads(&link);
        assert_eq!(feed.reads(), 1, "one read, the owner's");
        assert!(link.holds_input(), "the batch lies whole in the buffer");
        assert_eq!(received(&link).as_deref(), Some(&b"ping"[..]));
        assert_eq!(link.socket.reads.get(), 0, "the stream was not read again");

        let control = self::link();
        queue(&control, &batch(b"ping"));
        assert_eq!(received(&control).as_deref(), Some(&b"ping"[..]));
        assert_eq!(
            control.socket.reads.get(),
            1,
            "CONTROL: the link reads it itself"
        );
    }

    /// A link with no read of its owner's lends nothing; one lends its buffer once, not again
    /// while the lease is out, and receives nothing meanwhile, leaving what its stream holds
    /// there; a link that holds a whole batch, or has ended, lends nothing.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn a_link_lends_its_buffer_once_and_not_while_it_holds_input_or_has_ended() {
        assert!(link().lend_rx().is_none(), "no read of the owner's");

        let (link, feed) = owned_link();
        let lease = link.lend_rx().expect("the buffer is lent");
        assert!(link.lend_rx().is_none(), "not twice");
        queue(&link, &batch(b"late"));
        assert_eq!(
            received(&link),
            None,
            "nothing is received while it is lent"
        );
        assert_eq!(link.socket.reads.get(), 0, "and the stream is not read");
        link.land_rx(lease);
        assert_eq!(
            received(&link).as_deref(),
            Some(&b"late"[..]),
            "landed, the link reads its stream again"
        );

        let mut two = batch(b"one");
        two.extend(batch(b"two"));
        feed.answer(Answer::Bytes(two));
        owner_reads(&link);
        assert_eq!(received(&link).as_deref(), Some(&b"one"[..]));
        assert!(link.holds_input());
        assert!(link.lend_rx().is_none(), "a whole batch is held");
        assert_eq!(received(&link).as_deref(), Some(&b"two"[..]));

        feed.answer(Answer::Ended);
        owner_reads(&link);
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
        assert!(link.lend_rx().is_none(), "a link that ended");
    }

    /// A lease is taken back by the link that gave it alone: landed on another link it changes
    /// nothing there and is not back where it was lent, while that link's own lease is taken back
    /// and it lends again.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn a_lease_is_landed_by_the_link_that_gave_it_alone() {
        let (giver, feed) = owned_link();
        let (other, _) = owned_link();
        feed.answer(Answer::Bytes(batch(b"mine")));
        let mut lease = giver.lend_rx().expect("lent");
        lease.read(100);
        let others = other.lend_rx().expect("the other lends its own");
        other.land_rx(lease);
        assert!(!other.holds_input(), "the other's buffer took nothing");
        assert!(giver.lend_rx().is_none(), "the giver's lease is not back");
        other.land_rx(others);
        assert!(other.lend_rx().is_some(), "the other's own lease is back");
    }

    /// A failure the owner's read met ends the link, with the stream's failure kept.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn a_failed_read_of_the_owners_ends_the_link_and_keeps_why() {
        let (link, feed) = owned_link();
        feed.answer(Answer::Failed(104));
        owner_reads(&link);
        assert_eq!(link.lost(), Some(LostCause::OsError));
        assert_eq!(link.error(), Some(Broken));
    }

    /// What is left of a batch moves to the front of the buffer when the buffer is lent, as a
    /// receive moves it, and the owner's read lands the rest behind it: 3 bytes moved here.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn what_is_left_of_a_batch_moves_to_the_front_before_the_buffer_is_lent() {
        let (link, feed) = owned_link();
        let mut wire = batch(b"one");
        wire.extend(&batch(b"three")[..3]);
        queue(&link, &wire);
        assert_eq!(received(&link).as_deref(), Some(&b"one"[..]));
        assert_eq!(link.moved.get(), 0);
        feed.answer(Answer::Bytes(batch(b"three")[3..].to_vec()));
        owner_reads(&link);
        assert_eq!(link.moved.get(), 3, "the part of the batch, moved once");
        assert_eq!(received(&link).as_deref(), Some(&b"three"[..]));
    }

    /// A link let go of while its lease was read and not yet landed lets its buffer go at once:
    /// the read has ended, and the lease landed after finds nothing of it.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    #[test]
    fn a_link_let_go_after_its_lease_was_read_does_not_wait() {
        let (link, feed) = owned_link();
        feed.answer(Answer::Bytes(batch(b"gone")));
        let mut lease = link.lend_rx().expect("lent");
        lease.read(100);
        drop(link);
        assert_eq!(lease.waited(), ReadWaited::Read(6));
        drop(lease);
    }
}
