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
//! gathers what the socket has into the driver's buffer and hands the session one whole batch at a time, where the buffer holds it; the bytes of
//! the next batch, however the stream cut them, stay in front of the buffer for the next receive.
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
use crate::link_storage::{TxLender, TxStore};
use crate::session_drive::{LinkOpenError, LinkProto, SessionDatagramLink};
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

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes, `Ok(Some(0))`
    /// when the peer has closed the stream, `Ok(None)` when nothing is queued.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

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

    /// Whether the dial opens streams at all. A stack asks before it claims any buffer, so a
    /// protocol it does not carry is [`LinkOpenError::Unsupported`] (permanent) and never
    /// [`LinkOpenError::Exhausted`] (retried) when its tables happen to be full.
    const CARRIED: bool = true;

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

/// The dial of a stream protocol a stack does not carry: an image with no secure channel names
/// it for `tls/`, and every dial is [`LinkOpenError::Unsupported`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDial;

/// The stream [`NoDial`] would yield: there is none.
#[derive(Debug)]
pub enum NoStream {}

impl StreamSocket for NoStream {
    type Error = core::convert::Infallible;

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
pub struct StreamDriver<S: StreamSocket, B: AsMut<[u8]>, T: TxStore> {
    socket: S,
    /// The link's two ends, `tcp/<ip>:<port>` each, known from the connection.
    endpoints: LinkEndpoints,
    rx_buf: RefCell<B>,
    /// The length of `rx_buf`: a batch's length and the batch behind it.
    rx_len: usize,
    /// How many bytes at the front of `rx_buf` were received and not yet handed to the session.
    held: Cell<usize>,
    /// The memory the session encodes its frames into, and which of it is out.
    tx: TxLender<T>,
    /// Why the link is gone, once it is.
    lost: Cell<Option<LostCause>>,
    /// The last failure the socket reported, kept for the deploy to report.
    error: Cell<Option<S::Error>>,
    /// Whether the link's owner waits on its stream ([`Self::waited_by_owner`]), so its loop does
    /// not.
    owner_waits: bool,
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

impl<S: StreamSocket, B: AsMut<[u8]>, T: TxStore> StreamDriver<S, B, T> {
    /// The link over the connected `socket`, receiving into `rx_buf` and building its frames in
    /// `tx`.
    pub fn over(socket: S, mut rx_buf: B, tx: T) -> Self {
        let rx_len = rx_buf.as_mut().len();
        Self {
            endpoints: link_endpoints(S::PROTO, socket.local(), socket.peer()),
            socket,
            rx_buf: RefCell::new(rx_buf),
            rx_len,
            held: Cell::new(0),
            tx: TxLender::new(tx),
            lost: Cell::new(None),
            error: Cell::new(None),
            owner_waits: false,
        }
    }

    /// The same link, waited on by its owner when its stream can be
    /// ([`SessionDatagramLink::readiness`]): its loop then reads what is queued and does not
    /// wait, and its owner waits on the stream with nothing of the session held. A stream that
    /// gives no such wait keeps the link waiting in its loop.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.owner_waits = self.socket.readiness().is_some();
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

    /// Whether the front of the buffer is a whole batch, so the next receive needs no read.
    fn batch_held(&self) -> bool {
        let Ok(mut buf) = self.rx_buf.try_borrow_mut() else {
            return false;
        };
        let held = self.held.get();
        matches!(front(&buf.as_mut()[..held], self.rx_len), Front::Batch(_))
    }

    /// Hand the next whole batch to `f` where the buffer holds it, reading the socket until there
    /// is one or nothing more is queued; `false` when there is none. An empty batch is passed
    /// over. The bytes behind the batch are moved to the front for the next receive.
    fn receive(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.lost.get().is_some() {
            return false;
        }
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        loop {
            let held = self.held.get();
            match front(&bytes[..held], self.rx_len) {
                Front::Batch(len) => {
                    let end = STREAM_BATCH_LENGTH_BYTES + len;
                    if len > 0 {
                        f(&bytes[STREAM_BATCH_LENGTH_BYTES..end]);
                    }
                    bytes.copy_within(end..held, 0);
                    self.held.set(held - end);
                    if len > 0 {
                        return true;
                    }
                }
                Front::TooLong => {
                    self.end(LostCause::PeerClosed);
                    return false;
                }
                Front::Partial => match self.socket.try_read(&mut bytes[held..]) {
                    Ok(Some(0)) => {
                        self.end(LostCause::PeerClosed);
                        return false;
                    }
                    Ok(Some(n)) => self.held.set(held + n),
                    Ok(None) => return false,
                    Err(e) => {
                        self.error.set(Some(e));
                        self.end(LostCause::OsError);
                        return false;
                    }
                },
            }
        }
    }

    /// Write `parts` to the stream as the outcome the session counts: a write to a link that is
    /// gone, or one the stack refuses (which ends the link), is REPORTED, not swallowed.
    fn send(&self, parts: &[&[u8]]) -> LinkSendOutcome {
        if self.lost.get().is_some() {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        match self.socket.send_parts(parts) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(e) => {
                self.error.set(Some(e));
                self.end(LostCause::OsError);
                LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
            }
        }
    }
}

impl<S: StreamSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static> BoxedLinkDriver
    for StreamDriver<S, B, T>
{
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        let Ok(len) = u16::try_from(bytes.len()) else {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        self.send(&[&len.to_le_bytes(), bytes])
    }

    // The room is the stream's: the session asks before it builds a frame, and a stream that
    // will not take more bytes within the wait has none, as zenoh's queue has no batch for a
    // message by its deadline (`io/zenoh-transport/src/common/pipeline.rs` @
    // `// Wait for an available batch until deadline`). A droppable message is then dropped and a
    // blocking one closes the session, which is the session's decision and not the link's. A
    // stream that took more within the wait is counted as having answered at once: the stream
    // tells no time. A link that has ended answers room, so the send that follows reports the end.
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        if self.lost.get().is_some() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let wait_us = wait.wait_us();
        if self.socket.wait_writable(wait_us) {
            RoomAnswer::at_once(LinkRoom::Free)
        } else {
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: wait_us,
            }
        }
    }

    // The session encodes a batch straight into the driver's own storage behind the room its
    // length takes, and the length is written there at the send: length and batch are one write
    // from the slot, and no buffer is allocated for either.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        self.tx.acquire(STREAM_BATCH_LENGTH_BYTES)
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
            .take_prefixed(slot, start, len, &length.to_le_bytes())
        {
            Some(framed) => self.send(&[framed]),
            None => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    fn open_blocking(&self) {}

    // The session's Close frame has been written; the stream ends behind it, and the peer reads
    // the end.
    fn close_blocking(&self) {
        self.socket.shutdown();
        self.end(LostCause::PeerClosed);
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        Some(&self.endpoints)
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

impl<S: StreamSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static> SessionDatagramLink
    for StreamDriver<S, B, T>
{
    fn service(&self) {
        // A whole batch already held (the last read brought two) is read without waiting, and a
        // link its owner waits on does not wait here.
        if self.lost.get().is_none() && !self.batch_held() && !self.owner_waits {
            self.socket.wait_readable(SERVICE_WAIT_MS);
        }
    }

    fn holds_input(&self) -> bool {
        self.batch_held()
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
    // ahead of it (`wait_for_room` asks the socket too), so a wait on the socket from outside
    // answers what the session's own wait would.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        self.socket.writability()
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
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Broken;

    impl StreamSocket for Pipe {
        type Error = Broken;

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
            self.writes.borrow_mut().push(parts.concat());
            Ok(())
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
        }

        fn wait_writable(&self, timeout_us: u64) -> bool {
            self.room_waits.borrow_mut().push(timeout_us);
            !self.full.get()
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

    fn queue(link: &Link, piece: &[u8]) {
        link.socket.pieces.borrow_mut().push_back(piece.to_vec());
    }

    fn received(link: &Link) -> Option<Vec<u8>> {
        let mut got = None;
        link.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
        got
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

        use alloc::rc::Rc;
        use std::vec::Vec;
        use wz_session_core::link::BoxedLinkDriver;
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

        struct Counting(u8);

        impl wz_session_core::entropy::EntropySource for Counting {
            fn try_fill_bytes(
                &mut self,
                buf: &mut [u8],
            ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
                for slot in buf.iter_mut() {
                    *slot = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
                Ok(())
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
                    ..TxQueueConf::of_policy(&wz_session_core::policy::SessionPolicy::defaults())
                },
                link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
                policy: wz_session_core::policy::SessionPolicy::defaults(),
                cookie_signing_key: SigningKey::new(std::vec![7u8; 32]).expect(">=32-byte key"),
            }
        }

        fn link() -> Rc<Heap> {
            Rc::new(StreamDriver::with_buffers(
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
            let sink: Rc<dyn BoxedLinkDriver> = link.clone();
            let actions = new_session_actions(sink, params(), CoopTime::new(&runtime), Counting(0));
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
            let sink: Rc<dyn BoxedLinkDriver> = link.clone();
            let actions = new_session_actions(sink, params(), CoopTime::new(&runtime), Counting(0));
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
}
