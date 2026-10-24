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
use core::fmt::{Debug, Write};

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::caps::MAX_LOCATOR_LEN;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, LostCause, TxSlot, TxSlotGrant,
    DEFAULT_LINK_MTU, STREAM_BATCH_LENGTH_BYTES,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::{TxLender, TxStore};
use crate::session_drive::{IpEndpoint, LinkOpenError, LinkProto, Locator, SessionDatagramLink};
use crate::udp_link::SERVICE_WAIT_MS;

/// The receive buffer of a link that takes the largest batch zenoh can negotiate: its length and
/// the batch behind it.
pub const STREAM_RX_CAPACITY: usize = u16::MAX as usize + STREAM_BATCH_LENGTH_BYTES;

/// One connected IPv4 byte stream: a platform's TCP socket, or a channel over one. Only the one
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

    /// The `(address, port)` this end of the connection is bound to.
    fn local(&self) -> ([u8; 4], u16);

    /// The `(address, port)` of the other end.
    fn peer(&self) -> ([u8; 4], u16);

    /// Write every byte of `parts`, in order, as one write where the stack allows (a length and
    /// the batch behind it leave together), blocking until the stack has taken them all.
    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), Self::Error>;

    /// Block until bytes are queued or `timeout_ms` has passed, and return at once when some
    /// already are. A failed wait is the same as a quiet socket here: the read that follows
    /// reports the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes, `Ok(Some(0))`
    /// when the peer has closed the stream, `Ok(None)` when nothing is queued.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// End the connection in both directions. The peer reads the end of the stream.
    fn shutdown(&self);
}

/// How a stack opens the connected streams its `tcp/` links run over: a value the stack holds,
/// so whatever a dial needs besides the address (a secure channel's identity, its context
/// table) is the dial's, and the stack and the link stay written once.
pub trait StreamDial {
    /// The stream a dial yields.
    type Stream: StreamSocket;

    /// Connect to `addr:port`, blocking until the stream can carry a session or the dial has
    /// failed: [`LinkOpenError::Refused`] when the other end did not take it,
    /// [`LinkOpenError::Exhausted`] when the platform had no socket to give.
    fn dial(&self, addr: [u8; 4], port: u16) -> Result<Self::Stream, LinkOpenError>;

    /// Whether the dial opens streams at all. A stack asks before it claims any buffer, so a
    /// protocol it does not carry is [`LinkOpenError::Unsupported`] (permanent) and never
    /// [`LinkOpenError::Exhausted`] (retried) when its tables happen to be full.
    const CARRIED: bool = true;
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

    fn local(&self) -> ([u8; 4], u16) {
        match *self {}
    }

    fn peer(&self) -> ([u8; 4], u16) {
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

    fn dial(&self, _addr: [u8; 4], _port: u16) -> Result<NoStream, LinkOpenError> {
        Err(LinkOpenError::Unsupported)
    }
}

/// `<scheme>/a.b.c.d:port`, zenoh's rendering of a stream's locator, written into fixed text:
/// the longest one, `tcp/255.255.255.255:65535`, is 25 bytes of the [`MAX_LOCATOR_LEN`] the text
/// has, and every scheme is three letters.
fn locator_text(
    proto: LinkProto,
    (addr, port): ([u8; 4], u16),
) -> heapless::String<MAX_LOCATOR_LEN> {
    let mut text = heapless::String::new();
    let at = IpEndpoint { addr, port };
    // Cannot fail: the longest rendering is shorter than the text's capacity.
    let _ = write!(text, "{}", Locator { proto, at });
    text
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
        let (local, peer) = (socket.local(), socket.peer());
        Self {
            endpoints: LinkEndpoints::new(
                locator_text(S::PROTO, local).as_str(),
                locator_text(S::PROTO, peer).as_str(),
            ),
            socket,
            rx_buf: RefCell::new(rx_buf),
            rx_len,
            held: Cell::new(0),
            tx: TxLender::new(tx),
            lost: Cell::new(None),
            error: Cell::new(None),
        }
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
        // A whole batch already held (the last read brought two) is read without waiting.
        if self.lost.get().is_none() && !self.batch_held() {
            self.socket.wait_readable(SERVICE_WAIT_MS);
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
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Broken;

    impl StreamSocket for Pipe {
        type Error = Broken;

        fn local(&self) -> ([u8; 4], u16) {
            ([10, 0, 0, 2], 40_000)
        }

        fn peer(&self) -> ([u8; 4], u16) {
            ([10, 0, 0, 1], 7447)
        }

        fn send_parts(&self, parts: &[&[u8]]) -> Result<(), Broken> {
            self.writes.borrow_mut().push(parts.concat());
            Ok(())
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
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

    #[test]
    fn a_closed_link_shuts_the_stream_and_is_gone() {
        let link = link();
        link.close_blocking();
        assert!(link.socket.shut.get());
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
    }
}
