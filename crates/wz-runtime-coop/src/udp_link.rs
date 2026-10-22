// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over UDP datagrams, written once for every stack that has BSD-style
//! sockets under a cooperative loop.
//!
//! A platform supplies a [`DatagramSocket`]: bind, send, and the three ways of taking a datagram
//! (wait for one, take one that is queued, wait and take in one call). Everything above the socket
//! is the same on every platform and is here: [`UdpDriver`] is the session's outbound
//! [`BoxedLinkDriver`] and the drive loop's [`SessionDatagramLink`] over one socket, and
//! [`UdpStack`] is the stack the slot profile's session host is given, opening a driver for each
//! dial.
//!
//! Zephyr's sockets (`wz-runtime-zephyr`) and the host's (`wz-runtime-posix`) are the two sockets
//! that exist. They were one copy of this code each until the host needed it: a stack brings a
//! socket, not a link, because a second copy of a 400-line piece that decides is the shape
//! `docs/storage-policy-and-link-layer.md` D2 rejects.
//!
//! The receive buffer and the buffer outbound frames are encoded into are the driver's type
//! parameters: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the image's byte tables on
//! the fixed one ([`FixedUdpDriver`]), where the driver is a few words in the session's slot and a
//! datagram costs no allocation either way.

use core::cell::{Cell, OnceCell, RefCell};
use core::ffi::c_int;
use core::fmt::{Debug, Write};

// The heap profile's forms (`Vec`, `HeapTx`) exist only in the heap profile: under `session-slot`
// the crate does not link `alloc` at all, which `lib.rs` keeps so that a use creeping back into the
// slot profile is a compile error and not a silent allocation.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

#[cfg(feature = "session-slot")]
use core::marker::PhantomData;

use wz_session_core::byte_cells::ByteBuf;
#[cfg(feature = "session-slot")]
use wz_session_core::byte_cells::ByteSource;
use wz_session_core::caps::MAX_LOCATOR_LEN;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, TxSlot, TxSlotGrant,
    DEFAULT_LINK_MTU,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

use crate::session_drive::SessionDatagramLink;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Bind, DriverPump, LinkOpenError, SlotStack, UdpPeer};

/// The largest UDP payload the session receives in one datagram: the transport's own ceiling, so a
/// whole batch always fits.
pub const UDP_RX_CAPACITY: usize = 65_535;

/// How long one pass of the drive loop waits for its link's socket to have a datagram. It bounds
/// the loop's timers (the lease, the keep-alive, the retransmissions), which are looked at once
/// per pass, so it is as long as the loop has always slept between passes: a quiet link costs the
/// same, a datagram costs none of it. A socket bounds its blocking reads by it
/// ([`DatagramSocket::times_out`]).
pub const SERVICE_WAIT_MS: c_int = 1;

/// A datagram a socket took into the caller's buffer: how many bytes it wrote there, and the
/// address and port it came from.
pub type Received = (usize, [u8; 4], u16);

/// One IPv4 UDP socket of a platform's network stack, bound to an explicit local address (the one
/// the link's locator names). Only the one thread that drives the link touches it.
pub trait DatagramSocket: Sized {
    /// Why a call failed, as the platform reports it. `Copy`, because the driver keeps the last
    /// receive failure for the deploy to report.
    type Error: Copy + Debug;

    /// Open a socket and bind it to `addr:port`; port 0 has the stack choose one, as a dialling
    /// link needs, and [`Self::local`] then names the port it chose, never the 0.
    fn bind(addr: [u8; 4], port: u16) -> Result<Self, Self::Error>;

    /// The `(address, port)` this socket is bound to.
    fn local(&self) -> ([u8; 4], u16);

    /// Send one datagram to `addr:port`. A short or refused send is an error: UDP either takes
    /// the whole datagram or none of it.
    fn send_to(&self, addr: [u8; 4], port: u16, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Block until a datagram is queued or `timeout_ms` has passed, and return at once when one
    /// already is. A failed wait is the same as a quiet socket here: the receive that follows
    /// reads and reports the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Whether [`Self::recv_waiting`] can wait: a blocking read of this socket gives up after
    /// [`SERVICE_WAIT_MS`].
    fn times_out(&self) -> bool;

    /// Whether [`Self::set_receive_timeout`] can take a value. A constant, so that a link over a
    /// socket that cannot compiles the loop's deadline arithmetic out
    /// ([`SessionDatagramLink::uses_wake_budget`]) and an image over it is the image it was.
    const CAN_SET_RECEIVE_TIMEOUT: bool = false;

    /// Bound every blocking read of this socket by `ms` milliseconds from now on, in place of the
    /// [`SERVICE_WAIT_MS`] it was opened with. `true` when the socket took it.
    ///
    /// The provided form takes none, so a socket that cannot is waited on for the one tick it
    /// always was. A socket that can lets the link sleep until the session's next deadline
    /// ([`SessionDatagramLink::service_within`]) instead of waking every tick.
    fn set_receive_timeout(&self, ms: c_int) -> bool {
        let _ = ms;
        false
    }

    /// Wait up to the socket's receive timeout for a datagram and take it into `buf` in the same
    /// call: `Ok(None)` when the timeout ran out, else its length and source. Only for a socket
    /// whose [`Self::times_out`] is true: without the timeout the read would block for ever.
    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error>;

    /// Take one queued datagram into `buf` without blocking: `Ok(None)` when nothing is queued,
    /// else its length and source.
    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error>;
}

/// `udp/a.b.c.d:port`, zenoh's rendering of a UDP locator, written into fixed text: the longest
/// one, `udp/255.255.255.255:65535`, is 25 bytes of the [`MAX_LOCATOR_LEN`] the text has.
fn udp_locator(addr: [u8; 4], port: u16) -> heapless::String<MAX_LOCATOR_LEN> {
    let [a, b, c, d] = addr;
    let mut text = heapless::String::new();
    // Cannot fail: the longest rendering is shorter than the text's capacity.
    let _ = write!(text, "udp/{a}.{b}.{c}.{d}:{port}");
    text
}

/// Where a driver's outbound frames are built: memory of its own that it lends the session to
/// encode a frame into ([`BoxedLinkDriver::tx_slot_acquire`]), so the frame is written once, where
/// the socket reads it, and no buffer is allocated for it.
///
/// A driver whose storage is empty (a `HeapTx` of no bytes) lends nothing: the session builds
/// each frame in a buffer of its own (the heap) and hands the bytes to `send_blocking`. A driver
/// with storage lends it, and its link then also states the frames it
/// carries ([`BoxedLinkDriver::link_mtu`], `link_rx_capacity`), because its buffers are the bound.
/// The storage is a buffer of a table the image declares ([`ByteBuf`], the fixed-memory profile's,
/// whose sessions have no heap to build a frame on) or buffers the link allocated once
/// (`HeapTx`, the heap profile's).
///
/// The storage is some number of slots of one length. A session that batches holds one slot open
/// while it fills a batch and encodes the next message that does not join it into another, so a
/// batching session needs two; one that does not batch needs one. The driver lends a slot at a
/// time and takes it back at its send or abort.
pub trait TxStore {
    /// How many slots there are to lend, all of the length [`Self::slot_len`].
    fn slots(&self) -> usize;

    /// The length of every slot.
    fn slot_len(&self) -> usize;

    /// The first byte of slot `slot` (below [`Self::slots`]). The driver reads and writes it only
    /// while it has lent the slot, and to one holder.
    fn slot_base(&self, slot: usize) -> *mut u8;

    /// Whether there is storage to lend.
    fn lends(&self) -> bool {
        self.slots() != 0 && self.slot_len() != 0
    }
}

/// The fixed-memory profile's outbound storage: a buffer lent by a table the image declares, one
/// slot. The socket writes a frame before the session builds the next, and a session that does not
/// batch has no frame open beside it.
impl TxStore for ByteBuf {
    fn slots(&self) -> usize {
        1
    }

    fn slot_len(&self) -> usize {
        self.raw().1
    }

    fn slot_base(&self, _slot: usize) -> *mut u8 {
        self.raw().0
    }
}

/// The heap profile's outbound storage: `slots` buffers of `slot_len` bytes, allocated together
/// when the link is made and never again, so the frames of the link are encoded into them and a
/// frame costs no allocation. Of no bytes it lends nothing, which is the link as it was before the
/// profile lent.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct HeapTx {
    cells: Vec<core::cell::UnsafeCell<u8>>,
    slot_len: usize,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl HeapTx {
    /// `slots` slots of `slot_len` bytes each (none, with either 0).
    pub fn new(slots: usize, slot_len: usize) -> Self {
        let len = slots.saturating_mul(slot_len);
        Self {
            cells: (0..len).map(|_| core::cell::UnsafeCell::new(0)).collect(),
            slot_len,
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TxStore for HeapTx {
    fn slots(&self) -> usize {
        self.cells.len().checked_div(self.slot_len).unwrap_or(0)
    }

    fn slot_len(&self) -> usize {
        self.slot_len
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        // `UnsafeCell<u8>` is a `u8`, and a pointer to a cell may be written through.
        self.cells
            .as_ptr()
            .cast::<u8>()
            .cast_mut()
            .wrapping_add(slot * self.slot_len)
    }
}

/// The session's link over one socket `S`, with its receive buffer in `B` and its outbound frames
/// built in `T`: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the image's byte
/// tables on the fixed one ([`FixedUdpDriver`]).
///
/// Outbound sends target the peer captured from the most recent inbound
/// datagram: an acceptor is built with no peer and learns it from the
/// InitSyn, and [`SessionDatagramLink::recv_with`] retargets on every datagram
/// so replies go to whoever just spoke. UDP is connectionless, so
/// `open_blocking` / `close_blocking` are no-ops: the zenoh handshake and
/// Close frame are the session's open and close.
pub struct UdpDriver<S: DatagramSocket, B: AsMut<[u8]>, T: TxStore> {
    socket: S,
    peer: Cell<Option<([u8; 4], u16)>>,
    /// The link's two ends, `udp/<ip>:<port>` each, written once: when the
    /// peer is first known.
    endpoints: OnceCell<LinkEndpoints>,
    rx_buf: RefCell<B>,
    /// The length of `rx_buf`, the largest datagram the link receives whole.
    rx_len: usize,
    /// The memory the session encodes its frames into.
    tx: T,
    /// Which slots of `tx` are out with the session, bit by slot number, between a slot's grant and
    /// its send or abort.
    tx_lent: Cell<u8>,
    /// A datagram [`SessionDatagramLink::service`] already read into `rx_buf` while it waited
    /// (length and source), for the next receive to hand out without another call into the stack.
    stash: Cell<Option<Received>>,
    /// The last receive failure, kept for the deploy to report: the loop's
    /// seam returns a frame or nothing, and a socket that fails must not
    /// read as a quiet one.
    rx_error: Cell<Option<S::Error>>,
    /// The longest this link may wait for a datagram when its session has nothing due sooner, in
    /// milliseconds. [`SERVICE_WAIT_MS`] (the default) is the tick the loop has always slept:
    /// the image raises it ([`Self::with_idle_wait_ms`]) only when this link is the one thing its
    /// loop waits on, because another session's socket is not looked at while this one blocks.
    idle_wait_ms: u32,
    /// The receive timeout the socket is armed with now, in milliseconds.
    armed_wait_ms: Cell<c_int>,
}

/// The fixed-memory profile's driver: its receive buffer and the buffer its frames are built in
/// are each lent by a table the image declares
/// ([`ByteCells`](wz_session_core::byte_cells::ByteCells)), the first as long as the batch the
/// session advertises and the second as long as the largest frame the link carries. A datagram
/// longer than the receive buffer is truncated by the stack, which the session reads as a bad
/// frame.
pub type FixedUdpDriver<S> = UdpDriver<S, ByteBuf, ByteBuf>;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S: DatagramSocket> UdpDriver<S, Vec<u8>, HeapTx> {
    /// An acceptor's link: no peer until the first datagram names one.
    pub fn acceptor(socket: S) -> Self {
        Self::acceptor_with_capacity(socket, UDP_RX_CAPACITY)
    }

    /// An initiator's link: replies and first sends go to `peer`.
    pub fn initiator(socket: S, peer: ([u8; 4], u16)) -> Self {
        Self::initiator_with_capacity(socket, peer, UDP_RX_CAPACITY)
    }

    /// [`Self::acceptor_with_capacity`] that also lends the session the slots of `tx` to encode its
    /// frames into.
    pub fn acceptor_with_buffers(socket: S, rx_capacity: usize, tx: HeapTx) -> Self {
        Self::acceptor_in(socket, vec![0u8; rx_capacity], tx)
    }

    /// [`Self::initiator_with_capacity`] that also lends the session the slots of `tx` to encode
    /// its frames into.
    pub fn initiator_with_buffers(
        socket: S,
        peer: ([u8; 4], u16),
        rx_capacity: usize,
        tx: HeapTx,
    ) -> Self {
        Self::initiator_in(socket, peer, vec![0u8; rx_capacity], tx)
    }

    /// An acceptor's link whose receive buffer holds `rx_capacity` bytes: what a
    /// node that runs several links at once sizes to the batch it negotiates,
    /// rather than to the largest datagram UDP can carry ([`UDP_RX_CAPACITY`]).
    /// A datagram longer than that is truncated by the stack, which the session
    /// reads as a bad frame.
    pub fn acceptor_with_capacity(socket: S, rx_capacity: usize) -> Self {
        Self::acceptor_in(socket, vec![0u8; rx_capacity], HeapTx::new(0, 0))
    }

    /// [`Self::initiator`] with a receive buffer of `rx_capacity` bytes.
    pub fn initiator_with_capacity(socket: S, peer: ([u8; 4], u16), rx_capacity: usize) -> Self {
        Self::initiator_in(socket, peer, vec![0u8; rx_capacity], HeapTx::new(0, 0))
    }
}

impl<S: DatagramSocket, B: AsMut<[u8]>, T: TxStore> UdpDriver<S, B, T> {
    /// An acceptor's link over the receive buffer `rx_buf`, building its frames in `tx`: no peer
    /// until the first datagram names one.
    pub fn acceptor_in(socket: S, rx_buf: B, tx: T) -> Self {
        Self::with_peer(socket, None, rx_buf, tx)
    }

    /// An initiator's link over the receive buffer `rx_buf`, building its frames in `tx`: replies
    /// and first sends go to `peer`.
    pub fn initiator_in(socket: S, peer: ([u8; 4], u16), rx_buf: B, tx: T) -> Self {
        Self::with_peer(socket, Some(peer), rx_buf, tx)
    }

    fn with_peer(socket: S, peer: Option<([u8; 4], u16)>, mut rx_buf: B, tx: T) -> Self {
        let rx_len = rx_buf.as_mut().len();
        let driver = Self {
            socket,
            peer: Cell::new(None),
            endpoints: OnceCell::new(),
            rx_buf: RefCell::new(rx_buf),
            rx_len,
            tx,
            tx_lent: Cell::new(0),
            stash: Cell::new(None),
            rx_error: Cell::new(None),
            idle_wait_ms: SERVICE_WAIT_MS as u32,
            armed_wait_ms: Cell::new(SERVICE_WAIT_MS),
        };
        if let Some(peer) = peer {
            driver.set_peer(peer);
        }
        driver
    }

    /// Let this link wait up to `ms` milliseconds for a datagram when its session has nothing due
    /// sooner (see [`SessionDatagramLink::service_within`]). Said by the image, and only when this
    /// link is the one thing its loop waits on: a loop that serves several sessions would not look
    /// at the others' sockets for that long. A value below the tick is the tick.
    #[must_use]
    pub fn with_idle_wait_ms(mut self, ms: u32) -> Self {
        // Half of `c_int`'s range, so that rounding down to a power of two stays inside it.
        self.idle_wait_ms = ms.clamp(SERVICE_WAIT_MS as u32, (c_int::MAX / 2) as u32);
        self
    }

    /// Arm the socket's receive timeout at `ms` if it is not already. `false` when the socket
    /// cannot be armed at that value.
    fn arm(&self, ms: c_int) -> bool {
        if self.armed_wait_ms.get() == ms {
            return true;
        }
        let took = self.socket.set_receive_timeout(ms);
        if took {
            self.armed_wait_ms.set(ms);
        }
        took
    }

    /// The next datagram: the one `service` already read into `rx_buf`, if it did, else one the
    /// stack has queued. `Ok(None)` when there is none.
    fn next_datagram(&self, buf: &mut [u8]) -> Result<Option<Received>, S::Error> {
        match self.stash.take() {
            Some(held) => Ok(Some(held)),
            None => self.socket.try_recv(buf),
        }
    }

    fn set_peer(&self, peer: ([u8; 4], u16)) {
        self.peer.set(Some(peer));
        if self.endpoints.get().is_none() {
            let (addr, port) = self.socket.local();
            let _ = self.endpoints.set(LinkEndpoints::new(
                udp_locator(addr, port).as_str(),
                udp_locator(peer.0, peer.1).as_str(),
            ));
        }
    }

    /// The peer the next send goes to, once one is known.
    pub fn peer(&self) -> Option<([u8; 4], u16)> {
        self.peer.get()
    }

    /// The most recent receive failure, if the socket has failed.
    pub fn rx_error(&self) -> Option<S::Error> {
        self.rx_error.get()
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static>
    UdpDriver<S, B, T>
{
    /// Wait on the socket for a datagram, for as long as it is armed to wait.
    ///
    /// On a socket whose reads time out, the wait is the read: the datagram is taken into
    /// `rx_buf` in the same call that waited for it and held for the receive that follows, so
    /// a datagram crosses the stack once, as it does for zenoh-pico. Otherwise `poll` waits and
    /// the receive reads.
    fn wait_for_datagram(&self) {
        if !self.socket.times_out() {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        }
        if self.stash.get().is_some() {
            return;
        }
        // The buffer is lent out while a receive callback runs; a wait asked for from inside one
        // (the loop does not) falls back to `poll`, which needs no buffer.
        let Ok(mut buf) = self.rx_buf.try_borrow_mut() else {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        };
        match self.socket.recv_waiting(buf.as_mut()) {
            Ok(held) => self.stash.set(held),
            Err(e) => self.rx_error.set(Some(e)),
        }
    }

    /// The socket's send of `bytes` to the peer, as the outcome the session counts: a send with no
    /// peer yet, or one the stack refuses, is REPORTED (R2371's rule for the lwIP driver), not
    /// swallowed.
    fn send_datagram(&self, bytes: &[u8]) -> LinkSendOutcome {
        let Some((addr, port)) = self.peer.get() else {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        match self.socket.send_to(addr, port, bytes) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static> BoxedLinkDriver
    for UdpDriver<S, B, T>
{
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        // UDP is unreliable; the session's reliable channel recovers a drop.
        self.send_datagram(bytes)
    }

    // The session encodes a frame straight into the driver's own storage, and the socket reads it
    // from there: the frame is written once and no buffer is allocated for it. The socket takes a
    // datagram whole and synchronously, so a slot is back at its send; a session that batches
    // holds one open beside the message it encodes next, which is why there can be two. An ask
    // with every slot out is refused, which the lend-only profile counts rather than answering
    // from the heap.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        let slots = self.tx.slots().min(u8::BITS as usize);
        if self.tx.slot_len() == 0 {
            return None;
        }
        let lent = self.tx_lent.get();
        let free = (0..slots).find(|slot| lent & (1 << slot) == 0)?;
        self.tx_lent.set(lent | (1 << free));
        // The socket writes the datagram's own headers, so the frame starts at the slot's front.
        Some(TxSlotGrant {
            slot: TxSlot(free as u32),
            headroom: 0,
        })
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        (self.tx.slot_base(slot.0 as usize), self.tx.slot_len())
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        let (base, capacity) = self.tx_slot_storage(slot);
        self.tx_slot_abort(slot);
        if start.checked_add(len).map_or(true, |end| end > capacity) {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        // SAFETY: `base` is the first byte of a slot of `self.tx`, `capacity` bytes long, and
        // `start + len` is within it. The slot was granted to the session alone and has just been
        // taken back by this call, so nothing else writes the bytes while the socket reads them.
        let frame = unsafe { core::slice::from_raw_parts(base.add(start), len) };
        self.send_datagram(frame)
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx_lent.set(self.tx_lent.get() & !(1 << slot.0));
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.get()
    }

    // A driver whose buffers are declared is bounded by them: the frame it sends is at most the
    // storage it lends, and the batch it advertises is at most the datagram it receives whole, as
    // lwIP's session socket declares its slot (`link_mtu` bounds the session's send budget, so a
    // message past it fragments instead of being encoded into a slot too short for it).
    fn link_mtu(&self) -> usize {
        if self.tx.lends() {
            self.tx.slot_len()
        } else {
            DEFAULT_LINK_MTU
        }
    }

    fn link_rx_capacity(&self) -> usize {
        if self.tx.lends() {
            self.rx_len
        } else {
            DEFAULT_LINK_MTU
        }
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static>
    SessionDatagramLink for UdpDriver<S, B, T>
{
    fn service(&self) {
        // The loop's thread owes the network stack the CPU while it has nothing to do. It gives
        // it by waiting for the socket, so a datagram is taken the moment it is queued, and a
        // quiet socket costs one millisecond, which is what bounds the loop's timers.
        //
        // A longer wait armed by `service_within` is put back to the tick first: whoever asks for
        // `service` asks for the tick.
        if !self.arm(SERVICE_WAIT_MS) {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        }
        self.wait_for_datagram();
    }

    fn uses_wake_budget(&self) -> bool {
        // A socket that cannot be armed waits the tick whatever the budget says, and an image
        // that has not raised the idle wait asked for the tick.
        S::CAN_SET_RECEIVE_TIMEOUT && self.idle_wait_ms > SERVICE_WAIT_MS as u32
    }

    fn service_within(&self, max_wait_ms: u64) {
        // The most this link may wait: what its session has due, and what its image allows. At
        // or below the tick it is the tick, which is every link that has not been given more.
        let want = max_wait_ms.min(u64::from(self.idle_wait_ms));
        if want <= SERVICE_WAIT_MS as u64 || !self.socket.times_out() {
            self.service();
            return;
        }
        // The timeout is armed at the largest power of two not above `want`, so a wait never ends
        // after the deadline it was computed from, and re-arming (a system call) happens only
        // when the deadline moves to another power of two: a link whose deadlines are seconds
        // away arms once, and the approach to a deadline costs one wake per halving, not one per
        // tick.
        let armed = 1u64 << (u64::BITS - 1 - want.leading_zeros());
        // `idle_wait_ms` is at most half of `c_int`'s range, so the power of two is inside it.
        if !self.arm(armed as c_int) {
            self.service();
            return;
        }
        self.wait_for_datagram();
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        match self.next_datagram(bytes) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                Some(RxFrame::new(bytes[..len].to_vec()))
            }
            Ok(None) => None,
            Err(e) => {
                self.rx_error.set(Some(e));
                None
            }
        }
    }

    // The datagram is lent out of the link's own receive buffer, which the
    // stack has just written: no heap copy of it. The buffer stays borrowed
    // while `f` runs; the session's sends go through the socket, not through
    // it, and a receive from inside `f` would be refused by the `RefCell`.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        match self.next_datagram(bytes) {
            Ok(Some((len, addr, port))) => {
                self.set_peer((addr, port));
                f(&bytes[..len]);
                true
            }
            Ok(None) => false,
            Err(e) => {
                self.rx_error.set(Some(e));
                false
            }
        }
    }
}

/// A platform's sockets as a stack of the slot profile's session host: the driver in the
/// session's slot is a [`FixedUdpDriver`] over the socket `S`, and the drive loop pumps it through
/// the driver itself ([`DriverPump`]), because the platform has no input path of its own for the
/// loop to advance (the kernel's threads, or the host's, run the network stack). Each session's
/// driver claims its receive buffer (as long as the batch the session advertises) and the buffer
/// its frames are encoded into (the largest frame it sends) from two tables the image declares, so
/// a dial moves a few words and no bytes, and the lengths are the tables' and not the type's.
///
/// Nothing is kept for a listener (`Lane` is `()`): the client node dials, and a node that accepts
/// would bring a lane of its own. The sockets are the platform's descriptors, so no pool of them
/// is declared here; a descriptor the platform cannot give is the dial's
/// [`LinkOpenError::Exhausted`], and the session host's tables bound how many are open at once.
#[cfg(feature = "session-slot")]
pub struct UdpStack<S> {
    local: [u8; 4],
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    /// What each driver this stack opens is allowed to wait for a datagram when its session has
    /// nothing due sooner ([`UdpDriver::with_idle_wait_ms`]).
    idle_wait_ms: u32,
    socket: PhantomData<fn() -> S>,
}

// Not derived: a derive would ask `S: Clone`, and the stack holds no socket, only the knowledge of
// which type opens them.
#[cfg(feature = "session-slot")]
impl<S> Clone for UdpStack<S> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "session-slot")]
impl<S> Copy for UdpStack<S> {}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> UdpStack<S> {
    /// The stack of a node whose own address is `local`, as its interface holds it, whose links
    /// take their receive buffers from `rx` and their frame buffers from `tx`.
    pub const fn new(
        local: [u8; 4],
        rx: &'static dyn ByteSource,
        tx: &'static dyn ByteSource,
    ) -> Self {
        Self {
            local,
            rx,
            tx,
            idle_wait_ms: SERVICE_WAIT_MS as u32,
            socket: PhantomData,
        }
    }

    /// Let the drivers of this stack wait up to `ms` milliseconds for a datagram when their
    /// session has nothing due sooner. The image says so when it has ONE session and nothing else
    /// its loop waits on: with several, a link that blocks for long would leave the others'
    /// sockets unread for as long. The default is the tick, which is what every image had.
    #[must_use]
    pub const fn with_idle_wait_ms(mut self, ms: u32) -> Self {
        self.idle_wait_ms = ms;
        self
    }

    /// The link of a dial to `peer`: a socket on a port the stack picks, with replies and first
    /// sends going to `peer`. What the session host's `dial` is given to open its socket. A table
    /// with no buffer free, like a platform with no descriptor, is [`LinkOpenError::Exhausted`],
    /// and whatever was claimed before the refusal goes back with it.
    pub fn bind_initiator(&self, peer: UdpPeer) -> Result<FixedUdpDriver<S>, LinkOpenError> {
        let rx = self.rx.claim().ok_or(LinkOpenError::Exhausted)?;
        let tx = self.tx.claim().ok_or(LinkOpenError::Exhausted)?;
        let socket = S::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
        Ok(
            UdpDriver::initiator_in(socket, (peer.addr, peer.port), rx, tx)
                .with_idle_wait_ms(self.idle_wait_ms),
        )
    }
}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> Bind<FixedUdpDriver<S>> for UdpStack<S> {
    fn bind(&mut self, peer: UdpPeer) -> Result<FixedUdpDriver<S>, LinkOpenError> {
        self.bind_initiator(peer)
    }
}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> SlotStack for UdpStack<S> {
    type Driver = FixedUdpDriver<S>;
    type Pump = DriverPump<FixedUdpDriver<S>>;
    type Lane = ();

    fn pump(
        &self,
        driver: wz_session_core::session_slot::SlotDriver<FixedUdpDriver<S>>,
        _lane: Option<()>,
    ) -> Self::Pump {
        DriverPump(driver)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// A datagram the test queues for the driver to receive: its bytes and its source.
    type Datagram = (Vec<u8>, [u8; 4], u16);
    /// A datagram the driver sent: where it went and its bytes.
    type Sent = ([u8; 4], u16, Vec<u8>);

    /// A socket that is two queues: what the test queues for the driver to receive, and what the
    /// driver sent. The datagram a `recv_waiting` takes is the same one `try_recv` would, so the
    /// driver's two receive paths are told apart by which method was called.
    #[derive(Default)]
    struct Loop {
        inbound: core::cell::RefCell<VecDeque<Datagram>>,
        sent: core::cell::RefCell<Vec<Sent>>,
        waits: Cell<u32>,
        waiting_reads: Cell<u32>,
        timeouts: bool,
        /// Whether `set_receive_timeout` takes a value, and the values it was asked to take.
        can_arm: bool,
        arms: core::cell::RefCell<Vec<c_int>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Refused;

    impl Loop {
        fn take(&self, buf: &mut [u8]) -> Option<(usize, [u8; 4], u16)> {
            let (bytes, addr, port) = self.inbound.borrow_mut().pop_front()?;
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Some((n, addr, port))
        }
    }

    impl DatagramSocket for Loop {
        type Error = Refused;

        fn bind(_addr: [u8; 4], _port: u16) -> Result<Self, Refused> {
            Ok(Loop::default())
        }

        fn local(&self) -> ([u8; 4], u16) {
            ([10, 0, 0, 2], 4000)
        }

        fn send_to(&self, addr: [u8; 4], port: u16, bytes: &[u8]) -> Result<(), Refused> {
            self.sent.borrow_mut().push((addr, port, bytes.to_vec()));
            Ok(())
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
        }

        fn times_out(&self) -> bool {
            self.timeouts
        }

        const CAN_SET_RECEIVE_TIMEOUT: bool = true;

        fn set_receive_timeout(&self, ms: c_int) -> bool {
            self.arms.borrow_mut().push(ms);
            self.can_arm
        }

        fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<(usize, [u8; 4], u16)>, Refused> {
            self.waiting_reads.set(self.waiting_reads.get() + 1);
            Ok(self.take(buf))
        }

        fn try_recv(&self, buf: &mut [u8]) -> Result<Option<(usize, [u8; 4], u16)>, Refused> {
            Ok(self.take(buf))
        }
    }

    const PEER: ([u8; 4], u16) = ([10, 0, 0, 1], 7447);

    fn queued(socket: &Loop, bytes: &[u8]) {
        socket
            .inbound
            .borrow_mut()
            .push_back((bytes.to_vec(), PEER.0, PEER.1));
    }

    /// The driver the tests of the wait and of the link's behaviour are made over: the heap
    /// profile's, with two outbound slots...
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn driver(socket: Loop) -> UdpDriver<Loop, Vec<u8>, HeapTx> {
        UdpDriver::acceptor_with_buffers(socket, 64, HeapTx::new(2, 32))
    }

    /// ...or the slot profile's, whose two buffers are claimed from tables the test declares
    /// (more cells than tests run at once) and go back when the driver is dropped.
    #[cfg(feature = "session-slot")]
    fn driver(socket: Loop) -> UdpDriver<Loop, ByteBuf, ByteBuf> {
        use wz_session_core::byte_cells::ByteCells;
        static RX: ByteCells<64, 64> = ByteCells::new();
        static TX: ByteCells<32, 64> = ByteCells::new();
        UdpDriver::acceptor_in(
            socket,
            RX.claim().expect("a receive buffer"),
            TX.claim().expect("a frame buffer"),
        )
    }

    #[test]
    fn an_acceptor_learns_its_peer_from_the_first_datagram_and_answers_it() {
        let link = driver(Loop::default());
        assert_eq!(link.peer(), None);
        assert!(link.link_endpoints().is_none());
        assert_eq!(
            link.send_blocking(b"early", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
            "a send with no peer is reported, not swallowed"
        );

        queued(&link.socket, b"hello");
        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"hello");
        assert_eq!(link.peer(), Some(PEER));
        let ends = link
            .link_endpoints()
            .expect("endpoints once the peer is known");
        assert_eq!(ends.src.as_str(), "udp/10.0.0.2:4000");
        assert_eq!(ends.dst.as_str(), "udp/10.0.0.1:7447");

        assert_eq!(
            link.send_blocking(b"reply", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            link.socket.sent.borrow().as_slice(),
            &[(PEER.0, PEER.1, b"reply".to_vec())]
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn an_initiator_sends_to_its_peer_before_it_has_heard_from_it() {
        let link = UdpDriver::initiator_with_capacity(Loop::default(), PEER, 64);
        assert_eq!(link.peer(), Some(PEER));
        assert_eq!(
            link.send_blocking(b"init", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn the_session_encodes_into_a_lent_slot_and_the_slot_returns_at_the_send() {
        let link = UdpDriver::initiator_with_buffers(Loop::default(), PEER, 64, HeapTx::new(2, 32));
        assert_eq!(
            link.link_mtu(),
            32,
            "the bound is the slot the driver lends"
        );
        assert_eq!(link.link_rx_capacity(), 64);

        let first = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("a first slot");
        let second = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("a second slot");
        assert_ne!(first.slot.0, second.slot.0);
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_none(),
            "every slot out is a refusal"
        );

        let (base, capacity) = link.tx_slot_storage(first.slot);
        assert_eq!(capacity, 32);
        // SAFETY: the slot was granted to this test alone and is 32 bytes long.
        unsafe { core::slice::from_raw_parts_mut(base, 3) }.copy_from_slice(b"abc");
        assert_eq!(
            link.tx_slot_send(first.slot, 0, 3, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Sent
        );
        assert_eq!(link.socket.sent.borrow()[0].2, b"abc");
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_some(),
            "the slot is back once it is sent"
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_send_past_the_slot_is_dropped_oversize_and_gives_the_slot_back() {
        let link = UdpDriver::initiator_with_buffers(Loop::default(), PEER, 64, HeapTx::new(1, 8));
        let grant = link.tx_slot_acquire(4, Priority::Data).expect("a slot");
        assert_eq!(
            link.tx_slot_send(grant.slot, 4, 5, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert!(link.socket.sent.borrow().is_empty());
        assert!(link.tx_slot_acquire(4, Priority::Data).is_some());
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_driver_with_no_storage_lends_nothing_and_states_the_default_bounds() {
        let link = UdpDriver::acceptor_with_capacity(Loop::default(), 64);
        assert!(link.tx_slot_acquire(10, Priority::Data).is_none());
        assert_eq!(link.link_mtu(), DEFAULT_LINK_MTU);
        assert_eq!(link.link_rx_capacity(), DEFAULT_LINK_MTU);
    }

    #[test]
    fn a_socket_whose_reads_time_out_is_read_once_by_the_wait_and_not_again_by_the_receive() {
        let socket = Loop {
            timeouts: true,
            ..Loop::default()
        };
        let link = driver(socket);
        queued(&link.socket, b"one");
        link.service();
        assert_eq!(link.socket.waiting_reads.get(), 1);
        assert_eq!(link.socket.waits.get(), 0, "the read is the wait");

        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"one");
        assert!(
            link.socket.inbound.borrow().is_empty(),
            "one datagram, taken once"
        );

        // A held datagram is not read over by the next pass.
        queued(&link.socket, b"two");
        link.service();
        link.service();
        assert_eq!(link.socket.waiting_reads.get(), 2);
    }

    #[test]
    fn a_socket_with_no_timeout_waits_and_the_receive_reads() {
        let link = driver(Loop::default());
        queued(&link.socket, b"one");
        link.service();
        assert_eq!(link.socket.waits.get(), 1);
        assert_eq!(link.socket.waiting_reads.get(), 0);
        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"one");
        assert!(!link.recv_with(&mut |_| unreachable!("nothing is queued")));
    }

    fn arming_socket() -> Loop {
        Loop {
            timeouts: true,
            can_arm: true,
            ..Loop::default()
        }
    }

    #[test]
    fn a_link_waits_in_the_largest_power_of_two_not_above_what_is_due_and_arms_once_per_step() {
        let link = driver(arming_socket()).with_idle_wait_ms(1000);
        for (due, armed) in [
            (5000u64, 512),
            (1000, 512),
            (700, 512),
            (511, 256),
            (100, 64),
            (3, 2),
        ] {
            link.service_within(due);
            assert_eq!(link.armed_wait_ms.get(), armed, "due in {due} ms");
        }
        // A deadline at the tick puts the tick back.
        link.service_within(1);
        assert_eq!(link.armed_wait_ms.get(), SERVICE_WAIT_MS);
        // Each power of two was asked of the socket once, in the order the deadline came in: 700
        // and 1000 found 512 already armed.
        assert_eq!(*link.socket.arms.borrow(), [512, 256, 64, 2, 1]);
        assert_eq!(
            link.socket.waiting_reads.get(),
            7,
            "every pass waited once, in the read"
        );
    }

    #[test]
    fn a_wait_never_ends_after_the_deadline_it_came_from_and_is_more_than_half_of_it() {
        for due in 2..=1000u64 {
            let link = driver(arming_socket()).with_idle_wait_ms(1000);
            link.service_within(due);
            let armed = link.armed_wait_ms.get() as u64;
            assert!(
                armed <= due,
                "armed {armed} ms for a deadline {due} ms away"
            );
            assert!(
                armed * 2 > due,
                "armed {armed} ms for a deadline {due} ms away"
            );
        }
    }

    #[test]
    fn the_image_caps_the_wait_and_without_its_leave_a_link_waits_the_tick() {
        let capped = driver(arming_socket()).with_idle_wait_ms(100);
        capped.service_within(60_000);
        assert_eq!(capped.armed_wait_ms.get(), 64, "capped at 100 ms, so 64");

        // The default is the tick: a deadline an hour away does not make this link wait.
        let default = driver(arming_socket());
        default.service_within(3_600_000);
        assert!(default.socket.arms.borrow().is_empty(), "no re-arming");
        assert_eq!(default.armed_wait_ms.get(), SERVICE_WAIT_MS);
        assert_eq!(default.socket.waiting_reads.get(), 1, "one tick's read");
    }

    #[test]
    fn a_service_asked_for_after_a_long_wait_puts_the_tick_back() {
        let link = driver(arming_socket()).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(link.armed_wait_ms.get(), 512);
        link.service();
        assert_eq!(link.armed_wait_ms.get(), SERVICE_WAIT_MS);
        assert_eq!(*link.socket.arms.borrow(), [512, 1]);
    }

    #[test]
    fn a_socket_that_cannot_be_armed_is_waited_on_for_the_tick() {
        let socket = Loop {
            timeouts: true,
            can_arm: false,
            ..Loop::default()
        };
        let link = driver(socket).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(
            link.armed_wait_ms.get(),
            SERVICE_WAIT_MS,
            "nothing was armed"
        );
        assert_eq!(link.socket.waiting_reads.get(), 1, "the tick's read, once");
    }

    #[test]
    fn a_socket_with_no_read_timeout_is_polled_for_the_tick_whatever_is_due() {
        let link = driver(Loop::default()).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(link.socket.waits.get(), 1);
        assert!(link.socket.arms.borrow().is_empty());
    }

    #[test]
    fn a_link_asks_the_loop_for_the_deadline_only_when_its_image_let_it_wait_longer() {
        assert!(
            !driver(arming_socket()).uses_wake_budget(),
            "the default is the tick"
        );
        assert!(!driver(arming_socket())
            .with_idle_wait_ms(1)
            .uses_wake_budget());
        assert!(driver(arming_socket())
            .with_idle_wait_ms(1000)
            .uses_wake_budget());
    }

    #[test]
    fn a_wait_asked_for_from_inside_a_receive_falls_back_to_the_socket_wait() {
        let socket = Loop {
            timeouts: true,
            ..Loop::default()
        };
        let link = driver(socket);
        queued(&link.socket, b"one");
        assert!(link.recv_with(&mut |_| link.service()));
        assert_eq!(link.socket.waits.get(), 1);
        assert_eq!(link.socket.waiting_reads.get(), 0);
    }

    #[cfg(feature = "session-slot")]
    mod stack {
        use super::*;
        use wz_session_core::byte_cells::ByteCells;

        static RX: ByteCells<64, 1> = ByteCells::new();
        static TX: ByteCells<32, 1> = ByteCells::new();

        #[test]
        fn a_dial_claims_both_buffers_and_a_table_with_none_free_refuses() {
            let mut stack = UdpStack::<Loop>::new([10, 0, 0, 2], &RX, &TX);
            let link = stack
                .bind(UdpPeer {
                    addr: PEER.0,
                    port: PEER.1,
                })
                .expect("the first dial");
            assert_eq!(link.peer(), Some(PEER));
            assert_eq!(link.link_mtu(), 32);
            assert_eq!(link.link_rx_capacity(), 64);
            assert!(matches!(
                stack.bind(UdpPeer {
                    addr: PEER.0,
                    port: PEER.1,
                }),
                Err(LinkOpenError::Exhausted)
            ));
            drop(link);
            assert!(
                stack
                    .bind(UdpPeer {
                        addr: PEER.0,
                        port: PEER.1,
                    })
                    .is_ok(),
                "the buffers go back with the driver"
            );
        }

        static LEND_RX: ByteCells<64, 1> = ByteCells::new();
        static LEND_TX: ByteCells<32, 1> = ByteCells::new();

        #[test]
        fn the_fixed_driver_lends_its_one_slot_and_takes_it_back_at_the_send() {
            let mut stack = UdpStack::<Loop>::new([10, 0, 0, 2], &LEND_RX, &LEND_TX);
            let link = stack
                .bind(UdpPeer {
                    addr: PEER.0,
                    port: PEER.1,
                })
                .expect("a dial");
            let grant = link
                .tx_slot_acquire(10, Priority::Data)
                .expect("the one slot");
            assert!(
                link.tx_slot_acquire(10, Priority::Data).is_none(),
                "a byte buffer is one slot, and it is out"
            );
            let (base, capacity) = link.tx_slot_storage(grant.slot);
            assert_eq!(capacity, 32);
            // SAFETY: the slot was granted to this test alone and is 32 bytes long.
            unsafe { core::slice::from_raw_parts_mut(base, 3) }.copy_from_slice(b"abc");
            assert_eq!(
                link.tx_slot_send(grant.slot, 0, 3, Reliability::Reliable, Priority::Data),
                LinkSendOutcome::Sent
            );
            assert_eq!(link.socket.sent.borrow()[0].2, b"abc");

            let again = link
                .tx_slot_acquire(10, Priority::Data)
                .expect("the slot is back once it is sent");
            assert_eq!(
                link.tx_slot_send(again.slot, 30, 5, Reliability::Reliable, Priority::Data),
                LinkSendOutcome::Dropped(LinkDropCause::Oversize),
                "a frame past the slot is refused, not truncated"
            );
            assert_eq!(link.socket.sent.borrow().len(), 1, "and nothing was sent");
            assert!(link.tx_slot_acquire(10, Priority::Data).is_some());
        }
    }
}
