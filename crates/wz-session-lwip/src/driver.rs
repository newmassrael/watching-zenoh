// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipUdpDriver` — the MCU [`BoxedLinkDriver`] adapter over a shared
//! [`SessionRxSocket`] (`LwipUdpSocket<SESSION_RX_SLOT_SIZE, _>`).

#[cfg(not(feature = "session-slot"))]
use alloc::rc::Rc;
use core::cell::{Cell, OnceCell, RefCell, UnsafeCell};
use core::mem::MaybeUninit;
use core::net::SocketAddr;
use core::ptr::addr_of_mut;

use wz_link_lwip::rx_sockets::{SessionRxSocket, SESSION_RX_SLOT_SIZE};
use wz_link_lwip::Datagram;
use wz_runtime_coop::session_drive::LinkProto;
use wz_session_core::datagram_peer::{DatagramVerdict, ForeignCounts, PeerBinding};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEnds, LinkSendOutcome, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

/// How many outbound slots this driver lends at once: the one it reserves for its
/// link, as zenoh-pico writes every frame of a transport into its one write
/// buffer. The deploy tables state it per link (`limits.tx_lend_slots`).
///
/// One is enough because the send gives the slot back before it returns: the bytes
/// written are copied into the pbuf lwIP sends (`LwipUdpSocket::send_to`, which
/// returns once lwIP has the datagram), so no frame still being sent holds the
/// slot when the next one asks for it. That leaves only what a session holds past
/// the call that took a slot: the batch window of its one conduit, which it drains
/// before it sends a transport message and before it opens the next frame. This is
/// why the lwIP link needs fewer slots than `SESSION_TX_SLOTS`, the count for a
/// link whose writer keeps a slot after the send call returns.
///
/// A lend past it is not granted: the session encodes on the heap, or under
/// `tx-lend-only` (fixed-memory step S4) refuses the send as a counted
/// `LinkDropCause::NoTxSlot`, which `tests/tx_allocations.rs` holds the slot to
/// witness. Public so that witness can pin the capacity it fills.
pub const LENT_MAX: usize = 1;

/// The session socket shared by the drive loop (inbound `try_recv` /
/// `recv_with`) and the FSM action layer (outbound `send_blocking` and the
/// lent sends). A single-task synchronous loop owns both seams. Every send
/// takes a SHARED borrow, because `recv_with` holds one across the dispatch
/// of the datagram it lends and the dispatch sends replies; only the dequeue
/// takes the exclusive one, and never while a datagram is lent. `Rc` (not
/// `Arc`) because the profile is `!Send`: this matches
/// [`wz_session_core::link::SessionRuntime::LinkSink`] = `Rc<dyn
/// BoxedLinkDriver>` on the lwIP MCU profile, so no atomic refcount traffic
/// is incurred on a profile that never crosses threads.
///
/// Under `session-slot` (fixed-memory step S5) it is not shared by pointer at all:
/// the driver holds its socket by value, and the one driver is what the drive
/// loop and the send seam both reach (through the slot that holds it), so there
/// is no `Rc` to allocate. A driver is either the sole owner of its socket (a
/// session that dials) or one of several sessions that read and send through
/// the one socket a listener holds (`SessionSocket`).
#[cfg(not(feature = "session-slot"))]
pub type SharedSessionSocket = Rc<RefCell<SessionRxSocket>>;
/// See the shared form of this alias.
#[cfg(feature = "session-slot")]
pub type SharedSessionSocket = SessionSocket;

/// Where a driver on the `session-slot` profile reaches its socket: the socket
/// it owns, or the listener's, which every session accepted on one port shares
/// (`crate::listener::SessionListener`). The driver is written against the
/// `RefCell` either way, so how many sessions use a socket changes nothing in how
/// one of them sends or reads.
#[cfg(feature = "session-slot")]
pub enum SessionSocket {
    /// The session's own socket, held by value in the slot that holds the driver.
    Owned(RefCell<SessionRxSocket>),
    /// The socket of the listener this session was accepted by.
    Listened(&'static RefCell<SessionRxSocket>),
}

#[cfg(feature = "session-slot")]
impl SessionSocket {
    /// The listener's socket, shared by every session accepted on it.
    pub fn listened(socket: &'static RefCell<SessionRxSocket>) -> Self {
        Self::Listened(socket)
    }
}

#[cfg(feature = "session-slot")]
impl core::ops::Deref for SessionSocket {
    type Target = RefCell<SessionRxSocket>;

    fn deref(&self) -> &RefCell<SessionRxSocket> {
        match self {
            Self::Owned(socket) => socket,
            Self::Listened(socket) => socket,
        }
    }
}

/// A bound session socket in the form [`LwipUdpDriver::new`] takes it: shared by
/// `Rc` on every profile but `session-slot`, by value under it.
pub fn share_socket(socket: SessionRxSocket) -> SharedSessionSocket {
    #[cfg(not(feature = "session-slot"))]
    {
        Rc::new(RefCell::new(socket))
    }
    #[cfg(feature = "session-slot")]
    {
        SessionSocket::Owned(RefCell::new(socket))
    }
}

/// The inbound datagram type the session socket delivers — payload capped
/// at `SESSION_RX_SLOT_SIZE` (the `session_rx_pool_mcu` buffer-pool SSOT).
pub type SessionDatagram = Datagram<SESSION_RX_SLOT_SIZE>;

/// MCU [`BoxedLinkDriver`] over one shared [`SessionRxSocket`].
///
/// The link has one peer, fixed once known
/// (`wz_session_core::datagram_peer::PeerBinding`): an initiator's from its
/// dial ([`Self::new`]), an acceptor's from the first `InitSyn` it takes
/// ([`Self::accepting`]). Every send goes to it and the session reads its
/// datagrams only. On a socket the driver owns, what anyone else sends is
/// discarded and counted ([`Self::foreign`]); on a listener's, which other
/// sessions read too, it is left where it is for them. UDP is connectionless,
/// so `open_blocking` / `close_blocking` are no-ops (the zenoh session
/// handshake + Close frame are the session-layer open/close, emitted by the
/// FSM action methods, not transport events).
pub struct LwipUdpDriver {
    socket: SharedSessionSocket,
    /// The peer every send targets, `addr` lwIP-native network-byte-order.
    /// Interior-mutable, so an acceptor is bound by its receive seam while the
    /// send seam reads it, both through `&self`.
    binding: PeerBinding<(u32, u16)>,
    /// R2841 — the link's two ends, the address lwIP routes to the peer from with
    /// this socket's port and the peer's: what upstream's admin space reports
    /// them by. Learnt ONCE, when the peer is known: at construction for an
    /// initiator, at the binding `InitSyn` for an acceptor. The peer never
    /// changes after, so neither do they.
    ends: OnceCell<(SocketAddr, SocketAddr)>,
    /// ARCHITECTURE section 9.1 — the link's one outbound slot, as wide as the
    /// datagram its socket carries. Reserved with the link and made where the link is
    /// kept ([`Self::new_in`]: its cell, or the session's slot on the
    /// `session-slot` profile), so no frame takes a buffer of lwIP's heap to be
    /// encoded in and no move of the driver carries the slot.
    tx_slot: UnsafeCell<[u8; SESSION_RX_SLOT_SIZE]>,
    /// Whether `tx_slot` is lent to the session and not yet sent or given back.
    tx_lent: Cell<bool>,
}

/// How the drive loop's link holds the driver it reads from: a counted handle on the cell the
/// driver lives in on every profile but `session-slot` (`wz_runtime_coop::link_cells`), the
/// handle the session's actions send through is a clone of; and under it a counted handle to the
/// slot that holds the driver, which keeps the slot for as long as the loop reads.
#[cfg(not(feature = "session-slot"))]
pub type DriverHandle = wz_runtime_coop::link_cells::CellRc<LwipUdpDriver>;
/// See the cell form of this alias.
#[cfg(feature = "session-slot")]
pub type DriverHandle = wz_session_core::session_slot::SlotDriver<LwipUdpDriver>;

/// An IPv4 address as lwIP holds it and a port, as the socket address the
/// cooperative engine names a link's end by.
fn socket_addr(addr: u32, port: u16) -> SocketAddr {
    SocketAddr::from((wz_link_lwip::ipv4_octets(addr), port))
}

impl LwipUdpDriver {
    /// The link of a session with `peer_addr:peer_port` over `socket`: an
    /// initiator's, which dialled it, or one a listener admitted for that
    /// peer's `InitSyn`.
    ///
    /// Under `rx-in-place` the socket is asked to hold the frames its MAC lends
    /// in place ([`recv_with`](Self::recv_with) reads them where they lie).
    ///
    /// Returned by value, with its outbound slot in it: for a host that keeps the
    /// driver itself. A node makes the driver where it is kept
    /// ([`Self::new_in`]), so the slot is never a value on the stack that opens
    /// the link.
    pub fn new(socket: SharedSessionSocket, peer_addr: u32, peer_port: u16) -> Self {
        let mut place = MaybeUninit::uninit();
        Self::new_in(&mut place, socket, peer_addr, peer_port);
        // SAFETY: `new_in` wrote every field of the place.
        unsafe { place.assume_init() }
    }

    /// The link of an acceptor that owns `socket`: no peer until the first
    /// `InitSyn` it takes names one. By value, as [`Self::new`] is; a node makes
    /// it in place ([`Self::accepting_in`]).
    pub fn accepting(socket: SharedSessionSocket) -> Self {
        let mut place = MaybeUninit::uninit();
        Self::accepting_in(&mut place, socket);
        // SAFETY: `accepting_in` wrote every field of the place.
        unsafe { place.assume_init() }
    }

    /// [`Self::new`], made in `place`, where the driver is kept (the cell of its
    /// link, the session's slot), and lent back from there.
    pub fn new_in(
        place: &mut MaybeUninit<Self>,
        socket: SharedSessionSocket,
        peer_addr: u32,
        peer_port: u16,
    ) -> &mut Self {
        Self::made_in(place, socket, PeerBinding::dialled((peer_addr, peer_port)))
    }

    /// [`Self::accepting`], made in `place`, as [`Self::new_in`] makes a dialled
    /// link.
    pub fn accepting_in(place: &mut MaybeUninit<Self>, socket: SharedSessionSocket) -> &mut Self {
        Self::made_in(place, socket, PeerBinding::accepting())
    }

    /// The driver written field by field into `place`, its outbound slot zeroed
    /// where it lies: the slot is as wide as a datagram, and built in a frame and
    /// moved it would be that much more of the stack of every path that opens a
    /// link.
    fn made_in(
        place: &mut MaybeUninit<Self>,
        socket: SharedSessionSocket,
        binding: PeerBinding<(u32, u16)>,
    ) -> &mut Self {
        #[cfg(feature = "rx-in-place")]
        socket.borrow_mut().hold_lent_rx(true);
        // A field added to the driver and not written below would be read uninitialised.
        // This names every field with no `..`, so adding one without naming it here (and
        // so without writing it below) does not compile.
        let _every_field_is_written = |driver: &Self| {
            let Self {
                socket: _,
                binding: _,
                ends: _,
                tx_slot: _,
                tx_lent: _,
            } = driver;
        };
        let at = place.as_mut_ptr();
        // SAFETY: `at` is the place, aligned for the driver and this call's alone; each
        // field is written once, in place, and the slot's bytes are zeroed through a
        // pointer to them (`UnsafeCell` lays out as the array it holds).
        unsafe {
            addr_of_mut!((*at).socket).write(socket);
            addr_of_mut!((*at).binding).write(binding);
            addr_of_mut!((*at).ends).write(OnceCell::new());
            addr_of_mut!((*at).tx_slot)
                .cast::<u8>()
                .write_bytes(0, SESSION_RX_SLOT_SIZE);
            addr_of_mut!((*at).tx_lent).write(Cell::new(false));
        }
        // SAFETY: every field of the driver was written above.
        let driver = unsafe { place.assume_init_mut() };
        driver.note_endpoints();
        driver
    }

    /// Record the link's ends once the peer is known. The source is the
    /// address lwIP routes to that peer from, with this socket's port. Asked
    /// once, here, so a reader of the ends asks lwIP nothing.
    fn note_endpoints(&self) {
        let Some((addr, port)) = self.binding.peer() else {
            return;
        };
        if addr == 0 || port == 0 || self.ends.get().is_some() {
            return;
        }
        let Some(src) = wz_link_lwip::route_source(addr) else {
            return;
        };
        let local_port = self.socket.borrow().local_port();
        let _ = self
            .ends
            .set((socket_addr(src, local_port), socket_addr(addr, port)));
    }

    /// The peer every send targets `(addr, port)`, once one is known.
    pub fn peer(&self) -> Option<(u32, u16)> {
        self.binding.peer()
    }

    /// The datagrams this link has discarded for not being its peer's. A link on
    /// a listener's socket discards none: what is not its peer's is another
    /// session's, and the listener counts what is no session's.
    pub fn foreign(&self) -> ForeignCounts {
        self.binding.foreign()
    }

    /// Whether the socket is a listener's, read by every session it accepted.
    fn shares_socket(&self) -> bool {
        #[cfg(feature = "session-slot")]
        {
            matches!(self.socket, SessionSocket::Listened(_))
        }
        #[cfg(not(feature = "session-slot"))]
        {
            false
        }
    }

    /// Decide the datagram at the head of the socket's queue: `Some(true)` when
    /// the session reads it (it is the peer's, or the `InitSyn` that has just
    /// bound an acceptor), `Some(false)` when it was not admitted and has been
    /// discarded, so the next head is to be decided, and `None` when the queue is
    /// empty or the head is another session's on a shared socket, which is left
    /// where it is.
    fn admit_head(&self) -> Option<bool> {
        let verdict = {
            let socket = self.socket.borrow();
            let head = socket.peek_recv()?;
            let source = (head.src_addr, head.src_port);
            if self.shares_socket() && !self.binding.is_peer(source) {
                return None;
            }
            self.binding.admit(source, head.data)
        };
        if verdict == DatagramVerdict::Bound {
            self.note_endpoints();
        }
        if verdict.is_taken() {
            return Some(true);
        }
        self.socket.borrow_mut().consume_recv();
        Some(false)
    }

    /// Non-blocking inbound dequeue of the peer's next datagram. The `RefCell`
    /// borrow is scoped to this call (the returned [`SessionDatagram`] is
    /// owned), so a `send_blocking` re-borrow inside the subsequent
    /// dispatch cannot collide. Returns `None` when nothing of the peer's is
    /// queued (the caller must drive the lwIP input path first).
    pub fn try_recv(&self) -> Option<SessionDatagram> {
        while !self.admit_head()? {}
        self.socket.borrow_mut().try_recv()
    }

    /// Lend the peer's oldest queued datagram to `f` where the socket's receive
    /// queue holds it, and remove it once `f` returns. `false` when nothing of
    /// the peer's is queued.
    ///
    /// [`Self::try_recv`] moves the datagram out of the queue, a
    /// `SESSION_RX_SLOT_SIZE` value that a caller then copies onto the heap
    /// or holds on its stack while it dispatches. This hands `f` the bytes in
    /// place instead. The socket is borrowed SHARED while `f` runs, so the
    /// dispatch inside it can send (every send takes a shared borrow); a
    /// receive from inside `f` would need the exclusive borrow and panics,
    /// which is the loud answer to a re-entrant receive.
    ///
    /// Under `rx-in-place` the socket also holds a frame its MAC lent in place
    /// (`wz_link_lwip`'s `rx-hold`, turned on by [`Self::new`]), so for such a
    /// frame the bytes `f` reads are the frame's own, where the controller wrote
    /// them, and removing it gives the MAC its buffer back.
    pub fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        loop {
            match self.admit_head() {
                None => return false,
                Some(false) => continue,
                Some(true) => break,
            }
        }
        {
            let socket = self.socket.borrow();
            let Some(datagram) = socket.peek_recv() else {
                return false;
            };
            f(datagram.data);
        }
        self.socket.borrow_mut().consume_recv()
    }
}

impl BoxedLinkDriver for LwipUdpDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        // UDP is unreliable; the `reliability` hint is honoured by the
        // zenoh session layer's SN-window retransmit, not at the datagram
        // seam. Best-effort send: a transient pbuf exhaustion drops the
        // datagram (the reliable channel recovers it), mirroring the AP
        // adapter which enqueues without a synchronous delivery guarantee.
        //
        // R2371 — that drop is now REPORTED rather than swallowed. lwIP's
        // `send_to` failing is pbuf exhaustion or a dead netif, both of which
        // mean the writer cannot take the bytes, so the cause is `WriterGone`;
        // the MCU profile has no `transport-stats` build, but the seam must
        // still tell the truth for the lanes that assert on it. An acceptor
        // with no peer yet has no one to send to, which is the same report.
        let Some((addr, port)) = self.binding.peer() else {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        // A shared borrow: a send happens while `recv_with` lends a received
        // datagram out of the same socket.
        match self.socket.borrow().send_to(addr, port, bytes) {
            Ok(_) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    // ARCHITECTURE section 9.1 — lend the session the slot this link reserved, so
    // the frame is encoded once and no frame takes a buffer of its own to be
    // encoded in. The slot is the whole datagram width whatever `want` says: a
    // lend-only session asks for its batch budget for every frame, and the slot is
    // never past what the socket carries. No headroom: lwIP writes the UDP, IP and
    // Ethernet headers in front of the pbuf the send copies the frame into.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        if self.tx_lent.replace(true) {
            return None;
        }
        Some(TxSlotGrant {
            slot: TxSlot(0),
            headroom: 0,
        })
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        debug_assert!(
            slot.0 == 0 && self.tx_lent.get(),
            "a slot the session names is a slot this driver lent"
        );
        (self.tx_slot.get().cast::<u8>(), SESSION_RX_SLOT_SIZE)
    }

    // The bytes written leave through the copying send, into a pbuf of their own (a
    // slot of the transmit pool when one is installed) rather than a pbuf that
    // refers to this slot: a MAC that reads a frame in place keeps its pbuf past the
    // send, and this slot is lent again for the next frame at once.
    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        debug_assert!(
            slot.0 == 0 && self.tx_lent.get(),
            "a slot the session names is a slot this driver lent"
        );
        // SAFETY: the session's lease of the slot ended with this call, and the slot
        // is lent again only once `tx_lent` is cleared below, after the send, so
        // nothing writes it while these bytes are read.
        let reserved: &[u8; SESSION_RX_SLOT_SIZE] = unsafe { &*self.tx_slot.get() };
        let outcome = match start
            .checked_add(len)
            .and_then(|end| reserved.get(start..end))
        {
            Some(frame) => self.send_blocking(frame, reliability),
            None => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
        };
        self.tx_lent.set(false);
        outcome
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        debug_assert_eq!(
            slot.0, 0,
            "a slot the session names is a slot this driver lent"
        );
        self.tx_lent.set(false);
    }

    fn open_blocking(&self) {
        // UDP is connectionless: the session "open" is the zenoh-layer
        // InitSyn / OpenSyn handshake, not a transport connect.
    }

    fn close_blocking(&self) {
        // Symmetric with open_blocking: no transport teardown for UDP. The
        // session Close frame is emitted by the FSM action layer.
    }

    // The addresses are lent as they are; a reader that reports the link writes its locators.
    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        let &(local, peer) = self.ends.get()?;
        Some(LinkEnds::ip(LinkProto::Udp.kind(), local, peer))
    }

    // The widest datagram this socket carries, either way: it receives at most
    // `SESSION_RX_SLOT_SIZE` bytes per datagram and its outbound slot is that
    // wide. Declaring it bounds the session's send budget
    // (`min(link mtu, negotiated batch)`), so a message
    // past it fragments, or is refused as oversize, instead of being encoded
    // into a lend too short to hold it. Under `buffer-pool-session-rx-slim` it
    // is 256 bytes, below any batch size a handshake negotiates.
    fn link_mtu(&self) -> usize {
        SESSION_RX_SLOT_SIZE
    }

    // The same slot bounds what arrives: a datagram past it does not fit the
    // slot it is received into. Declaring it caps the batch size this node
    // advertises, so the slim profile tells its peer 256 rather than the
    // configured 1024 it could never receive.
    fn link_rx_capacity(&self) -> usize {
        SESSION_RX_SLOT_SIZE
    }
}

// The driver's tests share sockets and drivers by `Rc`, the form every profile
// but `session-slot` has; the slot profile's own are in `tests/`.
#[cfg(all(test, not(feature = "session-slot")))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    use wz_link_lwip::ipv4_addr_loopback;
    // Round 3277 -- the binder of `test_bind`: the constructor itself by default, a
    // leaked pool of one on `static-link-storage`, so these tests run on both.
    use wz_link_lwip::test_bind::session_rx as bind_session_rx;
    use wz_session_core::link::LinkEndsText;
    use wz_session_core::tx_lease::TxLease;

    /// A driver whose peer is its own socket, so what it sends loops back.
    fn looped(link: &wz_link_lwip::LwipLink, port: u16) -> LwipUdpDriver {
        let socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(link, port).expect("bind session rx"),
        ));
        LwipUdpDriver::new(socket, ipv4_addr_loopback(), port)
    }

    /// Everything the loopback netif delivered, as payloads.
    fn delivered(link: &wz_link_lwip::LwipLink, driver: &LwipUdpDriver) -> Vec<Vec<u8>> {
        link.poll_loopback();
        link.check_timeouts();
        let mut out = Vec::new();
        while let Some(dg) = driver.try_recv() {
            out.push(dg.data[..].to_vec());
        }
        out
    }

    /// The datagram a frame written into the reserved slot becomes is the datagram
    /// the copying send makes of the same bytes: the lend changes where the bytes
    /// are written and nothing on the wire.
    #[test]
    fn a_frame_written_into_the_reserved_slot_is_the_datagram_the_copying_send_makes() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7480);
        let frame: &[u8] = b"a frame encoded straight into the link's slot";

        let mut lease =
            TxLease::acquire(&driver, frame.len(), Priority::DEFAULT).expect("the slot is lent");
        std::assert!(lease.capacity() >= frame.len());
        lease.frame_mut().append(frame).expect("fits the slot");
        std::assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );
        let lent = delivered(&link, &driver);

        std::assert_eq!(
            driver.send_blocking(frame, Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let copied = delivered(&link, &driver);

        std::assert_eq!(lent, copied, "same bytes on the wire either way");
        std::assert_eq!(lent, std::vec![frame.to_vec()]);
    }

    /// The datagram is the bytes written and not the size asked for: only what the
    /// session wrote is copied into the pbuf that is sent.
    #[test]
    fn the_datagram_is_the_bytes_written_not_the_size_asked_for() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7481);

        // The whole slot the socket can carry, whatever its width in this build:
        // the default pool is 1536 bytes and the slim one 256, so a fixed size
        // would be capped differently in each leg of the feature matrix.
        let asked = SESSION_RX_SLOT_SIZE;
        let mut lease =
            TxLease::acquire(&driver, asked, Priority::DEFAULT).expect("the slot is lent");
        std::assert!(lease.capacity() >= asked, "room for what was asked");
        std::assert!(
            asked > b"short".len(),
            "CONTROL: the ask is larger than the write"
        );
        lease.frame_mut().append(b"short").expect("fits");
        std::assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );

        std::assert_eq!(delivered(&link, &driver), std::vec![b"short".to_vec()]);
    }

    /// A lend given back unsent sends nothing, and the slot is lent again.
    #[test]
    fn an_abandoned_lend_sends_nothing_and_frees_the_slot() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7482);

        for _ in 0..3 {
            let mut lease = TxLease::acquire(&driver, 64, Priority::DEFAULT)
                .expect("the slot came back after each abandoned lend");
            lease.frame_mut().append(b"never sent").expect("fits");
            drop(lease);
        }
        std::assert!(delivered(&link, &driver).is_empty());
    }

    /// The one reserved slot is all that is lent at once, and a refused lend is
    /// not an error: it is the session's cue to encode on the heap.
    #[test]
    fn no_more_than_the_reserved_slot_is_lent_at_once() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7483);

        std::assert_eq!(LENT_MAX, 1, "one slot per link");
        let first = driver
            .tx_slot_acquire(32, Priority::DEFAULT)
            .expect("the reserved slot");
        std::assert_eq!(first.headroom, 0, "lwIP puts its own headers in front");
        std::assert!(
            driver.tx_slot_acquire(32, Priority::DEFAULT).is_none(),
            "a second is not lent while the first is out"
        );
        driver.tx_slot_abort(first.slot);
        let again = driver
            .tx_slot_acquire(32, Priority::DEFAULT)
            .expect("the returned slot is lent again");
        std::assert_eq!(again.slot, first.slot);
        driver.tx_slot_abort(again.slot);
    }

    /// The slot is the link's own memory, reserved with it: the same bytes at every
    /// lend, inside the driver, the whole width the socket carries whatever was
    /// asked, and lending it takes nothing of lwIP's.
    #[test]
    fn the_reserved_slot_is_lent_whole_and_is_the_links_own_memory() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7484);

        let small = driver
            .tx_slot_acquire(1, Priority::DEFAULT)
            .expect("a lend");
        let (at, capacity) = driver.tx_slot_storage(small.slot);
        std::assert_eq!(
            capacity,
            SESSION_RX_SLOT_SIZE,
            "the whole slot, asked for one byte"
        );
        driver.tx_slot_abort(small.slot);

        let large = driver
            .tx_slot_acquire(1_000_000, Priority::DEFAULT)
            .expect("a lend");
        let (again, capacity) = driver.tx_slot_storage(large.slot);
        std::assert_eq!(
            capacity,
            SESSION_RX_SLOT_SIZE,
            "and never past the socket's width"
        );
        std::assert_eq!(again, at, "the same memory at every lend");
        let own = &driver as *const LwipUdpDriver as usize;
        let inside = own..own + core::mem::size_of::<LwipUdpDriver>();
        std::assert!(
            inside.contains(&(at as usize)) && inside.contains(&(at as usize + capacity - 1)),
            "the slot lies inside the link's driver"
        );
        driver.tx_slot_abort(large.slot);
    }

    /// A driver made in place keeps its outbound slot where it was made: the slot a
    /// lend names lies inside the place it was handed, zeroed there, so a node that
    /// makes its link in its cell carries no slot through the frames that open it.
    #[test]
    fn a_driver_made_in_place_lends_the_slot_inside_its_place() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, 7489).expect("bind session rx"),
        ));
        let mut place = std::boxed::Box::new(MaybeUninit::<LwipUdpDriver>::uninit());
        let start = place.as_ptr() as usize;
        let inside = start..start + core::mem::size_of::<LwipUdpDriver>();
        {
            let driver = LwipUdpDriver::new_in(&mut place, socket, ipv4_addr_loopback(), 7489);
            std::assert_eq!(
                driver as *const LwipUdpDriver as usize,
                start,
                "the driver is the place it was handed"
            );
            let grant = driver
                .tx_slot_acquire(8, Priority::DEFAULT)
                .expect("the slot");
            let (at, capacity) = driver.tx_slot_storage(grant.slot);
            std::assert!(
                inside.contains(&(at as usize)) && inside.contains(&(at as usize + capacity - 1)),
                "the slot lies inside the place"
            );
            // SAFETY: the slot is lent to this test, which reads it and writes nothing.
            let bytes = unsafe { core::slice::from_raw_parts(at, capacity) };
            std::assert!(bytes.iter().all(|&b| b == 0), "zeroed where it lies");
            driver.tx_slot_abort(grant.slot);
        }
        // SAFETY: `new_in` wrote the driver, which nothing refers to any more.
        unsafe { place.assume_init_drop() };
    }

    /// A send from the slot on a link with no peer yet is dropped, and the slot
    /// comes back with the drop.
    #[test]
    fn a_send_with_no_peer_is_dropped_and_gives_the_slot_back() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, 7487).expect("bind session rx"),
        ));
        let driver = LwipUdpDriver::accepting(socket);

        let grant = driver
            .tx_slot_acquire(8, Priority::DEFAULT)
            .expect("a lend before any peer");
        std::assert_eq!(
            driver.tx_slot_send(grant.slot, 0, 4, Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        );
        let again = driver
            .tx_slot_acquire(8, Priority::DEFAULT)
            .expect("the slot came back with the drop");
        driver.tx_slot_abort(again.slot);
    }

    /// A send that names bytes past the slot is refused as oversize, puts nothing
    /// on the wire, and the slot comes back.
    #[test]
    fn a_send_past_the_slot_is_refused_as_oversize_and_gives_the_slot_back() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7488);

        let grant = driver
            .tx_slot_acquire(8, Priority::DEFAULT)
            .expect("a lend");
        std::assert_eq!(
            driver.tx_slot_send(
                grant.slot,
                0,
                SESSION_RX_SLOT_SIZE + 1,
                Reliability::Reliable,
                Priority::DEFAULT
            ),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        std::assert!(
            delivered(&link, &driver).is_empty(),
            "nothing reached the wire"
        );
        let again = driver
            .tx_slot_acquire(8, Priority::DEFAULT)
            .expect("the slot came back with the refusal");
        driver.tx_slot_abort(again.slot);
    }

    // ---- `rx-in-place`: the datagram the loop dispatches is the lent frame ----

    /// The buffers a lending MAC double has lent and not had back, by cookie.
    #[cfg(feature = "rx-in-place")]
    type LentBuffers = Rc<RefCell<Vec<(u32, Vec<u8>)>>>;

    /// A MAC that lends each received frame out of a buffer of its own and records
    /// which come back.
    #[cfg(feature = "rx-in-place")]
    struct Lending {
        inbox: Rc<RefCell<alloc::collections::VecDeque<Vec<u8>>>>,
        lent: LentBuffers,
        returned: Rc<RefCell<Vec<u32>>>,
    }

    #[cfg(feature = "rx-in-place")]
    impl wz_link_lwip::ethernet::EthernetMac for Lending {
        fn mac_address(&self) -> [u8; 6] {
            [0x02, 0, 0, 0, 0, 0x2a]
        }
        fn transmit(&mut self, _frame: &[u8]) -> bool {
            true
        }
        fn receive(&mut self, _buf: &mut [u8]) -> Option<usize> {
            None
        }
        fn loans_rx(&self) -> bool {
            true
        }
        fn receive_loan(&mut self) -> Option<wz_runtime_core::RxLoan> {
            let frame = self.inbox.borrow_mut().pop_front()?;
            let cookie = self.lent.borrow().len() as u32 + self.returned.borrow().len() as u32;
            let (ptr, len) = (frame.as_ptr(), frame.len());
            self.lent.borrow_mut().push((cookie, frame));
            Some(wz_runtime_core::RxLoan { ptr, len, cookie })
        }
        fn return_rx(&mut self, cookie: u32) {
            self.lent.borrow_mut().retain(|(c, _)| *c != cookie);
            self.returned.borrow_mut().push(cookie);
        }
    }

    /// A UDP datagram on the wire to `10.9.2.1:dst` from `10.9.2.2:7601`, with no
    /// UDP checksum (zero, which IPv4 allows).
    #[cfg(feature = "rx-in-place")]
    fn udp_frame(dst: u16, payload: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x45, 0x00]);
        ip.extend_from_slice(&(28 + payload.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 10, 9, 2, 2, 10, 9, 2, 1]);
        let mut sum: u32 = ip
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let mut f = Vec::new();
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x2a, 0x02, 0, 0, 0, 0, 0x2b, 0x08, 0x00]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&7601u16.to_be_bytes());
        f.extend_from_slice(&dst.to_be_bytes());
        f.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// The receive the `rx-in-place` loop makes reads a datagram a MAC lent WHERE
    /// THE MAC WROTE IT: the driver's socket holds the lent frame, the bytes handed
    /// to the dispatch lie inside the MAC's own buffer, and the buffer goes back to
    /// the MAC when the datagram is removed, not before.
    #[cfg(feature = "rx-in-place")]
    #[test]
    fn the_in_place_receive_reads_a_lent_frame_in_the_macs_buffer() {
        use wz_link_lwip::ethernet::Ipv4Config;
        use wz_link_lwip::test_bind::add_netif;

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let inbox = Rc::new(RefCell::new(alloc::collections::VecDeque::new()));
        let lent = Rc::new(RefCell::new(Vec::new()));
        let returned = Rc::new(RefCell::new(Vec::new()));
        let mut node = add_netif(
            &link,
            Lending {
                inbox: inbox.clone(),
                lent: lent.clone(),
                returned: returned.clone(),
            },
            Ipv4Config {
                address: [10, 9, 2, 1],
                netmask: [255, 255, 255, 0],
                gateway: [0, 0, 0, 0],
            },
        )
        .expect("interface");
        let socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, 7485).expect("bind session rx"),
        ));
        // The link of a session with the frame's sender: only the peer's
        // datagrams are handed over.
        let peer = (wz_link_lwip::ipv4_addr_from_octets([10, 9, 2, 2]), 7601);
        let driver = LwipUdpDriver::new(socket, peer.0, peer.1);

        let payload = b"dispatched where the MAC wrote it";
        inbox.borrow_mut().push_back(udp_frame(7485, payload));
        std::assert_eq!(node.poll(), 1);
        let buffer = {
            let lent = lent.borrow();
            let (_, frame) = lent.first().expect("the frame is still lent");
            (frame.as_ptr() as usize, frame.len())
        };

        let mut seen: Option<(usize, Vec<u8>)> = None;
        std::assert!(driver.recv_with(&mut |bytes| {
            seen = Some((bytes.as_ptr() as usize, bytes.to_vec()));
        }));
        let (at, bytes) = seen.expect("the dispatch ran");
        std::assert_eq!(bytes, payload);
        std::assert_eq!(
            at,
            buffer.0 + 14 + 20 + 8,
            "the bytes are the MAC's buffer, behind the headers"
        );
        std::assert!(at + bytes.len() <= buffer.0 + buffer.1);
        std::assert_eq!(*returned.borrow(), std::vec![0u32], "given back once read");
        std::assert!(lent.borrow().is_empty());
        std::assert_eq!(driver.peer(), Some(peer));
    }

    /// A link names both its ends in the cooperative engine's locator text, each
    /// whole: the peer it was given, and the address lwIP routes to it from with
    /// the socket's port.
    #[test]
    fn a_link_names_its_ends_in_the_cooperative_engines_locator_text() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7486);
        let ends = driver.link_endpoints().expect("a dialled link has ends");
        let expected = LinkEnds::ip(
            LinkProto::Udp.kind(),
            SocketAddr::from(([127, 0, 0, 1], 7486)),
            SocketAddr::from(([127, 0, 0, 1], 7486)),
        )
        .endpoints()
        .expect("an IPv4 pair is held");
        std::assert_eq!(ends, expected);
        std::assert_eq!(ends.dst, "udp/127.0.0.1:7486");
    }
}
