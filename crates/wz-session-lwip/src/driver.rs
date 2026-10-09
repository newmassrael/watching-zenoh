// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipUdpDriver` — the MCU [`BoxedLinkDriver`] adapter over a shared
//! [`SessionRxSocket`] (`LwipUdpSocket<SESSION_RX_SLOT_SIZE, _>`).

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::{Cell, OnceCell, RefCell};

use wz_link_lwip::rx_sockets::{SessionRxSocket, SESSION_RX_SLOT_SIZE};
use wz_link_lwip::{Datagram, TxPayload};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

/// How many outbound payloads this driver may have lent at once. The session
/// encodes and sends one frame under its conduit lock, so one is in flight at a
/// time; the second is for a lend that is open while another path reaches the
/// driver, and a lend beyond them is simply not granted (the session encodes on
/// the heap).
const LENT_MAX: usize = 2;

/// The session socket shared by the drive loop (inbound `try_recv`) and
/// the FSM action layer (outbound `send_blocking`). A single-task
/// synchronous loop owns both seams, so the two `RefCell` borrows never
/// overlap — `try_recv` returns an owned [`Datagram`] (its borrow released
/// at the call site) before dispatch re-borrows for a send. `Rc` (not
/// `Arc`) because the profile is `!Send`: this matches
/// [`wz_session_core::link::SessionRuntime::LinkSink`] = `Rc<dyn
/// BoxedLinkDriver>` on the lwIP MCU profile, so no atomic refcount traffic
/// is incurred on a profile that never crosses threads.
pub type SharedSessionSocket = Rc<RefCell<SessionRxSocket>>;

/// The inbound datagram type the session socket delivers — payload capped
/// at `SESSION_RX_SLOT_SIZE` (the `session_rx_pool_mcu` buffer-pool SSOT).
pub type SessionDatagram = Datagram<SESSION_RX_SLOT_SIZE>;

/// MCU [`BoxedLinkDriver`] over one shared [`SessionRxSocket`].
///
/// Outbound sends target a peer captured from the most recent inbound
/// datagram: the acceptor learns its peer from the InitSyn source, and
/// [`Self::set_peer`] retargets each tick so the InitAck / OpenAck /
/// data-plane replies route back to whoever just spoke. UDP is
/// connectionless, so `open_blocking` / `close_blocking` are no-ops (the
/// zenoh session handshake + Close frame are the session-layer open/close,
/// emitted by the FSM action methods, not transport events).
pub struct LwipUdpDriver {
    socket: SharedSessionSocket,
    /// `(addr, port)` the next send targets. `addr` is lwIP-native
    /// network-byte-order. `Cell` (interior-mutable) so the `&self` send
    /// seam and the loop's per-tick [`Self::set_peer`] share it without a
    /// `&mut` driver.
    peer: Cell<(u32, u16)>,
    /// R2841 — the link's two ends as upstream's admin space reports them,
    /// `udp/<ip>:<port>` each. Written ONCE, when the peer is first known: at
    /// construction for an initiator, at the first datagram for an acceptor.
    /// Once written it is the link; a later datagram from elsewhere does not
    /// rename it.
    endpoints: OnceCell<LinkEndpoints>,
    /// ARCHITECTURE section 9.1 — the payload buffers lent to the session and not
    /// yet sent or given back, by slot number. Single-task, so a `RefCell`.
    lent: RefCell<[Option<TxPayload>; LENT_MAX]>,
}

/// `udp/a.b.c.d:port`, zenoh's rendering of a UDP locator.
fn udp_locator(addr: u32, port: u16) -> String {
    let [a, b, c, d] = wz_link_lwip::ipv4_octets(addr);
    format!("udp/{a}.{b}.{c}.{d}:{port}")
}

impl LwipUdpDriver {
    /// Wrap `socket` with an initial send target. An acceptor passes a
    /// placeholder that the first inbound datagram overwrites (via
    /// [`Self::set_peer`]); an initiator passes its configured peer.
    pub fn new(socket: SharedSessionSocket, peer_addr: u32, peer_port: u16) -> Self {
        let driver = Self {
            socket,
            peer: Cell::new((peer_addr, peer_port)),
            endpoints: OnceCell::new(),
            lent: RefCell::new([const { None }; LENT_MAX]),
        };
        driver.note_endpoints(peer_addr, peer_port);
        driver
    }

    /// Retarget subsequent sends. The drive loop calls this with each
    /// inbound datagram's `(src_addr, src_port)` so replies go back to the
    /// peer that just spoke — the acceptor reply path.
    pub fn set_peer(&self, addr: u32, port: u16) {
        self.peer.set((addr, port));
        self.note_endpoints(addr, port);
    }

    /// Record the link's ends the first time a real peer is known. The source
    /// is the address lwIP routes to that peer from, with this socket's port.
    fn note_endpoints(&self, addr: u32, port: u16) {
        if addr == 0 || port == 0 || self.endpoints.get().is_some() {
            return;
        }
        let Some(src) = wz_link_lwip::route_source(addr) else {
            return;
        };
        let local_port = self.socket.borrow().local_port();
        let _ = self.endpoints.set(LinkEndpoints::new(
            udp_locator(src, local_port),
            udp_locator(addr, port),
        ));
    }

    /// The currently-configured send target `(addr, port)`.
    pub fn peer(&self) -> (u32, u16) {
        self.peer.get()
    }

    /// Non-blocking inbound dequeue from the shared socket. The `RefCell`
    /// borrow is scoped to this call (the returned [`SessionDatagram`] is
    /// owned), so a `send_blocking` re-borrow inside the subsequent
    /// dispatch cannot collide. Returns `None` when the per-socket rx queue
    /// is empty (the caller must drive the lwIP input path first).
    pub fn try_recv(&self) -> Option<SessionDatagram> {
        self.socket.borrow_mut().try_recv()
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
        // still tell the truth for the lanes that assert on it.
        let (addr, port) = self.peer.get();
        match self.socket.borrow_mut().send_to(addr, port, bytes) {
            Ok(_) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    // ARCHITECTURE section 9.1 — lend the session the memory of the pbuf lwIP will
    // send, so the frame is encoded once, into the datagram itself.
    //
    // `send_blocking` is handed bytes already written somewhere else, so it
    // allocates a pbuf and copies them in. A pbuf allocated at the transport layer
    // has the room for the UDP, IP and Ethernet headers in front of its payload,
    // so lwIP writes those in place and the frame that reaches a MAC is one
    // contiguous piece. The headers are lwIP's, not the session's, so the
    // headroom the session must leave is none.
    fn tx_slot_acquire(&self, want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        let mut lent = self.lent.borrow_mut();
        let index = lent.iter().position(Option::is_none)?;
        // `want` is a hint (the codec's worst case); the socket caps it at the
        // width it could receive, and an encode that outgrows what was lent falls
        // back to the heap.
        lent[index] = Some(self.socket.borrow().alloc_tx_payload(want)?);
        Some(TxSlotGrant {
            slot: TxSlot(index as u32),
            headroom: 0,
        })
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.lent.borrow()[slot.0 as usize]
            .as_ref()
            .expect("a slot the session names is a slot this driver lent")
            .storage()
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        let payload = self.lent.borrow_mut()[slot.0 as usize]
            .take()
            .expect("a slot the session names is a slot this driver lent");
        // No headroom was asked for, so the frame starts at the payload.
        debug_assert_eq!(start, 0, "this driver lends with no headroom");
        let (addr, port) = self.peer.get();
        match self
            .socket
            .borrow_mut()
            .send_tx_payload(payload, start + len, addr, port)
        {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        // Dropping the payload gives the pbuf back to lwIP.
        drop(self.lent.borrow_mut()[slot.0 as usize].take());
    }

    fn open_blocking(&self) {
        // UDP is connectionless: the session "open" is the zenoh-layer
        // InitSyn / OpenSyn handshake, not a transport connect.
    }

    fn close_blocking(&self) {
        // Symmetric with open_blocking: no transport teardown for UDP. The
        // session Close frame is emitted by the FSM action layer.
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    use wz_link_lwip::ipv4_addr_loopback;
    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_session_core::tx_buf::TxBuf;
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

    /// The datagram a frame written into the lent pbuf becomes is the datagram the
    /// copying send makes of the same bytes: the lend changes where the bytes are
    /// written and nothing on the wire.
    #[test]
    fn a_frame_written_into_the_lent_pbuf_is_the_datagram_the_copying_send_makes() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7480);
        let frame: &[u8] = b"a frame encoded straight into the pbuf lwIP sends";

        let mut lease =
            TxLease::acquire(&driver, frame.len(), Priority::DEFAULT).expect("lwIP lends a pbuf");
        std::assert!(lease.capacity() >= frame.len());
        lease.append(frame).expect("fits the lent pbuf");
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
        std::assert_eq!(
            wz_link_lwip::tx_payloads_out(),
            0,
            "a sent lend is settled: lwIP holds the pbuf, the driver does not"
        );
    }

    /// The datagram is the bytes written and not the size asked for: the pbuf is
    /// shrunk to what the session wrote before it is sent.
    #[test]
    fn the_datagram_is_the_bytes_written_not_the_size_asked_for() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7481);

        // The whole slot the socket can carry, whatever its width in this build:
        // the default pool is 1536 bytes and the slim one 256, so a fixed size
        // would be capped differently in each leg of the feature matrix.
        let asked = SESSION_RX_SLOT_SIZE;
        let mut lease =
            TxLease::acquire(&driver, asked, Priority::DEFAULT).expect("lwIP lends a pbuf");
        std::assert!(lease.capacity() >= asked, "room for what was asked");
        std::assert!(
            asked > b"short".len(),
            "CONTROL: the ask is larger than the write"
        );
        lease.append(b"short").expect("fits");
        std::assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );

        std::assert_eq!(delivered(&link, &driver), std::vec![b"short".to_vec()]);
    }

    /// A lend given back unsent sends nothing and gives lwIP its pbuf back.
    #[test]
    fn an_abandoned_lend_sends_nothing_and_frees_its_place() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7482);

        for _ in 0..(LENT_MAX * 3) {
            let mut lease = TxLease::acquire(&driver, 64, Priority::DEFAULT)
                .expect("the place came back after each abandoned lend");
            lease.append(b"never sent").expect("fits");
            std::assert_eq!(wz_link_lwip::tx_payloads_out(), 1, "out while held");
            drop(lease);
            std::assert_eq!(
                wz_link_lwip::tx_payloads_out(),
                0,
                "and given back to lwIP when abandoned"
            );
        }
        std::assert!(delivered(&link, &driver).is_empty());
    }

    /// Only so many payloads are lent at once, and a refused lend is not an error:
    /// it is the session's cue to encode on the heap.
    #[test]
    fn no_more_than_the_table_holds_is_lent_at_once() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7483);

        let first = driver
            .tx_slot_acquire(32, Priority::DEFAULT)
            .expect("first lend");
        let second = driver
            .tx_slot_acquire(32, Priority::DEFAULT)
            .expect("second lend");
        std::assert_ne!(first.slot, second.slot);
        std::assert_eq!(first.headroom, 0, "lwIP puts its own headers in front");
        std::assert!(
            driver.tx_slot_acquire(32, Priority::DEFAULT).is_none(),
            "a third is not lent"
        );
        driver.tx_slot_abort(first.slot);
        let again = driver
            .tx_slot_acquire(32, Priority::DEFAULT)
            .expect("a returned place is lent again");
        std::assert_eq!(again.slot, first.slot);
        driver.tx_slot_abort(again.slot);
        driver.tx_slot_abort(second.slot);
    }

    /// The lent size is capped at the width the socket could receive, as the
    /// copying send truncates to it: a socket does not send what it cannot take.
    #[test]
    fn the_lent_size_is_capped_at_the_width_the_socket_can_receive() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let driver = looped(&link, 7484);

        let grant = driver
            .tx_slot_acquire(1_000_000, Priority::DEFAULT)
            .expect("a capped lend");
        let (_, capacity) = driver.tx_slot_storage(grant.slot);
        std::assert_eq!(capacity, SESSION_RX_SLOT_SIZE);
        driver.tx_slot_abort(grant.slot);
    }
}
