// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipUdpDriver` — the MCU [`BoxedLinkDriver`] adapter over a shared
//! [`SessionRxSocket`] (`LwipUdpSocket<SESSION_RX_SLOT_SIZE, _>`).

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use core::cell::{Cell, OnceCell, RefCell};

use wz_link_lwip::rx_sockets::{SessionRxSocket, SESSION_RX_SLOT_SIZE};
use wz_link_lwip::Datagram;
use wz_session_core::link::{BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome};
use wz_session_core::reliability::Reliability;

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
