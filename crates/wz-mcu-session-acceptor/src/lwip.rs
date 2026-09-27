// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The e2e's lwIP topology: both endpoints on one lwIP `NO_SYS` loopback.
//!
//! Gated on the `lwip` feature AND on `lwip_real_build` (set by build.rs from
//! the lwip-sys `DEP_LWIP_LWIP_REAL_BUILD` metadata). Without the latter — a
//! cross build with no `WZ_LWIP_PORT` — `wz::session_lwip` is empty, so the
//! module collapses to nothing rather than failing to resolve. Mirrors
//! wz-link-lwip / wz-session-lwip.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use wz::link_lwip::rx_sockets::{bind_session_rx, SESSION_RX_SLOT_SIZE};
use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};
use wz::session_lwip::driver::SharedSessionSocket;
use wz::session_lwip::{LwipSessionLink, LwipUdpDriver};
use wz_session_core::link::BoxedLinkDriver;

use crate::{
    run_acceptor_e2e_on, AcceptorE2eReport, AcceptorTopology, ClockSource, DataMode, PEER_PORT,
    SESSION_PORT,
};

/// Rx queue depth of the reactive peer socket. The peer receives only the
/// acceptor's session-control replies (InitAck, then OpenAck) one per drive
/// iteration, so at most 2 are ever outstanding; 4 is ample headroom. Kept
/// small (vs the default 8) so that under `buffer-pool-session-rx-slim` the
/// peer is a ~1 KB endpoint, not a ~12 KB one — the 2nd socket that has to
/// shrink for the whole e2e to fit microbit's 16 KB SRAM.
const PEER_RX_SLOTS: usize = 4;

/// The acceptor and the crafted peer as two sockets on one lwIP loopback.
pub struct LwipTopology {
    link: Rc<LwipLink>,
    driver: Rc<LwipUdpDriver>,
    peer: LwipUdpSocket<SESSION_RX_SLOT_SIZE, PEER_RX_SLOTS>,
}

impl LwipTopology {
    /// Bring lwIP up and bind both endpoints.
    pub fn new() -> Self {
        let link = Rc::new(LwipLink::init());

        // ── The acceptor: a session rx socket wrapped in the MCU
        //    BoxedLinkDriver. The initial peer target is a placeholder the
        //    first inbound datagram overwrites via set_peer (the
        //    acceptor-reply path).
        //
        //    R2915 — port 0, not PEER_PORT. It used to be PEER_PORT, so the
        //    "placeholder" was already the right answer and the reply path was
        //    never exercised: with the retarget removed from the drive loop's
        //    lwIP link, this whole e2e still reached Established. An acceptor
        //    cannot know its peer before the InitSyn, and now this one does not
        //    either; port 0 also leaves the link's endpoints unrecorded until
        //    then.
        let acceptor_sock: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, SESSION_PORT).expect("bind acceptor session rx"),
        ));
        let driver = Rc::new(LwipUdpDriver::new(acceptor_sock, ipv4_addr_loopback(), 0));

        // ── The reactive crafted peer: a second real loopback endpoint. Sized
        //    off the ACTIVE session-rx slot size (SESSION_RX_SLOT_SIZE: 1536
        //    default, 256 under buffer-pool-session-rx-slim) since it only
        //    receives the acceptor's session-control replies (InitAck /
        //    OpenAck, <= the session slot size), with the slim PEER_RX_SLOTS
        //    depth. Under the slim feature this is the 2nd endpoint that
        //    shrinks (~12 KB -> ~1 KB), so the whole two-endpoint e2e fits
        //    microbit's 16 KB SRAM.
        let peer = LwipUdpSocket::bind(&link, PEER_PORT).expect("bind peer socket");

        Self { link, driver, peer }
    }
}

impl Default for LwipTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptorTopology for LwipTopology {
    type Link = LwipSessionLink<Rc<LwipLink>>;

    fn acceptor_sink(&self) -> Rc<dyn BoxedLinkDriver> {
        self.driver.clone()
    }

    fn acceptor_link(&self) -> Self::Link {
        LwipSessionLink::new(self.link.clone(), self.driver.clone())
    }

    fn peer_send(&mut self, bytes: &[u8]) {
        let _ = self.peer.send_to(ipv4_addr_loopback(), SESSION_PORT, bytes);
    }

    fn peer_try_recv(&mut self) -> Option<Vec<u8>> {
        // Pull what the acceptor enqueued this iteration through the loopback
        // netif; `poll_loopback` is idempotent (the drive loop pumps it too).
        self.link.poll_loopback();
        self.peer.try_recv().map(|dg| dg.data.as_slice().to_vec())
    }
}

/// The acceptor e2e over lwIP — [`run_acceptor_e2e_on`] with a fresh
/// [`LwipTopology`]. The signature every lwIP caller (the host tests, the
/// bare-metal and FreeRTOS images) has always written.
pub fn run_acceptor_e2e<C, E, H>(
    clock_source: C,
    entropy: E,
    data_mode: DataMode,
    on_fragment: H,
) -> AcceptorE2eReport
where
    C: ClockSource,
    E: wz_session_core::entropy::EntropySource + Send + 'static,
    H: FnMut(),
{
    run_acceptor_e2e_on(
        LwipTopology::new(),
        clock_source,
        entropy,
        data_mode,
        on_fragment,
    )
}
