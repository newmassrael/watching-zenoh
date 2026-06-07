// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ip — the MCU link tier's pool-sized receive sockets.
//!
//! This is the link-tier sibling of `wz-runtime-lwip::reassembly_rx`. Just
//! as that seam parameterizes the `ReassemblyDispatcher` const generics
//! from the `reassembly_pool_mcu` buffer-pool SSOT, this module
//! parameterizes the [`LwipUdpSocket`] const generics from the
//! scout / session rx buffer-pool SSOTs:
//!
//! - `N` (per-datagram payload capacity) <- pool `SLOT_SIZE`
//! - `Q` (callback-to-application rx-queue depth) <- pool `SLOT_COUNT`
//!
//! The dims live once, in the `sce:kind="buffer-pool"` documents
//! (`sources/network/{scout_rx,session_rx}_pool_mcu.scxml`), and flow
//! mechanically to the socket types via SCE codegen — the same SSOT
//! pattern that closed the reassembly pool's triple-drift. Before this
//! module, `LwipUdpSocket` only had the hand-tuned defaults
//! ([`MAX_DATAGRAM`] / [`RX_QUEUE_DEPTH`]); the deploy's per-link pool
//! dims (`deploy/mcu_target.yaml` `mcu_node.buffer_pools`) were a
//! separate, unconsumed copy.
//!
//! ## Usage (the MCU main loop)
//!
//! ```ignore
//! let link = wz_link_lwip::LwipLink::init();
//! let mut session_rx = wz_link_lwip::rx_sockets::bind_session_rx(&link, 7447)?;
//! // each cooperative tick, after driving the lwIP input path:
//! while let Some(dg) = session_rx.try_recv() { /* decode + dispatch */ }
//! ```
//!
//! [`LwipUdpSocket`]: crate::LwipUdpSocket
//! [`MAX_DATAGRAM`]: crate::MAX_DATAGRAM
//! [`RX_QUEUE_DEPTH`]: crate::RX_QUEUE_DEPTH

use crate::{LinkError, LwipLink, LwipUdpSocket};

/// Scout-rx queue depth (`Q`) — the dispatcher-side rx-queue slot count,
/// from the SCE-codegen'd buffer-pool SSOT ([`crate::scout_rx_pool_mcu`]).
pub const SCOUT_RX_SLOTS: usize = crate::scout_rx_pool_mcu::SLOT_COUNT;

/// Scout-rx per-datagram payload cap (`N`) — from the same SSOT. Sized to
/// `udp_scout.expected_p99_bytes`; a scout datagram above this is
/// truncated by the receive copy (best-effort scouting retries).
pub const SCOUT_RX_SLOT_SIZE: usize = crate::scout_rx_pool_mcu::SLOT_SIZE;

/// The scouting-link receive socket, pool-sized from `scout_rx_pool_mcu`.
pub type ScoutRxSocket = LwipUdpSocket<SCOUT_RX_SLOT_SIZE, SCOUT_RX_SLOTS>;

/// Session-rx queue depth (`Q`) — from the SCE-codegen'd buffer-pool SSOT
/// ([`crate::session_rx_pool_mcu`]).
pub const SESSION_RX_SLOTS: usize = crate::session_rx_pool_mcu::SLOT_COUNT;

/// Session-rx per-datagram payload cap (`N`) — from the same SSOT. Sized
/// `>= udp_session.mtu_bytes` so a full-MTU datagram fits untruncated.
pub const SESSION_RX_SLOT_SIZE: usize = crate::session_rx_pool_mcu::SLOT_SIZE;

/// The session-link receive socket, pool-sized from `session_rx_pool_mcu`.
pub type SessionRxSocket = LwipUdpSocket<SESSION_RX_SLOT_SIZE, SESSION_RX_SLOTS>;

/// Bind the scouting-link receive socket on `port` with the scout pool's
/// dims. (Multicast group join for the deploy's `224.0.0.224:7446` scout
/// endpoint is a separate lwIP IGMP concern, not yet wired; binding
/// `IP_ADDR_ANY:port` receives unicast to the port today.)
pub fn bind_scout_rx(link: &LwipLink, port: u16) -> Result<ScoutRxSocket, LinkError> {
    ScoutRxSocket::bind(link, port)
}

/// Bind the session-link receive socket on `port` with the session pool's
/// dims (the deploy's `udp_session` unicast endpoint, `0.0.0.0:7447`).
pub fn bind_session_rx(link: &LwipLink, port: u16) -> Result<SessionRxSocket, LinkError> {
    SessionRxSocket::bind(link, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4_addr_loopback;

    /// The socket dims come from the buffer-pool SSOTs: scout 8 / 256
    /// (`scout_rx_pool_mcu.scxml`), session 16 / 1536
    /// (`session_rx_pool_mcu.scxml`). This is the link-tier analog of
    /// reassembly_rx's `mcu_dims_come_from_the_buffer_pool_ssot`.
    #[test]
    fn rx_socket_dims_come_from_the_buffer_pool_ssot() {
        std::assert_eq!(SCOUT_RX_SLOTS, 8);
        std::assert_eq!(SCOUT_RX_SLOT_SIZE, 256);
        std::assert_eq!(SESSION_RX_SLOTS, 16);
        std::assert_eq!(SESSION_RX_SLOT_SIZE, 1536);
    }

    /// Driving the session rx socket exactly as the MCU main loop will:
    /// bind to the deploy session port, loopback a datagram, and verify
    /// the recv callback delivers it into the pool-sized rx queue.
    #[test]
    fn session_rx_socket_loopback_round_trip() {
        // One-time lwIP init + serialize against the lib.rs `mod smoke`
        // lwIP test (NO_SYS=1 global state; `lwip_init` not re-entrant).
        let (_serial, link) = crate::lwip_test_link();
        let port: u16 = 7447;
        let mut sock: SessionRxSocket =
            bind_session_rx(&link, port).expect("bind session rx ANY:7447");

        let payload: &[u8] = b"r311ip session-rx pool-sized socket";
        sock.send_to(ipv4_addr_loopback(), port, payload)
            .expect("send_to 127.0.0.1");
        link.poll_loopback();
        link.check_timeouts();

        let dg = sock.try_recv().expect("expected one datagram");
        std::assert_eq!(&dg.data[..], payload);
        std::assert_eq!(dg.src_port, port);
        std::assert_eq!(sock.rx_drop_count(), 0);
    }
}
