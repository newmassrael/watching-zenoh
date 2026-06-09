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

/// The zenoh multicast scouting group, `224.0.0.224`, as a lwIP-native
/// (network-byte-order) u32 word — the host of zenoh-pico's
/// `Z_CONFIG_MULTICAST_LOCATOR_DEFAULT` (`udp/224.0.0.224:7446`). The
/// scout socket joins this group so it receives multicast Scout / Hello
/// datagrams; the port (7446) is the caller's `bind_scout_rx` argument.
pub const SCOUT_MULTICAST_GROUP: u32 = u32::from_le_bytes([224, 0, 0, 224]);

/// Session-rx queue depth (`Q`) — from the active session-rx buffer-pool
/// SSOT: default [`crate::session_rx_pool_mcu`] (16), or slim
/// [`crate::session_rx_pool_mcu_minimal`] (4) under
/// `buffer-pool-session-rx-slim`.
#[cfg(not(feature = "buffer-pool-session-rx-slim"))]
pub const SESSION_RX_SLOTS: usize = crate::session_rx_pool_mcu::SLOT_COUNT;
#[cfg(feature = "buffer-pool-session-rx-slim")]
pub const SESSION_RX_SLOTS: usize = crate::session_rx_pool_mcu_minimal::SLOT_COUNT;

/// Session-rx per-datagram payload cap (`N`) — from the same active SSOT.
/// Default 1536 (`>= udp_session.mtu_bytes`, full-MTU untruncated); slim
/// 256 (small-control-frame only, deliberately `< mtu_bytes` — see the
/// minimal scxml header).
#[cfg(not(feature = "buffer-pool-session-rx-slim"))]
pub const SESSION_RX_SLOT_SIZE: usize = crate::session_rx_pool_mcu::SLOT_SIZE;
#[cfg(feature = "buffer-pool-session-rx-slim")]
pub const SESSION_RX_SLOT_SIZE: usize = crate::session_rx_pool_mcu_minimal::SLOT_SIZE;

/// The session-link receive socket, pool-sized from the active session-rx
/// profile (default `session_rx_pool_mcu`, or `session_rx_pool_mcu_minimal`
/// under `buffer-pool-session-rx-slim`).
pub type SessionRxSocket = LwipUdpSocket<SESSION_RX_SLOT_SIZE, SESSION_RX_SLOTS>;

/// Bind the scouting-link receive socket on `port` with the scout pool's
/// dims and join the zenoh multicast scouting group
/// ([`SCOUT_MULTICAST_GROUP`], `224.0.0.224`) so the socket receives
/// multicast Scout / Hello datagrams — the MCU equivalent of the AP std
/// multicast socket. The deploy must have brought up a `NETIF_FLAG_IGMP`
/// netif before this call (the host smoke uses the loopback netif, gated
/// on `LWIP_LOOPIF_MULTICAST`).
///
/// # Errors
///
/// - [`LinkError::BindFailed`] / [`LinkError::PcbExhausted`] from the
///   underlying `udp_bind`.
/// - [`LinkError::MulticastJoinFailed`] if the IGMP join fails (no
///   IGMP-capable netif is up).
pub fn bind_scout_rx(link: &LwipLink, port: u16) -> Result<ScoutRxSocket, LinkError> {
    let sock = ScoutRxSocket::bind(link, port)?;
    link.join_multicast_group(SCOUT_MULTICAST_GROUP)?;
    Ok(sock)
}

/// Bind the session-link receive socket on `port` with the session pool's
/// dims (the deploy's `udp_session` unicast endpoint, `0.0.0.0:7447`).
pub fn bind_session_rx(link: &LwipLink, port: u16) -> Result<SessionRxSocket, LinkError> {
    SessionRxSocket::bind(link, port)
}

/// Multicast-session-rx queue depth (`Q`) — from the multicast session-rx
/// buffer-pool SSOT ([`crate::session_rx_pool_mcu_multicast`], 32 — twice
/// the unicast pool for the §3.1 multi-peer RxDispatch fan-in).
pub const SESSION_MULTICAST_RX_SLOTS: usize = crate::session_rx_pool_mcu_multicast::SLOT_COUNT;

/// Multicast-session-rx per-datagram payload cap (`N`) — from the same SSOT
/// (1536, `>= udp_session.mtu_bytes`, full-MTU untruncated; the multicast
/// data frame is the same wire shape as the unicast one).
pub const SESSION_MULTICAST_RX_SLOT_SIZE: usize = crate::session_rx_pool_mcu_multicast::SLOT_SIZE;

/// The multicast-session receive socket, pool-sized from
/// `session_rx_pool_mcu_multicast`. Distinct from [`SessionRxSocket`] (the
/// unicast session socket): a node can hold both at once, so they are
/// separate const-generic instances over separate pool SSOTs.
pub type SessionMulticastRxSocket =
    LwipUdpSocket<SESSION_MULTICAST_RX_SLOT_SIZE, SESSION_MULTICAST_RX_SLOTS>;

/// The default zenoh multicast TRANSPORT group, `224.0.0.224`
/// (`Z_CONFIG_MULTICAST_LOCATOR_DEFAULT` = `udp/224.0.0.224:7446`,
/// `~/zenoh-pico/include/zenoh-pico/config.h.in:133`). Numerically equal to
/// [`SCOUT_MULTICAST_GROUP`] because zenoh shares one multicast locator for
/// scouting AND the multicast transport; kept as a distinct named const so
/// the transport role is explicit and a deploy can override the group
/// independently of the scout group. The default port (7446) is the
/// `bind_session_multicast_rx` caller's argument.
pub const SESSION_MULTICAST_GROUP_DEFAULT: u32 = SCOUT_MULTICAST_GROUP;

/// Bind the MULTICAST session receive socket on `port` with the multicast
/// session pool's dims ([`SessionMulticastRxSocket`]) and join the
/// multicast `group` (default [`SESSION_MULTICAST_GROUP_DEFAULT`],
/// `224.0.0.224`) so the socket receives the §3.1 multicast transport
/// datagrams (Join / Frame / Fragment / KeepAlive / Close). The MCU mirror
/// of the AP `UdpDriver::bind_multicast_v4`; like [`bind_scout_rx`] it folds
/// bind + IGMP join so the two steps stay consistent, but it carries the
/// full-MTU data pool (not the small scout pool) and takes the group as a
/// parameter (the transport locator is deploy-configured). The deploy must
/// have brought up a `NETIF_FLAG_IGMP` netif before this call.
///
/// # Errors
///
/// - [`LinkError::BindFailed`] / [`LinkError::PcbExhausted`] from the
///   underlying `udp_bind`.
/// - [`LinkError::MulticastJoinFailed`] if the IGMP join fails (no
///   IGMP-capable netif is up).
pub fn bind_session_multicast_rx(
    link: &LwipLink,
    group: u32,
    port: u16,
) -> Result<SessionMulticastRxSocket, LinkError> {
    let sock = SessionMulticastRxSocket::bind(link, port)?;
    link.join_multicast_group(group)?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4_addr_loopback;

    /// The socket dims come from the buffer-pool SSOTs: scout 8 / 256
    /// (`scout_rx_pool_mcu.scxml`); session 16 / 1536 by default
    /// (`session_rx_pool_mcu.scxml`), or 4 / 256 under
    /// `buffer-pool-session-rx-slim` (`session_rx_pool_mcu_minimal.scxml`).
    /// This is the link-tier analog of reassembly_rx's
    /// `mcu_dims_come_from_the_buffer_pool_ssot`.
    #[test]
    fn rx_socket_dims_come_from_the_buffer_pool_ssot() {
        std::assert_eq!(SCOUT_RX_SLOTS, 8);
        std::assert_eq!(SCOUT_RX_SLOT_SIZE, 256);
        #[cfg(not(feature = "buffer-pool-session-rx-slim"))]
        {
            std::assert_eq!(SESSION_RX_SLOTS, 16);
            std::assert_eq!(SESSION_RX_SLOT_SIZE, 1536);
        }
        // The multicast session pool is independent of the slim toggle
        // (always 32 / 1536, twice the unicast Q for multi-peer fan-in).
        std::assert_eq!(SESSION_MULTICAST_RX_SLOTS, 32);
        std::assert_eq!(SESSION_MULTICAST_RX_SLOT_SIZE, 1536);
        #[cfg(feature = "buffer-pool-session-rx-slim")]
        {
            std::assert_eq!(SESSION_RX_SLOTS, 4);
            std::assert_eq!(SESSION_RX_SLOT_SIZE, 256);
        }
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

    /// The MCU mirror of the AP multicast scout socket: bind the scout
    /// socket (which joins 224.0.0.224), loop a Scout-sized datagram to
    /// the multicast group:port, and verify the recv callback delivers
    /// it. `lwip_test_link` routes multicast TX over the IGMP-capable
    /// loop netif, so this exercises the real lwIP IGMP accept path
    /// (`inp->flags & NETIF_FLAG_IGMP && igmp_lookfor_group`).
    #[test]
    fn scout_rx_multicast_loopback_round_trip() {
        let (_serial, link) = crate::lwip_test_link();
        let port: u16 = 7446;
        let mut sock: ScoutRxSocket =
            bind_scout_rx(&link, port).expect("bind scout rx + join 224.0.0.224");

        let payload: &[u8] = b"r311ir scout multicast hello";
        sock.send_to(SCOUT_MULTICAST_GROUP, port, payload)
            .expect("send_to 224.0.0.224");
        link.poll_loopback();
        link.check_timeouts();

        let dg = sock.try_recv().expect("expected one multicast datagram");
        std::assert_eq!(&dg.data[..], payload);
        std::assert_eq!(dg.src_port, port);
        std::assert_eq!(sock.rx_drop_count(), 0);

        // Symmetric leave succeeds (the group was joined on the loop netif).
        link.leave_multicast_group(SCOUT_MULTICAST_GROUP)
            .expect("leave 224.0.0.224");
    }

    /// Round B — the multicast SESSION transport socket: bind
    /// `bind_session_multicast_rx` (which joins the multicast group), loop a
    /// full-MTU-shaped data datagram to the group:port, and verify the recv
    /// callback delivers it into the 32 / 1536 multicast pool. The MCU
    /// mirror of the AP multicast session socket; exercises the same lwIP
    /// IGMP accept path as the scout test, but over the larger session-data
    /// pool. A distinct port (7448) from the scout (7446) / unicast (7447)
    /// tests; `lwip_test_link` serialises lwIP tests so the group membership
    /// does not race.
    #[test]
    fn session_multicast_rx_loopback_round_trip() {
        let (_serial, link) = crate::lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7448;
        let mut sock: SessionMulticastRxSocket = bind_session_multicast_rx(&link, group, port)
            .expect("bind multicast session rx + join 224.0.0.224");

        // A payload longer than the 256-byte scout slot, to exercise the
        // full-MTU session pool (1536) the scout pool could not hold.
        let payload: &[u8] = &[0x5Au8; 600];
        sock.send_to(group, port, payload)
            .expect("send_to 224.0.0.224");
        link.poll_loopback();
        link.check_timeouts();

        let dg = sock.try_recv().expect("expected one multicast datagram");
        std::assert_eq!(&dg.data[..], payload);
        std::assert_eq!(dg.src_port, port);
        std::assert_eq!(sock.rx_drop_count(), 0);

        link.leave_multicast_group(group)
            .expect("leave 224.0.0.224");
    }
}
