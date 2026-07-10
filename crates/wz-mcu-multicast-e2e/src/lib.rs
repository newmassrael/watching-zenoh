// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]
// Whole crate gated on `lwip_real_build` (set by build.rs from the lwip-sys
// `DEP_LWIP_LWIP_REAL_BUILD` metadata). Without it — a cross build with no
// `WZ_LWIP_PORT` — `wz::session_lwip::multicast_drive` is empty, so
// `run_multicast_session` does not exist; the gate collapses the body to
// nothing rather than failing to resolve. Mirrors wz-link-lwip /
// wz-session-lwip / wz-mcu-session-acceptor.
#![cfg(lwip_real_build)]

//! wz-mcu-multicast-e2e — the MCU multicast transport e2e SSOT (R311mi).
//!
//! [`run_multicast_e2e`] exercises the full MCU multicast feature profile end
//! to end over a REAL lwIP loopback, through the Stage 4b
//! [`wz::session_lwip::multicast_drive::run_multicast_session`] sync drive
//! loop. The multicast machinery is the shared [`wz_session_core`] SSOT; this
//! crate is only the e2e TOPOLOGY + verdict, factored into one
//! `ClockSource`-generic function so the host integration test and the
//! `deploy/mcu-multicast-e2e` footprint bin share a single implementation.
//!
//! ## The scenario (the full profile in one round trip)
//!
//! 1. **transport-multicast** — a crafted peer JOIN (a `zid` distinct from
//!    ours so it is not own-zid-filtered, advertising the same `batch_size`
//!    so [`validate_join`](wz_session_core::multicast_join) admits it) is
//!    injected onto the group from our own socket. Multicast loopback
//!    delivers it back, creating the §3.2 peer entry keyed by our
//!    `(src_addr, src_port)`.
//! 2. **transport-fragmentation (TX)** — an oversize `z_put` queued on the
//!    loop's `next_tx` pull-seam exceeds the (deliberately tiny, 64-byte)
//!    `batch_size`, so the shared `multicast_tx_emit` SSOT splits it into a
//!    `T_MID_FRAGMENT` chain that is multicast to the group.
//! 3. **reassembly (RX) + codec-push** — the echoed fragments attribute to
//!    the pre-admitted peer, mint consecutive SNs from the JOIN's advertised
//!    `next_sn 0` so the per-peer SN gate admits the chain in order, and the
//!    R311mf Fragment RX arm reassembles + re-parses them back into the SAME
//!    single `Push` the whole-`T_MID_FRAME` path would fan.
//!
//! ## Runtime proof: the host lane AND the on-target QEMU lane (R311y190)
//!
//! Multicast self-loopback needs `LWIP_LOOPIF_MULTICAST` + `LWIP_TESTMODE` +
//! `ip4_set_default_multicast_netif(netif_get_loopif())`. The HOST lwIP port
//! ships these, so the host integration test (using
//! [`wz_link_lwip::lwip_test_link`]'s routed link + a frozen clock) is ONE home
//! for this round trip. R311y190 added the SECOND home: the `loopback-multicast`
//! deploy build routes the loop netif via the no_std
//! [`LwipLink::route_multicast_over_loopback`] seam against the testmode
//! `lwip-sys/port/cross-test-mcast` port, so the deploy bin runs the SAME round
//! trip ON-TARGET (Cortex-M3/M4/M7 under QEMU, run-ci Layer Q.6). That is a
//! LOOPBACK transport-plumbing proof on the real CPU — NOT real-network multicast
//! (a production deploy joins on its ethernet netif; QEMU mps2 has no peer NIC,
//! so loopback is the on-target CI ceiling). WITHOUT `loopback-multicast` the
//! deploy bin passes a plain [`LwipLink::init`] link and stays build +
//! footprint-size only (`join_ok=false` on QEMU). The caller supplies the
//! [`LwipLink`] so this one function serves the host lane, the footprint
//! artifact, AND the on-target QEMU proof.

extern crate alloc;

use alloc::vec::Vec;

use wz::link_lwip::rx_sockets::{bind_session_multicast_rx, SESSION_MULTICAST_GROUP_DEFAULT};
use wz::runtime_coop::CoopRuntime;
use wz::session_lwip::multicast_drive::{run_multicast_session, LwipMulticastDriver};

// Re-export the trait a consumer must impl to supply monotonic time, so the
// host test and the bin depend only on THIS crate (single-dep facade
// boundary) rather than reaching into the wz facade themselves.
pub use wz::runtime_coop::ClockSource;
// Re-export the link handle so the deploy bin constructs the `&LwipLink` this
// function takes (a plain `LwipLink::init()`) without naming the wz facade —
// the same single-dep boundary. (The host test instead builds a routed link
// via the wz-link-lwip test-support `lwip_test_link`.)
pub use wz::link_lwip::LwipLink;
// Re-export the drive outcome so the host test asserts the SPECIFIC terminal
// (`IterationLimit`) without a direct wz-session-core dep (same single-dep
// boundary as the acceptor's ReassemblyDropReason re-export).
pub use wz_session_core::multicast_params::MulticastOutcome;

use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_params::{MulticastDriveConfig, MulticastParams};
use wz_session_core::multicast_tx::{multicast_put_literal, multicast_tx_emit, MulticastTxItem};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::sn::{self, TxSn};
use wz_session_core::WhatAmI;

/// The multicast transport group + port the e2e binds + multicasts to:
/// `224.0.0.224:7446` (zenoh's `Z_CONFIG_MULTICAST_LOCATOR_DEFAULT`).
const PORT: u16 = 7446;
/// The bounded peer-table capacity for the dispatcher. One peer (ours, at the
/// loopback source) is admitted; 4 is ample headroom.
const MAX_PEERS: usize = 4;
/// Iteration cap on the drive loop. The fragment chain completes within the
/// first few iterations (one fragment delivered per loopback poll); the
/// remainder spin the (frozen-clock no-op) JOIN/sweep branches. Bounds a
/// regression so a stuck loop fails fast instead of hanging.
const MAX_ITERS: usize = 32;
/// The tiny group-wide frame budget that forces the oversize Put to fragment.
/// `validate_join` admits a peer JOIN only when its advertised `batch_size`
/// matches the receiver's, so BOTH the self params and the crafted peer JOIN
/// carry this value (a mismatch would silently reject the JOIN and the echoed
/// fragments would hit an `UnknownPeer` drop).
const BATCH_SIZE: u16 = 64;
/// The oversize payload length. 200 bytes exceeds the 64-byte batch budget
/// (so the frame fragments) while staying under the owned-push codec's
/// payload cap — the same sizing the AP + C1m fragmentation tests use.
const PAYLOAD_LEN: usize = 200;
/// The literal keyexpr the Put publishes on.
const KEYEXPR: &str = "demo/mc";
/// Our own zenoh id (the §3.2 self key; own-zid JOINs are beacon-filtered).
const SELF_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
/// The crafted peer's zenoh id — distinct from ours so its JOIN is admitted
/// (not own-zid-filtered), creating the peer entry the echoed fragments match.
const PEER_ZID: &[u8] = &[0x01, 0x02, 0x03, 0x04];

/// The full e2e result: the multicast drive [`MulticastOutcome`] plus the
/// per-stage signals. The host test asserts the strong combination
/// (`peer_admitted` + `tx_fragmented` + `saw_push` + `!saw_drop`); the deploy
/// bin maps it to a semihost exit code (and prints the fields so a degraded
/// run is locatable on target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastE2eReport {
    /// The drive loop's terminal outcome. `None` when the multicast socket
    /// bind/join failed (no IGMP netif — the deploy bin booted on an
    /// environment without multicast, e.g. QEMU loopback; the loop never
    /// ran). `Some(IterationLimit)` on a clean bounded run.
    pub outcome: Option<MulticastOutcome>,
    /// `bind_session_multicast_rx` succeeded — the socket bound AND the IGMP
    /// group join succeeded. False on an environment with no IGMP-capable
    /// netif up (the loop is not driven; the rest of the report is inert).
    pub join_ok: bool,
    /// The oversize Put split into >1 datagram at the 64-byte budget — proven
    /// by a pre-loop `multicast_tx_emit` probe, so a passing `saw_push`
    /// exercised the Fragment RX arm, not the whole-Frame arm.
    pub tx_fragmented: bool,
    /// Exactly one peer (the crafted JOIN at our loopback source) is in the
    /// §3.2 table after the run — our own beacon is zid-filtered.
    pub peer_admitted: bool,
    /// The §3.2 peer-table population after the run (1 on success).
    pub active_peers: usize,
    /// The reassembled fragment chain surfaced as a `Push` `FramePayload` —
    /// the codec-push + reassembly RX data-plane proof.
    pub saw_push: bool,
    /// A reassembly chain was dropped at ingest (out-of-order / capacity /
    /// `UnknownPeer`). Must be false: the in-order chain reassembles cleanly.
    pub saw_drop: bool,
}

/// Drive the MCU multicast transport e2e to a verdict over the supplied
/// [`LwipLink`].
///
/// `link` is the lwIP link the loop pumps. The host test passes a
/// [`wz_link_lwip::lwip_test_link`] link (multicast TX routed over the
/// IGMP-capable loop netif, so the self-loopback round trip is observable);
/// the deploy bin's `loopback-multicast` build routes multicast over the loop
/// netif too (via [`LwipLink::route_multicast_over_loopback`] on the testmode
/// `cross-test-mcast` port), so `join_ok` + the round trip succeed ON-TARGET
/// under QEMU (Layer Q.6); its plain [`LwipLink::init`] default build routes
/// nothing, so `join_ok` comes back false on QEMU (footprint artifact) and true
/// only on real hardware with an IGMP netif.
///
/// `clock_source` is the monotonic time the [`CoopRuntime`] reads. The host
/// test passes a frozen clock (no JOIN-interval / lease deadline ever
/// elapses, so the run is fully deterministic — the fragment chain is
/// delivered FIFO over loopback and reassembles in order); the deploy bin
/// passes its SysTick clock.
pub fn run_multicast_e2e<C: ClockSource>(link: &LwipLink, clock_source: C) -> MulticastE2eReport {
    let group = SESSION_MULTICAST_GROUP_DEFAULT;

    // ── Bind the multicast RX socket + join the group. On an environment
    //    without an IGMP-capable netif (the deploy bin on QEMU loopback) this
    //    fails; report join_ok=false and return — the loop has nothing to
    //    drive. On the host (routed loop netif) and on real IGMP hardware it
    //    succeeds.
    let mut socket = match bind_session_multicast_rx(link, group, PORT) {
        Ok(sock) => sock,
        Err(_) => {
            return MulticastE2eReport {
                outcome: None,
                join_ok: false,
                tx_fragmented: false,
                peer_admitted: false,
                active_peers: 0,
                saw_push: false,
                saw_drop: false,
            };
        }
    };

    // ── Pre-admit a peer at OUR loopback source: a JOIN with a zid distinct
    //    from ours (so it is admitted, not own-zid-filtered) advertising
    //    next_sn 0 on a fresh ring, and the SAME batch_size as ours (a
    //    mismatch would fail validate_join -> the echoed fragments would hit
    //    an UnknownPeer drop). Injected BEFORE wrapping the socket in the
    //    driver so the loop's first poll delivers it ahead of our own beacon
    //    echo, creating the (src_addr, src_port) entry the fragments match.
    let mut peer = params(PEER_ZID);
    peer.batch_size = BATCH_SIZE;
    let peer_join = encode_join(&peer, &TxSn::new(sn::mask_from_res(peer.seq_num_res)));
    let _ = socket.send_to(group, PORT, &peer_join);

    let mut driver = LwipMulticastDriver::new(socket, group, PORT);
    let mut dispatcher = MulticastDispatcher::<MAX_PEERS>::new(MulticastConfig::new(5_000));
    let runtime = CoopRuntime::new(clock_source);
    let mut self_params = params(SELF_ZID);
    self_params.batch_size = BATCH_SIZE;

    // The oversize payload: deterministic bytes, length 200 > batch_size 64.
    let payload: Vec<u8> = (0..PAYLOAD_LEN as u32)
        .map(|i| (i.wrapping_mul(13)) as u8)
        .collect();

    // Probe the TX side fragments at this budget BEFORE the loop, so a passing
    // saw_push below is known to have exercised the Fragment RX arm (a single
    // frame would ride the whole-Frame admit path instead).
    let mut probe_sn = TxSn::new(sn::mask_from_res(self_params.seq_num_res));
    let tx_fragmented = match multicast_put_literal(KEYEXPR, &payload) {
        Ok(item) => {
            multicast_tx_emit(item, &mut probe_sn, &self_params)
                .datagrams
                .len()
                > 1
        }
        Err(_) => false,
    };

    // One queued Put on the reliable channel; the pull-seam yields it once,
    // then None (the loop keeps serving RX + the JOIN beacon).
    let mut pending: Option<MulticastTxItem> = multicast_put_literal(KEYEXPR, &payload).ok();

    let mut saw_push = false;
    let mut saw_drop = false;
    let outcome = run_multicast_session(
        &mut dispatcher,
        MulticastDriveConfig {
            params: &self_params,
            tick_ms: 5,
            max_iters: Some(MAX_ITERS),
        },
        &runtime,
        link,
        &mut driver,
        |event| match event {
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                if messages
                    .iter()
                    .any(|m| matches!(m, NetworkMessage::Push(_)))
                {
                    saw_push = true;
                }
            }
            IterationEvent::ReassemblyDropped(_) => saw_drop = true,
            _ => {}
        },
        || pending.take(),
    );

    let active_peers = dispatcher.active_peers();

    // Symmetric leave (best-effort; the bin exits the process anyway, the host
    // test runs in its own process — kept for cleanliness / parity with C1m).
    let _ = link.leave_multicast_group(group);

    MulticastE2eReport {
        outcome: Some(outcome),
        join_ok: true,
        tx_fragmented,
        peer_admitted: active_peers == 1,
        active_peers,
        saw_push,
        saw_drop,
    }
}

/// A multicast params fixture (the C1m `run_multicast_session` test shape): a
/// peer JOIN built with one `zid` is admitted by a loop running another. The
/// caller overrides `batch_size` to the tiny value that forces fragmentation
/// (and matches it on both sides so `validate_join` admits the peer).
fn params(zid: &[u8]) -> MulticastParams {
    MulticastParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid.to_vec(),
        lease_ms: 5_000,
        join_interval_ms: 1,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
    }
}
