// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mi — host integration of the MCU multicast transport e2e.
//!
//! Runs the SAME [`run_multicast_e2e`] scenario the `deploy/mcu-multicast-e2e`
//! footprint bin embodies, but on the host's real lwIP build with multicast
//! loopback routed (the sanctioned `LWIP_LOOPIF_MULTICAST` + `LWIP_TESTMODE`
//! affordance) and a frozen clock for full determinism. Since R311y190 the
//! deploy bin ALSO runs this round trip on-target (the `loopback-multicast`
//! build boots on QEMU M3/M4/M7, run-ci Layer Q.6); this host lane is the
//! frozen-clock, host-runtime counterpart: it asserts the full
//! multicast feature profile composes end to end — a peer JOIN admitted
//! (transport-multicast), an oversize Put split into a `T_MID_FRAGMENT` chain
//! (transport-fragmentation TX), reassembled back into one `Push`
//! (reassembly RX + codec-push) — over a live lwIP loopback driven by
//! `wz_session_lwip::run_multicast_session`.
//!
//! lwIP under NO_SYS=1 is a process-global single-init resource; this single
//! `#[test]` exercises the whole round trip in one process via the
//! `lwip_test_link` init-once harness (one `lwip_init` + the multicast-netif
//! routing per binary).

use wz_mcu_multicast_e2e::{run_multicast_e2e, ClockSource, MulticastOutcome};

/// Frozen host clock — `now_us` is constant, so no JOIN-interval / lease
/// deadline ever elapses. The fragment chain is delivered FIFO over loopback
/// and reassembles purely on arrival order, so the run is deterministic (the
/// verdict is decided by the round trip, never by a timing race) — the same
/// shape as the C1m `run_multicast_session` tests' `FrozenClock`.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn multicast_profile_admits_peer_and_reassembles_fragmented_put_over_lwip() {
    // The routed link: lwip_test_link inits lwIP once AND routes multicast TX
    // over the IGMP-capable loop netif, so the self-injected JOIN + the echoed
    // fragment chain loop back into ip_input and are accepted on the joined
    // group. The MutexGuard serialises lwIP's process-global group membership.
    let (_serial, link) = wz_link_lwip::lwip_test_link();

    let report = run_multicast_e2e(&link, FrozenClock);

    assert!(
        report.join_ok,
        "the multicast RX socket must bind + join the group on the routed host \
         loop netif; report = {report:#?}"
    );
    assert_eq!(
        report.outcome,
        Some(MulticastOutcome::IterationLimit),
        "the bounded drive loop must run to its iteration limit (not stop \
         early); report = {report:#?}"
    );
    assert!(
        report.tx_fragmented,
        "the 200-byte Put must split into >1 datagram at batch_size 64 (so the \
         round trip exercises the Fragment RX arm); report = {report:#?}"
    );
    assert!(
        report.peer_admitted,
        "the crafted peer JOIN must be admitted into the §3.2 table (our own \
         beacon is zid-filtered); report = {report:#?}"
    );
    assert!(
        !report.saw_drop,
        "the in-order fragment chain must reassemble cleanly (no drop); \
         report = {report:#?}"
    );
    assert!(
        report.saw_push,
        "the fragmented Put must be split by multicast_tx_emit, multicast to \
         the group, echoed back, and reassembled by the Fragment RX arm into \
         one Push; report = {report:#?}"
    );
    assert!(
        report.departed,
        "R2375 — the node must then LEAVE ANNOUNCED: the departure drive takes \
         §3.1 Running -> Stopped and clears the peer table, so a group peer \
         frees this member now instead of holding it until the lease expires; \
         report = {report:#?}"
    );
}
