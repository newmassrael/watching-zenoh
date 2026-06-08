// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! Stage 5 (reassembly axis) — host integration of the MCU acceptor session
//! e2e driving a STALLED fragment chain to a DEADLINE TIMEOUT.
//!
//! Same handshake topology as `host_acceptor_reassembly_e2e`, but post-
//! `Established` the reactive peer sends ONLY the first fragment of a
//! `T_MID_FRAGMENT` chain (`more=1`) and never the continuation. The acceptor
//! arms a `ReassemblyDispatcher` slot; the harness then advances its internal
//! `OffsetClock` past the chain's `reassembly_timeout_ms` (500ms) deadline, so
//! the per-iteration sweep in `wz_session_lwip::run_session` evicts the chain
//! and raises `IterationEvent::ReassemblyTimeout` — the timeout-eviction half
//! of the reassembly path that `host_acceptor_reassembly_e2e` (a chain that
//! COMPLETES before any deadline) structurally cannot exercise.
//!
//! This closes the R311iv carry: the sweep was wired + unit-tested
//! (`sweep_times_out_expired_chains_only`) but never driven end-to-end,
//! because the completion e2e uses a frozen clock so no deadline fires. The
//! `OffsetClock` jump — applied the instant the lone fragment is INGESTED, so
//! the chain arms at the pre-jump time — is the advancing clock that path
//! needed.
//!
//! A SEPARATE test binary (lwIP NO_SYS=1 is a process-global single-init
//! resource; each cargo integration-test file is its own process). Mirrors
//! the per-file split of `host_acceptor_e2e` / `host_acceptor_reassembly_e2e`.

use wz_mcu_session_acceptor::{run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode};

/// Frozen host clock — `now_us` is constant. The harness's internal
/// `OffsetClock` is what advances time for the stalled mode (after the chain
/// is armed); this inner clock keeps the handshake itself deterministic and
/// safely inside the 1_000ms `accepting_inactivity_ms` bound.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn acceptor_evicts_stalled_fragment_chain_on_deadline_over_lwip() {
    let report = run_acceptor_e2e(FrozenClock, DataMode::FragmentChainStalled);
    assert_eq!(
        report.outcome,
        AcceptorE2eOutcome::ReassemblyTimedOut,
        "acceptor must reach Established (cookie round-trip), arm a reassembly \
         chain from the lone first fragment, then EVICT it when the advancing \
         clock crosses the reassembly_timeout_ms deadline (sweep -> \
         ReassemblyTimeout) — NOT dispatch a FramePayload; report = {report:#?}"
    );
    assert!(
        report.reassembly_timed_out >= 1,
        "the deadline sweep must have evicted at least one chain (the stalled \
         FRAG_SN_0 chain); report = {report:#?}"
    );
    assert!(
        report.peer_frame_sent,
        "the peer must have sent the lone first fragment that armed the chain; \
         report = {report:#?}"
    );
    assert_eq!(
        report.frame_payload, 0,
        "no reassembled FramePayload surfaced — the lone fragment dispatches as \
         a `Fragment` outcome (which arms the chain) and the chain timed out \
         before any completion; report = {report:#?}"
    );
    assert_eq!(
        report.data_dispatch_msg_count, 0,
        "no message was dispatched — the chain timed out before completion; \
         report = {report:#?}"
    );
}
