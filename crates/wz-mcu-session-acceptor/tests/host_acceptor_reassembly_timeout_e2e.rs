// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! Stage 5 (reassembly axis) — host integration of the MCU acceptor session
//! e2e driving a STALLED fragment chain to a DEADLINE TIMEOUT.
//!
//! Same handshake topology as `host_acceptor_reassembly_e2e`, but post-
//! `Established` the reactive peer sends ONLY the first fragment of a
//! `T_MID_FRAGMENT` chain (`more=1`) and never the continuation. The acceptor
//! arms a `ReassemblyDispatcher` slot; this test then advances a controllable
//! clock past the chain's `reassembly_timeout_ms` (500ms) deadline, so the
//! per-iteration sweep in `wz_session_lwip::run_session` evicts the chain and
//! raises `IterationEvent::ReassemblyTimeout` — the timeout-eviction half of
//! the reassembly path that `host_acceptor_reassembly_e2e` (a chain that
//! COMPLETES before any deadline) structurally cannot exercise.
//!
//! This closes the R311iv carry: the sweep was wired + unit-tested
//! (`sweep_times_out_expired_chains_only`) but never driven end-to-end,
//! because the completion e2e uses a frozen clock so no deadline fires. The
//! advancing clock that path needs lives ENTIRELY in this test (a tiny
//! `AdvancingClock` + the `run_acceptor_e2e` fragment hook), so the shared
//! harness and the deploy QEMU binary keep a pristine, advance-free clock
//! path — the advancing-clock concern does not leak into production code.
//!
//! A SEPARATE test binary (lwIP NO_SYS=1 is a process-global single-init
//! resource; each cargo integration-test file is its own process). Mirrors
//! the per-file split of `host_acceptor_e2e` / `host_acceptor_reassembly_e2e`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use wz_mcu_session_acceptor::{run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode};

/// Milliseconds the clock jumps once the lone fragment is ingested, to cross
/// the chain's `reassembly_timeout_ms` (500ms) deadline so the next sweep
/// evicts it. Chosen in the window `reassembly_timeout_ms (500) < JUMP <
/// lease (10_000)` so the sweep fires but the Established lease deadline does
/// NOT — isolating the reassembly-timeout path. The handshake itself ran at
/// offset 0, safely inside the 1_000ms `accepting_inactivity_ms` bound.
const STALL_JUMP_MS: u32 = 2_000;

/// A host clock the test advances by writing a shared millisecond offset.
/// `now_us` is `offset_ms * 1000` (the base epoch is 0). `Arc<AtomicU32>`
/// because [`ClockSource`] is `Send + Sync`. The test holds a clone of the
/// offset handle and bumps it from the fragment hook AFTER the chain is
/// armed, so the arm lands at the pre-bump time and the next sweep evicts.
#[derive(Clone, Default)]
struct AdvancingClock {
    offset_ms: Arc<AtomicU32>,
}

impl ClockSource for AdvancingClock {
    fn now_us(&self) -> u64 {
        u64::from(self.offset_ms.load(Ordering::Relaxed)).saturating_mul(1000)
    }
}

#[test]
fn acceptor_evicts_stalled_fragment_chain_on_deadline_over_lwip() {
    let offset_ms = Arc::new(AtomicU32::new(0));
    let clock = AdvancingClock {
        offset_ms: offset_ms.clone(),
    };

    // The fragment hook fires when the acceptor dispatches the lone fragment,
    // BEFORE the ingest arms the chain (the arm reads the pre-bump now_ms).
    // Bump once: the next loop iteration's sweep then sees now_ms past the
    // chain deadline and evicts it.
    let mut armed = false;
    let on_fragment = move || {
        if !armed {
            offset_ms.store(STALL_JUMP_MS, Ordering::Relaxed);
            armed = true;
        }
    };

    let report = run_acceptor_e2e(clock, DataMode::FragmentChainStalled, on_fragment);
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
