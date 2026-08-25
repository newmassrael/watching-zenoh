// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! Stage 5 (reassembly axis) — host integration of the MCU acceptor session
//! e2e driving an OUT-OF-ORDER fragment chain to an INGEST ABORT.
//!
//! Same handshake topology as `host_acceptor_reassembly_e2e`, but post-
//! `Established` the reactive peer sends a two-fragment chain whose second
//! fragment carries a NON-CONSECUTIVE SN (FRAG_SN_0=10 then FRAG_SN_OOO=12,
//! skipping the expected 11). The acceptor arms the chain on the first
//! fragment, then the strict-in-order policy (§2.5 / `fragment.ooo`) aborts it
//! when the gap is seen — surfaced as
//! `IterationEvent::ReassemblyDropped(OutOfOrder)`. This is the ingest-abort
//! half of the reassembly path: `host_acceptor_reassembly_e2e` proves
//! completion, `host_acceptor_reassembly_timeout_e2e` proves the deadline
//! sweep, and this proves a malformed stream is dropped (not dispatched).
//!
//! No advancing clock is needed (the abort fires immediately on the second
//! fragment, not on a deadline), so a frozen clock keeps the run
//! deterministic.
//!
//! A SEPARATE test binary (lwIP NO_SYS=1 is a process-global single-init
//! resource; each cargo integration-test file is its own process). Mirrors the
//! per-file split of the other acceptor host tests.

use wz_mcu_session_acceptor::{
    run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode, ReassemblyDropReason,
};

/// Frozen host clock — `now_us` is constant; the ooo abort is event-driven
/// (the second fragment), so no deadline ever needs to fire.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn acceptor_aborts_out_of_order_fragment_chain_over_lwip() {
    // No-op fragment hook: the abort is event-driven (no clock advance needed).
    let report = run_acceptor_e2e(FrozenClock, DataMode::FragmentChainOoo, || {});
    assert_eq!(
        report.outcome,
        AcceptorE2eOutcome::ReassemblyDropped,
        "acceptor must reach Established (cookie round-trip), arm a chain from \
         the first fragment, then ABORT it when the non-consecutive second \
         fragment trips strict in-order (fragment.ooo -> ReassemblyDropped) — \
         NOT dispatch a FramePayload; report = {report:#?}"
    );
    assert!(
        report.reassembly_dropped >= 1,
        "at least one chain must have been dropped at ingest (the out-of-order \
         abort); report = {report:#?}"
    );
    assert_eq!(
        report.last_drop_reason,
        Some(ReassemblyDropReason::OutOfOrder),
        "the drop must specifically be the strict-in-order abort (the second \
         fragment's non-consecutive SN), not a capacity / quota / pool drop; \
         report = {report:#?}"
    );
    assert_eq!(
        report.reassembly_timed_out, 0,
        "the abort is immediate on the second fragment, not a deadline sweep, \
         so no timeout eviction should occur; report = {report:#?}"
    );
    assert_eq!(
        report.frame_payload, 0,
        "no reassembled FramePayload surfaced — the chain aborted before any \
         completion; report = {report:#?}"
    );
    assert_eq!(
        report.data_dispatch_msg_count, 0,
        "no message was dispatched — the chain was dropped; report = {report:#?}"
    );
}
