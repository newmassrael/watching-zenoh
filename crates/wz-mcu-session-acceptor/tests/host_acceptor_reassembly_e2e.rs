// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! Stage 5 (reassembly axis) — host integration of the MCU acceptor session
//! e2e driving a FRAGMENT CHAIN.
//!
//! Same handshake topology as `host_acceptor_e2e`, but post-`Established` the
//! reactive peer sends a two-fragment `T_MID_FRAGMENT` chain instead of one
//! whole `T_MID_FRAME`. The acceptor decodes each fragment through the
//! production `parse_inbound`, feeds it to the `ReassemblyDispatcher` ingest
//! (the const-generic MCU `LwipReassembly<4, 4096>`) wired into the swept
//! `wz_session_lwip::run_session` loop, and on chain completion re-parses the
//! reassembled bytes through `parse_frame_payload` + dispatches the result as
//! one `FramePayload` — exactly the steady-state data path
//! `report_outcome_reassembling` drives. This is the live MCU consumer the
//! R311ir reassembly carry awaited, now exercised end-to-end (the auto-sweep
//! is wired in the same loop; this proves the ingest half on a real lwIP
//! loopback).
//!
//! A SEPARATE test binary from `host_acceptor_e2e` (not a second `#[test]`):
//! lwIP under NO_SYS=1 is a process-global single-init resource and each
//! cargo integration-test file is its own process, so each inits the
//! loopback netif exactly once (a second `#[test]` in one binary would abort
//! on the re-init — R71 / YAGNI, the per-file split is the harness).

use wz_mcu_session_acceptor::{run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode};

/// Frozen host clock — `now_us` is constant, so no handshake / lease deadline
/// ever elapses. The handshake + the fragment chain advance purely on
/// crafted-frame arrival, so the run is deterministic.
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn acceptor_reassembles_fragment_chain_and_dispatches_over_lwip() {
    let report = run_acceptor_e2e(FrozenClock, DataMode::FragmentChain);
    assert_eq!(
        report.outcome,
        AcceptorE2eOutcome::EstablishedAndDispatched,
        "acceptor must reach Established (cookie round-trip) and dispatch the \
         REASSEMBLED two-fragment chain as one FramePayload over lwIP \
         loopback (ingest -> ReassemblyDispatcher -> parse_frame_payload -> \
         dispatch); report = {report:#?}"
    );
}
