// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Stage 5 — host integration of the MCU acceptor session e2e.
//!
//! Runs the SAME [`run_acceptor_e2e`] scenario the QEMU bin
//! (`deploy/mcu-session-acceptor`, Layer Q.4) boots, but on the host's real
//! lwIP build with a frozen clock for full determinism. Proves the acceptor
//! half of the unicast handshake reaches `Established` (real cookie
//! round-trip) and dispatches a post-handshake application Frame, end-to-end
//! over a live lwIP loopback, driven by `wz_session_lwip::run_session`.
//!
//! lwIP under NO_SYS=1 is a process-global single-init resource, so the
//! scenario inits the loopback netif once; this single `#[test]` exercises
//! the whole handshake in one process (a second lwIP-touching test would
//! need an init-once harness — deferred until one exists, R71 / YAGNI).

use wz_mcu_session_acceptor::{run_acceptor_e2e, AcceptorE2eOutcome, ClockSource, DataMode};

/// Frozen host clock — `now_us` is constant, so no handshake / lease deadline
/// ever elapses. The handshake advances purely on crafted-frame arrival, so
/// the run is deterministic (the verdict is decided by the cookie round-trip
/// + Frame dispatch, never by a timing race).
#[derive(Clone, Copy, Default)]
struct FrozenClock;

impl ClockSource for FrozenClock {
    fn now_us(&self) -> u64 {
        0
    }
}

#[test]
fn acceptor_handshake_reaches_established_and_dispatches_frame_over_lwip() {
    let report = run_acceptor_e2e(FrozenClock, DataMode::WholeFrame);
    assert_eq!(
        report.outcome,
        AcceptorE2eOutcome::EstablishedAndDispatched,
        "acceptor must reach Established (InitSyn -> InitAck -> OpenSyn with \
         the real round-tripped cookie -> OpenAck) and dispatch the \
         post-handshake application Frame over lwIP loopback; report = {report:#?}"
    );
}
