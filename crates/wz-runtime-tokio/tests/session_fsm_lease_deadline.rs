// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R77 — lease deadline driver wiring tests.
//!
//! Exercises `check_lease_deadline`, the production-shaped helper
//! that consumes `SessionLinkActions::last_inbound_keepalive_at`
//! (populated by R72b on every inbound KeepAlive) and injects
//! `SessionFsmUnicastEvent::LeaseExpired` into the engine when the
//! window has elapsed, so the session-fsm
//! `lease.expired -> Closing(Expired)` transition fires.
//!
//! This is the consumer wiring for the R72b lease-timestamp slot
//! foreshadowed by `inbound_to_fsm_event`'s `KeepAlive -> None`
//! branch (lease-timer side effect orthogonal to the state graph).
//! Production driver loops compose this helper between
//! `poll_and_dispatch_one` iterations.
//!
//! R80 — split into per-branch `#[test]` fns (NoBaseline /
//! WithinLease / Expired / boundary). The mega-test pattern was
//! load-bearing only until R79 closed the cross-test race carry via
//! SCE upstream's per-instance ScriptEngine DI.

use std::sync::Arc;
use std::sync::Mutex;
// R294: lease deadline arithmetic migrated to u64 ms

use sce_rust_runtime::Engine;
use wz_runtime_core::TimeSource;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    check_lease_deadline, BoxedLinkDriver, CloseReason, LeaseCheckOutcome, SessionLinkActions,
};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

/// Inert outbound driver — the lease-deadline helper does not pull
/// from the outbound driver, but `SessionLinkActions::new` requires
/// one for the script-closure capture path. The Closing entry from
/// the `lease.expired` transition fires `send_close_frame_with_reason`,
/// which routes through this driver as a no-op recording.
#[derive(Default)]
struct NoopOutboundDriver {
    _state: Mutex<()>,
}

impl BoxedLinkDriver for NoopOutboundDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

fn fresh_setup() -> (Arc<SessionLinkActions>, Engine<SessionFsmUnicastPolicy>) {
    let outbound: Arc<dyn BoxedLinkDriver> = Arc::new(NoopOutboundDriver::default());
    let actions =
        SessionLinkActions::new(outbound, fixture_session_init_params(), TokioTime::new());
    let lua = install_session_actions_for_test(actions.clone());
    let mut engine = Engine::new(SessionFsmUnicastPolicy::new(lua));
    engine.initialize();
    (actions, engine)
}

fn drive_to_established(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

// ── Scenario 1: both baseline slots empty (pre-Established) →
//                NoBaseline, state unchanged. R84 changed this from
//                "last_inbound_keepalive_at is empty" to "both slots
//                are empty" because Established.onentry now populates
//                established_at, so a post-Established session always
//                has at least one baseline.
#[test]
fn r77_no_baseline_when_both_slots_empty_pre_established() {
    let (actions, mut engine) = fresh_setup();
    // Do NOT drive to Established — both slots stay None.
    assert!(
        actions.last_inbound_keepalive_at.lock().unwrap().is_none(),
        "keepalive slot starts empty"
    );
    assert!(
        actions.established_at.lock().unwrap().is_none(),
        "established slot empty pre-Established"
    );
    let pre_state = engine.get_current_state();

    let outcome = check_lease_deadline(&actions, &mut engine, actions.clock.now_monotonic_ms());
    assert_eq!(
        outcome,
        LeaseCheckOutcome::NoBaseline,
        "both slots absent must surface NoBaseline; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        pre_state,
        "NoBaseline branch must NOT mutate FSM state"
    );
}

// ── R84 Scenario A: drive_to_established populates established_at;
//                    no KeepAlive stamp; check shortly after Established
//                    entry → WithinLease via established_at fallback
//                    baseline (session-fsm §2.5)
#[test]
fn r84_within_lease_via_established_baseline_alone() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    assert!(
        actions.last_inbound_keepalive_at.lock().unwrap().is_none(),
        "no peer KeepAlive yet — only established_at populated"
    );
    let established = actions
        .established_at
        .lock()
        .unwrap()
        .expect("Established.onentry populated established_at via R84 hook");

    // 1ms after Established entry, well within 10s lease.
    let now = established + 1;
    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::WithinLease,
        "established_at-only baseline within lease must surface WithinLease \
         (pre-R84 this was NoBaseline); got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Established);
}

// ── R84 Scenario B: established_at only, clock advanced past lease
//                    → Expired via established_at baseline
#[test]
fn r84_expired_via_established_baseline_alone() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    let established = actions.established_at.lock().unwrap().unwrap();

    // 20s after Established entry, past the 10s fixture lease.
    let now = established + 20 * 1000;
    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::Expired,
        "established_at + 20s past 10s lease must surface Expired \
         (pre-R84 this was NoBaseline indefinitely — wire-spec gap); \
         got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "Expired via established_at must drive Established -> Closing"
    );
    assert_eq!(
        actions.trace_snapshot().close_reason,
        CloseReason::Expired,
        "Closing.onentry must set close_reason=Expired"
    );
}

// ── R84 Scenario C: both slots populated; the more recent stamp wins
//                    via max(established_at, last_inbound_keepalive_at).
//                    Stale established + recent KeepAlive ⇒ WithinLease.
#[test]
fn r84_keepalive_wins_over_stale_established_via_max() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    let established = actions.established_at.lock().unwrap().unwrap();

    // KeepAlive arrived 5s after Established. 6s after Established
    // (1s after KeepAlive) is well within 10s lease counted from
    // KeepAlive — but it would be Expired if counted from
    // established_at alone (5s + 6s = 11s > 10s lease — actually no,
    // 6s < 10s either way). Pick stale established that WOULD fail.
    //
    // Stage: established = T0, keepalive = T0 + 9s, now = T0 + 9.5s.
    // Counted from established: 9.5s < 10s ⇒ WithinLease (no expiry).
    // Counted from keepalive: 0.5s < 10s ⇒ WithinLease (no expiry).
    // Both paths agree here; tighten to a case where they diverge.
    //
    // Better: established = T0, keepalive = T0 + 11s, now = T0 + 12s.
    // Counted from established (stale): 12s >= 10s ⇒ Expired.
    // Counted from keepalive (recent): 1s < 10s ⇒ WithinLease.
    // max() picks keepalive ⇒ WithinLease (correct R84 semantics).
    let keepalive = established + 11 * 1000;
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(keepalive);
    let now = established + 12 * 1000;

    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::WithinLease,
        "max(established=stale, keepalive=recent) baseline must pick keepalive \
         and surface WithinLease; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Established);
}

// ── Scenario 2: stamp recent, now = stamp + 1ms (lease=10000ms)
//                → WithinLease, state unchanged
#[test]
fn r77_within_lease_when_stamp_recent() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    // Fixture lease = 10_000 (ms, lease_in_seconds=false) ⇒ 10s window.
    let stamp = actions.clock.now_monotonic_ms();
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(stamp);
    let pre_state = engine.get_current_state();

    let now = stamp + 1;
    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::WithinLease,
        "1ms < 10s lease must surface WithinLease; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        pre_state,
        "WithinLease branch must NOT mutate FSM state"
    );
}

// ── Scenario 3: stamp old, now = stamp + 20s (lease=10000ms)
//                → Expired, FSM Established -> Closing, close_reason
//                = Expired, trace surfaces Established.onexit +
//                Closing.onentry side effects
#[test]
fn r77_expired_drives_established_to_closing() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    let stamp = actions.clock.now_monotonic_ms();
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(stamp);

    let now = stamp + 20 * 1000;
    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::Expired,
        "20s >= 10s lease must surface Expired; got {outcome:?}"
    );
    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "Expired must drive Established -> Closing via lease.expired"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(
        trace.close_reason,
        CloseReason::Expired,
        "Closing.onentry must set close_reason=Expired"
    );
    assert_eq!(
        trace.send_close_frame_with_reason, 1,
        "Closing.onentry must dispatch send_close_frame_with_reason"
    );
    assert_eq!(
        trace.stop_keepalive_worker, 1,
        "Established.onexit must stop the keepalive worker"
    );
    assert_eq!(
        trace.stop_lease_monitor, 1,
        "Established.onexit must stop the lease monitor"
    );
}

// ── Scenario 4: boundary — now = stamp + lease (exactly) → Expired
//                because the comparator is `>=` (a stamp older than
//                or equal to the deadline triggers expiry).
#[test]
fn r77_expired_at_exact_lease_boundary() {
    let (actions, mut engine) = fresh_setup();
    drive_to_established(&mut engine);
    let stamp = actions.clock.now_monotonic_ms();
    *actions.last_inbound_keepalive_at.lock().unwrap() = Some(stamp);

    let now = stamp + 10_000;
    let outcome = check_lease_deadline(&actions, &mut engine, now);
    assert_eq!(
        outcome,
        LeaseCheckOutcome::Expired,
        "exact lease boundary must surface Expired (>= comparator)"
    );
    assert_eq!(engine.get_current_state(), S::Closing);
}
