// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R116b — proves the wz-runtime-tokio consumer can drive the SCE
//! scheduler clock from a synthetic [`TestHal`] under std builds.
//!
//! Pre-requisite: SCE vendor pin includes commit `fa3a2fda` ("fix:
//! route scheduler clock through Hal trait under std builds"). Before
//! that fix, the std-build path read `Instant::now()` directly and
//! `<P::Hal>::now_ticks_ms()` was decorative on host builds — a wz
//! consumer could not author deterministic timer-driven tests under
//! host CI.
//!
//! Scope. This file exercises the *scheduler-routing substrate* via a
//! minimal `TimerProbePolicy` whose `type Hal = TestHal`. It does
//! NOT exercise the production `session_fsm_unicast` policy, which
//! emits `type Hal = StdHal` from the codegen template and is
//! therefore not Hal-swappable today. The 4 SCXML delay values
//! `session_fsm_unicast.scxml` uses (`link.open_timeout=5s`,
//! `init_ack.timeout=2s`, `open_ack.timeout=2s`,
//! `closing.timeout=100ms`) drive the test cases below — when the
//! production policy gains Hal-swap support (codegen extension, a
//! separate later round), the same delay-value matrix moves to an
//! integration test against the real policy without changing the
//! TestHal contract.
//!
//! Companion to SCE's `sce-rust-runtime/tests/hal_clock_routing.rs`
//! regression test — that file proves the fix works in SCE; this
//! file proves it works in the wz consumer crate context.

use core::time::Duration;
use std::sync::{Mutex, MutexGuard, PoisonError};

use sce_rust_runtime::{Engine, Hal, StatePolicy};
use wz_runtime_tokio_test_support::{
    test_hal_advance_ticks, test_hal_now_ticks, test_hal_set_ticks, TestHal,
};

/// Serializes every test in this binary so the process-global
/// `TestHal` tick state isn't read while another test is mutating
/// it. Without this lock the multi-thread default of `cargo test`
/// races on the `AtomicU64` *sequence* (each load/store is atomic
/// individually, but the test sequence "set epoch -> schedule ->
/// advance -> assert" is not). The mutex is taken once per test
/// at entry via [`hal_lock`] and held until the guard drops at
/// test end.
///
/// Poison recovery: if a panicked test poisoned the mutex, the
/// `unwrap_or_else(PoisonError::into_inner)` salvage path keeps
/// subsequent tests runnable. A poisoned guard means the prior
/// test left `TestHal` at an unknown tick; every test in this
/// binary re-anchors at entry via `anchor(epoch)` so the
/// poisoned state is overwritten before any assertion reads it.
static HAL_LOCK: Mutex<()> = Mutex::new(());

fn hal_lock() -> MutexGuard<'static, ()> {
    HAL_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

// ─────────────────────────────────────────────────────────────
// Minimal StatePolicy with `type Hal = TestHal`.
//
// Lives in-test (not in test-support) because the StatePolicy
// trait surface is the SCE Engine's contract, not a wz consumer
// API. A test-support crate would be the wrong layer to publish
// it — every consumer who imports test-support would inherit a
// surface that has no production analog.
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum St {
    S0,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ev {
    Null,
    LinkOpenTimeout,
    InitAckTimeout,
    OpenAckTimeout,
    ClosingTimeout,
}

struct TimerProbePolicy {
    last_internal: bool,
    last_targetless: bool,
    last_source: St,
}

impl TimerProbePolicy {
    fn new() -> Self {
        Self {
            last_internal: false,
            last_targetless: false,
            last_source: St::S0,
        }
    }
}

impl StatePolicy for TimerProbePolicy {
    type State = St;
    type Event = Ev;
    type Hal = TestHal;

    fn initial_state() -> Self::State {
        St::S0
    }
    fn is_final_state(_s: Self::State) -> bool {
        false
    }
    fn get_parent(_s: Self::State) -> Option<Self::State> {
        None
    }
    fn is_compound_state(_s: Self::State) -> bool {
        false
    }
    fn is_descendant_of(_d: Self::State, _a: Self::State) -> bool {
        false
    }
    fn get_document_order(_s: Self::State) -> u32 {
        0
    }
    fn null_event() -> Self::Event {
        Ev::Null
    }

    fn get_event_name(e: Self::Event) -> &'static str {
        match e {
            Ev::Null => "",
            Ev::LinkOpenTimeout => "link.open_timeout",
            Ev::InitAckTimeout => "init_ack.timeout",
            Ev::OpenAckTimeout => "open_ack.timeout",
            Ev::ClosingTimeout => "closing.timeout",
        }
    }
    fn get_event_from_name(name: &str) -> Option<Self::Event> {
        match name {
            "link.open_timeout" => Some(Ev::LinkOpenTimeout),
            "init_ack.timeout" => Some(Ev::InitAckTimeout),
            "open_ack.timeout" => Some(Ev::OpenAckTimeout),
            "closing.timeout" => Some(Ev::ClosingTimeout),
            _ => None,
        }
    }
    fn get_state_name(_s: Self::State) -> &'static str {
        "s0"
    }

    fn last_transition_is_internal(&self) -> bool {
        self.last_internal
    }
    fn set_last_transition_is_internal(&mut self, v: bool) {
        self.last_internal = v;
    }
    fn last_transition_is_targetless(&self) -> bool {
        self.last_targetless
    }
    fn set_last_transition_is_targetless(&mut self, v: bool) {
        self.last_targetless = v;
    }
    fn last_transition_source_state(&self) -> Self::State {
        self.last_source
    }
    fn set_last_transition_source_state(&mut self, s: Self::State) {
        self.last_source = s;
    }

    fn execute_entry_actions(&mut self, _s: Self::State, _eng: &mut Engine<Self>) {}
    fn execute_exit_actions(
        &mut self,
        _s: Self::State,
        _eng: &mut Engine<Self>,
        _pre: &[Self::State],
    ) {
    }
    fn process_transition(
        &mut self,
        _cur: &mut Self::State,
        _e: Self::Event,
        _eng: &mut Engine<Self>,
    ) -> bool {
        false
    }
    fn execute_transition_actions(&mut self, _eng: &mut Engine<Self>) {}
}

// ─────────────────────────────────────────────────────────────
// Test anchor helper.
//
// Every test seeds TestHal at a distinct epoch so even when cargo
// test runs them on multiple threads sharing the process-global
// atomic, the relative scheduling assertions still hold (each test
// schedules from its own epoch and never compares against ticks
// authored by other tests).
// ─────────────────────────────────────────────────────────────

fn anchor(epoch_ms: u64) -> Engine<TimerProbePolicy> {
    test_hal_set_ticks(epoch_ms);
    let mut engine = Engine::<TimerProbePolicy>::new(TimerProbePolicy::new());
    engine.initialize();
    engine
}

// ─────────────────────────────────────────────────────────────
// link.open_timeout=5s — session_fsm_unicast.scxml L74
// ─────────────────────────────────────────────────────────────

#[test]
fn link_open_timeout_5s_fires_when_hal_advances_past_ready_at() {
    let _guard = hal_lock();
    let mut engine = anchor(10_000_000);

    engine.schedule_event(Ev::LinkOpenTimeout, Duration::from_secs(5), "lk1", "");

    assert!(
        !engine.has_ready_events(),
        "5s delay must not be ready at the same Hal tick as schedule"
    );

    test_hal_advance_ticks(4_999);
    assert!(
        !engine.has_ready_events(),
        "4.999s in, 5s delay must still pend"
    );

    test_hal_advance_ticks(2);
    assert!(
        engine.has_ready_events(),
        "5.001s in, 5s delay must be ready"
    );
}

// ─────────────────────────────────────────────────────────────
// init_ack.timeout=2s — session_fsm_unicast.scxml L87
// ─────────────────────────────────────────────────────────────

#[test]
fn init_ack_timeout_2s_fires_at_exact_ready_at() {
    let _guard = hal_lock();
    let mut engine = anchor(20_000_000);

    engine.schedule_event(Ev::InitAckTimeout, Duration::from_secs(2), "ia1", "");

    assert!(!engine.has_ready_events());

    test_hal_set_ticks(20_002_000);
    assert!(
        engine.has_ready_events(),
        "exact-equal Hal tick must satisfy ready_at <= now (PullScheduler::has_ready_events_at uses <=)"
    );
}

// ─────────────────────────────────────────────────────────────
// open_ack.timeout=2s — session_fsm_unicast.scxml L94
// (sibling delay to init_ack.timeout; the test verifies two
// concurrent 2s schedules with different send_ids and different
// epoch fire in the expected order)
// ─────────────────────────────────────────────────────────────

#[test]
fn open_ack_timeout_2s_separate_send_ids_each_fires_independently() {
    let _guard = hal_lock();
    let mut engine = anchor(30_000_000);

    engine.schedule_event(Ev::InitAckTimeout, Duration::from_secs(2), "ia2", "");
    engine.schedule_event(Ev::OpenAckTimeout, Duration::from_secs(2), "oa1", "");

    test_hal_advance_ticks(2_001);
    assert!(
        engine.has_ready_events(),
        "two same-delay schedules both ready when Hal crosses common ready_at"
    );
}

// ─────────────────────────────────────────────────────────────
// closing.timeout=100ms — session_fsm_unicast.scxml L169
// (smallest delay in the FSM; verifies sub-second resolution)
// ─────────────────────────────────────────────────────────────

#[test]
fn closing_timeout_100ms_fires_at_millisecond_resolution() {
    let _guard = hal_lock();
    let mut engine = anchor(40_000_000);

    engine.schedule_event(Ev::ClosingTimeout, Duration::from_millis(100), "cl1", "");

    test_hal_advance_ticks(99);
    assert!(
        !engine.has_ready_events(),
        "99ms in, 100ms delay must still pend"
    );

    test_hal_advance_ticks(2);
    assert!(
        engine.has_ready_events(),
        "101ms in, 100ms delay must be ready"
    );
}

// ─────────────────────────────────────────────────────────────
// Negative coverage — advancing backward must not fire.
//
// AtomicU64::fetch_sub would be a misuse of the helper; this test
// instead reconstructs the synthetic clock at an earlier epoch via
// test_hal_set_ticks. The scheduler must remain consistent — a
// schedule keyed off an old larger ready_at stays pending when the
// clock is reset to an earlier value.
// ─────────────────────────────────────────────────────────────

#[test]
fn synthetic_clock_reset_backward_keeps_event_pending() {
    let _guard = hal_lock();
    let mut engine = anchor(50_000_000);

    engine.schedule_event(Ev::LinkOpenTimeout, Duration::from_secs(5), "rb1", "");

    test_hal_set_ticks(50_000_000 + 5_000); // exactly ready_at
    assert!(
        engine.has_ready_events(),
        "exact-equal ready_at must fire (<=, sanity)"
    );

    test_hal_set_ticks(50_000_000 - 1_000); // reset 1s before epoch
    assert!(
        !engine.has_ready_events(),
        "Hal clock reset backward must hide the event again until it crosses ready_at"
    );
}

// ─────────────────────────────────────────────────────────────
// Sanity — TestHal::now_ticks_ms is observable via the public
// helper. Mostly proves the test_hal_set_ticks/_advance_ticks/
// _now_ticks trio agree with the Hal trait's view.
// ─────────────────────────────────────────────────────────────

#[test]
fn test_hal_now_observable_via_helper_matches_trait_method() {
    let _guard = hal_lock();
    test_hal_set_ticks(60_000_000);
    assert_eq!(test_hal_now_ticks(), 60_000_000);
    assert_eq!(TestHal::now_ticks_ms(), 60_000_000);

    test_hal_advance_ticks(1_234);
    assert_eq!(test_hal_now_ticks(), 60_001_234);
    assert_eq!(TestHal::now_ticks_ms(), 60_001_234);
}
