// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311fa — handshake-timeout FSM wiring + staleness-safety tests.
//!
//! The open-deadline (carry #1) is realised by letting the SCE scheduler
//! fire the SCXML-declared handshake timers (`init_ack.timeout` /
//! `open_ack.timeout`, 2s each) once `connect_and_open_session`'s tick pump
//! advances past the deadline. These tests pin the FSM half of that wiring
//! deterministically — by injecting the timeout *events* directly (no real
//! clock), the same way `session_fsm_lease_deadline.rs` injects
//! `LeaseExpired`. The real wall-clock end-to-end path is covered by the
//! opt-in `#[ignore]` test in `connect_and_open_session.rs`.
//!
//! The third test is the regression guard for the R311fa correctness fix:
//! SCE does not auto-cancel a delayed `<send>` when its arming state is
//! exited (W3C SCXML 6.2). The per-phase timeout transitions therefore live
//! in the child state that arms each timer, so a *stale* `init_ack.timeout`
//! arriving after `init_ack.received` has moved the config to GotInitAck is
//! discarded (no handler in scope) instead of killing a healthy session.
//! Before the fix the handler lived on the parent Opening state and the
//! stale timer would drive an OpenAck-awaiting session to Closing.

use std::sync::Arc;
use std::sync::Mutex;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{BoxedLinkDriver, CloseReason, SessionLinkActions};
use wz_runtime_tokio::Reliability;
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, install_session_actions_for_test,
};

/// Inert outbound driver — Closing.onentry fires `send_close_frame_with_reason`,
/// which routes through this no-op recording (the timeout tests assert on the
/// FSM state + close-reason trace, not on emitted bytes).
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

/// Initiator activation through to SentInitSyn (the state that arms
/// `init_ack.timeout`): OutboundStart -> LinkOpening, LinkOpened -> Opening
/// (initial child SentInitSyn).
fn drive_to_sent_init_syn(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);
}

/// One step further: InitAck received moves the config to GotInitAck (the
/// state that arms `open_ack.timeout`). The `init_ack.timeout` armed back in
/// SentInitSyn is now stale.
fn drive_to_got_init_ack(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    drive_to_sent_init_syn(engine);
    engine.process_event(E::InitAckReceived);
    assert_eq!(engine.get_current_state(), S::GotInitAck);
}

// ── Legit timeout path 1: the peer never answers InitSyn. init_ack.timeout
//    fires while still in SentInitSyn -> Closing(Generic).
#[test]
fn init_ack_timeout_in_sent_init_syn_drives_closing_generic() {
    let (actions, mut engine) = fresh_setup();
    drive_to_sent_init_syn(&mut engine);

    engine.process_event(E::InitAckTimeout);

    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "init_ack.timeout in its arming state must drive SentInitSyn -> Closing"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(
        trace.close_reason,
        CloseReason::Generic,
        "the timeout transition runs set_close_reason_generic"
    );
    assert!(
        trace.set_close_reason_count >= 1,
        "set_close_reason_count must record the timeout close-reason action \
         (this is the signal connect_and_open_session maps to HandshakeTimeout)"
    );
    assert_eq!(
        trace.record_established_at, 0,
        "a handshake timeout must never have passed through Established"
    );
}

// ── Legit timeout path 2: InitAck arrived, but the peer never answers
//    OpenSyn. open_ack.timeout fires in GotInitAck -> Closing(Generic).
#[test]
fn open_ack_timeout_in_got_init_ack_drives_closing_generic() {
    let (actions, mut engine) = fresh_setup();
    drive_to_got_init_ack(&mut engine);

    engine.process_event(E::OpenAckTimeout);

    assert_eq!(
        engine.get_current_state(),
        S::Closing,
        "open_ack.timeout in its arming state must drive GotInitAck -> Closing"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(trace.close_reason, CloseReason::Generic);
    assert!(trace.set_close_reason_count >= 1);
    assert_eq!(trace.record_established_at, 0);
}

// ── R311fa staleness regression guard: a stale init_ack.timeout (armed in
//    SentInitSyn, delivered after the config moved to GotInitAck) must be
//    discarded — NOT drive the session to Closing — and the handshake must
//    still be able to complete to Established on OpenAck.
//
//    Pre-fix (handler on parent Opening) this test fails: the stale timer
//    transitions GotInitAck -> Closing and the subsequent OpenAckReceived
//    never reaches Established.
#[test]
fn stale_init_ack_timeout_in_got_init_ack_is_discarded() {
    let (actions, mut engine) = fresh_setup();
    drive_to_got_init_ack(&mut engine);

    // Deliver the stale timer.
    engine.process_event(E::InitAckTimeout);

    assert_eq!(
        engine.get_current_state(),
        S::GotInitAck,
        "a stale init_ack.timeout in GotInitAck must be discarded (no handler \
         in scope), leaving the session awaiting OpenAck"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(
        trace.set_close_reason_count, 0,
        "the discarded stale timer must not run any close-reason action"
    );

    // The healthy session still completes on OpenAck.
    engine.process_event(E::OpenAckReceived);
    assert_eq!(
        engine.get_current_state(),
        S::Established,
        "OpenAck after a discarded stale init_ack.timeout must reach Established"
    );
    assert!(
        actions.trace_snapshot().record_established_at >= 1,
        "Established.onentry must run record_established_at"
    );
}

/// Accepting activation through to AwaitingInitSyn — the state whose onentry
/// arms `accepting.inactivity_timeout` (R311fb): InboundStart -> Accepting
/// (initial child AwaitingInitSyn).
fn drive_to_awaiting_init_syn(engine: &mut Engine<SessionFsmUnicastPolicy>) {
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);
}

// ── R311fb accept-side open-deadline: a peer that opens the link but never
//    sends InitSyn. accepting.inactivity_timeout fires while still in
//    AwaitingInitSyn -> Closed. The drop is SILENT (transition targets Closed,
//    not Closing — §2.7 anti-amplification spends no Close frame on a
//    possibly-spoofed peer), so NO close-reason action runs. That count == 0
//    is exactly why `drive_open_loop` maps this terminal to
//    `OpenError::Terminal`, not `HandshakeTimeout` (the Initiator timeout goes
//    through Closing/set_close_reason_generic and is distinguishable).
#[test]
fn accept_inactivity_timeout_in_awaiting_init_syn_drives_closed_silently() {
    let (actions, mut engine) = fresh_setup();
    drive_to_awaiting_init_syn(&mut engine);

    engine.process_event(E::AcceptingInactivityTimeout);

    assert!(
        engine.is_in_final_state(),
        "accepting.inactivity_timeout in AwaitingInitSyn must drive -> Closed (final)"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(
        trace.set_close_reason_count, 0,
        "the accept timeout is a silent drop (target Closed, no Close frame); \
         no close-reason action runs"
    );
    assert_eq!(
        trace.record_established_at, 0,
        "a timed-out accept must never have passed through Established"
    );
}
