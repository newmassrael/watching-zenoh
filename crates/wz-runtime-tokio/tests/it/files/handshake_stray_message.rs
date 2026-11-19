// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "codec-open-body"
))]

//! `handshake-stray-message`: what an establishment step does with an Init or an Open it does not
//! await, driven through the real dispatch (`poll_and_dispatch_one`) with each value selected on
//! the session's own snapshot. `fail` is upstream's (the attempt ends with `framing.error`, so a
//! Close(INVALID)); `ignore` drops the message and the step keeps waiting, and a late Init or
//! Open that reaches an established session is no sign of the peer's life.
//!
//! A value the build's domain leaves out is not selectable, and its half of each test is skipped:
//! the build cannot run a session under it.

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::policy::HandshakeStrayMessage;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
    DriverLoopOutcome, SessionActionsBinding, SessionLinkActions,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver, QueueDriver};
use wz_session_wire_fixtures::{craft_initack_wire, craft_openack_wire};

type TestEngine = Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>;

/// A session whose snapshot holds `value`, or `None` when the build's domain leaves it out.
fn session_under(value: HandshakeStrayMessage) -> Option<(Arc<SessionLinkActions>, TestEngine)> {
    let mut params = fixture_session_init_params();
    params.policy.select_handshake_stray_message(value).ok()?;
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, params, TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    Some((actions, engine))
}

async fn deliver(
    actions: &Arc<SessionLinkActions>,
    engine: &mut TestEngine,
    wire: Vec<u8>,
) -> DriverLoopOutcome {
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);
    poll_and_dispatch_one(&mut driver, actions, engine).await
}

/// An initiator that sent its OpenSyn and is given the InitAck again (a peer whose first answer
/// it already took): `fail` ends the attempt INVALID, `ignore` keeps waiting and the OpenAck that
/// follows still completes the establishment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_init_ack_after_the_open_syn_fails_or_is_dropped_by_the_policy() {
    for value in [HandshakeStrayMessage::Fail, HandshakeStrayMessage::Ignore] {
        let Some((actions, mut engine)) = session_under(value) else {
            continue;
        };
        engine.process_event(E::OutboundStart);
        engine.process_event(E::LinkOpened);
        assert_eq!(engine.get_current_state(), S::SentInitSyn);
        let _ = deliver(&actions, &mut engine, craft_initack_wire(&[0x11; 8])).await;
        assert_eq!(engine.get_current_state(), S::GotInitAck, "{value:?}");

        let outcome = deliver(&actions, &mut engine, craft_initack_wire(&[0x11; 8])).await;
        match value {
            HandshakeStrayMessage::Fail => {
                assert!(
                    matches!(outcome, DriverLoopOutcome::HandshakeStrayRejected),
                    "fail: {outcome:?}"
                );
                assert_eq!(
                    engine.get_current_state(),
                    S::Closing,
                    "fail: the attempt ends, as upstream's establishment does"
                );
            }
            HandshakeStrayMessage::Ignore => {
                assert!(
                    matches!(outcome, DriverLoopOutcome::HandshakeStrayIgnored),
                    "ignore: {outcome:?}"
                );
                assert_eq!(
                    engine.get_current_state(),
                    S::GotInitAck,
                    "ignore: still waiting"
                );
                assert!(
                    actions.open_ack_awaited(),
                    "ignore: the OpenSyn still awaits"
                );
                let _ = deliver(&actions, &mut engine, craft_openack_wire(0)).await;
                assert_eq!(
                    engine.get_current_state(),
                    S::Established,
                    "ignore: the awaited OpenAck completes the establishment"
                );
            }
        }
    }
}

/// An OpenAck that reaches an initiator still waiting for its InitAck is out of its step too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_ack_before_the_init_ack_fails_or_is_dropped_by_the_policy() {
    for value in [HandshakeStrayMessage::Fail, HandshakeStrayMessage::Ignore] {
        let Some((actions, mut engine)) = session_under(value) else {
            continue;
        };
        engine.process_event(E::OutboundStart);
        engine.process_event(E::LinkOpened);
        let outcome = deliver(&actions, &mut engine, craft_openack_wire(0)).await;
        let (expected, state) = match value {
            HandshakeStrayMessage::Fail => (DriverLoopOutcome::HandshakeStrayRejected, S::Closing),
            HandshakeStrayMessage::Ignore => {
                (DriverLoopOutcome::HandshakeStrayIgnored, S::SentInitSyn)
            }
        };
        assert_eq!(
            core::mem::discriminant(&outcome),
            core::mem::discriminant(&expected),
            "{value:?}: {outcome:?}"
        );
        assert_eq!(engine.get_current_state(), state, "{value:?}");
    }
}

/// A late InitAck that reaches an ESTABLISHED session: under `ignore` it is dropped and is no
/// sign of the peer's life, so the lease stamp it would have set stays unset; under `fail` the
/// session keeps upstream's rule, where every message the peer sends counts for the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_init_ack_keeps_out_of_the_lease_only_under_ignore() {
    for value in [HandshakeStrayMessage::Fail, HandshakeStrayMessage::Ignore] {
        let Some((actions, mut engine)) = session_under(value) else {
            continue;
        };
        engine.process_event(E::OutboundStart);
        engine.process_event(E::LinkOpened);
        engine.process_event(E::InitAckReceived);
        engine.process_event(E::OpenAckReceived);
        assert_eq!(engine.get_current_state(), S::Established);
        *actions.link.last_inbound_at.lock().unwrap() = None;

        let outcome = deliver(&actions, &mut engine, craft_initack_wire(&[0x22; 8])).await;
        let stamped = actions.link.last_inbound_at.lock().unwrap().is_some();
        assert_eq!(engine.get_current_state(), S::Established, "{value:?}");
        match value {
            HandshakeStrayMessage::Fail => {
                assert!(stamped, "fail: upstream counts it as traffic");
                assert!(
                    !matches!(
                        outcome,
                        DriverLoopOutcome::HandshakeStrayRejected
                            | DriverLoopOutcome::HandshakeStrayIgnored
                    ),
                    "fail: the establishment is over, so no step judges it: {outcome:?}"
                );
            }
            HandshakeStrayMessage::Ignore => {
                assert!(
                    !stamped,
                    "ignore: a late handshake message is no sign of life"
                );
                assert!(
                    matches!(outcome, DriverLoopOutcome::HandshakeStrayIgnored),
                    "ignore: {outcome:?}"
                );
            }
        }
    }
}

/// The acceptor's side: an InitAck where an InitSyn is awaited, and the InitSyn again where the
/// OpenSyn is awaited (a peer that resent its first message because the InitAck was late).
#[cfg(feature = "session-unicast-accept")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_acceptor_judges_a_message_out_of_its_step_by_the_policy() {
    use wz_session_wire_fixtures::craft_initsyn_wire;
    for value in [HandshakeStrayMessage::Fail, HandshakeStrayMessage::Ignore] {
        let Some((actions, mut engine)) = session_under(value) else {
            continue;
        };
        engine.process_event(E::InboundStart);
        assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);
        let outcome = deliver(&actions, &mut engine, craft_initack_wire(&[0x33; 8])).await;
        match value {
            HandshakeStrayMessage::Fail => {
                assert!(
                    matches!(outcome, DriverLoopOutcome::HandshakeStrayRejected),
                    "fail: {outcome:?}"
                );
                assert_eq!(engine.get_current_state(), S::Closing);
                continue;
            }
            HandshakeStrayMessage::Ignore => {
                assert!(
                    matches!(outcome, DriverLoopOutcome::HandshakeStrayIgnored),
                    "ignore: {outcome:?}"
                );
                assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);
            }
        }
        let _ = deliver(&actions, &mut engine, craft_initsyn_wire()).await;
        assert_eq!(
            engine.get_current_state(),
            S::SentInitAck,
            "the awaited InitSyn"
        );
        let outcome = deliver(&actions, &mut engine, craft_initsyn_wire()).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::HandshakeStrayIgnored),
            "ignore: the repeated InitSyn is dropped: {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::SentInitAck,
            "ignore: the acceptor still awaits the OpenSyn"
        );
    }
}
