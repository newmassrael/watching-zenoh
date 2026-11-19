// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-unicast",
    feature = "session-unicast-accept",
    feature = "codec-init-body",
    feature = "codec-open-body"
))]

//! `handshake-cookie`: the cookie an acceptor puts in its InitAck and the OpenSyn it admits,
//! driven through the real dispatch with each value selected on the session's own snapshot.
//! `fixed` sends the session's configured cookie, admits an OpenSyn whose cookie is exactly that
//! value (an empty one for an empty value) and holds what it negotiated until the OpenSyn;
//! `stateless`, upstream's, admits only the sealed cookie it minted.
//!
//! A value the build's domain leaves out is not selectable, and its test returns at once.

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_runtime_tokio::policy::HandshakeCookie;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
    SessionActionsBinding, SessionLinkActions,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::{craft_initsyn_wire, craft_opensyn_wire};

type TestEngine = Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>;

/// An acceptor under `value` whose configured cookie is `cookie`, past the InitSyn (its InitAck
/// sent), with the cookie that InitAck carried; `None` when the build leaves the value out.
async fn accepting_under(
    value: HandshakeCookie,
    cookie: &[u8],
) -> Option<(Arc<SessionLinkActions>, TestEngine, Vec<u8>)> {
    let mut params = fixture_session_init_params();
    params.policy.select_handshake_cookie(value).ok()?;
    params.cookie = cookie.to_vec();
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, params, TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    engine.process_event(E::InboundStart);
    deliver(&actions, &mut engine, craft_initsyn_wire()).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);
    let sent = driver.snapshot().sends;
    let init_ack = sent.last().expect("the InitAck went out").0.clone();
    let carried = match parse_inbound(&init_ack).expect("wz parses its own InitAck") {
        InboundFrame::Init {
            is_ack: true, body, ..
        } => body.cookie.map(|c| c.to_vec()).unwrap_or_default(),
        other => panic!("not an InitAck: {other:?}"),
    };
    Some((actions, engine, carried))
}

async fn deliver(actions: &Arc<SessionLinkActions>, engine: &mut TestEngine, wire: Vec<u8>) {
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);
    let _ = poll_and_dispatch_one(&mut driver, actions, engine).await;
}

/// `fixed` with no configured cookie: the InitAck carries an empty cookie, an OpenSyn that
/// echoes none opens the session, and the same OpenSyn again after it is not admitted (the
/// pending accept was spent by the first).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_fixed_an_open_syn_with_an_empty_cookie_opens() {
    let Some((actions, mut engine, carried)) = accepting_under(HandshakeCookie::Fixed, &[]).await
    else {
        return;
    };
    assert!(carried.is_empty(), "the configured cookie, empty");
    deliver(&actions, &mut engine, craft_opensyn_wire(&[])).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(actions.trace_snapshot().send_open_ack, 1);
    deliver(&actions, &mut engine, craft_opensyn_wire(&[])).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(
        actions.trace_snapshot().send_open_ack,
        1,
        "no second OpenSyn is admitted after the establishment"
    );
}

/// `fixed` with a configured cookie: the InitAck carries that value, an OpenSyn with another
/// cookie or none is refused and the accept stays pending with what it negotiated, and the
/// exact value then opens it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_fixed_only_the_configured_cookie_is_admitted() {
    const CONFIGURED: [u8; 3] = [0x5A, 0x5B, 0x5C];
    let Some((actions, mut engine, carried)) =
        accepting_under(HandshakeCookie::Fixed, &CONFIGURED).await
    else {
        return;
    };
    assert_eq!(
        carried, CONFIGURED,
        "the InitAck carries the configured cookie"
    );
    for wrong in [&[][..], &[0x5A, 0x5B][..], &[0x77, 0x5B, 0x5C][..]] {
        deliver(&actions, &mut engine, craft_opensyn_wire(wrong)).await;
        assert_eq!(
            engine.get_current_state(),
            S::SentInitAck,
            "{wrong:?} is refused"
        );
    }
    assert_eq!(actions.trace_snapshot().send_open_ack, 0);
    deliver(&actions, &mut engine, craft_opensyn_wire(&CONFIGURED)).await;
    assert_eq!(engine.get_current_state(), S::Established);
}

/// A held accept that times out is let go with its session: the machine closes, and an OpenSyn
/// that arrives after it opens nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_fixed_a_held_accept_is_let_go_when_it_times_out() {
    let Some((actions, mut engine, _)) = accepting_under(HandshakeCookie::Fixed, &[]).await else {
        return;
    };
    engine.process_event(E::AcceptingInactivityTimeout);
    assert!(engine.is_in_final_state(), "the accept is closed");
    deliver(&actions, &mut engine, craft_opensyn_wire(&[])).await;
    assert_eq!(actions.trace_snapshot().send_open_ack, 0);
}

/// `stateless`, upstream's: the InitAck carries no configured value but a minted cookie (or
/// none, with no source to mint from), and an OpenSyn that echoes an empty cookie is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_stateless_an_empty_cookie_is_refused() {
    let Some((actions, mut engine, _)) = accepting_under(HandshakeCookie::Stateless, &[]).await
    else {
        return;
    };
    assert!(!actions.fixed_cookie());
    deliver(&actions, &mut engine, craft_opensyn_wire(&[])).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);
    assert_eq!(actions.trace_snapshot().send_open_ack, 0);
}
