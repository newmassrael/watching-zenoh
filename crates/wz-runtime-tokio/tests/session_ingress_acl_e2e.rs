// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2702 §5.16 — the JOIN: a message arrives over the wire, the production
//! drive loop decodes it, and the session's ingress chain withholds it from the
//! subscriber that would otherwise have seen it.
//!
//! This exists because both ENDS were already true and the join was not. The
//! loop calls whatever ingress decorator it is handed, and
//! `Session::apply_acl_ingress` drops a governed message from a batch — two
//! facts that unit tests pin separately, and that together say nothing about
//! whether the loop calls the decorator at a point where the drop still
//! matters. This tree has paid seven times for a claim true at both ends and
//! false in the join, so the witness is end to end or it is not a witness.
//!
//! ⚠ The frame under test is not hand-rolled. It is captured by PUBLISHING the
//! message on a session and reading the bytes its own encoder emitted, then
//! replayed inbound — so the wire shape cannot drift from what this tree
//! actually sends, and a codec change reds here rather than silently making the
//! fixture describe a message nobody sends.
//!
//! ⚠ ANTI-VACUITY IS A SEPARATE TEST, deliberately. The replayed frame passes
//! through an rx-SN conduit gate and an alias resolver before any policy sees
//! it, and either could swallow it. "The subscriber did not fire" therefore
//! proves nothing on its own: the second test runs the SAME frame through the
//! SAME loop with NO policy installed and requires the subscriber TO fire. A
//! failure names which half broke instead of leaving one assertion to mean two
//! things.
#![cfg(feature = "access-acl")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_access_control::{
    AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
};
use wz_runtime_core::TimeSource;
use wz_runtime_tokio::interceptor::{InterceptorConfig, InterceptorSink};
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal_with_extra_deadline, new_session_actions, new_session_engine,
    BoxedLinkDriver, ExtraDeadline, SessionActionsBinding, SessionLinkActions, SessionTimeouts,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, NoopOutboundDriver, QueueDriver,
};

/// The keyexpr a rule names, and the one the fixture publishes.
const GOVERNED: &str = "admin/secret";

/// An INGRESS-flow deny on `admin/**` Put.
fn ingress_deny_admin() -> InterceptorConfig {
    InterceptorConfig::default().with_acl(AclPolicy::new(AclConfig {
        default_permission: Permission::Allow,
        rules: vec![AclRule {
            subject: SubjectSelector::Any,
            key_exprs: vec!["admin/**".to_owned()],
            messages: vec![AclMessage::Put],
            flow: AclFlow::Ingress,
            permission: Permission::Deny,
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
            usernames: Vec::new(),
            cert_common_names: Vec::new(),
        }],
    }))
}

fn established(engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>) {
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    engine.process_event(E::InitAckReceived);
    engine.process_event(E::OpenAckReceived);
    assert_eq!(engine.get_current_state(), S::Established);
}

/// A REAL frame carrying a Put on `keyexpr`, captured from this tree's own
/// encoder by publishing it and reading what went out.
fn frame_carrying_put(keyexpr: &str) -> Vec<u8> {
    let recorder = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recorder.clone();
    // A DIFFERENT zid from the replaying session's, because the sender is a
    // peer. With the fixture's default on both sides the subscriber registry
    // reads the replayed Push as this node's own echo and drops it — which the
    // anti-vacuity test below caught, and which would otherwise have made the
    // deny assertion pass without any policy being consulted.
    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4];
    let actions = new_session_actions(outbound, params, TokioTime::new());
    *actions
        .link
        .established_at
        .lock()
        .expect("established_at poisoned in fixture") = Some(actions.clock.now_monotonic_ms());
    let session = TokioSession::new(
        actions,
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish(
            keyexpr,
            b"x",
            PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("the capture publish reaches the wire");
    let snap = recorder.snapshot();
    assert_eq!(
        snap.sends.len(),
        1,
        "the capture must be ONE frame, or the replay below is ambiguous"
    );
    snap.sends[0].0.clone()
}

/// Replay `wire` into a fresh session driven by the PRODUCTION loop, with
/// `config` installed, and answer (messages the decorator SAW arrive, times a
/// subscriber on `admin/**` fired). `None` installs nothing at all.
///
/// Two numbers rather than one, because one cannot tell "the policy withheld
/// it" from "it never arrived" — and the second is how the first version of
/// this test passed while proving nothing.
async fn arrivals_and_hits(wire: Vec<u8>, config: Option<InterceptorConfig>) -> (usize, usize) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions: Arc<SessionLinkActions> =
        new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    established(&mut engine);

    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions.clone(), observer, Arc::new(TokioTime::new()));
    // The enforcer admits a message it cannot attribute (open-debt item 655), so
    // without a conformant peer zid this fixture would reach no rule and BOTH
    // tests would pass while proving nothing.
    *session
        .actions()
        .remote_peer_zid
        .lock()
        .expect("remote_peer_zid poisoned in fixture") = Some(vec![0x5a; 16]);

    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    // The real subscriber API, not a registry poke: a wire-arrived Put reaches
    // an application through `declare_subscriber`, and using anything else here
    // would witness a delivery path no application takes.
    let _sub = session.declare_subscriber("admin/**", SubscribeOptions::default(), move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    if let Some(config) = config {
        session.set_interceptors(config);
    }

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);
    let clock = TokioTime::new();
    let arrivals = Arc::new(AtomicUsize::new(0));
    let arrived = arrivals.clone();
    let _ = drive_session_until_terminal_with_extra_deadline(
        &mut driver,
        &actions,
        &mut engine,
        Some(1),
        &clock,
        &SessionTimeouts::spec_defaults(),
        |event| session.dispatch_iteration_event_with(event, |_| {}),
        ExtraDeadline {
            next_ms: || None,
            revised: None,
        },
        // THE SEAM UNDER TEST. Everything else here is production code; the
        // count is the caller's own bookkeeping, taken BEFORE the decorator so
        // it reports what the loop delivered rather than what survived.
        |outcome| {
            if let wz_session_core::driver_loop::DriverLoopOutcome::FramePayload {
                messages, ..
            } = &*outcome
            {
                arrived.fetch_add(messages.len(), Ordering::SeqCst);
            }
            session.apply_acl_ingress(outcome);
        },
    )
    .await;

    (arrivals.load(Ordering::SeqCst), hits.load(Ordering::SeqCst))
}

/// The claim: a governed message that really arrived does NOT reach the
/// subscriber, because the loop consulted the session's ingress chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ingress_deny_withholds_a_message_the_loop_delivered() {
    let wire = frame_carrying_put(GOVERNED);
    let (arrivals, hits) = arrivals_and_hits(wire, Some(ingress_deny_admin())).await;
    assert_eq!(
        arrivals, 1,
        "precondition: the loop must actually deliver the message, or the \
         assertion below is about nothing"
    );
    assert_eq!(hits, 0, "the ingress chain must withhold it");
}

/// The anti-vacuity arm: the SAME frame, the SAME loop, no policy — and the
/// subscriber fires. Without this the test above would pass just as convincingly
/// if the rx-SN gate, the alias resolver, or the fixture itself had eaten the
/// frame before any policy saw it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_frame_reaches_the_subscriber_with_no_policy_installed() {
    let wire = frame_carrying_put(GOVERNED);
    let (arrivals, hits) = arrivals_and_hits(wire, None).await;
    assert_eq!(arrivals, 1, "the loop must deliver the replayed message");
    assert_eq!(
        hits, 1,
        "with no policy the message must reach the subscriber -- otherwise the \
         deny test proves nothing about the deny"
    );
}
