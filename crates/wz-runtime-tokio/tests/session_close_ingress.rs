// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2678 (`session-close-ingress`) — a rail message closes a RUNNING session.
//!
//! The whole point of this witness is the SEAM, not either end of it. Both ends
//! already worked and were witnessed separately: `switchboard_inject.rs` proves
//! a matched keyexpr reaches an `EventInjector`, and `session_fsm_full_path.rs`
//! proves `SessionClose` takes Established to Closing. What had never existed is
//! a path BETWEEN them, because the keyexpr matcher and the FSM engine live in
//! two ownership domains that are never in scope together — the matcher runs
//! under the observer lock on the `Session` handle, which does not hold the
//! engine, and the engine is moved into the drive loop and borrowed there for
//! its whole life.
//!
//! So this drives the join: register a row, put a wire Push on it, let the
//! ingress stage a request on the shared bundle, let the drive-loop comparator
//! drain it, and observe the session ACTUALLY CLOSING. An assertion on the
//! request alone would pass with the raiser deleted, which is why the state is
//! what is asserted.
//!
//! Gated at file scope on the two features whose symbols it names.

#![cfg(all(feature = "session-close-ingress", feature = "switchboard"))]

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_codecs::push::{Push, PushOwned, PushOwnedVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent, SessionFsmUnicastPolicy, SessionFsmUnicastState,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, DriverLoopOutcome, IterationEvent,
    NetworkMessage, SessionActionsBinding, SessionLinkActions,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};
use wz_session_core::drive::{check_requested_close, SessionLifecycleInjector};

/// The admin keyexpr this witness maps to the close verb. It is the TEST's
/// choice, not a product constant: nothing in the seam knows any particular
/// keyexpr, which is the property that lets a deployment pick its own.
const CLOSE_KEYEXPR: &str = "@/wz/session/close";

/// The event name as the SCXML document spells it. Written here ONCE and
/// checked against the machine's own mapping by
/// `the_ingress_reads_the_event_name_off_the_machine` below, so this literal
/// cannot drift away from the document without a test saying so.
const CLOSE_EVENT: &str = "session.close";

/// Build a wire-inbound Put Push carrying a literal keyexpr (id=0 => the
/// resolver returns the suffix verbatim, no peer-table lookup).
fn put_push(keyexpr: &str) -> PushOwned {
    let mut push = Push {
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr.len() as u64),
                suffix: Some(keyexpr),
            }),
        },
        ..Push::default()
    }
    .try_into_owned()
    .unwrap();
    if let PushOwnedVariant::CodecZenohMsgPut(ref mut put) = push.body {
        put.payload_len = 0;
        put.payload = wz_session_core::codec_owned::owned_bytes(b"").unwrap();
    }
    push
}

fn frame_event(push: PushOwned) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![NetworkMessage::Push(Box::new(push))],
        has_ext: false,
        extensions: Vec::new(),
    }
}

/// A session standing in `Established` — the only state whose document carries
/// a `session.close` transition, so a witness that stopped at `Init` would
/// assert nothing about closing.
fn established_session() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(SessionFsmUnicastEvent::OutboundStart);
    engine.process_event(SessionFsmUnicastEvent::LinkOpened);
    engine.process_event(SessionFsmUnicastEvent::InitAckReceived);
    engine.process_event(SessionFsmUnicastEvent::OpenAckReceived);
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the walk to Established is this witness's premise, not its claim"
    );
    (actions, engine)
}

#[test]
fn a_mapped_rail_message_closes_a_running_session() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer.switchboard.register(CLOSE_KEYEXPR, CLOSE_EVENT);

    // Nothing has asked yet, and the comparator says so rather than raising.
    assert!(
        !check_requested_close(&actions, &mut engine),
        "an unasked session must not be closed by the drain"
    );
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established
    );

    // The rail message arrives. The ingress cannot reach the engine, so all it
    // can do is stage the request.
    let outcome = frame_event(put_push(CLOSE_KEYEXPR));
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };
    assert_eq!(fired, 1, "the mapped row matched exactly once");
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the ingress must not have touched the machine -- it has no engine"
    );

    // The drive loop owns the engine and is what raises.
    assert!(check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Closing,
        "the session actually closed -- the effect, not the request, is the claim"
    );

    // Take-once: the same standing request must not close a second session's
    // worth of work on the next iteration.
    assert!(
        !check_requested_close(&actions, &mut engine),
        "the request was consumed by the first drain"
    );
}

#[test]
fn an_unmapped_rail_message_leaves_the_session_running() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer.switchboard.register(CLOSE_KEYEXPR, CLOSE_EVENT);

    let outcome = frame_event(put_push("@/wz/session/something-else"));
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    // ANTI-VACUITY: if the matcher matched everything, the test above would
    // pass for the wrong reason and this one would fail.
    assert_eq!(fired, 0, "an unmapped keyexpr matches no row");
    assert!(!check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "a session nobody asked about keeps running"
    );
}

#[test]
fn the_request_slot_is_set_once_and_taken_once() {
    let (actions, _engine) = established_session();

    // Nothing standing to begin with.
    assert!(!actions.take_requested_close());

    // Two requests before a drain are ONE request: the slot records that
    // someone asked, not how many did, because a session closes once.
    actions.request_close();
    actions.request_close();
    assert!(actions.take_requested_close(), "the request was standing");
    assert!(
        !actions.take_requested_close(),
        "and taking it consumed it -- a slot that kept answering true would \
         make every later iteration redo the work"
    );
}

#[test]
fn the_ingress_reads_the_event_name_off_the_machine() {
    use sce_rust_runtime::StatePolicy;
    type P = SessionFsmUnicastPolicy<SessionActionsBinding>;

    // The seam carries NO literal of its own: the injector asks the generated
    // machine what a name means. This pins that the name this test registers is
    // the one the document declares, so a rename in the SCXML surfaces here
    // rather than as a row that silently stops matching.
    assert_eq!(
        <P as StatePolicy>::get_event_from_name(CLOSE_EVENT),
        Some(SessionFsmUnicastEvent::SessionClose),
        "the document's own mapping is the only definition of this name"
    );

    // And a name the document does not carry resolves to nothing, which is why
    // the injector can be handed any row without a second guard.
    assert_eq!(
        <P as StatePolicy>::get_event_from_name("session.close.please"),
        None
    );
}
