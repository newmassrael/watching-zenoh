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
//! R2713 (residual (a)) — AND THE VERB IS NOW GOVERNED, which is a SECOND join
//! and was missing for the same reason the first one was. Both of ITS ends were
//! also already true and witnessed apart: `session_ingress_acl_e2e.rs` proves a
//! policy drops a governed message from a batch, and the arm below proves a
//! matched row closes a running session. Neither said the close verb is subject
//! to a policy at all.
//!
//! So the refusing arms drive that join, and each is paired with an admitting
//! authority on the SAME frame through the SAME path — a refusal on this port is
//! observable only as the absence of an effect, so "nothing happened" has to be
//! told apart from "nothing arrived".
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
use wz_session_core::drive::{
    check_requested_close, LifecycleKey, SessionCloseAuthority, SessionLifecycleInjector,
};

/// Admits every close. The ANTI-VACUITY control for every refusing arm below:
/// "the session did not close" proves nothing on its own, because the frame
/// passes a resolver and a matcher that could each swallow it, so each refusal
/// is paired with this one running the SAME frame through the SAME path.
struct AdmitAll;

impl SessionCloseAuthority for AdmitAll {
    fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
        true
    }
}

/// Refuses every close — a host whose policy governs the whole lifecycle rail.
struct DenyAll;

impl SessionCloseAuthority for DenyAll {
    fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
        false
    }
}

/// Admits closes on ONE TARGET and refuses every other. This is the authority
/// that makes the witness say something the two blanket ones cannot: that the
/// verdict is taken on the ARRIVING key rather than on the row's pattern or the
/// event name.
///
/// R2718 — it now compares `key.peer_zid`, not the whole keyexpr, which is
/// strictly stronger: "may close session X only" is a statement about the
/// TARGET, and an authority that matched the whole string would also be
/// refusing keys that name the same target through a different node or verb
/// chunk. Before the grammar was parsed, every authority had to carry its own
/// copy of it to say this much.
struct AdmitOnly(&'static str);

impl SessionCloseAuthority for AdmitOnly {
    fn admits_close(&self, key: &LifecycleKey<'_>) -> bool {
        key.peer_zid == self.0
    }
}

/// The admin keyexpr this witness maps to the close verb. WHICH key is the
/// TEST's choice — a deployment picks its own, which is why wz ships no default
/// row — but its SHAPE is not: R2718 made
/// `@/<zid>/<whatami>/session/<verb>/<peer-zid>` a parsed grammar, and the
/// injector refuses a key that is not one.
///
/// ⚠ This constant used to read `@/wz/session/close`, five chunks, which was
/// never the grammar at all — it matched because the switchboard PATTERN
/// matched and nothing ever read the key. That it had to change here is the
/// enforcement working, not a cost of it.
const CLOSE_KEYEXPR: &str = "@/node-a/peer/session/close/peer-b";

/// The target `CLOSE_KEYEXPR` names, spelled once so an arm can assert on the
/// authority's view of it rather than on the whole string.
const CLOSE_TARGET: &str = "peer-b";

/// The event name as the SCXML document spells it. Written here ONCE and
/// checked against the machine's own mapping by
/// `session_close_ingress_reads_the_name_off_the_machine` below, so this literal
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
fn session_close_ingress_closes_a_running_session() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register_command(CLOSE_KEYEXPR, CLOSE_EVENT);

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
    let admit = AdmitAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
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
fn session_close_ingress_leaves_an_unmapped_message_alone() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register_command(CLOSE_KEYEXPR, CLOSE_EVENT);

    let outcome = frame_event(put_push("@/node-a/peer/session/something-else/peer-b"));
    let admit = AdmitAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
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

/// R2714 residual (b) — THE DOCUMENT REACHES THE EFFECT. One `wz-switchboard.yaml`
/// model, applied to a registry by the mapping that lives on the registry, and a
/// wire Push on the declared key closes the session.
///
/// This is the join residual (b) is about. `apply_spec` is witnessed in
/// `wz-session-core` to map a `lifecycle` row to the command shape, and the arms
/// above witness that a command row closes a session. Neither says a DOCUMENT
/// closes one — and the acceptance is "no host binds a row by hand", which is a
/// statement about the whole path or about nothing.
///
/// ⚠ The row is NOT registered here. Every keyexpr this test names comes out of
/// the model, so a mapping that dropped the lifecycle section would fail here
/// rather than be quietly compensated by a hand registration.
#[test]
fn session_close_ingress_closes_from_a_switchboard_document() {
    use wz_switchboard_schema::{LifecycleBinding, SwitchboardSpec};

    const DECLARED: &str = "@/node-a/peer/session/close/peer-a";

    let (actions, mut engine) = established_session();
    let spec = SwitchboardSpec {
        machine: "sensor_monitor".to_string(),
        bindings: Vec::new(),
        lifecycle: vec![LifecycleBinding {
            keyexpr: DECLARED.to_string(),
            event: CLOSE_EVENT.to_string(),
        }],
    };

    let mut observer = ApplicationLayerObserver::new();
    observer.switchboard.apply_spec(&spec);
    assert_eq!(
        observer.switchboard.len(),
        1,
        "the document's one row is the registry's one row"
    );

    let outcome = frame_event(put_push(DECLARED));
    let admit = AdmitAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    assert_eq!(fired, 1, "the declared key fired the declared verb");
    assert!(check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Closing,
        "a document closed a running session -- the effect, not the registration"
    );
}

/// And the same document is still subject to the authority. A declaration says
/// WHICH key the verb answers on; it does not say who may use it, and a round
/// that let the document imply consent would have undone R2713 through the back
/// door.
#[test]
fn a_documented_row_is_still_refused_by_the_authority() {
    use wz_switchboard_schema::{LifecycleBinding, SwitchboardSpec};

    const DECLARED: &str = "@/node-a/peer/session/close/peer-a";

    let (actions, mut engine) = established_session();
    let spec = SwitchboardSpec {
        machine: "sensor_monitor".to_string(),
        bindings: Vec::new(),
        lifecycle: vec![LifecycleBinding {
            keyexpr: DECLARED.to_string(),
            event: CLOSE_EVENT.to_string(),
        }],
    };

    let mut observer = ApplicationLayerObserver::new();
    observer.switchboard.apply_spec(&spec);
    // The row IS there. Without this, "nothing happened" would also be what a
    // mapping that dropped the lifecycle section produces, and this arm would
    // pass for the opposite of its reason.
    assert_eq!(
        observer.switchboard.len(),
        1,
        "the document registered its row; the refusal below is the authority's"
    );

    let outcome = frame_event(put_push(DECLARED));
    let deny = DenyAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &deny);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    assert_eq!(fired, 0, "declared is not the same as permitted");
    assert!(!check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established
    );
}

/// R2718 — A MATCHED ROW IS NOT A LIFECYCLE KEY. A row's pattern can be a
/// wildcard, so matching says the key is in the row's shape, never that it is in
/// the GRAMMAR's. An authority handed a key it cannot parse would be answering
/// about a target it never read, so the injector refuses first.
///
/// ⚠ The authority here ADMITS EVERYTHING, which is what makes this arm about
/// the grammar: with `AdmitAll` bound, the only thing that can stop the close is
/// the key's shape.
#[test]
fn session_close_ingress_refuses_a_key_that_is_not_the_grammar() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    // A wildcard row wide enough to match keys of any shape under `@`.
    observer.switchboard.register_command("@/**", CLOSE_EVENT);

    // Five chunks, not six — the shape every test in this file used before the
    // grammar was parsed, and the shape a deployment could reach for by analogy.
    let outcome = frame_event(put_push("@/wz/session/close/peer-b"));
    let admit = AdmitAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    assert_eq!(fired, 0, "a key outside the grammar carries out nothing");
    assert!(!check_requested_close(&actions, &mut engine));
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established
    );

    // ANTI-VACUITY: the SAME row and the SAME authority close a session when the
    // key IS the grammar, so the refusal above is the shape's and not the row's.
    let (actions, mut engine) = established_session();
    let outcome = frame_event(put_push(CLOSE_KEYEXPR));
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };
    assert_eq!(fired, 1);
    assert!(check_requested_close(&actions, &mut engine));
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Closing);
}

/// The authority reads the TARGET, and this arm pins that the chunk it reads is
/// the one the grammar puts it in — `CLOSE_KEYEXPR`'s last chunk, not its whole
/// text.
#[test]
fn session_close_ingress_hands_the_authority_the_parsed_target() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register_command(CLOSE_KEYEXPR, CLOSE_EVENT);

    let outcome = frame_event(put_push(CLOSE_KEYEXPR));
    // Scoped to the TARGET chunk alone. An authority still comparing whole
    // keyexprs would refuse this, because `CLOSE_TARGET` is not `CLOSE_KEYEXPR`.
    let only = AdmitOnly(CLOSE_TARGET);
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &only);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    assert_eq!(fired, 1, "the target chunk is what the authority was given");
    assert!(check_requested_close(&actions, &mut engine));
    assert_eq!(engine.get_current_state(), SessionFsmUnicastState::Closing);
}

/// R2713 residual (a) — THE JOIN. Both ends were already witnessed: a policy
/// drops a governed message from a batch (`session_ingress_acl_e2e.rs`), and a
/// matched row closes a running session (the arm at the top of this file).
/// Neither says the verb is GOVERNED, and that is the claim this makes: the
/// same frame, the same loop, the same row, and an authority that refuses.
#[test]
fn session_close_ingress_refuses_a_close_the_authority_denies() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register_command(CLOSE_KEYEXPR, CLOSE_EVENT);

    let outcome = frame_event(put_push(CLOSE_KEYEXPR));
    let deny = DenyAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &deny);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    // A refusal is observable ONLY as nothing having happened -- this port
    // answers nothing by design -- so the count and the state are the two
    // places it has to show, and both are asserted.
    assert_eq!(fired, 0, "a refused command is not an injection");
    assert!(
        !check_requested_close(&actions, &mut engine),
        "a refused close must not even STAGE a request"
    );
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the session a policy refused to close is still running"
    );
}

/// ⛔ THE FAIL-CLOSED ARM. A close registered as a SIGNAL row reaches the
/// injector through the name-only shape, which carries no keyexpr -- so the
/// injector cannot know which session is named and cannot ask whether it may be
/// closed. It must decline, EVEN WITH AN ADMITTING AUTHORITY, because what it
/// would be admitting is unknown.
///
/// This is the arm that names the residual's defect directly: R2678 closed the
/// session from the signal path, so the verb was reachable through a name
/// alone. Reverting that one method body turns this arm red.
#[test]
fn session_close_ingress_cannot_be_reached_through_the_signal_path() {
    let (actions, mut engine) = established_session();
    let mut observer = ApplicationLayerObserver::new();
    // `register`, not `register_command` -- the misregistration this guards.
    observer.switchboard.register(CLOSE_KEYEXPR, CLOSE_EVENT);

    let outcome = frame_event(put_push(CLOSE_KEYEXPR));
    let admit = AdmitAll;
    let fired = {
        let mut injector = SessionLifecycleInjector::new(&actions, &admit);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };

    // The row MATCHED -- a signal row always counts -- so the count is not the
    // claim here and asserting it alone would pass with the gate removed.
    assert_eq!(fired, 1, "the row matched; this arm is not about matching");
    assert!(
        !check_requested_close(&actions, &mut engine),
        "a close that could not be authorised must not be carried out"
    );
    assert_eq!(
        engine.get_current_state(),
        SessionFsmUnicastState::Established,
        "the state is the claim: nothing closed"
    );
}

/// The verdict is taken on the ARRIVING keyexpr, which is why the grammar puts
/// the target there. One authority, two keys, opposite answers, and the row's
/// pattern is a wildcard covering both -- so neither the pattern nor the event
/// name can be what decided.
#[test]
fn session_close_ingress_judges_the_arriving_keyexpr_not_the_row() {
    const TARGET: &str = "@/node-a/peer/session/close/peer-a";
    const SIBLING: &str = "@/node-a/peer/session/close/peer-b";

    for (keyexpr, expect_closed) in [(TARGET, true), (SIBLING, false)] {
        let (actions, mut engine) = established_session();
        let mut observer = ApplicationLayerObserver::new();
        observer
            .switchboard
            .register_command("@/node-a/peer/session/close/*", CLOSE_EVENT);

        let outcome = frame_event(put_push(keyexpr));
        // R2718 — the authority is scoped to the TARGET chunk, so this arm now
        // says the verdict follows `peer_zid` rather than the whole string.
        let only = AdmitOnly("peer-a");
        let fired = {
            let mut injector = SessionLifecycleInjector::new(&actions, &only);
            observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
        };

        assert_eq!(
            fired,
            usize::from(expect_closed),
            "one wildcard row, two keys: {keyexpr} should fire={expect_closed}"
        );
        assert_eq!(
            check_requested_close(&actions, &mut engine),
            expect_closed,
            "the staged request must follow the key, not the row"
        );
        assert_eq!(
            engine.get_current_state(),
            if expect_closed {
                SessionFsmUnicastState::Closing
            } else {
                SessionFsmUnicastState::Established
            },
            "and the STATE is what the claim rests on for {keyexpr}"
        );
    }
}

#[test]
fn session_close_ingress_request_is_set_once_and_taken_once() {
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
fn session_close_ingress_reads_the_name_off_the_machine() {
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
