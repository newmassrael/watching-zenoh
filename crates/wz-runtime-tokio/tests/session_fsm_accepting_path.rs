// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R78 — Accepting-side path integration test.
//!
//! Walks the listener half of the 4-way handshake through the
//! production-shaped `poll_and_dispatch_one` driver so two crafted
//! inbound wires (InitSyn + OpenSyn) terminate at `Established`
//! without the test hand-routing
//! `parse_inbound + inbound_to_fsm_event + Engine::process_event`.
//!
//! Path under test:
//!   `Init -(inbound.start)-> AwaitingInitSyn
//!         -(Rx InitSyn via poll_and_dispatch_one)-> SentInitAck
//!         -(Rx OpenSyn via poll_and_dispatch_one)-> Established`
//!
//! The Initiator-side `Rx(InitAck)` scenario was already covered by
//! `session_fsm_driver_loop.rs::scenario_1` at R76; this complement
//! confirms `poll_and_dispatch_one` handles both halves of the
//! handshake symmetrically (it must, since the helper does not
//! discriminate Initiator vs Accepting — the FSM does).
//!
//! Single `#[test]` fn because the two phases (Rx InitSyn then Rx
//! OpenSyn) form one continuous handshake walk — phase 2 depends on
//! phase 1's resulting FSM state. R79 closed the cross-test race
//! carry that previously forced the mega-test pattern here, but
//! splitting this particular path-dependent flow gains no granularity.

use std::sync::{Arc, Mutex};

use sce_rust_runtime::Engine;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver,
    LinkSendOutcome, PeerInitCaps, SessionActionsBinding, SessionLinkActions,
};
// R311fr — DriverLoopOutcome is referenced only by the
// transport-keepalive-gated r78 handshake test; gate the import to match
// so a transport-keepalive-off subset does not see an unused import.
#[cfg(feature = "transport-keepalive")]
use wz_runtime_tokio::session_glue::DriverLoopOutcome;
use wz_runtime_tokio::{LinkEvent, Reliability, RxFrame};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver, QueueDriver};
// R311it — craft_initsyn/opensyn_wire + FIXTURE_PEER_ZID come from the
// shared no_std SSOT (was copy-pasted here and in the sibling session_fsm_*
// test files + re-rolled in wz-mcu-session-acceptor).
use wz_session_wire_fixtures::{craft_initsyn_wire, craft_opensyn_wire, FIXTURE_PEER_ZID};

fn fresh_setup() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
) {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine)
}

// R311fr — Established.onentry starts the keepalive worker only under
// `transport-keepalive`; the SSOT consumer-plane subsets omit it, so this
// handshake-termination test asserts that behaviour only where it exists.
#[cfg(feature = "transport-keepalive")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r78_accepting_path_handshake_terminates_at_established() {
    let (actions, mut engine) = fresh_setup();
    assert_eq!(engine.get_current_state(), S::Init);

    // Init -> AwaitingInitSyn via inbound.start (listener role
    // activation; the driver loop does not synthesize this — the
    // production caller dispatches it on socket-accept).
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // ── Rx InitSyn via poll_and_dispatch_one ───────────────────────
    {
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "InitSyn Rx must AdvanceFsm; got {outcome:?}"
        );
        assert_eq!(
            engine.get_current_state(),
            S::SentInitAck,
            "Rx(InitSyn) must advance AwaitingInitSyn -> SentInitAck"
        );
        let trace = actions.trace_snapshot();
        assert_eq!(
            trace.send_init_ack_with_cookie, 1,
            "SentInitAck.onentry must dispatch send_init_ack_with_cookie"
        );
    }

    // ── Rx OpenSyn via poll_and_dispatch_one ───────────────────────
    {
        // R89 — the OpenSyn must echo the HMAC-bound cookie the
        // Accepting side minted on InitAck (R86) for the
        // `cookie_valid()` guard to pass. peer_zid was captured by
        // R86 on InitSyn arrival (= [0xB0..0xB3] from craft_initsyn_wire).
        // R311y813 — the nonce comes from the ACCEPTOR, not from a constant:
        // the cookie is bound to this handshake, so the test can no longer
        // assume the derivation is reproducible from the deploy key alone.
        let expected_cookie = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
            &fixture_session_init_params().cookie_signing_key,
            &FIXTURE_PEER_ZID,
            actions
                .cookie_nonce()
                .expect("new_session_actions installs a cookie nonce at construction"),
        );
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
            &expected_cookie,
        )))]);
        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::AdvancedFsm),
            "OpenSyn Rx must AdvanceFsm; got {outcome:?}"
        );
        // SentOpenAck has an eventless transition to Established;
        // the SCXML macrostep traverses both states in one
        // process_event so the observable state is Established.
        assert_eq!(
            engine.get_current_state(),
            S::Established,
            "Rx(OpenSyn) must drive SentInitAck -> SentOpenAck -> Established"
        );

        let trace = actions.trace_snapshot();
        assert_eq!(
            trace.send_open_ack, 1,
            "SentOpenAck.onentry must dispatch send_open_ack"
        );
        // Established.onentry side effects (matches
        // session_fsm_coverage.rs::r61 listener-path assertions).
        assert_eq!(
            trace.enable_rx_tx_regions, 1,
            "Established.onentry must enable rx/tx regions"
        );
        assert_eq!(
            trace.start_lease_monitor, 1,
            "Established.onentry must start the lease monitor"
        );
        assert_eq!(
            trace.start_keepalive_worker, 1,
            "Established.onentry must start the keepalive worker"
        );
        // R89 — the cookie_valid() guard MUST have fired exactly
        // once on the SentInitAck -> SentOpenAck transition. The
        // happy-path OpenSyn arrival was the only candidate.
        assert_eq!(
            trace.cookie_valid_check, 1,
            "R89 dynamic guard must fire exactly once on the valid \
             OpenSyn cookie echo path; got count={}",
            trace.cookie_valid_check
        );
    }
}

// ───────────── R89 cookie verification negative paths ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r89_invalid_cookie_blocks_transition_to_sentopen_ack() {
    // Setup mirrors r78 happy path up through SentInitAck, then
    // stages an OpenSyn whose cookie is byte-mismatched against the
    // R86-minted HMAC. The cookie_valid() guard must reject the
    // transition and the FSM must stay at SentInitAck.
    let recording_driver = Arc::new(NoopOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver + Send + Sync> = recording_driver;
    let actions = new_session_actions(driver_arc, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();

    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // Forged cookie: 16 bytes of 0xFF — guaranteed to mismatch any
    // valid HMAC(cookie_signing_key, peer_zid) output.
    let forged = vec![0xFFu8; 16];
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &forged,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;

    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "forged cookie must NOT advance the FSM past SentInitAck \
         (cookie_valid guard rejects); state={:?}",
        engine.get_current_state()
    );
    let trace = actions.trace_snapshot();
    assert!(
        trace.cookie_valid_check >= 1,
        "cookie_valid guard must have fired (and rejected); got count={}",
        trace.cookie_valid_check
    );
    assert_eq!(
        trace.send_open_ack, 0,
        "send_open_ack must NOT fire when cookie verification fails"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r89_missing_cookie_blocks_transition_to_sentopen_ack() {
    let recording_driver = Arc::new(NoopOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver + Send + Sync> = recording_driver;
    let actions = new_session_actions(driver_arc, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();

    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // Zero-length cookie carrier: cookie_len VLE = 0, no cookie
    // bytes. OpenBody.cookie decodes as Some(Vec::new()) per the
    // present-if gating; the R89 guard sees an empty Vec which
    // never matches a non-empty HMAC output.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(&[])))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;

    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "missing/empty cookie must NOT advance past SentInitAck"
    );
    let trace = actions.trace_snapshot();
    assert!(trace.cookie_valid_check >= 1);
    assert_eq!(trace.send_open_ack, 0);
}

// ────── R86 cookie HMAC binding (Accepting-side InitAck wire) ──────

/// Recording outbound driver that captures every send_blocking call
/// so R86's HMAC-bound cookie can be inspected post-dispatch. The
/// inert NoopOutboundDriver above discards bytes — fine for the R78
/// FSM-shape walk, but R86 needs the InitAck wire bytes.
#[derive(Default)]
struct RecordingOutboundDriver {
    sent: Mutex<Vec<Vec<u8>>>,
}

impl BoxedLinkDriver for RecordingOutboundDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.sent.lock().unwrap().push(bytes.to_vec());
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r86_send_init_ack_with_cookie_binds_to_inbound_peer_zid() {
    use wz_runtime_tokio::session_glue::{
        generate_cookie_hmac_sha256, parse_inbound, InboundFrame,
    };

    // Setup with a RecordingOutboundDriver so the InitAck wire bytes
    // are captured for cookie inspection.
    let recording_driver = Arc::new(RecordingOutboundDriver::default());
    let driver_arc: Arc<dyn BoxedLinkDriver + Send + Sync> = recording_driver.clone();
    let params = fixture_session_init_params();
    let actions = new_session_actions(driver_arc, params, TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();

    // Init -> AwaitingInitSyn (listener role activation)
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // Rx InitSyn (zid = [0xB0..0xB3] per craft_initsyn_wire) routes
    // through poll_and_dispatch_one -> handle_inbound captures
    // peer_zid -> FSM transitions to SentInitAck -> SentInitAck.onentry
    // fires send_init_ack_with_cookie which (per R86) HMAC-binds the
    // cookie against the captured peer_zid.
    let mut queue_driver =
        QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut queue_driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);
    assert_eq!(
        actions.inbound_peer_zid.lock().unwrap().as_deref(),
        Some(&FIXTURE_PEER_ZID[..]),
        "InitSyn dispatch must capture peer_zid before SentInitAck.onentry fires"
    );

    // The InitAck wire was just sent through the recording driver.
    let sends = recording_driver.sent.lock().unwrap().clone();
    assert_eq!(sends.len(), 1, "exactly one outbound frame (the InitAck)");
    let initack_wire = &sends[0];

    // Re-parse the wire and pull out the cookie field. The InitAck
    // re-encode path is verified byte-identical against zenoh-pico by
    // layer3_init_body.rs; here we just need the cookie value.
    let frame = parse_inbound(initack_wire).expect("outbound InitAck wire re-parses");
    let cookie = match frame {
        InboundFrame::Init {
            is_ack: true, body, ..
        } => body.cookie.expect("InitAck carries cookie payload"),
        other => panic!(
            "expected InitAck variant, got {other:?}",
            other = std::any::type_name_of_val(&other)
        ),
    };

    // The expected cookie is HMAC-SHA256(cookie_signing_key,
    // nonce || peer_zid) truncated to 16 bytes per RFC §5.M. Recompute it
    // inline using the same fixture key so the test is independent of the
    // cookie module's internal constants; the nonce is read off the acceptor
    // because R311y813 made it per-handshake.
    let nonce = actions
        .cookie_nonce()
        .expect("new_session_actions installs a cookie nonce at construction");
    let expected_cookie = generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &FIXTURE_PEER_ZID,
        nonce,
    );
    assert_eq!(
        cookie.as_slice(),
        expected_cookie.as_slice(),
        "R86: outbound InitAck cookie MUST be HMAC(cookie_signing_key, \
         nonce || inbound_peer_zid)[..16] — pre-R86 this was params.cookie \
         verbatim which violated RFC §5.M anti-amplification (deploy-static \
         cookie offers no per-peer replay defense)"
    );

    // R311y813 — and it must be bound to THIS handshake, not merely to the
    // peer. The same key and the same zid under a DIFFERENT nonce is what a
    // captured cookie amounts to on the next connection; asserting the wire
    // cookie differs from it is the assertion that the binding term reached
    // the wire at all.
    let cookie_under_another_nonce = generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &FIXTURE_PEER_ZID,
        nonce.wrapping_add(1),
    );
    assert_ne!(
        cookie.as_slice(),
        cookie_under_another_nonce.as_slice(),
        "the emitted cookie must depend on the per-handshake nonce -- if it \
         does not, every handshake with this peer mints the same 16 bytes",
    );
}

/// R311y813 THE DISCRIMINATOR. A cookie an acceptor minted for ONE handshake
/// must not open a LATER one with the same peer.
///
/// This is the replay the per-handshake nonce closes, and it is stated as an
/// end-to-end FSM outcome rather than as a property of the MAC: the attacker's
/// capability is "I saw one OpenSyn echo", and the question is whether
/// re-sending those 16 bytes at a fresh acceptor reaches `Established`.
///
/// Before this round it did. The cookie was `HMAC(deploy key, peer zid)[..16]`
/// — no term that changes between handshakes — so the second acceptor derived
/// the identical expected value and admitted the replay. Deleting `nonce` from
/// either the mint or the verify makes exactly this test fail; every other
/// accept-path test fixes one bundle and cannot see across two.
///
/// The nonces are INSTALLED rather than drawn so the outcome is decided by the
/// binding and not by entropy luck (that `new_session_actions` really draws
/// distinct ones is a separate assertion, in `session_glue`'s unit tests).
/// Both halves of the pair are asserted: the stale cookie is refused AND the
/// second acceptor's OWN cookie is admitted, so a refusal cannot come from the
/// second bundle simply being broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_from_an_earlier_handshake_is_refused_by_the_next() {
    /// Drive a fresh acceptor bundle to `SentInitAck` with the shared crafted
    /// InitSyn, under a caller-chosen cookie nonce.
    async fn acceptor_at_sent_init_ack(
        nonce: u64,
    ) -> (
        Arc<SessionLinkActions>,
        Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    ) {
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> =
            Arc::new(NoopOutboundDriver::default());
        let actions =
            new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
        actions.refresh_cookie_nonce(nonce);
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        engine.process_event(E::InboundStart);
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
        let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert_eq!(engine.get_current_state(), S::SentInitAck);
        (actions, engine)
    }

    const FIRST_NONCE: u64 = 0x1111_1111_1111_1111;
    const SECOND_NONCE: u64 = 0x2222_2222_2222_2222;
    let key = || fixture_session_init_params().cookie_signing_key;

    // Handshake 1 — the observer captures this cookie off the wire.
    let (_first_actions, _first_engine) = acceptor_at_sent_init_ack(FIRST_NONCE).await;
    let captured = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
        &key(),
        &FIXTURE_PEER_ZID,
        FIRST_NONCE,
    );

    // Handshake 2 — a NEW connection from the same peer, same deploy key.
    let (actions, mut engine) = acceptor_at_sent_init_ack(SECOND_NONCE).await;
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &captured,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;

    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "a cookie minted for an EARLIER handshake must not advance this one; \
         reaching Established here is the replay window R311y813 closed"
    );
    assert_eq!(
        actions.trace_snapshot().send_open_ack,
        0,
        "the replayed cookie must not reach send_open_ack"
    );
    assert!(
        actions.trace_snapshot().cookie_valid_check >= 1,
        "the guard must have RUN and rejected -- a refusal from never running \
         would prove nothing about the binding"
    );

    // ANTI-VACUITY: the same acceptor admits the cookie IT minted.
    let own = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
        &key(),
        &FIXTURE_PEER_ZID,
        SECOND_NONCE,
    );
    assert_ne!(
        own, captured,
        "the two handshakes must mint different cookies, else the refusal \
         above is untestable"
    );
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(&own)))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(
        engine.get_current_state(),
        S::Established,
        "this handshake's OWN cookie must still be admitted -- otherwise the \
         refusal above is just a broken acceptor"
    );
}

/// R311y813 — an acceptor with NO cookie nonce installed is fail-CLOSED: it
/// mints no HMAC cookie and admits no OpenSyn.
///
/// The alternative rejected here is a silent fallback to the un-bound
/// derivation, which would be indistinguishable from the defect this round
/// removed — an operator reading a healthy session could not tell whether the
/// binding was in force. `new_generic`'s default is `None`, so this drives the
/// core constructor directly rather than the AP seam that installs one.
///
/// The InitAck still goes out (anti-amplification is about not ANSWERING a
/// forged OpenSyn, and the InitAck is the round-trip challenge itself); it
/// carries `params.cookie` verbatim, which no initiator can turn into a
/// passing echo because `cookie_valid` denies on the absent nonce regardless
/// of what came back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_cookie_nonce_the_acceptor_admits_no_open_syn() {
    use wz_runtime_tokio::runtime_impl::TokioRuntime;

    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    // `new_generic`, not `new_session_actions`: the AP seam installs a nonce,
    // and this test is about the state before one is installed.
    let actions = SessionLinkActions::<TokioRuntime, TokioTime>::new_generic(
        outbound,
        fixture_session_init_params(),
        TokioTime::new(),
    );
    assert_eq!(
        actions.cookie_nonce(),
        None,
        "the core constructor must not invent a nonce it has no entropy for"
    );
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // The cookie the OLD, un-bound derivation would have produced. If the mint
    // had fallen back to it, this echo would establish the session.
    let unbound = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &FIXTURE_PEER_ZID,
        0,
    );
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &unbound,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "no nonce installed must mean no OpenSyn is admitted, not a quiet \
         fallback to the deploy-static cookie"
    );
    assert_eq!(actions.trace_snapshot().send_open_ack, 0);
}

// ── R311fb staleness guard: once the accept handshake reaches Established,
//    a stale accepting.inactivity_timeout (armed on AwaitingInitSyn entry,
//    delivered after Established) must be discarded. Established is outside
//    the Accepting state that handles the event, so the single armed timer
//    has no handler in scope and cannot kill a healthy session. The
//    single-arm parent-scoped design needs no per-phase child-scoping (unlike
//    R311fa's init_ack/open_ack timers) precisely because there is only ever
//    one timer of this event name in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r311fb_stale_accept_inactivity_timeout_after_established_is_discarded() {
    let (actions, mut engine) = fresh_setup();
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // Walk the crafted handshake to Established (same wires as r78).
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = wz_runtime_tokio::session_glue::generate_cookie_hmac_sha256(
        &fixture_session_init_params().cookie_signing_key,
        &FIXTURE_PEER_ZID,
        actions
            .cookie_nonce()
            .expect("new_session_actions installs a cookie nonce at construction"),
    );
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);

    // Deliver the now-stale accept inactivity timer.
    engine.process_event(E::AcceptingInactivityTimeout);

    assert_eq!(
        engine.get_current_state(),
        S::Established,
        "a stale accepting.inactivity_timeout after Established must be \
         discarded (no handler in scope), leaving the session healthy"
    );
    assert_eq!(
        actions.trace_snapshot().set_close_reason_count,
        0,
        "the discarded stale timer must not run any close-reason action"
    );
}

// ───────────── R121d peer-caps negotiation unit tests ──────────────

#[test]
fn r121d_peer_init_caps_from_init_body_uses_defaults_when_s_bit_clear() {
    // When the peer's InitSyn carries `_Z_FLAG_T_INIT_S=0`, the
    // `sn_res` byte and `batch_size` are absent on the wire; the
    // decoder must substitute the Zenoh defaults
    // (`_Z_DEFAULT_RESOLUTION_SIZE=2`, `_Z_DEFAULT_UNICAST_BATCH_SIZE
    // =65535`) so the downstream `min(own, peer)` cap in
    // `init_ack_params` keeps the own params verbatim (peer's stated
    // ceiling is the maximum).
    let caps = PeerInitCaps::from_init_body(None, None);
    assert_eq!(caps.seq_num_res, 2);
    assert_eq!(caps.req_id_res, 2);
    assert_eq!(caps.batch_size, 65535);
}

// R311kl — PeerInitCaps decode is feature-independent (the R311fr-era
// `transport-batching` gate over the honoring was removed; negotiation
// is core transport), so this caps-behaviour test runs in every lane.
#[test]
fn r121d_peer_init_caps_decodes_packed_sn_res_byte() {
    // The InitSyn `sn_res` byte is packed
    // `(seq & 0x03) | ((req & 0x03) << 2)` per zenoh-pico
    // transport.c:196-197. Encoder shape: seq=1, req=2 →
    // 0x01 | (0x02 << 2) = 0x09. Decoder must invert that
    // composition exactly.
    let caps = PeerInitCaps::from_init_body(Some(0x09), Some(1024));
    assert_eq!(caps.seq_num_res, 1, "low 2 bits are seq_num_res");
    assert_eq!(caps.req_id_res, 2, "next 2 bits are req_id_res");
    assert_eq!(caps.batch_size, 1024);
}

// R311kl — InitAck caps negotiation is core transport behaviour
// (formerly `transport-batching`-gated, R311fr); runs in every lane.
#[test]
fn r121d_init_ack_params_caps_to_peer_when_peer_lower() {
    // The wire-spec invariant `InitAck.size <= InitSyn.size`
    // (zenoh-pico unicast/transport.c:123-140) requires the
    // Accepting side to cap each sizing field to `min(own, peer)`.
    // Construct an actions instance whose own params announce
    // permissive ceilings, capture a peer with stricter caps via
    // the inbound slot, and verify `init_ack_params` flattens the
    // three fields to the peer's stricter values.
    let driver: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.seq_num_res = 3;
    params.req_id_res = 3;
    params.batch_size = 65535;
    let actions = new_session_actions(driver, params, TokioTime::new());

    // No peer InitSyn parsed yet → init_ack_params returns own
    // params verbatim (the slot is `None`).
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 3);
    assert_eq!(p.req_id_res, 3);
    assert_eq!(p.batch_size, 65535);

    // Capture peer caps with stricter values across the board.
    *actions.inbound_peer_init_caps.lock().unwrap() = Some(PeerInitCaps {
        seq_num_res: 2,
        req_id_res: 1,
        batch_size: 2048,
    });
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 2, "seq_num_res capped to peer");
    assert_eq!(p.req_id_res, 1, "req_id_res capped to peer");
    assert_eq!(p.batch_size, 2048, "batch_size capped to peer");
}

#[test]
fn r121d_init_ack_params_keeps_own_when_own_lower() {
    // Symmetric case — when our own announced caps are stricter
    // than the peer's, `min(own, peer) = own`. Verifies the cap
    // never accidentally promotes a value upward.
    let driver: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let mut params = fixture_session_init_params();
    params.seq_num_res = 1;
    params.req_id_res = 1;
    params.batch_size = 512;
    let actions = new_session_actions(driver, params, TokioTime::new());

    *actions.inbound_peer_init_caps.lock().unwrap() = Some(PeerInitCaps {
        seq_num_res: 3,
        req_id_res: 3,
        batch_size: 65535,
    });
    let p = actions.init_ack_params();
    assert_eq!(p.seq_num_res, 1, "own seq_num_res preserved (1 < 3)");
    assert_eq!(p.req_id_res, 1, "own req_id_res preserved (1 < 3)");
    assert_eq!(p.batch_size, 512, "own batch_size preserved (512 < 65535)");
}
