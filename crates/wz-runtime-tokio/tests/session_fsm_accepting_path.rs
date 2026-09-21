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
    decode_accept_cookie, encode_accept_cookie, new_session_actions, new_session_engine,
    poll_and_dispatch_one, AcceptCookieState, AuthAcceptState, BoxedLinkDriver,
    CompressionAcceptState, LinkSendOutcome, LowlatencyAcceptState, MultilinkAcceptState,
    NegotiatedExtensions, PatchAcceptState, PeerInitCaps, QosAcceptState, RegionAcceptState,
    SessionActionsBinding, SessionLinkActions, ShmAcceptState,
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
use wz_session_wire_fixtures::{
    craft_initsyn_wire, craft_initsyn_wire_with_patch, craft_opensyn_wire, FIXTURE_PEER_ZID,
};

/// R2769 — the setup KEEPS the bytes the acceptor sends.
///
/// The inert driver discarded them, which is why every cookie test in this
/// file used to RECONSTRUCT what it believed was on the wire. Recording costs
/// a `Vec` per frame and lets a test read the artifact instead, so the
/// witness stops being a second copy of the mint.
///
/// ⚠ THE NON-RECORDING FORM IS GONE RATHER THAN KEPT AS A WRAPPER: after the
/// last caller moved, `fresh_setup` had none, and the compiler said so. A
/// wrapper nothing calls is a second way to set up that the next test would
/// have to choose between for no reason.
fn fresh_setup_recording() -> (
    Arc<SessionLinkActions>,
    Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
    Arc<RecordingOutboundDriver>,
) {
    let recording = Arc::new(RecordingOutboundDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recording.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    (actions, engine, recording)
}

// R311fr — Established.onentry starts the keepalive worker only under
// `transport-keepalive`; the SSOT consumer-plane subsets omit it, so this
// handshake-termination test asserts that behaviour only where it exists.
#[cfg(feature = "transport-keepalive")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r78_accepting_path_handshake_terminates_at_established() {
    let (actions, mut engine, recording) = fresh_setup_recording();
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
        // R2769 — taken OFF the InitAck this acceptor just sent, which is
        // what an initiator echoes. It used to be rebuilt from the deploy key
        // and the nonce slot, and that made this FSM-shape walk depend on the
        // mint's internals: the walk is about reaching Established, so it
        // should not have an opinion about how a cookie is built.
        let expected_cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
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

/// The cookie the acceptor ACTUALLY minted, read off the InitAck it sent.
///
/// R2769 — every caller here used to RECONSTRUCT the cookie by calling the
/// mint's own primitive with the same inputs, which made the witness a second
/// implementation of its subject. The cost was measured the moment the mint
/// changed from a bare tag to a state-carrying cookie: FOUR tests failed
/// together and not one of them was about what changed. Reading the ARTIFACT
/// cannot go stale that way — whatever the acceptor put on the wire is
/// exactly what a peer would echo, which is also what these tests are for.
///
/// Panics rather than returning an Option: a caller reaches this only after
/// asserting the FSM is at `SentInitAck`, so an absent InitAck is a broken
/// fixture and not a case to handle.
fn minted_cookie(sent: &[Vec<u8>]) -> Vec<u8> {
    minted_cookie_opt(sent).unwrap_or_else(|| {
        panic!(
            "no InitAck carrying a cookie among {} captured frame(s)",
            sent.len()
        )
    })
}

/// The same read, for a caller that must be able to say "nothing was sent".
///
/// R2769 — separate from [`minted_cookie`] because ONE caller genuinely has
/// to distinguish an absent frame from a broken fixture: the re-handshake
/// path emits nothing (open-debt item 801), and a helper that panics cannot
/// let a test PIN that.
fn minted_cookie_opt(sent: &[Vec<u8>]) -> Option<Vec<u8>> {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};
    let mut seen: Vec<String> = Vec::new();
    for wire in sent {
        match parse_inbound(wire) {
            Ok(InboundFrame::Init {
                is_ack: true, body, ..
            }) => match body.cookie.clone() {
                Some(c) => return Some(c.to_vec()),
                None => seen.push("InitAck with NO cookie field".to_string()),
            },
            Ok(other) => seen.push(format!("{} bytes, {other:?}", wire.len())),
            Err(e) => seen.push(format!("{} bytes, unparsable: {e:?}", wire.len())),
        }
    }
    // Kept even though the caller may tolerate a None: a frame that IS an
    // InitAck and carries no cookie, or one that will not parse at all, are
    // different findings from an empty log, and a bare `None` loses which.
    // The old failure said only "expected an InitAck", which is true of all
    // three.
    if !seen.is_empty() {
        eprintln!(
            "minted_cookie: {} frame(s), none an InitAck with a cookie: {seen:?}",
            sent.len()
        );
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r86_send_init_ack_with_cookie_binds_to_inbound_peer_zid() {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};

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
    // R2782 — "the InitSyn dispatch captured the zid before the mint" is
    // asserted on the COOKIE below (`carried.peer_zid`), not on the slot: the
    // slot is released once the InitAck is out, as the rest of the cookie's
    // head is, so reading it here would pin the hold that round removed.

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

    // R2769 — the cookie is DECODED rather than recomputed, and that is the
    // whole change in this assertion. Recomputing asked "does the mint agree
    // with a second copy of itself"; decoding asks what the atom's clause
    // asks — does the thing on the wire CARRY this handshake's state. R86's
    // original claim survives inside it: the zid is still bound, it is just
    // bound by being under the MAC rather than by being hashed into it.
    let nonce = actions
        .cookie_nonce()
        .expect("new_session_actions installs a cookie nonce at construction");
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies under the deploy key");
    assert_eq!(
        carried.peer_zid, FIXTURE_PEER_ZID,
        "R86: the InitAck cookie MUST bind the peer zid captured on InitSyn \
         — pre-R86 this was params.cookie verbatim, which violated RFC §5.M \
         anti-amplification (a deploy-static cookie offers no per-peer \
         replay defense)"
    );
    assert_eq!(
        carried.nonce, nonce,
        "R311y813: and to THIS handshake, by the nonce the acceptor drew"
    );

    // R311y813 — and it must be bound to THIS handshake, not merely to the
    // peer. The same key and the same zid under a DIFFERENT nonce is what a
    // captured cookie amounts to on the next connection; asserting the wire
    // cookie differs from it is the assertion that the binding term reached
    // the wire at all.
    //
    // R2769 — built by re-minting the state the wire carried with ONE field
    // moved, which is the honest way to say "the same handshake except for
    // the nonce". Reconstructing it from the primitive would put the second
    // implementation back.
    let mut next = carried.clone();
    next.nonce = nonce.wrapping_add(1);
    let cookie_under_another_nonce =
        encode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &next)
            .expect("a re-mint of a cookie this acceptor already emitted encodes");
    assert_ne!(
        cookie.as_slice(),
        cookie_under_another_nonce.as_slice(),
        "the emitted cookie must depend on the per-handshake nonce -- if it \
         does not, every handshake with this peer mints the same bytes",
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
///
/// R2763 — and installing them now means building through `new_generic`. The
/// AP seam installs an entropy SOURCE, and a bundle that has one re-draws on
/// every InitAck, so a hand-installed nonce would be overwritten before it was
/// used. That ordering is deliberate — a configured source is the live answer
/// and `refresh_cookie_nonce` is the affordance for a bundle without one — and
/// this test is the FSM-level witness of the other arm: no source installed
/// leaves the nonce exactly as a host put it.
/// Both halves of the pair are asserted: the stale cookie is refused AND the
/// second acceptor's OWN cookie is admitted, so a refusal cannot come from the
/// second bundle simply being broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_from_an_earlier_handshake_is_refused_by_the_next() {
    /// Drive a fresh acceptor bundle to `SentInitAck` with the shared crafted
    /// InitSyn, under a caller-chosen cookie nonce.
    /// R2769 — the driver RECORDS, so the caller takes the cookie the
    /// acceptor really emitted instead of re-deriving what it thinks it
    /// emitted. That is the whole point of a replay test: the attacker's
    /// capability is "I saw the wire", and a reconstruction models the mint
    /// rather than the wire.
    async fn acceptor_at_sent_init_ack(
        nonce: u64,
    ) -> (
        Arc<SessionLinkActions>,
        Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
        Vec<u8>,
    ) {
        use wz_runtime_tokio::runtime_impl::TokioRuntime;

        let recording = Arc::new(RecordingOutboundDriver::default());
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recording.clone();
        let actions = SessionLinkActions::<TokioRuntime, TokioTime>::new_generic(
            outbound,
            fixture_session_init_params(),
            TokioTime::new(),
        );
        actions.refresh_cookie_nonce(nonce);
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        engine.process_event(E::InboundStart);
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
        let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert_eq!(engine.get_current_state(), S::SentInitAck);
        let sent = recording.sent.lock().unwrap().clone();
        let cookie = minted_cookie(&sent);
        (actions, engine, cookie)
    }

    const FIRST_NONCE: u64 = 0x1111_1111_1111_1111;
    const SECOND_NONCE: u64 = 0x2222_2222_2222_2222;

    // Handshake 1 — the observer captures this cookie off the wire.
    let (_first_actions, _first_engine, captured) = acceptor_at_sent_init_ack(FIRST_NONCE).await;

    // Handshake 2 — a NEW connection from the same peer, same deploy key.
    let (actions, mut engine, own) = acceptor_at_sent_init_ack(SECOND_NONCE).await;
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

    // ANTI-VACUITY: the same acceptor admits the cookie IT minted, taken off
    // its own InitAck rather than rebuilt.
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

/// R2763 THE SAME-BUNDLE DISCRIMINATOR. One acceptor, two handshakes: the
/// cookie minted for the first must not open the second.
///
/// The sibling above proves the BINDING works by installing two nonces by
/// hand on two bundles. That leaves the question this test asks, which is the
/// one `session-unicast-accept`'s standing clause is about: does the acceptor
/// draw a fresh nonce PER HANDSHAKE, the way
/// `io/zenoh-transport/src/unicast/establishment/accept.rs` @ `let nonce: u64 = prng.gen();`
/// does inside its InitAck path? A draw at bundle CONSTRUCTION satisfies every
/// two-bundle test and still hands two handshakes on one bundle the same 16
/// bytes.
///
/// Nothing is installed here. The nonce is whatever the AP construction seam
/// arranges, which is the point — this test is about the seam, not about the
/// MAC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_bundle_mints_a_different_cookie_for_each_handshake() {
    /// Drive `actions` from `Init` to `SentInitAck` with the shared crafted
    /// InitSyn, and hand back the cookie that handshake minted.
    ///
    /// R2769 — read OFF THE WIRE. This used to rebuild the cookie from
    /// `cookie_nonce()` because the inert driver kept no bytes, and its own
    /// note said so; recording removes the reason. It matters more here than
    /// anywhere else in the file: the subject is whether the acceptor DRAWS
    /// per handshake, and a reconstruction from the slot would agree with the
    /// slot no matter what the wire carried.
    async fn handshake_to_sent_init_ack(
        actions: &Arc<SessionLinkActions>,
        engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding>>,
        recording: &Arc<RecordingOutboundDriver>,
    ) -> (usize, Option<Vec<u8>>) {
        let before = recording.sent.lock().unwrap().len();
        engine.process_event(E::InboundStart);
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
        let _ = poll_and_dispatch_one(&mut driver, actions, engine).await;
        assert_eq!(engine.get_current_state(), S::SentInitAck);
        // Only the frames THIS handshake sent: the bundle is reused across
        // two handshakes here, so reading the whole log would hand the
        // second call the first one's InitAck and the test would compare a
        // cookie with itself.
        let all = recording.sent.lock().unwrap().clone();
        (all.len() - before, minted_cookie_opt(&all[before..]))
    }

    let (actions, mut engine, recording) = fresh_setup_recording();
    let (first_frames, first) = handshake_to_sent_init_ack(&actions, &mut engine, &recording).await;
    assert!(first_frames > 0, "the first handshake must reach the wire");
    let first = first.expect("the first handshake's InitAck carries a cookie");
    let first_nonce = actions.cookie_nonce().expect("a nonce was drawn");

    // The acceptor-role re-handshake the `cookie_nonce` slot's own note names:
    // the slot survives this reset on purpose, so an un-refreshed bundle
    // re-mints its previous handshake's cookie.
    //
    // ⛔ R2771 — A NEW ENGINE, and `engine.initialize()` is NOT a substitute.
    // That is what this test used to do, and it made the whole second half
    // VACUOUS from R2763 until here: `Engine::initialize` does not reset
    // `current_state`, it builds the entry chain FROM it
    // (`vendor/sce/backends/rust/runtime/src/engine.rs` @
    // `build_entry_chain::<P>(self.current_state)`). So it re-fired
    // `SentInitAck.onentry` on an engine already there, and the "second
    // handshake" that followed hit a state with exactly one outgoing
    // transition — `sources/session/session_fsm_unicast.scxml` gives
    // `SentInitAck` only `open_syn.received` — so an InitSyn caused no
    // transition, no entry, no onentry and no frame. `get_current_state()`
    // still read `SentInitAck` because the FSM had never LEFT it, and the
    // assertion passed on that. `Engine::new` is what starts at
    // `P::initial_state()`.
    actions.reset_for_reopen();
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    assert_eq!(
        engine.get_current_state(),
        S::Init,
        "a fresh engine must start at Init -- if it does not, the second \
         handshake below is the same non-event the old fixture measured"
    );
    let (second_frames, second) =
        handshake_to_sent_init_ack(&actions, &mut engine, &recording).await;
    assert!(
        second_frames > 0,
        "the second handshake must reach the wire; 0 frames is the vacuity \
         open-debt 801 recorded"
    );
    let second = second.expect("the second handshake's InitAck carries a cookie");
    let second_nonce = actions.cookie_nonce().expect("a nonce was drawn");

    // THE SUBJECT, now asked of the WIRE and not of a slot: one bundle's two
    // handshakes must not mint the same cookie. The nonce is asserted beside
    // it because the draw is what R2763 moved, and a cookie difference that
    // did not come from the nonce would be a different claim.
    assert_ne!(
        first, second,
        "one bundle's two handshakes must not mint the same cookie -- an \
         initiator that echoed the first handshake's bytes would pass the \
         second's cookie_valid, which is the replay a per-handshake draw \
         closes"
    );
    assert_ne!(
        first_nonce, second_nonce,
        "and the difference must come from the per-handshake nonce draw"
    );

    // THE REPLAY CLAIM ITSELF: the first handshake's cookie must be REFUSED
    // by the second. This is the assertion the whole test exists for, and
    // until R2771 it ran against a "second handshake" that had never
    // happened, so a refusal proved nothing — an acceptor that had not moved
    // refuses on the nonce it still holds.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &first,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(
        engine.get_current_state(),
        S::SentInitAck,
        "the FIRST handshake's cookie must not open the second"
    );

    // ANTI-VACUITY, and it is restored rather than new: the second handshake
    // must still admit the cookie IT minted, read off its own InitAck. Without
    // this arm the refusal above is satisfied by an acceptor that admits
    // nothing at all, which is the shape a broken second handshake has.
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &second,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(
        engine.get_current_state(),
        S::Established,
        "this handshake's OWN cookie must still be admitted -- otherwise the \
         refusal above is just a broken acceptor"
    );
}

/// R2772 — THE REBUILD. After an admitted OpenSyn the acceptor's negotiated
/// state comes from the COOKIE, not from whatever it happened to still hold.
///
/// ## Why this is asked of `patch` and of nothing else
///
/// The cookie carries five accept states, and four of them are UNOBSERVABLE
/// in this build: `transport-qos`, `-lowlatency`, `-compression` and `-shm`
/// are absent from `wz-runtime-tokio`'s default feature set, so those slots
/// do not exist and both the cookie and the acceptor read `false`. A witness
/// over them would be the "population of zero reports green" trap — the
/// rebuild could be deleted and nothing would move. `negotiated_patch` is an
/// ungated field carrying `Option<u8>`, so it is the one member a default
/// build can see, and it is the member a flag bit could never have held.
///
/// ## What makes the assertion impossible to satisfy by accident
///
/// `negotiate_patch_against_peer` is a `min()` — monotonically
/// non-increasing, which its own note states. So the test LOWERS the held
/// level by hand and then requires it to come back UP. A rise cannot come
/// from the merge in any circumstance; the cookie is the only other source.
/// That is what separates "the rebuild ran" from "the value was already
/// right", which is the way a rebuild witness usually goes vacuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_open_syn_rebuilds_the_negotiated_state_from_the_cookie() {
    let (actions, mut engine, recording) = fresh_setup_recording();
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(
        craft_initsyn_wire_with_patch(2),
    ))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // The cookie is read off the wire, so what is asserted is what a peer
    // would echo rather than what this test believes was minted. R2774 made
    // it the ONLY place the level can be read here: the acceptor lets go of
    // its slots once the InitAck is out.
    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    let negotiated = carried
        .negotiated
        .patch
        .0
        .expect("an admitted InitSyn agrees a level, and the cookie carries it");
    assert!(
        negotiated >= 1,
        "ANTI-VACUITY: this handshake must negotiate a level the test can \
         LOWER, or the damage below is a no-op and the restore proves \
         nothing; got {negotiated}"
    );

    // DAMAGE the slot. `min()` can only lower, which is exactly why this is a
    // safe way to disturb it: nothing in the session can undo it except a
    // write from outside the merge. Since R2774 the slot starts EMPTY here,
    // and the damage is still what keeps the restore honest — from `None`
    // the `min()` merge would rise to the carried level on its own, so a
    // rebuild routed through the merge would pass without the damage.
    actions.negotiate_patch_against_peer(negotiated - 1);
    assert_eq!(
        actions.negotiated_patch(),
        negotiated - 1,
        "the min() merge must have lowered the held level"
    );

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(
        actions.negotiated_patch(),
        negotiated,
        "the admitted OpenSyn must RESTORE the level the cookie carried -- a \
         RISE is impossible from the min() merge, so the cookie is the only \
         place it can have come from"
    );
}

/// R2774 — THE RELEASE. Between InitAck and OpenSyn the acceptor holds none
/// of the negotiated state its cookie carries, and the OpenSyn rebuild is
/// what puts it back.
///
/// Upstream's acceptor holds nothing there because `send_init_ack` takes its
/// `State` by value —
/// `io/zenoh-transport/src/unicast/establishment/accept.rs` @ `type SendInitAckIn = (State, SendInitAckIn);`
/// — and `recv_open_syn` builds a new one from the cookie.
///
/// `patch` carries the witness in a default build, for the reason the rebuild
/// test gives. It is read through `patch_was_negotiated()`, which separates
/// "nothing agreed" from "agreed 0", so an acceptor that kept the level cannot
/// pass the middle assertion by happening to hold a zero.
///
/// The QoS arm is the stronger discriminator where it compiles: the offer and
/// the outcome DIFFER there — this node offers QoS and the peer does not — so
/// the slot reads the offer after InitAck and the outcome after OpenSyn, and
/// only a release followed by a rebuild produces that pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_acceptor_holds_no_negotiated_state_between_init_ack_and_open_syn() {
    let (actions, mut engine, recording) = fresh_setup_recording();
    #[cfg(feature = "transport-qos")]
    assert!(actions.set_qos_offer(true), "qos offer applies");
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(
        craft_initsyn_wire_with_patch(2),
    ))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    let agreed = carried
        .negotiated
        .patch
        .0
        .expect("ANTI-VACUITY: the handshake must agree a level for the release to let go of");
    assert!(
        !actions.patch_was_negotiated(),
        "after the InitAck the acceptor must hold no agreed level -- the \
         cookie carries it"
    );
    #[cfg(feature = "transport-qos")]
    {
        assert!(
            !carried.negotiated.qos.negotiated(),
            "ANTI-VACUITY: the peer offered no QoS, so the outcome must differ \
             from this node's offer"
        );
        assert!(
            actions.is_qos(),
            "after the InitAck the QoS slot is back at this node's OFFER"
        );
    }

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(
        (actions.patch_was_negotiated(), actions.negotiated_patch()),
        (true, agreed),
        "the admitted OpenSyn puts back the level the cookie carried"
    );
    #[cfg(feature = "transport-qos")]
    assert!(
        !actions.is_qos(),
        "the admitted OpenSyn puts back the OUTCOME, not the offer"
    );
}

/// R2780 — the peer's REGION NAME rides the cookie: between InitAck and
/// OpenSyn the acceptor holds none, and the admitted OpenSyn puts back the
/// name the InitSyn announced.
///
/// The InitSyn is a real wz initiator's, off its recording driver, with a
/// region identity set, so the entry on the wire is wz's own encoder's. The
/// carried name is decoded out of the cookie in the InitAck the acceptor
/// actually sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_peer_region_rides_the_cookie_between_init_ack_and_open_syn() {
    use wz_session_core::extregion::RegionName;

    let region = RegionName::new("eu-west").expect("a valid region name");
    let (initiator, mut initiator_engine, initiator_wire) = fresh_setup_recording();
    initiator.set_local_region(Some(region.clone()));
    initiator_engine.process_event(E::OutboundStart);
    initiator_engine.process_event(E::LinkOpened);
    let init_syn = initiator_wire
        .sent
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the initiator sent its InitSyn");

    let (actions, mut engine, recording) = fresh_setup_recording();
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    assert_eq!(
        carried.negotiated.region.name(),
        Some(region.clone()),
        "the cookie carries the region the InitSyn announced"
    );
    assert_eq!(
        actions.peer_region(),
        None,
        "after the InitAck the acceptor holds no peer region -- it is in the cookie"
    );

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(
        actions.peer_region(),
        Some(region),
        "the admitted OpenSyn puts back the region the cookie carried"
    );
}

/// R2782 — the cookie's HEAD rides it: the peer's zid, its role and its
/// sizing caps. Between InitAck and OpenSyn the acceptor holds none of the
/// four slots they live in, and the admitted OpenSyn puts back exactly what
/// the InitSyn announced -- read off the InitSyn's own bytes, not restated.
///
/// The two sides announce DIFFERENT rings on purpose, the acceptor 32-bit and
/// the initiator 8-bit, so the negotiated ring is the peer's. The RX SN seed
/// reads that ring, and one run before the restore would read the acceptor's
/// own advertisement instead and leave a different baseline -- which is what
/// the last assertion tells apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cookie_head_rides_between_init_ack_and_open_syn() {
    use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame, WhatAmI};
    use wz_session_core::sn::{mask_from_res, RxConduits};

    // A real wz initiator's InitSyn, with an identity, a role and caps that
    // are all unlike the acceptor's.
    let initiator_wire = Arc::new(RecordingOutboundDriver::default());
    let initiator_out: Arc<dyn BoxedLinkDriver + Send + Sync> = initiator_wire.clone();
    let mut initiator_params = fixture_session_init_params();
    initiator_params.zid = vec![0x5A; 4];
    initiator_params.whatami = WhatAmI::Client;
    initiator_params.seq_num_res = 0;
    initiator_params.req_id_res = 1;
    initiator_params.batch_size = 2048;
    let initiator = new_session_actions(initiator_out, initiator_params, TokioTime::new());
    let mut initiator_engine = new_session_engine(&initiator);
    initiator_engine.initialize();
    initiator_engine.process_event(E::OutboundStart);
    initiator_engine.process_event(E::LinkOpened);
    let init_syn = initiator_wire
        .sent
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the initiator sent its InitSyn");
    let announced = match parse_inbound(&init_syn).expect("the InitSyn parses") {
        InboundFrame::Init {
            is_ack: false,
            body,
            ..
        } => body,
        _ => panic!("the initiator's first frame is an InitSyn"),
    };

    // The acceptor, on a WIDER ring than the initiator announces.
    let recording = Arc::new(RecordingOutboundDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = recording.clone();
    let mut params = fixture_session_init_params();
    params.seq_num_res = 2;
    let actions = new_session_actions(outbound, params, TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    assert_eq!(
        carried.peer_zid,
        announced.zid.as_slice(),
        "the head carries the zid"
    );
    assert_eq!(carried.peer_whatami, announced.whatami(), "and the role");
    assert_eq!(
        PeerInitCaps::from_init_body(Some(carried.sn_res), Some(carried.batch_size)),
        PeerInitCaps::from_init_body(announced.sn_res, announced.batch_size),
        "and the sizing caps the InitSyn announced"
    );

    assert_eq!(
        actions.peer_zid(),
        None,
        "after the InitAck: no routing zid"
    );
    assert!(
        actions.inbound_peer_zid.lock().unwrap().is_none(),
        "no accept-side zid"
    );
    assert_eq!(actions.peer_whatami_wire(), None, "no role");
    assert!(
        actions.inbound_peer_init_caps.lock().unwrap().is_none(),
        "no caps -- all four are in the cookie"
    );

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);

    let zid = announced.zid.as_slice().to_vec();
    assert_eq!(
        actions.peer_zid(),
        Some(zid.clone()),
        "the routing zid is back"
    );
    assert_eq!(
        *actions.inbound_peer_zid.lock().unwrap(),
        Some(zid),
        "the accept-side zid is back"
    );
    assert_eq!(
        actions.peer_whatami_wire(),
        Some(announced.whatami()),
        "the role is back"
    );
    assert_eq!(
        *actions.inbound_peer_init_caps.lock().unwrap(),
        Some(PeerInitCaps::from_init_body(
            announced.sn_res,
            announced.batch_size
        )),
        "the caps are back"
    );

    // The seed read the RESTORED ring. `craft_opensyn_wire` announces
    // initial_sn 0.
    let negotiated = actions.negotiated_sn_mask();
    assert_ne!(
        negotiated,
        mask_from_res(2),
        "ANTI-VACUITY: the negotiated ring must differ from the acceptor's own, \
         or a seed that read the wrong one would pass"
    );
    let mut expected = RxConduits::default();
    expected.seed(negotiated, 0);
    assert_eq!(
        *actions.rx_sn.lock().unwrap(),
        expected,
        "the RX baseline is one before initial_sn on the NEGOTIATED ring"
    );
}

/// R2782 — the OpenSyn that admitted a session admits NOTHING after it.
///
/// MEASURED before the fix, through this same drive: a replay of the
/// admitting OpenSyn after `Established` passed `cookie_valid` (the nonce
/// was still in its slot), reset the RX SN baseline, and a frame the session
/// had already delivered was delivered again. The parse step also took the
/// replay's lease. Upstream's nonce lives on one call's stack, so its second
/// OpenSyn has nothing to match; the nonce is now spent by the OpenSyn it
/// admits, and the seed and the lease wait for admission.
///
/// The replay carries a DIFFERENT lease from the admitted one, so "the lease
/// did not move" is a claim about the replay and not about two equal values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_open_syn_after_established_is_not_admitted() {
    use wz_codecs::wire_const::T_MID_OPEN;
    use wz_runtime_tokio::session_glue::DriverLoopOutcome;
    use wz_session_wire_fixtures::craft_frame_wire;

    let (actions, mut engine, recording) = fresh_setup_recording();
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);

    for sn in [0u64, 1] {
        let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_frame_wire(
            sn, true,
        )))]);
        let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
        assert!(
            matches!(outcome, DriverLoopOutcome::FramePayload { .. }),
            "frame {sn} is delivered; got {outcome:?}"
        );
    }
    let rx_before = actions.rx_sn.lock().unwrap().clone();
    let lease_before = *actions.peer_open_lease_ms.lock().unwrap();

    // The same cookie, a different lease (VLE 5, where the admitted one
    // announced 0).
    let mut replay = vec![T_MID_OPEN, 0x05, 0x00, cookie.len() as u8];
    replay.extend_from_slice(&cookie);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(replay))]);
    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::SideEffectOnly),
        "the replay is dropped at admission; got {outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::Established);

    // Behaviour first, the state that explains it after: an assertion on a
    // slot placed first would red a control before the consequence is seen.
    let mut driver =
        QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_frame_wire(1, true)))]);
    let outcome = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::RxSnRejected { .. }),
        "the already-delivered frame 1 is a duplicate and stays one; got {outcome:?}"
    );
    assert_eq!(
        *actions.rx_sn.lock().unwrap(),
        rx_before,
        "the replay did not move the RX baseline"
    );
    assert_eq!(
        *actions.peer_open_lease_ms.lock().unwrap(),
        lease_before,
        "nor the peer lease"
    );
    assert_eq!(
        actions.cookie_nonce(),
        None,
        "because the admitting OpenSyn spent the nonce"
    );
}

/// R2777 — the QoS BAND rides the cookie: between InitAck and OpenSyn the
/// acceptor holds the band it OFFERED, and the admitted OpenSyn puts back the
/// band the handshake MERGED.
///
/// The input is a real wz initiator's InitSyn, taken off its recording
/// driver, so the band on the wire is what wz's own encoder writes rather
/// than what a fixture believes it writes. The acceptor offers a WIDER band
/// than the initiator, and the acceptor's merge keeps the initiator's band
/// when its own contains it — so the merged band differs from the offer,
/// and only a release followed by a rebuild shows the offer in the middle
/// and the merged band at the end.
#[cfg(feature = "session-extqos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_qos_band_rides_the_cookie_between_init_ack_and_open_syn() {
    use wz_session_core::extqos::QosLinkState;
    use wz_session_core::qos::Priority;
    use wz_session_core::session_actions::LinkPriorityRange;

    let band = |a, b| QosLinkState {
        priorities: Some(LinkPriorityRange::new(a, b)),
        reliability: None,
    };
    let wide = band(Priority::RealTime, Priority::Background);
    let narrow = band(Priority::InteractiveHigh, Priority::Data);
    assert_ne!(
        wide, narrow,
        "ANTI-VACUITY: offer and merged band must differ"
    );

    // The initiator's InitSyn, from wz's own encoder.
    let (initiator, mut initiator_engine, initiator_wire) = fresh_setup_recording();
    assert!(initiator.set_qos_offer(true), "qos offer applies");
    initiator.set_qos_link_metadata(narrow);
    initiator_engine.process_event(E::OutboundStart);
    initiator_engine.process_event(E::LinkOpened);
    let init_syn = initiator_wire
        .sent
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the initiator sent its InitSyn");

    let (actions, mut engine, recording) = fresh_setup_recording();
    assert!(actions.set_qos_offer(true), "qos offer applies");
    actions.set_qos_link_metadata(wide);
    engine.process_event(E::InboundStart);
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
    let carried = decode_accept_cookie(&fixture_session_init_params().cookie_signing_key, &cookie)
        .expect("the acceptor's own cookie verifies");
    assert_eq!(
        carried.negotiated.qos,
        narrow.qos_accept_state(),
        "the cookie carries the MERGED band"
    );
    assert_eq!(
        actions.qos_link_metadata(),
        wide,
        "after the InitAck the acceptor holds the band it OFFERED -- the \
         merged one is in the cookie"
    );

    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_opensyn_wire(
        &cookie,
    )))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::Established);
    assert_eq!(
        actions.qos_link_metadata(),
        narrow,
        "the admitted OpenSyn puts back the merged band the cookie carried"
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

    // R2769 — a WELL-FORMED cookie for a handshake that never happened,
    // minted under this deploy's real key with the nonce a bundle with
    // nothing installed would have. This is the stronger probe the old one
    // was reaching for: it used to hand over the bytes of a retired
    // derivation, which the decoder now refuses on shape alone, so the
    // assertion would have held without the nonce check ever running.
    //
    // Written field by field rather than through a `Default`: a default
    // `AcceptCookieState` would be a value that means nothing, and offering
    // one invites a caller to mint a cookie it never thought about.
    let unbound = encode_accept_cookie(
        &fixture_session_init_params().cookie_signing_key,
        &AcceptCookieState {
            peer_zid: FIXTURE_PEER_ZID.to_vec(),
            peer_whatami: 0,
            sn_res: 0,
            batch_size: 0,
            nonce: 0,
            negotiated: NegotiatedExtensions {
                qos: QosAcceptState::NoQos,
                shm: ShmAcceptState(false),
                auth: AuthAcceptState::default(),
                lowlatency: LowlatencyAcceptState(false),
                compression: CompressionAcceptState(false),
                patch: PatchAcceptState(None),
                region: RegionAcceptState::default(),
            },
            multilink: MultilinkAcceptState::default(),
        },
    )
    .expect("a 4-byte zid encodes");
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
    let (actions, mut engine, recording) = fresh_setup_recording();
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    // Walk the crafted handshake to Established (same wires as r78).
    let mut driver = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(craft_initsyn_wire()))]);
    let _ = poll_and_dispatch_one(&mut driver, &actions, &mut engine).await;
    assert_eq!(engine.get_current_state(), S::SentInitAck);

    // R2769 — off the wire, for the reason the R78 walk gives: this test is
    // about a stale timer and should not carry an opinion about how a cookie
    // is minted.
    let cookie = minted_cookie(&recording.sent.lock().unwrap().clone());
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
