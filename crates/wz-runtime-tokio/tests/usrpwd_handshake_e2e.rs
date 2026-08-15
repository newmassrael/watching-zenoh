// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3b — wz<->wz usrpwd handshake e2e (the live-wiring proof).
//!
//! Drives a REAL initiator<->responder unicast handshake over the actual
//! `encode_init`/`encode_open` + `parse_inbound` + `dispatch_link_event` path,
//! pumping each side's emitted wire bytes into the other through
//! `poll_and_dispatch_one`. Unlike the `extauth_usrpwd` / `auth_dispatch` kernel
//! unit tests (which exercise the four-stage exchange through the dispatch in
//! isolation), this test proves the LIVE WIRING the R3b round added:
//!
//!   - SEND: the four handshake send actions stage their usrpwd sub-ext into the
//!     role ext chain, so `encode_init`/`encode_open` actually carry the auth
//!     ext on the wire (asserted directly by re-parsing the InitSyn).
//!   - RECV: `dispatch_link_event` feeds each admitted handshake frame's ext
//!     chain into the matching demux stage, and a usrpwd reject drives
//!     `establishment.ext_rejected` (Accepting -> Closing,
//!     `CloseReason::Generic` — R311y823) surfaced as
//!     `DriverLoopOutcome::AuthRejected`.
//!
//! The responder challenge nonce is drawn fresh from OS entropy via
//! `nonce_from_os_entropy` (the AP-layer injection the no_std core cannot do),
//! exercising the real per-handshake nonce path. This is the wz<->wz down
//! payment on the wz<->zenohd cross-impl interop e2e (the next atom), mirroring
//! storage A11 (wz<->wz) before A10/A12 (cross-impl).

#![cfg(feature = "access-extauth-usrpwd")]

use std::sync::Arc;

use tokio::net::TcpListener;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, nonce_from_os_entropy, parse_inbound,
    poll_and_dispatch_one, BoxedLinkDriver, CloseReason, DriverLoopOutcome, InboundFrame,
    SessionLinkActions,
};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_auth, connect_and_open_session_with_auth, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::extauth::decode_auth_ext;
use wz_session_core::extauth_usrpwd::UsrPwdMethod;
use wz_session_core::locator::parse_any_locator;

const USER: &[u8] = b"alice";
const PASSWORD: &[u8] = b"s3cret";
/// Iteration cap for the real-TCP open loops (matches accept_and_open_session.rs).
const ITER_CAP_OPEN: usize = 64;

/// Build one session side: actions over a recording outbound driver with the
/// usrpwd `dispatch` installed, plus its initialized engine.
fn side(driver: &Arc<LifecycleRecordingDriver>, dispatch: AuthDispatch) -> Arc<SessionLinkActions> {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    actions.install_auth_dispatch(dispatch);
    actions
}

/// The most recent outbound frame the recording driver captured.
fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver
        .snapshot()
        .sends
        .last()
        .expect("a send was recorded")
        .0
        .clone()
}

/// Outcome of one full wz<->wz usrpwd handshake driven over the real wire path.
struct HandshakeOutcome {
    initiator_state: S,
    responder_state: S,
    /// The responder's verdict on the OpenSyn (where a bad credential surfaces).
    responder_open_syn_outcome: DriverLoopOutcome,
    initiator_actions: Arc<SessionLinkActions>,
    responder_actions: Arc<SessionLinkActions>,
    init_syn_wire: Vec<u8>,
}

/// Drive a complete initiator<->responder usrpwd handshake. The initiator
/// authenticates with `(USER, initiator_password)`; the responder's lookup holds
/// `(USER, PASSWORD)` and a fresh OS-entropy challenge nonce.
async fn drive_handshake(initiator_password: &[u8]) -> HandshakeOutcome {
    // Fresh per-handshake challenge nonce from OS entropy (the AP-layer
    // injection — the no_std core draws none).
    let challenge_nonce =
        nonce_from_os_entropy().expect("OS entropy for the usrpwd challenge nonce");

    let init_driver = Arc::new(LifecycleRecordingDriver::default());
    let resp_driver = Arc::new(LifecycleRecordingDriver::default());

    let initiator_dispatch = AuthDispatch::new(vec![Box::new(UsrPwdMethod::initiator(
        USER.to_vec(),
        initiator_password.to_vec(),
    )) as _]);
    // R4a — the responder is built with a SENTINEL nonce (0); the live
    // per-handshake nonce is injected via `refresh_auth_challenge_nonce` below,
    // exercising the SAME path the production accept seam
    // (`accept_and_open_session_with_auth`) drives — not the constructor. This
    // keeps the responder replay-defense an exercised contract, not a dead API.
    let responder_dispatch = AuthDispatch::new(vec![Box::new(UsrPwdMethod::responder(
        vec![(USER.to_vec(), PASSWORD.to_vec())],
        0,
    )) as _]);

    let init_actions = side(&init_driver, initiator_dispatch);
    let resp_actions = side(&resp_driver, responder_dispatch);
    resp_actions.refresh_auth_challenge_nonce(challenge_nonce);

    let mut init_engine = new_session_engine(&init_actions);
    init_engine.initialize();
    let mut resp_engine = new_session_engine(&resp_actions);
    resp_engine.initialize();

    // Responder: Init -> AwaitingInitSyn (listener role activation).
    resp_engine.process_event(E::InboundStart);

    // Initiator: Init -> SentInitSyn; send_init_syn emits the InitSyn carrying
    // the usrpwd Unit offer.
    init_engine.process_event(E::OutboundStart);
    init_engine.process_event(E::LinkOpened);
    let init_syn_wire = last_send(&init_driver);

    // Responder Rx InitSyn -> SentInitAck; send_init_ack_with_cookie emits the
    // InitAck carrying the Z64 challenge nonce (+ the R86 HMAC-bound cookie).
    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn_wire.clone()))]);
    poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;
    let init_ack_wire = last_send(&resp_driver);

    // Initiator Rx InitAck -> GotInitAck; open_recv_init_ack captures the nonce,
    // send_open_syn emits the OpenSyn carrying the Zbuf {user, HMAC} (+ cookie
    // echo).
    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_ack_wire))]);
    poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;
    let open_syn_wire = last_send(&init_driver);

    // Responder Rx OpenSyn -> accept_recv_open_syn verifies the HMAC. A match
    // advances SentInitAck -> Established (emitting OpenAck); a bad credential
    // drives framing.error -> Closing and returns AuthRejected.
    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_syn_wire))]);
    let responder_open_syn_outcome =
        poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;

    // On acceptance, feed the OpenAck back so the initiator reaches Established.
    if resp_engine.get_current_state() == S::Established {
        let open_ack_wire = last_send(&resp_driver);
        let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_ack_wire))]);
        poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;
    }

    HandshakeOutcome {
        initiator_state: init_engine.get_current_state(),
        responder_state: resp_engine.get_current_state(),
        responder_open_syn_outcome,
        initiator_actions: init_actions,
        responder_actions: resp_actions,
        init_syn_wire,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usrpwd_matching_credentials_reach_established_on_both_sides() {
    let h = drive_handshake(PASSWORD).await;

    // The behavioral proof: both sides reached Established over the real wire
    // path, which is only possible if the usrpwd HMAC verified AND the cookie
    // echo matched.
    assert_eq!(
        h.initiator_state,
        S::Established,
        "initiator must reach Established"
    );
    assert_eq!(
        h.responder_state,
        S::Established,
        "responder must reach Established after verifying the usrpwd HMAC"
    );
    assert!(
        matches!(h.responder_open_syn_outcome, DriverLoopOutcome::AdvancedFsm),
        "the OpenSyn verify must AdvanceFsm; got {:?}",
        h.responder_open_syn_outcome
    );
    let resp_trace = h.responder_actions.trace_snapshot();
    assert_eq!(
        resp_trace.send_open_ack, 1,
        "the responder must emit OpenAck only after the HMAC verified"
    );
    assert_eq!(
        resp_trace.set_close_reason_count, 0,
        "a matching credential must not run any close-reason action"
    );
    let init_trace = h.initiator_actions.trace_snapshot();
    assert_eq!(init_trace.send_open_syn, 1, "the initiator emitted OpenSyn");

    // The wire-level proof of the SEND wiring: re-parse the InitSyn and confirm
    // the usrpwd auth ext (id 0x3) is actually on the wire (not silently empty).
    let frame = parse_inbound(&h.init_syn_wire).expect("InitSyn re-parses");
    let extensions = match frame {
        InboundFrame::Init { extensions, .. } => extensions,
        other => panic!("expected Init, got {}", std::any::type_name_of_val(&other)),
    };
    assert!(
        decode_auth_ext(&extensions).is_some(),
        "the InitSyn must carry the Z_EXT_AUTH ext (the staged usrpwd offer)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usrpwd_bad_password_rejects_and_tears_down_the_responder() {
    let h = drive_handshake(b"wrong-password").await;

    // The reject must surface as the typed AuthRejected outcome (the wz mirror
    // of zenoh's establishment FSM propagating the usrpwd verify error).
    assert!(
        matches!(
            h.responder_open_syn_outcome,
            DriverLoopOutcome::AuthRejected(_)
        ),
        "a bad password must surface DriverLoopOutcome::AuthRejected; got {:?}",
        h.responder_open_syn_outcome
    );
    // establishment.ext_rejected tears the Accepting session down to
    // Closing(Generic) — R311y823.
    assert_eq!(
        h.responder_state,
        S::Closing,
        "a bad credential must drive the responder Accepting -> Closing"
    );
    assert_ne!(
        h.initiator_state,
        S::Established,
        "the initiator never gets an OpenAck, so it must not reach Established"
    );
    let resp_trace = h.responder_actions.trace_snapshot();
    assert_eq!(
        resp_trace.send_open_ack, 0,
        "send_open_ack must NOT fire when the usrpwd HMAC verify fails"
    );
    assert!(
        resp_trace.set_close_reason_count >= 1,
        "the reject must run a close-reason mutator on the way to Closing"
    );
    // R311y823 — this used to say `set_close_reason_invalid (wire
    // Close(INVALID))` in prose while asserting only that SOME reason ran, so
    // it could not have caught the value being wrong. It is now the AUTH arm's
    // witness for the establishment-extension family: zenoh closes GENERIC on
    // every ext handler's failure, and its usrpwd verify error reaches
    // `link.close(Some(GENERIC))` through exactly that map_err
    // (`unicast/establishment/accept.rs:302`, `open.rs:329`).
    assert_eq!(
        resp_trace.close_reason,
        CloseReason::Generic,
        "an auth reject is an establishment-EXTENSION failure, so it closes \
         GENERIC (wire Close(GENERIC)) rather than the body family's INVALID"
    );
}

/// R4a — the PRODUCTION open seams, end-to-end over a real TCP loopback: the
/// responder runs `accept_and_open_session_with_auth` (which draws a fresh
/// per-handshake challenge nonce IN-SEAM from OS entropy) and the initiator runs
/// `connect_and_open_session_with_auth`, both with a matching usrpwd dispatch.
/// This closes the review's C1: the responder auth path is no longer
/// test-double-only — the actual production accept seam authenticates a real
/// initiator over a real socket. Mirrors `accept_and_open_session.rs`'s
/// happy-path pairing, with auth on both sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usrpwd_production_open_seams_authenticate_over_real_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Responder: accept -> accept_and_open_session_with_auth. The dispatch
    // carries the credential lookup; the SEAM injects the live challenge nonce.
    let acceptor_fut = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        let responder = AuthDispatch::new(vec![Box::new(UsrPwdMethod::responder(
            vec![(USER.to_vec(), PASSWORD.to_vec())],
            0, // sentinel; the seam refreshes it from OS entropy per handshake
        )) as _]);
        accept_and_open_session_with_auth(
            DialedLink::Tcp(stream),
            params,
            responder,
            TokioTime::new(),
            Some(ITER_CAP_OPEN),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    };

    // Initiator: connect_and_open_session_with_auth with the matching credential.
    let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let cfg = DialConfig::default();
    let initiator =
        AuthDispatch::new(vec![
            Box::new(UsrPwdMethod::initiator(USER.to_vec(), PASSWORD.to_vec())) as _,
        ]);
    let initiator_fut = connect_and_open_session_with_auth(
        locator,
        params,
        initiator,
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP_OPEN),
        DEFAULT_OPEN_TICK_MS,
    );

    let (accepted, opened) = tokio::join!(acceptor_fut, initiator_fut);
    let accepted = accepted
        .expect("usrpwd responder reaches Established via accept_and_open_session_with_auth");
    let opened = opened
        .expect("usrpwd initiator reaches Established via connect_and_open_session_with_auth");
    assert!(
        accepted.actions.trace_snapshot().record_established_at >= 1,
        "responder Established after authenticating the real initiator"
    );
    assert!(
        opened.actions.trace_snapshot().record_established_at >= 1,
        "initiator Established after the usrpwd handshake over real TCP"
    );
}
