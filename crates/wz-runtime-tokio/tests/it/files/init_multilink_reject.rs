// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multilink arm of the establishment-extension rejects, read off the
//! Close an acceptor puts on the wire.
//!
//! An acceptor that negotiates multilink requires the initiator's ephemeral
//! public key in the InitSyn's `0x4` extension; a key it cannot read aborts
//! the handshake, and zenoh closes every extension handler's failure GENERIC
//! (`unicast/establishment/accept.rs` maps the error to
//! `close::reason::GENERIC`). wz takes the `establishment.ext_rejected` arm for
//! it. The reason value is asserted here, as the auth arm's is in
//! `usrpwd_handshake_e2e` and the `QoSLink` arm's in `init_qos_link_reject`:
//! an arm that set the wrong reason would otherwise still tear the session
//! down and pass every test that only looks at the state.

#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "transport-multilink"
))]

use std::sync::Arc;

use wz_codecs::wire_const::T_MID_CLOSE;
use wz_runtime_tokio::multilink::{accept_multilink_dispatch, open_multilink_dispatch};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{
    SessionFsmUnicastEvent as E, SessionFsmUnicastState as S,
};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, BoxedLinkDriver, CloseReason,
    DriverLoopOutcome,
};
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::auth_dispatch::{AuthError, AuthSubExt};
use wz_session_core::extmultilink::{decode_multilink_ext, MULTILINK_EXT_EID};
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::craft_initsyn_wire_with_multilink;

/// What a multilink acceptor did with one InitSyn: the outcome of the
/// dispatch, the state it reached, the reason it recorded, the reason byte of
/// the Close it sent if it sent one, and whether it answered with an InitAck.
struct Answer {
    outcome: DriverLoopOutcome,
    state: S,
    recorded: Option<CloseReason>,
    close_byte: Option<u8>,
    answered: bool,
}

async fn multilink_acceptor_answers(init_syn_wire: Vec<u8>) -> Answer {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    // The dispatch an accept seam that negotiates multilink installs; without
    // it the `0x4` extension is not read at all and nothing could be refused.
    actions.install_multilink_dispatch(accept_multilink_dispatch());
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    engine.process_event(E::InboundStart);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn_wire))]);
    let outcome = poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let mut close_byte = None;
    let mut answered = false;
    for (bytes, ..) in &driver.snapshot().sends {
        if bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE) {
            assert_eq!(bytes.len(), 2, "Close is a header plus one reason byte");
            assert_eq!(close_byte, None, "one Close, not two");
            close_byte = Some(bytes[1]);
            continue;
        }
        if matches!(
            parse_inbound(bytes),
            Ok(InboundFrame::Init { is_ack: true, .. })
        ) {
            answered = true;
        }
    }
    Answer {
        outcome,
        state: engine.get_current_state(),
        recorded: actions.close_reason(),
        close_byte,
        answered,
    }
}

/// The `0x4` body a wz initiator offers: its ephemeral public key, as the
/// open-side dispatch encodes it.
fn an_initiator_key_body() -> Vec<u8> {
    let ext = open_multilink_dispatch()
        .open_init_syn()
        .expect("the open-side dispatch produces its InitSyn offer")
        .expect("an open-side dispatch always offers its key");
    match decode_multilink_ext(&[ext], MULTILINK_EXT_EID) {
        Some(AuthSubExt::Zbuf(body)) => body,
        other => panic!("the InitSyn offer is a ZBuf; got {other:?}"),
    }
}

/// A `0x4` body that names a modulus five bytes long and carries none of them
/// is not a key: the responder cannot read it, the dispatch names the decode
/// failure, the acceptor does not answer, and the Close it sends says GENERIC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_multilink_key_closes_generic_on_the_wire() {
    let answer = multilink_acceptor_answers(craft_initsyn_wire_with_multilink(&[0x05])).await;
    assert!(
        matches!(
            answer.outcome,
            DriverLoopOutcome::AuthRejected(AuthError::Decode)
        ),
        "a multilink key the responder cannot read must surface \
         AuthRejected(Decode); got {:?}",
        answer.outcome
    );
    assert_eq!(answer.state, S::Closing);
    assert!(!answer.answered, "a refused InitSyn is not answered");
    assert_eq!(
        answer.recorded,
        Some(CloseReason::Generic),
        "a multilink reject is an establishment-EXTENSION failure, so it \
         closes GENERIC rather than the body family's INVALID"
    );
    assert_eq!(
        answer.close_byte,
        Some(CloseReason::Generic as u8),
        "the byte the peer reads must be GENERIC"
    );
}

/// The control: the same InitSyn carrying the key a wz initiator offers is
/// answered with an InitAck and closes nothing. Without it the refusal above
/// would also pass an acceptor that refused every InitSyn carrying the
/// extension.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_readable_multilink_key_is_answered() {
    let answer =
        multilink_acceptor_answers(craft_initsyn_wire_with_multilink(&an_initiator_key_body()))
            .await;
    assert!(
        !matches!(answer.outcome, DriverLoopOutcome::AuthRejected(_)),
        "a readable multilink key must not be refused; got {:?}",
        answer.outcome
    );
    assert_eq!(answer.close_byte, None, "nothing is closed");
    assert!(answer.answered, "the acceptor answers with an InitAck");
    assert_ne!(answer.state, S::Closing);
}
