// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `QoSLink` arm of the establishment-extension rejects, read off the
//! Close an acceptor puts on the wire.
//!
//! A `QoSLink` body upstream cannot read (`State::try_from_u64`'s `zerror!`)
//! aborts the handshake, and zenoh closes every extension handler's failure
//! GENERIC (`io/zenoh-transport/src/unicast/establishment/accept.rs` @
//! `(init_syn.ext_qos, init_syn.ext_qos_link),` is mapped by the
//! `map_err` after it to `close::reason::GENERIC`), keeping INVALID for the
//! body's size parameters.
//! wz takes the `establishment.ext_rejected` arm for it. The reason value is
//! asserted here, as the auth arm's is in `usrpwd_handshake_e2e`: an arm that
//! set the wrong reason would otherwise still tear the session down and pass
//! every test that only looks at the state.

#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "session-extqos"
))]

use std::sync::Arc;

use wz_codecs::wire_const::T_MID_CLOSE;
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
use wz_session_core::extqos::QosLinkError;
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::craft_initsyn_wire_with_qos_link;

/// What an acceptor did with one InitSyn: the outcome of the dispatch, the
/// state it reached, the reason it recorded, the reason byte of the Close it
/// sent if it sent one, and whether it answered with an InitAck.
struct Answer {
    outcome: DriverLoopOutcome,
    state: S,
    recorded: Option<CloseReason>,
    close_byte: Option<u8>,
    answered: bool,
}

async fn acceptor_answers(init_syn_wire: Vec<u8>) -> Answer {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
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

/// A reserved tag in the `QoSLink` body (`0b1000`: no tag bit, and neither 0
/// nor 1) is refused: the dispatch names the `QoSLink` reason, the acceptor
/// does not answer, and the Close it sends says GENERIC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_qos_link_closes_generic_on_the_wire() {
    let answer = acceptor_answers(craft_initsyn_wire_with_qos_link(0b1000)).await;
    assert!(
        matches!(
            answer.outcome,
            DriverLoopOutcome::QosLinkRejected(QosLinkError::InvalidValue)
        ),
        "a QoSLink body upstream cannot read must surface QosLinkRejected(InvalidValue); \
         got {:?}",
        answer.outcome
    );
    assert_eq!(answer.state, S::Closing);
    assert!(!answer.answered, "a refused InitSyn is not answered");
    assert_eq!(
        answer.recorded,
        Some(CloseReason::Generic),
        "a QoSLink reject is an establishment-EXTENSION failure, so it closes \
         GENERIC rather than the body family's INVALID"
    );
    assert_eq!(
        answer.close_byte,
        Some(CloseReason::Generic as u8),
        "the byte the peer reads must be GENERIC"
    );
}

/// The control: the same InitSyn carrying a body upstream reads (`0b001`, QoS
/// with no band and no class) is answered with an InitAck and closes nothing.
/// Without it the refusal above would also pass an acceptor that refused every
/// InitSyn carrying the extension.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_readable_qos_link_is_answered() {
    let answer = acceptor_answers(craft_initsyn_wire_with_qos_link(0b001)).await;
    assert!(
        !matches!(answer.outcome, DriverLoopOutcome::QosLinkRejected(_)),
        "a readable QoSLink must not be refused; got {:?}",
        answer.outcome
    );
    assert_eq!(answer.close_byte, None, "nothing is closed");
    assert!(answer.answered, "the acceptor answers with an InitAck");
    assert_ne!(answer.state, S::Closing);
}
