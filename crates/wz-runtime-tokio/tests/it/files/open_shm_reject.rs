// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The shared-memory arm of the establishment-extension rejects, read off the
//! Close an initiator puts on the wire.
//!
//! An acceptor that offered shared memory on its InitAck commits to it on its
//! OpenAck. An initiator that could not use the offer (it mapped no segment, so
//! it proposed nothing on its OpenSyn) cannot honour that commitment, and zenoh
//! 1.10.2 refuses the link rather than run with shared memory on one side only
//! (`unicast/establishment/ext/shm/auth.rs` @ `SHM acknowledgement without a
//! local proposal`); the error leaves the establishment through the extension
//! handler's `map_err`, which closes GENERIC
//! (`unicast/establishment/open.rs`). wz takes the
//! `establishment.ext_rejected` arm for it. The reason value is asserted here,
//! as the auth arm's is in `usrpwd_handshake_e2e`: an arm that set the wrong
//! reason would otherwise still tear the session down and pass every test that
//! only looks at the state.

#![cfg(all(
    feature = "session-extshm",
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "codec-open-body"
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
use wz_runtime_tokio::shm_auth_segment::PosixShmAuthenticator;
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_wire_fixtures::{
    craft_initack_wire, craft_initack_wire_with_shm, craft_openack_wire_with_shm,
};

/// The cookie the crafted InitAck carries; the initiator echoes it unread.
const COOKIE: [u8; 2] = [0xC0, 0x01];

/// An `Shm` InitAck body whose first VLE never ends: no challenge and no
/// segment can be read out of it, so the initiator maps nothing, while the
/// extension's presence is still the acceptor's offer.
const UNUSABLE_OFFER: [u8; 1] = [0x80];

/// An `Shm` OpenAck body naming no handoff counters (status byte 0): well
/// formed, so a refusal of it is the commitment's and not the body's.
const COMMITMENT: [u8; 1] = [0x00];

/// What a shared-memory initiator did with one OpenAck: the outcome of the
/// dispatch, the state it reached, the reason it recorded, and the reason byte
/// of the Close it sent if it sent one.
struct Answer {
    outcome: DriverLoopOutcome,
    state: S,
    recorded: Option<CloseReason>,
    close_byte: Option<u8>,
}

/// Drive an initiator with an authenticator installed through `init_ack` and
/// then `open_ack`.
async fn shm_initiator_answers(init_ack: Vec<u8>, open_ack: Vec<u8>) -> Answer {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    actions.set_shm_offer(true);
    actions.install_shm_auth(Box::new(
        PosixShmAuthenticator::new().expect("publish an auth segment"),
    ));
    let mut engine = new_session_engine(&actions);
    engine.initialize().unwrap_or_else(|never| match never {});
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_ack))]);
    poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
    assert_eq!(
        engine.get_current_state(),
        S::GotInitAck,
        "precondition: the InitAck is taken and the OpenSyn sent, whatever \
         the offer said"
    );

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_ack))]);
    let outcome = poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let mut close_byte = None;
    for (bytes, ..) in &driver.snapshot().sends {
        if bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE) {
            assert_eq!(bytes.len(), 2, "Close is a header plus one reason byte");
            assert_eq!(close_byte, None, "one Close, not two");
            close_byte = Some(bytes[1]);
        }
    }
    Answer {
        outcome,
        state: engine.get_current_state(),
        recorded: actions.close_reason(),
        close_byte,
    }
}

/// The acceptor offered shared memory the initiator could not use, then
/// committed to it: the dispatch names the shared-memory reject, the session
/// does not establish, and the Close it sends says GENERIC.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_commitment_the_initiator_cannot_honour_closes_generic_on_the_wire() {
    let answer = shm_initiator_answers(
        craft_initack_wire_with_shm(&COOKIE, &UNUSABLE_OFFER),
        craft_openack_wire_with_shm(0, &COMMITMENT),
    )
    .await;
    assert!(
        matches!(answer.outcome, DriverLoopOutcome::ShmChallengeRejected),
        "an OpenAck commitment the initiator cannot honour must surface \
         ShmChallengeRejected; got {:?}",
        answer.outcome
    );
    assert_eq!(answer.state, S::Closing);
    assert_eq!(
        answer.recorded,
        Some(CloseReason::Generic),
        "a shared-memory reject is an establishment-EXTENSION failure, so it \
         closes GENERIC rather than the body family's INVALID"
    );
    assert_eq!(
        answer.close_byte,
        Some(CloseReason::Generic as u8),
        "the byte the peer reads must be GENERIC"
    );
}

/// The control: the same OpenAck from an acceptor that offered nothing on its
/// InitAck is ignored, and the session establishes without shared memory.
/// Without it the refusal above would also pass an initiator that refused
/// every OpenAck carrying the extension, which an acceptor that does not
/// check its own offer sends on every link.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_commitment_without_an_offer_is_ignored() {
    let answer = shm_initiator_answers(
        craft_initack_wire(&COOKIE),
        craft_openack_wire_with_shm(0, &COMMITMENT),
    )
    .await;
    assert!(
        !matches!(answer.outcome, DriverLoopOutcome::ShmChallengeRejected),
        "an OpenAck extension with no offer behind it must not be refused; \
         got {:?}",
        answer.outcome
    );
    assert_eq!(answer.close_byte, None, "nothing is closed");
    assert_eq!(answer.state, S::Established);
}
