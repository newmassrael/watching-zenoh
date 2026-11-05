// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-unicast", feature = "codec-init-body"))]

//! THE PROTOCOL VERSION AN INIT ANNOUNCES, on both roles.
//!
//! # The rule, and whose it is
//!
//! zenoh's acceptor refuses an InitSyn whose version is not its own before it
//! reads any other field, and closes INVALID
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs` @
//! `if init_syn.version != input.mine_version {`). Its own version is the
//! protocol's: the transport manager is built with `zenoh_protocol::VERSION`
//! and no builder method moves it. The initiator does not look at the version
//! an InitAck carries.
//!
//! zenoh-pico checks no InitSyn's version. wz takes zenoh's rule because the
//! byte decides how every byte after it is laid out: answering a body of
//! another revision would be negotiating fields whose meaning this node does
//! not know.
//!
//! # What is read, and off what
//!
//! The refusal is read as the Close a peer would receive, off the bytes the
//! acceptor sent, and as the typed outcome the dispatcher returns. A version
//! wz itself announces is read off its emitted Init, parsed back with the
//! production reader.

use std::sync::Arc;

use wz_codecs::wire_const::{PROTOCOL_VERSION, T_MID_CLOSE};
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
use wz_session_core::inbound::{parse_inbound, InboundFrame};
use wz_session_wire_fixtures::{craft_initack_wire, craft_initsyn_wire};

/// The crafted InitSyn with its version byte, the one after the header,
/// replaced.
fn init_syn_of_version(version: u8) -> Vec<u8> {
    let mut wire = craft_initsyn_wire();
    assert_eq!(
        wire[1], PROTOCOL_VERSION,
        "the fixture's second byte is the version this file rewrites"
    );
    wire[1] = version;
    wire
}

/// What an acceptor did with ONE InitSyn.
struct Answer {
    outcome: DriverLoopOutcome,
    /// The version of the InitAck it sent, if it sent one.
    init_ack_version: Option<u8>,
    /// The reason byte of the Close it sent, if it sent one.
    close_reason: Option<u8>,
    state: S,
}

async fn acceptor_answers(init_syn_wire: Vec<u8>) -> Answer {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::InboundStart);
    assert_eq!(engine.get_current_state(), S::AwaitingInitSyn);

    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn_wire))]);
    let outcome = poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;

    let mut init_ack_version = None;
    let mut close_reason = None;
    for (bytes, ..) in &driver.snapshot().sends {
        if bytes.first().map(|h| h & 0x1f) == Some(T_MID_CLOSE) {
            assert_eq!(bytes.len(), 2, "Close is a header plus one reason byte");
            close_reason = Some(bytes[1]);
            continue;
        }
        if let Ok(InboundFrame::Init {
            is_ack: true, body, ..
        }) = parse_inbound(bytes)
        {
            init_ack_version = Some(body.version);
        }
    }
    Answer {
        outcome,
        init_ack_version,
        close_reason,
        state: engine.get_current_state(),
    }
}

/// THE REFUSAL: every version but the protocol's is closed INVALID and never
/// answered. Zero is among them, so a run of zero bytes is not a handshake;
/// 0x05 is the internal test profile this workspace used to announce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_init_syn_of_another_version_is_closed_invalid_and_not_answered() {
    for version in [0x00, 0x05, 0x08, 0x0a, 0xff] {
        let answer = acceptor_answers(init_syn_of_version(version)).await;
        assert!(
            matches!(
                answer.outcome,
                DriverLoopOutcome::InitSynVersionRejected { version: v } if v == version
            ),
            "{version:#04x}: {:?}",
            answer.outcome
        );
        assert_eq!(
            answer.close_reason,
            Some(CloseReason::Invalid as u8),
            "{version:#04x}: a version refusal is a BODY refusal, so INVALID"
        );
        assert_eq!(
            answer.init_ack_version, None,
            "{version:#04x}: a refused InitSyn is not answered with an InitAck"
        );
        assert_ne!(
            answer.state,
            S::AwaitingInitSyn,
            "{version:#04x}: the session left the state that awaits an InitSyn"
        );
    }
}

/// THE NARROWING CONTROL: the protocol's own version is answered, and the
/// answer carries it. Without this arm the refusal above would also pass an
/// acceptor that refused every InitSyn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_init_syn_of_the_protocol_version_is_answered_in_it() {
    let answer = acceptor_answers(init_syn_of_version(PROTOCOL_VERSION)).await;
    assert!(
        matches!(answer.outcome, DriverLoopOutcome::AdvancedFsm),
        "{:?}",
        answer.outcome
    );
    assert_eq!(answer.close_reason, None);
    assert_eq!(answer.init_ack_version, Some(PROTOCOL_VERSION));
}

/// wz's own InitSyn announces the protocol's version: nothing a caller passes
/// can move it, because nothing a caller passes holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_init_syn_wz_sends_announces_the_protocol_version() {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);
    assert_eq!(engine.get_current_state(), S::SentInitSyn);

    let versions: Vec<u8> = driver
        .snapshot()
        .sends
        .iter()
        .filter_map(|(bytes, ..)| match parse_inbound(bytes) {
            Ok(InboundFrame::Init {
                is_ack: false,
                body,
                ..
            }) => Some(body.version),
            _ => None,
        })
        .collect();
    assert_eq!(versions, vec![PROTOCOL_VERSION]);
}

/// THE ASYMMETRY, which is upstream's: an initiator does not refuse an InitAck
/// for its version. Neither reference reads that byte on the open side, so an
/// InitAck of another version is taken as the answer it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_initiator_does_not_refuse_an_init_ack_for_its_version() {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = driver.clone();
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine.process_event(E::OutboundStart);
    engine.process_event(E::LinkOpened);

    let mut wire = craft_initack_wire(&[0xC0, 0x01]);
    assert_eq!(wire[1], PROTOCOL_VERSION, "the fixture's version byte");
    wire[1] = 0x08;
    let mut queue = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(wire))]);
    let outcome = poll_and_dispatch_one(&mut queue, &actions, &mut engine).await;
    assert!(
        matches!(outcome, DriverLoopOutcome::AdvancedFsm),
        "{outcome:?}"
    );
    assert_eq!(engine.get_current_state(), S::GotInitAck);
}
