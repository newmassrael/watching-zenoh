// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The receive loop decodes out of the unit a link read, and what it hands up
//! is a range of that unit.
//!
//! A link can lend its read buffer (a recycled box, a slot of the node's receive
//! pool, a datagram the transport already refcounts) so that a frame is the
//! storage it arrived in. That sharing used to end at the first decode: the
//! drive loop copied the frame's payload out, then the batch walk copied each
//! message's bytes out of that. These tests read ADDRESSES, because a decode
//! over a copy of the frame is correct by value and shares nothing, and no
//! assertion on the bytes would notice.
//!
//! Each leg drives a real established session through
//! [`dispatch_link_event`], the synchronous core `poll_and_dispatch_one` wraps,
//! and reads the payload of the Push it hands up. The legs:
//!
//! - a LENT unit: the payload lies inside the lent storage;
//! - a HEAP unit (an owned `Vec`, which is what most links still hand up): the
//!   buffer is moved behind one reference count once, and the payload lies
//!   inside the buffer the link read into, not in a copy of it;
//! - a unit holding TWO messages: the second is parked as a range of the same
//!   storage and dispatched on the next turn, and its payload lies inside it;
//! - the CONTROL: a copy of the same frame decoded without an origin puts the
//!   payload outside it, so the three address checks cannot pass for a reason
//!   that has nothing to do with sharing;
//! - a SUBSCRIBER's callback, and a sample the application KEEPS: these go on to
//!   project the Put into a sample, which `pubsub-put` gates. Without it a Push is
//!   delivered to the observer and no subscriber fires, so they carry that gate
//!   themselves and the legs above, which stop at the message, do not.

#![cfg(all(
    feature = "session-unicast-open",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-frame",
    feature = "codec-push"
))]

use std::sync::Arc;
#[cfg(feature = "pubsub-put")]
use std::sync::Mutex;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastState};
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, LinkSendOutcome,
};
use wz_runtime_tokio::{LinkEvent, Reliability, RxBytes, RxFrame, RxStorage};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::drive::{dispatch_link_event, dispatch_pending};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::frame_encode::encode_frame_with_push;
use wz_session_core::network_message::NetworkMessage;
#[cfg(feature = "pubsub-put")]
use wz_session_core::pubsub::SubscriberRegistry;
use wz_session_core::push_build::build_push_literal;
use wz_session_wire_fixtures::{craft_initack_wire, craft_openack_wire};

const PAYLOAD: &[u8] = b"shared-payload-through-the-drive-loop";

/// The sequence number the OpenAck below announces: the first frame the
/// session admits.
const FIRST_SN: u64 = 5;

struct NoopDriver;

impl BoxedLinkDriver for NoopDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// An initiator session driven through its handshake to `Established`, as the
/// crate's own sequence-gate test does, so a data frame is admitted. A macro and
/// not a function because the engine's type is the policy's, which a helper would
/// have to name for no gain.
macro_rules! established {
    ($actions:ident, $engine:ident) => {
        let driver: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopDriver);
        let $actions = new_session_actions(driver, fixture_session_init_params(), TokioTime::new());
        let mut $engine = new_session_engine(&$actions);
        $engine.initialize();
        $engine.process_event(E::OutboundStart);
        $engine.process_event(E::LinkOpened);
        for wire in [craft_initack_wire(&[0x11; 8]), craft_openack_wire(FIRST_SN)] {
            let _ = dispatch_link_event(LinkEvent::Rx(RxFrame::new(wire)), &$actions, &mut $engine);
        }
        assert_eq!(
            $engine.get_current_state(),
            SessionFsmUnicastState::Established,
            "the handshake completed, so a data frame is admitted"
        );
    };
}

/// The wire bytes of one reliable Frame at `sn` carrying one literal Put.
fn frame_wire(sn: u64) -> Vec<u8> {
    let push = build_push_literal("demo/shared", PAYLOAD).expect("build a literal put");
    encode_frame_with_push(sn, push, true)
}

/// The payload of the one Push a `FramePayload` outcome carries.
fn pushed_payload(outcome: &DriverLoopOutcome) -> &[u8] {
    let DriverLoopOutcome::FramePayload { messages, .. } = outcome else {
        panic!("a data frame in an established session is delivered, got {outcome:?}");
    };
    assert_eq!(messages.len(), 1, "the unit carries one Push");
    let NetworkMessage::Push(push) = &messages[0] else {
        panic!("the batch is one Push, got {:?}", messages[0]);
    };
    let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
        panic!("a literal put carries a Put body");
    };
    wz_session_core::put_payload::inline_bytes(put).expect("an inline Put")
}

fn lies_within(whole: &std::ops::Range<*const u8>, part: &[u8]) -> bool {
    whole.contains(&part.as_ptr())
}

/// A link that lent its buffer: the Push's payload is a range of the lent
/// storage, and it is still readable after the frame handle is gone because the
/// message holds the storage.
#[test]
fn a_lent_unit_hands_up_a_payload_that_is_a_range_of_the_storage_it_arrived_in() {
    established!(actions, engine);
    let wire = frame_wire(FIRST_SN);
    let storage = Arc::new(wire);
    let span = storage.as_slice().as_ptr_range();
    let lent: Arc<dyn RxStorage> = storage.clone();
    let unit = RxBytes::shared(lent, 0..storage.len()).expect("the whole storage is a range of it");
    assert!(unit.is_shared(), "the premise: this unit is lent storage");

    let outcome = dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine);
    assert_eq!(pushed_payload(&outcome), PAYLOAD);
    assert!(
        lies_within(&span, pushed_payload(&outcome)),
        "the payload must be a range of the storage the link lent, not a copy of it"
    );
}

/// The common case: a link that read into a `Vec` and handed that up owned. The
/// drive loop makes it shareable once, by moving the buffer behind a reference
/// count, so the payload lies inside the very buffer the link filled.
#[test]
fn a_heap_unit_is_lent_once_and_its_payload_is_still_a_range_of_what_was_read() {
    established!(actions, engine);
    let wire = frame_wire(FIRST_SN);
    let span = wire.as_ptr_range();
    let unit = RxBytes::from(wire);
    assert!(
        !unit.is_shared(),
        "the premise: this unit is an owned buffer"
    );

    let outcome = dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine);
    assert_eq!(pushed_payload(&outcome), PAYLOAD);
    assert!(
        lies_within(&span, pushed_payload(&outcome)),
        "moving an owned buffer behind the count must not copy it"
    );
}

/// A unit that holds a KeepAlive and then a Frame: the walk dispatches the front
/// message and parks the rest for the next turn. What is parked is a range of the
/// unit, so the Frame decoded on the next turn still reads out of the storage the
/// link filled.
#[test]
fn the_remainder_of_a_batch_is_parked_as_a_range_of_the_unit_and_decoded_from_it() {
    established!(actions, engine);
    let mut wire = vec![0x04]; // T_MID_KEEP_ALIVE, no flags, no body
    wire.extend_from_slice(&frame_wire(FIRST_SN));
    let span = wire.as_ptr_range();
    let unit = RxBytes::from(wire);

    let front = dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine);
    assert!(
        matches!(front, DriverLoopOutcome::SideEffectOnly),
        "the KeepAlive at the front is a liveness signal, got {front:?}"
    );
    let rest = dispatch_pending(&actions, &mut engine).expect("the Frame was parked behind it");
    assert_eq!(pushed_payload(&rest), PAYLOAD);
    assert!(
        lies_within(&span, pushed_payload(&rest)),
        "the parked remainder must be a range of the unit, not a copy cut out of it"
    );
}

/// The whole way: a subscriber registered on the key is handed a sample whose
/// payload is a range of the very buffer the link read. This is the claim the
/// receive path exists to keep, read at its far end: the three legs above stop at
/// the message the drive loop hands up, and a copy between there and the callback
/// (the sample projection used to make one) would not show in any of them.
///
/// The payload address is read INSIDE the callback, from the view the subscriber
/// is given, so nothing here can be satisfied by a retained copy.
#[cfg(feature = "pubsub-put")]
#[test]
fn a_subscriber_is_handed_a_sample_whose_payload_is_the_buffer_the_link_read() {
    established!(actions, engine);
    let wire = frame_wire(FIRST_SN);
    let span = wire.as_ptr_range();
    let outcome = dispatch_link_event(
        LinkEvent::Rx(RxFrame::new(RxBytes::from(wire))),
        &actions,
        &mut engine,
    );
    let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
        panic!("a data frame in an established session is delivered, got {outcome:?}");
    };

    // The address as an integer: the callback must be `Send`, a raw pointer is not.
    let delivered = Arc::new(Mutex::new(None::<(usize, Vec<u8>)>));
    let sink = Arc::clone(&delivered);
    let mut registry = SubscriberRegistry::new();
    registry.register("demo/shared", move |view| {
        let payload = view.payload();
        *sink.lock().unwrap() = Some((payload.as_ptr() as usize, payload.to_vec()));
    });
    registry.dispatch(&messages[0], Reliability::Reliable);

    let (at, bytes) = delivered
        .lock()
        .unwrap()
        .take()
        .expect("the subscriber on the key fired");
    assert_eq!(bytes, PAYLOAD);
    assert!(
        span.contains(&(at as *const u8)),
        "the sample's payload must be a range of the buffer the link read, not a copy of it"
    );
}

/// The sample an application KEEPS. The session hands every user callback an owned
/// retention sample built from the borrowed view (`Sample::from_view`), and a
/// subscriber that stores samples stores that one, so the claim has to hold for
/// it: it is a second reference to the storage the link lent, not a copy, and it
/// is what keeps that storage out of its pool. The count of holders of the lent
/// storage is the observable: the link's handle, the frame's, and the retained
/// sample's, down to the sample's alone and then to none once it drops.
#[cfg(feature = "pubsub-put")]
#[test]
fn a_sample_the_application_keeps_holds_the_lent_storage_until_it_is_dropped() {
    established!(actions, engine);
    let storage = Arc::new(frame_wire(FIRST_SN));
    let span = storage.as_slice().as_ptr_range();
    let lent: Arc<dyn RxStorage> = storage.clone();
    let unit = RxBytes::shared(lent, 0..storage.len()).expect("the whole storage is a range of it");

    let outcome = dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine);
    let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
        panic!("a data frame in an established session is delivered, got {outcome:?}");
    };
    let kept = Arc::new(Mutex::new(None::<wz_session_core::sample::Sample>));
    let sink = Arc::clone(&kept);
    let mut registry = SubscriberRegistry::new();
    registry.register("demo/shared", move |view| {
        *sink.lock().unwrap() = Some(wz_session_core::sample::Sample::from_view(view));
    });
    registry.dispatch(&messages[0], Reliability::Reliable);
    let sample = kept.lock().unwrap().take().expect("the subscriber fired");

    assert_eq!(sample.payload.as_slice(), PAYLOAD);
    assert!(
        span.contains(&sample.payload.as_ptr()),
        "the retained sample must be a range of the lent storage, not a copy of it"
    );
    // Everything the drive loop and the registry held is let go. What is left is
    // the test's own handle and the retained sample's reference.
    drop(outcome);
    drop(registry);
    assert_eq!(
        Arc::strong_count(&storage),
        2,
        "after the frame and the messages are gone, the retained sample holds the storage"
    );
    drop(sample);
    assert_eq!(
        Arc::strong_count(&storage),
        1,
        "and when the sample is dropped the storage goes home"
    );
}

/// The control. The copying decode of the same frame, with no origin to share,
/// owns its payload: it lies outside the bytes it was decoded from. Without this
/// the three checks above could pass for a reason that has nothing to do with
/// sharing, such as the allocator handing a copy an address in the same range.
#[test]
fn the_copying_decode_of_the_same_frame_owns_its_payload() {
    let wire = frame_wire(FIRST_SN);
    let span = wire.as_ptr_range();
    let frame = match wz_session_core::inbound::parse_inbound(&wire).expect("the frame parses") {
        wz_session_core::inbound::InboundFrame::Frame { payload, .. } => payload,
        other => panic!("expected a Frame, got {other:?}"),
    };
    assert_eq!(
        wz_session_core::network_message::parse_frame_payload(&frame)
            .expect("the batch parses")
            .len(),
        1
    );
    assert!(
        !lies_within(&span, frame.as_slice()),
        "a decode with no origin copies the frame's payload out"
    );
}
