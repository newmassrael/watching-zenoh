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
//!   themselves and the legs above, which stop at the message, do not;
//! - the ALLOCATION CENSUS at the end of the file, which counts what the
//!   allocator is asked for between the frame and a kept sample, the one thing
//!   an address cannot show: that no copy was made on the way.

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

/// An allocation census, the second instrument beside the address checks above.
///
/// An address check says where the payload IS; it cannot say that nothing made
/// a copy on the way, because a copy that is dropped again, or one the sample
/// does not end up holding, leaves the address untouched. The census counts what
/// the allocator was asked for instead: it records the size of every allocation
/// of a kilobyte or more that the ARMED thread makes. The payload the tests send
/// is far above that line and a copy of it is an allocation of its own size
/// (growing a vector to it records each size it grows to), so a copy of the
/// payload anywhere on the path shows as a size at or above the payload's.
///
/// The record is per thread, so the other tests in this file, which run in
/// parallel, cannot add to it; the path under test runs on the calling thread.
#[cfg(feature = "pubsub-put")]
mod census {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::{Cell, RefCell};

    /// Allocations below this are bookkeeping (a key expression, a handle, a
    /// message struct); the byte fields the census is about are far above it.
    const LARGE: usize = 1024;
    /// Room for the sizes of one armed window. A fixed array, because the
    /// allocator cannot allocate to record an allocation.
    const SLOTS: usize = 32;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
        static SEEN: RefCell<[usize; SLOTS]> = const { RefCell::new([0; SLOTS]) };
    }

    pub struct Counting;

    fn note(size: usize) {
        if size < LARGE {
            return;
        }
        // `try_with`: a thread that is being torn down has no cell to write to,
        // and an allocation made then is not one the census is looking for.
        let _ = ARMED.try_with(|armed| {
            if !armed.get() {
                return;
            }
            let _ = COUNT.try_with(|count| {
                let i = count.get();
                if i < SLOTS {
                    let _ = SEEN.try_with(|seen| seen.borrow_mut()[i] = size);
                }
                count.set(i + 1);
            });
        });
    }

    // SAFETY: every method defers to `System` with the arguments it was given;
    // the only addition is a write to const-initialised thread-local cells,
    // which neither allocates nor can fail.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            System.alloc(layout)
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            System.alloc_zeroed(layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            note(new_size);
            System.realloc(ptr, layout, new_size)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
    }

    /// Run `f` and return what it returned with the size of every large
    /// allocation THIS thread made meanwhile, in order.
    pub fn large_allocations<R>(f: impl FnOnce() -> R) -> (R, Vec<usize>) {
        COUNT.with(|count| count.set(0));
        SEEN.with(|seen| *seen.borrow_mut() = [0; SLOTS]);
        ARMED.with(|armed| armed.set(true));
        let out = f();
        ARMED.with(|armed| armed.set(false));
        let count = COUNT.with(Cell::get);
        assert!(
            count <= SLOTS,
            "{count} large allocations overflow the {SLOTS} the census keeps"
        );
        let sizes = SEEN.with(|seen| seen.borrow()[..count].to_vec());
        (out, sizes)
    }
}

#[cfg(feature = "pubsub-put")]
#[global_allocator]
static COUNTING: census::Counting = census::Counting;

/// What the census tests send: a payload and an attachment of sizes that cannot
/// be mistaken for each other or for any bookkeeping allocation.
#[cfg(feature = "pubsub-put")]
const CENSUS_PAYLOAD: usize = 32 * 1024;
#[cfg(feature = "pubsub-put")]
const CENSUS_ATTACHMENT: usize = 6 * 1024;

/// A reliable Frame at `FIRST_SN` carrying one Put on `demo/census` with a
/// payload of [`CENSUS_PAYLOAD`] bytes, and an attachment of
/// [`CENSUS_ATTACHMENT`] when `attached`.
#[cfg(feature = "pubsub-put")]
fn census_wire(attached: bool) -> Vec<u8> {
    use wz_session_core::metadata::PushMetadata;
    use wz_session_core::push_build::build_push_literal_with_meta;

    let meta = PushMetadata {
        attachment: attached.then(|| vec![0xA7; CENSUS_ATTACHMENT]),
        ..PushMetadata::default()
    };
    let push = build_push_literal_with_meta("demo/census", &vec![0x5C; CENSUS_PAYLOAD], &meta)
        .expect("build a literal put");
    encode_frame_with_push(FIRST_SN, push, true)
}

/// Drive `wire`, an owned heap buffer as most links hand it up, to the end of the
/// receive path: the session decodes it, and a subscriber on the key RETAINS the
/// sample it is handed, as an application that keeps samples does. Returns the
/// large allocations of the two steps, the drive and the delivery.
#[cfg(feature = "pubsub-put")]
fn large_allocations_to_a_kept_sample(wire: Vec<u8>) -> (Vec<usize>, Vec<usize>) {
    established!(actions, engine);
    let unit = RxBytes::from(wire);
    let (outcome, drive) = census::large_allocations(|| {
        dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine)
    });
    let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
        panic!("a data frame in an established session is delivered, got {outcome:?}");
    };
    let kept = Arc::new(Mutex::new(None::<wz_session_core::sample::Sample>));
    let sink = Arc::clone(&kept);
    let mut registry = SubscriberRegistry::new();
    registry.register("demo/census", move |view| {
        *sink.lock().unwrap() = Some(wz_session_core::sample::Sample::from_view(view));
    });
    let ((), delivery) =
        census::large_allocations(|| registry.dispatch(&messages[0], Reliability::Reliable));
    let sample = kept.lock().unwrap().take().expect("the subscriber fired");
    assert_eq!(
        sample.payload.len(),
        CENSUS_PAYLOAD,
        "the premise: the sample the application kept carries the whole payload"
    );
    (drive, delivery)
}

/// Nothing as large as a kilobyte is allocated from the buffer the link read to
/// a sample the application keeps, for a Put with or without an attachment.
#[cfg(feature = "pubsub-put")]
fn assert_nothing_large_is_allocated(attached: bool) {
    let (drive, delivery) = large_allocations_to_a_kept_sample(census_wire(attached));
    assert!(
        drive.is_empty(),
        "driving the frame allocated {drive:?}; its bytes must stay in the buffer the link read"
    );
    assert!(
        delivery.is_empty(),
        "delivering the sample allocated {delivery:?}; the sample must hold ranges of that buffer"
    );
}

/// The whole way, counted in allocations: from the buffer the link read to a
/// sample the application keeps, nothing as large as a kilobyte is allocated.
/// The payload is thirty-two of them, so a copy of it anywhere on the path, in
/// the drive loop, the batch walk, the registry's projection or the sample's
/// retention, is a size in one of the two lists and fails this.
#[cfg(feature = "pubsub-put")]
#[test]
fn no_allocation_of_the_payloads_size_stands_between_the_frame_and_a_kept_sample() {
    assert_nothing_large_is_allocated(false);
}

/// The control for the census. The copying decode of the same frame (no origin
/// to share) must show the payload's size as an allocation, or the test above
/// could be empty because the instrument sees nothing.
#[cfg(feature = "pubsub-put")]
#[test]
fn the_census_sees_the_copying_decode_allocate_the_payload() {
    let wire = census_wire(false);
    let (_, sizes) = census::large_allocations(|| {
        let frame = match wz_session_core::inbound::parse_inbound(&wire).expect("the frame parses")
        {
            wz_session_core::inbound::InboundFrame::Frame { payload, .. } => payload,
            other => panic!("expected a Frame, got {other:?}"),
        };
        wz_session_core::network_message::parse_frame_payload(&frame)
            .expect("the batch parses")
            .len()
    });
    assert!(
        sizes.iter().any(|&size| size >= CENSUS_PAYLOAD),
        "the copying decode owns its payload, so the census must see {CENSUS_PAYLOAD} bytes allocated, got {sizes:?}"
    );
}

/// The same count with an attachment on the Put. The attachment's bytes are a
/// range of the frame in the decoded message (the extension chain is projected
/// through the same origin), and the sample holds them as it holds the payload:
/// a second reference to the storage, taken where the registry builds the sample
/// (`dispatch_push`) and again where the retention sample is built from its view
/// (`Sample::from_view`). Both used to copy them, once each, as a `Vec<u8>`.
///
/// Without `pubsub-attachment` the sample never reads the extension, so there is
/// nothing to count and the premise is absent.
#[cfg(all(feature = "pubsub-put", feature = "pubsub-attachment"))]
#[test]
fn no_allocation_of_an_attachments_size_stands_between_the_frame_and_a_kept_sample() {
    assert_nothing_large_is_allocated(true);
}

/// The attachment of a sample the application KEEPS, read the way the payload's
/// is above: by address and by the count of holders of the lent storage. The
/// attachment is a range of the frame, and a kept sample holds the frame's
/// storage through it as well as through the payload.
#[cfg(all(feature = "pubsub-put", feature = "pubsub-attachment"))]
#[test]
fn a_sample_the_application_keeps_holds_the_lent_storage_through_its_attachment() {
    established!(actions, engine);
    let storage = Arc::new(census_wire(true));
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
    registry.register("demo/census", move |view| {
        *sink.lock().unwrap() = Some(wz_session_core::sample::Sample::from_view(view));
    });
    registry.dispatch(&messages[0], Reliability::Reliable);
    let mut sample = kept.lock().unwrap().take().expect("the subscriber fired");

    let attachment = sample
        .attachment
        .take()
        .expect("the Put carried an attachment");
    assert_eq!(attachment.as_slice(), vec![0xA7; CENSUS_ATTACHMENT]);
    assert!(
        span.contains(&attachment.as_ptr()),
        "the kept attachment must be a range of the lent storage, not a copy of it"
    );
    // The payload's reference is let go with the sample, the attachment's is the
    // one still held: the storage stays out of its pool for as long as it lives.
    drop(sample);
    drop(outcome);
    drop(registry);
    assert_eq!(
        Arc::strong_count(&storage),
        2,
        "with the frame and the messages gone, the kept attachment holds the storage"
    );
    drop(attachment);
    assert_eq!(
        Arc::strong_count(&storage),
        1,
        "and when the attachment is dropped the storage goes home"
    );
}

/// A reliable Frame at `FIRST_SN` carrying one reply to request `CENSUS_RID`:
/// a Put with the census payload, or a Del when `del`, and the census
/// attachment when `attached`.
#[cfg(all(feature = "query-reply", feature = "pubsub-put"))]
fn census_reply_wire(attached: bool, del: bool) -> Vec<u8> {
    use wz_session_core::frame_encode::encode_frame_with_response;
    use wz_session_core::response_build::ResponseReplyBuilder;

    let mut builder = ResponseReplyBuilder::new(
        CENSUS_RID,
        0,
        Some("demo/census"),
        &vec![0x5C; CENSUS_PAYLOAD],
    );
    if attached {
        builder = builder.attachment(&vec![0xA7; CENSUS_ATTACHMENT]);
    }
    if del {
        builder = builder.reply_del();
    }
    let response = builder.build().expect("build a literal reply");
    encode_frame_with_response(FIRST_SN, response, true)
}

#[cfg(all(feature = "query-reply", feature = "pubsub-put"))]
const CENSUS_RID: u64 = 42;

/// [`large_allocations_to_a_kept_sample`] for a reply: drive `wire` and hand the
/// Response to a registry whose callback RETAINS the reply it is handed, as a
/// querier that keeps replies does.
#[cfg(all(feature = "query-reply", feature = "pubsub-put"))]
fn large_allocations_to_a_kept_reply(wire: Vec<u8>) -> (Vec<usize>, Vec<usize>) {
    use hashbrown::HashMap;
    use wz_session_core::reply::{InboundReply, InboundReplyBody, ReplyRegistry};
    use wz_session_core::reply_acceptance::ReplyAcceptance;

    established!(actions, engine);
    let unit = RxBytes::from(wire);
    let (outcome, drive) = census::large_allocations(|| {
        dispatch_link_event(LinkEvent::Rx(RxFrame::new(unit)), &actions, &mut engine)
    });
    let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
        panic!("a data frame in an established session is delivered, got {outcome:?}");
    };
    let NetworkMessage::Response(response) = &messages[0] else {
        panic!("the batch is one Response, got {:?}", messages[0]);
    };
    let kept = Arc::new(Mutex::new(None::<InboundReply>));
    let sink = Arc::clone(&kept);
    let mut registry = ReplyRegistry::new();
    registry.register(
        CENSUS_RID,
        1,
        None,
        ReplyAcceptance::Any,
        move |view| *sink.lock().unwrap() = Some(InboundReply::from_view(view)),
        |_| {},
    );
    let ((), delivery) =
        census::large_allocations(|| registry.dispatch_response(response, &HashMap::new()));
    let reply = kept.lock().unwrap().take().expect("the reply fired");
    match &reply.body {
        InboundReplyBody::Put { payload, .. } => assert_eq!(
            payload.len(),
            CENSUS_PAYLOAD,
            "the premise: the reply the querier kept carries the whole payload"
        ),
        InboundReplyBody::Del { .. } => {}
        other => panic!("expected a data reply, got {other:?}"),
    }
    (drive, delivery)
}

/// The reply plane counted as the push plane is: from the buffer the link read
/// to a reply the querier keeps, nothing as large as a kilobyte is allocated,
/// with the payload alone and with an attachment beside it.
#[cfg(all(feature = "query-reply", feature = "pubsub-put"))]
#[test]
fn no_allocation_of_a_replys_payload_stands_between_the_frame_and_a_kept_reply() {
    let (drive, delivery) = large_allocations_to_a_kept_reply(census_reply_wire(false, false));
    assert!(
        drive.is_empty(),
        "driving the frame allocated {drive:?}; its bytes must stay in the buffer the link read"
    );
    assert!(
        delivery.is_empty(),
        "delivering the reply allocated {delivery:?}; the reply must hold ranges of that buffer"
    );
}

/// See the test above; the attachment of a reply is the side-band the storage
/// aligner reads its `AlignmentReply` off, and it used to be copied out of the
/// frame twice, as a sample's was.
#[cfg(all(
    feature = "query-reply",
    feature = "pubsub-put",
    feature = "pubsub-attachment"
))]
#[test]
fn no_allocation_of_a_replys_attachment_stands_between_the_frame_and_a_kept_reply() {
    let (drive, delivery) = large_allocations_to_a_kept_reply(census_reply_wire(true, false));
    assert!(
        drive.is_empty(),
        "driving the frame allocated {drive:?}; its bytes must stay in the buffer the link read"
    );
    assert!(
        delivery.is_empty(),
        "delivering the reply allocated {delivery:?}; the reply must hold ranges of that buffer"
    );
}

/// The Del arm reads its attachment at its own extension id and through its own
/// extractor (`del_reply_attachment`), so the Put arm's count cannot speak for it.
#[cfg(all(
    feature = "query-reply",
    feature = "pubsub-put",
    feature = "pubsub-attachment"
))]
#[test]
fn no_allocation_of_a_del_replys_attachment_stands_between_the_frame_and_a_kept_reply() {
    let (drive, delivery) = large_allocations_to_a_kept_reply(census_reply_wire(true, true));
    assert!(
        drive.is_empty(),
        "driving the frame allocated {drive:?}; its bytes must stay in the buffer the link read"
    );
    assert!(
        delivery.is_empty(),
        "delivering the reply allocated {delivery:?}; the reply must hold ranges of that buffer"
    );
}
