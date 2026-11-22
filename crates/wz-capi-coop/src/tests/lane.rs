// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's delivery lane: a sample is handed to its subscriber's callback as it was offered,
//! from the lane's area; a full lane drops what may be dropped and counts apart what holds its
//! sender; the gate reads a link only while the lane takes a batch.

use core::ptr::NonNull;

use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::qos::CongestionControl;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{
    EncodingHint, QosLevel, Sample, SampleKind, SourceInfo, TimestampHint,
};
use wz_session_core::sink::SampleView;

use wz_capi_port::SubId;

use crate::lane::{LaneCounts, LaneItem, LaneSample, MatchFlips, ReadRoom, SampleLane};

/// The QoS byte of a sample sent at the data priority whose congestion control holds its sender.
const BLOCK: u8 = 0x05 | 0x08;

/// A lane over an area of `bytes` the test leaks, admitting `events` samples at once; `None` in a
/// build whose domains keep either limit to its own value.
fn lane(bytes: usize, events: usize) -> Option<SampleLane> {
    let mut limits = SessionLimits::defaults();
    limits.select_delivery_lane_bytes(bytes).ok()?;
    limits
        .select_delivery_lane_events(Quota::at_most(events))
        .ok()?;
    let area: &'static mut [u8] = vec![0u8; bytes].leak();
    // SAFETY: the area is leaked, so it outlives the lane, and nothing else uses it.
    Some(unsafe { SampleLane::over(NonNull::from(area).cast::<u8>(), bytes, &limits) })
}

/// [`lane`] whose callbacks owed at once are `callbacks` at most.
fn lane_owing(bytes: usize, events: usize, callbacks: usize) -> Option<SampleLane> {
    let mut limits = SessionLimits::defaults();
    limits.select_delivery_lane_bytes(bytes).ok()?;
    limits
        .select_delivery_lane_events(Quota::at_most(events))
        .ok()?;
    limits
        .select_delivery_lane_callbacks(Quota::at_most(callbacks))
        .ok()?;
    let area: &'static mut [u8] = vec![0u8; bytes].leak();
    // SAFETY: the area is leaked, so it outlives the lane, and nothing else uses it.
    Some(unsafe { SampleLane::over(NonNull::from(area).cast::<u8>(), bytes, &limits) })
}

/// The sample at the head of `lane`, and the subscribers it is for, held by the caller until it
/// completes it.
fn front(lane: &mut SampleLane) -> Option<(Vec<SubId>, LaneSample)> {
    match lane.take_front()? {
        LaneItem::Sample(sample) => Some((sample.subscribers().collect(), sample)),
        #[cfg(feature = "liveliness")]
        LaneItem::Liveliness(_) => panic!("a sample was offered, not a token"),
        #[cfg(feature = "query")]
        LaneItem::Reply(_) => panic!("a sample was offered, not a reply"),
    }
}

/// The subscribers each sample in `lane` is for, in order, and its payload's first byte, each
/// sample completed as it is read.
fn drain(lane: &mut SampleLane) -> Vec<(Vec<SubId>, u8)> {
    let mut handed = Vec::new();
    while let Some((ids, sample)) = front(lane) {
        handed.push((ids, sample.payload().first().copied().unwrap_or(0)));
        lane.complete();
    }
    handed
}

/// The room of a record of `bytes` bytes for one subscriber.
fn room(bytes: usize) -> ReadRoom {
    ReadRoom {
        bytes,
        callbacks: 1,
    }
}

/// A best-effort put of `len` bytes of `byte` on `demo/lane`.
fn filled(len: usize, byte: u8) -> Sample {
    Sample::new_put("demo/lane", vec![byte; len]).with_reliability(Reliability::BestEffort)
}

/// A best-effort put of `payload` on `demo/lane`.
fn best_effort(payload: usize) -> Sample {
    Sample::new_put("demo/lane", vec![0xab; payload]).with_reliability(Reliability::BestEffort)
}

/// A sample with every part is handed to its subscriber with every part as it was offered, from
/// the lane's area, and the lane is empty once its callback is done.
#[test]
fn a_sample_is_handed_as_it_was_offered() {
    let Some(mut lane) = lane(1024, 4) else {
        return;
    };
    let source = SourceInfo::new(&[9, 9], 3, 4);
    let sample = Sample::new_put("demo/a", b"payload".to_vec())
        .with_attachment(b"att".to_vec())
        .with_encoding(EncodingHint {
            packed_id: 7,
            schema: Some(b"text".to_vec()),
        })
        .with_timestamp(TimestampHint {
            time: 42,
            zid: vec![1, 2, 3],
        })
        .with_qos(QosLevel::from_raw(5))
        .with_source_info(source.clone())
        .with_reliability(Reliability::BestEffort);
    lane.offer(7, &sample);
    {
        let (ids, view) = front(&mut lane).expect("the sample is at the head");
        assert_eq!(ids, [7]);
        assert_eq!(view.keyexpr(), "demo/a");
        assert_eq!(view.payload(), b"payload");
        assert_eq!(view.kind(), SampleKind::Put);
        assert_eq!(view.reliability(), Reliability::BestEffort);
        assert_eq!(view.qos(), Some(QosLevel::from_raw(5)));
        assert_eq!(view.attachment(), Some(&b"att"[..]));
        assert_eq!(view.encoding_parts(), Some((7, Some(&b"text"[..]))));
        assert_eq!(view.timestamp_parts(), Some((42, &[1u8, 2, 3][..])));
        assert_eq!(view.source_info(), Some(&source));
    }
    lane.complete();
    assert!(lane.take_front().is_none(), "nothing is left");
    assert_eq!(lane.counts(), LaneCounts::default());
}

/// A sample with no attachment, encoding or timestamp is handed with none: absent is not empty.
#[test]
fn a_sample_with_no_metadata_is_handed_with_none() {
    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    lane.offer(1, &Sample::new_del("demo/gone"));
    {
        let (_, view) = front(&mut lane).expect("the sample is at the head");
        assert_eq!(view.keyexpr(), "demo/gone");
        assert_eq!(view.kind(), SampleKind::Del);
        assert!(view.payload().is_empty());
        assert_eq!(view.attachment(), None);
        assert_eq!(view.encoding_parts(), None);
        assert_eq!(view.timestamp_parts(), None);
    }
    lane.complete();
}

/// While one delivery holds the head, another finds nothing, and the next sample is handed once
/// the head is complete: no sample is handed twice.
#[test]
fn a_second_delivery_finds_the_head_held() {
    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    lane.offer(1, &filled(8, 1));
    lane.offer(2, &filled(8, 2));
    let (first, _) = front(&mut lane).expect("the first sample");
    assert_eq!(first, [1]);
    assert!(lane.take_front().is_none(), "the head is held");
    lane.complete();
    let (second, _view) = front(&mut lane).expect("the second sample");
    assert_eq!(second, [2]);
}

/// A lane that admits one sample drops a second that may be dropped and counts it; one whose
/// congestion control holds its sender is counted apart; a reliable sample with no QoS has
/// zenoh's default, `drop`.
#[test]
fn a_full_lane_drops_what_may_be_dropped_and_counts_apart_what_holds_its_sender() {
    assert_eq!(
        QosLevel::from_raw(BLOCK).congestion(),
        CongestionControl::Block
    );
    let Some(mut lane) = lane(1024, 1) else {
        return;
    };
    lane.offer(1, &best_effort(8));
    lane.offer(1, &best_effort(8));
    assert_eq!(
        lane.counts(),
        LaneCounts {
            dropped: 1,
            held_over: 0
        }
    );
    lane.offer(1, &Sample::new_put("demo/lane", b"x".to_vec()));
    assert_eq!(lane.counts().dropped, 2, "no QoS is `drop`");
    lane.offer(
        1,
        &Sample::new_put("demo/lane", b"x".to_vec()).with_qos(QosLevel::from_raw(BLOCK)),
    );
    assert_eq!(
        lane.counts(),
        LaneCounts {
            dropped: 2,
            held_over: 1
        }
    );
    let (_, view) = front(&mut lane).expect("the first sample is kept");
    assert_eq!(view.payload().len(), 8);
}

/// A sample longer than the whole area is refused, whatever is queued.
#[test]
fn a_sample_longer_than_the_area_is_refused() {
    let Some(mut lane) = lane(64, 4) else {
        return;
    };
    lane.offer(1, &best_effort(100));
    assert_eq!(lane.counts().dropped, 1);
    assert!(lane.take_front().is_none());
}

/// The gate reads a link while the lane can take a whole batch, and not while it cannot; a batch
/// longer than the area is read only into an empty lane, so a link is never stopped for good.
#[test]
fn the_gate_reads_a_link_only_while_the_lane_takes_a_batch() {
    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    assert!(lane.takes_a_read(room(128)));
    assert!(
        lane.takes_a_read(room(512)),
        "an empty lane takes any batch"
    );
    lane.offer(1, &best_effort(200));
    assert!(
        !lane.takes_a_read(room(128)),
        "the lane has no room for a batch"
    );
    assert!(
        !lane.takes_a_read(room(512)),
        "nor for one longer than its area"
    );
    assert!(lane.take_front().is_some(), "the sample is at the head");
    lane.complete();
    assert!(
        lane.takes_a_read(room(128)),
        "the delivery gave the room back"
    );
}

/// The changes of matching statuses are handed in the order they were found; a change and the
/// change back before the first was handed leave the listener where it stood and are handed as
/// nothing.
#[test]
fn a_change_and_its_change_back_are_handed_as_nothing() {
    let mut flips = MatchFlips::new();
    flips.flip(1, true);
    flips.flip(2, true);
    flips.flip(1, false);
    assert_eq!(flips.next(), Some((2, true)));
    assert_eq!(flips.next(), None, "listener 1 stands where it stood");
    flips.flip(1, true);
    assert_eq!(flips.next(), Some((1, true)));
}

/// A listener that is gone is handed nothing it was owed, and the others keep their order.
#[test]
fn a_listener_that_is_gone_is_handed_nothing() {
    let mut flips = MatchFlips::new();
    flips.flip(1, true);
    flips.flip(2, true);
    flips.flip(3, false);
    flips.forget(2);
    assert_eq!(flips.next(), Some((1, true)));
    assert_eq!(flips.next(), Some((3, false)));
    assert_eq!(flips.next(), None);
}

/// Every listener the build admits has a row: as many listeners as the build's value each owe a
/// change, and each is handed.
#[test]
fn every_listener_the_build_admits_has_a_row() {
    let mut flips = MatchFlips::new();
    let listeners = wz_session_core::caps::MAX_MATCHING_LISTENERS as u64;
    for id in 0..listeners {
        flips.flip(id, true);
    }
    for id in 0..listeners {
        assert_eq!(flips.next(), Some((id, true)));
    }
    assert_eq!(flips.next(), None);
}

/// The build's lane holds the sample of the build's largest rejoined message on its longest key,
/// which is what lets a session's lane be sized from its own message under the build's; a lane
/// one byte short of a message's sample does not hold it.
#[test]
fn the_builds_lane_holds_the_builds_largest_message() {
    use crate::lane::{holds_a_read, read_bytes, sample_overhead};
    use wz_session_core::caps;

    assert!(holds_a_read::<
        { caps::DELIVERY_LANE_BYTES },
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >());
    assert_eq!(
        read_bytes(100, 50, 8, 2),
        100 + 32,
        "a batch longer than a message"
    );
    assert_eq!(
        read_bytes(50, 100, 8, 2),
        100 + 32,
        "a message longer than a batch"
    );
    assert!(holds_a_read::<{ 100 + 32 }, 100, 50, 8, 2, 0>());
    assert!(!holds_a_read::<{ 100 + 31 }, 100, 50, 8, 2, 0>());
    assert_eq!(
        sample_overhead(8, 2),
        32,
        "a key of 8, a clock id of 16 and two subscribers' ids of 4"
    );
}

/// A lane stated shorter than what one record can hand it is lengthened to hold it, from the
/// session's own (lowered) message length and batch and not the build's, the larger of the two;
/// a lane stated longer is kept.
#[test]
fn a_lane_is_sized_from_the_sessions_message() {
    use crate::lane::{holding_a_read, sample_overhead};
    use wz_session_core::caps;

    let frag = caps::PICO_FRAG_MAX_BYTES / 4;
    let mut short = SessionLimits::defaults();
    if short.select_delivery_lane_bytes(1).is_err()
        || short
            .select_pico_frag_max_bytes(Quota::at_most(frag))
            .is_err()
    {
        // A build that keeps either limit to its own value has no other.
        return;
    }
    let held = holding_a_read::<
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(short);
    let subscribers = if cfg!(feature = "liveliness") {
        caps::MAX_SUBSCRIPTIONS.max(caps::MAX_LIVELINESS_SUBSCRIPTIONS)
    } else {
        caps::MAX_SUBSCRIPTIONS
    };
    assert_eq!(
        held.delivery_lane_bytes(),
        frag.max(short.pico_unicast_batch_bytes())
            + sample_overhead(caps::MAX_KEYEXPR_BYTES, subscribers)
    );

    let long = SessionLimits::defaults();
    let kept = holding_a_read::<
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(long);
    assert_eq!(kept.delivery_lane_bytes(), long.delivery_lane_bytes());
}

/// A token's appearance takes the lane in the order it happens among the samples, handed back with
/// its key where it lies; a token whose key finds no room is counted with the samples that hold
/// their sender.
#[cfg(feature = "liveliness")]
#[test]
fn a_token_takes_the_lane_in_order_with_the_samples() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let Some(mut lane) = lane(64, 4) else {
        return;
    };
    lane.offer(1, &best_effort(8));
    lane.offer_liveliness(
        2,
        &LivelinessSample {
            kind: LivelinessSampleKind::Put,
            keyexpr: "demo/alive",
            token_id: 9,
        },
    );
    let (first, _) = front(&mut lane).expect("the sample first");
    assert_eq!(first, [1]);
    lane.complete();
    let Some(LaneItem::Liveliness(token)) = lane.take_front() else {
        panic!("the token next");
    };
    assert_eq!(token.subscribers().collect::<Vec<_>>(), [2]);
    let sample = token.as_sample();
    assert_eq!(
        (sample.kind, sample.keyexpr, sample.token_id),
        (LivelinessSampleKind::Put, "demo/alive", 9)
    );
    lane.complete();
    assert!(lane.take_front().is_none(), "nothing is left");

    let long = "k".repeat(100);
    lane.offer_liveliness(
        3,
        &LivelinessSample {
            kind: LivelinessSampleKind::Delete,
            keyexpr: &long,
            token_id: 1,
        },
    );
    assert_eq!(lane.counts().held_over, 1, "a key past the whole lane");
    assert!(lane.take_front().is_none());
}

/// A link that has nothing to give: what a gate over it holds back is the gate's alone.
struct Quiet;

impl wz_runtime_coop::session_drive::SessionDatagramLink for Quiet {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        None
    }
}

/// The gate holds the session's input back, the rest of a datagram already read included, while
/// the lane cannot take a batch, and lets it go once the delivery has given the room back.
#[test]
fn the_gate_holds_back_what_was_read_while_the_lane_is_full() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let Some(lane) = lane(64, 4) else {
        return;
    };
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    // SAFETY (every hold and the gate here): this thread is the lane's one writer and asks the
    // gate itself, as a session's step does under its lock.
    let gate = unsafe { LaneGate::new(Quiet, lane.clone(), room(32)) };
    assert!(gate.takes_input(), "an empty lane takes a batch");
    {
        let mut held = unsafe { lane.held() };
        held.offer(1, &best_effort(40));
        held.seal();
    }
    assert!(!gate.takes_input(), "no room left for a batch of 32");
    let delivery = lane.deliver().expect("no other delivery");
    let (item, head) = delivery.take().expect("the sample was handed on");
    assert!(matches!(item, LaneItem::Sample(_)));
    drop(head);
    drop(delivery);
    assert!(
        gate.takes_input(),
        "given back, the lane takes a batch again"
    );
}

/// The gate is asked before every datagram and every further record and reads the lane's room
/// from the word the lane's last holder left, holding the lane only while the word says there is
/// none; a delivery on another thread takes a sample and gives it back with no lock, and the gate
/// then finds the room it gave back.
#[test]
fn a_delivery_on_another_thread_gives_the_room_back_with_no_lock() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let Some(lane) = lane(64, 4) else {
        return;
    };
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    // SAFETY (every hold and the gate here): this thread is the lane's one writer.
    let gate = unsafe { LaneGate::new(Quiet, lane.clone(), room(32)) };
    for _ in 0..10 {
        assert!(gate.takes_input(), "an empty lane takes a batch");
        assert!(gate.try_recv().is_none(), "the link has nothing");
    }
    {
        let mut held = unsafe { lane.held() };
        held.offer(1, &best_effort(40));
        held.seal();
    }
    assert!(!gate.takes_input(), "no room left for a batch of 32");
    assert!(lane.owes_a_delivery(), "the sample was handed on");
    let delivery = {
        let lane = lane.clone();
        std::thread::spawn(move || {
            let delivery = lane.deliver().expect("the one delivery");
            let (_, head) = delivery.take().expect("the sample");
            drop(head);
            assert!(delivery.take().is_none(), "one sample was handed on");
        })
    };
    delivery.join().expect("the delivery");
    assert!(!lane.owes_a_delivery(), "the delivery took it");
    assert!(
        gate.takes_input(),
        "the delivery's thread gave the room back"
    );
}

/// The samples of several holds are handed on in the order they were written, one delivery holds
/// the deliveries' side at a time, and a sample's room comes back only once it is given back.
#[test]
fn the_lane_hands_its_samples_on_in_order_to_one_delivery_at_a_time() {
    use crate::lane::SharedLane;

    let Some(lane) = lane(256, 4) else {
        return;
    };
    let lane = SharedLane::new(lane);
    for subscriber in 1..=3 {
        // SAFETY: this thread is the lane's one writer.
        let mut held = unsafe { lane.held() };
        held.offer(subscriber, &filled(16, 7));
        held.seal();
    }
    let delivery = lane.deliver().expect("one delivery");
    assert!(
        lane.deliver().is_none(),
        "the deliveries' side is held by one delivery at a time"
    );
    let mut seen = Vec::new();
    while let Some((item, head)) = delivery.take() {
        // The other items exist only where their planes are built.
        #[cfg(any(feature = "liveliness", feature = "query"))]
        let LaneItem::Sample(sample) = item
        else {
            panic!("samples were offered");
        };
        #[cfg(not(any(feature = "liveliness", feature = "query")))]
        let LaneItem::Sample(sample) = item;
        seen.push(sample.subscribers().collect::<Vec<_>>());
        drop(head);
    }
    assert_eq!(
        seen,
        vec![vec![1], vec![2], vec![3]],
        "first written, first handed"
    );
    drop(delivery);
    assert!(lane.deliver().is_some(), "let go, the side is free again");
}

/// A sample whose parts lie in the datagram a link lends the step is handed to its callbacks where
/// they lie, once for every subscriber it reaches, and holds the links back until it is given
/// back; one offered while a delivery runs, or whose payload lies elsewhere, is written into the
/// lane instead.
#[test]
fn a_sample_whose_parts_lie_in_the_lent_datagram_is_handed_where_they_lie() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let Some(lane) = lane(256, 4) else {
        return;
    };
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    // SAFETY (every hold, the gate and the lending here): this thread is the lane's one writer,
    // as a session's step is under its lock, and the sample's payload stands for the datagram it
    // lies in, which outlives every use below.
    let gate = unsafe { LaneGate::new(Quiet, lane.clone(), room(32)) };
    let sample = filled(8, 7);
    let datagram = sample.payload();
    let offer = |subscribers: &[SubId], sample: &Sample| {
        unsafe { lane.set_lending(Some(datagram)) };
        let mut held = unsafe { lane.held() };
        for subscriber in subscribers {
            held.offer_sample(*subscriber, sample);
        }
        held.seal_all();
        drop(held);
        unsafe { lane.set_lending(None) };
    };
    offer(&[1, 2], &sample);
    assert!(!gate.takes_input(), "the lent datagram holds the link back");
    assert_eq!(lane.handed_on(), 0, "nothing was written into the lane");
    let delivery = lane.deliver().expect("one delivery");
    let lent = delivery.take_lent().expect("the sample was lent");
    assert_eq!(
        lent.sample().payload().as_ptr(),
        datagram.as_ptr(),
        "handed where it lies"
    );
    assert_eq!(lent.sample().keyexpr(), "demo/lane");
    assert_eq!(lent.sample().subscribers().collect::<Vec<_>>(), vec![1, 2]);
    drop(lent);
    assert!(
        delivery.take().is_none(),
        "nothing was written into the lane"
    );
    drop(delivery);
    assert!(gate.takes_input(), "given back, the link is read again");

    let running = lane.deliver().expect("a delivery runs");
    offer(&[3], &sample);
    assert_eq!(
        lane.handed_on(),
        1,
        "offered while a delivery runs, the sample is written into the lane"
    );
    while let Some((_, head)) = running.take() {
        drop(head);
    }
    drop(running);

    offer(&[4], &filled(8, 9));
    assert_eq!(
        lane.handed_on(),
        2,
        "a payload outside the lent datagram is written into the lane"
    );
    assert_eq!(lane.lent_count(), 1, "one sample was lent");
}

/// A sample offered for several subscribers is written once and handed to each of them, in the
/// order it was offered to them: it takes the room of one copy and the ids, and one event slot.
#[test]
fn a_sample_for_several_subscribers_is_written_once_and_handed_to_each() {
    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    let sample = filled(40, 7);
    lane.offer(3, &sample);
    lane.offer(1, &sample);
    lane.offer(2, &sample);
    // One copy: the key's 9 bytes, the payload's 40 and three ids of 4; three copies would leave
    // fewer than 100 bytes of the 256.
    assert!(lane.takes_a_read(room(256 - (9 + 40 + 3 * 4))));
    assert_eq!(drain(&mut lane), [(vec![3, 1, 2], 7)]);
    assert_eq!(lane.counts(), LaneCounts::default());
}

/// A second sample of the same bytes is a sample of its own, and a sample offered after another
/// one is written again: neither is folded into a sample its subscriber already has, nor moved
/// ahead of the sample between them.
#[test]
fn a_sample_is_shared_only_by_the_subscribers_offered_it_together() {
    let Some(mut lane) = lane(512, 8) else {
        return;
    };
    let same = filled(8, 1);
    lane.offer(1, &same);
    lane.offer(2, &same);
    lane.offer(1, &same);
    lane.offer(2, &same);
    lane.offer(1, &filled(8, 2));
    lane.offer(2, &same);
    assert_eq!(
        drain(&mut lane),
        [(vec![1, 2], 1), (vec![1, 2], 1), (vec![1], 2), (vec![2], 1)]
    );
}

/// The head a delivery holds keeps its bytes and its subscribers until the delivery completes
/// it: a sample that would need its room is refused meanwhile, and the room comes back after.
#[test]
fn a_held_sample_keeps_its_room_until_its_last_subscriber_is_done() {
    let Some(mut lane) = lane(128, 4) else {
        return;
    };
    let shared = filled(40, 5);
    lane.offer(1, &shared);
    lane.offer(2, &shared);
    lane.offer(3, &shared);
    let (ids, held) = front(&mut lane).expect("the shared sample");
    assert_eq!(ids, [1, 2, 3]);
    // 61 bytes held; 63 more fit, and nothing after them.
    lane.offer(4, &filled(50, 6));
    lane.offer(4, &filled(10, 8));
    assert_eq!(lane.counts().dropped, 1, "no room while the head is held");
    assert_eq!(held.payload(), [5u8; 40]);
    assert_eq!(held.subscribers().collect::<Vec<_>>(), [1, 2, 3]);
    lane.complete();
    lane.offer(4, &filled(10, 8));
    assert_eq!(lane.counts().dropped, 1, "the room came back");
    assert_eq!(drain(&mut lane), [(vec![4], 6), (vec![4], 8)]);
}

/// Each subscriber of a shared sample owes a callback: those past the callbacks the lane owes at
/// once are counted and handed nothing, and the ones before them are handed the sample.
#[test]
fn subscribers_past_the_callbacks_owed_are_counted() {
    let Some(mut lane) = lane_owing(256, 4, 3) else {
        return;
    };
    // A sample queued ahead owes one of the three, so the shared one is not alone in the lane,
    // where it would be let owe more than all of them.
    lane.offer(9, &filled(8, 9));
    let shared = filled(8, 3);
    lane.offer(1, &shared);
    lane.offer(2, &shared);
    lane.offer(3, &shared);
    assert_eq!(lane.counts().dropped, 1);
    assert_eq!(drain(&mut lane), [(vec![9], 9), (vec![1, 2], 3)]);
}

/// A subscriber whose id finds no room after the shared sample is offered a copy of its own,
/// which is refused and counted when there is no room for that either.
#[test]
fn a_subscriber_with_no_room_for_its_id_is_counted() {
    let Some(mut lane) = lane(64, 4) else {
        return;
    };
    // The key's 9 bytes, the payload's 47 and two ids fill the 64.
    let shared = filled(47, 4);
    lane.offer(1, &shared);
    lane.offer(2, &shared);
    lane.offer(3, &shared);
    assert_eq!(lane.counts().dropped, 1);
    assert_eq!(drain(&mut lane), [(vec![1, 2], 4)]);
}

/// The gate asks for a record's callbacks too: those the event held open owes once it is
/// published count, and callbacks past the whole budget are found only in an empty lane.
#[test]
fn the_gate_asks_for_the_callbacks_of_a_record() {
    let Some(mut lane) = lane_owing(256, 4, 3) else {
        return;
    };
    let two = ReadRoom {
        bytes: 16,
        callbacks: 2,
    };
    let past = ReadRoom {
        bytes: 16,
        callbacks: 4,
    };
    assert!(lane.takes_a_read(past), "an empty lane takes any record");
    let shared = filled(8, 1);
    lane.offer(1, &shared);
    lane.offer(2, &shared);
    assert!(
        !lane.takes_a_read(two),
        "two owed by the open sample, two more past three"
    );
    assert!(lane.takes_a_read(room(16)), "one more fits");
    assert!(!lane.takes_a_read(past));
    assert_eq!(drain(&mut lane), [(vec![1, 2], 1)]);
    assert!(lane.takes_a_read(two));
}

/// A token offered for several liveliness subscribers is written once and handed to each, and a
/// token of another kind for the same key is a token of its own.
#[cfg(feature = "liveliness")]
#[test]
fn a_token_for_several_subscribers_is_written_once() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    let token = |kind| LivelinessSample {
        kind,
        keyexpr: "demo/alive",
        token_id: 9,
    };
    lane.offer_liveliness(1, &token(LivelinessSampleKind::Put));
    lane.offer_liveliness(2, &token(LivelinessSampleKind::Put));
    lane.offer_liveliness(1, &token(LivelinessSampleKind::Delete));
    // One copy of the key's 10 bytes and two ids, then the second token's key and id.
    assert!(lane.takes_a_read(room(256 - (10 + 2 * 4) - (10 + 4))));
    let mut handed = Vec::new();
    while let Some(LaneItem::Liveliness(token)) = lane.take_front() {
        handed.push((
            token.subscribers().collect::<Vec<_>>(),
            token.as_sample().kind,
        ));
        lane.complete();
    }
    assert_eq!(
        handed,
        [
            (vec![1, 2], LivelinessSampleKind::Put),
            (vec![1], LivelinessSampleKind::Delete)
        ]
    );
}

/// A record the gate let through that holds its sender and finds no room is a defect: a debug
/// build stops there, and a release build counts it apart.
#[test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "a record the gate let through found no room")
)]
fn a_gated_record_that_finds_no_room_is_a_defect() {
    let Some(mut lane) = lane(1024, 1) else {
        // A build that keeps the lane's limits to its own values has no such lane: its debug form
        // ends as the test expects of it.
        #[cfg(debug_assertions)]
        panic!("a record the gate let through found no room: no such lane in this build");
        #[cfg(not(debug_assertions))]
        return;
    };
    lane.offer(1, &best_effort(8));
    #[cfg(debug_assertions)]
    lane.offering_gated(true);
    lane.offer(
        2,
        &Sample::new_put("demo/lane", b"x".to_vec()).with_qos(QosLevel::from_raw(BLOCK)),
    );
    assert_eq!(lane.counts().held_over, 1);
}

/// While the lane captures, an offer notes its subscriber and queues nothing; a sample queued for
/// several subscribers at once is written once, and the room for it is asked first.
#[cfg(feature = "local-subscriber")]
#[test]
fn a_captured_offer_queues_nothing_and_a_sample_for_several_is_written_once() {
    let Some(mut lane) = lane(64, 4) else {
        return;
    };
    lane.capture();
    lane.offer(3, &filled(8, 1));
    lane.offer(1, &filled(8, 1));
    assert_eq!(lane.captured().to_vec(), [3, 1]);
    assert!(lane.take_front().is_none(), "nothing was queued");
    let sample = filled(40, 2);
    assert!(lane.takes_sample(&sample, 2), "9 + 40 + 8 bytes of 64");
    assert!(
        !lane.takes_sample(&sample, 5),
        "9 + 40 + 20 bytes are past 64"
    );
    lane.offer_to(&[3, 1], &sample);
    assert_eq!(drain(&mut lane), [(vec![3, 1], 2)]);
    assert_eq!(lane.counts(), LaneCounts::default());
}

/// Tokens offered while the lane rehearses are placed on a copy of its bookkeeping and not queued:
/// the rehearsal says whether every one would find room, and the lane is left as it was.
#[cfg(feature = "liveliness")]
#[test]
fn a_rehearsal_says_whether_the_tokens_fit_and_queues_none() {
    use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};

    let Some(mut lane) = lane(64, 4) else {
        return;
    };
    let token = |token_id| LivelinessSample {
        kind: LivelinessSampleKind::Put,
        keyexpr: "demo/alive",
        token_id,
    };
    lane.rehearse();
    for token_id in 0..4 {
        lane.offer_liveliness(1, &token(token_id));
    }
    assert!(lane.rehearsed(), "four tokens of 14 bytes in 64");
    assert!(lane.take_front().is_none(), "the rehearsal queued nothing");
    lane.rehearse();
    for token_id in 0..5 {
        lane.offer_liveliness(1, &token(token_id));
    }
    assert!(!lane.rehearsed(), "a fifth is past the lane's four events");
    assert!(lane.take_front().is_none());
    assert_eq!(
        lane.counts(),
        LaneCounts::default(),
        "a rehearsal counts nothing"
    );
}

/// A reply a test hands the lane: an Err with an encoding, an attachment-free answer of a
/// responder, stamped.
#[cfg(feature = "query")]
struct Answer;

#[cfg(feature = "query")]
impl wz_session_core::reply_sink::ReplyView for Answer {
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        9
    }

    fn keyexpr(&self) -> &str {
        "demo/answer"
    }

    fn kind(&self) -> wz_session_core::reply_sink::ReplyKind {
        wz_session_core::reply_sink::ReplyKind::Err
    }

    fn payload(&self) -> &[u8] {
        b"refused"
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        Some((3, Some(b"text")))
    }

    fn timestamp_parts(&self) -> Option<wz_session_core::reply_stage::TimestampParts<'_>> {
        Some(wz_session_core::reply_stage::TimestampParts {
            time: 42,
            zid: &[1, 2],
        })
    }

    fn responder(&self) -> Option<(&[u8], u32)> {
        Some((&[7, 7, 7], 5))
    }
}

/// A reply takes one event of the lane and is handed to its leg's callback with every part as it
/// came, from the lane's area; the lane is idle once it is done, and not while it is held.
#[cfg(feature = "query")]
#[test]
fn a_reply_is_handed_from_the_lane_as_it_came() {
    use wz_session_core::reply_sink::{ReplyKind, ReplyView};

    let Some(mut lane) = lane(256, 4) else {
        return;
    };
    assert!(lane.is_idle());
    lane.offer_reply(11, &Answer);
    assert!(!lane.is_idle(), "a reply waits");
    let Some(LaneItem::Reply(reply)) = lane.take_front() else {
        panic!("the reply is at the head");
    };
    assert_eq!(reply.leg(), 11);
    assert_eq!(
        (reply.rid(), reply.keyexpr(), reply.kind(), reply.payload()),
        (9, "demo/answer", ReplyKind::Err, &b"refused"[..])
    );
    assert_eq!(reply.err_encoding(), Some((3, Some(&b"text"[..]))));
    assert_eq!(
        reply.put_encoding(),
        None,
        "an Err's encoding is not a Put's"
    );
    assert_eq!(reply.attachment(), None);
    assert_eq!(
        reply.timestamp_parts().map(|stamp| (stamp.time, stamp.zid)),
        Some((42, &[1u8, 2][..]))
    );
    assert_eq!(reply.responder(), Some((&[7u8, 7, 7][..], 5)));
    assert!(!lane.is_idle(), "a delivery holds the head");
    lane.complete();
    assert!(lane.is_idle());
    assert_eq!(lane.counts(), LaneCounts::default());
}
