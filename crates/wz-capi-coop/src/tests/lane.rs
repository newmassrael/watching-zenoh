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
use wz_session_core::sink::{BorrowedSample, SampleView};

use wz_capi_port::SubId;

use super::entity_tables::lowered;
use crate::lane::{LaneCounts, LaneItem, LaneSample, MatchFlips, ReadRoom, SampleLane};

/// The QoS byte of a sample sent at the data priority whose congestion control holds its sender.
const BLOCK: u8 = 0x05 | 0x08;

/// The build's limits with the lane's area `bytes` long, admitting `events` samples at once.
fn lane_limits(bytes: usize, events: usize) -> SessionLimits {
    lowered(|l| {
        l.select_delivery_lane_bytes(bytes)?;
        l.select_delivery_lane_events(Quota::at_most(events))
    })
}

/// A lane over an area of `bytes` the test leaks, under `limits`.
fn over(bytes: usize, limits: &SessionLimits) -> SampleLane {
    let area: &'static mut [u8] = vec![0u8; bytes].leak();
    // SAFETY: the area is leaked, so it outlives the lane, and nothing else uses it.
    unsafe { SampleLane::over(NonNull::from(area).cast::<u8>(), bytes, limits) }
}

/// A lane over an area of `bytes` the test leaks, admitting `events` samples at once.
fn lane(bytes: usize, events: usize) -> SampleLane {
    over(bytes, &lane_limits(bytes, events))
}

/// [`lane`] whose callbacks owed at once are `callbacks` at most.
fn lane_owing(bytes: usize, events: usize, callbacks: usize) -> SampleLane {
    let limits = lowered(|l| {
        l.select_delivery_lane_bytes(bytes)?;
        l.select_delivery_lane_events(Quota::at_most(events))?;
        l.select_delivery_lane_callbacks(Quota::at_most(callbacks))
    });
    over(bytes, &limits)
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
        LaneItem::Batch(_) => panic!("a sample was offered with no datagram lent"),
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
    let mut lane = lane(1024, 4);
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
    let mut lane = lane(256, 4);
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
    let mut lane = lane(256, 4);
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
    let mut lane = lane(1024, 1);
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

/// A lane built where the allocation that shares it keeps it serves as one built by value: a full
/// lane drops what may be dropped and counts it, and hands what it kept, alike.
#[test]
fn a_lane_built_in_its_shared_place_serves_as_one_built_by_value() {
    let mut by_value = lane(1024, 1);
    let limits = lane_limits(1024, 1);
    let area: &'static mut [u8] = vec![0u8; 1024].leak();
    // SAFETY: the area is leaked, so it outlives the lane, and nothing else uses it.
    let shared = unsafe {
        crate::lane::SharedLane::shared_over(NonNull::from(area).cast::<u8>(), 1024, &limits)
    };
    // SAFETY: this thread is the lane's one writer.
    let mut in_place = unsafe { shared.held() };
    for lane in [&mut by_value, &mut *in_place] {
        assert_eq!(
            lane.counts(),
            LaneCounts::default(),
            "CONTROL: nothing is counted yet"
        );
        lane.offer(1, &best_effort(8));
        lane.offer(1, &best_effort(8));
        assert_eq!(
            lane.counts(),
            LaneCounts {
                dropped: 1,
                held_over: 0
            }
        );
        assert_eq!(drain(lane), [(vec![1], 0xab)]);
        assert!(lane.take_front().is_none(), "nothing is left");
    }
}

/// A sample longer than the whole area is refused, whatever is queued.
#[test]
fn a_sample_longer_than_the_area_is_refused() {
    let mut lane = lane(64, 4);
    lane.offer(1, &best_effort(100));
    assert_eq!(lane.counts().dropped, 1);
    assert!(lane.take_front().is_none());
}

/// The gate reads a link while the lane can take a whole batch, and not while it cannot; a batch
/// longer than the area is read only into an empty lane, so a link is never stopped for good.
#[test]
fn the_gate_reads_a_link_only_while_the_lane_takes_a_batch() {
    let mut lane = lane(256, 4);
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
    use crate::lane::{holds_a_read, read_bytes, sample_overhead, ENTRY_BYTES};
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
        read_bytes(1000, 500, 8, 2),
        1000 + 32,
        "a batch longer than a message"
    );
    assert_eq!(
        read_bytes(500, 1000, 8, 2),
        1000 + 32,
        "a message longer than a batch"
    );
    assert_eq!(
        read_bytes(8, 4, 8, 2),
        ENTRY_BYTES + 32,
        "a batch and a message shorter than the entry of a sample of a lent batch"
    );
    assert!(holds_a_read::<{ 1000 + 32 }, 1000, 500, 8, 2, 0>());
    assert!(!holds_a_read::<{ 1000 + 31 }, 1000, 500, 8, 2, 0>());
    assert_eq!(
        sample_overhead(8, 2),
        32,
        "a key of 8, a clock id of 16 and two subscribers' ids of 4"
    );
}

/// The speed image's lane (`deploy/zephyr-mcu-speed/arm_w.conf`) is the room of one record at the
/// limits that image states: its batch of 2,048 bytes, its largest rejoined message of 4,096, its
/// keys of 64 bytes and one subscriber, 4,180 bytes; a lane one byte shorter holds no read.
#[test]
fn the_speed_images_lane_is_the_room_of_one_record() {
    use crate::lane::{holds_a_read, read_bytes};

    assert_eq!(read_bytes(2048, 4096, 64, 1), 4180);
    assert!(holds_a_read::<4180, 2048, 4096, 64, 1, 1>());
    assert!(!holds_a_read::<4179, 2048, 4096, 64, 1, 1>());
}

/// A lane stated shorter than what one record can hand it is lengthened to hold it, from the
/// session's own (lowered) message length and batch and not the build's, the larger of the two;
/// a lane stated longer is kept.
#[test]
fn a_lane_is_sized_from_the_sessions_message() {
    use crate::lane::{holding_a_read, sample_overhead};
    use wz_session_core::caps;

    let frag = caps::PICO_FRAG_MAX_BYTES / 4;
    let short = lowered(|l| {
        l.select_delivery_lane_bytes(1)?;
        l.select_pico_frag_max_bytes(Quota::at_most(frag))
    });
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

    let mut lane = lane(64, 4);
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

    let lane = lane(64, 4);
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

    let lane = lane(64, 4);
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

    let lane = lane(256, 4);
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
        let LaneItem::Sample(sample) = item else {
            panic!("samples were offered with no datagram lent");
        };
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

/// A best-effort put on `demo/lane` whose payload is borrowed where it lies, as a sample read in
/// place is.
fn borrowed(payload: &[u8]) -> BorrowedSample<'_> {
    BorrowedSample {
        keyexpr: "demo/lane",
        payload,
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    }
}

/// The samples whose parts lie in the datagram a link lends the step are one record of the lane,
/// a batch, handed to their callbacks where they lie: every sample of the datagram in the one
/// step, in the order they came, one hand-on and one give-back for the three. A key that lies
/// elsewhere is written once for the samples on it. The batch holds the link back from its next
/// receive until it is given back, and not from the records after it. The CONTROLS: a sample
/// offered while a delivery runs, and one whose payload lies elsewhere, are written into the lane
/// whole as a record each and hold nothing back.
#[test]
fn the_samples_of_a_lent_datagram_are_one_record_handed_where_they_lie() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let lane = lane(1024, 4);
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    // SAFETY (every hold, the gate and the lending here): this thread is the lane's one writer,
    // as a session's step is under its lock, and the datagram outlives every use below.
    let gate = unsafe { LaneGate::new(Quiet, lane.clone(), room(32)) };
    let datagram = [1u8, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3];
    unsafe { lane.set_lending(Some(&datagram[..])) };
    for (subscriber, payload) in (1..).zip(datagram.chunks(4)) {
        unsafe { lane.held() }.offer_sample(subscriber, &borrowed(payload));
        assert!(
            lane.lends_a_datagram(),
            "the batch held open lies in the datagram"
        );
        assert!(gate.takes_input(), "and holds back no record after it");
    }
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert!(
        lane.lends_a_datagram(),
        "handed on, the batch holds the link back"
    );
    assert_eq!(lane.handed_on(), 1, "one record for the three samples");
    assert_eq!(lane.lent_count(), 3, "each lying in the datagram");
    let delivery = lane.deliver().expect("one delivery");
    let (item, head) = delivery.take().expect("the batch was handed on");
    let LaneItem::Batch(batch) = item else {
        panic!("the samples of a lent datagram are a batch");
    };
    let seen: Vec<_> = batch
        .samples()
        .map(|sample| {
            (
                sample.subscribers().collect::<Vec<_>>(),
                sample.payload().as_ptr(),
                sample.keyexpr().to_owned(),
                sample.keyexpr().as_ptr(),
            )
        })
        .collect();
    assert!(
        delivery.take().is_none(),
        "the batch is all that was handed on"
    );
    assert!(
        lane.lends_a_datagram(),
        "the link is held back until the batch is given back"
    );
    drop(head);
    drop(delivery);
    assert!(
        !lane.lends_a_datagram(),
        "given back, the link is read again"
    );
    assert_eq!(
        seen.iter()
            .map(|(ids, payload, key, _)| (ids.clone(), *payload, key.clone()))
            .collect::<Vec<_>>(),
        [1usize, 2, 3]
            .map(|n| (
                vec![n as SubId],
                datagram[(n - 1) * 4..].as_ptr(),
                "demo/lane".to_owned()
            ))
            .to_vec(),
        "each handed where it lies, in the order they came"
    );
    let key = seen[0].3;
    assert!(
        seen.iter().all(|(.., at)| *at == key),
        "the key that lies outside the datagram is written once for the three"
    );
    assert_ne!(
        key,
        "demo/lane".as_ptr(),
        "and written into the lane, as its own bytes may be gone when the callbacks run"
    );

    let running = lane.deliver().expect("a delivery runs");
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.held() }.offer_sample(4, &borrowed(&datagram[..4]));
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert_eq!(
        (lane.handed_on(), lane.lent_count()),
        (2, 3),
        "CONTROL: offered while a delivery runs, the sample is written into the lane whole"
    );
    assert!(!lane.lends_a_datagram(), "and holds nothing back");
    let (item, head) = running.take().expect("the sample written whole");
    assert!(
        matches!(item, LaneItem::Sample(_)),
        "a record of its own, not a batch"
    );
    drop(head);
    drop(running);

    let elsewhere = [9u8; 4];
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.held() }.offer_sample(5, &borrowed(&elsewhere));
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert_eq!(
        (lane.handed_on(), lane.lent_count()),
        (3, 3),
        "CONTROL: a payload outside the lent datagram is written into the lane whole"
    );
    assert!(!lane.lends_a_datagram(), "and holds nothing back");
}

/// A link that lends one datagram where it lies, as UDP and a stream do.
struct Lends(Vec<u8>);

impl wz_runtime_coop::session_drive::SessionDatagramLink for Lends {
    fn service(&self) {}

    fn try_recv(&self) -> Option<wz_session_core::link::RxFrame> {
        None
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        f(&self.0);
        true
    }

    fn lends_until_next_receive(&self) -> bool {
        true
    }
}

/// The samples of a datagram a link's gate lends the step are offered with no hold of the lane
/// each, into the datagram's batch, and the one hold the gate takes when the walk ends publishes
/// the batch and hands it on: three samples, one hold, one record. The room the gate asks before
/// each record is left after each all the same. The CONTROL is a sample offered with no datagram
/// lent, which takes a hold of its own.
#[test]
fn the_samples_of_a_lent_datagram_are_handed_on_by_one_hold() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let lane = lane(1024, 8);
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    let datagram = vec![1u8, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3];
    // SAFETY (every offer, hold and the gate here): this thread is the lane's one writer, as a
    // session's step is under its lock.
    let gate = unsafe { LaneGate::new(Lends(datagram), lane.clone(), room(32)) };
    let holds = lane.holds();
    let walked = gate.recv_with(&mut |datagram| {
        for (subscriber, payload) in (1..).zip(datagram.chunks(4)) {
            unsafe { lane.offer_sample(subscriber, &borrowed(payload)) };
            assert!(gate.takes_input(), "the room is left after each record");
        }
    });
    assert!(walked, "the link lent its datagram");
    assert_eq!(
        lane.holds() - holds,
        1,
        "one hold for the datagram's three samples"
    );
    assert_eq!(
        (lane.handed_on(), lane.lent_count()),
        (1, 3),
        "the batch handed on as the walk ends, its three samples lying where they lie"
    );
    assert!(lane.lends_a_datagram(), "and it holds the link back");
    assert_eq!(
        delivered(&lane),
        [(true, vec![(vec![1], 1), (vec![2], 2), (vec![3], 3)])],
        "three callbacks from the one record, in the order the samples came"
    );
    assert!(
        !lane.lends_a_datagram(),
        "given back, the link is read again"
    );

    let holds = lane.holds();
    unsafe { lane.offer_sample(4, &best_effort(8)) };
    assert_eq!(
        lane.holds() - holds,
        1,
        "CONTROL: a sample offered with no datagram lent takes a hold of its own"
    );
}

/// One record a delivery took: whether it was a lent batch, and each sample's subscribers and
/// first payload byte.
type TakenRecord = (bool, Vec<(Vec<SubId>, u8)>);

/// What one delivery of `lane` takes, in order, each given back as it is read: whether it is a
/// batch, and the subscribers and the first payload byte of each of its samples.
fn delivered(lane: &crate::lane::SharedLane) -> Vec<TakenRecord> {
    let first = |payload: &[u8]| payload.first().copied().unwrap_or(0);
    let delivery = lane.deliver().expect("no other delivery");
    let mut seen = Vec::new();
    while let Some((item, head)) = delivery.take() {
        let samples: (bool, Vec<(Vec<SubId>, u8)>) = match &item {
            LaneItem::Batch(batch) => (
                true,
                batch
                    .samples()
                    .map(|sample| (sample.subscribers().collect(), first(sample.payload())))
                    .collect(),
            ),
            LaneItem::Sample(sample) => (
                false,
                vec![(sample.subscribers().collect(), first(sample.payload()))],
            ),
            #[cfg(feature = "liveliness")]
            LaneItem::Liveliness(_) => panic!("samples were offered, not a token"),
            #[cfg(feature = "query")]
            LaneItem::Reply(_) => panic!("samples were offered, not a reply"),
        };
        seen.push(samples);
        drop(head);
    }
    seen
}

/// A lent datagram's samples take one event slot together, so the samples one read hands on are
/// bounded by the lane's bytes and callbacks and not by its event slots: ten samples of one
/// datagram go through a lane of two event slots as one record, the gate taking input before each.
/// The CONTROL is the same lane with two samples written whole, one slot each, after which the
/// gate takes no further record.
#[test]
fn a_lent_batch_takes_one_event_slot_however_many_samples_it_holds() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let (lane, mut whole) = (lane(4096, 2), lane(4096, 2));
    let lane = alloc::sync::Arc::new(SharedLane::new(lane));
    let datagram: Vec<u8> = (0..10).collect();
    // SAFETY (every offer and the gate here): this thread is the lane's one writer.
    let gate = unsafe { LaneGate::new(Lends(datagram), lane.clone(), room(256)) };
    let walked = gate.recv_with(&mut |datagram| {
        for (subscriber, payload) in (1..).zip(datagram.chunks(1)) {
            assert!(gate.takes_input(), "the batch leaves the room of a record");
            unsafe { lane.offer_sample(subscriber, &borrowed(payload)) };
        }
    });
    assert!(walked, "the link lent its datagram");
    assert_eq!((lane.handed_on(), lane.lent_count()), (1, 10));
    assert_eq!(
        delivered(&lane),
        [(
            true,
            (0..10u8)
                .map(|n| (vec![SubId::from(n) + 1], n))
                .collect::<Vec<_>>()
        )],
        "ten callbacks in the order the samples came"
    );

    whole.offer(1, &filled(1, 1));
    whole.offer(2, &filled(1, 2));
    assert!(
        !whole.takes_a_read(room(256)),
        "CONTROL: two samples written whole hold both event slots"
    );
}

/// A sample of a lent datagram offered for several subscribers is one entry of its batch, its
/// subscribers' ids after it, and is handed to each in the order it was offered to them; offered
/// again for a subscriber it is for already, it is an entry of its own, and so is the next sample.
#[test]
fn a_lent_sample_for_several_subscribers_is_one_entry_of_its_batch() {
    use crate::lane::SharedLane;

    let lane = lane(1024, 4);
    let lane = SharedLane::new(lane);
    let datagram = [7u8, 7, 8, 8];
    let (first, second) = (borrowed(&datagram[..2]), borrowed(&datagram[2..]));
    // SAFETY (every hold and the lending here): this thread is the lane's one writer, and the
    // datagram outlives every use below.
    unsafe { lane.set_lending(Some(&datagram[..])) };
    for subscriber in [3, 1, 2, 1] {
        unsafe { lane.held() }.offer_sample(subscriber, &first);
    }
    unsafe { lane.held() }.offer_sample(1, &second);
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert_eq!((lane.handed_on(), lane.lent_count()), (1, 3));
    assert_eq!(
        delivered(&lane),
        [(true, vec![(vec![3, 1, 2], 7), (vec![1], 7), (vec![1], 8)])]
    );
}

/// A sample of a lent datagram with a part outside it is written into the lane whole, and the
/// batch before it is published first: the samples are handed out in the order they came, the
/// ones after it in a batch of their own.
#[test]
fn a_lent_sample_with_a_part_elsewhere_is_written_whole_in_order() {
    use crate::lane::SharedLane;

    let lane = lane(1024, 8);
    let lane = SharedLane::new(lane);
    let datagram = [1u8, 1, 3, 3];
    let elsewhere = [2u8, 2];
    // SAFETY (every hold and the lending here): this thread is the lane's one writer, and the
    // datagram outlives every use below.
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.held() }.offer_sample(1, &borrowed(&datagram[..2]));
    unsafe { lane.held() }.offer_sample(1, &borrowed(&elsewhere));
    unsafe { lane.held() }.offer_sample(1, &borrowed(&datagram[2..]));
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert_eq!((lane.handed_on(), lane.lent_count()), (3, 2));
    assert_eq!(
        delivered(&lane),
        [
            (true, vec![(vec![1], 1)]),
            (false, vec![(vec![1], 2)]),
            (true, vec![(vec![1], 3)]),
        ]
    );
}

/// A sample whose key lies in the lent datagram as well is read there, key and all: the view's
/// key is the datagram's bytes.
#[test]
fn a_key_that_lies_in_the_lent_datagram_is_read_there() {
    use crate::lane::SharedLane;

    let lane = lane(1024, 4);
    let lane = SharedLane::new(lane);
    let datagram = *b"demo/kxyz";
    let sample = BorrowedSample {
        keyexpr: core::str::from_utf8(&datagram[..6]).expect("a key of the test's"),
        payload: &datagram[6..],
        kind: SampleKind::Put,
        reliability: Reliability::BestEffort,
    };
    // SAFETY (every hold and the lending here): this thread is the lane's one writer, and the
    // datagram outlives every use below.
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.held() }.offer_sample(1, &sample);
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    let delivery = lane.deliver().expect("one delivery");
    let (item, head) = delivery.take().expect("the batch was handed on");
    let LaneItem::Batch(batch) = item else {
        panic!("the samples of a lent datagram are a batch");
    };
    let seen: Vec<_> = batch
        .samples()
        .map(|sample| {
            (
                sample.keyexpr().to_owned(),
                sample.keyexpr().as_ptr(),
                sample.payload().as_ptr(),
            )
        })
        .collect();
    drop(head);
    assert_eq!(
        seen,
        [(
            "demo/k".to_owned(),
            datagram.as_ptr(),
            datagram[6..].as_ptr()
        )]
    );
}

/// A sample of a lent datagram with every part, each lying in the datagram, is handed from its
/// batch with every part as it was offered, read where it lies.
#[test]
fn a_lent_sample_with_every_part_is_handed_from_its_batch_as_it_was_offered() {
    use crate::lane::SharedLane;

    // A sample whose payload, attachment, timestamp id and encoding schema lie in `datagram`.
    struct Every<'a> {
        datagram: &'a [u8],
        source: SourceInfo,
    }

    impl SampleView for Every<'_> {
        fn keyexpr(&self) -> &str {
            "demo/every"
        }

        fn payload(&self) -> &[u8] {
            &self.datagram[..4]
        }

        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }

        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }

        fn qos(&self) -> Option<QosLevel> {
            Some(QosLevel::from_raw(5))
        }

        fn attachment(&self) -> Option<&[u8]> {
            Some(&self.datagram[4..6])
        }

        fn source_info(&self) -> Option<&SourceInfo> {
            Some(&self.source)
        }

        fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
            Some((42, &self.datagram[6..8]))
        }

        fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
            Some((7, Some(&self.datagram[8..10])))
        }
    }

    let lane = lane(1024, 4);
    let lane = SharedLane::new(lane);
    let datagram = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let source = SourceInfo::new(&[9, 9], 3, 4);
    let every = Every {
        datagram: &datagram,
        source: source.clone(),
    };
    // SAFETY (every hold and the lending here): this thread is the lane's one writer, and the
    // datagram outlives every use below.
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.held() }.offer_sample(1, &every);
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert_eq!((lane.handed_on(), lane.lent_count()), (1, 1));
    let delivery = lane.deliver().expect("one delivery");
    let (item, head) = delivery.take().expect("the batch was handed on");
    let LaneItem::Batch(batch) = item else {
        panic!("the samples of a lent datagram are a batch");
    };
    let mut samples = batch.samples();
    let view = samples.next().expect("its one sample");
    assert_eq!(view.keyexpr(), "demo/every");
    assert_eq!(
        view.payload().as_ptr(),
        datagram.as_ptr(),
        "read where it lies"
    );
    assert_eq!(view.payload(), [1, 2, 3, 4]);
    assert_eq!(view.kind(), SampleKind::Put);
    assert_eq!(view.reliability(), Reliability::Reliable);
    assert_eq!(view.qos(), Some(QosLevel::from_raw(5)));
    assert_eq!(view.attachment(), Some(&[5u8, 6][..]));
    assert_eq!(view.timestamp_parts(), Some((42, &[7u8, 8][..])));
    assert_eq!(view.encoding_parts(), Some((7, Some(&[9u8, 10][..]))));
    assert_eq!(view.source_info(), Some(&source));
    assert_eq!(view.subscribers().collect::<Vec<_>>(), [1]);
    assert!(samples.next().is_none(), "one sample was offered");
    drop(head);
}

/// A sample offered for several subscribers is written once and handed to each of them, in the
/// order it was offered to them: it takes the room of one copy and the ids, and one event slot.
#[test]
fn a_sample_for_several_subscribers_is_written_once_and_handed_to_each() {
    let mut lane = lane(256, 4);
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
    let mut lane = lane(512, 8);
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
    let mut lane = lane(128, 4);
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
    let mut lane = lane_owing(256, 4, 3);
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
    let mut lane = lane(64, 4);
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
    let mut lane = lane_owing(256, 4, 3);
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

    let mut lane = lane(256, 4);
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
    let mut lane = lane(1024, 1);
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
    let mut lane = lane(64, 4);
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

    let mut lane = lane(64, 4);
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

    let mut lane = lane(256, 4);
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

/// A callback the tests count the samples of: each is noted with `tag`, its payload's first
/// byte and where its payload lies.
fn noting(
    tag: u8,
    seen: &std::sync::Arc<std::sync::Mutex<Vec<(u8, u8, usize)>>>,
) -> crate::engine::SubscriberCallback {
    let seen = seen.clone();
    alloc::sync::Arc::new(crate::engine::LiveCallback::new(Box::new(
        move |sample: &dyn SampleView| {
            let payload = sample.payload();
            seen.lock().unwrap().push((
                tag,
                payload.first().copied().unwrap_or(0),
                payload.as_ptr() as usize,
            ));
        },
    )))
}

/// The samples of a datagram a link lends, offered while the lane holds nothing, are held in the
/// pending table where they lie: one entry for a sample however many subscribers it reaches, the
/// link held back from the next datagram until they are handed out, and each handed to its
/// callbacks in the order it came, from the row's callback it carries. Nothing goes through the
/// lane.
#[test]
fn the_pending_samples_of_a_lent_datagram_are_handed_where_they_lie() {
    use crate::lane::{LaneGate, SharedLane};
    use wz_runtime_coop::session_drive::SessionDatagramLink;

    let lane = alloc::sync::Arc::new(SharedLane::new(lane(1024, 4)));
    // SAFETY (every call on the lane, the gate and the lending here): this thread is the lane's one
    // writer, as a session's step is under its lock, and the datagram outlives every use below.
    let gate = unsafe { LaneGate::new(Quiet, lane.clone(), room(32)) };
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (first, second) = (noting(1, &seen), noting(2, &seen));
    let datagram = [1u8, 1, 2, 2];
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.offer_to(1, Some(&first), &borrowed(&datagram[..2])) };
    unsafe { lane.offer_to(2, Some(&second), &borrowed(&datagram[..2])) };
    unsafe { lane.offer_to(1, Some(&first), &borrowed(&datagram[2..])) };
    assert!(
        gate.takes_input(),
        "the table takes the datagram's next record"
    );
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert!(
        lane.lends_a_datagram(),
        "sealed, the table holds the link back"
    );
    assert!(!gate.takes_input(), "and no further record is read");
    assert_eq!(lane.handed_on(), 0, "nothing went through the lane");
    assert!(lane.deliver_pending(|_, callback, sample| callback.hand(sample)));
    let at = datagram.as_ptr() as usize;
    assert_eq!(
        *seen.lock().unwrap(),
        [(1, 1, at), (2, 1, at), (1, 2, at + 2)],
        "each sample handed where it lies, to each of its subscribers, in the order they came"
    );
    assert!(
        !lane.lends_a_datagram(),
        "handed out, the link is read again"
    );
    assert_eq!(lane.pending_counts(), (1, 2), "one round of two samples");
    assert!(
        !lane.deliver_pending(|_, _, _| panic!("the table was emptied")),
        "nothing is left to hand"
    );
}

/// A sample of a lent datagram offered while the lane holds a record not handed out yet goes
/// into the lane after it, and the pending table takes nothing: what came first is handed out
/// first. The CONTROL is the previous test, where the lane holds nothing.
#[test]
fn a_sample_behind_what_the_lane_holds_goes_through_the_lane() {
    use crate::lane::SharedLane;

    let lane = alloc::sync::Arc::new(SharedLane::new(lane(1024, 4)));
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let first = noting(1, &seen);
    // SAFETY (every call on the lane and the lending here): as the previous test's.
    unsafe { lane.held() }.offer_sample(9, &filled(4, 9));
    let datagram = [1u8, 1];
    unsafe { lane.set_lending(Some(&datagram[..])) };
    unsafe { lane.offer_to(1, Some(&first), &borrowed(&datagram[..])) };
    unsafe { lane.set_lending(None) };
    unsafe { lane.held() }.seal_all();
    assert!(
        !lane.deliver_pending(|_, _, _| panic!("the table took a sample behind the lane's")),
        "the pending table holds nothing"
    );
    assert_eq!(
        lane.handed_on(),
        2,
        "both went through the lane, in the order they came"
    );
}
