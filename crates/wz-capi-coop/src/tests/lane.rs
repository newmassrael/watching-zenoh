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

use crate::lane::{LaneCounts, MatchFlips, SampleLane};

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
        let (id, view) = lane.take_front().expect("the sample is at the head");
        assert_eq!(id, 7);
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
        let (_, view) = lane.take_front().expect("the sample is at the head");
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
    lane.offer(1, &best_effort(8));
    lane.offer(2, &best_effort(8));
    let (first, _) = lane.take_front().expect("the first sample");
    assert_eq!(first, 1);
    assert!(lane.take_front().is_none(), "the head is held");
    lane.complete();
    let (second, _view) = lane.take_front().expect("the second sample");
    assert_eq!(second, 2);
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
    let (_, view) = lane.take_front().expect("the first sample is kept");
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
    assert!(lane.takes_a_batch(128));
    assert!(lane.takes_a_batch(512), "an empty lane takes any batch");
    lane.offer(1, &best_effort(200));
    assert!(!lane.takes_a_batch(128), "the lane has no room for a batch");
    assert!(!lane.takes_a_batch(512), "nor for one longer than its area");
    assert!(lane.take_front().is_some(), "the sample is at the head");
    lane.complete();
    assert!(lane.takes_a_batch(128), "the delivery gave the room back");
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
