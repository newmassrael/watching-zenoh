// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's delivery lane for its subscribers: what the session hands their callbacks,
//! queued under the session's lock as bytes in a ring of the session's arena and handed out after
//! the lock is released (decision D8), so no sample is built on the heap between its arrival and its
//! callback (`docs/c-abi-no-heap-pools.md`, section 4.10).
//!
//! # The ring
//!
//! The bookkeeping is the session core's [`DeliveryLane`]: event slots under
//! `DELIVERY_LANE_EVENTS`, a byte area of `DELIVERY_LANE_BYTES`, a callback budget of
//! `DELIVERY_LANE_CALLBACKS`, all read from the limits the session opened under. The byte area is a
//! span of the session's arena; a sample's key, payload, attachment, encoding schema and timestamp
//! id lie one after the other in it, and what is not bytes (the subscriber, the kind, the
//! reliability, the QoS, the source) is a [`Record`] at the sample's event slot. A callback is
//! handed a view of the sample where it lies ([`LaneSample`]); the slot and its bytes are given
//! back when the callback returns.
//!
//! # A full lane (decision Q4)
//!
//! What a full lane does is what the sample's congestion control says. A sample sent reliably
//! whose congestion control holds its sender (`block`, `block-first`) applies backpressure: the
//! session stops reading the link while the lane cannot take a whole batch ([`LaneGate`]), so the
//! transport's flow control carries the wait back to the sender and the samples wait in the link.
//! Any other sample that finds no room is dropped and counted ([`LaneCounts::dropped`]). The gate
//! is asked before a batch is read, so a batch only overflows the room it found when its samples
//! take more than its own length: a key a peer named by its declaration, resolved longer than it
//! travelled, or a sample many subscribers take. A sample that holds its sender and still finds no
//! room is refused and counted apart ([`LaneCounts::held_over`]), as the session core's lane
//! answers such a sample with a local resource limit (`delivery_lane::Overload`) and not with a
//! silent loss.

use alloc::sync::Arc;
use core::ptr::NonNull;

use wz_capi_port::os::Mutex;
use wz_capi_port::SubId;
use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability, SessionDatagramLink};
use wz_session_core::caps;
use wz_session_core::delivery_lane::{DeliveryLane, Next};
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{LostCause, RxFrame};
use wz_session_core::qos::CongestionControl;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{QosLevel, SampleKind, SourceInfo};
use wz_session_core::sink::SampleView;

use crate::prelude::*;

/// What a sample is, besides its bytes: kept at its event slot of the lane.
#[derive(Clone)]
struct Record {
    /// The subscriber whose callback the sample goes to.
    subscriber: SubId,
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    /// The bytes of each part, in the order they lie in the area.
    key: usize,
    payload: usize,
    attachment: Option<usize>,
    /// The packed id, and the bytes of the schema when there is one.
    encoding: Option<(u32, Option<usize>)>,
    /// The time word, and the bytes of the id prefix.
    timestamp: Option<(u64, usize)>,
    source_info: Option<SourceInfo>,
}

/// What the lane did not hand a subscriber, by why.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneCounts {
    /// Samples whose congestion control lets them be dropped (sent best effort, or with `drop`)
    /// that found no room.
    pub dropped: u64,
    /// Samples whose congestion control holds their sender that found no room all the same: what
    /// a batch the lane let be read carried past the room it found.
    pub held_over: u64,
}

/// The lane of one session: its bookkeeping, the records at its event slots and the byte area the
/// session's arena lent it.
pub(crate) struct SampleLane {
    lane: DeliveryLane<{ caps::DELIVERY_LANE_EVENTS }>,
    records: [Option<Record>; caps::DELIVERY_LANE_EVENTS],
    area: NonNull<u8>,
    /// A delivery holds the head: another thread that delivers finds nothing until it completes.
    handing: bool,
    counts: LaneCounts,
}

// SAFETY: the area is the session's arena's, lent to this lane alone for the life of the session,
// and reached only through the lock the lane is held behind, or by the one delivery that holds the
// head (`handing`), which reads the bytes of the head alone, which nothing writes until it completes.
unsafe impl Send for SampleLane {}

impl SampleLane {
    /// A lane over the `area_bytes` bytes at `area`, held to `limits`.
    ///
    /// # Safety
    /// `area` points at `area_bytes` bytes valid for reads and writes, used by nothing else, for
    /// as long as the lane is used; `area_bytes` is `limits`' `DELIVERY_LANE_BYTES`.
    pub(crate) unsafe fn over(
        area: NonNull<u8>,
        area_bytes: usize,
        limits: &SessionLimits,
    ) -> Self {
        debug_assert_eq!(area_bytes, limits.delivery_lane_bytes());
        Self {
            lane: DeliveryLane::with_limits(limits),
            records: [const { None }; caps::DELIVERY_LANE_EVENTS],
            area,
            handing: false,
            counts: LaneCounts::default(),
        }
    }

    /// Queue `sample` for the callback of `subscriber`, or count it when the lane has no room
    /// for it.
    pub(crate) fn offer(&mut self, subscriber: SubId, sample: &dyn SampleView) {
        let key = sample.keyexpr().as_bytes();
        let payload = sample.payload();
        let attachment = sample.attachment();
        let encoding = encoding_of(sample);
        let timestamp = timestamp_of(sample);
        let schema = encoding.and_then(|(_, schema)| schema).unwrap_or(&[]);
        let zid = timestamp.map_or(&[][..], |(_, zid)| zid);
        let parts: [&[u8]; 5] = [key, payload, attachment.unwrap_or(&[]), schema, zid];
        let Some(bytes) = parts
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.len()))
        else {
            self.refuse(sample);
            return;
        };
        let Ok(reservation) = self.lane.reserve(bytes) else {
            self.refuse(sample);
            return;
        };
        let mut at = reservation.offset();
        for part in parts {
            // SAFETY: the lane placed the sample's `bytes` contiguously at `reservation.offset()`,
            // inside the area (`DeliveryLane::reserve`), and no other sample's bytes lie there
            // until this one is completed; `part` is the sample's and not the area's.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    part.as_ptr(),
                    self.area.as_ptr().add(at),
                    part.len(),
                )
            };
            at += part.len();
        }
        let index = reservation.index();
        self.records[index] = Some(Record {
            subscriber,
            kind: sample.kind(),
            reliability: sample.reliability(),
            qos: sample.qos(),
            key: key.len(),
            payload: payload.len(),
            attachment: attachment.map(<[u8]>::len),
            encoding: encoding.map(|(id, schema)| (id, schema.map(<[u8]>::len))),
            timestamp: timestamp.map(|(time, zid)| (time, zid.len())),
            source_info: sample.source_info().cloned(),
        });
        if self.lane.publish(reservation, 1).is_err() {
            self.records[index] = None;
            self.refuse(sample);
        }
    }

    /// Count a sample the lane had no room for, by its congestion control.
    fn refuse(&mut self, sample: &dyn SampleView) {
        let count = if holds_sender(sample) {
            &mut self.counts.held_over
        } else {
            &mut self.counts.dropped
        };
        *count = count.saturating_add(1);
    }

    /// Whether the lane can take a whole batch of `batch` bytes now: what a link is read for. A
    /// batch longer than the whole area is read only into an empty lane, so the link is never
    /// stopped for good.
    pub(crate) fn takes_a_batch(&self, batch: usize) -> bool {
        if self.lane.can_ever_fit(batch) {
            self.lane.fits(batch).is_ok()
        } else {
            self.lane.stats().queued_events == 0
        }
    }

    /// The sample at the head of the lane, for its subscriber's callback: held by this delivery
    /// until [`Self::complete`]. `None` when the lane is empty or another delivery holds the
    /// head.
    pub(crate) fn take_front(&mut self) -> Option<(SubId, LaneSample)> {
        if self.handing {
            return None;
        }
        loop {
            let Next::Ready(delivery) = self.lane.front() else {
                return None;
            };
            let Some(record) = self.records[delivery.index].clone() else {
                // A published slot always has its record; one without is passed over.
                self.lane.complete();
                continue;
            };
            self.handing = true;
            // SAFETY: the head's bytes are inside the area (`DeliveryLane::front`).
            let base = unsafe { self.area.as_ptr().add(delivery.offset) };
            return Some((record.subscriber, LaneSample { record, base }));
        }
    }

    /// The callback of the head sample returned: its slot and its bytes come back.
    pub(crate) fn complete(&mut self) {
        if let Next::Ready(delivery) = self.lane.front() {
            self.records[delivery.index] = None;
            self.lane.complete();
        }
        self.handing = false;
    }

    /// What the lane did not hand a subscriber.
    pub(crate) fn counts(&self) -> LaneCounts {
        self.counts
    }
}

/// The encoding `sample` carries, read where it lies or from its hint.
fn encoding_of(sample: &dyn SampleView) -> Option<(u32, Option<&[u8]>)> {
    sample.encoding_parts().or_else(|| {
        sample
            .encoding()
            .map(|hint| (hint.packed_id, hint.schema.as_deref()))
    })
}

/// The timestamp `sample` carries, read where it lies or from its hint.
fn timestamp_of(sample: &dyn SampleView) -> Option<(u64, &[u8])> {
    sample.timestamp_parts().or_else(|| {
        sample
            .timestamp()
            .map(|hint| (hint.time, hint.zid.as_slice()))
    })
}

/// Whether `sample`'s congestion control holds its sender: sent reliably, with `block` or
/// `block-first`. A sample that states no QoS has zenoh's default, `drop`.
fn holds_sender(sample: &dyn SampleView) -> bool {
    sample.reliability() == Reliability::Reliable
        && sample
            .qos()
            .is_some_and(|qos| qos.congestion() != CongestionControl::Drop)
}

/// A sample at the head of the lane, where its bytes lie: what a subscriber's callback is handed.
/// Valid until the delivery that took it completes it.
pub(crate) struct LaneSample {
    record: Record,
    base: *const u8,
}

impl LaneSample {
    /// The `len` bytes `skip` bytes into the sample.
    fn part(&self, skip: usize, len: usize) -> &[u8] {
        // SAFETY: the sample's parts were written one after the other from `base` (`SampleLane::offer`),
        // and the head's bytes are not written again until the delivery that holds it completes it,
        // which is after this view is gone.
        unsafe { core::slice::from_raw_parts(self.base.add(skip), len) }
    }

    fn after_payload(&self) -> usize {
        self.record.key + self.record.payload
    }

    fn after_attachment(&self) -> usize {
        self.after_payload() + self.record.attachment.unwrap_or(0)
    }

    fn after_schema(&self) -> usize {
        self.after_attachment() + self.record.encoding.and_then(|(_, s)| s).unwrap_or(0)
    }
}

impl SampleView for LaneSample {
    fn keyexpr(&self) -> &str {
        // SAFETY: the bytes were a `&str`'s (`SampleView::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.part(0, self.record.key)) }
    }

    fn payload(&self) -> &[u8] {
        self.part(self.record.key, self.record.payload)
    }

    fn kind(&self) -> SampleKind {
        self.record.kind
    }

    fn reliability(&self) -> Reliability {
        self.record.reliability
    }

    fn qos(&self) -> Option<QosLevel> {
        self.record.qos
    }

    fn attachment(&self) -> Option<&[u8]> {
        self.record
            .attachment
            .map(|len| self.part(self.after_payload(), len))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.record.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        self.record
            .timestamp
            .map(|(time, zid)| (time, self.part(self.after_schema(), zid)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.record.encoding.map(|(id, schema)| {
            (
                id,
                schema.map(|len| self.part(self.after_attachment(), len)),
            )
        })
    }
}

/// `pump`, which gives the session nothing while the lane cannot take a whole batch of `batch`
/// bytes (decision Q4): what the peer sends meanwhile waits in the link, and the transport's flow
/// control carries the wait back to it.
pub(crate) struct LaneGate<P> {
    pump: P,
    lane: Arc<Mutex<SampleLane>>,
    batch: usize,
}

impl<P> LaneGate<P> {
    pub(crate) fn new(pump: P, lane: Arc<Mutex<SampleLane>>, batch: usize) -> Self {
        Self { pump, lane, batch }
    }

    /// Whether the link's input is held back: the lane cannot take a batch.
    fn shut(&self) -> bool {
        !self.lane.lock().takes_a_batch(self.batch)
    }
}

impl<P: SessionDatagramLink> SessionDatagramLink for LaneGate<P> {
    fn service(&self) {
        self.pump.service()
    }

    fn service_within(&self, max_wait_ms: u64) {
        self.pump.service_within(max_wait_ms)
    }

    fn uses_wake_budget(&self) -> bool {
        self.pump.uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        if self.shut() {
            return None;
        }
        self.pump.try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.shut() {
            return false;
        }
        self.pump.recv_with(f)
    }

    /// A link that ended is told to the session after what it queued before the end was read, and
    /// what it queued is held back: the end waits with it.
    fn lost(&self) -> Option<LostCause> {
        if self.shut() {
            return None;
        }
        self.pump.lost()
    }

    fn holds_input(&self) -> bool {
        self.pump.holds_input()
    }

    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        self.pump.readiness()
    }

    // The gate holds back input only: what the session sends goes out while the lane is full.
    fn writability(&self) -> Option<Box<dyn LinkWritability>> {
        self.pump.writability()
    }
}
