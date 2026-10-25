// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A subscription whose callback runs OFF the receive path (`docs/rx-delivery-lane.md`, phase 3a).
//!
//! # What it is
//!
//! A [`declare_subscriber`](super::Session::declare_subscriber) callback runs on the drive loop. A
//! callback that is slow therefore holds up keepalive, lease and every other subscription of the
//! session. [`Session::declare_subscriber_offloaded`] takes the callback off the loop: the sink the
//! registry fires COPIES the sample into a bounded lane and returns, and a task of its own runs the
//! callbacks, in order, with no lock of the session held.
//!
//! # The copy is the point
//!
//! A received sample is a view over the link's receive buffer, and a reference that outlives the
//! call holds one of the link's receive slots. A slow callback holding those would hold the link's
//! receive pool, which is what taking it off the loop is for. So the sink copies the key, the
//! payload, the attachment and the encoding schema into the lane's byte area and keeps the small
//! fixed metadata beside it, and the receive buffer is free the moment the sink returns. The
//! consumer copies a sample out under the lane's own lock into a buffer it owns before it calls the
//! callback, because the callback must not run with that lock held (it may publish to a key its own
//! subscription matches, which comes back to this sink).
//!
//! # What this seam can and cannot say
//!
//! * The registry's sink returns nothing, so a refused sample is COUNTED here and not answered up the
//!   receive path: [`OffloadStats::dropped_reliable`] counts the samples that were sent reliably and
//!   lost to a full lane, which a deployment reads as an overload, and
//!   [`OffloadStats::dropped_best_effort`] the ones that asked for nothing more. Which counter a
//!   sample goes to is [`Overload::of`](wz_session_core::delivery_lane::Overload::of), the one
//!   function every host asks.
//! * The registry fires each matching sink separately, so the lane admits a sample once for each
//!   offloaded subscription it reaches and publishes it with one callback: the callback budget
//!   never binds before the event bound. This host holds ONE LANE PER OFFLOADED SUBSCRIPTION, so
//!   each has its own bounds and its own order; a lane for the whole session is a change to the
//!   session's state that this one does not need.
//! * Only `reject` is built: a full lane refuses. A lane that makes the receive path wait waits in
//!   the drain step, outside the observer lock, and is the next part of the design.

use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use wz_session_core::caps;
use wz_session_core::delivery_lane::{DeliveryLane, Next, Overload, Stats};
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{EncodingHint, QosLevel, SourceInfo, TimestampHint};
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::SampleView;

use super::*;
use crate::sync::PlainMutex;

/// How many samples a lane holds: the limit `DELIVERY_LANE_EVENTS`.
const EVENTS: usize = caps::DELIVERY_LANE_EVENTS;

/// What a lane keeps of a sample besides its bytes: the lengths that cut the bytes back into their
/// four parts, and the fields of the view that are not bytes.
struct Meta {
    key: usize,
    payload: usize,
    attachment: Option<usize>,
    schema: Option<usize>,
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    timestamp: Option<TimestampHint>,
    encoding_id: Option<u32>,
    source_info: Option<SourceInfo>,
}

struct State {
    lane: DeliveryLane<EVENTS>,
    /// The bytes of the waiting samples, the lane's ring.
    area: Vec<u8>,
    /// The record of each waiting sample, at the event slot the lane gave it.
    meta: Vec<Option<Meta>>,
    dropped_best_effort: usize,
    dropped_reliable: usize,
}

/// The lane of one offloaded subscription and what wakes its consumer.
pub struct OffloadLane {
    state: PlainMutex<State>,
    wake: Notify,
}

/// A snapshot of an offloaded subscription's lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadStats {
    /// What waits, against what bound, and what was refused by reason.
    pub lane: Stats,
    /// Samples sent best-effort that a full lane refused: lost, as that reliability allows.
    pub dropped_best_effort: usize,
    /// Samples sent RELIABLY that a full lane refused: lost although the sender asked for more, so
    /// an overload a deployment wants to see.
    pub dropped_reliable: usize,
}

impl OffloadLane {
    fn new() -> Self {
        Self {
            state: PlainMutex::new(State {
                lane: DeliveryLane::new(caps::DELIVERY_LANE_BYTES, caps::DELIVERY_LANE_CALLBACKS),
                area: vec![0; caps::DELIVERY_LANE_BYTES],
                meta: (0..EVENTS).map(|_| None).collect(),
                dropped_best_effort: 0,
                dropped_reliable: 0,
            }),
            wake: Notify::new(),
        }
    }

    /// Copy `view` in and wake the consumer, or count why it was refused. Runs on the drive loop,
    /// under the observer lock, so it takes the lane's lock for the length of one copy and nothing
    /// else.
    fn admit(&self, view: &dyn SampleView) {
        let key = view.keyexpr().as_bytes();
        let payload = view.payload();
        let attachment = view.attachment();
        let encoding = view.encoding();
        let schema = encoding
            .and_then(|hint| hint.schema.as_deref())
            .map(str::as_bytes);
        let total = key.len()
            + payload.len()
            + attachment.map_or(0, <[u8]>::len)
            + schema.map_or(0, <[u8]>::len);
        let admitted = self.state.with(|state| {
            let reservation = match state.lane.reserve(total) {
                Ok(reservation) => reservation,
                Err(_) => return Err(()),
            };
            let (index, mut at) = (reservation.index(), reservation.offset());
            for part in [Some(key), Some(payload), attachment, schema]
                .into_iter()
                .flatten()
            {
                state.area[at..at + part.len()].copy_from_slice(part);
                at += part.len();
            }
            state.meta[index] = Some(Meta {
                key: key.len(),
                payload: payload.len(),
                attachment: attachment.map(<[u8]>::len),
                schema: schema.map(<[u8]>::len),
                kind: view.kind(),
                reliability: view.reliability(),
                qos: view.qos(),
                timestamp: view.timestamp().cloned(),
                encoding_id: encoding.map(|hint| hint.packed_id),
                source_info: view.source_info().cloned(),
            });
            // One callback: this sink is one subscription's. A refusal here can only be the
            // callback budget, which is larger than the event bound on this host.
            if state.lane.publish(reservation, 1).is_err() {
                state.meta[index] = None;
                return Err(());
            }
            Ok(())
        });
        match admitted {
            Ok(()) => self.wake.notify_one(),
            Err(()) => self.state.with(|state| {
                match Overload::of(view.reliability()) {
                    Overload::Drop => state.dropped_best_effort += 1,
                    Overload::LocalResourceLimit => state.dropped_reliable += 1,
                };
            }),
        }
    }

    /// The sample at the head of the lane, copied out into `scratch` and its record: `None` when no
    /// published sample is at the head.
    fn take_head(&self, scratch: &mut Vec<u8>) -> Option<Meta> {
        self.state.with(|state| {
            let Next::Ready(head) = state.lane.front() else {
                return None;
            };
            scratch.clear();
            scratch.extend_from_slice(&state.area[head.offset..head.offset + head.bytes]);
            state.meta[head.index].take()
        })
    }

    /// The callback for the head sample has run: its charges come back.
    fn complete(&self) {
        self.state.with(|state| {
            let _ = state.lane.complete();
        });
    }

    fn stop(&self) {
        self.state.with(|state| state.lane.stop());
        self.wake.notify_one();
    }

    fn is_stopped(&self) -> bool {
        self.state.with(|state| state.lane.is_stopped())
    }

    /// A snapshot of the lane.
    pub fn stats(&self) -> OffloadStats {
        self.state.with(|state| OffloadStats {
            lane: state.lane.stats(),
            dropped_best_effort: state.dropped_best_effort,
            dropped_reliable: state.dropped_reliable,
        })
    }
}

/// The view a callback is handed: the copy the lane held, cut back into its parts.
struct LaneSample<'a> {
    key: &'a str,
    payload: &'a [u8],
    attachment: Option<&'a [u8]>,
    meta: &'a Meta,
    encoding: Option<EncodingHint>,
}

impl<'a> LaneSample<'a> {
    fn of(bytes: &'a [u8], meta: &'a Meta) -> Self {
        let (key, rest) = bytes.split_at(meta.key);
        let (payload, rest) = rest.split_at(meta.payload);
        let (attachment, rest) = match meta.attachment {
            Some(len) => {
                let (attachment, rest) = rest.split_at(len);
                (Some(attachment), rest)
            }
            None => (None, rest),
        };
        let schema = meta
            .schema
            .map(|len| String::from_utf8_lossy(&rest[..len]).into_owned());
        Self {
            // The bytes were a `&str` when they went in, so they are text.
            key: std::str::from_utf8(key).unwrap_or(""),
            payload,
            attachment,
            meta,
            encoding: meta
                .encoding_id
                .map(|packed_id| EncodingHint { packed_id, schema }),
        }
    }
}

impl SampleView for LaneSample<'_> {
    fn keyexpr(&self) -> &str {
        self.key
    }
    fn payload(&self) -> &[u8] {
        self.payload
    }
    fn kind(&self) -> SampleKind {
        self.meta.kind
    }
    fn reliability(&self) -> Reliability {
        self.meta.reliability
    }
    fn qos(&self) -> Option<QosLevel> {
        self.meta.qos
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    fn timestamp(&self) -> Option<&TimestampHint> {
        self.meta.timestamp.as_ref()
    }
    fn encoding(&self) -> Option<&EncodingHint> {
        self.encoding.as_ref()
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.meta.source_info.as_ref()
    }
    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        self.meta
            .timestamp
            .as_ref()
            .map(|hint| (hint.time, hint.zid.as_slice()))
    }
    fn encoding_parts(&self) -> Option<(u32, Option<&str>)> {
        self.encoding
            .as_ref()
            .map(|hint| (hint.packed_id, hint.schema.as_deref()))
    }
}

enum Slot<F> {
    At(F),
    /// The callback is running on the consumer: taken out so that it runs with the cell unlocked.
    Out,
    Dead,
}

/// The callback of one offloaded subscription, taken out to run and put back after, so that it may
/// undeclare its own subscription: the undeclare marks the slot dead and the put-back drops the
/// callback instead of bringing it back.
struct CallbackCell<F>(Mutex<Slot<F>>);

impl<F: FnMut(&dyn SampleView)> CallbackCell<F> {
    fn new(callback: F) -> Self {
        Self(Mutex::new(Slot::At(callback)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Slot<F>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn kill(&self) {
        *self.lock() = Slot::Dead;
    }

    fn call(&self, view: &dyn SampleView) {
        // One guard for the whole take: a guard taken in the scrutinee lives to the end of the
        // `match`, and a second lock inside an arm would wait for it for ever.
        let taken = {
            let mut slot = self.lock();
            match std::mem::replace(&mut *slot, Slot::Out) {
                Slot::At(callback) => Some(callback),
                Slot::Out => None,
                Slot::Dead => {
                    *slot = Slot::Dead;
                    return;
                }
            }
        };
        let Some(mut callback) = taken else {
            return;
        };
        callback(view);
        let mut slot = self.lock();
        if !matches!(*slot, Slot::Dead) {
            *slot = Slot::At(callback);
        }
    }
}

/// Stops the lane when the consumer ends, however it ends: a callback that panics ends the task, and
/// a lane nobody empties would fill and refuse without saying why.
struct StopOnDrop(Arc<OffloadLane>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

async fn consume<F: FnMut(&dyn SampleView) + Send + 'static>(
    lane: Arc<OffloadLane>,
    cell: Arc<CallbackCell<F>>,
) {
    let _stop = StopOnDrop(lane.clone());
    let mut scratch: Vec<u8> = Vec::new();
    loop {
        while let Some(meta) = lane.take_head(&mut scratch) {
            let sample = LaneSample::of(&scratch, &meta);
            cell.call(&sample);
            lane.complete();
        }
        if lane.is_stopped() {
            return;
        }
        lane.wake.notified().await;
    }
}

/// Why [`Session::declare_subscriber_offloaded`] declared nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffloadError {
    /// The subscription could not be declared; the reason is the plain subscriber's.
    Subscribe(SubscribeError),
    /// There is no tokio runtime to run the consumer on: the call is made off a runtime.
    NoRuntime,
}

/// A subscription whose callback runs on a task of its own, over a bounded lane.
///
/// Dropping it undeclares the subscription and ends the task: the callback does not run for a
/// sample that was waiting at that moment, as it does not for a sample after an undeclare.
pub struct OffloadedSubscriber<R: SessionRuntime = TokioRuntime> {
    subscriber: Option<Subscriber<R>>,
    lane: Arc<OffloadLane>,
    on_drop: Box<dyn Fn() + Send + Sync>,
}

impl<R: SessionRuntime> OffloadedSubscriber<R> {
    /// The subscription this callback is behind.
    pub fn subscriber(&self) -> &Subscriber<R> {
        self.subscriber.as_ref().expect("held until dropped")
    }

    /// A snapshot of the lane: what waits, what was refused and why.
    pub fn stats(&self) -> OffloadStats {
        self.lane.stats()
    }
}

impl<R: SessionRuntime> Drop for OffloadedSubscriber<R> {
    fn drop(&mut self) {
        // The subscription first, so that nothing fires into a lane that is being stopped and is
        // counted as refused for it.
        drop(self.subscriber.take());
        (self.on_drop)();
        self.lane.stop();
    }
}

impl<R: SessionRuntime, T: TimeSource> Session<R, T, Unicast> {
    /// Declare a subscriber whose callback runs OFF the drive loop (`docs/rx-delivery-lane.md`).
    ///
    /// Each matching sample is copied into a lane of at most `DELIVERY_LANE_EVENTS` samples and
    /// `DELIVERY_LANE_BYTES` bytes, and the callback runs on a task of its own, in order, with no
    /// lock of the session held, so it may declare, undeclare, publish or query. A sample the lane
    /// has no room for is refused, counted by reason in [`OffloadedSubscriber::stats`], and not
    /// delivered: this subscription loses samples under overload, which an inline subscriber does
    /// not (it stalls the loop instead).
    ///
    /// Call it on a tokio runtime: the consumer is a task.
    pub fn declare_subscriber_offloaded(
        &self,
        keyexpr: impl Into<String>,
        options: SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<OffloadedSubscriber<R>, OffloadError>
    where
        wz_session_core::session_actions::SessionLinkActions<R, T>: Send + Sync,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        T: 'static,
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| OffloadError::NoRuntime)?;
        let lane = Arc::new(OffloadLane::new());
        let cell = Arc::new(CallbackCell::new(callback));
        let sink_lane = lane.clone();
        let subscriber = self
            .declare_subscriber(keyexpr, options, move |view| sink_lane.admit(view))
            .map_err(OffloadError::Subscribe)?;
        runtime.spawn(consume(lane.clone(), cell.clone()));
        Ok(OffloadedSubscriber {
            subscriber: Some(subscriber),
            lane,
            on_drop: Box::new(move || cell.kill()),
        })
    }
}
