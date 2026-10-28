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
//! * A full lane does one of two things, and the subscription says which
//!   ([`SubscribeOptions::with_overload`], default the build's `subscriber-overload` policy).
//!   `reject` refuses the sample at the sink: the receive path is never held and the sample is
//!   lost and counted. `block` must not wait at the sink, which runs under the observer lock that
//!   the consumer's callback may be waiting for, so the sink HOLDS a copy outside the lane and
//!   returns, and the drain step the drive loop awaits after the lock is released admits the held
//!   samples in order and waits for room: the transport's own backpressure is the flow control, as
//!   it is for a buffered subscriber, and no sample is lost. A sample longer than the whole lane
//!   would wait for ever, so it is refused under either answer.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use wz_session_core::caps;
use wz_session_core::delivery_lane::{DeliveryLane, Next, Overload, Refusal, Stats};
use wz_session_core::policy::SubscriberOverload;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{EncodingHint, QosLevel, SourceInfo, TimestampHint};
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::SampleView;

use super::buffered::{BufferedDrain, BufferedWork, RegisteredDrain};
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

/// A sample the lane had no room for under `block`: its four parts in one buffer, cut by the lengths
/// in its record, waiting outside the lane for the drain to admit it.
struct Held {
    bytes: Vec<u8>,
    meta: Meta,
}

struct State {
    lane: DeliveryLane<EVENTS>,
    /// The bytes of the waiting samples, the lane's ring.
    area: Vec<u8>,
    /// The record of each waiting sample, at the event slot the lane gave it.
    meta: Vec<Option<Meta>>,
    /// Samples held for room under `block`, oldest first. Bounded by what one dispatch delivers:
    /// while the drain awaits room the loop is not polling, so nothing more arrives.
    held: VecDeque<Held>,
    dropped_best_effort: usize,
    dropped_reliable: usize,
}

/// The lane of one offloaded subscription and what wakes its consumer.
pub struct OffloadLane {
    state: PlainMutex<State>,
    /// Wakes the consumer: a sample is published, or the lane is stopping.
    wake: Notify,
    /// Wakes the drain: the consumer finished a sample, so a held one may now fit.
    room: Notify,
}

/// A snapshot of an offloaded subscription's lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffloadStats {
    /// What waits, against what bound, and what was refused by reason.
    pub lane: Stats,
    /// Samples held outside the lane under `block`, waiting for room: delayed and not lost.
    pub held: usize,
    /// Samples sent best-effort that a full lane refused: lost, as that reliability allows.
    pub dropped_best_effort: usize,
    /// Samples sent RELIABLY that a full lane refused: lost although the sender asked for more, so
    /// an overload a deployment wants to see.
    pub dropped_reliable: usize,
}

/// A view's parts and what is not bytes, taken once, so the direct path and the held one write the
/// same thing.
struct Captured<'a> {
    slices: [Option<&'a [u8]>; 4],
    total: usize,
    meta: Meta,
}

impl<'a> Captured<'a> {
    fn of(view: &'a dyn SampleView) -> Self {
        let key = view.keyexpr().as_bytes();
        let payload = view.payload();
        let attachment = view.attachment();
        let encoding = view.encoding();
        let schema = encoding
            .and_then(|hint| hint.schema.as_deref())
            .map(str::as_bytes);
        let slices = [Some(key), Some(payload), attachment, schema];
        Self {
            total: slices.iter().flatten().map(|part| part.len()).sum(),
            meta: Meta {
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
            },
            slices,
        }
    }

    /// The sample in one buffer, to hold it outside the lane.
    fn held(self) -> Held {
        let mut bytes = Vec::with_capacity(self.total);
        for part in self.slices.into_iter().flatten() {
            bytes.extend_from_slice(part);
        }
        Held {
            bytes,
            meta: self.meta,
        }
    }
}

/// What the sink did with a sample.
enum Admission {
    Admitted,
    Held,
    Refused,
}

impl State {
    /// Write a sample into the lane, or say it was refused. The parts are cut by `meta`.
    fn write(
        &mut self,
        parts: [Option<&[u8]>; 4],
        total: usize,
        meta: Meta,
    ) -> Result<(), Refusal> {
        let reservation = self.lane.reserve(total)?;
        let (index, mut at) = (reservation.index(), reservation.offset());
        for part in parts.into_iter().flatten() {
            self.area[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        self.meta[index] = Some(meta);
        // One callback: this sink is one subscription's. A refusal here can only be the callback
        // budget, which is larger than the event bound on this host.
        if let Err(why) = self.lane.publish(reservation, 1) {
            self.meta[index] = None;
            return Err(why);
        }
        Ok(())
    }

    /// Write a held sample, which `fits` said the lane has room for.
    fn write_held(&mut self, held: Held) -> Result<(), Refusal> {
        let Held { bytes, meta } = held;
        let total = bytes.len();
        let rest = bytes.as_slice();
        let (key, rest) = rest.split_at(meta.key);
        let (payload, rest) = rest.split_at(meta.payload);
        let (attachment, rest) = match meta.attachment {
            Some(len) => {
                let (attachment, rest) = rest.split_at(len);
                (Some(attachment), rest)
            }
            None => (None, rest),
        };
        let schema = meta.schema.map(|len| &rest[..len]);
        self.write([Some(key), Some(payload), attachment, schema], total, meta)
    }

    /// Make room for a sample of `bytes` bytes by taking out the newest samples already queued,
    /// as `keep-latest` does where `block` waits and `reject` refuses. Each one taken is lost to
    /// the lane and counted by how it was sent, as a refusal is. It stops when the sample fits, or
    /// when what is left is the head, which the consumer may be running. A sample that could never
    /// fit takes nothing out: it is refused whatever the lane holds.
    fn make_room(&mut self, bytes: usize) {
        if !self.lane.can_ever_fit(bytes) {
            return;
        }
        while matches!(
            self.lane.fits(bytes),
            Err(Refusal::EventsFull | Refusal::BytesFull)
        ) {
            let Some(index) = self.lane.evict_latest() else {
                return;
            };
            if let Some(taken) = self.meta[index].take() {
                self.lose(taken.reliability);
            }
        }
    }

    /// A sample was lost to the lane: count it by how it was sent.
    fn lose(&mut self, reliability: Reliability) {
        match Overload::of(reliability) {
            Overload::Drop => self.dropped_best_effort += 1,
            Overload::LocalResourceLimit => self.dropped_reliable += 1,
        }
    }
}

impl OffloadLane {
    fn new() -> Self {
        Self {
            state: PlainMutex::new(State {
                lane: DeliveryLane::new(caps::DELIVERY_LANE_BYTES, caps::DELIVERY_LANE_CALLBACKS),
                area: vec![0; caps::DELIVERY_LANE_BYTES],
                meta: (0..EVENTS).map(|_| None).collect(),
                held: VecDeque::new(),
                dropped_best_effort: 0,
                dropped_reliable: 0,
            }),
            wake: Notify::new(),
            room: Notify::new(),
        }
    }

    /// Copy `view` in and wake the consumer, or count why it was refused. Runs on the drive loop,
    /// under the observer lock, so it takes the lane's lock for the length of one copy and nothing
    /// else.
    fn admit(&self, view: &dyn SampleView, overload: SubscriberOverload) {
        let captured = Captured::of(view);
        let reliability = captured.meta.reliability;
        let admission = self.state.with(|state| {
            // Under `block`, a sample the lane has no room for waits outside it, and so does every
            // sample behind it, so that nothing overtakes it. One that could never fit, however
            // empty the lane, is refused: waiting for it would never end.
            if overload == SubscriberOverload::Block && state.lane.can_ever_fit(captured.total) {
                let no_room = matches!(
                    state.lane.fits(captured.total),
                    Err(Refusal::EventsFull | Refusal::BytesFull)
                );
                if no_room || !state.held.is_empty() {
                    state.held.push_back(captured.held());
                    return Admission::Held;
                }
            }
            if overload == SubscriberOverload::KeepLatest {
                state.make_room(captured.total);
            }
            // `write` reserves, and a reservation that is refused counts the reason.
            match state.write(captured.slices, captured.total, captured.meta) {
                Ok(()) => Admission::Admitted,
                Err(_) => {
                    state.lose(reliability);
                    Admission::Refused
                }
            }
        });
        match admission {
            Admission::Admitted => self.wake.notify_one(),
            // The drain, which the loop awaits once it has released the observer lock, admits it.
            Admission::Held | Admission::Refused => {}
        }
    }

    /// Admit the held samples that now fit, in order, and wait for room for the one that does not.
    /// Returns when nothing is held, or the lane is stopping (what is held is then lost with it).
    ///
    /// Awaited by the drive loop after it has released the observer lock, so the wait holds up the
    /// loop and nothing else: the backpressure `block` is. It awaits only the room notification, and
    /// moves a sample in one step under the lane's lock, so a drain cancelled while it waits has
    /// taken nothing.
    async fn drain_held(&self) {
        loop {
            let (empty, stopping, admitted) = self.state.with(|state| {
                let mut admitted = false;
                while let Some(front) = state.held.front() {
                    if state.lane.fits(front.bytes.len()).is_err() {
                        break;
                    }
                    let held = state.held.pop_front().expect("front was there");
                    let reliability = held.meta.reliability;
                    match state.write_held(held) {
                        Ok(()) => admitted = true,
                        Err(_) => state.lose(reliability),
                    }
                }
                (state.held.is_empty(), state.lane.is_stopping(), admitted)
            });
            if admitted {
                self.wake.notify_one();
            }
            if empty {
                return;
            }
            if stopping {
                self.state.with(|state| {
                    while let Some(held) = state.held.pop_front() {
                        state.lose(held.meta.reliability);
                    }
                });
                return;
            }
            self.room.notified().await;
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
        // A sample that was held for room may fit now.
        self.room.notify_one();
    }

    fn stop(&self) {
        self.state.with(|state| state.lane.stop());
        self.wake.notify_one();
        self.room.notify_one();
    }

    fn is_stopped(&self) -> bool {
        self.state.with(|state| state.lane.is_stopped())
    }

    /// A snapshot of the lane.
    pub fn stats(&self) -> OffloadStats {
        self.state.with(|state| OffloadStats {
            lane: state.lane.stats(),
            held: state.held.len(),
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

impl BufferedDrain for OffloadLane {
    fn drain(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.drain_held())
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
    /// lock of the session held, so it may declare, undeclare, publish or query.
    ///
    /// What a full lane does is `options`' [`SubscribeOptions::overload`]: under `reject` the sample
    /// is refused, counted by reason in [`OffloadedSubscriber::stats`] and lost, and the receive
    /// path is never held; under `block` the sample waits outside the lane and the drive loop waits
    /// for room, so nothing is lost and a slow callback slows the session instead. The drive loop
    /// awaits that wait on its own (`drive_session_until_terminal*` drain this session's buffered
    /// work every iteration); an embedder driving a loop of its own awaits
    /// [`Session::drain_buffered`].
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
        <R as SessionRuntime>::IterationWork: BufferedWork,
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| OffloadError::NoRuntime)?;
        let lane = Arc::new(OffloadLane::new());
        let cell = Arc::new(CallbackCell::new(callback));
        let overload = options.overload();
        let sink_lane = lane.clone();
        let subscriber = self
            .declare_subscriber(keyexpr, options, move |view| {
                sink_lane.admit(view, overload)
            })
            .map_err(OffloadError::Subscribe)?;
        // Registered on the kernel, as a buffered subscription is, so the loop finds it unasked.
        // The registry holds it weakly: the lane the handle keeps is what keeps it alive.
        let drain: Arc<dyn BufferedDrain> = lane.clone();
        self.transport
            .core
            .iteration_work
            .register(&RegisteredDrain::of(drain));
        runtime.spawn(consume(lane.clone(), cell.clone()));
        Ok(OffloadedSubscriber {
            subscriber: Some(subscriber),
            lane,
            on_drop: Box::new(move || cell.kill()),
        })
    }
}
