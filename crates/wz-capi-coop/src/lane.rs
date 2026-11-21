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
//! id lie one after the other in it, followed by the ids of the subscribers it is for, and what is
//! not bytes (the kind, the reliability, the QoS, the source) is a [`Record`] at the sample's event
//! slot. A sample is written once for all the subscribers it reaches: the session hands it to each
//! subscriber in turn, and the lane holds the sample it wrote last open until something else
//! reaches it, so the same sample offered for another subscriber adds only that subscriber's id.
//! Each callback is handed a view of the sample where it lies ([`LaneSample`]); the slot and its
//! bytes are given back when the last of them returns.
//!
//! A liveliness subscriber's samples, a token appearing or retracted, take the same lane in the
//! order they happen among the subscribers' samples: the token's key is the slot's bytes, and its
//! kind and id are the event at the slot.
//!
//! # A full lane (decision Q4)
//!
//! What a full lane does is what the sample's congestion control says. A sample sent reliably
//! whose congestion control holds its sender (`block`, `block-first`) applies backpressure: the
//! session is handed no record of a link while the lane has not the room one record can take
//! ([`ReadRoom`], [`LaneGate`]), so the transport's flow control carries the wait back to the
//! sender and the samples wait in the link. The room is the larger of a batch and a rejoined
//! message, with the most a sample adds to the record it came in: its key resolved from an alias,
//! its timestamp's clock id and the ids of its subscribers; and an event slot, and a callback for
//! each subscriber. A link keeps the datagram a session stopped in and lends it again, so the
//! gate is asked before each record and not only before each datagram. Any other sample that
//! finds no room is dropped and counted ([`LaneCounts::dropped`]). A sample that holds its sender
//! and still finds no room is refused and counted apart ([`LaneCounts::held_over`]), as the
//! session core's lane answers such a sample with a local resource limit
//! (`delivery_lane::Overload`) and not with a silent loss: a defect for a record the gate let
//! through, which a debug build stops at, and for the session's own puts, which wait for no room,
//! a count.

use alloc::sync::Arc;
use core::ptr::NonNull;

use wz_capi_port::os::Mutex;
use wz_capi_port::{MatchId, SubId};
use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability, SessionDatagramLink};
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps;
#[cfg(feature = "liveliness")]
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::delivery_lane::{DeliveryLane, Next, Reservation};
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{LostCause, RxFrame};
use wz_session_core::qos::CongestionControl;
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{QosLevel, SampleKind, SourceInfo};
use wz_session_core::sink::SampleView;

use crate::prelude::*;

/// The longest id of the clock that stamped a sample's timestamp the wire carries.
const TIMESTAMP_ID_BYTES: usize = 16;

/// The bytes of a subscriber's id in the list that follows a sample's parts.
const SUBSCRIBER_ID_BYTES: usize = core::mem::size_of::<SubId>();

/// The most bytes one sample takes in the lane beyond the message it arrived in, for a session
/// whose longest key is `key_bytes` and that holds `subscribers` subscribers at most: its key as
/// the session resolved it, which a peer may have named by an alias of a few bytes, the id of its
/// timestamp's clock, and the id of each subscriber it is for. Its payload, its attachment and its
/// encoding's schema are bytes of the message.
pub(crate) const fn sample_overhead(key_bytes: usize, subscribers: usize) -> usize {
    key_bytes
        .saturating_add(TIMESTAMP_ID_BYTES)
        .saturating_add(subscribers.saturating_mul(SUBSCRIBER_ID_BYTES))
}

/// The most subscribers one record of a session hands the lane for: a sample's, of the
/// `subscribers` it holds, or a token's, of the `liveliness` subscribers it holds (none in a build
/// without liveliness), whichever is more.
const fn most_subscribers(subscribers: usize, liveliness: usize) -> usize {
    let liveliness = if cfg!(feature = "liveliness") {
        liveliness
    } else {
        0
    };
    if liveliness > subscribers {
        liveliness
    } else {
        subscribers
    }
}

/// The most bytes one record a session is handed can put in its lane, for a session whose batch
/// is `batch` bytes, whose largest rejoined message is `frag` bytes, whose longest key is `key`
/// bytes and whose records reach `subscribers` subscribers at most: a record is no longer than a
/// batch or a rejoined message, and its sample adds to it at most [`sample_overhead`].
pub(crate) const fn read_bytes(batch: usize, frag: usize, key: usize, subscribers: usize) -> usize {
    let message = if batch > frag { batch } else { frag };
    message.saturating_add(sample_overhead(key, subscribers))
}

/// What one record a session is handed can take of its lane at most: the room the lane is asked
/// for before each record ([`LaneGate`]), so that what a record hands it always finds room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadRoom {
    /// Its bytes ([`read_bytes`]); and an event slot, which every record takes one of at most.
    pub(crate) bytes: usize,
    /// The callbacks it owes: one for each subscriber it reaches.
    pub(crate) callbacks: usize,
}

/// Whether a lane of `LANE` bytes holds what one record can hand it in a build whose batch is
/// `BATCH` bytes, whose largest rejoined message is `FRAG` bytes, whose longest key is `KEY`
/// bytes and that holds `SUBS` subscribers and `LIVE` liveliness subscribers.
pub(crate) const fn holds_a_read<
    const LANE: usize,
    const BATCH: usize,
    const FRAG: usize,
    const KEY: usize,
    const SUBS: usize,
    const LIVE: usize,
>() -> bool {
    read_bytes(BATCH, FRAG, KEY, most_subscribers(SUBS, LIVE)) <= LANE
}

// The build's lane holds what one record can hand it at the build's largest batch and rejoined
// message, so a session's lane, sized from the session's values under the build's, never needs
// more than the build gives it: a build that raises `PICO_UNICAST_BATCH_BYTES` or
// `PICO_FRAG_MAX_BYTES` raises `DELIVERY_LANE_BYTES` with it.
const _: () = assert!(
    holds_a_read::<
        { caps::DELIVERY_LANE_BYTES },
        { caps::PICO_UNICAST_BATCH_BYTES },
        { caps::PICO_FRAG_MAX_BYTES },
        { caps::MAX_KEYEXPR_BYTES },
        { caps::MAX_SUBSCRIPTIONS },
        { caps::MAX_LIVELINESS_SUBSCRIPTIONS },
    >(),
    "the build's delivery lane holds what one record of the build's largest batch hands it"
);

/// What one record of a session whose batch is `batch` bytes and whose limits are `limits` can
/// take of its lane ([`ReadRoom`]), each limit lent under the build's value (`FRAG`, `KEY`,
/// `SUBS`, `LIVE`). A value over the build's counts as the build's: the open refuses it.
pub(crate) fn read_room<
    const FRAG: usize,
    const KEY: usize,
    const SUBS: usize,
    const LIVE: usize,
>(
    batch: usize,
    limits: &SessionLimits,
) -> ReadRoom {
    let frag = limits
        .pico_frag_max_bytes()
        .lent_under(Quota::at_most(FRAG))
        .unwrap_or(FRAG);
    let key = limits
        .max_keyexpr_bytes()
        .lent_under(Quota::at_most(KEY))
        .unwrap_or(KEY);
    let subscribers = limits
        .max_subscriptions()
        .lent_under(Quota::at_most(SUBS))
        .unwrap_or(SUBS);
    let liveliness = limits
        .max_liveliness_subscriptions()
        .lent_under(Quota::at_most(LIVE))
        .unwrap_or(LIVE);
    let callbacks = most_subscribers(subscribers, liveliness);
    ReadRoom {
        bytes: read_bytes(batch, frag, key, callbacks),
        callbacks,
    }
}

/// `limits` with the delivery lane long enough for what one record can hand it
/// ([`read_room`] of the session's `PICO_UNICAST_BATCH_BYTES`): a lane stated shorter is
/// lengthened to it, as a record that found no room could never be handed on. `BATCH`, `FRAG`,
/// `KEY`, `SUBS` and `LIVE` are the build's values, under which the session's lie.
pub(crate) fn holding_a_read<
    const BATCH: usize,
    const FRAG: usize,
    const KEY: usize,
    const SUBS: usize,
    const LIVE: usize,
>(
    mut limits: SessionLimits,
) -> SessionLimits {
    let Ok(batch) =
        Quota::at_most(limits.pico_unicast_batch_bytes()).lent_under(Quota::at_most(BATCH))
    else {
        // A value over the build's refuses the session's open when its arena is laid out.
        return limits;
    };
    let read = read_room::<FRAG, KEY, SUBS, LIVE>(batch, &limits).bytes;
    if read > limits.delivery_lane_bytes() {
        // Refused only by a domain of one value, which is the build's lane, and the build's lane
        // holds the read (the assertion above).
        let _ = limits.select_delivery_lane_bytes(read);
    }
    limits
}

/// What waits at an event slot of the lane, besides its bytes. Each is for the callbacks of its
/// `subscribers` subscribers, whose ids follow its bytes.
#[derive(Clone)]
enum Event {
    /// A sample.
    Sample { record: Record, subscribers: usize },
    /// A token's appearance or retraction, for liveliness subscribers; the token's key is the
    /// slot's bytes.
    #[cfg(feature = "liveliness")]
    Liveliness {
        kind: LivelinessSampleKind,
        key: usize,
        token_id: u64,
        subscribers: usize,
    },
}

impl Event {
    /// The subscribers it is for.
    fn subscribers(&self) -> usize {
        match self {
            Self::Sample { subscribers, .. } => *subscribers,
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => *subscribers,
        }
    }

    /// One more subscriber is its.
    fn joined(&mut self) {
        match self {
            Self::Sample { subscribers, .. } => *subscribers += 1,
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => *subscribers += 1,
        }
    }

    /// Whether what it carries holds its sender. A token is declared and retracted by a
    /// declaration, which does.
    fn holds_sender(&self) -> bool {
        match self {
            Self::Sample { record, .. } => record.holds_sender(),
            #[cfg(feature = "liveliness")]
            Self::Liveliness { .. } => true,
        }
    }
}

/// What a sample is, besides its bytes. Two samples of equal records and equal bytes are one
/// sample to every callback, which is what lets one written copy serve each subscriber of it.
#[derive(Clone, PartialEq)]
struct Record {
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

impl Record {
    /// What `sample` is besides its bytes, and its parts in the order they lie in the area.
    fn of(sample: &dyn SampleView) -> (Self, [&[u8]; 5]) {
        let key = sample.keyexpr().as_bytes();
        let payload = sample.payload();
        let attachment = sample.attachment();
        let encoding = encoding_of(sample);
        let timestamp = timestamp_of(sample);
        let schema = encoding.and_then(|(_, schema)| schema).unwrap_or(&[]);
        let zid = timestamp.map_or(&[][..], |(_, zid)| zid);
        let record = Self {
            kind: sample.kind(),
            reliability: sample.reliability(),
            qos: sample.qos(),
            key: key.len(),
            payload: payload.len(),
            attachment: attachment.map(<[u8]>::len),
            encoding: encoding.map(|(id, schema)| (id, schema.map(<[u8]>::len))),
            timestamp: timestamp.map(|(time, zid)| (time, zid.len())),
            source_info: sample.source_info().cloned(),
        };
        (
            record,
            [key, payload, attachment.unwrap_or(&[]), schema, zid],
        )
    }

    fn after_payload(&self) -> usize {
        self.key + self.payload
    }

    fn after_attachment(&self) -> usize {
        self.after_payload() + self.attachment.unwrap_or(0)
    }

    fn after_schema(&self) -> usize {
        self.after_attachment() + self.encoding.and_then(|(_, s)| s).unwrap_or(0)
    }

    /// Where the ids of the subscribers start: after the last part.
    fn after_parts(&self) -> usize {
        self.after_schema() + self.timestamp.map_or(0, |(_, zid)| zid)
    }

    /// Whether the sample's congestion control holds its sender: sent reliably, with `block` or
    /// `block-first`. A sample that states no QoS has zenoh's default, `drop`.
    fn holds_sender(&self) -> bool {
        self.reliability == Reliability::Reliable
            && self
                .qos
                .is_some_and(|qos| qos.congestion() != CongestionControl::Drop)
    }
}

/// Tokens placed on a copy of a lane's bookkeeping ([`SampleLane::rehearse`]).
#[cfg(feature = "liveliness")]
struct Rehearsal {
    lane: DeliveryLane<{ caps::DELIVERY_LANE_EVENTS }>,
    /// Whether each found room.
    fits: bool,
}

#[cfg(feature = "liveliness")]
impl Rehearsal {
    /// Place a token of `bytes` bytes, for one subscriber, as the lane would.
    fn offer(&mut self, bytes: usize) {
        let placed = self.lane.admits_callbacks(1)
            && match self.lane.reserve(bytes) {
                Ok(reservation) => self.lane.publish(reservation, 1).is_ok(),
                Err(_) => false,
            };
        self.fits &= placed;
    }
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
    records: [Option<Event>; caps::DELIVERY_LANE_EVENTS],
    area: NonNull<u8>,
    /// The sample written last, its reservation held so that the other subscribers it reaches join
    /// it: published, and so handed out, once anything else reaches the lane.
    open: Option<Reservation>,
    /// A delivery holds the head: another thread that delivers finds nothing until it completes.
    handing: bool,
    /// What is offered now is a record a link's gate let through ([`Self::offering_gated`]).
    gated: bool,
    /// The tokens offered now are rehearsed on a copy of the bookkeeping and not queued
    /// ([`Self::rehearse`]).
    #[cfg(feature = "liveliness")]
    rehearsal: Option<Rehearsal>,
    /// The subscribers the samples offered now are for, noted instead of queued
    /// ([`Self::capture`]).
    #[cfg(feature = "local-subscriber")]
    capturing: Option<BoundedVec<SubId, { caps::MAX_SUBSCRIPTIONS }, Static>>,
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
            open: None,
            handing: false,
            gated: false,
            #[cfg(feature = "liveliness")]
            rehearsal: None,
            #[cfg(feature = "local-subscriber")]
            capturing: None,
            counts: LaneCounts::default(),
        }
    }

    /// Queue `sample` for the callback of `subscriber`, or count it when the lane has no room
    /// for it. The sample the lane holds open, offered again for a subscriber it is not for yet,
    /// is not written again: the subscriber's id joins the ones that follow it.
    pub(crate) fn offer(&mut self, subscriber: SubId, sample: &dyn SampleView) {
        #[cfg(feature = "local-subscriber")]
        if let Some(found) = &mut self.capturing {
            let kept = found.push(subscriber);
            debug_assert!(
                kept.is_ok(),
                "a session's subscribers fit the table of them"
            );
            return;
        }
        let (record, parts) = Record::of(sample);
        let same =
            |event: &Event| matches!(event, Event::Sample { record: held, .. } if *held == record);
        if self.join_open(subscriber, &parts, same, record.holds_sender()) {
            return;
        }
        self.open_sample(&[subscriber], record, &parts);
    }

    /// Write a sample of `record` and `parts` for `subscribers` and hold it open, the one held
    /// open before published; or count it, for each of them, when the lane has no room for it.
    fn open_sample(&mut self, subscribers: &[SubId], record: Record, parts: &[&[u8]; 5]) {
        self.seal();
        let ids = subscribers.len().saturating_mul(SUBSCRIBER_ID_BYTES);
        let bytes = parts
            .iter()
            .try_fold(ids, |sum, part| sum.checked_add(part.len()));
        let reservation = match bytes {
            Some(bytes) if self.lane.admits_callbacks(subscribers.len()) => {
                self.lane.reserve(bytes).ok()
            }
            _ => None,
        };
        let Some(reservation) = reservation else {
            for _ in subscribers {
                self.refuse(&record);
            }
            return;
        };
        let mut at = reservation.offset();
        for part in parts {
            self.put(at, part);
            at += part.len();
        }
        for subscriber in subscribers {
            self.put(at, &subscriber.to_ne_bytes());
            at += SUBSCRIBER_ID_BYTES;
        }
        self.records[reservation.index()] = Some(Event::Sample {
            record,
            subscribers: subscribers.len(),
        });
        self.open = Some(reservation);
    }

    /// Note, instead of queueing, the subscribers the samples offered from here on are for, until
    /// [`Self::captured`]: how the session's own put learns which of its subscribers it reaches,
    /// to hand it to them itself.
    #[cfg(feature = "local-subscriber")]
    pub(crate) fn capture(&mut self) {
        self.capturing = Some(BoundedVec::new_static());
    }

    /// The subscribers noted since [`Self::capture`], in the order the session reached them; the
    /// lane queues what is offered again.
    #[cfg(feature = "local-subscriber")]
    pub(crate) fn captured(&mut self) -> BoundedVec<SubId, { caps::MAX_SUBSCRIPTIONS }, Static> {
        self.capturing.take().unwrap_or_else(BoundedVec::new_static)
    }

    /// Whether the lane has room now for `sample` written once for `subscribers` subscribers.
    #[cfg(feature = "local-subscriber")]
    pub(crate) fn takes_sample(&self, sample: &dyn SampleView, subscribers: usize) -> bool {
        let (_, parts) = Record::of(sample);
        let ids = subscribers.saturating_mul(SUBSCRIBER_ID_BYTES);
        let bytes = parts
            .iter()
            .fold(ids, |sum, part| sum.saturating_add(part.len()));
        self.lane.can_ever_fit(bytes)
            && self.takes_a_read(ReadRoom {
                bytes,
                callbacks: subscribers,
            })
    }

    /// Queue `sample` once for `subscribers`, published at once: what the session's own put
    /// leaves for the subscribers whose callbacks are running on its thread, having found the room
    /// first ([`Self::takes_sample`]).
    #[cfg(feature = "local-subscriber")]
    pub(crate) fn offer_to(&mut self, subscribers: &[SubId], sample: &dyn SampleView) {
        let (record, parts) = Record::of(sample);
        self.open_sample(subscribers, record, &parts);
        self.seal();
    }

    /// Add `subscriber` to the event held open when `same` says it is the one offered, `parts`
    /// its bytes, and it is not for `subscriber` already: `true` when the offer is answered so,
    /// the id written after the others, or counted when the callbacks owed are full. `false`
    /// leaves the offer to an event of its own: another one, a subscriber the open one is for
    /// already (a second event of the same bytes), or no room for one more id after it.
    fn join_open(
        &mut self,
        subscriber: SubId,
        parts: &[&[u8]],
        same: impl Fn(&Event) -> bool,
        holds_sender: bool,
    ) -> bool {
        let Some(mut open) = self.open.take() else {
            return false;
        };
        let joined = self.join(&mut open, subscriber, parts, same, holds_sender);
        self.open = Some(open);
        joined
    }

    /// [`Self::join_open`] for the event held `open`.
    fn join(
        &mut self,
        open: &mut Reservation,
        subscriber: SubId,
        parts: &[&[u8]],
        same: impl Fn(&Event) -> bool,
        holds_sender: bool,
    ) -> bool {
        let index = open.index();
        let subscribers = match &self.records[index] {
            Some(event) if same(event) => event.subscribers(),
            _ => return false,
        };
        let length = parts.iter().map(|part| part.len()).sum::<usize>();
        // SAFETY: the open event's bytes lie at its reservation, written by the offer that opened
        // it and by `Self::join`, and nothing else writes there while it is held open.
        let written = unsafe {
            core::slice::from_raw_parts(self.area.as_ptr().add(open.offset()), open.bytes())
        };
        if written.len() < length {
            return false;
        }
        let (mut held, ids) = written.split_at(length);
        for part in parts {
            let (bytes, rest) = held.split_at(part.len());
            if bytes != *part {
                return false;
            }
            held = rest;
        }
        let id = subscriber.to_ne_bytes();
        if ids
            .chunks_exact(SUBSCRIBER_ID_BYTES)
            .any(|other| *other == id[..])
        {
            return false;
        }
        if !self.lane.admits_callbacks(subscribers + 1) {
            self.count_refused(holds_sender);
            return true;
        }
        let at = open.offset() + open.bytes();
        if !self.lane.extend(open, SUBSCRIBER_ID_BYTES) {
            return false;
        }
        self.put(at, &id);
        if let Some(event) = &mut self.records[index] {
            event.joined();
        }
        true
    }

    /// Publish the sample held open, so a delivery hands it out: no subscriber joins it after.
    fn seal(&mut self) {
        let Some(open) = self.open.take() else {
            return;
        };
        let index = open.index();
        let (subscribers, holds_sender) =
            self.records[index].as_ref().map_or((0, false), |event| {
                (event.subscribers(), event.holds_sender())
            });
        // Its callbacks were admitted one by one as it was written, so only a lane that stops
        // refuses it, and then every subscriber it was for goes without.
        if self.lane.publish(open, subscribers).is_err() {
            self.records[index] = None;
            for _ in 0..subscribers {
                self.count_refused(holds_sender);
            }
        }
    }

    /// Copy `bytes` into the area from `at`, inside the reservation of the sample being written:
    /// no other sample's bytes lie there until that one is completed.
    fn put(&mut self, at: usize, bytes: &[u8]) {
        let inside = at
            .checked_add(bytes.len())
            .is_some_and(|end| self.lane.can_ever_fit(end));
        assert!(inside, "a sample's bytes lie inside the lane's area");
        // SAFETY: inside the area (asserted above), which is this lane's alone (`Self::over`);
        // `bytes` are the sample's and not the area's.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.area.as_ptr().add(at), bytes.len())
        };
    }

    /// Queue a token's appearance or retraction, `sample`, for the callback of liveliness
    /// subscriber `subscriber`, or count it when the lane has no room for its key. Written once
    /// for all the liveliness subscribers it reaches, as a sample is ([`Self::offer`]). A token
    /// is declared and retracted by a declaration, which holds its sender, so a refusal is
    /// counted with the samples that do ([`LaneCounts::held_over`]).
    #[cfg(feature = "liveliness")]
    pub(crate) fn offer_liveliness(&mut self, subscriber: SubId, sample: &LivelinessSample<'_>) {
        let key = sample.keyexpr.as_bytes();
        if let Some(rehearsal) = &mut self.rehearsal {
            rehearsal.offer(key.len() + SUBSCRIBER_ID_BYTES);
            return;
        }
        let same = |event: &Event| {
            matches!(
                event,
                Event::Liveliness { kind, key: length, token_id, .. }
                    if *kind == sample.kind && *length == key.len() && *token_id == sample.token_id
            )
        };
        if self.join_open(subscriber, &[key], same, true) {
            return;
        }
        self.seal();
        if !self.lane.admits_callbacks(1) {
            self.count_refused(true);
            return;
        }
        let Ok(reservation) = self.lane.reserve(key.len() + SUBSCRIBER_ID_BYTES) else {
            self.count_refused(true);
            return;
        };
        self.put(reservation.offset(), key);
        self.put(reservation.offset() + key.len(), &subscriber.to_ne_bytes());
        self.records[reservation.index()] = Some(Event::Liveliness {
            kind: sample.kind,
            key: key.len(),
            token_id: sample.token_id,
            subscribers: 1,
        });
        self.open = Some(reservation);
    }

    /// Count a sample the lane had no room for, by its congestion control.
    fn refuse(&mut self, record: &Record) {
        self.count_refused(record.holds_sender());
    }

    /// Count one subscriber's sample the lane had no room for: apart when it holds its sender.
    /// A record a link's gate let through waited for the room one record can take ([`LaneGate`]),
    /// so one that holds its sender and finds no room is a defect of that bound, and a debug build
    /// stops there; what did not wait is counted.
    fn count_refused(&mut self, holds_sender: bool) {
        debug_assert!(
            !(holds_sender && self.gated),
            "a record the gate let through found no room in the delivery lane"
        );
        let count = if holds_sender {
            &mut self.counts.held_over
        } else {
            &mut self.counts.dropped
        };
        *count = count.saturating_add(1);
    }

    /// Rehearse the tokens offered from here on, until [`Self::rehearsed`]: each is placed on a copy
    /// of the lane's bookkeeping and nothing is written or queued. How the session learns, before
    /// it hands a liveliness subscriber the tokens it already knows, that the lane holds them all.
    #[cfg(feature = "liveliness")]
    pub(crate) fn rehearse(&mut self) {
        // The event held open is published before the tokens are queued, and its callbacks are
        // then owed: the copy is made with them.
        self.seal();
        self.rehearsal = Some(Rehearsal {
            lane: self.lane.clone(),
            fits: true,
        });
    }

    /// Whether every token offered since [`Self::rehearse`] found room; the lane queues what is
    /// offered again.
    #[cfg(feature = "liveliness")]
    pub(crate) fn rehearsed(&mut self) -> bool {
        match self.rehearsal.take() {
            Some(rehearsal) => rehearsal.fits,
            None => true,
        }
    }

    /// Whether the lane has the room one record can take now ([`ReadRoom`]): what the session
    /// is handed a record for. Room past the whole lane is found only in an empty lane, so the
    /// link is never stopped for good; so is a record's callbacks past the whole budget, which
    /// the lane admits alone ([`DeliveryLane::publish`]).
    pub(crate) fn takes_a_read(&self, room: ReadRoom) -> bool {
        let stats = self.lane.stats();
        let empty = stats.queued_events == 0;
        let bytes = if self.lane.can_ever_fit(room.bytes) {
            self.lane.fits(room.bytes).is_ok()
        } else {
            empty
        };
        // The event held open owes its callbacks once it is published, which is before the next
        // record's are.
        let open = self
            .open
            .as_ref()
            .and_then(|open| self.records[open.index()].as_ref())
            .map_or(0, Event::subscribers);
        let owed = stats
            .pending_callbacks
            .saturating_add(open)
            .saturating_add(room.callbacks);
        bytes && (empty || owed <= stats.callback_budget)
    }

    /// Whether what is offered from here on is a record a link's gate let through (`true`), which
    /// waited for the room one record can take ([`LaneGate`]), or anything else (`false`, the
    /// lane's state when made): the session's own puts, the tokens a liveliness subscriber is
    /// handed when it is declared, a group's records. Only the first is a defect when it holds
    /// its sender and finds no room.
    pub(crate) fn offering_gated(&mut self, gated: bool) {
        self.gated = gated;
    }

    /// What is at the head of the lane, with the subscribers it is for: held by this delivery
    /// until [`Self::complete`]. `None` when the lane is empty or another delivery holds the head.
    pub(crate) fn take_front(&mut self) -> Option<LaneItem> {
        self.seal();
        if self.handing {
            return None;
        }
        loop {
            let Next::Ready(delivery) = self.lane.front() else {
                return None;
            };
            let Some(event) = self.records[delivery.index].clone() else {
                // A published slot always has its record; one without is passed over.
                self.lane.complete();
                continue;
            };
            self.handing = true;
            // SAFETY: the head's bytes are inside the area (`DeliveryLane::front`).
            let base = unsafe { self.area.as_ptr().add(delivery.offset) };
            return Some(match event {
                Event::Sample {
                    record,
                    subscribers,
                } => LaneItem::Sample(LaneSample {
                    record,
                    subscribers,
                    base,
                }),
                #[cfg(feature = "liveliness")]
                Event::Liveliness {
                    kind,
                    key,
                    token_id,
                    subscribers,
                } => LaneItem::Liveliness(LaneLiveliness {
                    kind,
                    key,
                    token_id,
                    subscribers,
                    base,
                }),
            });
        }
    }

    /// The callbacks of the head returned, each of them: its slot and its bytes come back.
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

/// What a delivery takes from the head of the lane, where its bytes lie. Valid until the delivery
/// that took it completes it.
pub(crate) enum LaneItem {
    /// A sample, for the callbacks of its subscribers.
    Sample(LaneSample),
    /// A token's appearance or retraction, for a liveliness subscriber's callback.
    #[cfg(feature = "liveliness")]
    Liveliness(LaneLiveliness),
}

/// A token's appearance or retraction at the head of the lane, its key where it lies.
#[cfg(feature = "liveliness")]
pub(crate) struct LaneLiveliness {
    kind: LivelinessSampleKind,
    key: usize,
    token_id: u64,
    subscribers: usize,
    base: *const u8,
}

#[cfg(feature = "liveliness")]
impl LaneLiveliness {
    /// The liveliness subscribers whose callbacks it is for, in the order the session offered it
    /// to them.
    pub(crate) fn subscribers(&self) -> impl Iterator<Item = SubId> + '_ {
        // SAFETY: the key and the subscribers' ids were written one after the other from `base`
        // (`SampleLane::offer_liveliness`, `SampleLane::join`), and are not written again until
        // the delivery that holds the head completes it, which is after this view is gone.
        let ids = unsafe {
            core::slice::from_raw_parts(
                self.base.add(self.key),
                self.subscribers * SUBSCRIBER_ID_BYTES,
            )
        };
        subscriber_ids(ids)
    }

    /// The sample, for the liveliness subscriber's callback.
    pub(crate) fn as_sample(&self) -> LivelinessSample<'_> {
        // SAFETY: the key's bytes were a `&str`'s, written at `base` (`SampleLane::offer_liveliness`),
        // and are not written again until the delivery that holds the head completes it, which is
        // after this view is gone.
        let keyexpr = unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(self.base, self.key))
        };
        LivelinessSample {
            kind: self.kind,
            keyexpr,
            token_id: self.token_id,
        }
    }
}

/// A sample at the head of the lane, where its bytes lie: what each of its subscribers' callbacks
/// is handed. Valid until the delivery that took it completes it.
pub(crate) struct LaneSample {
    record: Record,
    subscribers: usize,
    base: *const u8,
}

impl LaneSample {
    /// The `len` bytes `skip` bytes into the sample.
    fn part(&self, skip: usize, len: usize) -> &[u8] {
        // SAFETY: the sample's parts and its subscribers' ids were written one after the other
        // from `base` (`SampleLane::offer`, `SampleLane::join`), and the head's bytes are not
        // written again until the delivery that holds it completes it, which is after this view
        // is gone.
        unsafe { core::slice::from_raw_parts(self.base.add(skip), len) }
    }

    /// The subscribers whose callbacks it is for, in the order the session offered it to them.
    pub(crate) fn subscribers(&self) -> impl Iterator<Item = SubId> + '_ {
        subscriber_ids(self.part(
            self.record.after_parts(),
            self.subscribers * SUBSCRIBER_ID_BYTES,
        ))
    }
}

/// The subscribers' ids written one after the other in `ids`.
fn subscriber_ids(ids: &[u8]) -> impl Iterator<Item = SubId> + '_ {
    ids.chunks_exact(SUBSCRIBER_ID_BYTES).map(|held| {
        let mut id = [0u8; SUBSCRIBER_ID_BYTES];
        id.copy_from_slice(held);
        SubId::from_ne_bytes(id)
    })
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
            .map(|len| self.part(self.record.after_payload(), len))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.record.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        self.record
            .timestamp
            .map(|(time, zid)| (time, self.part(self.record.after_schema(), zid)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.record.encoding.map(|(id, schema)| {
            (
                id,
                schema.map(|len| self.part(self.record.after_attachment(), len)),
            )
        })
    }
}

/// The changes of the session's matching statuses its lock found, handed to their listeners after
/// it, in the order they were found. A listener holds one row at most: a change and the change
/// back before the first was handed leave the listener where it stood, so the second takes the
/// first's row away rather than a row of its own, and the table needs a row for each listener the
/// build admits and no more.
pub(crate) struct MatchFlips {
    flips: BoundedVec<(MatchId, bool), { caps::MAX_MATCHING_LISTENERS }, Static>,
}

impl MatchFlips {
    pub(crate) fn new() -> Self {
        Self {
            flips: BoundedVec::new_static(),
        }
    }

    /// The status of `listener` changed to `matching`.
    pub(crate) fn flip(&mut self, listener: MatchId, matching: bool) {
        if let Some(at) = self.flips.iter().position(|(id, _)| *id == listener) {
            self.flips.remove(at);
            return;
        }
        let held = self.flips.push((listener, matching));
        debug_assert!(held.is_ok(), "a row for each listener the build admits");
    }

    /// The change found first, to hand to its listener.
    pub(crate) fn next(&mut self) -> Option<(MatchId, bool)> {
        if self.flips.is_empty() {
            None
        } else {
            Some(self.flips.remove(0))
        }
    }

    /// `listener` is gone: nothing it was owed is handed.
    pub(crate) fn forget(&mut self, listener: MatchId) {
        self.flips.retain(|(id, _)| *id != listener);
    }
}

/// `pump`, which gives the session nothing while the lane has not the room one record can take
/// (`room`, decision Q4): not the next datagram, and not the next record of one the link keeps.
/// What the peer sends meanwhile waits in the link, and the transport's flow control carries the
/// wait back to it.
pub(crate) struct LaneGate<P> {
    pump: P,
    lane: Arc<Mutex<SampleLane>>,
    room: ReadRoom,
}

impl<P> LaneGate<P> {
    pub(crate) fn new(pump: P, lane: Arc<Mutex<SampleLane>>, room: ReadRoom) -> Self {
        Self { pump, lane, room }
    }

    /// Whether the link's input is held back: the lane has not the room of a record.
    fn shut(&self) -> bool {
        !self.lane.lock().takes_a_read(self.room)
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

    /// The rest of a datagram already read is held back with the link's next one.
    fn takes_input(&self) -> bool {
        !self.shut() && self.pump.takes_input()
    }

    fn keeps_input(&self) -> bool {
        self.pump.keeps_input()
    }

    fn keep(&self) {
        self.pump.keep()
    }

    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        self.pump.readiness()
    }

    // The gate holds back input only: what the session sends goes out while the lane is full.
    fn writability(&self) -> Option<Box<dyn LinkWritability>> {
        self.pump.writability()
    }
}
