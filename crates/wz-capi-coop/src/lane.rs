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
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

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
#[cfg(feature = "query")]
use wz_session_core::reply_sink::{ReplyKind, ReplyView};
use wz_session_core::sample::{QosLevel, SampleKind, SourceInfo};
use wz_session_core::sink::SampleView;

use crate::prelude::*;

/// The handle the lane's queues carry: the event slot a sample holds and where its bytes start,
/// generated from `sources/session/delivery_lane_handle.scxml`.
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    unexpected_cfgs,
    non_snake_case,
    clippy::all
)]
mod delivery_lane_handle {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-capi-coop/delivery_lane_handle.rs"
    ));
}

/// The queue between the session and its deliveries ([`SharedLane`]), generated from
/// `sources/session/delivery_lane_queue.scxml`.
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    unexpected_cfgs,
    non_snake_case,
    clippy::all
)]
mod delivery_lane_queue {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-capi-coop/delivery_lane_queue.rs"
    ));
}

use delivery_lane_handle::DeliveryLaneHandle;
use delivery_lane_queue::DeliveryLaneQueue;

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
    let most = most_subscribers(subscribers, liveliness);
    ReadRoom {
        bytes: read_bytes(batch, frag, key, most),
        // A reply owes its leg's callback, whatever the session's subscribers.
        callbacks: most.max(1),
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
    /// A reply, for the callback of the leg of a get it answers, which is its one subscriber.
    #[cfg(feature = "query")]
    Reply(ReplyRecord),
}

impl Event {
    /// The subscribers it is for.
    fn subscribers(&self) -> usize {
        match self {
            Self::Sample { subscribers, .. } => *subscribers,
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => *subscribers,
            #[cfg(feature = "query")]
            Self::Reply(_) => 1,
        }
    }

    /// One more subscriber is its.
    fn joined(&mut self) {
        match self {
            Self::Sample { subscribers, .. } => *subscribers += 1,
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => *subscribers += 1,
            // A reply is never held open, so none joins it.
            #[cfg(feature = "query")]
            Self::Reply(_) => {}
        }
    }

    /// Whether what it carries holds its sender. A token is declared and retracted by a
    /// declaration, which does.
    fn holds_sender(&self) -> bool {
        match self {
            Self::Sample { record, .. } => record.holds_sender(),
            #[cfg(feature = "liveliness")]
            Self::Liveliness { .. } => true,
            // A reply is the answer a get waits for; its loss is not the sender's to choose.
            #[cfg(feature = "query")]
            Self::Reply(_) => true,
        }
    }
}

/// What a reply is, besides its bytes: its key, payload, attachment, encoding schema, timestamp
/// id and responder id lie one after the other in the lane's area.
#[cfg(feature = "query")]
#[derive(Clone)]
struct ReplyRecord {
    leg: u64,
    rid: wz_session_core::wire_id::RequestId,
    kind: ReplyKind,
    qos: Option<QosLevel>,
    key: usize,
    payload: usize,
    attachment: Option<usize>,
    /// The packed id of the Put's or the Err's encoding, and the bytes of its schema.
    encoding: Option<(u32, Option<usize>)>,
    /// The time word, and the bytes of the id prefix.
    timestamp: Option<(u64, usize)>,
    source_info: Option<SourceInfo>,
    /// The bytes of the responder's zid, and its entity id.
    responder: Option<(usize, u32)>,
}

#[cfg(feature = "query")]
impl ReplyRecord {
    /// What `view`, a reply to leg `leg`, is besides its bytes, and its parts in the order they
    /// lie in the area.
    fn of(leg: u64, view: &dyn ReplyView) -> (Self, [&[u8]; 6]) {
        let key = view.keyexpr().as_bytes();
        let payload = view.payload();
        let attachment = view.attachment();
        let encoding = view.put_encoding().or_else(|| view.err_encoding());
        let timestamp = view
            .timestamp_parts()
            .map(|stamp| (stamp.time, stamp.zid))
            .or_else(|| {
                view.timestamp()
                    .map(|hint| (hint.time, hint.zid.as_slice()))
            });
        let responder = view.responder();
        let schema = encoding.and_then(|(_, schema)| schema).unwrap_or(&[]);
        let zid = timestamp.map_or(&[][..], |(_, zid)| zid);
        let record = Self {
            leg,
            rid: view.rid(),
            kind: view.kind(),
            qos: view.qos(),
            key: key.len(),
            payload: payload.len(),
            attachment: attachment.map(<[u8]>::len),
            encoding: encoding.map(|(id, schema)| (id, schema.map(<[u8]>::len))),
            timestamp: timestamp.map(|(time, zid)| (time, zid.len())),
            source_info: view.source_info().cloned(),
            responder: responder.map(|(zid, eid)| (zid.len(), eid)),
        };
        let parts = [
            key,
            payload,
            attachment.unwrap_or(&[]),
            schema,
            zid,
            responder.map_or(&[][..], |(zid, _)| zid),
        ];
        (record, parts)
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

    fn after_timestamp(&self) -> usize {
        self.after_schema() + self.timestamp.map_or(0, |(_, zid)| zid)
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

/// What waits at each event slot of the lane besides its bytes, a cell for each slot, reached
/// through a pointer as the area is: the lane's holder writes a slot while it writes the sample
/// there, and the one delivery a sample is handed to takes it ([`SharedLane`]), so a hold of the
/// lane is not a hold of a slot a delivery reads.
struct Records(NonNull<UnsafeCell<Option<Event>>>);

impl Records {
    fn new() -> Self {
        let cells: Box<[UnsafeCell<Option<Event>>]> = (0..caps::DELIVERY_LANE_EVENTS)
            .map(|_| UnsafeCell::new(None))
            .collect();
        let first = Box::into_raw(cells).cast::<UnsafeCell<Option<Event>>>();
        // SAFETY: the pointer of a box is never null.
        Self(unsafe { NonNull::new_unchecked(first) })
    }

    /// The cell of event slot `index`.
    fn cell(&self, index: usize) -> &UnsafeCell<Option<Event>> {
        assert!(index < caps::DELIVERY_LANE_EVENTS, "a slot of the lane");
        // SAFETY: the cells are `DELIVERY_LANE_EVENTS`, this one's until it drops.
        unsafe { &*self.0.as_ptr().add(index) }
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        let cells =
            core::ptr::slice_from_raw_parts_mut(self.0.as_ptr(), caps::DELIVERY_LANE_EVENTS);
        // SAFETY: the box `Records::new` made, of `DELIVERY_LANE_EVENTS` cells, given back once.
        drop(unsafe { Box::from_raw(cells) });
    }
}

/// The samples a lane published and has not handed on to its deliveries, oldest first: the event
/// slot of each and where its bytes start. Published in the order their slots were taken, so the
/// front is the oldest of the lane's heads not handed on.
struct Published {
    entries: [(u16, u32); caps::DELIVERY_LANE_EVENTS],
    head: usize,
    len: usize,
}

impl Published {
    const fn new() -> Self {
        Self {
            entries: [(0, 0); caps::DELIVERY_LANE_EVENTS],
            head: 0,
            len: 0,
        }
    }

    /// The sample at event slot `index`, its bytes at `offset`, was published.
    fn push(&mut self, index: usize, offset: usize) {
        debug_assert!(
            self.len < caps::DELIVERY_LANE_EVENTS,
            "a published sample holds a slot of the lane"
        );
        let at = (self.head + self.len) % caps::DELIVERY_LANE_EVENTS;
        self.entries[at] = (index as u16, offset as u32);
        self.len += 1;
    }

    /// The oldest sample published and not handed on.
    fn front(&self) -> Option<(u16, u32)> {
        (self.len > 0).then(|| self.entries[self.head])
    }

    /// The oldest was handed on.
    fn pop(&mut self) {
        if self.len > 0 {
            self.head = (self.head + 1) % caps::DELIVERY_LANE_EVENTS;
            self.len -= 1;
        }
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
    records: Records,
    /// The samples published and not handed on to the deliveries yet ([`SharedLane`]).
    published: Published,
    area: NonNull<u8>,
    /// The sample written last, its reservation held so that the other subscribers it reaches join
    /// it: published, and so handed out, once anything else reaches the lane.
    open: Option<Reservation>,
    /// The lane's own hand-out ([`Self::take_front`]) holds the head.
    #[cfg(all(test, feature = "std"))]
    handing: bool,
    /// The room the session's links ask for before each record ([`LaneGate`]), once a link was
    /// opened: what the lane's holder publishes for the gates as it lets go ([`SharedLane`]).
    link_room: Option<ReadRoom>,
    /// What is offered now is a record a link's gate let through ([`Self::offering_gated`]).
    /// Read only by a debug build's check of the gate's bound, so a release build neither keeps
    /// nor sets it; [`SharedLane`] tells it each time the lane is taken.
    #[cfg(debug_assertions)]
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

// SAFETY: the area and the records are the lane's alone for the life of the session, reached by the
// lane's holder, or by the one delivery a sample is handed to (`SharedLane`), which reads that
// sample's bytes and takes its record alone, which nothing writes until the sample is given back.
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
            records: Records::new(),
            published: Published::new(),
            area,
            open: None,
            #[cfg(all(test, feature = "std"))]
            handing: false,
            link_room: None,
            #[cfg(debug_assertions)]
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
        self.set_record(
            reservation.index(),
            Some(Event::Sample {
                record,
                subscribers: subscribers.len(),
            }),
        );
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
        let subscribers = match self.record(index) {
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
        if let Some(event) = self.record_mut(index) {
            event.joined();
        }
        true
    }

    /// Publish the sample held open, so a delivery hands it out: no subscriber joins it after.
    pub(crate) fn seal(&mut self) {
        let Some(open) = self.open.take() else {
            return;
        };
        let (index, offset) = (open.index(), open.offset());
        let (subscribers, holds_sender) = self.record(index).map_or((0, false), |event| {
            (event.subscribers(), event.holds_sender())
        });
        // Its callbacks were admitted one by one as it was written, so only a lane that stops
        // refuses it, and then every subscriber it was for goes without.
        if self.lane.publish(open, subscribers).is_err() {
            self.set_record(index, None);
            for _ in 0..subscribers {
                self.count_refused(holds_sender);
            }
        } else if subscribers > 0 {
            self.published.push(index, offset);
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
        self.set_record(
            reservation.index(),
            Some(Event::Liveliness {
                kind: sample.kind,
                key: key.len(),
                token_id: sample.token_id,
                subscribers: 1,
            }),
        );
        self.open = Some(reservation);
    }

    /// Queue `view`, a reply to leg `leg`, for the leg's callback, or count it when the lane has
    /// no room for it: one event of the lane, published at once.
    #[cfg(feature = "query")]
    pub(crate) fn offer_reply(&mut self, leg: u64, view: &dyn ReplyView) {
        self.seal();
        let (record, parts) = ReplyRecord::of(leg, view);
        let bytes = parts
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.len()));
        let reservation = match bytes {
            Some(bytes) if self.lane.admits_callbacks(1) => self.lane.reserve(bytes).ok(),
            _ => None,
        };
        let Some(reservation) = reservation else {
            self.count_refused(true);
            return;
        };
        let mut at = reservation.offset();
        for part in parts {
            self.put(at, part);
            at += part.len();
        }
        let (index, offset) = (reservation.index(), reservation.offset());
        self.set_record(index, Some(Event::Reply(record)));
        if self.lane.publish(reservation, 1).is_err() {
            self.set_record(index, None);
            self.count_refused(true);
        } else {
            self.published.push(index, offset);
        }
    }

    /// Whether the lane holds nothing and no delivery holds its head: what a lane a thread writes
    /// and delivers alone is idle by; a session's lane says it without a hold
    /// ([`SharedLane::is_idle`]).
    #[cfg(all(test, feature = "std", feature = "query"))]
    pub(crate) fn is_idle(&self) -> bool {
        !self.handing && self.lane.stats().queued_events == 0
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
        #[cfg(debug_assertions)]
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
            .and_then(|open| self.record(open.index()))
            .map_or(0, Event::subscribers);
        let owed = stats
            .pending_callbacks
            .saturating_add(open)
            .saturating_add(room.callbacks);
        bytes && (empty || owed <= stats.callback_budget)
    }

    /// The session's links ask for `room` before each record ([`LaneGate`]). Every link of a
    /// session asks for the same room; were two to differ, the larger is asked for all, which holds
    /// a link back sooner and never lets a record through that its own room would not.
    pub(crate) fn gate_links(&mut self, room: ReadRoom) {
        self.link_room = Some(match self.link_room {
            Some(held) => ReadRoom {
                bytes: held.bytes.max(room.bytes),
                callbacks: held.callbacks.max(room.callbacks),
            },
            None => room,
        });
    }

    /// Whether the lane has the room the links ask for now: `true` before a link asked.
    fn takes_a_link_read(&self) -> bool {
        self.link_room.map_or(true, |room| self.takes_a_read(room))
    }

    /// Whether what is offered from here on is a record a link's gate let through (`true`), which
    /// waited for the room one record can take ([`LaneGate`]), or anything else (`false`, the
    /// lane's state when made): the session's own puts, the tokens a liveliness subscriber is
    /// handed when it is declared, a group's records. Only the first is a defect when it holds
    /// its sender and finds no room. A debug build's alone (`gated`).
    #[cfg(debug_assertions)]
    pub(crate) fn offering_gated(&mut self, gated: bool) {
        self.gated = gated;
    }

    /// What is at the head of the lane, with the subscribers it is for: held by this delivery
    /// until [`Self::complete`]. `None` when the lane is empty or another delivery holds the head.
    /// The lane's own hand-out, for a lane a thread writes and delivers alone; a session's lane
    /// hands its samples on through [`SharedLane`].
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn take_front(&mut self) -> Option<LaneItem> {
        self.seal();
        if self.handing {
            return None;
        }
        loop {
            let Next::Ready(delivery) = self.lane.front() else {
                return None;
            };
            self.published.pop();
            let Some(event) = self.record(delivery.index).cloned() else {
                // A published slot always has its record; one without is passed over.
                self.lane.complete();
                continue;
            };
            self.handing = true;
            // SAFETY: the head's bytes are inside the area (`DeliveryLane::front`).
            let base = unsafe { self.area.as_ptr().add(delivery.offset) };
            return Some(LaneItem::of(event, base));
        }
    }

    /// The callbacks of the head returned, each of them: its slot and its bytes come back.
    pub(crate) fn complete(&mut self) {
        if let Next::Ready(delivery) = self.lane.front() {
            self.set_record(delivery.index, None);
            self.lane.complete();
        }
        #[cfg(all(test, feature = "std"))]
        {
            self.handing = false;
        }
    }

    /// The record at event slot `index`, a slot the lane holds: one it has not handed on, or
    /// one handed and given back.
    fn record(&self, index: usize) -> Option<&Event> {
        // SAFETY: a slot the lane holds is reached by the lane's holder alone (`SharedLane`), and
        // nothing writes it while this borrow of the lane lives.
        unsafe { (*self.records.cell(index).get()).as_ref() }
    }

    /// [`Self::record`], to change.
    fn record_mut(&mut self, index: usize) -> Option<&mut Event> {
        // SAFETY: as `Self::record`, with the lane held mutably.
        unsafe { (*self.records.cell(index).get()).as_mut() }
    }

    /// Write the record at event slot `index`, a slot the lane holds.
    fn set_record(&mut self, index: usize, event: Option<Event>) {
        // SAFETY: as `Self::record`, with the lane held mutably.
        unsafe { *self.records.cell(index).get() = event };
    }

    /// What the lane did not hand a subscriber.
    pub(crate) fn counts(&self) -> LaneCounts {
        self.counts
    }
}

/// The session's lane, handed between the session and its deliveries with no lock: the session
/// writes it under its own lock ([`Self::held`]), and each sample it publishes is handed to the
/// deliveries through a queue of the sample's handles (`handed`), the event slot it holds and
/// where its bytes start, and comes back through a second queue once its callbacks have returned
/// (`returned`), for the session to give its slot and bytes back to the lane at its next hold.
///
/// Both queues are the SCE document `sources/session/delivery_lane_queue.scxml`: one producer and
/// one consumer each, a Lamport ring that is wait-free on both sides. Each side is single by a
/// serialisation the lane does not have to make: every writer of the lane, which is the producer
/// of `handed` and the consumer of `returned`, holds the session's lock, and every delivery,
/// which is the consumer of `handed` and the producer of `returned`, holds the lane's delivery
/// word (`delivering`, taken by a compare-exchange). The ring publishes an element with a
/// Release store of its index and reads it after an Acquire load of it, so what a side wrote
/// before a push (a sample's record and bytes, or the end of its callbacks) happens-before the
/// other side's use after the pop.
///
/// What a sample is besides its bytes (its record) cannot ride in the queue: the queue holds the
/// element type its document names, a record of scalars, and a record holds a source info and a
/// variant per kind. So the element is the handle, and the record waits in its event slot, a cell
/// of its own ([`Records`]) that the handle's push hands to the delivery and its return hands back.
pub(crate) struct SharedLane {
    lane: UnsafeCell<SampleLane>,
    handed: DeliveryLaneQueue,
    returned: DeliveryLaneQueue,
    /// The lane's records and area, as the deliveries read them: the pointers the lane holds.
    records: NonNull<UnsafeCell<Option<Event>>>,
    area: NonNull<u8>,
    /// Whether a delivery holds the deliveries' side of the lane ([`Self::deliver`]).
    delivering: portable_atomic::AtomicBool,
    /// How many samples were handed on, taken by a delivery, and done with: each written by its
    /// one side, read by the other without the lock.
    handed_count: AtomicUsize,
    taken_count: AtomicUsize,
    #[cfg(feature = "query")]
    done_count: AtomicUsize,
    /// Whether the lane has the room the links ask for (`SampleLane::takes_a_link_read`), as the
    /// lane's last holder left it.
    reads: AtomicBool,
    /// What a link's dispatch tells the lane while it runs, which a debug build's check of the
    /// gate's bound reads ([`SampleLane::offering_gated`]): told to the lane at each hold.
    #[cfg(debug_assertions)]
    gated: AtomicBool,
    /// Where the datagram lies that a link lends the session's step now, when the link leaves it
    /// where it lies until it is next asked to receive (`LaneGate::recv_with`): its first byte's
    /// address and its length. Written under the session's lock.
    lending: UnsafeCell<Option<(usize, usize)>>,
    /// The sample handed to its callbacks where its datagram lies ([`LentSample`]), and where it
    /// is in its life (`LENT_*`): opened and written by the lane's holder, published at the end of
    /// the hold, taken and given back by a delivery. While it is not free the links are held back,
    /// so the datagram stays where it lies.
    lent: UnsafeCell<Option<LentSample>>,
    lent_state: AtomicU8,
    /// How many samples were handed where their datagram lies, which the tests count.
    #[cfg(all(test, feature = "std"))]
    lent_count: AtomicUsize,
}

/// No sample is lent where its datagram lies.
const LENT_FREE: u8 = 0;
/// The lane's holder writes the lent sample; the subscribers it reaches join it.
const LENT_OPEN: u8 = 1;
/// The lent sample is published for a delivery.
const LENT_READY: u8 = 2;
/// A delivery runs the lent sample's callbacks.
const LENT_DELIVERING: u8 = 3;

// SAFETY: the lane is reached by the holder of the session's lock alone (`Self::held`), the
// deliveries' side by the holder of `delivering` alone, and a slot's record and bytes by the one
// side the queues have handed them to; every other field is an atomic.
unsafe impl Send for SharedLane {}
// SAFETY: as `Send`.
unsafe impl Sync for SharedLane {}

// The queues hold a handle for every event slot the lane can have out at once, and a handle names
// any slot and any offset of the area.
const _: () = assert!(
    delivery_lane_queue::CAPACITY >= caps::DELIVERY_LANE_EVENTS,
    "the delivery lane's queue holds every event slot of the lane: raise its document's capacity"
);
const _: () = assert!(
    caps::DELIVERY_LANE_EVENTS <= u16::MAX as usize
        && caps::DELIVERY_LANE_BYTES <= u32::MAX as usize,
    "a delivery lane handle names every event slot and every offset of the area"
);

impl SharedLane {
    pub(crate) fn new(lane: SampleLane) -> Self {
        let reads = lane.takes_a_link_read();
        let records = lane.records.0;
        let area = lane.area;
        Self {
            lane: UnsafeCell::new(lane),
            handed: DeliveryLaneQueue::new(),
            returned: DeliveryLaneQueue::new(),
            records,
            area,
            delivering: portable_atomic::AtomicBool::new(false),
            handed_count: AtomicUsize::new(0),
            taken_count: AtomicUsize::new(0),
            #[cfg(feature = "query")]
            done_count: AtomicUsize::new(0),
            reads: AtomicBool::new(reads),
            #[cfg(debug_assertions)]
            gated: AtomicBool::new(false),
            lending: UnsafeCell::new(None),
            lent: UnsafeCell::new(None),
            lent_state: AtomicU8::new(LENT_FREE),
            #[cfg(all(test, feature = "std"))]
            lent_count: AtomicUsize::new(0),
        }
    }

    /// The datagram a link lends the session's step now, which a sample may be handed to its
    /// callbacks where it lies; `None` once the link takes it back.
    ///
    /// # Safety
    /// The caller holds the session's lock, and the link leaves the bytes where they lie until it
    /// is next asked to receive or to be serviced
    /// (`SessionDatagramLink::lends_until_next_receive`).
    pub(crate) unsafe fn set_lending(&self, datagram: Option<&[u8]>) {
        let range = datagram.map(|bytes| (bytes.as_ptr() as usize, bytes.len()));
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.lending.get() = range };
    }

    /// Whether a sample handed where its datagram lies holds the links back: no link is read or
    /// serviced until its callbacks have returned.
    pub(crate) fn lends_a_datagram(&self) -> bool {
        self.lent_state.load(Ordering::Acquire) != LENT_FREE
    }

    /// How many samples were handed where their datagram lies since the lane was made, which the
    /// tests of the cost of one sample count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn lent_count(&self) -> usize {
        self.lent_count.load(Ordering::SeqCst)
    }

    /// The lane, to write: the samples the deliveries are done with are given back to it first,
    /// and what it published is handed on to them when the hold ends.
    ///
    /// # Safety
    /// The caller holds the session's lock, under which every hold of the lane is made, and holds
    /// no other [`LaneHeld`] of it.
    pub(crate) unsafe fn held(&self) -> LaneHeld<'_> {
        let mut held = LaneHeld { shared: self };
        #[cfg(debug_assertions)]
        held.offering_gated(self.gated.load(Ordering::Acquire));
        held.take_back();
        held
    }

    /// The deliveries' side of the lane, or `None` while another delivery holds it, which hands out
    /// what is handed on meanwhile before it lets go ([`LaneDelivery`]).
    pub(crate) fn deliver(&self) -> Option<LaneDelivery<'_>> {
        self.delivering
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .ok()
            .map(|_| LaneDelivery { shared: self })
    }

    /// Whether the lane has the room the links ask for before each record, as its last holder
    /// left it, read without a hold.
    pub(crate) fn takes_a_link_read(&self) -> bool {
        self.reads.load(Ordering::Acquire)
    }

    /// Whether a sample was handed on that no delivery has taken yet. Read with the order the
    /// delivery word is let go with, so a delivery that lets go and reads it clear, and a hold that
    /// hands a sample on and then finds the word held, cannot both miss the sample.
    pub(crate) fn owes_a_delivery(&self) -> bool {
        self.lent_state.load(Ordering::SeqCst) == LENT_READY
            || self.handed_count.load(Ordering::SeqCst) != self.taken_count.load(Ordering::SeqCst)
    }

    /// Whether every sample handed on is done with: what a leg's end waits for, so that it is told
    /// after every reply queued before it.
    #[cfg(feature = "query")]
    pub(crate) fn is_idle(&self) -> bool {
        self.handed_count.load(Ordering::SeqCst) == self.done_count.load(Ordering::SeqCst)
    }

    /// Whether what is offered from here on is a record a link's gate let through
    /// ([`SampleLane::offering_gated`]), told without a hold.
    #[cfg(debug_assertions)]
    pub(crate) fn offering_gated(&self, gated: bool) {
        self.gated.store(gated, Ordering::Release);
    }

    /// How many samples were handed on since the lane was made, which the tests of the cost of
    /// one sample count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn handed_on(&self) -> usize {
        self.handed_count.load(Ordering::SeqCst)
    }

    /// The cell of event slot `index`.
    fn record_cell(&self, index: usize) -> &UnsafeCell<Option<Event>> {
        assert!(index < caps::DELIVERY_LANE_EVENTS, "a slot of the lane");
        // SAFETY: the lane's records are `DELIVERY_LANE_EVENTS` cells, which live as long as the
        // lane, and so as long as `self`.
        unsafe { &*self.records.as_ptr().add(index) }
    }
}

/// The lane held by the session ([`SharedLane::held`]). As it lets go it hands on what was
/// published under it and leaves the room the links ask for in the word the gates read.
pub(crate) struct LaneHeld<'a> {
    shared: &'a SharedLane,
}

impl Deref for LaneHeld<'_> {
    type Target = SampleLane;

    fn deref(&self) -> &SampleLane {
        // SAFETY: this is the lane's one hold (`SharedLane::held`).
        unsafe { &*self.shared.lane.get() }
    }
}

impl DerefMut for LaneHeld<'_> {
    fn deref_mut(&mut self) -> &mut SampleLane {
        // SAFETY: as `deref`.
        unsafe { &mut *self.shared.lane.get() }
    }
}

impl LaneHeld<'_> {
    /// Give back to the lane the slots and bytes of the samples the deliveries are done with, in
    /// the order they were handed on, which is the order of the lane's heads.
    fn take_back(&mut self) {
        let shared = self.shared;
        // SAFETY: the session's lock is held (`SharedLane::held`), under which every consumer of
        // `returned` takes it, the one before it having let go of the lock.
        let mut back = unsafe { shared.returned.consumer() };
        while back.try_pop().is_some() {
            self.complete();
        }
    }
}

impl LaneHeld<'_> {
    /// Queue `sample` for the callback of `subscriber`, or hand it to the callback where it lies:
    /// when every part of it but its key lies in the datagram a link lends the step now
    /// ([`SharedLane::set_lending`]), no delivery runs and nothing older waits, the sample is lent
    /// where it lies ([`LentSample`]), its key copied beside it, and the links are held back until
    /// a delivery has handed it to its callbacks and given it back. Any other sample, and every
    /// sample offered while one is lent, is written into the lane ([`SampleLane::offer`]).
    pub(crate) fn offer_sample(&mut self, subscriber: SubId, sample: &dyn SampleView) {
        let shared = self.shared;
        if shared.lent_state.load(Ordering::Relaxed) == LENT_OPEN {
            // SAFETY: an open lent sample is the lane's holder's until it is sealed.
            if let Some(lent) = unsafe { &mut *shared.lent.get() } {
                if lent.is(sample) {
                    lent.join(subscriber);
                    return;
                }
            }
            self.seal_lent();
        }
        if let Some(lent) = self.lends(subscriber, sample) {
            // SAFETY: the slot is free (`Self::lends`), and the lane's holder writes it.
            unsafe { *shared.lent.get() = Some(lent) };
            shared.lent_state.store(LENT_OPEN, Ordering::Relaxed);
            #[cfg(all(test, feature = "std"))]
            shared.lent_count.fetch_add(1, Ordering::SeqCst);
            return;
        }
        self.offer(subscriber, sample);
    }

    /// `sample` lent where it lies, for `subscriber`, when it may be (`Self::offer_sample`).
    fn lends(&self, subscriber: SubId, sample: &dyn SampleView) -> Option<LentSample> {
        let shared = self.shared;
        // SAFETY: written under the session's lock, under which this hold is.
        let (start, length) = unsafe { *shared.lending.get() }?;
        // A delivery running now may be the one this sample's own step runs inside of; what waits
        // in the lane is older and is handed first.
        if shared.lent_state.load(Ordering::Acquire) != LENT_FREE
            || shared.delivering.load(Ordering::SeqCst)
            || shared.owes_a_delivery()
            || self.open.is_some()
            || self.published.front().is_some()
        {
            return None;
        }
        #[cfg(feature = "local-subscriber")]
        if self.capturing.is_some() {
            return None;
        }
        let inside = |part: &[u8]| {
            let at = part.as_ptr() as usize;
            part.is_empty()
                || (at >= start && at - start <= length && part.len() <= length - (at - start))
        };
        let (record, [key, payload, attachment, schema, zid]) = Record::of(sample);
        if key.len() > caps::MAX_KEYEXPR_BYTES
            || ![payload, attachment, schema, zid].into_iter().all(inside)
        {
            return None;
        }
        let mut lent = LentSample {
            record,
            key: [0; caps::MAX_KEYEXPR_BYTES],
            key_len: key.len(),
            parts: [payload, attachment, schema, zid].map(|part| (part.as_ptr(), part.len())),
            subscribers: BoundedVec::new_static(),
        };
        lent.key[..key.len()].copy_from_slice(key);
        lent.join(subscriber);
        Some(lent)
    }

    /// Publish the sample lent where it lies, if one is open: no subscriber joins it after.
    fn seal_lent(&mut self) {
        let shared = self.shared;
        if shared.lent_state.load(Ordering::Relaxed) == LENT_OPEN {
            shared.lent_state.store(LENT_READY, Ordering::SeqCst);
        }
    }

    /// Publish what this hold leaves open: the sample lent where its datagram lies, and the sample
    /// the lane holds open for more subscribers. What every hold of the session's lock ends with.
    pub(crate) fn seal_all(&mut self) {
        self.seal_lent();
        self.seal();
    }
}

impl Drop for LaneHeld<'_> {
    fn drop(&mut self) {
        let shared = self.shared;
        // SAFETY: as `take_back`, for the producer of `handed`.
        let mut on = unsafe { shared.handed.producer() };
        while let Some((slot, offset)) = self.published.front() {
            let pushed = on.try_push(DeliveryLaneHandle { slot, offset });
            debug_assert!(
                pushed.is_ok(),
                "the delivery lane's queue holds every event slot of the lane"
            );
            if pushed.is_err() {
                break;
            }
            self.published.pop();
            let handed = shared.handed_count.load(Ordering::Relaxed).wrapping_add(1);
            shared.handed_count.store(handed, Ordering::SeqCst);
        }
        let reads = self.takes_a_link_read();
        shared.reads.store(reads, Ordering::Release);
    }
}

/// The deliveries' side of the lane, held by one delivery at a time ([`SharedLane::deliver`]).
pub(crate) struct LaneDelivery<'a> {
    shared: &'a SharedLane,
}

impl LaneDelivery<'_> {
    /// The oldest sample handed on, where its bytes lie, and the hold on it that gives it back
    /// when it drops; `None` when none waits.
    pub(crate) fn take(&self) -> Option<(LaneItem, HeldHead<'_>)> {
        loop {
            // SAFETY: this delivery holds `delivering`, so it is the one consumer of `handed`,
            // and the delivery before it let go of the word before this one's exchange took it.
            let handle = unsafe { self.shared.handed.consumer() }.try_pop()?;
            let taken = self
                .shared
                .taken_count
                .load(Ordering::Relaxed)
                .wrapping_add(1);
            self.shared.taken_count.store(taken, Ordering::SeqCst);
            let (slot, offset) = (usize::from(handle.slot), handle.offset as usize);
            let head = HeldHead {
                delivery: self,
                handle: Some(handle),
            };
            // SAFETY: the record was written before its handle was pushed, which the pop read in
            // the push's order, and the lane writes the slot again only once the handle is back.
            let Some(event) = (unsafe { (*self.shared.record_cell(slot).get()).take() }) else {
                // A handed slot always has its record; one without is given back at once.
                continue;
            };
            // SAFETY: the sample's bytes lie at `offset` inside the area (`DeliveryLane::reserve`).
            let base = unsafe { self.shared.area.as_ptr().add(offset) };
            return Some((LaneItem::of(event, base), head));
        }
    }

    /// The sample lent where its datagram lies, when one waits: handed first, as it is older than
    /// whatever was written into the lane while it waited.
    pub(crate) fn take_lent(&self) -> Option<LentHeld<'_>> {
        if self.shared.lent_state.load(Ordering::Acquire) != LENT_READY {
            return None;
        }
        self.shared
            .lent_state
            .store(LENT_DELIVERING, Ordering::Relaxed);
        // SAFETY: a published lent sample is the deliveries', and this delivery holds their side.
        let Some(lent) = (unsafe { (*self.shared.lent.get()).take() }) else {
            self.shared.lent_state.store(LENT_FREE, Ordering::Release);
            return None;
        };
        Some(LentHeld {
            shared: self.shared,
            lent,
        })
    }

    /// The callbacks of the sample of `handle` returned: it goes back to the session.
    fn give_back(&self, handle: DeliveryLaneHandle) {
        // SAFETY: this delivery holds `delivering`, so it is the one producer of `returned`.
        let back = unsafe { self.shared.returned.producer() }.try_push(handle);
        debug_assert!(
            back.is_ok(),
            "the delivery lane's queue holds every event slot of the lane"
        );
        #[cfg(feature = "query")]
        {
            let done = self
                .shared
                .done_count
                .load(Ordering::Relaxed)
                .wrapping_add(1);
            self.shared.done_count.store(done, Ordering::SeqCst);
        }
    }
}

impl Drop for LaneDelivery<'_> {
    fn drop(&mut self) {
        self.shared.delivering.store(false, Ordering::SeqCst);
    }
}

/// A sample handed to its subscribers' callbacks where the datagram it arrived in lies: its parts
/// are pointers into the datagram, which the link leaves where it lies while the sample is lent
/// (`SharedLane::lends_a_datagram`), and its key is copied beside them, since a key resolved from
/// an alias lies in a frame of the session's dispatch that is gone when the callbacks run.
pub(crate) struct LentSample {
    record: Record,
    key: [u8; caps::MAX_KEYEXPR_BYTES],
    key_len: usize,
    /// The payload, the attachment, the encoding's schema and the timestamp's id, where the
    /// datagram holds them.
    parts: [(*const u8, usize); 4],
    subscribers: BoundedVec<SubId, { caps::MAX_SUBSCRIPTIONS }, Static>,
}

impl LentSample {
    /// Whether `sample` is this one, offered for another subscriber: the same payload where it
    /// lies, on the same key.
    fn is(&self, sample: &dyn SampleView) -> bool {
        let payload = sample.payload();
        payload.as_ptr() == self.parts[0].0
            && payload.len() == self.parts[0].1
            && sample.keyexpr().as_bytes() == &self.key[..self.key_len]
    }

    /// One more subscriber is this sample's.
    fn join(&mut self, subscriber: SubId) {
        if self.subscribers.iter().any(|held| *held == subscriber) {
            return;
        }
        let kept = self.subscribers.push(subscriber);
        debug_assert!(
            kept.is_ok(),
            "a session's subscribers fit the table of them"
        );
    }

    /// The `at`th of its parts.
    fn part(&self, at: usize) -> &[u8] {
        let (start, length) = self.parts[at];
        if length == 0 {
            return &[];
        }
        // SAFETY: the part lies in the lent datagram, which the link leaves where it lies while
        // the sample is lent, and that outlasts every borrow of the sample.
        unsafe { core::slice::from_raw_parts(start, length) }
    }

    /// The subscribers whose callbacks it is for, in the order the session offered it to them.
    pub(crate) fn subscribers(&self) -> impl Iterator<Item = SubId> + '_ {
        self.subscribers.iter().copied()
    }
}

impl SampleView for LentSample {
    fn keyexpr(&self) -> &str {
        // SAFETY: the bytes were a `&str`'s (`SampleView::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.key[..self.key_len]) }
    }

    fn payload(&self) -> &[u8] {
        self.part(0)
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
        self.record.attachment.map(|_| self.part(1))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.record.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        self.record.timestamp.map(|(time, _)| (time, self.part(3)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.record
            .encoding
            .map(|(id, schema)| (id, schema.map(|_| self.part(2))))
    }
}

/// The sample lent where its datagram lies, held by the delivery that took it
/// ([`LaneDelivery::take_lent`]); the links are let read again when it drops.
pub(crate) struct LentHeld<'a> {
    shared: &'a SharedLane,
    lent: LentSample,
}

impl LentHeld<'_> {
    /// The sample.
    pub(crate) fn sample(&self) -> &LentSample {
        &self.lent
    }
}

impl Drop for LentHeld<'_> {
    fn drop(&mut self) {
        self.shared.lent_state.store(LENT_FREE, Ordering::Release);
    }
}

/// A sample a delivery took ([`LaneDelivery::take`]), given back when its callbacks have
/// returned, or one unwinds.
pub(crate) struct HeldHead<'d> {
    delivery: &'d LaneDelivery<'d>,
    handle: Option<DeliveryLaneHandle>,
}

impl Drop for HeldHead<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.delivery.give_back(handle);
        }
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
    /// A reply, for the callback of the leg it answers.
    #[cfg(feature = "query")]
    Reply(LaneReply),
}

impl LaneItem {
    /// What `event` is for its callbacks, its bytes at `base`.
    fn of(event: Event, base: *const u8) -> Self {
        match event {
            Event::Sample {
                record,
                subscribers,
            } => Self::Sample(LaneSample {
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
            } => Self::Liveliness(LaneLiveliness {
                kind,
                key,
                token_id,
                subscribers,
                base,
            }),
            #[cfg(feature = "query")]
            Event::Reply(record) => Self::Reply(LaneReply { record, base }),
        }
    }
}

/// A reply at the head of the lane, where its bytes lie: what its leg's callback is handed. Valid
/// until the delivery that took it completes it.
#[cfg(feature = "query")]
pub(crate) struct LaneReply {
    record: ReplyRecord,
    base: *const u8,
}

#[cfg(feature = "query")]
impl LaneReply {
    /// The leg of the get it answers.
    pub(crate) fn leg(&self) -> u64 {
        self.record.leg
    }

    /// The `len` bytes `skip` bytes into the reply.
    fn part(&self, skip: usize, len: usize) -> &[u8] {
        // SAFETY: the reply's parts were written one after the other from `base`
        // (`SampleLane::offer_reply`), and the head's bytes are not written again until the
        // delivery that holds it completes it, which is after this view is gone.
        unsafe { core::slice::from_raw_parts(self.base.add(skip), len) }
    }

    /// The schema of its encoding, of the kind `kind` is.
    fn encoding_of(&self, kind: ReplyKind) -> Option<(u32, Option<&[u8]>)> {
        if self.record.kind != kind {
            return None;
        }
        self.record.encoding.map(|(id, schema)| {
            (
                id,
                schema.map(|len| self.part(self.record.after_attachment(), len)),
            )
        })
    }
}

#[cfg(feature = "query")]
impl ReplyView for LaneReply {
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.record.rid
    }

    fn keyexpr(&self) -> &str {
        // SAFETY: the bytes were a `&str`'s (`ReplyView::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.part(0, self.record.key)) }
    }

    fn kind(&self) -> ReplyKind {
        self.record.kind
    }

    fn payload(&self) -> &[u8] {
        self.part(self.record.key, self.record.payload)
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Err)
    }

    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Put)
    }

    fn attachment(&self) -> Option<&[u8]> {
        self.record
            .attachment
            .map(|len| self.part(self.record.after_payload(), len))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.record.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<wz_session_core::reply_stage::TimestampParts<'_>> {
        self.record
            .timestamp
            .map(|(time, zid)| wz_session_core::reply_stage::TimestampParts {
                time,
                zid: self.part(self.record.after_schema(), zid),
            })
    }

    fn responder(&self) -> Option<(&[u8], u32)> {
        self.record
            .responder
            .map(|(zid, eid)| (self.part(self.record.after_timestamp(), zid), eid))
    }

    fn qos(&self) -> Option<QosLevel> {
        self.record.qos
    }
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

    /// Whether no change is owed.
    pub(crate) fn is_empty(&self) -> bool {
        self.flips.is_empty()
    }
}

/// The group twin of [`LaneGate`]: whether the lane has the room one record of a group can take
/// (`room`, decision Q4), asked before each datagram of the group and before each further message
/// and record of one its transport keeps. While it has not, what the members send waits in the
/// group's socket. A group's record does not claim that room as a link's does (a debug build's
/// `SampleLane::offering_gated`): the room of a group's batch is not one the lane is lengthened
/// to hold.
///
/// # Safety
/// The gate it answers is asked by the session's step alone, under the session's lock, as the
/// group's transport is driven.
#[cfg(feature = "group")]
pub(crate) unsafe fn takes_a_group_read(
    lane: Arc<SharedLane>,
    room: ReadRoom,
) -> impl Fn() -> bool + 'static {
    // SAFETY: the caller's contract: the session's lock is held whenever this is asked.
    move || unsafe { lane.held() }.takes_a_read(room)
}

/// `pump`, which gives the session nothing while the lane has not the room one record can take
/// (`room`, decision Q4): not the next datagram, and not the next record of one the link keeps.
/// What the peer sends meanwhile waits in the link, and the transport's flow control carries the
/// wait back to it. The gate is asked before every datagram and every further record, so it reads
/// the room from the word the lane's holder leaves ([`SharedLane::takes_a_link_read`]) and takes
/// no lock; only when the word says no room does it hold the lane, to take back what the
/// deliveries have given back since, which it may: it is asked under the session's lock.
pub(crate) struct LaneGate<P> {
    pump: P,
    lane: Arc<SharedLane>,
}

impl<P> LaneGate<P> {
    /// `pump`, gated by `lane` for the room `room` of one of its records, which the lane is told
    /// once here.
    ///
    /// # Safety
    /// Made under the session's lock, and asked by the session's step alone, which holds it.
    pub(crate) unsafe fn new(pump: P, lane: Arc<SharedLane>, room: ReadRoom) -> Self {
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { lane.held() }.gate_links(room);
        Self { pump, lane }
    }

    /// Whether the link's input is held back: the lane has not the room of a record, once what
    /// the deliveries gave back is taken back.
    fn shut(&self) -> bool {
        if self.lane.lends_a_datagram() {
            return true;
        }
        if self.lane.takes_a_link_read() {
            return false;
        }
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        !unsafe { self.lane.held() }.takes_a_link_read()
    }
}

impl<P: SessionDatagramLink> SessionDatagramLink for LaneGate<P> {
    /// A link whose datagram a sample is lent from is not serviced: its stack may read the next
    /// datagram into the buffer the sample lies in.
    fn service(&self) {
        if !self.lane.lends_a_datagram() {
            self.pump.service()
        }
    }

    fn service_within(&self, max_wait_ms: u64) {
        if !self.lane.lends_a_datagram() {
            self.pump.service_within(max_wait_ms)
        }
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

    /// The datagram is lent to the session's step; a link that leaves it where it lies until it
    /// is next asked to receive tells the lane where it lies while it is lent, so a sample of it
    /// may be handed to its callback there (`LaneHeld::offer_sample`).
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.shut() {
            return false;
        }
        if !self.pump.lends_until_next_receive() {
            return self.pump.recv_with(f);
        }
        self.pump.recv_with(&mut |datagram: &[u8]| {
            // SAFETY: a link's gate is asked by the session's step alone, under the session's
            // lock (`Self::new`), and the link leaves the bytes where they lie until it is next
            // asked to receive or to be serviced, which it is not while a sample is lent.
            unsafe { self.lane.set_lending(Some(datagram)) };
            f(datagram);
            // SAFETY: as above.
            unsafe { self.lane.set_lending(None) };
        })
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
