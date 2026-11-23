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
//! # The samples of a lent batch
//!
//! A link whose receive buffer holds what it lent until its next receive (UDP, a stream) lets the
//! session's samples be read there. The samples of one datagram, a batch of a stream, whose parts
//! lie in it are one record of the lane ([`BatchRecord`]): one event slot, one hand-on and one
//! give-back for the batch, its bytes an entry a sample ([`EntryHead`]) that says where the
//! sample's parts lie in the datagram and is followed by the ids of its subscribers. A key that lies
//! elsewhere (resolved from an alias, in a frame of the dispatch) is written once for the samples
//! on it that follow one another. The delivery walks the entries and hands each sample to its
//! subscribers' callbacks from a view built where its entry lies ([`BatchSample`]), in the order
//! the samples came; the link is held back from its next receive until the batch is given back
//! after its last callback ([`SharedLane::lends_a_datagram`]). A sample offered while a delivery
//! runs, or with a part outside the datagram, is written into the lane whole as a record of its
//! own, after the batch before it.
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
//! gate is asked before each record and not only before each datagram. A batch takes one event
//! slot for all of its samples and grows by an entry a record, no longer than the room asked
//! (`read_bytes`), so the samples one read hands on are bounded by the lane's bytes and its
//! callbacks owed and not by its event slots; the gate still asks for the slot a record written
//! whole would take. Any other sample that finds no room is dropped and counted
//! ([`LaneCounts::dropped`]). A sample that holds its sender and still finds no room is refused
//! and counted apart ([`LaneCounts::held_over`]), as the session core's lane answers such a
//! sample with a local resource limit (`delivery_lane::Overload`) and not with a silent loss: a
//! defect for a record the gate let through, which a debug build stops at, and for the session's
//! own puts, which wait for no room, a count.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, addr_of_mut, NonNull};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

#[cfg(feature = "liveliness")]
use crate::engine::LivelinessCallback;
use crate::engine::SubscriberCallback;
use crate::prelude::*;
#[cfg(feature = "query")]
use wz_capi_port::ReplyCallback;

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
/// batch or a rejoined message, and its sample adds to it at most [`sample_overhead`]. A sample of
/// a lent batch writes its entry ([`ENTRY_BYTES`]) where a sample written whole writes its
/// message, so a message shorter than an entry is counted as long as one.
pub(crate) const fn read_bytes(batch: usize, frag: usize, key: usize, subscribers: usize) -> usize {
    let message = if batch > frag { batch } else { frag };
    let message = if ENTRY_BYTES > message {
        ENTRY_BYTES
    } else {
        message
    };
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
    /// The samples of a datagram a link lent the step, read where they lie; its bytes are an
    /// entry a sample.
    Batch(BatchRecord),
}

impl Event {
    /// Whether its samples lie in the datagram a link lent the step it was written in
    /// ([`BatchRecord`]), which the link is then held back for until it is given back.
    fn lies(&self) -> bool {
        matches!(self, Self::Batch(_))
    }

    /// How many samples lying in their datagram it holds, which the tests count.
    #[cfg(all(test, feature = "std"))]
    fn lying(&self) -> usize {
        match self {
            Self::Batch(batch) => batch.samples,
            _ => 0,
        }
    }

    /// The callbacks it owes: one for each subscriber it is for, of each of its samples.
    fn subscribers(&self) -> usize {
        match self {
            Self::Sample { subscribers, .. } => *subscribers,
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => *subscribers,
            #[cfg(feature = "query")]
            Self::Reply(_) => 1,
            Self::Batch(batch) => batch.callbacks,
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
            // A subscriber joins a batch's sample in its entry (`SampleLane::join_batch`).
            Self::Batch(_) => {}
        }
    }

    /// The callbacks it owes, and of those the ones whose samples hold their sender. A token is
    /// declared and retracted by a declaration, which does.
    fn owed(&self) -> (usize, usize) {
        match self {
            Self::Sample {
                record,
                subscribers,
            } => {
                let held = if record.holds_sender() {
                    *subscribers
                } else {
                    0
                };
                (*subscribers, held)
            }
            #[cfg(feature = "liveliness")]
            Self::Liveliness { subscribers, .. } => (*subscribers, *subscribers),
            // A reply is the answer a get waits for; its loss is not the sender's to choose.
            #[cfg(feature = "query")]
            Self::Reply(_) => (1, 1),
            Self::Batch(batch) => (batch.callbacks, batch.held),
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

    /// Whether the sample's congestion control holds its sender ([`holds_its_sender`]).
    fn holds_sender(&self) -> bool {
        holds_its_sender(self.reliability, self.qos)
    }
}

/// Whether a sample sent with `reliability` and `qos` holds its sender: sent reliably, with
/// `block` or `block-first`. A sample that states no QoS has zenoh's default, `drop`.
fn holds_its_sender(reliability: Reliability, qos: Option<QosLevel>) -> bool {
    reliability == Reliability::Reliable
        && qos.is_some_and(|qos| qos.congestion() != CongestionControl::Drop)
}

/// A part of a sample of a batch ([`BatchRecord`]): where it starts, from the first byte of the
/// datagram it lies in or of the batch's own bytes, and how long it is.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Span {
    at: u32,
    len: u32,
}

impl Span {
    /// An empty part, which lies anywhere.
    const EMPTY: Self = Self { at: 0, len: 0 };

    /// Where `part` lies in `datagram`, its first byte and its length; `None` when it lies
    /// elsewhere.
    fn of(part: &[u8], (start, length): (*const u8, usize)) -> Option<Self> {
        if part.is_empty() {
            return Some(Self::EMPTY);
        }
        let at = (part.as_ptr() as usize).checked_sub(start as usize)?;
        if at > length || part.len() > length - at {
            return None;
        }
        Some(Self {
            at: u32::try_from(at).ok()?,
            len: u32::try_from(part.len()).ok()?,
        })
    }

    fn first(self) -> usize {
        self.at as usize
    }

    fn bytes(self) -> usize {
        self.len as usize
    }
}

/// Where the key of a sample of a batch lies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyAt {
    /// In the datagram, with the sample's other parts.
    Lent(Span),
    /// In the batch's own bytes: a key the session resolved from an alias lies in a frame of the
    /// dispatch, gone when the callbacks run. Written once for the samples on it that follow one
    /// another.
    Written(Span),
}

/// A sample of a batch as the lane writes it ([`BatchRecord`]): what it is besides its bytes,
/// where its key and its payload lie, and how many subscribers it is for. Its [`EntryRest`]
/// follows it when the sample carries more, then its key when the batch had not written it for
/// the sample before, then the ids of its subscribers. Written and read unaligned, as the lane's
/// area is bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EntryHead {
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    key: KeyAt,
    payload: Span,
    /// Whether an [`EntryRest`] follows it.
    rest: bool,
    /// The bytes of its key written after it.
    written: u32,
    subscribers: u32,
}

impl EntryHead {
    /// Whether `other` has its kind, reliability, QoS and payload where it has them: with an equal
    /// key and an equal rest, the one sample.
    fn same_sample(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.reliability == other.reliability
            && self.qos == other.qos
            && self.payload == other.payload
            && self.rest == other.rest
    }
}

/// What a sample of a batch carries beyond its key and its payload, written after its
/// [`EntryHead`] only when it carries any of it.
#[derive(Clone, PartialEq)]
struct EntryRest {
    attachment: Option<Span>,
    /// The packed id, and where the schema lies when there is one.
    encoding: Option<(u32, Option<Span>)>,
    /// The time word, and where the id prefix lies.
    timestamp: Option<(u64, Span)>,
    source_info: Option<SourceInfo>,
}

// An entry's head and rest are written into the lane's bytes as values and read back as copies,
// and never dropped there: neither may own what a drop gives back.
const _: () = assert!(
    !core::mem::needs_drop::<EntryHead>() && !core::mem::needs_drop::<EntryRest>(),
    "a batch's entries are plain values in the lane's bytes"
);

/// The bytes of an entry's head.
const HEAD_BYTES: usize = core::mem::size_of::<EntryHead>();

/// The bytes of an entry's rest.
const REST_BYTES: usize = core::mem::size_of::<EntryRest>();

/// The most bytes a sample of a batch writes into the lane besides its key and its subscribers'
/// ids: its entry's head and rest.
pub(crate) const ENTRY_BYTES: usize = HEAD_BYTES + REST_BYTES;

/// The samples of one datagram a link lent the step, read where they lie: one record of the lane
/// for all of them, whose bytes are an entry a sample ([`EntryHead`]), one after the other. Written
/// as the datagram is walked and published when the walk ends (`LaneGate::recv_with`); the link
/// is held back from its next receive until the delivery gives the batch back.
#[derive(Clone, Copy)]
struct BatchRecord {
    /// The datagram's first byte and its length.
    datagram: (*const u8, usize),
    /// Its samples, the callbacks they owe, and of those the ones whose samples hold their sender.
    samples: usize,
    callbacks: usize,
    held: usize,
    /// Where its last sample's entry starts, from the batch's first byte.
    last: usize,
    /// The key it wrote last, which the samples on it that follow share.
    key: Option<Span>,
}

/// A sample of the datagram a link lends the step, for one subscriber, as an entry of the
/// datagram's batch holds it.
struct LentEntry<'s> {
    subscriber: SubId,
    head: EntryHead,
    rest: Option<EntryRest>,
    /// The key, when it lies outside the datagram; the head's is then a placeholder until the
    /// entry is written.
    key: Option<&'s [u8]>,
    holds_sender: bool,
}

impl<'s> LentEntry<'s> {
    /// `sample`, for `subscriber`, as it lies in `datagram`, its first byte and its length;
    /// `None` when a part of it other than its key lies elsewhere.
    fn of(
        subscriber: SubId,
        sample: &'s dyn SampleView,
        datagram: (*const u8, usize),
    ) -> Option<Self> {
        let payload = Span::of(sample.payload(), datagram)?;
        let attachment = match sample.attachment() {
            Some(part) => Some(Span::of(part, datagram)?),
            None => None,
        };
        let encoding = match encoding_of(sample) {
            Some((id, Some(schema))) => Some((id, Some(Span::of(schema, datagram)?))),
            Some((id, None)) => Some((id, None)),
            None => None,
        };
        let timestamp = match timestamp_of(sample) {
            Some((time, zid)) => Some((time, Span::of(zid, datagram)?)),
            None => None,
        };
        let source_info = sample.source_info().cloned();
        let key = sample.keyexpr().as_bytes();
        let (at, outside) = match Span::of(key, datagram) {
            Some(span) => (KeyAt::Lent(span), None),
            None => (KeyAt::Lent(Span::EMPTY), Some(key)),
        };
        let carries = attachment.is_some()
            || encoding.is_some()
            || timestamp.is_some()
            || source_info.is_some();
        let rest = if carries {
            Some(EntryRest {
                attachment,
                encoding,
                timestamp,
                source_info,
            })
        } else {
            None
        };
        let (reliability, qos) = (sample.reliability(), sample.qos());
        Some(Self {
            subscriber,
            head: EntryHead {
                kind: sample.kind(),
                reliability,
                qos,
                key: at,
                payload,
                rest: carries,
                written: 0,
                subscribers: 1,
            },
            rest,
            key: outside,
            holds_sender: holds_its_sender(reliability, qos),
        })
    }

    /// The bytes its entry takes, its key among them unless the batch wrote it already
    /// (`shared`).
    fn bytes(&self, shared: bool) -> usize {
        let rest = if self.rest.is_some() { REST_BYTES } else { 0 };
        let key = match self.key {
            Some(key) if !shared => key.len(),
            _ => 0,
        };
        HEAD_BYTES + rest + key + SUBSCRIBER_ID_BYTES
    }
}

/// The event slots a lane holds: the length of its records and of its published list, storage
/// only the build sizes; a session's limits hold the lane to fewer of them (`with_limits`).
const LANE_SLOTS: usize = caps::DELIVERY_LANE_EVENTS;

/// What waits at each event slot of the lane besides its bytes, a cell for each slot, reached
/// through a pointer as the area is: the lane's holder writes a slot while it writes the sample
/// there, and the one delivery a sample is handed to takes it ([`SharedLane`]), so a hold of the
/// lane is not a hold of a slot a delivery reads.
struct Records(NonNull<UnsafeCell<Option<Event>>>);

impl Records {
    fn new() -> Self {
        let cells: Box<[UnsafeCell<Option<Event>>]> =
            (0..LANE_SLOTS).map(|_| UnsafeCell::new(None)).collect();
        let first = Box::into_raw(cells).cast::<UnsafeCell<Option<Event>>>();
        // SAFETY: the pointer of a box is never null.
        Self(unsafe { NonNull::new_unchecked(first) })
    }

    /// The cell of event slot `index`.
    fn cell(&self, index: usize) -> &UnsafeCell<Option<Event>> {
        assert!(index < LANE_SLOTS, "a slot of the lane");
        // SAFETY: the cells are `DELIVERY_LANE_EVENTS`, this one's until it drops.
        unsafe { &*self.0.as_ptr().add(index) }
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        let cells = core::ptr::slice_from_raw_parts_mut(self.0.as_ptr(), LANE_SLOTS);
        // SAFETY: the box `Records::new` made, of `LANE_SLOTS` cells, given back once.
        drop(unsafe { Box::from_raw(cells) });
    }
}

/// The samples a lane published and has not handed on to its deliveries, oldest first: the event
/// slot of each and where its bytes start. Published in the order their slots were taken, so the
/// front is the oldest of the lane's heads not handed on.
struct Published {
    entries: [(u16, u32); LANE_SLOTS],
    head: usize,
    len: usize,
}

impl Published {
    /// The sample at event slot `index`, its bytes at `offset`, was published.
    fn push(&mut self, index: usize, offset: usize) {
        debug_assert!(
            self.len < LANE_SLOTS,
            "a published sample holds a slot of the lane"
        );
        let at = (self.head + self.len) % LANE_SLOTS;
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
            self.head = (self.head + 1) % LANE_SLOTS;
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
    counts: LaneCounts,
}

// SAFETY: the area and the records are the lane's alone for the life of the session, reached by the
// lane's holder, or by the one delivery a sample is handed to (`SharedLane`), which reads that
// sample's bytes and takes its record alone, which nothing writes until the sample is given back.
unsafe impl Send for SampleLane {}

impl SampleLane {
    /// [`Self::over_in`] as a value, for the tests that hold a lane of their own.
    ///
    /// # Safety
    /// As [`Self::over_in`]'s.
    #[cfg(all(test, feature = "std"))]
    pub(crate) unsafe fn over(
        area: NonNull<u8>,
        area_bytes: usize,
        limits: &SessionLimits,
    ) -> Self {
        let mut place = MaybeUninit::uninit();
        // SAFETY: the caller's, which are `over_in`'s; `over_in` wrote every field into `place`.
        unsafe {
            Self::over_in(&mut place, area, area_bytes, limits);
            place.assume_init()
        }
    }

    /// A lane over the `area_bytes` bytes at `area`, held to `limits`, written field by field into
    /// `place`, which is overwritten without dropping what it held: the records are cells on the
    /// heap, each written empty where it lies (`Records::new`), and the published list is written
    /// entry by entry, so neither is ever an array of its own on a stack. Not inlined: the largest
    /// value its frame holds is the lane's bookkeeping.
    ///
    /// # Safety
    /// `area` points at `area_bytes` bytes valid for reads and writes, used by nothing else, for
    /// as long as the lane is used; `area_bytes` is `limits`' `DELIVERY_LANE_BYTES`.
    #[inline(never)]
    pub(crate) unsafe fn over_in<'p>(
        place: &'p mut MaybeUninit<Self>,
        area: NonNull<u8>,
        area_bytes: usize,
        limits: &SessionLimits,
    ) -> &'p mut Self {
        debug_assert_eq!(area_bytes, limits.delivery_lane_bytes());
        let at = place.as_mut_ptr();
        // Each gated statement opens with the path `ptr::write(`, not with the `addr_of_mut!`
        // macro, as `SlotObserverOf::init_in_place` says why.
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it, the published entries one by one (an array's first element is at its
        // address);
        // `every_field_is_written` names every field, so the lane is whole when it is lent.
        unsafe {
            ptr::write(addr_of_mut!((*at).lane), DeliveryLane::with_limits(limits));
            // The records are cells on the heap, each written empty where it lies
            // (`Records::new`); the published list is written entry by entry.
            ptr::write(addr_of_mut!((*at).records), Records::new());
            let published = addr_of_mut!((*at).published);
            let entries = addr_of_mut!((*published).entries).cast::<(u16, u32)>();
            for slot in 0..LANE_SLOTS {
                ptr::write(entries.add(slot), (0, 0));
            }
            ptr::write(addr_of_mut!((*published).head), 0);
            ptr::write(addr_of_mut!((*published).len), 0);
            ptr::write(addr_of_mut!((*at).area), area);
            ptr::write(addr_of_mut!((*at).open), None);
            #[cfg(all(test, feature = "std"))]
            ptr::write(addr_of_mut!((*at).handing), false);
            ptr::write(addr_of_mut!((*at).link_room), None);
            #[cfg(debug_assertions)]
            ptr::write(addr_of_mut!((*at).gated), false);
            ptr::write(addr_of_mut!((*at).counts), LaneCounts::default());
            &mut *at
        }
    }

    /// A field added to [`SampleLane`] and not written by [`Self::over_in`] would be read
    /// uninitialised. This destructures the lane with no `..`, so adding a field without naming it
    /// here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(lane: Self) {
        let Self {
            lane: _,
            records: _,
            published: _,
            area: _,
            open: _,
            #[cfg(all(test, feature = "std"))]
                handing: _,
            link_room: _,
            #[cfg(debug_assertions)]
                gated: _,
            counts: _,
        } = lane;
    }

    /// Queue `sample` for the callback of `subscriber`, or count it when the lane has no room
    /// for it. The sample the lane holds open, offered again for a subscriber it is not for yet,
    /// is not written again: the subscriber's id joins the ones that follow it.
    pub(crate) fn offer(&mut self, subscriber: SubId, sample: &dyn SampleView) {
        let (record, parts) = Record::of(sample);
        let same =
            |event: &Event| matches!(event, Event::Sample { record: held, .. } if *held == record);
        if self.join_open(subscriber, &parts, same, record.holds_sender()) {
            return;
        }
        self.open_sample(&[subscriber], record, &parts);
    }

    /// [`Self::offer`] for a sample of the datagram a link lends the step, `datagram` its first
    /// byte and its length: an entry of the datagram's batch ([`BatchRecord`]) when every part of
    /// it but its key lies there, and otherwise written whole, after the batch before it.
    fn offer_lent(
        &mut self,
        subscriber: SubId,
        sample: &dyn SampleView,
        datagram: (*const u8, usize),
    ) {
        let Some(lent) = LentEntry::of(subscriber, sample, datagram) else {
            self.offer(subscriber, sample);
            return;
        };
        if !self.join_batch(&lent, datagram) {
            self.append_batch(&lent, datagram);
        }
    }

    /// Add `lent`'s subscriber to the last sample of the batch of `datagram` held open, when
    /// `lent` is that sample and it is not for that subscriber already: `true` when the offer is
    /// answered so, the id written after the others, or counted when the callbacks owed are full.
    /// `false` leaves the offer to an entry of its own, as [`Self::join_open`] leaves a sample
    /// written whole.
    fn join_batch(&mut self, lent: &LentEntry<'_>, datagram: (*const u8, usize)) -> bool {
        let Some(mut open) = self.open.take() else {
            return false;
        };
        let joined = self.join_last(&mut open, lent, datagram);
        self.open = Some(open);
        joined
    }

    /// [`Self::join_batch`] for the record held `open`.
    fn join_last(
        &mut self,
        open: &mut Reservation,
        lent: &LentEntry<'_>,
        datagram: (*const u8, usize),
    ) -> bool {
        let Some(mut batch) = self.batch_at(open, datagram) else {
            return false;
        };
        if batch.samples == 0 {
            return false;
        }
        let entry = open.offset() + batch.last;
        // SAFETY: the batch's last entry starts there, written by `Self::write_entry`.
        let mut head: EntryHead = unsafe { self.entry_value(entry) };
        if !head.same_sample(&lent.head) {
            return false;
        }
        let same_key = match (head.key, lent.key) {
            (KeyAt::Lent(_), None) => head.key == lent.head.key,
            (KeyAt::Written(span), Some(key)) => {
                self.area_bytes(open.offset() + span.first(), span.bytes()) == key
            }
            _ => false,
        };
        if !same_key {
            return false;
        }
        let mut ids = entry + HEAD_BYTES;
        if head.rest {
            // SAFETY: an entry whose head says so has its rest right after the head.
            let held: EntryRest = unsafe { self.entry_value(ids) };
            if lent.rest.as_ref() != Some(&held) {
                return false;
            }
            ids += REST_BYTES;
        }
        ids += head.written as usize;
        let id = lent.subscriber.to_ne_bytes();
        if self
            .area_bytes(ids, head.subscribers as usize * SUBSCRIBER_ID_BYTES)
            .chunks_exact(SUBSCRIBER_ID_BYTES)
            .any(|other| *other == id[..])
        {
            return false;
        }
        if !self.lane.admits_callbacks(batch.callbacks + 1) {
            self.count_refused(lent.holds_sender);
            return true;
        }
        // The last entry's ids are the last bytes of the batch, so the new one follows them.
        let at = open.offset() + open.bytes();
        if !self.lane.extend(open, SUBSCRIBER_ID_BYTES) {
            return false;
        }
        self.put(at, &id);
        head.subscribers += 1;
        self.put_value(entry, head);
        batch.callbacks += 1;
        batch.held += usize::from(lent.holds_sender);
        self.update_batch(open.index(), batch);
        true
    }

    /// Write `lent` as the next entry of the batch of `datagram` held open, or as the first of a
    /// batch of its own when none is or the area has no room after it, the record held open
    /// published first; or count it when the lane has no room for it.
    fn append_batch(&mut self, lent: &LentEntry<'_>, datagram: (*const u8, usize)) {
        if let Some(mut open) = self.open.take() {
            if let Some(mut batch) = self.batch_at(&open, datagram) {
                if !self.lane.admits_callbacks(batch.callbacks + 1) {
                    self.open = Some(open);
                    self.count_refused(lent.holds_sender);
                    return;
                }
                let shared = self.shared_key(&open, &batch, lent);
                let at = open.bytes();
                if self.lane.extend(&mut open, lent.bytes(shared.is_some())) {
                    self.write_entry(open.offset(), at, &mut batch, lent, shared);
                    self.update_batch(open.index(), batch);
                    self.open = Some(open);
                    return;
                }
            }
            self.open = Some(open);
        }
        self.seal();
        if !self.lane.admits_callbacks(1) {
            self.count_refused(lent.holds_sender);
            return;
        }
        let Ok(open) = self.lane.reserve(lent.bytes(false)) else {
            self.count_refused(lent.holds_sender);
            return;
        };
        let mut batch = BatchRecord {
            datagram,
            samples: 0,
            callbacks: 0,
            held: 0,
            last: 0,
            key: None,
        };
        self.write_entry(open.offset(), 0, &mut batch, lent, None);
        self.set_record(open.index(), Some(Event::Batch(batch)));
        self.open = Some(open);
    }

    /// Write `batch` over the batch at event slot `index` where it lies: an entry a sample
    /// rewrites the batch's counts, and not the whole event its slot is sized for.
    fn update_batch(&mut self, index: usize, batch: BatchRecord) {
        if let Some(Event::Batch(held)) = self.record_mut(index) {
            *held = batch;
        }
    }

    /// The batch of `datagram` at the record held `open`, when it is one.
    fn batch_at(&self, open: &Reservation, datagram: (*const u8, usize)) -> Option<BatchRecord> {
        match self.record(open.index()) {
            Some(Event::Batch(batch)) if batch.datagram == datagram => Some(*batch),
            _ => None,
        }
    }

    /// Where `batch`, held `open`, wrote the key it wrote last, when `lent`'s key lies outside
    /// its datagram and is that key.
    fn shared_key(
        &self,
        open: &Reservation,
        batch: &BatchRecord,
        lent: &LentEntry<'_>,
    ) -> Option<Span> {
        let (key, span) = (lent.key?, batch.key?);
        (self.area_bytes(open.offset() + span.first(), span.bytes()) == key).then_some(span)
    }

    /// Write `lent`'s entry `at` bytes into `batch`, whose bytes start at `base` in the area:
    /// its head, its rest, its key unless the batch wrote it already (`shared`), and its
    /// subscriber's id, the last bytes of the batch.
    fn write_entry(
        &mut self,
        base: usize,
        at: usize,
        batch: &mut BatchRecord,
        lent: &LentEntry<'_>,
        shared: Option<Span>,
    ) {
        let mut head = lent.head;
        let mut after = at + HEAD_BYTES;
        if let Some(rest) = &lent.rest {
            self.put_value(base + after, rest.clone());
            after += REST_BYTES;
        }
        if let Some(key) = lent.key {
            let span = match shared {
                Some(span) => span,
                None => {
                    self.put(base + after, key);
                    let span = Span {
                        at: after as u32,
                        len: key.len() as u32,
                    };
                    after += key.len();
                    head.written = span.len;
                    batch.key = Some(span);
                    span
                }
            };
            head.key = KeyAt::Written(span);
        }
        self.put(base + after, &lent.subscriber.to_ne_bytes());
        self.put_value(base + at, head);
        batch.last = at;
        batch.samples += 1;
        batch.callbacks += 1;
        batch.held += usize::from(lent.holds_sender);
    }

    /// Write `value` into the area from `at`, inside the reservation of the record being written,
    /// as [`Self::put`] writes bytes: an entry's head or rest, read back where it lies.
    fn put_value<T>(&mut self, at: usize, value: T) {
        let inside = at
            .checked_add(core::mem::size_of::<T>())
            .is_some_and(|end| self.lane.can_ever_fit(end));
        assert!(inside, "a batch's entry lies inside the lane's area");
        // SAFETY: inside the area (asserted above), which is this lane's alone
        // (`Self::over_in`); written unaligned, as the area is bytes.
        unsafe { ptr::write_unaligned(self.area.as_ptr().add(at).cast::<T>(), value) };
    }

    /// The `T` written at `at` in the area.
    ///
    /// # Safety
    /// [`Self::put_value`] wrote a `T` there, in the record held open.
    unsafe fn entry_value<T>(&self, at: usize) -> T {
        let inside = at
            .checked_add(core::mem::size_of::<T>())
            .is_some_and(|end| self.lane.can_ever_fit(end));
        assert!(inside, "a batch's entry lies inside the lane's area");
        // SAFETY: inside the area (asserted above), and a `T` lies there (the caller's).
        unsafe { ptr::read_unaligned(self.area.as_ptr().add(at).cast::<T>()) }
    }

    /// The `len` bytes at `at` in the area, written as bytes ([`Self::put`]) for the record
    /// held open.
    fn area_bytes(&self, at: usize, len: usize) -> &[u8] {
        let inside = at
            .checked_add(len)
            .is_some_and(|end| self.lane.can_ever_fit(end));
        assert!(inside, "a batch's bytes lie inside the lane's area");
        // SAFETY: inside the area (asserted above), written by `Self::put` for the record held
        // open, which nothing else writes while it is held open.
        unsafe { core::slice::from_raw_parts(self.area.as_ptr().add(at), len) }
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
        let (callbacks, held) = self.record(index).map_or((0, 0), Event::owed);
        // Its callbacks were admitted one by one as it was written, so only a lane that stops
        // refuses it, and then every subscriber it was for goes without.
        if self.lane.publish(open, callbacks).is_err() {
            self.set_record(index, None);
            for at in 0..callbacks {
                self.count_refused(at < held);
            }
        } else if callbacks > 0 {
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
        // SAFETY: inside the area (asserted above), which is this lane's alone (`Self::over_in`);
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

    /// Whether the lane has the room the links ask for at present: `true` before a link asked.
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

/// The callbacks one sample owes at most: one for each subscriber of the session, and no more than
/// the pending table holds.
const SAMPLE_CALLBACKS: usize =
    least::<{ caps::MAX_SUBSCRIPTIONS }, { caps::DELIVERY_LANE_CALLBACKS }>();

/// The lesser of two capacities the build sizes.
const fn least<const A: usize, const B: usize>() -> usize {
    if A < B {
        A
    } else {
        B
    }
}

/// The bytes of the keys the pending table writes, for a key of `KEY` bytes at most: a key the
/// session resolved from an alias lies in a frame of the dispatch, gone when the callbacks run.
const fn pending_key_bytes<const KEY: usize>() -> usize {
    KEY.saturating_mul(2)
}

/// The pending table holds nothing; the session may write it.
const EMPTY: u8 = 0;
/// The session writes the samples of the datagram a link lends its step now.
const FILLING: u8 = 1;
/// The samples wait for their callbacks; nothing joins them.
const SEALED: u8 = 2;
/// A delivery hands them to their callbacks.
const DELIVERING: u8 = 3;

/// A record of the pending table: what it is, where its parts lie, and the place of its first
/// callback.
struct PendingEntry {
    what: Pended,
    first: usize,
}

impl PendingEntry {
    /// The callbacks it owes, from `first` on.
    fn owed(&self) -> usize {
        match &self.what {
            Pended::Sample { head, .. } => head.subscribers as usize,
            #[cfg(feature = "liveliness")]
            Pended::Liveliness { owed, .. } => *owed as usize,
            #[cfg(feature = "query")]
            Pended::Reply(_) => 1,
        }
    }
}

/// What a record of the pending table is.
enum Pended {
    /// A sample, for the callbacks of the subscribers it matched.
    Sample {
        head: EntryHead,
        rest: Option<EntryRest>,
    },
    /// A token's appearance or retraction, for the callbacks of the liveliness subscribers it
    /// matched.
    #[cfg(feature = "liveliness")]
    Liveliness {
        kind: LivelinessSampleKind,
        key: KeyAt,
        token_id: u64,
        owed: u32,
    },
    /// A reply, for the callback of the leg of the get it answers.
    #[cfg(feature = "query")]
    Reply(PendedReply),
}

/// A reply of the pending table: what it is besides its bytes, and where its parts lie.
#[cfg(feature = "query")]
struct PendedReply {
    rid: wz_session_core::wire_id::RequestId,
    kind: ReplyKind,
    qos: Option<QosLevel>,
    key: KeyAt,
    payload: Span,
    attachment: Option<Span>,
    encoding: Option<(u32, Option<Span>)>,
    timestamp: Option<(u64, Span)>,
    source_info: Option<SourceInfo>,
    responder: Option<(Span, u32)>,
}

#[cfg(feature = "query")]
impl PendedReply {
    /// `view` as it lies in `datagram`, and its key when that lies elsewhere; `None` when a part
    /// of it other than its key lies elsewhere.
    fn of<'v>(
        view: &'v dyn ReplyView,
        datagram: (*const u8, usize),
    ) -> Option<(Self, Option<&'v [u8]>)> {
        let payload = Span::of(view.payload(), datagram)?;
        let attachment = match view.attachment() {
            Some(part) => Some(Span::of(part, datagram)?),
            None => None,
        };
        let encoding = match view.put_encoding().or_else(|| view.err_encoding()) {
            Some((id, Some(schema))) => Some((id, Some(Span::of(schema, datagram)?))),
            Some((id, None)) => Some((id, None)),
            None => None,
        };
        let timestamp = match view.timestamp_parts() {
            Some(stamp) => Some((stamp.time, Span::of(stamp.zid, datagram)?)),
            // A stamp the view holds only as its own value lies outside the datagram.
            None if view.timestamp().is_some() => return None,
            None => None,
        };
        let responder = match view.responder() {
            Some((zid, eid)) => Some((Span::of(zid, datagram)?, eid)),
            None => None,
        };
        let key = view.keyexpr().as_bytes();
        let (at, outside) = match Span::of(key, datagram) {
            Some(span) => (KeyAt::Lent(span), None),
            None => (KeyAt::Lent(Span::EMPTY), Some(key)),
        };
        let reply = Self {
            rid: view.rid(),
            kind: view.kind(),
            qos: view.qos(),
            key: at,
            payload,
            attachment,
            encoding,
            timestamp,
            source_info: view.source_info().cloned(),
            responder,
        };
        Some((reply, outside))
    }
}

/// A callback a record of the pending table owes, copied out of the row that matched it under the
/// session's lock and let go of, with no lock held, when the table is emptied.
enum Owed {
    /// A subscriber's.
    Subscriber(SubId, SubscriberCallback),
    /// A liveliness subscriber's.
    #[cfg(feature = "liveliness")]
    Liveliness(LivelinessCallback),
    /// A get's leg's.
    #[cfg(feature = "query")]
    Reply(Arc<ReplyCallback>),
}

impl Owed {
    /// The subscriber and its callback, when it is a subscriber's.
    fn as_subscriber(&self) -> Option<(SubId, &SubscriberCallback)> {
        match self {
            Self::Subscriber(id, callback) => Some((*id, callback)),
            #[cfg(feature = "liveliness")]
            Self::Liveliness(_) => None,
            #[cfg(feature = "query")]
            Self::Reply(_) => None,
        }
    }

    /// The callback, when it is a liveliness subscriber's.
    #[cfg(feature = "liveliness")]
    fn as_liveliness(&self) -> Option<&LivelinessCallback> {
        match self {
            Self::Liveliness(callback) => Some(callback),
            _ => None,
        }
    }

    /// The callback, when it is a leg's.
    #[cfg(feature = "query")]
    fn as_reply(&self) -> Option<&Arc<ReplyCallback>> {
        match self {
            Self::Reply(callback) => Some(callback),
            _ => None,
        }
    }
}

/// What the pending table holds: the datagram its samples lie in, the samples, the callbacks
/// they owe, in order, and the keys it wrote.
struct PendingTable {
    datagram: (*const u8, usize),
    /// As many samples of one datagram as the lane has event slots, which the session's limits
    /// size. A datagram that carries more has the rest kept by its link and handed out in the next
    /// round.
    entries: BoundedVec<PendingEntry, { caps::DELIVERY_LANE_EVENTS }, Static>,
    /// The callbacks the records owe at most, one for each subscriber each of them reaches.
    callbacks: BoundedVec<Owed, { caps::DELIVERY_LANE_CALLBACKS }, Static>,
    keys: BoundedVec<u8, { pending_key_bytes::<{ caps::MAX_KEYEXPR_BYTES }>() }, Static>,
    /// The key written last, which the samples on it that follow share.
    key: Option<Span>,
}

impl PendingTable {
    /// The part at `span` of the datagram the samples lie in.
    fn lent(&self, span: Span) -> &[u8] {
        if span.bytes() == 0 {
            return &[];
        }
        // SAFETY: the part lies in the datagram (`Span::of`), which its link leaves where it lies
        // while the table holds anything (`SharedLane::lends_a_datagram`).
        unsafe { core::slice::from_raw_parts(self.datagram.0.add(span.first()), span.bytes()) }
    }

    /// The part at `span` of the keys the table wrote.
    fn written(&self, span: Span) -> &[u8] {
        self.keys
            .get(span.first()..span.first() + span.bytes())
            .unwrap_or(&[])
    }

    /// The key of the sample `head` names.
    fn key_of(&self, head: &EntryHead) -> &[u8] {
        self.key_at(head.key)
    }

    /// The key `key` names.
    fn key_at(&self, key: KeyAt) -> &[u8] {
        match key {
            KeyAt::Lent(span) => self.lent(span),
            KeyAt::Written(span) => self.written(span),
        }
    }

    /// The key `key` names, as text.
    #[cfg(any(feature = "liveliness", feature = "query"))]
    fn key_text(&self, key: KeyAt) -> &str {
        // SAFETY: the bytes were a `&str`'s (`SampleView::keyexpr`, `ReplyView::keyexpr`,
        // `LivelinessSample::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.key_at(key)) }
    }

    /// Where `key`, a key lying outside the datagram, is written: where the table wrote it last,
    /// when it is that key again, or after the keys written before it; `None` when the table has
    /// not the room for it.
    fn write_key(&mut self, key: &[u8]) -> Option<Span> {
        if let Some(span) = self.key {
            if self.written(span) == key {
                return Some(span);
            }
        }
        let at = self.keys.len();
        let (Ok(first), Ok(len)) = (u32::try_from(at), u32::try_from(key.len())) else {
            return None;
        };
        self.keys.extend_from_slice(key).ok()?;
        let span = Span { at: first, len };
        self.key = Some(span);
        Some(span)
    }

    /// Hold nothing, for the next datagram.
    fn clear(&mut self) {
        self.entries.clear();
        self.callbacks.clear();
        self.keys.clear();
        self.key = None;
        self.datagram = (ptr::null(), 0);
    }
}

/// The samples of one datagram a link lends the session's step, read where they lie, each with
/// the callbacks of the subscribers whose rows it matched, copied out of those rows under the
/// session's lock and called after it is let go, as zenoh-pico copies its subscriptions' callbacks
/// out of its session mutex before it calls them. One datagram at a time: while the table holds
/// anything the links are read no further and their datagram stays where it lies, so a callback
/// that waits for what the same link brings next waits for itself.
///
/// The session writes the table under its lock while it is empty or filling; the end of the
/// datagram's walk, or anything handed to the lane after it, seals it; one delivery takes it,
/// hands every sample to its callbacks in order and empties it. The state word orders the two
/// sides: the seal is a release the delivery's take acquires, and the delivery's emptying is a
/// release the session's next write acquires.
pub(crate) struct Pending {
    state: portable_atomic::AtomicU8,
    table: UnsafeCell<PendingTable>,
    /// The rounds handed out and the samples in them, which the tests count.
    #[cfg(all(test, feature = "std"))]
    rounds: AtomicUsize,
    #[cfg(all(test, feature = "std"))]
    samples: AtomicUsize,
}

impl Pending {
    /// An empty table, as a value, for a lane a test holds.
    #[cfg(all(test, feature = "std"))]
    fn new() -> Self {
        Self {
            state: portable_atomic::AtomicU8::new(EMPTY),
            table: UnsafeCell::new(PendingTable {
                datagram: (ptr::null(), 0),
                entries: BoundedVec::new_static(),
                callbacks: BoundedVec::new_static(),
                keys: BoundedVec::new_static(),
                key: None,
            }),
            #[cfg(all(test, feature = "std"))]
            rounds: AtomicUsize::new(0),
            #[cfg(all(test, feature = "std"))]
            samples: AtomicUsize::new(0),
        }
    }

    /// An empty table written where `at` points, field by field: its rows are kilobytes, which
    /// a value of the whole would lay in the frame of the session's open.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, and what it held is overwritten without a drop.
    unsafe fn write_in(at: *mut Self) {
        // SAFETY: the caller's contract; an `UnsafeCell<T>` is laid out as the `T` it holds, and
        // each field is written once through a pointer to it.
        unsafe {
            ptr::write(
                addr_of_mut!((*at).state),
                portable_atomic::AtomicU8::new(EMPTY),
            );
            let table = addr_of_mut!((*at).table).cast::<PendingTable>();
            ptr::write(addr_of_mut!((*table).datagram), (ptr::null(), 0));
            ptr::write(addr_of_mut!((*table).entries), BoundedVec::new_static());
            ptr::write(addr_of_mut!((*table).callbacks), BoundedVec::new_static());
            ptr::write(addr_of_mut!((*table).keys), BoundedVec::new_static());
            ptr::write(addr_of_mut!((*table).key), None);
            #[cfg(all(test, feature = "std"))]
            ptr::write(addr_of_mut!((*at).rounds), AtomicUsize::new(0));
            #[cfg(all(test, feature = "std"))]
            ptr::write(addr_of_mut!((*at).samples), AtomicUsize::new(0));
        }
    }

    /// A field added to [`Pending`] or its table and not written by [`Self::write_in`] would be
    /// read uninitialised. This destructures both with no `..`, so adding a field without naming
    /// it here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(pending: Self) {
        let Self {
            state: _,
            table,
            #[cfg(all(test, feature = "std"))]
                rounds: _,
            #[cfg(all(test, feature = "std"))]
                samples: _,
        } = pending;
        let PendingTable {
            datagram: _,
            entries: _,
            callbacks: _,
            keys: _,
            key: _,
        } = table.into_inner();
    }

    /// Whether the table holds anything: its datagram is held where it lies.
    fn holds(&self) -> bool {
        self.state.load(Ordering::Acquire) != EMPTY
    }

    /// Whether the table takes one more record of the datagram its link lends now: empty, or
    /// filling with the room of a sample that reaches every subscriber and has a key of its own.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn has_room(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            EMPTY => true,
            FILLING => {
                // SAFETY: a filling table is the lock holder's, and the caller holds the lock.
                let table = unsafe { &*self.table.get() };
                table.entries.free_slots() > 0
                    && table.callbacks.free_slots() >= SAMPLE_CALLBACKS
                    && table.keys.free_slots() >= caps::MAX_KEYEXPR_BYTES
            }
            _ => false,
        }
    }

    /// Take no more samples: what is handed to the lane after this is handed out after them.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn seal(&self) {
        let _ = self
            .state
            .compare_exchange(FILLING, SEALED, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// The state the table is in when it takes a record of `datagram`: `None` when it is sealed,
    /// handed out, or holds another datagram's records.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn open_for(&self, datagram: (*const u8, usize)) -> Option<u8> {
        match self.state.load(Ordering::Acquire) {
            EMPTY => Some(EMPTY),
            // SAFETY: a filling table is the lock holder's, and the caller holds the lock.
            FILLING if unsafe { (*self.table.get()).datagram } == datagram => Some(FILLING),
            _ => None,
        }
    }

    /// Ready `table`, in `state`, for a record of `datagram`: an empty table forgets what it held.
    fn begin(table: &mut PendingTable, state: u8, datagram: (*const u8, usize)) {
        if state == EMPTY {
            table.clear();
            table.datagram = datagram;
        }
    }

    /// A record was offered to a table that was in `state`: an empty one is filling from now on.
    fn filled(&self, state: u8) {
        if state == EMPTY {
            self.state.store(FILLING, Ordering::Release);
        }
    }

    /// Hold `sample` of `datagram` for `callback`, subscriber `subscriber`'s: whether it was
    /// taken. Refused, holding nothing more, when the table is sealed or holds another datagram's
    /// samples, when a part of the sample but its key lies outside the datagram, or when it has
    /// not the room.
    ///
    /// # Safety
    /// The caller holds the session's lock, and the link leaves `datagram` where it lies until it
    /// is next asked to receive.
    unsafe fn offer(
        &self,
        subscriber: SubId,
        callback: &SubscriberCallback,
        sample: &dyn SampleView,
        datagram: (*const u8, usize),
    ) -> bool {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { self.open_for(datagram) }) else {
            return false;
        };
        // SAFETY: an empty or filling table is the lock holder's, and the caller holds the lock.
        let table = unsafe { &mut *self.table.get() };
        let Some(lent) = LentEntry::of(subscriber, sample, datagram) else {
            return false;
        };
        Self::begin(table, state, datagram);
        let key = sample.keyexpr().as_bytes();
        // The sample offered last, for one more of its subscribers.
        if let Some(PendingEntry {
            what: Pended::Sample { head, rest },
            first,
        }) = table.entries.last()
        {
            let joins = head.same_sample(&lent.head)
                && *rest == lent.rest
                && table.key_of(head) == key
                && !table
                    .callbacks
                    .get(*first..)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(Owed::as_subscriber)
                    .any(|(_, held)| Arc::ptr_eq(held, callback));
            if joins {
                if table
                    .callbacks
                    .push(Owed::Subscriber(subscriber, Arc::clone(callback)))
                    .is_err()
                {
                    return false;
                }
                if let Some(PendingEntry {
                    what: Pended::Sample { head, .. },
                    ..
                }) = table.entries.last_mut()
                {
                    head.subscribers += 1;
                }
                return true;
            }
        }
        if table.entries.free_slots() == 0 || table.callbacks.free_slots() == 0 {
            return false;
        }
        let mut head = lent.head;
        if let Some(outside) = lent.key {
            let Some(span) = table.write_key(outside) else {
                return false;
            };
            head.key = KeyAt::Written(span);
        }
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(PendingEntry {
                what: Pended::Sample {
                    head,
                    rest: lent.rest,
                },
                first,
            })
            .is_ok()
            && table
                .callbacks
                .push(Owed::Subscriber(subscriber, Arc::clone(callback)))
                .is_ok();
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(state);
        kept
    }

    /// Hold `sample`, a token's appearance or retraction a record of `datagram` told, for
    /// `callback`, a liveliness subscriber's: whether it was taken. Written once for the
    /// liveliness subscribers it reaches one after the other, as a sample is. Refused, holding
    /// nothing more, as [`Self::offer`] refuses a sample.
    ///
    /// # Safety
    /// As [`Self::offer`]'s.
    #[cfg(feature = "liveliness")]
    unsafe fn offer_liveliness(
        &self,
        callback: &LivelinessCallback,
        sample: &LivelinessSample<'_>,
        datagram: (*const u8, usize),
    ) -> bool {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { self.open_for(datagram) }) else {
            return false;
        };
        // SAFETY: an empty or filling table is the lock holder's, and the caller holds the lock.
        let table = unsafe { &mut *self.table.get() };
        Self::begin(table, state, datagram);
        let key = sample.keyexpr.as_bytes();
        // The token offered last, for one more of its liveliness subscribers.
        if let Some(PendingEntry {
            what:
                Pended::Liveliness {
                    kind,
                    key: at,
                    token_id,
                    ..
                },
            first,
        }) = table.entries.last()
        {
            let joins = *kind == sample.kind
                && *token_id == sample.token_id
                && table.key_at(*at) == key
                && !table
                    .callbacks
                    .get(*first..)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(Owed::as_liveliness)
                    .any(|held| Arc::ptr_eq(held, callback));
            if joins {
                if table
                    .callbacks
                    .push(Owed::Liveliness(Arc::clone(callback)))
                    .is_err()
                {
                    return false;
                }
                if let Some(PendingEntry {
                    what: Pended::Liveliness { owed, .. },
                    ..
                }) = table.entries.last_mut()
                {
                    *owed += 1;
                }
                return true;
            }
        }
        if table.entries.free_slots() == 0 || table.callbacks.free_slots() == 0 {
            return false;
        }
        let at = match Span::of(key, datagram) {
            Some(span) => KeyAt::Lent(span),
            None => match table.write_key(key) {
                Some(span) => KeyAt::Written(span),
                None => return false,
            },
        };
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(PendingEntry {
                what: Pended::Liveliness {
                    kind: sample.kind,
                    key: at,
                    token_id: sample.token_id,
                    owed: 1,
                },
                first,
            })
            .is_ok()
            && table
                .callbacks
                .push(Owed::Liveliness(Arc::clone(callback)))
                .is_ok();
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(state);
        kept
    }

    /// Hold `view`, a reply a record of `datagram` carried, for `callback`, the leg's it answers:
    /// whether it was taken. Refused, holding nothing more, as [`Self::offer`] refuses a sample.
    ///
    /// # Safety
    /// As [`Self::offer`]'s.
    #[cfg(feature = "query")]
    unsafe fn offer_reply(
        &self,
        callback: &Arc<ReplyCallback>,
        view: &dyn ReplyView,
        datagram: (*const u8, usize),
    ) -> bool {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { self.open_for(datagram) }) else {
            return false;
        };
        // SAFETY: an empty or filling table is the lock holder's, and the caller holds the lock.
        let table = unsafe { &mut *self.table.get() };
        let Some((mut reply, outside)) = PendedReply::of(view, datagram) else {
            return false;
        };
        Self::begin(table, state, datagram);
        if table.entries.free_slots() == 0 || table.callbacks.free_slots() == 0 {
            return false;
        }
        if let Some(outside) = outside {
            let Some(span) = table.write_key(outside) else {
                return false;
            };
            reply.key = KeyAt::Written(span);
        }
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(PendingEntry {
                what: Pended::Reply(reply),
                first,
            })
            .is_ok()
            && table
                .callbacks
                .push(Owed::Reply(Arc::clone(callback)))
                .is_ok();
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(state);
        kept
    }

    /// Hand each record the table holds, sealed, to its callbacks in order, `hand` making each
    /// call of a sample, and empty it: whether there was anything to hand. Nothing of the session
    /// is held; a delivery that finds the table not sealed, or taken by another, hands nothing.
    fn deliver(&self, mut hand: impl FnMut(SubId, &SubscriberCallback, &dyn SampleView)) -> bool {
        if self
            .state
            .compare_exchange(SEALED, DELIVERING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let emptied = Emptied(self);
        // SAFETY: a table being delivered is this delivery's alone until `emptied` empties it.
        let table = unsafe { &*self.table.get() };
        for entry in table.entries.iter() {
            let owed = table
                .callbacks
                .get(entry.first..entry.first + entry.owed())
                .unwrap_or(&[]);
            match &entry.what {
                Pended::Sample { head, rest } => {
                    let sample = PendingSample {
                        head: *head,
                        rest: rest.as_ref(),
                        table,
                    };
                    for (subscriber, callback) in owed.iter().filter_map(Owed::as_subscriber) {
                        hand(subscriber, callback, &sample);
                    }
                }
                #[cfg(feature = "liveliness")]
                Pended::Liveliness {
                    kind,
                    key,
                    token_id,
                    ..
                } => {
                    let sample = LivelinessSample {
                        kind: *kind,
                        keyexpr: table.key_text(*key),
                        token_id: *token_id,
                    };
                    for callback in owed.iter().filter_map(Owed::as_liveliness) {
                        callback.call(sample);
                    }
                }
                #[cfg(feature = "query")]
                Pended::Reply(reply) => {
                    let view = PendingReply { reply, table };
                    for callback in owed.iter().filter_map(Owed::as_reply) {
                        callback.call(&view);
                    }
                }
            }
        }
        #[cfg(all(test, feature = "std"))]
        {
            self.rounds.fetch_add(1, Ordering::SeqCst);
            self.samples
                .fetch_add(table.entries.len(), Ordering::SeqCst);
        }
        drop(emptied);
        true
    }
}

/// A delivery of the pending table ends, a callback's unwinding included: the table is emptied,
/// its callbacks let go of with no lock of the session held, and given back to the session.
struct Emptied<'p>(&'p Pending);

impl Drop for Emptied<'_> {
    fn drop(&mut self) {
        // SAFETY: the table is this delivery's until the store below gives it back.
        unsafe { (*self.0.table.get()).clear() };
        self.0.state.store(EMPTY, Ordering::Release);
    }
}

/// A sample of the pending table, read where its datagram and the table's keys hold it: what each
/// of its subscribers' callbacks is handed.
struct PendingSample<'t> {
    head: EntryHead,
    rest: Option<&'t EntryRest>,
    table: &'t PendingTable,
}

impl SampleView for PendingSample<'_> {
    fn keyexpr(&self) -> &str {
        // SAFETY: the bytes were a `&str`'s (`SampleView::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.table.key_of(&self.head)) }
    }

    fn payload(&self) -> &[u8] {
        self.table.lent(self.head.payload)
    }

    fn kind(&self) -> SampleKind {
        self.head.kind
    }

    fn reliability(&self) -> Reliability {
        self.head.reliability
    }

    fn qos(&self) -> Option<QosLevel> {
        self.head.qos
    }

    fn attachment(&self) -> Option<&[u8]> {
        let span = self.rest?.attachment?;
        Some(self.table.lent(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.rest?.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        let (time, zid) = self.rest?.timestamp?;
        Some((time, self.table.lent(zid)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        let (id, schema) = self.rest?.encoding?;
        Some((id, schema.map(|span| self.table.lent(span))))
    }
}

/// A reply of the pending table, read where its datagram and the table's keys hold it: what its
/// leg's callback is handed.
#[cfg(feature = "query")]
struct PendingReply<'t> {
    reply: &'t PendedReply,
    table: &'t PendingTable,
}

#[cfg(feature = "query")]
impl PendingReply<'_> {
    /// Its encoding, when it is of the kind `kind`.
    fn encoding_of(&self, kind: ReplyKind) -> Option<(u32, Option<&[u8]>)> {
        if self.reply.kind != kind {
            return None;
        }
        self.reply
            .encoding
            .map(|(id, schema)| (id, schema.map(|span| self.table.lent(span))))
    }
}

#[cfg(feature = "query")]
impl ReplyView for PendingReply<'_> {
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.reply.rid
    }

    fn keyexpr(&self) -> &str {
        self.table.key_text(self.reply.key)
    }

    fn kind(&self) -> ReplyKind {
        self.reply.kind
    }

    fn payload(&self) -> &[u8] {
        self.table.lent(self.reply.payload)
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Err)
    }

    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Put)
    }

    fn attachment(&self) -> Option<&[u8]> {
        self.reply.attachment.map(|span| self.table.lent(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.reply.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<wz_session_core::reply_stage::TimestampParts<'_>> {
        self.reply
            .timestamp
            .map(|(time, zid)| wz_session_core::reply_stage::TimestampParts {
                time,
                zid: self.table.lent(zid),
            })
    }

    fn responder(&self) -> Option<(&[u8], u32)> {
        self.reply
            .responder
            .map(|(zid, eid)| (self.table.lent(zid), eid))
    }

    fn qos(&self) -> Option<QosLevel> {
        self.reply.qos
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
    /// where it lies until it is next asked to receive (`LaneGate::recv_with`): its first byte and
    /// its length. Written under the session's lock.
    lending: UnsafeCell<Option<(*const u8, usize)>>,
    /// How many batches of samples lying in their datagram ([`BatchRecord`]) were handed on and
    /// given back: the first written by the lane's holder, the second by the deliveries. While
    /// they differ, or while the batch held open lies in its datagram (`lying_open`, as the
    /// holder left it), the links are held back, so the datagram stays where it lies.
    lying_handed: AtomicUsize,
    lying_back: AtomicUsize,
    lying_open: AtomicBool,
    /// How many samples were handed on lying in their datagram, in their batches, which the tests
    /// count.
    #[cfg(all(test, feature = "std"))]
    lent_count: AtomicUsize,
    /// How many holds of the lane were taken ([`Self::held`]), which the tests count.
    #[cfg(all(test, feature = "std"))]
    holds: AtomicUsize,
    /// The samples of the datagram a link lends the step that the lane holds nothing ahead of,
    /// handed to their callbacks before anything the lane holds ([`Pending`]).
    pending: Pending,
    /// The callbacks of the subscribers the samples offered now reach, copied out of their rows
    /// instead of queued, while the session's own put asks for them ([`Self::capture`]). Written
    /// under the session's lock.
    #[cfg(feature = "local-subscriber")]
    capturing: UnsafeCell<Option<Captured>>,
}

/// The subscribers a put of the session's own reaches, in the order the session's table reached
/// them, each with the callback its row holds ([`SharedLane::captured`]).
#[cfg(feature = "local-subscriber")]
pub(crate) type Captured =
    BoundedVec<(SubId, SubscriberCallback), { caps::MAX_SUBSCRIPTIONS }, Static>;

// SAFETY: the lane is reached by the holder of the session's lock alone (`Self::held`), the
// deliveries' side by the holder of `delivering` alone, and a slot's record and bytes by the one
// side the queues have handed them to; every other field is an atomic.
unsafe impl Send for SharedLane {}
// SAFETY: as `Send`.
unsafe impl Sync for SharedLane {}

// The queues hold a handle for every event slot the lane can have out at once, and a handle names
// any slot and any offset of the area.
const _: () = assert!(
    delivery_lane_queue::CAPACITY >= LANE_SLOTS,
    "the delivery lane's queue holds every event slot of the lane: raise its document's capacity"
);
const _: () = assert!(
    LANE_SLOTS <= u16::MAX as usize && caps::DELIVERY_LANE_BYTES <= u32::MAX as usize,
    "a delivery lane handle names every event slot and every offset of the area"
);

impl SharedLane {
    /// A lane of a lane a test holds, moved in by value.
    #[cfg(all(test, feature = "std"))]
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
            lying_handed: AtomicUsize::new(0),
            lying_back: AtomicUsize::new(0),
            lying_open: AtomicBool::new(false),
            #[cfg(all(test, feature = "std"))]
            lent_count: AtomicUsize::new(0),
            #[cfg(all(test, feature = "std"))]
            holds: AtomicUsize::new(0),
            pending: Pending::new(),
            #[cfg(feature = "local-subscriber")]
            capturing: UnsafeCell::new(None),
        }
    }

    /// The session's lane over the `area_bytes` bytes at `area`, held to `limits`, built where the
    /// allocation that shares it keeps it: the lane and its two queues are kilobytes, and built as
    /// a value and moved into the allocation, they lay in the frame of the session's open once for
    /// each move.
    ///
    /// # Safety
    /// As [`SampleLane::over_in`]'s.
    #[inline(never)]
    pub(crate) unsafe fn shared_over(
        area: NonNull<u8>,
        area_bytes: usize,
        limits: &SessionLimits,
    ) -> Arc<Self> {
        // `Arc::new_uninit` is newer than this crate's minimum Rust; an uninitialised value put in
        // an `Arc` is the same allocation, and the optimiser writes nothing into it.
        let raw = Arc::into_raw(Arc::new(MaybeUninit::<Self>::uninit())).cast_mut();
        // SAFETY: `raw` is the one handle of an allocation made on the line above, so the place
        // is valid and nothing else reads or writes it while it is written; the rest is the
        // caller's, which are `SampleLane::over_in`'s.
        unsafe { Self::new_in(&mut *raw, area, area_bytes, limits) };
        // SAFETY: `new_in` wrote every field into the allocation, and a `MaybeUninit<T>` has the
        // size and alignment of `T`, which is what `Arc::from_raw` asks of the pointer's type.
        unsafe { Arc::from_raw(raw.cast::<Self>().cast_const()) }
    }

    /// The lane written field by field into `place`, the lane itself where its cell keeps it
    /// ([`SampleLane::over_in`]), so neither is ever a value of its own on a stack.
    ///
    /// # Safety
    /// As [`SampleLane::over_in`]'s.
    #[inline(never)]
    unsafe fn new_in(
        place: &mut MaybeUninit<Self>,
        area: NonNull<u8>,
        area_bytes: usize,
        limits: &SessionLimits,
    ) {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it; an `UnsafeCell<T>` and a `MaybeUninit<T>` are each laid out as the `T`
        // they hold, so the lane's cell is the place of a lane. `every_field_is_written` names
        // every field, so the lane is whole when it is shared.
        unsafe {
            let cell = addr_of_mut!((*at).lane).cast::<MaybeUninit<SampleLane>>();
            let lane = SampleLane::over_in(&mut *cell, area, area_bytes, limits);
            let reads = lane.takes_a_link_read();
            let records = lane.records.0;
            ptr::write(addr_of_mut!((*at).handed), DeliveryLaneQueue::new());
            ptr::write(addr_of_mut!((*at).returned), DeliveryLaneQueue::new());
            ptr::write(addr_of_mut!((*at).records), records);
            ptr::write(addr_of_mut!((*at).area), area);
            ptr::write(
                addr_of_mut!((*at).delivering),
                portable_atomic::AtomicBool::new(false),
            );
            ptr::write(addr_of_mut!((*at).handed_count), AtomicUsize::new(0));
            ptr::write(addr_of_mut!((*at).taken_count), AtomicUsize::new(0));
            #[cfg(feature = "query")]
            ptr::write(addr_of_mut!((*at).done_count), AtomicUsize::new(0));
            ptr::write(addr_of_mut!((*at).reads), AtomicBool::new(reads));
            #[cfg(debug_assertions)]
            ptr::write(addr_of_mut!((*at).gated), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).lending), UnsafeCell::new(None));
            ptr::write(addr_of_mut!((*at).lying_handed), AtomicUsize::new(0));
            ptr::write(addr_of_mut!((*at).lying_back), AtomicUsize::new(0));
            ptr::write(addr_of_mut!((*at).lying_open), AtomicBool::new(false));
            #[cfg(all(test, feature = "std"))]
            ptr::write(addr_of_mut!((*at).lent_count), AtomicUsize::new(0));
            #[cfg(all(test, feature = "std"))]
            ptr::write(addr_of_mut!((*at).holds), AtomicUsize::new(0));
            Pending::write_in(addr_of_mut!((*at).pending));
            #[cfg(feature = "local-subscriber")]
            ptr::write(addr_of_mut!((*at).capturing), UnsafeCell::new(None));
        }
    }

    /// A field added to [`SharedLane`] and not written by [`Self::new_in`] would be read
    /// uninitialised. This destructures the lane with no `..`, so adding a field without naming it
    /// here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(shared: Self) {
        let Self {
            lane: _,
            handed: _,
            returned: _,
            records: _,
            area: _,
            delivering: _,
            handed_count: _,
            taken_count: _,
            #[cfg(feature = "query")]
                done_count: _,
            reads: _,
            #[cfg(debug_assertions)]
                gated: _,
            lending: _,
            lying_handed: _,
            lying_back: _,
            lying_open: _,
            #[cfg(all(test, feature = "std"))]
                lent_count: _,
            #[cfg(all(test, feature = "std"))]
                holds: _,
            pending: _,
            #[cfg(feature = "local-subscriber")]
                capturing: _,
        } = shared;
    }

    /// Copy out, instead of queueing, the callbacks of the subscribers the samples offered from
    /// here on reach, until [`Self::captured`]: how the session's own put learns which of its
    /// subscribers it reaches and what to call, to hand the sample to them itself.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "local-subscriber")]
    pub(crate) unsafe fn capture(&self) {
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.capturing.get() = Some(BoundedVec::new_static()) };
    }

    /// The subscribers reached since [`Self::capture`] and their callbacks; what is offered after
    /// this is queued again.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "local-subscriber")]
    pub(crate) unsafe fn captured(&self) -> Captured {
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { (*self.capturing.get()).take() }.unwrap_or_else(BoundedVec::new_static)
    }

    /// The datagram a link lends the session's step now, whose samples may be handed to their
    /// callbacks where they lie; `None` once the link takes it back.
    ///
    /// # Safety
    /// The caller holds the session's lock, and the link leaves the bytes where they lie until it
    /// is next asked to receive or to be serviced
    /// (`SessionDatagramLink::lends_until_next_receive`).
    pub(crate) unsafe fn set_lending(&self, datagram: Option<&[u8]>) {
        let range = datagram.map(|bytes| (bytes.as_ptr(), bytes.len()));
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.lending.get() = range };
    }

    /// Whether a batch lying in its datagram holds the links back: no link is read or serviced
    /// until the callbacks of every such sample have returned. Asked by the session's step, which
    /// holds the session's lock, under which `lying_handed` and `lying_open` are written.
    pub(crate) fn lends_a_datagram(&self) -> bool {
        self.pending.holds()
            || self.lying_open.load(Ordering::Acquire)
            || self.lying_handed.load(Ordering::SeqCst) != self.lying_back.load(Ordering::SeqCst)
    }

    /// How many samples were handed on lying in their datagram since the lane was made, which the
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
        #[cfg(all(test, feature = "std"))]
        self.holds.fetch_add(1, Ordering::SeqCst);
        // What the lane is handed under this hold is handed out after the pending samples.
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.pending.seal() };
        let mut held = LaneHeld { shared: self };
        #[cfg(debug_assertions)]
        held.offering_gated(self.gated.load(Ordering::Acquire));
        held.take_back();
        held
    }

    /// Queue `sample` for the callback of `subscriber` ([`LaneHeld::offer_sample`]). While a link
    /// lends the step a datagram, its records are offered with no hold of the lane each: what a
    /// hold does as it is taken and let go (taking back what the deliveries gave back, handing on
    /// what was published, the hold its samples put on the links) is done once, by the hold the
    /// link's gate takes when the datagram's walk ends (`LaneGate::recv_with`), and after each
    /// record only the room the gate asks before the next one is left in its word. Any other
    /// sample takes a hold of its own.
    ///
    /// # Safety
    /// As [`Self::held`]'s.
    pub(crate) unsafe fn offer_sample(&self, subscriber: SubId, sample: &dyn SampleView) {
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        if unsafe { (*self.lending.get()).is_none() } {
            // SAFETY: the caller's contract.
            unsafe { self.held() }.offer_sample(subscriber, sample);
            return;
        }
        // SAFETY: the caller holds the session's lock and no hold of the lane, so this borrow is
        // the lane's one, and it ends with this call.
        let lane = unsafe { &mut *self.lane.get() };
        #[cfg(debug_assertions)]
        lane.offering_gated(self.gated.load(Ordering::Acquire));
        offer_into(self, lane, subscriber, sample);
        self.reads
            .store(lane.takes_a_link_read(), Ordering::Release);
    }

    /// Hold `sample` for `callback`, subscriber `subscriber`'s, in the pending table when it lies
    /// in the datagram a link lends the step and the lane holds nothing to be handed out before
    /// it ([`Pending`]); queue it in the lane otherwise ([`Self::offer_sample`]), after which the
    /// pending table takes no more.
    ///
    /// # Safety
    /// As [`Self::held`]'s.
    pub(crate) unsafe fn offer_to(
        &self,
        subscriber: SubId,
        callback: Option<&SubscriberCallback>,
        sample: &dyn SampleView,
    ) {
        // The session's own put copies the callbacks out and queues nothing.
        #[cfg(feature = "local-subscriber")]
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        if let Some(found) = unsafe { &mut *self.capturing.get() } {
            // A row whose registration was refused mints no callback, and is handed nothing.
            if let Some(callback) = callback {
                let kept = found.push((subscriber, Arc::clone(callback)));
                debug_assert!(
                    kept.is_ok(),
                    "a session's subscribers fit the table of them"
                );
            }
            return;
        }
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        let lending = unsafe { *self.lending.get() };
        if let (Some(datagram), Some(callback)) = (lending, callback) {
            // SAFETY: the caller's contract, and the link leaves the datagram where it lies while
            // the table holds it (`Self::lends_a_datagram`).
            if unsafe { self.quiet() && self.pending.offer(subscriber, callback, sample, datagram) }
            {
                return;
            }
        }
        // SAFETY: the caller's contract.
        unsafe {
            self.pending.seal();
            self.offer_sample(subscriber, sample);
        }
    }

    /// Hold `sample`, a token's appearance or retraction, for `callback`, liveliness subscriber
    /// `subscriber`'s, in the pending table when its record lies in the datagram a link lends the
    /// step and the lane holds nothing to be handed out before it, as [`Self::offer_to`] holds a
    /// sample; queue it in the lane otherwise, after which the pending table takes no more.
    ///
    /// # Safety
    /// As [`Self::held`]'s.
    #[cfg(feature = "liveliness")]
    pub(crate) unsafe fn offer_liveliness_to(
        &self,
        subscriber: SubId,
        callback: &LivelinessCallback,
        sample: &LivelinessSample<'_>,
    ) {
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        if let Some(datagram) = unsafe { *self.lending.get() } {
            // SAFETY: the caller's contract, and the link leaves the datagram where it lies while
            // the table holds it (`Self::lends_a_datagram`).
            if unsafe { self.quiet() && self.pending.offer_liveliness(callback, sample, datagram) }
            {
                return;
            }
        }
        // SAFETY: the caller's contract; the hold seals the pending table.
        unsafe { self.held() }.offer_liveliness(subscriber, sample);
    }

    /// Hold `view`, a reply to leg `leg`, for `callback`, the leg's, in the pending table when it
    /// lies in the datagram a link lends the step and the lane holds nothing to be handed out
    /// before it, as [`Self::offer_to`] holds a sample; queue it in the lane otherwise, after
    /// which the pending table takes no more.
    ///
    /// # Safety
    /// As [`Self::held`]'s.
    #[cfg(feature = "query")]
    pub(crate) unsafe fn offer_reply_to(
        &self,
        leg: u64,
        callback: &Arc<ReplyCallback>,
        view: &dyn ReplyView,
    ) {
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        if let Some(datagram) = unsafe { *self.lending.get() } {
            // SAFETY: the caller's contract, and the link leaves the datagram where it lies while
            // the table holds it (`Self::lends_a_datagram`).
            if unsafe { self.quiet() && self.pending.offer_reply(callback, view, datagram) } {
                return;
            }
        }
        // SAFETY: the caller's contract; the hold seals the pending table.
        unsafe { self.held() }.offer_reply(leg, view);
    }

    /// Whether the lane holds nothing to be handed out and no delivery of it runs: what a sample
    /// is held in the pending table after, so the samples are handed out in the order they came.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn quiet(&self) -> bool {
        // SAFETY: the caller holds the session's lock, under which the lane is reached, and holds
        // no hold of it.
        let lane = unsafe { &*self.lane.get() };
        lane.open.is_none()
            && lane.published.front().is_none()
            && !self.owes_a_delivery()
            && !self.delivering.load(Ordering::SeqCst)
            && !self.lying_open.load(Ordering::Acquire)
            && self.lying_handed.load(Ordering::SeqCst) == self.lying_back.load(Ordering::SeqCst)
    }

    /// Whether the pending table takes one more record of the datagram a link lends the step.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(crate) unsafe fn pending_room(&self) -> bool {
        // SAFETY: the caller's contract.
        unsafe { self.pending.has_room() }
    }

    /// Hand the pending samples to their callbacks ([`Pending::deliver`]), with nothing of the
    /// session held: whether there were any.
    pub(crate) fn deliver_pending(
        &self,
        hand: impl FnMut(SubId, &SubscriberCallback, &dyn SampleView),
    ) -> bool {
        self.pending.deliver(hand)
    }

    /// How many rounds of pending samples were handed out, and how many samples were in them,
    /// which the tests of the cost of one sample count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn pending_counts(&self) -> (usize, usize) {
        (
            self.pending.rounds.load(Ordering::SeqCst),
            self.pending.samples.load(Ordering::SeqCst),
        )
    }

    /// How many holds of the lane were taken since it was made, which the tests of the cost of
    /// one sample count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn holds(&self) -> usize {
        self.holds.load(Ordering::SeqCst)
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
        self.handed_count.load(Ordering::SeqCst) != self.taken_count.load(Ordering::SeqCst)
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
        assert!(index < LANE_SLOTS, "a slot of the lane");
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
    /// Queue `sample` for the callback of `subscriber`, reading it where it lies when every part
    /// of it but its key lies in the datagram a link lends the step now
    /// ([`SharedLane::set_lending`]): an entry of the datagram's batch ([`BatchRecord`]), the one
    /// record of the lane for all of its samples, and the links are held back until a delivery has
    /// handed them to their callbacks and given the batch back. Every sample of the datagram is
    /// read so, in the order they arrive among whatever else the lane holds, so one step hands on
    /// all of a batch.
    pub(crate) fn offer_sample(&mut self, subscriber: SubId, sample: &dyn SampleView) {
        let shared = self.shared;
        offer_into(shared, self, subscriber, sample);
    }

    /// Publish what this hold leaves open: the sample the lane holds open for more subscribers.
    /// What every hold of the session's lock ends with.
    pub(crate) fn seal_all(&mut self) {
        self.seal();
    }
}

/// Queue `sample` for `subscriber` in `lane`, `shared`'s, as [`LaneHeld::offer_sample`] says.
fn offer_into(
    shared: &SharedLane,
    lane: &mut SampleLane,
    subscriber: SubId,
    sample: &dyn SampleView,
) {
    // SAFETY: written under the session's lock, under which the lane is reached.
    let lending = unsafe { *shared.lending.get() };
    match lending {
        // A delivery running now may be the one this sample's own step runs inside of (a callback
        // that steps its session), which hands the sample on only once that callback returns: a
        // batch lying in the datagram would hold the link back until then, and the callback may be
        // waiting for what the link brings next. It is written whole instead.
        Some(datagram) if !shared.delivering.load(Ordering::SeqCst) => {
            lane.offer_lent(subscriber, sample, datagram)
        }
        _ => lane.offer(subscriber, sample),
    }
}

impl Drop for LaneHeld<'_> {
    fn drop(&mut self) {
        let shared = self.shared;
        // SAFETY: as `take_back`, for the producer of `handed`.
        let mut on = unsafe { shared.handed.producer() };
        // The counts are stored once, after every record this hold hands on: a hold at the end of
        // a datagram's walk hands on its batch and whatever was written before it together.
        let (mut handed, mut lying) = (0usize, 0usize);
        #[cfg(all(test, feature = "std"))]
        let mut lent = 0usize;
        while let Some((slot, offset)) = self.published.front() {
            // Read before the push: from then on the slot's record is the delivery's.
            let event = self.record(usize::from(slot));
            let lies = event.is_some_and(Event::lies);
            #[cfg(all(test, feature = "std"))]
            let samples = event.map_or(0, Event::lying);
            let pushed = on.try_push(DeliveryLaneHandle { slot, offset });
            debug_assert!(
                pushed.is_ok(),
                "the delivery lane's queue holds every event slot of the lane"
            );
            if pushed.is_err() {
                break;
            }
            self.published.pop();
            handed += 1;
            if lies {
                lying += 1;
            }
            #[cfg(all(test, feature = "std"))]
            {
                lent += samples;
            }
        }
        if handed > 0 {
            let total = shared
                .handed_count
                .load(Ordering::Relaxed)
                .wrapping_add(handed);
            shared.handed_count.store(total, Ordering::SeqCst);
        }
        // Counted after the push: a delivery that gives one back first leaves the counts apart for
        // that while, which holds the links back, and never lets them read early.
        if lying > 0 {
            let total = shared
                .lying_handed
                .load(Ordering::Relaxed)
                .wrapping_add(lying);
            shared.lying_handed.store(total, Ordering::SeqCst);
        }
        #[cfg(all(test, feature = "std"))]
        shared.lent_count.fetch_add(lent, Ordering::SeqCst);
        // A batch not handed on yet holds the links back all the same: the one held open, and any
        // record the queue did not take.
        let open = self
            .open
            .as_ref()
            .and_then(|open| self.record(open.index()))
            .is_some_and(Event::lies);
        let unpushed = self.published.front().is_some();
        shared.lying_open.store(open || unpushed, Ordering::Release);
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
            // SAFETY: the record was written before its handle was pushed, which the pop read in
            // the push's order, and the lane writes the slot again only once the handle is back.
            let event = unsafe { (*self.shared.record_cell(slot).get()).take() };
            let head = HeldHead {
                delivery: self,
                handle: Some(handle),
                lies: event.as_ref().is_some_and(Event::lies),
            };
            let Some(event) = event else {
                // A handed slot always has its record; one without is given back at once.
                continue;
            };
            // SAFETY: the sample's bytes lie at `offset` inside the area (`DeliveryLane::reserve`).
            let base = unsafe { self.shared.area.as_ptr().add(offset) };
            return Some((LaneItem::of(event, base), head));
        }
    }

    /// The callbacks of the sample of `handle` returned: it goes back to the session, and when it
    /// lay in its datagram (`lies`), the datagram is no longer read through it.
    fn give_back(&self, handle: DeliveryLaneHandle, lies: bool) {
        if lies {
            let back = self
                .shared
                .lying_back
                .load(Ordering::Relaxed)
                .wrapping_add(1);
            self.shared.lying_back.store(back, Ordering::SeqCst);
        }
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

/// A sample a delivery took ([`LaneDelivery::take`]), given back when its callbacks have
/// returned, or one unwinds.
pub(crate) struct HeldHead<'d> {
    delivery: &'d LaneDelivery<'d>,
    handle: Option<DeliveryLaneHandle>,
    /// Whether it is a batch whose samples lie in their datagram ([`BatchRecord`]).
    lies: bool,
}

impl Drop for HeldHead<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.delivery.give_back(handle, self.lies);
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
    /// The samples of a datagram a link lent, for the callbacks of each one's subscribers.
    Batch(LaneBatch),
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
            Event::Batch(batch) => Self::Batch(LaneBatch { batch, base }),
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

/// A batch at the head of the lane ([`BatchRecord`]): its samples, for the callbacks of each one's
/// subscribers, in the order they came. Valid until the delivery that took it gives it back.
pub(crate) struct LaneBatch {
    batch: BatchRecord,
    /// The first byte of its entries.
    base: *const u8,
}

impl LaneBatch {
    /// Its samples, in the order they came, each read where its entry and its datagram hold it.
    pub(crate) fn samples(&self) -> BatchSamples<'_> {
        BatchSamples {
            batch: self,
            at: 0,
            left: self.batch.samples,
        }
    }
}

/// The samples of a [`LaneBatch`], read entry by entry.
pub(crate) struct BatchSamples<'b> {
    batch: &'b LaneBatch,
    /// Where the next entry starts, from the batch's first byte.
    at: usize,
    /// The entries not read yet.
    left: usize,
}

impl<'b> Iterator for BatchSamples<'b> {
    type Item = BatchSample<'b>;

    fn next(&mut self) -> Option<BatchSample<'b>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        // SAFETY (each block below): the batch's entries were written one after the other from
        // `base` (`SampleLane::write_entry`), each its head, its rest when the head says so, the
        // key it wrote and its subscribers' ids, and they are not written again until the delivery
        // that holds the batch gives it back, after these views are gone.
        let entry = unsafe { self.batch.base.add(self.at) };
        let head = unsafe { ptr::read_unaligned(entry.cast::<EntryHead>()) };
        let mut skip = HEAD_BYTES;
        let rest = if head.rest {
            skip += REST_BYTES;
            Some(unsafe { ptr::read_unaligned(entry.add(HEAD_BYTES).cast::<EntryRest>()) })
        } else {
            None
        };
        skip += head.written as usize;
        let ids = unsafe { entry.add(skip) };
        self.at += skip + head.subscribers as usize * SUBSCRIBER_ID_BYTES;
        Some(BatchSample {
            head,
            rest,
            ids,
            batch: self.batch,
        })
    }
}

/// A sample of a batch at the head of the lane, read where its entry and its datagram hold it:
/// what each of its subscribers' callbacks is handed, a view on the delivery's stack.
pub(crate) struct BatchSample<'b> {
    head: EntryHead,
    rest: Option<EntryRest>,
    /// Its subscribers' ids.
    ids: *const u8,
    batch: &'b LaneBatch,
}

impl BatchSample<'_> {
    /// The subscribers whose callbacks it is for, in the order the session offered it to them.
    pub(crate) fn subscribers(&self) -> impl Iterator<Item = SubId> + '_ {
        let len = self.head.subscribers as usize * SUBSCRIBER_ID_BYTES;
        // SAFETY: as its entry's (`BatchSamples::next`): its ids follow its key.
        subscriber_ids(unsafe { core::slice::from_raw_parts(self.ids, len) })
    }

    /// The part at `span` of the datagram the batch's samples lie in.
    fn lent(&self, span: Span) -> &[u8] {
        if span.bytes() == 0 {
            return &[];
        }
        // SAFETY: the part lies in the datagram the link lent (`Span::of`), which it leaves where it
        // lies while the batch is out (`SharedLane::lends_a_datagram`), and the batch is out until
        // the delivery that holds it gives it back, after this view is gone.
        unsafe {
            core::slice::from_raw_parts(self.batch.batch.datagram.0.add(span.first()), span.bytes())
        }
    }

    /// The part at `span` of the batch's own bytes.
    fn written(&self, span: Span) -> &[u8] {
        if span.bytes() == 0 {
            return &[];
        }
        // SAFETY: as its entry's (`BatchSamples::next`): the batch wrote the key there.
        unsafe { core::slice::from_raw_parts(self.batch.base.add(span.first()), span.bytes()) }
    }
}

impl SampleView for BatchSample<'_> {
    fn keyexpr(&self) -> &str {
        let key = match self.head.key {
            KeyAt::Lent(span) => self.lent(span),
            KeyAt::Written(span) => self.written(span),
        };
        // SAFETY: the bytes were a `&str`'s (`SampleView::keyexpr`), so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(key) }
    }

    fn payload(&self) -> &[u8] {
        self.lent(self.head.payload)
    }

    fn kind(&self) -> SampleKind {
        self.head.kind
    }

    fn reliability(&self) -> Reliability {
        self.head.reliability
    }

    fn qos(&self) -> Option<QosLevel> {
        self.head.qos
    }

    fn attachment(&self) -> Option<&[u8]> {
        let span = self.rest.as_ref()?.attachment?;
        Some(self.lent(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.rest.as_ref()?.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        let (time, zid) = self.rest.as_ref()?.timestamp?;
        Some((time, self.lent(zid)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        let (id, schema) = self.rest.as_ref()?.encoding?;
        Some((id, schema.map(|span| self.lent(span))))
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

    /// Whether the lane has the room of a record, once what the deliveries gave back is taken
    /// back, and the pending table the room of one more record of the datagram lent now.
    fn has_room(&self) -> bool {
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        if !unsafe { self.lane.pending_room() } {
            return false;
        }
        if self.lane.takes_a_link_read() {
            return true;
        }
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        unsafe { self.lane.held() }.takes_a_link_read()
    }

    /// Whether the link is held back from receiving: a batch lies in the datagram it lent last
    /// (the next receive may write where it lies), or the lane has not the room of a record.
    fn shut(&self) -> bool {
        self.lane.lends_a_datagram() || !self.has_room()
    }
}

impl<P: SessionDatagramLink> SessionDatagramLink for LaneGate<P> {
    /// A link whose datagram a sample is lent from is not serviced: its stack may read the next
    /// datagram into the buffer the batch lies in.
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
            // The datagram's samples were offered with no hold each (`SharedLane::offer_sample`),
            // into its batch: this hold publishes the batch and hands it on, and the batch holds
            // the links back until it is given back.
            // SAFETY: as above, with no other hold of the lane taken.
            unsafe { self.lane.held() }.seal_all();
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

    // The gate holds back input only: what the session owes the stack is written whatever it
    // holds, and the owner's wait wakes for it.
    fn owes_write(&self) -> bool {
        self.pump.owes_write()
    }

    /// The rest of a datagram already read is held back with the link's next one while the lane
    /// has not the room of a record. A batch lying in the datagram does not hold the rest back:
    /// it lies where the rest does, and the records after it join it.
    fn takes_input(&self) -> bool {
        self.has_room() && self.pump.takes_input()
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
