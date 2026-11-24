// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's round of deliveries: what the session hands its callbacks under its lock, held
//! until the lock is let go and handed to them after it (decision D8), with nothing built on the
//! heap between a record's arrival and its callbacks (`docs/c-abi-no-heap-pools.md`, section 4.10).
//!
//! # One table
//!
//! A round is one table: the records the session's tables matched while the lock was held, each
//! with the calls it owes: a call of a subscriber's callback begun on its row's latch, which the
//! row's table keeps where it lies until the call ends (`docs/c-abi-architecture.md`, P11), and a
//! copy of any other callback, as zenoh-pico copies its subscriptions' callbacks out of its
//! session mutex before it calls them. A record's parts are read where they
//! lie when they lie in the datagram a link lends the step (UDP, a stream), so a sample of it is
//! never copied; a key the session resolved from an alias lies in a frame of the dispatch, and is
//! written into the table's keys; every other part that lies elsewhere (a rejoined message, a
//! frame the link handed over, a group's datagram) is written into the table's area, which the
//! session's arena lends (`DELIVERY_LANE_BYTES`). A record offered again for one more subscriber
//! is written once: the subscriber's callback joins the ones it owes.
//!
//! The session writes the table under its lock while it is empty or filling; the lock's release
//! seals it ([`Round::seal`]); one delivery takes it, hands every record to its callbacks in
//! order with nothing of the session held, and empties it. The state word orders the two sides:
//! the seal is a release the delivery's take acquires, and the delivery's emptying is a release
//! the session's next write acquires.
//!
//! # Backpressure (decision Q4)
//!
//! The session is handed no record of a link while the table has not the room one record can take
//! ([`ReadRoom`], [`RoundGate`]): what the peer sends meanwhile waits in the link, and the
//! transport's flow control carries the wait back to the sender. Nor is a link read again while a
//! record lies in the datagram it lent, which its next receive may overwrite. The room is the
//! larger of a batch and a rejoined message, with the most a sample adds to the record it came
//! in: its key resolved from an alias, its timestamp's clock id and the subscribers' share; and
//! an entry, and a callback for each subscriber. What finds no room is counted
//! ([`RoundCounts`]): apart when its congestion control holds its sender, which a record the gate
//! let through never does (a debug build stops there).

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{self, addr_of_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use portable_atomic::{AtomicU64, AtomicU8, AtomicUsize};
use wz_capi_port::SubId;
use wz_runtime_coop::session_drive::{SessionDatagramLink, WaitOn};
use wz_session_core::bounded::{Arena, BoundedVec, LendRefused, Lent};
use wz_session_core::caps;
#[cfg(feature = "liveliness")]
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
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
use crate::engine::SubscriberCall;
#[allow(unused_imports)]
use crate::prelude::*;
use wz_capi_port::sync::Lock;
#[cfg(feature = "query")]
use wz_capi_port::ReplyCallback;
use wz_session_core::bounded::Static;
use wz_session_core::session_tables::SubscriberHandle;

/// The longest id of the clock that stamped a sample's timestamp the wire carries.
const TIMESTAMP_ID_BYTES: usize = 16;

/// The share of a record's room each subscriber it reaches is given, a subscriber's id: the
/// build's sizes of the area are stated with it.
const SUBSCRIBER_ID_BYTES: usize = core::mem::size_of::<SubId>();

/// The most bytes one sample takes in the round beyond the message it arrived in, for a session
/// whose longest key is `key_bytes` and that holds `subscribers` subscribers at most: its key as
/// the session resolved it, which a peer may have named by an alias of a few bytes, the id of its
/// timestamp's clock, and a share for each subscriber it is for.
pub(crate) const fn sample_overhead(key_bytes: usize, subscribers: usize) -> usize {
    key_bytes
        .saturating_add(TIMESTAMP_ID_BYTES)
        .saturating_add(subscribers.saturating_mul(SUBSCRIBER_ID_BYTES))
}

/// The most subscribers one record of a session reaches: a sample's, of the `subscribers` it
/// holds, or a token's, of the `liveliness` subscribers it holds (none in a build without
/// liveliness), whichever is more.
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

/// The most bytes one record a session is handed can put in its round, for a session whose batch
/// is `batch` bytes, whose largest rejoined message is `frag` bytes, whose longest key is `key`
/// bytes and whose records reach `subscribers` subscribers at most: a record is no longer than a
/// batch or a rejoined message, and its sample adds to it at most [`sample_overhead`].
pub(crate) const fn read_bytes(batch: usize, frag: usize, key: usize, subscribers: usize) -> usize {
    let message = if batch > frag { batch } else { frag };
    message.saturating_add(sample_overhead(key, subscribers))
}

/// What one record a session is handed can take of its round at most: the room the round is asked
/// for before each record ([`RoundGate`]), so that what a record hands it always finds room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadRoom {
    /// Its bytes ([`read_bytes`]); and an entry, which every record takes one of at most.
    pub(crate) bytes: usize,
    /// The callbacks it owes: one for each subscriber it reaches.
    pub(crate) callbacks: usize,
}

/// Whether an area of `AREA` bytes holds what one record can hand it in a build whose batch is
/// `BATCH` bytes, whose largest rejoined message is `FRAG` bytes, whose longest key is `KEY`
/// bytes and that holds `SUBS` subscribers and `LIVE` liveliness subscribers.
pub(crate) const fn holds_a_read<
    const AREA: usize,
    const BATCH: usize,
    const FRAG: usize,
    const KEY: usize,
    const SUBS: usize,
    const LIVE: usize,
>() -> bool {
    read_bytes(BATCH, FRAG, KEY, most_subscribers(SUBS, LIVE)) <= AREA
}

// The build's area holds what one record can hand it at the build's largest batch and rejoined
// message, so a session's area, sized from the session's values under the build's, never needs
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
    "the build's delivery area holds what one record of the build's largest batch hands it"
);

/// What one record of a session whose batch is `batch` bytes and whose limits are `limits` can
/// take of its round ([`ReadRoom`]), each limit lent under the build's value (`FRAG`, `KEY`,
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

/// `limits` with the round's area long enough for what one record can hand it ([`read_room`] of
/// the session's `PICO_UNICAST_BATCH_BYTES`): an area stated shorter is lengthened to it, as a
/// record that found no room could never be handed on. `BATCH`, `FRAG`, `KEY`, `SUBS` and
/// `LIVE` are the build's values, under which the session's lie.
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
        // Refused only by a domain of one value, which is the build's area, and the build's area
        // holds the read (the assertion above).
        let _ = limits.select_delivery_lane_bytes(read);
    }
    limits
}

/// Whether a sample sent with `reliability` and `qos` holds its sender: sent reliably, with
/// `block` or `block-first`. A sample that states no QoS has zenoh's default, `drop`.
fn holds_its_sender(reliability: Reliability, qos: Option<QosLevel>) -> bool {
    reliability == Reliability::Reliable
        && qos.is_some_and(|qos| qos.congestion() != CongestionControl::Drop)
}

/// What a round did not hand a callback, by why.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoundCounts {
    /// Samples whose congestion control lets them be dropped (sent best effort, or with `drop`)
    /// that found no room.
    pub dropped: u64,
    /// Records whose congestion control holds their sender that found no room all the same:
    /// what was offered past the room the gate asked for (a token or a reply is one).
    pub held_over: u64,
}

/// Where a part of a record lies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// In the datagram a link lent the step the record was written in.
    Lent,
    /// In the table's keys.
    Key,
    /// In the table's area.
    Area,
}

/// A part of a record: where it lies, from the first byte of its place, and how long it is.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Span {
    at: u32,
    len: u32,
    place: Place,
}

impl Span {
    /// An empty part, which lies anywhere.
    const EMPTY: Self = Self {
        at: 0,
        len: 0,
        place: Place::Area,
    };

    /// Where `part` lies in `datagram`, its first byte and its length; `None` when it lies
    /// elsewhere.
    fn lent(part: &[u8], (start, length): (*const u8, usize)) -> Option<Self> {
        if part.is_empty() {
            return Some(Self::EMPTY);
        }
        let at = (part.as_ptr() as usize).checked_sub(start as usize)?;
        if part.len() > length.checked_sub(at)? {
            return None;
        }
        Some(Self {
            at: u32::try_from(at).ok()?,
            len: u32::try_from(part.len()).ok()?,
            place: Place::Lent,
        })
    }
}

/// Whether `a` and `b` are the same bytes: the same place, or equal.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && (ptr::eq(a.as_ptr(), b.as_ptr()) || a == b)
}

/// A sample as a record of the round holds it: what it is besides its bytes, and where its key and
/// its payload lie.
#[derive(Clone, Copy)]
struct Head {
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    key: Span,
    payload: Span,
}

/// What a sample carries beyond its key and its payload, held only when it carries any of it.
#[derive(Clone)]
struct Rest {
    attachment: Option<Span>,
    /// The packed id, and where the schema lies when there is one.
    encoding: Option<(u32, Option<Span>)>,
    /// The time word, and where the id prefix lies.
    timestamp: Option<(Word, Span)>,
    source_info: Option<SourceInfo>,
}

/// A 64-bit value a record holds at the alignment of a byte, so that the record keeps the
/// alignment of its spans and pads nothing before the value.
#[derive(Clone, Copy)]
struct Word([u8; 8]);

impl Word {
    const fn of(value: u64) -> Self {
        Self(value.to_ne_bytes())
    }

    const fn get(self) -> u64 {
        u64::from_ne_bytes(self.0)
    }
}

/// The parts of a sample, as a view hands them or as the table holds them.
struct Parts<'s> {
    attachment: Option<&'s [u8]>,
    encoding: Option<(u32, Option<&'s [u8]>)>,
    timestamp: Option<(u64, &'s [u8])>,
    source_info: Option<&'s SourceInfo>,
}

impl<'s> Parts<'s> {
    /// The parts `sample` carries beyond its key and its payload.
    fn of(sample: &'s dyn SampleView) -> Self {
        Self {
            attachment: sample.attachment(),
            encoding: encoding_of(sample),
            timestamp: timestamp_of(sample),
            source_info: sample.source_info(),
        }
    }

    /// Whether it carries any part.
    fn carries(&self) -> bool {
        self.attachment.is_some()
            || self.encoding.is_some()
            || self.timestamp.is_some()
            || self.source_info.is_some()
    }

    /// Whether `other` is the same parts, read where each lies.
    fn same(&self, other: &Self) -> bool {
        let bytes = |a: Option<&[u8]>, b: Option<&[u8]>| match (a, b) {
            (Some(a), Some(b)) => same(a, b),
            (None, None) => true,
            _ => false,
        };
        bytes(self.attachment, other.attachment)
            && match (self.encoding, other.encoding) {
                (Some((a, x)), Some((b, y))) => a == b && bytes(x, y),
                (None, None) => true,
                _ => false,
            }
            && match (self.timestamp, other.timestamp) {
                (Some((a, x)), Some((b, y))) => a == b && same(x, y),
                (None, None) => true,
                _ => false,
            }
            && self.source_info == other.source_info
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

/// A reply as a record of the round holds it: what it is besides its bytes, and where its parts
/// lie.
#[cfg(feature = "query")]
struct HeldReply {
    rid: wz_session_core::wire_id::RequestId,
    kind: ReplyKind,
    qos: Option<QosLevel>,
    key: Span,
    payload: Span,
    attachment: Option<Span>,
    encoding: Option<(u32, Option<Span>)>,
    timestamp: Option<(Word, Span)>,
    source_info: Option<SourceInfo>,
    responder: Option<(Span, u32)>,
}

/// What a record of the round is.
enum Held {
    /// A sample, for the callbacks of the subscribers it matched.
    Sample { head: Head, rest: Option<Rest> },
    /// A token's appearance or retraction, for the callbacks of the liveliness subscribers it
    /// matched.
    #[cfg(feature = "liveliness")]
    Liveliness {
        kind: LivelinessSampleKind,
        key: Span,
        token_id: Word,
    },
    /// A reply, for the callback of the leg of the get it answers.
    #[cfg(feature = "query")]
    Reply(HeldReply),
}

/// A record of the round: what it is, and the callbacks it owes, `owed` of them from `first` on.
/// Both count callbacks of a table of at most `DELIVERY_LANE_CALLBACKS`, which a `u32` holds.
struct Entry {
    what: Held,
    first: u32,
    owed: u32,
}

const _: () = assert!(
    caps::DELIVERY_LANE_CALLBACKS <= u32::MAX as usize,
    "a record names its callbacks by a u32"
);

// A record is aligned as its spans are: a field aligned wider pads every record of the table.
const _: () = assert!(
    core::mem::align_of::<Entry>() == core::mem::align_of::<Span>(),
    "a record holds nothing aligned wider than its spans"
);

impl Entry {
    /// A record of `what` owing one callback, the one at `first` of its table's.
    fn owing_one(what: Held, first: usize) -> Self {
        Self {
            what,
            // Lossless: `first` is a length of the table of callbacks (asserted above).
            first: first as u32,
            owed: 1,
        }
    }

    /// Where the callbacks it owes lie in its table's.
    fn callbacks(&self) -> core::ops::Range<usize> {
        let first = self.first as usize;
        first..first.saturating_add(self.owed as usize)
    }
}

/// A callback a record of the round owes: a call of a subscriber's callback begun on its row under
/// the session's lock and ended as the round is emptied ([`Released::settle`]), or another
/// callback copied out of the row that matched it and let go of, with no lock held, as the round is
/// emptied.
enum Owed {
    /// A subscriber's.
    Subscriber(SubscriberCall),
    /// A liveliness subscriber's.
    #[cfg(feature = "liveliness")]
    Liveliness(LivelinessCallback),
    /// A get's leg's.
    #[cfg(feature = "query")]
    Reply(Arc<ReplyCallback>),
}

impl Owed {
    /// The call, when it is of a subscriber's callback.
    fn subscriber(&self) -> Option<&SubscriberCall> {
        match self {
            Self::Subscriber(callback) => Some(callback),
            #[cfg(feature = "liveliness")]
            Self::Liveliness(_) => None,
            #[cfg(feature = "query")]
            Self::Reply(_) => None,
        }
    }

    /// The callback, when it is a liveliness subscriber's.
    #[cfg(feature = "liveliness")]
    fn liveliness(&self) -> Option<&LivelinessCallback> {
        match self {
            Self::Liveliness(callback) => Some(callback),
            _ => None,
        }
    }

    /// The callback, when it is a leg's.
    #[cfg(feature = "query")]
    fn reply(&self) -> Option<&Arc<ReplyCallback>> {
        match self {
            Self::Reply(callback) => Some(callback),
            _ => None,
        }
    }
}

/// The bytes of the keys the table writes, for a key of `KEY` bytes at most: a key the session
/// resolved from an alias lies in a frame of the dispatch, gone when the callbacks run.
const fn key_bytes<const KEY: usize>() -> usize {
    KEY.saturating_mul(2)
}

/// How many rows of each table of a round its session's arena lends: its records
/// (`DELIVERY_LANE_EVENTS`), the callbacks they owe (`DELIVERY_LANE_CALLBACKS`) and its longest
/// key (`MAX_KEYEXPR_BYTES`), two of which its keys hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoundRowCounts {
    /// The records a round holds at once.
    pub records: usize,
    /// The callbacks those records owe together.
    pub callbacks: usize,
    /// The longest key a record names.
    pub longest_key: usize,
}

impl RoundRowCounts {
    /// The bytes of the keys a round writes: two of the longest, as a key the session resolved
    /// and the one before it may both be held.
    pub const fn key_bytes(&self) -> usize {
        self.longest_key.saturating_mul(2)
    }
}

/// The bytes of one record of a round.
pub(crate) const RECORD_BYTES: usize = core::mem::size_of::<Entry>();

/// The bytes of one callback a record of a round owes.
pub(crate) const CALLBACK_BYTES: usize = core::mem::size_of::<Owed>();

/// The tables of a round, lent from its session's arena ([`RoundRows::lent`]).
pub(crate) struct RoundRows {
    records: BoundedVec<Entry, { caps::DELIVERY_LANE_EVENTS }, Lent>,
    callbacks: BoundedVec<Owed, { caps::DELIVERY_LANE_CALLBACKS }, Lent>,
    keys: BoundedVec<u8, { key_bytes::<{ caps::MAX_KEYEXPR_BYTES }>() }, Lent>,
    longest_key: usize,
}

impl RoundRows {
    /// The tables of a round of `counts`, lent from `arena` in the order the plan counts them:
    /// the records, the callbacks, the keys. Refused past the build's bound of a table or past what
    /// the arena has left.
    pub(crate) fn lent(arena: &mut Arena, counts: RoundRowCounts) -> Result<Self, LendRefused> {
        Ok(Self {
            records: arena.lend(counts.records)?,
            callbacks: arena.lend(counts.callbacks)?,
            keys: arena.lend(counts.key_bytes())?,
            longest_key: counts.longest_key,
        })
    }
}

/// The table holds nothing; the session may write it.
const EMPTY: u8 = 0;
/// The session writes it.
const FILLING: u8 = 1;
/// The records wait for their callbacks; nothing joins them.
const SEALED: u8 = 2;
/// A delivery hands them to their callbacks.
const DELIVERING: u8 = 3;

/// What the round holds: its records, the callbacks they owe, in order, and where their parts lie.
struct Table {
    /// The datagram the records' lent parts lie in, its first byte and its length.
    datagram: (*const u8, usize),
    /// Whether a part lies in it: its link is held back from its next receive.
    lends: bool,
    /// As many records as the session's `DELIVERY_LANE_EVENTS`, rows its arena lent.
    entries: BoundedVec<Entry, { caps::DELIVERY_LANE_EVENTS }, Lent>,
    /// The callbacks the records owe at most, one for each subscriber each of them reaches: as
    /// many as the session's `DELIVERY_LANE_CALLBACKS`, rows its arena lent.
    callbacks: BoundedVec<Owed, { caps::DELIVERY_LANE_CALLBACKS }, Lent>,
    /// The keys written, two of the session's longest, bytes its arena lent.
    keys: BoundedVec<u8, { key_bytes::<{ caps::MAX_KEYEXPR_BYTES }>() }, Lent>,
    /// The session's longest key: the room a record's key may take of `keys`.
    longest_key: usize,
    /// The key written last, which the records on it that follow share.
    key: Option<Span>,
    /// The area the parts that lie nowhere the callbacks can read them are written into, and how
    /// much of it is written.
    area: NonNull<u8>,
    area_bytes: usize,
    written: usize,
}

impl Table {
    /// The part at `span`.
    fn bytes(&self, span: Span) -> &[u8] {
        let (at, len) = (span.at as usize, span.len as usize);
        if len == 0 {
            return &[];
        }
        match span.place {
            // SAFETY: the part lies in the datagram (`Span::lent`), which its link leaves where it
            // lies while the table lends it (`Round::lends_a_datagram`).
            Place::Lent => unsafe { core::slice::from_raw_parts(self.datagram.0.add(at), len) },
            Place::Key => self.keys.get(at..at.saturating_add(len)).unwrap_or(&[]),
            // SAFETY: the part was written inside the area (`Self::write`), which the session's
            // arena lends the round for as long as the round lives, and nothing writes it again
            // until the table is emptied.
            Place::Area => unsafe { core::slice::from_raw_parts(self.area.as_ptr().add(at), len) },
        }
    }

    /// The text at `span`: a key, whose bytes were a `&str`'s.
    fn text(&self, span: Span) -> &str {
        // SAFETY: a key's bytes were a `&str`'s (`SampleView::keyexpr`, `ReplyView::keyexpr`,
        // `LivelinessSample::keyexpr`), copied whole, so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.bytes(span)) }
    }

    /// Where `part` is read: where it lies in `lending`, the datagram a link lends the step, when
    /// it lies there and the table lends no other; written into the area otherwise. `None` when
    /// the area has not the room. Out of line: every offer places its parts through this one body.
    #[inline(never)]
    fn place(&mut self, part: &[u8], lending: Option<(*const u8, usize)>) -> Option<Span> {
        if part.is_empty() {
            return Some(Span::EMPTY);
        }
        if let Some(span) = self.lent(part, lending) {
            return Some(span);
        }
        self.write(part)
    }

    /// Where `part` lies in `lending`, when the table may read it there.
    fn lent(&mut self, part: &[u8], lending: Option<(*const u8, usize)>) -> Option<Span> {
        let datagram = lending?;
        if self.lends && self.datagram != datagram {
            return None;
        }
        let span = Span::lent(part, datagram)?;
        self.datagram = datagram;
        self.lends = true;
        Some(span)
    }

    /// Write `part` after what the area holds.
    fn write(&mut self, part: &[u8]) -> Option<Span> {
        let left = self.area_bytes.checked_sub(self.written)?;
        if part.len() > left {
            return None;
        }
        let span = Span {
            at: u32::try_from(self.written).ok()?,
            len: u32::try_from(part.len()).ok()?,
            place: Place::Area,
        };
        // SAFETY: `written + part.len()` is inside the area (checked above), which the round's
        // table alone writes, and no delivery reads it while the session writes the table.
        unsafe {
            ptr::copy_nonoverlapping(
                part.as_ptr(),
                self.area.as_ptr().add(self.written),
                part.len(),
            );
        }
        self.written = self.written.checked_add(part.len())?;
        Some(span)
    }

    /// Where `key` is read: where it lies in `lending`, where the table wrote it last when it is
    /// that key again, after the keys written before it, or in the area once the keys are full;
    /// `None` when there is no room. Out of line, as [`Self::place`] is.
    #[inline(never)]
    fn place_key(&mut self, key: &[u8], lending: Option<(*const u8, usize)>) -> Option<Span> {
        if let Some(span) = self.lent(key, lending) {
            return Some(span);
        }
        if let Some(span) = self.key {
            if self.bytes(span) == key {
                return Some(span);
            }
        }
        let span = if self.keys.free_slots() >= key.len() {
            let span = Span {
                at: u32::try_from(self.keys.len()).ok()?,
                len: u32::try_from(key.len()).ok()?,
                place: Place::Key,
            };
            self.keys.extend_from_slice(key).ok()?;
            span
        } else {
            self.write(key)?
        };
        self.key = Some(span);
        Some(span)
    }

    /// The parts `rest` holds, read where each lies.
    fn parts<'t>(&'t self, rest: Option<&'t Rest>) -> Parts<'t> {
        let Some(rest) = rest else {
            return Parts {
                attachment: None,
                encoding: None,
                timestamp: None,
                source_info: None,
            };
        };
        Parts {
            attachment: rest.attachment.map(|span| self.bytes(span)),
            encoding: rest
                .encoding
                .map(|(id, schema)| (id, schema.map(|span| self.bytes(span)))),
            timestamp: rest
                .timestamp
                .map(|(time, zid)| (time.get(), self.bytes(zid))),
            source_info: rest.source_info.as_ref(),
        }
    }

    /// `parts` placed for the table.
    fn place_parts(
        &mut self,
        parts: &Parts<'_>,
        lending: Option<(*const u8, usize)>,
    ) -> Option<Option<Rest>> {
        if !parts.carries() {
            return Some(None);
        }
        let attachment = match parts.attachment {
            Some(part) => Some(self.place(part, lending)?),
            None => None,
        };
        let encoding = match parts.encoding {
            Some((id, Some(schema))) => Some((id, Some(self.place(schema, lending)?))),
            Some((id, None)) => Some((id, None)),
            None => None,
        };
        let timestamp = match parts.timestamp {
            Some((time, zid)) => Some((Word::of(time), self.place(zid, lending)?)),
            None => None,
        };
        Some(Some(Rest {
            attachment,
            encoding,
            timestamp,
            source_info: parts.source_info.cloned(),
        }))
    }

    /// The callbacks `entry` owes.
    fn owed(&self, entry: &Entry) -> &[Owed] {
        self.callbacks.get(entry.callbacks()).unwrap_or(&[])
    }

    /// Hold nothing, for the next round, each call it owes ended into `released`; the area stays
    /// the table's.
    fn empty(&mut self, released: &Released) {
        while let Some(owed) = self.callbacks.pop() {
            released.settle(owed);
        }
        self.entries.clear();
        self.keys.clear();
        self.key = None;
        self.datagram = (ptr::null(), 0);
        self.lends = false;
        self.written = 0;
    }
}

/// The calls of the subscribers a put of the session's own reaches, in the order the session's
/// table reached them, each begun on its row ([`Round::captured`]).
#[cfg(feature = "local-subscriber")]
pub(crate) type Captured = BoundedVec<SubscriberCall, { caps::MAX_SUBSCRIPTIONS }, Static>;

/// The rows whose last call ended after their subscriber was undeclared, by handle, for the session
/// to let go of under its lock and drop after it ([`Round::take_released`]). Written by whoever
/// ends a call: a delivery emptying the round with no lock of the session held, the session's own
/// put after its calls, the session refusing a record under its lock.
struct Released {
    handles: Lock<BoundedVec<SubscriberHandle, { caps::MAX_SUBSCRIPTIONS }, Static>>,
    /// The rows not dropped yet: those `handles` holds and those taken from it whose drop has not
    /// ended ([`Releasing`]). A delivery that reads none takes no lock for them, and an
    /// undeclaration that waits for its row reads that no drop is under way.
    owed: AtomicUsize,
}

impl Released {
    fn new() -> Self {
        Self {
            handles: Lock::new(BoundedVec::new_static()),
            owed: AtomicUsize::new(0),
        }
    }

    /// End `call`, its row kept for the session to let go of when it was the row's last call.
    fn end(&self, call: SubscriberCall) {
        let Some(handle) = call.end() else {
            return;
        };
        let kept = self.handles.with(|handles| {
            let kept = handles.push(handle).is_ok();
            if kept {
                self.owed.fetch_add(1, Ordering::AcqRel);
            }
            kept
        });
        // An undeclared row keeps its slot until it is let go of, so the rows waiting here are
        // never more than a table of subscribers holds; one that found no room would keep its slot.
        debug_assert!(kept, "the rows waiting to be let go of fit a table of them");
    }

    /// End what `owed` is: a call, by [`Self::end`]; any other callback is let go of here.
    fn settle(&self, owed: Owed) {
        match owed {
            Owed::Subscriber(call) => self.end(call),
            #[cfg(feature = "liveliness")]
            Owed::Liveliness(callback) => drop(callback),
            #[cfg(feature = "query")]
            Owed::Reply(callback) => drop(callback),
        }
    }

    /// The next row to let go of, counted as owed until what it hands back is dropped.
    fn take(&self) -> Option<Releasing<'_>> {
        if self.owed.load(Ordering::Acquire) == 0 {
            return None;
        }
        let handle = self.handles.with(|handles| handles.pop())?;
        Some(Releasing {
            released: self,
            handle,
        })
    }

    /// Whether no row is owed: none waits to be let go of and no drop of one is under way.
    fn settled(&self) -> bool {
        self.owed.load(Ordering::Acquire) == 0
    }
}

/// A row taken to be let go of ([`Round::take_released`]): owed until this is dropped, which its
/// taker does once the row was dropped.
pub(crate) struct Releasing<'r> {
    released: &'r Released,
    handle: SubscriberHandle,
}

impl Releasing<'_> {
    /// The row's handle.
    pub(crate) fn handle(&self) -> SubscriberHandle {
        self.handle
    }
}

impl Drop for Releasing<'_> {
    fn drop(&mut self) {
        self.released.owed.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The session's round of deliveries (see the module).
pub(crate) struct Round {
    state: AtomicU8,
    table: UnsafeCell<Table>,
    /// Whether a record lies in the datagram a link lent ([`Self::lends_a_datagram`]): set by the
    /// session's writes, cleared as a delivery empties the table.
    lends: AtomicBool,
    /// Whether a source the gate does not hold back owes the round records it had no room for (a
    /// lost face's tokens, still to be retracted): no link is read until it has handed them, so
    /// they come before anything the link brings after the loss ([`Self::owe`]).
    owes: AtomicBool,
    /// Where the datagram lies that a link lends the session's step now, when the link leaves it
    /// where it lies until it is next asked to receive (`RoundGate::recv_with`): its first byte
    /// and its length. Written under the session's lock.
    lending: UnsafeCell<Option<(*const u8, usize)>>,
    /// The datagram lent before a rejoined message was lent in its place ([`Self::lend_rejoined`]),
    /// lent again once the message's records are dispatched. Written under the session's lock.
    lent_before: UnsafeCell<Option<(*const u8, usize)>>,
    /// The calls of the subscribers the samples offered now reach, begun on their rows and handed
    /// to the session's own put instead of held, while it asks for them ([`Self::capture`]).
    /// Written under the session's lock.
    #[cfg(feature = "local-subscriber")]
    capturing: UnsafeCell<Option<Captured>>,
    /// The rows whose last call ended after their subscriber was undeclared ([`Released`]).
    released: Released,
    /// What was not handed a callback ([`RoundCounts`]).
    dropped: AtomicU64,
    held_over: AtomicU64,
    /// Whether what is offered now is a record a link's gate let through
    /// ([`Self::offering_gated`]), which a debug build's check of the gate's bound reads.
    #[cfg(debug_assertions)]
    gated: AtomicBool,
    /// The rounds handed out and the samples in them, and of those the ones read where their
    /// datagram lies, which the tests count.
    #[cfg(all(test, feature = "std"))]
    rounds: core::sync::atomic::AtomicUsize,
    #[cfg(all(test, feature = "std"))]
    samples: core::sync::atomic::AtomicUsize,
    #[cfg(all(test, feature = "std"))]
    lent_samples: core::sync::atomic::AtomicUsize,
}

// SAFETY: the table is reached by the holder of the session's lock while the state is empty or
// filling, and by the one delivery that took it while it is delivering; `lending` and `capturing`
// by the holder of the session's lock alone; `released` behind its own lock; every other field is
// an atomic or never written after the round is made. A call the table owes reads a row its table
// keeps where it lies until the call ends, through a sink that is `Send` and `Sync`; every other
// callback it owes is `Send` and `Sync`; and the parts it reads lie where the link and the arena
// keep them while it holds them.
unsafe impl Send for Round {}
// SAFETY: as `Send`.
unsafe impl Sync for Round {}

impl Round {
    /// The session's round over the `area_bytes` bytes at `area`, held to `limits`, built where
    /// the allocation that shares it keeps it: its table's rows are kilobytes, which a value of the
    /// whole would lay in the frame of the session's open once for each move.
    ///
    /// # Safety
    /// `area` points at `area_bytes` bytes valid for reads and writes, used by nothing else, for
    /// as long as the round is used.
    #[inline(never)]
    pub(crate) unsafe fn shared_over(
        area: NonNull<u8>,
        area_bytes: usize,
        rows: RoundRows,
    ) -> Arc<Self> {
        // `Arc::new_uninit` is newer than this crate's minimum Rust; an uninitialised value put in
        // an `Arc` is the same allocation, and the optimiser writes nothing into it.
        let raw = Arc::into_raw(Arc::new(MaybeUninit::<Self>::uninit())).cast_mut();
        // SAFETY: `raw` is the one handle of an allocation made on the line above, so the place
        // is valid and nothing else reads or writes it while it is written; the rest is the
        // caller's.
        unsafe { Self::write_in((*raw).as_mut_ptr(), area, area_bytes, rows) };
        // SAFETY: `write_in` wrote every field into the allocation, and a `MaybeUninit<T>` has
        // the size and alignment of `T`, which is what `Arc::from_raw` asks of the pointer's type.
        unsafe { Arc::from_raw(raw.cast::<Self>().cast_const()) }
    }

    /// An empty round written where `at` points, field by field.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, and what it held is overwritten without a drop; the
    /// area is as [`Self::shared_over`] says.
    #[inline(never)]
    unsafe fn write_in(at: *mut Self, area: NonNull<u8>, area_bytes: usize, rows: RoundRows) {
        // SAFETY: the caller's contract; an `UnsafeCell<T>` is laid out as the `T` it holds, and
        // each field is written once through a pointer to it. `every_field_is_written` names
        // every field, so the round is whole when it is shared.
        unsafe {
            ptr::write(addr_of_mut!((*at).state), AtomicU8::new(EMPTY));
            let table = addr_of_mut!((*at).table).cast::<Table>();
            ptr::write(addr_of_mut!((*table).datagram), (ptr::null(), 0));
            ptr::write(addr_of_mut!((*table).lends), false);
            ptr::write(addr_of_mut!((*table).entries), rows.records);
            ptr::write(addr_of_mut!((*table).callbacks), rows.callbacks);
            ptr::write(addr_of_mut!((*table).keys), rows.keys);
            ptr::write(addr_of_mut!((*table).longest_key), rows.longest_key);
            ptr::write(addr_of_mut!((*table).key), None);
            ptr::write(addr_of_mut!((*table).area), area);
            ptr::write(addr_of_mut!((*table).area_bytes), area_bytes);
            ptr::write(addr_of_mut!((*table).written), 0);
            ptr::write(addr_of_mut!((*at).lends), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).owes), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).lending), UnsafeCell::new(None));
            ptr::write(addr_of_mut!((*at).lent_before), UnsafeCell::new(None));
            #[cfg(feature = "local-subscriber")]
            ptr::write(addr_of_mut!((*at).capturing), UnsafeCell::new(None));
            ptr::write(addr_of_mut!((*at).released), Released::new());
            ptr::write(addr_of_mut!((*at).dropped), AtomicU64::new(0));
            ptr::write(addr_of_mut!((*at).held_over), AtomicU64::new(0));
            #[cfg(debug_assertions)]
            ptr::write(addr_of_mut!((*at).gated), AtomicBool::new(false));
            #[cfg(all(test, feature = "std"))]
            {
                use core::sync::atomic::AtomicUsize;
                ptr::write(addr_of_mut!((*at).rounds), AtomicUsize::new(0));
                ptr::write(addr_of_mut!((*at).samples), AtomicUsize::new(0));
                ptr::write(addr_of_mut!((*at).lent_samples), AtomicUsize::new(0));
            }
        }
    }

    /// A field added to [`Round`] or its table and not written by [`Self::write_in`] would be
    /// read uninitialised. This destructures both with no `..`, so adding a field without naming
    /// it here (and so without writing it there) does not compile.
    #[allow(dead_code)]
    fn every_field_is_written(round: Self) {
        let Self {
            state: _,
            table,
            lends: _,
            owes: _,
            lending: _,
            lent_before: _,
            #[cfg(feature = "local-subscriber")]
                capturing: _,
            released: _,
            dropped: _,
            held_over: _,
            #[cfg(debug_assertions)]
                gated: _,
            #[cfg(all(test, feature = "std"))]
                rounds: _,
            #[cfg(all(test, feature = "std"))]
                samples: _,
            #[cfg(all(test, feature = "std"))]
                lent_samples: _,
        } = round;
        let Table {
            datagram: _,
            lends: _,
            entries: _,
            callbacks: _,
            keys: _,
            longest_key: _,
            key: _,
            area: _,
            area_bytes: _,
            written: _,
        } = table.into_inner();
    }

    /// The table, to write, while it is empty or filling: `None` once it is sealed or handed out.
    ///
    /// # Safety
    /// The caller holds the session's lock, and holds no other borrow of the table.
    #[allow(clippy::mut_from_ref)]
    unsafe fn writable(&self) -> Option<&mut Table> {
        match self.state.load(Ordering::Acquire) {
            // SAFETY: an empty or filling table is the lock holder's, and the caller holds the
            // lock and no other borrow of it.
            EMPTY | FILLING => Some(unsafe { &mut *self.table.get() }),
            _ => None,
        }
    }

    /// A record was written into `table`: it is filling, and lends what it lends.
    fn filled(&self, table: &Table) {
        if table.lends {
            self.lends.store(true, Ordering::Release);
        }
        self.state.store(FILLING, Ordering::Release);
    }

    /// The datagram a link lends the step now.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn lending(&self) -> Option<(*const u8, usize)> {
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.lending.get() }
    }

    /// Whether `table` takes one more record, owing `callbacks` callbacks.
    fn takes(table: &Table, callbacks: usize) -> bool {
        table.entries.free_slots() > 0 && table.callbacks.free_slots() >= callbacks
    }

    /// Whether `table` takes one more callback of the record it holds last.
    fn joins(table: &Table) -> bool {
        table.callbacks.free_slots() > 0
    }

    /// Count a record that found no room, apart when it holds its sender. A record a link's gate
    /// let through waited for the room one record can take ([`RoundGate`]), so one that holds its
    /// sender and finds no room is a defect of that bound, and a debug build stops there.
    fn refuse(&self, holds_sender: bool) {
        #[cfg(debug_assertions)]
        debug_assert!(
            !(holds_sender && self.gated.load(Ordering::Acquire)),
            "a record the gate let through found no room in the round"
        );
        let count = if holds_sender {
            &self.held_over
        } else {
            &self.dropped
        };
        count.fetch_add(1, Ordering::Relaxed);
    }

    /// Hand out, instead of holding, the calls of the subscribers the samples offered from here on
    /// reach, until [`Self::captured`]: how the session's own put learns which of its subscribers
    /// it reaches and what to call, to hand the sample to them itself and end each call
    /// ([`Self::end_call`]).
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "local-subscriber")]
    pub(crate) unsafe fn capture(&self) {
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.capturing.get() = Some(BoundedVec::new_static()) };
    }

    /// The calls of the subscribers reached since [`Self::capture`]; what is offered after this is
    /// held again.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "local-subscriber")]
    pub(crate) unsafe fn captured(&self) -> Captured {
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { (*self.capturing.get()).take() }.unwrap_or_else(BoundedVec::new_static)
    }

    /// Hold `sample` for `call`, a call of a subscriber's callback begun on its row, read where it
    /// lies when it lies in the datagram a link lends the step. A sample offered again for one more
    /// subscriber is written once; what finds no room is counted, and its call ended.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(crate) unsafe fn offer_sample(&self, call: SubscriberCall, sample: &dyn SampleView) {
        // The session's own put is handed the calls and holds nothing.
        #[cfg(feature = "local-subscriber")]
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        if let Some(found) = unsafe { &mut *self.capturing.get() } {
            let kept = match found.push(call) {
                Ok(()) => true,
                Err(full) => {
                    self.released.end(full.0);
                    false
                }
            };
            debug_assert!(kept, "a session's subscribers fit the table of them");
            return;
        }
        let holds_sender = holds_its_sender(sample.reliability(), sample.qos());
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(holds_sender);
            self.released.end(call);
            return;
        };
        let call = match self.join_sample(table, call, sample) {
            Ok(()) => {
                self.filled(table);
                return;
            }
            Err(call) => call,
        };
        if !Self::takes(table, 1) {
            self.refuse(holds_sender);
            self.released.end(call);
            return;
        }
        let Some((key, payload, rest)) = Self::place_sample(table, sample, lending) else {
            self.refuse(holds_sender);
            self.released.end(call);
            return;
        };
        let first = table.callbacks.len();
        let entry = table.entries.push(Entry::owing_one(
            Held::Sample {
                head: Head {
                    kind: sample.kind(),
                    reliability: sample.reliability(),
                    qos: sample.qos(),
                    key,
                    payload,
                },
                rest,
            },
            first,
        ));
        let kept = match entry {
            Ok(()) => self.owe_call(table, call),
            Err(_) => {
                self.released.end(call);
                false
            }
        };
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(table);
    }

    /// Owe `call` in `table`, which has the room for it: `false`, the call ended, when it had
    /// not after all.
    fn owe_call(&self, table: &mut Table, call: SubscriberCall) -> bool {
        match table.callbacks.push(Owed::Subscriber(call)) {
            Ok(()) => true,
            Err(full) => {
                self.released.settle(full.0);
                false
            }
        }
    }

    /// `sample`'s key, payload and other parts placed in `table`; `None` when a part finds no
    /// room.
    fn place_sample(
        table: &mut Table,
        sample: &dyn SampleView,
        lending: Option<(*const u8, usize)>,
    ) -> Option<(Span, Span, Option<Rest>)> {
        let key = table.place_key(sample.keyexpr().as_bytes(), lending)?;
        let payload = table.place(sample.payload(), lending)?;
        let rest = table.place_parts(&Parts::of(sample), lending)?;
        Some((key, payload, rest))
    }

    /// Join `call` to the record `table` holds last when that is `sample` and no call of the same
    /// row is owed it yet; the call back when it does not join.
    fn join_sample(
        &self,
        table: &mut Table,
        call: SubscriberCall,
        sample: &dyn SampleView,
    ) -> Result<(), SubscriberCall> {
        let Some(
            entry @ Entry {
                what: Held::Sample { head, rest },
                ..
            },
        ) = table.entries.last()
        else {
            return Err(call);
        };
        let joins = head.kind == sample.kind()
            && head.reliability == sample.reliability()
            && head.qos == sample.qos()
            && same(table.bytes(head.key), sample.keyexpr().as_bytes())
            && same(table.bytes(head.payload), sample.payload())
            && table.parts(rest.as_ref()).same(&Parts::of(sample))
            && !table
                .owed(entry)
                .iter()
                .filter_map(Owed::subscriber)
                .any(|held| held.same_row(&call));
        if !joins || !Self::joins(table) {
            return Err(call);
        }
        if self.owe_call(table, call) {
            if let Some(last) = table.entries.last_mut() {
                last.owed = last.owed.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Hold `sample`, a token's appearance or retraction, for `callback`, a liveliness
    /// subscriber's, its key read where it lies or written into the table. Written once for the
    /// liveliness subscribers it reaches one after the other, as a sample is; what finds no room
    /// is counted with the records that hold their sender.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "liveliness")]
    pub(crate) unsafe fn offer_liveliness(
        &self,
        callback: &LivelinessCallback,
        sample: &LivelinessSample<'_>,
    ) {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(true);
            return;
        };
        let key = sample.keyexpr.as_bytes();
        if let Some(
            entry @ Entry {
                what:
                    Held::Liveliness {
                        kind,
                        key: at,
                        token_id,
                    },
                ..
            },
        ) = table.entries.last()
        {
            let joins = *kind == sample.kind
                && token_id.get() == sample.token_id
                && same(table.bytes(*at), key)
                && !table
                    .owed(entry)
                    .iter()
                    .filter_map(Owed::liveliness)
                    .any(|held| Arc::ptr_eq(held, callback));
            if joins && Self::joins(table) {
                if table
                    .callbacks
                    .push(Owed::Liveliness(Arc::clone(callback)))
                    .is_err()
                {
                    self.refuse(true);
                    return;
                }
                if let Some(last) = table.entries.last_mut() {
                    last.owed = last.owed.saturating_add(1);
                }
                self.filled(table);
                return;
            }
        }
        if !Self::takes(table, 1) {
            self.refuse(true);
            return;
        }
        let Some(at) = table.place_key(key, lending) else {
            self.refuse(true);
            return;
        };
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(Entry::owing_one(
                Held::Liveliness {
                    kind: sample.kind,
                    key: at,
                    token_id: Word::of(sample.token_id),
                },
                first,
            ))
            .is_ok()
            && table
                .callbacks
                .push(Owed::Liveliness(Arc::clone(callback)))
                .is_ok();
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(table);
    }

    /// Hold `view`, a reply, for `callback`, the leg's it answers, each part read where it lies
    /// or written into the table. A reply is the answer a get waits for: one that finds no room is
    /// counted with the records that hold their sender.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "query")]
    pub(crate) unsafe fn offer_reply(&self, callback: &Arc<ReplyCallback>, view: &dyn ReplyView) {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(true);
            return;
        };
        if !Self::takes(table, 1) {
            self.refuse(true);
            return;
        }
        let Some(reply) = Self::place_reply(table, view, lending) else {
            self.refuse(true);
            return;
        };
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(Entry::owing_one(Held::Reply(reply), first))
            .is_ok()
            && table
                .callbacks
                .push(Owed::Reply(Arc::clone(callback)))
                .is_ok();
        debug_assert!(kept, "the table had the room its checks found");
        self.filled(table);
    }

    /// `view` placed in `table`; `None` when a part finds no room.
    #[cfg(feature = "query")]
    fn place_reply(
        table: &mut Table,
        view: &dyn ReplyView,
        lending: Option<(*const u8, usize)>,
    ) -> Option<HeldReply> {
        let key = table.place_key(view.keyexpr().as_bytes(), lending)?;
        let payload = table.place(view.payload(), lending)?;
        let attachment = match view.attachment() {
            Some(part) => Some(table.place(part, lending)?),
            None => None,
        };
        let encoding = match view.put_encoding().or_else(|| view.err_encoding()) {
            Some((id, Some(schema))) => Some((id, Some(table.place(schema, lending)?))),
            Some((id, None)) => Some((id, None)),
            None => None,
        };
        let stamp = view
            .timestamp_parts()
            .map(|stamp| (stamp.time, stamp.zid))
            .or_else(|| {
                view.timestamp()
                    .map(|hint| (hint.time, hint.zid.as_slice()))
            });
        let timestamp = match stamp {
            Some((time, zid)) => Some((Word::of(time), table.place(zid, lending)?)),
            None => None,
        };
        let responder = match view.responder() {
            Some((zid, eid)) => Some((table.place(zid, lending)?, eid)),
            None => None,
        };
        Some(HeldReply {
            rid: view.rid(),
            kind: view.kind(),
            qos: view.qos(),
            key,
            payload,
            attachment,
            encoding,
            timestamp,
            source_info: view.source_info().cloned(),
            responder,
        })
    }

    /// Take no more records: what is offered after this is refused until a delivery has handed
    /// these out. What the release of the session's lock does.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(crate) unsafe fn seal(&self) {
        let _ = self
            .state
            .compare_exchange(FILLING, SEALED, Ordering::AcqRel, Ordering::Relaxed);
    }

    /// The datagram a link lends the session's step now, whose records may be read where they lie;
    /// `None` once the link takes it back.
    ///
    /// # Safety
    /// The caller holds the session's lock, and the link leaves the bytes where they lie until it
    /// is next asked to receive or to be serviced, which it is not while the table lends them
    /// ([`Self::lends_a_datagram`]).
    pub(crate) unsafe fn set_lending(&self, datagram: Option<&[u8]>) {
        let range = datagram.map(|bytes| (bytes.as_ptr(), bytes.len()));
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.lending.get() = range };
    }

    /// Whether a source the gate does not hold back still owes the round records (`owed`): the
    /// links are read no further until it says it owes none.
    #[cfg(feature = "liveliness")]
    pub(crate) fn owe(&self, owed: bool) {
        self.owes.store(owed, Ordering::Release);
    }

    /// Whether a source the gate does not hold back still owes the round records ([`Self::owe`]).
    pub(crate) fn owes(&self) -> bool {
        self.owes.load(Ordering::Acquire)
    }

    /// The records offered from here on lie in `message`, a message rejoined from its fragments in
    /// its chain's buffer, until the same call with `None`, which lends again the datagram lent
    /// before it. A part is read there only while the round lends nothing else
    /// (`Table::lent`); otherwise it is copied, as one from any source but the lent one is. The
    /// buffer is written again only when a fragment is staged into it, which needs a link read,
    /// and the gate reads none while the round lends.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(crate) unsafe fn lend_rejoined(&self, message: Option<&[u8]>) {
        // SAFETY: the caller's contract: both are written under the session's lock alone.
        unsafe {
            match message {
                Some(bytes) => {
                    *self.lent_before.get() = *self.lending.get();
                    *self.lending.get() = Some((bytes.as_ptr(), bytes.len()));
                }
                None => *self.lending.get() = (*self.lent_before.get()).take(),
            }
        }
    }

    /// Whether a record lies in the datagram a link lent: no link is read or serviced until its
    /// callbacks have returned. Asked by the session's step, which holds the session's lock.
    pub(crate) fn lends_a_datagram(&self) -> bool {
        self.lends.load(Ordering::Acquire)
    }

    /// Whether the table takes the room `room` of one more record: empty, or filling with an
    /// entry, the callbacks, a key (in the keys, or in the area past the record's bytes) and the
    /// bytes of a record written whole left. An empty table takes any record, so a link is never
    /// stopped for good.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(crate) unsafe fn has_room(&self, room: ReadRoom) -> bool {
        match self.state.load(Ordering::Acquire) {
            EMPTY => true,
            FILLING => {
                // SAFETY: a filling table is the lock holder's, and the caller holds the lock.
                let table = unsafe { &*self.table.get() };
                let keys = table.keys.free_slots() >= table.longest_key;
                Self::takes(table, room.callbacks)
                    && table
                        .area_bytes
                        .checked_sub(table.written)
                        .and_then(|left| left.checked_sub(room.bytes))
                        .is_some_and(|spare| keys || spare >= table.longest_key)
            }
            _ => false,
        }
    }

    /// Let go of the round's tables, their records and the callbacks those owe, each call ended,
    /// before the arena that lent them: what the session's end does. The tables left are lent
    /// nothing, so the round's own drop, which may come after the arena's, reads none of the arena.
    /// A row whose last call this ends waits in [`Self::take_released`].
    ///
    /// # Safety
    /// No delivery runs and none starts: the session's last handle is being let go of.
    pub(crate) unsafe fn let_go(&self) {
        // SAFETY: the caller's contract: nothing else reaches the table now.
        let table = unsafe { &mut *self.table.get() };
        table.empty(&self.released);
        drop(core::mem::take(&mut table.entries));
        drop(core::mem::take(&mut table.callbacks));
        drop(core::mem::take(&mut table.keys));
        self.lends.store(false, Ordering::Release);
        self.state.store(EMPTY, Ordering::Release);
    }

    /// Whether the table holds nothing: what a leg's end waits for, so that it is told after every
    /// reply held before it.
    #[cfg(feature = "query")]
    pub(crate) fn is_idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == EMPTY
    }

    /// Whether what is offered from here on is a record a link's gate let through (`true`), which
    /// waited for the room one record can take ([`RoundGate`]), or anything else (`false`): the
    /// session's own puts, the tokens a lost face retracts, a group's records. Only the first is a
    /// defect when it holds its sender and finds no room. A debug build's alone.
    #[cfg(debug_assertions)]
    pub(crate) fn offering_gated(&self, gated: bool) {
        self.gated.store(gated, Ordering::Release);
    }

    /// What the round did not hand a callback.
    pub(crate) fn counts(&self) -> RoundCounts {
        RoundCounts {
            dropped: self.dropped.load(Ordering::Relaxed),
            held_over: self.held_over.load(Ordering::Relaxed),
        }
    }

    /// End `call`, which the session's own put made ([`Self::captured`]): its row waits in
    /// [`Self::take_released`] when it was the row's last call.
    #[cfg(feature = "local-subscriber")]
    pub(crate) fn end_call(&self, call: SubscriberCall) {
        self.released.end(call);
    }

    /// The next row whose last call ended after its subscriber was undeclared, for the session to
    /// let go of (`SessionTables::release_subscriber`) under its lock and drop after it, and then
    /// drop what this hands back.
    pub(crate) fn take_released(&self) -> Option<Releasing<'_>> {
        self.released.take()
    }

    /// Whether no row waits to be let go of and no drop of one is under way: what an undeclaration
    /// that waits for its row reads once the row left its table.
    pub(crate) fn released_settled(&self) -> bool {
        self.released.settled()
    }

    /// Empty a sealed round no delivery has taken, handing nothing out, its calls ended: what the
    /// session's close does, after which no callback of it is called. `false` when no round
    /// waited, or a delivery hands it out now, which empties it itself.
    pub(crate) fn discard(&self) -> bool {
        if self
            .state
            .compare_exchange(SEALED, DELIVERING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        drop(Emptied(self));
        true
    }

    /// Hand each record the table holds, sealed, to its callbacks in order, and empty it: whether
    /// there was anything to hand. Nothing of the session is held; a delivery that finds the table
    /// not sealed, or taken by another, hands nothing.
    pub(crate) fn deliver(&self) -> bool {
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
            let owed = table.owed(entry);
            match &entry.what {
                Held::Sample { head, rest } => {
                    let sample = RoundSample {
                        head: *head,
                        rest: rest.as_ref(),
                        table,
                    };
                    for call in owed.iter().filter_map(Owed::subscriber) {
                        call.hand(&sample);
                    }
                }
                #[cfg(feature = "liveliness")]
                Held::Liveliness {
                    kind,
                    key,
                    token_id,
                } => {
                    let sample = LivelinessSample {
                        kind: *kind,
                        keyexpr: table.text(*key),
                        token_id: token_id.get(),
                    };
                    for callback in owed.iter().filter_map(Owed::liveliness) {
                        callback.call(sample);
                    }
                }
                #[cfg(feature = "query")]
                Held::Reply(reply) => {
                    let view = RoundReply { reply, table };
                    for callback in owed.iter().filter_map(Owed::reply) {
                        callback.call(&view);
                    }
                }
            }
        }
        #[cfg(all(test, feature = "std"))]
        self.count_round(table);
        drop(emptied);
        true
    }

    /// Count a round handed out, its samples, and of those the ones read where they lie.
    #[cfg(all(test, feature = "std"))]
    fn count_round(&self, table: &Table) {
        let samples = table
            .entries
            .iter()
            .filter(|entry| matches!(entry.what, Held::Sample { .. }))
            .count();
        let lent = table
            .entries
            .iter()
            .filter(|entry| match &entry.what {
                Held::Sample { head, .. } => head.payload.place == Place::Lent,
                #[allow(unreachable_patterns)]
                _ => false,
            })
            .count();
        self.rounds.fetch_add(1, Ordering::SeqCst);
        self.samples.fetch_add(samples, Ordering::SeqCst);
        self.lent_samples.fetch_add(lent, Ordering::SeqCst);
    }

    /// How many rounds were handed out since the round was made, which the tests count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn rounds_handed(&self) -> usize {
        self.rounds.load(Ordering::SeqCst)
    }

    /// How many samples the rounds handed out held, which the tests count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_handed(&self) -> usize {
        self.samples.load(Ordering::SeqCst)
    }

    /// How many samples were handed where their datagram lies, which the tests count.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn samples_lent(&self) -> usize {
        self.lent_samples.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
impl Round {
    /// A round over an area of `bytes` the test leaks, holding `events` records at once, its tables
    /// lent from an arena the test leaks too, so both outlive the round.
    pub(crate) fn leaked(bytes: usize, events: usize) -> Arc<Self> {
        use crate::arena::{AllocatorMemory, SessionArena};
        use wz_session_core::bounded::ARENA_ALIGN;

        let counts = RoundRowCounts {
            records: events,
            callbacks: caps::DELIVERY_LANE_CALLBACKS,
            longest_key: caps::MAX_KEYEXPR_BYTES,
        };
        // Each table on a span of its own, rounded up to the next start of one.
        let bytes_of_rows = events * RECORD_BYTES
            + counts.callbacks * CALLBACK_BYTES
            + counts.key_bytes()
            + 3 * ARENA_ALIGN;
        let arena: &'static mut SessionArena = Box::leak(Box::new(
            SessionArena::of_bytes(bytes_of_rows, &AllocatorMemory)
                .expect("the host has the memory"),
        ));
        let rows = RoundRows::lent(arena.arena_mut(), counts).expect("the arena has the rows");
        let area: &'static mut [u8] = vec![0u8; bytes].leak();
        // SAFETY: the area is leaked, so it outlives the round, and nothing else uses it.
        unsafe { Self::shared_over(NonNull::from(area).cast::<u8>(), bytes, rows) }
    }
}

/// A delivery of the round ends, a callback's unwinding included: the table is emptied, its calls
/// ended and its other callbacks let go of with no lock of the session held, and given back to the
/// session.
struct Emptied<'r>(&'r Round);

impl Drop for Emptied<'_> {
    fn drop(&mut self) {
        // SAFETY: the table is this delivery's until the store below gives it back.
        unsafe { (*self.0.table.get()).empty(&self.0.released) };
        self.0.lends.store(false, Ordering::Release);
        self.0.state.store(EMPTY, Ordering::Release);
    }
}

/// A sample of the round, read where its parts lie: what each of its subscribers' callbacks is
/// handed.
struct RoundSample<'t> {
    head: Head,
    rest: Option<&'t Rest>,
    table: &'t Table,
}

impl SampleView for RoundSample<'_> {
    fn keyexpr(&self) -> &str {
        self.table.text(self.head.key)
    }

    fn payload(&self) -> &[u8] {
        self.table.bytes(self.head.payload)
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
        Some(self.table.bytes(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.rest?.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        let (time, zid) = self.rest?.timestamp?;
        Some((time.get(), self.table.bytes(zid)))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        let (id, schema) = self.rest?.encoding?;
        Some((id, schema.map(|span| self.table.bytes(span))))
    }
}

/// A reply of the round, read where its parts lie: what its leg's callback is handed.
#[cfg(feature = "query")]
struct RoundReply<'t> {
    reply: &'t HeldReply,
    table: &'t Table,
}

#[cfg(feature = "query")]
impl RoundReply<'_> {
    /// Its encoding, when it is of the kind `kind`.
    fn encoding_of(&self, kind: ReplyKind) -> Option<(u32, Option<&[u8]>)> {
        if self.reply.kind != kind {
            return None;
        }
        self.reply
            .encoding
            .map(|(id, schema)| (id, schema.map(|span| self.table.bytes(span))))
    }
}

#[cfg(feature = "query")]
impl ReplyView for RoundReply<'_> {
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.reply.rid
    }

    fn keyexpr(&self) -> &str {
        self.table.text(self.reply.key)
    }

    fn kind(&self) -> ReplyKind {
        self.reply.kind
    }

    fn payload(&self) -> &[u8] {
        self.table.bytes(self.reply.payload)
    }

    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Err)
    }

    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Put)
    }

    fn attachment(&self) -> Option<&[u8]> {
        self.reply.attachment.map(|span| self.table.bytes(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.reply.source_info.as_ref()
    }

    fn timestamp_parts(&self) -> Option<wz_session_core::reply_stage::TimestampParts<'_>> {
        self.reply
            .timestamp
            .map(|(time, zid)| wz_session_core::reply_stage::TimestampParts {
                time: time.get(),
                zid: self.table.bytes(zid),
            })
    }

    fn responder(&self) -> Option<(&[u8], u32)> {
        self.reply
            .responder
            .map(|(zid, eid)| (self.table.bytes(zid), eid))
    }

    fn qos(&self) -> Option<QosLevel> {
        self.reply.qos
    }
}

/// The group twin of [`RoundGate`]: whether the round has the room one record of a group can
/// take (`room`, decision Q4), asked before each datagram of the group and before each further
/// message and record of one its transport keeps, and holds nothing lent. While it has not, what
/// the members send waits in the group's socket.
///
/// # Safety
/// The gate it answers is asked by the session's step alone, under the session's lock, as the
/// group's transport is driven.
#[cfg(feature = "group")]
pub(crate) unsafe fn takes_a_group_read(
    round: Arc<Round>,
    room: ReadRoom,
) -> impl Fn() -> bool + 'static {
    // SAFETY: the caller's contract: the session's lock is held whenever this is asked.
    move || !round.owes() && !round.lends_a_datagram() && unsafe { round.has_room(room) }
}

/// `pump`, which gives the session nothing while the round has not the room one record can take
/// (`room`, decision Q4), nor while a record lies in the datagram a link lent: not the next
/// datagram, and not the next record of one the link keeps. What the peer sends meanwhile waits in
/// the link, and the transport's flow control carries the wait back to it.
pub(crate) struct RoundGate<P> {
    pump: P,
    round: Arc<Round>,
    room: ReadRoom,
}

impl<P> RoundGate<P> {
    /// `pump`, gated by `round` for the room `room` of one of its records.
    ///
    /// # Safety
    /// Asked by the session's step alone, which holds the session's lock.
    pub(crate) unsafe fn new(pump: P, round: Arc<Round>, room: ReadRoom) -> Self {
        Self { pump, round, room }
    }

    /// Whether the round has the room of a record, and nothing a source outside the gate owes is
    /// still to come before it.
    fn has_room(&self) -> bool {
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        !self.round.owes() && unsafe { self.round.has_room(self.room) }
    }

    /// Whether the link is held back from receiving: a record lies in the datagram it lent last
    /// (the next receive may write where it lies), or the round has not the room of a record.
    fn shut(&self) -> bool {
        self.round.lends_a_datagram() || !self.has_room()
    }
}

impl<P: SessionDatagramLink> SessionDatagramLink for RoundGate<P> {
    /// A link whose datagram a record is read from is not serviced: its stack may read the next
    /// datagram into the buffer the record lies in.
    fn service(&self) {
        if !self.round.lends_a_datagram() {
            self.pump.service()
        }
    }

    fn service_within(&self, max_wait_ms: u64) {
        if !self.round.lends_a_datagram() {
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
    /// is next asked to receive tells the round where it lies while it is lent, so a record of it
    /// may be read there.
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
            // asked to receive or to be serviced, which it is not while a record lies there.
            unsafe { self.round.set_lending(Some(datagram)) };
            f(datagram);
            // SAFETY: as above.
            unsafe { self.round.set_lending(None) };
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

    #[cfg(feature = "listen")]
    fn waits_for_buffer(&self) -> bool {
        self.pump.waits_for_buffer()
    }

    // The gate holds back input only: what the session owes the stack is written whatever it
    // holds, and the owner's wait wakes for it.
    fn owes_write(&self) -> bool {
        self.pump.owes_write()
    }

    // What the session owes the stack is written whatever the round holds, as `owes_write` says.
    #[cfg(feature = "listen")]
    fn write_owed_now(&self) {
        self.pump.write_owed_now()
    }

    /// The rest of a datagram already read is held back with the link's next one while the round
    /// has not the room of a record. A record lying in the datagram does not hold the rest back:
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

    fn input_wait(&self) -> Option<WaitOn> {
        self.pump.input_wait()
    }

    // The gate holds back input only: what the session sends goes out while the round is full.
    fn room_wait(&self) -> Option<WaitOn> {
        self.pump.room_wait()
    }
}
