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
//! lie when they lie in the datagram a link lends the step (UDP, a stream), or in a message
//! rejoined from its fragments whose buffer the round keeps until it is emptied
//! ([`Round::end_rejoined`]), so a sample of either is never copied; a key the session resolved
//! from an alias lies in a frame of the dispatch, and is written into the table's keys. The round
//! keeps no area to copy any other part into: a record with a part that lies nowhere the round
//! reads it is refused and counted ([`RoundCounts::unplaced`]). A sample one fan-out hands to
//! many subscribers is read and written once, at its first row: each later row's call joins the
//! ones the record owes, or is refused as the first was.
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
//! ([`ReadRoom`], and the gate an engine puts on each of its links): what the peer sends meanwhile waits in the link, and the
//! transport's flow control carries the wait back to the sender. Nor is a link read again while a
//! record lies in the datagram it lent, which its next receive may overwrite. The room is the
//! larger of a batch and a rejoined message, with the most a sample adds to the record it came
//! in: its key resolved from an alias, its timestamp's clock id and the subscribers' share; and
//! an entry, and a callback for each subscriber. What finds no room is counted
//! ([`RoundCounts`]): apart when its congestion control holds its sender, which a record the gate
//! let through never does (a debug build stops there).

use alloc::sync::{Arc, Weak};
use core::cell::{OnceCell, UnsafeCell};
use core::convert::Infallible;
use core::mem::MaybeUninit;
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};
// The split `hlc` and `session_actions` use: the host profile has the native atomics, the
// `no_std` profile gets the critical-section ones for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize};
#[cfg(feature = "no_std")]
use portable_atomic::{AtomicU64, AtomicU8, AtomicUsize};

use crate::bounded::{Arena, BoundedVec, LendRefused, Lent, Static};
use crate::byte_cells::{ByteBuf, KeptBytes};
use crate::caps;
use crate::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use crate::key_arena::{KeyRef, KeySpace};
use crate::plane_lock::LockFamily;
use crate::qos::CongestionControl;
use crate::query_sink::QueryView;
use crate::reliability::Reliability;
use crate::reply_sink::{ReplyKind, ReplyView};
use crate::sample::{EncodingHint, QosLevel, SampleKind, SourceInfo};
use crate::session_tables::Presence;
use crate::session_zid::ZID_MAX;
use crate::sink::SampleView;

/// A call a record of the round owes, begun on a row of the session's tables under its lock and
/// ended once, with no lock held, after the record was handed to it or refused.
pub trait RoundCall: Sized {
    /// End the call: `true` when it was the last call of a row undeclared while it ran, which
    /// the session's walk of its tables then lets go of.
    fn end(self) -> bool;
}

/// A call of a subscriber's callback, which a sample is handed to.
pub trait SampleCall: RoundCall {
    /// Hand `sample` to the row's callback.
    fn hand(&self, sample: &dyn SampleView);
}

/// A call of a liveliness subscriber's callback, which a token's appearance or retraction is
/// handed to.
pub trait TokenCall: RoundCall {
    /// Whether `other` is a call of the same row.
    fn same_row(&self, other: &Self) -> bool;

    /// Hand `sample` to the row's callback.
    fn hand(&self, sample: LivelinessSample<'_>);
}

/// What a declaration watch is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclEventKind {
    /// A peer declared an entity.
    Declared,
    /// A peer retracted the entity it had declared.
    Undeclared,
    /// A peer has sent every declaration it held when its link came up.
    Synced,
    /// The watch was owed events the round had no room for.
    Lost,
}

/// One event a declaration watch is handed ([`WatchCall::hand`]); what it borrows lives for the
/// call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclEvent<'a> {
    /// What it tells.
    pub kind: DeclEventKind,
    /// The id of the declaration, for a declaration and a retraction; how many events were lost,
    /// for a loss.
    pub id: u64,
    /// The key of a declaration; empty for the others.
    pub keyexpr: &'a str,
    /// The zenoh id of the peer it came from, as its link's handshake gave it, when it names one.
    pub peer: Option<&'a [u8]>,
}

/// A call of a declaration watch's sink, which what the peers declare and retract is handed to.
pub trait WatchCall: RoundCall {
    /// Whether `other` is a call of the same watch.
    fn same_row(&self, other: &Self) -> bool;

    /// Hand `event` to the watch's sink.
    fn hand(&self, event: DeclEvent<'_>);
}

/// What a round is made of in an engine's own types: the calls its records owe, as the rows of
/// the engine's tables begin them, and which kinds of record its build keeps. A kind of row the
/// build keeps none of has the call [`Infallible`], of which none is ever made, and its record
/// kind [`Absent`](crate::session_tables::Absent), so a record of it takes no room in the round's
/// rows and every arm that reads one is left out of the build. This crate's features are unified
/// across the workspace and the engine's are not, so the kinds follow the engine's build through
/// these types and not a feature of this crate.
pub trait RoundCalls: 'static {
    /// A call of a subscriber's callback.
    type Subscriber: SampleCall;
    /// A call of a liveliness subscriber's callback.
    type Liveliness: TokenCall;
    /// A call of a queryable's callback.
    type Queryable: RoundCall;
    /// A call of a declaration watch's sink.
    type Watch: WatchCall;
    /// The leg of a get a reply is held for: the place of the row its callback lies in.
    type Leg: Copy;
    /// A leg's callback, as its holders hand it back once its row's last count is given back.
    type ReplyCallback;
    /// Whether the round holds tokens' appearances and retractions.
    type Tokens: Presence;
    /// Whether the round holds replies to the session's gets.
    type Replies: Presence;
    /// Whether the round holds queries for the session's queryables.
    type Queries: Presence;
    /// Whether the round holds what the peers declare and retract, for the declaration watches.
    type Watches: Presence;
    /// Whether the session's own put is handed the calls of the subscribers it reaches
    /// ([`Round::capture`]).
    type Capture: Presence;
    /// Whether the round reads the datagrams of a group, whose receive buffer it may keep
    /// ([`Round::keep_rx`]).
    type Group: Presence;
    /// The locks the round keeps what answers its queries under.
    type Locks: LockFamily;
    /// What the round counts of what it hands out.
    type Tally: RoundTally;
}

/// What the session's planes are made of in an engine's own types beyond what its round owes:
/// whether the session's own queryables answer its gets, and the locks the planes keep their state
/// and their queues under. The get plane ([`crate::get_plane`]) and the query plane
/// ([`crate::query_plane`]) read both.
pub trait PlaneCalls: RoundCalls {
    /// Whether the session's own queryables answer a get of the session on the thread that holds
    /// the session's lock: the get plane captures the callback the answer reaches, and the query
    /// plane notes the calls the get begins.
    type LocalAnswers: Presence;
    /// The locks of the planes' state and of the queues every delivery looks at
    /// ([`Queued`](crate::plane_lock::Queued)).
    type Queues: LockFamily;
}

/// What a round counts of the rounds it hands out, for an engine that reads it: `()` counts
/// nothing, and the count is not even made.
pub trait RoundTally: Default + Send + Sync {
    /// A round was handed out: `count` says how many samples it held and how many of those were
    /// read where they lie, asked only by a tally that keeps them.
    fn handed(&self, count: impl FnOnce() -> (usize, usize));
}

impl RoundTally for () {
    fn handed(&self, _count: impl FnOnce() -> (usize, usize)) {}
}

impl RoundCall for Infallible {
    fn end(self) -> bool {
        match self {}
    }
}

impl SampleCall for Infallible {
    fn hand(&self, _sample: &dyn SampleView) {
        match *self {}
    }
}

impl TokenCall for Infallible {
    fn same_row(&self, _other: &Self) -> bool {
        match *self {}
    }

    fn hand(&self, _sample: LivelinessSample<'_>) {
        match *self {}
    }
}

impl WatchCall for Infallible {
    fn same_row(&self, _other: &Self) -> bool {
        match *self {}
    }

    fn hand(&self, _event: DeclEvent<'_>) {
        match *self {}
    }
}

/// What one record a session is handed can take of its round at most: the room the round is asked
/// for before each record, by the gate an engine puts on each of its links, so that what a record hands it always finds room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadRoom {
    /// The callbacks it owes: one for each subscriber it reaches; and an entry, which every record
    /// takes one of at most. A record asks for no bytes: its parts lie where the round reads them.
    pub callbacks: usize,
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
    /// Of the records above, those refused for a part that lies nowhere the round reads it, as the
    /// round keeps no area to copy it into: a datagram its transport does not lend, or a key the
    /// round's keys have no room for.
    pub unplaced: u64,
}

/// Where a part of a record lies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// In the datagram a link lent the step the record was written in.
    Datagram,
    /// In the rejoined message the round keeps ([`Round::end_rejoined`]).
    Rejoined,
    /// In the session's key arena, in a block the record holds from when it is written
    /// ([`Table::hold_key`]) until the lock holder clears the table ([`Table::clear`]).
    Held,
    /// In the session's key arena, in a block a record written before holds.
    Shared,
    /// In the table's keys.
    Key,
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
        place: Place::Key,
    };

    /// The span as a record that reads a block another record holds sees it: it holds none of
    /// its own.
    fn shared(self) -> Self {
        match self.place {
            Place::Held => Self {
                place: Place::Shared,
                ..self
            },
            _ => self,
        }
    }

    /// Where `part` lies in the region `lending` names; `None` when it lies elsewhere.
    fn lent(part: &[u8], lending: Lending) -> Option<Self> {
        let (start, length) = lending.at;
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
            place: lending.place,
        })
    }
}

/// A region a link or the reassembly lends the step, whose parts the table may read where they
/// lie: its first byte and its length, and which of the table's lent places it is.
#[derive(Clone, Copy)]
struct Lending {
    at: (*const u8, usize),
    place: Place,
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

/// A sample as its view hands it, read once: what an offer that writes a record of its own places.
struct Offered<'s> {
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    key: &'s [u8],
    /// The key of the session's key arena `key` is the whole text of, when the view read it there.
    held: Option<&'s KeyRef>,
    payload: &'s [u8],
    rest: Parts<'s>,
}

impl<'s> Offered<'s> {
    fn of(sample: &'s dyn SampleView) -> Self {
        Self {
            kind: sample.kind(),
            reliability: sample.reliability(),
            qos: sample.qos(),
            key: sample.keyexpr().as_bytes(),
            held: sample.keyexpr_held(),
            payload: sample.payload(),
            rest: Parts::of(sample),
        }
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
            encoding: crate::sink::encoding_carried(sample),
            timestamp: crate::sink::timestamp_carried(sample),
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
}

/// A reply as a record of the round holds it: what it is besides its bytes, and where its parts
/// lie.
struct HeldReply {
    rid: crate::wire_id::RequestId,
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

/// What a record of the round is. A kind the round's build keeps none of is a variant of no value
/// and no size ([`Presence::Record`]).
enum Held<C: RoundCalls> {
    /// A sample, for the callbacks of the subscribers it matched.
    Sample { head: Head, rest: Option<Rest> },
    /// A token's appearance or retraction, for the callbacks of the liveliness subscribers it
    /// matched.
    Liveliness(<C::Tokens as Presence>::Record<HeldToken>),
    /// A reply, for the callback of the leg of the get it answers.
    Reply(<C::Replies as Presence>::Record<HeldReply>),
    /// A query, for the callbacks of the queryables it reached.
    Query(<C::Queries as Presence>::Record<HeldQuery>),
    /// What a peer declared or retracted, for the sinks of the declaration watches it reached.
    DeclWatch(<C::Watches as Presence>::Record<HeldWatch>),
}

/// What a peer declared or retracted as a record of the round holds it: where the key of a
/// declaration lies, and the peer it came from.
struct HeldWatch {
    kind: DeclEventKind,
    id: Word,
    key: Span,
    peer: PeerZid,
}

/// The zenoh id of the peer an event came from, in bytes of the record: no link lends it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerZid {
    bytes: [u8; ZID_MAX],
    /// How many of `bytes` it is; none at all names no peer.
    len: u8,
}

impl PeerZid {
    /// `peer` held; `None` for bytes longer than a zenoh id, which no handshake gives.
    fn of(peer: Option<&[u8]>) -> Option<Self> {
        let mut held = Self {
            bytes: [0; ZID_MAX],
            len: 0,
        };
        if let Some(peer) = peer {
            held.bytes.get_mut(..peer.len())?.copy_from_slice(peer);
            held.len = u8::try_from(peer.len()).ok()?;
        }
        Some(held)
    }

    /// The peer, when one is named.
    fn peer(&self) -> Option<&[u8]> {
        self.bytes
            .get(..usize::from(self.len))
            .filter(|zid| !zid.is_empty())
    }
}

/// A token's appearance or retraction as a record of the round holds it: where its key lies.
struct HeldToken {
    kind: LivelinessSampleKind,
    key: Span,
    token_id: Word,
}

/// A query as a record of the round holds it: what it is besides its bytes, where its parts lie,
/// and the generation of the link it came in on, which its answers go out on.
struct HeldQuery {
    rid: crate::wire_id::RequestId,
    qos: QosLevel,
    generation: Word,
    key: Span,
    parameters: Option<Span>,
    payload: Option<Span>,
    attachment: Option<Span>,
    encoding: Option<(u32, Option<Span>)>,
    source_info: Option<SourceInfo>,
}

/// A record of the round: what it is, and the callbacks it owes, `owed` of them from `first` on.
/// Both count callbacks of a table of at most `DELIVERY_LANE_CALLBACKS`, which a `u32` holds.
struct Entry<C: RoundCalls> {
    what: Held<C>,
    first: u32,
    owed: u32,
}

const _: () = assert!(
    caps::DELIVERY_LANE_CALLBACKS <= u32::MAX as usize,
    "a record names its callbacks by a u32"
);

impl<C: RoundCalls> Entry<C> {
    /// A record of `what` owing one callback, the one at `first` of its table's.
    fn owing_one(what: Held<C>, first: usize) -> Self {
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

/// What the fan-out of a sample that runs now made of it at its first row, which each later row of
/// the fan-out follows without reading the sample again ([`Round::offer_sample`]).
#[derive(Clone, Copy)]
enum Fan {
    /// No fan-out's first row was offered to the table since it was emptied.
    None,
    /// The record the table holds last is the fan-out's sample: a later row owes a call of it,
    /// counted by the sample's congestion control (`holds_sender`) when no callback is left.
    Written { holds_sender: bool },
    /// The sample found no room, or a part of it found no place (`unplaced`): a later row is
    /// refused as the first was.
    Refused { holds_sender: bool, unplaced: bool },
}

/// A callback a record of the round owes: a call of a subscriber's callback begun on its row under
/// the session's lock and ended as the round is emptied ([`Released::settle`]), or another
/// callback copied out of the row that matched it and let go of, with no lock held, as the round is
/// emptied.
enum Owed<C: RoundCalls> {
    /// A subscriber's.
    Subscriber(C::Subscriber),
    /// A liveliness subscriber's.
    Liveliness(C::Liveliness),
    /// A get's leg's: a count of the row of its callback ([`LegHolders`]).
    Reply(C::Leg),
    /// A queryable's: the call begun on its row as the query reached it.
    Query(C::Queryable),
    /// A declaration watch's: the call begun on its row as the event reached it.
    DeclWatch(C::Watch),
}

impl<C: RoundCalls> Owed<C> {
    /// The call, when it is of a subscriber's callback.
    fn subscriber(&self) -> Option<&C::Subscriber> {
        match self {
            Self::Subscriber(callback) => Some(callback),
            Self::Liveliness(_) | Self::Reply(_) | Self::Query(_) | Self::DeclWatch(_) => None,
        }
    }

    /// The call, when it is of a declaration watch's sink.
    fn watch(&self) -> Option<&C::Watch> {
        match self {
            Self::DeclWatch(call) => Some(call),
            _ => None,
        }
    }

    /// The call, when it is of a queryable's callback.
    fn query(&self) -> Option<&C::Queryable> {
        match self {
            Self::Query(call) => Some(call),
            _ => None,
        }
    }

    /// The call, when it is of a liveliness subscriber's callback.
    fn liveliness(&self) -> Option<&C::Liveliness> {
        match self {
            Self::Liveliness(callback) => Some(callback),
            _ => None,
        }
    }

    /// The leg, when it is a leg's callback.
    fn reply(&self) -> Option<C::Leg> {
        match self {
            Self::Reply(leg) => Some(*leg),
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

/// The tables of a round, lent from its session's arena ([`RoundRows::lent`]).
pub struct RoundRows<C: RoundCalls> {
    records: BoundedVec<Entry<C>, { caps::DELIVERY_LANE_EVENTS }, Lent>,
    callbacks: BoundedVec<Owed<C>, { caps::DELIVERY_LANE_CALLBACKS }, Lent>,
    keys: BoundedVec<u8, { key_bytes::<{ caps::MAX_KEYEXPR_BYTES }>() }, Lent>,
    longest_key: usize,
}

impl<C: RoundCalls> RoundRows<C> {
    /// The bytes of one record of a round.
    pub const RECORD_BYTES: usize = core::mem::size_of::<Entry<C>>();

    /// The bytes of one callback a record of a round owes.
    pub const CALLBACK_BYTES: usize = core::mem::size_of::<Owed<C>>();

    /// The tables of a round of `counts`, lent from `arena` in the order the plan counts them:
    /// the records, the callbacks, the keys. Refused past the build's bound of a table or past what
    /// the arena has left.
    pub fn lent(arena: &mut Arena, counts: RoundRowCounts) -> Result<Self, LendRefused> {
        const {
            // A record is aligned as its spans are: a field aligned wider pads every record of the
            // table.
            assert!(
                core::mem::align_of::<Entry<C>>() == core::mem::align_of::<Span>(),
                "a record holds nothing aligned wider than its spans"
            );
        }
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
struct Table<C: RoundCalls> {
    /// The datagram a record's part lies in, its first byte and its length: its link is held back
    /// from its next receive.
    datagram: Option<(*const u8, usize)>,
    /// The rejoined message a record's part lies in, whose buffer the round keeps until the table
    /// is emptied ([`Round::end_rejoined`]).
    rejoined: Option<(*const u8, usize)>,
    /// The session's key arena, whose blocks a record's key is read in when it holds one
    /// ([`Self::hold_key`]); none for a round that reads no key there.
    key_space: Option<KeySpace>,
    /// Whether a delivery handed the records out and ended their calls: what they hold is the lock
    /// holder's to let go of before the next record is written ([`Self::clear`]).
    spent: bool,
    /// As many records as the session's `DELIVERY_LANE_EVENTS`, rows its arena lent.
    entries: BoundedVec<Entry<C>, { caps::DELIVERY_LANE_EVENTS }, Lent>,
    /// The callbacks the records owe at most, one for each subscriber each of them reaches: as
    /// many as the session's `DELIVERY_LANE_CALLBACKS`, rows its arena lent.
    callbacks: BoundedVec<Owed<C>, { caps::DELIVERY_LANE_CALLBACKS }, Lent>,
    /// The keys written, two of the session's longest, bytes its arena lent.
    keys: BoundedVec<u8, { key_bytes::<{ caps::MAX_KEYEXPR_BYTES }>() }, Lent>,
    /// The session's longest key: the room a record's key may take of `keys`.
    longest_key: usize,
    /// The key written last, which the records on it that follow share.
    key: Option<Span>,
    /// What the fan-out that runs now made of its sample ([`Fan`]): what a later row of it follows.
    fan: Fan,
}

impl<C: RoundCalls> Table<C> {
    /// The part at `span`.
    fn bytes(&self, span: Span) -> &[u8] {
        let (at, len) = (span.at as usize, span.len as usize);
        if len == 0 {
            return &[];
        }
        let start = match span.place {
            Place::Key => return self.keys.get(at..at.saturating_add(len)).unwrap_or(&[]),
            Place::Held | Place::Shared => {
                let Some(space) = self.key_space.as_ref() else {
                    return &[];
                };
                // SAFETY: a record of the table holds the block from when it was written
                // (`Self::hold_key`) until the lock holder clears the table (`Self::clear`),
                // which it does only once a delivery has handed the records out.
                return unsafe { space.held_text(span.at, span.len) }.as_bytes();
            }
            Place::Datagram => self.datagram.map(|(start, _)| start),
            Place::Rejoined => self.rejoined.map(|(start, _)| start),
        };
        let Some(start) = start else {
            return &[];
        };
        // SAFETY: the part lies inside its place (`Span::lent`): the datagram, which its link leaves
        // where it lies while the table lends it (`Round::lends_a_datagram`); or the rejoined
        // message, whose buffer the round keeps and no chain is staged into until the table no
        // longer reads it (`Round::settle`).
        unsafe { core::slice::from_raw_parts(start.add(at), len) }
    }

    /// The text at `span`: a key, whose bytes were a `&str`'s.
    fn text(&self, span: Span) -> &str {
        // SAFETY: a key's bytes were a `&str`'s (`SampleView::keyexpr`, `ReplyView::keyexpr`,
        // `LivelinessSample::keyexpr`, `DeclEvent::keyexpr`), copied whole, so they are UTF-8.
        unsafe { core::str::from_utf8_unchecked(self.bytes(span)) }
    }

    /// Where `part` is read: where it lies in `lending`, the datagram a link lends the step or the
    /// rejoined message being dispatched, when it lies there and the table reads no other of that
    /// kind. `None` when it lies anywhere else: the round keeps no area to copy it into. Out of
    /// line: every offer places its parts through this one body.
    #[inline(never)]
    fn place(&mut self, part: &[u8], lending: Option<Lending>) -> Option<Span> {
        if part.is_empty() {
            return Some(Span::EMPTY);
        }
        self.lent(part, lending)
    }

    /// Where `part` lies in `lending`, when the table may read it there.
    fn lent(&mut self, part: &[u8], lending: Option<Lending>) -> Option<Span> {
        let lending = lending?;
        let region = match lending.place {
            Place::Rejoined => &mut self.rejoined,
            _ => &mut self.datagram,
        };
        if region.is_some_and(|lent| lent != lending.at) {
            return None;
        }
        let span = Span::lent(part, lending)?;
        if span.len > 0 {
            *region = Some(lending.at);
        }
        Some(span)
    }

    /// Whether a part lies in a region a link or the reassembly lent.
    fn lends(&self) -> bool {
        self.datagram.is_some() || self.rejoined.is_some()
    }

    /// Where `key` is read: where it lies in `lending`, where the table wrote it last when it is
    /// that key again, or after the keys written before it; `None` when the keys have no room. Out
    /// of line, as [`Self::place`] is.
    #[inline(never)]
    fn place_key(&mut self, key: &[u8], lending: Option<Lending>) -> Option<Span> {
        if let Some(span) = self.lent(key, lending) {
            return Some(span);
        }
        if let Some(span) = self.key {
            if self.bytes(span) == key {
                return Some(span.shared());
            }
        }
        let span = Span {
            at: u32::try_from(self.keys.len()).ok()?,
            len: u32::try_from(key.len()).ok()?,
            place: Place::Key,
        };
        self.keys.extend_from_slice(key).ok()?;
        self.key = Some(span);
        Some(span)
    }

    /// Where a key that is the whole text of `held`, a key of the session's key arena, is read: in
    /// its block, which the record written with it holds from then on ([`Self::hold_key`]), or
    /// which the record before holds when that one reads the same block. `None` when the table
    /// reads no key arena, `held` is not of it, or it is the empty key, which holds no block: the
    /// key is then placed as any other ([`Self::place_key`]).
    fn held_key(&self, held: &KeyRef) -> Option<Span> {
        let space = self.key_space?;
        if !held.is_of(&space) || held.as_str().is_empty() {
            return None;
        }
        let (at, len) = held.parts();
        let span = Span {
            at,
            len,
            place: Place::Held,
        };
        Some(match self.key {
            Some(last)
                if matches!(last.place, Place::Held | Place::Shared)
                    && (last.at, last.len) == (at, len) =>
            {
                span.shared()
            }
            _ => span,
        })
    }

    /// The record just written reads its key at `key` ([`Self::held_key`]): one more holder of
    /// `held`'s block when it is the first record to read it there, and the key the records after
    /// it may share.
    fn hold_key(&mut self, key: Span, held: &KeyRef) {
        match key.place {
            Place::Held => {
                // The count is the record's, handed back by `Self::clear`.
                let _ = held.hold_apart();
                self.key = Some(key);
            }
            Place::Shared => self.key = Some(key),
            _ => {}
        }
    }

    /// `parts` placed for the table.
    fn place_parts(&mut self, parts: &Parts<'_>, lending: Option<Lending>) -> Option<Option<Rest>> {
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
    fn owed(&self, entry: &Entry<C>) -> &[Owed<C>] {
        self.callbacks.get(entry.callbacks()).unwrap_or(&[])
    }

    /// End every call the records owe, each into `released`, as a delivery does with no lock of
    /// the session held. What the records hold besides is let go of by the lock holder before it
    /// writes the next record ([`Self::clear`]): a key of the session's key arena is let go of
    /// under that lock alone.
    fn end_calls(&mut self, released: &Released<C>) {
        while let Some(owed) = self.callbacks.pop() {
            released.settle(owed);
        }
        self.spent = true;
    }

    /// Hold nothing, for the next round: the count each record holds of a block of the session's
    /// key arena handed back, and every row and part let go of. The
    /// lock holder's, once the calls are ended ([`Self::end_calls`]).
    fn clear(&mut self) {
        if let Some(space) = self.key_space {
            for entry in self.entries.iter() {
                let key = match &entry.what {
                    Held::Sample { head, .. } => head.key,
                    Held::Liveliness(token) => {
                        <C::Tokens as Presence>::read::<HeldToken>(token).key
                    }
                    Held::Reply(reply) => <C::Replies as Presence>::read::<HeldReply>(reply).key,
                    Held::Query(query) => <C::Queries as Presence>::read::<HeldQuery>(query).key,
                    Held::DeclWatch(watch) => {
                        <C::Watches as Presence>::read::<HeldWatch>(watch).key
                    }
                };
                if key.place == Place::Held {
                    // SAFETY: the record took one count of the block when it was written
                    // (`Self::hold_key`), handed back here once, under the lock.
                    drop(unsafe { space.adopt(key.at, key.len) });
                }
            }
        }
        self.entries.clear();
        self.keys.clear();
        self.key = None;
        self.fan = Fan::None;
        self.datagram = None;
        self.rejoined = None;
        self.spent = false;
    }
}

/// The calls of the subscribers a put of the session's own reaches, in the order the session's
/// table reached them, each begun on its row ([`Round::captured`]).
///
/// A fixed array the put takes out of the round whole and holds in its own frame while it hands
/// the calls out with no lock held, so it takes no heap after the open; its cost is stack. One is
/// `MAX_SUBSCRIPTIONS` calls of a row's address each (8 bytes on a 64-bit target, 4 on a 32-bit
/// one) and a length: at the build's default of 100 subscribers, 808 bytes on a 64-bit target and
/// 404 on a 32-bit one. A subscriber's callback that puts on
/// its own session from inside the call holds a second one in a frame above the first, and so
/// on, as zenoh-pico's put re-enters its subscribers at any depth: the session bounds no such
/// nesting, so its depth, and the stack it takes, are the program's, each level these bytes
/// beside the callback's own frame. Shared rows of the arena would hand a nested put's calls to
/// the round when they overflow, which reorders the calls zenoh-pico makes inline, so the frame
/// keeps its own.
pub type Captured<C> =
    BoundedVec<<C as RoundCalls>::Subscriber, { caps::MAX_SUBSCRIPTIONS }, Static>;

/// What answers a query the round hands a queryable: the engine, which builds the responder the
/// query's replies go out through on the link it came in on, and lets go of its Final's hold once
/// the callback returned.
pub trait AnswersQueries<C: RoundCalls> {
    /// Hand `query`, which arrived on the link of `generation`, to the callback `call` was
    /// begun for, and send what it answers. The call is ended by the round.
    fn answer_query(&self, call: &C::Queryable, query: &dyn QueryView, generation: u64);
}

/// What holds the callbacks of the legs of the session's gets, each in a row held by count: a
/// record of the round that owes a leg a reply holds one count of its row from when it is written
/// to when its call is ended, so the callback outlives every reply held for it.
pub trait LegHolders<C: RoundCalls>: Send + Sync {
    /// Take one more count of `leg`'s row: `false` when it names none.
    fn hold(&self, leg: C::Leg) -> bool;

    /// Hand `reply` to `leg`'s callback, which a count the caller holds keeps; the callback is
    /// called with none of the holders' locks held.
    fn call(&self, leg: C::Leg, reply: &dyn ReplyView);

    /// Give back one count of `leg`'s row: its callback, taken out of the row, when that was the
    /// last count, for the caller to drop with no lock held.
    fn release(&self, leg: C::Leg) -> Option<C::ReplyCallback>;
}

/// The holders of the legs' callbacks, once the session told the round of them.
type Legs<C> = Option<Arc<dyn LegHolders<C>>>;

/// The datagram of a group a record of the round reads, its first byte and its length.
type GroupRead = Option<(*const u8, usize)>;

/// What the round's ends of calls leave the session to let go of: whether a row may wait, and the
/// drops under way of the rows the session took ([`Round::take_marked`], [`Round::releasing`]).
/// The rows that wait are found by a walk of the session's tables, each row's latch its own mark
/// (`SessionTables::release_drained_subscriber` and its kin), so the round keeps no list of them
/// and none can overflow. Written by whoever ends a call: a delivery emptying the round with no
/// lock of the session held, the session's own put after its calls, the session refusing a record
/// under its lock.
struct Released<C: RoundCalls> {
    /// Set by a call that was the last of a row undeclared while it ran, after its latch said so;
    /// cleared by the session as it starts a walk. The session walks only while it is set, so the
    /// ends of the calls of live rows cost it no walk.
    marked: AtomicBool,
    /// The rows taken out of their tables whose drop has not ended ([`Releasing`]): an
    /// undeclaration that waits for its row reads that no drop is under way.
    dropping: AtomicUsize,
    /// The rows of the legs' callbacks the replies' records hold counts of, once the session told
    /// the round of them ([`Round::calls_legs_of`]): a round never told holds no reply.
    legs: <C::Replies as Presence>::Table<Legs<C>>,
}

impl<C: RoundCalls> Released<C> {
    fn new() -> Self {
        Self {
            marked: AtomicBool::new(false),
            dropping: AtomicUsize::new(0),
            legs: <C::Replies as Presence>::empty::<Legs<C>>(),
        }
    }

    /// End `call`, marked for the session to let its row go when it was the row's last call.
    fn end(&self, call: C::Subscriber) {
        if call.end() {
            self.mark();
        }
    }

    /// [`Self::end`] for a call of a liveliness subscriber's callback.
    fn end_liveliness(&self, call: C::Liveliness) {
        if call.end() {
            self.mark();
        }
    }

    /// [`Self::end`] for a call of a queryable's callback.
    fn end_query(&self, call: C::Queryable) {
        if call.end() {
            self.mark();
        }
    }

    /// [`Self::end`] for a call of a declaration watch's sink.
    fn end_watch(&self, call: C::Watch) {
        if call.end() {
            self.mark();
        }
    }

    /// The holders of the legs' callbacks, once the session told the round of them.
    fn legs(&self) -> Option<&dyn LegHolders<C>> {
        <C::Replies as Presence>::get::<Legs<C>>(&self.legs).and_then(Option::as_deref)
    }

    /// Say that a row waits: set after the row's latch said its last call ended, so a session that
    /// reads it set finds the row drained when it walks.
    fn mark(&self) {
        self.marked.store(true, Ordering::Release);
    }

    /// End what `owed` is: a call, by [`Self::end`]; any other callback is let go of here.
    fn settle(&self, owed: Owed<C>) {
        match owed {
            Owed::Subscriber(call) => self.end(call),
            Owed::Liveliness(call) => self.end_liveliness(call),
            Owed::Reply(leg) => {
                // The record's count; the callback goes here, with no lock held, when it was the
                // last.
                if let Some(legs) = self.legs() {
                    drop(legs.release(leg));
                }
            }
            Owed::Query(call) => self.end_query(call),
            Owed::DeclWatch(call) => self.end_watch(call),
        }
    }
}

/// The drop of a row the session took out of its tables, under way until this is dropped, which
/// its taker does once the row was dropped ([`Round::releasing`]).
pub struct Releasing<'r, C: RoundCalls> {
    released: &'r Released<C>,
}

impl<C: RoundCalls> Drop for Releasing<'_, C> {
    fn drop(&mut self) {
        self.released.dropping.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The session's round of deliveries (see the module), owing the calls `C` names.
pub struct Round<C: RoundCalls> {
    state: AtomicU8,
    table: UnsafeCell<Table<C>>,
    /// Whether a record lies in the datagram a link lent or a rejoined message the round keeps
    /// ([`Self::lends_a_datagram`]): set by the session's writes, cleared as a delivery empties
    /// the table.
    lends: AtomicBool,
    /// Whether a source the gate does not hold back owes the round records it had no room for (a
    /// lost face's tokens, still to be retracted): no link is read until it has handed them, so
    /// they come before anything the link brings after the loss ([`Self::owe`]).
    owes: AtomicBool,
    /// Where the datagram lies that a link lends the session's step now, when the link leaves it
    /// where it lies until it is next asked to receive (the engine's gate on the link): its first byte
    /// and its length. Written under the session's lock.
    lending: UnsafeCell<Option<(*const u8, usize)>>,
    /// Where the rejoined message lies whose records are dispatched now, between
    /// [`Self::lend_rejoined`] and [`Self::end_rejoined`]: what is offered meanwhile is read in
    /// it and not in the datagram. Written under the session's lock.
    rejoining: UnsafeCell<Option<(*const u8, usize)>>,
    /// The buffer of the rejoined message the table reads, kept until the lock holder finds the
    /// table no longer reads it ([`Self::settle`]). Written under the session's lock.
    kept: UnsafeCell<Option<KeptBytes>>,
    /// The datagram a record of the table reads where it lies, as the lock holder last wrote it
    /// ([`Self::filled`]): what a buffer given back is asked about while a delivery has the table
    /// ([`Self::keep_rx`]). Written under the session's lock.
    reading: UnsafeCell<<C::Group as Presence>::Table<GroupRead>>,
    /// The receive buffer of a group the session left whose datagram the table reads, kept until
    /// the lock holder finds the table no longer reads it ([`Self::settle`]). Written under the
    /// session's lock.
    kept_rx: UnsafeCell<<C::Group as Presence>::Table<Option<ByteBuf>>>,
    /// The calls of the subscribers the samples offered now reach, begun on their rows and handed
    /// to the session's own put instead of held, while it asks for them ([`Self::capture`]).
    /// Written under the session's lock.
    capturing: UnsafeCell<<C::Capture as Presence>::Table<Option<Captured<C>>>>,
    /// What the ends of the calls leave the session to let go of ([`Released`]).
    released: Released<C>,
    /// What answers the queries the round hands their queryables, once the engine that sends the
    /// answers is made ([`Self::answer_queries_with`]): the queries' replies go out on their links
    /// and their Finals' holds are let go of there.
    answering: <C::Queries as Presence>::Table<Answering<C>>,
    /// What was not handed a callback ([`RoundCounts`]).
    dropped: AtomicU64,
    held_over: AtomicU64,
    unplaced: AtomicU64,
    /// Whether what is offered now is a record a link's gate let through
    /// ([`Self::offering_gated`]), which a debug build's check of the gate's bound reads.
    #[cfg(debug_assertions)]
    gated: AtomicBool,
    /// What the round counts of the rounds it hands out ([`RoundTally`]).
    tally: C::Tally,
}

/// What answers the queries a round hands their queryables, once it is told
/// ([`Round::answer_queries_with`]), under a lock of the engine's.
struct Answering<C: RoundCalls>(
    <C::Locks as LockFamily>::Lock<Option<Weak<dyn AnswersQueries<C>>>>,
);

impl<C: RoundCalls> Default for Answering<C> {
    fn default() -> Self {
        Self(<C::Locks as LockFamily>::new(None))
    }
}

// SAFETY: the table is reached by the holder of the session's lock while the state is empty or
// filling, and by the one delivery that took it while it is delivering; `lending`, `rejoining`,
// `kept`, `reading`, `kept_rx` and `capturing` by the holder of the session's lock alone, so the
// kept buffers, whose claims belong to the session's task, are let go of on that task alone;
// `answering` behind its own lock, naming the engine, whose answering is made for any thread, as
// is the holder of the legs' rows `released` names, whose other fields are atomics; every
// other field is an atomic or never written after the round is made. A call the table owes reads a row its table keeps where it lies until the call ends,
// through a sink that is `Send` and `Sync`; every other callback it owes is `Send` and `Sync`; and
// the parts it reads lie where the link, the kept buffers and the arena keep them while it holds
// them.
unsafe impl<C: RoundCalls> Send for Round<C> {}
// SAFETY: as `Send`.
unsafe impl<C: RoundCalls> Sync for Round<C> {}

impl<C: RoundCalls> Round<C> {
    /// The session's round over `rows`, built where the allocation that shares it keeps it: its
    /// table's rows are kilobytes, which a value of the whole would lay in the frame of the
    /// session's open once for each move.
    #[inline(never)]
    pub fn shared_over(rows: RoundRows<C>) -> Arc<Self> {
        // `Arc::new_uninit` is newer than this crate's minimum Rust; an uninitialised value put in
        // an `Arc` is the same allocation, and the optimiser writes nothing into it.
        let raw = Arc::into_raw(Arc::new(MaybeUninit::<Self>::uninit())).cast_mut();
        // SAFETY: `raw` is the one handle of an allocation made on the line above, so the place
        // is valid and nothing else reads or writes it while it is written.
        unsafe { Self::write_in((*raw).as_mut_ptr(), rows) };
        // SAFETY: `write_in` wrote every field into the allocation, and a `MaybeUninit<T>` has
        // the size and alignment of `T`, which is what `Arc::from_raw` asks of the pointer's type.
        unsafe { Arc::from_raw(raw.cast::<Self>().cast_const()) }
    }

    /// An empty round written where `at` points, field by field.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self`, and what it held is overwritten without a drop.
    #[inline(never)]
    unsafe fn write_in(at: *mut Self, rows: RoundRows<C>) {
        // A field added to the round or its table and not written below would be read
        // uninitialised. These name every field of both with no `..`, so adding one without naming
        // it here (and so without writing it below) does not compile.
        let _every_field_is_written = |round: &Self| {
            let Self {
                state: _,
                table: _,
                lends: _,
                owes: _,
                lending: _,
                rejoining: _,
                kept: _,
                reading: _,
                kept_rx: _,
                capturing: _,
                released: _,
                answering: _,
                dropped: _,
                held_over: _,
                unplaced: _,
                #[cfg(debug_assertions)]
                    gated: _,
                tally: _,
            } = round;
        };
        let _every_table_field_is_written = |table: &Table<C>| {
            let Table {
                datagram: _,
                rejoined: _,
                key_space: _,
                spent: _,
                entries: _,
                callbacks: _,
                keys: _,
                longest_key: _,
                key: _,
                fan: _,
            } = table;
        };
        // SAFETY: the caller's contract; an `UnsafeCell<T>` is laid out as the `T` it holds, and
        // each field is written once through a pointer to it. The lists above name every field, so
        // the round is whole when it is shared.
        unsafe {
            ptr::write(addr_of_mut!((*at).state), AtomicU8::new(EMPTY));
            let table = addr_of_mut!((*at).table).cast::<Table<C>>();
            ptr::write(addr_of_mut!((*table).datagram), None);
            ptr::write(addr_of_mut!((*table).rejoined), None);
            ptr::write(addr_of_mut!((*table).key_space), None);
            ptr::write(addr_of_mut!((*table).spent), false);
            ptr::write(addr_of_mut!((*table).entries), rows.records);
            ptr::write(addr_of_mut!((*table).callbacks), rows.callbacks);
            ptr::write(addr_of_mut!((*table).keys), rows.keys);
            ptr::write(addr_of_mut!((*table).longest_key), rows.longest_key);
            ptr::write(addr_of_mut!((*table).key), None);
            ptr::write(addr_of_mut!((*table).fan), Fan::None);
            ptr::write(addr_of_mut!((*at).lends), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).owes), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).lending), UnsafeCell::new(None));
            ptr::write(addr_of_mut!((*at).rejoining), UnsafeCell::new(None));
            ptr::write(addr_of_mut!((*at).kept), UnsafeCell::new(None));
            ptr::write(
                addr_of_mut!((*at).reading),
                UnsafeCell::new(<C::Group as Presence>::empty::<GroupRead>()),
            );
            ptr::write(
                addr_of_mut!((*at).kept_rx),
                UnsafeCell::new(<C::Group as Presence>::empty::<Option<ByteBuf>>()),
            );
            ptr::write(
                addr_of_mut!((*at).capturing),
                UnsafeCell::new(<C::Capture as Presence>::empty::<Option<Captured<C>>>()),
            );
            ptr::write(addr_of_mut!((*at).released), Released::new());
            ptr::write(
                addr_of_mut!((*at).answering),
                <C::Queries as Presence>::empty::<Answering<C>>(),
            );
            ptr::write(addr_of_mut!((*at).dropped), AtomicU64::new(0));
            ptr::write(addr_of_mut!((*at).held_over), AtomicU64::new(0));
            ptr::write(addr_of_mut!((*at).unplaced), AtomicU64::new(0));
            #[cfg(debug_assertions)]
            ptr::write(addr_of_mut!((*at).gated), AtomicBool::new(false));
            ptr::write(addr_of_mut!((*at).tally), <C::Tally as Default>::default());
        }
    }

    /// Read the key of a record in the block of `keys`, the session's key arena, that the record
    /// holds, when the sample names one ([`SampleView::keyexpr_held`]), rather than copy it. Told
    /// once, before the round is shared; a round never told copies every key.
    pub fn reads_keys_in(&mut self, keys: KeySpace) {
        self.table.get_mut().key_space = Some(keys);
    }

    /// Hold the replies offered from here on for the callbacks `legs` holds, by a count of each
    /// leg's row. Told once, before the round is shared.
    pub fn calls_legs_of(&mut self, legs: Arc<dyn LegHolders<C>>) {
        if let Some(held) = <C::Replies as Presence>::get_mut::<Legs<C>>(&mut self.released.legs) {
            *held = Some(legs);
        }
    }

    /// The table, to write, while it is empty or filling: `None` once it is sealed or handed out.
    /// A table a delivery handed out is cleared first, and the rejoined buffer kept for it let go
    /// of ([`Self::settle`]).
    ///
    /// # Safety
    /// The caller holds the session's lock, and holds no other borrow of the table.
    #[allow(clippy::mut_from_ref)]
    unsafe fn writable(&self) -> Option<&mut Table<C>> {
        match self.state.load(Ordering::Acquire) {
            EMPTY => {
                // SAFETY: an empty table is the lock holder's, and the caller holds the lock and
                // no other borrow of it; `kept` is written under that lock alone.
                unsafe {
                    let table = &mut *self.table.get();
                    if table.spent {
                        table.clear();
                        *self.kept.get() = None;
                        self.forget_group_read();
                    }
                    Some(table)
                }
            }
            // SAFETY: a filling table is the lock holder's, and the caller holds the lock and no
            // other borrow of it.
            FILLING => Some(unsafe { &mut *self.table.get() }),
            _ => None,
        }
    }

    /// A record was written into `table`: it is filling, and lends what it lends.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn filled(&self, table: &Table<C>) {
        if table.lends() {
            self.lends.store(true, Ordering::Release);
        }
        // SAFETY: the caller's contract: written under the session's lock alone.
        let reading = unsafe { &mut *self.reading.get() };
        if let Some(reading) = <C::Group as Presence>::get_mut::<GroupRead>(reading) {
            *reading = table.datagram;
        }
        self.state.store(FILLING, Ordering::Release);
    }

    /// Forget the datagram of a group a record read and the group's receive buffer kept for it:
    /// the table no longer reads either.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn forget_group_read(&self) {
        // SAFETY: the caller's contract: both are written under the session's lock alone.
        let (reading, kept) = unsafe { (&mut *self.reading.get(), &mut *self.kept_rx.get()) };
        if let Some(reading) = <C::Group as Presence>::get_mut::<GroupRead>(reading) {
            *reading = None;
        }
        if let Some(kept) = <C::Group as Presence>::get_mut::<Option<ByteBuf>>(kept) {
            *kept = None;
        }
    }

    /// What is lent the step now: the rejoined message whose records are dispatched, or else the
    /// datagram a link lends.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    unsafe fn lending(&self) -> Option<Lending> {
        // SAFETY: the caller's contract: both are written under the session's lock alone.
        let (rejoining, datagram) = unsafe { (*self.rejoining.get(), *self.lending.get()) };
        match rejoining {
            Some(at) => Some(Lending {
                at,
                place: Place::Rejoined,
            }),
            None => datagram.map(|at| Lending {
                at,
                place: Place::Datagram,
            }),
        }
    }

    /// The records one message makes at most: a token's appearance or retraction is held for the
    /// liveliness subscribers and, as a record of its own, for the declaration watches, where the
    /// round keeps both.
    const MESSAGE_RECORDS: usize =
        if <C::Tokens as Presence>::KEPT && <C::Watches as Presence>::KEPT {
            2
        } else {
            1
        };

    /// Whether `table` takes one more record, owing `callbacks` callbacks.
    fn takes(table: &Table<C>, callbacks: usize) -> bool {
        table.entries.free_slots() > 0 && table.callbacks.free_slots() >= callbacks
    }

    /// Whether `table` takes one more callback of the record it holds last.
    fn joins(table: &Table<C>) -> bool {
        table.callbacks.free_slots() > 0
    }

    /// Count a record that found no room, apart when it holds its sender. A record a link's gate
    /// let through waited for the room one record can take (the engine's gate on each link), so one that holds its
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

    /// Count a record a part of which found no place: one the round cannot read where it lies, as
    /// it keeps no area to copy it into. Refused as one that found no room is, and counted apart as
    /// well ([`RoundCounts::unplaced`]).
    fn refuse_unplaced(&self, holds_sender: bool) {
        self.unplaced.fetch_add(1, Ordering::Relaxed);
        self.refuse(holds_sender);
    }

    /// Hand out, instead of holding, the calls of the subscribers the samples offered from here on
    /// reach, until [`Self::captured`]: how the session's own put learns which of its subscribers
    /// it reaches and what to call, to hand the sample to them itself and end each call
    /// ([`Self::end_call`]). A round whose build hands its put no calls holds them as any others.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn capture(&self) {
        // SAFETY: the caller's contract: written under the session's lock alone.
        let capturing = unsafe { &mut *self.capturing.get() };
        if let Some(capturing) = <C::Capture as Presence>::get_mut::<Option<Captured<C>>>(capturing)
        {
            *capturing = Some(BoundedVec::new_static());
        }
    }

    /// The calls of the subscribers reached since [`Self::capture`]; what is offered after this is
    /// held again.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn captured(&self) -> Captured<C> {
        // SAFETY: the caller's contract: written under the session's lock alone.
        let capturing = unsafe { &mut *self.capturing.get() };
        <C::Capture as Presence>::get_mut::<Option<Captured<C>>>(capturing)
            .and_then(Option::take)
            .unwrap_or_else(BoundedVec::new_static)
    }

    /// Hold `sample` for `call`, a call of a subscriber's callback begun on its row, read where it
    /// lies when it lies in the datagram a link lends the step; `first` when `call` is the first
    /// row of the sample's fan-out. The first row reads the sample once and writes its record, or
    /// finds it refused; each later row of the same fan-out follows that without reading the sample
    /// again: its call is owed by the same record, or refused as the first was. A sample offered to
    /// many subscribers is so written once; what finds no room is counted for each call, and the
    /// call ended.
    ///
    /// # Safety
    /// The caller holds the session's lock, and offers a later row of a fan-out in the same hold of
    /// it as the fan-out's first row.
    pub unsafe fn offer_sample(&self, call: C::Subscriber, sample: &dyn SampleView, first: bool) {
        // The session's own put is handed the calls and holds nothing.
        // SAFETY: the caller's contract: written under the session's lock, which is held.
        let capturing = unsafe { &mut *self.capturing.get() };
        if let Some(found) = <C::Capture as Presence>::get_mut::<Option<Captured<C>>>(capturing)
            .and_then(Option::as_mut)
        {
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
        if !first {
            // SAFETY: the caller's contract.
            if let Some(table) = unsafe { self.writable() } {
                match table.fan {
                    Fan::Written { holds_sender } => {
                        if let Some(
                            last @ Entry {
                                what: Held::Sample { .. },
                                ..
                            },
                        ) = table.entries.last_mut()
                        {
                            match table.callbacks.push(Owed::Subscriber(call)) {
                                Ok(()) => last.owed = last.owed.saturating_add(1),
                                Err(full) => {
                                    self.refuse(holds_sender);
                                    self.released.settle(full.0);
                                }
                            }
                            return;
                        }
                    }
                    Fan::Refused {
                        holds_sender,
                        unplaced,
                    } => {
                        self.refuse_sample(call, holds_sender, unplaced);
                        return;
                    }
                    Fan::None => {}
                }
            }
        }
        let sample = Offered::of(sample);
        let holds_sender = holds_its_sender(sample.reliability, sample.qos);
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse_sample(call, holds_sender, false);
            return;
        };
        if !Self::takes(table, 1) {
            table.fan = Fan::Refused {
                holds_sender,
                unplaced: false,
            };
            self.refuse_sample(call, holds_sender, false);
            return;
        }
        let Some((key, payload, rest)) = Self::place_sample(table, &sample, lending) else {
            table.fan = Fan::Refused {
                holds_sender,
                unplaced: true,
            };
            self.refuse_sample(call, holds_sender, true);
            return;
        };
        let first = table.callbacks.len();
        let entry = table.entries.push(Entry::owing_one(
            Held::Sample {
                head: Head {
                    kind: sample.kind,
                    reliability: sample.reliability,
                    qos: sample.qos,
                    key,
                    payload,
                },
                rest,
            },
            first,
        ));
        let kept = match entry {
            Ok(()) => {
                if let Some(held) = sample.held {
                    table.hold_key(key, held);
                }
                self.owe_call(table, call)
            }
            Err(_) => {
                self.released.end(call);
                false
            }
        };
        debug_assert!(kept, "the table had the room its checks found");
        table.fan = Fan::Written { holds_sender };
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.filled(table) };
    }

    /// Refuse `call` of a sample the round keeps no record of: counted by the sample's congestion
    /// control (`holds_sender`), apart as well when a part of it found no place (`unplaced`), and
    /// the call ended.
    fn refuse_sample(&self, call: C::Subscriber, holds_sender: bool, unplaced: bool) {
        if unplaced {
            self.unplaced.fetch_add(1, Ordering::Relaxed);
        }
        self.refuse(holds_sender);
        self.released.end(call);
    }

    /// Owe `call` in `table`, which has the room for it: `false`, the call ended, when it had
    /// not after all.
    fn owe_call(&self, table: &mut Table<C>, call: C::Subscriber) -> bool {
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
        table: &mut Table<C>,
        sample: &Offered<'_>,
        lending: Option<Lending>,
    ) -> Option<(Span, Span, Option<Rest>)> {
        let key = match sample.held.and_then(|held| table.held_key(held)) {
            Some(key) => key,
            None => table.place_key(sample.key, lending)?,
        };
        let payload = table.place(sample.payload, lending)?;
        let rest = table.place_parts(&sample.rest, lending)?;
        Some((key, payload, rest))
    }

    /// Hold `sample`, a token's appearance or retraction, for `call`, a call of a liveliness
    /// subscriber's callback begun on its row, its key read where it lies or written into the
    /// table. Written once for the liveliness subscribers it reaches one after the other, as a
    /// sample is; what finds no room is counted with the records that hold their sender, and its
    /// call ended.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn offer_liveliness(
        &self,
        call: C::Liveliness,
        sample: &LivelinessSample<'_>,
        held: Option<&KeyRef>,
    ) {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(true);
            self.released.end_liveliness(call);
            return;
        };
        let key = sample.keyexpr.as_bytes();
        if let Some(
            entry @ Entry {
                what: Held::Liveliness(token),
                ..
            },
        ) = table.entries.last()
        {
            let token = <C::Tokens as Presence>::read::<HeldToken>(token);
            let joins = token.kind == sample.kind
                && token.token_id.get() == sample.token_id
                && same(table.bytes(token.key), key)
                && !table
                    .owed(entry)
                    .iter()
                    .filter_map(Owed::liveliness)
                    .any(|held| held.same_row(&call));
            if joins && Self::joins(table) {
                if let Err(full) = table.callbacks.push(Owed::Liveliness(call)) {
                    self.refuse(true);
                    self.released.settle(full.0);
                    return;
                }
                if let Some(last) = table.entries.last_mut() {
                    last.owed = last.owed.saturating_add(1);
                }
                // SAFETY: the caller's contract: the session's lock is held.
                unsafe { self.filled(table) };
                return;
            }
        }
        if !Self::takes(table, 1) {
            self.refuse(true);
            self.released.end_liveliness(call);
            return;
        }
        let placed = match held.and_then(|held| table.held_key(held)) {
            Some(at) => Some(at),
            None => table.place_key(key, lending),
        };
        let Some(at) = placed else {
            self.refuse_unplaced(true);
            self.released.end_liveliness(call);
            return;
        };
        let token = HeldToken {
            kind: sample.kind,
            key: at,
            token_id: Word::of(sample.token_id),
        };
        // A round whose build keeps no token refuses it, as one with no room does.
        let Some(token) = <C::Tokens as Presence>::record(token) else {
            self.refuse(true);
            self.released.end_liveliness(call);
            return;
        };
        let first = table.callbacks.len();
        let entry = table
            .entries
            .push(Entry::owing_one(Held::Liveliness(token), first));
        if let (Ok(()), Some(held)) = (&entry, held) {
            table.hold_key(at, held);
        }
        let kept = match entry {
            Ok(()) => match table.callbacks.push(Owed::Liveliness(call)) {
                Ok(()) => true,
                Err(full) => {
                    self.released.settle(full.0);
                    false
                }
            },
            Err(_) => {
                self.released.end_liveliness(call);
                false
            }
        };
        debug_assert!(kept, "the table had the room its checks found");
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.filled(table) };
    }

    /// Hold `event`, what a peer declared or retracted, for `call`, a call of a declaration watch's
    /// sink begun on its row: the key of a declaration read where it lies, in the block of
    /// `held`, a key of the session's key arena, when the declaration's row keeps it there, which
    /// the record holds until it is handed out (so a retraction in the same frame does not take it
    /// from under the record), or else written into the table. Written once for the watches it
    /// reaches one after the other, as a sample is. `false`, the call ended, when it found no room
    /// or no place, counted with what was dropped: the watch is told the loss
    /// ([`DeclEventKind::Lost`]), and the peer is not held back for it.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn offer_decl_watch(
        &self,
        call: C::Watch,
        event: DeclEvent<'_>,
        held: Option<&KeyRef>,
    ) -> bool {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(false);
            self.released.end_watch(call);
            return false;
        };
        let key = event.keyexpr.as_bytes();
        if let Some(
            entry @ Entry {
                what: Held::DeclWatch(watch),
                ..
            },
        ) = table.entries.last()
        {
            let watch = <C::Watches as Presence>::read::<HeldWatch>(watch);
            let joins = watch.kind == event.kind
                && watch.id.get() == event.id
                && watch.peer.peer() == event.peer
                && same(table.bytes(watch.key), key)
                && !table
                    .owed(entry)
                    .iter()
                    .filter_map(Owed::watch)
                    .any(|owed| owed.same_row(&call));
            if joins && Self::joins(table) {
                if let Err(full) = table.callbacks.push(Owed::DeclWatch(call)) {
                    self.refuse(false);
                    self.released.settle(full.0);
                    return false;
                }
                if let Some(last) = table.entries.last_mut() {
                    last.owed = last.owed.saturating_add(1);
                }
                // SAFETY: the caller's contract: the session's lock is held.
                unsafe { self.filled(table) };
                return true;
            }
        }
        if !Self::takes(table, 1) {
            self.refuse(false);
            self.released.end_watch(call);
            return false;
        }
        let placed = match held.and_then(|held| table.held_key(held)) {
            Some(at) => Some(at),
            None => table.place_key(key, lending),
        };
        let (Some(at), Some(peer)) = (placed, PeerZid::of(event.peer)) else {
            self.refuse_unplaced(false);
            self.released.end_watch(call);
            return false;
        };
        let watch = HeldWatch {
            kind: event.kind,
            id: Word::of(event.id),
            key: at,
            peer,
        };
        // A round whose build keeps no watch refuses the event, as one with no room does.
        let Some(watch) = <C::Watches as Presence>::record(watch) else {
            self.refuse(false);
            self.released.end_watch(call);
            return false;
        };
        let first = table.callbacks.len();
        let entry = table
            .entries
            .push(Entry::owing_one(Held::DeclWatch(watch), first));
        if let (Ok(()), Some(held)) = (&entry, held) {
            table.hold_key(at, held);
        }
        let kept = match entry {
            Ok(()) => match table.callbacks.push(Owed::DeclWatch(call)) {
                Ok(()) => true,
                Err(full) => {
                    self.released.settle(full.0);
                    false
                }
            },
            Err(_) => {
                self.released.end_watch(call);
                false
            }
        };
        debug_assert!(kept, "the table had the room its checks found");
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.filled(table) };
        kept
    }

    /// Whether the table takes `records` more records owing `callbacks` callbacks now: what a
    /// source that writes several records at once asks before it writes the first (a declaration
    /// watch's catch-up). `false` while the table is sealed or handed out.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn has_room_for(&self, records: usize, callbacks: usize) -> bool {
        // SAFETY: the caller's contract.
        (unsafe { self.writable() }).is_some_and(|table| {
            table.entries.free_slots() >= records && table.callbacks.free_slots() >= callbacks
        })
    }

    /// Hold `view`, a reply, for leg `leg`, whose callback answers it, each part read where it lies
    /// or written into the table, with a count of the leg's row ([`LegHolders`]). A reply is the
    /// answer a get waits for: one that finds no room is counted with the records that hold their
    /// sender.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn offer_reply(&self, leg: C::Leg, view: &dyn ReplyView) {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(true);
            return;
        };
        let Some(legs) = self.released.legs() else {
            self.refuse(true);
            return;
        };
        if !Self::takes(table, 1) {
            self.refuse(true);
            return;
        }
        let held = view.keyexpr_held();
        let Some(reply) = Self::place_reply(table, view, held, lending) else {
            self.refuse_unplaced(true);
            return;
        };
        let key = reply.key;
        let Some(reply) = <C::Replies as Presence>::record(reply) else {
            self.refuse(true);
            return;
        };
        if !legs.hold(leg) {
            self.refuse(true);
            return;
        }
        let first = table.callbacks.len();
        let entered = table
            .entries
            .push(Entry::owing_one(Held::Reply(reply), first))
            .is_ok();
        if let (true, Some(held)) = (entered, held) {
            table.hold_key(key, held);
        }
        let kept = entered && table.callbacks.push(Owed::Reply(leg)).is_ok();
        if !kept {
            // Refused after its count was taken: given back at once. The sink that offers the
            // reply holds the row too, so this is never the count that lets the callback go.
            drop(legs.release(leg));
        }
        debug_assert!(kept, "the table had the room its checks found");
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.filled(table) };
    }

    /// `view` placed in `table`; `None` when a part finds no room.
    fn place_reply(
        table: &mut Table<C>,
        view: &dyn ReplyView,
        held: Option<&KeyRef>,
        lending: Option<Lending>,
    ) -> Option<HeldReply> {
        let key = match held.and_then(|held| table.held_key(held)) {
            Some(key) => key,
            None => table.place_key(view.keyexpr().as_bytes(), lending)?,
        };
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
    pub unsafe fn seal(&self) {
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
    pub unsafe fn set_lending(&self, datagram: Option<&[u8]>) {
        let range = datagram.map(|bytes| (bytes.as_ptr(), bytes.len()));
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.lending.get() = range };
    }

    /// Whether a source the gate does not hold back still owes the round records (`owed`): the
    /// links are read no further until it says it owes none.
    pub fn owe(&self, owed: bool) {
        self.owes.store(owed, Ordering::Release);
    }

    /// Whether a source the gate does not hold back still owes the round records ([`Self::owe`]).
    pub fn owes(&self) -> bool {
        self.owes.load(Ordering::Acquire)
    }

    /// Answer the queries the round hands their queryables through `answering`, the engine the
    /// round is the session's of: told once, when the engine is made.
    pub fn answer_queries_with(&self, answering: Weak<dyn AnswersQueries<C>>) {
        if let Some(slot) = <C::Queries as Presence>::get::<Answering<C>>(&self.answering) {
            <C::Locks as LockFamily>::with(&slot.0, |held| *held = Some(answering));
        }
    }

    /// Hold `view`, a query of the link of `generation`, for `call`, the call begun on the
    /// queryable's row it reached, each part read where it lies or written into the table: whether
    /// the round took it. A query not taken is refused and counted as a record that holds its
    /// sender, and its call is ended; the caller lets go of the hold it took on its Final.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn offer_query(
        &self,
        call: C::Queryable,
        view: &dyn QueryView,
        generation: u64,
    ) -> bool {
        // SAFETY: the caller's contract.
        let lending = unsafe { self.lending() };
        // SAFETY: the caller's contract.
        let Some(table) = (unsafe { self.writable() }) else {
            self.refuse(true);
            self.released.end_query(call);
            return false;
        };
        if !Self::takes(table, 1) {
            self.refuse(true);
            self.released.end_query(call);
            return false;
        }
        let Some(query) = Self::place_query(table, view, generation, lending) else {
            self.refuse_unplaced(true);
            self.released.end_query(call);
            return false;
        };
        // A round whose build keeps no query refuses it, as one with no room does.
        let Some(query) = <C::Queries as Presence>::record(query) else {
            self.refuse(true);
            self.released.end_query(call);
            return false;
        };
        let first = table.callbacks.len();
        let kept = table
            .entries
            .push(Entry::owing_one(Held::Query(query), first))
            .is_ok();
        let owed = if kept {
            table
                .callbacks
                .push(Owed::Query(call))
                .err()
                .map(|full| full.0)
        } else {
            Some(Owed::Query(call))
        };
        if let Some(owed) = owed {
            self.released.settle(owed);
        }
        debug_assert!(kept, "the table had the room its checks found");
        // SAFETY: the caller's contract: the session's lock is held.
        unsafe { self.filled(table) };
        kept
    }

    /// `view` placed in `table`; `None` when a part finds no place.
    fn place_query(
        table: &mut Table<C>,
        view: &dyn QueryView,
        generation: u64,
        lending: Option<Lending>,
    ) -> Option<HeldQuery> {
        let key = table.place_key(view.keyexpr().as_bytes(), lending)?;
        let mut part = |bytes: Option<&[u8]>| match bytes {
            Some(bytes) => table.place(bytes, lending).map(Some),
            None => Some(None),
        };
        let parameters = part(view.parameters())?;
        let payload = part(view.payload())?;
        let attachment = part(view.attachment())?;
        // Its encoding where the dispatcher read it, so a schema that lies in the datagram is read
        // there and not out of the hint the dispatcher made.
        let encoding = match view.encoding_parts() {
            Some((packed_id, schema)) => Some((packed_id, part(schema)?)),
            None => None,
        };
        Some(HeldQuery {
            rid: view.rid(),
            qos: view.qos(),
            generation: Word::of(generation),
            key,
            parameters,
            payload,
            attachment,
            encoding,
            source_info: view.source_info().cloned(),
        })
    }

    /// The records offered from here on lie in `message`, a message rejoined from its fragments and
    /// kept in its chain's buffer, until [`Self::end_rejoined`]; the datagram a link lends is lent
    /// again after it. A part is read there while the table reads no other rejoined message
    /// (`Table::lent`), and copied otherwise, as one from any source but a lent one is.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn lend_rejoined(&self, message: &KeptBytes) {
        let bytes = message.as_slice();
        // SAFETY: the caller's contract: written under the session's lock alone.
        unsafe { *self.rejoining.get() = Some((bytes.as_ptr(), bytes.len())) };
    }

    /// The records of `message` are offered: the round keeps its buffer when the table reads a
    /// part of it, until the table no longer does ([`Self::settle`]), and drops it here
    /// otherwise, which gives it back to its chains at once. A buffer kept before is let go of
    /// then, as the table reads one rejoined message at most.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn end_rejoined(&self, message: KeptBytes) {
        let bytes = message.as_slice();
        let at = (bytes.as_ptr(), bytes.len());
        // SAFETY: the caller's contract: `rejoining` and `kept` are written under the session's
        // lock alone, and a table not sealed is the lock holder's (`Self::writable`).
        unsafe {
            *self.rejoining.get() = None;
            if self
                .writable()
                .is_some_and(|table| table.rejoined == Some(at))
            {
                *self.kept.get() = Some(message);
            }
        }
    }

    /// Let go of what the records of a round a delivery handed out still hold, once the table is
    /// no longer read: the counts of the session's key arena they hold and the rejoined buffer kept
    /// for them. A delivery hands the records out with no lock of the session held, and both are
    /// let go of under that lock alone, so the lock holder does it: before it writes the next
    /// record ([`Self::writable`]) and before the gate lets a link be read (the engine's gate on each link).
    ///
    /// # Safety
    /// The caller holds the session's lock, and holds no borrow of the table.
    pub unsafe fn settle(&self) {
        // SAFETY: the caller's contract.
        let _ = unsafe { self.writable() };
    }

    /// `buf`, the receive buffer of a group the session is leaving, given back by its transport
    /// (`GroupTransport::give_back_rx`): kept while a record of the table reads a datagram in it,
    /// until the lock holder finds the table no longer does ([`Self::settle`]), and let go of at
    /// once otherwise, which gives it back to the session's table of group buffers. The table reads
    /// one datagram at most, so the round keeps one such buffer at most.
    ///
    /// # Safety
    /// The caller holds the session's lock, and holds no borrow of the table.
    pub unsafe fn keep_rx(&self, buf: ByteBuf) {
        // SAFETY: the caller's contract; `reading` and `kept_rx` are written under that lock
        // alone. A round handed out and not yet cleared is cleared first, so what it read is not
        // taken for what the next one reads.
        unsafe {
            self.settle();
            let (base, len) = buf.raw();
            let reading = <C::Group as Presence>::get::<GroupRead>(&*self.reading.get())
                .copied()
                .flatten();
            let inside = reading.is_some_and(|(at, n)| {
                let (start, end) = (base as usize, (base as usize).saturating_add(len));
                let at = at as usize;
                at >= start && at.saturating_add(n) <= end
            });
            if inside {
                if let Some(kept) =
                    <C::Group as Presence>::get_mut::<Option<ByteBuf>>(&mut *self.kept_rx.get())
                {
                    *kept = Some(buf);
                }
            }
        }
    }

    /// Whether a record lies in the datagram a link lent: no link is read or serviced until its
    /// callbacks have returned. Asked by the session's step, which holds the session's lock.
    pub fn lends_a_datagram(&self) -> bool {
        self.lends.load(Ordering::Acquire)
    }

    /// Whether the table takes the room `room` of one more record: empty, or filling with an
    /// entry, the callbacks and a key of the longest left. A record's other parts lie where the
    /// round reads them. An empty table takes any record, so a link is never stopped for good.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub unsafe fn has_room(&self, room: ReadRoom) -> bool {
        match self.state.load(Ordering::Acquire) {
            EMPTY => true,
            FILLING => {
                // SAFETY: a filling table is the lock holder's, and the caller holds the lock.
                let table = unsafe { &*self.table.get() };
                // A record's parts lie where the round reads them, apart from a key the session
                // composed, which the keys take.
                let keys = table.keys.free_slots() >= table.longest_key;
                Self::takes(table, room.callbacks)
                    && table.entries.free_slots() >= Self::MESSAGE_RECORDS
                    && keys
            }
            _ => false,
        }
    }

    /// Let go of the round's tables, their records and the callbacks those owe, each call ended,
    /// before the arena that lent them: what the session's end does. The tables left are lent
    /// nothing, so the round's own drop, which may come after the arena's, reads none of the arena.
    /// A row whose last call this ends is marked ([`Self::take_marked`]) and goes with the tables.
    ///
    /// # Safety
    /// No delivery runs and none starts: the session's last handle is being let go of.
    pub unsafe fn let_go(&self) {
        // SAFETY: the caller's contract: nothing else reaches the table now.
        let table = unsafe { &mut *self.table.get() };
        table.end_calls(&self.released);
        // The counts of the session's key arena the records hold go back before the arena does.
        table.clear();
        drop(core::mem::take(&mut table.entries));
        drop(core::mem::take(&mut table.callbacks));
        drop(core::mem::take(&mut table.keys));
        // SAFETY: as above; the kept buffer is a cell of a table the session's arena lent, so it
        // goes back before the arena does.
        unsafe {
            *self.rejoining.get() = None;
            *self.kept.get() = None;
            self.forget_group_read();
        }
        self.lends.store(false, Ordering::Release);
        self.state.store(EMPTY, Ordering::Release);
    }

    /// Whether the table holds nothing: what a leg's end waits for, so that it is told after every
    /// reply held before it.
    pub fn is_idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == EMPTY
    }

    /// Whether what is offered from here on is a record a link's gate let through (`true`), which
    /// waited for the room one record can take (the engine's gate on each link), or anything else (`false`): the
    /// session's own puts, the tokens a lost face retracts, a group's records. Only the first is a
    /// defect when it holds its sender and finds no room. A debug build's alone.
    #[cfg(debug_assertions)]
    pub fn offering_gated(&self, gated: bool) {
        self.gated.store(gated, Ordering::Release);
    }

    /// What the round did not hand a callback.
    pub fn counts(&self) -> RoundCounts {
        RoundCounts {
            dropped: self.dropped.load(Ordering::Relaxed),
            held_over: self.held_over.load(Ordering::Relaxed),
            unplaced: self.unplaced.load(Ordering::Relaxed),
        }
    }

    /// End `call`, which the session's own put made ([`Self::captured`]): its row is marked to be
    /// let go of ([`Self::take_marked`]) when it was the row's last call.
    pub fn end_call(&self, call: C::Subscriber) {
        self.released.end(call);
    }

    /// End `call`, which the session's own get began on a queryable it asked and handed with no
    /// lock held: its row is marked to be let go of ([`Self::take_marked`]) when it was the
    /// row's last call.
    pub fn end_query_call(&self, call: C::Queryable) {
        self.released.end_query(call);
    }

    /// End `call`, which the session's declaration made of a liveliness subscriber's history: its
    /// row is marked to be let go of ([`Self::take_marked`]) when it was the row's last call.
    pub fn end_liveliness_call(&self, call: C::Liveliness) {
        self.released.end_liveliness(call);
    }

    /// Whether a row may wait to be let go of since this was last asked: a call that was the last
    /// of a row undeclared while it ran has ended. Asking clears it, so the session walks its
    /// tables for such rows (`SessionTables::release_drained_subscriber` and its kin) once each
    /// time one may wait, and not at all while none does. A walk begun after the asking finds every
    /// row marked before it, its latch drained before the mark was set; a row whose last call ends
    /// after the asking sets it again, for the next walk.
    pub fn take_marked(&self) -> bool {
        self.released.marked.swap(false, Ordering::AcqRel)
    }

    /// Count the drop of a row the session took out of its tables, under its lock, as under way
    /// until what this hands back is dropped, after the row was.
    pub fn releasing(&self) -> Releasing<'_, C> {
        self.released.dropping.fetch_add(1, Ordering::AcqRel);
        Releasing {
            released: &self.released,
        }
    }

    /// Whether no drop of a row the session took out of its tables is under way: what an
    /// undeclaration that waits for its row reads once the row left its table.
    pub fn released_settled(&self) -> bool {
        self.released.dropping.load(Ordering::Acquire) == 0
    }

    /// Empty a sealed round no delivery has taken, handing nothing out, its calls ended: what the
    /// session's close does, after which no callback of it is called. `false` when no round
    /// waited, or a delivery hands it out now, which empties it itself.
    pub fn discard(&self) -> bool {
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
    pub fn deliver(&self) -> bool {
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
                Held::Liveliness(token) => {
                    let token = <C::Tokens as Presence>::read::<HeldToken>(token);
                    let sample = LivelinessSample {
                        kind: token.kind,
                        keyexpr: table.text(token.key),
                        token_id: token.token_id.get(),
                    };
                    for call in owed.iter().filter_map(Owed::liveliness) {
                        call.hand(sample);
                    }
                }
                Held::Reply(reply) => {
                    let reply = <C::Replies as Presence>::read::<HeldReply>(reply);
                    let view = RoundReply { reply, table };
                    // A reply was held only for a round told of the legs (`Self::offer_reply`).
                    if let Some(legs) = self.released.legs() {
                        for leg in owed.iter().filter_map(Owed::reply) {
                            legs.call(leg, &view);
                        }
                    }
                }
                Held::Query(query) => {
                    let query = <C::Queries as Presence>::read::<HeldQuery>(query);
                    // The engine that sends the answers, once it is made; a query handed out
                    // before, or after it went, is answered by none, its calls ended all the same.
                    let answering = <C::Queries as Presence>::get::<Answering<C>>(&self.answering)
                        .and_then(|slot| {
                            <C::Locks as LockFamily>::with(&slot.0, |held| held.as_ref()?.upgrade())
                        });
                    if let Some(answering) = answering {
                        let view = RoundQuery {
                            query,
                            table,
                            encoding: OnceCell::new(),
                        };
                        for call in owed.iter().filter_map(Owed::query) {
                            answering.answer_query(call, &view, query.generation.get());
                        }
                    }
                }
                Held::DeclWatch(watch) => {
                    let watch = <C::Watches as Presence>::read::<HeldWatch>(watch);
                    let event = DeclEvent {
                        kind: watch.kind,
                        id: watch.id.get(),
                        keyexpr: table.text(watch.key),
                        peer: watch.peer.peer(),
                    };
                    for call in owed.iter().filter_map(Owed::watch) {
                        call.hand(event);
                    }
                }
            }
        }
        self.tally.handed(|| Self::count_round(table));
        drop(emptied);
        true
    }

    /// What the round counts of the rounds it handed out ([`RoundTally`]).
    pub fn tally(&self) -> &C::Tally {
        &self.tally
    }

    /// The samples a round handed out held, and of those the ones read where they lie.
    fn count_round(table: &Table<C>) -> (usize, usize) {
        let samples = table
            .entries
            .iter()
            .filter(|entry| matches!(entry.what, Held::Sample { .. }))
            .count();
        let lent = table
            .entries
            .iter()
            .filter(|entry| match &entry.what {
                Held::Sample { head, .. } => {
                    matches!(head.payload.place, Place::Datagram | Place::Rejoined)
                }
                _ => false,
            })
            .count();
        (samples, lent)
    }
}

/// A query of the round, read where its parts lie: what each queryable it reached is handed.
struct RoundQuery<'t, C: RoundCalls> {
    query: &'t HeldQuery,
    table: &'t Table<C>,
    /// The encoding as the hint a queryable reads it by, made from the table's parts the first
    /// time one asks for it.
    encoding: OnceCell<EncodingHint>,
}

impl<C: RoundCalls> QueryView for RoundQuery<'_, C> {
    fn keyexpr(&self) -> &str {
        self.table.text(self.query.key)
    }

    fn parameters(&self) -> Option<&[u8]> {
        self.query.parameters.map(|span| self.table.bytes(span))
    }

    fn attachment(&self) -> Option<&[u8]> {
        self.query.attachment.map(|span| self.table.bytes(span))
    }

    fn source_info(&self) -> Option<&SourceInfo> {
        self.query.source_info.as_ref()
    }

    fn payload(&self) -> Option<&[u8]> {
        self.query.payload.map(|span| self.table.bytes(span))
    }

    fn encoding(&self) -> Option<&EncodingHint> {
        let (packed_id, schema) = self.query.encoding?;
        Some(self.encoding.get_or_init(|| EncodingHint {
            packed_id,
            schema: schema.map(|span| self.table.bytes(span).to_vec()),
        }))
    }

    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.query
            .encoding
            .map(|(packed_id, schema)| (packed_id, schema.map(|span| self.table.bytes(span))))
    }

    fn rid(&self) -> crate::wire_id::RequestId {
        self.query.rid
    }

    fn qos(&self) -> QosLevel {
        self.query.qos
    }
}

/// A delivery of the round ends, a callback's unwinding included: the table is emptied, its calls
/// ended and its other callbacks let go of with no lock of the session held, and given back to the
/// session.
struct Emptied<'r, C: RoundCalls>(&'r Round<C>);

impl<C: RoundCalls> Drop for Emptied<'_, C> {
    fn drop(&mut self) {
        // SAFETY: the table is this delivery's until the store below gives it back.
        unsafe { (*self.0.table.get()).end_calls(&self.0.released) };
        self.0.lends.store(false, Ordering::Release);
        self.0.state.store(EMPTY, Ordering::Release);
    }
}

/// A sample of the round, read where its parts lie: what each of its subscribers' callbacks is
/// handed.
struct RoundSample<'t, C: RoundCalls> {
    head: Head,
    rest: Option<&'t Rest>,
    table: &'t Table<C>,
}

impl<C: RoundCalls> SampleView for RoundSample<'_, C> {
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
struct RoundReply<'t, C: RoundCalls> {
    reply: &'t HeldReply,
    table: &'t Table<C>,
}

impl<C: RoundCalls> RoundReply<'_, C> {
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

impl<C: RoundCalls> ReplyView for RoundReply<'_, C> {
    fn rid(&self) -> crate::wire_id::RequestId {
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

    fn timestamp_parts(&self) -> Option<crate::reply_stage::TimestampParts<'_>> {
        self.reply
            .timestamp
            .map(|(time, zid)| crate::reply_stage::TimestampParts {
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

#[cfg(test)]
pub(crate) mod tests;
