// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What is OWED to one peer by its queries: the replies a queryable has staged
//! and the `ResponseFinal`s that must follow them (fixed-memory steps S9a and S9b).
//!
//! Both are written by a PEER, in the sense that matters: the peer's `Request`
//! makes the session stage them, and a peer that sends requests faster than the
//! session drains them decides how many there are. Each is ONE type over a storage
//! policy ([`crate::bounded::Storage`]), written once. On the growable policy (the AP
//! profile) the tables grow with the allocator. On the policy that enforces its capacity
//! (the fixed backing, selected by `bounded-heapless`) each is a table of declared
//! capacity ([`caps::MAX_PENDING_REPLIES`], [`caps::MAX_PENDING_FINALS`]). On either
//! policy each table is also held to the quota its creator resolved for the session
//! (the same two limits in [`crate::limits::SessionLimits`], handed over by `limit_to`):
//! the build's value until one is stated, which is no bound on the growable policy and
//! the capacity on the fixed one. A table that cannot take another entry, by its quota
//! or by its storage, REFUSES it, COUNTS it, and tells whoever asked:
//!
//! - a reply the stage has no room for, or whose payload is longer than the stage's
//!   payload bound (`MAX_REPLY_PAYLOAD_BYTES`, held in [`crate::reply_stage::ReplyBounds`] beside the
//!   count), is an `Err` to the queryable's handler
//!   ([`crate::query_sink::ReplyError::StagingFull`],
//!   [`crate::query_sink::ReplyError::PayloadTooLarge`]) and is counted
//!   in [`crate::reply_stage::ReplyRefusals`]. It is never truncated and never built on the heap in
//!   place of the table;
//! - a `Request` whose `Final` the finals table could not hold is refused BEFORE
//!   its queryables run ([`crate::reply_stage::FinalStaging::refuse_request`]) and counted: a reply that
//!   cannot be followed by its `Final` leaves the peer's `get` open until its own
//!   timeout, and running the handler for it would spend the application's work on
//!   an answer nobody can be told is complete.
//!
//! # A staged reply is bytes in the stage, not a record on the heap (S9b)
//!
//! A queryable describes a reply as [`crate::reply_stage::ReplyParts`], every field BORROWED from the
//! handler. The stage writes the reply's bytes (keyexpr, payload, attachment,
//! encoding schema) into ONE byte arena it owns and a small row that points into it.
//! On the fixed policy the arena is [`caps::REPLY_STAGE_BYTES`], the room for
//! [`caps::MAX_PENDING_REPLIES`] replies of [`caps::MAX_REPLY_PAYLOAD_BYTES`] and a
//! keyexpr each, so staging a reply allocates nothing; a reply that does not fit what
//! is left of the arena is refused as
//! [`crate::query_sink::ReplyError::StagingFull`], counted, like a reply the table has
//! no row for. On the growable policy the arena and the rows grow with the allocator
//! and are reused across drains, where the stage used to build an owned
//! [`crate::query::QueryReply`] at every staging.
//!
//! What this does NOT take off the heap is the DRAIN: handing a staged reply to the
//! wire builds the owned [`crate::query::QueryReply`] from its row, and that owned
//! record and the owned `Response` made from it are the codec's owned mirrors, not
//! the stage's. The allocation has moved from the moment the handler replies to the
//! moment the session sends, which is where the codec mirrors are replaced.

use crate::bounded::{Arena, BoundedVec, LendRefused, Lent, Profile, SpanOffset, Static, Storage};
use crate::caps;
use crate::limit_binding::Quota;
#[cfg(feature = "alloc")]
use crate::query::QueryReply;
use crate::query_sink::ReplyError;
#[cfg(feature = "alloc")]
use crate::sample::TimestampHint;
use crate::sample::{QosLevel, SourceInfo};

/// A reply's encoding as borrowed parts: the wire `packed_id` and the optional schema, read
/// where their holder keeps them. The one borrowed encoding of the crate, so a reply's encoding
/// and a publication's are the same value.
pub type EncodingParts<'a> = crate::sample::EncodingRef<'a>;

/// A reply's value timestamp as borrowed parts: the time and the identity bytes
/// of the clock that stamped it, a slice of the caller's own buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampParts<'a> {
    /// The timestamp's time value.
    pub time: u64,
    /// The identity of the clock, as the wire carries it.
    pub zid: &'a [u8],
}

#[cfg(feature = "alloc")]
impl<'a> TimestampParts<'a> {
    /// The parts of an owned hint, borrowing its identity.
    pub fn of(hint: &'a TimestampHint) -> Self {
        Self {
            time: hint.time,
            zid: &hint.zid,
        }
    }
}

/// A timestamp a node minted for a reply its handler did not stamp: the time and the node's
/// identity, held inline (a zid is at most 16 bytes on the wire), so minting one allocates nothing
/// and a build without a heap can mint it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyStamp {
    /// The timestamp's time value.
    pub time: u64,
    /// The identity of the node's clock, as the wire carries it.
    pub zid: heapless::Vec<u8, 16>,
}

impl ReplyStamp {
    /// A stamp of `time` under the identity `zid`, or `None` for an identity longer than the 16
    /// bytes a Timestamp carries on the wire.
    pub fn new(time: u64, zid: &[u8]) -> Option<Self> {
        Some(Self {
            time,
            zid: heapless::Vec::from_slice(zid).ok()?,
        })
    }

    /// The stamp as the borrowed parts a staged reply carries.
    pub fn parts(&self) -> TimestampParts<'_> {
        TimestampParts {
            time: self.time,
            zid: &self.zid,
        }
    }
}

/// What mints the timestamp of a reply whose handler gave it none, under the
/// `reply-auto-timestamp` policy: the node's own clock.
///
/// An answer of `None` is a node that does not stamp (no clock, a clock that does not know the
/// date, a clock its quality policy does not trust), and the reply goes out as it would with the
/// policy off. Each `Some` is a new time, so two replies never carry the same stamp.
pub trait ReplyClock {
    /// The next stamp of this node's clock, or `None` when the node stamps nothing.
    fn next_stamp(&self) -> Option<ReplyStamp>;
}

/// The body of a staged data reply, borrowed.
#[derive(Clone, Copy)]
pub enum PartsBody<'a> {
    /// A Put with these payload bytes.
    Put(&'a [u8]),
    /// A Del: no payload.
    Del,
    /// A Put whose payload is a buffer of shared memory, staged as the handle and
    /// not as a copy of its bytes.
    #[cfg(feature = "transport-shm")]
    Shared(&'a crate::extshm::ShmSendHandle),
}

/// What kind of reply is staged, borrowed.
#[derive(Clone, Copy)]
pub enum PartsKind<'a> {
    /// A successful reply, Put or Del.
    Reply {
        /// The Put payload or the Del.
        body: PartsBody<'a>,
        /// The value's encoding (the inner body's E-flag), if any.
        encoding: Option<EncodingParts<'a>>,
        /// The value's timestamp, if any.
        timestamp: Option<TimestampParts<'a>>,
        /// The opaque attachment, if any.
        attachment: Option<&'a [u8]>,
        /// The sample's source info, if any.
        source_info: Option<&'a SourceInfo>,
    },
    /// An Err reply.
    #[cfg(feature = "query-reply-err")]
    Err {
        /// The error body's encoding id and schema, if any.
        encoding: Option<(u32, Option<&'a [u8]>)>,
        /// The error payload.
        payload: &'a [u8],
    },
}

/// One reply as the queryable describes it, every field BORROWED: the one shape
/// every `send_*` arm of the responder builds and every stage takes, so there is
/// one place that turns a described reply into a staged one on each backing.
#[derive(Clone, Copy)]
pub struct ReplyParts<'a> {
    /// The request id the reply answers.
    pub rid: crate::wire_id::RequestId,
    /// The keyexpr the reply is stamped with.
    pub keyexpr: &'a str,
    /// The responder identity (`zid` bytes, entity id) stamped on the response, if
    /// one was attached.
    pub responder: Option<(&'a [u8], u32)>,
    /// The `ext_qos` the response goes out with.
    pub qos: QosLevel,
    /// The timestamp stack the response goes out with (extension `0x7`), when it is
    /// instrumented: the stack of the query it answers, and the interception of the node that
    /// replies.
    #[cfg(feature = "pubsub-ts-stack")]
    pub ts_stack: Option<&'a crate::ts_stack::TsStack>,
    /// What the reply is.
    pub kind: PartsKind<'a>,
}

impl ReplyParts<'_> {
    /// The lengths a reply's payload bound (`MAX_REPLY_PAYLOAD_BYTES`) is read on: its payload's,
    /// none for a Del or for a buffer of shared memory, which is not copied, and its attachment's.
    /// What a stage refuses a reply by, and what a node that sends a reply as it is made refuses it
    /// by.
    pub fn bounded_lengths(&self) -> (usize, usize) {
        match &self.kind {
            PartsKind::Reply {
                body, attachment, ..
            } => (
                match body {
                    PartsBody::Put(payload) => payload.len(),
                    PartsBody::Del => 0,
                    #[cfg(feature = "transport-shm")]
                    PartsBody::Shared(_) => 0,
                },
                attachment.map_or(0, <[u8]>::len),
            ),
            #[cfg(feature = "query-reply-err")]
            PartsKind::Err { payload, .. } => (payload.len(), 0),
        }
    }
}

/// The longest `zid` a timestamp or a responder identity carries on the wire.
const ZID_BYTES: usize = 16;

/// How a queryable's replies are staged, the same for every storage policy.
pub trait ReplyStaging {
    /// Stage one reply, or refuse it and count it: a stage with no room
    /// ([`ReplyError::StagingFull`]) or a payload past the bound
    /// ([`ReplyError::PayloadTooLarge`]). Asked with the reply still BORROWED, so a
    /// refusal costs nothing, not even a record that is then dropped.
    fn stage_parts(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError>;

    /// How many replies are staged.
    fn staged(&self) -> usize;

    /// The `index`-th staged reply, in the order they were staged, as the owned
    /// record. Built from its row (an allocation, which is the drain's, see the
    /// module documentation). Heap profile only: the owned record is the owned
    /// mirror's.
    #[cfg(feature = "alloc")]
    fn nth(&self, index: usize) -> Option<QueryReply>;

    /// Take every staged reply, in the order they were staged. Whatever has not
    /// been taken when the iterator is dropped is dropped with it. Heap profile
    /// only, as [`Self::nth`].
    #[cfg(feature = "alloc")]
    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> + '_;

    /// Hand every staged reply, in the order they were staged, to `emit` as borrowed
    /// parts, and leave the stage empty: the drain that builds no owned record, so a
    /// node with no allocator can send what it staged. `emit` reads the parts where
    /// they lie, in the arena, and must not keep them.
    fn drain_parts<F: FnMut(ReplyParts<'_>)>(&mut self, emit: F);
}

/// How the `ResponseFinal`s owed to a peer are staged, the same for every storage
/// policy.
pub trait FinalStaging {
    /// Whether another `Final` can be owed. A `false` is the caller's cue to
    /// refuse the request ([`Self::refuse_request`]) before running anything.
    fn has_room(&self) -> bool;

    /// Owe a `Final` for `rid`, carrying the query's `qos`.
    fn owe(&mut self, rid: crate::wire_id::RequestId, qos: QosLevel);

    /// A request refused because no `Final` could be owed for it. Counted.
    fn refuse_request(&mut self);

    /// How many `Final`s are owed.
    fn owed(&self) -> usize;

    /// Take every owed `Final`, in the order they were owed.
    fn drain_owed(&mut self) -> impl Iterator<Item = (crate::wire_id::RequestId, QosLevel)>;
}

// ---------------------------------------------------------------------------
// The stage, once, over a storage policy: tables of declared capacity on a policy
// that enforces it (refusing and counting), and the same tables growing with the
// allocator on one that does not.
// ---------------------------------------------------------------------------

/// What a [`ReplyStage`] refused since it was made, by why.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRefusals {
    /// Replies the stage had no room for (as many rows held as its quota or its
    /// capacity of `MAX_PENDING_REPLIES` admits, or the byte arena had no room left
    /// for the reply's bytes).
    pub staging_full: u32,
    /// Replies whose payload, or attachment, was longer than the stage's payload bound
    /// (`MAX_REPLY_PAYLOAD_BYTES`, [`ReplyBounds`]).
    pub payload_too_large: u32,
}

/// The bounds a [`ReplyStage`] holds the replies staged in it to: how many it holds
/// (`MAX_PENDING_REPLIES`) and how many bytes the payload of one, and its attachment, may
/// take (`MAX_REPLY_PAYLOAD_BYTES`), as the creator of the session resolved them. Taken out
/// of the session's snapshot once ([`Self::of`]), so a stage a runtime makes to answer one
/// query outside the session's lock is held as the session's own stage is. Where the build
/// allows each limit one value it holds no byte.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplyBounds {
    replies: crate::limits::MaxPendingRepliesHeld,
    payload: crate::limits::MaxReplyPayloadBytesHeld,
}

impl ReplyBounds {
    /// The build's bounds: what a stage that no snapshot reached holds.
    pub const BUILD: Self = Self {
        replies: crate::limits::MaxPendingRepliesHeld::build_default(),
        payload: crate::limits::MaxReplyPayloadBytesHeld::build_default(),
    };

    /// The bounds `limits` states.
    pub const fn of(limits: &crate::limits::SessionLimits) -> Self {
        Self {
            replies: limits.max_pending_replies_held(),
            payload: limits.max_reply_payload_bytes_held(),
        }
    }

    /// The most bytes of payload, and of attachment, one reply staged on the policy `P` may
    /// take: the stated bound, and on a policy that enforces its capacity no more than the
    /// build's value as well, since that policy's arena is sized for `MAX_PENDING_REPLIES`
    /// replies of it whatever the profile lets a statement raise the bound to.
    const fn payload_most<P: Storage>(self) -> Quota {
        let stated = self.payload.get();
        if P::ENFORCES_CAPACITY {
            stated.tighter(Quota::at_most(caps::MAX_REPLY_PAYLOAD_BYTES))
        } else {
            stated
        }
    }
}

/// The offset a stage of policy `P` addresses its arena with.
type Off<P> = <P as Storage>::Offset;

/// Where the bytes of one staged reply's text or payload lie in the stage's arena.
/// The width of an offset is the policy's: 16 bits where the capacity is fixed in the
/// type, so a row costs what it always cost, and 32 where the arena grows with the
/// allocator.
struct Span<P: Storage> {
    start: Off<P>,
    len: Off<P>,
}

impl<P: Storage> Clone for Span<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Storage> Copy for Span<P> {}

/// A staged reply's encoding: the packed id and, if there is one, where its schema is.
type RowEncoding<P> = Option<(u32, Option<Span<P>>)>;

enum RowPayload<P: Storage> {
    Put(Span<P>),
    Del,
    #[cfg(feature = "transport-shm")]
    Shared(crate::extshm::ShmSendHandle),
}

/// What a staged row holds of a reply. The timestamp, the attachment and the source info are held
/// only by a build that puts them on a reply's wire (`pubsub-timestamp`, `pubsub-attachment`,
/// `reply-source-info`, the gates `crate::lent_response` and the owned `Response` write them
/// under, and the loopback reads them under): a build without one drops it at both, so a row of
/// it would hold bytes no reader takes.
enum RowKind<P: Storage> {
    Reply {
        payload: RowPayload<P>,
        encoding: RowEncoding<P>,
        // A zid is a few bytes of the row, not a table of its own: a policy whose rows are only
        // lent holds it inline (`Storage::Scratch`).
        #[cfg(feature = "pubsub-timestamp")]
        timestamp: Option<(u64, BoundedVec<u8, ZID_BYTES, P::Scratch>)>,
        #[cfg(feature = "pubsub-attachment")]
        attachment: Option<Span<P>>,
        #[cfg(feature = "reply-source-info")]
        source_info: Option<SourceInfo>,
    },
    #[cfg(feature = "query-reply-err")]
    Err {
        encoding: RowEncoding<P>,
        payload: Span<P>,
    },
}

/// One staged reply: fixed fields, and spans into the stage's arena for its bytes.
struct Row<P: Storage> {
    rid: crate::wire_id::RequestId,
    qos: QosLevel,
    keyexpr: Span<P>,
    // Inline on a policy whose rows are only lent, as the timestamp's zid is.
    responder: Option<(BoundedVec<u8, ZID_BYTES, P::Scratch>, u32)>,
    #[cfg(feature = "pubsub-ts-stack")]
    ts_stack: Option<crate::ts_stack::TsStack>,
    kind: RowKind<P>,
}

/// The replies a queryable has staged for one peer, over a storage policy.
///
/// On a policy that enforces its capacity ([`Static`]) the
/// stage holds [`caps::MAX_PENDING_REPLIES`] rows and [`caps::REPLY_STAGE_BYTES`] of
/// bytes, no more: a full stage refuses and counts, and does not grow. On one that
/// does not ([`Heap`](crate::bounded::Heap)) the same rows and the same arena grow
/// with the allocator, and the storage refuses nothing. One algorithm for both: the
/// row table and the arena are [`BoundedVec`]s of the policy, the room check asks
/// them how many pushes are still guaranteed, and the heap policy answers
/// `usize::MAX`.
///
/// On both, a reply that would leave more rows staged than the quota its creator
/// stated ([`Self::limit_to`]) is refused and counted as a full stage is, and a reply
/// whose payload or attachment is longer than the payload bound it stated is refused and
/// counted as too large.
///
/// The policy defaults to this build's [`Profile`], so `ReplyStage` alone is the
/// build's stage.
pub struct ReplyStage<P: Storage = Profile> {
    rows: BoundedVec<Row<P>, { caps::MAX_PENDING_REPLIES }, P>,
    arena: BoundedVec<u8, { caps::REPLY_STAGE_BYTES }, P>,
    refusals: ReplyRefusals,
    /// The most replies the stage holds (`MAX_PENDING_REPLIES`) and the longest payload it
    /// takes (`MAX_REPLY_PAYLOAD_BYTES`): what the creator of the session resolved
    /// ([`Self::limit_to`]), the build's values until it does. A growable stage refuses
    /// nothing by its storage, so these are what bound it; where the build fixes a bound to
    /// one value it is held in no byte.
    bounds: ReplyBounds,
}

impl ReplyStage<Static> {
    /// An empty stage of the static policy. `const`, so a session slot that holds
    /// one can be a `static` whatever the build's profile is.
    pub const fn new_static() -> Self {
        Self {
            rows: BoundedVec::new_static(),
            arena: BoundedVec::new_static(),
            refusals: ReplyRefusals {
                staging_full: 0,
                payload_too_large: 0,
            },
            bounds: ReplyBounds::BUILD,
        }
    }
}

impl ReplyStage<Lent> {
    /// An empty stage whose `replies` rows and `bytes` bytes of reply text and payload are lent
    /// from `arena`, held to the build's bounds until its creator states the session's
    /// ([`Self::limit_to`]). Refused when either is over the build's capacity or the arena has not
    /// the room, the rows lent so far going back with the arena.
    pub fn lent(arena: &mut Arena, replies: usize, bytes: usize) -> Result<Self, LendRefused> {
        Ok(Self {
            rows: arena.lend(replies)?,
            arena: arena.lend(bytes)?,
            refusals: ReplyRefusals {
                staging_full: 0,
                payload_too_large: 0,
            },
            bounds: ReplyBounds::BUILD,
        })
    }

    /// The bytes of an arena [`Self::lent`] takes for `replies` rows and `bytes` bytes. `None`
    /// past the address space.
    pub const fn arena_bytes(replies: usize, bytes: usize) -> Option<usize> {
        match (
            Arena::table_bytes::<Row<Lent>>(replies),
            Arena::table_bytes::<u8>(bytes),
        ) {
            (Some(rows), Some(bytes)) => rows.checked_add(bytes),
            _ => None,
        }
    }

    /// The bytes of reply text and payload a stage of `replies` replies holds when each carries a
    /// payload of `payload` bytes and a key of `key`: what [`caps::REPLY_STAGE_BYTES`] is of the
    /// build's values, of the values a session's open resolved. `None` past the address space.
    pub const fn area_bytes(replies: usize, payload: usize, key: usize) -> Option<usize> {
        match payload.checked_add(key) {
            Some(each) => replies.checked_mul(each),
            None => None,
        }
    }
}

impl ReplyStage<Profile> {
    /// An empty stage of this build's profile, held to the build's bounds. `const`, so a
    /// session slot that holds one can be a `static`.
    pub const fn new() -> Self {
        Self::held_to(ReplyBounds::BUILD)
    }

    /// An empty stage of this build's profile, held to `bounds`: the stage a runtime makes to
    /// answer one query, held as the stage of the session the query came to is
    /// ([`Self::bounds`]).
    pub const fn held_to(bounds: ReplyBounds) -> Self {
        Self {
            rows: BoundedVec::new(),
            arena: BoundedVec::new(),
            refusals: ReplyRefusals {
                staging_full: 0,
                payload_too_large: 0,
            },
            bounds,
        }
    }
}

impl<P: Storage> ReplyStage<P> {
    /// Hold the stage to the bounds its creator resolved: a reply that would leave more rows
    /// staged than `MAX_PENDING_REPLIES` admits is refused ([`ReplyError::StagingFull`],
    /// counted in [`ReplyRefusals::staging_full`]), one whose payload or attachment is longer
    /// than `MAX_REPLY_PAYLOAD_BYTES` admits is refused ([`ReplyError::PayloadTooLarge`],
    /// counted in [`ReplyRefusals::payload_too_large`]), and the replies already staged are
    /// kept, as a lowered soft limit keeps what it holds.
    pub fn limit_to(&mut self, bounds: ReplyBounds) {
        self.bounds = bounds;
    }

    /// The bounds the stage holds its replies to ([`Self::limit_to`]).
    pub const fn bounds(&self) -> ReplyBounds {
        self.bounds
    }

    /// What this stage has refused since it was made.
    pub fn refusals(&self) -> ReplyRefusals {
        self.refusals
    }

    /// How many replies are staged.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no reply is staged.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// How many bytes of the arena the staged replies hold.
    pub fn bytes_held(&self) -> usize {
        self.arena.len()
    }

    /// Exchange the staged replies of this stage and `other`, rows and the bytes they lie in, each
    /// keeping its own counts of what it refused and its own quota: the replies move to the stage
    /// that sends them, and the counts and the quota stay with the stage that refused.
    pub fn exchange_staged(&mut self, other: &mut Self) {
        core::mem::swap(&mut self.rows, &mut other.rows);
        core::mem::swap(&mut self.arena, &mut other.arena);
    }

    /// Drop every staged reply; the counts are kept.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.arena.clear();
    }

    /// Remove and return the reply staged last, as `Vec::pop` does.
    #[cfg(feature = "alloc")]
    pub fn pop(&mut self) -> Option<QueryReply> {
        let reply = self.nth(self.rows.len().checked_sub(1)?)?;
        // Rows are written front to back, key first, so this row's bytes are the
        // arena's tail from where its key starts.
        if let Some(row) = self.rows.pop() {
            self.arena.truncate(row.keyexpr.start.to_usize());
        }
        Some(reply)
    }

    /// An iterator over owned copies of the staged replies, in order. Each is built
    /// from its row, so it allocates (the drain's allocation, see the module
    /// documentation); the stage itself is not changed.
    #[cfg(feature = "alloc")]
    pub fn iter(&self) -> impl Iterator<Item = QueryReply> + '_ {
        (0..self.rows.len()).filter_map(|index| self.nth(index))
    }

    fn bytes(&self, span: Span<P>) -> &[u8] {
        let start = span.start.to_usize();
        self.arena
            .get(start..start.saturating_add(span.len.to_usize()))
            .unwrap_or_default()
    }

    fn text(&self, span: Span<P>) -> &str {
        core::str::from_utf8(self.bytes(span)).unwrap_or_default()
    }

    /// Copy `bytes` onto the end of the arena. Room was checked by the caller
    /// ([`Self::stage_parts`] sizes the whole reply first), so this cannot refuse.
    fn put(&mut self, bytes: &[u8]) -> Span<P> {
        let start = self.arena.len();
        // Checked by `stage_parts` before anything is written: the whole reply fits,
        // and every offset of it is within what the policy's width can address.
        let _ = self.arena.extend_from_slice(bytes);
        Span {
            start: Off::<P>::from_usize(start),
            len: Off::<P>::from_usize(bytes.len()),
        }
    }

    fn put_encoding(&mut self, encoding: Option<(u32, Option<&[u8]>)>) -> RowEncoding<P> {
        encoding.map(|(id, schema)| (id, schema.map(|schema| self.put(schema))))
    }

    /// A row's encoding as the id and the schema's bytes read out of the arena.
    fn encoding_of(&self, encoding: &RowEncoding<P>) -> Option<(u32, Option<&[u8]>)> {
        encoding
            .as_ref()
            .map(|(packed_id, schema)| (*packed_id, schema.map(|schema| self.bytes(schema))))
    }

    /// A row as the borrowed description it was staged from. Nothing is copied:
    /// every slice points into the arena or the row, so this is what a writer that
    /// puts the reply on the wire reads, and what the owned record is built from.
    fn row_parts<'a>(&'a self, row: &'a Row<P>) -> ReplyParts<'a> {
        let kind = match &row.kind {
            RowKind::Reply {
                payload,
                encoding,
                #[cfg(feature = "pubsub-timestamp")]
                timestamp,
                #[cfg(feature = "pubsub-attachment")]
                attachment,
                #[cfg(feature = "reply-source-info")]
                source_info,
            } => PartsKind::Reply {
                body: match payload {
                    RowPayload::Put(span) => PartsBody::Put(self.bytes(*span)),
                    RowPayload::Del => PartsBody::Del,
                    #[cfg(feature = "transport-shm")]
                    RowPayload::Shared(handle) => PartsBody::Shared(handle),
                },
                encoding: self
                    .encoding_of(encoding)
                    .map(|(packed_id, schema)| EncodingParts { packed_id, schema }),
                #[cfg(feature = "pubsub-timestamp")]
                timestamp: timestamp
                    .as_ref()
                    .map(|(time, zid)| TimestampParts { time: *time, zid }),
                #[cfg(not(feature = "pubsub-timestamp"))]
                timestamp: None,
                #[cfg(feature = "pubsub-attachment")]
                attachment: attachment.map(|span| self.bytes(span)),
                #[cfg(not(feature = "pubsub-attachment"))]
                attachment: None,
                #[cfg(feature = "reply-source-info")]
                source_info: source_info.as_ref(),
                #[cfg(not(feature = "reply-source-info"))]
                source_info: None,
            },
            #[cfg(feature = "query-reply-err")]
            RowKind::Err { encoding, payload } => PartsKind::Err {
                encoding: self.encoding_of(encoding),
                payload: self.bytes(*payload),
            },
        };
        ReplyParts {
            rid: row.rid,
            keyexpr: self.text(row.keyexpr),
            responder: row.responder.as_ref().map(|(zid, eid)| (&**zid, *eid)),
            qos: row.qos,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: row.ts_stack.as_ref(),
            kind,
        }
    }

    /// The `index`-th staged reply as borrowed parts, in the order they were
    /// staged. No allocation: the parts point into the stage.
    pub fn parts(&self, index: usize) -> Option<ReplyParts<'_>> {
        self.rows.get(index).map(|row| self.row_parts(row))
    }

    /// A row as the owned record, built from its parts: the one place a described
    /// reply becomes a [`QueryReply`].
    #[cfg(feature = "alloc")]
    fn row_to_reply(&self, row: &Row<P>) -> QueryReply {
        QueryReply::from_parts(&self.row_parts(row))
    }
}

/// The staged replies of a stage taken BY VALUE, in order, as owned records.
#[cfg(feature = "alloc")]
pub struct StagedIntoIter<P: Storage = Profile> {
    stage: ReplyStage<P>,
    next: usize,
}

#[cfg(feature = "alloc")]
impl<P: Storage> Iterator for StagedIntoIter<P> {
    type Item = QueryReply;

    fn next(&mut self) -> Option<QueryReply> {
        let reply = self.stage.nth(self.next)?;
        self.next = self.next.saturating_add(1);
        Some(reply)
    }
}

#[cfg(feature = "alloc")]
impl<P: Storage> IntoIterator for ReplyStage<P> {
    type Item = QueryReply;
    type IntoIter = StagedIntoIter<P>;

    fn into_iter(self) -> StagedIntoIter<P> {
        StagedIntoIter {
            stage: self,
            next: 0,
        }
    }
}

/// The staged replies of a stage taken IN PLACE: what [`ReplyStaging::drain_staged`]
/// hands back. The stage is emptied when this is dropped, however much was taken.
#[cfg(feature = "alloc")]
struct StagedDrain<'a, P: Storage> {
    stage: &'a mut ReplyStage<P>,
    next: usize,
}

#[cfg(feature = "alloc")]
impl<P: Storage> Iterator for StagedDrain<'_, P> {
    type Item = QueryReply;

    fn next(&mut self) -> Option<QueryReply> {
        let reply = self.stage.nth(self.next)?;
        self.next = self.next.saturating_add(1);
        Some(reply)
    }
}

#[cfg(feature = "alloc")]
impl<P: Storage> Drop for StagedDrain<'_, P> {
    fn drop(&mut self) {
        self.stage.clear();
    }
}

impl<P: Storage> Default for ReplyStage<P> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
            arena: BoundedVec::default(),
            refusals: ReplyRefusals::default(),
            bounds: ReplyBounds::BUILD,
        }
    }
}

/// The one thing a responder does with the stage it is lent: put a reply in it. A trait apart from
/// [`ReplyStaging`] so a responder holds the stage of any storage policy behind one reference,
/// whatever policy the session's tables of its peer are.
pub trait StagesReplies {
    /// [`ReplyStaging::stage_parts`].
    fn stage_reply(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError>;
}

impl<P: Storage> StagesReplies for ReplyStage<P> {
    fn stage_reply(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        ReplyStaging::stage_parts(self, parts)
    }
}

impl<P: Storage> ReplyStaging for ReplyStage<P> {
    fn stage_parts(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        // The sizes the reply would put in the arena, and the two bounds a peer's
        // query must not be able to move: the payload (and attachment) length, and
        // the identity lengths the wire cannot carry.
        let (payload_len, attachment_len) = parts.bounded_lengths();
        let schema_len = match &parts.kind {
            PartsKind::Reply { encoding, .. } => {
                encoding.and_then(|e| e.schema).map_or(0, <[u8]>::len)
            }
            #[cfg(feature = "query-reply-err")]
            PartsKind::Err { encoding, .. } => encoding
                .and_then(|(_, schema)| schema)
                .map_or(0, <[u8]>::len),
        };
        // A policy that enforces its capacity addresses its arena with 16 bits, which
        // is only sound while the arena it declares fits them.
        const {
            assert!(
                !P::ENFORCES_CAPACITY || caps::REPLY_STAGE_BYTES <= <Off<P> as SpanOffset>::MAX,
                "a staged reply's bytes are addressed by offsets of the policy's width"
            );
        }
        if self.rows.free_slots() == 0
            || !self
                .bounds
                .replies
                .admits(self.rows.len().saturating_add(1))
        {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }
        // The bounds a peer's query must not be able to move: the payload length the session
        // states, on every policy, and the identity lengths the row can hold, on the fixed one.
        // The growable policy has no identity cap, and no payload cap until one is stated.
        let payload_most = self.bounds.payload_most::<P>();
        let identity_too_long = parts
            .responder
            .is_some_and(|(zid, _)| zid.len() > ZID_BYTES)
            || matches!(
                &parts.kind,
                PartsKind::Reply { timestamp: Some(ts), .. } if ts.zid.len() > ZID_BYTES
            );
        if !payload_most.admits(payload_len)
            || !payload_most.admits(attachment_len)
            || (P::ENFORCES_CAPACITY && identity_too_long)
        {
            self.refusals.payload_too_large = self.refusals.payload_too_large.saturating_add(1);
            return Err(ReplyError::PayloadTooLarge);
        }
        // Sized and bounded as the handler described it, in every build: what a build's features
        // keep of a reply (`RowKind`) decides what goes out, not which replies a handler is told
        // were refused.
        let need = parts
            .keyexpr
            .len()
            .saturating_add(payload_len)
            .saturating_add(attachment_len)
            .saturating_add(schema_len);
        // The arena's room. On the fixed policy it is the declared bytes, and the
        // assertion above makes them addressable, so that is the whole check; on the
        // growable one the allocator has room, and what bounds the arena is the
        // largest offset the policy's width can address.
        let arena_has_room = if P::ENFORCES_CAPACITY {
            need <= self.arena.free_slots()
        } else {
            self.arena.len().saturating_add(need) <= <Off<P> as SpanOffset>::MAX
        };
        if !arena_has_room {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }

        // Everything fits: write it. The order is fixed (key first) because `pop`
        // gives the arena back from where the last row's key starts.
        let keyexpr = self.put(parts.keyexpr.as_bytes());
        let responder = parts.responder.map(|(zid, eid)| {
            let mut copy = BoundedVec::default();
            // The length was checked above on a policy that enforces it; the growable
            // one takes any length.
            let _ = copy.extend_from_slice(zid);
            (copy, eid)
        });
        let kind = match parts.kind {
            PartsKind::Reply {
                body,
                encoding,
                #[cfg(feature = "pubsub-timestamp")]
                timestamp,
                #[cfg(feature = "pubsub-attachment")]
                attachment,
                #[cfg(feature = "reply-source-info")]
                source_info,
                ..
            } => RowKind::Reply {
                payload: match body {
                    PartsBody::Put(payload) => RowPayload::Put(self.put(payload)),
                    PartsBody::Del => RowPayload::Del,
                    #[cfg(feature = "transport-shm")]
                    PartsBody::Shared(handle) => RowPayload::Shared(handle.clone()),
                },
                encoding: self.put_encoding(encoding.map(|e| (e.packed_id, e.schema))),
                #[cfg(feature = "pubsub-timestamp")]
                timestamp: timestamp.map(|ts| {
                    let mut zid = BoundedVec::default();
                    // The length was checked above, as the responder's was.
                    let _ = zid.extend_from_slice(ts.zid);
                    (ts.time, zid)
                }),
                #[cfg(feature = "pubsub-attachment")]
                attachment: attachment.map(|bytes| self.put(bytes)),
                #[cfg(feature = "reply-source-info")]
                source_info: source_info.cloned(),
            },
            #[cfg(feature = "query-reply-err")]
            PartsKind::Err { encoding, payload } => RowKind::Err {
                encoding: self.put_encoding(encoding),
                payload: self.put(payload),
            },
        };
        // Room for a row was checked first.
        let _ = self.rows.push(Row {
            rid: parts.rid,
            qos: parts.qos,
            keyexpr,
            responder,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: parts.ts_stack.cloned(),
            kind,
        });
        Ok(())
    }

    fn staged(&self) -> usize {
        self.rows.len()
    }

    #[cfg(feature = "alloc")]
    fn nth(&self, index: usize) -> Option<QueryReply> {
        self.rows.get(index).map(|row| self.row_to_reply(row))
    }

    #[cfg(feature = "alloc")]
    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> + '_ {
        StagedDrain {
            stage: self,
            next: 0,
        }
    }

    fn drain_parts<F: FnMut(ReplyParts<'_>)>(&mut self, mut emit: F) {
        for row in self.rows.iter() {
            emit(self.row_parts(row));
        }
        self.clear();
    }
}

/// The `Final`s owed to one peer, as `(rid, the query's QoS)`: up to
/// [`caps::MAX_PENDING_FINALS`] rows on a policy that enforces the capacity
/// ([`Static`]), where a full table refuses the REQUEST that
/// would have needed one ([`Self::refusals`] counts them) and does not grow; and as
/// many as are owed on one that does not ([`Heap`](crate::bounded::Heap)), whose
/// storage refuses nothing. On both, a request that would leave more `Final`s owed than
/// the quota its creator stated ([`Self::limit_to`]) is refused and counted as a full
/// table's is.
///
/// One algorithm for both: the table is a [`BoundedVec`] of its storage policy,
/// `has_room` asks it how many pushes are still guaranteed, and the heap policy
/// answers `usize::MAX`. The policy defaults to this build's
/// [`Profile`], so `FinalStage` alone is the build's table.
pub struct FinalStage<P: Storage = Profile> {
    rows: BoundedVec<(crate::wire_id::RequestId, QosLevel), { caps::MAX_PENDING_FINALS }, P>,
    refused_requests: u32,
    /// The most `Final`s the table owes (`MAX_PENDING_FINALS`): what the creator of the
    /// session resolved ([`Self::limit_to`]), the build's value until it does. A growable
    /// table refuses nothing by its storage, so this is what bounds it; where the build fixes
    /// the bound to the storage's capacity it is held in no byte and the storage refuses alone.
    quota: crate::limits::MaxPendingFinalsHeld,
}

impl FinalStage<Static> {
    /// An empty table of the static policy. `const`, so a session slot that holds
    /// one can be a `static` whatever the build's profile is.
    pub const fn new_static() -> Self {
        Self {
            rows: BoundedVec::new_static(),
            refused_requests: 0,
            quota: crate::limits::MaxPendingFinalsHeld::build_default(),
        }
    }
}

impl FinalStage<Lent> {
    /// An empty table whose `rows` rows are lent from `arena`, held to the build's quota until its
    /// creator states the session's ([`Self::limit_to`]). Refused when `rows` is over the build's
    /// capacity or the arena has not the room.
    pub fn lent(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        Ok(Self {
            rows: arena.lend(rows)?,
            refused_requests: 0,
            quota: crate::limits::MaxPendingFinalsHeld::build_default(),
        })
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows` rows. `None` past the address space.
    pub const fn arena_bytes(rows: usize) -> Option<usize> {
        Arena::table_bytes::<(crate::wire_id::RequestId, QosLevel)>(rows)
    }
}

impl FinalStage<Profile> {
    /// An empty table of this build's profile. `const`, so a session slot that holds
    /// one can be a `static`.
    pub const fn new() -> Self {
        Self {
            rows: BoundedVec::new(),
            refused_requests: 0,
            quota: crate::limits::MaxPendingFinalsHeld::build_default(),
        }
    }
}

impl<P: Storage> FinalStage<P> {
    /// Hold the table to the `MAX_PENDING_FINALS` its creator resolved: a request that would
    /// leave more `Final`s owed than `quota` admits has no room ([`FinalStaging::has_room`])
    /// and is refused and counted, and the `Final`s already owed are kept, as a lowered soft
    /// limit keeps what it holds.
    pub fn limit_to(&mut self, quota: crate::limits::MaxPendingFinalsHeld) {
        self.quota = quota;
    }

    /// How many requests were refused because no `Final` could be owed for them.
    pub fn refusals(&self) -> u32 {
        self.refused_requests
    }

    /// Drop every owed `Final`; the count is kept.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Take every owed `Final` out, in the order they were owed, as a table of its own. This
    /// table is left empty, with its count of refused requests, its quota and its rows: the
    /// count says what was asked of this table, the quota is the one its creator stated, and
    /// the rows are the ones its maker lent it, which a table moved out would take with it. The
    /// table taken out is a buffer of its own (`Storage::Scratch`), as a policy whose rows are
    /// only lent makes none for itself.
    pub fn take_owed(&mut self) -> FinalStage<P::Scratch> {
        let mut owed = FinalStage {
            rows: BoundedVec::default(),
            refused_requests: 0,
            quota: self.quota,
        };
        for row in self.rows.iter() {
            let taken = owed.rows.push(*row);
            debug_assert!(taken.is_ok(), "a table of the same capacity");
        }
        self.rows.clear();
        owed
    }
}

impl<P: Storage> IntoIterator for FinalStage<P> {
    type Item = (crate::wire_id::RequestId, QosLevel);
    type IntoIter = <BoundedVec<
        (crate::wire_id::RequestId, QosLevel),
        { caps::MAX_PENDING_FINALS },
        P,
    > as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

impl<P: Storage> Default for FinalStage<P> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
            refused_requests: 0,
            quota: crate::limits::MaxPendingFinalsHeld::build_default(),
        }
    }
}

impl<P: Storage> core::ops::Deref for FinalStage<P> {
    type Target = [(crate::wire_id::RequestId, QosLevel)];

    fn deref(&self) -> &[(crate::wire_id::RequestId, QosLevel)] {
        &self.rows
    }
}

impl<P: Storage> FinalStaging for FinalStage<P> {
    fn has_room(&self) -> bool {
        self.rows.free_slots() > 0 && self.quota.admits(self.rows.len().saturating_add(1))
    }

    fn owe(&mut self, rid: crate::wire_id::RequestId, qos: QosLevel) {
        // Room was asked for before the request ran; a table that has none by
        // now is the caller's contract broken, and counted rather than dropped
        // in silence.
        if !self.quota.admits(self.rows.len().saturating_add(1))
            || self.rows.push((rid, qos)).is_err()
        {
            self.refused_requests = self.refused_requests.saturating_add(1);
        }
    }

    fn refuse_request(&mut self) {
        self.refused_requests = self.refused_requests.saturating_add(1);
    }

    fn owed(&self) -> usize {
        self.rows.len()
    }

    fn drain_owed(&mut self) -> impl Iterator<Item = (crate::wire_id::RequestId, QosLevel)> {
        OwedDrain {
            rows: &mut self.rows,
            at: 0,
        }
    }
}

/// What [`FinalStaging::drain_owed`] hands out: the owed rows in order, with the table
/// emptied when the iterator is dropped, consumed or not.
///
/// Not `mem::take(rows).into_iter()`: that moves the backing out, and a growable one
/// then allocates again at the next row. The table keeps the capacity it grew to, which
/// is what lets a frame of queries cost no allocation once the first one has run. A row
/// is two words and `Copy`, so it is read in place and the backing never moves.
struct OwedDrain<'a, P: Storage> {
    rows:
        &'a mut BoundedVec<(crate::wire_id::RequestId, QosLevel), { caps::MAX_PENDING_FINALS }, P>,
    at: usize,
}

impl<P: Storage> Iterator for OwedDrain<'_, P> {
    type Item = (crate::wire_id::RequestId, QosLevel);

    fn next(&mut self) -> Option<Self::Item> {
        let row = *self.rows.get(self.at)?;
        self.at = self.at.saturating_add(1);
        Some(row)
    }
}

impl<P: Storage> Drop for OwedDrain<'_, P> {
    fn drop(&mut self) {
        self.rows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Static;
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;

    const N: usize = caps::MAX_PENDING_FINALS;

    /// The finals table, written once and run on every policy: fill it to its
    /// declared capacity, then ask for one more. A policy that enforces the
    /// capacity says there is no room and takes the refusal as counted, and so does
    /// a table whose quota is the capacity: a fixed build states its capacity as
    /// every table's quota, a table on the heap policy included. Otherwise there is
    /// room and the entry is taken. The expectations are read from the policy's own
    /// contract and the build's quota, never from a feature gate.
    fn fill_to_n_then_refuse_at_n_plus_one<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        for rid in 0..N as u32 {
            assert!(finals.has_room(), "entry {rid} is within the capacity");
            finals.owe(rid, QosLevel::DEFAULT);
        }
        assert_eq!(finals.owed(), N);
        assert_eq!(finals.refusals(), 0, "nothing was refused up to N");

        let held_to_n =
            P::ENFORCES_CAPACITY || !crate::limits::MaxPendingFinalsHeld::default().admits(N + 1);
        if held_to_n {
            assert!(!finals.has_room(), "a full table has no room");
            finals.refuse_request();
            assert_eq!(finals.refusals(), 1, "the refused request is counted");
            finals.owe(N as u32, QosLevel::DEFAULT);
            assert_eq!(finals.owed(), N, "an entry past N is not taken");
            assert_eq!(
                finals.refusals(),
                2,
                "and is counted, not dropped in silence"
            );
        } else {
            assert!(finals.has_room(), "an advisory capacity always has room");
            finals.owe(N as u32, QosLevel::DEFAULT);
            assert_eq!(finals.owed(), N + 1);
            assert_eq!(finals.refusals(), 0, "the growable table refuses nothing");
        }
    }

    /// What is owed is taken in the order it was owed, and taking it empties the
    /// table without touching the count of what was refused.
    fn drain_takes_in_order_and_keeps_the_count<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        for rid in 10..13u32 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        finals.refuse_request();
        let mut taken: [crate::wire_id::RequestId; 3] = [0; 3];
        for (slot, (rid, _)) in taken.iter_mut().zip(finals.drain_owed()) {
            *slot = rid;
        }
        assert_eq!(taken, [10, 11, 12]);
        assert_eq!(finals.owed(), 0);
        assert!(finals.is_empty());
        assert_eq!(finals.refusals(), 1, "draining does not clear the count");
    }

    /// Taking what is owed leaves the table the memory it grew to: the rows of the
    /// next frame lie where the rows of this one did, so a growable table does not
    /// allocate again for each frame (the in-place receive path's turn is measured to
    /// cost the heap nothing for a query, and moving the backing out of the table in
    /// the drain made it cost one allocation per frame).
    fn drain_keeps_the_backing<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        for rid in 0..6u32 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        let first = finals.as_ptr();
        assert_eq!(finals.drain_owed().count(), 6);
        assert!(finals.is_empty());
        for rid in 0..6u32 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        assert_eq!(
            finals.as_ptr(),
            first,
            "the second frame's rows lie where the first frame's did"
        );
        // An iterator dropped before its end empties the table all the same.
        let _ = finals.drain_owed().next();
        assert!(finals.is_empty());
    }

    /// `clear` drops what is owed and keeps the count, as `forget_peer` relies on.
    fn clear_keeps_the_count<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        finals.owe(1, QosLevel::DEFAULT);
        finals.refuse_request();
        finals.clear();
        assert_eq!(finals.owed(), 0);
        assert_eq!(finals.refusals(), 1);
    }

    // ---- The reply stage, the same bodies on every policy ----------------------

    /// A plain data reply, described the way a queryable's `send_*` describes it.
    fn put_reply<'a>(
        rid: crate::wire_id::RequestId,
        keyexpr: &'a str,
        payload: &'a [u8],
    ) -> ReplyParts<'a> {
        ReplyParts {
            rid,
            keyexpr,
            responder: None,
            qos: QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: None,
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        }
    }

    /// A reply whose bytes come from three places every build holds: key, payload and the schema
    /// of its encoding.
    fn fat_reply<'a>(
        rid: crate::wire_id::RequestId,
        payload: &'a [u8],
        schema: &'a [u8],
    ) -> ReplyParts<'a> {
        let key = "k";
        ReplyParts {
            rid,
            keyexpr: key,
            responder: None,
            qos: QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: Some(EncodingParts {
                    packed_id: 1,
                    schema: Some(schema),
                }),
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        }
    }

    /// A one-byte Put on `"k"` carrying the side-bands a build may or may not hold: a timestamp,
    /// an attachment and a source info.
    fn side_band_reply<'a>(
        zid: &'a [u8],
        attachment: &'a [u8],
        source_info: &'a SourceInfo,
    ) -> ReplyParts<'a> {
        ReplyParts {
            rid: 1,
            keyexpr: "k",
            responder: None,
            qos: QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(b"v"),
                encoding: None,
                timestamp: Some(TimestampParts { time: 42, zid }),
                attachment: Some(attachment),
                source_info: Some(source_info),
            },
        }
    }

    /// A source info unlike any default.
    fn some_source_info() -> SourceInfo {
        SourceInfo {
            zid: [3; 16],
            zid_len: 4,
            eid: 7,
            sn: 9,
        }
    }

    /// Fill the row table to `MAX_PENDING_REPLIES`, then stage one more: refused and
    /// counted where the capacity is hard or the build's quota is the capacity, taken
    /// where neither refuses.
    fn rows_fill_to_n_then_refuse_at_n_plus_one<P: Storage>() {
        let mut stage: ReplyStage<P> = ReplyStage::default();
        for rid in 0..caps::MAX_PENDING_REPLIES as u32 {
            assert!(stage.stage_parts(put_reply(rid, "a/b", b"x")).is_ok());
        }
        assert_eq!(stage.staged(), caps::MAX_PENDING_REPLIES);
        assert_eq!(stage.refusals(), ReplyRefusals::default());

        let held_to_n = P::ENFORCES_CAPACITY
            || !crate::limits::MaxPendingRepliesHeld::default()
                .admits(caps::MAX_PENDING_REPLIES + 1);
        let beyond = stage.stage_parts(put_reply(99, "a/b", b"x"));
        if held_to_n {
            assert_eq!(beyond, Err(ReplyError::StagingFull));
            assert_eq!(stage.staged(), caps::MAX_PENDING_REPLIES);
            assert_eq!(stage.refusals().staging_full, 1);
            assert_eq!(stage.refusals().payload_too_large, 0);
        } else {
            assert_eq!(beyond, Ok(()));
            assert_eq!(stage.staged(), caps::MAX_PENDING_REPLIES + 1);
            assert_eq!(stage.refusals(), ReplyRefusals::default());
        }
    }

    /// Whether a stage of the policy `P` holding the snapshot's default bounds refuses a
    /// payload one byte past the build's `MAX_REPLY_PAYLOAD_BYTES`: the fixed policy always
    /// does, and any stage does where the snapshot's default bound is a number, as it is in a
    /// build on the fixed profile; where the default is no bound a growable stage takes it.
    fn refuses_past_the_build<P: Storage>() -> bool {
        P::ENFORCES_CAPACITY
            || !crate::limits::MaxReplyPayloadBytesHeld::default()
                .get()
                .admits(caps::MAX_REPLY_PAYLOAD_BYTES + 1)
    }

    /// A payload past `MAX_REPLY_PAYLOAD_BYTES` is a refusal where the stage's bound is that
    /// value (the fixed policy, or the snapshot's default bound of a build on the fixed profile)
    /// and leaves the stage as it was; a growable stage with no bound takes it.
    fn payload_past_the_bound<P: Storage>() {
        let big = [7u8; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        let outcome = stage.stage_parts(put_reply(1, "a", &big));
        if refuses_past_the_build::<P>() {
            assert_eq!(outcome, Err(ReplyError::PayloadTooLarge));
            assert_eq!(stage.staged(), 0);
            assert_eq!(stage.bytes_held(), 0, "a refusal writes nothing");
            assert_eq!(stage.refusals().payload_too_large, 1);
        } else {
            assert_eq!(outcome, Ok(()));
            assert_eq!(stage.staged(), 1);
            assert_eq!(stage.refusals(), ReplyRefusals::default());
        }
    }

    /// An exchange moves the staged replies, rows and bytes, to the other stage, in their
    /// order, and leaves each stage the counts of what it refused itself.
    fn exchange_moves_the_replies_and_keeps_the_refusals<P: Storage>() {
        let big = [7u8; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
        let mut staging: ReplyStage<P> = ReplyStage::default();
        // Refused on a policy that enforces its bound, and so counted there; staged on one
        // that does not.
        let _ = staging.stage_parts(put_reply(9, "a", &big));
        staging.clear();
        let refused = staging.refusals();
        assert_eq!(staging.stage_parts(put_reply(1, "a/b", b"one")), Ok(()));
        assert_eq!(staging.stage_parts(put_reply(2, "a/c", b"two")), Ok(()));
        let mut sending: ReplyStage<P> = ReplyStage::default();

        staging.exchange_staged(&mut sending);

        assert_eq!(
            staging.staged(),
            0,
            "the stage that staged holds none after"
        );
        assert_eq!(staging.bytes_held(), 0);
        assert_eq!(staging.refusals(), refused, "its refusals stay with it");
        assert_eq!(sending.refusals(), ReplyRefusals::default());
        let mut seen: [(crate::wire_id::RequestId, usize); 2] = [(0, 0); 2];
        let mut count = 0usize;
        sending.drain_parts(|parts| {
            if let Some(slot) = seen.get_mut(count) {
                *slot = (parts.rid, parts.keyexpr.len());
            }
            count += 1;
        });
        assert_eq!(count, 2, "both replies were moved");
        assert_eq!(seen, [(1, 3), (2, 3)], "in their order");
    }

    /// The arena has its own room, apart from the rows: replies fat enough to use up
    /// the declared bytes before the rows are used up are refused as `StagingFull`.
    fn arena_runs_out_before_the_rows<P: Storage>() {
        let payload = [1u8; caps::MAX_REPLY_PAYLOAD_BYTES];
        let schema = [2u8; caps::MAX_REPLY_PAYLOAD_BYTES];
        let per_reply = 1 + payload.len() + schema.len();
        let fits = caps::REPLY_STAGE_BYTES / per_reply;
        assert!(
            fits < caps::MAX_PENDING_REPLIES,
            "the fixture is fat enough to meet the arena first"
        );
        let mut stage: ReplyStage<P> = ReplyStage::default();
        for rid in 0..fits as u32 {
            assert_eq!(stage.stage_parts(fat_reply(rid, &payload, &schema)), Ok(()));
        }
        let beyond = stage.stage_parts(fat_reply(99, &payload, &schema));
        if P::ENFORCES_CAPACITY {
            assert_eq!(beyond, Err(ReplyError::StagingFull));
            assert_eq!(stage.staged(), fits);
            assert_eq!(stage.bytes_held(), fits * per_reply);
            assert_eq!(stage.refusals().staging_full, 1);
        } else {
            assert_eq!(beyond, Ok(()));
            assert_eq!(stage.staged(), fits + 1);
        }
    }

    /// What was staged is handed out as borrowed parts, in order, with every field
    /// as it went in, and the stage is left empty with its counts kept.
    fn drain_parts_hands_out_what_was_staged<P: Storage>() {
        let zid = [9u8; 4];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        for rid in 0..3u32 {
            let payload = [rid as u8 + 1; 3];
            let parts = ReplyParts {
                rid,
                keyexpr: "home/temp",
                responder: Some((&zid, 5)),
                qos: QosLevel::DEFAULT,
                #[cfg(feature = "pubsub-ts-stack")]
                ts_stack: None,
                kind: PartsKind::Reply {
                    body: PartsBody::Put(&payload),
                    encoding: Some(EncodingParts {
                        packed_id: 7,
                        schema: Some(&b"s"[..]),
                    }),
                    timestamp: Some(TimestampParts {
                        time: 42,
                        zid: &zid,
                    }),
                    attachment: Some(b"att"),
                    source_info: None,
                },
            };
            assert_eq!(stage.stage_parts(parts), Ok(()));
        }

        let mut seen = 0u32;
        stage.drain_parts(|parts| {
            assert_eq!(parts.rid, seen, "in the order they were staged");
            assert_eq!(parts.keyexpr, "home/temp");
            assert_eq!(parts.responder, Some((&zid[..], 5)));
            let PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: Some(encoding),
                ..
            } = parts.kind
            else {
                panic!("the staged reply is a Put with its encoding");
            };
            assert_eq!(payload, &[seen as u8 + 1; 3]);
            assert_eq!((encoding.packed_id, encoding.schema), (7, Some(&b"s"[..])));
            seen += 1;
        });
        assert_eq!(seen, 3);
        assert_eq!(stage.staged(), 0);
        assert_eq!(stage.bytes_held(), 0);
    }

    /// A reply's timestamp is held and handed back by a build that sends it
    /// (`pubsub-timestamp`), and not held by one that does not.
    fn staged_timestamp_follows_the_build<P: Storage>() {
        let info = some_source_info();
        let zid = [9u8; 4];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        assert_eq!(
            stage.stage_parts(side_band_reply(&zid, b"att", &info)),
            Ok(())
        );
        let mut drained = 0;
        stage.drain_parts(|parts| {
            let PartsKind::Reply {
                body: PartsBody::Put(_),
                timestamp,
                ..
            } = parts.kind
            else {
                panic!("a Put was staged");
            };
            #[cfg(feature = "pubsub-timestamp")]
            {
                let timestamp = timestamp.expect("the build sends a reply's timestamp");
                assert_eq!((timestamp.time, timestamp.zid), (42, &zid[..]));
            }
            #[cfg(not(feature = "pubsub-timestamp"))]
            assert!(
                timestamp.is_none(),
                "a build that does not send a reply's timestamp does not hold it"
            );
            drained += 1;
        });
        assert_eq!(drained, 1);
    }

    /// A reply's attachment is held in the arena and handed back by a build that sends it
    /// (`pubsub-attachment`); a build that does not holds none of its bytes. Either way the
    /// reply is sized as it was described.
    fn staged_attachment_follows_the_build<P: Storage>() {
        let info = some_source_info();
        let zid = [9u8; 4];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        assert_eq!(
            stage.stage_parts(side_band_reply(&zid, b"att", &info)),
            Ok(())
        );
        let key_and_payload = "k".len() + b"v".len();
        #[cfg(feature = "pubsub-attachment")]
        assert_eq!(stage.bytes_held(), key_and_payload + b"att".len());
        #[cfg(not(feature = "pubsub-attachment"))]
        assert_eq!(
            stage.bytes_held(),
            key_and_payload,
            "a build that does not send a reply's attachment holds none of its bytes"
        );
        let mut drained = 0;
        stage.drain_parts(|parts| {
            let PartsKind::Reply {
                body: PartsBody::Put(_),
                attachment,
                ..
            } = parts.kind
            else {
                panic!("a Put was staged");
            };
            #[cfg(feature = "pubsub-attachment")]
            assert_eq!(attachment, Some(&b"att"[..]));
            #[cfg(not(feature = "pubsub-attachment"))]
            assert_eq!(attachment, None);
            drained += 1;
        });
        assert_eq!(drained, 1);
    }

    /// A reply's source info is held and handed back by a build that sends it
    /// (`reply-source-info`), and not held by one that does not.
    fn staged_source_info_follows_the_build<P: Storage>() {
        let info = some_source_info();
        let zid = [9u8; 4];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        assert_eq!(
            stage.stage_parts(side_band_reply(&zid, b"att", &info)),
            Ok(())
        );
        let mut drained = 0;
        stage.drain_parts(|parts| {
            let PartsKind::Reply {
                body: PartsBody::Put(_),
                source_info,
                ..
            } = parts.kind
            else {
                panic!("a Put was staged");
            };
            #[cfg(feature = "reply-source-info")]
            assert_eq!(source_info, Some(&info));
            #[cfg(not(feature = "reply-source-info"))]
            assert_eq!(source_info, None);
            drained += 1;
        });
        assert_eq!(drained, 1);
    }

    /// An attachment past the payload bound is refused where the stage's bound is that value
    /// (`refuses_past_the_build`) whether or not the build holds attachments: a handler is
    /// told the same in every build.
    fn attachment_past_the_bound_is_refused_in_every_build<P: Storage>() {
        let big = [7u8; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
        let info = some_source_info();
        let zid = [9u8; 4];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        let outcome = stage.stage_parts(side_band_reply(&zid, &big, &info));
        if refuses_past_the_build::<P>() {
            assert_eq!(outcome, Err(ReplyError::PayloadTooLarge));
            assert_eq!(stage.staged(), 0);
            assert_eq!(stage.refusals().payload_too_large, 1);
        } else {
            assert_eq!(outcome, Ok(()));
            assert_eq!(stage.staged(), 1);
        }
    }

    /// The owned drain builds exactly the record `QueryReply::from_parts` builds from
    /// the same description, in order, and `pop` takes the last and gives its bytes
    /// back.
    fn owned_drain_is_from_parts<P: Storage>() {
        #[cfg(feature = "alloc")]
        owned_drain_is_from_parts_body::<P>();
    }

    #[cfg(feature = "alloc")]
    fn owned_drain_is_from_parts_body<P: Storage>() {
        let mut stage: ReplyStage<P> = ReplyStage::default();
        let described = [
            put_reply(1, "a/b", b"one"),
            put_reply(2, "a/c", b"second"),
            put_reply(3, "a/d", b""),
        ];
        for parts in described {
            assert_eq!(stage.stage_parts(parts), Ok(()));
        }
        assert_eq!(
            stage.nth(1),
            Some(QueryReply::from_parts(&described[1])),
            "nth builds the record from its row"
        );

        let held = stage.bytes_held();
        let last = stage.pop().expect("three are staged");
        assert_eq!(last, QueryReply::from_parts(&described[2]));
        assert_eq!(stage.staged(), 2);
        assert_eq!(
            stage.bytes_held(),
            held - "a/d".len(),
            "pop gives its bytes back"
        );

        let drained: Vec<QueryReply> = stage.drain_staged().collect();
        assert_eq!(
            drained,
            [
                QueryReply::from_parts(&described[0]),
                QueryReply::from_parts(&described[1])
            ]
        );
        assert_eq!(stage.staged(), 0, "a drain leaves the stage empty");
    }

    /// `clear` drops what is staged and its bytes and keeps what was refused.
    fn clear_keeps_the_refusals<P: Storage>() {
        let mut stage: ReplyStage<P> = ReplyStage::default();
        let big = [0u8; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
        let _ = stage.stage_parts(put_reply(1, "a", &big));
        let _ = stage.stage_parts(put_reply(2, "a", b"x"));
        let refused = stage.refusals();
        stage.clear();
        assert_eq!(stage.staged(), 0);
        assert_eq!(stage.bytes_held(), 0);
        assert_eq!(stage.refusals(), refused);
    }

    macro_rules! on_every_policy {
        ($($case:ident),* $(,)?) => {
            mod on_static {
                use super::*;
                $(#[test] fn $case() { super::$case::<Static>(); })*
            }
            #[cfg(feature = "alloc")]
            mod on_heap {
                use crate::bounded::Heap;
                $(#[test] fn $case() { super::$case::<Heap>(); })*
            }
        };
    }

    on_every_policy!(
        fill_to_n_then_refuse_at_n_plus_one,
        drain_takes_in_order_and_keeps_the_count,
        drain_keeps_the_backing,
        clear_keeps_the_count,
        rows_fill_to_n_then_refuse_at_n_plus_one,
        payload_past_the_bound,
        exchange_moves_the_replies_and_keeps_the_refusals,
        arena_runs_out_before_the_rows,
        drain_parts_hands_out_what_was_staged,
        staged_timestamp_follows_the_build,
        staged_attachment_follows_the_build,
        staged_source_info_follows_the_build,
        attachment_past_the_bound_is_refused_in_every_build,
        owned_drain_is_from_parts,
        clear_keeps_the_refusals,
    );

    /// The growable policy addresses its arena with 32-bit offsets: a stage that holds
    /// more than 64 KiB keeps every reply's bytes where they were put. (The fixed
    /// policy's 16-bit offsets are why its arena is declared under 64 KiB.)
    #[cfg(feature = "alloc")]
    #[test]
    fn the_growable_stage_addresses_past_64_kib() {
        use crate::bounded::Heap;
        // A build on the fixed profile holds every stage, a growable one included, to the
        // snapshot's default payload bound, which no reply of 40,000 bytes fits; the offsets
        // past 64 KiB are reached only where that default is no bound.
        if !crate::limits::MaxReplyPayloadBytesHeld::default()
            .get()
            .is_unbounded()
        {
            return;
        }
        let first = alloc::vec![1u8; 40_000];
        let second = alloc::vec![2u8; 40_000];
        let mut stage: ReplyStage<Heap> = ReplyStage::default();
        assert_eq!(stage.stage_parts(put_reply(1, "a", &first)), Ok(()));
        assert_eq!(stage.stage_parts(put_reply(2, "b", &second)), Ok(()));
        assert!(stage.bytes_held() > usize::from(u16::MAX));

        let mut lens = [0usize; 2];
        let mut fills = [0u8; 2];
        let mut at = 0;
        stage.drain_parts(|parts| {
            let PartsKind::Reply {
                body: PartsBody::Put(payload),
                ..
            } = parts.kind
            else {
                panic!("a Put was staged");
            };
            lens[at] = payload.len();
            assert!(payload.iter().all(|byte| *byte == payload[0]));
            fills[at] = payload[0];
            at += 1;
        });
        assert_eq!(lens, [40_000, 40_000]);
        assert_eq!(
            fills,
            [1, 2],
            "the second reply's bytes are not the first's"
        );
    }

    /// The default `FinalStage` is the build's profile and can sit in a `static`.
    #[test]
    fn the_profile_table_is_const_constructible() {
        static FINALS: FinalStage = FinalStage::new();
        assert_eq!(FINALS.owed(), 0);
    }
}
