// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What is OWED to one peer by its queries: the replies a queryable has staged
//! and the `ResponseFinal`s that must follow them (fixed-memory steps S9a and S9b).
//!
//! Both are written by a PEER, in the sense that matters: the peer's `Request`
//! makes the session stage them, and a peer that sends requests faster than the
//! session drains them decides how many there are. Each is ONE type over a storage
//! policy ([`crate::bounded::Storage`]), written once. On the growable policy (the AP
//! profile) the tables grow with the allocator and nothing is refused, as it always
//! was. On the policy that enforces its capacity (the fixed backing, selected by
//! `bounded-heapless`) each is a table of declared capacity
//! ([`caps::MAX_PENDING_REPLIES`], [`caps::MAX_PENDING_FINALS`]) and a table that
//! cannot take another entry REFUSES it, COUNTS it, and tells whoever asked:
//!
//! - a reply the stage has no room for, or whose payload is longer than
//!   [`caps::MAX_REPLY_PAYLOAD_BYTES`], is an `Err` to the queryable's handler
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

use crate::bounded::{BoundedVec, Profile, SpanOffset, Static, Storage};
use crate::caps;
#[cfg(feature = "alloc")]
use crate::query::QueryReply;
use crate::query_sink::ReplyError;
#[cfg(feature = "alloc")]
use crate::sample::{EncodingHint, TimestampHint};
use crate::sample::{QosLevel, SourceInfo};

/// A reply's encoding as borrowed parts: the wire `packed_id` and the optional
/// schema, a slice of the caller's own string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingParts<'a> {
    /// The wire-packed id (`id << 1 | schema_present`).
    pub packed_id: u32,
    /// The schema text, if the encoding carries one.
    pub schema: Option<&'a str>,
}

#[cfg(feature = "alloc")]
impl<'a> EncodingParts<'a> {
    /// The parts of an owned hint, borrowing its schema.
    pub fn of(hint: &'a EncodingHint) -> Self {
        Self {
            packed_id: hint.packed_id,
            schema: hint.schema.as_deref(),
        }
    }
}

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
        encoding: Option<(u32, Option<&'a str>)>,
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
    pub rid: u64,
    /// The keyexpr the reply is stamped with.
    pub keyexpr: &'a str,
    /// The responder identity (`zid` bytes, entity id) stamped on the response, if
    /// one was attached.
    pub responder: Option<(&'a [u8], u32)>,
    /// The `ext_qos` the response goes out with.
    pub qos: QosLevel,
    /// What the reply is.
    pub kind: PartsKind<'a>,
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
    fn owe(&mut self, rid: u64, qos: QosLevel);

    /// A request refused because no `Final` could be owed for it. Counted.
    fn refuse_request(&mut self);

    /// How many `Final`s are owed.
    fn owed(&self) -> usize;

    /// Take every owed `Final`, in the order they were owed.
    fn drain_owed(&mut self) -> impl Iterator<Item = (u64, QosLevel)>;
}

// ---------------------------------------------------------------------------
// The stage, once, over a storage policy: tables of declared capacity on a policy
// that enforces it (refusing and counting), and the same tables growing with the
// allocator on one that does not.
// ---------------------------------------------------------------------------

/// What a [`ReplyStage`] refused since it was made, by why.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplyRefusals {
    /// Replies the stage had no room for ([`caps::MAX_PENDING_REPLIES`] rows held,
    /// or the byte arena had no room left for the reply's bytes).
    pub staging_full: u32,
    /// Replies whose payload was longer than [`caps::MAX_REPLY_PAYLOAD_BYTES`].
    pub payload_too_large: u32,
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

enum RowKind<P: Storage> {
    Reply {
        payload: RowPayload<P>,
        encoding: RowEncoding<P>,
        timestamp: Option<(u64, BoundedVec<u8, ZID_BYTES, P>)>,
        attachment: Option<Span<P>>,
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
    rid: u64,
    qos: QosLevel,
    keyexpr: Span<P>,
    responder: Option<(BoundedVec<u8, ZID_BYTES, P>, u32)>,
    kind: RowKind<P>,
}

/// The replies a queryable has staged for one peer, over a storage policy.
///
/// On a policy that enforces its capacity ([`Static`](crate::bounded::Static)) the
/// stage holds [`caps::MAX_PENDING_REPLIES`] rows and [`caps::REPLY_STAGE_BYTES`] of
/// bytes, no more: a full stage refuses and counts, and does not grow. On one that
/// does not ([`Heap`](crate::bounded::Heap)) the same rows and the same arena grow
/// with the allocator, nothing is refused and nothing is counted, as the AP always
/// had it. One algorithm for both: the row table and the arena are
/// [`BoundedVec`]s of the policy, the room check asks them how many pushes are
/// still guaranteed, and the heap policy answers `usize::MAX`.
///
/// The policy defaults to this build's [`Profile`], so `ReplyStage` alone is the
/// build's stage.
pub struct ReplyStage<P: Storage = Profile> {
    rows: BoundedVec<Row<P>, { caps::MAX_PENDING_REPLIES }, P>,
    arena: BoundedVec<u8, { caps::REPLY_STAGE_BYTES }, P>,
    refusals: ReplyRefusals,
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
        }
    }
}

impl ReplyStage<Profile> {
    /// An empty stage of this build's profile. `const`, so a session slot that holds
    /// one can be a `static`.
    pub const fn new() -> Self {
        Self {
            rows: BoundedVec::new(),
            arena: BoundedVec::new(),
            refusals: ReplyRefusals {
                staging_full: 0,
                payload_too_large: 0,
            },
        }
    }
}

impl<P: Storage> ReplyStage<P> {
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
            .get(start..start + span.len.to_usize())
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

    fn put_encoding(&mut self, encoding: Option<(u32, Option<&str>)>) -> RowEncoding<P> {
        encoding.map(|(id, schema)| (id, schema.map(|schema| self.put(schema.as_bytes()))))
    }

    /// A row's encoding as the id and the schema text read out of the arena.
    fn encoding_of(&self, encoding: &RowEncoding<P>) -> Option<(u32, Option<&str>)> {
        encoding
            .as_ref()
            .map(|(packed_id, schema)| (*packed_id, schema.map(|schema| self.text(schema))))
    }

    /// A row as the borrowed description it was staged from. Nothing is copied:
    /// every slice points into the arena or the row, so this is what a writer that
    /// puts the reply on the wire reads, and what the owned record is built from.
    fn row_parts<'a>(&'a self, row: &'a Row<P>) -> ReplyParts<'a> {
        let kind = match &row.kind {
            RowKind::Reply {
                payload,
                encoding,
                timestamp,
                attachment,
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
                timestamp: timestamp
                    .as_ref()
                    .map(|(time, zid)| TimestampParts { time: *time, zid }),
                attachment: attachment.map(|span| self.bytes(span)),
                source_info: source_info.as_ref(),
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
            responder: row.responder.as_ref().map(|(zid, eid)| (&zid[..], *eid)),
            qos: row.qos,
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
        self.next += 1;
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
        self.next += 1;
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
        }
    }
}

impl<P: Storage> ReplyStaging for ReplyStage<P> {
    fn stage_parts(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        // The sizes the reply would put in the arena, and the two bounds a peer's
        // query must not be able to move: the payload (and attachment) length, and
        // the identity lengths the wire cannot carry.
        let (payload_len, attachment_len, schema_len) = match &parts.kind {
            PartsKind::Reply {
                body,
                encoding,
                attachment,
                ..
            } => (
                match body {
                    PartsBody::Put(payload) => payload.len(),
                    PartsBody::Del => 0,
                    #[cfg(feature = "transport-shm")]
                    PartsBody::Shared(_) => 0,
                },
                attachment.map_or(0, <[u8]>::len),
                encoding.and_then(|e| e.schema).map_or(0, str::len),
            ),
            #[cfg(feature = "query-reply-err")]
            PartsKind::Err { encoding, payload } => (
                payload.len(),
                0,
                encoding.and_then(|(_, schema)| schema).map_or(0, str::len),
            ),
        };
        // A policy that enforces its capacity addresses its arena with 16 bits, which
        // is only sound while the arena it declares fits them.
        const {
            assert!(
                !P::ENFORCES_CAPACITY || caps::REPLY_STAGE_BYTES <= <Off<P> as SpanOffset>::MAX,
                "a staged reply's bytes are addressed by offsets of the policy's width"
            );
        }
        if self.rows.free_slots() == 0 {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }
        // The bounds a peer's query must not be able to move are the fixed policy's:
        // the payload length and the identity lengths the row can hold. The growable
        // policy has neither a payload cap nor an identity cap, as it never had.
        let identity_too_long = parts
            .responder
            .is_some_and(|(zid, _)| zid.len() > ZID_BYTES)
            || matches!(
                &parts.kind,
                PartsKind::Reply { timestamp: Some(ts), .. } if ts.zid.len() > ZID_BYTES
            );
        if P::ENFORCES_CAPACITY
            && (payload_len > caps::MAX_REPLY_PAYLOAD_BYTES
                || attachment_len > caps::MAX_REPLY_PAYLOAD_BYTES
                || identity_too_long)
        {
            self.refusals.payload_too_large = self.refusals.payload_too_large.saturating_add(1);
            return Err(ReplyError::PayloadTooLarge);
        }
        let need = parts.keyexpr.len() + payload_len + attachment_len + schema_len;
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
                timestamp,
                attachment,
                source_info,
            } => RowKind::Reply {
                payload: match body {
                    PartsBody::Put(payload) => RowPayload::Put(self.put(payload)),
                    PartsBody::Del => RowPayload::Del,
                    #[cfg(feature = "transport-shm")]
                    PartsBody::Shared(handle) => RowPayload::Shared(handle.clone()),
                },
                encoding: self.put_encoding(encoding.map(|e| (e.packed_id, e.schema))),
                timestamp: timestamp.map(|ts| {
                    let mut zid = BoundedVec::default();
                    // The length was checked above, as the responder's was.
                    let _ = zid.extend_from_slice(ts.zid);
                    (ts.time, zid)
                }),
                attachment: attachment.map(|bytes| self.put(bytes)),
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
/// ([`Static`](crate::bounded::Static)), where a full table refuses the REQUEST that
/// would have needed one ([`Self::refusals`] counts them) and does not grow; and as
/// many as are owed on one that does not ([`Heap`](crate::bounded::Heap)), which
/// refuses nothing and counts nothing, as it always did.
///
/// One algorithm for both: the table is a [`BoundedVec`] of its storage policy,
/// `has_room` asks it how many pushes are still guaranteed, and the heap policy
/// answers `usize::MAX`. The policy defaults to this build's
/// [`Profile`](crate::bounded::Profile), so `FinalStage` alone is the build's table.
pub struct FinalStage<P: Storage = Profile> {
    rows: BoundedVec<(u64, QosLevel), { caps::MAX_PENDING_FINALS }, P>,
    refused_requests: u32,
}

impl FinalStage<Static> {
    /// An empty table of the static policy. `const`, so a session slot that holds
    /// one can be a `static` whatever the build's profile is.
    pub const fn new_static() -> Self {
        Self {
            rows: BoundedVec::new_static(),
            refused_requests: 0,
        }
    }
}

impl FinalStage<Profile> {
    /// An empty table of this build's profile. `const`, so a session slot that holds
    /// one can be a `static`.
    pub const fn new() -> Self {
        Self {
            rows: BoundedVec::new(),
            refused_requests: 0,
        }
    }
}

impl<P: Storage> FinalStage<P> {
    /// How many requests were refused because no `Final` could be owed for them.
    pub fn refusals(&self) -> u32 {
        self.refused_requests
    }

    /// Drop every owed `Final`; the count is kept.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl<P: Storage> IntoIterator for FinalStage<P> {
    type Item = (u64, QosLevel);
    type IntoIter =
        <BoundedVec<(u64, QosLevel), { caps::MAX_PENDING_FINALS }, P> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

impl<P: Storage> Default for FinalStage<P> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
            refused_requests: 0,
        }
    }
}

impl<P: Storage> core::ops::Deref for FinalStage<P> {
    type Target = [(u64, QosLevel)];

    fn deref(&self) -> &[(u64, QosLevel)] {
        &self.rows
    }
}

impl<P: Storage> FinalStaging for FinalStage<P> {
    fn has_room(&self) -> bool {
        self.rows.free_slots() > 0
    }

    fn owe(&mut self, rid: u64, qos: QosLevel) {
        // Room was asked for before the request ran; a table that has none by
        // now is the caller's contract broken, and counted rather than dropped
        // in silence.
        if self.rows.push((rid, qos)).is_err() {
            self.refused_requests = self.refused_requests.saturating_add(1);
        }
    }

    fn refuse_request(&mut self) {
        self.refused_requests = self.refused_requests.saturating_add(1);
    }

    fn owed(&self) -> usize {
        self.rows.len()
    }

    fn drain_owed(&mut self) -> impl Iterator<Item = (u64, QosLevel)> {
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
    rows: &'a mut BoundedVec<(u64, QosLevel), { caps::MAX_PENDING_FINALS }, P>,
    at: usize,
}

impl<P: Storage> Iterator for OwedDrain<'_, P> {
    type Item = (u64, QosLevel);

    fn next(&mut self) -> Option<Self::Item> {
        let row = *self.rows.get(self.at)?;
        self.at += 1;
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
    /// capacity says there is no room and takes the refusal as counted; one that
    /// does not says there is room and takes the entry. The expectations are read
    /// from the policy's own contract, never from a feature gate.
    fn fill_to_n_then_refuse_at_n_plus_one<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        for rid in 0..N as u64 {
            assert!(finals.has_room(), "entry {rid} is within the capacity");
            finals.owe(rid, QosLevel::DEFAULT);
        }
        assert_eq!(finals.owed(), N);
        assert_eq!(finals.refusals(), 0, "nothing was refused up to N");

        if P::ENFORCES_CAPACITY {
            assert!(!finals.has_room(), "a full table has no room");
            finals.refuse_request();
            assert_eq!(finals.refusals(), 1, "the refused request is counted");
            finals.owe(N as u64, QosLevel::DEFAULT);
            assert_eq!(finals.owed(), N, "an entry past N is not taken");
            assert_eq!(
                finals.refusals(),
                2,
                "and is counted, not dropped in silence"
            );
        } else {
            assert!(finals.has_room(), "an advisory capacity always has room");
            finals.owe(N as u64, QosLevel::DEFAULT);
            assert_eq!(finals.owed(), N + 1);
            assert_eq!(finals.refusals(), 0, "the growable table refuses nothing");
        }
    }

    /// What is owed is taken in the order it was owed, and taking it empties the
    /// table without touching the count of what was refused.
    fn drain_takes_in_order_and_keeps_the_count<P: Storage>() {
        let mut finals: FinalStage<P> = FinalStage::default();
        for rid in 10..13u64 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        finals.refuse_request();
        let mut taken = [0u64; 3];
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
        for rid in 0..6u64 {
            finals.owe(rid, QosLevel::DEFAULT);
        }
        let first = finals.as_ptr();
        assert_eq!(finals.drain_owed().count(), 6);
        assert!(finals.is_empty());
        for rid in 0..6u64 {
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
    fn put_reply<'a>(rid: u64, keyexpr: &'a str, payload: &'a [u8]) -> ReplyParts<'a> {
        ReplyParts {
            rid,
            keyexpr,
            responder: None,
            qos: QosLevel::DEFAULT,
            kind: PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: None,
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        }
    }

    /// A reply whose bytes come from four places: key, payload, attachment, schema.
    fn fat_reply<'a>(rid: u64, payload: &'a [u8], attachment: &'a [u8]) -> ReplyParts<'a> {
        let key = "k";
        ReplyParts {
            rid,
            keyexpr: key,
            responder: None,
            qos: QosLevel::DEFAULT,
            kind: PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: None,
                timestamp: None,
                attachment: Some(attachment),
                source_info: None,
            },
        }
    }

    /// Fill the row table to `MAX_PENDING_REPLIES`, then stage one more: refused and
    /// counted where the capacity is hard, taken where it is not.
    fn rows_fill_to_n_then_refuse_at_n_plus_one<P: Storage>() {
        let mut stage: ReplyStage<P> = ReplyStage::default();
        for rid in 0..caps::MAX_PENDING_REPLIES as u64 {
            assert!(stage.stage_parts(put_reply(rid, "a/b", b"x")).is_ok());
        }
        assert_eq!(stage.staged(), caps::MAX_PENDING_REPLIES);
        assert_eq!(stage.refusals(), ReplyRefusals::default());

        let beyond = stage.stage_parts(put_reply(99, "a/b", b"x"));
        if P::ENFORCES_CAPACITY {
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

    /// A payload past `MAX_REPLY_PAYLOAD_BYTES` is a refusal on the fixed policy and
    /// leaves the stage as it was; the growable policy never had that bound.
    fn payload_past_the_bound<P: Storage>() {
        let big = [7u8; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
        let mut stage: ReplyStage<P> = ReplyStage::default();
        let outcome = stage.stage_parts(put_reply(1, "a", &big));
        if P::ENFORCES_CAPACITY {
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

    /// The arena has its own room, apart from the rows: replies fat enough to use up
    /// the declared bytes before the rows are used up are refused as `StagingFull`.
    fn arena_runs_out_before_the_rows<P: Storage>() {
        let payload = [1u8; caps::MAX_REPLY_PAYLOAD_BYTES];
        let attachment = [2u8; caps::MAX_REPLY_PAYLOAD_BYTES];
        let per_reply = 1 + payload.len() + attachment.len();
        let fits = caps::REPLY_STAGE_BYTES / per_reply;
        assert!(
            fits < caps::MAX_PENDING_REPLIES,
            "the fixture is fat enough to meet the arena first"
        );
        let mut stage: ReplyStage<P> = ReplyStage::default();
        for rid in 0..fits as u64 {
            assert_eq!(
                stage.stage_parts(fat_reply(rid, &payload, &attachment)),
                Ok(())
            );
        }
        let beyond = stage.stage_parts(fat_reply(99, &payload, &attachment));
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
        for rid in 0..3u64 {
            let payload = [rid as u8 + 1; 3];
            let parts = ReplyParts {
                rid,
                keyexpr: "home/temp",
                responder: Some((&zid, 5)),
                qos: QosLevel::DEFAULT,
                kind: PartsKind::Reply {
                    body: PartsBody::Put(&payload),
                    encoding: Some(EncodingParts {
                        packed_id: 7,
                        schema: Some("s"),
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

        let mut seen = 0u64;
        stage.drain_parts(|parts| {
            assert_eq!(parts.rid, seen, "in the order they were staged");
            assert_eq!(parts.keyexpr, "home/temp");
            assert_eq!(parts.responder, Some((&zid[..], 5)));
            let PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: Some(encoding),
                timestamp: Some(timestamp),
                attachment: Some(attachment),
                ..
            } = parts.kind
            else {
                panic!("the staged reply is a Put with every optional field");
            };
            assert_eq!(payload, &[seen as u8 + 1; 3]);
            assert_eq!((encoding.packed_id, encoding.schema), (7, Some("s")));
            assert_eq!((timestamp.time, timestamp.zid), (42, &zid[..]));
            assert_eq!(attachment, b"att");
            seen += 1;
        });
        assert_eq!(seen, 3);
        assert_eq!(stage.staged(), 0);
        assert_eq!(stage.bytes_held(), 0);
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
        arena_runs_out_before_the_rows,
        drain_parts_hands_out_what_was_staged,
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
