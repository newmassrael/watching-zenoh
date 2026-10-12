// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What is OWED to one peer by its queries: the replies a queryable has staged
//! and the `ResponseFinal`s that must follow them (fixed-memory steps S9a and S9b).
//!
//! Both are written by a PEER, in the sense that matters: the peer's `Request`
//! makes the session stage them, and a peer that sends requests faster than the
//! session drains them decides how many there are. On the growable backing (the AP
//! profile) that is a `Vec` and nothing is refused, as it always was. On the fixed
//! backing (`bounded-heapless`) each is a table of declared capacity
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
//! handler. On the growable backing the stage turns that into the owned
//! [`crate::query::QueryReply`] it has always held. On the fixed backing it writes
//! the reply's bytes (keyexpr, payload, attachment, encoding schema) into ONE byte
//! arena the stage owns ([`caps::REPLY_STAGE_BYTES`], the room for
//! [`caps::MAX_PENDING_REPLIES`] replies of [`caps::MAX_REPLY_PAYLOAD_BYTES`] and a
//! keyexpr each) and a small fixed row that points into it, so staging a reply
//! allocates nothing. A reply that does not fit what is left of the arena is
//! refused as [`crate::query_sink::ReplyError::StagingFull`], counted, like a reply
//! the table has no row for.
//!
//! What this does NOT take off the heap is the DRAIN: handing a staged reply to the
//! wire builds the owned [`crate::query::QueryReply`] from its row, and that owned
//! record and the owned `Response` made from it are the codec's owned mirrors, not
//! the stage's. The allocation has moved from the moment the handler replies to the
//! moment the session sends, which is where the codec mirrors are replaced.

#[cfg(not(feature = "bounded-heapless"))]
use alloc::vec::Vec;

#[cfg(feature = "bounded-heapless")]
use crate::bounded::BoundedVec;
#[cfg(feature = "bounded-heapless")]
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
#[cfg(feature = "bounded-heapless")]
const ZID_BYTES: usize = 16;

/// How a queryable's replies are staged, the same for both backings.
pub trait ReplyStaging {
    /// Stage one reply, or refuse it and count it: a stage with no room
    /// ([`ReplyError::StagingFull`]) or a payload past the bound
    /// ([`ReplyError::PayloadTooLarge`]). Asked with the reply still BORROWED, so a
    /// refusal costs nothing, not even a record that is then dropped.
    fn stage_parts(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError>;

    /// How many replies are staged.
    fn staged(&self) -> usize;

    /// The `index`-th staged reply, in the order they were staged, as the owned
    /// record. The fixed backing builds it from its row (an allocation, which is
    /// the drain's, see the module documentation); the growable one clones.
    /// Heap profile only: the owned record is the owned mirror's.
    #[cfg(feature = "alloc")]
    fn nth(&self, index: usize) -> Option<QueryReply>;

    /// Take every staged reply, in the order they were staged. Whatever has not
    /// been taken when the iterator is dropped is dropped with it. Heap profile
    /// only, as [`Self::nth`].
    #[cfg(feature = "alloc")]
    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> + '_;
}

/// How the `ResponseFinal`s owed to a peer are staged, the same for both backings.
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
// The growable backing: what the AP has always had.
// ---------------------------------------------------------------------------

/// The replies a queryable has staged for one peer.
#[cfg(not(feature = "bounded-heapless"))]
pub type ReplyStage = Vec<QueryReply>;

/// The `Final`s owed to one peer, as `(rid, the query's QoS)`.
#[cfg(not(feature = "bounded-heapless"))]
pub type FinalStage = Vec<(u64, QosLevel)>;

#[cfg(not(feature = "bounded-heapless"))]
impl ReplyStaging for Vec<QueryReply> {
    fn stage_parts(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        self.push(QueryReply::from_parts(&parts));
        Ok(())
    }

    fn staged(&self) -> usize {
        self.len()
    }

    #[cfg(feature = "alloc")]
    fn nth(&self, index: usize) -> Option<QueryReply> {
        self.get(index).cloned()
    }

    #[cfg(feature = "alloc")]
    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> + '_ {
        self.drain(..)
    }
}

#[cfg(not(feature = "bounded-heapless"))]
impl FinalStaging for Vec<(u64, QosLevel)> {
    fn has_room(&self) -> bool {
        true
    }

    fn owe(&mut self, rid: u64, qos: QosLevel) {
        self.push((rid, qos));
    }

    fn refuse_request(&mut self) {}

    fn owed(&self) -> usize {
        self.len()
    }

    fn drain_owed(&mut self) -> impl Iterator<Item = (u64, QosLevel)> {
        self.drain(..)
    }
}

// ---------------------------------------------------------------------------
// The fixed backing: tables of declared capacity, refusing and counting.
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

/// Where the bytes of one staged reply's text or payload lie in the stage's arena.
#[cfg(feature = "bounded-heapless")]
#[derive(Debug, Clone, Copy)]
struct Span {
    start: u16,
    len: u16,
}

#[cfg(feature = "bounded-heapless")]
const _: () = assert!(
    caps::REPLY_STAGE_BYTES <= u16::MAX as usize,
    "a staged reply's bytes are addressed by 16-bit offsets"
);

/// A staged reply's encoding: the packed id and, if there is one, where its schema is.
#[cfg(feature = "bounded-heapless")]
type RowEncoding = Option<(u32, Option<Span>)>;

#[cfg(feature = "bounded-heapless")]
#[derive(Clone)]
enum RowPayload {
    Put(Span),
    Del,
    #[cfg(feature = "transport-shm")]
    Shared(crate::extshm::ShmSendHandle),
}

#[cfg(feature = "bounded-heapless")]
#[derive(Clone)]
enum RowKind {
    Reply {
        payload: RowPayload,
        encoding: RowEncoding,
        timestamp: Option<(u64, heapless::Vec<u8, ZID_BYTES>)>,
        attachment: Option<Span>,
        source_info: Option<SourceInfo>,
    },
    #[cfg(feature = "query-reply-err")]
    Err {
        encoding: RowEncoding,
        payload: Span,
    },
}

/// One staged reply: fixed fields, and spans into the stage's arena for its bytes.
#[cfg(feature = "bounded-heapless")]
#[derive(Clone)]
struct Row {
    rid: u64,
    qos: QosLevel,
    keyexpr: Span,
    responder: Option<(heapless::Vec<u8, ZID_BYTES>, u32)>,
    kind: RowKind,
}

/// The replies a queryable has staged for one peer: [`caps::MAX_PENDING_REPLIES`]
/// rows and [`caps::REPLY_STAGE_BYTES`] of bytes, no more. A full stage refuses and
/// counts; it does not grow.
#[cfg(feature = "bounded-heapless")]
pub struct ReplyStage {
    rows: heapless::Vec<Row, { caps::MAX_PENDING_REPLIES }>,
    arena: heapless::Vec<u8, { caps::REPLY_STAGE_BYTES }>,
    refusals: ReplyRefusals,
}

#[cfg(feature = "bounded-heapless")]
impl ReplyStage {
    /// An empty stage. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new() -> Self {
        Self {
            rows: heapless::Vec::new(),
            arena: heapless::Vec::new(),
            refusals: ReplyRefusals {
                staging_full: 0,
                payload_too_large: 0,
            },
        }
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
            self.arena.truncate(usize::from(row.keyexpr.start));
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

    fn bytes(&self, span: Span) -> &[u8] {
        let start = usize::from(span.start);
        self.arena
            .get(start..start + usize::from(span.len))
            .unwrap_or_default()
    }

    fn text(&self, span: Span) -> &str {
        core::str::from_utf8(self.bytes(span)).unwrap_or_default()
    }

    /// Copy `bytes` onto the end of the arena. Room was checked by the caller
    /// ([`Self::stage_parts`] sizes the whole reply first), so this cannot refuse.
    fn put(&mut self, bytes: &[u8]) -> Span {
        let start = self.arena.len();
        // Checked by `stage_parts` before anything is written: the whole reply fits.
        let _ = self.arena.extend_from_slice(bytes);
        Span {
            start: start as u16,
            len: bytes.len() as u16,
        }
    }

    fn put_encoding(&mut self, encoding: Option<(u32, Option<&str>)>) -> RowEncoding {
        encoding.map(|(id, schema)| (id, schema.map(|schema| self.put(schema.as_bytes()))))
    }

    /// A row's encoding as the id and the schema text read out of the arena.
    fn encoding_of(&self, encoding: &RowEncoding) -> Option<(u32, Option<&str>)> {
        encoding
            .as_ref()
            .map(|(packed_id, schema)| (*packed_id, schema.map(|schema| self.text(schema))))
    }

    /// A row as the borrowed description it was staged from. Nothing is copied:
    /// every slice points into the arena or the row, so this is what a writer that
    /// puts the reply on the wire reads, and what the owned record is built from.
    fn row_parts<'a>(&'a self, row: &'a Row) -> ReplyParts<'a> {
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
            responder: row
                .responder
                .as_ref()
                .map(|(zid, eid)| (zid.as_slice(), *eid)),
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
    fn row_to_reply(&self, row: &Row) -> QueryReply {
        QueryReply::from_parts(&self.row_parts(row))
    }
}

/// The staged replies of a stage taken BY VALUE, in order, as owned records.
#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
pub struct StagedIntoIter {
    stage: ReplyStage,
    next: usize,
}

#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
impl Iterator for StagedIntoIter {
    type Item = QueryReply;

    fn next(&mut self) -> Option<QueryReply> {
        let reply = self.stage.nth(self.next)?;
        self.next += 1;
        Some(reply)
    }
}

#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
impl IntoIterator for ReplyStage {
    type Item = QueryReply;
    type IntoIter = StagedIntoIter;

    fn into_iter(self) -> StagedIntoIter {
        StagedIntoIter {
            stage: self,
            next: 0,
        }
    }
}

/// The staged replies of a stage taken IN PLACE: what [`ReplyStaging::drain_staged`]
/// hands back. The stage is emptied when this is dropped, however much was taken.
#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
struct StagedDrain<'a> {
    stage: &'a mut ReplyStage,
    next: usize,
}

#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
impl Iterator for StagedDrain<'_> {
    type Item = QueryReply;

    fn next(&mut self) -> Option<QueryReply> {
        let reply = self.stage.nth(self.next)?;
        self.next += 1;
        Some(reply)
    }
}

#[cfg(all(feature = "bounded-heapless", feature = "alloc"))]
impl Drop for StagedDrain<'_> {
    fn drop(&mut self) {
        self.stage.clear();
    }
}

#[cfg(feature = "bounded-heapless")]
impl Default for ReplyStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bounded-heapless")]
impl ReplyStaging for ReplyStage {
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
        if self.rows.is_full() {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }
        let identity_too_long = parts
            .responder
            .is_some_and(|(zid, _)| zid.len() > ZID_BYTES)
            || matches!(
                &parts.kind,
                PartsKind::Reply { timestamp: Some(ts), .. } if ts.zid.len() > ZID_BYTES
            );
        if payload_len > caps::MAX_REPLY_PAYLOAD_BYTES
            || attachment_len > caps::MAX_REPLY_PAYLOAD_BYTES
            || identity_too_long
        {
            self.refusals.payload_too_large = self.refusals.payload_too_large.saturating_add(1);
            return Err(ReplyError::PayloadTooLarge);
        }
        let need = parts.keyexpr.len() + payload_len + attachment_len + schema_len;
        if self.arena.len() + need > caps::REPLY_STAGE_BYTES {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }

        // Everything fits: write it. The order is fixed (key first) because `pop`
        // gives the arena back from where the last row's key starts.
        let keyexpr = self.put(parts.keyexpr.as_bytes());
        let responder = parts.responder.map(|(zid, eid)| {
            let mut copy = heapless::Vec::new();
            // The length was checked above.
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
                    let mut zid = heapless::Vec::new();
                    // The length was checked above.
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
}

/// The `Final`s owed to one peer: [`caps::MAX_PENDING_FINALS`] rows, no more. A full
/// table refuses the REQUEST that would have needed one ([`Self::refusals`]
/// counts them) and does not grow.
#[cfg(feature = "bounded-heapless")]
pub struct FinalStage {
    rows: BoundedVec<(u64, QosLevel), { caps::MAX_PENDING_FINALS }>,
    refused_requests: u32,
}

#[cfg(feature = "bounded-heapless")]
impl FinalStage {
    /// An empty table. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new() -> Self {
        Self {
            rows: BoundedVec::new(),
            refused_requests: 0,
        }
    }

    /// How many requests were refused because no `Final` could be owed for them.
    pub fn refusals(&self) -> u32 {
        self.refused_requests
    }

    /// Drop every owed `Final`; the count is kept.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

#[cfg(feature = "bounded-heapless")]
impl IntoIterator for FinalStage {
    type Item = (u64, QosLevel);
    type IntoIter =
        <BoundedVec<(u64, QosLevel), { caps::MAX_PENDING_FINALS }> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

#[cfg(feature = "bounded-heapless")]
impl Default for FinalStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bounded-heapless")]
impl core::ops::Deref for FinalStage {
    type Target = [(u64, QosLevel)];

    fn deref(&self) -> &[(u64, QosLevel)] {
        &self.rows
    }
}

#[cfg(feature = "bounded-heapless")]
impl FinalStaging for FinalStage {
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
        core::mem::take(&mut self.rows).into_iter()
    }
}
