// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What is OWED to one peer by its queries: the replies a queryable has staged
//! and the `ResponseFinal`s that must follow them (fixed-memory step S9a).
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
//!   ([`ReplyError::StagingFull`], [`ReplyError::PayloadTooLarge`]) and is counted
//!   in [`ReplyRefusals`]. It is never truncated and never built on the heap in
//!   place of the table;
//! - a `Request` whose `Final` the finals table could not hold is refused BEFORE
//!   its queryables run ([`FinalStage::refuse_request`]) and counted: a reply that
//!   cannot be followed by its `Final` leaves the peer's `get` open until its own
//!   timeout, and running the handler for it would spend the application's work on
//!   an answer nobody can be told is complete.
//!
//! What this does NOT yet take off the heap is the reply record itself: a staged
//! [`QueryReply`] still owns its keyexpr and payload as a `String` and a `Vec`
//! (bounded in size now, by the same limits), and draining one into a wire
//! `Response` builds an owned message. Both belong to the codec's owned mirrors,
//! not to the table that holds the record.

#[cfg(not(feature = "bounded-heapless"))]
use alloc::vec::Vec;

#[cfg(feature = "bounded-heapless")]
use crate::bounded::BoundedVec;
#[cfg(feature = "bounded-heapless")]
use crate::caps;
use crate::query::QueryReply;
use crate::query_sink::ReplyError;
use crate::sample::QosLevel;

/// How a queryable's replies are staged, the same for both backings.
pub trait ReplyStaging {
    /// Stage one reply, or refuse it ([`ReplyError::StagingFull`]) and count it.
    fn stage(&mut self, reply: QueryReply) -> Result<(), ReplyError>;

    /// Whether a reply with `len` bytes of payload (0 for a reply with none) can
    /// be staged at all, counting the refusal when it cannot: no room
    /// ([`ReplyError::StagingFull`]) or a payload past the bound
    /// ([`ReplyError::PayloadTooLarge`]). Asked BEFORE the reply record is built,
    /// so a refusal costs nothing, not even the allocation of a record that is
    /// then dropped.
    fn admit_payload(&mut self, len: usize) -> Result<(), ReplyError>;

    /// How many replies are staged.
    fn staged(&self) -> usize;

    /// Take every staged reply, in the order they were staged.
    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply>;
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
    fn stage(&mut self, reply: QueryReply) -> Result<(), ReplyError> {
        self.push(reply);
        Ok(())
    }

    fn admit_payload(&mut self, _len: usize) -> Result<(), ReplyError> {
        Ok(())
    }

    fn staged(&self) -> usize {
        self.len()
    }

    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> {
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
    /// Replies the stage had no room for ([`caps::MAX_PENDING_REPLIES`] held).
    pub staging_full: u32,
    /// Replies whose payload was longer than [`caps::MAX_REPLY_PAYLOAD_BYTES`].
    pub payload_too_large: u32,
}

/// The replies a queryable has staged for one peer: [`caps::MAX_PENDING_REPLIES`]
/// rows, no more. A full stage refuses and counts; it does not grow.
#[cfg(feature = "bounded-heapless")]
pub struct ReplyStage {
    rows: BoundedVec<QueryReply, { caps::MAX_PENDING_REPLIES }>,
    refusals: ReplyRefusals,
}

#[cfg(feature = "bounded-heapless")]
impl ReplyStage {
    /// An empty stage. `const`, so a session slot that holds one can be a
    /// `static`.
    pub const fn new() -> Self {
        Self {
            rows: BoundedVec::new(),
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

    /// Drop every staged reply; the counts are kept.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

#[cfg(feature = "bounded-heapless")]
impl Default for ReplyStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bounded-heapless")]
impl core::ops::Deref for ReplyStage {
    type Target = [QueryReply];

    fn deref(&self) -> &[QueryReply] {
        &self.rows
    }
}

#[cfg(feature = "bounded-heapless")]
impl ReplyStaging for ReplyStage {
    fn stage(&mut self, reply: QueryReply) -> Result<(), ReplyError> {
        self.rows.push(reply).map_err(|_| {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            ReplyError::StagingFull
        })
    }

    fn admit_payload(&mut self, len: usize) -> Result<(), ReplyError> {
        if self.rows.free_slots() == 0 {
            self.refusals.staging_full = self.refusals.staging_full.saturating_add(1);
            return Err(ReplyError::StagingFull);
        }
        if len > caps::MAX_REPLY_PAYLOAD_BYTES {
            self.refusals.payload_too_large = self.refusals.payload_too_large.saturating_add(1);
            return Err(ReplyError::PayloadTooLarge);
        }
        Ok(())
    }

    fn staged(&self) -> usize {
        self.rows.len()
    }

    fn drain_staged(&mut self) -> impl Iterator<Item = QueryReply> {
        core::mem::take(&mut self.rows).into_iter()
    }
}

/// The `Final`s owed to one peer: [`caps::MAX_PENDING_FINALS`] rows, no more. A
/// full table refuses the REQUEST that would have needed one ([`Self::refusals`]
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
