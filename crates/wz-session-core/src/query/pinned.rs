// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A peer's query handed to the session's queryables one at a time, each call made with no lock of
//! the session held.
//!
//! A session whose read steps its one link itself hands each record out as it reads it. A query is
//! read off its Request under the session's lock into a [`PinnedQuery`] in the read's own frame
//! (`QueryPeer::pin_request_in_place`), nothing of it copied: its key is the frame's, the peer's
//! literal, or composed in a buffer of the read's frame where an alias and a suffix join, and every
//! other part lies in the frame, which the read holds throughout. A read that walks with the lock
//! let go of keeps the peer's tables unwritten for as long as it holds the query. The
//! queryables it reaches are found one at a time from the place after the last
//! (`SessionTables::next_queryable_reached`), each called with the lock let go of, so a callback
//! finds the session free and what the queryables before its own did. The match and the view are
//! those of the fan-out a dispatch makes under the lock (`fire_query`), so a queryable is shown the
//! same query whichever way it reaches it.

use crate::keyexpr_match::KeyFacts;
use crate::query_mode::QueryTarget;
use crate::query_sink::{BorrowedQuery, ProvenQuery, QueryView};
use crate::sample::{QosLevel, SourceInfo};
use crate::wire_id::RequestId;

use super::QueryableRef;

/// A peer's query, read off its Request for a walk that hands it to each queryable it reaches, one
/// at a time: what each is shown of it, held in the walk's frame, and the place in the table after
/// the last queryable the walk reached.
pub struct PinnedQuery<'q> {
    pub(super) rid: RequestId,
    pub(super) target: Option<QueryTarget>,
    pub(super) qos: QosLevel,
    /// The zid the link's key proved, as each queryable is shown it (decision D12).
    pub(super) requester: Option<[u8; 16]>,
    /// The key, where it lies: the frame, the peer's literal, or the walk's buffer.
    pub(super) keyexpr: &'q str,
    pub(super) facts: KeyFacts,
    pub(super) parameters: Option<&'q [u8]>,
    pub(super) attachment: Option<&'q [u8]>,
    pub(super) source_info: Option<SourceInfo>,
    #[cfg(feature = "alloc")]
    pub(super) payload: Option<&'q [u8]>,
    /// The value's encoding as the hint a view hands out.
    #[cfg(feature = "alloc")]
    pub(super) encoding: Option<crate::sample::EncodingHint>,
    /// The value's encoding as its parts, where the frame holds them.
    pub(super) lent_encoding: Option<(u32, Option<&'q [u8]>)>,
    /// The timestamp stack the Request carried, decoded off its chain.
    #[cfg(all(feature = "alloc", feature = "pubsub-ts-stack"))]
    pub(super) ts_stack: Option<crate::ts_stack::TsStack>,
    /// The place in the queryables' table the walk goes on from.
    pub(super) next: usize,
}

impl PinnedQuery<'_> {
    /// The query's request id.
    pub fn rid(&self) -> RequestId {
        self.rid
    }

    /// The query's QoS, which its replies and its Final carry.
    pub fn qos(&self) -> QosLevel {
        self.qos
    }

    /// The place in the queryables' table the walk goes on from.
    pub(crate) fn reached_from(&self) -> usize {
        self.next
    }

    /// Whether the query reaches `row`, by the rule of every fan-out of a peer's query.
    pub(crate) fn reaches(&self, row: QueryableRef<'_>) -> bool {
        row.reaches(self.keyexpr, self.facts, true, self.target)
    }

    /// The walk reached the queryable at `place`, and goes on after it.
    pub(crate) fn passed(&mut self, place: usize) {
        self.next = place.saturating_add(1);
    }

    /// Call `f` with the query as each queryable it reaches is shown it: the view the fan-out of
    /// a dispatch builds for each row (`fire_query`).
    pub fn hand<R>(&self, f: impl FnOnce(&dyn QueryView) -> R) -> R {
        let base = BorrowedQuery {
            keyexpr: self.keyexpr,
            parameters: self.parameters,
            attachment: self.attachment,
            source_info: self.source_info.as_ref(),
            #[cfg(feature = "alloc")]
            payload: self.payload,
            #[cfg(not(feature = "alloc"))]
            payload: None,
            #[cfg(feature = "alloc")]
            encoding: self.encoding.as_ref(),
            rid: self.rid,
            is_local: false,
            qos: self.qos,
        };
        // An instrumented query is shown its stack beside the rest, as the fan-out shows it.
        #[cfg(all(feature = "alloc", feature = "pubsub-ts-stack"))]
        if self.ts_stack.is_some() {
            let shared = crate::query_sink::SharedQuery {
                base,
                value: None,
                attachment: None,
                ts_stack: self.ts_stack.as_ref(),
            };
            return f(&ProvenQuery {
                inner: &shared,
                peer: self.requester,
                encoding: self.lent_encoding,
            });
        }
        f(&ProvenQuery {
            inner: &base,
            peer: self.requester,
            encoding: self.lent_encoding,
        })
    }
}
