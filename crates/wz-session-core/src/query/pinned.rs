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
//!
//! A query the copying receive decoded is read off its owned Request the same way
//! (`QueryPeer::pin_request`), what the Request does not hold itself (a key composed past the
//! bounded buffer, a value read out of shared memory, the shared ranges of the frame) kept in a
//! [`QueryRoom`] of the read's frame.
//!
//! [`PinnedQuery`]: crate::query::pinned::PinnedQuery
//! [`QueryRoom`]: crate::query::pinned::QueryRoom

use crate::keyexpr_match::KeyFacts;
use crate::query_mode::QueryTarget;
use crate::query_sink::{BorrowedQuery, ProvenQuery, QueryView};
use crate::sample::{QosLevel, SourceInfo};
use crate::wire_id::RequestId;

use super::QueryableRef;

#[cfg(feature = "alloc")]
use super::{
    project_owned_query, request_past_bounds, DispatchOutcome, MappingSpaces, QueryPeer,
    RequestOwned, RequestOwnedVariant,
};
#[cfg(feature = "alloc")]
use crate::bounded::Storage;
#[cfg(feature = "alloc")]
use crate::reply_stage::{FinalStage, FinalStaging};
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::{
    resolve_wireexpr_in, resolve_wireexpr_into, KeyexprBuf, KeyexprPastBound,
};

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
    /// The value as shareable bytes, which `payload` reads: out of shared memory, or the range
    /// of a frame the link lent.
    #[cfg(feature = "alloc")]
    pub(super) value: Option<&'q crate::link::RxBytes>,
    /// The attachment as shareable bytes, which `attachment` reads.
    #[cfg(feature = "alloc")]
    pub(super) attachment_shared: Option<&'q crate::link::RxBytes>,
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
        // A value or an attachment held as shareable bytes is lent as such, and an instrumented
        // query is shown its stack beside the rest, as the fan-out shows them.
        #[cfg(feature = "alloc")]
        {
            #[cfg(feature = "pubsub-ts-stack")]
            let carries_stack = self.ts_stack.is_some();
            #[cfg(not(feature = "pubsub-ts-stack"))]
            let carries_stack = false;
            if self.value.is_some() || self.attachment_shared.is_some() || carries_stack {
                let shared = crate::query_sink::SharedQuery {
                    base,
                    value: self.value,
                    attachment: self.attachment_shared,
                    #[cfg(feature = "pubsub-ts-stack")]
                    ts_stack: self.ts_stack.as_ref(),
                };
                return f(&ProvenQuery {
                    inner: &shared,
                    peer: self.requester,
                    encoding: self.lent_encoding,
                });
            }
        }
        f(&ProvenQuery {
            inner: &base,
            peer: self.requester,
            encoding: self.lent_encoding,
        })
    }
}

/// What a query read off an owned Request keeps in the read's frame that the Request does not
/// hold itself: the key where an alias and a suffix join (past the bounded buffer, as a string of
/// its own), the value read out of shared memory or lent as a range of the frame, and the
/// attachment as such a range. One room serves one query.
#[cfg(feature = "alloc")]
#[derive(Default)]
pub struct QueryRoom {
    composed: KeyexprBuf,
    long: Option<alloc::string::String>,
    value: Option<(crate::sample::EncodingHint, crate::link::RxBytes)>,
    attachment: Option<crate::link::RxBytes>,
}

/// The owned record of the Request `record` lends where the lent form does not represent it
/// (`QueryPeer::pin_request_in_place` refused it with `OwedToProjection`), for a read that pins
/// it with [`QueryPeer::pin_request`]: the record the copying receive decodes for it. `None` for
/// a record that is no Request and one the codec refuses, and in a build that lends only, which
/// refuses no Request to the projection.
#[cfg(feature = "alloc")]
pub fn project_request(record: &crate::driver_loop::InPlaceRecord<'_, '_>) -> Option<RequestOwned> {
    #[cfg(not(feature = "rx-lent-only"))]
    {
        super::in_place::project_request(record.request()?)
    }
    #[cfg(feature = "rx-lent-only")]
    {
        let _ = record;
        None
    }
}

#[cfg(feature = "alloc")]
impl QueryPeer {
    /// Read the query of `request`, which the copying receive decoded, for a walk that hands it to
    /// each queryable it reaches with no lock held ([`PinnedQuery`]), by the rules of its dispatch
    /// (`Self::dispatch_messages`): a value that arrived in shared memory read and acknowledged
    /// first, the key resolved through `peer_keyexpr_table` and borrowed where it lies, and what
    /// the Request does not hold kept in `room`, an empty one. The query so borrows the peer's
    /// space: a caller that walks with the session's lock let go of keeps the peer's tables
    /// unwritten while it holds the query. `None`, with what the Request owes staged in
    /// `pending_final_rids` as its dispatch stages it, for a record that is no Query, a value
    /// that cannot be read (owed nothing), one the table has no room to owe a Final for, one
    /// whose key does not resolve and one past the bounds the face holds queries to. The query
    /// handed back owes its Final once the walk is over, which stages nothing here.
    pub fn pin_request<'q, PS: Storage, OS: Storage, S: Storage>(
        &mut self,
        request: &'q RequestOwned,
        peer_keyexpr_table: impl Into<MappingSpaces<'q, PS, OS>>,
        room: &'q mut QueryRoom,
        pending_final_rids: &mut FinalStage<S>,
    ) -> Option<PinnedQuery<'q>> {
        let RequestOwnedVariant::CodecZenohQuery(query) = &request.body else {
            return None;
        };
        if !pending_final_rids.has_room() {
            pending_final_rids.refuse_request();
            return None;
        }
        let qos = crate::declare_ext_qos::read_request_qos(request);
        // Read and acknowledged before the query is routed, and a value that cannot be read
        // drops the whole query with no Final, as its dispatch does.
        #[cfg(feature = "transport-shm")]
        let unswapped = match self.unswap_query_value(query, qos.priority().wire_byte() as usize) {
            Ok(value) => value,
            Err(()) => return None,
        };
        #[cfg(not(feature = "transport-shm"))]
        let unswapped = None;
        let spaces: MappingSpaces<'q, PS, OS> = peer_keyexpr_table.into();
        let QueryRoom {
            composed,
            long,
            value,
            attachment,
        } = room;
        let keyexpr = match resolve_wireexpr_into(&request.keyexpr.body, spaces, composed) {
            Ok(keyexpr) => keyexpr,
            // Past the bounded buffer the key is still routed, composed as a string of its own.
            Err(KeyexprPastBound) => {
                *long = resolve_wireexpr_in(&request.keyexpr.body, spaces);
                long.as_deref()
            }
        };
        let Some(keyexpr) = keyexpr else {
            if DispatchOutcome::UNRESOLVED.owes_final(self.answers_unresolved_queries()) {
                pending_final_rids.owe(request.rid, qos);
            }
            return None;
        };
        #[cfg(feature = "pubsub-ts-stack")]
        let ts_stack = crate::ts_stack::read_ts_stack(
            crate::held_list::HeldList::entries(&request.extensions)
                .unwrap_or(&[])
                .iter(),
        );
        let projection = project_owned_query(
            query,
            unswapped,
            #[cfg(feature = "pubsub-ts-stack")]
            None,
        );
        let (max_parameters, max_attachment) = self.query_size_bounds();
        if request_past_bounds(
            projection.parameters,
            projection.attachment,
            max_parameters,
            max_attachment,
        ) {
            self.oversize_refused = self.oversize_refused.saturating_add(1);
            pending_final_rids.owe(request.rid, qos);
            return None;
        }
        *value = projection.shared_value;
        *attachment = projection.attachment_shared;
        let value: &'q Option<_> = value;
        let attachment: &'q Option<_> = attachment;
        // The value's bytes and encoding as the fan-out reads them (`fire_query`): the shareable
        // value's where there is one, the plain one's where the Request holds it.
        #[cfg(feature = "query-value")]
        let (payload, encoding, lent_encoding) = match (value, projection.plain_value) {
            (Some((hint, bytes)), _) => (Some(bytes.as_slice()), Some(hint.clone()), None),
            (None, Some(parts)) => (
                Some(parts.payload),
                Some(crate::sample::EncodingHint {
                    packed_id: parts.packed_id,
                    schema: parts.schema.map(<[u8]>::to_vec),
                }),
                Some((parts.packed_id, parts.schema)),
            ),
            (None, None) => (None, None, None),
        };
        #[cfg(not(feature = "query-value"))]
        let (payload, encoding, lent_encoding) = {
            let _ = projection.plain_value;
            (None, None, None)
        };
        Some(PinnedQuery {
            rid: request.rid,
            target: crate::request_routing_context::read_request_target(request),
            qos,
            requester: self.requester(),
            keyexpr,
            facts: crate::keyexpr_match::KeyFacts::of(keyexpr),
            parameters: projection.parameters,
            attachment: projection.attachment,
            source_info: projection.source_info,
            payload,
            encoding,
            lent_encoding,
            value: value.as_ref().map(|(_, bytes)| bytes),
            attachment_shared: attachment.as_ref(),
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack,
            next: 0,
        })
    }
}
