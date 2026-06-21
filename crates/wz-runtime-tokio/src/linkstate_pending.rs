// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Pending-query return table (P4 routing, query-routing atom 3) — the
//! per-outbound-face map that lets a routed Query's `Response` / `ResponseFinal`
//! route BACK to the querier across the mesh.
//!
//! The wz analogue of zenoh's per-`FaceState` `pending_queries:
//! HashMap<RequestId, (Arc<Query>, CancellationToken)>` where `Query { src_face,
//! src_qid }` (`net/routing/dispatcher/face.rs:76` + `queries.rs:50-53`). When a
//! relay forwards a Query out a face it ALLOCATES a fresh local query id on THAT
//! face ([`allocate`](PendingQueries::allocate), bumping a per-face `next_qid`,
//! zenoh `insert_pending_query`) and records the RETURN mapping `out qid ->
//! (inbound face, inbound rid)`. A `Response` arriving on that face carrying that
//! qid is then routed back: the relay rewrites the response's `request_id` to the
//! recorded inbound rid and forwards it to the recorded inbound face — the
//! reverse of the forward hop, reconstructed hop-by-hop from this table (NOT from
//! the topology tree; the forward path is the spanning tree, the return path is
//! this pending state).
//!
//! Why remap the qid per hop (not carry the querier's rid verbatim): the qid is
//! LOCAL to a (relay, face) pair. Two queriers can pick the same rid; without a
//! per-face-unique local qid their pending entries would collide on a shared
//! relay face and a Response could route to the wrong querier. zenoh remaps at
//! every hop for exactly this reason; wz mirrors it.
//!
//! Lifecycle: [`allocate`](PendingQueries::allocate) on forward (the Query out a
//! face) -> [`peek`](PendingQueries::peek) on each `Response` (the entry stays
//! alive for further replies) -> [`take`](PendingQueries::take) on the
//! `ResponseFinal` (which closes the query and frees the entry). A departed
//! face's entries are dropped whole by
//! [`remove_face`](PendingQueries::remove_face) (the forwarder's `deregister`).
//! NOT yet modelled (a tracked atom-3 deferral): zenoh's per-query TIMEOUT
//! (`QueryCleanup`) that frees an entry whose `ResponseFinal` never arrives while
//! the face stays up — face-down purge is the only GC here so far.

use std::collections::HashMap;

use crate::accept_loop::FaceId;

/// The pending-query return table — one [`FacePending`] per outbound face.
#[derive(Debug, Default)]
pub struct PendingQueries {
    /// out face -> that face's local-qid allocator + live return mappings. A
    /// face is present only while it holds at least one pending query: the last
    /// [`take`](Self::take) (or a [`remove_face`](Self::remove_face)) drops it.
    by_face: HashMap<FaceId, FacePending>,
}

/// One outbound face's pending state: a monotonic local-qid counter + the live
/// `local qid -> (inbound face, inbound rid)` return mappings.
#[derive(Debug, Default)]
struct FacePending {
    /// The next local query id to hand out on this face (zenoh `next_qid`).
    /// Monotonic per face; the first allocation is `1` (the pre-increment leaves
    /// `0` unused, a harmless reserved-looking sentinel).
    next_qid: u64,
    /// local qid -> the return target `(inbound face, inbound rid)` to rewrite a
    /// Response/ResponseFinal carrying that qid back toward.
    returns: HashMap<u64, (FaceId, u64)>,
}

impl PendingQueries {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh local query id on `out_face` for a Query being forwarded
    /// there, recording the return mapping back to `(src_face, src_rid)` (the
    /// face the Query arrived on + its inbound rid). Returns the new qid to stamp
    /// on the outbound Request. Mirrors zenoh `insert_pending_query`'s
    /// `next_qid.wrapping_add(1)` + `pending_queries.insert(qid, ..)`.
    pub fn allocate(&mut self, out_face: FaceId, src_face: FaceId, src_rid: u64) -> u64 {
        let fp = self.by_face.entry(out_face).or_default();
        fp.next_qid = fp.next_qid.wrapping_add(1);
        let qid = fp.next_qid;
        fp.returns.insert(qid, (src_face, src_rid));
        qid
    }

    /// Look up the return target for a `Response` carrying `qid` on `out_face`,
    /// WITHOUT removing it — a query may yield several `Response`s before its
    /// `ResponseFinal`, so the entry stays alive (zenoh `route_send_response`
    /// reads `pending_queries.get`, it does not remove). `None` for an unknown
    /// qid (no such pending query — already finalized, timed out, or never sent).
    pub fn peek(&self, out_face: FaceId, qid: u64) -> Option<(FaceId, u64)> {
        self.by_face
            .get(&out_face)
            .and_then(|fp| fp.returns.get(&qid).copied())
    }

    /// Take (remove) the return target for a `ResponseFinal` carrying `qid` on
    /// `out_face` — the final closes the query and frees the entry (zenoh
    /// `route_send_response_final` removes the pending entry). An emptied face is
    /// pruned. `None` for an unknown qid (already closed / never sent).
    pub fn take(&mut self, out_face: FaceId, qid: u64) -> Option<(FaceId, u64)> {
        let fp = self.by_face.get_mut(&out_face)?;
        let entry = fp.returns.remove(&qid);
        if fp.returns.is_empty() {
            self.by_face.remove(&out_face);
        }
        entry
    }

    /// Drop ALL pending queries on a departed `face` — the forwarder's
    /// `deregister` calls this when a face goes down, so a Response can never be
    /// routed toward (or expected back from) a dead face. Mirrors the face-down
    /// teardown of zenoh's per-face `pending_queries`. (Entries on OTHER faces
    /// that pointed back to this one as their inbound target are left to
    /// self-heal — a Response toward the dead face simply drops at send — and to
    /// the tracked per-query timeout; only the entries keyed by this out face are
    /// dropped here.)
    pub fn remove_face(&mut self, face: &FaceId) {
        self.by_face.remove(face);
    }

    /// Total live pending queries across every face — the work witness a test (or
    /// a future timeout sweep) reads.
    pub fn len(&self) -> usize {
        self.by_face.values().map(|fp| fp.returns.len()).sum()
    }

    /// Whether the table holds no pending queries.
    pub fn is_empty(&self) -> bool {
        self.by_face.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    #[test]
    fn allocate_hands_out_monotonic_per_face_qids_from_one() {
        let mut pq = PendingQueries::new();
        // First allocation on a face is qid 1 (pre-increment leaves 0 unused).
        assert_eq!(pq.allocate(face(10), face(0), 100), 1);
        assert_eq!(pq.allocate(face(10), face(0), 101), 2);
        // A DIFFERENT out face has its own independent counter.
        assert_eq!(pq.allocate(face(11), face(0), 200), 1);
        assert_eq!(pq.len(), 3);
    }

    #[test]
    fn peek_returns_the_mapping_without_removing() {
        let mut pq = PendingQueries::new();
        let qid = pq.allocate(face(10), face(3), 99);
        // Peek twice: the entry survives (a query may yield several Responses).
        assert_eq!(pq.peek(face(10), qid), Some((face(3), 99)));
        assert_eq!(pq.peek(face(10), qid), Some((face(3), 99)));
        assert_eq!(pq.len(), 1, "peek does not consume");
        // A qid on the wrong face, or an unknown qid, has no mapping.
        assert_eq!(pq.peek(face(11), qid), None);
        assert_eq!(pq.peek(face(10), 999), None);
    }

    #[test]
    fn take_removes_the_mapping_and_prunes_the_emptied_face() {
        let mut pq = PendingQueries::new();
        let q1 = pq.allocate(face(10), face(3), 99);
        let q2 = pq.allocate(face(10), face(4), 77);
        // Take q1: returns its mapping, leaves q2.
        assert_eq!(pq.take(face(10), q1), Some((face(3), 99)));
        assert_eq!(pq.peek(face(10), q1), None, "taken entry is gone");
        assert_eq!(pq.peek(face(10), q2), Some((face(4), 77)), "q2 survives");
        // A second take of the same qid is a no-op.
        assert_eq!(pq.take(face(10), q1), None);
        // Taking the last entry prunes the face.
        assert_eq!(pq.take(face(10), q2), Some((face(4), 77)));
        assert!(pq.is_empty(), "the emptied face is pruned");
    }

    #[test]
    fn remove_face_drops_every_pending_on_that_face_only() {
        let mut pq = PendingQueries::new();
        pq.allocate(face(10), face(3), 1);
        pq.allocate(face(10), face(3), 2);
        pq.allocate(face(11), face(4), 1);
        pq.remove_face(&face(10));
        assert_eq!(pq.peek(face(10), 1), None, "face 10's entries dropped");
        assert_eq!(pq.peek(face(10), 2), None);
        assert_eq!(
            pq.peek(face(11), 1),
            Some((face(4), 1)),
            "face 11 untouched"
        );
        // Removing an absent face is a no-op.
        pq.remove_face(&face(99));
        assert_eq!(pq.len(), 1);
    }
}
