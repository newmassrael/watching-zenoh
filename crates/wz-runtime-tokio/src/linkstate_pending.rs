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
//! zenoh `insert_pending_query`) and records the RETURN mapping — `out qid` ->
//! the query's shared [`QueryFan`]. A `Response` arriving on that face carrying
//! that qid is then routed back: the relay rewrites the response's `request_id`
//! to the inbound rid recorded on the query's shared [`QueryFan`] and forwards it
//! to the recorded inbound face — the reverse of the forward hop, reconstructed
//! hop-by-hop from this table (NOT from the topology tree; the forward path is
//! the spanning tree, the return path is this pending state).
//!
//! ## Fan aggregation (the last-out final gate)
//!
//! One logical Query may fan to SEVERAL queryables (`QueryTarget::All` /
//! `AllComplete`, or BestMatching's fall-back-to-All): each outbound branch gets
//! its OWN per-face qid + pending entry, but the querier must receive exactly ONE
//! closing `ResponseFinal` — after the LAST branch finalizes, else the fastest
//! branch's final would terminate the querier's `get()` while the other branches'
//! replies are still in flight. zenoh expresses this with ONE `Arc<Query>` cloned
//! into every branch's pending entry (`compute_final_route`,
//! `dispatcher/queries.rs:221/236`) and an `Arc::into_inner` gate in
//! `finalize_pending_query` (`queries.rs:667-681`): only the branch whose removal
//! drops the LAST strong reference propagates the upstream final. wz mirrors that
//! exactly with an [`Rc<QueryFan>`] shared by every branch of the fan (the
//! single-task `Rc` analog of the `Arc`): [`take`](PendingQueries::take) /
//! [`expired`](PendingQueries::expired) report `last == true` only when the
//! removed entry held the fan's final reference, and
//! [`remove_face`](PendingQueries::remove_face) returns the fans a face-down
//! DRAINED (zenoh `finalize_pending_queries`) so the caller can synthesize their
//! closing finals. The caller forwards every `Response` unconditionally and the
//! `ResponseFinal` only on `last`.
//!
//! Why remap the qid per hop (not carry the querier's rid verbatim): the qid is
//! LOCAL to a (relay, face) pair. Two queriers can pick the same rid; without a
//! per-face-unique local qid their pending entries would collide on a shared
//! relay face and a Response could route to the wrong querier. zenoh remaps at
//! every hop for exactly this reason; wz mirrors it.
//!
//! Lifecycle: [`allocate`](PendingQueries::allocate) on forward (the Query out a
//! face, recording a per-entry `deadline`) -> [`peek`](PendingQueries::peek) on
//! each `Response` (the entry stays alive for further replies) ->
//! [`take`](PendingQueries::take) on the `ResponseFinal` (which closes the BRANCH
//! and frees the entry; the QUERY closes when the last branch does). Two GC paths
//! reclaim an entry whose `ResponseFinal` never arrives:
//! [`remove_face`](PendingQueries::remove_face) drops a departed face's entries
//! whole (the forwarder's `deregister`), and
//! [`expired`](PendingQueries::expired) sweeps entries past their `deadline` (the
//! forwarder's `tick`, the wz form of zenoh's per-query `QueryCleanup` timeout,
//! `dispatcher/queries.rs:271-349`) so a queryable that crashes without a final
//! on a STILL-UP face cannot leak the entry forever.

use std::collections::HashMap;
use std::rc::Rc;
use std::time::Instant;

use crate::accept_loop::FaceId;

/// One logical query's shared RETURN TARGET — the querier's inbound face + the
/// upstream rid every branch of the fan rewrites its replies back to. The wz
/// analogue of zenoh's `Query { src_face, src_qid }` (`dispatcher/queries.rs:50`),
/// shared across the fan's pending entries via `Rc` exactly as zenoh clones one
/// `Arc<Query>` per branch: ONCE THE CALLER RELEASES ITS CONSTRUCTION HANDLE the
/// `Rc` strong count is the live-branch count, and the entry whose removal drops
/// the final reference is the fan's LAST branch (the `Arc::into_inner` last-out
/// gate, `queries.rs:670`). Construct one per routed Query ([`QueryFan::new`]),
/// pass it to every [`allocate`](PendingQueries::allocate) of that Query's fan,
/// and DROP the handle when the routing call returns — a cached handle would
/// hold a phantom reference and silently suppress `last` forever (the
/// allocation-scope contract both forwarders follow and the
/// `a_dropped_construction_handle_leaves_the_last_out_gate_intact` test pins).
#[derive(Debug)]
pub struct QueryFan {
    /// The inbound face the forward Query arrived on — where replies route back.
    inbound: FaceId,
    /// The upstream rid to rewrite each reply's `request_id` back to.
    inbound_rid: u64,
}

impl QueryFan {
    /// A new fan target for one routed Query — `Rc`-wrapped so each branch's
    /// [`allocate`](PendingQueries::allocate) shares it. The caller must DROP
    /// this handle when its routing call returns (see the type docs — a cached
    /// handle suppresses the last-out gate).
    pub fn new(inbound: FaceId, inbound_rid: u64) -> Rc<Self> {
        Rc::new(Self {
            inbound,
            inbound_rid,
        })
    }
}

/// The pending-query return table — one [`FacePending`] per outbound face.
#[derive(Debug, Default)]
pub struct PendingQueries {
    /// out face -> that face's local-qid allocator + live return mappings. A
    /// face's slot lives from its first [`allocate`](Self::allocate) until
    /// [`remove_face`](Self::remove_face) (the face-down teardown) — NOT merely
    /// until its `returns` drain: the `next_qid` allocator is FACE-LIFETIME
    /// (zenoh's per-face `next_qid`, `dispatcher/face.rs:75`), so a qid handed
    /// out for a new query can never collide with a qid still riding a stale
    /// in-flight reply of a reaped/finalized earlier query on the same face.
    by_face: HashMap<FaceId, FacePending>,
}

/// One outbound face's pending state: a monotonic local-qid counter + the live
/// `local qid -> ` return mappings.
#[derive(Debug, Default)]
struct FacePending {
    /// The next local query id to hand out on this face (zenoh `next_qid`,
    /// `dispatcher/face.rs:75` — a FACE-LIFETIME field). Monotonic across the
    /// face's whole life, surviving `returns` drains; the first allocation is
    /// `1` (the pre-increment leaves `0` unused, a harmless reserved-looking
    /// sentinel). Resetting it on a drain would let a stale in-flight reply
    /// (e.g. from a queryable still answering a timed-out query) alias the NEXT
    /// query's qid and misroute into — or prematurely close — that query.
    next_qid: u64,
    /// local qid -> the return mapping + expiry to rewrite a Response /
    /// ResponseFinal carrying that qid back toward (and to time out if no final
    /// ever arrives).
    returns: HashMap<u64, PendingReturn>,
}

/// One live return mapping: the fan's shared return target (the `Rc` clone whose
/// drop-count gates the last-out final), plus the deadline past which this branch
/// is abandoned ([`expired`](PendingQueries::expired)).
#[derive(Debug)]
struct PendingReturn {
    /// The fan this branch belongs to — shared across the logical query's
    /// branches (zenoh's per-branch `Arc<Query>` clone).
    fan: Rc<QueryFan>,
    /// When this pending branch is abandoned if no `ResponseFinal` has arrived —
    /// `allocate`-time + the forwarder's query timeout (zenoh `QueryCleanup`'s
    /// `tokio::time::sleep(timeout)`).
    deadline: Instant,
}

/// A pending branch that has passed its deadline, returned by
/// [`expired`](PendingQueries::expired) so the forwarder can synthesize the
/// querier-ward timeout messages (zenoh `QueryCleanup::run`): the `Err` reply per
/// reaped branch, and — when `last` — the closing `ResponseFinal` that closes the
/// whole fan. The entry is already removed from the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredQuery {
    /// The out face the timed-out branch had been forwarded on (its local key).
    pub out_face: FaceId,
    /// The local qid that timed out on `out_face`.
    pub qid: u64,
    /// The inbound face to route the timeout messages back to.
    pub inbound: FaceId,
    /// The upstream rid to stamp on them.
    pub inbound_rid: u64,
    /// Whether this branch was the LAST of its fan (the `Rc::into_inner` gate) —
    /// only then does the caller send the closing `ResponseFinal`; the `Err`
    /// reply goes per branch (zenoh runs one `QueryCleanup` per branch, each
    /// sending an Err, while `finalize_pending_query` gates the final last-out).
    pub last: bool,
}

impl PendingQueries {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh local query id on `out_face` for one BRANCH of `fan`'s
    /// Query being forwarded there, recording the shared return mapping and the
    /// `deadline` past which the branch times out if no `ResponseFinal` arrives.
    /// Returns the new qid to stamp on the outbound Request. Mirrors zenoh
    /// `insert_pending_query`'s `next_qid.wrapping_add(1)` +
    /// `pending_queries.insert(qid, (query.clone(), ..))` followed by
    /// `QueryCleanup::spawn_query_clean_up_task` arming the timeout — the `Rc`
    /// clone here IS zenoh's per-branch `Arc<Query>` clone.
    pub fn allocate(&mut self, out_face: FaceId, fan: &Rc<QueryFan>, deadline: Instant) -> u64 {
        let fp = self.by_face.entry(out_face).or_default();
        fp.next_qid = fp.next_qid.wrapping_add(1);
        let qid = fp.next_qid;
        fp.returns.insert(
            qid,
            PendingReturn {
                fan: fan.clone(),
                deadline,
            },
        );
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
            .and_then(|fp| fp.returns.get(&qid))
            .map(|r| (r.fan.inbound, r.fan.inbound_rid))
    }

    /// Take (remove) the return mapping for a `ResponseFinal` carrying `qid` on
    /// `out_face` — the final closes this BRANCH and frees the entry (zenoh
    /// `route_send_response_final` removes the pending entry). Returns `(inbound
    /// face, inbound rid, last)`: `last` is `true` IFF this was the fan's FINAL
    /// live branch (the removed entry held the last `Rc` reference — zenoh's
    /// `Arc::into_inner` gate in `finalize_pending_query`), and only then must
    /// the caller forward the closing `ResponseFinal` upstream; a non-last final
    /// is ABSORBED (the querier still awaits the other branches). The face's
    /// slot (its `next_qid` allocator) SURVIVES a drain — it is face-lifetime,
    /// freed only by [`remove_face`](Self::remove_face) — so a later query on
    /// this face can never reuse a qid a stale in-flight reply still carries.
    /// `None` for an unknown qid (already closed / never sent).
    pub fn take(&mut self, out_face: FaceId, qid: u64) -> Option<(FaceId, u64, bool)> {
        let fp = self.by_face.get_mut(&out_face)?;
        let entry = fp.returns.remove(&qid);
        entry.map(|r| {
            let inbound = r.fan.inbound;
            let inbound_rid = r.fan.inbound_rid;
            let last = Rc::into_inner(r.fan).is_some();
            (inbound, inbound_rid, last)
        })
    }

    /// Drop ALL pending branches on a departed `face`, returning the fans this
    /// DRAINED — the `(inbound face, inbound rid)` of each fan whose LAST live
    /// branch died with this face, so the forwarder's `deregister` can synthesize
    /// the closing `ResponseFinal` that terminates the querier (zenoh
    /// `finalize_pending_queries` on face teardown drains the face's
    /// `pending_queries` through the same `finalize_pending_query` last-out gate,
    /// final only — no Err). A fan with surviving branches on OTHER faces is NOT
    /// drained (those branches still answer). Entries on OTHER faces that pointed
    /// back to this one as their inbound target are left to self-heal — a reply
    /// toward the dead face simply drops at send — and to the per-branch timeout
    /// [`expired`](Self::expired).
    pub fn remove_face(&mut self, face: &FaceId) -> Vec<(FaceId, u64)> {
        let Some(fp) = self.by_face.remove(face) else {
            return Vec::new();
        };
        let mut drained = Vec::new();
        for (_qid, ret) in fp.returns {
            let inbound = ret.fan.inbound;
            let inbound_rid = ret.fan.inbound_rid;
            if Rc::into_inner(ret.fan).is_some() {
                drained.push((inbound, inbound_rid));
            }
        }
        drained
    }

    /// Reap every pending branch whose `deadline` is at or before `now`, removing
    /// it and returning the [`ExpiredQuery`] descriptors so the caller can route
    /// the timeout messages back to each querier (the `Err` per branch, the
    /// closing `ResponseFinal` only for a `last` branch). The forwarder's `tick`
    /// drives this on its coalescing cadence — the wz form of zenoh's per-query
    /// `QueryCleanup` timer (`dispatcher/queries.rs`): where zenoh arms one
    /// `tokio::time::sleep(timeout)` task per branch, wz sweeps the whole table
    /// each tick, so a branch is reaped within one tick window of its deadline
    /// rather than exactly at it (a coarser but allocation-free GC). A face's
    /// `next_qid` allocator survives the sweep (face-lifetime, like
    /// [`take`](Self::take)). When SEVERAL branches of one fan expire in the
    /// same sweep, exactly ONE of them reports `last` (whichever removal drops
    /// the fan's final reference).
    pub fn expired(&mut self, now: Instant) -> Vec<ExpiredQuery> {
        // Phase 1: collect the victims under a shared borrow (the `Rc::into_inner`
        // last-out accounting needs owned removal, which `retain` cannot express).
        let mut victims: Vec<(FaceId, u64)> = Vec::new();
        for (&out_face, fp) in &self.by_face {
            for (&qid, ret) in &fp.returns {
                if ret.deadline <= now {
                    victims.push((out_face, qid));
                }
            }
        }
        // Phase 2: remove each through the take path, which computes the
        // per-branch `last` flag (the face's allocator slot survives).
        let mut reaped = Vec::with_capacity(victims.len());
        for (out_face, qid) in victims {
            if let Some((inbound, inbound_rid, last)) = self.take(out_face, qid) {
                reaped.push(ExpiredQuery {
                    out_face,
                    qid,
                    inbound,
                    inbound_rid,
                    last,
                });
            }
        }
        reaped
    }

    /// Total live pending branches across every face — the work witness a test
    /// (or the [`expired`](Self::expired) timeout sweep) reads.
    pub fn len(&self) -> usize {
        self.by_face.values().map(|fp| fp.returns.len()).sum()
    }

    /// Whether the table holds no pending branches. (A drained face's
    /// `next_qid` allocator slot may still be alive — it is face-lifetime and
    /// does not count as pending work.)
    pub fn is_empty(&self) -> bool {
        self.by_face.values().all(|fp| fp.returns.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    /// A far-future deadline for tests that exercise the non-timeout lifecycle —
    /// every entry stays live across the test.
    fn never(base: Instant) -> Instant {
        base + Duration::from_secs(3600)
    }

    #[test]
    fn allocate_hands_out_monotonic_per_face_qids_from_one() {
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        // First allocation on a face is qid 1 (pre-increment leaves 0 unused).
        assert_eq!(pq.allocate(face(10), &QueryFan::new(face(0), 100), t), 1);
        assert_eq!(pq.allocate(face(10), &QueryFan::new(face(0), 101), t), 2);
        // A DIFFERENT out face has its own independent counter.
        assert_eq!(pq.allocate(face(11), &QueryFan::new(face(0), 200), t), 1);
        assert_eq!(pq.len(), 3);
    }

    #[test]
    fn peek_returns_the_mapping_without_removing() {
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        let qid = pq.allocate(face(10), &QueryFan::new(face(3), 99), t);
        // Peek twice: the entry survives (a query may yield several Responses).
        assert_eq!(pq.peek(face(10), qid), Some((face(3), 99)));
        assert_eq!(pq.peek(face(10), qid), Some((face(3), 99)));
        assert_eq!(pq.len(), 1, "peek does not consume");
        // A qid on the wrong face, or an unknown qid, has no mapping.
        assert_eq!(pq.peek(face(11), qid), None);
        assert_eq!(pq.peek(face(10), 999), None);
    }

    #[test]
    fn take_removes_the_mapping_and_the_face_allocator_survives() {
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        // Two INDEPENDENT single-branch queries on one out face.
        let q1 = pq.allocate(face(10), &QueryFan::new(face(3), 99), t);
        let q2 = pq.allocate(face(10), &QueryFan::new(face(4), 77), t);
        // Take q1: returns its mapping (last — a single-branch fan), leaves q2.
        assert_eq!(pq.take(face(10), q1), Some((face(3), 99, true)));
        assert_eq!(pq.peek(face(10), q1), None, "taken entry is gone");
        assert_eq!(pq.peek(face(10), q2), Some((face(4), 77)), "q2 survives");
        // A second take of the same qid is a no-op.
        assert_eq!(pq.take(face(10), q1), None);
        // Taking the last entry drains the face's branches...
        assert_eq!(pq.take(face(10), q2), Some((face(4), 77, true)));
        assert!(pq.is_empty(), "no pending branches remain");
        // ...but the face's qid ALLOCATOR survives the drain (face-lifetime,
        // zenoh next_qid): the next query continues the sequence.
        assert_eq!(
            pq.allocate(face(10), &QueryFan::new(face(3), 55), t),
            3,
            "the allocator did not reset to 1 on the drain"
        );
    }

    #[test]
    fn qids_stay_monotonic_across_a_timeout_drain() {
        // The stale-reply aliasing regression: a query whose entry is REAPED (its
        // queryable may still be answering!) drains the face — the next query on
        // that face must get a FRESH qid, never the reaped one, else the old
        // queryable's late Response/Final would misroute into (and could
        // prematurely close) the new query.
        let mut pq = PendingQueries::new();
        let base = Instant::now();
        let q1 = pq.allocate(face(10), &QueryFan::new(face(3), 99), base);
        assert_eq!(q1, 1);
        let reaped = pq.expired(base); // deadline <= now: reaped, face drained
        assert_eq!(reaped.len(), 1);
        let q2 = pq.allocate(face(10), &QueryFan::new(face(3), 100), never(base));
        assert_ne!(q2, q1, "a reaped qid is never reused for the next query");
        assert_eq!(q2, 2, "the allocator continued monotonically");
    }

    #[test]
    fn a_fan_take_reports_last_only_on_the_final_branch() {
        // The last-out final gate (zenoh Arc::into_inner): a Query fanned to TWO
        // out faces closes only when BOTH branches finalize — the first take is
        // NOT last (the final is absorbed), the second IS (the final propagates).
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        let fan = QueryFan::new(face(3), 99);
        let qa = pq.allocate(face(10), &fan, t);
        let qb = pq.allocate(face(11), &fan, t);
        drop(fan); // the caller's handle drops; only the entries keep it alive
        assert_eq!(
            pq.take(face(10), qa),
            Some((face(3), 99, false)),
            "first branch's final is absorbed (the other branch is still live)"
        );
        assert_eq!(
            pq.take(face(11), qb),
            Some((face(3), 99, true)),
            "the LAST branch's final closes the fan"
        );
        assert!(pq.is_empty());
    }

    #[test]
    fn a_dropped_construction_handle_leaves_the_last_out_gate_intact() {
        // The gate counts live Rc REFERENCES (pending entries + any caller
        // handle), so the allocation-scope contract is load-bearing: the caller
        // must drop its construction handle when the routing call returns — a
        // handle still live at take time WOULD suppress `last` (a phantom
        // branch). This pins the honored side of the contract: with the handle
        // dropped, a single-branch fan is `last` at its only take. Both
        // forwarders bind the fan in a scope that ends before any reply event.
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        let fan = QueryFan::new(face(3), 99);
        let qa = pq.allocate(face(10), &fan, t);
        drop(fan);
        assert_eq!(
            pq.take(face(10), qa),
            Some((face(3), 99, true)),
            "a single-branch fan is last at its only take"
        );
    }

    #[test]
    fn remove_face_drops_every_pending_on_that_face_only() {
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        pq.allocate(face(10), &QueryFan::new(face(3), 1), t);
        pq.allocate(face(10), &QueryFan::new(face(3), 2), t);
        pq.allocate(face(11), &QueryFan::new(face(4), 1), t);
        let drained = pq.remove_face(&face(10));
        assert_eq!(pq.peek(face(10), 1), None, "face 10's entries dropped");
        assert_eq!(pq.peek(face(10), 2), None);
        assert_eq!(
            pq.peek(face(11), 1),
            Some((face(4), 1)),
            "face 11 untouched"
        );
        // Both dropped entries were single-branch fans -> both drained (their
        // queriers are owed a closing final).
        let mut drained = drained;
        drained.sort();
        assert_eq!(drained, vec![(face(3), 1), (face(3), 2)]);
        // Removing an absent face is a no-op.
        assert!(pq.remove_face(&face(99)).is_empty());
        assert_eq!(pq.len(), 1);
    }

    #[test]
    fn remove_face_drains_only_fans_whose_last_branch_died() {
        // A fan spanning faces 10 and 11: face 10's departure leaves the branch
        // on face 11 answering (NOT drained); face 11's later departure drains
        // it (the querier is owed the closing final exactly once).
        let mut pq = PendingQueries::new();
        let t = never(Instant::now());
        let fan = QueryFan::new(face(3), 99);
        pq.allocate(face(10), &fan, t);
        pq.allocate(face(11), &fan, t);
        drop(fan);
        assert!(
            pq.remove_face(&face(10)).is_empty(),
            "the fan survives on face 11 -> not drained"
        );
        assert_eq!(
            pq.remove_face(&face(11)),
            vec![(face(3), 99)],
            "the last branch's face-down drains the fan"
        );
        assert!(pq.is_empty());
    }

    #[test]
    fn expired_reaps_only_entries_past_the_deadline() {
        let mut pq = PendingQueries::new();
        let base = Instant::now();
        let soon = base + Duration::from_millis(10);
        let late = base + Duration::from_secs(60);
        // Two independent single-branch queries on the same face with DIFFERENT
        // deadlines, one on another face.
        let q_soon = pq.allocate(face(10), &QueryFan::new(face(3), 99), soon);
        let q_late = pq.allocate(face(10), &QueryFan::new(face(4), 88), late);
        let q_other = pq.allocate(face(11), &QueryFan::new(face(5), 77), soon);
        assert_eq!(pq.len(), 3);

        // A sweep BEFORE any deadline reaps nothing.
        assert!(pq.expired(base).is_empty(), "nothing past its deadline yet");
        assert_eq!(pq.len(), 3);

        // A sweep AFTER `soon` (but before `late`) reaps the two soon entries and
        // prunes the face that those emptied (face 11), keeping the late one.
        let mut reaped = pq.expired(base + Duration::from_millis(20));
        reaped.sort_by_key(|e| (e.out_face.0, e.qid));
        assert_eq!(
            reaped,
            vec![
                ExpiredQuery {
                    out_face: face(10),
                    qid: q_soon,
                    inbound: face(3),
                    inbound_rid: 99,
                    last: true, // single-branch fan
                },
                ExpiredQuery {
                    out_face: face(11),
                    qid: q_other,
                    inbound: face(5),
                    inbound_rid: 77,
                    last: true,
                },
            ],
        );
        assert_eq!(pq.peek(face(10), q_soon), None, "soon entry reaped");
        assert_eq!(
            pq.peek(face(10), q_late),
            Some((face(4), 88)),
            "late entry survives"
        );
        assert_eq!(pq.peek(face(11), q_other), None, "other-face soon reaped");
        assert_eq!(pq.len(), 1);

        // A deadline exactly at `now` counts as expired (`<=`).
        let reaped = pq.expired(late);
        assert_eq!(
            reaped.len(),
            1,
            "the late entry reaps at its exact deadline"
        );
        assert!(pq.is_empty(), "the table drains to empty");
    }

    #[test]
    fn expired_marks_exactly_one_branch_of_a_fan_last() {
        // Two branches of ONE fan expiring in the SAME sweep: the querier is owed
        // one Err per branch but exactly ONE closing final — precisely one of the
        // reaped descriptors reports `last`.
        let mut pq = PendingQueries::new();
        let base = Instant::now();
        let soon = base + Duration::from_millis(10);
        let fan = QueryFan::new(face(3), 99);
        pq.allocate(face(10), &fan, soon);
        pq.allocate(face(11), &fan, soon);
        drop(fan);
        let reaped = pq.expired(base + Duration::from_millis(20));
        assert_eq!(reaped.len(), 2, "both branches reaped");
        assert_eq!(
            reaped.iter().filter(|e| e.last).count(),
            1,
            "exactly one branch closes the fan"
        );
        assert!(pq.is_empty());
    }
}
