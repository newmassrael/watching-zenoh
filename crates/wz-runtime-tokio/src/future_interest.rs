// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! FUTURE-mode subscriber-interest store (R311y146) — the per-forwarder record of
//! which CLIENT faces declared a FUTURE (`f()`) subscriber `Interest`, and which
//! `DeclareSubscriber`s wz has already pushed back to them.
//!
//! ## Why this exists
//!
//! A zenoh(-pico) PUBLISHER keeps a WRITE-FILTER that drops its own puts locally
//! until it receives a matching `DeclareSubscriber` (pico `net/filtering.c`). Its
//! declare-`Interest` is `RESTRICTED | CURRENT | AGGREGATE | FUTURE` for a client
//! (`filtering.c:231-234`). The CURRENT part is answered by the forwarder's
//! `respond_to_interest` current dump; the FUTURE part means: when a matching
//! subscriber is LEARNED LATER, PROACTIVELY push a `DeclareSubscriber` to the
//! publisher so its filter deactivates — closing the pub-BEFORE-sub hole (an empty
//! current dump would otherwise leave the filter armed forever).
//!
//! wz previously DROPPED the FUTURE bit (`respond_to_interest` early-returned on
//! `!interest.c()` and never read `f()`); this store is the FUTURE half.
//!
//! ## The zenoh mapping (bundled per face on purpose)
//!
//! - [`ClientFutureSubs::interests`] = zenoh's per-`FaceState`
//!   `remote_interests` (the interests a face declared), filtered to FUTURE
//!   subscriber interests. Keyed by the soliciting `interest_id` so an inbound
//!   `Interest(Final)` (pico sends one on every publisher/querier drop —
//!   `net/primitives.c:_z_remove_interest`) removes exactly one.
//! - [`ClientFutureSubs::pushed`] = zenoh's `face_hat.local_subs` (`reply keyexpr
//!   -> the decl id declared to that face`). Seeded by the current dump and by
//!   every FUTURE push; read for dedup (never declare the same reply ke twice to a
//!   face) and to keep the `(decl_id, peer)` a pico write-filter target is keyed on
//!   (`filtering.c:202`) consistent for the deferred undeclare-push.
//!
//! zenoh warns against two parallel `FaceId`-keyed maps drifting
//! ([`crate::linkstate_forward`] `FaceState` doc); the two live in ONE per-face
//! struct so a single [`FutureInterestStore::purge_face`] on `deregister` covers
//! both.
//!
//! ## Scope (SUBS plane only)
//!
//! This store carries the SUBSCRIBER plane. The QUERYABLE future-push needs a
//! VALUE-AWARE `(id, QueryableInfo)` registry that RE-pushes when completeness
//! flips `false -> true` (zenoh `linkstate_peer/queries.rs:186`; a presence-only
//! dedup would black-hole a `Z_QUERY_TARGET_ALL_COMPLETE` querier whose filter
//! deactivates only on `msg->is_complete`), so it is a SEPARATE unit, not this
//! type. Likewise a match-all (`r()==false`) future interest is NOT stored — the
//! current dump defers match-all, and storing it would push every new sub with no
//! current-dump parity; pico always sets RESTRICTED so this is not a live gap.

use std::collections::HashMap;

use wz_session_core::keyexpr_match::keyexpr_intersects_target;

use crate::accept_loop::FaceId;

/// One CLIENT face's declared FUTURE subscriber interest: the RESOLVED literal
/// target keyexpr and whether the interest is AGGREGATE (a match reply is keyed on
/// the interest keyexpr, not the concrete subscription — pico matches an aggregate
/// interest's replies by keyexpr EQUALITY).
#[derive(Debug, Clone)]
struct FutureInterest {
    target: String,
    aggregate: bool,
}

/// One CLIENT face's FUTURE subscriber interests + the declarations already pushed
/// to it. See the module docs for the zenoh mapping.
#[derive(Debug, Default)]
struct ClientFutureSubs {
    /// Declared FUTURE interests, keyed by the soliciting `interest_id`.
    interests: HashMap<u64, FutureInterest>,
    /// `reply keyexpr -> the decl id declared to this face` (zenoh
    /// `face_hat.local_subs`). Seeded by the current dump (get-or-alloc, so a
    /// redundant re-declare REUSES the id and pico stays idempotent) and by each
    /// FUTURE push.
    pushed: HashMap<String, u64>,
    /// Per-face monotonic decl-id source. Ids start at 1 (0 is a NON-future
    /// current-dump reply id and pico's declarations-propagation sentinel, so any
    /// interned id is `>= 1`) and are never recycled.
    next_id: u64,
}

impl ClientFutureSubs {
    /// Get-or-allocate the decl id for `reply_ke`, returning `(id, is_new)`.
    /// `is_new` is `true` only on the first allocation — the current dump reports a
    /// current sub whether or not it is new (always emitting with the returned id),
    /// while the FUTURE push emits only when it actually adds a declaration.
    fn intern(&mut self, reply_ke: &str) -> (u64, bool) {
        if let Some(id) = self.pushed.get(reply_ke) {
            return (*id, false);
        }
        self.next_id += 1;
        let id = self.next_id;
        self.pushed.insert(reply_ke.to_owned(), id);
        (id, true)
    }
}

/// The per-forwarder FUTURE-mode subscriber-interest store — the wz analogue of
/// zenoh's per-`FaceState` `remote_interests` + `face_hat.local_subs`, keyed by the
/// CLIENT [`FaceId`]. Both forwarders (router + peer) own one; the store logic is
/// shared here.
#[derive(Debug, Default)]
pub struct FutureInterestStore {
    by_face: HashMap<FaceId, ClientFutureSubs>,
}

impl FutureInterestStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a CLIENT face's FUTURE subscriber interest for `target` (a resolved
    /// literal; a match-all interest is not stored — see the module docs). Keyed by
    /// `interest_id`; a re-declare of the same id is last-wins.
    pub fn store_interest(
        &mut self,
        face: FaceId,
        interest_id: u64,
        target: String,
        aggregate: bool,
    ) {
        self.by_face
            .entry(face)
            .or_default()
            .interests
            .insert(interest_id, FutureInterest { target, aggregate });
    }

    /// Get-or-allocate the decl id the CURRENT-dump reply of a FUTURE interest
    /// carries for `reply_ke`, seeding `pushed` so a later FUTURE push of the same
    /// ke dedups. Always returns an id (the current dump reports the sub whether or
    /// not the id is new). Call only after [`store_interest`](Self::store_interest)
    /// for the same face (else the seed would linger with no interest); an existing
    /// entry's id is reused (redundant re-declare stays idempotent on pico).
    pub fn intern_current_reply(&mut self, face: FaceId, reply_ke: &str) -> u64 {
        self.by_face.entry(face).or_default().intern(reply_ke).0
    }

    /// A newly-learned subscription `new_ke` sourced at `origin` (`None` for a
    /// self-originated local subscriber, which has no inbound face) — return the
    /// `(face, reply keyexpr, decl id)` FUTURE pushes to emit: one per stored
    /// interest whose target INTERSECTS `new_ke`, on a face other than `origin`,
    /// whose reply keyexpr (the interest ke for an aggregate interest, else
    /// `new_ke`) has NOT already been declared to that face. Interns each reply ke,
    /// so a second matching interest on the same face and any later sub for the same
    /// ke dedup. The caller builds the unsolicited `DeclareSubscriber(id, reply_ke)`
    /// (interest_id `None`, no `I` flag) and sends it to `face`.
    pub fn pushes_for_new_sub(
        &mut self,
        new_ke: &str,
        origin: Option<FaceId>,
    ) -> Vec<(FaceId, String, u64)> {
        let mut out = Vec::new();
        for (face, state) in self.by_face.iter_mut() {
            if origin == Some(*face) {
                continue; // never echo a declaration back to the face that sourced it
            }
            // Gather the reply kes this face's interests want BEFORE interning: the
            // read borrow of `interests` and the mutable `intern` cannot overlap.
            let mut reply_kes: Vec<String> = Vec::new();
            for interest in state.interests.values() {
                let target_chunks: Vec<&str> = interest.target.split('/').collect();
                if keyexpr_intersects_target(new_ke, &target_chunks) {
                    reply_kes.push(if interest.aggregate {
                        interest.target.clone()
                    } else {
                        new_ke.to_owned()
                    });
                }
            }
            for reply_ke in reply_kes {
                let (id, is_new) = state.intern(&reply_ke);
                if is_new {
                    out.push((*face, reply_ke, id));
                }
            }
        }
        out
    }

    /// Remove a FUTURE interest by `interest_id` on `face` — an inbound
    /// `Interest(Final)`. Returns `true` if one was removed.
    ///
    /// When the face's LAST interest is removed, the whole face entry (including
    /// `pushed`) is pruned: pico sends an `Interest(Final)` precisely because a
    /// publisher DROPPED (`net/filtering.c:_z_write_filter_clear` ->
    /// `_z_remove_interest`), so with no interests left the face has no publisher
    /// and pico holds no write-filter — a retained `pushed` record would then
    /// wrongly DEDUP-SUPPRESS a push to a FUTURE publisher on the same face (a later
    /// `store_interest` re-starts a fresh registry). While OTHER interests remain,
    /// `pushed` is kept — a shared reply ke may still back a live publisher.
    ///
    /// RESIDUAL (subsumed by the deferred undeclare-push, NOT a silent gap): a sub
    /// that WITHDRAWS while an interest is still live leaves the `pushed` entry
    /// stale (wz defers the sub-withdrawal UndeclareSubscriber), so a second
    /// publisher on that ke, declared during the sub's absence, can miss its
    /// re-push when the sub reappears. The undeclare-push unit — which clears
    /// `pushed` and re-arms the filter on sub-withdrawal, zenoh
    /// `propagate_forget_simple_subscription` — is the complete fix.
    pub fn remove_interest(&mut self, face: FaceId, interest_id: u64) -> bool {
        let Some(state) = self.by_face.get_mut(&face) else {
            return false;
        };
        let removed = state.interests.remove(&interest_id).is_some();
        if state.interests.is_empty() {
            self.by_face.remove(&face);
        }
        removed
    }

    /// Drop ALL of a face's future-interest state — the `deregister` face-down
    /// purge. Returns `true` if the face held any.
    pub fn purge_face(&mut self, face: FaceId) -> bool {
        self.by_face.remove(&face).is_some()
    }

    /// Test-only: number of faces holding any future state.
    #[cfg(test)]
    fn face_count(&self) -> usize {
        self.by_face.len()
    }

    /// Test-only: number of stored interests on `face`.
    #[cfg(test)]
    fn interest_count(&self, face: FaceId) -> usize {
        self.by_face.get(&face).map_or(0, |s| s.interests.len())
    }

    /// Test-only: number of reply keyexprs pushed to `face`.
    #[cfg(test)]
    fn pushed_count(&self, face: FaceId) -> usize {
        self.by_face.get(&face).map_or(0, |s| s.pushed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    #[test]
    fn pub_before_sub_pushes_the_first_later_sub_with_a_non_zero_id() {
        // The raison d'être: an interest arrives with NO matching sub (empty
        // current dump seeds nothing), then a sub is learned later -> exactly one
        // push, id >= 1.
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let pushes = s.pushes_for_new_sub("demo/data", Some(face(9)));
        assert_eq!(pushes.len(), 1, "one push to the interest holder");
        let (f, reply_ke, id) = &pushes[0];
        assert_eq!(*f, face(1));
        assert_eq!(
            reply_ke, "demo/**",
            "aggregate reply keyed on the interest ke"
        );
        assert!(
            *id >= 1,
            "a future push carries a non-zero decl id, got {id}"
        );
    }

    #[test]
    fn non_aggregate_reply_is_keyed_on_the_concrete_sub_ke() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), false);
        let pushes = s.pushes_for_new_sub("demo/data", Some(face(9)));
        assert_eq!(pushes.len(), 1);
        assert_eq!(
            pushes[0].1, "demo/data",
            "non-aggregate replies with the concrete ke"
        );
    }

    #[test]
    fn a_second_sub_for_an_aggregate_interest_dedups() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let first = s.pushes_for_new_sub("demo/a", Some(face(9)));
        assert_eq!(first.len(), 1);
        let second = s.pushes_for_new_sub("demo/b", Some(face(9)));
        assert!(
            second.is_empty(),
            "a second sub under the same aggregate ke needs no new declare (filter already off)",
        );
    }

    #[test]
    fn a_non_matching_sub_pushes_nothing() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.pushes_for_new_sub("other/key", Some(face(9))).is_empty(),
            "a sub outside the interest target is not pushed",
        );
    }

    #[test]
    fn a_sub_sourced_by_the_interest_holder_is_not_echoed() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.pushes_for_new_sub("demo/data", Some(face(1))).is_empty(),
            "never push a declaration back to the face that sourced it",
        );
    }

    #[test]
    fn current_dump_seed_dedups_the_later_matching_push() {
        // A sub that existed at interest time is reported by the current dump
        // (intern_current_reply seeds `pushed`); a later re-learn of the SAME
        // aggregate ke must not double-declare.
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let seeded_id = s.intern_current_reply(face(1), "demo/**");
        assert!(seeded_id >= 1);
        assert!(
            s.pushes_for_new_sub("demo/late", Some(face(9))).is_empty(),
            "the aggregate reply ke was already seeded by the current dump",
        );
    }

    #[test]
    fn two_interests_same_target_share_one_push() {
        // Two publishers on the same key -> two interests, one aggregate target ->
        // a single declaration covers both (pico fires every matching filter).
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/x".to_owned(), true);
        s.store_interest(face(1), 8, "demo/x".to_owned(), true);
        let pushes = s.pushes_for_new_sub("demo/x", Some(face(9)));
        assert_eq!(
            pushes.len(),
            1,
            "one reply ke -> one push, not one-per-interest"
        );
    }

    #[test]
    fn two_faces_each_get_their_own_push() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(2), 3, "demo/**".to_owned(), true);
        let mut pushes = s.pushes_for_new_sub("demo/data", Some(face(9)));
        pushes.sort_by_key(|(f, _, _)| f.0);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].0, face(1));
        assert_eq!(pushes[1].0, face(2));
    }

    #[test]
    fn interest_final_removes_one_interest_and_stops_its_future_pushes() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.remove_interest(face(1), 7),
            "the stored interest is removed"
        );
        assert!(
            s.pushes_for_new_sub("demo/data", Some(face(9))).is_empty(),
            "a removed interest attracts no further pushes",
        );
        assert!(!s.remove_interest(face(1), 7), "removing again is a no-op");
    }

    #[test]
    fn interest_final_of_the_last_interest_prunes_pushed() {
        // Removing the LAST interest (the publisher DROPPED — pico's write-filter is
        // gone) prunes the whole face, so a stale `pushed` entry cannot suppress a
        // push to a FUTURE publisher on the same face.
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new_sub("demo/data", Some(face(9)));
        assert_eq!(s.pushed_count(face(1)), 1);
        assert!(s.remove_interest(face(1), 7));
        assert_eq!(
            s.face_count(),
            0,
            "the face is pruned once its last interest is gone"
        );
        // A FRESH publisher on the same face + same aggregate ke, pub-before-sub,
        // is NOT suppressed by the pruned registry.
        s.store_interest(face(1), 9, "demo/**".to_owned(), true);
        let pushes = s.pushes_for_new_sub("demo/late", Some(face(9)));
        assert_eq!(
            pushes.len(),
            1,
            "the new publisher's later sub is pushed, not dedup-suppressed"
        );
    }

    #[test]
    fn interest_final_of_one_of_several_keeps_pushed_for_the_rest() {
        // Removing ONE of several interests keeps `pushed` — a shared reply ke may
        // still back a live publisher; only when the last goes is it pruned.
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(1), 8, "other/**".to_owned(), true);
        let _ = s.pushes_for_new_sub("demo/data", Some(face(9)));
        assert_eq!(s.pushed_count(face(1)), 1);
        assert!(s.remove_interest(face(1), 7));
        assert_eq!(s.interest_count(face(1)), 1, "interest 8 remains");
        assert_eq!(
            s.pushed_count(face(1)),
            1,
            "pushed kept while an interest remains"
        );
        assert!(s.remove_interest(face(1), 8));
        assert_eq!(s.face_count(), 0, "the last removal prunes the face");
    }

    #[test]
    fn purge_face_drops_everything_for_a_face() {
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(2), 3, "other/**".to_owned(), true);
        assert!(s.purge_face(face(1)));
        assert_eq!(s.face_count(), 1, "only face 2 remains");
        assert!(
            s.pushes_for_new_sub("demo/data", Some(face(9))).is_empty(),
            "the purged face attracts no push",
        );
        assert!(!s.purge_face(face(1)), "purging an absent face is a no-op");
    }

    #[test]
    fn ids_start_at_one_and_advance_within_a_face_lifetime() {
        // Ids start at 1 (0 is reserved for a non-future current reply + pico's
        // declarations-propagation sentinel) and advance per distinct reply ke while
        // the face entry lives. (Across a face prune the counter restarts from a
        // fresh entry — the old publisher is gone, so no live id can collide.)
        let mut s = FutureInterestStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), false);
        let a = s.pushes_for_new_sub("demo/a", Some(face(9)));
        let b = s.pushes_for_new_sub("demo/b", Some(face(9)));
        assert_eq!(a[0].2, 1, "first alloc is 1 (0 is reserved)");
        assert_eq!(b[0].2, 2, "second distinct ke gets a fresh id");
    }
}
