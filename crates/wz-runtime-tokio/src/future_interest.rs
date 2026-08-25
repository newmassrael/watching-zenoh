// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! FUTURE-mode declare-interest store (R311y146 subs; R311y150 generalized to
//! queryables) — the per-forwarder record of which CLIENT faces declared a FUTURE
//! (`f()`) `Interest`, and which declarations wz has already pushed back to them.
//!
//! ## Why this exists
//!
//! A zenoh(-pico) PUBLISHER/QUERIER keeps a WRITE-FILTER that drops its own
//! puts/gets locally until it receives a matching `DeclareSubscriber`/
//! `DeclareQueryable` (pico `net/filtering.c`). Its declare-`Interest` is
//! `RESTRICTED | CURRENT | AGGREGATE | FUTURE` for a client (`filtering.c:231-234`).
//! The CURRENT part is answered by the forwarder's `respond_to_interest` current
//! dump; the FUTURE part means: when a matching subscriber/queryable is LEARNED
//! LATER, PROACTIVELY push a declaration to the publisher/querier so its filter
//! deactivates — closing the pub-BEFORE-sub / querier-BEFORE-queryable hole (an
//! empty current dump would otherwise leave the filter armed forever).
//!
//! wz previously DROPPED the FUTURE bit (`respond_to_interest` early-returned on
//! `!interest.c()` and never read `f()`); this store is the FUTURE half.
//!
//! ## The value parameter `V` (subs vs queryables)
//!
//! The SUBSCRIBER plane is presence-only: a `DeclareSubscriber` carries no value,
//! so once pushed it is never re-pushed (`V = ()`, [`FutureSubStore`]). The
//! QUERYABLE plane is VALUE-AWARE: a `DeclareQueryable` carries a [`QueryableInfo`]
//! (`complete` + `distance`), and a `Z_QUERY_TARGET_ALL_COMPLETE` querier's filter
//! deactivates only on a `msg->is_complete` reply (`filtering.c:206`). So when the
//! FOLDED completeness of a matched keyexpr flips `false -> true`, wz must RE-push
//! the same declaration id carrying the new value (zenoh
//! `linkstate_peer/queries.rs:180-198` `current.unwrap().1 != info`, reusing
//! `current.0`) — else the ALL_COMPLETE querier black-holes. `V = QueryableInfo`
//! ([`FutureQablStore`]) makes [`pushes_for_new`](FutureInterestStore::pushes_for_new)
//! re-emit on a value change; `V = ()` degenerates to presence-only (a `()` value
//! never differs, so the qabl re-push logic is provably inert for subs).
//!
//! The pushed value MUST be the RE-FOLDED merged info (the fold over every matching
//! queryable source — zenoh's `local_qabl_info`), NOT a single source's raw info:
//! pushing a second source's incomplete info while a complete source is still
//! present would DOWNGRADE the querier's view (`merge` is OR-complete) and re-arm
//! an ALL_COMPLETE filter. The forwarder recomputes the fold at each push site.
//!
//! ## The zenoh mapping (bundled per face on purpose)
//!
//! - [`ClientFutureInterests::interests`] = zenoh's per-`FaceState`
//!   `remote_interests` (the interests a face declared), filtered to FUTURE
//!   declare interests. Keyed by the soliciting `interest_id` so an inbound
//!   `Interest(Final)` (pico sends one on every publisher/querier drop —
//!   `net/primitives.c:_z_remove_interest`) removes exactly one.
//! - [`ClientFutureInterests::pushed`] = zenoh's `face_hat.local_subs` /
//!   `local_qabls` (`reply keyexpr -> (decl id, last-declared value)`). Seeded by
//!   the current dump and by every FUTURE push; read for the value-diff re-push
//!   decision and to keep the `(decl_id, peer)` a pico write-filter target is keyed
//!   on (`filtering.c:202`) consistent for the deferred undeclare-push.
//!
//! zenoh warns against two parallel `FaceId`-keyed maps drifting
//! ([`crate::linkstate_forward`] `FaceState` doc); the two live in ONE per-face
//! struct so a single [`FutureInterestStore::purge_face`] on `deregister` covers
//! both — and the sub and qabl stores are ONE generic type, so the invariant is
//! enforced once for both planes (mirroring the y144 `emit_current_interest_replies`
//! `<V>` lift, which already unifies the sub/qabl current-dump emit on this same
//! `V=() / V=QueryableInfo` split).
//!
//! ## Deferred: match-all + undeclare-push
//!
//! A match-all (`r()==false`) future interest is NOT stored — the current dump
//! defers match-all, and storing it would push every new declaration with no
//! current-dump parity; pico always sets RESTRICTED so this is not a live gap.
//!
//! The undeclare-push (a declaration WITHDRAWN clears `pushed` + re-arms the filter,
//! zenoh `propagate_forget_simple_subscription/_queryable`) is a SEPARATE unit
//! (R311y151). See [`remove_interest`](FutureInterestStore::remove_interest) for the
//! stale-`pushed` residual it closes.

use std::collections::HashMap;

use wz_session_core::keyexpr_match::keyexpr_intersects_target;
use wz_session_core::queryable_info::QueryableInfo;

use crate::accept_loop::FaceId;

/// The subscriber-plane store: presence-only (no value), so a pushed
/// `DeclareSubscriber` is never re-pushed.
pub type FutureSubStore = FutureInterestStore<()>;

/// The queryable-plane store: value-aware over [`QueryableInfo`], so a completeness
/// flip `false -> true` re-pushes the same id carrying the new (folded) value.
pub type FutureQablStore = FutureInterestStore<QueryableInfo>;

/// One CLIENT face's declared FUTURE interest: the RESOLVED literal target keyexpr
/// and whether the interest is AGGREGATE (a match reply is keyed on the interest
/// keyexpr, not the concrete declaration — pico matches an aggregate interest's
/// replies by keyexpr EQUALITY). Value-agnostic: the same shape for subs and qabls
/// (the value lives on the [`ClientFutureInterests::pushed`] side, not here).
#[derive(Debug, Clone)]
struct FutureInterest {
    target: String,
    aggregate: bool,
}

/// One CLIENT face's FUTURE interests + the declarations already pushed to it. See
/// the module docs for the zenoh mapping. `V` is `()` for subs, [`QueryableInfo`]
/// for queryables.
#[derive(Debug)]
struct ClientFutureInterests<V> {
    /// Declared FUTURE interests, keyed by the soliciting `interest_id`.
    interests: HashMap<u64, FutureInterest>,
    /// `reply keyexpr -> (decl id declared to this face, last-declared value)`
    /// (zenoh `face_hat.local_subs` / `local_qabls`). Seeded by the current dump
    /// (get-or-alloc, so a redundant re-declare REUSES the id) and by each FUTURE
    /// push. The value drives the re-push decision (a change re-pushes the SAME id).
    pushed: HashMap<String, (u64, V)>,
    /// Per-face monotonic decl-id source. Ids start at 1 (0 is a NON-future
    /// current-dump reply id and pico's declarations-propagation sentinel, so any
    /// interned id is `>= 1`) and are never recycled.
    next_id: u64,
}

// A manual `Default` (deriving it would demand `V: Default`, which is not needed —
// an empty store holds no value).
impl<V> Default for ClientFutureInterests<V> {
    fn default() -> Self {
        Self {
            interests: HashMap::new(),
            pushed: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<V: Copy + PartialEq> ClientFutureInterests<V> {
    /// Get-or-allocate the decl id for `reply_ke` carrying `value`, returning
    /// `(id, should_push)`. `should_push` is `true` when the reply ke is NEW (first
    /// declaration) or its value CHANGED (a value-aware re-push, same id, updated
    /// value); `false` when the same value was already declared (dedup). For
    /// `V = ()` a value never changes, so `should_push == is_new` — presence-only,
    /// the subscriber behavior.
    fn intern(&mut self, reply_ke: &str, value: V) -> (u64, bool) {
        match self.pushed.get_mut(reply_ke) {
            Some((id, stored)) => {
                let changed = *stored != value;
                if changed {
                    *stored = value;
                }
                (*id, changed)
            }
            None => {
                self.next_id += 1;
                let id = self.next_id;
                self.pushed.insert(reply_ke.to_owned(), (id, value));
                (id, true)
            }
        }
    }
}

/// The per-forwarder FUTURE-mode declare-interest store — the wz analogue of
/// zenoh's per-`FaceState` `remote_interests` + `face_hat.local_subs`/`local_qabls`,
/// keyed by the CLIENT [`FaceId`]. Both forwarders (router + peer) own one per plane
/// ([`FutureSubStore`] + [`FutureQablStore`]); the store logic is shared here.
#[derive(Debug)]
pub struct FutureInterestStore<V> {
    by_face: HashMap<FaceId, ClientFutureInterests<V>>,
}

impl<V> Default for FutureInterestStore<V> {
    fn default() -> Self {
        Self {
            by_face: HashMap::new(),
        }
    }
}

impl<V: Copy + PartialEq> FutureInterestStore<V> {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a CLIENT face's FUTURE interest for `target` (a resolved literal; a
    /// match-all interest is not stored — see the module docs). Keyed by
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
    /// carries for `reply_ke` (with the folded `value`), seeding `pushed` so a later
    /// FUTURE push of the same ke dedups (subs) or re-pushes on a value change
    /// (qabls). Always returns an id (the current dump reports the declaration
    /// whether or not the id is new). Call only after
    /// [`store_interest`](Self::store_interest) for the same face; an existing
    /// entry's id is reused (redundant re-declare stays idempotent on pico), and its
    /// stored value is REFRESHED to `value` so the seed matches what the dump emitted.
    pub fn intern_current_reply(&mut self, face: FaceId, reply_ke: &str, value: V) -> u64 {
        self.by_face
            .entry(face)
            .or_default()
            .intern(reply_ke, value)
            .0
    }

    /// A newly-learned declaration `new_ke` sourced at `origin` (`None` for a
    /// self-originated local declaration, which has no inbound face) — return the
    /// `(face, reply keyexpr, decl id, value)` FUTURE pushes to emit: one per stored
    /// interest whose target INTERSECTS `new_ke`, on a face other than `origin`,
    /// whose reply keyexpr (the interest ke for an aggregate interest, else
    /// `new_ke`) is NEW to that face OR whose value CHANGED.
    ///
    /// `value_of(reply_ke)` yields the value to declare for a given reply keyexpr —
    /// for the queryable plane this MUST be the RE-FOLDED merged [`QueryableInfo`]
    /// over ALL current matching queryables for THAT reply keyexpr (zenoh's
    /// `local_qabl_info`), which differs between an aggregate reply (folded over the
    /// whole interest target) and a concrete reply (folded for `new_ke`) — passing a
    /// single source's raw info would DOWNGRADE an aggregate reply and re-arm an
    /// ALL_COMPLETE filter. For the subscriber plane it is `|_| ()`. Interns each
    /// reply ke (updating the stored value), so a second matching interest on the
    /// same face and any later declaration for the same ke with the same value dedup.
    /// The caller builds the unsolicited `DeclareSubscriber`/`DeclareQueryable(id,
    /// reply_ke, value)` (interest_id `None`, no `I` flag) and sends it to `face`.
    /// `value_of(reply_ke, dest_face)` receives the DESTINATION face so a
    /// queryable-plane fold can EXCLUDE that face's own co-hosted queryable (zenoh's
    /// `local_qabl_info(res, dst_face)` is per-destination, and the wz current dump
    /// likewise excludes the requesting face) — so the CURRENT-dump seed and this
    /// later push are like-for-like and a querier that co-hosts a matching queryable
    /// gets no spurious re-push. The subscriber plane ignores both args (`|_, _| ()`).
    pub fn pushes_for_new<F: Fn(&str, FaceId) -> V>(
        &mut self,
        new_ke: &str,
        origin: Option<FaceId>,
        value_of: F,
    ) -> Vec<(FaceId, String, u64, V)> {
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
                let value = value_of(&reply_ke, *face);
                let (id, should_push) = state.intern(&reply_ke, value);
                if should_push {
                    out.push((*face, reply_ke, id, value));
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
    /// publisher/querier DROPPED (`net/filtering.c:_z_write_filter_clear` ->
    /// `_z_remove_interest`), so with no interests left the face has no
    /// publisher/querier and pico holds no write-filter — a retained `pushed` record
    /// would then wrongly DEDUP-SUPPRESS a push to a FUTURE publisher/querier on the
    /// same face (a later `store_interest` re-starts a fresh registry). While OTHER
    /// interests remain, `pushed` is kept — a shared reply ke may still back a live
    /// publisher/querier.
    ///
    /// RESIDUAL (CLOSED by the undeclare-push — R311y151 graceful + R311y152 detach,
    /// NOT a silent gap): a subscriber/queryable that WITHDRAWS while an interest is
    /// still live would leave the `pushed` entry stale, so a second publisher/querier
    /// on that ke declared during the absence could miss its re-push when the
    /// declaration reappears — and for the QUERYABLE plane strictly WORSE, the stale
    /// `(id, value)` also pinning a stale COMPLETENESS (an ALL_COMPLETE filter
    /// mis-armed). Both the GRACEFUL explicit-Undeclare (R311y151) and the UNGRACEFUL
    /// face-down / link-down / topology-detach (R311y152) now run
    /// [`forgets_for_withdrawn`](Self::forgets_for_withdrawn) → clear `pushed` + re-arm
    /// the filter (zenoh `propagate_forget_simple_subscription/_queryable`). The qabl
    /// completeness-DOWNGRADE on a PARTIAL withdrawal (the reply ke stays backed at a
    /// lower folded completeness) — case (c), a value-aware re-push rather than a
    /// `pushed`-clear — is CLOSED by
    /// [`re_pushes_for_withdrawn`](Self::re_pushes_for_withdrawn) (R311y153).
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

    /// A declaration for `withdrawn_ke` was WITHDRAWN (R311y151 undeclare-push) —
    /// return the `(face, reply keyexpr, decl id)` UNDECLARE pushes to emit and
    /// REMOVE their now-stale `pushed` entries: one per pushed reply ke that
    /// `withdrawn_ke` could have backed (they INTERSECT) AND is NO LONGER backed
    /// (`!still_backed(reply_ke)`). The caller must run this AFTER the withdrawn
    /// declaration is removed from its routing table, so `still_backed` reflects the
    /// post-withdrawal state (a reply ke backed by ANOTHER declaration must return
    /// `true` and NOT be undeclared — the aggregate multi-backer case). The caller
    /// builds an unsolicited `Undeclare{Subscriber,Queryable}(id)` (interest_id
    /// `None`) and sends it to `face`; clearing `pushed` re-arms the pico write-filter
    /// AND lets a later re-declaration of the ke re-push (the stale-`pushed` residual
    /// [`remove_interest`](Self::remove_interest) documents). Value-agnostic — an
    /// undeclare drops the entry regardless of `V` (the qabl value-downgrade on a
    /// PARTIAL withdrawal, where the reply ke stays backed, is a separate unit —
    /// [`re_pushes_for_withdrawn`](Self::re_pushes_for_withdrawn), R311y153 — NOT
    /// touched here, since this method is value-agnostic).
    pub fn forgets_for_withdrawn<B: Fn(&str) -> bool>(
        &mut self,
        withdrawn_ke: &str,
        still_backed: B,
    ) -> Vec<(FaceId, String, u64)> {
        let mut out = Vec::new();
        for (face, state) in self.by_face.iter_mut() {
            // Select the pushed reply kes the withdrawal could have un-backed (the
            // withdrawn ke intersects the reply ke) that are now unbacked — collect
            // before mutating `pushed` (the read borrow can't overlap the remove).
            let to_forget: Vec<String> = state
                .pushed
                .keys()
                .filter(|reply_ke| {
                    let chunks: Vec<&str> = reply_ke.split('/').collect();
                    keyexpr_intersects_target(withdrawn_ke, &chunks) && !still_backed(reply_ke)
                })
                .cloned()
                .collect();
            for reply_ke in to_forget {
                if let Some((id, _)) = state.pushed.remove(&reply_ke) {
                    out.push((*face, reply_ke, id));
                }
            }
        }
        out
    }

    /// After a withdrawal, RE-PUSH the value-aware DOWNGRADE — the value-aware twin of
    /// [`forgets_for_withdrawn`](Self::forgets_for_withdrawn) (case c, R311y153). For
    /// each STILL-PRESENT pushed reply ke that INTERSECTS `withdrawn_ke`, re-fold via
    /// `value_of` and, if the value CHANGED, emit `(face, reply keyexpr, decl id,
    /// new_value)` carrying the SAME interned id — the caller re-declares
    /// `DeclareQueryable(id, reply_ke, new_value)` so pico updates the `(decl_id, peer)`
    /// write-filter target in place. Call AFTER
    /// [`forgets_for_withdrawn`](Self::forgets_for_withdrawn) (the FULLY-unbacked reply
    /// kes are removed first, so the survivors this scans are still-backed) AND AFTER
    /// the withdrawn declaration left its routing table (so `value_of` re-folds the
    /// POST-withdrawal survivors). `value_of(reply_ke, dest_face)` receives the
    /// ITERATING face as `dest` — exactly as [`pushes_for_new`](Self::pushes_for_new) —
    /// so a per-destination fold excludes that face's own co-hosted declaration
    /// like-for-like (see [`crate::router_forward`] `merged_qabl_info`).
    ///
    /// Inert for `V = ()` — a `()` value never differs, so the SUBSCRIBER plane never
    /// downgrades (a `DeclareSubscriber` carries no value; only
    /// [`FutureQablStore`](crate::future_interest::FutureQablStore)'s `undeclare_push`
    /// drives this). Iterates `pushed` (the reply kes ALREADY declared to the face —
    /// zenoh `face_hat.local_qabls`), NOT `interests` (that is
    /// [`pushes_for_new`](Self::pushes_for_new)'s ingest domain): only an
    /// already-declared id can be downgraded in place. `intern`'s value-diff is the
    /// analogue of zenoh's `register_router_queryable` -> `propagate_simple_queryable`
    /// re-declare gate `current.unwrap().1 != info` (hat/router/queries.rs:255, reusing
    /// the same id `current.map(|c| c.0)` at :274-276), which fires on a partial
    /// node-removal via the `register_router_queryable(local_router_qabl_info)` call at
    /// queries.rs:930-940.
    pub fn re_pushes_for_withdrawn<F: Fn(&str, FaceId) -> V>(
        &mut self,
        withdrawn_ke: &str,
        value_of: F,
    ) -> Vec<(FaceId, String, u64, V)> {
        let mut out = Vec::new();
        for (face, state) in self.by_face.iter_mut() {
            // Collect the still-present pushed reply kes intersecting withdrawn_ke
            // BEFORE interning (the read borrow of `pushed` cannot overlap `intern`'s
            // mutable borrow) — the same collect-then-intern shape as `pushes_for_new`.
            let candidates: Vec<String> = state
                .pushed
                .keys()
                .filter(|reply_ke| {
                    let chunks: Vec<&str> = reply_ke.split('/').collect();
                    keyexpr_intersects_target(withdrawn_ke, &chunks)
                })
                .cloned()
                .collect();
            for reply_ke in candidates {
                let value = value_of(&reply_ke, *face);
                let (id, changed) = state.intern(&reply_ke, value);
                if changed {
                    out.push((*face, reply_ke, id, value));
                }
            }
        }
        out
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

    // ── SUBSCRIBER plane (V = ()): the R311y146 presence-only behavior, unchanged
    // by the R311y150 generic lift (a `()` value never differs, so the re-push logic
    // is inert — these prove the specialization is behavior-preserving). ──────────

    #[test]
    fn pub_before_sub_pushes_the_first_later_sub_with_a_non_zero_id() {
        // The raison d'être: an interest arrives with NO matching sub (empty
        // current dump seeds nothing), then a sub is learned later -> exactly one
        // push, id >= 1.
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let pushes = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert_eq!(pushes.len(), 1, "one push to the interest holder");
        let (f, reply_ke, id, ()) = &pushes[0];
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
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), false);
        let pushes = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert_eq!(pushes.len(), 1);
        assert_eq!(
            pushes[0].1, "demo/data",
            "non-aggregate replies with the concrete ke"
        );
    }

    #[test]
    fn a_second_sub_for_an_aggregate_interest_dedups() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let first = s.pushes_for_new("demo/a", Some(face(9)), |_, _| ());
        assert_eq!(first.len(), 1);
        let second = s.pushes_for_new("demo/b", Some(face(9)), |_, _| ());
        assert!(
            second.is_empty(),
            "a second sub under the same aggregate ke needs no new declare (filter already off)",
        );
    }

    #[test]
    fn a_non_matching_sub_pushes_nothing() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.pushes_for_new("other/key", Some(face(9)), |_, _| ())
                .is_empty(),
            "a sub outside the interest target is not pushed",
        );
    }

    #[test]
    fn a_sub_sourced_by_the_interest_holder_is_not_echoed() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.pushes_for_new("demo/data", Some(face(1)), |_, _| ())
                .is_empty(),
            "never push a declaration back to the face that sourced it",
        );
    }

    #[test]
    fn current_dump_seed_dedups_the_later_matching_push() {
        // A sub that existed at interest time is reported by the current dump
        // (intern_current_reply seeds `pushed`); a later re-learn of the SAME
        // aggregate ke must not double-declare.
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let seeded_id = s.intern_current_reply(face(1), "demo/**", ());
        assert!(seeded_id >= 1);
        assert!(
            s.pushes_for_new("demo/late", Some(face(9)), |_, _| ())
                .is_empty(),
            "the aggregate reply ke was already seeded by the current dump",
        );
    }

    #[test]
    fn two_interests_same_target_share_one_push() {
        // Two publishers on the same key -> two interests, one aggregate target ->
        // a single declaration covers both (pico fires every matching filter).
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/x".to_owned(), true);
        s.store_interest(face(1), 8, "demo/x".to_owned(), true);
        let pushes = s.pushes_for_new("demo/x", Some(face(9)), |_, _| ());
        assert_eq!(
            pushes.len(),
            1,
            "one reply ke -> one push, not one-per-interest"
        );
    }

    #[test]
    fn two_faces_each_get_their_own_push() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(2), 3, "demo/**".to_owned(), true);
        let mut pushes = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        pushes.sort_by_key(|(f, _, _, _)| f.0);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0].0, face(1));
        assert_eq!(pushes[1].0, face(2));
    }

    #[test]
    fn interest_final_removes_one_interest_and_stops_its_future_pushes() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.remove_interest(face(1), 7),
            "the stored interest is removed"
        );
        assert!(
            s.pushes_for_new("demo/data", Some(face(9)), |_, _| ())
                .is_empty(),
            "a removed interest attracts no further pushes",
        );
        assert!(!s.remove_interest(face(1), 7), "removing again is a no-op");
    }

    #[test]
    fn interest_final_of_the_last_interest_prunes_pushed() {
        // Removing the LAST interest (the publisher DROPPED — pico's write-filter is
        // gone) prunes the whole face, so a stale `pushed` entry cannot suppress a
        // push to a FUTURE publisher on the same face.
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
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
        let pushes = s.pushes_for_new("demo/late", Some(face(9)), |_, _| ());
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
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(1), 8, "other/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
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
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        s.store_interest(face(2), 3, "other/**".to_owned(), true);
        assert!(s.purge_face(face(1)));
        assert_eq!(s.face_count(), 1, "only face 2 remains");
        assert!(
            s.pushes_for_new("demo/data", Some(face(9)), |_, _| ())
                .is_empty(),
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
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), false);
        let a = s.pushes_for_new("demo/a", Some(face(9)), |_, _| ());
        let b = s.pushes_for_new("demo/b", Some(face(9)), |_, _| ());
        assert_eq!(a[0].2, 1, "first alloc is 1 (0 is reserved)");
        assert_eq!(b[0].2, 2, "second distinct ke gets a fresh id");
    }

    // ── QUERYABLE plane (V = QueryableInfo): the R311y150 VALUE-AWARE behavior the
    // subscriber store cannot have. ─────────────────────────────────────────────

    fn info(complete: bool) -> QueryableInfo {
        QueryableInfo {
            complete,
            distance: 0,
        }
    }

    #[test]
    fn querier_before_queryable_pushes_the_first_later_qabl() {
        // The query-plane presence hole (analog of pub-before-sub): a querier
        // solicits with no matching queryable, then one is learned later -> one push.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let pushes = s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(false));
        assert_eq!(pushes.len(), 1, "one push to the interest holder");
        let (f, reply_ke, id, v) = &pushes[0];
        assert_eq!(*f, face(1));
        assert_eq!(
            reply_ke, "demo/**",
            "aggregate reply keyed on the interest ke"
        );
        assert!(*id >= 1);
        assert_eq!(*v, info(false), "carries the queryable's (folded) info");
    }

    #[test]
    fn complete_flip_false_to_true_re_pushes_the_same_id() {
        // A Z_QUERY_TARGET_ALL_COMPLETE querier's filter deactivates only on a
        // complete reply. Seed an incomplete current reply; a later fold flip to
        // complete=true must RE-push the SAME id with the new value.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let seeded_id = s.intern_current_reply(face(1), "demo/**", info(false));
        assert!(seeded_id >= 1);
        // Fold now complete=true (a complete queryable learned/merged in).
        let pushes = s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(true));
        assert_eq!(pushes.len(), 1, "the completeness flip re-pushes");
        assert_eq!(pushes[0].2, seeded_id, "re-push reuses the SAME decl id");
        assert_eq!(
            pushes[0].3,
            info(true),
            "carries the new complete=true value"
        );
    }

    #[test]
    fn same_value_qabl_dedups_no_re_push() {
        // Once complete=true is declared, a later fold that is STILL complete=true
        // (a second complete source, no change) does NOT re-push.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.intern_current_reply(face(1), "demo/**", info(true));
        assert!(
            s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(true))
                .is_empty(),
            "no value change -> no re-push (presence dedup on the value)",
        );
    }

    #[test]
    fn value_change_true_to_false_re_pushes_same_id() {
        // The store re-pushes on ANY value change, including a DOWNGRADE — correct,
        // because a genuine fold downgrade must re-arm an ALL_COMPLETE filter. The
        // fold is monotonic-up when a NEW source is ADDED (merge = OR-complete), so
        // an add-ingest never fires this arm; but a same-source completeness
        // DOWNGRADE re-declare (true->false) IS a value-diff ingest that fires it
        // (correctly), and the y151 undeclare (a complete source WITHDRAWS) is the
        // other downgrade path — both reuse this change-symmetric store.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let id0 = s.intern_current_reply(face(1), "demo/**", info(true));
        let pushes = s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(false));
        assert_eq!(pushes.len(), 1, "a value change re-pushes");
        assert_eq!(pushes[0].2, id0, "same id");
        assert_eq!(pushes[0].3, info(false), "carries the changed value");
    }

    #[test]
    fn qabl_interest_final_and_purge_mirror_the_sub_plane() {
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(false));
        assert_eq!(s.pushed_count(face(1)), 1);
        assert!(s.remove_interest(face(1), 7));
        assert_eq!(s.face_count(), 0, "last interest gone -> face pruned");
        // A fresh querier on the same face is not suppressed by the pruned registry.
        s.store_interest(face(1), 9, "demo/**".to_owned(), true);
        assert_eq!(
            s.pushes_for_new("demo/late", Some(face(9)), |_, _| info(false))
                .len(),
            1,
        );
    }

    // ── undeclare-push (R311y151): the withdrawal side. ──────────────────────────

    #[test]
    fn withdrawal_of_the_last_backer_undeclares_and_clears_pushed() {
        // A sub was pushed to a waiting publisher; when the LAST backing sub
        // withdraws (still_backed=false), the store returns the undeclare + clears
        // the stale `pushed` entry (so the pico write-filter re-arms).
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let pushed = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert_eq!(pushed.len(), 1);
        let pushed_id = pushed[0].2;
        let forgets = s.forgets_for_withdrawn("demo/data", |_| false);
        assert_eq!(forgets.len(), 1, "the unbacked reply ke is undeclared");
        assert_eq!(forgets[0].0, face(1));
        assert_eq!(
            forgets[0].1, "demo/**",
            "undeclare keyed on the aggregate reply ke"
        );
        assert_eq!(
            forgets[0].2, pushed_id,
            "undeclare carries the pushed decl id"
        );
        assert_eq!(
            s.pushed_count(face(1)),
            0,
            "the stale pushed entry is cleared"
        );
    }

    #[test]
    fn withdrawal_while_still_backed_does_not_undeclare() {
        // demo/a withdraws but demo/b still backs the aggregate demo/** -> NO
        // undeclare (still_backed=true), the pushed entry is kept.
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/a", Some(face(9)), |_, _| ());
        assert!(
            s.forgets_for_withdrawn("demo/a", |_| true).is_empty(),
            "a reply ke still backed by another sub is not undeclared",
        );
        assert_eq!(s.pushed_count(face(1)), 1, "the pushed entry is retained");
    }

    #[test]
    fn cleared_pushed_lets_a_later_re_declaration_re_push() {
        // The residual the undeclare-push closes: after a withdrawal clears `pushed`,
        // a LATER re-declaration of the same ke re-pushes (a stale entry would have
        // dedup-suppressed it).
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert_eq!(s.forgets_for_withdrawn("demo/data", |_| false).len(), 1);
        // The sub reappears -> re-push (not suppressed by a stale pushed entry).
        let re = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert_eq!(
            re.len(),
            1,
            "the reappearing sub re-pushes after the undeclare"
        );
    }

    #[test]
    fn a_non_intersecting_withdrawal_is_a_no_op() {
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.pushes_for_new("demo/data", Some(face(9)), |_, _| ());
        assert!(
            s.forgets_for_withdrawn("other/key", |_| false).is_empty(),
            "a withdrawal outside the pushed reply ke does not undeclare",
        );
        assert_eq!(s.pushed_count(face(1)), 1);
    }

    #[test]
    fn qabl_withdrawal_undeclares_value_agnostically() {
        // The qabl twin: an undeclare drops the pushed (id, info) entry regardless of
        // the stored completeness value.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let pushed = s.pushes_for_new("demo/svc", Some(face(9)), |_, _| info(true));
        assert_eq!(pushed.len(), 1);
        let forgets = s.forgets_for_withdrawn("demo/svc", |_| false);
        assert_eq!(forgets.len(), 1);
        assert_eq!(
            forgets[0].2, pushed[0].2,
            "undeclare carries the pushed qabl id"
        );
        assert_eq!(s.pushed_count(face(1)), 0);
    }

    // ── re-push on partial-withdrawal DOWNGRADE (R311y153, case c): a queryable
    // withdraws but the reply ke STAYS backed at a lower folded completeness. ──────

    #[test]
    fn re_pushes_downgrades_a_still_backed_reply_ke_same_id() {
        // Seed complete=true (a complete backer folded in); on a withdrawal the fold
        // re-computes to complete=false (only incomplete survivors) -> re-push the SAME
        // id with the downgraded value so an ALL_COMPLETE filter re-arms.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let id0 = s.intern_current_reply(face(1), "demo/**", info(true));
        let re = s.re_pushes_for_withdrawn("demo/svc", |_rk, _dest| info(false));
        assert_eq!(re.len(), 1, "the downgrade re-pushes");
        let (f, reply_ke, id, v) = &re[0];
        assert_eq!(*f, face(1));
        assert_eq!(reply_ke, "demo/**", "keyed on the aggregate reply ke");
        assert_eq!(*id, id0, "re-push reuses the SAME interned id");
        assert_eq!(*v, info(false), "carries the DOWNGRADED folded value");
    }

    #[test]
    fn re_pushes_with_no_value_change_is_inert() {
        // A withdrawal that does NOT move the fold (a redundant/incomplete source left)
        // re-folds to the SAME value -> no re-push (the intern value-diff dedup).
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.intern_current_reply(face(1), "demo/**", info(true));
        assert!(
            s.re_pushes_for_withdrawn("demo/svc", |_rk, _dest| info(true))
                .is_empty(),
            "an unchanged fold does not re-push",
        );
    }

    #[test]
    fn re_pushes_is_inert_on_the_subscriber_plane() {
        // V = () never differs, so the subscriber store never downgrades (only the
        // qabl plane's undeclare_push drives this; the specialization is provably inert).
        let mut s = FutureSubStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.intern_current_reply(face(1), "demo/**", ());
        assert!(
            s.re_pushes_for_withdrawn("demo/svc", |_rk, _dest| ())
                .is_empty(),
            "a () value never differs -> the subscriber plane never re-pushes",
        );
    }

    #[test]
    fn re_pushes_skips_a_non_intersecting_withdrawal() {
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        let _ = s.intern_current_reply(face(1), "demo/**", info(true));
        assert!(
            s.re_pushes_for_withdrawn("other/key", |_rk, _dest| info(false))
                .is_empty(),
            "a withdrawal outside the pushed reply ke does not re-fold it",
        );
    }

    #[test]
    fn re_pushes_only_touches_already_declared_reply_kes() {
        // Iterates `pushed` (declared), NOT `interests`: an interest with NO pushed
        // reply ke (nothing was ever declared to the face) yields no re-push, since
        // there is no id for pico to downgrade in place.
        let mut s = FutureQablStore::new();
        s.store_interest(face(1), 7, "demo/**".to_owned(), true);
        assert!(
            s.re_pushes_for_withdrawn("demo/svc", |_rk, _dest| info(false))
                .is_empty(),
            "no pushed reply ke -> nothing to downgrade",
        );
    }
}
