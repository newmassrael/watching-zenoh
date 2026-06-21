// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer interest table (P4 routing, step c3c-3 atom2) — which
//! PEERS are interested in which key expression. ONE generic table type,
//! instantiated TWICE by the forwarder: once for subscriptions
//! (`DeclareSubscriber` interest, the data-route filter) and once for
//! queryables (`DeclareQueryable` interest, the query-route filter). The two
//! interest planes are structurally identical here — a keyexpr -> interested
//! peer-set map with the same register / withdraw / face-down-purge / wildcard
//! matching mechanics — so they share this one SSOT type rather than two clones.
//!
//! The wz analogue of zenoh's per-`Resource` `linkstatepeer_subs:
//! HashSet<ZenohIdProto>` AND `linkstatepeer_qabls: HashMap<ZenohIdProto, ..>`
//! (`hat/linkstate_peer/mod.rs:515,517`) — zenoh keeps BOTH interest sets as the
//! same per-resource peer-keyed shape, off the topology `Network` (they hang on
//! the routing `Resource` in the HAT). wz mirrors that separation: the topology
//! graph is the pure [`wz_routing_graph::LinkstateNetwork`], and these interest
//! tables are SEPARATE structures the forwarder (the HAT analogue) owns
//! alongside it. Pure host data — no async, no graph coupling beyond the
//! [`Zid`] key type.
//!
//! How it is driven: a sourced `DeclareSubscriber` / `DeclareQueryable` arriving
//! from the mesh [`register`](LinkstatepeerInterest::register)s the advertising
//! peer's interest (c3c-3 atom3); the route filter reads
//! [`interested_remote`](LinkstatepeerInterest::interested_remote) and feeds the
//! peer set to [`wz_routing_graph::LinkstateNetwork::directions_toward`] so a
//! Push (subs) / Query (qabls) is replicated only toward subtrees holding an
//! interested peer — the bounded fan-out that replaces a
//! broadcast-to-every-tree-child.
//!
//! Single set, filter on read (zenoh-faithful): this node's OWN declaration is
//! registered into the SAME set under its own zid — exactly as zenoh's
//! `declare_simple_subscription` / `declare_simple_queryable` call
//! `register_linkstatepeer_*(.., tables.zid, ..)`. The "remote-only" view the
//! route needs is DERIVED by filtering self at read time
//! ([`interested_remote`](LinkstatepeerInterest::interested_remote), mirroring
//! zenoh's `remote_linkstatepeer_subs`), not by keeping a second structure. So
//! "what is declared" has ONE source of truth: self-origination and remote
//! interest are the same datum, distinguished by zid, and the tree-change
//! re-advertise iterates them uniformly.
//!
//! Wildcard matching (c3c-3 B2): a lookup is the key-expression INTERSECTION
//! of the published key against every registered declaration keyexpr, via the
//! shared [`keyexpr_intersects_target`] scan SSOT — the same per-candidate
//! membership test the local [`SubscriberRegistry`](wz_session_core::SubscriberRegistry)
//! uses through `declared_intersects` (zenoh's intersection route matching,
//! `Resource::get_matches`). So a `demo/**` or
//! `demo/*` declaration now attracts a concrete `demo/data` lookup, while a
//! literal declaration stays exact. STILL deferred (a performance, not a
//! correctness, concern): zenoh folds declarations into a prefix RESOURCE
//! TREE for sublinear matching; wz does an O(declarations) scan per lookup,
//! which is correct but linear — the tree is a tracked optimisation for large
//! interest sets, not modelled here.

use std::collections::{HashMap, HashSet};

use wz_routing_graph::Zid;
use wz_session_core::keyexpr_match::keyexpr_intersects_target;

/// Per-key-expression set of interested PEER zids — the linkstate-peer
/// interest table, instantiated once per interest plane (subscriptions,
/// queryables). See the module docs for the zenoh mapping and the exact-match
/// MVP scope.
#[derive(Debug, Default)]
pub struct LinkstatepeerInterest {
    /// declared keyexpr (a literal OR a `*`/`**` pattern) -> the peers that
    /// declared interest in it. A key is present only while at least one peer
    /// is interested: the last peer's [`remove_peer`](Self::remove_peer) prunes
    /// the entry. A lookup matches a published / queried key against these keys
    /// by keyexpr INTERSECTION ([`matching_peers`](Self::matching_peers)), so a
    /// `demo/**` key attracts a `demo/data` lookup.
    by_key: HashMap<String, HashSet<Zid>>,
}

impl LinkstatepeerInterest {
    /// An empty interest table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` is interested in `keyexpr` — a sourced
    /// `DeclareSubscriber` / `DeclareQueryable` from the mesh, or a redundant
    /// re-declare. Idempotent. Returns `true` if this NEWLY added the interest (a
    /// real change the caller may need to act on — re-propagate the declaration
    /// onward, recompute a route), `false` if the peer was already
    /// recorded for that key. Mirrors zenoh
    /// `register_linkstatepeer_subscription` / `register_linkstatepeer_queryable`'s
    /// `linkstatepeer_{subs,qabls}.insert`.
    pub fn register(&mut self, keyexpr: &str, peer: Zid) -> bool {
        self.by_key
            .entry(keyexpr.to_owned())
            .or_default()
            .insert(peer)
    }

    /// Withdraw `peer`'s interest in ONE `keyexpr` — a sourced
    /// `UndeclareSubscriber` arriving from the mesh while the peer's face stays
    /// up (the per-keyexpr retraction, vs [`remove_peer`](Self::remove_peer)'s
    /// whole-peer face-down purge). Idempotent. Returns `true` if the peer WAS
    /// interested (a real change the caller re-propagates onward — re-flood the
    /// retraction, recompute a data route), `false` if it held no such interest
    /// (already gone / never declared). The emptied key is pruned, so
    /// [`interested`](Self::interested) of a fully-unsubscribed key is empty.
    /// Mirrors zenoh `unregister_peer_subscription`'s
    /// `linkstatepeer_subs.retain(|p| p != peer)` + empty-set cleanup.
    pub fn withdraw(&mut self, keyexpr: &str, peer: &Zid) -> bool {
        let Some(set) = self.by_key.get_mut(keyexpr) else {
            return false;
        };
        let removed = set.remove(peer);
        if set.is_empty() {
            self.by_key.remove(keyexpr);
        }
        removed
    }

    /// Drop ALL of `peer`'s interests across every key — called from the
    /// forwarder's `deregister` when a peer's face goes down, so stale interest
    /// never keeps a departed subscriber / queryable armed in the route gate.
    /// Returns the number of keys the peer was dropped from; emptied keys are
    /// pruned. Mirrors zenoh's `pubsub_remove_node` / `queries_remove_node`
    /// link-down purge (`hat/linkstate_peer/mod.rs`). (A per-keyexpr undeclare
    /// while the face stays up — `UndeclareSubscriber`, or `UndeclareQueryable`
    /// once the codec carries an ext_keyexpr — is a separate tracked deferral;
    /// only whole-peer departure is wired for queryables so far.)
    pub fn remove_peer(&mut self, peer: &Zid) -> usize {
        let mut dropped = 0;
        self.by_key.retain(|_key, set| {
            if set.remove(peer) {
                dropped += 1;
            }
            !set.is_empty()
        });
        dropped
    }

    /// Every `(keyexpr, interested-peer)` pair, as an owned snapshot — the input
    /// to the tree-change re-advertise (c3c-3 debt A2). On a topology change the
    /// forwarder re-floods each pair's `DeclareSubscriber` / `DeclareQueryable`
    /// (sourced from the peer) toward that peer's recomputed tree children, so a
    /// node that joined AFTER the declaration still learns it (zenoh
    /// `pubsub_tree_change` / `queries_tree_change`). Owned (`String` / `Zid`
    /// clones) so the caller can re-flood without holding this table's borrow
    /// across a graph borrow. Order is unspecified (`HashMap` / `HashSet`
    /// iteration); the receiver change-gate dedups, so order is moot.
    pub fn entries(&self) -> Vec<(String, Zid)> {
        self.by_key
            .iter()
            .flat_map(|(key, peers)| peers.iter().map(move |p| (key.clone(), *p)))
            .collect()
    }

    /// The distinct peers whose subscription keyexpr INTERSECTS `target` (the
    /// published key), optionally excluding `exclude` (this node's own zid).
    /// Wildcard-aware: a `demo/**` subscription matches a concrete `demo/data`
    /// target via the shared [`keyexpr_intersects_target`] scan SSOT — the same
    /// per-candidate membership test the local subscriber registry uses (zenoh's
    /// intersection route matching). An O(subscriptions) scan; the resource-tree
    /// fold for sublinear matching is a tracked performance deferral, and that
    /// shared helper is the single seam it would land behind (see the module
    /// docs). Note: this runs on
    /// the DATA path ([`interested_remote`](Self::interested_remote) is called
    /// per forwarded Push / publish), so it is a per-message keyexpr-intersection
    /// scan, not the prior single `HashMap::get`. A literal target against a
    /// literal key reduces to byte equality, so exact interest is unchanged.
    /// Peers are deduped across multiple matching keys via a `HashSet` (`Zid` is
    /// `Copy + Hash`), not an O(matches²) linear membership scan.
    fn matching_peers(&self, target: &str, exclude: Option<&Zid>) -> Vec<Zid> {
        // A malformed target (an empty chunk, e.g. a trailing '/') matches no
        // peer: the shared `keyexpr_intersects_target` rejects it at the matcher
        // (zenoh compute_data_route parity), so the scan below yields the empty
        // set. The invariant is single-sourced in the matcher, not re-guarded
        // here — see `wz_session_core::keyexpr_match::target_chunks_well_formed`.
        // Split the published target ONCE, then test each registered subscription
        // keyexpr via the shared keyexpr-scan SSOT (the same per-candidate
        // membership test the local registry's `declared_intersects` uses).
        let target_chunks: Vec<&str> = target.split('/').collect();
        let mut out: HashSet<Zid> = HashSet::new();
        for (sub, peers) in &self.by_key {
            if keyexpr_intersects_target(sub, &target_chunks) {
                out.extend(peers.iter().filter(|p| exclude != Some(*p)).copied());
            }
        }
        out.into_iter().collect()
    }

    /// The peers interested in `keyexpr`, as a snapshot — every interested peer
    /// INCLUDING this node itself when it has a local subscription (`register`ed
    /// with its own zid). Matches by keyexpr intersection (a `demo/**` key
    /// answers a `demo/data` lookup). The tree-change re-advertise uses this
    /// whole view; the data-route filter uses
    /// [`interested_remote`](Self::interested_remote) instead (it must exclude
    /// self). Order is unspecified (`HashMap` iteration); a snapshot `Vec` (not a
    /// borrow) so the caller can hold it across a graph borrow.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.matching_peers(keyexpr, None)
    }

    /// The peers interested in `keyexpr` EXCLUDING `self_zid` — the snapshot the
    /// data-route filter passes to
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// Mirrors zenoh's `remote_linkstatepeer_subs` (`.any(|peer| peer !=
    /// &tables.zid)`): the interest set is the single SSOT that holds self AND
    /// remote peers, and the "remote-only" view is derived by filtering self at
    /// READ time — not by maintaining a second structure. A data Push is replicated
    /// toward each REMOTE subscriber's subtree; self is the local sink (delivered
    /// by the session layer, not over the mesh), so it is excluded from the
    /// forward directions. Wildcard-aware (see [`interested`](Self::interested)).
    pub fn interested_remote(&self, keyexpr: &str, self_zid: &Zid) -> Vec<Zid> {
        self.matching_peers(keyexpr, Some(self_zid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b, b, b, b])
    }

    #[test]
    fn register_is_idempotent_and_reports_change() {
        let mut subs = LinkstatepeerInterest::new();
        assert!(
            subs.register("demo/data", zid(0xAA)),
            "first interest is a change"
        );
        assert!(
            !subs.register("demo/data", zid(0xAA)),
            "re-declaring the same peer is a no-op"
        );
        assert!(
            subs.register("demo/data", zid(0xBB)),
            "a second distinct peer is a change"
        );
        let mut got = subs.interested("demo/data");
        got.sort();
        assert_eq!(got, vec![zid(0xAA), zid(0xBB)]);
    }

    #[test]
    fn a_literal_subscription_stays_exact() {
        // B2 widens matching to wildcards, but a LITERAL subscription must still
        // be exact: `demo/data` must NOT answer for a sibling or a prefix key
        // (intersection of two literals reduces to byte equality).
        let mut subs = LinkstatepeerInterest::new();
        subs.register("demo/data", zid(0xAA));
        assert_eq!(subs.interested("demo/data"), vec![zid(0xAA)]);
        assert!(
            subs.interested("demo/other").is_empty(),
            "a sibling key has no interest"
        );
        assert!(
            subs.interested("demo").is_empty(),
            "a prefix key does not match a literal subscription"
        );
    }

    #[test]
    fn a_wildcard_subscription_attracts_a_concrete_publish() {
        // B2: `**` (any depth) and `*` (one chunk) subscriptions now attract a
        // concrete Push by keyexpr intersection — the exact-match MVP missed it.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("demo/**", zid(0xAA));
        subs.register("demo/*", zid(0xBB));
        subs.register("other/**", zid(0xCC));
        let mut got = subs.interested("demo/data");
        got.sort();
        assert_eq!(
            got,
            vec![zid(0xAA), zid(0xBB)],
            "demo/** and demo/* cover demo/data; other/** does not"
        );
        // `**` spans depth, `*` is a single chunk.
        assert_eq!(
            subs.interested("demo/a/b"),
            vec![zid(0xAA)],
            "only ** spans the extra chunk"
        );
        // interested_remote applies the same matching, then drops self.
        assert_eq!(
            subs.interested_remote("demo/data", &zid(0xAA)),
            vec![zid(0xBB)],
            "wildcard match minus the self subscriber AA"
        );
    }

    #[test]
    fn a_peer_matching_via_two_patterns_appears_once() {
        // A peer subscribed via two keys that both cover the published key is
        // deduped across the matching keys.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("demo/**", zid(0xAA));
        subs.register("demo/data", zid(0xAA));
        assert_eq!(
            subs.interested("demo/data"),
            vec![zid(0xAA)],
            "peer AA matches both keys but appears once"
        );
    }

    #[test]
    fn remove_peer_drops_interest_across_all_keys() {
        // A departed peer (face down) must lose interest everywhere, and a
        // key it was the sole subscriber of is pruned while a shared key
        // survives with the remaining peer.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("a", zid(0xAA));
        subs.register("b", zid(0xAA));
        subs.register("b", zid(0xBB));
        let dropped = subs.remove_peer(&zid(0xAA));
        assert_eq!(dropped, 2, "peer AA was interested in both keys");
        assert!(
            subs.interested("a").is_empty(),
            "sole-subscriber key 'a' pruned"
        );
        assert_eq!(
            subs.interested("b"),
            vec![zid(0xBB)],
            "shared key 'b' survives with the remaining peer"
        );
        // removing the same (already-gone) peer drops nothing.
        assert_eq!(subs.remove_peer(&zid(0xAA)), 0, "no-op for an absent peer");
    }

    #[test]
    fn withdraw_removes_one_key_and_reports_change() {
        // A per-keyexpr retraction drops only the named key's interest; a
        // co-subscribed key survives, and the change-gate reports the removal.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("a", zid(0xAA));
        subs.register("b", zid(0xAA));
        assert!(subs.withdraw("a", &zid(0xAA)), "peer was interested in 'a'");
        assert!(
            subs.interested("a").is_empty(),
            "sole-subscriber key 'a' pruned"
        );
        assert_eq!(
            subs.interested("b"),
            vec![zid(0xAA)],
            "co-subscribed key 'b' survives",
        );
    }

    #[test]
    fn withdraw_keeps_a_co_interested_peer() {
        // Withdrawing one peer leaves a key alive while another peer still wants
        // it — only the withdrawing peer's interest goes.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("k", zid(0xAA));
        subs.register("k", zid(0xBB));
        assert!(subs.withdraw("k", &zid(0xAA)));
        assert_eq!(
            subs.interested("k"),
            vec![zid(0xBB)],
            "key 'k' survives with the remaining peer BB",
        );
    }

    #[test]
    fn withdraw_is_idempotent_for_absent_interest() {
        // Withdrawing an interest never held (unknown key, or a peer that never
        // declared it) is a no-op the change-gate reports as false.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("k", zid(0xAA));
        // A peer that never declared 'k', and an unknown key, both report no
        // change.
        assert!(!subs.withdraw("k", &zid(0xBB)), "BB never declared 'k'");
        assert!(
            !subs.withdraw("other", &zid(0xAA)),
            "no interest in an unknown key",
        );
        // A real withdraw of AA empties + prunes 'k'; a second is a no-op.
        assert!(subs.withdraw("k", &zid(0xAA)), "AA's real interest removed");
        assert!(
            subs.interested("k").is_empty(),
            "sole subscriber pruned the key"
        );
        assert!(
            !subs.withdraw("k", &zid(0xAA)),
            "key already pruned -> no change"
        );
    }

    #[test]
    fn subscriptions_snapshots_every_keyexpr_peer_pair() {
        // The tree-change re-advertise input: one (keyexpr, peer) entry per
        // interested peer per key, across all keys.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("demo/a", zid(0xAA));
        subs.register("demo/a", zid(0xBB));
        subs.register("demo/b", zid(0xAA));
        let mut got = subs.entries();
        got.sort();
        let mut want = vec![
            ("demo/a".to_owned(), zid(0xAA)),
            ("demo/a".to_owned(), zid(0xBB)),
            ("demo/b".to_owned(), zid(0xAA)),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(
            LinkstatepeerInterest::new().entries().is_empty(),
            "an empty table yields no pairs"
        );
    }

    #[test]
    fn interested_remote_filters_out_self() {
        // The data-route view excludes this node's OWN subscription (zenoh
        // remote_linkstatepeer_subs): self is the local sink, delivered by the
        // session layer, not forwarded toward over the mesh.
        let mut subs = LinkstatepeerInterest::new();
        let me = zid(0x05);
        subs.register("k", me); // self subscribes
        subs.register("k", zid(0xAA)); // and a remote peer
        let mut all = subs.interested("k");
        all.sort();
        assert_eq!(
            all,
            vec![zid(0x05), zid(0xAA)],
            "interested() is the single set: self + remote"
        );
        assert_eq!(
            subs.interested_remote("k", &me),
            vec![zid(0xAA)],
            "interested_remote() drops self, keeps the remote peer",
        );
        // A key only self subscribes to has no remote forward target.
        subs.register("self-only", me);
        assert!(
            subs.interested_remote("self-only", &me).is_empty(),
            "a self-only subscription yields no remote direction",
        );
    }

    #[test]
    fn a_trailing_slash_target_matches_no_peer() {
        // zenoh compute_data_route guard (pubsub.rs:948): a published key ending
        // in '/' is malformed (a trailing empty chunk). It must reach no peer --
        // not even a `**` subscriber, whose backtrack would otherwise absorb the
        // empty chunk and spuriously match. The control confirms the SAME `**`
        // subscription answers the well-formed key.
        let mut subs = LinkstatepeerInterest::new();
        subs.register("demo/**", zid(0xAA));
        assert!(
            subs.interested("demo/data/").is_empty(),
            "a trailing-slash target intersects no subscription",
        );
        assert_eq!(
            subs.interested("demo/data"),
            vec![zid(0xAA)],
            "the well-formed key still matches the `**` subscription",
        );
    }
}
