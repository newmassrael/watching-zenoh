// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer subscription interest table (P4 routing, step c3c-3
//! atom2) — which PEERS are interested in which key expression.
//!
//! The wz analogue of zenoh's per-`Resource` `linkstatepeer_subs:
//! HashSet<ZenohIdProto>` (`hat/linkstate_peer/mod.rs:515`). zenoh keeps
//! this interest set OFF the topology `Network` (it hangs on the routing
//! `Resource` in the HAT), so wz mirrors that separation: the topology graph
//! is the pure [`wz_routing_graph::LinkstateNetwork`], and this interest
//! table is a SEPARATE structure the forwarder (the HAT analogue) owns
//! alongside it. Pure host data — no async, no graph coupling beyond the
//! [`Zid`] key type.
//!
//! How it is driven: a sourced `DeclareSubscriber` arriving from the mesh
//! [`register`](LinkstatepeerSubs::register)s the advertising peer's
//! interest (c3c-3 atom3); the data-route filter (c3c-3 atom4) reads
//! [`interested_remote`](LinkstatepeerSubs::interested_remote) and feeds the
//! peer set to [`wz_routing_graph::LinkstateNetwork::directions_toward`] so a
//! Push is replicated only toward subtrees holding an interested subscriber —
//! the bounded fan-out that replaces the current broadcast-to-every-tree-child.
//!
//! Single set, filter on read (zenoh-faithful): this node's OWN subscription is
//! registered into the SAME set under its own zid — exactly as zenoh's
//! `declare_simple_subscription` calls `register_linkstatepeer_subscription(..,
//! tables.zid, ..)`. The "remote-only" view the data route needs is DERIVED by
//! filtering self at read time ([`interested_remote`](LinkstatepeerSubs::interested_remote),
//! mirroring zenoh's `remote_linkstatepeer_subs`), not by keeping a second
//! structure. So "what is subscribed" has ONE source of truth: self-origination
//! and remote interest are the same datum, distinguished by zid, and the
//! tree-change re-advertise iterates them uniformly.
//!
//! MVP scope (honest): keys match by EXACT string equality. zenoh matches
//! by full key-expression INTERSECTION over a resource tree (`*` / `**`
//! wildcards, prefix folding); that resource-tree keyexpr matching is a
//! tracked deferral, not modelled here. So a `demo/**` subscription does
//! NOT (yet) attract `demo/data` data through this table — only an exact
//! `demo/data` interest does.

use std::collections::{HashMap, HashSet};

use wz_routing_graph::Zid;

/// Per-key-expression set of interested PEER zids — the linkstate-peer
/// subscription interest table. See the module docs for the zenoh mapping
/// and the exact-match MVP scope.
#[derive(Debug, Default)]
pub struct LinkstatepeerSubs {
    /// keyexpr (exact string) -> the peers that declared interest in it.
    /// A key is present only while at least one peer is interested: the last
    /// peer's [`remove_peer`](Self::remove_peer) prunes the entry, so
    /// [`interested`](Self::interested) of an unsubscribed key is empty.
    by_key: HashMap<String, HashSet<Zid>>,
}

impl LinkstatepeerSubs {
    /// An empty interest table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` is interested in `keyexpr` — a sourced
    /// `DeclareSubscriber` from the mesh, or a redundant re-declare.
    /// Idempotent. Returns `true` if this NEWLY added the interest (a real
    /// change the caller may need to act on — re-propagate the declaration
    /// onward, recompute a data route), `false` if the peer was already
    /// recorded for that key. Mirrors zenoh
    /// `register_linkstatepeer_subscription`'s `linkstatepeer_subs.insert`.
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
    /// never keeps a departed subscriber armed in the publisher's any-interest
    /// gate. Returns the number of keys the peer was dropped from; emptied keys
    /// are pruned. Mirrors zenoh's `pubsub_remove_node` link-down purge
    /// (`hat/linkstate_peer/mod.rs`). (A per-keyexpr undeclare —
    /// `UndeclareSubscriber` while the face stays up — is a separate tracked
    /// deferral; only whole-peer departure is wired so far.)
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
    /// forwarder re-floods each pair's `DeclareSubscriber` (sourced from the
    /// peer) toward that peer's recomputed tree children, so a node that joined
    /// AFTER the declaration still learns it (zenoh `pubsub_tree_change`). Owned
    /// (`String` / `Zid` clones) so the caller can re-flood without holding this
    /// table's borrow across a graph borrow. Order is unspecified (`HashMap` /
    /// `HashSet` iteration); the receiver change-gate dedups, so order is moot.
    pub fn subscriptions(&self) -> Vec<(String, Zid)> {
        self.by_key
            .iter()
            .flat_map(|(key, peers)| peers.iter().map(move |p| (key.clone(), p.clone())))
            .collect()
    }

    /// The peers interested in `keyexpr` (EXACT match), as a snapshot — every
    /// interested peer INCLUDING this node itself when it has a local
    /// subscription (`register`ed with its own zid). The tree-change re-advertise
    /// uses this whole view; the data-route filter uses
    /// [`interested_remote`](Self::interested_remote) instead (it must exclude
    /// self). Order is unspecified (`HashSet` iteration); a snapshot `Vec` (not a
    /// borrow) so the caller can hold it across a graph borrow.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.by_key
            .get(keyexpr)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
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
    /// forward directions.
    pub fn interested_remote(&self, keyexpr: &str, self_zid: &Zid) -> Vec<Zid> {
        self.by_key
            .get(keyexpr)
            .map(|set| set.iter().filter(|p| *p != self_zid).cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: u8) -> Zid {
        vec![b, b, b, b]
    }

    #[test]
    fn register_is_idempotent_and_reports_change() {
        let mut subs = LinkstatepeerSubs::new();
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
    fn interest_is_keyed_exactly_not_by_prefix() {
        // MVP exact-match: a `demo/data` interest must NOT answer for a
        // different (even prefix-related) key. Wildcard intersection is the
        // tracked deferral.
        let mut subs = LinkstatepeerSubs::new();
        subs.register("demo/data", zid(0xAA));
        assert_eq!(subs.interested("demo/data"), vec![zid(0xAA)]);
        assert!(
            subs.interested("demo/other").is_empty(),
            "a sibling key has no interest"
        );
        assert!(
            subs.interested("demo").is_empty(),
            "a prefix key does not match (no resource-tree folding yet)"
        );
    }

    #[test]
    fn remove_peer_drops_interest_across_all_keys() {
        // A departed peer (face down) must lose interest everywhere, and a
        // key it was the sole subscriber of is pruned while a shared key
        // survives with the remaining peer.
        let mut subs = LinkstatepeerSubs::new();
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
        let mut subs = LinkstatepeerSubs::new();
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
        let mut subs = LinkstatepeerSubs::new();
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
        let mut subs = LinkstatepeerSubs::new();
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
        let mut subs = LinkstatepeerSubs::new();
        subs.register("demo/a", zid(0xAA));
        subs.register("demo/a", zid(0xBB));
        subs.register("demo/b", zid(0xAA));
        let mut got = subs.subscriptions();
        got.sort();
        let mut want = vec![
            ("demo/a".to_owned(), zid(0xAA)),
            ("demo/a".to_owned(), zid(0xBB)),
            ("demo/b".to_owned(), zid(0xAA)),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(
            LinkstatepeerSubs::new().subscriptions().is_empty(),
            "an empty table yields no pairs"
        );
    }

    #[test]
    fn interested_remote_filters_out_self() {
        // The data-route view excludes this node's OWN subscription (zenoh
        // remote_linkstatepeer_subs): self is the local sink, delivered by the
        // session layer, not forwarded toward over the mesh.
        let mut subs = LinkstatepeerSubs::new();
        let me = zid(0x05);
        subs.register("k", me.clone()); // self subscribes
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
        subs.register("self-only", me.clone());
        assert!(
            subs.interested_remote("self-only", &me).is_empty(),
            "a self-only subscription yields no remote direction",
        );
    }
}
