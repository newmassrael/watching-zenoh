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
//! [`interested`](LinkstatepeerSubs::interested) and feeds the peer set to
//! [`wz_routing_graph::LinkstateNetwork::directions_toward`] so a Push is
//! replicated only toward subtrees holding an interested subscriber — the
//! bounded fan-out that replaces the current broadcast-to-every-tree-child.
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

    /// The peers interested in `keyexpr` (EXACT match), as a snapshot the
    /// data-route filter passes to
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// Empty when no peer is interested. Order is unspecified (`HashSet`
    /// iteration); the route filter dedups by direction, so order does not
    /// matter. A snapshot `Vec` (not a borrow) so the caller can hold it
    /// across a graph borrow; interest sets are small.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.by_key
            .get(keyexpr)
            .map(|set| set.iter().cloned().collect())
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
}
