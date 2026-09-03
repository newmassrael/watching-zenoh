// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Linkstate-peer interest table (P4 routing, step c3c-3 atom2) — which
//! PEERS are interested in which key expression, and (per peer) WHAT they
//! declared. ONE generic table type `LinkstatepeerInterest<V>`, instantiated
//! TWICE by the forwarder: once for subscriptions (`V = ()` — a
//! `DeclareSubscriber` carries no per-peer payload, the data-route filter) and
//! once for queryables (`V = `[`QueryableInfo`](wz_session_core::queryable_info::QueryableInfo)
//! — a `DeclareQueryable` carries `complete` / `distance`, the BestMatching
//! query-route input).
//!
//! The wz analogue of zenoh's per-`Resource` `linkstatepeer_subs:
//! HashSet<ZenohIdProto>` AND `linkstatepeer_qabls: HashMap<ZenohIdProto,
//! QueryableInfoType>` (`zenoh/src/net/routing/hat/peer/mod.rs`
//! @ `remote_qabls`). zenoh DELIBERATELY
//! uses a value-less `HashSet` for subs and a value-bearing `HashMap` for qabls,
//! because the queryable plane carries semantic per-peer state (completeness,
//! distance) that BestMatching reads and the subscription plane does not. This
//! type expresses BOTH as `HashMap<Zid, V>` per keyexpr — `V = ()` is morally a
//! set (a zero-size value), `V = QueryableInfo` is the value-bearing map — so the
//! shared register / withdraw / face-down-purge / wildcard-matching mechanics
//! live once, while the per-peer value differs by plane. The topology graph is
//! the pure [`wz_routing_graph::LinkstateNetwork`]; these interest tables are
//! SEPARATE structures the forwarder (the HAT analogue) owns alongside it.
//!
//! How it is driven: a sourced `DeclareSubscriber` / `DeclareQueryable` arriving
//! from the mesh [`register`](LinkstatepeerInterest::register)s the advertising
//! peer's interest (c3c-3 atom3); the route filter reads
//! [`interested_remote`](LinkstatepeerInterest::interested_remote) and feeds the
//! peer set to [`wz_routing_graph::LinkstateNetwork::directions_toward`] so a
//! Push (subs) / Query (qabls) is replicated only toward subtrees holding an
//! interested peer.
//!
//! VALUE-DIFF change-gate (zenoh-faithful, R311ul): `register` returns `true` on
//! a NEW peer OR a CHANGED value — mirroring zenoh's
//! peer-hat queryable registration gate `current.is_none() ||
//! current != qabl_info` (`zenoh/src/net/routing/hat/peer/queries.rs`
//! @ `fn register_queryable`). The forwarder
//! re-floods only on `true`, so a queryable that flips `complete: false -> true`
//! (e.g. a storage finishing its load) DOES re-propagate, while a redundant
//! re-declare of the same value does not loop. For `V = ()` the value never
//! differs, so the gate reduces to "new peer" — the prior subscription
//! behaviour, exactly.
//!
//! Single set, filter on read (zenoh-faithful): this node's OWN declaration is
//! registered into the SAME map under its own zid (zenoh
//! `register_linkstatepeer_*(.., tables.zid, ..)`); the "remote-only" view the
//! route needs is DERIVED by filtering self at read time
//! ([`interested_remote`](LinkstatepeerInterest::interested_remote)), not by a
//! second structure.
//!
//! Wildcard matching (c3c-3 B2): a lookup is the key-expression INTERSECTION of
//! the published key against every registered declaration keyexpr, via the
//! shared [`keyexpr_intersects_target`] scan SSOT. Still deferred (performance,
//! not correctness): zenoh folds declarations into a prefix RESOURCE TREE for
//! sublinear matching; wz does an O(declarations) scan per lookup.

use std::collections::{HashMap, HashSet};

use wz_routing_graph::Zid;
use wz_session_core::keyexpr_match::keyexpr_intersects_target;

/// Per-key-expression map of interested PEER zid -> the per-peer value `V` they
/// declared — the linkstate-peer interest table, instantiated once per interest
/// plane (`V = ()` subscriptions, `V = QueryableInfo` queryables). See the module
/// docs for the zenoh mapping, the value-diff change-gate, and the MVP scope.
#[derive(Debug)]
pub struct LinkstatepeerInterest<V> {
    /// declared keyexpr (a literal OR a `*`/`**` pattern) -> the peers that
    /// declared interest in it, each mapped to its declared value `V`. A key is
    /// present only while at least one peer is interested: the last peer's
    /// [`remove_peer`](Self::remove_peer) / [`withdraw`](Self::withdraw) prunes
    /// the entry. A lookup matches a published / queried key against these keys by
    /// keyexpr INTERSECTION ([`matching_peers`](Self::matching_peers)), so a
    /// `demo/**` key attracts a `demo/data` lookup.
    by_key: HashMap<String, HashMap<Zid, V>>,
}

impl<V> Default for LinkstatepeerInterest<V> {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
        }
    }
}

impl<V> LinkstatepeerInterest<V> {
    /// An empty interest table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Withdraw `peer`'s interest in ONE `keyexpr` — a sourced
    /// `UndeclareSubscriber` arriving from the mesh while the peer's face stays
    /// up (the per-keyexpr retraction, vs [`remove_peer`](Self::remove_peer)'s
    /// whole-peer face-down purge). Idempotent. Returns `true` if the peer WAS
    /// interested (a real change the caller re-propagates onward), `false`
    /// otherwise. The emptied key is pruned. Value-agnostic — a withdraw drops
    /// the peer regardless of `V`. Mirrors zenoh `unregister_peer_subscription`.
    pub fn withdraw(&mut self, keyexpr: &str, peer: &Zid) -> bool {
        let Some(peers) = self.by_key.get_mut(keyexpr) else {
            return false;
        };
        let removed = peers.remove(peer).is_some();
        if peers.is_empty() {
            self.by_key.remove(keyexpr);
        }
        removed
    }

    /// Drop ALL of `peer`'s interests across every key — called from the
    /// forwarder's `deregister` when a peer's face goes down, so stale interest
    /// never keeps a departed subscriber / queryable armed in the route gate.
    /// Returns the number of keys the peer was dropped from; emptied keys are
    /// pruned. Mirrors zenoh's `pubsub_remove_node` / `queries_remove_node`
    /// link-down purge.
    pub fn remove_peer(&mut self, peer: &Zid) -> usize {
        self.remove_peer_keys(peer).len()
    }

    /// Drop ALL of `peer`'s interests, returning the KEYEXPRS it was dropped from
    /// — the value-carrying twin of [`remove_peer`](Self::remove_peer). The router
    /// forwarder's cross-tier advertisement is per-keyexpr, so a face-down /
    /// topology detach that removes a native must know WHICH keyexprs to
    /// re-evaluate for a stale self-advertisement (a whole-peer count is not
    /// enough — R311y125 lifecycle-symmetry). Emptied keys are pruned. The
    /// returned order is unspecified (HashMap iteration).
    pub fn remove_peer_keys(&mut self, peer: &Zid) -> Vec<String> {
        let mut dropped = Vec::new();
        self.by_key.retain(|key, peers| {
            if peers.remove(peer).is_some() {
                dropped.push(key.clone());
            }
            !peers.is_empty()
        });
        dropped
    }

    /// Every `(keyexpr, interested-peer, declared value)` triple, as an owned
    /// snapshot — the input to the tree-change re-advertise (c3c-3 debt A2). On a
    /// topology change the forwarder re-floods each entry's `DeclareSubscriber` /
    /// `DeclareQueryable` (sourced from the peer, CARRYING the value `V`) toward
    /// that peer's recomputed tree children. Owned (`String` / `Zid` / `V`
    /// clones) so the caller can re-flood without holding this table's borrow
    /// across a graph borrow. Value-bearing (R311uq): the re-advertise re-floods
    /// the keyexpr + source + per-peer `V`, so a queryable's completeness reaches
    /// a late-joining branch exactly as a steady-state re-flood does — the
    /// multi-hop QueryableInfo propagation. For `V = ()` (subs) the value is the
    /// zero-size unit.
    pub fn entries(&self) -> Vec<(String, Zid, V)>
    where
        V: Clone,
    {
        self.by_key
            .iter()
            .flat_map(|(key, peers)| peers.iter().map(move |(p, v)| (key.clone(), *p, v.clone())))
            .collect()
    }

    /// The total number of `(keyexpr, source-peer)` registrations across every
    /// key — the cardinality of [`entries`](Self::entries) WITHOUT its owned
    /// clone. The router forwarder's readiness witnesses
    /// ([`mesh_subs_seen`](crate::router_forward::RouterForwarder::mesh_subs_seen)
    /// / [`queryables_seen`](crate::router_forward::RouterForwarder::queryables_seen))
    /// need only "how many declarations do I hold", not the declarations
    /// themselves, so they sum the per-key source counts directly instead of
    /// materialising (and immediately discarding via `.len()`) an owned
    /// `Vec<(String, Zid, V)>` of every keyexpr + zid + value clone.
    /// Value-agnostic (no `V: Clone` bound, unlike `entries`).
    pub fn count(&self) -> usize {
        self.by_key.values().map(|peers| peers.len()).sum()
    }

    /// The distinct peers whose declaration keyexpr INTERSECTS `target`,
    /// optionally excluding `exclude` (this node's own zid). Wildcard-aware via
    /// the shared [`keyexpr_intersects_target`] scan SSOT — an O(declarations)
    /// scan (the resource-tree fold for sublinear matching is a tracked
    /// deferral). Value-agnostic — returns the zids; the per-peer `V` is read via
    /// the value-aware accessors when BestMatching needs it.
    fn matching_peers(&self, target: &str, exclude: Option<&Zid>) -> Vec<Zid> {
        // A malformed target (an empty chunk, e.g. a trailing '/') matches no
        // peer: the shared `keyexpr_intersects_target` rejects it at the matcher.
        let target_chunks: Vec<&str> = target.split('/').collect();
        // Dedup peers across multiple matching keys via a `HashSet` (`Zid` is
        // `Copy + Hash`), not an O(matches^2) linear membership scan.
        let mut out: HashSet<Zid> = HashSet::new();
        for (decl, peers) in &self.by_key {
            if keyexpr_intersects_target(decl, &target_chunks) {
                out.extend(peers.keys().filter(|p| exclude != Some(*p)).copied());
            }
        }
        out.into_iter().collect()
    }

    /// Every `(declaration-keyexpr, interested-peer, declared value V)` tuple
    /// whose declaration keyexpr INTERSECTS `target`, optionally excluding
    /// `exclude` (this node's own zid) — the VALUE-BEARING twin of
    /// [`matching_peers`](Self::matching_peers). BestMatching needs the per-peer
    /// `V` ([`QueryableInfo`](wz_session_core::queryable_info::QueryableInfo)) AND
    /// the matched DECLARATION keyexpr (to test query-inclusion), both of which
    /// the value-agnostic [`matching_peers`](Self::matching_peers) / route filter
    /// discards. A peer that matches via several declarations yields one tuple
    /// PER declaration — no dedup (the per-declaration value is the point),
    /// mirroring zenoh's per-`(matched-resource, qabl)` iteration in
    /// query-route build (`zenoh/src/net/routing/hat/peer/queries.rs`
    /// @ `fn compute_query_route`), where each
    /// matched resource carries its own `QueryableInfoType` and its own
    /// includes-the-query verdict. Borrowed (`&str` / `&V`) — the BestMatching
    /// select consumes them under the same table borrow.
    pub(crate) fn matching_entries(
        &self,
        target: &str,
        exclude: Option<&Zid>,
    ) -> Vec<(&str, Zid, &V)> {
        let target_chunks: Vec<&str> = target.split('/').collect();
        let mut out: Vec<(&str, Zid, &V)> = Vec::new();
        for (decl, peers) in &self.by_key {
            if keyexpr_intersects_target(decl, &target_chunks) {
                out.extend(
                    peers
                        .iter()
                        .filter(|(peer, _value)| exclude != Some(*peer))
                        .map(|(peer, value)| (decl.as_str(), *peer, value)),
                );
            }
        }
        out
    }

    /// The peers interested in `keyexpr`, as a snapshot — every interested peer
    /// INCLUDING this node itself when it has a local declaration. Matches by
    /// keyexpr intersection. Order is unspecified.
    pub fn interested(&self, keyexpr: &str) -> Vec<Zid> {
        self.matching_peers(keyexpr, None)
    }

    /// The peers interested in `keyexpr` EXCLUDING `self_zid` — the snapshot the
    /// route filter passes to
    /// [`directions_toward`](wz_routing_graph::LinkstateNetwork::directions_toward).
    /// Mirrors zenoh's `remote_linkstatepeer_subs` (filter self at read time).
    pub fn interested_remote(&self, keyexpr: &str, self_zid: &Zid) -> Vec<Zid> {
        self.matching_peers(keyexpr, Some(self_zid))
    }

    /// Number of sources registered under the EXACT `keyexpr` (no wildcard
    /// intersection) — the per-keyexpr contributor count the router forwarder's
    /// cross-tier advertise/withdraw flip-gate reads: a native for the exact ke
    /// makes self ADVERTISE that ke into the opposite mesh only when it is the
    /// FIRST such source (`== 1` after register), and WITHDRAW only when the LAST
    /// leaves (`== 0` after removal). Exact (not `interested`/`interested_remote`,
    /// which are wildcard-aware for the DELIVERY route) because the advertisement
    /// mirrors zenoh's per-`Resource` cross-registration — self advertises the
    /// exact ke it learned, not a wildcard cover. Self is never a source here
    /// (derive-not-store: self is not inserted into a tier table), so no
    /// self-exclusion is needed.
    pub fn source_count(&self, keyexpr: &str) -> usize {
        self.by_key.get(keyexpr).map_or(0, |peers| peers.len())
    }

    /// The declared VALUES of every source under the EXACT `keyexpr` — the
    /// value-bearing twin of [`source_count`](Self::source_count). The router
    /// forwarder folds these (with [`QueryableInfo::merge`]) into the MERGED
    /// `QueryableInfo` it advertises cross-tier for `keyexpr` — zenoh's
    /// `local_*_qabl_info` fold over the opposite-tier table (`queries.rs:67-133`).
    /// Exact (per-`Resource`), self-excluding by construction (self is never a
    /// source — derive-not-store). Owned clones so the caller folds without holding
    /// the table borrow.
    pub fn values_for(&self, keyexpr: &str) -> Vec<V>
    where
        V: Clone,
    {
        self.by_key
            .get(keyexpr)
            .map_or_else(Vec::new, |peers| peers.values().cloned().collect())
    }
}

impl<V: PartialEq> LinkstatepeerInterest<V> {
    /// Record that `peer` declared interest in `keyexpr` with value `value` — a
    /// sourced `DeclareSubscriber` (`V = ()`) / `DeclareQueryable` (`V =
    /// QueryableInfo`) from the mesh, or a re-declare. Returns `true` if this was
    /// a real CHANGE — a NEW peer, OR an existing peer whose value DIFFERS — and
    /// `false` for a redundant re-declare of the same value. The VALUE-DIFF gate
    /// (not just new-peer) is zenoh's peer-hat queryable registration:
    /// `current.is_none() || current != qabl_info`
    /// (`zenoh/src/net/routing/hat/peer/queries.rs` @ `fn register_queryable`),
    /// so a queryable flipping `complete`
    /// re-propagates. For `V = ()` the value never differs, so this is the prior
    /// "new peer only" subscription gate exactly. The caller re-floods only on
    /// `true` (the loop-bounding change-gate).
    pub fn register(&mut self, keyexpr: &str, peer: Zid, value: V) -> bool {
        use std::collections::hash_map::Entry;
        match self
            .by_key
            .entry(keyexpr.to_owned())
            .or_default()
            .entry(peer)
        {
            Entry::Vacant(slot) => {
                slot.insert(value);
                true
            }
            Entry::Occupied(mut slot) => {
                if *slot.get() == value {
                    false
                } else {
                    slot.insert(value);
                    true
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::queryable_info::QueryableInfo;

    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b, b, b, b])
    }

    // A subscription-plane table (V = ()), the common case the route filter uses.
    fn subs() -> LinkstatepeerInterest<()> {
        LinkstatepeerInterest::new()
    }

    #[test]
    fn register_is_idempotent_and_reports_change() {
        let mut subs = subs();
        assert!(
            subs.register("demo/data", zid(0xAA), ()),
            "first interest is a change"
        );
        assert!(
            !subs.register("demo/data", zid(0xAA), ()),
            "re-declaring the same peer is a no-op"
        );
        assert!(
            subs.register("demo/data", zid(0xBB), ()),
            "a second distinct peer is a change"
        );
        let mut got = subs.interested("demo/data");
        got.sort();
        assert_eq!(got, vec![zid(0xAA), zid(0xBB)]);
    }

    #[test]
    fn register_re_floods_on_a_value_change_not_just_a_new_peer() {
        // The R311ul value-diff change-gate (zenoh queries.rs:268): a queryable
        // that flips `complete` re-propagates. The subscription `V = ()` gate
        // never sees a value change, so it reduces to new-peer (covered above).
        let mut qabls: LinkstatepeerInterest<QueryableInfo> = LinkstatepeerInterest::new();
        let incomplete = QueryableInfo {
            complete: false,
            distance: 0,
        };
        let complete = QueryableInfo {
            complete: true,
            distance: 0,
        };
        assert!(
            qabls.register("demo/q", zid(0xCC), incomplete),
            "new peer -> change",
        );
        assert!(
            !qabls.register("demo/q", zid(0xCC), incomplete),
            "same value -> NO change (no re-flood loop)",
        );
        assert!(
            qabls.register("demo/q", zid(0xCC), complete),
            "complete flipped false->true -> CHANGE (must re-flood)",
        );
        assert!(
            !qabls.register("demo/q", zid(0xCC), complete),
            "same complete value again -> no change",
        );
    }

    #[test]
    fn matching_entries_yields_the_per_peer_value_for_best_matching() {
        // The value-bearing accessor BestMatching reads (atom 3): each matching
        // (declaration, peer) pair WITH its stored QueryableInfo, one tuple PER
        // declaration (no peer dedup — the per-declaration completeness is what
        // the select needs), self excluded.
        let mut qabls: LinkstatepeerInterest<QueryableInfo> = LinkstatepeerInterest::new();
        let complete = QueryableInfo {
            complete: true,
            distance: 0,
        };
        let incomplete = QueryableInfo {
            complete: false,
            distance: 0,
        };
        qabls.register("demo/**", zid(0xAA), complete); // wildcard, complete
        qabls.register("demo/q", zid(0xBB), incomplete); // literal, incomplete
        let me = zid(0x05);
        qabls.register("demo/q", me, complete); // self — excluded below

        let mut got: Vec<(String, Zid, QueryableInfo)> = qabls
            .matching_entries("demo/q", Some(&me))
            .into_iter()
            .map(|(decl, peer, info)| (decl.to_owned(), peer, *info))
            .collect();
        got.sort_by_key(|(_decl, peer, _info)| *peer);
        assert_eq!(
            got,
            vec![
                ("demo/**".to_owned(), zid(0xAA), complete),
                ("demo/q".to_owned(), zid(0xBB), incomplete),
            ],
            "the wildcard (complete) and the literal (incomplete) declarations both \
             match demo/q with their OWN per-peer value; the self declaration is excluded",
        );
        assert!(
            qabls.matching_entries("other/key", None).is_empty(),
            "a non-intersecting target matches no declaration",
        );
    }

    #[test]
    fn a_literal_subscription_stays_exact() {
        let mut subs = subs();
        subs.register("demo/data", zid(0xAA), ());
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
        let mut subs = subs();
        subs.register("demo/**", zid(0xAA), ());
        subs.register("demo/*", zid(0xBB), ());
        subs.register("other/**", zid(0xCC), ());
        let mut got = subs.interested("demo/data");
        got.sort();
        assert_eq!(
            got,
            vec![zid(0xAA), zid(0xBB)],
            "demo/** and demo/* cover demo/data; other/** does not"
        );
        assert_eq!(
            subs.interested("demo/a/b"),
            vec![zid(0xAA)],
            "only ** spans the extra chunk"
        );
        assert_eq!(
            subs.interested_remote("demo/data", &zid(0xAA)),
            vec![zid(0xBB)],
            "wildcard match minus the self subscriber AA"
        );
    }

    #[test]
    fn a_peer_matching_via_two_patterns_appears_once() {
        let mut subs = subs();
        subs.register("demo/**", zid(0xAA), ());
        subs.register("demo/data", zid(0xAA), ());
        assert_eq!(
            subs.interested("demo/data"),
            vec![zid(0xAA)],
            "peer AA matches both keys but appears once"
        );
    }

    #[test]
    fn remove_peer_drops_interest_across_all_keys() {
        let mut subs = subs();
        subs.register("a", zid(0xAA), ());
        subs.register("b", zid(0xAA), ());
        subs.register("b", zid(0xBB), ());
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
        assert_eq!(subs.remove_peer(&zid(0xAA)), 0, "no-op for an absent peer");
    }

    #[test]
    fn withdraw_removes_one_key_and_reports_change() {
        let mut subs = subs();
        subs.register("a", zid(0xAA), ());
        subs.register("b", zid(0xAA), ());
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
        let mut subs = subs();
        subs.register("k", zid(0xAA), ());
        subs.register("k", zid(0xBB), ());
        assert!(subs.withdraw("k", &zid(0xAA)));
        assert_eq!(
            subs.interested("k"),
            vec![zid(0xBB)],
            "key 'k' survives with the remaining peer BB",
        );
    }

    #[test]
    fn withdraw_is_idempotent_for_absent_interest() {
        let mut subs = subs();
        subs.register("k", zid(0xAA), ());
        assert!(!subs.withdraw("k", &zid(0xBB)), "BB never declared 'k'");
        assert!(
            !subs.withdraw("other", &zid(0xAA)),
            "no interest in an unknown key",
        );
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
        let mut subs = subs();
        subs.register("demo/a", zid(0xAA), ());
        subs.register("demo/a", zid(0xBB), ());
        subs.register("demo/b", zid(0xAA), ());
        let mut got = subs.entries();
        got.sort();
        // Value-bearing (R311uq): the subscription value is the unit ().
        let mut want = vec![
            ("demo/a".to_owned(), zid(0xAA), ()),
            ("demo/a".to_owned(), zid(0xBB), ()),
            ("demo/b".to_owned(), zid(0xAA), ()),
        ];
        want.sort();
        assert_eq!(got, want);
        assert!(
            LinkstatepeerInterest::<()>::new().entries().is_empty(),
            "an empty table yields no entries"
        );
    }

    #[test]
    fn entries_carry_the_per_peer_queryable_info() {
        // R311uq — entries() is value-bearing so the tree-change re-advertise can
        // carry a queryable's completeness onto a late-joining branch.
        let mut qabls: LinkstatepeerInterest<QueryableInfo> = LinkstatepeerInterest::new();
        let complete = QueryableInfo {
            complete: true,
            distance: 0,
        };
        qabls.register("demo/q", zid(0xAA), complete);
        assert_eq!(
            qabls.entries(),
            vec![("demo/q".to_owned(), zid(0xAA), complete)],
            "the entry carries the peer's QueryableInfo, not just the (key, peer) pair",
        );
    }

    #[test]
    fn count_totals_every_keyexpr_peer_pair_without_cloning() {
        // count() is the cardinality of entries() (B-d): the readiness witnesses
        // need only "how many declarations", so they must NOT clone every
        // (keyexpr, zid, value) triple just to read its length.
        let mut subs = subs();
        assert_eq!(subs.count(), 0, "an empty table holds nothing");
        subs.register("demo/a", zid(0xAA), ());
        subs.register("demo/a", zid(0xBB), ()); // same key, second peer
        subs.register("demo/b", zid(0xAA), ()); // second key, first peer again
        assert_eq!(
            subs.count(),
            3,
            "three (keyexpr, peer) registrations across two keys",
        );
        assert_eq!(
            subs.count(),
            subs.entries().len(),
            "count() is exactly entries().len(), minus the owned clone",
        );
        assert!(
            subs.withdraw("demo/a", &zid(0xAA)),
            "AA drops out of demo/a"
        );
        assert_eq!(
            subs.count(),
            2,
            "a per-key withdraw removes one registration"
        );
        subs.remove_peer(&zid(0xAA)); // drops the remaining demo/b:AA
        assert_eq!(
            subs.count(),
            1,
            "the sole survivor is demo/a:BB after AA is purged everywhere",
        );
    }

    #[test]
    fn interested_remote_filters_out_self() {
        let mut subs = subs();
        let me = zid(0x05);
        subs.register("k", me, ());
        subs.register("k", zid(0xAA), ());
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
        subs.register("self-only", me, ());
        assert!(
            subs.interested_remote("self-only", &me).is_empty(),
            "a self-only subscription yields no remote direction",
        );
    }

    #[test]
    fn a_trailing_slash_target_matches_no_peer() {
        let mut subs = subs();
        subs.register("demo/**", zid(0xAA), ());
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
