// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2908 — the route cache both mesh forwarders compute through.
//!
//! Upstream computes a route once per (resource, source) and serves it until
//! the tables change: each routing `Resource` holds `Routes<T>`, read through
//! `get_or_set_route`, whose freshness is one `routes_version` counter
//! (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) fn get_or_set_route<T: Clone>(`).
//! A route is keyed by the SOURCE as well as the keyexpr, because the same
//! Put forwarded along two sources' spanning trees goes different ways.
//!
//! [`RouteCache`](crate::route_cache::RouteCache) is that shape, keyed by keyexpr then source. Three points
//! where it is wz's own rather than a transcription:
//!
//! - FRESHNESS IS READ, NOT BUMPED. Upstream increments `routes_version` at
//!   each site that changes a route input, a list a new mutation site has to
//!   remember to join. Here the freshness is a [`RouteInputs`](crate::route_cache::RouteInputs) built from the
//!   versions the tables report themselves
//!   ([`LinkstateNetwork::route_version`](wz_routing_graph::LinkstateNetwork::route_version),
//!   [`LinkstatepeerInterest::version`](crate::linkstate_interest::LinkstatepeerInterest::version)),
//!   each moved by every mutable access, so no mutation can leave a route
//!   served past the change.
//! - ONLY A RESOURCE IS CACHED. Upstream has somewhere to put a route only
//!   when the expression names an existing `Resource` and computes it afresh
//!   otherwise (`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `None => compute_route(),`).
//!   That is also what bounds the cache: a router fed Puts on ever-new keys
//!   keeps no entry per key. The caller says whether its expression is a
//!   declared one (`resource` on
//!   [`RouteCache::get_or_compute`](crate::route_cache::RouteCache::get_or_compute)).
//! - A MEMO BELONGS TO ONE VERSION OF THE TABLES. Where the router's tables are published versions
//!   (`docs/router-table-snapshots.md`, section 6.8), a route is derived data of the version it
//!   was computed from, and the memo is part of that version: its inputs are fixed when the writer
//!   brings it to the version it publishes ([`RouteCache::bring_to`]), before any reader can load
//!   that version, and a reader only adds the routes it computed at those inputs. A reader of an
//!   older version is served from the older version's memo, and none moves a memo's inputs.

use std::hash::Hash;
use std::sync::Arc;

use wz_routing_graph::Zid;

use crate::counter::Counter;
use crate::persistent_map::PersistentMap;
use crate::sync::PlainRwLock;

/// The versions of the tables a route is read from: what a cached route is
/// fresh against. A route computed at one value is stale at any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInputs {
    /// The topology graph's [`route_version`](wz_routing_graph::LinkstateNetwork::route_version),
    /// or 0 for a route no graph enters: a CLIENT leg reaches leaf faces
    /// directly, so only its declaration store decides it.
    pub net: u64,
    /// The declaration table's version: a mesh table's
    /// [`version`](crate::linkstate_interest::LinkstatepeerInterest::version),
    /// or a client store's [`Versioned::version`](wz_routing_graph::Versioned::version).
    pub table: u64,
}

/// Routes by keyexpr and source together, as upstream keeps one route per resource and source.
/// Persistent, so that the memo of the next version starts as the memo of this one at the cost of
/// one count, and leaving out a route copies its path alone. One map rather than a map of keyexprs
/// to maps of sources: a route read hashes its key once and walks one trie (the two lookups of the
/// nested form cost the readers 586 instructions a Put, `docs/router-table-snapshots.md` section 6.8).
type Routes<T, S> = PersistentMap<RouteKey<S>, T>;

/// The key a route is kept under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteKey<S> {
    keyexpr: String,
    source: S,
}

/// A route's key as its two parts, so that a route is read by a key borrowed from the caller's
/// keyexpr and source, with nothing allocated: [`RouteKey`] owns its parts and a pair of
/// references borrows them, and both hash and compare by the parts alone.
trait RouteKeyParts<S> {
    fn parts(&self) -> (&str, &S);
}

impl<S> RouteKeyParts<S> for RouteKey<S> {
    fn parts(&self) -> (&str, &S) {
        (&self.keyexpr, &self.source)
    }
}

impl<S> RouteKeyParts<S> for (&str, &S) {
    fn parts(&self) -> (&str, &S) {
        (self.0, self.1)
    }
}

impl<'a, S: 'a> std::borrow::Borrow<dyn RouteKeyParts<S> + 'a> for RouteKey<S> {
    fn borrow(&self) -> &(dyn RouteKeyParts<S> + 'a) {
        self
    }
}

impl<S: Hash> Hash for dyn RouteKeyParts<S> + '_ {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let (keyexpr, source) = self.parts();
        keyexpr.hash(state);
        source.hash(state);
    }
}

impl<S: PartialEq> PartialEq for dyn RouteKeyParts<S> + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}

impl<S: Eq> Eq for dyn RouteKeyParts<S> + '_ {}

/// Hashed as its borrowed form is, which a map that finds an owned key by a borrowed one needs.
impl<S: Hash> Hash for RouteKey<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self as &dyn RouteKeyParts<S>).hash(state);
    }
}

/// A per-(keyexpr, source) route cache of one version of the tables; see the module docs.
///
/// `S` is what distinguishes one route for a keyexpr from another: the source
/// node on a mesh, whose spanning tree the route follows (upstream's mapped
/// `NodeId`). A client leg has no such dimension, since every source reaches
/// the same leaf faces, and keys by `()`.
///
/// The tables hold it behind an `Arc` that every version with the same inputs shares, and the
/// writer of a version whose inputs moved gives that version a memo of its own
/// ([`bring_to`](Self::bring_to), [`bring_to_retiring`](Self::bring_to_retiring)). Its inputs are
/// therefore those of every version that holds it, and a reader never finds a memo of a version
/// other than its own: no reader moves the inputs, and none computes a route it does not keep
/// because another reader brought the memo to a newer version (`docs/router-table-snapshots.md`,
/// sections 6.7 and 6.8).
///
/// Interior-mutable because the forwarders route through `&self`: a route is read on every
/// message and added on a miss. The routes are behind their own reader-writer lock, as upstream's
/// per-resource routes are
/// (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) data_routes: RwLock<DataRoutes>,`),
/// and a miss adds its route under the write lock, copying its path of the persistent map where
/// the next version's memo shares it. Measured in section 6.8, an `ArcSwap` in place of the lock
/// cost the readers 347 instructions a Put more, about 100 a load, against the lock's one count;
/// a lock read is the cheaper of the two at the readers' one or two lookups a message.
///
/// Two threads that miss the same key at the same inputs compute the same route, since a route is
/// a function of its inputs alone, and the second store replaces the first with an equal value.
/// Neither runs `compute` while it holds anything, so a route that is slow to compute holds no one.
#[derive(Debug)]
pub struct RouteCache<T, S = Zid> {
    /// The inputs the routes are fresh at: those of the versions of the tables that hold this memo.
    /// `None` until a writer first brings the memo to a version: such a memo keeps nothing.
    inputs: Option<RouteInputs>,
    routes: PlainRwLock<Routes<T, S>>,
    /// How many routes were COMPUTED rather than served, by this memo and every memo it was
    /// brought from. The witness that separates "the cache is consulted and invalidated" from "the
    /// cache exists": a delivery assertion alone passes with the cache bypassed.
    computes: Arc<Counter>,
}

impl<T, S> Default for RouteCache<T, S> {
    fn default() -> Self {
        Self {
            inputs: None,
            routes: PlainRwLock::new(PersistentMap::new()),
            computes: Arc::new(Counter::new()),
        }
    }
}

impl<T: Clone, S: Clone + Eq + Hash> RouteCache<T, S> {
    /// An empty cache, brought to no version yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The route from `source` for `keyexpr` at `inputs`: served when this memo holds one,
    /// else computed by `compute` and, when `resource` answers that the expression is a declared
    /// one, kept. `resource` is asked only on a miss, so a served route never pays for the
    /// question.
    ///
    /// `inputs` are those of the version the caller reads, and a memo the writer has brought to
    /// that version has them. A caller whose inputs differ reads a version whose memo was not
    /// brought to it: the writer reading its own draft before it publishes, or, under `rwlock`,
    /// tables a writer left mid-write when it unwound. Its route is computed and returned, and not
    /// kept, since it is fresh only for tables no memo was made for. `compute` must not route
    /// through this cache.
    pub fn get_or_compute(
        &self,
        inputs: RouteInputs,
        source: &S,
        keyexpr: &str,
        resource: impl FnOnce() -> bool,
        compute: impl FnOnce() -> T,
    ) -> T {
        let ours = self.inputs == Some(inputs);
        if ours {
            let key: &dyn RouteKeyParts<S> = &(keyexpr, source);
            if let Some(route) = self.routes.read().get(key) {
                return route.clone();
            }
        }
        let route = compute();
        self.computes.bump();
        if ours && resource() {
            let key = RouteKey {
                keyexpr: keyexpr.to_owned(),
                source: source.clone(),
            };
            self.routes.write().insert(key, route.clone());
        }
        route
    }

    /// Give a version of the tables whose inputs are `inputs` its memo: `memo` stays when it is
    /// already at them, and is otherwise replaced by an empty memo at `inputs`, as upstream's
    /// `Routes::set_route` drops every route on a version change. Called by the writer, before it
    /// publishes the version; a version that shared `memo` before keeps it as it was.
    pub fn bring_to(memo: &mut Arc<Self>, inputs: RouteInputs) {
        Self::bring_to_retiring(memo, inputs, |_, _| false, |_, _| true);
    }

    /// [`bring_to`](Self::bring_to), keeping the routes that the move cannot have changed.
    ///
    /// Without this, a route is dropped whenever ANY input moved, because freshness is one comparison
    /// of versions; a service whose clients come and go then recomputes every key in use after each
    /// change. A table that can say which keys moved lets the new memo leave out only the routes
    /// those keys reach.
    ///
    /// `changes(since, visit)` is asked, when only the declaration table's version moved, to call
    /// `visit` with every key declared or withdrawn after `since` (the table version `memo` is
    /// at), and to answer `false` when it can no longer say. `reaches(changed, cached)` is whether
    /// a change of `changed` can alter the route kept for `cached`. A topology move (`net`), a
    /// memo brought to no version yet, or a table that cannot answer starts the new memo empty.
    ///
    /// Safe by construction: it only ever leaves out more than it must, never fewer, because the
    /// caller supplies the keys the table's own mutators recorded and every mutation records its
    /// key. The new memo starts from the routes `memo` holds when it is called, which readers of the
    /// versions before may still add to: what they add after it is theirs alone.
    pub fn bring_to_retiring(
        memo: &mut Arc<Self>,
        inputs: RouteInputs,
        changes: impl FnOnce(u64, &mut dyn FnMut(&str)) -> bool,
        reaches: impl Fn(&str, &str) -> bool,
    ) {
        if memo.inputs == Some(inputs) {
            return;
        }
        let kept = match memo.inputs {
            Some(was) if was.net == inputs.net => {
                let mut moved: Vec<String> = Vec::new();
                if changes(was.table, &mut |keyexpr| moved.push(keyexpr.to_owned())) {
                    let mut routes = Routes::clone(&memo.routes.read());
                    let reached: Vec<RouteKey<S>> = routes
                        .keys()
                        .filter(|cached| {
                            moved
                                .iter()
                                .any(|changed| reaches(changed, &cached.keyexpr))
                        })
                        .cloned()
                        .collect();
                    for cached in &reached {
                        routes.remove(cached);
                    }
                    routes
                } else {
                    PersistentMap::new()
                }
            }
            _ => PersistentMap::new(),
        };
        *memo = Arc::new(Self {
            inputs: Some(inputs),
            routes: PlainRwLock::new(kept),
            computes: Arc::clone(&memo.computes),
        });
    }

    /// How many routes this memo, and every memo it was brought from, computed rather than served.
    pub fn computes(&self) -> usize {
        self.computes.get()
    }

    /// How many routes this memo keeps.
    pub fn len(&self) -> usize {
        self.routes.read().len()
    }

    /// Whether no route is kept.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zid(b: u8) -> Zid {
        Zid::from_slice(&[b, b, b, b])
    }

    const AT: RouteInputs = RouteInputs { net: 1, table: 1 };

    /// A memo brought to `inputs`, as the writer of the first version leaves it.
    fn at<T: Clone, S: Clone + Eq + Hash>(inputs: RouteInputs) -> Arc<RouteCache<T, S>> {
        let mut memo = Arc::new(RouteCache::new());
        RouteCache::bring_to(&mut memo, inputs);
        memo
    }

    /// The memo is what many faces' tasks read at once (`docs/router-task-per-face.md`, phase 2), so a
    /// cache of routes that can themselves be shared is `Send + Sync`. The proof is the compile.
    #[test]
    fn a_cache_of_shareable_routes_can_be_shared_between_threads() {
        fn shared<T: Send + Sync>() {}
        shared::<RouteCache<std::sync::Arc<[Zid]>>>();
        shared::<RouteCache<std::sync::Arc<[u64]>, ()>>();
    }

    /// Eight threads asking for the same key at the same inputs, each handed the route and none a
    /// different one: the memo keeps one entry for it, and every thread's answer is that route
    /// (a miss races, so more than one may compute it, and never more than the threads that asked).
    #[test]
    fn threads_asking_for_one_key_at_one_input_all_get_its_route_and_it_is_kept_once() {
        const THREADS: usize = 8;
        let cache: Arc<RouteCache<Arc<[Zid]>>> = at(AT);
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        let route = cache.get_or_compute(
                            AT,
                            &zid(1),
                            "demo/a",
                            || true,
                            || Arc::from([zid(9)]),
                        );
                        assert_eq!(&*route, &[zid(9)]);
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("a routing thread ends");
        }
        assert_eq!(cache.len(), 1);
        assert!(
            (1..=THREADS).contains(&cache.computes()),
            "computed {} times by {THREADS} threads",
            cache.computes()
        );
    }

    #[test]
    fn a_resource_route_is_computed_once_and_served_at_the_same_inputs() {
        let cache: Arc<RouteCache<Vec<Zid>>> = at(AT);
        let first = cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let again = cache.get_or_compute(AT, &zid(1), "demo/a", || true, || unreachable!());
        assert_eq!(first, again);
        assert_eq!(cache.computes(), 1);
    }

    #[test]
    fn a_route_is_per_source_and_per_keyexpr() {
        let cache: Arc<RouteCache<Vec<Zid>>> = at(AT);
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let other_source = cache.get_or_compute(AT, &zid(2), "demo/a", || true, || vec![zid(8)]);
        let other_key = cache.get_or_compute(AT, &zid(1), "demo/b", || true, || vec![zid(7)]);
        assert_eq!(other_source, vec![zid(8)]);
        assert_eq!(other_key, vec![zid(7)]);
        assert_eq!(cache.computes(), 3);
        assert_eq!(cache.len(), 3);
    }

    /// A memo no writer has brought to a version keeps nothing: it is fresh at no inputs.
    #[test]
    fn a_memo_brought_to_no_version_computes_every_time_and_keeps_nothing() {
        let cache: RouteCache<Vec<Zid>> = RouteCache::new();
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        assert_eq!(cache.computes(), 2);
        assert!(cache.is_empty());
    }

    /// A caller at inputs other than the memo's (a writer reading its own draft) is given the
    /// route of its tables, and the memo keeps what it held: neither the route nor the move.
    #[test]
    fn a_route_asked_at_other_inputs_is_computed_and_not_kept() {
        let cache: Arc<RouteCache<Vec<Zid>>> = at(AT);
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let draft = RouteInputs { table: 2, ..AT };
        let got = cache.get_or_compute(draft, &zid(1), "demo/a", || true, || vec![zid(3)]);
        assert_eq!(
            got,
            vec![zid(3)],
            "the other inputs are not served this memo's route"
        );
        cache.get_or_compute(draft, &zid(1), "demo/b", || true, || vec![zid(4)]);
        assert_eq!(
            cache.len(),
            1,
            "nothing computed at the other inputs was kept"
        );
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || unreachable!());
        assert_eq!(cache.computes(), 3);
    }

    /// The writer of a version whose inputs moved gives it a memo of its own; the version before
    /// keeps its memo, routes and all, for the readers that still hold it.
    #[test]
    fn a_move_gives_the_new_version_its_own_memo_and_leaves_the_old_one_whole() {
        let old: Arc<RouteCache<Vec<Zid>>> = at(AT);
        old.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let mut new = Arc::clone(&old);
        let net_moved = RouteInputs { net: 2, ..AT };
        RouteCache::bring_to(&mut new, net_moved);
        assert!(!Arc::ptr_eq(&old, &new));
        assert!(new.is_empty(), "a topology move starts the new memo empty");
        let got = new.get_or_compute(net_moved, &zid(1), "demo/a", || true, || vec![zid(3)]);
        assert_eq!(
            got,
            vec![zid(3)],
            "a net change must not serve the old route"
        );
        let served = old.get_or_compute(AT, &zid(1), "demo/a", || true, || unreachable!());
        assert_eq!(
            served,
            vec![zid(9)],
            "a reader of the old version is served its route"
        );
        assert_eq!(old.computes(), 2, "the memos count into one witness");
    }

    #[test]
    fn a_memo_already_at_the_inputs_is_kept_and_nothing_is_asked() {
        let old: Arc<RouteCache<Vec<Zid>>> = at(AT);
        old.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let mut new = Arc::clone(&old);
        RouteCache::bring_to_retiring(&mut new, AT, |_, _| unreachable!(), |_, _| unreachable!());
        assert!(
            Arc::ptr_eq(&old, &new),
            "versions at the same inputs share one memo"
        );
    }

    /// A memo of `demo/a` and `demo/b`, brought to a table move whose log is `changed`, as a client
    /// leg's is (`None`: the log no longer reaches back).
    fn brought(changed: Option<&[&str]>) -> (Arc<RouteCache<Vec<Zid>>>, RouteInputs) {
        let mut memo: Arc<RouteCache<Vec<Zid>>> = at(AT);
        memo.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        memo.get_or_compute(AT, &zid(1), "demo/b", || true, || vec![zid(9)]);
        let moved = RouteInputs { table: 2, ..AT };
        RouteCache::bring_to_retiring(
            &mut memo,
            moved,
            |since, visit| {
                assert_eq!(since, AT.table, "asked from the version the memo was at");
                match changed {
                    Some(keys) => {
                        keys.iter().for_each(|k| visit(k));
                        true
                    }
                    None => false,
                }
            },
            |changed, cached| changed == cached,
        );
        (memo, moved)
    }

    #[test]
    fn a_table_move_leaves_out_only_the_routes_the_changed_key_reaches() {
        let (memo, moved) = brought(Some(&["demo/a"]));
        assert_eq!(memo.len(), 1, "only the route of the changed key went");
        memo.get_or_compute(moved, &zid(1), "demo/b", || true, || unreachable!());
        assert_eq!(memo.computes(), 2, "the other key was served, not computed");
        memo.get_or_compute(moved, &zid(1), "demo/a", || true, || vec![zid(5)]);
        assert_eq!(memo.computes(), 3, "the changed key was computed afresh");
    }

    #[test]
    fn a_table_that_cannot_say_what_moved_starts_the_new_memo_empty() {
        let (memo, _) = brought(None);
        assert!(memo.is_empty());
    }

    #[test]
    fn a_topology_move_starts_the_new_memo_empty_whatever_the_table_says() {
        let mut memo: Arc<RouteCache<Vec<Zid>>> = at(AT);
        memo.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        // The table says nothing relevant moved, but the graph did.
        RouteCache::bring_to_retiring(
            &mut memo,
            RouteInputs { net: 2, ..AT },
            |_, _| true,
            |_, _| false,
        );
        assert!(memo.is_empty());
    }

    #[test]
    fn an_expression_that_is_not_a_resource_is_computed_every_time_and_never_kept() {
        let cache: Arc<RouteCache<Vec<Zid>>> = at(AT);
        cache.get_or_compute(AT, &zid(1), "demo/x", || false, || vec![zid(9)]);
        cache.get_or_compute(AT, &zid(1), "demo/x", || false, || vec![zid(9)]);
        assert_eq!(cache.computes(), 2);
        assert!(cache.is_empty(), "an undeclared expression keeps nothing");
    }
}
