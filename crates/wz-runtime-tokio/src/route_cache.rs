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
//! [`RouteCache`] is that shape, keyed by keyexpr then source. Three points
//! where it is wz's own rather than a transcription:
//!
//! - FRESHNESS IS READ, NOT BUMPED. Upstream increments `routes_version` at
//!   each site that changes a route input, a list a new mutation site has to
//!   remember to join. Here the freshness is a [`RouteInputs`] built from the
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
//! - A CHANGED KEY FINDS ITS ROUTES BY INDEX. A memo whose writer leaves out the routes a change
//!   reaches ([`RouteCache::bring_to_retiring`]) is built by [`RouteCache::indexed`] and keeps its
//!   routes' keyexprs in a trie of chunks beside the routes, the index the client stores keep their
//!   keys in, so the writer asks the index for the routes a changed key may meet instead of trying
//!   every route kept against every changed key (`docs/router-table-snapshots.md`, section 6.9).
//! - A WRITER MAY KEEP WHAT IT ROUTES THROUGH ITS DRAFT. A writer that routes through the version
//!   it is still writing asks at inputs no memo was brought to, and its route is computed and not
//!   kept. Tables that ask for it give the draft a memo of its own where a write first moves an
//!   input ([`RouteCache::open_draft`]); what that memo keeps at the inputs the draft is published
//!   at becomes part of the published version's memo (section 6.9).

use std::hash::Hash;
use std::sync::Arc;

use wz_routing_graph::Zid;

use crate::counter::Counter;
use crate::keyexpr_index::KeyexprIndex;
use crate::persistent_map::PersistentMap;
use crate::sync::{PlainMutex, PlainRwLock};

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

/// The key a route is kept under. The keyexpr is shared, because an indexed memo holds the key
/// twice, in its routes and in its index.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteKey<S> {
    keyexpr: Arc<str>,
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
    /// `None` until a writer first brings the memo to a version, and for a draft's memo, whose
    /// inputs are the draft's own: such a memo keeps nothing of its own.
    inputs: Option<RouteInputs>,
    kept: PlainRwLock<Kept<T, S>>,
    /// How many routes were COMPUTED rather than served, by this memo and every memo it was
    /// brought from. The witness that separates "the cache is consulted and invalidated" from "the
    /// cache exists": a delivery assertion alone passes with the cache bypassed.
    computes: Arc<Counter>,
    /// The routes asked at inputs no version's memo was brought to, and computed then, by this memo
    /// and every memo it was brought from: how often a writer routes through its own draft. Counted
    /// in test builds only, where the instruments read it, so that a reader pays nothing for it.
    #[cfg(test)]
    off_version: Arc<OffVersion>,
    /// Set on the memo of a write's draft ([`open_draft`](Self::open_draft)), and never on a
    /// published version's.
    draft: Option<Box<Draft<T, S>>>,
}

/// What a memo keeps: its routes and, for an indexed memo, their keys by keyexpr. One value behind
/// one lock, so that a route and its index entry are added and left out together.
struct Kept<T, S> {
    routes: Routes<T, S>,
    /// The keys of `routes` by their keyexpr, in an indexed memo ([`RouteCache::indexed`]).
    by_keyexpr: Option<KeyexprIndex<RouteKey<S>>>,
}

/// A copy shares every node of the routes and of the index: one count each.
impl<T, S> Clone for Kept<T, S> {
    fn clone(&self) -> Self {
        Self {
            routes: self.routes.clone(),
            by_keyexpr: self.by_keyexpr.clone(),
        }
    }
}

impl<T, S> Kept<T, S> {
    fn empty(indexed: bool) -> Self {
        Self {
            routes: PersistentMap::new(),
            by_keyexpr: indexed.then(KeyexprIndex::new),
        }
    }

    fn is_indexed(&self) -> bool {
        self.by_keyexpr.is_some()
    }
}

impl<T: Clone, S: Clone + Eq + Hash> Kept<T, S> {
    fn insert(&mut self, keyexpr: &str, source: &S, route: T) {
        let key = RouteKey {
            keyexpr: Arc::from(keyexpr),
            source: source.clone(),
        };
        self.put(key, route);
    }

    fn put(&mut self, key: RouteKey<S>, route: T) {
        if let Some(index) = &mut self.by_keyexpr {
            index.insert(&key.keyexpr, key.clone());
        }
        self.routes.insert(key, route);
    }

    fn remove(&mut self, key: &RouteKey<S>) {
        if self.routes.remove(key).is_none() {
            return;
        }
        if let Some(index) = &mut self.by_keyexpr {
            index.remove(&key.keyexpr, key);
        }
    }

    /// These routes less those a key changed after `since` reaches; `None` when `changes` can no
    /// longer say which keys changed (see [`RouteCache::bring_to_retiring`]).
    ///
    /// An indexed memo asks its index for the routes whose keyexpr may meet each changed key and
    /// refines them with `reaches`, so its cost follows the routes the changes meet. A memo with no
    /// index tries every route against every changed key.
    fn retiring(
        mut self,
        since: u64,
        changes: impl FnOnce(u64, &mut dyn FnMut(&str)) -> bool,
        reaches: impl Fn(&str, &[&str]) -> bool,
    ) -> Option<Self> {
        let mut reached: Vec<RouteKey<S>> = Vec::new();
        // One buffer for the chunks of every kept keyexpr asked about, in turn.
        let mut chunks: Vec<&str> = Vec::new();
        let complete = match &self.by_keyexpr {
            // The index's candidates for each key that moved, each split to be asked.
            Some(index) => changes(since, &mut |changed| {
                reached.extend(
                    index
                        .intersecting(changed)
                        .into_iter()
                        .filter(|cached| {
                            // The key as the index lends it, which outlives the buffer.
                            let cached: &RouteKey<S> = cached;
                            chunks.clear();
                            chunks.extend(cached.keyexpr.split('/'));
                            reaches(changed, &chunks)
                        })
                        .cloned(),
                );
            }),
            // Every kept keyexpr, split once and asked of every key that moved.
            None => {
                let mut moved: Vec<String> = Vec::new();
                let complete = changes(since, &mut |changed| moved.push(changed.to_owned()));
                if complete && !moved.is_empty() {
                    reached.extend(
                        self.routes
                            .keys()
                            .filter(|cached| {
                                let cached: &RouteKey<S> = cached;
                                chunks.clear();
                                chunks.extend(cached.keyexpr.split('/'));
                                moved.iter().any(|changed| reaches(changed, &chunks))
                            })
                            .cloned(),
                    );
                }
                complete
            }
        };
        if !complete {
            return None;
        }
        for key in &reached {
            self.remove(key);
        }
        Some(self)
    }
}

/// The memo of a write's draft, while the write moves the inputs of the memo it was opened over.
#[derive(Debug)]
struct Draft<T, S> {
    /// The memo of the version the draft was copied from. A route asked at its inputs (the draft
    /// before the write moved them) is served from it and added to it, as a reader's is.
    base: Arc<RouteCache<T, S>>,
    /// Whether `base` is indexed, so that what the draft keeps is indexed as `base` is.
    indexed: bool,
    /// The routes computed at the inputs the draft was last asked at, and those inputs. One set:
    /// the draft's inputs only move forward, so the routes of the inputs it left are never asked
    /// for again.
    at: PlainMutex<Option<(RouteInputs, Kept<T, S>)>>,
}

impl<T: Clone, S: Clone + Eq + Hash> Draft<T, S> {
    /// [`RouteCache::get_or_compute`] for the memo of a draft.
    fn get_or_compute(
        &self,
        inputs: RouteInputs,
        source: &S,
        keyexpr: &str,
        resource: impl FnOnce() -> bool,
        compute: impl FnOnce() -> T,
    ) -> T {
        if self.base.inputs == Some(inputs) {
            return self
                .base
                .get_or_compute(inputs, source, keyexpr, resource, compute);
        }
        #[cfg(test)]
        self.base.off_version.asked.bump();
        let key: &dyn RouteKeyParts<S> = &(keyexpr, source);
        let served = match &*self.at.guard() {
            Some((at, kept)) if *at == inputs => kept.routes.get(key).cloned(),
            _ => None,
        };
        if let Some(route) = served {
            return route;
        }
        let route = compute();
        self.base.computes.bump();
        #[cfg(test)]
        self.base.off_version.computed.bump();
        if resource() {
            let mut at = self.at.guard();
            if !matches!(&*at, Some((was, _)) if *was == inputs) {
                *at = Some((inputs, Kept::empty(self.indexed)));
            }
            if let Some((_, kept)) = &mut *at {
                kept.insert(keyexpr, source, route.clone());
            }
        }
        route
    }
}

/// The asks a memo answered at inputs no version's memo was brought to.
#[cfg(test)]
#[derive(Debug, Default)]
struct OffVersion {
    /// Routes asked.
    asked: Counter,
    /// Of those, the routes computed: every one where the tables keep no draft memo.
    computed: Counter,
}

impl<T, S> Default for RouteCache<T, S> {
    fn default() -> Self {
        Self::starting(Kept::empty(false))
    }
}

impl<T, S> RouteCache<T, S> {
    /// A memo brought to no version yet, keeping `kept`.
    fn starting(kept: Kept<T, S>) -> Self {
        Self {
            inputs: None,
            kept: PlainRwLock::new(kept),
            computes: Arc::new(Counter::new()),
            #[cfg(test)]
            off_version: Arc::default(),
            draft: None,
        }
    }
}

impl<T: Clone, S: Clone + Eq + Hash> RouteCache<T, S> {
    /// An empty cache, brought to no version yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty cache, brought to no version yet, that also keeps its routes' keyexprs in an index:
    /// for a memo whose writer leaves out the routes a change reaches
    /// ([`bring_to_retiring`](Self::bring_to_retiring)). Every route a reader adds is also added to
    /// the index, and the writer then finds the routes a changed key reaches by a walk of the
    /// index. The memos brought from it are indexed too.
    pub fn indexed() -> Self {
        Self::starting(Kept::empty(true))
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
        if self.inputs != Some(inputs) {
            return match &self.draft {
                Some(draft) => draft.get_or_compute(inputs, source, keyexpr, resource, compute),
                None => self.compute_off_version(compute),
            };
        }
        let key: &dyn RouteKeyParts<S> = &(keyexpr, source);
        if let Some(route) = self.kept.read().routes.get(key) {
            return route.clone();
        }
        let route = compute();
        self.computes.bump();
        if resource() {
            self.kept.write().insert(keyexpr, source, route.clone());
        }
        route
    }

    /// The route asked of a published version's memo at inputs other than its own: computed, and
    /// not kept.
    fn compute_off_version(&self, compute: impl FnOnce() -> T) -> T {
        #[cfg(test)]
        self.off_version.asked.bump();
        let route = compute();
        self.computes.bump();
        #[cfg(test)]
        self.off_version.computed.bump();
        route
    }

    /// Give the draft of a write a memo of its own, in place of `memo`, before the write moves an
    /// input of `memo`: what the writer routes through its draft is then kept, at the draft's
    /// inputs, and becomes part of the version's memo when the draft is published at those inputs
    /// ([`bring_to_retiring`](Self::bring_to_retiring)). A route asked at the inputs `memo` is at
    /// is served from `memo` and added to it, as a reader's is. Called by the writer of tables that
    /// keep what their writer routes (`docs/router-table-snapshots.md`, section 6.9); the version
    /// that shares `memo` keeps it as it was. A memo that is already a draft's stays.
    ///
    /// A draft that is abandoned takes its memo with it, so no other draft is ever served the
    /// routes of tables that were never published, though its inputs may come to the same numbers.
    pub fn open_draft(memo: &mut Arc<Self>) {
        if memo.draft.is_some() {
            return;
        }
        let base = Arc::clone(memo);
        let indexed = base.kept.read().is_indexed();
        *memo = Arc::new(Self {
            inputs: None,
            kept: PlainRwLock::new(Kept::empty(false)),
            computes: Arc::clone(&base.computes),
            #[cfg(test)]
            off_version: Arc::clone(&base.off_version),
            draft: Some(Box::new(Draft {
                base,
                indexed,
                at: PlainMutex::new(None),
            })),
        });
    }

    /// `memo` as the memo it was opened over, and what its draft kept at the draft's inputs. A
    /// draft's memo is never published.
    fn close_draft(memo: &mut Arc<Self>) -> Option<(RouteInputs, Kept<T, S>)> {
        let (base, drafted) = {
            let draft = memo.draft.as_ref()?;
            (
                Arc::clone(&draft.base),
                std::mem::take(&mut *draft.at.guard()),
            )
        };
        *memo = base;
        drafted
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
    /// a change of `changed` can alter the route kept for the keyexpr whose chunks are `cached`, and
    /// must imply that the two keyexprs intersect: an indexed memo ([`indexed`](Self::indexed))
    /// asks it only of the routes whose keyexpr the index finds may intersect `changed`, and an
    /// unindexed one splits each kept keyexpr once and asks it of every key that moved. A topology
    /// move (`net`), a memo brought to no version yet, or a table that cannot answer starts the new
    /// memo empty; a table that answers that nothing moved keeps every route.
    ///
    /// Safe by construction: it only ever leaves out more than it must, never fewer, because the
    /// caller supplies the keys the table's own mutators recorded and every mutation records its
    /// key. The new memo starts from the routes `memo` holds when it is called, which readers of the
    /// versions before may still add to: what they add after it is theirs alone.
    ///
    /// A draft's memo ([`open_draft`](Self::open_draft)) is closed first: the new memo is brought
    /// from the memo the draft was opened over, and also keeps what the draft kept when the draft
    /// was last asked at `inputs`, which are routes of these very tables.
    pub fn bring_to_retiring(
        memo: &mut Arc<Self>,
        inputs: RouteInputs,
        changes: impl FnOnce(u64, &mut dyn FnMut(&str)) -> bool,
        reaches: impl Fn(&str, &[&str]) -> bool,
    ) {
        let drafted = Self::close_draft(memo);
        if memo.inputs == Some(inputs) {
            return;
        }
        let mut kept = match memo.inputs {
            Some(was) if was.net == inputs.net => {
                let kept = Kept::clone(&memo.kept.read());
                let indexed = kept.is_indexed();
                kept.retiring(was.table, changes, reaches)
                    .unwrap_or_else(|| Kept::empty(indexed))
            }
            _ => Kept::empty(memo.kept.read().is_indexed()),
        };
        if let Some((_, routes)) = drafted.filter(|(at, _)| *at == inputs) {
            for (key, route) in &routes.routes {
                kept.put(key.clone(), route.clone());
            }
        }
        *memo = Arc::new(Self {
            inputs: Some(inputs),
            kept: PlainRwLock::new(kept),
            computes: Arc::clone(&memo.computes),
            #[cfg(test)]
            off_version: Arc::clone(&memo.off_version),
            draft: None,
        });
    }

    /// How many routes this memo, and every memo it was brought from, computed rather than served.
    pub fn computes(&self) -> usize {
        self.computes.get()
    }

    /// The routes asked of this memo, and of every memo it was brought from, at inputs no
    /// version's memo was brought to, and how many of those were computed.
    #[cfg(test)]
    pub(crate) fn asks_off_version(&self) -> (usize, usize) {
        (
            self.off_version.asked.get(),
            self.off_version.computed.get(),
        )
    }

    /// How many routes this memo keeps: for a draft's memo, those of the memo it was opened over
    /// and those it kept at the draft's inputs.
    pub fn len(&self) -> usize {
        match &self.draft {
            Some(draft) => {
                let drafted = match &*draft.at.guard() {
                    Some((_, kept)) => kept.routes.len(),
                    None => 0,
                };
                draft.base.len() + drafted
            }
            None => self.kept.read().routes.len(),
        }
    }

    /// Whether no route is kept.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wz_session_core::keyexpr_match::{keyexpr_intersects_target, keyexpr_intersects_text};

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
        assert_eq!(
            cache.asks_off_version(),
            (2, 2),
            "both asks at the other inputs are counted, and both were computed"
        );
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
            |changed, cached| changed.split('/').eq(cached.iter().copied()),
        );
        (memo, moved)
    }

    #[test]
    fn a_table_move_that_moved_no_key_keeps_every_route_and_asks_no_reach() {
        let mut memo: Arc<RouteCache<Vec<Zid>>> = at(AT);
        memo.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        RouteCache::bring_to_retiring(
            &mut memo,
            RouteInputs { table: 2, ..AT },
            |_, _| true,
            |_, _| unreachable!("nothing moved, so no route is asked about"),
        );
        assert_eq!(memo.len(), 1, "the route was kept");
    }

    #[test]
    fn the_reach_is_asked_with_the_chunks_of_the_kept_keyexpr() {
        let mut memo: Arc<RouteCache<Vec<Zid>>> = at(AT);
        memo.get_or_compute(AT, &zid(1), "demo/a/b", || true, || vec![zid(9)]);
        let asked = std::cell::RefCell::new(Vec::new());
        RouteCache::bring_to_retiring(
            &mut memo,
            RouteInputs { table: 2, ..AT },
            |_, visit| {
                visit("other/x");
                visit("other/y");
                true
            },
            |changed, cached| {
                asked
                    .borrow_mut()
                    .push((changed.to_owned(), cached.join("|")));
                false
            },
        );
        assert_eq!(
            *asked.borrow(),
            [
                ("other/x".to_owned(), "demo|a|b".to_owned()),
                ("other/y".to_owned(), "demo|a|b".to_owned())
            ],
            "each moved key is asked of the kept keyexpr's chunks"
        );
        assert_eq!(memo.len(), 1, "a route no moved key reaches is kept");
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

    /// The inputs of a draft whose write moved the table once, and of the same draft moved again.
    const DRAFT: RouteInputs = RouteInputs { net: 1, table: 2 };
    const LATER: RouteInputs = RouteInputs { net: 1, table: 3 };

    /// An indexed memo brought to `inputs`, as the writer of the first version leaves it.
    fn indexed_at(inputs: RouteInputs) -> Arc<RouteCache<u64, ()>> {
        let mut memo = Arc::new(RouteCache::indexed());
        RouteCache::bring_to(&mut memo, inputs);
        memo
    }

    /// The keyexprs a memo of one source keeps. For an indexed memo, also requires that the index
    /// holds every route's key under its keyexpr and nothing else.
    fn kept_keys(memo: &RouteCache<u64, ()>) -> BTreeSet<String> {
        let kept = memo.kept.read();
        if let Some(index) = &kept.by_keyexpr {
            assert_eq!(
                index.len(),
                kept.routes.len(),
                "the index holds one entry per route"
            );
            for key in kept.routes.keys() {
                assert!(
                    index.contains(&key.keyexpr, key),
                    "{} is indexed under its keyexpr",
                    key.keyexpr
                );
            }
        }
        let keys = kept
            .routes
            .keys()
            .map(|key| key.keyexpr.to_string())
            .collect();
        drop(kept);
        keys
    }

    /// A small deterministic generator (xorshift64*), so that a failing sequence replays.
    struct Draw(u64);

    impl Draw {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        /// A keyexpr of one to three chunks, drawn from chunks that exercise every rule of the
        /// matcher: literals, `*`, `**`, `$*` within a chunk and a verbatim chunk.
        fn keyexpr(&mut self) -> String {
            const CHUNKS: [&str; 8] = ["a", "b", "dev_7", "*", "**", "x$*", "$*7", "@v"];
            let depth = 1 + self.next() % 3;
            (0..depth)
                .map(|_| CHUNKS[(self.next() % CHUNKS.len() as u64) as usize])
                .collect::<Vec<_>>()
                .join("/")
        }
    }

    /// An indexed memo, brought across table moves whose changed keys are drawn from every kind of
    /// chunk the matcher knows, leaves out exactly the routes a memo with no index leaves out, which
    /// are the routes some changed key intersects, and its index holds exactly its routes after
    /// every move. Turned red by an index walk that misses a route a changed key meets, or by a
    /// route left out of the routes and not of the index.
    #[test]
    fn an_indexed_memo_leaves_out_exactly_the_routes_a_scan_leaves_out() {
        for seed in 1..=6u64 {
            let mut draw = Draw(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut scanned: Arc<RouteCache<u64, ()>> = at(AT);
            let mut indexed = indexed_at(AT);
            let mut inputs = AT;
            for step in 0..40 {
                for _ in 0..12 {
                    let keyexpr = draw.keyexpr();
                    let route = draw.next();
                    for memo in [&scanned, &indexed] {
                        memo.get_or_compute(inputs, &(), &keyexpr, || true, || route);
                    }
                }
                let before = kept_keys(&scanned);
                assert_eq!(
                    kept_keys(&indexed),
                    before,
                    "seed {seed} step {step}: both memos keep the routes the readers added"
                );
                let changed: Vec<String> =
                    (0..1 + draw.next() % 3).map(|_| draw.keyexpr()).collect();
                let moved = RouteInputs {
                    table: inputs.table + 1,
                    ..inputs
                };
                for memo in [&mut scanned, &mut indexed] {
                    RouteCache::bring_to_retiring(
                        memo,
                        moved,
                        |since, visit| {
                            assert_eq!(since, inputs.table, "asked from the memo's version");
                            changed.iter().for_each(|key| visit(key));
                            true
                        },
                        keyexpr_intersects_target,
                    );
                }
                inputs = moved;
                let want: BTreeSet<String> = before
                    .into_iter()
                    .filter(|cached| {
                        !changed
                            .iter()
                            .any(|key| keyexpr_intersects_text(key, cached))
                    })
                    .collect();
                assert_eq!(
                    kept_keys(&scanned),
                    want,
                    "seed {seed} step {step}: the scan leaves out what {changed:?} reaches"
                );
                assert_eq!(
                    kept_keys(&indexed),
                    want,
                    "seed {seed} step {step}: the index finds what {changed:?} reaches"
                );
            }
        }
    }

    /// A draft's memo keeps what its writer computes at the draft's inputs and serves it when it is
    /// asked again there, and the version published at those inputs keeps it, so its readers are
    /// served. The version the draft was copied from keeps what it kept. Turned red by a draft memo
    /// that computes every time, or by a publish that drops what the draft kept.
    #[test]
    fn a_drafts_memo_keeps_what_its_writer_routes_and_its_version_serves_it() {
        let published: Arc<RouteCache<u64, ()>> = at(AT);
        published.get_or_compute(AT, &(), "demo/a", || true, || 1);
        let mut draft = Arc::clone(&published);
        RouteCache::open_draft(&mut draft);
        assert_eq!(draft.get_or_compute(DRAFT, &(), "demo/b", || true, || 2), 2);
        assert_eq!(
            draft.get_or_compute(DRAFT, &(), "demo/b", || true, || unreachable!()),
            2,
            "asked again at the draft's inputs, the route is served"
        );
        assert_eq!(
            draft.asks_off_version(),
            (2, 1),
            "two asks at the draft's inputs, one computed"
        );
        assert_eq!(
            published.len(),
            1,
            "the published version's memo is as it was"
        );
        assert_eq!(draft.len(), 2);
        RouteCache::bring_to_retiring(
            &mut draft,
            DRAFT,
            |_, visit| {
                visit("demo/b");
                true
            },
            |changed, cached| changed.split('/').eq(cached.iter().copied()),
        );
        assert!(draft.draft.is_none(), "a published memo is no draft's");
        let computes = draft.computes();
        assert_eq!(
            draft.get_or_compute(DRAFT, &(), "demo/b", || true, || unreachable!()),
            2,
            "the version keeps the route its draft computed"
        );
        assert_eq!(
            draft.get_or_compute(DRAFT, &(), "demo/a", || true, || unreachable!()),
            1,
            "and the route the change did not reach"
        );
        assert_eq!(draft.computes(), computes);
    }

    /// A draft's memo asked at the inputs of the memo it was opened over (the draft before its write
    /// moved them) reads and adds to that memo, as a reader of the version does, and the ask is not
    /// counted as one off a version. Turned red by a draft memo that keeps such a route to itself.
    #[test]
    fn a_drafts_memo_at_the_inputs_it_was_opened_over_reads_and_adds_to_the_versions_memo() {
        let published: Arc<RouteCache<u64, ()>> = at(AT);
        published.get_or_compute(AT, &(), "demo/a", || true, || 1);
        let mut draft = Arc::clone(&published);
        RouteCache::open_draft(&mut draft);
        assert_eq!(
            draft.get_or_compute(AT, &(), "demo/a", || true, || unreachable!()),
            1
        );
        draft.get_or_compute(AT, &(), "demo/c", || true, || 3);
        assert_eq!(
            published.len(),
            2,
            "a route asked at the version's inputs is the version's"
        );
        assert_eq!(draft.asks_off_version(), (0, 0));
    }

    /// What a draft kept at inputs it then moved past is not published, nor is anything when the
    /// draft is published at inputs it was never asked at. Turned red by a publish that keeps
    /// routes computed for tables other than the published ones.
    #[test]
    fn a_draft_publishes_only_what_it_kept_at_the_inputs_it_is_published_at() {
        let published: Arc<RouteCache<u64, ()>> = at(AT);
        let mut moved_on = Arc::clone(&published);
        RouteCache::open_draft(&mut moved_on);
        moved_on.get_or_compute(DRAFT, &(), "demo/a", || true, || 1);
        moved_on.get_or_compute(LATER, &(), "demo/b", || true, || 2);
        assert_eq!(
            moved_on.len(),
            1,
            "moving on to later inputs left the earlier inputs' routes"
        );
        RouteCache::bring_to(&mut moved_on, LATER);
        assert_eq!(moved_on.len(), 1);
        moved_on.get_or_compute(LATER, &(), "demo/b", || true, || unreachable!());

        let mut elsewhere = Arc::clone(&published);
        RouteCache::open_draft(&mut elsewhere);
        elsewhere.get_or_compute(DRAFT, &(), "demo/a", || true, || 1);
        RouteCache::bring_to(&mut elsewhere, LATER);
        assert!(
            elsewhere.is_empty(),
            "nothing the draft kept was at the inputs it was published at"
        );
    }

    /// A memo that is already a draft's is not opened again, and a draft that is abandoned leaves
    /// the version's memo as it was: a later draft that comes to the same inputs is served nothing
    /// the abandoned one kept. Turned red by a draft's routes kept in the version's memo, which a
    /// draft of other tables at equal version numbers would then be served.
    #[test]
    fn a_draft_is_opened_once_and_one_abandoned_leaves_nothing_behind() {
        let published: Arc<RouteCache<u64, ()>> = at(AT);
        let mut abandoned = Arc::clone(&published);
        RouteCache::open_draft(&mut abandoned);
        let opened = Arc::clone(&abandoned);
        RouteCache::open_draft(&mut abandoned);
        assert!(
            Arc::ptr_eq(&opened, &abandoned),
            "a draft's memo is opened once"
        );
        abandoned.get_or_compute(DRAFT, &(), "demo/a", || true, || 1);
        drop((opened, abandoned));
        assert!(published.is_empty());
        let mut next = Arc::clone(&published);
        RouteCache::open_draft(&mut next);
        assert_eq!(
            next.get_or_compute(DRAFT, &(), "demo/a", || true, || 2),
            2,
            "the next draft computes its own route"
        );
    }

    /// The routes a draft of an indexed memo keeps are indexed in the version it is published as,
    /// so the next change finds them. Turned red by a draft that keeps its routes unindexed.
    #[test]
    fn a_drafts_routes_published_into_an_indexed_memo_are_found_by_the_next_change() {
        let mut memo = indexed_at(AT);
        RouteCache::open_draft(&mut memo);
        memo.get_or_compute(DRAFT, &(), "demo/a", || true, || 1);
        memo.get_or_compute(DRAFT, &(), "demo/b", || true, || 2);
        RouteCache::bring_to(&mut memo, DRAFT);
        assert_eq!(
            kept_keys(&memo),
            BTreeSet::from(["demo/a".to_owned(), "demo/b".to_owned()])
        );
        RouteCache::bring_to_retiring(
            &mut memo,
            LATER,
            |_, visit| {
                visit("demo/*");
                true
            },
            keyexpr_intersects_target,
        );
        assert!(
            memo.is_empty(),
            "the index found both routes the change reaches"
        );
    }
}
