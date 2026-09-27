// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! [`RouteCache`](crate::route_cache::RouteCache) is that shape, keyed by keyexpr then source. Two points
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

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::hash::Hash;

use wz_routing_graph::Zid;

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

/// Routes by keyexpr, then by source, all fresh at one [`RouteInputs`].
#[derive(Debug)]
struct Fresh<T, S> {
    inputs: Option<RouteInputs>,
    routes: HashMap<String, HashMap<S, T>>,
}

/// A per-(keyexpr, source) route cache; see the module docs.
///
/// `S` is what distinguishes one route for a keyexpr from another: the source
/// node on a mesh, whose spanning tree the route follows (upstream's mapped
/// `NodeId`). A client leg has no such dimension, since every source reaches
/// the same leaf faces, and keys by `()`.
///
/// Interior-mutable because the forwarders route through `&self`.
#[derive(Debug)]
pub struct RouteCache<T, S = Zid> {
    fresh: RefCell<Fresh<T, S>>,
    /// How many routes were COMPUTED rather than served. The witness that
    /// separates "the cache is consulted and invalidated" from "the cache
    /// exists": a delivery assertion alone passes with the cache bypassed.
    computes: Cell<usize>,
}

impl<T, S> Default for RouteCache<T, S> {
    fn default() -> Self {
        Self {
            fresh: RefCell::new(Fresh {
                inputs: None,
                routes: HashMap::new(),
            }),
            computes: Cell::new(0),
        }
    }
}

impl<T: Clone, S: Clone + Eq + Hash> RouteCache<T, S> {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The route from `source` for `keyexpr` at `inputs`: served when one was
    /// computed at the same inputs, else computed by `compute` and, when
    /// `resource` answers that the expression is a declared one, kept.
    /// `resource` is asked only on a miss, so a served route never pays for
    /// the question.
    ///
    /// Storing at new inputs first drops every route kept at the old ones, as
    /// upstream's `Routes::set_route` clears on a version change, so stale
    /// entries never outlive the next store. `compute` must not route through
    /// this cache.
    pub fn get_or_compute(
        &self,
        inputs: RouteInputs,
        source: &S,
        keyexpr: &str,
        resource: impl FnOnce() -> bool,
        compute: impl FnOnce() -> T,
    ) -> T {
        {
            let fresh = self.fresh.borrow();
            if fresh.inputs == Some(inputs) {
                if let Some(route) = fresh.routes.get(keyexpr).and_then(|by| by.get(source)) {
                    return route.clone();
                }
            }
        }
        let route = compute();
        self.computes.set(self.computes.get() + 1);
        if resource() {
            let mut fresh = self.fresh.borrow_mut();
            if fresh.inputs != Some(inputs) {
                fresh.routes.clear();
                fresh.inputs = Some(inputs);
            }
            fresh
                .routes
                .entry(keyexpr.to_owned())
                .or_default()
                .insert(source.clone(), route.clone());
        }
        route
    }

    /// How many routes this cache computed rather than served.
    pub fn computes(&self) -> usize {
        self.computes.get()
    }

    /// How many routes are kept, fresh or not.
    pub fn len(&self) -> usize {
        self.fresh.borrow().routes.values().map(HashMap::len).sum()
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

    #[test]
    fn a_resource_route_is_computed_once_and_served_at_the_same_inputs() {
        let cache: RouteCache<Vec<Zid>> = RouteCache::new();
        let first = cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let again = cache.get_or_compute(AT, &zid(1), "demo/a", || true, || unreachable!());
        assert_eq!(first, again);
        assert_eq!(cache.computes(), 1);
    }

    #[test]
    fn a_route_is_per_source_and_per_keyexpr() {
        let cache: RouteCache<Vec<Zid>> = RouteCache::new();
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        let other_source = cache.get_or_compute(AT, &zid(2), "demo/a", || true, || vec![zid(8)]);
        let other_key = cache.get_or_compute(AT, &zid(1), "demo/b", || true, || vec![zid(7)]);
        assert_eq!(other_source, vec![zid(8)]);
        assert_eq!(other_key, vec![zid(7)]);
        assert_eq!(cache.computes(), 3);
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn either_input_moving_recomputes_and_drops_the_old_routes() {
        let cache: RouteCache<Vec<Zid>> = RouteCache::new();
        cache.get_or_compute(AT, &zid(1), "demo/a", || true, || vec![zid(9)]);
        cache.get_or_compute(AT, &zid(1), "demo/b", || true, || vec![zid(9)]);
        let net_moved = RouteInputs { net: 2, ..AT };
        let got = cache.get_or_compute(net_moved, &zid(1), "demo/a", || true, || vec![zid(3)]);
        assert_eq!(
            got,
            vec![zid(3)],
            "a net change must not serve the old route"
        );
        assert_eq!(
            cache.len(),
            1,
            "the store at new inputs dropped the stale route"
        );
        let table_moved = RouteInputs {
            table: 2,
            ..net_moved
        };
        let got = cache.get_or_compute(table_moved, &zid(1), "demo/a", || true, || vec![zid(4)]);
        assert_eq!(
            got,
            vec![zid(4)],
            "a table change must not serve the old route"
        );
        assert_eq!(cache.computes(), 4);
    }

    #[test]
    fn an_expression_that_is_not_a_resource_is_computed_every_time_and_never_kept() {
        let cache: RouteCache<Vec<Zid>> = RouteCache::new();
        cache.get_or_compute(AT, &zid(1), "demo/x", || false, || vec![zid(9)]);
        cache.get_or_compute(AT, &zid(1), "demo/x", || false, || vec![zid(9)]);
        assert_eq!(cache.computes(), 2);
        assert!(cache.is_empty(), "an undeclared expression keeps nothing");
    }
}
