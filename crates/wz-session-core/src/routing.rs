// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qc/qd/qf — the data-plane forwarding kernel: the `routing-routes` atom.
//!
//! [`crate::switchboard`] turns an inbound Push into a *local* statechart
//! event; the [`RouteTable`] here turns an inbound Push into *outbound Pushes
//! on the other peers' links* — a router's data plane. The
//! `routing-router` foundation ([`accept_loop`](../../wz_runtime_tokio/accept_loop/index.html))
//! binds once and *holds* N concurrent peer faces with no traffic between
//! them; this kernel is what makes a held face a *route*: a Put received on
//! face A is forwarded to every other face that has declared a matching
//! subscriber.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh's dispatcher data-plane forward (zenoh 1.5.0,
//! `zenoh/src/net/routing`): a face's subscriptions live as
//! `Resource::session_ctxs[face].subs` (`dispatcher/resource.rs`), an inbound
//! Push routes via `route_data` -> `compute_data_route` to the set of faces
//! whose subscription matches (`hat/router/pubsub.rs`, `sub.matches(res)` =
//! keyexpr intersection), and each destination receives it through
//! `outface.primitives.send_push` (`dispatcher/pubsub.rs`). Here the per-face
//! subscription set is [`FaceRoute::subs`], the route computation is the
//! [`declared_intersects`](crate::declare) scan in
//! [`RouteTable::forward_push`] — the SAME matcher the destination's own
//! [`SubscriberRegistry`](crate::declare::subscriber) uses, so the router's
//! route decision and the endpoint's fire decision cannot diverge — and the
//! per-destination send is
//! [`SessionLinkActions::send_network_message`](crate::session_actions::SessionLinkActions::send_network_message),
//! the same transport send seam a session's own publish routes through, so the
//! forwarded Push is framed and SN-stamped by the *destination* face's own
//! outbound (exactly as zenoh's egress `Mux` re-frames a forwarded message).
//!
//! ## Route cache (R311qf, matching zenoh)
//!
//! [`forward_push`](RouteTable::forward_push) does not recompute the
//! destination set on every Put. A resolved keyexpr's matching face set is
//! cached (`RouteCache`) and reused until a *topology change* — a subscription
//! declared / undeclared, or a face removed — bumps the table's `generation`
//! epoch, after which the next lookup recomputes. This is zenoh's mechanism:
//! `dispatcher/resource.rs` caches a `Routes<T> { version, .. }` on each
//! resource and `dispatcher/pubsub.rs` `get_or_set_route` reads-or-computes it,
//! gated by `tables.routes_version`; a generation/version stamp decides
//! freshness, so an invalidation is one counter bump that touches no cache
//! entry (lazy, self-healing on the next read).
//!
//! Remaining divergence (intentional, single-hop star): the cache is one
//! global keyexpr-keyed map, not a per-resource cache split by the source's
//! `whatami` / routing-context node. A star router has a single source class
//! and no multi-hop routing context, so the node/whatami dimension zenoh keys
//! on collapses to a point — one entry per keyexpr suffices, and it is
//! source-independent (it holds every matching face, even the eventual ingress;
//! [`forward_push`](RouteTable::forward_push) skips the ingress at send time),
//! so a single entry serves every face that publishes the keyexpr.
//!
//! This collapse holds because the `routing-routes` data plane only ever runs
//! over the accept-only star (one Client->Peer source class): `routing-peer`
//! deliberately does NOT pull `routing-routes` (Cargo.toml), so a mesh peer
//! reaches this cache only once mesh forwarding lands — at which point the
//! whatami / node dimension stops collapsing and this single-map design must be
//! revisited (the route key gains the source dimension zenoh keys on).
//!
//! ## Keyexpr forms (literal + aliased)
//!
//! A peer's default publish / declare path emits a **literal** keyexpr
//! (`WireexprLocal { id: 0, suffix }`, see `push_build` / `declare_build`); a
//! peer that opts into the bandwidth optimisation first sends a
//! `Declare(DeclareKeyexpr)` mapping `id -> "K"`, then carries only `id` on
//! subsequent records. R311qc routed the literal form; R311qd resolves the
//! aliased form too: [`record_declare`](RouteTable::record_declare) records each
//! `DeclareKeyexpr` into the source face's [`peer_aliases`](FaceRoute), and both
//! an aliased subscription and an aliased Put resolve through it
//! ([`resolve_wireexpr`]). A literal Put is still forwarded **verbatim** (all
//! metadata preserved); an aliased Put is **re-literalized** for the
//! destination ([`reliteralize_push`](crate::push_build::reliteralize_push)) —
//! the destination never saw the source's
//! expr-id mapping, so it receives the resolved keyexpr as a literal (`id = 0`)
//! while the Put body (payload / encoding / attachment) is preserved. An
//! expr-id with no prior `DeclareKeyexpr` resolves to `None` and is dropped with
//! a debug trace.
//!
//! ## NON-goals (this atom)
//!
//! Multi-hop declaration propagation (a router forwarding a peer's
//! DeclareSubscriber to the *other* peers so they gate their own emit — an
//! interest optimisation, not required for a single-hop star: a producer
//! sends its Put unconditionally and the router routes it), zid-keyed mesh
//! de-duplication (the `src != dst` skip suffices for the star topology; a
//! mesh needs source-zid suppression), and Queryable / liveliness routing
//! (Push only).
//! Self-echo cannot occur: a face never receives its own Put back (`src_id`
//! is skipped).

#[cfg(all(feature = "alloc", feature = "routing-routes"))]
pub use imp::{FaceRoute, RouteTable};

#[cfg(all(feature = "alloc", feature = "routing-routes"))]
mod imp {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use hashbrown::HashMap;

    use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
    use wz_codecs::push::PushOwned;
    use wz_runtime_core::TimeSource;

    use crate::declare::declared_intersects;
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::link::SessionRuntime;
    use crate::network_message::NetworkMessage;
    use crate::session_actions::SessionLinkActions;
    use crate::wireexpr_resolve::resolve_wireexpr;
    use alloc::sync::Arc;

    /// One held peer face's routing state: the outbound send seam shared with
    /// the face's own session driver (so this kernel can forward TO the peer)
    /// plus the subscriptions it has declared.
    pub struct FaceRoute<R: SessionRuntime, T: TimeSource> {
        /// The face's transport send seam — an [`Arc`] clone of the same
        /// [`SessionLinkActions`] the face's driver holds. A forward is a
        /// [`SessionLinkActions::send_network_message`] call on this, so the
        /// Put is framed + SN-stamped on the destination face's own outbound.
        actions: Arc<SessionLinkActions<R, T>>,
        /// Declared subscriptions: the resolved keyexpr string, keyed by the
        /// wire subscriber id so an `UndeclareSubscriber` removes exactly the
        /// matching one. This is the SAME stored form as the destination's own
        /// [`SubscriberRegistry`](crate::declare::subscriber)`::declared`
        /// (id -> resolved keyexpr `String`), and the match below routes through
        /// the SAME [`declared_intersects`] SSOT that registry uses — so the
        /// router's route decision and the destination subscriber's fire
        /// decision are computed by one function and cannot disagree.
        subs: HashMap<u64, String>,
        /// Per-face expr-id -> literal-keyexpr alias table, the resolution
        /// context [`resolve_wireexpr`] consumes. Populated from inbound
        /// `DeclareKeyexpr` records (R311qd) and consulted when resolving both
        /// an aliased subscription's keyexpr and an aliased Put's keyexpr.
        /// Per-face because each peer owns an independent expr-id namespace —
        /// the same per-session table [`crate::pubsub::SubscriberRegistry`]
        /// keeps (`peer_keyexpr_table`).
        peer_aliases: HashMap<u64, String>,
    }

    impl<R: SessionRuntime, T: TimeSource> FaceRoute<R, T> {
        fn new(actions: Arc<SessionLinkActions<R, T>>) -> Self {
            Self {
                actions,
                subs: HashMap::new(),
                peer_aliases: HashMap::new(),
            }
        }

        /// Does any of this face's subscriptions match `keyexpr`? Routes through
        /// [`declared_intersects`] — the exact matcher
        /// [`SubscriberRegistry::has_matching`](crate::declare::subscriber)
        /// uses — so keyexpr intersection (zenoh's `sub.matches(res)` semantics,
        /// symmetric pattern-vs-pattern), not a pattern-vs-literal shortcut.
        fn matches(&self, keyexpr: &str) -> bool {
            declared_intersects(&self.subs, keyexpr)
        }
    }

    /// The per-keyexpr destination cache: a resolved keyexpr -> the set of face
    /// ids whose subscriptions match it. Tagged with the
    /// [`RouteTable::generation`] epoch it was computed at, so a topology change
    /// (a generation bump) makes every entry stale without touching the map —
    /// the next [`insert`](RouteCache::insert) at the new epoch physically drops
    /// the stale entries first, bounding the map to the keyexprs published since
    /// the last topology change. A direct mirror of zenoh's
    /// `Routes<T> { version, .. }` (`dispatcher/resource.rs`): [`get`](RouteCache::get)
    /// is zenoh's `get_route` (version-gated read), [`insert`](RouteCache::insert)
    /// is `set_route` (clear-on-version-change, then store).
    struct RouteCache {
        version: u64,
        routes: HashMap<String, Arc<[u64]>>,
    }

    impl RouteCache {
        /// The cached destination set for `keyexpr`, but only if the cache is
        /// still fresh at `generation`. A stale cache (version != generation)
        /// reports a miss for every key — its entries are logically cleared
        /// (and physically cleared on the next [`insert`](Self::insert)).
        fn get(&self, keyexpr: &str, generation: u64) -> Option<Arc<[u64]>> {
            if self.version != generation {
                return None;
            }
            self.routes.get(keyexpr).cloned()
        }

        /// Store `ids` for `keyexpr`. If the cache is stale (its version
        /// predates `generation`), clear the stale entries and adopt the new
        /// version first, so the map only ever holds entries from one
        /// generation. Mirrors zenoh's `set_route` clear-on-version-change.
        fn insert(&mut self, keyexpr: &str, generation: u64, ids: Arc<[u64]>) {
            if self.version != generation {
                self.routes.clear();
                self.version = generation;
            }
            self.routes.insert(keyexpr.into(), ids);
        }

        /// Number of entries valid at `generation` (0 if the cache is stale) —
        /// the witness behind [`RouteTable::cached_route_count`].
        fn valid_len(&self, generation: u64) -> usize {
            if self.version == generation {
                self.routes.len()
            } else {
                0
            }
        }
    }

    /// The router's live routing table: the held faces keyed by the
    /// accept-loop [`FaceId`](../../wz_runtime_tokio/accept_loop/struct.FaceId.html)
    /// value. Single-task by construction (the accept loop holds every face on
    /// one `!Send` task, so the table is wrapped in `Rc<RefCell<…>>` by the
    /// tokio forwarder, never a `Mutex`) — mirroring
    /// [`crate::switchboard::SwitchboardRegistry`]'s `!Sync` contract.
    pub struct RouteTable<R: SessionRuntime, T: TimeSource> {
        faces: HashMap<u64, FaceRoute<R, T>>,
        /// The routing-topology epoch: bumped by every structural change (a
        /// subscription declared / undeclared, a face removed) that can change
        /// which faces a keyexpr routes to. Mirrors zenoh's
        /// `tables.routes_version` (`dispatcher/tables.rs`); [`RouteCache`]
        /// checks an entry's stored version against this to decide freshness, so
        /// an invalidation ([`invalidate_routes`](RouteTable::invalidate_routes))
        /// is a single counter bump that touches no cache entry (lazy,
        /// self-healing on read).
        generation: u64,
        /// The per-keyexpr destination cache. Interior-mutable because
        /// [`forward_push`](RouteTable::forward_push) reads `&self` yet must
        /// populate it on a miss — exactly as zenoh's `get_or_set_route` writes
        /// the per-resource `data_routes` from the read path. `RefCell`, not
        /// `Mutex`, by the same single-task contract as the table itself.
        route_cache: RefCell<RouteCache>,
        /// Count of route computations (cache misses): the full
        /// [`declared_intersects`] scan a miss runs. The cache-effectiveness
        /// witness ([`route_computations`](RouteTable::route_computations)) — a
        /// `Cell` for the same `&self`-on-miss reason as `route_cache`.
        route_computations: Cell<u64>,
    }

    impl<R: SessionRuntime, T: TimeSource> Default for RouteTable<R, T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<R: SessionRuntime, T: TimeSource> RouteTable<R, T> {
        /// A new, empty routing table.
        pub fn new() -> Self {
            Self {
                faces: HashMap::new(),
                generation: 0,
                route_cache: RefCell::new(RouteCache {
                    version: 0,
                    routes: HashMap::new(),
                }),
                route_computations: Cell::new(0),
            }
        }

        /// Register a face that reached Established: its send seam enters the
        /// table so other faces can forward to it. Called from the accept
        /// loop's `FaceUp` handling with an [`Arc`] clone of the face's
        /// actions.
        pub fn add_face(&mut self, id: u64, actions: Arc<SessionLinkActions<R, T>>) {
            // No generation bump: a freshly added face has no subscriptions, so
            // it matches no keyexpr and belongs to no cached route until it
            // declares one — and that declaration bumps the generation. Adding a
            // face therefore cannot stale any cached route.
            self.faces.insert(id, FaceRoute::new(actions));
        }

        /// Remove a face that left (peer Close / link loss): it can no longer
        /// be a destination, and its subscriptions are dropped with it. Called
        /// from the accept loop's `FaceDown` handling.
        pub fn remove_face(&mut self, id: u64) {
            // A removed face may have carried subscriptions that fed cached
            // routes (and its id must never resurface in one), so its departure
            // invalidates the cache.
            if self.faces.remove(&id).is_some() {
                self.invalidate_routes();
            }
        }

        /// Total subscriptions recorded across all faces — the witness the
        /// forwarder's `subscription_count()` passthrough exposes so a test can
        /// assert routing state directly (e.g. that an aliased declare was NOT
        /// recorded), distinct from the observable forward count.
        pub fn subscription_count(&self) -> usize {
            self.faces.values().map(|f| f.subs.len()).sum()
        }

        /// Number of currently-valid cached routes — the cache-state witness a
        /// test asserts to watch a route get cached (1 after a Put on a fresh
        /// keyexpr) and an invalidation empty it (0 after a declare / undeclare /
        /// face-removal, before the next Put recomputes). `pub` (with
        /// [`subscription_count`](Self::subscription_count)) only because the
        /// `RouteTable` lives in this crate while its tests live in
        /// `wz-runtime-tokio`: a cross-crate test observes live cache state
        /// through the public surface, where a `#[cfg(test)]` gate could not
        /// reach. A read-only snapshot, no production state maintained for it.
        pub fn cached_route_count(&self) -> usize {
            self.route_cache.borrow().valid_len(self.generation)
        }

        /// Total route computations (cache misses) run so far — a cumulative
        /// cache-effectiveness signal. A repeated Put on a cached keyexpr does
        /// NOT increment it (served from cache); a Put after an invalidation
        /// does (a fresh [`declared_intersects`] scan). Both a test witness AND
        /// a production ops metric: the demo router logs it in its shutdown
        /// summary (`run_router`), so the counter has a real reader.
        pub fn route_computations(&self) -> u64 {
            self.route_computations.get()
        }

        /// Bump the routing-topology epoch so every cached route becomes stale
        /// on its next lookup. The lazy counterpart to zenoh's
        /// `disable_all_routes` (`dispatcher/tables.rs`): no cache entry is
        /// touched here — freshness is decided on read against
        /// [`generation`](Self::generation), and the stale entries are dropped
        /// by the next insert at the new epoch.
        fn invalidate_routes(&mut self) {
            self.generation = self.generation.saturating_add(1);
        }

        /// Observe one inbound iteration event from face `src_id`: record any
        /// subscription it declared and forward any Put it published to every
        /// other matching face. Returns the number of forwards emitted (0 for
        /// every non-Push, non-Declare event). The single ingress the tokio
        /// [`FaceForwarder`](../../wz_runtime_tokio/accept_loop/trait.FaceForwarder.html)
        /// threads each face's `drive_session_until_terminal` observer into.
        pub fn observe(&mut self, src_id: u64, event: IterationEvent<'_>) -> usize {
            let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages, reliable, ..
            }) = event
            else {
                return 0;
            };
            let mut forwarded = 0;
            for message in messages {
                match message {
                    NetworkMessage::Declare(declare) => self.record_declare(src_id, declare),
                    NetworkMessage::Push(push) => {
                        forwarded += self.forward_push(src_id, push, *reliable)
                    }
                    _ => {}
                }
            }
            forwarded
        }

        /// Apply an inbound `Declare` from `src_id` to that face's routing
        /// state: a `DeclareKeyexpr` records an expr-id -> literal alias, a
        /// `DeclareSubscriber` adds a subscription (resolving any aliased
        /// keyexpr through those aliases), and the `Undeclare*` counterparts
        /// remove them. Other declarations (Queryable / Token) are not routed
        /// (see the module scope note).
        fn record_declare(&mut self, src_id: u64, declare: &DeclareOwned) {
            let Some(face) = self.faces.get_mut(&src_id) else {
                return;
            };
            // Whether this declaration changed the face's *subscription* set
            // (and so which keyexprs route to it). Expr-id alias changes do NOT:
            // an already-recorded subscription stores its resolved literal
            // keyexpr, not the id, so a later DeclareKeyexpr / UndeclareKeyexpr
            // cannot retroactively re-resolve it (record_declare resolves at
            // declare time), and an inbound Put's keyexpr is resolved fresh per
            // Put in `forward_push` before the cache is consulted. So only a
            // subscription delta invalidates the route cache.
            let subscriptions_changed = match &declare.body {
                // R311qd — record the peer's expr-id -> literal-keyexpr mapping
                // so a later aliased subscription / Put resolves through it.
                // Resolved against the EXISTING aliases (a declare may chain off
                // a prior one), mirroring `SubscriberRegistry`'s peer table
                // (pubsub.rs). An id referencing an unknown alias is dropped.
                DeclareOwnedVariant::CodecZenohDeclKexpr(decl) => {
                    if let Some(literal) = resolve_wireexpr(&decl.keyexpr.body, &face.peer_aliases)
                    {
                        face.peer_aliases.insert(decl.id, literal);
                    }
                    false
                }
                DeclareOwnedVariant::CodecZenohUndeclKexpr(undecl) => {
                    face.peer_aliases.remove(&undecl.id);
                    false
                }
                DeclareOwnedVariant::CodecZenohDeclSubscriber(sub) => {
                    // resolve_wireexpr returns an owned String, so the
                    // immutable borrow of `peer_aliases` ends before the
                    // mutable insert into `subs`. A keyexpr that references an
                    // expr-id with no prior DeclareKeyexpr is dropped with a
                    // debug trace (not silently) — an operator can see why a
                    // route never formed.
                    match resolve_wireexpr(&sub.keyexpr.body, &face.peer_aliases) {
                        Some(keyexpr) => {
                            face.subs.insert(sub.id, keyexpr);
                            true
                        }
                        None => {
                            log::debug!(
                                "RouteTable: face {src_id} declared subscriber id={} on an \
                                 expr-id with no prior DeclareKeyexpr mapping; not recorded",
                                sub.id
                            );
                            false
                        }
                    }
                }
                DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl) => {
                    face.subs.remove(&undecl.id).is_some()
                }
                _ => false,
            };
            // `face`'s borrow of `self.faces` ends with the match; bump the epoch
            // after, so a stale cache is recomputed on the next Put.
            if subscriptions_changed {
                self.invalidate_routes();
            }
        }

        /// Forward a Put received on `src_id` to every OTHER face whose
        /// subscriptions match its keyexpr. Returns the number of forwards
        /// that the destination send seam accepted.
        fn forward_push(&self, src_id: u64, push: &PushOwned, reliable: bool) -> usize {
            // Resolve the source keyexpr in the source face's alias context
            // (literal id=0 verbatim; aliased id!=0 via DeclareKeyexpr). An id
            // with no prior mapping yields None and is dropped.
            let Some(src) = self.faces.get(&src_id) else {
                return 0;
            };
            let Some(keyexpr) = resolve_wireexpr(&push.keyexpr.body, &src.peer_aliases) else {
                log::debug!(
                    "RouteTable: face {src_id} published on an expr-id with no prior \
                     DeclareKeyexpr mapping; not forwarded"
                );
                return 0;
            };
            // The destination face-id set for this keyexpr, served from the
            // route cache: a hit (same keyexpr, no topology change since)
            // returns the previously computed set in O(1); a miss runs the
            // O(faces x subs) `declared_intersects` scan once and caches it. The
            // set is SOURCE-INDEPENDENT (it holds every matching face, even the
            // eventual ingress), so one entry serves every face publishing the
            // keyexpr; the ingress is skipped below. Mirrors zenoh's
            // `get_or_set_route` over a resource's `data_routes`.
            let targets = self.route_targets(&keyexpr);
            // Any destination other than the source? A face may subscribe its
            // own keyexpr; it must not receive its own Put — the `src_id` skip
            // is the loop guard, identical to the pre-cache `**id != src_id`
            // filter. (Skip the re-literalize work when only the source matches.)
            if !targets.iter().any(|id| *id != src_id) {
                return 0;
            }
            // Build the destination-facing Push ONCE via the wire-layer SSOT: a
            // literal (id=0) source is forwarded verbatim; an aliased (id!=0)
            // source is re-literalized so a destination that never saw the
            // source's expr-id mapping can decode it. Fails only if the resolved
            // keyexpr exceeds the wire bound (no_std heapless cap; unbounded in
            // alloc) — dropped, logged. The routing kernel stays free of
            // wire-format knowledge ([`reliteralize_push`] owns the keyexpr
            // construction + N-flag bit).
            let forwarded = match crate::push_build::reliteralize_push(push, &keyexpr) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!(
                        "RouteTable: face {src_id} keyexpr could not be re-literalized \
                         for forwarding ({e:?}); not forwarded"
                    );
                    return 0;
                }
            };
            let mut count = 0;
            for id in targets.iter() {
                if *id == src_id {
                    continue;
                }
                // A target id from a fresh cache entry is always still present
                // (a face removal bumps the generation, invalidating the entry);
                // the get-skip is a defensive guard, not a load-bearing path.
                let Some(face) = self.faces.get(id) else {
                    continue;
                };
                // The destination's own send seam mints the frame SN. `express`
                // so an open batch window flushes (deliver-now forward).
                let msg = NetworkMessage::Push(Box::new(forwarded.clone()));
                if face
                    .actions
                    .send_network_message(msg, reliable, true)
                    .is_ok()
                {
                    count += 1;
                }
            }
            count
        }

        /// The destination face-id set for `keyexpr`, served from
        /// [`route_cache`](Self::route_cache). A fresh hit returns the cached
        /// `Arc<[u64]>` directly; a miss runs the [`declared_intersects`] scan
        /// over every face, caches it, and counts one route computation.
        /// Source-independent (see [`forward_push`](Self::forward_push)) —
        /// zenoh's `get_or_set_route` analog.
        fn route_targets(&self, keyexpr: &str) -> Arc<[u64]> {
            let generation = self.generation;
            // Read borrow scoped so the miss path can re-borrow `route_cache`
            // mutably; the scan below reads only `self.faces`, never the cache,
            // so the two borrows never overlap.
            if let Some(ids) = self.route_cache.borrow().get(keyexpr, generation) {
                return ids;
            }
            let ids: Vec<u64> = self
                .faces
                .iter()
                .filter(|(_, face)| face.matches(keyexpr))
                .map(|(id, _)| *id)
                .collect();
            let ids: Arc<[u64]> = Arc::from(ids);
            self.route_computations
                .set(self.route_computations.get() + 1);
            self.route_cache
                .borrow_mut()
                .insert(keyexpr, generation, ids.clone());
            ids
        }
    }
}
