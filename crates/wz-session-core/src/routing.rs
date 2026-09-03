// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ## The liveliness plane (R311y803)
//!
//! Tokens route here too, and the reason is a property of the MESSAGE KINDS
//! this table dispatches rather than a scope decision:
//! [`observe`](RouteTable::observe) handles `Declare`, `Push` and `Interest`,
//! and the whole liveliness plane is expressed in the first and the third — a
//! `DeclareToken` IS the delivery to a liveliness subscriber, a
//! `Declare(UndeclareToken)` IS the retraction, and a TOKENS `Interest` is how
//! a subscriber asks for the current set. Nothing on that plane needs a
//! `Request` or a `Response`. So a token declared on one face reaches every
//! other face whose registered TOKENS interest matches it
//! ([`propagate_token_declaration`](RouteTable::propagate_token_declaration)),
//! it is retracted when its holder withdraws it or its face LEAVES
//! ([`propagate_token_forget`](RouteTable::propagate_token_forget) —
//! zenoh's `close_face` drain, `hat/router/mod.rs:541-544`), and a CURRENT
//! TOKENS interest is answered with the tokens already held
//! ([`dump_current_tokens`](RouteTable::dump_current_tokens)). Before this the
//! table recorded none of it: a liveliness subscriber behind a wz `--router`
//! read an empty world, and a peer that dropped left its tokens alive forever.
//!
//! ## NON-goals (this atom)
//!
//! Multi-hop declaration propagation (a router forwarding a peer's
//! DeclareSubscriber to the *other* peers so they gate their own emit — an
//! interest optimisation, not required for a single-hop star: a producer
//! sends its Put unconditionally and the router routes it) and zid-keyed mesh
//! de-duplication (the `src != dst` skip suffices for the star topology; a
//! mesh needs source-zid suppression).
//! Self-echo cannot occur: a face never receives its own Put back (`src_id`
//! is skipped).
//!
//! ## The QUERY plane (R311y840)
//!
//! Queryable routing used to be listed above as a non-goal, on the argument
//! that "a queryable advertised from here would invite a `Request` this table
//! has no arm for". That was true of the table and false of the protocol: it
//! made a wz `--router` a router a `z_get` cannot traverse, so every queryable
//! behind one was unreachable and every querier waited out its own timeout with
//! no reply and no `ResponseFinal`. The premise is what this section removes.
//!
//! zenoh routes both planes from ONE dispatcher over the same per-face state
//! (`dispatcher/pubsub.rs` and `dispatcher/queries.rs` over
//! `Resource::session_ctxs`), and the query half has three parts wz now
//! mirrors:
//!
//! - **Fan-out** ([`RouteTable::route_query`], zenoh `route_query`): the faces
//!   the query's own `QueryTarget` selects out of those whose declared queryable
//!   matches receive the `Request` under a router-minted request id, because the
//!   querier's id is unique only within ITS face and two faces may mint the same
//!   one. The target is HONOURED here rather than merely relayed (R311y841,
//!   correcting R311y840): zenoh branches three ways in `compute_final_route`
//!   (`dispatcher/queries.rs:205-266`), and the branch a plain `z_get` takes —
//!   `BestMatching`, which pico signals by OMITTING the ext — asks the single
//!   nearest queryable that covers the whole keyexpr, falling back to all
//!   matches only when none does. An empty route is answered with an immediate
//!   `ResponseFinal` (upstream's `if route.is_empty()` arm) rather than silence
//!   — the same "a requester is entitled to a termination" rule R311y773 applied
//!   to `declare-final`.
//! - **Return path** ([`RouteTable::route_response`] /
//!   [`RouteTable::route_response_final`], zenoh's `face.pending_queries` ->
//!   `query.src_qid`): a reply is re-stamped with the querier's own id, and the
//!   querier is closed by exactly ONE `ResponseFinal` once the LAST outstanding
//!   answerer finishes — upstream gets that count from `Drop for Query` over an
//!   `Arc`; here it is an explicit outstanding counter, because the same
//!   accounting has to survive a face DEPARTING mid-query, which a refcount
//!   would only handle by making the face own the `Arc`.
//! - **Advertisement** ([`RouteTable::propagate_qabl_declaration`] and the
//!   QUERYABLES arm of [`RouteTable::record_interest`]): the same two rules the
//!   token plane already follows — a CURRENT interest is dumped, a FUTURE one
//!   registers — because a zenoh ROUTER forwards a queryable declaration only
//!   to a face that registered a QUERYABLES interest
//!   (`hat/router/queries.rs:255-259`).

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
    use wz_codecs::interest::InterestOwned;
    use wz_codecs::push::PushOwned;
    use wz_codecs::request::RequestOwned;
    use wz_codecs::response::ResponseOwned;
    use wz_codecs::response_final::ResponseFinalOwned;
    use wz_runtime_core::TimeSource;

    use crate::declare::declared_intersects;
    use crate::declare_build::{
        build_declare_final_reply, build_declare_queryable_reply,
        build_declare_queryable_reply_with_id, build_declare_queryable_with_id_info,
        build_declare_subscriber_reply, build_declare_subscriber_reply_with_id,
        build_declare_token, build_declare_token_reply, build_declare_token_reply_with_id,
        build_undeclare_queryable, build_undeclare_queryable_with_keyexpr, build_undeclare_token,
        build_undeclare_token_with_keyexpr,
    };
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::link::SessionRuntime;
    use crate::network_message::NetworkMessage;
    use crate::qos::Priority;
    use crate::query_mode::QueryTarget;
    use crate::queryable_info::{read_queryable_info, QueryableInfo};
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
        /// FUTURE (C+F) subscriber interests this face declared — a pico
        /// publisher's write-filter interest (`net/filtering.c`
        /// `_z_write_filter_create`, flags `SUBSCRIBERS|CURRENT|FUTURE|AGGREGATE`).
        /// A subscription that arrives LATER on ANOTHER face is pushed to this
        /// face unsolicited (see [`RouteTable::push_future_subscriber`]) so the
        /// publisher's write filter deactivates and it begins putting. Empty for
        /// a face that declared no subscriber interest (a plain wz/zenoh
        /// publisher that puts without a write filter, e.g. `z_put`).
        future_subs: Vec<FutureSubInterest>,
        /// Liveliness TOKENS this face has declared: the resolved keyexpr keyed
        /// by the wire token id, so an `UndeclareToken` — which carries only the
        /// id — removes exactly the matching one. The token twin of
        /// [`subs`](Self::subs), and the same stored form a receiving endpoint's
        /// own
        /// [`LivelinessSubscriberRegistry`](crate::declare::liveliness_subscriber)
        /// keeps in its `peer_token_table`.
        tokens: HashMap<u64, String>,
        /// Tokens this table has ADVERTISED TO this face: the advertised keyexpr
        /// -> the id that advertisement carried. zenoh's
        /// `face_hat.local_tokens` (`hat/router/token.rs`), and it is
        /// load-bearing for one reason — the retraction must name the SAME id
        /// the declaration did, because the receiver keys its token table by
        /// that id and an id-only `UndeclareToken` is the ordinary retraction
        /// shape. It doubles as the already-advertised guard (zenoh's
        /// `!face_hat!(dst_face).local_tokens.contains_key(res)`), so two faces
        /// holding the same keyexpr advertise once.
        local_tokens: HashMap<String, u64>,
        /// TOKENS-kind interests this face registered — the liveliness twin of
        /// [`future_subs`](Self::future_subs). zenoh's `remote_interests`
        /// filtered by `options.tokens()`; propagation to a face is GATED on one
        /// of these matching (`hat/router/token.rs::propagate_simple_token_to`),
        /// which is why a face that never asks for tokens hears none.
        token_interests: Vec<TokenInterest>,
        /// QUERYABLES this face has declared: the resolved keyexpr and the
        /// carried [`QueryableInfo`], keyed by the wire queryable id so an
        /// `UndeclareQueryable` — which carries only the id — removes exactly
        /// the matching one. The query-plane twin of [`subs`](Self::subs), and
        /// the set [`RouteTable::route_query`] computes a query's destinations
        /// from (zenoh's `Resource::session_ctxs[face].qabl`).
        qabls: HashMap<u64, QueryableRoute>,
        /// Queryables this table has ADVERTISED TO this face: advertised
        /// keyexpr -> the id that advertisement carried. The exact twin of
        /// [`local_tokens`](Self::local_tokens), load-bearing for the same
        /// reason — the retraction must name the id the declaration did,
        /// because the receiver keys its remote-queryable table by it.
        local_qabls: HashMap<String, u64>,
        /// QUERYABLES-kind interests this face registered. The gate every
        /// queryable advertisement to this face passes, because a zenoh ROUTER
        /// propagates a queryable declaration only to a face that asked
        /// (`hat/router/queries.rs:255-259`) — the same rule
        /// [`token_interests`](Self::token_interests) enforces on the
        /// liveliness plane.
        qabl_interests: Vec<QueryableInterest>,
        /// Queries this table has SENT to this face and not yet closed: the
        /// router-minted request id -> the [`PendingQuery`] key it belongs to.
        /// Kept per-face rather than only table-wide so a departing face's
        /// outstanding queries are findable from the face alone
        /// ([`RouteTable::remove_face`]), and so a `Response` is only honoured
        /// on the face the `Request` actually went to — a face cannot answer
        /// another face's query by guessing its id.
        pending_queries: HashMap<u64, u64>,
    }

    /// One queryable a face declared: the resolved keyexpr plus the
    /// [`QueryableInfo`] the declaration carried. The info is kept (rather than
    /// discarded as the subscriber plane discards its lack of one) because an
    /// advertisement of this queryable to an interested face must carry it —
    /// `complete` is what tells a querier the answer needs no other responder,
    /// and dropping it would silently downgrade every relayed queryable to
    /// incomplete.
    struct QueryableRoute {
        keyexpr: String,
        info: QueryableInfo,
    }

    /// One QUERYABLES-kind `Interest` a face registered — the query-plane twin
    /// of [`TokenInterest`], with the same fields for the same reasons: the id
    /// is held for dedup of a repeated identical interest (the unsolicited
    /// advertisement carries none), and `aggregate` decides whether the
    /// advertisement names the interest's own keyexpr or the queryable's.
    struct QueryableInterest {
        interest_id: u64,
        keyexpr: String,
        aggregate: bool,
    }

    /// One query in flight through this table: who asked, under which id, and
    /// how many answerers are still outstanding.
    ///
    /// zenoh carries the first two in `Query { src_face, src_qid }` and gets the
    /// third from the `Arc<Query>` refcount, closing the querier in
    /// `Drop for Query` (`dispatcher/queries.rs`). The count is explicit here
    /// because the event this table has to survive is a DESTINATION FACE
    /// DEPARTING mid-query: with a refcount that is only expressible by making
    /// each face own a clone, and the departure then has to find every clone it
    /// owns — which is [`FaceRoute::pending_queries`] doing the refcount's job
    /// anyway, minus the ability to say how many are left.
    struct PendingQuery {
        /// The face that asked. Absent from
        /// [`RouteTable::faces`](RouteTable) once it departs, at which point the
        /// whole entry is dropped un-answered (there is nobody to answer).
        src_face: u64,
        /// The request id the QUERIER minted. Every reply routed back to it is
        /// re-stamped with this, and the single closing `ResponseFinal` carries
        /// it.
        src_rid: u64,
        /// How many destination faces have been sent this query and not yet
        /// sent their `ResponseFinal`. The querier is closed when this reaches
        /// zero — never before, because a querier that counts finals (zenoh and
        /// zenoh-pico both do) would otherwise stop reading at the first
        /// answerer and drop the rest.
        outstanding: usize,
    }

    /// One FUTURE subscriber interest a face registered — the state
    /// [`RouteTable::push_future_subscriber`] consults when a new subscription
    /// arrives so a pico publisher's write filter releases on the pub-before-sub
    /// ordering (the CURRENT dump in [`RouteTable::record_interest`] covers the
    /// sub-before-pub ordering).
    struct FutureSubInterest {
        /// The soliciting interest id — echoed onto every unsolicited FUTURE
        /// `DeclareSubscriber` push so the peer routes it to this interest
        /// (`session/interest.c` `__z_get_interest_by_key_and_flags`).
        interest_id: u64,
        /// The resolved (literal) interest keyexpr — matched against each new
        /// subscription's keyexpr to decide whether to push.
        keyexpr: String,
        /// Whether the interest is AGGREGATE (pico client publishers always are):
        /// an aggregate reply MUST carry the interest's OWN keyexpr, associated by
        /// `_z_keyexpr_equals` on the peer, not the concrete subscription keyexpr.
        aggregate: bool,
        /// reply-keyexpr -> the non-zero subscriber id allocated for its FUTURE
        /// push, reused on a redundant re-push of the same keyexpr (the peer
        /// dedups a `(decl_id, peer)` target, `net/filtering.c`).
        pushed: HashMap<String, u64>,
    }

    /// One TOKENS-kind `Interest` a face registered — the liveliness-plane twin
    /// of [`FutureSubInterest`], and the gate every advertisement to that face
    /// passes (zenoh keeps the same thing as a `RemoteInterest` filtered by
    /// `options.tokens()`).
    ///
    /// Unlike its subscriber twin this carries no `pushed` id map: an advertised
    /// token's id is allocated per DESTINATION FACE rather than per interest
    /// (zenoh's `face_hat.next_id` into `local_tokens`), because the retraction
    /// that must reuse it — `propagate_forget_simple_token` — reaches the face
    /// with a resource in hand and no interest, so the id has to be findable
    /// from the face alone. It lives in [`FaceRoute::local_tokens`].
    struct TokenInterest {
        /// The soliciting interest id. Held for DEDUP of a repeated identical
        /// interest only: the unsolicited advertisement this gates carries
        /// `interest_id: None`, which is zenoh's shape
        /// (`propagate_simple_token_to` leaves it `None`) and the one every
        /// receiver accepts — zenoh-pico matches an inbound declaration against
        /// EVERY interest bearing the kind bit when the id is absent or zero
        /// (`session/interest.c:270`), and wz's own liveliness subscriber never
        /// consults it at all (`liveliness_subscriber.rs::dispatch_declare` fans
        /// to every keyexpr-matching slot). Stamping a concrete id would NARROW
        /// the advertisement to one interest for no gain.
        interest_id: u64,
        /// The resolved (literal) interest keyexpr, matched against each
        /// declared token's keyexpr to decide whether to advertise.
        keyexpr: String,
        /// Whether the interest is AGGREGATE: the advertisement then carries the
        /// interest's OWN keyexpr rather than the token's, because the peer
        /// associates an aggregate interest's replies by `_z_keyexpr_equals`
        /// (`session/interest.c:274-276`) — the same rule
        /// [`FutureSubInterest::aggregate`] follows on the subscriber plane.
        aggregate: bool,
    }

    impl<R: SessionRuntime, T: TimeSource> FaceRoute<R, T> {
        fn new(actions: Arc<SessionLinkActions<R, T>>) -> Self {
            Self {
                actions,
                subs: HashMap::new(),
                peer_aliases: HashMap::new(),
                future_subs: Vec::new(),
                tokens: HashMap::new(),
                local_tokens: HashMap::new(),
                token_interests: Vec::new(),
                qabls: HashMap::new(),
                local_qabls: HashMap::new(),
                qabl_interests: Vec::new(),
                pending_queries: HashMap::new(),
            }
        }

        /// Is this face a destination for a query on the already-split
        /// `target_chunks`, and if so, can it answer the WHOLE query by itself?
        /// The query-plane twin of [`matches`](Self::matches), widened in
        /// R311y841 from a bare bool because a `QueryTarget` route needs the
        /// completeness as well as the membership.
        ///
        /// - `None` — no queryable here intersects the query; not a destination.
        /// - `Some(None)` — a destination, but nothing it holds COVERS the whole
        ///   query, so it can only contribute a partial answer.
        /// - `Some(Some(d))` — it can answer alone, `d` being the nearest such
        ///   queryable's declared hop distance (the BestMatching ordering key).
        ///
        /// Membership is [`keyexpr_intersects_target`](crate::keyexpr_match::keyexpr_intersects_target),
        /// the same SSOT [`declared_intersects`] wraps, so a router's query route
        /// and the destination queryable's own fire decision are computed by one
        /// function exactly as on the Push plane. COMPLETENESS is the strictly
        /// stronger [`keyexpr_includes_target`](crate::keyexpr_match::keyexpr_includes_target)
        /// ANDed with the declared flag — zenoh's
        /// `complete && qabl_info.complete` where the left operand is
        /// `DEFAULT_INCLUDER.includes(queryable_ke, queried_ke)`
        /// (`zenoh/src/net/routing/hat/router/queries.rs`
        /// @ `fn insert_target_for_qabls`). The distinction is
        /// load-bearing: a queryable on `demo/a` that declared itself complete
        /// still cannot serve all of `demo/*`, and treating it as if it could
        /// would silence every other answerer.
        ///
        /// Takes the pre-split chunks rather than the keyexpr because the caller
        /// scans every face against ONE target and the split is the expensive
        /// half.
        fn query_fit(&self, target_chunks: &[&str]) -> Option<Option<u16>> {
            let mut matched = false;
            let mut complete: Option<u16> = None;
            for q in self.qabls.values() {
                if !crate::keyexpr_match::keyexpr_intersects_target(&q.keyexpr, target_chunks) {
                    continue;
                }
                matched = true;
                if q.info.complete
                    && crate::keyexpr_match::keyexpr_includes_target(&q.keyexpr, target_chunks)
                {
                    // NEAREST wins when a face holds several complete
                    // queryables: zenoh's route set carries one entry per
                    // queryable and is sorted by distance, so the entry that
                    // survives the BestMatching find is the closest one.
                    complete = Some(match complete {
                        Some(d) => {
                            if q.info.distance < d {
                                q.info.distance
                            } else {
                                d
                            }
                        }
                        None => q.info.distance,
                    });
                }
            }
            matched.then_some(complete)
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
        /// Monotonic allocator for the non-zero subscriber id an unsolicited
        /// FUTURE `DeclareSubscriber` push carries (id 0 is reserved for the
        /// CURRENT dump — zenoh `make_sub_id` = 0 for non-future). Starts at 1;
        /// [`push_future_subscriber`](RouteTable::push_future_subscriber) hands
        /// out and remembers one id per `(future interest, reply keyexpr)` so a
        /// redundant re-push reuses it. `Cell` because the push path runs off the
        /// `&mut` observe borrow but the id state is logically interior.
        next_future_sub_id: Cell<u64>,
        /// Monotonic allocator for the id an advertised `DeclareToken` carries —
        /// zenoh's per-face `face_hat.next_id` (`hat/router/token.rs`), kept
        /// table-wide here because a table-wide counter satisfies the only
        /// property the id needs: uniqueness WITHIN the destination face, which
        /// a globally-unique id has for free. Starts at 1 because 0 is reserved
        /// for the CURRENT-only dump (zenoh's `make_token_id` returns 0 when
        /// `!mode.future()`), so a non-zero id always means "this advertisement
        /// is retractable by id".
        next_local_token_id: Cell<u64>,
        /// Queries in flight, keyed by a table-minted query key. One entry per
        /// INBOUND query (not per destination); the per-destination side lives
        /// in [`FaceRoute::pending_queries`], which maps a router-minted request
        /// id back to a key here.
        pending_queries: HashMap<u64, PendingQuery>,
        /// Monotonic allocator shared by the query key and the router-minted
        /// per-destination request id. One counter for both because both need
        /// exactly one property — uniqueness — and drawing them from one source
        /// makes it impossible for a key and a live request id to collide while
        /// a reader is deciding which map to look in. Starts at 1 so 0 is never
        /// a live id (a zero rid on the wire is a legitimate QUERIER id, which
        /// is precisely why the router mints its own).
        next_query_id: Cell<u64>,
        /// Monotonic allocator for the id an advertised `DeclareQueryable`
        /// carries — the queryable twin of
        /// [`next_local_token_id`](Self::next_local_token_id), with the same
        /// table-wide-is-enough argument and the same reservation of 0 for the
        /// CURRENT-only dump.
        next_local_qabl_id: Cell<u64>,
        /// Cumulative count of queries this table ROUTED (one per inbound
        /// `Request` that reached at least one queryable). Deliberately NOT
        /// folded into [`forward_push`](Self::forward_push)'s count, which the
        /// demo router logs as its Put throughput: two planes with different
        /// units — a Put counts one per DESTINATION, a query counts one per
        /// QUERY however many answerers it fanned to.
        queries_routed: u64,
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
                next_future_sub_id: Cell::new(1),
                next_local_token_id: Cell::new(1),
                pending_queries: HashMap::new(),
                next_query_id: Cell::new(1),
                next_local_qabl_id: Cell::new(1),
                queries_routed: 0,
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
        ///
        /// The liveliness tokens it held are RETRACTED to the faces that were
        /// told about them, because a token's whole meaning is that its holder
        /// is alive: a face that vanishes without a retraction leaves every
        /// observer believing a dead peer is still there, and no later message
        /// corrects it. zenoh does this in `close_face`, draining
        /// `hat_face.remote_tokens` into `undeclare_simple_token`
        /// (`hat/router/mod.rs:541-544`, `hat/client/mod.rs:209-212`) — the
        /// retraction the ROUTER synthesises, as opposed to the one a departing
        /// peer sends for itself.
        /// The QUERY plane departs with it too, in both directions. A face that
        /// was ANSWERING queries can no longer finish them, so each is counted
        /// down and the querier closed if it was the last outstanding answerer —
        /// otherwise a `z_get` whose only responder crashed hangs to its own
        /// timeout, which is the very failure the empty-route arm of
        /// [`route_query`](Self::route_query) refuses to cause. A face that was
        /// ASKING has nobody to answer to, so its entries are dropped silently.
        /// zenoh does both in `close_face` (draining `pending_queries` and
        /// `Drop for Query`).
        pub fn remove_face(&mut self, id: u64) {
            // A removed face may have carried subscriptions that fed cached
            // routes (and its id must never resurface in one), so its departure
            // invalidates the cache.
            let Some(face) = self.faces.remove(&id) else {
                return;
            };
            self.invalidate_routes();
            // The query plane FIRST, while the departed face's own pending map
            // is still in hand: every query it owed an answer to is one
            // outstanding fewer, and the querier may now be closable.
            for query_key in face.pending_queries.values() {
                self.close_one_answerer(*query_key);
            }
            // Queries this face ASKED are unanswerable now. Drop the pending
            // entries and, with them, every destination face's mapping into
            // them — leaving those behind would let a late reply resolve to a
            // querier that no longer exists.
            let orphaned: Vec<u64> = self
                .pending_queries
                .iter()
                .filter(|(_, q)| q.src_face == id)
                .map(|(k, _)| *k)
                .collect();
            for key in &orphaned {
                self.pending_queries.remove(key);
            }
            if !orphaned.is_empty() {
                for f in self.faces.values_mut() {
                    f.pending_queries.retain(|_, key| !orphaned.contains(key));
                }
            }
            // Its queryables leave with it, and the faces that were told about
            // them are told they are gone — the same argument the token
            // retraction below makes: an observer that is never corrected keeps
            // routing queries at a peer that is not there. zenoh drains the
            // departing face's `qabls` in `close_face` the same way.
            let mut retracted_qabls: Vec<String> = Vec::new();
            for q in face.qabls.values() {
                if !retracted_qabls.contains(&q.keyexpr) {
                    retracted_qabls.push(q.keyexpr.clone());
                }
            }
            for keyexpr in &retracted_qabls {
                self.propagate_qabl_forget(None, keyexpr);
            }
            // Deduplicated: one face may hold several token ids on the SAME
            // keyexpr, and each retraction is per-keyexpr.
            let mut retracted: Vec<String> = Vec::new();
            for keyexpr in face.tokens.into_values() {
                if retracted.contains(&keyexpr) {
                    continue;
                }
                retracted.push(keyexpr);
            }
            for keyexpr in &retracted {
                // `id` is already out of `self.faces`, so the src-face guard
                // inside the forget cannot fire on it; pass `None` for the same
                // reason zenoh's close_face path does (it has no source face to
                // exclude — `src_face.map_or(true, ..)`, token.rs:428).
                self.propagate_token_forget(None, keyexpr);
            }
        }

        /// Total subscriptions recorded across all faces — the witness the
        /// forwarder's `subscription_count()` passthrough exposes so a test can
        /// assert routing state directly (e.g. that an aliased declare was NOT
        /// recorded), distinct from the observable forward count.
        pub fn subscription_count(&self) -> usize {
            self.faces.values().map(|f| f.subs.len()).sum()
        }

        /// Total liveliness tokens recorded across all faces — the token twin of
        /// [`subscription_count`](Self::subscription_count), so a test can
        /// assert the table's own state (a token recorded, a token retracted, a
        /// departed face's tokens gone) independently of the declarations it
        /// emitted onto other faces.
        pub fn token_count(&self) -> usize {
            self.faces.values().map(|f| f.tokens.len()).sum()
        }

        /// Total queryables recorded across all faces — the query-plane twin of
        /// [`subscription_count`](Self::subscription_count).
        pub fn queryable_count(&self) -> usize {
            self.faces.values().map(|f| f.qabls.len()).sum()
        }

        /// Queries currently in flight (routed, not yet closed). A LEAK
        /// WITNESS: every path that ends a query — the last `ResponseFinal`, an
        /// answerer departing, the querier departing — must drive this back to
        /// zero, and a router whose count only grows is one that will exhaust
        /// memory on query traffic alone.
        pub fn pending_query_count(&self) -> usize {
            self.pending_queries.len()
        }

        /// Total queries routed to at least one queryable. The query-plane
        /// counterpart of the Push forward count (see
        /// [`queries_routed`](Self::queries_routed) on the field for why they
        /// are not one number).
        pub fn queries_routed(&self) -> u64 {
            self.queries_routed
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
                messages,
                reliable,
                priority,
                ..
            }) = event
            else {
                return 0;
            };
            let mut forwarded = 0;
            for message in messages {
                match message {
                    NetworkMessage::Declare(declare) => self.record_declare(src_id, declare),
                    NetworkMessage::Push(push) => {
                        forwarded += self.forward_push(src_id, push, *reliable, *priority)
                    }
                    // R311y373 — a subscriber Interest (a pico publisher's
                    // write-filter interest, `net/filtering.c`): reply with the
                    // matching subscriptions so the publisher's filter releases.
                    // NOT counted as a forward (control plane, not data).
                    NetworkMessage::Interest(interest) => self.record_interest(src_id, interest),
                    // R311y840 — the QUERY plane. Not added to `forwarded`: that
                    // is the Push destination count the demo router logs, and a
                    // query's unit is the query (see `queries_routed`).
                    NetworkMessage::Request(request) => self.route_query(src_id, request),
                    NetworkMessage::Response(response) => self.route_response(src_id, response),
                    NetworkMessage::ResponseFinal(final_msg) => {
                        self.route_response_final(src_id, final_msg)
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
            // A newly-added subscription's resolved keyexpr — carried out of the
            // `face` borrow so the post-match FUTURE push (which re-borrows the
            // OTHER faces) can consult it. `Some` only on a DeclareSubscriber that
            // recorded a route (so `subscriptions_changed` is implied by it).
            let mut new_sub_keyexpr = None;
            // The liveliness-plane counterparts, carried out of the `face`
            // borrow for the same reason: advertising / retracting re-borrows
            // the OTHER faces.
            let mut new_token_keyexpr = None;
            let mut forgotten_token_keyexpr = None;
            // The query-plane counterparts, carried out for the same reason.
            let mut new_qabl_keyexpr = None;
            let mut forgotten_qabl_keyexpr = None;
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
                            face.subs.insert(sub.id, keyexpr.clone());
                            new_sub_keyexpr = Some(keyexpr);
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
                // The LIVELINESS plane. Recorded and advertised on the same
                // rules as a subscription, but it feeds no route cache: a token
                // is not a destination for anything, so `subscriptions_changed`
                // stays false and the Push cache is left alone.
                DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                    match resolve_wireexpr(&decl.keyexpr.body, &face.peer_aliases) {
                        Some(keyexpr) => {
                            // FIRST DECLARATION OF AN ID WINS, matching the
                            // endpoint registry this table feeds
                            // (`liveliness_subscriber.rs` skips an occupied id,
                            // zenoh's `Entry::Vacant`). Re-binding the id would
                            // make the later id-only retraction name a keyexpr
                            // the token was never declared on.
                            if !face.tokens.contains_key(&decl.id) {
                                face.tokens.insert(decl.id, keyexpr.clone());
                                new_token_keyexpr = Some(keyexpr);
                            }
                        }
                        None => {
                            log::debug!(
                                "RouteTable: face {src_id} declared token id={} on an \
                                 expr-id with no prior DeclareKeyexpr mapping; not recorded",
                                decl.id
                            );
                        }
                    }
                    false
                }
                DeclareOwnedVariant::CodecZenohUndeclToken(undecl) => {
                    // Id first, then the SOURCED form. zenoh identifies a
                    // sourced token by its KEYEXPR carried in `ext_wire_expr`
                    // with `id == 0` (`build_undeclare_token_with_keyexpr` emits
                    // exactly that shape), so a table miss is not "unknown
                    // token" — it is the ordinary shape of every sourced
                    // retraction, and dropping on it discards all of them. The
                    // same two-step, in the same order, as the endpoint
                    // registry's (`liveliness_subscriber.rs`, R311y769).
                    forgotten_token_keyexpr = face.tokens.remove(&undecl.id).or_else(|| {
                        crate::declare_ext_keyexpr::resolve_ext_keyexpr(
                            undecl.extensions.as_ref(),
                            &face.peer_aliases,
                        )
                    });
                    false
                }
                // The QUERY plane (R311y840). Recorded on the same rules as a
                // subscription — the id keys the entry so the id-only
                // `UndeclareQueryable` removes exactly one — but like the token
                // plane it feeds no PUSH route, so `subscriptions_changed` stays
                // false and the Put cache is not invalidated. Query routes are
                // computed per query rather than cached (see
                // [`route_query`](Self::route_query)), which is what makes that
                // safe rather than merely cheap.
                DeclareOwnedVariant::CodecZenohDeclQueryable(decl) => {
                    match resolve_wireexpr(&decl.keyexpr.body, &face.peer_aliases) {
                        Some(keyexpr) => {
                            // The carried info is READ rather than defaulted: a
                            // relayed queryable that silently lost `complete`
                            // would make every querier behind this router keep
                            // waiting for a second answerer that does not exist.
                            let info = read_queryable_info(decl.extensions.as_ref());
                            face.qabls.insert(
                                decl.id,
                                QueryableRoute {
                                    keyexpr: keyexpr.clone(),
                                    info,
                                },
                            );
                            new_qabl_keyexpr = Some(keyexpr);
                        }
                        None => {
                            log::debug!(
                                "RouteTable: face {src_id} declared queryable id={} on an \
                                 expr-id with no prior DeclareKeyexpr mapping; not recorded",
                                decl.id
                            );
                        }
                    }
                    false
                }
                DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl) => {
                    // Id first, then the SOURCED form — the same two-step, for
                    // the same reason, as the token retraction above: an
                    // `id == 0` retraction carrying its keyexpr in
                    // `ext_wire_expr` is the ordinary shape of a sourced
                    // undeclare, so a table miss is not "unknown queryable".
                    forgotten_qabl_keyexpr = face
                        .qabls
                        .remove(&undecl.id)
                        .map(|q| q.keyexpr)
                        .or_else(|| {
                            crate::declare_ext_keyexpr::resolve_ext_keyexpr(
                                undecl.extensions.as_ref(),
                                &face.peer_aliases,
                            )
                        });
                    false
                }
                _ => false,
            };
            // `face`'s borrow of `self.faces` ends with the match; bump the epoch
            // after, so a stale cache is recomputed on the next Put.
            if subscriptions_changed {
                self.invalidate_routes();
            }
            // FUTURE interest fulfilment (pub-before-sub ordering): a face that
            // published a subscriber Interest before this subscription existed is
            // now told about it, releasing its write filter.
            if let Some(keyexpr) = new_sub_keyexpr {
                self.push_future_subscriber(src_id, &keyexpr);
            }
            // The liveliness plane's own fan-out. Unlike the subscriber one this
            // is not an optimisation that a later Put would paper over: a
            // `DeclareToken` IS the delivery, so a table that records it without
            // advertising it carries liveliness nowhere.
            if let Some(keyexpr) = new_token_keyexpr {
                self.propagate_token_declaration(src_id, &keyexpr);
            }
            if let Some(keyexpr) = forgotten_token_keyexpr {
                self.propagate_token_forget(Some(src_id), &keyexpr);
            }
            // The query plane's fan-out, on the token plane's rules. Unlike a
            // subscription this is not an optimisation a later message papers
            // over: a face that asked for QUERYABLES and is never told has no
            // remote queryable to match a `Querier` against, so its
            // matching-status stays false and (against zenoh's own client
            // behaviour) it can decline to send the query at all.
            if let Some(keyexpr) = new_qabl_keyexpr {
                self.propagate_qabl_declaration(src_id, &keyexpr);
            }
            if let Some(keyexpr) = forgotten_qabl_keyexpr {
                self.propagate_qabl_forget(Some(src_id), &keyexpr);
            }
        }

        /// Reply to an inbound subscriber `Interest` from face `src_id` — a pico
        /// publisher's write-filter interest (`net/filtering.c`
        /// `_z_write_filter_create`, flags `SUBSCRIBERS|CURRENT|FUTURE|AGGREGATE`).
        /// Until the publisher receives a matching `DeclareSubscriber` its write
        /// filter stays ACTIVE and it drops every put locally, so a router that
        /// never answers the interest cannot carry a pico publisher's data (a
        /// `z_put` with no publisher has no filter and is unaffected). CURRENT
        /// dumps the subscriptions already held on OTHER faces; the interest_id is
        /// echoed on each reply and on the terminating Final so the peer routes
        /// them to this interest. FUTURE registers the interest so a later
        /// matching subscription is pushed (see
        /// [`push_future_subscriber`](Self::push_future_subscriber)).
        ///
        /// The TOKENS and QUERYABLES kinds are answered on exactly the same two
        /// rules ([`propagate_token_declaration`](Self::propagate_token_declaration)
        /// and [`propagate_qabl_declaration`](Self::propagate_qabl_declaration)
        /// are the FUTURE halves). QUERYABLES was excluded until R311y840 on the
        /// argument that "a queryable is an invitation to send a `Request`,
        /// which this table has no arm for" — true when written, and now false
        /// in its premise rather than its logic: [`route_query`](Self::route_query)
        /// is that arm.
        fn record_interest(&mut self, src_id: u64, interest: &InterestOwned) {
            let Some(body) = interest.body.as_ref() else {
                return;
            };
            let interest_id = interest.interest_id;
            let Some(src) = self.faces.get(&src_id) else {
                return;
            };
            let src_actions = src.actions.clone();

            // R311y773 — A CURRENT INTEREST IS TERMINATED WHATEVER KIND IT NAMES.
            // zenoh sends the `DeclareFinal` for a `mode.current()` interest
            // regardless of which option bits are set (`hat/client/interests.rs`,
            // the `if mode.current()` block after the per-kind dump), and the
            // requester is entitled to it: pico's `_z_interest_process_declares`
            // holds the pending interest until a Final arrives, so silence is not
            // "no matches" but a HANG to the requester's own timeout.
            //
            // As of R311y840 this table dumps all three declaration planes it
            // can hold; only the KEYEXPRS kind remains undumpable (an alias
            // table is per-face state, not a declaration another face can be
            // told about), and a KEYEXPRS-only CURRENT interest still gets the
            // bare Final below — a truthful "I have none".
            //
            // Newly load-bearing as of R311y771: wz itself now emits QUERYABLES
            // interests from `Querier::declare_matching_listener`, so a wz face
            // peered with a wz RouteTable router would hang on its own message.
            // The defect predates that and was reachable from pico and zenoh.
            let wants_subscribers = body.su();
            let wants_tokens = body.to();
            let wants_queryables = body.qu();
            if !wants_subscribers && !wants_tokens && !wants_queryables {
                if interest.c() {
                    let _ = src_actions.send_network_message(
                        NetworkMessage::Declare(Box::new(build_declare_final_reply(interest_id))),
                        true,
                        true,
                    );
                }
                // FUTURE-only: nothing to terminate and nothing this table can
                // stream, so it is correctly silent -- zenoh Finals only on
                // `mode.current()` too.
                return;
            }

            let aggregate = body.ag();
            let future = interest.f();
            // Resolve the interest keyexpr in the SOURCE face's alias context
            // (literal id=0, or aliased id!=0 via a prior DeclareKeyexpr). A
            // keyexpr-less interest has nothing to match against -- but a CURRENT
            // one is still owed its Final for the same reason as above, so the
            // unresolvable case terminates rather than dropping silently.
            let Some(interest_ke) = body
                .keyexpr
                .as_ref()
                .and_then(|w| resolve_wireexpr(&w.body, &src.peer_aliases))
            else {
                if interest.c() {
                    let _ = src_actions.send_network_message(
                        NetworkMessage::Declare(Box::new(build_declare_final_reply(interest_id))),
                        true,
                        true,
                    );
                }
                return;
            };

            if interest.c() {
                // The CURRENT dump: the subscriptions already held on OTHER faces
                // that match. AGGREGATE (pico client publishers always are) sends
                // ONE reply carrying the interest's OWN keyexpr iff any face
                // matches — the peer associates an aggregate interest's replies by
                // `_z_keyexpr_equals` (`session/interest.c`), so a concrete
                // subscription keyexpr would silently fail to match. Non-aggregate
                // sends one reply per matching subscription with the subscription's
                // own keyexpr.
                let mut replies: Vec<String> = Vec::new();
                if wants_subscribers {
                    if aggregate {
                        if self
                            .faces
                            .iter()
                            .any(|(id, f)| *id != src_id && f.matches(&interest_ke))
                        {
                            replies.push(interest_ke.clone());
                        }
                    } else {
                        let target_chunks: Vec<&str> = interest_ke.split('/').collect();
                        for (id, f) in self.faces.iter() {
                            if *id == src_id {
                                continue;
                            }
                            for sub_ke in f.subs.values() {
                                if crate::keyexpr_match::keyexpr_intersects_target(
                                    sub_ke,
                                    &target_chunks,
                                ) {
                                    replies.push(sub_ke.clone());
                                }
                            }
                        }
                    }
                }
                for ke in &replies {
                    if let Ok(decl) = build_declare_subscriber_reply(interest_id, ke) {
                        let _ = src_actions.send_network_message(
                            NetworkMessage::Declare(Box::new(decl)),
                            true,
                            true,
                        );
                    }
                }
                if wants_queryables {
                    self.dump_current_queryables(
                        src_id,
                        interest_id,
                        &interest_ke,
                        aggregate,
                        future,
                    );
                }
                if wants_tokens {
                    self.dump_current_tokens(src_id, interest_id, &interest_ke, aggregate, future);
                }
                // Close the CURRENT dump with a Final stamped with interest_id —
                // sent even with zero replies (no matching subscriber -> the
                // publisher's filter correctly stays ACTIVE and it does not put).
                // ONE Final closes the whole interest however many kinds it
                // named, as upstream's single post-dump `if mode.current()`
                // block does (`hat/client/interests.rs`).
                let _ = src_actions.send_network_message(
                    NetworkMessage::Declare(Box::new(build_declare_final_reply(interest_id))),
                    true,
                    true,
                );
            }

            if future {
                if let Some(src) = self.faces.get_mut(&src_id) {
                    // Dedup an identical re-declared interest so future entries do
                    // not stack.
                    if wants_subscribers
                        && !src
                            .future_subs
                            .iter()
                            .any(|fi| fi.interest_id == interest_id && fi.keyexpr == interest_ke)
                    {
                        src.future_subs.push(FutureSubInterest {
                            interest_id,
                            keyexpr: interest_ke.clone(),
                            aggregate,
                            pushed: HashMap::new(),
                        });
                    }
                    if wants_queryables
                        && !src
                            .qabl_interests
                            .iter()
                            .any(|qi| qi.interest_id == interest_id && qi.keyexpr == interest_ke)
                    {
                        src.qabl_interests.push(QueryableInterest {
                            interest_id,
                            keyexpr: interest_ke.clone(),
                            aggregate,
                        });
                    }
                    if wants_tokens
                        && !src
                            .token_interests
                            .iter()
                            .any(|ti| ti.interest_id == interest_id && ti.keyexpr == interest_ke)
                    {
                        src.token_interests.push(TokenInterest {
                            interest_id,
                            keyexpr: interest_ke,
                            aggregate,
                        });
                    }
                }
            }
        }

        /// The CURRENT half of a TOKENS interest: the liveliness tokens already
        /// held on OTHER faces that match `interest_ke`, each sent back as a
        /// `Declare(DeclToken)` stamped with the soliciting `interest_id`
        /// (zenoh's token-interest replay,
        /// `zenoh/src/net/routing/hat/router/token.rs` @ `router_tokens`).
        ///
        /// `future` decides the ADVERTISED ID, and it is not cosmetic. Upstream's
        /// `make_token_id` (`token.rs:977-990`) returns 0 for a CURRENT-only
        /// interest and otherwise allocates-and-REMEMBERS a per-face id. The
        /// remembering is what makes the eventual retraction expressible as the
        /// ordinary id-only `UndeclareToken`: a receiver keys its token table by
        /// the declared id, so an advertisement that carried 0 could only ever be
        /// retracted by the sourced keyexpr form. A CURRENT-only interest has no
        /// future to retract into, which is why 0 is right there and wrong here.
        fn dump_current_tokens(
            &mut self,
            src_id: u64,
            interest_id: u64,
            interest_ke: &str,
            aggregate: bool,
            future: bool,
        ) {
            let Some(src) = self.faces.get(&src_id) else {
                return;
            };
            let src_actions = src.actions.clone();
            let target_chunks: Vec<&str> = interest_ke.split('/').collect();
            // AGGREGATE answers with ONE reply carrying the interest's OWN
            // keyexpr iff anything matches — the peer associates an aggregate
            // interest's replies by `_z_keyexpr_equals`, so a concrete token
            // keyexpr would silently fail to match. Same rule as the subscriber
            // dump above. Deduplicated either way: two faces holding the same
            // keyexpr are ONE liveliness fact, and a receiver that keys tokens
            // by id would otherwise hold two ids for it and stay "alive" after
            // one retraction.
            let mut replies: Vec<String> = Vec::new();
            for (id, f) in self.faces.iter() {
                if *id == src_id {
                    continue;
                }
                for token_ke in f.tokens.values() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(token_ke, &target_chunks) {
                        continue;
                    }
                    let reply_ke = if aggregate {
                        interest_ke
                    } else {
                        token_ke.as_str()
                    };
                    if !replies.iter().any(|k| k == reply_ke) {
                        replies.push(String::from(reply_ke));
                    }
                }
            }
            for reply_ke in &replies {
                let token_id = if future {
                    self.advertised_token_id(src_id, reply_ke)
                } else {
                    0
                };
                let built = if token_id == 0 {
                    build_declare_token_reply(interest_id, reply_ke)
                } else {
                    build_declare_token_reply_with_id(interest_id, token_id, reply_ke)
                };
                if let Ok(decl) = built {
                    let _ = src_actions.send_network_message(
                        NetworkMessage::Declare(Box::new(decl)),
                        true,
                        true,
                    );
                }
            }
        }

        /// The id under which `keyexpr` is advertised to face `face_id`,
        /// allocating and remembering one on first use — zenoh's `make_token_id`
        /// future branch over `face_hat.local_tokens`. Reusing the remembered id
        /// is what keeps a repeated advertisement idempotent on the receiver
        /// (which keys its token table by id) and what lets the retraction be
        /// id-only. Returns 0 for an unknown face, which the callers treat as
        /// "nothing to send".
        fn advertised_token_id(&mut self, face_id: u64, keyexpr: &str) -> u64 {
            let next = self.next_local_token_id.get();
            let Some(face) = self.faces.get_mut(&face_id) else {
                return 0;
            };
            if let Some(id) = face.local_tokens.get(keyexpr) {
                return *id;
            }
            face.local_tokens.insert(String::from(keyexpr), next);
            self.next_local_token_id.set(next.saturating_add(1));
            next
        }

        /// Advertise a newly-declared token on `keyexpr` (held by face
        /// `src_id`) to every OTHER face whose registered TOKENS interest
        /// matches it — the FUTURE half, and the liveliness twin of
        /// [`push_future_subscriber`](Self::push_future_subscriber).
        ///
        /// Interest-GATED, which is zenoh's router rule
        /// (`propagate_simple_token_to` collects `remote_interests` filtered by
        /// `options.tokens() && i.matches(res)`) and not its client rule, which
        /// propagates to every face. The router rule is the right one here for
        /// the reason it is upstream: a face that never asked has no liveliness
        /// subscriber to fire, so an advertisement to it is a message with no
        /// reader.
        ///
        /// Already-advertised keyexprs are SKIPPED via
        /// [`local_tokens`](FaceRoute::local_tokens) (zenoh's
        /// `!local_tokens.contains_key(res)`): two peers holding the same
        /// liveliness keyexpr are one fact to an observer, and a second
        /// advertisement under a second id would leave that observer still
        /// believing after only one of them retracts.
        fn propagate_token_declaration(&mut self, src_id: u64, keyexpr: &str) {
            let target_chunks: Vec<&str> = keyexpr.split('/').collect();
            // (destination face, the keyexpr to advertise) — collected first so
            // the id allocation below can take `&mut self`.
            let mut targets: Vec<(u64, String)> = Vec::new();
            for (fid, face) in self.faces.iter() {
                if *fid == src_id {
                    continue;
                }
                for ti in face.token_interests.iter() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(&ti.keyexpr, &target_chunks)
                    {
                        continue;
                    }
                    let advertised = if ti.aggregate {
                        ti.keyexpr.clone()
                    } else {
                        String::from(keyexpr)
                    };
                    if face.local_tokens.contains_key(&advertised) {
                        continue;
                    }
                    if !targets.iter().any(|(f, k)| *f == *fid && *k == advertised) {
                        targets.push((*fid, advertised));
                    }
                }
            }
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, DeclareOwned)> = Vec::new();
            for (fid, advertised) in &targets {
                let token_id = self.advertised_token_id(*fid, advertised);
                if token_id == 0 {
                    continue;
                }
                let Some(face) = self.faces.get(fid) else {
                    continue;
                };
                // `interest_id: None` — the unsolicited advertisement carries no
                // interest id, which is upstream's shape and the one every
                // receiver accepts (see [`TokenInterest::interest_id`]).
                if let Ok(decl) = build_declare_token(token_id, 0, Some(advertised.as_str())) {
                    sends.push((face.actions.clone(), decl));
                }
            }
            for (actions, decl) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(decl)),
                    true,
                    true,
                );
            }
        }

        /// Retract a token on `keyexpr` from every face that was told about it —
        /// zenoh's `propagate_forget_simple_token` (`hat/router/token.rs:400`).
        /// `src_id` is the face the retraction ARRIVED on (`None` when this table
        /// synthesised it, i.e. from [`remove_face`](Self::remove_face)).
        ///
        /// Nothing is emitted while ANY face still holds a token on the same
        /// keyexpr: a liveliness fact is alive as long as one holder is, and
        /// upstream guards the same condition through `simple_tokens(res)`
        /// being empty (`token.rs:239-242`). Two forms go out, and which one
        /// depends on whether this table ever advertised the keyexpr to that
        /// face — the id-only retraction when it did (the id is the one
        /// [`local_tokens`](FaceRoute::local_tokens) remembered), and the SOURCED
        /// form (id 0 plus the keyexpr in an `ext_wire_expr`) when it did not.
        /// The second arm is not redundant: a face whose interest was registered
        /// AFTER the CURRENT dump never received a declaration to retract by id,
        /// and upstream sends it the same one-shot sourced form.
        fn propagate_token_forget(&mut self, src_id: Option<u64>, keyexpr: &str) {
            if self
                .faces
                .values()
                .any(|f| f.tokens.values().any(|k| k == keyexpr))
            {
                return;
            }
            let target_chunks: Vec<&str> = keyexpr.split('/').collect();
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, DeclareOwned)> = Vec::new();
            for (fid, face) in self.faces.iter_mut() {
                if let Some(id) = face.local_tokens.remove(keyexpr) {
                    sends.push((face.actions.clone(), build_undeclare_token(id)));
                    continue;
                }
                // The face was never told, so there is no id to name. Only a
                // NON-aggregate interest gets the sourced form: an aggregate
                // interest's holder associates replies by keyexpr equality and
                // was told about the INTEREST's keyexpr, never this one — which
                // is why upstream excludes it here too (`!i.options.aggregate()`,
                // token.rs:436).
                if src_id == Some(*fid) {
                    continue;
                }
                let interested = face.token_interests.iter().any(|ti| {
                    !ti.aggregate
                        && crate::keyexpr_match::keyexpr_intersects_target(
                            &ti.keyexpr,
                            &target_chunks,
                        )
                });
                if !interested {
                    continue;
                }
                if let Ok(decl) = build_undeclare_token_with_keyexpr(keyexpr) {
                    sends.push((face.actions.clone(), decl));
                }
            }
            for (actions, decl) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(decl)),
                    true,
                    true,
                );
            }
        }

        // ─── The QUERY plane (R311y840) ──────────────────────────────────
        //
        // Three groups below, in the order a query meets them: the
        // advertisement of a queryable (so a peer knows to ask at all), the
        // fan-out of a `Request`, and the return path of `Response` /
        // `ResponseFinal`.

        /// The CURRENT half of a QUERYABLES interest: the queryables already
        /// held on OTHER faces that match `interest_ke`, each sent back as a
        /// `Declare(DeclQueryable)` stamped with the soliciting `interest_id`
        /// (zenoh's `declare_qabl_interest`, `hat/router/queries.rs`). The exact
        /// twin of [`dump_current_tokens`](Self::dump_current_tokens), including
        /// the `future`-decides-the-id rule and the dedup — see that method for
        /// why both are load-bearing rather than cosmetic.
        ///
        /// The one field the token twin has no counterpart for is the
        /// [`QueryableInfo`], and the dedup is where it matters: when two faces
        /// cover the same advertised keyexpr they collapse to ONE declaration,
        /// so its info must be the MERGE of theirs (zenoh's `merge_qabl_infos`)
        /// — advertising only the first contributor's would drop a `complete`
        /// the other one had.
        fn dump_current_queryables(
            &mut self,
            src_id: u64,
            interest_id: u64,
            interest_ke: &str,
            aggregate: bool,
            future: bool,
        ) {
            let Some(src) = self.faces.get(&src_id) else {
                return;
            };
            let src_actions = src.actions.clone();
            let target_chunks: Vec<&str> = interest_ke.split('/').collect();
            let mut replies: Vec<(String, QueryableInfo)> = Vec::new();
            for (id, f) in self.faces.iter() {
                if *id == src_id {
                    continue;
                }
                for q in f.qabls.values() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(&q.keyexpr, &target_chunks)
                    {
                        continue;
                    }
                    let reply_ke = if aggregate {
                        interest_ke
                    } else {
                        q.keyexpr.as_str()
                    };
                    match replies.iter_mut().find(|(k, _)| k == reply_ke) {
                        Some((_, info)) => *info = info.merge(q.info),
                        None => replies.push((String::from(reply_ke), q.info)),
                    }
                }
            }
            for (reply_ke, info) in &replies {
                let qabl_id = if future {
                    self.advertised_qabl_id(src_id, reply_ke)
                } else {
                    0
                };
                let built = if qabl_id == 0 {
                    build_declare_queryable_reply(interest_id, reply_ke, *info)
                } else {
                    build_declare_queryable_reply_with_id(interest_id, qabl_id, reply_ke, *info)
                };
                if let Ok(decl) = built {
                    let _ = src_actions.send_network_message(
                        NetworkMessage::Declare(Box::new(decl)),
                        true,
                        true,
                    );
                }
            }
        }

        /// The id under which a queryable on `keyexpr` is advertised to face
        /// `face_id`, allocating and remembering one on first use — the exact
        /// twin of [`advertised_token_id`](Self::advertised_token_id), and 0 for
        /// an unknown face for the same reason.
        fn advertised_qabl_id(&mut self, face_id: u64, keyexpr: &str) -> u64 {
            let next = self.next_local_qabl_id.get();
            let Some(face) = self.faces.get_mut(&face_id) else {
                return 0;
            };
            if let Some(id) = face.local_qabls.get(keyexpr) {
                return *id;
            }
            face.local_qabls.insert(String::from(keyexpr), next);
            self.next_local_qabl_id.set(next.saturating_add(1));
            next
        }

        /// Advertise a newly-declared queryable on `keyexpr` (held by face
        /// `src_id`) to every OTHER face whose registered QUERYABLES interest
        /// matches — the FUTURE half, and the query-plane twin of
        /// [`propagate_token_declaration`](Self::propagate_token_declaration).
        /// Interest-GATED for the same reason and by the same upstream rule
        /// (`hat/router/queries.rs:255-259`).
        ///
        /// The advertised [`QueryableInfo`] is the MERGE over every face
        /// covering the advertised keyexpr, not just the newly-declared one:
        /// the advertisement is one declaration standing for all of them (the
        /// `local_qabls` skip guarantees exactly one), so it must describe all
        /// of them. A second queryable that arrives later and is `complete`
        /// where the first was not is the case this gets wrong if the merge is
        /// skipped — and it is why the already-advertised skip does NOT simply
        /// return: it re-sends the same id with the widened info, which is
        /// upstream's own idempotent re-declare (`propagate_simple_qabl_to`
        /// sends whenever the computed info differs from the advertised one).
        fn propagate_qabl_declaration(&mut self, src_id: u64, keyexpr: &str) {
            let target_chunks: Vec<&str> = keyexpr.split('/').collect();
            let mut targets: Vec<(u64, String, QueryableInfo)> = Vec::new();
            for (fid, face) in self.faces.iter() {
                if *fid == src_id {
                    continue;
                }
                for qi in face.qabl_interests.iter() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(&qi.keyexpr, &target_chunks)
                    {
                        continue;
                    }
                    let advertised = if qi.aggregate {
                        qi.keyexpr.clone()
                    } else {
                        String::from(keyexpr)
                    };
                    if targets
                        .iter()
                        .any(|(f, k, _)| *f == *fid && *k == advertised)
                    {
                        continue;
                    }
                    let info = self.covering_queryable_info(*fid, &advertised);
                    targets.push((*fid, advertised, info));
                }
            }
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, DeclareOwned)> = Vec::new();
            for (fid, advertised, info) in &targets {
                let qabl_id = self.advertised_qabl_id(*fid, advertised);
                if qabl_id == 0 {
                    continue;
                }
                let Some(face) = self.faces.get(fid) else {
                    continue;
                };
                if let Ok(decl) =
                    build_declare_queryable_with_id_info(qabl_id, advertised.as_str(), *info)
                {
                    sends.push((face.actions.clone(), decl));
                }
            }
            for (actions, decl) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(decl)),
                    true,
                    true,
                );
            }
        }

        /// The merged [`QueryableInfo`] of every queryable — held on a face
        /// OTHER than `dst_id` — that intersects `advertised`. zenoh's
        /// `compute_qabl_info` fold; seeded from the FIRST contributor rather
        /// than from [`QueryableInfo::DEFAULT`], because `DEFAULT.distance == 0`
        /// would collapse the `min` (the fold's own documented trap).
        fn covering_queryable_info(&self, dst_id: u64, advertised: &str) -> QueryableInfo {
            let target_chunks: Vec<&str> = advertised.split('/').collect();
            let mut merged: Option<QueryableInfo> = None;
            for (fid, face) in self.faces.iter() {
                if *fid == dst_id {
                    continue;
                }
                for q in face.qabls.values() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(&q.keyexpr, &target_chunks)
                    {
                        continue;
                    }
                    merged = Some(match merged {
                        Some(acc) => acc.merge(q.info),
                        None => q.info,
                    });
                }
            }
            merged.unwrap_or(QueryableInfo::DEFAULT)
        }

        /// Retract a queryable on `keyexpr` from every face that was told about
        /// it — the query-plane twin of
        /// [`propagate_token_forget`](Self::propagate_token_forget), with the
        /// same still-held guard (another face covering the same keyexpr keeps
        /// the advertisement alive), the same id-only-when-we-advertised /
        /// sourced-when-we-did-not pair, and the same aggregate exclusion on the
        /// sourced arm.
        fn propagate_qabl_forget(&mut self, src_id: Option<u64>, keyexpr: &str) {
            if self
                .faces
                .values()
                .any(|f| f.qabls.values().any(|q| q.keyexpr == keyexpr))
            {
                return;
            }
            let target_chunks: Vec<&str> = keyexpr.split('/').collect();
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, DeclareOwned)> = Vec::new();
            for (fid, face) in self.faces.iter_mut() {
                if let Some(id) = face.local_qabls.remove(keyexpr) {
                    sends.push((face.actions.clone(), build_undeclare_queryable(id)));
                    continue;
                }
                if src_id == Some(*fid) {
                    continue;
                }
                let interested = face.qabl_interests.iter().any(|qi| {
                    !qi.aggregate
                        && crate::keyexpr_match::keyexpr_intersects_target(
                            &qi.keyexpr,
                            &target_chunks,
                        )
                });
                if !interested {
                    continue;
                }
                if let Ok(decl) = build_undeclare_queryable_with_keyexpr(keyexpr) {
                    sends.push((face.actions.clone(), decl));
                }
            }
            for (actions, decl) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(decl)),
                    true,
                    true,
                );
            }
        }

        /// Route an inbound `Request(Query)` from face `src_id` to every OTHER
        /// face holding a matching queryable — zenoh's `route_query`
        /// (`dispatcher/queries.rs`).
        ///
        /// Three things this does that a naive fan-out would not:
        ///
        /// 1. **It mints its own request id per destination.** The querier's id
        ///    is unique only within its own face; two faces querying at once
        ///    routinely both use `0`, and a reply could then not be attributed.
        ///    zenoh mints from `face.next_qid` for exactly this.
        /// 2. **It re-literalizes the keyexpr.** A destination face never saw
        ///    the querier's `DeclareKeyexpr` aliases, so an aliased Request
        ///    forwarded verbatim names an id that face cannot resolve — the
        ///    same rule (and the same reason) as
        ///    [`forward_push`](Self::forward_push)'s `reliteralize_push`.
        /// 3. **An empty route is ANSWERED, not dropped.** A querier holds the
        ///    query open until a `ResponseFinal` arrives, so silence costs it a
        ///    full timeout rather than telling it there are no queryables.
        ///    Upstream's `route_query` sends the final itself on an empty route;
        ///    this is the same class of defect R311y773 fixed for
        ///    `declare-final`, and the same fix.
        fn route_query(&mut self, src_id: u64, request: &RequestOwned) {
            let Some(src) = self.faces.get(&src_id) else {
                return;
            };
            let src_actions = src.actions.clone();
            let src_rid = request.rid;
            let Some(keyexpr) = resolve_wireexpr(&request.keyexpr.body, &src.peer_aliases) else {
                log::debug!(
                    "RouteTable: face {src_id} queried on an expr-id with no prior \
                     DeclareKeyexpr mapping; finalized without routing"
                );
                Self::send_final_to(&src_actions, src_rid);
                return;
            };
            let target_chunks: Vec<&str> = keyexpr.split('/').collect();
            // Every face that could answer, paired with whether it can answer
            // ALONE and from how far. The source face is excluded HERE rather
            // than in each target arm — zenoh carries the same exclusion inside
            // its BestMatching predicate and its `egress_filter`, so a query is
            // never a candidate for its own asker whatever the target says.
            let mut candidates: Vec<(u64, Option<u16>)> = self
                .faces
                .iter()
                .filter(|(id, _)| **id != src_id)
                .filter_map(|(id, face)| face.query_fit(&target_chunks).map(|fit| (*id, fit)))
                .collect();
            // NEAREST-COMPLETE FIRST, then by face id. The first key is zenoh's
            // `route.sort_by_key(|qabl| qabl.info.map_or(u16::MAX, |i| i.distance))`
            // (`zenoh/src/net/routing/hat/router/queries.rs` @ `distance`);
            // a face that cannot answer alone
            // sorts to the end, which selects the same element as zenoh's
            // sort-then-find because that find skips it anyway. The SECOND key
            // has no zenoh counterpart and needs one here: zenoh's stable sort
            // runs over an insertion-ordered `Vec`, while this scans a
            // `HashMap` whose iteration order is randomised per process, so
            // without an explicit tiebreak a tie would be resolved by a coin
            // flip and the router would answer the same query from a different
            // peer each time.
            candidates.sort_unstable_by_key(|(id, fit)| (fit.unwrap_or(u16::MAX), *id));
            let targets: Vec<u64> =
                match crate::request_routing_context::read_request_target(request) {
                    // BestMatching — the WIRE DEFAULT, and what a plain `z_get`
                    // asks for: pico omits the ext entirely for it
                    // (`network.c:27`). ONE queryable, the nearest that covers the
                    // whole query; if none does, no single answer exists and the
                    // route degrades to All rather than dropping the others
                    // (zenoh `dispatcher/queries.rs:243-266`).
                    None => match candidates.iter().find(|(_, fit)| fit.is_some()) {
                        Some((id, _)) => alloc::vec![*id],
                        None => candidates.iter().map(|(id, _)| *id).collect(),
                    },
                    // AllComplete — a FILTER, not a selection: every AUTHORITATIVE
                    // answerer and no other (`dispatcher/queries.rs:228-241`). An
                    // empty result is a real empty route and falls through to the
                    // immediate-final arm below.
                    Some(QueryTarget::AllComplete) => candidates
                        .iter()
                        .filter(|(_, fit)| fit.is_some())
                        .map(|(id, _)| *id)
                        .collect(),
                    // All — everyone that matches, completeness irrelevant
                    // (`dispatcher/queries.rs:206-227`).
                    Some(QueryTarget::All) => candidates.iter().map(|(id, _)| *id).collect(),
                };
            if targets.is_empty() {
                Self::send_final_to(&src_actions, src_rid);
                return;
            }
            // Built ONCE, then re-stamped per destination with that
            // destination's own router-minted id.
            let routed = match crate::request_build::reliteralize_request(request, &keyexpr) {
                Ok(r) => r,
                Err(e) => {
                    log::debug!(
                        "RouteTable: face {src_id} query keyexpr could not be re-literalized \
                         for routing ({e:?}); finalized without routing"
                    );
                    Self::send_final_to(&src_actions, src_rid);
                    return;
                }
            };
            let query_key = self.mint_id();
            let mut outstanding = 0usize;
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, RequestOwned)> = Vec::new();
            for dst_id in &targets {
                let out_rid = self.mint_id();
                let Some(face) = self.faces.get_mut(dst_id) else {
                    continue;
                };
                face.pending_queries.insert(out_rid, query_key);
                let mut out = routed.clone();
                out.rid = out_rid;
                sends.push((face.actions.clone(), out));
                outstanding += 1;
            }
            if outstanding == 0 {
                // Unreachable in practice (every target came out of `faces` a
                // statement ago); still answered rather than dropped, because
                // the one thing a querier must never get is silence.
                Self::send_final_to(&src_actions, src_rid);
                return;
            }
            self.pending_queries.insert(
                query_key,
                PendingQuery {
                    src_face: src_id,
                    src_rid,
                    outstanding,
                },
            );
            self.queries_routed = self.queries_routed.saturating_add(1);
            for (actions, out) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Request(Box::new(out)),
                    true,
                    true,
                );
            }
        }

        /// Route a `Response` (a query reply) from an answering face back to the
        /// face that asked, re-stamped with the request id THAT face minted —
        /// zenoh's `route_send_response` reading `face.pending_queries` and
        /// sending under `query.src_qid`.
        ///
        /// The lookup is per-face on purpose: an id is honoured only on the face
        /// the matching `Request` was sent to, so a peer cannot answer (or
        /// poison) another peer's query by guessing an id. An unknown id is
        /// dropped — it is either a late reply after the final or a fabricated
        /// one, and neither has a querier to reach.
        fn route_response(&mut self, src_id: u64, response: &ResponseOwned) {
            let Some(src) = self.faces.get(&src_id) else {
                return;
            };
            let Some(query_key) = src.pending_queries.get(&response.request_id).copied() else {
                log::debug!(
                    "RouteTable: face {src_id} replied to request id {} it was never sent; dropped",
                    response.request_id
                );
                return;
            };
            // Resolved in the RESPONDER's alias context and re-literalized for
            // the querier, the same reason the Request was on the way out: the
            // querier never saw the responder's expr-id mappings.
            let keyexpr = resolve_wireexpr(&response.keyexpr.body, &src.peer_aliases);
            let Some(pending) = self.pending_queries.get(&query_key) else {
                return;
            };
            let (src_face, src_rid) = (pending.src_face, pending.src_rid);
            let Some(querier) = self.faces.get(&src_face) else {
                return;
            };
            let querier_actions = querier.actions.clone();
            let mut out = response.clone();
            out.request_id = src_rid;
            if let Some(keyexpr) = keyexpr {
                if let Err(e) =
                    crate::response_build::set_response_keyexpr_literal(&mut out, &keyexpr)
                {
                    log::debug!(
                        "RouteTable: reply keyexpr could not be re-literalized ({e:?}); dropped"
                    );
                    return;
                }
            }
            let _ = querier_actions.send_network_message(
                NetworkMessage::Response(Box::new(out)),
                true,
                true,
            );
        }

        /// Route a `ResponseFinal` from an answering face: that answerer is
        /// done. The querier is closed only when the LAST one is
        /// ([`close_one_answerer`](Self::close_one_answerer)) — zenoh gets the
        /// same behaviour from `Drop for Query` once the last `Arc` clone goes.
        fn route_response_final(&mut self, src_id: u64, final_msg: &ResponseFinalOwned) {
            let Some(src) = self.faces.get_mut(&src_id) else {
                return;
            };
            let Some(query_key) = src.pending_queries.remove(&final_msg.request_id) else {
                log::debug!(
                    "RouteTable: face {src_id} finalized request id {} it was never sent; dropped",
                    final_msg.request_id
                );
                return;
            };
            self.close_one_answerer(query_key);
        }

        /// One answerer of `query_key` has finished (replied and finalized, or
        /// departed). Drop the outstanding count and, when it reaches zero, send
        /// the querier the single `ResponseFinal` that closes its query and
        /// forget the pending entry.
        fn close_one_answerer(&mut self, query_key: u64) {
            let Some(pending) = self.pending_queries.get_mut(&query_key) else {
                return;
            };
            pending.outstanding = pending.outstanding.saturating_sub(1);
            if pending.outstanding > 0 {
                return;
            }
            let (src_face, src_rid) = (pending.src_face, pending.src_rid);
            self.pending_queries.remove(&query_key);
            if let Some(querier) = self.faces.get(&src_face) {
                Self::send_final_to(&querier.actions.clone(), src_rid);
            }
        }

        /// Mint the next unique id (a query key or a router-minted request id) —
        /// see [`next_query_id`](Self::next_query_id) for why one counter serves
        /// both.
        fn mint_id(&self) -> u64 {
            let id = self.next_query_id.get();
            self.next_query_id.set(id.saturating_add(1));
            id
        }

        /// Send a `ResponseFinal` for `rid` on `actions`. The one place the
        /// closing message is built, so the four paths that close a query (empty
        /// route, unresolvable keyexpr, last answerer, answerer departure) cannot
        /// drift apart.
        fn send_final_to(actions: &Arc<SessionLinkActions<R, T>>, rid: u64) {
            let _ = actions.send_network_message(
                NetworkMessage::ResponseFinal(crate::response_final_build::build_response_final(
                    rid,
                )),
                true,
                true,
            );
        }

        /// Push an unsolicited `DeclareSubscriber` for a newly-declared
        /// subscription `new_sub_keyexpr` (on face `new_sub_face`) to every OTHER
        /// face whose registered FUTURE subscriber interest matches it — the
        /// pub-before-sub half of the write-filter release. The reply keyexpr is
        /// the interest's OWN keyexpr for an AGGREGATE interest (peer associates by
        /// `_z_keyexpr_equals`) else the concrete subscription keyexpr; each
        /// carries a non-zero subscriber id (id 0 is the CURRENT dump), reused per
        /// `(interest, reply keyexpr)` so a redundant re-push dedups on the peer.
        fn push_future_subscriber(&mut self, new_sub_face: u64, new_sub_keyexpr: &str) {
            let target_chunks: Vec<&str> = new_sub_keyexpr.split('/').collect();
            let mut sends: Vec<(Arc<SessionLinkActions<R, T>>, DeclareOwned)> = Vec::new();
            for (fid, face) in self.faces.iter_mut() {
                if *fid == new_sub_face {
                    continue;
                }
                for fi in face.future_subs.iter_mut() {
                    if !crate::keyexpr_match::keyexpr_intersects_target(&fi.keyexpr, &target_chunks)
                    {
                        continue;
                    }
                    let reply_ke = if fi.aggregate {
                        fi.keyexpr.clone()
                    } else {
                        String::from(new_sub_keyexpr)
                    };
                    let sub_id = match fi.pushed.get(&reply_ke) {
                        Some(id) => *id,
                        None => {
                            let id = self.next_future_sub_id.get();
                            self.next_future_sub_id.set(id.saturating_add(1));
                            fi.pushed.insert(reply_ke.clone(), id);
                            id
                        }
                    };
                    if let Ok(decl) =
                        build_declare_subscriber_reply_with_id(fi.interest_id, sub_id, &reply_ke)
                    {
                        sends.push((face.actions.clone(), decl));
                    }
                }
            }
            for (actions, decl) in sends {
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(decl)),
                    true,
                    true,
                );
            }
        }

        /// Forward a Put received on `src_id` to every OTHER face whose
        /// subscriptions match its keyexpr. Returns the number of forwards
        /// that the destination send seam accepted.
        fn forward_push(
            &self,
            src_id: u64,
            push: &PushOwned,
            reliable: bool,
            priority: Priority,
        ) -> usize {
            // Resolve the source keyexpr in the source face's alias context
            // (literal id=0 verbatim; aliased id!=0 via DeclareKeyexpr). An id
            // with no prior mapping yields None and is dropped.
            //
            // PEER TABLE ONLY, and that is a PREMISE rather than an oversight
            // (carry N39, closed R311y766). R311y739 gave every other inbound
            // plane the pair the `M` bit picks between — pubsub, reply,
            // switchboard, liveliness all take `impl Into<MappingSpaces>` — and
            // left this kernel peer-only. The consequence: an `M=0` alias, one
            // naming an id the RELAY declared, resolves against nothing here and
            // is dropped indistinguishably from a peer naming an id it never
            // declared. Correct while the relay declares no alias of its own,
            // wrong the day it does.
            //
            // So that premise is a test rather than a sentence:
            // `routing_forward::tests::the_relay_emits_no_alias_of_its_own`
            // decodes the bytes this forwarder puts on a destination face and
            // requires every keyexpr in them to be literal. Falsified by making
            // `reliteralize_push` forward verbatim, which reds it with `id 9`.
            // The day a forward path emits an alias, that test names this site.
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
                // so an open batch window flushes (deliver-now forward). R311y224 —
                // route through `send_network_message_qos` on the received
                // `FramePayload.priority` so this switchboard transit PRESERVES the
                // band (the twin of the linkstate `forward_push` / router
                // `forward_push_tier`), instead of re-clamping to DEFAULT. `express`
                // stays TRUE here (the switchboard's deliver-now forward, unlike the
                // mesh transit's express=false); DEFAULT under a non-QoS session (the
                // `dispatch_push` clamp), so byte-identical to the prior
                // `send_network_message` on every non-QoS transit.
                let msg = NetworkMessage::Push(Box::new(forwarded.clone()));
                if face
                    .actions
                    .send_network_message_qos(msg, reliable, true, priority)
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
            // A malformed keyexpr (an empty chunk, e.g. a trailing '/') matches
            // no face: `Face::matches` -> `declared_intersects` ->
            // `keyexpr_intersects_target` rejects it at the matcher, so the scan
            // below yields an empty route. The malformed-target invariant is
            // single-sourced in the matcher (zenoh compute_data_route parity),
            // not re-guarded here — see `keyexpr_match::target_chunks_well_formed`.
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
