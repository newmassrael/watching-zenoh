// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer observer helper — bundles the six per-domain
//! registries plus their pending-reply / pending-final scratch
//! buffers into one cohesive struct so a production caller can drive
//! the whole dispatch graph with a single
//! [`ApplicationLayerObserver::dispatch`] call per
//! [`IterationEvent`].
//!
//! ## Why this exists
//!
//! Pre-R121k-7, every production binary (wz-ap-demo) had to manually
//! instantiate six registries, hold two `Vec<…>` staging buffers,
//! and write a 6-step fan-out closure that mirrored:
//!
//! ```text
//! |event| {
//!     subscribers.dispatch_iteration_event(event);
//!     let peer_table = subscribers.peer_keyexpr_table();
//!     queryables.dispatch_iteration_event(event, peer_table, …);
//!     remote_subscribers.dispatch_iteration_event(event, peer_table);
//!     remote_queryables.dispatch_iteration_event(event, peer_table);
//!     liveliness.dispatch_iteration_event(event, peer_table);
//!     replies.dispatch_iteration_event(event, peer_table);
//!     for reply in pending_replies.drain(..) { … }
//!     for rid   in pending_final_rids.drain(..) { … }
//! }
//! ```
//!
//! Every consumer that wired even a subset of the registries
//! replicated the same shape (with subtle drift opportunities: a
//! missing fan-out, a peer_table snapshot inconsistency, a swapped
//! drain order). The helper struct centralises the wire-up so a
//! consumer writes one line at session boot and the registries fan
//! uniformly thereafter:
//!
//! ```text
//! let mut observer = ApplicationLayerObserver::new();
//! observer.subscribe("home/temp", on_temp)?;
//! observer.with_app(|app| app.queryables.register("metrics/**", on_metric))?;
//! observer.face().replies.register(rid, expected_finals, on_reply, on_final)?;
//! // … later, inside the drive_session observer closure:
//! observer.dispatch(event, &actions);
//! ```
//!
//! ## What is NOT in scope
//!
//! - **No interior mutability**: the struct is `!Sync` (each contained
//!   registry is `!Sync` by construction). Cross-task sharing still
//!   wraps in `Arc<Mutex<…>>` or `Arc<tokio::sync::Mutex<…>>`.
//! - **No async**: dispatch is synchronous — every contained
//!   registry's callback shape is `FnMut`, and the actions-side
//!   drain (`send_response` / `send_response_final`) is also
//!   synchronous. The bundle preserves the MCU-runtime compatibility
//!   of every sub-registry.
//! - **No re-export shimming**: consumers still import the underlying
//!   registry types from their own modules
//!   (`wz_runtime_tokio::pubsub::SubscriberRegistry`,
//!   `wz_runtime_tokio::reply::ReplyRegistry`, etc. — each a re-export
//!   shell over this crate's modules) when they need the types for
//!   non-bundled usage. The bundle hands out its two halves (the
//!   application's tables and the peer's, `with_app` / `face` and their
//!   kin) so application code calls `register` on each table itself.
//!
//! ## Dispatch flow
//!
//! `dispatch(event, &actions)` runs in two phases:
//!
//! 1. **Fan** — `dispatch_event(event)` routes `event` into every
//!    registry. The subscriber registry runs FIRST so any
//!    `Declare(DeclKexpr)` body in the same frame populates the
//!    peer_keyexpr_table before the consumer registries read it.
//! 2. **Drain** — `flush_pending(&actions)` walks the peer tables' staged
//!    replies and owed `Final`s (populated by the queryable side during
//!    fan-out) and emits each through the action layer. Order is
//!    preserved on the wire: every Reply for rid R precedes the
//!    matching ResponseFinal for R (zenoh-pico's z_get correlator
//!    depends on this).
//!
//! `dispatch_event` and `flush_pending` are exposed individually so
//! tests can exercise the fan without an actions stand-in (the
//! actions-side drain is covered by integration tests against a real
//! TCP loopback). Production code calls the combined
//! `ApplicationLayerObserver::dispatch` form.
//!
//! ## R311dz — migrated to wz-session-core
//!
//! This module moved from `wz-runtime-tokio::observer` into
//! `wz-session-core` so MCU runtime profiles compose the same dispatch
//! bundle without inheriting std / tokio. The move was unblocked by
//! R311dz-pre's [`crate::response_sink::ResponseSink`] IoC trait (the
//! observer's only hard dependency on the tokio actions layer). Every
//! per-domain registry it aggregates already lives here (`pubsub` /
//! `query` / `reply` / `declare` — R311do..dy); the AP crate keeps a
//! one-line re-export shell
//! (`pub use wz_session_core::observer::ApplicationLayerObserver;`) so
//! `wz_runtime_tokio::observer::*` consumer paths are unchanged. The
//! whole module gates on `codec-declare` (the `liveliness_subscribers`
//! field's type lives under the `codec-declare`-gated `declare`
//! module); the `queryables` field additionally gates on
//! `query-queryable`, so a `codec-declare`-on / `query-queryable`-off
//! subset composes the observer with the queryable slot elided.

// The observer's halves are the slot profile's tables; what is named here is what the halves'
// borrowed forms (`ObserverApp`, `ObserverFace`) spell out, each under the feature of its table.
#[cfg(feature = "liveliness-token")]
use crate::declare::liveliness::LivelinessRegistry;
#[cfg(feature = "liveliness-get")]
use crate::declare::liveliness_get::LivelinessGetRegistry;
#[cfg(feature = "liveliness-token")]
use crate::declare::local_token::LocalTokenRegistry;
use crate::driver_loop::IterationEvent;
use crate::owed_replies::OwedReplies;
use crate::peer_tables::PeerTables;
#[cfg(feature = "query-queryable")]
use crate::query::QueryableRegistry;
use crate::reply::ReplyRegistry;
use crate::reply_stage::FinalStage;
// The drains are generic over the sink traits, so the AP's `SessionLinkActions` and an MCU sink
// drive the same observer.
use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use crate::slot_observer::{Requesters, SlotObserver};
#[cfg(feature = "switchboard")]
use crate::switchboard::{EventInjector, SwitchboardRegistry};

/// The application-layer dispatch of one session, in its two halves (`docs/c-abi-l3-tables.md`,
/// section 7): what the program registers (the slot observer's tables, [`SlotObserver`]) and what
/// this session's peer writes and is owed ([`PeerTables`]) with the gets the session asked of it
/// ([`Requesters`]). See the module-level docs for the dispatch flow.
pub struct ApplicationLayerObserver {
    /// What the program registers: its subscribers, queryables, tokens and liveliness
    /// subscribers, the statechart switchboard and the listeners on what a peer declares.
    app: SlotObserver,
    /// What this session's peer declared, asked and is owed: its key aliases and interests, its
    /// subscribers, queryables and tokens, the replies and `Final`s staged for its queries and the
    /// answers staged for its liveliness interests.
    peers: PeerTables,
    /// The session's own gets pending on the peer: its queries, each reply passed through its
    /// consolidation, and its liveliness snapshots.
    requesters: Requesters<
        crate::reply_sink::ConsolidatingSink<crate::reply_sink::BoxedReplySink>,
        crate::reply_sink::BoxedReplySink,
    >,
    /// `QUERIER_MAX_PENDING_QUERIES` as the session's creator stated it: how many queries one
    /// querier declared on the session has in flight at once. The runtime that declares a querier
    /// reads it here ([`Self::querier_max_pending_queries`]) and holds the querier's places to it
    /// in a [`crate::quota::Quota`]; the pending entries themselves are rows of the requesters.
    querier_max_pending_queries: crate::limits::QuerierMaxPendingQueriesHeld,
    /// The interest-response chains owed to peers' QUERYABLE Interests, in stage
    /// order, drained through
    /// [`DeclareReplySink::send_declare_queryable_reply`]. Owned (see
    /// [`crate::query::QueryableInterestReply`]), so it exists only where the
    /// heap does, and only where the `Final` that ends a chain can be sent.
    #[cfg(all(
        feature = "alloc",
        feature = "query-queryable",
        feature = "declare-queryable",
        any(feature = "liveliness-token", feature = "declare-subscriber"),
        feature = "interest-answer"
    ))]
    pending_queryable_replies: alloc::vec::Vec<crate::query::QueryableInterestReply>,
    /// The observers told, once, that the peer ended its initial declarations
    /// (`declarations-synced-event`). Not fired by [`Self::dispatch_event`]: the session that
    /// drives this observer fires it where it sees the fact turn true, because the flag it turns
    /// on lives on the subscriber plane and the observers listen on all three.
    #[cfg(feature = "declarations-synced-event")]
    declarations_final: crate::decl_sink::SyncedSinks,
}

/// The application half of an [`ApplicationLayerObserver`], to change: what the program registers
/// on the session (its subscribers, queryables, tokens, liveliness subscribers, switchboard rows and
/// the listeners on what a peer declares), apart from anything a peer writes.
///
/// Reached only through [`ApplicationLayerObserver::with_app`] and
/// [`ApplicationLayerObserver::with_parts`], whose closures cannot keep a borrow of it past their
/// return: a session whose application half is shared with the other faces of its node keeps that
/// half behind a lock of its own, taken while the face's observer is held and let go before it
/// (`docs/c-abi-l3-tables.md`, section 7: the face's observer first, the shared half second, never
/// the reverse).
pub struct ObserverApp<'a> {
    /// The local subscriptions.
    pub subscribers: &'a mut crate::pubsub::SubscriberTable<crate::sink::BoxedSink>,
    /// The statechart switchboard.
    #[cfg(feature = "switchboard")]
    pub switchboard: &'a mut SwitchboardRegistry,
    /// The local queryables.
    #[cfg(feature = "query-queryable")]
    pub queryables: &'a mut QueryableRegistry<crate::query_sink::BoxedQuerySink>,
    /// The listeners on the subscribers a peer declares, and the matching watches.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: &'a mut crate::declare::subscriber::RemoteSubscriberTable<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// The listeners on the queryables a peer declares, and the matching watches.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: &'a mut crate::declare::queryable::RemoteQueryableTable<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// The listeners on the tokens a peer declares.
    #[cfg(feature = "liveliness-token")]
    pub liveliness: &'a mut LivelinessRegistry<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// The tokens the session holds.
    #[cfg(feature = "liveliness-token")]
    pub local_tokens: &'a mut LocalTokenRegistry,
    /// The local liveliness subscribers.
    #[cfg(feature = "liveliness-subscriber")]
    pub liveliness_subscribers:
        &'a mut crate::declare::liveliness_subscriber::LivelinessSubscriberTable<
            crate::declare::liveliness_sample::BoxedLivelinessSampleSink,
        >,
    /// The observers told that a peer ended its initial declarations.
    #[cfg(feature = "declarations-synced-event")]
    pub declarations_final: &'a mut crate::decl_sink::SyncedSinks,
}

/// The application half of an [`ApplicationLayerObserver`], to read ([`ObserverApp`]).
pub struct ObserverAppRef<'a> {
    /// The local subscriptions.
    pub subscribers: &'a crate::pubsub::SubscriberTable<crate::sink::BoxedSink>,
    /// The statechart switchboard.
    #[cfg(feature = "switchboard")]
    pub switchboard: &'a SwitchboardRegistry,
    /// The local queryables.
    #[cfg(feature = "query-queryable")]
    pub queryables: &'a QueryableRegistry<crate::query_sink::BoxedQuerySink>,
    /// The listeners on the subscribers a peer declares, and the matching watches.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: &'a crate::declare::subscriber::RemoteSubscriberTable<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// The listeners on the queryables a peer declares, and the matching watches.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: &'a crate::declare::queryable::RemoteQueryableTable<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// The listeners on the tokens a peer declares.
    #[cfg(feature = "liveliness-token")]
    pub liveliness:
        &'a LivelinessRegistry<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// The tokens the session holds.
    #[cfg(feature = "liveliness-token")]
    pub local_tokens: &'a LocalTokenRegistry,
    /// The local liveliness subscribers.
    #[cfg(feature = "liveliness-subscriber")]
    pub liveliness_subscribers:
        &'a crate::declare::liveliness_subscriber::LivelinessSubscriberTable<
            crate::declare::liveliness_sample::BoxedLivelinessSampleSink,
        >,
    /// The observers told that a peer ended its initial declarations.
    #[cfg(feature = "declarations-synced-event")]
    pub declarations_final: &'a crate::decl_sink::SyncedSinks,
}

/// The face half of an [`ApplicationLayerObserver`], to change: what the session's peer writes
/// (its key aliases and interests, its subscribers, queryables and tokens) and the gets the session
/// asked of it. It is the observer's own in every session, so it is borrowed directly
/// ([`ApplicationLayerObserver::face`]).
pub struct ObserverFace<'a> {
    /// The peer's key aliases and the interests it asked.
    pub subscribers: &'a mut crate::pubsub::SubscriberPeer,
    /// What the peer's queries are judged by.
    pub queries: &'a mut crate::query::QueryPeer,
    /// The subscribers the peer declared.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: &'a mut crate::declare::subscriber::RemoteSubscriberPeer,
    /// The queryables the peer declared.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: &'a mut crate::declare::queryable::RemoteQueryablePeer,
    /// The tokens the peer declared.
    #[cfg(feature = "liveliness-subscriber")]
    pub tokens: &'a mut crate::declare::liveliness_subscriber::PeerTokens,
    /// The session's gets pending on the peer.
    pub replies: &'a mut ReplyRegistry<
        crate::reply_sink::ConsolidatingSink<crate::reply_sink::BoxedReplySink>,
    >,
    /// The session's liveliness gets pending on the peer.
    #[cfg(feature = "liveliness-get")]
    pub liveliness_gets: &'a mut LivelinessGetRegistry<crate::reply_sink::BoxedReplySink>,
}

/// The face half of an [`ApplicationLayerObserver`], to read ([`ObserverFace`]).
pub struct ObserverFaceRef<'a> {
    /// The peer's key aliases and the interests it asked.
    pub subscribers: &'a crate::pubsub::SubscriberPeer,
    /// What the peer's queries are judged by.
    pub queries: &'a crate::query::QueryPeer,
    /// The subscribers the peer declared.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: &'a crate::declare::subscriber::RemoteSubscriberPeer,
    /// The queryables the peer declared.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: &'a crate::declare::queryable::RemoteQueryablePeer,
    /// The tokens the peer declared.
    #[cfg(feature = "liveliness-subscriber")]
    pub tokens: &'a crate::declare::liveliness_subscriber::PeerTokens,
    /// The session's gets pending on the peer.
    pub replies:
        &'a ReplyRegistry<crate::reply_sink::ConsolidatingSink<crate::reply_sink::BoxedReplySink>>,
    /// The session's liveliness gets pending on the peer.
    #[cfg(feature = "liveliness-get")]
    pub liveliness_gets: &'a LivelinessGetRegistry<crate::reply_sink::BoxedReplySink>,
}

impl Default for ApplicationLayerObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationLayerObserver {
    /// New observer with empty registries, each held to the limits `limits` states: what the
    /// creator of the session (an open, a node) resolved for it. A table reads its bound here and
    /// never from the build.
    pub fn with_limits(limits: &crate::limits::SessionLimits) -> Self {
        let mut observer = Self::new();
        observer.app.limit_to(limits);
        observer.peers.limit_to(limits);
        observer.requesters.limit_to(limits);
        observer.querier_max_pending_queries = limits.querier_max_pending_queries_held();
        observer
    }

    /// The bound of each querier declared on the session: `QUERIER_MAX_PENDING_QUERIES` as the
    /// session's creator stated it ([`Self::with_limits`]), the build's value for an observer made
    /// by [`Self::new`].
    pub const fn querier_max_pending_queries(&self) -> crate::limit_binding::Quota {
        self.querier_max_pending_queries.get()
    }

    /// The bounds the session's replies are staged under (`MAX_PENDING_REPLIES`,
    /// `MAX_REPLY_PAYLOAD_BYTES`) as the session's creator stated them ([`Self::with_limits`]),
    /// the build's for an observer made by [`Self::new`]. A runtime that stages the replies of
    /// one query apart from this observer (a handler run outside its lock, a query held past its
    /// handler) holds that stage to them.
    pub const fn reply_bounds(&self) -> crate::reply_stage::ReplyBounds {
        self.peers.replies.bounds()
    }

    /// Run `f` over the application half ([`ObserverApp`]), with this observer held: the one way
    /// a caller changes what the program registered on the session.
    pub fn with_app<Rt>(&mut self, f: impl FnOnce(ObserverApp<'_>) -> Rt) -> Rt {
        f(self.parts_mut().0)
    }

    /// Run `f` over the application half, to read ([`Self::with_app`]).
    pub fn read_app<Rt>(&self, f: impl FnOnce(ObserverAppRef<'_>) -> Rt) -> Rt {
        f(self.parts_ref().0)
    }

    /// Run `f` over both halves at once: what a call that hands the peer's tables to a method of
    /// the application's needs (a matching re-judgement, an answer to a peer's interest).
    pub fn with_parts<Rt>(
        &mut self,
        f: impl FnOnce(ObserverApp<'_>, ObserverFace<'_>) -> Rt,
    ) -> Rt {
        let (app, face) = self.parts_mut();
        f(app, face)
    }

    /// Run `f` over both halves at once, to read ([`Self::with_parts`]).
    pub fn read_parts<Rt>(
        &self,
        f: impl FnOnce(ObserverAppRef<'_>, ObserverFaceRef<'_>) -> Rt,
    ) -> Rt {
        let (app, face) = self.parts_ref();
        f(app, face)
    }

    /// The face half ([`ObserverFace`]), the observer's own in every session.
    pub fn face(&mut self) -> ObserverFace<'_> {
        self.parts_mut().1
    }

    /// The face half, to read ([`Self::face`]).
    pub fn face_ref(&self) -> ObserverFaceRef<'_> {
        self.parts_ref().1
    }

    /// Register a local subscription on `keyexpr_pattern` that hears what `allowed_origin`
    /// admits, delivered to `sink`, and stage what it owes this observer's peer (a peer that holds
    /// a future subscriber interest is told of it): both halves in one step, as
    /// [`SubscriberTable::register_sink_for`](crate::pubsub::SubscriberTable::register_sink_for)
    /// does.
    pub fn register_subscriber(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        sink: crate::sink::BoxedSink,
    ) -> Result<crate::pubsub::SubscriptionId, crate::registry_error::RegisterError> {
        self.app.tables.subscribers.register_sink_for(
            &mut self.peers.subscribers,
            keyexpr_pattern,
            allowed_origin,
            sink,
        )
    }

    /// [`Self::register_subscriber`] for a callback, heard from every origin: what a program that
    /// holds the observer itself registers a subscriber with.
    pub fn subscribe(
        &mut self,
        keyexpr_pattern: &str,
        callback: impl FnMut(&dyn crate::sink::SampleView) + Send + 'static,
    ) -> Result<crate::pubsub::SubscriptionId, crate::registry_error::RegisterError> {
        self.subscribe_with_locality(keyexpr_pattern, crate::locality::Locality::Any, callback)
    }

    /// [`Self::register_subscriber`] for a callback that hears what `allowed_origin` admits.
    pub fn subscribe_with_locality(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        callback: impl FnMut(&dyn crate::sink::SampleView) + Send + 'static,
    ) -> Result<crate::pubsub::SubscriptionId, crate::registry_error::RegisterError> {
        self.register_subscriber(
            keyexpr_pattern,
            allowed_origin,
            crate::sink::BoxedSink::new(callback),
        )
    }

    /// Retire local subscription `id`, and stage what its going owes this observer's peer (the
    /// retraction of an aggregate it alone stood for): both halves in one step, as
    /// [`SubscriberTable::unregister_for`](crate::pubsub::SubscriberTable::unregister_for) does.
    /// Whether it was registered.
    pub fn unregister_subscriber(&mut self, id: crate::pubsub::SubscriptionId) -> bool {
        self.app
            .tables
            .subscribers
            .unregister_for(&mut self.peers.subscribers, id)
    }

    /// Both halves, borrowed apart.
    fn parts_mut(&mut self) -> (ObserverApp<'_>, ObserverFace<'_>) {
        let app = &mut self.app;
        let peers = &mut self.peers;
        let requesters = &mut self.requesters;
        (
            ObserverApp {
                subscribers: &mut app.tables.subscribers,
                #[cfg(feature = "switchboard")]
                switchboard: &mut app.switchboard,
                #[cfg(feature = "query-queryable")]
                queryables: &mut app.tables.queryables,
                #[cfg(feature = "declare-subscriber")]
                remote_subscribers: &mut app.remote_subscribers,
                #[cfg(feature = "declare-queryable")]
                remote_queryables: &mut app.remote_queryables,
                #[cfg(feature = "liveliness-token")]
                liveliness: &mut app.liveliness,
                #[cfg(feature = "liveliness-token")]
                local_tokens: &mut app.local_tokens,
                #[cfg(feature = "liveliness-subscriber")]
                liveliness_subscribers: &mut app.tables.liveliness_subscribers,
                #[cfg(feature = "declarations-synced-event")]
                declarations_final: &mut self.declarations_final,
            },
            ObserverFace {
                subscribers: &mut peers.subscribers,
                queries: &mut peers.queries,
                #[cfg(feature = "declare-subscriber")]
                remote_subscribers: &mut peers.remote_subscribers,
                #[cfg(feature = "declare-queryable")]
                remote_queryables: &mut peers.remote_queryables,
                #[cfg(feature = "liveliness-subscriber")]
                tokens: &mut peers.tokens,
                replies: &mut requesters.replies,
                #[cfg(feature = "liveliness-get")]
                liveliness_gets: &mut requesters.liveliness_gets,
            },
        )
    }

    /// Both halves, borrowed apart, to read.
    fn parts_ref(&self) -> (ObserverAppRef<'_>, ObserverFaceRef<'_>) {
        let app = &self.app;
        let peers = &self.peers;
        let requesters = &self.requesters;
        (
            ObserverAppRef {
                subscribers: &app.tables.subscribers,
                #[cfg(feature = "switchboard")]
                switchboard: &app.switchboard,
                #[cfg(feature = "query-queryable")]
                queryables: &app.tables.queryables,
                #[cfg(feature = "declare-subscriber")]
                remote_subscribers: &app.remote_subscribers,
                #[cfg(feature = "declare-queryable")]
                remote_queryables: &app.remote_queryables,
                #[cfg(feature = "liveliness-token")]
                liveliness: &app.liveliness,
                #[cfg(feature = "liveliness-token")]
                local_tokens: &app.local_tokens,
                #[cfg(feature = "liveliness-subscriber")]
                liveliness_subscribers: &app.tables.liveliness_subscribers,
                #[cfg(feature = "declarations-synced-event")]
                declarations_final: &self.declarations_final,
            },
            ObserverFaceRef {
                subscribers: &peers.subscribers,
                queries: &peers.queries,
                #[cfg(feature = "declare-subscriber")]
                remote_subscribers: &peers.remote_subscribers,
                #[cfg(feature = "declare-queryable")]
                remote_queryables: &peers.remote_queryables,
                #[cfg(feature = "liveliness-subscriber")]
                tokens: &peers.tokens,
                replies: &requesters.replies,
                #[cfg(feature = "liveliness-get")]
                liveliness_gets: &requesters.liveliness_gets,
            },
        )
    }

    /// New observer with empty tables, held to the build's limits. Callers register through the
    /// observer's halves ([`Self::with_app`], [`Self::subscribe`], [`Self::face`]) before driving
    /// the session loop; a registration a table's quota refuses comes back as
    /// [`RegisterError`](crate::registry_error::RegisterError).
    pub fn new() -> Self {
        Self {
            app: SlotObserver::new(),
            peers: PeerTables::new(),
            requesters: Requesters::new(),
            querier_max_pending_queries: crate::limit_binding::Limited::build_default(),
            #[cfg(all(
                feature = "alloc",
                feature = "query-queryable",
                feature = "declare-queryable",
                any(feature = "liveliness-token", feature = "declare-subscriber"),
                feature = "interest-answer"
            ))]
            pending_queryable_replies: alloc::vec::Vec::new(),
            #[cfg(feature = "declarations-synced-event")]
            declarations_final: crate::decl_sink::SyncedSinks::new(),
        }
    }

    /// Stage the interest-response chain a peer's QUERYABLE `Interest` is owed.
    ///
    /// Only a CURRENT interest solicits a dump, only a queryables interest (the
    /// `Q` bit) is answered here, and a keyexpr naming an undeclared peer mapping
    /// drops silently, as every sibling registry drops one: answering a partial
    /// key is worse than not answering. A FINAL (neither bit set) cancels an
    /// interest and owes nothing, because nothing about a CURRENT answer is
    /// retained.
    #[cfg(all(
        feature = "alloc",
        feature = "query-queryable",
        feature = "declare-queryable",
        any(feature = "liveliness-token", feature = "declare-subscriber"),
        feature = "interest-answer"
    ))]
    fn stage_queryable_interest(
        queryables: &QueryableRegistry<crate::query_sink::BoxedQuerySink>,
        staged: &mut alloc::vec::Vec<crate::query::QueryableInterestReply>,
        interest: &crate::transport_profile::owned::InterestOwned,
        peer_table: crate::wireexpr_resolve::MappingSpaces<'_>,
    ) {
        if !interest.c() {
            return;
        }
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            return;
        };
        if !body.qu() {
            return;
        }
        let pattern = match &body.keyexpr {
            Some(w) => match crate::wireexpr_resolve::resolve_wireexpr_in(&w.body, peer_table) {
                Some(p) => Some(p),
                None => return,
            },
            None => None,
        };
        queryables.respond_to_queryable_interest(
            interest.interest_id,
            pattern.as_deref(),
            body.ag(),
            staged,
        );
    }

    /// [`Self::stage_queryable_interest`] for an `Interest` lent where its frame lies: the same
    /// reading of it (only a CURRENT queryables interest is answered, a key naming an undeclared
    /// mapping drops), its key resolved by the rule both forms share
    /// ([`crate::wireexpr_resolve::resolve_wireexpr_view`]).
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "query-queryable",
        feature = "declare-queryable",
        any(feature = "liveliness-token", feature = "declare-subscriber"),
        feature = "interest-answer"
    ))]
    fn stage_queryable_interest_view(
        queryables: &QueryableRegistry<crate::query_sink::BoxedQuerySink>,
        staged: &mut alloc::vec::Vec<crate::query::QueryableInterestReply>,
        interest: &wz_codecs::lent::Interest<'_>,
        peer_table: crate::wireexpr_resolve::MappingSpaces<'_>,
    ) {
        if !interest.c() {
            return;
        }
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            return;
        };
        if !body.qu() {
            return;
        }
        let mut composed = crate::wireexpr_resolve::KeyexprBuf::new();
        let pattern = match &body.keyexpr {
            Some(w) => match crate::wireexpr_resolve::resolve_wireexpr_view(
                &w.body,
                peer_table,
                &mut composed,
            ) {
                Ok(Some(p)) => Some(p),
                // Undeclared, or past what the bounded buffer holds: no held queryable's key
                // is longer, so neither reaches one.
                Ok(None) | Err(_) => return,
            },
            None => None,
        };
        queryables.respond_to_queryable_interest(interest.interest_id, pattern, body.ag(), staged);
    }

    /// How many inbound liveliness-token Interests had their reply chain
    /// refused whole by the staging buffer since this observer was built.
    /// Always zero on the growable backing, where staging never refuses.
    #[cfg(feature = "liveliness-token")]
    pub fn token_interest_chains_refused(&self) -> u32 {
        self.peers.token_interest_chains_refused
    }

    /// State the `query-unanswerable-final` value of the session about to be dispatched, from
    /// the snapshot that session holds. An observer may serve more than one session (a unicast
    /// session and the group it also joins), so the session says it before every dispatch, into
    /// the observer's one face ([`crate::query::QueryPeer::set_unanswerable_final`]).
    pub fn set_unanswerable_final(&mut self, value: crate::policy::QueryUnanswerableFinal) {
        self.peers.queries.set_unanswerable_final(value);
    }

    /// Phase 1 — fan an [`IterationEvent`] into every table, through the slot observer's fan
    /// ([`SlotObserverOf::dispatch_event`](crate::slot_observer::SlotObserverOf::dispatch_event)) over this session's peer tables and requesters: the
    /// subscriber side first, so a `DeclKexpr` binds before the planes that resolve through it.
    /// A peer's QUERYABLE Interest is then staged against the queryables this session holds.
    ///
    /// `event` is `Copy`; the same reference fans into each table at zero cost.
    pub fn dispatch_event(&mut self, event: IterationEvent<'_, '_>) {
        self.app
            .dispatch_event(&mut (), &mut self.peers, &mut self.requesters, event);
        // A peer's QUERYABLE Interest is answered from the queryables this
        // session holds (see `QueryableRegistry::respond_to_queryable_interest`).
        // Staged here and drained with the other interest-response chains, so no
        // sink runs under the observer lock.
        #[cfg(all(
            feature = "alloc",
            feature = "query-queryable",
            feature = "declare-queryable",
            any(feature = "liveliness-token", feature = "declare-subscriber"),
            feature = "interest-answer"
        ))]
        if let IterationEvent::Poll(crate::driver_loop::DriverLoopOutcome::FramePayload {
            messages,
            ..
        }) = event
        {
            for message in crate::driver_loop::owned_records(messages).unwrap_or_default() {
                if let crate::network_message::NetworkMessage::Interest(interest) = message {
                    Self::stage_queryable_interest(
                        &self.app.tables.queryables,
                        &mut self.pending_queryable_replies,
                        interest,
                        self.peers.subscribers.mapping_spaces(),
                    );
                }
            }
        }
        // The same Interest lent where its frame lies, on a build that lends control records.
        #[cfg(all(
            feature = "rx-lent-control",
            feature = "query-queryable",
            feature = "declare-queryable",
            any(feature = "liveliness-token", feature = "declare-subscriber"),
            feature = "interest-answer"
        ))]
        if let IterationEvent::InPlace(record) = event {
            if let Some(interest) = record.interest() {
                Self::stage_queryable_interest_view(
                    &self.app.tables.queryables,
                    &mut self.pending_queryable_replies,
                    interest,
                    self.peers.subscribers.mapping_spaces(),
                );
            }
        }
    }

    /// R311y521 — the LINK-LOSS hook: flush every remote liveliness token,
    /// delivering a `Delete` to each matching subscriber. Returns the count.
    ///
    /// zenoh-pico fires this from `_zp_unicast_failed_result` the instant a
    /// unicast transport fails (`src/transport/unicast/lease.c:74-78` into
    /// `src/session/liveliness.c:99-120`). It is NOT part of the ordinary
    /// dispatch fan above: no inbound message announces a dead link, so the
    /// supervisor that observed the loss has to say so.
    ///
    /// A no-op when `liveliness-subscriber` is compiled out — there is no
    /// registry to flush and no subscriber to tell.
    pub fn flush_liveliness_on_link_loss(&mut self) -> usize {
        self.app
            .flush_liveliness_on_link_loss(&mut (), &mut self.peers)
    }

    /// R311y799 — the DECLARATION plane's twin of
    /// [`Self::flush_liveliness_on_link_loss`]: the peer's link died, so
    /// every subscriber and queryable it had declared is gone. Drops both
    /// membership tables and re-evaluates the matching watches against what
    /// remains — which on a session with no local declarations is nothing,
    /// so a publisher or querier that was matching flips back to `false`.
    /// Returns the total number of declarations dropped.
    ///
    /// WITHOUT THIS the tables outlive the link. The observer survives a
    /// reconnect by design (it is built over the shared
    /// `SessionLinkActions`, and `ReconnectingSession` replaces only the
    /// link), so a peer's declarations stayed in `declared` across the loss,
    /// kept every matching verdict `true`, and were never overwritten
    /// because the peer re-declares with FRESH ids after the re-handshake.
    /// R311y521 built exactly this for the token plane and the declaration
    /// plane was left behind; pico purges both from one sweep
    /// (`vendor/zenoh-pico/src/net/filtering.c:217-220`).
    ///
    /// Each plane's local half is passed in from its sibling field under a
    /// disjoint borrow, the same shape the inbound fan uses — a watch held
    /// `true` by a LOCAL subscriber or queryable must not be flipped by a
    /// remote link dying.
    pub fn flush_declarations_on_link_loss(&mut self) -> usize {
        self.app.flush_declarations_on_link_loss(&mut self.peers)
    }

    /// R311gi gc-2c — fan an [`IterationEvent`] into the statechart
    /// switchboard, injecting the mapped SCXML domain event through
    /// `injector` for each inbound `FramePayload` Push whose resolved
    /// keyexpr matches a registered row. Returns the number of events
    /// injected.
    ///
    /// Kept SEPARATE from [`dispatch_event`](Self::dispatch_event): the
    /// data-callback / declare consumers are injector-free, whereas
    /// statechart injection threads the engine ingress port — the gc-2a
    /// separation of the two inbound adapters, preserved at the fan-out
    /// layer. The production driver closure calls this AFTER
    /// [`dispatch`](Self::dispatch) so the switchboard resolves keyexprs
    /// against the peer mapping table the `subscribers` registry just
    /// refreshed on this same iteration (the single
    /// `peer_keyexpr_table` SSOT, never a second copy).
    #[cfg(feature = "switchboard")]
    pub fn dispatch_switchboard(
        &self,
        event: IterationEvent<'_, '_>,
        injector: &mut dyn EventInjector,
    ) -> usize {
        self.app.dispatch_switchboard(&self.peers, event, injector)
    }

    /// Phase 2 — drain the pending reply / final buffers through the
    /// action layer. `send_response` and `send_response_final`
    /// enqueue synchronously onto the OutboundWriteDriver mpsc
    /// channel, so the wire order mirrors enqueue order: every
    /// Reply for rid R precedes the matching ResponseFinal for R.
    ///
    /// R311li — this combined form (replies AND finals under one call)
    /// remains the raw-registry / MCU direct-drive drain. The
    /// Session-tier dispatch SSOT instead calls
    /// [`Self::flush_pending_replies`] under the observer lock and
    /// emits the rids from [`Self::take_pending_final_rids`] AFTER the
    /// deferred-fire drain, so a deferred queryable handler's replies
    /// (emitted at the drain, outside the lock) still precede their
    /// ResponseFinal on the wire.
    ///
    /// R311lq — the `actions` bound is the union of the three observer
    /// drain-sink concerns ([`ResponseSink`] + [`DeclareReplySink`] +
    /// [`LivelinessGetPrune`]) because this full drain touches all three
    /// staged buffers. A consumer that drains only ONE concern (the
    /// multicast reply loop, query-replies only) calls the narrower
    /// [`Self::flush_query_replies`] instead and need only implement
    /// [`ResponseSink`]. Body is a pure composition of the per-concern
    /// drains — same emit order as before the R311lq segregation
    /// (replies, declarer interest-responses, get-prunes, then finals).
    pub fn flush_pending<S>(&mut self, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.flush_pending_replies(actions);
        self.drain_query_finals(actions);
    }

    /// R311li — drain every pending buffer EXCEPT the queryable
    /// ResponseFinal rids (replies, declarer interest-responses,
    /// terminated liveliness-get prunes). The Session-tier dispatch
    /// SSOT pairs this with [`Self::take_pending_final_rids`]; raw /
    /// MCU consumers keep the combined [`Self::flush_pending`].
    ///
    /// R311lq — a pure composition of the per-concern drains (the
    /// segregated `Self::drain_query_replies` /
    /// `Self::drain_declare_replies` / `Self::drain_get_prunes`),
    /// in the same stage order as before. The `actions` bound is the
    /// three-concern union because this aggregate touches all three
    /// staged buffers; a single-concern consumer drains its concern
    /// directly and is bounded on only that trait.
    pub fn flush_pending_replies<S>(&mut self, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.drain_query_replies(actions);
        #[cfg(all(
            feature = "interest-answer",
            any(feature = "declare-subscriber", feature = "liveliness-token")
        ))]
        self.drain_declare_replies(actions);
        self.drain_get_prunes(actions);
    }

    /// R311lq — drain the queryable reply CHAIN (data replies then their
    /// terminal `ResponseFinal` rids) through a [`ResponseSink`]. This is
    /// the query-reply concern in isolation: a consumer that drives a
    /// queryable but neither the liveliness-token nor liveliness-get
    /// planes (the multicast reply loop) drains exactly this and need only
    /// implement [`ResponseSink`]. Reply-before-Final ordering is
    /// self-contained here (data replies drain before the finals), so the
    /// invariant lives with the concern rather than spread across a fat
    /// drain.
    /// The staged query replies through `sink`, WITHOUT their finals: for a host that stages
    /// each owed final behind the deferred handler jobs that may still answer the same query
    /// ([`Self::take_pending_final_rids`]), as a session does, so no final overtakes a reply.
    pub fn flush_query_reply_bodies<S: ResponseSink>(&mut self, sink: &S) {
        self.drain_query_replies(sink);
    }

    pub fn flush_query_replies<S: ResponseSink>(&mut self, sink: &S) {
        self.drain_query_replies(sink);
        self.drain_query_finals(sink);
    }

    /// R311lr — drain the staged declarer-side liveliness interest-responses
    /// (`peers.pending_declares`) through a [`DeclareReplySink`]. The
    /// `DeclareReplySink` sibling of [`Self::flush_query_replies`]: a consumer
    /// that replies to inbound liveliness Interests but drives neither the
    /// query-reply nor the liveliness-get-prune planes (the multicast reply
    /// loop, which answers a peer's liveliness Interest over the group) drains
    /// exactly this and need only implement [`DeclareReplySink`] — not the
    /// `LivelinessGetPrune` concern, which is genuinely absent on the
    /// connectionless multicast transport (no reconnect cache to prune).
    /// Stage order (each interest-response batch's `Token`s precede its
    /// terminating `Final`) is owned by the underlying
    /// `Self::drain_declare_replies`. Exposed demand-driven: the per-concern
    /// drains stay private until a single-concern consumer needs one (the
    /// get-prune concern has no such consumer yet, so it stays bundled in
    /// [`Self::flush_pending`]). Not in a build that answers no Interest, which stages none.
    #[cfg(all(
        feature = "interest-answer",
        any(feature = "declare-subscriber", feature = "liveliness-token")
    ))]
    pub fn flush_declare_replies<S: DeclareReplySink>(&mut self, sink: &S) {
        self.drain_declare_replies(sink);
    }

    /// [`Self::flush_pending_replies`] for a host that sends after it lets go of this observer:
    /// the staged query replies move into `owed` whole, each declaration owed to a peer's
    /// interest is resolved against the registries, as the drain resolves it, and kept in `owed`,
    /// and the liveliness-get prunes, which put nothing on a link, run through `prunes` here. The
    /// host sends `owed` ([`OwedReplies::send`]) once it has let go of the observer, and before
    /// it takes again.
    ///
    /// A send may wait for room on its link, for as long as the link stays full, and whoever
    /// holds this observer meanwhile stops every thread that needs it, the drive thread first.
    pub fn take_owed_replies<P: LivelinessGetPrune>(&mut self, owed: &mut OwedReplies, prunes: &P) {
        self.take_owed_reply_bodies(owed);
        #[cfg(all(
            feature = "interest-answer",
            any(feature = "declare-subscriber", feature = "liveliness-token")
        ))]
        self.take_owed_declarations(owed);
        self.drain_get_prunes(prunes);
    }

    /// The staged query replies alone, into `owed`: [`Self::flush_query_reply_bodies`] for a host
    /// that sends after it lets go of this observer (see [`Self::take_owed_replies`]).
    pub fn take_owed_reply_bodies(&mut self, owed: &mut OwedReplies) {
        owed.take_replies_from(&mut self.peers.replies);
    }

    /// The declarations owed to peers' interests alone, resolved now and kept in `owed`:
    /// [`Self::flush_declare_replies`] for a host that sends after it lets go of this observer
    /// (see [`Self::take_owed_replies`]). Not in a build that answers no Interest.
    #[cfg(all(
        feature = "interest-answer",
        any(feature = "declare-subscriber", feature = "liveliness-token")
    ))]
    pub fn take_owed_declarations(&mut self, owed: &mut OwedReplies) {
        self.drain_declare_replies(&*owed);
    }

    /// R311lq — drain the staged queryable data replies (`peers.replies`)
    /// through `send_response`. Does NOT touch the terminal rids (see
    /// [`Self::drain_query_finals`]); the Session-tier path drains data
    /// replies under the lock and defers the finals past the deferred-fire
    /// drain, so the two halves are separate primitives.
    fn drain_query_replies<S: ResponseSink>(&mut self, sink: &S) {
        self.app.drain_query_replies(&mut self.peers, sink);
    }

    /// R311lq — drain the staged queryable ResponseFinal rids
    /// (`peers.finals`) through `send_response_final`. Pairs with
    /// [`Self::drain_query_replies`] to form the full reply chain; emitted
    /// last so every data Reply for rid R precedes the matching
    /// ResponseFinal for R.
    fn drain_query_finals<S: ResponseSink>(&mut self, sink: &S) {
        self.app.drain_query_finals(&mut self.peers, sink);
    }

    /// R311lq — drain the declarer-side interest-response staging buffer
    /// (`peers.pending_declares`) through a [`DeclareReplySink`].
    ///
    /// R283 / R311hn — every staged `DeclResponseItem` is emitted in stage
    /// order, so each interest-response batch's `Token`s precede its
    /// terminating `Final`. The sink owns the encode (a `VecSink` on AP, a
    /// `SliceSink` on MCU) — no owned `DeclareOwned` crosses the seam.
    #[cfg(all(
        feature = "interest-answer",
        any(feature = "declare-subscriber", feature = "liveliness-token")
    ))]
    fn drain_declare_replies<S: DeclareReplySink>(&mut self, sink: &S) {
        self.app.drain_declare_replies(&mut self.peers, sink);
        // The QUERYABLE interest-response chains, in stage order: each chain's
        // `Declared` items precede its `Final`.
        #[cfg(all(
            feature = "alloc",
            feature = "query-queryable",
            feature = "declare-queryable",
            any(feature = "liveliness-token", feature = "declare-subscriber"),
            feature = "interest-answer"
        ))]
        for item in core::mem::take(&mut self.pending_queryable_replies) {
            match item {
                crate::query::QueryableInterestReply::Declared {
                    interest_id,
                    queryable_id,
                    keyexpr,
                    complete,
                } => {
                    sink.send_declare_queryable_reply(queryable_id, &keyexpr, complete, interest_id)
                }
                crate::query::QueryableInterestReply::Final { interest_id } => {
                    sink.send_declare_final_reply(interest_id)
                }
            }
        }
    }

    /// R311lq — drain the terminated-get staging (inbound DeclFinal +
    /// timeout sweeps) through a [`LivelinessGetPrune`]: a finished
    /// one-shot get must not replay its CURRENT Interest on the next
    /// reconnect. The sink no-ops when `session-reconnect` is off, so the
    /// drain is unconditional within the gate.
    fn drain_get_prunes<S: LivelinessGetPrune>(&mut self, sink: &S) {
        self.app.drain_get_prunes(&mut self.requesters, sink);
    }

    /// R311li — take the staged queryable ResponseFinal rids out of the
    /// observer. The Session-tier dispatch SSOT calls this under the
    /// observer lock (after [`Self::flush_pending_replies`]) and emits
    /// each rid through the actions layer AFTER the deferred-fire drain
    /// — the Reply-before-Final invariant owner on the deferred path
    /// (the combined [`Self::flush_pending`] owns it on the inline /
    /// MCU path).
    ///
    /// R311y336 — signature-stable, no `query-queryable` gate. The gate this
    /// carried was gratuitous: `peers.finals` is an UNCONDITIONAL field
    /// (R311r made the staging buffers ungated precisely so the observer's
    /// shape is stable across consumer-feature subsets), so the body compiles
    /// in every subset and only the POPULATE side is gated. Without
    /// `query-queryable` nothing ever stages a rid, so this honestly returns an
    /// empty `Vec` — the same OFF projection its sibling drains
    /// (`Self::drain_query_replies` / `Self::drain_query_finals`) already
    /// document, and the shape a `pub` accessor owes its callers.
    ///
    /// The table left behind keeps the quota [`Self::with_limits`] stated and the count of
    /// what it refused ([`FinalStage::take_owed`]).
    pub fn take_pending_final_rids(&mut self) -> FinalStage {
        self.peers.finals.take_owed()
    }

    /// What the staged-reply table has refused since this observer was built, by
    /// why: past its capacity on the fixed backing, and past the quota
    /// [`Self::with_limits`] stated on either. All zero on the growable backing with no
    /// quota stated, which refuses nothing.
    pub fn reply_refusals(&self) -> crate::reply_stage::ReplyRefusals {
        self.peers.replies.refusals()
    }

    /// How many requests were refused because no `Final` could be owed for them
    /// (`MAX_PENDING_FINALS` held, by the capacity on the fixed backing or by the
    /// quota [`Self::with_limits`] stated on either). All zero on the growable backing
    /// with no quota stated, which refuses nothing.
    pub fn request_refusals(&self) -> u32 {
        self.peers.finals.refusals()
    }

    /// Combined fan + drain — the production single-call form used
    /// inside the `drive_session_until_terminal` observer closure.
    /// Equivalent to `dispatch_event(event)` followed by
    /// `flush_pending(actions)`.
    pub fn dispatch<S>(&mut self, event: IterationEvent<'_, '_>, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.dispatch_event(event);
        self.flush_pending(actions);
    }

    /// Number of replies currently staged for the next `flush_pending`
    /// call. Exposed for diagnostic surfaces and unit tests; not
    /// expected to drive production logic (the production drain
    /// path runs every iteration so this is normally zero between
    /// dispatches).
    ///
    /// R311r — type-ungated alongside the underlying buffer.
    pub fn pending_reply_count(&self) -> usize {
        self.peers.replies.len()
    }

    /// Number of `ResponseFinal` rids currently staged for the next
    /// `flush_pending` call. Same diagnostic / test-only role as
    /// [`Self::pending_reply_count`].
    ///
    /// R311r — type-ungated alongside the underlying buffer.
    pub fn pending_final_count(&self) -> usize {
        self.peers.finals.len()
    }
}

#[cfg(all(test, feature = "codec-push"))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // ── Unconditional tests ──────────────────────────────────────────
    // Exercise the always-compiled observer surface (the subscriber +
    // replies registries) and need no consumer feature. Per-domain slot
    // assertions gate on the feature that owns the slot.

    // R307 / R311dz — assertions over each per-domain slot gate on the
    // feature that owns that slot; the subscriber + replies assertions
    // stay unconditional (always-compiled registries) so a minimal
    // build still exercises the always-on portion of the constructor.
    #[test]
    fn new_observer_starts_empty() {
        let observer = ApplicationLayerObserver::new();
        assert_eq!(observer.app.tables.subscribers.len(), 0);
        #[cfg(feature = "query-queryable")]
        assert_eq!(observer.app.tables.queryables.len(), 0);
        #[cfg(feature = "declare-subscriber")]
        assert_eq!(observer.app.remote_subscribers.on_decl_len(), 0);
        #[cfg(feature = "declare-queryable")]
        assert_eq!(observer.app.remote_queryables.on_decl_len(), 0);
        #[cfg(feature = "liveliness-token")]
        assert_eq!(observer.app.liveliness.on_decl_len(), 0);
        assert_eq!(observer.requesters.replies.len(), 0);
        #[cfg(feature = "query-queryable")]
        assert_eq!(observer.pending_reply_count(), 0);
        #[cfg(feature = "query-queryable")]
        assert_eq!(observer.pending_final_count(), 0);
    }

    #[test]
    fn dispatch_event_lease_variant_is_silent_noop() {
        let mut observer = ApplicationLayerObserver::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        observer
            .subscribe("anything", move |_p| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let event = IterationEvent::Lease(crate::lease::LeaseCheckOutcome::WithinLease);
        observer.dispatch_event(event);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    // ── Shared fixtures ──────────────────────────────────────────────
    // R311gk CLEANUP-1 — the consumer dispatch tests below live in
    // per-consumer `#[cfg]` sub-modules so each test's gate is its own
    // single consumer feature. Fixtures shared by more than one consumer
    // live here, each in a sub-module whose gate (the genuine consumer
    // union) is written exactly ONCE as the module gate — replacing the
    // prior per-item `cfg(any(...))` unions hand-copied across every
    // shared import.

    // `make_outcome` wraps a message batch in a FramePayload outcome; it
    // is used by every consumer dispatch test (push / decl-subscriber /
    // cross-talk / query). Its gate is the union of those consumers'
    // features — `switchboard` (⇒ codec-push, no consumer) is the first
    // combo that compiles this module with none of them on.
    #[cfg(any(
        feature = "pubsub-put",
        feature = "declare-subscriber",
        feature = "query-queryable",
        feature = "liveliness-get"
    ))]
    mod fixtures {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::network_message::NetworkMessage;
        use alloc::vec::Vec;

        // Fixtures build the borrowed codec views (borrowing the `&str`
        // / `&[u8]` params) then `.into_owned()` at the boundary — the
        // `NetworkMessage` carriers store the lifetime-free `*Owned`
        // mirrors.
        pub(super) fn make_outcome(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
            DriverLoopOutcome::FramePayload {
                priority: crate::qos::Priority::DEFAULT,
                reliable: true,
                sn: 0,
                messages,
                has_ext: false,
                extensions: Vec::new(),
            }
        }
    }

    // `push_literal` builds an owned Push carrying an inline keyexpr
    // suffix + payload. Used by the pubsub-put dispatch test AND the
    // cross-talk test (which drives all peer-declare arms), so its gate
    // is exactly that two-consumer union.
    #[cfg(any(
        feature = "pubsub-put",
        all(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token"
        )
    ))]
    mod push_fixtures {
        use crate::wire::PushOwned;
        use wz_codecs::lent::{Push, Wireexpr, WireexprNonlocal, WireexprVariant};

        pub(super) fn push_literal(suffix: &str, payload: &[u8]) -> PushOwned {
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(wz_codecs::Bounded::new(suffix).unwrap()),
                }),
            };
            let mut push = Push {
                keyexpr,
                ..Push::default()
            };
            // Set the inner MsgPut body's payload to the test bytes, inline.
            if let wz_codecs::lent::PushVariant::CodecZenohMsgPut(ref mut put) = push.body {
                put.payload_len = Some(payload.len() as u64);
                put.extensions_has_0x12 = wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 {
                    extensions: None,
                    payload: wz_codecs::Bounded::new(payload).unwrap(),
                };
            }
            push.try_into_owned_in::<crate::wire::WireStorage>()
                .unwrap()
        }
    }

    // `declare_decl_subscriber` builds an owned peer DeclSubscriber
    // record. Used by the declare-subscriber dispatch test AND the
    // cross-talk test; both require `declare-subscriber`, so that single
    // feature is the gate.
    #[cfg(feature = "declare-subscriber")]
    mod decl_fixtures {
        use crate::transport_profile::owned::DeclareOwned;
        use wz_codecs::lent::{
            DeclSubscriber, Declare, DeclareVariant, Wireexpr, WireexprNonlocal, WireexprVariant,
        };

        pub(super) fn declare_decl_subscriber(id: u64, suffix: &str) -> DeclareOwned {
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(wz_codecs::Bounded::new(suffix).unwrap()),
                }),
            };
            let decl = DeclSubscriber {
                id,
                keyexpr,
                ..DeclSubscriber::default()
            };
            Declare {
                body: DeclareVariant::CodecZenohDeclSubscriber(decl),
                ..Declare::default()
            }
            .try_into_owned_in::<crate::transport_profile::TransportStorage>()
            .unwrap()
        }
    }

    // ── Per-consumer dispatch tests ──────────────────────────────────

    // Asserts the subscriber callback FIRES, which is the `pubsub-put`
    // projection arm (dispatch_push fires only under any(pubsub-put,
    // pubsub-delete)). The enclosing module gates on `codec-push` for
    // the `NetworkMessage::Push` type; firing additionally needs the
    // data plane. R311gi exposed this: `switchboard = ["codec-push"]` is
    // the first combo with codec-push ON but pubsub-put OFF.
    #[cfg(feature = "pubsub-put")]
    mod pubsub_put {
        use super::super::ApplicationLayerObserver;
        use super::fixtures::make_outcome;
        use super::push_fixtures::push_literal;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[test]
        fn dispatch_event_routes_push_to_subscriber_registry() {
            let mut observer = ApplicationLayerObserver::new();
            let fired = Arc::new(AtomicUsize::new(0));
            let fired_cb = fired.clone();
            observer
                .subscribe("home/temp", move |_push| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");

            let outcome = make_outcome(vec![NetworkMessage::Push(Box::new(push_literal(
                "home/temp",
                b"21.0",
            )))]);
            crate::driver_loop::deliver_frame(&outcome, |event| observer.dispatch_event(event));
            assert_eq!(fired.load(Ordering::SeqCst), 1);
        }
    }

    // R311dz — references `observer.remote_subscribers`
    // (declare-subscriber slot) + the DeclSubscriber fixture, so gate on
    // `declare-subscriber` rather than relying on the workspace default.
    #[cfg(feature = "declare-subscriber")]
    mod declare_subscriber {
        use super::super::ApplicationLayerObserver;
        use super::decl_fixtures::declare_decl_subscriber;
        use super::fixtures::make_outcome;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[test]
        fn dispatch_event_routes_decl_subscriber_to_remote_subscriber_registry() {
            let mut observer = ApplicationLayerObserver::new();
            let fired = Arc::new(AtomicUsize::new(0));
            let fired_cb = fired.clone();
            observer
                .app
                .remote_subscribers
                .on_subscriber_declared(move |decl| {
                    assert_eq!(decl.id(), 7);
                    assert_eq!(decl.keyexpr(), "peer/sensor");
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");

            let outcome = make_outcome(vec![NetworkMessage::Declare(Box::new(
                declare_decl_subscriber(7, "peer/sensor"),
            ))]);
            crate::driver_loop::deliver_frame(&outcome, |event| observer.dispatch_event(event));
            assert_eq!(fired.load(Ordering::SeqCst), 1);
        }
    }

    // R311dz — exercises subscribers + remote_subscribers +
    // remote_queryables + liveliness, so gate on the conjunction of the
    // three peer-declare features it touches (the original
    // `liveliness-token`-only gate implicitly relied on the workspace
    // default having declare-subscriber / declare-queryable on too).
    #[cfg(all(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-token"
    ))]
    mod cross_talk {
        use super::super::ApplicationLayerObserver;
        use super::decl_fixtures::declare_decl_subscriber;
        use super::fixtures::make_outcome;
        use super::push_fixtures::push_literal;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_codecs::lent::{
            Declare, DeclareVariant, Wireexpr, WireexprNonlocal, WireexprVariant,
        };

        #[test]
        fn dispatch_event_routes_event_into_all_consumer_registries_without_cross_talk() {
            // Each registry sees only the arm it is wired for; the
            // single dispatch call fans the same IterationEvent into all
            // five consumer registries (+ subscribers absorbing
            // DeclKexpr / Push) without any cross-talk.
            let mut observer = ApplicationLayerObserver::new();
            let sub_fired = Arc::new(AtomicUsize::new(0));
            let r_sub_fired = Arc::new(AtomicUsize::new(0));
            let r_q_fired = Arc::new(AtomicUsize::new(0));
            let l_fired = Arc::new(AtomicUsize::new(0));

            let s = sub_fired.clone();
            observer
                .subscribe("a", move |_p| {
                    s.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
            let rs = r_sub_fired.clone();
            observer
                .app
                .remote_subscribers
                .on_subscriber_declared(move |_d| {
                    rs.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
            let rq = r_q_fired.clone();
            observer
                .app
                .remote_queryables
                .on_queryable_declared(move |_d| {
                    rq.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
            let l = l_fired.clone();
            observer
                .app
                .liveliness
                .on_token_declared(move |_d| {
                    l.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");

            // Frame carrying a Push + 3 different Declare arms.
            let outcome = make_outcome(vec![
                NetworkMessage::Push(Box::new(push_literal("a", b"v"))),
                NetworkMessage::Declare(Box::new(declare_decl_subscriber(1, "x"))),
                NetworkMessage::Declare(Box::new({
                    let keyexpr = Wireexpr {
                        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                            id: 0,
                            suffix_len: Some(1),
                            suffix: Some(wz_codecs::Bounded::new("y").unwrap()),
                        }),
                    };
                    Declare {
                        body: DeclareVariant::CodecZenohDeclQueryable(
                            wz_codecs::lent::DeclQueryable {
                                id: 2,
                                keyexpr,
                                ..wz_codecs::lent::DeclQueryable::default()
                            },
                        ),
                        ..Declare::default()
                    }
                    .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                    .unwrap()
                })),
                NetworkMessage::Declare(Box::new({
                    let keyexpr = Wireexpr {
                        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                            id: 0,
                            suffix_len: Some(1),
                            suffix: Some(wz_codecs::Bounded::new("z").unwrap()),
                        }),
                    };
                    Declare {
                        body: DeclareVariant::CodecZenohDeclToken(wz_codecs::lent::DeclToken {
                            id: 3,
                            keyexpr,
                            ..wz_codecs::lent::DeclToken::default()
                        }),
                        ..Declare::default()
                    }
                    .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                    .unwrap()
                })),
            ]);
            crate::driver_loop::deliver_frame(&outcome, |event| observer.dispatch_event(event));

            assert_eq!(sub_fired.load(Ordering::SeqCst), 1);
            assert_eq!(r_sub_fired.load(Ordering::SeqCst), 1);
            assert_eq!(r_q_fired.load(Ordering::SeqCst), 1);
            assert_eq!(l_fired.load(Ordering::SeqCst), 1);
        }

        /// R311y742 (N51) — the own-space witness AT THE FAN, not per registry.
        ///
        /// R311y740 measured every plane individually: given the pair, each one
        /// reads the space the `M` bit names. What no per-registry test can see
        /// is the EDGE — that `dispatch_event` actually hands the pair over
        /// rather than the bare peer table. The type forces the parameter, but
        /// a fan that passed `MappingSpaces::peer_only(&self.peer_table)` would
        /// type-check perfectly and silently restore the R311y739 defect on
        /// every plane at once.
        ///
        /// So this drives ONE `IterationEvent` carrying four planes' messages,
        /// each naming id 7 with `M=0`, and requires all four to resolve OUR
        /// literal. THE DISCRIMINATOR is the collision: the peer has declared
        /// id 7 as `theirs/x` in the same registry, so a fan that handed over
        /// the peer table alone would resolve a confident WRONG keyexpr on all
        /// four rather than dropping them.
        #[test]
        fn an_own_space_alias_resolves_through_the_fan_on_every_plane() {
            use alloc::string::ToString;
            use hashbrown::HashMap;
            use std::sync::Mutex;
            use wz_session_core_test_support::{decl_kexpr, declare_envelope_decl_kexpr};

            let mut observer = ApplicationLayerObserver::new();

            // OUR space: id 7 -> `ours/x`.
            let mut own: HashMap<crate::wire_id::ExprId, alloc::string::String> = HashMap::new();
            own.insert(7, "ours/x".to_string());
            observer
                .peers
                .subscribers
                .set_own_mapping_space(std::sync::Arc::new(own));

            // THE PEER's space: the same id 7, a different literal. Absorbed
            // through the ordinary inbound DeclKexpr path, not injected.
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_kexpr(decl_kexpr(7, "theirs/x")),
                ))]),
                |event| observer.dispatch_event(event),
            );

            let ours_fired = Arc::new(AtomicUsize::new(0));
            let theirs_fired = Arc::new(AtomicUsize::new(0));
            let o = ours_fired.clone();
            observer
                .subscribe("ours/x", move |_p| {
                    o.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
            let t = theirs_fired.clone();
            observer
                .subscribe("theirs/x", move |_p| {
                    t.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");

            let seen: Arc<Mutex<alloc::vec::Vec<alloc::string::String>>> =
                Arc::new(Mutex::new(alloc::vec::Vec::new()));
            let s1 = seen.clone();
            observer
                .app
                .remote_subscribers
                .on_subscriber_declared(move |d| s1.lock().unwrap().push(d.keyexpr().to_string()))
                .expect("no quota is stated on this table");
            let s2 = seen.clone();
            observer
                .app
                .remote_queryables
                .on_queryable_declared(move |d| s2.lock().unwrap().push(d.keyexpr().to_string()))
                .expect("no quota is stated on this table");
            let s3 = seen.clone();
            observer
                .app
                .liveliness
                .on_token_declared(move |d| s3.lock().unwrap().push(d.keyexpr().to_string()))
                .expect("no quota is stated on this table");

            crate::driver_loop::deliver_frame(
                &make_outcome(vec![
                    NetworkMessage::Push(Box::new(push_own_alias(7))),
                    NetworkMessage::Declare(Box::new(decl_subscriber_own_alias(1, 7))),
                    NetworkMessage::Declare(Box::new(decl_queryable_own_alias(2, 7))),
                    NetworkMessage::Declare(Box::new(decl_token_own_alias(3, 7))),
                ]),
                |event| observer.dispatch_event(event),
            );

            assert_eq!(
                ours_fired.load(Ordering::SeqCst),
                1,
                "the Push plane resolved id 7 in OUR space",
            );
            assert_eq!(
                theirs_fired.load(Ordering::SeqCst),
                0,
                "a fan handing over the peer table alone would have fired this one",
            );
            let seen = seen.lock().unwrap();
            assert_eq!(
                *seen,
                vec![
                    "ours/x".to_string(),
                    "ours/x".to_string(),
                    "ours/x".to_string()
                ],
                "declare-subscriber / declare-queryable / liveliness all resolved \
                 in OUR space through the fan",
            );
        }

        /// ANTI-VACUITY twin: the SAME frame with no own space installed
        /// resolves nothing on any of the four planes. Without this the test
        /// above would still pass if the peer table happened to be empty.
        #[test]
        fn without_an_own_space_the_fan_refuses_the_same_frame_on_every_plane() {
            use alloc::string::ToString;
            use std::sync::Mutex;
            use wz_session_core_test_support::{decl_kexpr, declare_envelope_decl_kexpr};

            let mut observer = ApplicationLayerObserver::new();
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_kexpr(decl_kexpr(7, "theirs/x")),
                ))]),
                |event| observer.dispatch_event(event),
            );

            let fired = Arc::new(AtomicUsize::new(0));
            let f = fired.clone();
            observer
                .subscribe("theirs/x", move |_p| {
                    f.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
            let seen: Arc<Mutex<alloc::vec::Vec<alloc::string::String>>> =
                Arc::new(Mutex::new(alloc::vec::Vec::new()));
            let s1 = seen.clone();
            observer
                .app
                .remote_subscribers
                .on_subscriber_declared(move |d| s1.lock().unwrap().push(d.keyexpr().to_string()))
                .expect("no quota is stated on this table");

            crate::driver_loop::deliver_frame(
                &make_outcome(vec![
                    NetworkMessage::Push(Box::new(push_own_alias(7))),
                    NetworkMessage::Declare(Box::new(decl_subscriber_own_alias(1, 7))),
                ]),
                |event| observer.dispatch_event(event),
            );

            assert_eq!(
                fired.load(Ordering::SeqCst),
                0,
                "an M=0 alias must refuse with no own space -- never fall back \
                 to the peer's table",
            );
            assert!(seen.lock().unwrap().is_empty());
        }

        // `M=0` (`Mapping::Receiver`) fixtures: the id names OUR space. Local
        // to this module because the cross-talk suite above deliberately uses
        // the id=0 LITERAL form, which consults no space at all.
        fn push_own_alias(mapping_id: crate::wire_id::ExprId) -> crate::wire::PushOwned {
            use wz_codecs::lent::Push;
            Push {
                keyexpr: Wireexpr {
                    body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                        id: mapping_id,
                        suffix_len: None,
                        suffix: None,
                    }),
                },
                ..Push::default()
            }
            .try_into_owned_in::<crate::wire::WireStorage>()
            .unwrap()
        }

        fn decl_subscriber_own_alias(
            id: u64,
            mapping_id: crate::wire_id::ExprId,
        ) -> crate::transport_profile::owned::DeclareOwned {
            wz_session_core_test_support::declare_envelope_decl_subscriber(
                wz_session_core_test_support::decl_subscriber_nonlocal(id, mapping_id, None),
            )
        }

        fn decl_queryable_own_alias(
            id: u64,
            mapping_id: crate::wire_id::ExprId,
        ) -> crate::transport_profile::owned::DeclareOwned {
            wz_session_core_test_support::declare_envelope_decl_queryable(
                wz_session_core_test_support::decl_queryable_nonlocal(id, mapping_id, None),
            )
        }

        fn decl_token_own_alias(
            id: u64,
            mapping_id: crate::wire_id::ExprId,
        ) -> crate::transport_profile::owned::DeclareOwned {
            wz_session_core_test_support::declare_envelope_decl_token(
                wz_session_core_test_support::decl_token_nonlocal(id, mapping_id, None),
            )
        }
    }

    #[cfg(feature = "query-queryable")]
    mod query_queryable {
        use super::super::ApplicationLayerObserver;
        use super::fixtures::make_outcome;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use wz_codecs::lent::{Wireexpr, WireexprNonlocal, WireexprVariant};

        #[test]
        fn flush_pending_clears_queryable_staged_buffers() {
            // Register a queryable that emits one Reply on match; absent
            // a real wire dispatch, we cannot call the action layer in a
            // unit test (no ResponseSink stand-in is wired here). What
            // we CAN verify is that dispatch_event populates the pending
            // bufs and subsequent dispatch (or explicit flush) drains
            // them. Here we simulate by hand: after dispatch_event,
            // pending_reply_count > 0; we then manually clear and confirm
            // the helper's accessor goes back to 0.
            let mut observer = ApplicationLayerObserver::new();
            observer
                .app
                .tables
                .queryables
                .register("home/temp", |_query, responder| {
                    responder.reply(b"21.0");
                })
                .expect("no quota is stated on this table");

            // Synthesize an inbound Query for "home/temp".
            use wz_codecs::lent::{Query, Request, RequestVariant};
            let suffix = "home/temp";
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(wz_codecs::Bounded::new(suffix).unwrap()),
                }),
            };
            let request = Request {
                rid: 42,
                keyexpr,
                body: RequestVariant::CodecZenohQuery(Query::default()),
                ..Request::default()
            }
            .try_into_owned_in::<crate::wire::WireStorage>()
            .unwrap();
            let outcome = make_outcome(vec![NetworkMessage::Request(Box::new(request))]);
            crate::driver_loop::deliver_frame(&outcome, |event| observer.dispatch_event(event));

            assert_eq!(
                observer.pending_reply_count(),
                1,
                "one matched query staged one Reply"
            );
            assert_eq!(
                observer.pending_final_count(),
                1,
                "matched query staged one Final"
            );

            // Bypass the ResponseSink drain (no test stand-in here) and
            // simulate the flush by clearing manually. Production code
            // calls flush_pending(&actions) which drains through the
            // outbound link; the integration tests cover that path
            // end-to-end. Here we exercise just the accessor lifecycle.
            observer.peers.replies.clear();
            observer.peers.finals.clear();
            assert_eq!(observer.pending_reply_count(), 0);
            assert_eq!(observer.pending_final_count(), 0);
        }
    }

    /// The SOLICITED-DECLARE routing rule: a `Declare(DeclToken)` whose outer
    /// `interest_id` names a pending liveliness GET belongs to that GET and to
    /// nothing else.
    ///
    /// zenoh states it as an early return — `if let Some(query) =
    /// state.liveliness_queries.get(&interest_id) { query.callback.call(reply);
    /// return; }` (`zenoh/src/api/session.rs:2609-2632`, the zenoh-1.5.0
    /// `49c8a53` tree) — placed BEFORE the `remote_tokens` insert and before
    /// `execute_subscriber_callbacks`. wz's observer fans one message into
    /// every registry in sequence, so the rule has to be expressed as a filter
    /// on the subscriber plane instead of as control flow.
    ///
    /// These three tests are one claim in three positions: the GET's reply is
    /// the requester's alone, the SUBSCRIBER's own solicited replies still
    /// arrive, and an unsolicited token still arrives. Only the middle one
    /// distinguishes "route by whether a pending GET owns this id" from the
    /// cruder "drop every solicited declare".
    #[cfg(all(
        feature = "liveliness-get",
        feature = "liveliness-subscriber",
        feature = "alloc"
    ))]
    mod solicited_declare_routing {
        use super::fixtures::make_outcome;
        use super::*;
        use crate::declare::liveliness_sample::BoxedLivelinessSampleSink;
        use crate::network_message::NetworkMessage;
        use alloc::boxed::Box;
        use alloc::vec;
        use wz_session_core_test_support::{
            decl_token_nonlocal, declare_envelope_decl_token,
            declare_envelope_decl_token_with_interest,
        };

        /// The subscriber's interest id. Distinct from the GET's on purpose:
        /// both planes mint from the same `alloc_next_interest_id` counter in
        /// production, so a rule that keyed on anything but "is this id a
        /// pending GET" would confuse them.
        const SUB_INTEREST: u64 = 1;
        /// The pending GET's interest id.
        const GET_INTEREST: u64 = 9;

        struct Fixture {
            observer: ApplicationLayerObserver,
            sub_fired: Arc<AtomicUsize>,
            get_fired: Arc<AtomicUsize>,
        }

        /// One liveliness subscriber on `k/**` and one pending GET, so every
        /// token below matches BOTH planes by keyexpr. The routing rule is the
        /// only thing that can tell them apart.
        ///
        /// The subscriber asks for HISTORY, and R2359 made that load-bearing
        /// rather than incidental. A declare tagged with the SUBSCRIBER's own
        /// interest id can only exist because that subscriber sent a CURRENT
        /// interest, and only a `history = true` declare sends one — so a
        /// future-only subscriber in this fixture would be a state the wire
        /// cannot produce, and the module's whole subject is declares carrying
        /// exactly that id. It read `false` until R2359 and nothing noticed,
        /// because until then the history flag changed no delivery.
        fn fixture() -> Fixture {
            fixture_with_history(true)
        }

        /// [`fixture`] with the subscriber's `history` flag under the test's
        /// control, for the one case that needs the other value.
        fn fixture_with_history(history: bool) -> Fixture {
            let mut observer = ApplicationLayerObserver::new();
            let sub_fired = Arc::new(AtomicUsize::new(0));
            let s = sub_fired.clone();
            observer
                .app
                .tables
                .liveliness_subscribers
                .register(
                    &observer.peers.tokens,
                    SUB_INTEREST,
                    "k/**",
                    history,
                    BoxedLivelinessSampleSink::new(move |_sample| {
                        s.fetch_add(1, Ordering::SeqCst);
                    }),
                )
                .expect("register the liveliness subscriber");
            let get_fired = Arc::new(AtomicUsize::new(0));
            let g = get_fired.clone();
            observer
                .requesters
                .liveliness_gets
                .register_get(
                    GET_INTEREST,
                    None,
                    move |_reply| {
                        g.fetch_add(1, Ordering::SeqCst);
                    },
                    |_id| {},
                )
                .expect("register the pending liveliness get");
            Fixture {
                observer,
                sub_fired,
                get_fired,
            }
        }

        /// `id: 0` with a suffix is a literal keyexpr — no peer mapping needed,
        /// so these tests measure the ROUTING and not a resolution accident.
        fn token(id: u64, keyexpr: &str) -> crate::transport_profile::owned::DeclTokenOwned {
            decl_token_nonlocal(id, 0, Some(keyexpr))
        }

        /// THE DEFECT. A GET's reply reaches the requester AND the liveliness
        /// subscribers, so an application that runs a snapshot while holding a
        /// subscription is told a token "came alive" at the instant of its own
        /// unrelated query. zenoh returns before the subscriber callbacks.
        #[test]
        fn a_get_reply_is_the_requesters_alone() {
            let mut f = fixture();
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_token_with_interest(token(5, "k/a"), GET_INTEREST),
                ))]),
                |event| f.observer.dispatch_event(event),
            );

            assert_eq!(
                f.get_fired.load(Ordering::SeqCst),
                1,
                "the snapshot's requester must receive its reply"
            );
            assert_eq!(
                f.sub_fired.load(Ordering::SeqCst),
                0,
                "and the liveliness subscriber must NOT: this token was solicited \
                 by a GET, not announced to the subscription"
            );
        }

        /// The paired positive that keeps the rule from being "drop every
        /// solicited declare": a history subscriber's OWN CURRENT replay is
        /// also interest_id-tagged, and it must arrive.
        #[test]
        fn a_subscribers_own_solicited_replay_still_arrives() {
            let mut f = fixture();
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_token_with_interest(token(6, "k/b"), SUB_INTEREST),
                ))]),
                |event| f.observer.dispatch_event(event),
            );

            assert_eq!(
                f.sub_fired.load(Ordering::SeqCst),
                1,
                "a solicited declare whose id is NOT a pending GET is the \
                 subscriber's replay"
            );
            assert_eq!(
                f.get_fired.load(Ordering::SeqCst),
                0,
                "and it is not an answer to the snapshot"
            );
        }

        /// The SECOND observer plane. `ApplicationLayerObserver::liveliness` is
        /// the un-filtered token observer — no keyexpr pattern, no table — and
        /// it fires on every inbound `DeclToken` the fan hands it. It needs its
        /// own witness rather than riding the subscriber tests: the two planes
        /// are separate registries reached by separate calls, and a fix applied
        /// to one is invisible to the other's tests.
        #[cfg(feature = "liveliness-token")]
        #[test]
        fn a_get_reply_does_not_reach_the_generic_token_observer() {
            use std::sync::Mutex;
            let mut f = fixture();
            let seen: Arc<Mutex<alloc::vec::Vec<alloc::string::String>>> =
                Arc::new(Mutex::new(alloc::vec::Vec::new()));
            let s = seen.clone();
            f.observer
                .app
                .liveliness
                .on_token_declared(move |d| {
                    use alloc::string::ToString;
                    s.lock().unwrap().push(d.keyexpr().to_string());
                })
                .expect("no quota is stated on this table");

            crate::driver_loop::deliver_frame(
                &make_outcome(vec![
                    // Claimed by the GET.
                    NetworkMessage::Declare(Box::new(declare_envelope_decl_token_with_interest(
                        token(5, "k/a"),
                        GET_INTEREST,
                    ))),
                    // Unsolicited — the control, in the SAME batch, so a fan
                    // that stopped dispatching altogether cannot pass.
                    NetworkMessage::Declare(Box::new(declare_envelope_decl_token(token(7, "k/c")))),
                ]),
                |event| f.observer.dispatch_event(event),
            );

            use alloc::string::ToString;
            assert_eq!(
                *seen.lock().unwrap(),
                vec!["k/c".to_string()],
                "the GET's answer is not a declaration to observe; the \
                 unsolicited one beside it still is"
            );
            assert_eq!(f.get_fired.load(Ordering::SeqCst), 1);
        }

        /// R2359 — the same routing question asked of a FUTURE-ONLY
        /// subscriber, at the observer plane rather than the registry's.
        /// It gets its own witness for the reason this module already records
        /// one line up: the planes are separate registries reached by separate
        /// calls, so the registry-level tests cannot speak for this one.
        ///
        /// The declare is tagged with an interest id that is NOT the pending
        /// GET's, so the claim filter lets it through — and it is still a
        /// CURRENT answer, which a `history = false` subscriber declined.
        /// Upstream: `zenoh/src/api/session.rs` @ `&& (!historical || sub.history)`.
        #[test]
        fn a_solicited_replay_does_not_reach_a_future_only_subscriber() {
            let mut f = fixture_with_history(false);
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_token_with_interest(token(6, "k/b"), SUB_INTEREST),
                ))]),
                |event| f.observer.dispatch_event(event),
            );

            assert_eq!(
                f.sub_fired.load(Ordering::SeqCst),
                0,
                "a future-only subscriber is not told about a token that \
                 existed before it declared, whoever solicited it"
            );
            assert_eq!(f.get_fired.load(Ordering::SeqCst), 0);
        }

        /// The unsolicited arm, unchanged: a peer declaring a token live with
        /// no interest_id at all is the subscription's ordinary traffic.
        #[test]
        fn an_unsolicited_token_still_reaches_the_subscriber() {
            let mut f = fixture();
            crate::driver_loop::deliver_frame(
                &make_outcome(vec![NetworkMessage::Declare(Box::new(
                    declare_envelope_decl_token(token(7, "k/c")),
                ))]),
                |event| f.observer.dispatch_event(event),
            );

            assert_eq!(f.sub_fired.load(Ordering::SeqCst), 1);
            assert_eq!(f.get_fired.load(Ordering::SeqCst), 0);
        }
    }
}

// R2290 (open-debt item 626) — the SUBSCRIBER interest-response chain's
// stage/drain window, exercised through `flush_declare_replies` (the door the
// session tier actually calls) rather than through the resolver alone.
//
// The staging and the drain are deliberately separated so no C callback runs
// under the observer lock, which means the application can undeclare a
// subscription BETWEEN them. What a reply announces therefore has to be true
// when it is SENT, and until this round the AGGREGATE arm checked only that
// the peer's INTEREST row still existed — a row an undeclare never touches.
#[cfg(all(
    test,
    feature = "declare-subscriber",
    feature = "interest-answer",
    feature = "alloc"
))]
mod sub_interest_reply_tests {
    use super::*;
    use crate::pubsub::SubInterestReply;
    use crate::response_sink::DeclareReplySink;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// The peer's interest id, echoed on every reply of its chain.
    const INTEREST: u64 = 7;

    /// Records what a drain actually emitted, so an assertion can name the
    /// wire message rather than a resolver's return value.
    #[derive(Default)]
    struct RecordingSink {
        subscriber_replies: Mutex<Vec<(u64, String, u64)>>,
        finals: Mutex<Vec<u64>>,
        /// R2292 (open-debt item 627) — the `UndeclSubscriber.id`s this drain
        /// emitted, in order.
        #[cfg(feature = "declare-undeclare")]
        subscriber_retracts: Mutex<Vec<u64>>,
    }

    impl DeclareReplySink for RecordingSink {
        #[cfg(feature = "liveliness-token")]
        fn send_declare_token_reply(&self, _token_id: u64, _keyexpr: &str, _interest_id: u64) {}

        fn send_declare_final_reply(&self, interest_id: u64) {
            self.finals.lock().unwrap().push(interest_id);
        }

        fn send_declare_subscriber_reply(
            &self,
            subscriber_id: u64,
            keyexpr: &str,
            interest_id: u64,
        ) {
            self.subscriber_replies.lock().unwrap().push((
                subscriber_id,
                keyexpr.to_string(),
                interest_id,
            ));
        }

        #[cfg(feature = "declare-undeclare")]
        fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
            self.subscriber_retracts.lock().unwrap().push(subscriber_id);
        }
    }

    /// One observer holding one subscription on `reenter/**`, with the peer's
    /// CURRENT+FUTURE interest already staged. `aggregate` picks which arm of
    /// [`SubInterestReply`] the chain stages.
    fn staged(aggregate: bool) -> (ApplicationLayerObserver, crate::pubsub::SubscriptionId) {
        let mut observer = ApplicationLayerObserver::new();
        let id = observer
            .subscribe("reenter/**", |_| {})
            .expect("no quota is stated on this table");
        let count = observer
            .app
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut observer.peers.subscribers,
                INTEREST,
                Some("reenter/**"),
                aggregate,
                /*current=*/ true,
                /*future=*/ true,
            );
        assert_eq!(
            count, 1,
            "a matching subscription must stage exactly one reply — a fixture \
             that stages none would make every assertion below vacuous"
        );
        (observer, id)
    }

    /// THE DEFECT: the subscription is undeclared inside the stage/drain
    /// window, so the reply must never reach the wire.
    ///
    /// Without the drain-time re-check the emitted `DeclSubscriber` lands
    /// AFTER the undeclare's `UndeclSubscriber` (the drain runs on the drive
    /// thread, the undeclare on the application's), so the peer re-inserts the
    /// entry it was just told to drop and its matching verdict flips back to
    /// `true` for the rest of the link's life.
    /// Open-debt item 913 — a member's subscriber interest, keyed by an alias the member
    /// declared in the SAME batch, is answered: the subscription that matches and the final.
    /// This is a zenoh-pico write filter's interest on a group (MEASURED off the wire:
    /// `decl_kexpr(1, demo/mc/cross)` then `Interest(3, [current,subscribers,restricted], 1:)`).
    #[cfg(feature = "codec-declare")]
    #[test]
    fn a_member_interest_on_its_own_alias_is_answered() {
        let mut observer = ApplicationLayerObserver::new();
        observer
            .subscribe("demo/mc/cross", |_| {})
            .expect("no quota is stated on this table");
        let kexpr = crate::declare_build::build_declare_kexpr(1, "demo/mc/cross")
            .expect("a literal key builds");
        let interest = crate::interest_build::build_interest_subscribers(3, true, false, 1, None)
            .expect("an alias builds");
        // In two frames, as the member sends them: the alias outlives the batch that declared it.
        let frame = |message| crate::driver_loop::DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: alloc::vec![message],
            has_ext: false,
            extensions: Vec::new(),
        };
        crate::driver_loop::deliver_frame(
            &frame(crate::network_message::NetworkMessage::Declare(
                alloc::boxed::Box::new(kexpr),
            )),
            |event| observer.dispatch_event(event),
        );
        crate::driver_loop::deliver_frame(
            &frame(crate::network_message::NetworkMessage::Interest(interest)),
            |event| observer.dispatch_event(event),
        );
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        assert_eq!(
            sink.subscriber_replies
                .lock()
                .unwrap()
                .iter()
                .map(|(_, key, interest)| (key.clone(), *interest))
                .collect::<Vec<_>>(),
            alloc::vec![("demo/mc/cross".to_string(), 3)],
            "the matching subscription is the answer"
        );
        assert_eq!(
            *sink.finals.lock().unwrap(),
            alloc::vec![3],
            "and the final ends it"
        );
    }

    #[test]
    fn an_aggregate_reply_is_not_emitted_once_its_subscription_is_undeclared() {
        let (mut observer, id) = staged(/*aggregate=*/ true);
        assert!(observer.unregister_subscriber(id));

        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);

        let replies = sink.subscriber_replies.lock().unwrap().clone();
        assert!(
            replies.is_empty(),
            "an aggregate reply survived the undeclare of the only subscription \
             it could have been announcing: {replies:?}"
        );
        assert_eq!(
            *sink.finals.lock().unwrap(),
            alloc::vec![INTEREST],
            "the chain's Final must still terminate the peer's solicitation"
        );
    }

    /// The CONTROL, and it is what stops the guard above from being satisfied
    /// by never emitting anything: with the subscription still held, the
    /// aggregate reply IS emitted, carrying the INTEREST's keyexpr (pico
    /// associates an aggregate interest's replies by `_z_keyexpr_equals`).
    #[test]
    fn an_aggregate_reply_is_emitted_while_its_subscription_lives() {
        let (mut observer, _id) = staged(/*aggregate=*/ true);

        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);

        let replies = sink.subscriber_replies.lock().unwrap().clone();
        assert_eq!(
            replies.len(),
            1,
            "a live subscription must still answer the peer's CURRENT interest"
        );
        assert_eq!(replies[0].1, "reenter/**".to_string());
        assert_eq!(replies[0].2, INTEREST);
    }

    /// The CONCRETE arm's twin of the two above — it already re-resolved
    /// through the subscription table, and stating it here is what makes the
    /// contract a property of the whole enum rather than of one arm.
    #[test]
    fn a_concrete_reply_is_not_emitted_once_its_subscription_is_undeclared() {
        let (mut observer, id) = staged(/*aggregate=*/ false);
        assert!(observer.unregister_subscriber(id));

        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);

        assert!(
            sink.subscriber_replies.lock().unwrap().is_empty(),
            "a concrete reply survived its own subscription's undeclare"
        );
    }

    /// The POPULATION is the enum, not a list somebody typed: every
    /// ANNOUNCING arm of [`SubInterestReply`] must resolve to `None` once what
    /// it announces is gone. The match is exhaustive, so a new arm cannot join
    /// this contract without a decision being recorded here — which is a
    /// compile-time obligation, not a claim that the new arm is exercised.
    ///
    /// The reached-arm count is asserted for the reason a zero population is
    /// always the trap: a fixture that staged nothing would satisfy every
    /// `is_none()` below by having nothing to check.
    #[test]
    fn every_announcing_reply_arm_drops_when_its_subject_is_gone() {
        let mut reached_aggregate = 0usize;
        let mut reached_concrete = 0usize;
        // R2292 (open-debt item 627) — the enum grew a RETRACTING arm, and
        // this is the decision the exhaustive match above demanded: it is not
        // in this test's population, and it must not be STAGED here either.
        // The fixture never drains, so no row is `announced`, so
        // `unregister` has nothing to retract — which is the same rule that
        // keeps the declare-rollback path silent.
        //
        // `mut` only where the arm that writes it exists: without
        // `declare-undeclare` the enum has no such variant, and an
        // unconditional `mut` is `-D unused-mut` in that subset.
        #[cfg(feature = "declare-undeclare")]
        let mut reached_retract = 0usize;
        #[cfg(not(feature = "declare-undeclare"))]
        let reached_retract = 0usize;

        for aggregate in [true, false] {
            let (mut observer, id) = staged(aggregate);
            assert!(observer.unregister_subscriber(id));

            let items = observer
                .peers
                .subscribers
                .take_staged_sub_interest_replies();
            for item in items.iter() {
                let resolved = observer
                    .peers
                    .subscribers
                    .sub_interest_reply(&observer.app.tables.subscribers, item);
                match item {
                    SubInterestReply::Aggregate { .. } => {
                        reached_aggregate += 1;
                        assert!(
                            resolved.is_none(),
                            "the aggregate arm announced a subscription that is gone"
                        );
                    }
                    SubInterestReply::Concrete { .. } => {
                        reached_concrete += 1;
                        assert!(
                            resolved.is_none(),
                            "the concrete arm announced a subscription that is gone"
                        );
                    }
                    // Not an announcing arm: it terminates the chain and
                    // carries no declaration, so it resolves to `None` always.
                    SubInterestReply::Final { .. } => {
                        assert!(resolved.is_none(), "a Final carries no declaration")
                    }
                    #[cfg(feature = "declare-undeclare")]
                    SubInterestReply::AggregateRetract { .. } => {
                        reached_retract += 1;
                        assert!(
                            resolved.is_none(),
                            "a retraction resolves through take_aggregate_retract, not here"
                        );
                    }
                }
            }
        }

        assert_eq!(
            (reached_aggregate, reached_concrete),
            (1, 1),
            "every announcing arm must have been reached — a population of zero \
             would report green without checking anything"
        );
        assert_eq!(
            reached_retract, 0,
            "an unannounced aggregate must stage NO retraction: nothing drained \
             here, so no peer was told an id, and retracting one would name an \
             id that was never sent"
        );
    }

    // ── R2292 (open-debt item 627) — an aggregate declaration's own
    //    retraction, and the one id space that makes it unambiguous ──

    /// R2292 — THE DEFECT. An aggregate `DeclSubscriber` stands for "some
    /// local subscription matches your interest". When the last such
    /// subscription goes away that sentence becomes false, and until this
    /// round nothing on wz took it back: the peer's `declared` map is keyed by
    /// id and is only ever cleared wholesale by
    /// `flush_declarations_on_link_loss`, so the entry survived as a GHOST
    /// remote subscriber for the rest of the link's life.
    ///
    /// zenoh emits exactly this transition. Its aggregated resource holds
    /// `info: Option<SubscriberInfo>` where `SubscriberInfo` is a UNIT struct,
    /// so `aggregate_many` yields `Some` iff at least one simple resource is
    /// aggregated into it; `remove_simple_resource` reports the AGGREGATE's own
    /// id when that flips to `None`
    /// (`zenoh/src/net/routing/dispatcher/local_resources.rs`
    /// @ `pub(crate) fn remove_simple_resource`), and
    /// `maybe_unpropagate_subscriber` turns every such report into an
    /// `UndeclareSubscriber { id }`
    /// (`zenoh/src/net/routing/hat/broker/pubsub.rs`
    /// @ `fn maybe_unpropagate_subscriber`, 1.10.0).
    #[cfg(feature = "declare-undeclare")]
    #[test]
    fn an_aggregate_declaration_is_retracted_when_its_last_subscription_goes() {
        let (mut observer, id) = staged(/*aggregate=*/ true);
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        let announced = sink.subscriber_replies.lock().unwrap().clone();
        assert_eq!(
            announced.len(),
            1,
            "the fixture must ANNOUNCE the aggregate first — a retraction test \
             whose declaration never reached the wire measures nothing"
        );
        let announced_id = announced[0].0;

        assert!(observer.unregister_subscriber(id));
        observer.flush_declare_replies(&sink);

        assert_eq!(
            *sink.subscriber_retracts.lock().unwrap(),
            alloc::vec![announced_id],
            "the aggregate declaration must be retracted with ITS OWN id once \
             the last subscription it stood for is gone — anything else leaves \
             a ghost remote subscriber on the peer until the link dies"
        );
    }

    /// R2292 — the DISCRIMINATOR, and the reason the rule is a TRANSITION
    /// rather than "an unregister happened": a second subscription still
    /// matches the interest, so the aggregate declaration is still TRUE and
    /// must stay standing.
    ///
    /// Reverting the drain-time `any_subscription_matches` re-check in
    /// `take_aggregate_retract` fails this while leaving the test above green.
    /// MEASURED, R2292 — and the STAGING-time twin of that predicate is NOT
    /// the guard: deleting it leaves this green, because the drain-time one
    /// still catches the item. That check is a pressure filter with its own
    /// red in `an_unrelated_unregister_stages_no_aggregate_retraction`.
    #[cfg(all(feature = "declare-undeclare", feature = "keyexpr-wildcard-double"))]
    #[test]
    fn an_aggregate_declaration_survives_while_another_subscription_matches() {
        let mut observer = ApplicationLayerObserver::new();
        let first = observer
            .subscribe("reenter/a", |_| {})
            .expect("no quota is stated on this table");
        let _second = observer
            .subscribe("reenter/b", |_| {})
            .expect("no quota is stated on this table");
        let staged_count = observer
            .app
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut observer.peers.subscribers,
                INTEREST,
                Some("reenter/**"),
                /*aggregate=*/ true,
                /*current=*/ true,
                /*future=*/ true,
            );
        assert_eq!(
            staged_count, 1,
            "an aggregate interest answers ONCE however many subscriptions match"
        );

        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        assert_eq!(
            sink.subscriber_replies.lock().unwrap().len(),
            1,
            "the aggregate must be announced before the retraction can be the \
             thing under test"
        );

        assert!(observer.unregister_subscriber(first));
        observer.flush_declare_replies(&sink);

        assert!(
            sink.subscriber_retracts.lock().unwrap().is_empty(),
            "`reenter/b` still matches `reenter/**`, so the aggregate \
             declaration is still true and retracting it would blind the peer's \
             write filter to a subscriber this session still holds: {:?}",
            sink.subscriber_retracts.lock().unwrap()
        );
    }

    /// R2292 — the STAGING-time filter's own red, and the reason it is a
    /// separate test from the wire ones above.
    ///
    /// `stage_emptied_aggregate_retracts` tests `any_subscription_matches`
    /// before pushing, and MEASURED that test is not what makes a retraction
    /// truthful — the drain re-checks the same predicate, so deleting the
    /// staging one leaves every wire assertion green. What it does buy is the
    /// staging buffer: `pending_sub_interest_replies` is a `BoundedVec`, and
    /// an unregister that empties no interest would otherwise push one item
    /// per announced aggregate into it for the drain to discard.
    ///
    /// So the claim is made where it is observable — on the staged items, not
    /// on the wire.
    #[cfg(feature = "declare-undeclare")]
    #[test]
    fn an_unrelated_unregister_stages_no_aggregate_retraction() {
        let mut observer = ApplicationLayerObserver::new();
        let unrelated = observer
            .subscribe("elsewhere/a", |_| {})
            .expect("no quota is stated on this table");
        let _matching = observer
            .subscribe("reenter/a", |_| {})
            .expect("no quota is stated on this table");
        observer
            .app
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut observer.peers.subscribers,
                INTEREST,
                Some("reenter/a"),
                /*aggregate=*/ true,
                /*current=*/ true,
                /*future=*/ true,
            );
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        assert_eq!(
            sink.subscriber_replies.lock().unwrap().len(),
            1,
            "the aggregate must be ANNOUNCED first — an unannounced row is \
             filtered by a different clause, so this test would then be \
             measuring the wrong one"
        );

        assert!(observer.unregister_subscriber(unrelated));

        assert!(
            observer
                .peers
                .subscribers
                .take_staged_sub_interest_replies()
                .is_empty(),
            "dropping a subscription that stands for no interest must stage \
             NOTHING: `reenter/a` still matches, so the aggregate is untouched, \
             and pushing an item the drain will discard only spends the bounded \
             staging buffer"
        );
    }

    /// R2292 — a NON-aggregate interest has no aggregate declaration to
    /// retract. Its replies carry each subscription's own id, and each is
    /// retracted by that subscription's own `UndeclSubscriber` on teardown, so
    /// staging one here would emit a second retraction for the same id.
    ///
    /// The population argument, not a spot check: `aggregate` is a `bool`, the
    /// test above drives `true` and this one drives `false`.
    #[cfg(feature = "declare-undeclare")]
    #[test]
    fn a_concrete_interest_stages_no_aggregate_retraction() {
        let (mut observer, id) = staged(/*aggregate=*/ false);
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        assert_eq!(
            sink.subscriber_replies.lock().unwrap().len(),
            1,
            "the concrete reply must have been announced, else this test's \
             `unregister` has nothing to react to"
        );

        assert!(observer.unregister_subscriber(id));
        observer.flush_declare_replies(&sink);

        assert!(
            sink.subscriber_retracts.lock().unwrap().is_empty(),
            "a concrete interest's replies are retracted by their own \
             subscriptions' teardown; an aggregate retraction here would be a \
             second `UndeclSubscriber` for an id already retracted"
        );
    }

    /// R2292 — item 627's HEAD SENTENCE: one session must never announce two
    /// different things under one `DeclSubscriber.id`.
    ///
    /// The aggregate decl id used to come from a second counter that also
    /// started at 1, so a session's first subscription and its first aggregate
    /// reply were both announced as id 1. The peer's registry is keyed by that
    /// id with same-id-replaces, so it saw ONE declaration where two were
    /// sent — and R2292's retraction makes that ambiguity harmful rather than
    /// merely wrong. Upstream draws both from one per-face counter
    /// (`zenoh/src/net/routing/hat/broker/interests.rs`
    /// @ `local_subs.insert_aggregated_resource`, 1.10.0).
    ///
    /// The assertion is over the SET of announced ids, derived from the
    /// declarations the drain actually emitted rather than from a literal:
    /// pinning `decl_id == 2` would pass just as well if the counters were
    /// still separate and merely offset.
    #[test]
    fn one_session_never_announces_two_things_under_one_id() {
        let mut observer = ApplicationLayerObserver::new();
        let sub = observer
            .subscribe("reenter/a", |_| {})
            .expect("no quota is stated on this table");
        observer
            .app
            .tables
            .subscribers
            .respond_to_subscriber_interest_borrowed(
                &mut observer.peers.subscribers,
                INTEREST,
                Some("reenter/a"),
                /*aggregate=*/ true,
                /*current=*/ true,
                /*future=*/ true,
            );
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);

        let aggregate_ids: Vec<u64> = sink
            .subscriber_replies
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _, _)| *id)
            .collect();
        assert_eq!(
            aggregate_ids.len(),
            1,
            "exactly one aggregate declaration must have been emitted — with \
             none, the disjointness below holds vacuously"
        );

        let mut all = aggregate_ids;
        all.push(sub.as_u64());
        let unique: alloc::collections::BTreeSet<u64> = all.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "the aggregate declaration and the subscription were announced \
             under the same id {all:?} — one session, two id counters, and a \
             peer keyed by id sees one declaration where two were sent"
        );
    }
}

/// A build that answers no peer's Interest (`interest-answer` off), asked as one that does: the
/// subscriber Interest reaches the subscriber plane, and what the observer owes after it, and after
/// a subscription the Interest's FUTURE half reaches, is nothing: no declaration and no `Final`.
/// Such a build has no drain of answers at all (`flush_declare_replies` is not in it), so what is
/// taken is everything owed. The build that answers is held by
/// `a_member_interest_on_its_own_alias_is_answered`.
#[cfg(all(
    test,
    feature = "declare-subscriber",
    not(feature = "interest-answer"),
    feature = "alloc"
))]
mod unanswered_interest_tests {
    use super::*;

    /// No liveliness get to prune: the tests here ask none.
    struct NoPrunes;

    impl LivelinessGetPrune for NoPrunes {
        #[cfg(feature = "liveliness-get")]
        fn prune_liveliness_get_interest(&self, _interest_id: u64) {}
    }

    #[test]
    fn a_peers_subscriber_interest_is_not_answered() {
        let mut observer = ApplicationLayerObserver::new();
        observer
            .subscribe("demo/unasked/a", |_| {})
            .expect("no quota is stated on this table");
        let interest = crate::interest_build::build_interest_subscribers(
            3,
            /*current=*/ true,
            /*future=*/ true,
            0,
            Some("demo/unasked/**"),
        )
        .expect("a literal key builds");
        let frame = crate::driver_loop::DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: alloc::vec![crate::network_message::NetworkMessage::Interest(interest)],
            has_ext: false,
            extensions: alloc::vec::Vec::new(),
        };
        crate::driver_loop::deliver_frame(&frame, |event| observer.dispatch_event(event));
        let mut owed = OwedReplies::new();
        observer.take_owed_replies(&mut owed, &NoPrunes);
        assert!(
            owed.is_empty(),
            "the CURRENT half is not answered, not even by a Final"
        );
        observer
            .subscribe("demo/unasked/b", |_| {})
            .expect("no quota is stated on this table");
        observer.take_owed_replies(&mut owed, &NoPrunes);
        assert!(
            owed.is_empty(),
            "and the FUTURE half is not told of a later subscription"
        );
    }
}

/// R2349 (`liveliness-history`) — the HISTORY replay covers the peer's
/// tokens and NOT this session's own, and that exclusion is a PARITY
/// DECISION rather than a gap.
///
/// Measured against the pinned upstreams rather than inherited, because the
/// atom's own prose has asserted it for two rounds without anything
/// enforcing it:
///
/// - zenoh replays `state.remote_tokens` only
///   (`zenoh/src/api/session.rs` @ `let known_tokens = if history {`).
/// - zenoh-pico iterates `zn->_remote_tokens` only, and records the gap as
///   its OWN todo (`vendor/zenoh-pico/src/net/liveliness.c`, the
///   `add support for local tokens` comment above the iterator).
///
/// So replaying local tokens here would be DIVERGENCE, not a fix.
///
/// ⚠ WHAT THIS PAIR IS, STATED EXACTLY, because R2349 probed it and the
/// probe came back WEAKER than hoped. A mutation that makes the replay emit
/// an extra local-looking token reds the CONTROL below and NOT the first
/// test — because `replay_known_tokens` returns early on an empty
/// `peer_token_table`, which is exactly the state the first test sets up.
/// The first test therefore cannot be broken from inside the replay at all:
/// the registry holds no local tokens and structurally cannot reach them.
///
/// So this is a REGRESSION FENCE, not a mutation-provable guard. It pins
/// the observable fact against a FUTURE wiring — the two registries sit
/// side by side on this struct, and connecting them is the change that
/// would make it red. It is NOT evidence that the exclusion is defended
/// today by anything but the type system, and must not be cited as such.
///
/// THE CONTROL IS THE HALF THAT CARRIES WEIGHT: a replay that is simply
/// broken also delivers zero samples, so without a peer token actually
/// arriving the first assertion is satisfiable by an inert registry.
#[cfg(all(
    test,
    feature = "liveliness-token",
    feature = "liveliness-subscriber",
    feature = "alloc"
))]
mod history_replay_is_peer_scoped {
    use super::*;
    use crate::declare::liveliness_sample::BoxedLivelinessSampleSink;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use std::sync::{Arc, Mutex};
    use wz_session_core_test_support::decl_token_nonlocal;

    #[test]
    fn a_locally_held_token_is_not_replayed_to_a_history_subscriber() {
        let mut observer = ApplicationLayerObserver::new();
        // A token THIS session holds, matching the pattern the subscriber
        // will declare. Upstream would not replay it; neither may wz.
        observer
            .app
            .local_tokens
            .register(41, "live/mine")
            .expect("register a locally held token");

        let fired: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let f = fired.clone();
        observer
            .app
            .tables
            .liveliness_subscribers
            .register(
                &observer.peers.tokens,
                9,
                "live/**",
                true, // history: the replay fires inside `register`
                BoxedLivelinessSampleSink::new(move |sample| {
                    f.lock().unwrap().push(sample.keyexpr.to_string());
                }),
            )
            .expect("register the history subscriber");

        assert!(
            fired.lock().unwrap().is_empty(),
            "a history subscriber is owed the PEER's tokens, not this \
                 session's own — replaying a local token would diverge from \
                 both upstreams, neither of which does it"
        );
    }

    /// The control for the above: the SAME pattern and the same `history`
    /// flag, with a token that arrived from the PEER. It must be replayed.
    ///
    /// Without this, "zero samples" is equally explained by the replay
    /// being broken, by the pattern not matching, or by `history` not being
    /// honoured — none of which is the claim.
    #[test]
    fn a_peer_token_is_replayed_to_the_same_history_subscriber() {
        let mut observer = ApplicationLayerObserver::new();
        // Same shape as the local token above, but arriving over the wire.
        observer.app.tables.liveliness_subscribers.dispatch_declare(
            &mut observer.peers.tokens,
            &crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohDeclToken(
                decl_token_nonlocal(41, 0, Some("live/theirs")),
            ),
            &hashbrown::HashMap::<u64, alloc::string::String>::new(),
        );

        let fired: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let f = fired.clone();
        observer
            .app
            .tables
            .liveliness_subscribers
            .register(
                &observer.peers.tokens,
                9,
                "live/**",
                true,
                BoxedLivelinessSampleSink::new(move |sample| {
                    f.lock().unwrap().push(sample.keyexpr.to_string());
                }),
            )
            .expect("register the history subscriber");

        assert_eq!(
            fired.lock().unwrap().as_slice(),
            ["live/theirs".to_string()],
            "control: the replay itself works, the pattern matches, and \
                 `history` is honoured — so the empty result above is about \
                 the token being LOCAL and nothing else"
        );
    }
}

// A peer's QUERYABLE Interest is answered from the queryables this session
// holds. zenoh-pico arms a write filter per `z_declare_querier` and drops every
// query it is handed until a `DeclQueryable` stamped with ITS interest's id
// reaches the filter, so a session that never answers the interest serves a
// querier only when an earlier unsolicited declaration happened to be processed
// before the filter was created. These tests drive the answer through
// `flush_declare_replies`, the door the session tier calls.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "query-queryable",
    feature = "declare-queryable",
    any(feature = "liveliness-token", feature = "declare-subscriber"),
    feature = "interest-answer"
))]
mod queryable_interest_reply_tests {
    use super::*;
    use crate::driver_loop::DriverLoopOutcome;
    use crate::interest_build::{build_interest_kinds_with_aggregate, InterestKinds};
    use crate::locality::Locality;
    use crate::network_message::NetworkMessage;
    use crate::query_sink::BoxedQuerySink;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use std::sync::Mutex;

    /// What the drain emitted, in order, as text an assertion can name.
    #[derive(Default)]
    struct RecordingSink {
        wire: Mutex<Vec<String>>,
    }

    impl DeclareReplySink for RecordingSink {
        #[cfg(feature = "liveliness-token")]
        fn send_declare_token_reply(&self, _token_id: u64, _keyexpr: &str, _interest_id: u64) {}

        fn send_declare_final_reply(&self, interest_id: u64) {
            self.wire
                .lock()
                .unwrap()
                .push(alloc::format!("final {interest_id}"));
        }

        #[cfg(feature = "declare-subscriber")]
        fn send_declare_subscriber_reply(&self, _id: u64, _keyexpr: &str, _interest_id: u64) {}

        #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
        fn send_undeclare_subscriber_reply(&self, _subscriber_id: u64) {}

        fn send_declare_queryable_reply(
            &self,
            queryable_id: u64,
            keyexpr: &str,
            complete: bool,
            interest_id: u64,
        ) {
            self.wire.lock().unwrap().push(alloc::format!(
                "queryable {queryable_id} {keyexpr} complete={complete} interest={interest_id}"
            ));
        }
    }

    fn outcome(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// The interest zenoh-pico's write filter sends for a client querier:
    /// queryables, CURRENT and FUTURE, AGGREGATE, keyed `key`.
    fn querier_interest(interest_id: u64, key: &str, aggregate: bool) -> NetworkMessage {
        NetworkMessage::Interest(
            build_interest_kinds_with_aggregate(
                interest_id,
                InterestKinds::QUERYABLES,
                /*current=*/ true,
                /*future=*/ true,
                aggregate,
                0,
                Some(key),
            )
            .expect("a literal key builds"),
        )
    }

    fn answer(observer: &mut ApplicationLayerObserver, interest: NetworkMessage) -> Vec<String> {
        crate::driver_loop::deliver_frame(&outcome(alloc::vec![interest]), |event| {
            observer.dispatch_event(event)
        });
        let sink = RecordingSink::default();
        observer.flush_declare_replies(&sink);
        sink.wire.into_inner().unwrap()
    }

    /// THE CASE THAT STALLED `z_get_lat`: the session holds a queryable on the
    /// key, the peer's querier asks, and the answer is the queryable stamped with
    /// the interest's id and then the `Final`.
    #[test]
    fn a_queryable_interest_is_answered_with_the_queryable_and_a_final() {
        let mut observer = ApplicationLayerObserver::new();
        let id = observer
            .app
            .tables
            .queryables
            .register("lat", |_q, _out| {})
            .expect("no quota is stated on this table")
            .as_u64();
        assert_eq!(
            answer(&mut observer, querier_interest(7, "lat", false)),
            [
                alloc::format!("queryable {id} lat complete=false interest=7"),
                "final 7".to_string()
            ]
        );
    }

    /// The same interest lent where its frame lies, on a build that lends control records, is
    /// answered as the owned one is: the queryable stamped with the interest's id, then the
    /// `Final`. A FUTURE-only interest asks no dump and is answered with nothing.
    #[cfg(all(feature = "rx-lent-control", feature = "rx-control"))]
    #[test]
    fn a_lent_queryable_interest_is_answered_as_the_owned_one_is() {
        use crate::driver_loop::InPlaceRecord;
        use sce_forge_runtime::codec::SceCursor;

        let lent_answer = |observer: &mut ApplicationLayerObserver, current: bool| {
            let owned = build_interest_kinds_with_aggregate(
                7,
                InterestKinds::QUERYABLES,
                current,
                /*future=*/ true,
                false,
                0,
                Some("lat"),
            )
            .expect("a literal key builds");
            let wire = owned
                .try_as_borrowed()
                .expect("a borrowed view")
                .encode_to_vec();
            let view =
                wz_codecs::lent::Interest::decode(&mut SceCursor::new(&wire)).expect("decodes");
            observer.dispatch_event(IterationEvent::InPlace(InPlaceRecord::interest_of_frame(
                &view,
                true,
                0,
                crate::qos::Priority::DEFAULT,
            )));
            let sink = RecordingSink::default();
            observer.flush_declare_replies(&sink);
            sink.wire.into_inner().unwrap()
        };
        let mut observer = ApplicationLayerObserver::new();
        let id = observer
            .app
            .tables
            .queryables
            .register("lat", |_q, _out| {})
            .expect("no quota is stated on this table")
            .as_u64();
        assert_eq!(
            lent_answer(&mut observer, true),
            [
                alloc::format!("queryable {id} lat complete=false interest=7"),
                "final 7".to_string()
            ]
        );
        assert!(
            lent_answer(&mut observer, false).is_empty(),
            "a FUTURE-only interest asks for no dump"
        );
    }

    /// With nothing to declare the chain is the `Final` alone: "no matching
    /// queryable" is an answer, and the peer's CURRENT interest must still end.
    #[test]
    fn an_interest_no_queryable_reaches_is_answered_with_a_final_alone() {
        let mut observer = ApplicationLayerObserver::new();
        observer
            .app
            .tables
            .queryables
            .register("other/key", |_q, _out| {})
            .expect("no quota is stated on this table");
        assert_eq!(
            answer(&mut observer, querier_interest(3, "lat", false)),
            ["final 3".to_string()]
        );
        let mut empty = ApplicationLayerObserver::new();
        assert_eq!(
            answer(&mut empty, querier_interest(4, "lat", true)),
            ["final 4".to_string()]
        );
    }

    /// An AGGREGATE interest (a pico client querier's always is) is answered
    /// ONCE, with the INTEREST's key: the peer associates the reply with its
    /// interest by key equality, so a wildcard queryable's own key would match
    /// nothing. The reply is for the first queryable that reaches it.
    #[test]
    fn an_aggregate_interest_is_answered_once_under_the_interests_key() {
        let mut observer = ApplicationLayerObserver::new();
        let first = observer
            .app
            .tables
            .queryables
            .register("demo/**", |_q, _out| {})
            .expect("no quota is stated on this table")
            .as_u64();
        observer
            .app
            .tables
            .queryables
            .register("demo/a", |_q, _out| {})
            .expect("no quota is stated on this table");
        observer
            .app
            .tables
            .queryables
            .register("elsewhere/x", |_q, _out| {})
            .expect("no quota is stated on this table");
        assert_eq!(
            answer(&mut observer, querier_interest(9, "demo/a", true)),
            [
                alloc::format!("queryable {first} demo/a complete=false interest=9"),
                "final 9".to_string()
            ]
        );
    }

    /// A non-aggregate interest gets one reply per queryable that reaches it,
    /// each under its own key, and the completeness of an aggregate reply is
    /// the OR of the matches'.
    #[test]
    fn a_plain_interest_gets_one_reply_per_match_and_an_aggregate_merges_completeness() {
        let mut observer = ApplicationLayerObserver::new();
        let a = observer
            .app
            .tables
            .queryables
            .register("demo/*", |_q, _out| {})
            .expect("no quota is stated on this table")
            .as_u64();
        let b = observer
            .app
            .tables
            .queryables
            .register_sink(
                "demo/b",
                Locality::Any,
                /*complete=*/ true,
                BoxedQuerySink::new(|_q, _out| {}),
            )
            .expect("the alloc backing never refuses")
            .as_u64();
        assert_eq!(
            answer(&mut observer, querier_interest(1, "demo/**", false)),
            [
                alloc::format!("queryable {a} demo/* complete=false interest=1"),
                alloc::format!("queryable {b} demo/b complete=true interest=1"),
                "final 1".to_string()
            ]
        );
        assert_eq!(
            answer(&mut observer, querier_interest(2, "demo/**", true)),
            [
                alloc::format!("queryable {a} demo/** complete=true interest=2"),
                "final 2".to_string()
            ]
        );
    }

    /// A queryable that accepts only LOCAL origin is not one a peer may see.
    #[test]
    fn a_local_only_queryable_is_not_declared_to_a_peer() {
        let mut observer = ApplicationLayerObserver::new();
        observer
            .app
            .tables
            .queryables
            .register_with_locality("lat", Locality::SessionLocal, |_q, _out| {})
            .expect("no quota is stated on this table");
        assert_eq!(
            answer(&mut observer, querier_interest(5, "lat", false)),
            ["final 5".to_string()]
        );
    }

    /// Only a CURRENT interest solicits a dump, and only the queryables kind is
    /// answered here: a FUTURE-only interest, a FINAL, and a subscribers
    /// interest owe nothing from this plane.
    #[test]
    fn only_a_current_queryables_interest_is_answered() {
        let mut observer = ApplicationLayerObserver::new();
        observer
            .app
            .tables
            .queryables
            .register("lat", |_q, _out| {})
            .expect("no quota is stated on this table");
        let future_only = NetworkMessage::Interest(
            build_interest_kinds_with_aggregate(
                11,
                InterestKinds::QUERYABLES,
                false,
                true,
                false,
                0,
                Some("lat"),
            )
            .expect("builds"),
        );
        assert!(answer(&mut observer, future_only).is_empty());
        let subscribers = NetworkMessage::Interest(
            build_interest_kinds_with_aggregate(
                12,
                InterestKinds::SUBSCRIBERS,
                true,
                true,
                false,
                0,
                Some("lat"),
            )
            .expect("builds"),
        );
        // The subscriber chain answers a subscribers interest with its own
        // terminator; what this plane owes it is no queryable declaration.
        assert!(answer(&mut observer, subscribers)
            .iter()
            .all(|wire| !wire.starts_with("queryable")));
        let cancel = NetworkMessage::Interest(crate::interest_build::build_interest_final(13));
        assert!(answer(&mut observer, cancel).is_empty());
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;

    /// A session that shares nothing: the application half is a view of the observer's own tables,
    /// so what is registered through it is what the observer holds.
    #[test]
    fn the_application_half_is_the_observers_own_tables() {
        let mut observer = ApplicationLayerObserver::new();
        let id = observer
            .with_app(|app| app.subscribers.register("demo/a", |_| {}))
            .unwrap();
        assert_eq!(observer.app.tables.subscribers.len(), 1);
        assert_eq!(observer.read_app(|app| app.subscribers.len()), 1);
        assert!(observer.with_app(|app| app.subscribers.unregister(id)));
        assert!(observer.app.tables.subscribers.is_empty());
    }

    /// Registering through the observer reaches the same table as the half does, and retiring an
    /// id it does not hold says so.
    #[test]
    fn a_subscriber_registered_on_the_observer_is_in_the_application_half() {
        let mut observer = ApplicationLayerObserver::new();
        let id = observer
            .register_subscriber(
                "demo/b",
                crate::locality::Locality::Any,
                crate::sink::BoxedSink::new(|_| {}),
            )
            .unwrap();
        assert_eq!(observer.read_app(|app| app.subscribers.len()), 1);
        assert!(observer.unregister_subscriber(id));
        assert!(!observer.unregister_subscriber(id));
        assert_eq!(observer.read_app(|app| app.subscribers.len()), 0);
        let local = observer
            .subscribe_with_locality("demo/b", crate::locality::Locality::SessionLocal, |_| {})
            .unwrap();
        let any = observer.subscribe("demo/b", |_| {}).unwrap();
        assert_ne!(local, any);
        assert_eq!(observer.read_app(|app| app.subscribers.len()), 2);
    }

    /// The face half is the observer's own peer side: nothing pending on a fresh observer, and the
    /// two halves borrowed together read the same tables as each alone.
    #[test]
    fn the_face_half_is_the_observers_own_peer_side() {
        let mut observer = ApplicationLayerObserver::new();
        assert_eq!(observer.face().replies.len(), 0);
        assert_eq!(
            observer.face_ref().replies.len(),
            observer.requesters.replies.len()
        );
        let both = observer.read_parts(|app, face| (app.subscribers.len(), face.replies.len()));
        assert_eq!(both, (0, 0));
        let (registered, pending) = observer.with_parts(|app, face| {
            (
                app.subscribers.register("demo/c", |_| {}).is_ok(),
                face.replies.len(),
            )
        });
        assert!(registered);
        assert_eq!(pending, 0);
        assert_eq!(observer.app.tables.subscribers.len(), 1);
    }
}
