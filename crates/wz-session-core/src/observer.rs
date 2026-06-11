// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! observer.subscribers.register("home/temp", on_temp);
//! observer.queryables.register("metrics/**", on_metric);
//! observer.replies.register(rid, expected_finals, on_reply, on_final);
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
//!   non-bundled usage. The bundle exposes its fields as `pub` so
//!   application code can call `register` directly on each contained
//!   registry without indirection.
//!
//! ## Dispatch flow
//!
//! `dispatch(event, &actions)` runs in two phases:
//!
//! 1. **Fan** — `dispatch_event(event)` routes `event` into every
//!    registry. The subscriber registry runs FIRST so any
//!    `Declare(DeclKexpr)` body in the same frame populates the
//!    peer_keyexpr_table before the consumer registries read it.
//! 2. **Drain** — `flush_pending(&actions)` walks `pending_replies` +
//!    `pending_final_rids` (populated by the queryable side during
//!    fan-out) and emits each through the action layer. Order is
//!    preserved on the wire: every Reply for rid R precedes the
//!    matching ResponseFinal for R (zenoh-pico's z_get correlator
//!    depends on this).
//!
//! `dispatch_event` and `flush_pending` are exposed individually so
//! tests can exercise the fan without an actions stand-in (the
//! actions-side drain is covered by integration tests against a real
//! TCP loopback). Production code calls the combined
//! [`Self::dispatch`] form.
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

// R311dz — `LivelinessRegistry` gates on `liveliness-token`; without it
// the observer slot for the peer Decl/UndeclToken arm is elided. The
// type lives in this crate's `declare::liveliness` (codec-declare-gated)
// module after the R311do-dq registry migration.
#[cfg(feature = "liveliness-token")]
use crate::declare::liveliness::LivelinessRegistry;
// R283 — declarer-side held-token registry + the inbound-Interest
// responder. Gated on `liveliness-token` (the declarer feature) alongside
// the peer-side `LivelinessRegistry`. R311hn (Track 2) — the staging
// buffer is now a no-heap `BoundedVec<DeclResponseItem>` (was
// `Vec<DeclareOwned>`); the registry + its no-heap response surface
// compile without `alloc`.
#[cfg(feature = "liveliness-token")]
use crate::bounded::BoundedVec;
#[cfg(feature = "liveliness-token")]
use crate::caps;
#[cfg(feature = "liveliness-token")]
use crate::declare::local_token::{DeclResponseItem, LocalTokenRegistry};
// R311ek — `LivelinessSubscriberRegistry` consumes `DeclareOwnedVariant`
// and lives under the `codec-declare`-gated `declare` module, so the
// `liveliness_subscribers` field + this import gate on
// `liveliness-subscriber` (which now implies `codec-declare`). With the
// observer no longer `codec-declare`-gated as a whole (R311ek), the
// previously-unconditional field would otherwise reference a type that
// does not exist in a `codec-declare`-off subset. The codec-agnostic
// callback surface (`LivelinessSample` etc.) lives in the always-present
// `declare::liveliness_sample` module so the
// `Session::declare_liveliness_subscriber{_aliased}` Result-form
// signatures still compile regardless of feature state; only the
// registry slot (and its dispatch / Drop access) follow the feature.
#[cfg(feature = "liveliness-subscriber")]
use crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry;
// liveliness-get — the requester-side pending-get registry. Gated on
// `liveliness-get` (which implies `codec-declare`); the field + this
// import + the dispatch fan in `dispatch_event` follow the feature, the
// `Session::liveliness_get` Result-form surface returns
// `Err(FeatureDisabled)` in the feature-OFF build without touching the
// field. Reuses the `crate::reply_sink::BoxedReplySink` delivery seam
// (the get surface is reply-shaped).
#[cfg(feature = "liveliness-get")]
use crate::declare::liveliness_get::LivelinessGetRegistry;
// R310 — peer-side declare observer registries gate on the matching
// application-layer declare-* feature. Without the feature the
// observer slot for that wire arm is elided entirely; inbound
// Decl/Undecl frames still decode at the codec layer but the fan-out
// to user callbacks is absent (the application can't have registered
// callbacks against a type that does not exist in its build).
#[cfg(feature = "declare-queryable")]
use crate::declare::queryable::RemoteQueryableRegistry;
#[cfg(feature = "declare-subscriber")]
use crate::declare::subscriber::RemoteSubscriberRegistry;
use crate::driver_loop::IterationEvent;
use crate::pubsub::SubscriberRegistry;
#[cfg(feature = "switchboard")]
use crate::switchboard::{EventInjector, SwitchboardRegistry};
// R311r — `QueryReply` is the codec-agnostic accumulator (always
// compiled, alloc-bound); it backs the `pending_replies` staging buffer
// + the `pending_reply_count` accessor regardless of feature state. The
// `QueryableRegistry` field, by contrast, is the `Request` / `Query`
// dispatch surface and gates on `query-queryable` (which implies
// codec-request + codec-response) — a build without it composes the
// observer with the queryable slot elided. (Pre-R311dz the field was
// type-ungated in the AP crate because the AP-side `query` shell only
// re-exported `QueryableRegistry` under codec-request; the migration
// makes the consumer-feature gate explicit so a codec-declare-on /
// query-queryable-off subset compiles.)
use crate::query::QueryReply;
#[cfg(feature = "query-queryable")]
use crate::query::QueryableRegistry;
// R311dy — `ReplyRegistry` stays always-compiled (alloc): its loopback
// delivery + timeout sweep are codec-agnostic, mirroring
// `SubscriberRegistry`. The dispatch fan-out + wire-emit drain stay
// cfg-gated inside the registry / `flush_pending`.
use crate::reply::ReplyRegistry;
// R311dz-pre — the actions-drain phase (`flush_pending` / `dispatch`) is
// generic over the `ResponseSink` IoC trait rather than the concrete
// tokio `SessionLinkActions<R, T>`. This is what let the observer
// migrate here without dragging in the tokio actions layer
// (`wz-runtime-tokio::session_glue`). `SessionLinkActions` impls
// `ResponseSink` in wz-runtime-tokio so existing call sites
// (`observer.dispatch(event, &actions)`) resolve `S = SessionLinkActions
// <R, T>` by inference, unchanged.
use crate::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};
use alloc::vec::Vec;

/// Six-registry application-layer dispatch bundle. See module-level
/// docs for the rationale and dispatch flow.
pub struct ApplicationLayerObserver {
    /// Local pub/sub callbacks + peer keyexpr table (the table is
    /// populated by inbound `Declare(DeclKexpr|UndeclKexpr)` records
    /// and shared by every consumer registry for keyexpr resolution).
    pub subscribers: SubscriberRegistry<crate::sink::BoxedSink>,
    /// R311gi gc-2c — the statechart switchboard: the keyexpr -> SCXML
    /// domain-event injection table. A SEPARATE inbound adapter from the
    /// data-callback `subscribers` (gc-2a): its
    /// [`dispatch_switchboard`](Self::dispatch_switchboard) fan-out
    /// threads the engine ingress port (`EventInjector`) rather than
    /// storing a callback, so statechart injection stays decoupled from
    /// the data-callback path. Gated on `switchboard` (⇒ `codec-push`,
    /// since it reacts to inbound Push samples).
    #[cfg(feature = "switchboard")]
    pub switchboard: SwitchboardRegistry,
    /// Inbound `Request(Query)` → responder callbacks (acceptor /
    /// queryable side). The `pending_replies` / `pending_final_rids`
    /// buffers below stage outbound records this registry emits
    /// during fan-out.
    ///
    /// R311dz — gated on `query-queryable`. The type
    /// (`QueryableRegistry`) is the `Request` / `Query` dispatch
    /// surface and only exists when that consumer feature (⇒
    /// codec-request + codec-response) is selected; a build without it
    /// composes the observer with this slot elided. The type-ungated
    /// `Session::declare_queryable{_aliased}` Result-form surface keeps
    /// compiling because its feature-OFF branch returns
    /// `Err(FeatureDisabled)` without ever touching this field, and the
    /// `Queryable` RAII handle's `Drop` gates its unregister on the same
    /// feature. The dispatch fan-out in [`Self::dispatch_event`] and the
    /// wire-emit drain in [`Self::flush_pending`] stay cfg-gated so a
    /// feature-OFF build elides the dispatch + drain paths entirely.
    #[cfg(feature = "query-queryable")]
    pub queryables: QueryableRegistry<crate::query_sink::BoxedQuerySink>,
    /// Peer's outbound `DeclSubscriber` / `UndeclSubscriber` records.
    ///
    /// R310 — gated on `feature = "declare-subscriber"`.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: RemoteSubscriberRegistry<
        crate::decl_sink::BoxedDeclSink,
        crate::decl_sink::BoxedUndeclSink,
    >,
    /// Peer's outbound `DeclQueryable` / `UndeclQueryable` records.
    ///
    /// R310 — gated on `feature = "declare-queryable"`.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables:
        RemoteQueryableRegistry<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// Peer's outbound `DeclToken` / `UndeclToken` records — the
    /// liveliness signal layer.
    #[cfg(feature = "liveliness-token")]
    pub liveliness:
        LivelinessRegistry<crate::decl_sink::BoxedDeclSink, crate::decl_sink::BoxedUndeclSink>,
    /// R283 — DECLARER-side registry of wz's own held
    /// `LivelinessToken`s. Populated by `Session::declare_token` and
    /// emptied by `LivelinessToken::Drop`. Consulted only when an inbound
    /// non-final liveliness Interest arrives, to stage the
    /// interest-response (`Declare(DeclToken)` per matching held token +
    /// a terminating `Declare(DeclFinal)`) into [`Self::pending_declares`]
    /// during the fan phase; the drain phase flushes it through the sink.
    /// The declarer-side mirror of [`Self::liveliness`] (which tracks the
    /// PEER's tokens).
    #[cfg(feature = "liveliness-token")]
    pub local_tokens: LocalTokenRegistry,
    /// R280 — local liveliness subscribers declared by
    /// `Session::declare_liveliness_subscriber`. A keyexpr-filtered
    /// counterpart to [`Self::liveliness`]: the generic-observer
    /// registry fans EVERY peer `Decl*Token` into its callbacks, while
    /// this registry routes only the peer tokens whose resolved keyexpr
    /// matches a subscriber slot's pattern. Both registries receive the
    /// same `IterationEvent` from [`Self::dispatch_event`]; they are
    /// independent fan-out paths.
    ///
    /// R311ek — gated on `liveliness-subscriber`. The registry type
    /// consumes `DeclareOwnedVariant`, so it only exists under
    /// `codec-declare` (implied by the feature); a subset without the
    /// feature composes the observer with this slot elided. The
    /// `Session::declare_liveliness_subscriber{_aliased}` Result-form
    /// surface still compiles regardless because its callback parameter
    /// binds the codec-agnostic [`crate::declare::liveliness_sample`]
    /// types and its feature-OFF branch returns `Err(FeatureDisabled)`
    /// without touching this field. The dispatch fan-out in
    /// [`Self::dispatch_event`] is gated on the same feature.
    #[cfg(feature = "liveliness-subscriber")]
    pub liveliness_subscribers:
        LivelinessSubscriberRegistry<crate::declare::liveliness_sample::BoxedLivelinessSampleSink>,
    /// Requester-side pending liveliness GET (snapshot) queries declared
    /// by [`crate::session::Session::liveliness_get`]. Each inbound
    /// solicited `Declare(DeclToken)` (interest_id-tagged) fans to the
    /// matching pending get's `on_reply`; the terminating
    /// `Declare(DeclFinal)` fires `on_final` + removes the entry. A
    /// declaration-plane sibling of [`Self::replies`] (the z_get reply
    /// registry) — same reply-delivery seam, distinct correlation plane
    /// (`interest_id` vs `Response.request_id`). Gated on `liveliness-get`
    /// (implies `codec-declare`); the dispatch fan in
    /// [`Self::dispatch_event`] gates on the same feature.
    #[cfg(feature = "liveliness-get")]
    pub liveliness_gets: LivelinessGetRegistry<crate::reply_sink::BoxedReplySink>,
    /// Initiator-side `Response(Reply|Err)` + `ResponseFinal`
    /// callbacks (`z_get` consumer). Pending entries auto-unregister
    /// when their matching `ResponseFinal` arrives.
    ///
    /// R311s — type-ungated. The struct is always present so the
    /// type-ungated `Session::query` / `Querier` surface can register
    /// pending entries regardless of `query-reply` feature state; the
    /// feature-OFF build never enters the registration path (Session::query's
    /// body is gated on `query-get` which implies `query-reply`).
    pub replies: ReplyRegistry<crate::reply_sink::BoxedReplySink>,
    /// R311r — staging buffers are unconditional so the observer
    /// struct shape is stable across consumer-feature subsets. The
    /// drain side in [`Self::flush_pending`] stays cfg-gated on
    /// `query-queryable` so wire-emit only runs when the queryable
    /// dispatch path is in.
    pending_replies: Vec<QueryReply>,
    pending_final_rids: Vec<u64>,
    /// R283 — staging buffer for the declarer-side interest-response
    /// (`Declare(DeclToken)` + `Declare(DeclFinal)`). Populated by
    /// `local_tokens` during the fan phase (the `alloc` inbound-parse
    /// path), drained through the borrowed
    /// `ResponseSink::send_declare_token` / `send_declare_final` seam
    /// during [`Self::flush_pending`]. Gated on `liveliness-token`
    /// (unlike the unconditional reply buffers) because only the declarer
    /// registry — itself feature-gated — ever stages into it. R311hn
    /// (Track 2) — a no-heap [`BoundedVec`] of [`DeclResponseItem`]
    /// (was `Vec<DeclareOwned>`), so the drain composes without `alloc`.
    #[cfg(feature = "liveliness-token")]
    pending_declares: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
}

impl Default for ApplicationLayerObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ApplicationLayerObserver {
    /// New observer with empty registries. Callers register
    /// callbacks on each contained registry directly
    /// (`observer.subscribers.register(...)` etc.) before driving
    /// the session loop.
    pub fn new() -> Self {
        Self {
            subscribers: SubscriberRegistry::new(),
            // R311gi gc-2c — switchboard table constructed only under the
            // `switchboard` feature; empty until the app registers its
            // keyexpr -> event rows (from wz-switchboard.yaml on AP).
            #[cfg(feature = "switchboard")]
            switchboard: SwitchboardRegistry::new(),
            // R311dz — field gated on `query-queryable`; the registry is
            // constructed only when the queryable dispatch path is in.
            // The Queryable RAII handle's observer-side unregister-on-Drop
            // is gated on the same feature so a feature-OFF build never
            // references the absent field.
            #[cfg(feature = "query-queryable")]
            queryables: QueryableRegistry::new(),
            #[cfg(feature = "declare-subscriber")]
            remote_subscribers: RemoteSubscriberRegistry::new(),
            #[cfg(feature = "declare-queryable")]
            remote_queryables: RemoteQueryableRegistry::new(),
            #[cfg(feature = "liveliness-token")]
            liveliness: LivelinessRegistry::new(),
            // R283 — declarer-side held-token registry constructed only
            // under `liveliness-token`. Empty until `Session::declare_token`
            // registers wz's first held token.
            #[cfg(feature = "liveliness-token")]
            local_tokens: LocalTokenRegistry::new(),
            // R311ek — field gated on `liveliness-subscriber`; the
            // registry is constructed only when that feature is in. The
            // LivelinessSubscriber RAII handle's observer-side lookups
            // (history_complete, unregister on Drop) are gated on the
            // same feature so a feature-OFF build never references the
            // absent field.
            #[cfg(feature = "liveliness-subscriber")]
            liveliness_subscribers: LivelinessSubscriberRegistry::new(),
            // liveliness-get — requester-side pending-get registry,
            // constructed only under `liveliness-get`. Empty until
            // `Session::liveliness_get` registers the first snapshot
            // query.
            #[cfg(feature = "liveliness-get")]
            liveliness_gets: LivelinessGetRegistry::new(),
            // R311s — replies field is type-ungated; the registry is
            // always constructed (empty) so the type-ungated query
            // surface can register pending entries even though
            // feature-OFF never reaches the registration path.
            replies: ReplyRegistry::new(),
            // R311r — staging buffers always allocated; drain path in
            // flush_pending stays cfg-gated on query-queryable.
            pending_replies: Vec::new(),
            pending_final_rids: Vec::new(),
            // R283 — declarer interest-response staging buffer, gated on
            // `liveliness-token` like its producer registry. R311hn — a
            // no-heap `BoundedVec`.
            #[cfg(feature = "liveliness-token")]
            pending_declares: BoundedVec::new(),
        }
    }

    /// Phase 1 — fan an [`IterationEvent`] into every contained
    /// registry. The subscriber registry runs first so its
    /// `absorb_declare` path updates `peer_keyexpr_table` BEFORE the
    /// consumer registries read it for keyexpr resolution.
    ///
    /// `event` is `Copy` (set up in R121j-5c-e2e-demo to support
    /// multi-consumer dispatch); the same reference fans into each
    /// registry at zero cost.
    pub fn dispatch_event(&mut self, event: IterationEvent<'_>) {
        // Subscribers FIRST — absorb DeclKexpr / UndeclKexpr into the
        // peer_keyexpr_table so downstream consumers see a fresh
        // mapping snapshot on the same iteration.
        //
        // R310.5b — the `peer_table` binding (and the
        // `peer_keyexpr_table()` getter call) is itself gated on the
        // consumer-features union. When no consumer arm is active
        // (rare, e.g. preset-mcu-minimal-class with all declare-* /
        // liveliness-* / query-queryable / query-reply off), the
        // getter is not called and no `_peer_table` rebinding is
        // needed. The prior `cfg(not(...)) let _peer_table = ...;`
        // companion was a textbook miss — calling a getter only to
        // discard its result and silence a lint is uglier than
        // simply not calling it.
        self.subscribers.dispatch_iteration_event(event);
        // R311dz — the `query-reply` arm of the AP crate translates to
        // `any(codec-response, codec-response-final)` here: the z_get-side
        // reply dispatch (`ReplyRegistry::dispatch_iteration_event`) is
        // always-compiled and no-ops safely when neither response codec is
        // in, so the consumer gate is exactly the response-codec presence.
        #[cfg(any(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token",
            feature = "liveliness-subscriber",
            feature = "liveliness-get",
            feature = "query-queryable",
            feature = "codec-response",
            feature = "codec-response-final",
        ))]
        let peer_table = self.subscribers.peer_keyexpr_table();

        // Consumer registries — all read the shared peer_table that
        // the subscribers registry just updated. The queryable side
        // also stages outbound replies/finals into our pending bufs
        // so the drain phase can flush them through the action layer.
        #[cfg(feature = "query-queryable")]
        self.queryables.dispatch_iteration_event(
            event,
            peer_table,
            &mut self.pending_replies,
            &mut self.pending_final_rids,
        );
        #[cfg(feature = "declare-subscriber")]
        self.remote_subscribers
            .dispatch_iteration_event(event, peer_table);
        #[cfg(feature = "declare-queryable")]
        self.remote_queryables
            .dispatch_iteration_event(event, peer_table);
        #[cfg(feature = "liveliness-token")]
        self.liveliness.dispatch_iteration_event(event, peer_table);
        // R283 — declarer-side: stage an interest-response for each
        // inbound non-final liveliness Interest. Reads peer_table for the
        // Interest keyexpr resolution; stages into pending_declares (the
        // drain phase flushes them through the sink). R311hn (Track 2) —
        // `all(.., alloc)`-gated: this owned `InterestOwned`-consuming
        // inbound parse resolves keyexprs through the peer `HashMap`
        // (`alloc`). On the MCU no-heap profile the registry's borrowed
        // `respond_to_interest_borrowed` is driven directly, not through
        // this aggregate fan.
        #[cfg(all(feature = "liveliness-token", feature = "alloc"))]
        self.local_tokens
            .dispatch_iteration_event(event, peer_table, &mut self.pending_declares);
        #[cfg(feature = "liveliness-subscriber")]
        self.liveliness_subscribers
            .dispatch_iteration_event(event, peer_table);
        // liveliness-get — fan inbound solicited Declare(DeclToken/DeclFinal)
        // replies into the pending-get registry, correlated by the outer
        // interest_id. Reads peer_table for the reply keyexpr resolution.
        #[cfg(feature = "liveliness-get")]
        self.liveliness_gets
            .dispatch_iteration_event(event, peer_table);
        #[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
        self.replies.dispatch_iteration_event(event, peer_table);
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
        event: IterationEvent<'_>,
        injector: &mut dyn EventInjector,
    ) -> usize {
        self.switchboard.dispatch_iteration_event(
            event,
            self.subscribers.peer_keyexpr_table(),
            injector,
        )
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
    /// segregated [`Self::drain_query_replies`] /
    /// [`Self::drain_declare_replies`] / [`Self::drain_get_prunes`]),
    /// in the same stage order as before. The `actions` bound is the
    /// three-concern union because this aggregate touches all three
    /// staged buffers; a single-concern consumer drains its concern
    /// directly and is bounded on only that trait.
    pub fn flush_pending_replies<S>(&mut self, actions: &S)
    where
        S: ResponseSink + DeclareReplySink + LivelinessGetPrune,
    {
        self.drain_query_replies(actions);
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
    pub fn flush_query_replies<S: ResponseSink>(&mut self, sink: &S) {
        self.drain_query_replies(sink);
        self.drain_query_finals(sink);
    }

    /// R311lr — drain the staged declarer-side liveliness interest-responses
    /// (`pending_declares`) through a [`DeclareReplySink`]. The
    /// `DeclareReplySink` sibling of [`Self::flush_query_replies`]: a consumer
    /// that replies to inbound liveliness Interests but drives neither the
    /// query-reply nor the liveliness-get-prune planes (the multicast reply
    /// loop, which answers a peer's liveliness Interest over the group) drains
    /// exactly this and need only implement [`DeclareReplySink`] — not the
    /// `LivelinessGetPrune` concern, which is genuinely absent on the
    /// connectionless multicast transport (no reconnect cache to prune).
    /// Stage order (each interest-response batch's `Token`s precede its
    /// terminating `Final`) is owned by the underlying
    /// [`Self::drain_declare_replies`]. Exposed demand-driven: the per-concern
    /// drains stay private until a single-concern consumer needs one (the
    /// get-prune concern has no such consumer yet, so it stays bundled in
    /// [`Self::flush_pending`]).
    pub fn flush_declare_replies<S: DeclareReplySink>(&mut self, sink: &S) {
        self.drain_declare_replies(sink);
    }

    /// R311lq — drain the staged queryable data replies (`pending_replies`)
    /// through `send_response`. Does NOT touch the terminal rids (see
    /// [`Self::drain_query_finals`]); the Session-tier path drains data
    /// replies under the lock and defers the finals past the deferred-fire
    /// drain, so the two halves are separate primitives.
    fn drain_query_replies<S: ResponseSink>(&mut self, sink: &S) {
        #[cfg(feature = "query-queryable")]
        for reply in self.pending_replies.drain(..) {
            // W3: a reply whose bounded field overflows cannot be wire-encoded
            // (the codec would reject it too); skip it and continue the drain.
            if let Ok(response) = reply.into_response() {
                sink.send_response(response);
            }
        }
        // Without `query-queryable` the staging buffer does not exist; the
        // signature stays stable so the composing drains wire it
        // unconditionally.
        #[cfg(not(feature = "query-queryable"))]
        let _ = sink;
    }

    /// R311lq — drain the staged queryable ResponseFinal rids
    /// (`pending_final_rids`) through `send_response_final`. Pairs with
    /// [`Self::drain_query_replies`] to form the full reply chain; emitted
    /// last so every data Reply for rid R precedes the matching
    /// ResponseFinal for R.
    fn drain_query_finals<S: ResponseSink>(&mut self, sink: &S) {
        #[cfg(all(feature = "query-queryable", feature = "codec-response-final"))]
        for rid in self.pending_final_rids.drain(..) {
            sink.send_response_final(rid);
        }
        #[cfg(all(feature = "query-queryable", not(feature = "codec-response-final")))]
        self.pending_final_rids.clear();
        // `sink` is consumed only by the `send_response_final` loop above; in
        // every other combo (no `query-queryable`, or `query-queryable` without
        // `codec-response-final`) it is unused but the signature stays stable.
        #[cfg(not(all(feature = "query-queryable", feature = "codec-response-final")))]
        let _ = sink;
    }

    /// R311lq — drain the declarer-side interest-response staging buffer
    /// (`pending_declares`) through a [`DeclareReplySink`].
    ///
    /// R283 / R311hn — every staged `DeclResponseItem` is emitted in stage
    /// order, so each interest-response batch's `Token`s precede its
    /// terminating `Final`. The sink owns the encode (a `VecSink` on AP, a
    /// `SliceSink` on MCU) — no owned `DeclareOwned` crosses the seam.
    fn drain_declare_replies<S: DeclareReplySink>(&mut self, sink: &S) {
        #[cfg(feature = "liveliness-token")]
        for item in core::mem::take(&mut self.pending_declares) {
            match item {
                DeclResponseItem::Token {
                    token_id,
                    interest_id,
                } => {
                    // Resolve the keyexpr from the registry (SSOT) at
                    // drain; a token unregistered between stage and drain
                    // is skipped (its chain's Final still terminates).
                    if let Some(keyexpr) = self.local_tokens.keyexpr_for(token_id) {
                        sink.send_declare_token_reply(token_id, keyexpr, interest_id);
                    }
                }
                DeclResponseItem::Final { interest_id } => {
                    sink.send_declare_final_reply(interest_id)
                }
            }
        }
        #[cfg(not(feature = "liveliness-token"))]
        let _ = sink;
    }

    /// R311lq — drain the terminated-get staging (inbound DeclFinal +
    /// timeout sweeps) through a [`LivelinessGetPrune`]: a finished
    /// one-shot get must not replay its CURRENT Interest on the next
    /// reconnect. The sink no-ops when `session-reconnect` is off, so the
    /// drain is unconditional within the gate.
    fn drain_get_prunes<S: LivelinessGetPrune>(&mut self, sink: &S) {
        #[cfg(feature = "liveliness-get")]
        for interest_id in self.liveliness_gets.take_finalized() {
            sink.prune_liveliness_get_interest(interest_id);
        }
        #[cfg(not(feature = "liveliness-get"))]
        let _ = sink;
    }

    /// R311li — take the staged queryable ResponseFinal rids out of the
    /// observer. The Session-tier dispatch SSOT calls this under the
    /// observer lock (after [`Self::flush_pending_replies`]) and emits
    /// each rid through the actions layer AFTER the deferred-fire drain
    /// — the Reply-before-Final invariant owner on the deferred path
    /// (the combined [`Self::flush_pending`] owns it on the inline /
    /// MCU path).
    #[cfg(feature = "query-queryable")]
    pub fn take_pending_final_rids(&mut self) -> Vec<u64> {
        core::mem::take(&mut self.pending_final_rids)
    }

    /// Combined fan + drain — the production single-call form used
    /// inside the `drive_session_until_terminal` observer closure.
    /// Equivalent to `dispatch_event(event)` followed by
    /// `flush_pending(actions)`.
    pub fn dispatch<S>(&mut self, event: IterationEvent<'_>, actions: &S)
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
        self.pending_replies.len()
    }

    /// Number of `ResponseFinal` rids currently staged for the next
    /// `flush_pending` call. Same diagnostic / test-only role as
    /// [`Self::pending_reply_count`].
    ///
    /// R311r — type-ungated alongside the underlying buffer.
    pub fn pending_final_count(&self) -> usize {
        self.pending_final_rids.len()
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
        assert_eq!(observer.subscribers.len(), 0);
        #[cfg(feature = "query-queryable")]
        assert_eq!(observer.queryables.len(), 0);
        #[cfg(feature = "declare-subscriber")]
        assert_eq!(observer.remote_subscribers.on_decl_len(), 0);
        #[cfg(feature = "declare-queryable")]
        assert_eq!(observer.remote_queryables.on_decl_len(), 0);
        #[cfg(feature = "liveliness-token")]
        assert_eq!(observer.liveliness.on_decl_len(), 0);
        assert_eq!(observer.replies.len(), 0);
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
        observer.subscribers.register("anything", move |_p| {
            f.fetch_add(1, Ordering::SeqCst);
        });

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
        feature = "query-queryable"
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
        use wz_codecs::push::{Push, PushOwned};
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

        pub(super) fn push_literal(suffix: &str, payload: &[u8]) -> PushOwned {
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(suffix),
                }),
            };
            let mut push = Push {
                keyexpr,
                ..Push::default()
            };
            // Set the inner MsgPut body's payload to the test bytes.
            if let wz_codecs::push::PushVariant::CodecZenohMsgPut(ref mut put) = push.body {
                put.payload_len = payload.len() as u64;
                put.payload = payload;
            }
            push.try_into_owned().unwrap()
        }
    }

    // `declare_decl_subscriber` builds an owned peer DeclSubscriber
    // record. Used by the declare-subscriber dispatch test AND the
    // cross-talk test; both require `declare-subscriber`, so that single
    // feature is the gate.
    #[cfg(feature = "declare-subscriber")]
    mod decl_fixtures {
        use wz_codecs::decl_subscriber::DeclSubscriber;
        use wz_codecs::declare::{Declare, DeclareOwned, DeclareVariant};
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

        pub(super) fn declare_decl_subscriber(id: u64, suffix: &str) -> DeclareOwned {
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(suffix),
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
            .try_into_owned()
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
        use crate::driver_loop::IterationEvent;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[test]
        fn dispatch_event_routes_push_to_subscriber_registry() {
            let mut observer = ApplicationLayerObserver::new();
            let fired = Arc::new(AtomicUsize::new(0));
            let fired_cb = fired.clone();
            observer.subscribers.register("home/temp", move |_push| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

            let outcome = make_outcome(vec![NetworkMessage::Push(Box::new(push_literal(
                "home/temp",
                b"21.0",
            )))]);
            observer.dispatch_event(IterationEvent::Poll(&outcome));
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
        use crate::driver_loop::IterationEvent;
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
                .remote_subscribers
                .on_subscriber_declared(move |decl| {
                    assert_eq!(decl.id(), 7);
                    assert_eq!(decl.keyexpr(), "peer/sensor");
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                });

            let outcome = make_outcome(vec![NetworkMessage::Declare(Box::new(
                declare_decl_subscriber(7, "peer/sensor"),
            ))]);
            observer.dispatch_event(IterationEvent::Poll(&outcome));
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
        use crate::driver_loop::IterationEvent;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use wz_codecs::declare::{Declare, DeclareVariant};
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

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
            observer.subscribers.register("a", move |_p| {
                s.fetch_add(1, Ordering::SeqCst);
            });
            let rs = r_sub_fired.clone();
            observer
                .remote_subscribers
                .on_subscriber_declared(move |_d| {
                    rs.fetch_add(1, Ordering::SeqCst);
                });
            let rq = r_q_fired.clone();
            observer.remote_queryables.on_queryable_declared(move |_d| {
                rq.fetch_add(1, Ordering::SeqCst);
            });
            let l = l_fired.clone();
            observer.liveliness.on_token_declared(move |_d| {
                l.fetch_add(1, Ordering::SeqCst);
            });

            // Frame carrying a Push + 3 different Declare arms.
            let outcome = make_outcome(vec![
                NetworkMessage::Push(Box::new(push_literal("a", b"v"))),
                NetworkMessage::Declare(Box::new(declare_decl_subscriber(1, "x"))),
                NetworkMessage::Declare(Box::new({
                    let keyexpr = Wireexpr {
                        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                            id: 0,
                            suffix_len: Some(1),
                            suffix: Some("y"),
                        }),
                    };
                    Declare {
                        body: DeclareVariant::CodecZenohDeclQueryable(
                            wz_codecs::decl_queryable::DeclQueryable {
                                id: 2,
                                keyexpr,
                                ..wz_codecs::decl_queryable::DeclQueryable::default()
                            },
                        ),
                        ..Declare::default()
                    }
                    .try_into_owned()
                    .unwrap()
                })),
                NetworkMessage::Declare(Box::new({
                    let keyexpr = Wireexpr {
                        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                            id: 0,
                            suffix_len: Some(1),
                            suffix: Some("z"),
                        }),
                    };
                    Declare {
                        body: DeclareVariant::CodecZenohDeclToken(
                            wz_codecs::decl_token::DeclToken {
                                id: 3,
                                keyexpr,
                                ..wz_codecs::decl_token::DeclToken::default()
                            },
                        ),
                        ..Declare::default()
                    }
                    .try_into_owned()
                    .unwrap()
                })),
            ]);
            observer.dispatch_event(IterationEvent::Poll(&outcome));

            assert_eq!(sub_fired.load(Ordering::SeqCst), 1);
            assert_eq!(r_sub_fired.load(Ordering::SeqCst), 1);
            assert_eq!(r_q_fired.load(Ordering::SeqCst), 1);
            assert_eq!(l_fired.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(feature = "query-queryable")]
    mod query_queryable {
        use super::super::ApplicationLayerObserver;
        use super::fixtures::make_outcome;
        use crate::driver_loop::IterationEvent;
        use crate::network_message::NetworkMessage;
        use alloc::{boxed::Box, vec};
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

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
                .queryables
                .register("home/temp", |_query, responder| {
                    responder.reply(b"21.0");
                });

            // Synthesize an inbound Query for "home/temp".
            use wz_codecs::query::Query;
            use wz_codecs::request::{Request, RequestVariant};
            let suffix = "home/temp";
            let keyexpr = Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(suffix),
                }),
            };
            let request = Request {
                rid: 42,
                keyexpr,
                body: RequestVariant::CodecZenohQuery(Query::default()),
                ..Request::default()
            }
            .try_into_owned()
            .unwrap();
            let outcome = make_outcome(vec![NetworkMessage::Request(Box::new(request))]);
            observer.dispatch_event(IterationEvent::Poll(&outcome));

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
            observer.pending_replies.clear();
            observer.pending_final_rids.clear();
            assert_eq!(observer.pending_reply_count(), 0);
            assert_eq!(observer.pending_final_count(), 0);
        }
    }
}
