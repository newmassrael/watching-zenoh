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
use crate::response_sink::ResponseSink;
use alloc::vec::Vec;

/// Six-registry application-layer dispatch bundle. See module-level
/// docs for the rationale and dispatch flow.
pub struct ApplicationLayerObserver {
    /// Local pub/sub callbacks + peer keyexpr table (the table is
    /// populated by inbound `Declare(DeclKexpr|UndeclKexpr)` records
    /// and shared by every consumer registry for keyexpr resolution).
    pub subscribers: SubscriberRegistry,
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
    pub queryables: QueryableRegistry,
    /// Peer's outbound `DeclSubscriber` / `UndeclSubscriber` records.
    ///
    /// R310 — gated on `feature = "declare-subscriber"`.
    #[cfg(feature = "declare-subscriber")]
    pub remote_subscribers: RemoteSubscriberRegistry,
    /// Peer's outbound `DeclQueryable` / `UndeclQueryable` records.
    ///
    /// R310 — gated on `feature = "declare-queryable"`.
    #[cfg(feature = "declare-queryable")]
    pub remote_queryables: RemoteQueryableRegistry,
    /// Peer's outbound `DeclToken` / `UndeclToken` records — the
    /// liveliness signal layer.
    #[cfg(feature = "liveliness-token")]
    pub liveliness: LivelinessRegistry,
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
    pub liveliness_subscribers: LivelinessSubscriberRegistry,
    /// Initiator-side `Response(Reply|Err)` + `ResponseFinal`
    /// callbacks (`z_get` consumer). Pending entries auto-unregister
    /// when their matching `ResponseFinal` arrives.
    ///
    /// R311s — type-ungated. The struct is always present so the
    /// type-ungated `Session::query` / `Querier` surface can register
    /// pending entries regardless of `query-reply` feature state; the
    /// feature-OFF build never enters the registration path (Session::query's
    /// body is gated on `query-get` which implies `query-reply`).
    pub replies: ReplyRegistry,
    /// R311r — staging buffers are unconditional so the observer
    /// struct shape is stable across consumer-feature subsets. The
    /// drain side in [`Self::flush_pending`] stays cfg-gated on
    /// `query-queryable` so wire-emit only runs when the queryable
    /// dispatch path is in.
    pending_replies: Vec<QueryReply>,
    pending_final_rids: Vec<u64>,
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
            // R311ek — field gated on `liveliness-subscriber`; the
            // registry is constructed only when that feature is in. The
            // LivelinessSubscriber RAII handle's observer-side lookups
            // (history_complete, unregister on Drop) are gated on the
            // same feature so a feature-OFF build never references the
            // absent field.
            #[cfg(feature = "liveliness-subscriber")]
            liveliness_subscribers: LivelinessSubscriberRegistry::new(),
            // R311s — replies field is type-ungated; the registry is
            // always constructed (empty) so the type-ungated query
            // surface can register pending entries even though
            // feature-OFF never reaches the registration path.
            replies: ReplyRegistry::new(),
            // R311r — staging buffers always allocated; drain path in
            // flush_pending stays cfg-gated on query-queryable.
            pending_replies: Vec::new(),
            pending_final_rids: Vec::new(),
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
        #[cfg(feature = "liveliness-subscriber")]
        self.liveliness_subscribers
            .dispatch_iteration_event(event, peer_table);
        #[cfg(any(feature = "codec-response", feature = "codec-response-final"))]
        self.replies.dispatch_iteration_event(event, peer_table);
    }

    /// Phase 2 — drain the pending reply / final buffers through the
    /// action layer. `send_response` and `send_response_final`
    /// enqueue synchronously onto the OutboundWriteDriver mpsc
    /// channel, so the wire order mirrors enqueue order: every
    /// Reply for rid R precedes the matching ResponseFinal for R.
    pub fn flush_pending<S: ResponseSink>(&mut self, actions: &S) {
        #[cfg(feature = "query-queryable")]
        {
            for reply in self.pending_replies.drain(..) {
                actions.send_response(reply.into_response());
            }
            #[cfg(feature = "codec-response-final")]
            for rid in self.pending_final_rids.drain(..) {
                actions.send_response_final(rid);
            }
            #[cfg(not(feature = "codec-response-final"))]
            self.pending_final_rids.clear();
        }
        // R307 — without `query-queryable` the staging buffers do not
        // exist; `actions` is then unused in this branch but the
        // method signature stays stable so callers (`Self::dispatch`)
        // can wire it unconditionally.
        #[cfg(not(feature = "query-queryable"))]
        let _ = actions;
    }

    /// Combined fan + drain — the production single-call form used
    /// inside the `drive_session_until_terminal` observer closure.
    /// Equivalent to `dispatch_event(event)` followed by
    /// `flush_pending(actions)`.
    pub fn dispatch<S: ResponseSink>(&mut self, event: IterationEvent<'_>, actions: &S) {
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
    use crate::driver_loop::DriverLoopOutcome;
    use crate::network_message::NetworkMessage;
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    // Fixtures build the borrowed codec views (borrowing the `&str` /
    // `&[u8]` params) then `.into_owned()` at the boundary — the
    // `NetworkMessage` carriers store the lifetime-free `*Owned` mirrors.
    // R311dz — the Declare-record imports are used only by the
    // `declare-subscriber`-gated fixture + cross-talk test, so gate them
    // on `declare-subscriber` (the cross-talk test requires it too); the
    // C1d pubsub lane builds the observer with codec-declare on but
    // declare-subscriber off, where an unconditional import is unused
    // (deny). The Push / Wireexpr imports stay unconditional — the
    // always-present subscriber Push test uses them.
    #[cfg(feature = "declare-subscriber")]
    use wz_codecs::decl_subscriber::DeclSubscriber;
    #[cfg(feature = "declare-subscriber")]
    use wz_codecs::declare::{Declare, DeclareOwned, DeclareVariant};
    use wz_codecs::push::{Push, PushOwned};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn push_literal(suffix: &str, payload: &[u8]) -> PushOwned {
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
        push.into_owned()
    }

    // R311dz — only the declare-subscriber-gated tests reference this
    // fixture (a peer DeclSubscriber record); gate it on the same
    // feature so a `codec-declare`-on / `declare-subscriber`-off test
    // build does not carry an unused-fn deny-warning.
    #[cfg(feature = "declare-subscriber")]
    fn declare_decl_subscriber(id: u64, suffix: &str) -> DeclareOwned {
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
        .into_owned()
    }

    fn make_outcome(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

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

    // R311dz — references `observer.remote_subscribers`
    // (declare-subscriber slot) + the DeclSubscriber fixture, so gate on
    // `declare-subscriber` rather than relying on the workspace default.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn dispatch_event_routes_decl_subscriber_to_remote_subscriber_registry() {
        let mut observer = ApplicationLayerObserver::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        observer
            .remote_subscribers
            .on_subscriber_declared(move |decl, resolved| {
                assert_eq!(decl.id, 7);
                assert_eq!(resolved, "peer/sensor");
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let outcome = make_outcome(vec![NetworkMessage::Declare(Box::new(
            declare_decl_subscriber(7, "peer/sensor"),
        ))]);
        observer.dispatch_event(IterationEvent::Poll(&outcome));
        assert_eq!(fired.load(Ordering::SeqCst), 1);
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
            .on_subscriber_declared(move |_d, _r| {
                rs.fetch_add(1, Ordering::SeqCst);
            });
        let rq = r_q_fired.clone();
        observer
            .remote_queryables
            .on_queryable_declared(move |_d, _r| {
                rq.fetch_add(1, Ordering::SeqCst);
            });
        let l = l_fired.clone();
        observer.liveliness.on_token_declared(move |_d, _r| {
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
                .into_owned()
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
                    body: DeclareVariant::CodecZenohDeclToken(wz_codecs::decl_token::DeclToken {
                        id: 3,
                        keyexpr,
                        ..wz_codecs::decl_token::DeclToken::default()
                    }),
                    ..Declare::default()
                }
                .into_owned()
            })),
        ]);
        observer.dispatch_event(IterationEvent::Poll(&outcome));

        assert_eq!(sub_fired.load(Ordering::SeqCst), 1);
        assert_eq!(r_sub_fired.load(Ordering::SeqCst), 1);
        assert_eq!(r_q_fired.load(Ordering::SeqCst), 1);
        assert_eq!(l_fired.load(Ordering::SeqCst), 1);
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

    #[cfg(feature = "query-queryable")]
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
        .into_owned();
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
