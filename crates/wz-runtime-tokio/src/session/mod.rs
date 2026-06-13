// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R228 — application-level [`Session`] bundle.
//!
//! [`Session`] owns the outbound action handle ([`SessionLinkActions`])
//! and a shared reference to the inbound observer
//! ([`ApplicationLayerObserver`]) so a single [`Session::publish`] call
//! routes through both the wire-side codec and the in-process
//! subscriber loopback. Mirrors zenoh-pico's `_z_session_t`, which
//! similarly owns both the transport handle and the local subscription
//! table (`vendor/zenoh-pico/include/zenoh-pico/net/session.h` 172,
//! `vendor/zenoh-pico/src/net/primitives.c::_z_write` 170-205 fans the
//! outbound publish across `allows_remote()` / `allows_local()` from a
//! single entry point).
//!
//! ## Scope (R228 minimum-viable)
//!
//! * [`Session::publish`] handles literal-keyexpr Put + Del. Aliased
//!   (`mapping_id != 0`) publish is an R229 carry — the symmetric
//!   counterpart to [`crate::session_glue::SessionLinkActions::send_push_aliased`]
//!   will land as `publish_aliased` once a use case surfaces.
//! * [`PublishOptions`] carries the three load-bearing knobs
//!   (`allowed_destination`, `reliability`, `kind`). The remaining
//!   five [`crate::sample::Sample`] body fields (`qos`, `attachment`,
//!   `timestamp`, `encoding`, `source_info`) are R229+ carries —
//!   the wire path's `send_push_literal` currently does not accept
//!   them either, so propagating them through `Session::publish`
//!   would surface an asymmetry between the wire branch (loses the
//!   metadata) and the loopback branch (preserves it).
//! * `Session` is a NEW public surface introduced in parallel with
//!   the legacy direct-`SessionLinkActions` + direct-`ApplicationLayerObserver`
//!   pattern that `wz-ap-demo` and the integration suite still use.
//!   R230+ carry: migrate `wz-ap-demo` to `Session` and route every
//!   subscriber registration through `Session::observer().lock()`
//!   instead of directly on `observer.subscribers`.
//!
//! ## Locking discipline
//!
//! The observer is wrapped in the per-runtime synchronous [`Mutex`]
//! alias exposed by [`crate::sync`] (R311y option (a) per-runtime
//! type alias; R311ar trait shape mechanical land). On the AP profile
//! this resolves to [`std::sync::Mutex`]; the future MCU profiles
//! (`wz-runtime-lwip` / `wz-runtime-embassy`) will rebind the alias
//! to a profile-native synchronous lock with the same
//! exclusive-access semantic (e.g. `critical_section::Mutex<T>` on
//! single-core MCU, `embassy_sync::Mutex<RawMutex, T>` on
//! multi-priority embassy executors). The choice of a *synchronous*
//! lock (over [`tokio::sync::Mutex`] or its embassy async-mutex
//! equivalents) reflects the loopback branch's contract: subscriber
//! callbacks run synchronously — exactly the semantic of a locally-
//! published Sample under zenoh-pico's
//! `_z_session_deliver_push_locally`
//! (`vendor/zenoh-pico/src/session/loopback.c` 70-100) which fires
//! the subscription callbacks in-line under the session lock. A
//! `tokio::sync::Mutex` would force `publish` to be `async`, which
//! would in turn force callers to be `async`, propagating a
//! coloring change for no measurable benefit — the lock window is
//! the time it takes to walk the subscriber table once. R311as
//! migration replaces the previous direct `std::sync::Mutex` import
//! with the alias so the eventual `Session<R: Runtime, T:
//! TimeSource>` reparam (R311at+) lifts to `Arc<R::Mutex<...>>`
//! mechanically; the underlying type on the AP profile is unchanged.
//!
//! ## Wire / loopback symmetry today (R228) vs zenoh-pico
//!
//! zenoh-pico's `_z_write` constructs the same [`crate::sample::Sample`]-
//! shaped record once and routes both branches off the same record.
//! wz at R228 constructs the wire-side `Push` via the legacy
//! `send_push_literal` / `send_push_del_literal` builders AND
//! constructs the loopback-side `Sample` via the `new_put` / `new_del`
//! builder — two separate constructions. R229+ candidate: unify the
//! construction so both branches read the same source struct (an
//! intermediate `PublishRecord` that the wire side encodes and the
//! loopback side projects to `Sample`).

use std::sync::Arc;
// R311as — Session<observer> migrates from direct `std::sync::Mutex`
// to the per-runtime synchronous lock alias exposed by
// [`crate::sync::Mutex`] (R311y option (a) per-runtime type alias;
// R311ar trait shape lock). The alias resolves to
// `std::sync::Mutex<T>` on the AP profile (no behavioural change);
// the future MCU profiles re-bind the same name to a profile-native
// synchronous lock so the eventual `Session<R: Runtime, T:
// TimeSource>` reparam (R311at+) lifts to `Arc<R::Mutex<...>>`
// mechanically. Closes the §5.P "Session-last" gate raised at R311x.
// R311da — after Session::new lifted to impl<R, T> Session<R, T>
// (the observer parameter now reads `Arc<<R as Runtime>::Mutex<...>>`,
// no longer the crate-level `Mutex<...>` alias), production-side code
// in session.rs stops referring to the `Mutex` alias name. Tests still
// use it (`Arc::new(Mutex::new(ApplicationLayerObserver::new()))`),
// so the import is cfg(test)-gated to keep test compilation working
// without producing an unused-import lint on the lib build.
#[cfg(test)]
use crate::sync::Mutex;

// R307 — `wz_codecs::query::Query` is referenced bare only by the
// loopback fan inside `Session::query` (`Query::default()`); the
// `declare_queryable` callback signature uses the fully-qualified
// path so it does not consume this `use`.
// R311fq — the loopback fan is now `query-queryable`-gated (decoupled
// from `query-get`), so this import follows `all(query-get,
// query-queryable)` — its sole call site.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
use wz_codecs::query::Query;
// R311s — `TimeSource` is the generic-parameter bound on the
// type-ungated `Session::query` + `Querier::get` + `QuerierAliased::get`
// surfaces; the import stays unconditional alongside those methods.
use wz_runtime_core::Runtime;
use wz_runtime_core::TimeSource;
// Stage 2b — `Session<R, T>` (and every handle that wraps it) holds an
// `Arc<SessionLinkActions<R, T>>`, which now bounds `R: SessionRuntime`
// (the runtime-tier owner of `R::LinkSink`). `SessionRuntime: Runtime`,
// so the `<R as Runtime>::Mutex<...>` field types still resolve.
use wz_session_core::link::SessionRuntime;

use crate::runtime_impl::TokioRuntime;
// R311cw — `TokioTime` is the AP-profile default binding for the
// new `T: TimeSource` 2nd type parameter on `Session<R, T>` and on
// the `Querier<R, T>` / `QuerierAliased<R, T>` helper cascade. The
// `TokioSession` / `TokioQuerier{,Aliased}` type aliases name it
// explicitly so the default-param shape is documented at the alias
// site rather than relying on the struct definition's default.
use crate::runtime_impl::TokioTime;

// R311q — `LivelinessSample` is type-ungated because the unconditional
// `Session::declare_liveliness_subscriber{_aliased}` Result-form
// signatures bind it as the callback parameter type. R311gb-3d — the
// `BoxedLivelinessSampleSink` seam adapter is only referenced inside the
// cfg-gated body of those methods (it wraps the `impl FnMut(LivelinessSample)`
// closure before the registry `register` call), so it follows the body
// gate; the split prevents an `unused import` lint on the feature-OFF build.
#[cfg(feature = "liveliness-subscriber")]
use crate::declare::BoxedLivelinessSampleSink;
// R311mn (B2) — `LivelinessSample` is the callback parameter type of the
// `transport-unicast`-gated `declare_liveliness_subscriber{_aliased}`
// methods (and is re-exported into the gated `liveliness` submodule); gate
// the import so a multicast-only build does not flag it unused.
#[cfg(feature = "transport-unicast")]
use crate::declare::LivelinessSample;
// R311o — `OutboundKeyexprError` is wrapped by
// `LivelinessAliasError::InvalidKeyexpr` which is itself unconditional
// after the R311o type-ungating cascade; the import must therefore be
// unconditional too.
// R311mn (B2) — `LivelinessAliasError` lives in the `transport-unicast`-
// gated `liveliness` submodule, the sole consumer of this import, so it now
// follows the same gate.
#[cfg(feature = "transport-unicast")]
use crate::keyexpr_canon::OutboundKeyexprError;
use crate::locality::Locality;
use crate::observer::ApplicationLayerObserver;
use crate::pubsub::SubscriptionId;
// R311gb-2b — the subscriber registry now delivers `&dyn SampleView`
// (the sink seam accessor contract) rather than the owned `&Sample`.
use crate::sink::SampleView;
// R311r — `crate::query` is type-ungated; `QueryableId` follows the
// same shape (always available). `QueryReply` is only referenced from
// `Session::query`'s loopback fan; R311fq gated that fan on
// `query-queryable`, so this import now follows
// `all(query-get, query-queryable)` to match the sole call site.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
use crate::query::QueryReply;
// R311mn (B2) — `QueryableId` names a queryable-plane id used only by the
// `transport-unicast`-gated `queryable` submodule (via `use super::*`) and
// the gated query loopback; gate it so the multicast-only build does not see
// an unused import.
#[cfg(feature = "transport-unicast")]
use crate::query::QueryableId;
// R311gb-3b — the queryable callback signature dispatches through the
// model-B query seam contracts (`QueryView` inbound accessor +
// `ReplyOut` outbound emit). Both traits are unconditional so the
// type-ungated `Session::declare_queryable{_aliased}` Result-form
// signatures compile in any consumer-feature subset; the registry hands
// the handler `&dyn QueryView` + `&mut dyn ReplyOut` (the reply
// accumulator `QueryResponder` impls `ReplyOut` directly, and the
// dispatch builds a `BorrowedQuery` for the `QueryView` —
// R311gb-3b-cleanup).
// R311mn (B2) — the `QueryView` / `ReplyOut` seam traits are named only by
// the `transport-unicast`-gated `declare_queryable{_aliased}` signatures
// (and the gated `queryable` submodule via `use super::*`); gate so the
// multicast-only build is unused-import clean.
#[cfg(feature = "transport-unicast")]
use crate::query_sink::{QueryView, ReplyOut};
// R311s — `crate::reply` is type-ungated; `ReplyHandle` is the inner
// success value of [`Session::query`]'s `Result<ReplyHandle, ...>` and is
// used unconditionally. R311gb-3c — the z_get `on_reply` callback now
// dispatches through the `ReplyView` accessor contract (`&dyn ReplyView`,
// also unconditional — the signatures are type-ungated), not the owned
// `&InboundReply`. `InboundReply` is now named only on the
// `query-queryable` loopback path (the `QueryReply -> InboundReply`
// projection fed into `deliver_local_reply`) + its tests, so the import
// follows that gate; a `query-queryable`-OFF subset (e.g. handshake-only)
// would otherwise see it unused. R311lg — the deferred reply staging
// sink copies each inbound reply into the owned `InboundReply` form, so
// the import widens to plain `query-get` (the staging sink exists on
// every getter build, queryable plane or not). R311lk — the
// liveliness-get plane installs the same staging sink (it does NOT imply
// `query-get`), so the import follows the `deferred_reply_sink` gate:
// `any(query-get, liveliness-get)`.
#[cfg(any(feature = "query-get", feature = "liveliness-get"))]
use crate::reply::InboundReply;
// R311mn (B2) — `ReplyHandle` is the success value of the
// `transport-unicast`-gated `query{,_aliased,_aliased_auto}` methods (and is
// re-exported into the gated `querier` submodule); `ReplyView` is the z_get
// reply seam those same gated methods + `liveliness_get` consume. Both are
// unused in a multicast-only build, so they follow `transport-unicast`.
#[cfg(feature = "transport-unicast")]
use crate::reply::ReplyHandle;
#[cfg(feature = "transport-unicast")]
use crate::reply_sink::ReplyView;
// R311mn (B2) — the `Sample` metadata-hint enums feed the
// `transport-unicast`-gated publish path + `build_loopback_sample` (in the
// gated `publisher` submodule) + the `query`/`queryable` metadata builders;
// none are named by the agnostic surface, so gate the import on
// `transport-unicast` to keep the multicast-only build unused-import clean.
#[cfg(feature = "transport-unicast")]
use crate::sample::{EncodingHint, QosLevel, Reliability, SampleKind, SourceInfo, TimestampHint};
// R311gb-2b — `declare_subscriber` no longer names `Sample` (it now
// takes `impl FnMut(&dyn SampleView)`), so the only remaining uses of
// the owned `Sample` type are the `pubsub-allow-loop` loopback assembly
// (`build_loopback_sample`) and the test module. Gate the import to
// match, keeping a feature-restricted lib build warning-clean.
#[cfg(any(test, feature = "pubsub-allow-loop"))]
use crate::sample::Sample;
// R311mn (B2) — every `session_glue` import gains a `transport-unicast`
// conjunct: `session_glue` is `#[cfg(feature = "transport-unicast")]`, so
// in a multicast-only build the module (and these types) do not exist.
// The consumers (the gated unicast `Session` methods + the gated
// submodules) all carry the same `transport-unicast` gate, so ANDing it in
// here is a no-op in a unicast-on build and elides a dangling import in a
// multicast-only build.
#[cfg(all(feature = "liveliness-token", feature = "transport-unicast"))]
use crate::session_glue::SendDeclareError;
#[cfg(feature = "transport-unicast")]
use crate::session_glue::SendWireError;
#[cfg(feature = "transport-unicast")]
use crate::session_glue::SessionLinkActions;
// W3 — PushMetadata is consumed only by the `codec-push`-gated
// `PublishOptions::push_metadata`, so the import carries the same gate.
#[cfg(all(feature = "codec-push", feature = "transport-unicast"))]
use crate::session_glue::PushMetadata;
// R311o — `QueryTarget` / `ConsolidationMode` are referenced from
// the now-unconditional `QueryOptions` struct fields + builder
// bodies, so they import unconditionally. `QueryMetadata` is only
// returned by the private `query_metadata` helper which stays gated
// on `query-get` (the helper is dead-code under the lower gate), so
// its import follows the same gate.
#[cfg(all(feature = "query-get", feature = "transport-unicast"))]
use crate::session_glue::QueryMetadata;
#[cfg(feature = "transport-unicast")]
use crate::session_glue::{ConsolidationMode, QueryTarget};

// Per-cluster handle submodules split out of this file (pure refactor).
// Each holds one responsibility cluster (its options + handle + error
// types and their impls); `pub use <mod>::*` preserves the public
// `wz_runtime_tokio::session::<Type>` paths unchanged.
//
// R311mn (Level B, B2) — the four UNICAST clusters (publisher / querier /
// queryable / liveliness) are gated `transport-unicast`: each names a
// `session_glue` type (`SendWireError` / `PushMetadata` / `QueryMetadata` /
// `QueryTarget` / `ConsolidationMode`) or projects the unicast transport
// variant (`self.actions()`), so they do not compile in a multicast-only
// build. The three remaining clusters (subscriber / decl_listener /
// matching_listener) touch only the transport-AGNOSTIC observer surface
// (`self.session.observer()` / `deferred_sample_sink`), so they stay
// ungated and compile in every transport configuration. Each `mod X;` is
// gated together with its `pub use X::*;` so the re-export disappears in
// lockstep with the module.
mod decl_listener;
#[cfg(feature = "transport-unicast")]
mod liveliness;
mod matching_listener;
#[cfg(feature = "transport-unicast")]
mod publisher;
#[cfg(feature = "transport-unicast")]
mod querier;
#[cfg(feature = "transport-unicast")]
mod queryable;
mod subscriber;
// R311mm (Level B, B1) — the per-session transport sum; internal-only
// (`SessionTransport` is `pub(crate)`), so it gets no `pub use` re-export.
mod transport;
pub use decl_listener::*;
#[cfg(feature = "transport-unicast")]
pub use liveliness::*;
pub use matching_listener::*;
#[cfg(feature = "transport-unicast")]
pub use publisher::*;
#[cfg(feature = "transport-unicast")]
pub use querier::*;
#[cfg(feature = "transport-unicast")]
pub use queryable::*;
pub use subscriber::*;
use transport::SessionTransport;

/// Application-level session bundle. Owns the outbound action handle
/// plus a shared reference to the inbound observer so a single call
/// to [`Session::publish`] routes both branches per the
/// `allowed_destination` predicate on [`PublishOptions`].
///
/// See module-level docs for the wire / loopback symmetry contract,
/// the locking discipline, and the R228 → R229+ carry map.
///
/// `Clone` is cheap (both fields are `Arc`) — application code spawns
/// background tasks (publisher / query / declare emitters) with their
/// own `Session` clone so the task can call `publish` /
/// `publish_aliased_auto` without re-deriving the bundle. Every clone
/// shares the same outbound actions and the same observer mutex, so
/// loopback dispatches from a background task are observable to the
/// main `drive_session` loop's `observer.dispatch` calls and vice
/// versa.
pub struct Session<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    /// Outbound action handle. Cloned `Arc` — multiple `Session`s
    /// can share the same actions if the application binds several
    /// publish surfaces to the same physical session. R311di-pre-f1b
    /// binds the actions' TimeSource parameter to the same `T` as
    /// the surrounding Session so the action bundle's `clock` field
    /// (R311di-pre-f1 reparam) shares the monotonic epoch with the
    /// Session's own `clock: Arc<T>` slot — the R311cw single-epoch
    /// invariant ("single Session value owns the monotonic epoch
    /// its background sweep + per-call deadlines share") now extends
    /// to the action bundle by type.
    ///
    /// R311mm (Level B, B1) — the field is now the [`SessionTransport`] sum
    /// (B1 inhabits only `Unicast`, wrapping the same
    /// `Arc<SessionLinkActions<R, T>>`); the [`Self::actions`] accessor
    /// projects the unicast handle. See `session::transport` for why a sum
    /// type, not a trait object.
    transport: SessionTransport<R, T>,
    /// Inbound observer wrapped in the per-runtime mutex alias
    /// (`R::Mutex<...>` — R311ar GAT) so [`Session::publish`]'s
    /// loopback branch can borrow the subscriber registry through
    /// the same handle the main dispatch loop uses. R267 cascade
    /// lifts this from the prior `Arc<crate::sync::Mutex<...>>`
    /// (R311as alias-pierced) to the trait-projected form so MCU
    /// profiles can bind their own mutex (`embassy_sync::Mutex<...>`,
    /// `critical_section::Mutex<...>`) without touching this field.
    observer: Arc<<R as Runtime>::Mutex<ApplicationLayerObserver>>,
    /// R311kz — per-session deferred-fire queue (the F-6 fix): the
    /// matching-listener sinks installed in the registries stage their
    /// fires here (under the observer lock), and the drive-loop
    /// dispatch site drains it through [`Self::drain_deferred_fires`]
    /// AFTER the observer lock drops — so the user callbacks run
    /// lock-free and may re-enter any observer-locking session API.
    /// Cheap-`Clone` handle (Arc inside), shared with every deferred
    /// sink this session registers.
    ///
    /// R311lc — the decl-sink planes' staging sinks (decl_listener.rs)
    /// share this queue; R311lg added the first data planes
    /// (liveliness samples + z_get reply/final). R311lh — the field is
    /// UNCONDITIONAL: the always-compiled subscriber plane defers
    /// (R311lf round (b)), so every Session build needs the queue.
    /// This host-only crate's `wz-session-core` dependency enables the
    /// `deferred-fire` consumer arm, so the core module exists in
    /// every feature subset here; the prior six-feature cfg union
    /// (R311le forced-inline) is superseded for this tier — core keeps
    /// its plane-arm union for direct consumers.
    fires: wz_session_core::deferred_fire::DeferredFireQueue<R>,
    /// R311cw — the trait-mediated monotonic clock the query / get
    /// methods use to compute reply-pending deadlines. Folded from
    /// the prior method-level `<T: TimeSource>` generic into a
    /// type-level parameter so a single Session value owns the
    /// monotonic epoch its background sweep + per-call deadlines
    /// share, closing the R311w "Session-last" reparam target (T
    /// fold-in pending since R311ab carry).
    ///
    /// Held behind `Arc` so cheap `Session::clone` is unchanged —
    /// every helper (Querier / QuerierAliased / Publisher /
    /// Subscriber / Queryable / LivelinessToken /
    /// LivelinessSubscriber) propagates its own Session clone, and
    /// the Arc-shared clock keeps the same monotonic anchor across
    /// all helper-issued query / get calls. AP-profile T binds to
    /// [`TokioTime`] (Copy), MCU profile will bind to
    /// `wz_runtime_lwip::LwipTime<C>` once Session moves to a
    /// runtime-agnostic crate (post-R311cw architectural step).
    clock: Arc<T>,
}

// R267 cascade — manual Clone impl avoids the derive(Clone) auto-added
// `R: Clone` + `T: Clone` bounds. Neither `Runtime` nor `TimeSource`
// requires `Clone` (instances are zero-sized or carry small handles,
// and all three fields are `Arc<...>` — `Arc<X>: Clone` for any `X`,
// so the inner mutex alias's and TimeSource impl's Clone-status are
// irrelevant). R311cw extends the bound set with `T: TimeSource` so
// `Session<R, T>` clones uniformly across both type parameters.
impl<R: SessionRuntime, T: TimeSource> Clone for Session<R, T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            observer: self.observer.clone(),
            fires: self.fires.clone(),
            clock: self.clock.clone(),
        }
    }
}

/// R311cq — explicit alias for the tokio-runtime-bound Session. The
/// bare `Session` name still resolves to this through the R267
/// default-param `Session<R: Runtime = TokioRuntime, T: TimeSource =
/// TokioTime>`, so existing call sites stay unchanged. The alias
/// surfaces the runtime binding explicitly for downstream code that
/// wants its signatures to read `fn x(s: TokioSession)` rather than
/// `fn x(s: Session)` — useful once the R267 helper cascade lands
/// and wz-runtime-lwip surfaces its own
/// `LwipSession<C> = Session<LwipRuntime<C>, LwipTime<C>>` alias so
/// the two runtimes compose side-by-side without bare-`Session`
/// ambiguity. R311cw extended the alias's second slot from inferred
/// `TimeSource = TokioTime` default to explicit naming so the
/// Session<R, T> shape reads literally at the alias site.
pub type TokioSession = Session<TokioRuntime, TokioTime>;

// R311mn (Level B, B2) — the TRANSPORT-AGNOSTIC `Session` surface. These
// methods read the transport-independent fields (`observer` / `fires` /
// `clock`) without ever projecting the transport sum's unicast variant
// (no `self.actions()`, no `session_glue` type), so they compile in EVERY
// transport configuration — unicast-only, both, AND the new
// multicast-only build. They are split out of the (now `transport-unicast`-
// gated) big impl block below precisely so a multicast-only `Session` still
// exposes observer / clock / deferred-fire-drain / zid-dedup. The unicast
// publish / query / declare surface stays in the gated block.
impl<R: SessionRuntime, T: TimeSource> Session<R, T> {
    /// R311mn (Level B, B2) — construct a multicast `Session` from the shared
    /// observer + clock (the handshake-free multicast transport has no
    /// `SessionLinkActions` bundle). R311mo (B3) adds the `codec-push`-gated
    /// `tx` argument: the sender half of the channel
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// drains, so [`Self::publish`] can enqueue onto it (a bare multicast
    /// build with no data plane omits `tx` and gets an RX-only session).
    /// Gated `all(transport-multicast, not(transport-unicast))` to mirror the
    /// `SessionTransport::Multicast` variant gate (see `session::transport`).
    #[cfg(all(feature = "transport-multicast", not(feature = "transport-unicast")))]
    pub fn new_multicast(
        observer: Arc<<R as Runtime>::Mutex<ApplicationLayerObserver>>,
        clock: Arc<T>,
        #[cfg(feature = "codec-push")] tx: tokio::sync::mpsc::UnboundedSender<
            wz_session_core::multicast_tx::MulticastTxItem,
        >,
    ) -> Self {
        Self {
            transport: SessionTransport::Multicast {
                #[cfg(feature = "codec-push")]
                tx,
                _marker: core::marker::PhantomData,
            },
            observer,
            fires: wz_session_core::deferred_fire::DeferredFireQueue::new(),
            clock,
        }
    }

    /// R311mo (Level B, B3) / R311mp (Level B, B4) — publish a literal-keyexpr
    /// Put over the multicast transport. Two legs, mirroring the unicast
    /// [`Session::publish`]:
    ///
    /// * **Remote leg** (B3): the wire send is an ENQUEUE onto the multicast
    ///   TX seam — the `MulticastTxItem::Push` built by
    ///   [`multicast_put_literal`](wz_session_core::multicast_tx::multicast_put_literal)
    ///   is pushed onto the channel
    ///   [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    ///   drains, which mints the per-channel SN, frames it, and multicasts to
    ///   the group (the A1c TX seam). Fire-and-forget — like the unicast wire
    ///   leg — so a closed channel (the drive loop dropped its receiver) is
    ///   silently ignored; the session is defunct at that point.
    /// * **Local loopback leg** (B4, `pubsub-allow-loop`-gated): the same Put
    ///   is delivered in-process to this session's matching subscribers via
    ///   [`crate::pubsub::SubscriberRegistry::local_publish`], then the
    ///   deferred-fire queue is drained so the subscriber callbacks run on the
    ///   caller thread OUTSIDE the observer lock — byte-for-byte the unicast
    ///   loopback leg's discipline (R227+ / R311lh / R311lj). Returns the
    ///   number of local subscriber callbacks the loopback fired (0 when
    ///   `pubsub-allow-loop` is off, exactly like the unicast `publish`).
    ///
    /// A `Locality::SessionLocal`/`Any` subscriber declared through
    /// [`Self::declare_subscriber`] (B4, now transport-agnostic) fires on this
    /// loopback; a `Locality::Remote`-only one is suppressed
    /// (`local_publish` passes `is_remote = false`). The loopback Sample is a
    /// plain Put — B4 carries no `PublishOptions`, so there are no metadata
    /// fields to thread (the unicast `build_loopback_sample` machinery becomes
    /// shared only once multicast `publish` grows opts, a follow-on like the
    /// Del / aliased / reliability surface the unicast `publish` grew at R229+).
    ///
    /// Gated on `codec-push` (the Put data plane) AND
    /// `all(transport-multicast, not(transport-unicast))` so it never collides
    /// with the unicast `publish` in a both-transports build.
    #[cfg(all(
        feature = "transport-multicast",
        not(feature = "transport-unicast"),
        feature = "codec-push"
    ))]
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
    ) -> Result<usize, sce_forge_runtime::codec::CodecError> {
        // Remote leg (B3): mint nothing here — enqueue onto the TX seam the
        // drive loop drains. A capacity overflow fails the whole publish before
        // the loopback runs (the unicast remote leg `?`s for the same reason).
        let item = wz_session_core::multicast_tx::multicast_put_literal(keyexpr, payload)?;
        match &self.transport {
            SessionTransport::Multicast { tx, .. } => {
                let _ = tx.send(item);
            }
        }
        // Local loopback leg (B4): deliver to in-process subscribers + drain
        // the staged fires on the caller thread, mirroring the unicast publish
        // loopback. cfg-off short-circuits to 0 (remote-only).
        #[cfg(feature = "pubsub-allow-loop")]
        {
            let sample = Sample::new_put(keyexpr, payload.to_vec());
            let delivered = R::with_mutex_mut(&self.observer, |observer| {
                observer.subscribers.local_publish(&sample)
            });
            // R311lh / R311lj — run the loopback subscriber callbacks
            // synchronously, outside the observer lock, before `publish`
            // returns (the observer-serialized batch take keeps a concurrent
            // drive-loop batch atomic).
            self.drain_deferred_fires();
            Ok(delivered)
        }
        #[cfg(not(feature = "pubsub-allow-loop"))]
        Ok(0)
    }

    /// R311mq (Level B, B5a) — the MULTICAST dispatch SSOT: fan one
    /// drive-loop [`IterationEvent`](wz_session_core::driver_loop::IterationEvent)
    /// into THIS session's observer under its lock, then drain the
    /// deferred-fire queue after the lock drops. The multicast analogue of
    /// the unicast [`Self::dispatch_iteration_event`], MINUS the unicast
    /// reply flush: that method's `flush_pending_replies` +
    /// `take_pending_final_rids` legs thread the unicast `SessionLinkActions`
    /// handle a multicast session has no analogue of, and the multicast
    /// reply plane (queryable `Response` / declarer `Declare`) drains
    /// separately through
    /// [`MulticastReplySink`](crate::multicast_glue::MulticastReplySink). So
    /// this method carries ONLY the dispatch + drain pairing the deferred
    /// subscriber plane needs — the same `dispatch -> (lock drops) -> drain`
    /// discipline the F-6 contract mechanizes so a dispatch site cannot
    /// forget the drain.
    ///
    /// Wire the multicast drive loop's `on_event` to this so a subscriber
    /// declared through [`Self::declare_subscriber`] (B4) — whose deferred
    /// staging sink stages onto THIS session's `fires` — fires on a
    /// wire-arrived multicast Frame. B4 left that wire-RX leg unconnected:
    /// the standalone
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// loop dispatched into a free-standing observer and never drained the
    /// session's queue, so a Session-declared deferred subscriber saw
    /// loopback Puts but not wire ones. Canonical closure:
    ///
    /// ```text
    /// drive_multicast_session(
    ///     .., |event| session.dispatch_multicast_iteration_event(event), ..)
    /// ```
    ///
    /// Gated `transport-multicast` (it is meaningful only for a multicast
    /// session); a unicast session uses [`Self::dispatch_iteration_event`],
    /// which additionally flushes the unicast reply plane.
    #[cfg(feature = "transport-multicast")]
    pub fn dispatch_multicast_iteration_event(
        &self,
        event: wz_session_core::driver_loop::IterationEvent<'_>,
    ) {
        R::with_mutex_mut(&self.observer, |obs| {
            obs.dispatch_event(event);
        });
        self.drain_deferred_fires();
    }

    /// Borrow the observer handle. Application code registers
    /// callbacks on the contained registries through this — typically
    /// `session.observer().lock().unwrap().subscribers.register(...)`
    /// on the AP profile (where `R::Mutex<T>` resolves to
    /// `std::sync::Mutex<T>`); generic-R callers must route through
    /// [`wz_runtime_core::Runtime::with_mutex_mut`] instead since the
    /// `Runtime` trait does not expose a direct `.lock()` method
    /// across profiles.
    pub fn observer(&self) -> &Arc<<R as Runtime>::Mutex<ApplicationLayerObserver>> {
        &self.observer
    }

    /// R311kz — drain the deferred-fire queue, running every staged
    /// listener callback (matching listeners, the R311lc decl
    /// listeners, and the R311lg data-plane callbacks — liveliness
    /// samples + z_get reply/final) OUTSIDE the observer mutex (the
    /// F-6 deferred-fire contract). The drive-loop dispatch site calls
    /// this once per iteration event, AFTER its `observer` lock scope
    /// ends:
    ///
    /// ```text
    /// { observer.lock().dispatch(event, &actions); }  // lock dropped
    /// session.drain_deferred_fires();                 // callbacks run free
    /// ```
    ///
    /// The callbacks may therefore re-enter any observer-locking
    /// session API — `get_matching_status`, declares, further listener
    /// registration, even their own `MatchingListener::undeclare` —
    /// without self-deadlocking. Fires staged BY a running callback are
    /// drained in the same call (the queue loops until empty). Returns
    /// the number of callbacks run.
    ///
    /// An undrained queue delays fires until the next drain; it never
    /// drops them — but a dispatch site that never drains starves every
    /// deferred listener, so any custom drive closure that dispatches
    /// this session's observer MUST pair it with a drain.
    ///
    /// R311lh — unconditional body (no more feature-union fork): the
    /// always-compiled subscriber plane defers, so a deferred sink can
    /// exist in every feature subset of this host-only crate and the
    /// queue field is always present.
    ///
    /// R311lm — delegates to the single serialized drain SSOT
    /// ([`wz_session_core::deferred_fire::DeferredFireQueue::drain`]),
    /// passing the observer mutex as the serializer. The discipline that
    /// closes the Finding-A Reply-before-Final hazard (R311li review,
    /// R311lj fix) — take each batch under the observer lock so a take
    /// observes only whole staging windows — now lives THERE, enforced
    /// structurally: `take_batch` is `pub(crate)`, so `drain` is the only
    /// representable way to empty the queue and an auxiliary drainer (a
    /// query-tail / publish / sweep drain) physically cannot `mem::take`
    /// a half-staged window. Jobs run OUTSIDE the lock (the lock-free
    /// callback invariant), so a callback may re-enter any
    /// observer-locking session API; the drain loops until empty.
    ///
    /// MUST be called with the observer lock RELEASED (the standing
    /// drain-after-dispatch contract); calling it while holding the
    /// observer lock self-deadlocks on the first take.
    pub fn drain_deferred_fires(&self) -> usize {
        self.fires.drain(&self.observer)
    }

    /// R311cy — borrow the Session-owned clock (R311cw fold-in
    /// stored `clock: Arc<T>`). Callers that need to thread the same
    /// monotonic epoch into a peer task (sweep_task,
    /// drive_session_until_terminal, etc.) clone this Arc rather
    /// than rebuilding a separate `T` instance which would carry a
    /// fresh epoch.
    pub fn clock(&self) -> &Arc<T> {
        &self.clock
    }

    /// R231 — forward this session's own zid (1..=16 bytes) to the
    /// inbound subscriber registry so wire-arrived self-echoes (a
    /// `Locality::Any` publish that the network routes back to its
    /// publisher) are recognised by
    /// [`crate::pubsub::SubscriberRegistry::dispatch_push`] and
    /// suppressed before the local callback fires a second time.
    ///
    /// Returns `true` when the registry accepted the install,
    /// `false` when `zid.len()` was outside `1..=16` (the wire-form
    /// `_z_id_t` range) — an invalid length is a hard reject so a
    /// buggy caller cannot accidentally silence dedup with a
    /// length-0 or length-17 input.
    ///
    /// Production deployment path: the session-FSM open handshake
    /// settles with both peers' zids known
    /// (`SessionInitParams.zid` is the local zid passed into
    /// outbound `InitSyn`; the peer's zid lands in
    /// [`crate::session_glue::SessionLinkActions::inbound_peer_zid`]).
    /// The local zid is therefore already authoritative at
    /// [`Session::new`] time, so R236 wires the install
    /// automatically from `actions.params.zid` — the application
    /// no longer needs to call this method explicitly after the
    /// handshake completes. The method remains public for two
    /// scenarios: (1) explicit override when the application
    /// derives a per-session zid outside the
    /// `SessionInitParams` block (rare but supported), and
    /// (2) session re-init flows where a prior
    /// [`Session::clear_own_zid`] released the install and the
    /// caller now wants to reinstate the dedup guard with the
    /// same or a different zid.
    ///
    /// R311cz — migrated from direct `self.observer.lock().expect()` to
    /// the [`wz_runtime_core::Runtime::with_mutex_mut`] closure form
    /// (R311ct API). Per-runtime poison-recovery semantics live inside
    /// the impl: tokio recovers via PoisonError::into_inner, MCU
    /// profiles whose mutex has no poison concept just acquire and
    /// drop the guard at closure exit. Lifts this method to the
    /// R-generic impl block.
    pub fn set_own_zid(&self, zid: Vec<u8>) -> bool {
        R::with_mutex_mut(&self.observer, |observer| {
            observer.subscribers.set_own_zid(zid)
        })
    }

    /// R231 — release the previously-installed own zid (paired with
    /// [`Session::set_own_zid`]). After clear, every wire-arrived
    /// Push fires its matching subscribers; the self-echo guard
    /// stays disabled until a fresh `set_own_zid` install. Useful
    /// in session re-init / close scenarios where the prior zid
    /// must not bleed into a new session's dispatch state.
    ///
    /// R311cz — see [`Self::set_own_zid`] for the R::with_mutex_mut
    /// migration rationale.
    pub fn clear_own_zid(&self) {
        R::with_mutex_mut(&self.observer, |observer| {
            observer.subscribers.clear_own_zid();
        });
    }

    /// R245 — declare a [`Subscriber`] for `keyexpr` + `options`
    /// that fires `callback` on every matching inbound `Sample`.
    /// Returns a [`Subscriber`] handle whose `Drop` auto-unregisters
    /// the subscription from the underlying
    /// [`crate::pubsub::SubscriberRegistry`] (RAII).
    ///
    /// Mirrors zenoh-pico's `z_declare_subscriber` shape: caller
    /// supplies the keyexpr pattern + options + callback at declare
    /// time; the runtime fires the callback synchronously inside
    /// [`crate::pubsub::SubscriberRegistry::dispatch_push`] (wire
    /// arrival) and
    /// [`crate::pubsub::SubscriberRegistry::local_publish`]
    /// (loopback, R227+). No wire frame is emitted at declare time —
    /// `Declare(DeclareSubscriber)` is a router-mode feature wz
    /// elides today (peer-only) per the same router-less rationale
    /// as [`Self::declare_publisher`].
    ///
    /// R311mp (Level B, B4) — TRANSPORT-AGNOSTIC: this method reads only
    /// `self.fires` (via `deferred_sample_sink`) + the observer's
    /// subscriber registry, never `self.actions()`, so it was lifted out
    /// of the (now `transport-unicast`-gated) big impl block into this
    /// ungated one. A multicast-only `Session` therefore declares
    /// subscribers through the same surface — the handle type
    /// [`Subscriber`] is already transport-agnostic (it owns only the
    /// `SubscriptionId` + the deferred cell + a `Session` clone, no
    /// transport payload). The multicast LOOPBACK leg of
    /// [`Self::publish`] fires these subscribers in-process; the
    /// multicast WIRE-RX leg reaches them once the drive loop shares this
    /// session's observer + drains its `fires` after dispatch (the B5
    /// both-build unification — until then the multicast drive loop
    /// dispatches into a standalone observer with raw `register`).
    pub fn declare_subscriber(
        &self,
        keyexpr: impl Into<String>,
        options: SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Subscriber<R, T> {
        let keyexpr_string = keyexpr.into();
        // R311lh — DEFERRED FIRE (the R311lf lock-free callback
        // invariant on the subscriber-sample plane): the registry
        // stores a staging sink that copies each matched sample to the
        // owned retention form and stages it on the deferred-fire
        // queue; `callback` runs at a drain site OUTSIDE the observer
        // lock and may re-enter any observer-locking session API —
        // publish with local loopback, queries, declares, handle Drop,
        // even its own handle's `undeclare`.
        let (cell, sink) = self.deferred_sample_sink(callback);
        // R311de — observer access via R::with_mutex_mut closure form.
        let id = R::with_mutex_mut(&self.observer, |observer| {
            observer.subscribers.register_with_locality(
                keyexpr_string.clone(),
                options.allowed_origin,
                sink,
            )
        });
        Subscriber {
            session: self.clone(),
            id,
            keyexpr: keyexpr_string,
            options,
            cell,
            // R311lo — armed: Drop/undeclare teardown frees this handle.
            armed: true,
        }
    }
}

// R311cy — pure-accessor method generic lift. The three accessors
// below (`actions` / `observer` / `is_established`) and the
// R311cy-added `clock` accessor read fields directly without acquiring
// any per-runtime lock, so their bodies compile identically for any
// `R: Runtime` impl. Moving them to a dedicated `impl<R: Runtime, T:
// TimeSource> Session<R, T>` block is the first concrete step of the
// multi-round method generic lift cascade (R311cv carry #4): the
// 100+ AP-bound methods that DO call `self.observer.lock().expect()`
// stay on the `impl<T: TimeSource> Session<TokioRuntime, T>` block
// until follow-up rounds migrate them to the `R::with_mutex_mut`
// closure form (R311ct API). The `observer()` return type lifts
// from the per-runtime alias `&Arc<Mutex<...>>` to the trait-
// projected `&Arc<<R as Runtime>::Mutex<...>>`; for the AP profile
// this resolves to the same `std::sync::Mutex<...>` concrete type so
// every existing `session.observer().lock()` call site keeps
// compiling under `R = TokioRuntime` (no breaking change to consumers).
//
// R311mn (Level B, B2) — gated `transport-unicast`: every method in this
// block projects the unicast transport variant (`self.actions()`) or names
// a `session_glue` type, so the whole block is the unicast `Session`
// surface. The five transport-agnostic methods (observer / clock /
// drain_deferred_fires / set_own_zid / clear_own_zid) were lifted into the
// ungated block above; this block now compiles only when
// `transport-unicast` is on.
#[cfg(feature = "transport-unicast")]
impl<R: SessionRuntime, T: TimeSource> Session<R, T> {
    /// Construct a new session bundle from existing handles.
    /// `actions` typically comes from
    /// [`SessionLinkActions::new`](crate::session_glue::SessionLinkActions::new);
    /// `observer` is a freshly-wrapped
    /// [`ApplicationLayerObserver::new`](crate::observer::ApplicationLayerObserver::new)
    /// inside the per-runtime mutex alias (`R::Mutex<...>`);
    /// `clock` is the shared `Arc<T>` monotonic source the session
    /// uses to compute reply-pending deadlines from
    /// [`QueryOptions::timeout_ms`] (R311cw fold-in — previously
    /// passed per-call to each `query` / `get` invocation).
    ///
    /// ## R236 — auto-wire self-echo dedup from `SessionInitParams.zid`
    ///
    /// When `actions.params.zid` carries a valid 1..=16 byte zid
    /// (the wire-form `_z_id_t` range), this constructor forwards it
    /// into the inbound subscriber registry via
    /// [`Session::set_own_zid`] so the application is shielded by the
    /// R231 self-echo dedup guard without writing an explicit hook
    /// against a future FSM `Established` event. Mirrors
    /// zenoh-pico's `_z_session_init` which stamps the local zid
    /// into `_z_session_t._local_zid` at session creation —
    /// `vendor/zenoh-pico/src/session/session.c` (`_z_session_init`
    /// initializes `_local_zid` before any RX/TX driver runs).
    ///
    /// Silent skip on `zid.is_empty()` so test fixtures that
    /// construct a Session with a placeholder `SessionInitParams`
    /// (no zid declared) are not affected; the registry's `own_zid`
    /// stays `None`, dedup remains disabled, and every wire-arrived
    /// Push fires its matching subscribers (the pre-R231 default).
    /// Silent skip also on `zid.len() > 16` for the same reason —
    /// `set_own_zid`'s range check rejects the install and returns
    /// `false`; no panic, no diagnostic noise during construction.
    /// An application that wants to override or re-install the
    /// dedup zid after construction still has the explicit
    /// `set_own_zid` / `clear_own_zid` surface available.
    ///
    /// R311da — constructor lifts from the AP-bound impl<T>
    /// Session<TokioRuntime, T> block to the R-generic impl<R, T>
    /// Session<R, T> block. The observer parameter type lifts from
    /// the per-runtime alias `Arc<Mutex<...>>` (resolved to
    /// std::sync::Mutex on AP) to the trait-projected `Arc<<R as
    /// Runtime>::Mutex<...>>`; for R = TokioRuntime the resolved
    /// concrete type is identical so existing call sites
    /// (`Arc::new(Mutex::new(...))` where `Mutex` is the
    /// `crate::sync` alias) compile unchanged. The internal
    /// `set_own_zid` call composes generically over R because
    /// R311cz lifted that method too. Closes the R311cz carry.
    pub fn new(
        actions: Arc<SessionLinkActions<R, T>>,
        observer: Arc<<R as Runtime>::Mutex<ApplicationLayerObserver>>,
        clock: Arc<T>,
    ) -> Self {
        let session = Self {
            transport: SessionTransport::Unicast(actions),
            observer,
            // R311kz — fresh deferred-fire queue per logical session;
            // every deferred sink (matching, decl listeners, data
            // planes) clones a handle out of it at registration.
            // R311lh — unconditional, see the field doc.
            fires: wz_session_core::deferred_fire::DeferredFireQueue::new(),
            clock,
        };
        // R236 — forward the local zid from SessionInitParams into
        // the subscriber registry so wire-arrived self-echo Pushes
        // are dedup'd from session creation onward. The `1..=16`
        // range check inside `set_own_zid` quietly rejects an
        // out-of-range value (returns `false`); empty zid skipped
        // here so the registry stays in its pre-R231 default state
        // for test fixtures that don't supply a zid.
        if !session.actions().params.zid.is_empty() {
            let _ = session.set_own_zid(session.actions().params.zid.clone());
        }
        session
    }

    /// Borrow the outbound action handle. Useful when the caller
    /// needs to invoke non-publish methods like `send_declare_*` or
    /// `send_request_query` directly on the actions surface.
    pub fn actions(&self) -> &Arc<SessionLinkActions<R, T>> {
        match &self.transport {
            SessionTransport::Unicast(actions) => actions,
        }
    }

    // R311mn (B2) — `observer` / `drain_deferred_fires` are
    // transport-agnostic and now live in the ungated impl block above.

    /// R311ld — the dispatch SSOT (session-review minor F closure):
    /// fan one drive-loop [`IterationEvent`](crate::session_glue::IterationEvent)
    /// into the observer under its lock, then drain the deferred-fire
    /// queue AFTER the lock drops — the lock/dispatch/drain pairing the
    /// F-6 contract requires, mechanized in one method so a dispatch
    /// site cannot forget the drain. The canonical drive-loop closure
    /// is now:
    ///
    /// ```text
    /// |event: IterationEvent<'_>| session.dispatch_iteration_event(event)
    /// ```
    ///
    /// Uses the session's own actions handle as the flush sink (the
    /// same `Arc` the dispatch closures previously threaded by hand —
    /// [`Session::new`] receives it from the same bundle). A site that
    /// needs extra work under the same lock scope (e.g. the wz-ap-demo
    /// switchboard fan) uses
    /// [`Self::dispatch_iteration_event_with`]; a site that bypasses
    /// both and locks the observer directly retains the documented
    /// obligation to pair every dispatch with
    /// [`Self::drain_deferred_fires`].
    pub fn dispatch_iteration_event(&self, event: crate::session_glue::IterationEvent<'_>)
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        self.dispatch_iteration_event_with(event, |_obs| {});
    }

    /// R311ld — [`Self::dispatch_iteration_event`] with an
    /// `under_lock` extension hook that runs INSIDE the same observer
    /// lock scope, after the registry fan + pending flush. The hook
    /// receives the locked observer; it carries the R311kj inline
    /// constraint (no observer-locking session API re-entry from inside
    /// it). The deferred-fire drain still runs after the lock drops,
    /// covering fires staged by the hook too.
    ///
    /// R311li — each queryable-matched request's ResponseFinal is
    /// staged as a deferred-fire JOB, contiguous (same observer lock
    /// window) with the handler jobs the registry fan just staged. A
    /// drainer takes the whole staged batch and runs it sequentially,
    /// so each rid's deferred handler replies precede its
    /// ResponseFinal on the wire EVEN when an auxiliary drainer (a
    /// query/publish tail, the sweep task) steals the batch — the
    /// ordering is structural, not drainer-identity-dependent. Inline
    /// (raw-registry) handler replies flush under the lock, before any
    /// staged job runs. The `SessionLinkActions: Send + Sync` bound is
    /// the deferred wire-emit capability: the tokio profile satisfies
    /// it (`Arc` + `Send + Sync` link sink); the MCU profile drives
    /// registries directly and never constructs these jobs.
    pub fn dispatch_iteration_event_with(
        &self,
        event: crate::session_glue::IterationEvent<'_>,
        under_lock: impl FnOnce(&mut ApplicationLayerObserver),
    ) where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        R::with_mutex_mut(&self.observer, |obs| {
            obs.dispatch_event(event);
            obs.flush_pending_replies(self.actions().as_ref());
            under_lock(obs);
            #[cfg(feature = "query-queryable")]
            for rid in obs.take_pending_final_rids() {
                let actions = self.actions().clone();
                self.fires.stage(Box::new(move || {
                    use wz_session_core::response_sink::ResponseSink as _;
                    actions.send_response_final(rid);
                }));
            }
        });
        self.drain_deferred_fires();
    }

    // R311mn (B2) — `clock` is transport-agnostic and now lives in the
    // ungated impl block above.

    /// R283 — `true` once the session-FSM has entered `Established`.
    /// Thin proxy over
    /// [`crate::session_glue::SessionLinkActions::is_established`];
    /// see that method's doc-comment for the underlying mechanism
    /// (the `record_established_at` Lua action wired to
    /// `Established.onentry` in `session_fsm_unicast.scxml`).
    ///
    /// Callers that emit Interest / declare wire frames pre-Established
    /// risk silent peer-side discard: the peer's `remote-interests`
    /// table is empty until handshake completes, so a pre-Established
    /// Interest never lands. The R283 gate on
    /// [`Self::declare_liveliness_subscriber_aliased`] enforces this
    /// invariant at the declare API boundary; callers wanting to time
    /// their declares against the FSM directly can poll this
    /// predicate. The non-aliased
    /// [`Self::declare_liveliness_subscriber`] remains best-effort —
    /// see its doc-comment for the asymmetric-gate carry.
    pub fn is_established(&self) -> bool {
        self.actions().is_established()
    }

    /// R311jp — zenoh-pico `zp_batch_start` parity: open a TX batching
    /// window. Subsequent network-message sends on this session (puts /
    /// queries / declares / replies) accumulate into one outbound
    /// transport frame — up to the negotiated `batch_size` byte budget —
    /// instead of flushing per message, until [`Self::batch_flush`] /
    /// [`Self::batch_stop`] drains the window (an overflow or an
    /// express-flagged publish drains it implicitly, mirroring pico).
    /// Idempotent on an already-open window.
    ///
    /// Errors with `SendWireError::FeatureDisabled` when the
    /// `transport-batching` feature is off (R311g signature stability).
    pub fn batch_start(&self) -> Result<(), SendWireError> {
        self.actions().batch_start()
    }

    /// R311jp — zenoh-pico `zp_batch_flush` parity: send the currently
    /// batched messages now, keeping the batching window open. No-op when
    /// nothing is batched.
    pub fn batch_flush(&self) -> Result<(), SendWireError> {
        self.actions().batch_flush()
    }

    /// R311jp — zenoh-pico `zp_batch_stop` parity: close the batching
    /// window and send the currently batched messages. Sends after this
    /// call flush per message again.
    pub fn batch_stop(&self) -> Result<(), SendWireError> {
        self.actions().batch_stop()
    }

    // R311mn (B2) — `set_own_zid` / `clear_own_zid` are transport-agnostic
    // and now live in the ungated impl block above.

    /// Publish a literal-keyexpr Sample. Routes both branches per
    /// `opts.allowed_destination`:
    ///
    /// * [`Locality::allows_remote`] → wire send via
    ///   [`SessionLinkActions::send_push_literal`] (Put) or
    ///   [`SessionLinkActions::send_push_del_literal`] (Del). The
    ///   `payload` is ignored on Del kind.
    /// * [`Locality::allows_local`] → loopback dispatch via
    ///   [`crate::pubsub::SubscriberRegistry::local_publish`] with a
    ///   newly-built [`Sample`] carrying `keyexpr` / `payload` /
    ///   `opts.kind` / `opts.reliability` plus every metadata field
    ///   the caller attached via `opts.with_*` (R232 — timestamp /
    ///   encoding / source_info / attachment / qos).
    ///
    /// Returns the number of subscriber callbacks the loopback branch
    /// fired (0 if `allows_local()` is false OR no subscribers match
    /// the keyexpr). Wire-branch outcomes are not reported through
    /// this return value — fire-and-forget per
    /// [`SessionLinkActions::send_push_literal`]'s shape.
    ///
    /// ## R233 — wire-side metadata parity
    ///
    /// The wire branch routes through
    /// [`SessionLinkActions::send_push_with_meta_literal`] /
    /// [`SessionLinkActions::send_push_del_with_meta_literal`],
    /// threading every caller-set [`PublishOptions`] metadata field
    /// (timestamp, encoding, source_info, attachment, qos) onto the
    /// outbound `MsgPut`/`MsgDel` so the peer's
    /// `_z_trigger_subscriptions_impl` projects the same
    /// `_z_sample_t` shape the loopback branch projects in-process.
    /// Encoding is dropped silently for Del kind (mirrors
    /// `_z_msg_del_t`'s missing encoding slot); the loopback path
    /// applies the same projection in
    /// [`build_loopback_sample`].
    ///
    /// Mirrors zenoh-pico's `_z_write` `vendor/zenoh-pico/src/net/primitives.c`
    /// 170-205: wire branch under `allows_remote()`, loopback branch
    /// under `allows_local()`. Both branches run when
    /// `Locality::Any` (the default) and the publisher's intent is
    /// "fan to every receiver, in-process and remote".
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> Result<usize, PublishError> {
        // W3 — the remote wire leg is `codec-push`-gated (symmetric with
        // the `pubsub-allow-loop` loopback gate below). On a build
        // without `codec-push` the Push codec is statically absent, so
        // the remote leg is elided entirely and the loopback leg still
        // runs — rather than `?`-aborting on a `FeatureDisabled` reject,
        // which would break in-process pub/sub for codec-push-less
        // deploys. With `codec-push` on, the only runtime reject is a
        // payload/keyexpr that overflows the declared codec capacity
        // (`PublishError::ExceedsCapacity`).
        #[cfg(feature = "codec-push")]
        if opts.allowed_destination.allows_remote() {
            let reliable = opts.reliable_bool();
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions()
                        .send_push_with_meta_literal(keyexpr, payload, reliable, &meta)?;
                }
                SampleKind::Del => {
                    self.actions()
                        .send_push_del_with_meta_literal(keyexpr, reliable, &meta)?;
                }
            }
        }
        // R311cc — pubsub-allow-loop gates the local_publish loopback
        // branch of Session::publish. cfg-off short-circuits to 0
        // (only remote dispatch fires); the Locality::Any default
        // becomes effectively Locality::Remote_Only.
        //
        // R311db — observer access migrates from
        // `self.observer.lock().expect(...).subscribers.local_publish(&sample)`
        // to the R::with_mutex_mut closure form (R311ct API) so this
        // method composes generically across the runtime profile.
        #[cfg(feature = "pubsub-allow-loop")]
        {
            let delivered = if opts.allowed_destination.allows_local() {
                let sample = build_loopback_sample(keyexpr, payload, &opts);
                let delivered = R::with_mutex_mut(&self.observer, |observer| {
                    observer.subscribers.local_publish(&sample)
                });
                // R311lh / R311lj — drain the fires THIS publish staged
                // (the loopback `local_publish`) so local subscriber
                // callbacks run synchronously on the caller thread,
                // outside the observer lock, before `publish` returns
                // (pico fires subscription callbacks outside the session
                // mutex on the delivering thread). Drain is gated on the
                // local-delivery path: a Remote-only publish stages
                // nothing, so draining there would be gratuitous (it
                // would run drive-loop-staged callbacks on the publish
                // thread). The observer-serialized take keeps a
                // concurrent drive-loop batch atomic (R311lj).
                self.drain_deferred_fires();
                delivered
            } else {
                0
            };
            Ok(delivered)
        }
        #[cfg(not(feature = "pubsub-allow-loop"))]
        {
            let _ = (keyexpr, payload, opts);
            Ok(0)
        }
    }

    /// R229 — aliased-keyexpr counterpart of [`Session::publish`].
    /// Routes the wire branch through
    /// [`SessionLinkActions::send_push_aliased`] (Put) or
    /// [`SessionLinkActions::send_push_del_aliased`] (Del) so the
    /// peer resolves the keyexpr through its inbound mapping table
    /// (populated by an earlier
    /// [`SessionLinkActions::send_declare_keyexpr`] from this side),
    /// and routes the loopback branch through the same
    /// [`crate::pubsub::SubscriberRegistry::local_publish`] as
    /// [`Session::publish`] using `loopback_keyexpr` as the resolved
    /// literal form.
    ///
    /// `inline_suffix = None` emits a pure-aliased Push (the declared
    /// literal is the full keyexpr). `inline_suffix = Some(s)` emits
    /// a composite Push (declared prefix + `s`) — the wire branch
    /// passes the pair through to the peer as-is; the loopback branch
    /// trusts `loopback_keyexpr` to already be the resolved form
    /// (typically `<declared prefix> + s`).
    ///
    /// ## Caller precondition
    ///
    /// `loopback_keyexpr` MUST equal the literal form the peer would
    /// resolve `(mapping_id, inline_suffix)` to through its inbound
    /// mapping table. Typical usage:
    ///
    /// 1. `session.actions().send_declare_keyexpr(7, "home/temp")` —
    ///    registers `7 -> "home/temp"` on the peer.
    /// 2. `session.publish_aliased(7, None, "home/temp", payload, opts)`
    ///    — wire carries `(id=7, suffix=None)`; loopback fires on the
    ///    literal `"home/temp"`.
    /// 3. `session.publish_aliased(7, Some("/kitchen"), "home/temp/kitchen", payload, opts)`
    ///    — wire carries `(id=7, suffix="/kitchen")`; loopback fires
    ///    on `"home/temp/kitchen"`.
    ///
    /// A wz-side outbound mapping table that auto-resolves the
    /// `loopback_keyexpr` from `(mapping_id, inline_suffix)` is an
    /// R230+ carry; until that lands, the caller's assertion is the
    /// single source of truth for the loopback literal.
    ///
    /// Returns the number of loopback subscriber callbacks that
    /// fired, same as [`Session::publish`].
    ///
    /// Mirrors zenoh-pico's `_z_write` with a `_z_declared_keyexpr_t`
    /// carrying both the aliased pair and the resolved literal —
    /// zenoh-pico embeds both forms in one type
    /// (`vendor/zenoh-pico/include/zenoh-pico/session/resource.h`),
    /// the wz R229 surface separates them for now since wz lacks the
    /// outbound mapping table that would produce them as a pair.
    pub fn publish_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        loopback_keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> Result<usize, PublishError> {
        // W3 — remote wire leg `codec-push`-gated (see Session::publish);
        // a codec-push-less build elides it and runs loopback only.
        #[cfg(feature = "codec-push")]
        if opts.allowed_destination.allows_remote() {
            let reliable = opts.reliable_bool();
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions().send_push_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        payload,
                        reliable,
                        &meta,
                    )?;
                }
                SampleKind::Del => {
                    self.actions().send_push_del_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        reliable,
                        &meta,
                    )?;
                }
            }
        }
        #[cfg(not(feature = "codec-push"))]
        let _ = (mapping_id, inline_suffix);
        // R311cc — pubsub-allow-loop gates the aliased-publish
        // loopback fan-out (mirror of Session::publish gate).
        // R311db — observer access via R::with_mutex_mut (closure form).
        #[cfg(feature = "pubsub-allow-loop")]
        {
            let delivered = if opts.allowed_destination.allows_local() {
                let sample = build_loopback_sample(loopback_keyexpr, payload, &opts);
                let delivered = R::with_mutex_mut(&self.observer, |observer| {
                    observer.subscribers.local_publish(&sample)
                });
                // R311lh / R311lj — drain the loopback-staged fires;
                // gated on the local-delivery path, see `Session::publish`.
                self.drain_deferred_fires();
                delivered
            } else {
                0
            };
            Ok(delivered)
        }
        #[cfg(not(feature = "pubsub-allow-loop"))]
        {
            let _ = (loopback_keyexpr, payload, opts);
            Ok(0)
        }
    }

    /// R234 — auto-resolved counterpart of [`Self::publish_aliased`].
    /// Looks up `mapping_id` in the outbound keyexpr table populated
    /// by prior
    /// [`SessionLinkActions::send_declare_keyexpr`] calls, composes
    /// with `inline_suffix` per the same rule as the caller-asserted
    /// form (`id != 0, suffix = None` → declared literal; `id != 0,
    /// suffix = Some(s)` → declared literal + `s`), then routes both
    /// wire and loopback branches without the caller restating the
    /// resolved literal. Mirrors zenoh-pico's
    /// `_z_session_t._local_resources` lookup on the publish path
    /// (`_z_write` → `_z_resource_get_by_id`), retiring the R229
    /// caller-asserted `loopback_keyexpr` workaround on this surface.
    ///
    /// Returns `Err(PublishAliasError::UnknownMapping(id))` when no
    /// prior `send_declare_keyexpr` registered `mapping_id` OR when
    /// a subsequent `send_undeclare_kexpr` retracted it. In the
    /// error case NEITHER branch fires — sending a wire Push with an
    /// id the peer cannot resolve would also fail there, and
    /// running the loopback branch on a guess at the literal would
    /// silently mis-deliver. The caller treats `Err` as a contract
    /// violation (declare-before-publish ordering bug) and either
    /// re-declares the mapping or falls back to
    /// [`Self::publish_aliased`] with an explicit loopback literal.
    pub fn publish_aliased_auto(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        payload: &[u8],
        opts: PublishOptions,
    ) -> Result<usize, PublishAliasError> {
        let base = self
            .actions()
            .resolve_outbound_mapping(mapping_id)
            .ok_or(PublishAliasError::UnknownMapping(mapping_id))?;
        let loopback_keyexpr = match inline_suffix {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        Ok(self.publish_aliased(mapping_id, inline_suffix, &loopback_keyexpr, payload, opts)?)
    }

    /// R311lg — build the deferred staging sink a reply-stream
    /// registration installs: the z_get `query*` path stores it in the
    /// [`crate::reply::ReplyRegistry`]; R311lk routes the liveliness-get
    /// path through the same helper into its
    /// `LivelinessGetRegistry` (both share the `ReplySink` seam, so one
    /// staging helper backs both reply-stream planes). The
    /// user `(on_reply, on_final)` pair lives in a deferred-fire
    /// cell, and the registry-stored sink only copies each inbound
    /// reply out to its owned form ([`InboundReply`] — the existing AP
    /// retention form, no third reply struct) and stages one queue job
    /// per fire. The drain runs the user callbacks OUTSIDE the
    /// observer lock (the R311lf lock-free callback invariant on the
    /// reply/final plane), so they may re-enter any observer-locking
    /// session API — including issuing further queries or gets.
    ///
    /// The staged `on_final` job kills the cell after firing: Final is
    /// terminal (the registry auto-removes the pending entry, so no
    /// later fire can stage), and the kill drops the user closures
    /// promptly — outside every framework lock, unlike the pre-R311lg
    /// inline path which dropped them inside the observer lock window.
    #[cfg(any(feature = "query-get", feature = "liveliness-get"))]
    fn deferred_reply_sink(
        &self,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> crate::reply_sink::BoxedReplySink {
        use crate::reply::InboundReplyBody;
        use crate::reply_sink::{BoxedReplySink, ReplyKind};
        let cell: wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedReplySink> =
            wz_session_core::deferred_fire::DeferredListenerCell::new(BoxedReplySink::new(
                on_reply, on_final,
            ));
        let queue = self.fires.clone();
        let cell_for_reply = cell.clone();
        let staged_reply = move |view: &dyn ReplyView| {
            // Owned copy — a deferred fire outlives the dispatch borrow.
            let owned = InboundReply {
                rid: view.rid(),
                keyexpr_literal: view.keyexpr().to_string(),
                body: match view.kind() {
                    ReplyKind::Put => InboundReplyBody::Put {
                        payload: view.payload().to_vec(),
                    },
                    ReplyKind::Del => InboundReplyBody::Del,
                    ReplyKind::Err => InboundReplyBody::Err {
                        encoding: view
                            .err_encoding()
                            .map(|(id, schema)| (id, schema.map(str::to_string))),
                        payload: view.payload().to_vec(),
                    },
                },
            };
            let cell = cell_for_reply.clone();
            queue.stage(Box::new(move || {
                cell.invoke(move |sink| {
                    use crate::reply_sink::ReplySink as _;
                    sink.on_reply(&owned)
                })
            }));
        };
        let queue = self.fires.clone();
        let staged_final = move |rid: u64| {
            let cell = cell.clone();
            queue.stage(Box::new(move || {
                cell.invoke(move |sink| {
                    use crate::reply_sink::ReplySink as _;
                    sink.on_final(rid)
                });
                cell.kill();
            }));
        };
        BoxedReplySink::new(staged_reply, staged_final)
    }

    /// R239 — issue a query on `keyexpr` and route replies to
    /// `on_reply` (one fire per Reply or Err) plus `on_final` (one
    /// fire after every expected branch has emitted its Final).
    ///
    /// Routes both branches per `opts.allowed_destination`:
    ///
    /// * [`Locality::allows_remote`] → wire send via
    ///   [`SessionLinkActions::send_request_query`] with
    ///   `(mapping_id = 0, suffix = Some(keyexpr))` (literal-only at
    ///   R239; aliased / suffix-composite form is a follow-up).
    /// * [`Locality::allows_local`] → loopback fan via
    ///   [`crate::query::QueryableRegistry::local_query`] (R238)
    ///   into every locally-registered queryable that matches the
    ///   keyexpr pattern. Each emitted [`QueryReply`] projects into
    ///   an [`InboundReply`] (via `From<QueryReply>`) and routes
    ///   through [`crate::reply::ReplyRegistry::deliver_local_reply`]
    ///   so the same callback fires regardless of wire vs loopback
    ///   origin — the R239 single-dispatch-path commitment.
    ///
    /// The rid is allocated through
    /// [`SessionLinkActions::alloc_next_request_id`] so wire and
    /// loopback branches see the same id; the
    /// [`crate::reply::ReplyRegistry`] pending entry registers with
    /// `expected_finals = opts.allows_remote() as u32 +
    /// opts.allows_local() as u32`, mirroring zenoh-pico's
    /// `_z_pending_query_t._remaining_finals` initialisation so
    /// `on_final` fires exactly once after every contributing branch
    /// has emitted its Final (loopback is synchronous so its Final
    /// arrives before this call returns; the wire Final arrives
    /// asynchronously via [`crate::reply::ReplyRegistry::dispatch_response_final`]).
    ///
    /// Order of effects:
    /// 1. Allocate `rid = actions.alloc_next_request_id()`.
    /// 2. Take the observer lock; register the pending entry on
    ///    `observer.replies`. If `allows_local()` holds, fan the
    ///    loopback inline (queryable callbacks → `QueryReply` →
    ///    `InboundReply` → `deliver_local_reply` → eventually
    ///    `deliver_local_final`) under the same lock so the
    ///    pending entry's `remaining_finals` decrement happens
    ///    while no Final from the wire can race in.
    /// 3. Drop the observer lock. If `allows_remote()` holds, dispatch
    ///    the outbound wire `Request(Query)` via
    ///    [`SessionLinkActions::send_request_query`].
    ///
    /// The wire send happens OUTSIDE the observer lock so the actions
    /// layer's outbound mutex (driver channel) doesn't nest with the
    /// observer mutex — order discipline mirrors
    /// [`Session::publish`]'s wire-after-loopback (or wire-only)
    /// dispatch pattern.
    ///
    /// Mirrors zenoh-pico's `_z_query` (`vendor/zenoh-pico/src/net/query.c`):
    /// `_z_unsafe_register_pending_query` inside the session mutex,
    /// `_z_send_n_msg` outside, `_z_session_deliver_query_locally`
    /// reads the local queryable table under the session mutex.
    ///
    /// R307 — gated on `feature = "query-get"`. The implication chain
    /// (`query-get` → `query-reply` + `query-queryable`) guarantees
    /// both the `ReplyRegistry` pending-entry registration and the
    /// loopback `QueryableRegistry::local_query` fan are available;
    /// the body holds no further per-feature cfg when query-get is ON.
    ///
    /// R311t — signature is type-ungated and Result-form. When
    /// `query-get` is OFF the body returns
    /// `Err(QueryAliasError::FeatureDisabled)` without touching the
    /// observer or emitting any wire frame; callers branch uniformly
    /// across consumer-feature subsets on the same enum that the
    /// aliased variants ([`Self::query_aliased`],
    /// [`Self::query_aliased_auto`]) already surface. Promoted from
    /// the R311s stub-form fall-through (sentinel `ReplyHandle(0)`)
    /// because the silent-no-op path was an honest-signal anti-pattern
    /// — callers that did not check the rid would silently misfile
    /// replies into a non-registration. The R311t transition costs
    /// ~22 internal-test callsites a `.expect()` chaining, which is
    /// the textbook price for the honest-signal property.
    pub fn query(
        &self,
        keyexpr: &str,
        opts: QueryOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (keyexpr, opts, on_reply, on_final);
            Err(QueryAliasError::FeatureDisabled)
        }
        #[cfg(feature = "query-get")]
        {
            let rid = self.actions().alloc_next_request_id();
            let expected_finals = opts.expected_finals();
            let allows_remote = opts.allowed_destination.allows_remote();
            let allows_local = opts.allowed_destination.allows_local();
            // R262 — compute the absolute monotonic-ms deadline from
            // `self.clock.now_monotonic_ms()` + `opts.timeout_ms`.
            // timeout_ms == 0 is the "no timeout" sentinel; the pending
            // entry is registered with deadline_ms = None and survives
            // every sweep until a wire/loopback Final arrives. The Session-
            // owned clock (R311cw fold-in) shares monotonic epoch with
            // `drive_session_until_terminal`'s `clock` parameter as long
            // as the application threads the same `Arc<T>` instance into
            // both `Session::new` and `drive_session_until_terminal`; this
            // is the contract every production caller honours (see
            // wz-ap-demo/src/runner.rs which builds one `session_clock`
            // and forks it through both call sites).
            let deadline_ms = (opts.timeout_ms > 0)
                .then(|| self.clock.now_monotonic_ms() + opts.timeout_ms as u64);

            // R311lg — DEFERRED FIRE (the R311lf lock-free callback
            // invariant on the reply/final plane): the registry stores
            // a staging sink; `on_reply` / `on_final` run at a drain
            // site OUTSIDE the observer lock and may re-enter any
            // observer-locking session API. Loopback fires staged by
            // the `deliver_local_*` calls below are drained at this
            // method's tail, so SessionLocal replies still arrive
            // synchronously before `query` returns (pico parity:
            // `_z_session_deliver_query_locally` fires on the caller
            // thread, outside the session mutex).
            let sink = self.deferred_reply_sink(on_reply, on_final);

            // R311dc — observer access migrates from `.lock().expect()` to
            // R::with_mutex_mut closure form (R311ct API). The closure body
            // performs all observer-side mutations (replies.register +
            // queryables.local_query + replies.deliver_local_*) under a
            // single lock acquisition, identical to the prior pattern; the
            // closure returns the ReplyHandle which propagates out.
            // R311ln (Finding B sibling) — register the pending sink,
            // THEN emit the wire Query, THEN fan the loopback, mirroring
            // zenoh-pico's `_z_query`
            // (`vendor/zenoh-pico/src/net/primitives.c:585-629`):
            // register the pending query under the session mutex, run
            // `_z_send_n_msg`, then `_z_session_deliver_query_locally`
            // ONLY when the send returned `_Z_RES_OK`, and
            // `_z_unregister_pending_query` on any failure. The R239
            // shape fanned the loopback inside the register lock BEFORE
            // the wire emit, so a failed `send_request_query` left the
            // pending entry as a permanent orphan — firing `on_final` on
            // the deadline sweep for a query the caller got an `Err`
            // from, plus staged loopback fires invoking `on_reply` for
            // that same failed query. Emitting first keeps the rollback
            // unregister-only: the rid is FRESH (`alloc_next_request_id`,
            // so no solicited reply can correlate before the send) and no
            // loopback has fanned yet, so dropping the pending entry
            // drops the sink and its deferred cell — a complete rollback
            // with no cell kill, the same shape as `liveliness_get`
            // (R311ll).
            let handle = R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .replies
                    .register_sink(rid, expected_finals, deadline_ms, sink)
                    .expect("register on the alloc backing never exceeds declared capacity")
            });

            if allows_remote {
                // R240 — thread QueryOptions metadata (target /
                // consolidation / attachment / timeout_ms) through the
                // wire branch. The R233 PushMetadata pattern is mirrored
                // here: empty bundle short-circuits to the no-metadata
                // builder so the byte-stable
                // `send_request_query` wire shape stays unchanged for
                // callers that pass `QueryOptions::default()`.
                let meta = opts.query_metadata();
                let emit = if meta.is_empty() {
                    self.actions().send_request_query(rid, 0, Some(keyexpr))
                } else {
                    self.actions()
                        .send_request_query_with_meta(rid, 0, Some(keyexpr), &meta)
                };
                // R311ln — roll the pending entry back on a failed wire
                // emit (unregister-only; see the header comment).
                if let Err(e) = emit {
                    R::with_mutex_mut(&self.observer, |observer| {
                        observer.replies.unregister(rid);
                    });
                    return Err(e.into());
                }
            }

            // R311ln — loopback fan AFTER a successful wire emit (pico
            // parity: `_z_session_deliver_query_locally` runs only on
            // `ret == _Z_RES_OK`). R311fq — the in-process queryable fan
            // is gated on `query-queryable`: `observer.queryables` only
            // exists when this process selected the queryable responder
            // plane. A pure getter (query-queryable OFF) has no local
            // queryable to answer, so the loopback yields zero replies
            // and only the synthetic Final (below) fires.
            if allows_local {
                #[cfg(feature = "query-queryable")]
                {
                    R::with_mutex_mut(&self.observer, |observer| {
                        let mut replies: Vec<QueryReply> = Vec::new();
                        // `QueryOwned` has no `Default`; build the borrowed
                        // default and deep-copy into the owned form the
                        // loopback dispatch path (`local_query`) now takes.
                        let query = Query::default().try_into_owned().expect(
                            "Query::default has empty fields, trivially within codec bounds",
                        );
                        observer
                            .queryables
                            .local_query(rid, keyexpr, &query, &mut replies);
                        for reply in replies.drain(..) {
                            let inbound: InboundReply = reply.into();
                            observer.replies.deliver_local_reply(&inbound);
                        }
                    });
                }
            }

            // R311lg — drain the fires this call staged (the loopback
            // `deliver_local_reply` path and, R311li, the deferred
            // local queryable handler jobs — whose replies deliver
            // back into the local reply registry and drain in this
            // same pass) so local replies run synchronously on the
            // caller thread, outside the observer lock, before `query`
            // returns. An overlapping drive-loop drain is lossless
            // (the cell backlog hands the overlapped call to the
            // active drainer).
            self.drain_deferred_fires();

            if allows_local {
                // R311li — the synthetic loopback Final closes the
                // loopback half of the pending entry's
                // `remaining_finals` counter AFTER the drain above ran
                // every deferred local queryable handler and delivered
                // its replies — so `on_final` fires after every local
                // `on_reply` (the pico `_z_session_deliver_query_locally`
                // emit-final-at-tail ordering, preserved across the
                // deferred handler shape). Stays under `query-get` so
                // the wire-only getter finalises the loopback half even
                // with no queryable plane (R311fq).
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.replies.deliver_local_final(rid);
                });
                self.drain_deferred_fires();
            }

            Ok(handle)
        }
    }

    /// R241 — aliased-keyexpr counterpart of [`Session::query`].
    /// Mirror of [`Session::publish_aliased`] on the z_get side:
    /// the wire branch encodes the `(mapping_id, inline_suffix)`
    /// pair so the peer resolves the keyexpr through its inbound
    /// mapping table (populated by an earlier
    /// [`SessionLinkActions::send_declare_keyexpr`] from this side),
    /// while the loopback branch trusts `loopback_keyexpr` to
    /// already be the literal form the peer would resolve.
    ///
    /// `mapping_id = 0` is invalid for this surface — use
    /// [`Self::query`] for the literal-only path. `inline_suffix =
    /// None` emits a pure-aliased Query (declared literal is the
    /// full keyexpr); `inline_suffix = Some(s)` emits a composite
    /// Query (declared prefix + `s`).
    ///
    /// ## Caller precondition
    ///
    /// `loopback_keyexpr` MUST equal the literal form the peer would
    /// resolve `(mapping_id, inline_suffix)` to through its inbound
    /// mapping table. Use [`Self::query_aliased_auto`] to skip the
    /// caller assertion when the mapping was declared through this
    /// session's outbound table.
    ///
    /// Routes both branches per `opts.allowed_destination`, allocates
    /// rid through [`SessionLinkActions::alloc_next_request_id`],
    /// registers the pending [`crate::reply::ReplyRegistry`] entry
    /// with `expected_finals = opts.expected_finals()`. Same
    /// lock-discipline as [`Self::query`]: observer locked during
    /// register + loopback fan, dropped before the wire dispatch.
    ///
    /// Mirrors zenoh-pico's `_z_query` with a
    /// `_z_declared_keyexpr_t` (`vendor/zenoh-pico/src/net/query.c`)
    /// carrying both the aliased pair and the resolved literal.
    ///
    /// 8-argument signature (matches the 6 distinct atomic parameters
    /// the aliased Query needs on the wire + 2 application closures).
    /// `clippy::too_many_arguments` is explicitly allowed here because
    /// every argument is load-bearing: mapping_id + inline_suffix +
    /// loopback_keyexpr are the wire-aliased triple, opts is the
    /// metadata bundle, clock is the R262 deadline source, and the
    /// two closures are the on_reply / on_final consumer callbacks.
    ///
    /// R311t — signature type-ungated and Result-form alongside
    /// [`Self::query`]. When `query-get` is OFF the body returns
    /// `Err(QueryAliasError::FeatureDisabled)`; the aliased variant
    /// already carried `Result<_, QueryAliasError>` for the
    /// `UnknownMapping` signal, so the FeatureDisabled variant
    /// (introduced at R311s) is now the active OFF arm here too.
    pub fn query_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        loopback_keyexpr: &str,
        opts: QueryOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (
                mapping_id,
                inline_suffix,
                loopback_keyexpr,
                opts,
                on_reply,
                on_final,
            );
            Err(QueryAliasError::FeatureDisabled)
        }
        #[cfg(feature = "query-get")]
        {
            let rid = self.actions().alloc_next_request_id();
            let expected_finals = opts.expected_finals();
            let allows_remote = opts.allowed_destination.allows_remote();
            let allows_local = opts.allowed_destination.allows_local();
            // R262 — same deadline_ms computation as `Session::query`.
            // R311cw — clock is Session-owned (`Arc<T>` field), same
            // monotonic epoch shared with the sweep caller as long as
            // both `Session::new` and `drive_session_until_terminal`
            // receive the same `Arc<T>` instance (the wz-ap-demo runner
            // is the production-side fixture that honours this).
            let deadline_ms = (opts.timeout_ms > 0)
                .then(|| self.clock.now_monotonic_ms() + opts.timeout_ms as u64);

            // R311lg — deferred staging sink; same lock-free callback
            // contract + tail drain as `Session::query`.
            let sink = self.deferred_reply_sink(on_reply, on_final);

            // R311dc — closure-form observer access via R::with_mutex_mut
            // (R311ct API). Same closure body shape as Session::query.
            // R311ln (Finding B sibling) — register, emit the wire
            // Query, then fan the loopback; same pico `_z_query` order
            // and unregister-only rollback as `Session::query` (see its
            // header comment). The aliased wire branch routes by
            // (mapping_id, inline_suffix); a failed emit rolls the FRESH
            // rid back with `unregister` alone (no loopback fanned yet,
            // no solicited reply can correlate before the send).
            let handle = R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .replies
                    .register_sink(rid, expected_finals, deadline_ms, sink)
                    .expect("register on the alloc backing never exceeds declared capacity")
            });

            if allows_remote {
                let meta = opts.query_metadata();
                let emit = if meta.is_empty() {
                    self.actions()
                        .send_request_query(rid, mapping_id, inline_suffix)
                } else {
                    self.actions().send_request_query_with_meta(
                        rid,
                        mapping_id,
                        inline_suffix,
                        &meta,
                    )
                };
                if let Err(e) = emit {
                    R::with_mutex_mut(&self.observer, |observer| {
                        observer.replies.unregister(rid);
                    });
                    return Err(e.into());
                }
            }

            // R311fq — `loopback_keyexpr` feeds only the query-queryable
            // loopback fan; the wire branch routes by (mapping_id,
            // inline_suffix). Under a wire-only getter (query-queryable
            // OFF) the param is otherwise unused.
            #[cfg(not(feature = "query-queryable"))]
            let _ = loopback_keyexpr;
            // R311ln — loopback fan AFTER a successful wire emit (pico
            // parity). R311fq — gated on `query-queryable`; the synthetic
            // Final (below) stays under `query-get` so a wire-only getter
            // still closes the loopback half of the pending entry.
            if allows_local {
                #[cfg(feature = "query-queryable")]
                {
                    R::with_mutex_mut(&self.observer, |observer| {
                        let mut replies: Vec<QueryReply> = Vec::new();
                        // `QueryOwned` has no `Default`; build the borrowed
                        // default and deep-copy into the owned form the
                        // loopback dispatch path (`local_query`) now takes.
                        let query = Query::default().try_into_owned().expect(
                            "Query::default has empty fields, trivially within codec bounds",
                        );
                        observer.queryables.local_query(
                            rid,
                            loopback_keyexpr,
                            &query,
                            &mut replies,
                        );
                        for reply in replies.drain(..) {
                            let inbound: InboundReply = reply.into();
                            observer.replies.deliver_local_reply(&inbound);
                        }
                    });
                }
            }

            // R311lg / R311li — drain + post-drain loopback Final; see
            // `Session::query` for the ordering rationale.
            self.drain_deferred_fires();

            if allows_local {
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.replies.deliver_local_final(rid);
                });
                self.drain_deferred_fires();
            }

            Ok(handle)
        }
    }

    /// R241 — auto-resolved counterpart of [`Self::query_aliased`].
    /// Mirror of [`Self::publish_aliased_auto`] on the z_get side:
    /// looks up `mapping_id` in the outbound keyexpr table populated
    /// by prior [`SessionLinkActions::send_declare_keyexpr`] calls,
    /// composes with `inline_suffix` per the same rule as the
    /// caller-asserted form, then routes both wire and loopback
    /// branches without the caller restating the resolved literal.
    ///
    /// Returns `Err(QueryAliasError::UnknownMapping(id))` when no
    /// prior `send_declare_keyexpr` registered `mapping_id` OR when
    /// a subsequent `send_undeclare_kexpr` retracted it. In the
    /// error case NEITHER branch fires — sending a wire Query with
    /// an id the peer cannot resolve would also fail there, and
    /// running the loopback branch on a guess at the literal would
    /// silently mis-deliver replies into a stale pending entry. The
    /// caller treats `Err` as a contract violation
    /// (declare-before-query ordering bug) and either re-declares
    /// the mapping or falls back to [`Self::query_aliased`] with an
    /// explicit `loopback_keyexpr`.
    ///
    /// R311t — signature type-ungated and Result-form (unchanged
    /// from R311s in this method; the surface already carried
    /// `Result<_, QueryAliasError>` for `UnknownMapping` signaling).
    /// At R311t [`Self::query`] and [`Self::query_aliased`] also
    /// adopted Result-form, so the inner delegate call propagates
    /// the inner Result with `?` rather than re-wrapping an inner
    /// `ReplyHandle` in `Ok(...)`.
    pub fn query_aliased_auto(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        opts: QueryOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (mapping_id, inline_suffix, opts, on_reply, on_final);
            Err(QueryAliasError::FeatureDisabled)
        }
        #[cfg(feature = "query-get")]
        {
            let base = self
                .actions()
                .resolve_outbound_mapping(mapping_id)
                .ok_or(QueryAliasError::UnknownMapping(mapping_id))?;
            let loopback_keyexpr = match inline_suffix {
                None => base,
                Some(s) => {
                    let mut composed = base;
                    composed.push_str(s);
                    composed
                }
            };
            // R311cw — clock fold-in: the inner `query_aliased` delegate
            // reads `self.clock` directly; no clock parameter to thread.
            self.query_aliased(
                mapping_id,
                inline_suffix,
                &loopback_keyexpr,
                opts,
                on_reply,
                on_final,
            )
        }
    }

    /// R242 — declare a reusable [`Querier`] bound to `keyexpr` +
    /// `options`. The returned Querier holds a clone of this
    /// session and emits subsequent outbound queries through
    /// [`Querier::get`] without restating the keyexpr or options
    /// on every call.
    ///
    /// Unlike zenoh-pico's `z_declare_querier`, this constructor
    /// does NOT emit any wire frame at declare time — there is no
    /// peer-side state to register (the Query side has no
    /// `DeclareQueryable`-equivalent emitted from the requester
    /// side; queryables live on the responder). The "declaration"
    /// is purely a caller-side aggregation of (keyexpr, options).
    /// Matches the zenoh-pico C API ergonomically while skipping
    /// the no-op wire emit.
    ///
    /// Use [`Querier::get`] to issue each query; the rid allocator
    /// hands a fresh rid per call so concurrent gets through the
    /// same Querier remain independent.
    ///
    /// R311s — type-ungated. The body is a pure aggregator (no
    /// observer access, no wire emit) so the constructor compiles
    /// regardless of `query-get` feature state. Calling
    /// [`Querier::get`] on the returned handle without `query-get`
    /// returns `Err(QueryAliasError::FeatureDisabled)` (R311t
    /// Result-form transition — no wire frame, no callback
    /// registration).
    pub fn declare_querier(
        &self,
        keyexpr: impl Into<String>,
        options: QueryOptions,
    ) -> Querier<R, T> {
        Querier {
            session: self.clone(),
            keyexpr: keyexpr.into(),
            options,
        }
    }

    /// R243 — aliased-keyexpr counterpart of [`Self::declare_querier`].
    /// Holds the `(mapping_id, inline_suffix, options)` triple so
    /// subsequent [`QuerierAliased::get`] calls route through
    /// [`Self::query_aliased_auto`] without restating them.
    ///
    /// Same no-wire-emit contract as [`Self::declare_querier`]: the
    /// outbound `send_declare_keyexpr` that registers `mapping_id`
    /// on the peer is the caller's earlier responsibility; this
    /// constructor only aggregates state on the caller side.
    ///
    /// R311s — type-ungated alongside [`Self::declare_querier`]; body
    /// is aggregator-only with no observer / wire dependency. The
    /// aliased querier's `.get` path returns
    /// `Err(QueryAliasError::FeatureDisabled)` via
    /// [`Session::query_aliased_auto`] when `query-get` is OFF
    /// (R311t Result-form transition).
    pub fn declare_querier_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: QueryOptions,
    ) -> QuerierAliased<R, T> {
        QuerierAliased {
            session: self.clone(),
            mapping_id,
            inline_suffix: inline_suffix.map(str::to_string),
            options,
        }
    }

    /// R244 — declare a reusable [`Publisher`] bound to `keyexpr` +
    /// `options`. Pub-side mirror of [`Self::declare_querier`]: the
    /// returned handle holds a clone of this session and emits
    /// subsequent outbound publishes through [`Publisher::put`] /
    /// [`Publisher::delete`] without restating the keyexpr or
    /// options on every call.
    ///
    /// Same no-wire-emit contract as [`Self::declare_querier`]:
    /// declaration is a caller-side aggregation only. Mirrors
    /// zenoh-pico's `z_declare_publisher` minus the wire-emitted
    /// `DeclarePublisher` record, which zenoh-pico itself elides
    /// when running without router (peer-only) — wz is router-less
    /// today so the wire elision is always correct.
    pub fn declare_publisher(
        &self,
        keyexpr: impl Into<String>,
        options: PublishOptions,
    ) -> Publisher<R, T> {
        Publisher {
            session: self.clone(),
            keyexpr: keyexpr.into(),
            options,
        }
    }

    /// R244 — aliased-keyexpr counterpart of [`Self::declare_publisher`].
    /// Holds `(mapping_id, inline_suffix, options)` so subsequent
    /// [`PublisherAliased::put`] / [`PublisherAliased::delete`]
    /// calls route through [`Self::publish_aliased_auto`] without
    /// restating them.
    ///
    /// Same outbound-mapping-table dependency as
    /// [`Self::declare_querier_aliased`]: the caller is responsible
    /// for the earlier [`SessionLinkActions::send_declare_keyexpr`]
    /// that registers `mapping_id`.
    pub fn declare_publisher_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: PublishOptions,
    ) -> PublisherAliased<R, T> {
        PublisherAliased {
            session: self.clone(),
            mapping_id,
            inline_suffix: inline_suffix.map(str::to_string),
            options,
        }
    }

    // R311mp (B4) — `declare_subscriber` (non-aliased) is TRANSPORT-AGNOSTIC
    // (it touches only `self.fires` via `deferred_sample_sink` + the
    // observer's subscriber registry, never `self.actions()`), so it was
    // lifted into the ungated impl block above so a multicast-only `Session`
    // can declare subscribers too. The aliased `declare_subscriber_aliased`
    // below STAYS here: it resolves through the unicast outbound mapping
    // table (`self.actions().resolve_outbound_mapping`), which a
    // connectionless multicast session has no analogue of.

    /// R245 — aliased-keyexpr counterpart of
    /// [`Self::declare_subscriber`]. Resolves `mapping_id` +
    /// `inline_suffix` to the literal form *at declare time* via the
    /// outbound mapping table and registers the subscriber against
    /// the resolved literal.
    ///
    /// Unlike [`Self::query_aliased_auto`] /
    /// [`Self::publish_aliased_auto`] (which resolve at call time
    /// and so can fail on every call), subscribers resolve once at
    /// declare and the [`Subscriber`] handle thereafter holds the
    /// resolved literal. A later
    /// [`SessionLinkActions::send_undeclare_kexpr`] retracting
    /// `mapping_id` does NOT affect this Subscriber — the
    /// registration already captured the literal pattern. Mirrors
    /// zenoh-pico's `_z_register_subscription` resolving the
    /// keyexpr once at declare and storing the literal on
    /// `_z_subscription_t`.
    ///
    /// Returns `Err(SubscribeAliasError::UnknownMapping(id))` only
    /// when the mapping is absent at declare time — no
    /// caller-facing error on every callback fire.
    pub fn declare_subscriber_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<Subscriber<R, T>, SubscribeAliasError> {
        let base = self
            .actions()
            .resolve_outbound_mapping(mapping_id)
            .ok_or(SubscribeAliasError::UnknownMapping(mapping_id))?;
        let resolved = match inline_suffix {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        Ok(self.declare_subscriber(resolved, options, callback))
    }

    /// R246 — declare a [`Queryable`] for `keyexpr` + `options` that
    /// fires `callback` on every matching inbound `Request(Query)`.
    /// Pub/sub mirror of [`Self::declare_subscriber`] on the
    /// responder/replier side. Returns a [`Queryable`] handle whose
    /// `Drop` auto-unregisters the queryable from the underlying
    /// [`crate::query::QueryableRegistry`] (RAII).
    ///
    /// Mirrors zenoh-pico's `z_declare_queryable` shape: caller
    /// supplies the keyexpr pattern + options + callback at declare
    /// time; the runtime fires the callback synchronously inside
    /// [`crate::query::QueryableRegistry::dispatch_request`] (wire
    /// arrival) and
    /// [`crate::query::QueryableRegistry::local_query`] (loopback,
    /// R238+). No wire frame is emitted at declare time — router-mode
    /// `DeclareQueryable` is elided in peer-only operation.
    ///
    /// R311r — signature switched to
    /// `Result<Queryable, QueryableAliasError>` for surface parity
    /// with [`Self::declare_queryable_aliased`]; the handler signature is
    /// `FnMut(&dyn QueryView, &mut dyn ReplyOut)` (R311gb-3b model-B seam
    /// contracts) so the application handler depends on the two narrow
    /// contracts rather than the wz-codecs wire types. The new Err
    /// variant a caller sees on this method (over the prior `->
    /// Queryable` form) is `QueryableAliasError::FeatureDisabled`
    /// when the build elides `query-queryable`; default-feature
    /// builds always observe `Ok(...)`. Body cfg-wrap follows the
    /// R311g1 signature-stability principle.
    pub fn declare_queryable(
        &self,
        keyexpr: impl Into<String>,
        options: QueryableOptions,
        callback: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
    ) -> Result<Queryable<R, T>, QueryableAliasError>
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        #[cfg(feature = "query-queryable")]
        {
            let keyexpr_string = keyexpr.into();
            // R311li — DEFERRED FIRE (the R311lf lock-free callback
            // invariant on the queryable plane): the registry stores a
            // staging sink; the handler runs at a drain site OUTSIDE
            // the observer lock over a job-local responder, may
            // re-enter any observer-locking session API, and its
            // replies precede the matching ResponseFinal on the wire
            // (the dispatch SSOT emits finals after the drain).
            let (cell, sink) = self.deferred_query_sink(callback);
            // R311df — observer access via R::with_mutex_mut closure form.
            let id = R::with_mutex_mut(&self.observer, |observer| {
                observer.queryables.register_with_locality(
                    keyexpr_string.clone(),
                    options.allowed_origin,
                    sink,
                )
            });
            Ok(Queryable {
                session: self.clone(),
                id,
                keyexpr: keyexpr_string,
                options,
                cell,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
            })
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = (keyexpr, options, callback);
            Err(QueryableAliasError::FeatureDisabled)
        }
    }

    /// R246 — aliased-keyexpr counterpart of
    /// [`Self::declare_queryable`]. Resolves the
    /// `(mapping_id, inline_suffix)` pair through the outbound
    /// mapping table at declare time. Same one-shot-resolution
    /// contract as [`Self::declare_subscriber_aliased`]: subsequent
    /// `send_undeclare_kexpr` does NOT affect the Queryable handle.
    ///
    /// R311r — body cfg-gated on `query-queryable`; signature stays
    /// stable so the caller's `Result` branch on
    /// `QueryableAliasError::FeatureDisabled` handles the feature-OFF
    /// build uniformly. FeatureDisabled is checked FIRST in the OFF
    /// arm so the early-return preserves zero-side-effect semantics
    /// across all error variants.
    pub fn declare_queryable_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: QueryableOptions,
        callback: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
    ) -> Result<Queryable<R, T>, QueryableAliasError>
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        #[cfg(feature = "query-queryable")]
        {
            let base = self
                .actions()
                .resolve_outbound_mapping(mapping_id)
                .ok_or(QueryableAliasError::UnknownMapping(mapping_id))?;
            let resolved = match inline_suffix {
                None => base,
                Some(s) => {
                    let mut composed = base;
                    composed.push_str(s);
                    composed
                }
            };
            // R311r — delegate to the type-ungated declare_queryable
            // entry. The unwrap is safe inside the cfg-ON branch
            // because the feature-OFF return path is unreachable here
            // (the surrounding cfg block already gates on the same
            // feature).
            self.declare_queryable(resolved, options, callback)
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = (mapping_id, inline_suffix, options, callback);
            Err(QueryableAliasError::FeatureDisabled)
        }
    }

    /// R248 — declare a [`LivelinessToken`] on `keyexpr` + `options`,
    /// emitting a `Declare(DeclToken)` on the outbound link so the
    /// peer's liveliness-token table can fan the declaration out to
    /// any subscribers that intersect the keyexpr. Mirrors
    /// zenoh-pico's `_z_declare_liveliness_token`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:52-95`):
    /// `_z_get_entity_id` allocation → `_z_liveliness_send_declare_token`.
    ///
    /// Wire-side semantics: a fresh `token_id` is allocated via
    /// [`SessionLinkActions::alloc_next_token_id`] (independent
    /// counter from subscriber / queryable / request id spaces, see
    /// the field comment on
    /// [`SessionLinkActions::next_outbound_token_id`]) and embedded
    /// in both the `Declare(DeclToken)` emitted here and the
    /// `Declare(UndeclToken)` emitted by the returned handle's
    /// `Drop` (or explicit [`LivelinessToken::undeclare`]). The
    /// keyexpr is sent in inline-literal form
    /// (`mapping_id = 0, suffix = Some(literal)`); for the
    /// previously-declared-keyexpr alias form use
    /// [`Self::declare_token_aliased`].
    ///
    /// Contrast with [`Self::declare_subscriber`] /
    /// [`Self::declare_queryable`]: those declare APIs are peer-only
    /// (no wire emit at declare time) because zenoh-pico's
    /// router-mode `DeclareSubscriber` / `DeclareQueryable` fan-out
    /// is out of scope for wz. The Liveliness Token is the inverse —
    /// it MUST emit wire on both declare and undeclare so the peer's
    /// liveliness subscribers receive PUT + DELETE samples (per
    /// zenoh-pico's `z_liveliness_declare_token` doc-comment:
    /// "subscribers on an intersecting key expression will receive a
    /// PUT sample when connectivity is achieved, and a DELETE
    /// sample if it's lost").
    ///
    /// Returns a [`LivelinessToken`] handle whose `Drop` emits
    /// `Declare(UndeclToken)` (RAII), retracting the token from the
    /// peer. The token stays alive on the peer for as long as this
    /// handle is alive on the local session.
    ///
    /// Returns `Err(LivelinessAliasError::InvalidKeyexpr(_))` (R300)
    /// when `keyexpr` fails the outbound pico-safety gate — either
    /// non-canonical per the zenoh keyexpr grammar or matching the
    /// R299 bug #3 SIGABRT pattern family. The gate rejects pre-emit,
    /// so the wire bytes never leave and the token id allocator state
    /// is unchanged (the id is *consumed* but with no token-id
    /// bookkeeping leak: `alloc_next_token_id` is a pure counter
    /// `fetch_add`, and a skipped id has no protocol meaning on
    /// either side per zenoh-pico's entity-id contract).
    ///
    /// Returns `Err(LivelinessAliasError::FeatureDisabled)` (R311o)
    /// when the `liveliness-token` feature is disabled on this
    /// `wz-runtime-tokio` build. The method signature stays available
    /// regardless of the feature gate (R311o type-ungating cascade);
    /// the body cfg-gates the wire-emit path and returns the
    /// `FeatureDisabled` variant on a feature-off build so callers do
    /// not need to mirror the cfg-gate at their call site.
    pub fn declare_token(
        &self,
        keyexpr: impl Into<String>,
        options: LivelinessOptions,
    ) -> Result<LivelinessToken<R, T>, LivelinessAliasError> {
        #[cfg(feature = "liveliness-token")]
        {
            let keyexpr_string = keyexpr.into();
            let token_id = self.actions().alloc_next_token_id();
            self.actions()
                .send_declare_token(token_id, /*mapping_id=*/ 0, Some(&keyexpr_string))
                .map_err(|e| match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
                    // W3 — a literal keyexpr longer than MAX_KEYEXPR_BYTES
                    // is a reachable caller-data condition (not a
                    // protocol invariant), so it projects to the typed
                    // public reject rather than the unreachable guard.
                    SendDeclareError::Codec(_) => LivelinessAliasError::ExceedsCapacity,
                    // declare_token always calls send_declare_token in
                    // literal mode (mapping_id = 0, suffix = Some(_)),
                    // so the protocol-invariant variants cannot fire.
                    // The unreachable!() guards future refactors that
                    // change the call shape.
                    other => unreachable!(
                        "declare_token literal-mode send_declare_token returned \
                         {other:?} unexpectedly"
                    ),
                })?;
            // R283 — register the held token in the declarer-side registry
            // so an inbound non-final liveliness Interest can reply with
            // it. The proactive send_declare_token above covers peers
            // already subscribed; this registration is the CURRENT-replay
            // state that lets a peer which subscribes LATER still learn the
            // token via its Interest. Removed by LivelinessToken::Drop.
            R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .local_tokens
                    .register(token_id, &keyexpr_string)
                    .expect("register on the alloc backing never exceeds declared capacity");
            });
            Ok(LivelinessToken {
                session: self.clone(),
                id: token_id,
                keyexpr: keyexpr_string,
                options,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
            })
        }
        #[cfg(not(feature = "liveliness-token"))]
        {
            let _ = (keyexpr, options);
            Err(LivelinessAliasError::FeatureDisabled)
        }
    }

    /// R248 — aliased-keyexpr counterpart of
    /// [`Self::declare_token`]. Resolves `(mapping_id,
    /// inline_suffix)` to the literal form via the outbound mapping
    /// table at declare time (the literal is stored on the returned
    /// handle for introspection symmetry with R245/R246 aliased
    /// flows) AND emits `Declare(DeclToken)` carrying the alias on
    /// the wire (`send_declare_token(token_id, mapping_id,
    /// inline_suffix)` — the more bandwidth-efficient form
    /// zenoh-pico picks natively when the caller hands a previously
    /// `z_declared_keyexpr_t`-form keyexpr to
    /// `z_liveliness_declare_token`).
    ///
    /// Subsequent retraction of `mapping_id` via
    /// [`SessionLinkActions::send_undeclare_kexpr`] does NOT affect
    /// this handle's bookkeeping — the wire frame already left the
    /// session and the peer resolved + stored the literal at
    /// receive time. Same R245/R246 one-shot-resolution contract.
    ///
    /// Returns `Err(LivelinessAliasError::UnknownMapping(id))` when
    /// the mapping is absent at declare time, or
    /// `Err(LivelinessAliasError::InvalidKeyexpr(_))` (R300) when
    /// the reconstructed keyexpr (`prefix || inline_suffix`) fails
    /// the outbound pico-safety gate. Mirror of
    /// [`SubscribeAliasError`] / [`QueryableAliasError`] /
    /// [`QueryAliasError`] / [`PublishAliasError`] on the token
    /// side.
    pub fn declare_token_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: LivelinessOptions,
    ) -> Result<LivelinessToken<R, T>, LivelinessAliasError> {
        #[cfg(feature = "liveliness-token")]
        {
            let base = self
                .actions()
                .resolve_outbound_mapping(mapping_id)
                .ok_or(LivelinessAliasError::UnknownMapping(mapping_id))?;
            let resolved = match inline_suffix {
                None => base,
                Some(s) => {
                    let mut composed = base;
                    composed.push_str(s);
                    composed
                }
            };
            let token_id = self.actions().alloc_next_token_id();
            self.actions()
                .send_declare_token(token_id, mapping_id, inline_suffix)
                .map_err(|e| match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
                    // W3 — reconstructed keyexpr over MAX_KEYEXPR_BYTES is a
                    // reachable caller-data condition projecting to the
                    // typed public reject.
                    SendDeclareError::Codec(_) => LivelinessAliasError::ExceedsCapacity,
                    // F2 — reconnect-window reject, typed through.
                    SendDeclareError::TransportUnavailable => {
                        LivelinessAliasError::TransportUnavailable
                    }
                    SendDeclareError::UnknownMappingId(id) => {
                        // Race against a concurrent send_undeclare_kexpr
                        // between the pre-check resolve_outbound_mapping
                        // above and this send_declare_token call.
                        LivelinessAliasError::UnknownMapping(id)
                    }
                    SendDeclareError::ReservedMappingIdZero | SendDeclareError::MissingKeyexpr => {
                        unreachable!(
                            "declare_token_aliased aliased-mode send_declare_token \
                         returned {e:?} unexpectedly"
                        )
                    }
                    // R311g1 — `liveliness-token = ["declare-token", ...]`
                    // Cargo implication: this branch is reachable only
                    // when `liveliness-token` is ON, which forces
                    // `declare-token` ON via the implication chain. The
                    // signature-stability contract requires the variant
                    // exist in the enum and be matched explicitly, but
                    // the implication chain guarantees the runtime arm
                    // is unreachable.
                    SendDeclareError::FeatureDisabled => unreachable!(
                        "declare-token feature must be ON whenever \
                         liveliness-token is ON (Cargo implication chain); \
                         send_declare_token returned FeatureDisabled despite \
                         liveliness-token-gated caller"
                    ),
                })?;
            Ok(LivelinessToken {
                session: self.clone(),
                id: token_id,
                keyexpr: resolved,
                options,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
            })
        }
        #[cfg(not(feature = "liveliness-token"))]
        {
            let _ = (mapping_id, inline_suffix, options);
            Err(LivelinessAliasError::FeatureDisabled)
        }
    }

    /// R280 — declare a liveliness subscriber on a literal `keyexpr`
    /// pattern, registering a [`LivelinessSampleSink`] that fires
    /// for every peer `Decl*Token` whose resolved keyexpr matches the
    /// pattern. Returns a [`LivelinessSubscriber`] RAII handle whose
    /// `Drop` emits `Interest(Final)` on the outbound link and
    /// removes the slot from the local
    /// [`crate::declare::LivelinessSubscriberRegistry`].
    ///
    /// Mirrors zenoh-pico's `z_liveliness_declare_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:220-235`):
    /// `_z_register_liveliness_subscriber` allocates the entity id and
    /// inserts the slot; `_z_n_interest_encode` emits the Interest
    /// frame; the optional `history` flag in zenoh-pico's
    /// `z_liveliness_subscriber_options_t` becomes the `CURRENT` bit
    /// on the outbound Interest header and gates the peer's
    /// `_z_liveliness_subscription_trigger_history` replay
    /// (interest.c:198).
    ///
    /// ## Wire side
    ///
    /// One `Interest` frame on the reliable channel with body
    /// `flags = KEYEXPRS | TOKENS | RESTRICTED | FUTURE [| CURRENT]`
    /// carrying the literal keyexpr. The peer registers the
    /// subscription against its remote-interests table; subsequent
    /// `Declare(DeclToken)` / `Declare(UndeclToken)` records that the
    /// peer emits for matching keyexprs arrive here through the
    /// session loop and surface to the application as
    /// [`LivelinessSample`] callbacks with kind `Put` / `Delete`.
    ///
    /// ## Registration ordering
    ///
    /// The local slot register runs BEFORE the wire emit so any
    /// racing inbound dispatch (the peer responding to an earlier
    /// session-arming Interest, an out-of-order DeclToken that
    /// arrives before our Interest is processed by the peer) finds
    /// the slot ready and fires the callback instead of silently
    /// dropping. Same ordering rule as
    /// [`crate::pubsub::SubscriberRegistry::register`].
    ///
    /// ## Aliased counterpart
    ///
    /// For previously-declared-keyexpr alias form use
    /// [`Self::declare_liveliness_subscriber_aliased`] (R282) — same
    /// one-shot-resolution contract as
    /// [`Self::declare_subscriber_aliased`] /
    /// [`Self::declare_token_aliased`], plus the wire-side
    /// bandwidth-efficient alias-form `Interest` emit. The literal
    /// form on this method stays the entry point when the caller has
    /// no prior `send_declare_keyexpr` mapping for the pattern.
    ///
    /// ## Established gate — asymmetric with the aliased counterpart
    ///
    /// R283 added a session-FSM `Established` gate to
    /// [`Self::declare_liveliness_subscriber_aliased`] (the aliased
    /// version already returned `Result`, so adding a `NotEstablished`
    /// variant was non-breaking). This non-aliased version
    /// **does NOT yet enforce the gate** — it remains best-effort
    /// against pre-Established state, relying on the driver-side
    /// buffer + SN-window ordering to land the Interest once
    /// handshake completes. The peer may discard a pre-Established
    /// Interest (`remote-interests` table empty) and the local slot
    /// then waits without ever firing a callback.
    ///
    /// Callers that want the explicit-gate contract can either:
    /// - poll [`Self::is_established`] before calling this method, or
    /// - call [`Self::declare_liveliness_subscriber_aliased`] with a
    ///   prior `send_declare_keyexpr` of the literal pattern.
    ///
    /// R311q — signature switched to
    /// `Result<LivelinessSubscriber, LivelinessSubscriberAliasError>`
    /// for surface parity with [`Self::declare_subscriber_aliased`]
    /// and the sibling aliased entry point. The Result form lets a
    /// feature-OFF build return
    /// `Err(LivelinessSubscriberAliasError::FeatureDisabled)` without
    /// breaking the call signature (signature-stability principle per
    /// `feedback_signature_stability`). The legacy non-aliased path
    /// did NOT enforce the R283 `NotEstablished` gate; that asymmetry
    /// is preserved — pre-Established Interests stay best-effort here
    /// and only the aliased surface returns `NotEstablished` — so the
    /// only NEW Result variant a caller hits on this method is
    /// `FeatureDisabled` (default-build paths still observe `Ok(...)`).
    pub fn declare_liveliness_subscriber(
        &self,
        keyexpr: impl Into<String>,
        options: LivelinessSubscriberOptions,
        callback: impl FnMut(LivelinessSample<'_>) + Send + 'static,
    ) -> Result<LivelinessSubscriber<R, T>, LivelinessSubscriberAliasError> {
        #[cfg(feature = "liveliness-subscriber")]
        {
            let keyexpr_string = keyexpr.into();
            let interest_id = self.actions().alloc_next_interest_id();
            // R311lg — DEFERRED FIRE (the R311lf lock-free callback
            // invariant on the liveliness-sample plane): the registry
            // stores a staging sink that copies each matched sample out
            // and stages it on the session's deferred-fire queue; the
            // drive loop's dispatch SSOT runs `callback` AFTER the
            // observer lock drops, so the callback may re-enter any
            // observer-locking session API (declares, publishes with
            // local loopback, queries, even its own handle's
            // `undeclare`) without self-deadlocking.
            let (cell, sink) = self.deferred_liveliness_sample_sink(callback);
            // Register first, emit Interest second — the order matters for
            // races against an inbound DeclToken whose Interest reached
            // the peer earlier (e.g. a re-declared subscriber after a
            // session-layer Reconnect, R267+ topology). The wire-emit
            // panic-free invariant from `send_declare_token` applies
            // equally to `send_interest_liveliness_subscriber`.
            //
            // R311dh — observer access via R::with_mutex_mut closure form.
            R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .liveliness_subscribers
                    .register(interest_id, &keyexpr_string, options.history, sink)
                    .expect("register on the alloc backing never exceeds declared capacity");
            });
            // R311ll (Finding B) — roll the slot back if the wire emit
            // fails. Register-first guards the race against an inbound
            // DeclToken (the slot matches by keyexpr, so a proactive peer
            // declaration can fire it before our Interest lands), but a
            // FAILED send means no Interest reached the peer: the slot
            // would be a permanent orphan firing a callback the caller
            // got no handle to retract. Kill the cell first (suppress any
            // sample staged in the register->send window, the same
            // suppression order as `undeclare`), drop the orphaned slot,
            // and surface the error. No Interest(Final) wire retract —
            // nothing was ever declared to the peer.
            if let Err(e) = self.actions().send_interest_liveliness_subscriber(
                interest_id,
                options.history,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            ) {
                cell.kill();
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_subscribers.unregister(interest_id);
                });
                return Err(e.into());
            }
            Ok(LivelinessSubscriber {
                session: self.clone(),
                interest_id,
                keyexpr: keyexpr_string,
                options,
                cell,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
            })
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = (keyexpr, options, callback);
            Err(LivelinessSubscriberAliasError::FeatureDisabled)
        }
    }

    /// R282 — aliased-keyexpr counterpart of
    /// [`Self::declare_liveliness_subscriber`]. Resolves `mapping_id` +
    /// `inline_suffix` to the literal form *at declare time* via the
    /// outbound mapping table and registers the slot against the
    /// resolved literal; the outbound `Interest` frame carries the
    /// alias form (`mapping_id` + optional `inline_suffix`) on the
    /// wire so the peer's `_z_n_interest_decode` can pick the
    /// bandwidth-efficient form natively — same rationale as
    /// [`Self::declare_token_aliased`].
    ///
    /// ## One-shot resolution
    ///
    /// Resolution runs once at declare time. A subsequent
    /// [`SessionLinkActions::send_undeclare_kexpr`] retracting
    /// `mapping_id` does NOT affect this handle's bookkeeping:
    ///
    /// - the local slot already captured the resolved literal pattern
    ///   so callback dispatch (which matches inbound `Decl*Token`
    ///   resolved keyexprs against the slot's stored pattern) keeps
    ///   firing;
    /// - the wire frame already left the session, so the peer's
    ///   `remote-interests` table already holds the resolved
    ///   subscription.
    ///
    /// Same contract as [`Self::declare_subscriber_aliased`] /
    /// [`Self::declare_queryable_aliased`] /
    /// [`Self::declare_token_aliased`] on their respective sides.
    ///
    /// ## Registration ordering
    ///
    /// Slot register precedes wire emit, identical to
    /// [`Self::declare_liveliness_subscriber`] — the race against an
    /// inbound `DeclToken` arriving before our `Interest` is processed
    /// by the peer (or against a re-declared subscriber after a
    /// session-layer Reconnect, R267+ topology) needs the slot ready
    /// at callback-dispatch time.
    ///
    /// ## Errors
    ///
    /// - `Err(LivelinessSubscriberAliasError::UnknownMapping(id))`
    ///   (R282) when the mapping is absent at declare time. Mirror of
    ///   [`SubscribeAliasError`] / [`QueryableAliasError`] /
    ///   [`QueryAliasError`] / [`PublishAliasError`] /
    ///   [`LivelinessAliasError`] on the liveliness subscriber side.
    /// - `Err(LivelinessSubscriberAliasError::NotEstablished)` (R283)
    ///   when the session-FSM has not yet entered `Established`. A
    ///   pre-Established Interest is silently dropped by the peer (no
    ///   `remote-interests` table entry yet); rejecting at the API
    ///   boundary surfaces the bug to the caller. Poll
    ///   [`Self::is_established`] (or wire a session-layer
    ///   Established signal at the higher tier) before retrying.
    ///
    /// Variant ordering: `UnknownMapping` first (mapping resolution is
    /// FSM-state-independent and cheaper), then `NotEstablished`. A
    /// pre-Established call with an unknown mapping returns
    /// `UnknownMapping`, surfacing the bug-class error before the
    /// session-state-dependent retry loop. No slot register, no
    /// interest-id allocation, no wire emit on either early-return
    /// path.
    ///
    /// R311q — body cfg-gated under the `liveliness-subscriber`
    /// feature; the signature stays stable so the caller's `Result`
    /// branch on `LivelinessSubscriberAliasError::FeatureDisabled`
    /// handles the feature-OFF build uniformly (R311 signature-
    /// stability principle). FeatureDisabled is checked FIRST in the
    /// feature-OFF arm so the early-return preserves zero-side-effect
    /// semantics across all error variants.
    pub fn declare_liveliness_subscriber_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        options: LivelinessSubscriberOptions,
        callback: impl FnMut(LivelinessSample<'_>) + Send + 'static,
    ) -> Result<LivelinessSubscriber<R, T>, LivelinessSubscriberAliasError> {
        #[cfg(feature = "liveliness-subscriber")]
        {
            // Mapping check first — FSM-state-independent, surfaces a
            // bug-class error (caller forgot send_declare_keyexpr) before
            // the state-dependent retry loop. R282 + R283 ordering rule.
            let base = self
                .actions()
                .resolve_outbound_mapping(mapping_id)
                .ok_or(LivelinessSubscriberAliasError::UnknownMapping(mapping_id))?;
            // R283 Established gate. Done after mapping resolution so a
            // pre-Established call with a bad mapping surfaces the bad
            // mapping (the bug) rather than the transient state. No
            // interest-id is burned on the early-return path.
            if !self.actions().is_established() {
                return Err(LivelinessSubscriberAliasError::NotEstablished);
            }
            let resolved = match inline_suffix {
                None => base,
                Some(s) => {
                    let mut composed = base;
                    composed.push_str(s);
                    composed
                }
            };
            let interest_id = self.actions().alloc_next_interest_id();
            // R311lg — deferred staging sink; same lock-free callback
            // contract as `declare_liveliness_subscriber`.
            let (cell, sink) = self.deferred_liveliness_sample_sink(callback);
            // Register first against the resolved literal so any racing
            // inbound dispatch (peer responding to an earlier
            // session-arming Interest, an out-of-order DeclToken that
            // arrives before our Interest is processed by the peer) finds
            // the slot ready and fires the callback. Same ordering rule
            // as `declare_liveliness_subscriber`.
            //
            // R311dh — observer access via R::with_mutex_mut closure form.
            R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .liveliness_subscribers
                    .register(interest_id, &resolved, options.history, sink)
                    .expect("register on the alloc backing never exceeds declared capacity");
            });
            // Wire emit carries the alias form so the peer pays the
            // mapping_id + optional inline_suffix cost rather than the
            // full literal each time — bandwidth parity with
            // `declare_token_aliased`'s aliased wire emit.
            // R311ll (Finding B) — same wire-emit rollback as the literal
            // `declare_liveliness_subscriber`: a failed alias-form Interest
            // leaves no peer subscription, so the keyexpr-matched slot must
            // not survive as an orphan. Kill the cell (suppress a sample
            // staged in the register->send window), drop the slot, surface
            // the error; no Interest(Final) retract (nothing was declared).
            if let Err(e) = self.actions().send_interest_liveliness_subscriber(
                interest_id,
                options.history,
                mapping_id,
                inline_suffix,
            ) {
                cell.kill();
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_subscribers.unregister(interest_id);
                });
                return Err(e.into());
            }
            Ok(LivelinessSubscriber {
                session: self.clone(),
                interest_id,
                keyexpr: resolved,
                options,
                cell,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
            })
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = (mapping_id, inline_suffix, options, callback);
            Err(LivelinessSubscriberAliasError::FeatureDisabled)
        }
    }

    /// liveliness-get — one-shot snapshot of the peer's currently-alive
    /// liveliness tokens matching `keyexpr`. Emits a single CURRENT
    /// liveliness `Interest` (C=1, F=0); the peer replies with one
    /// `on_reply` invocation per matching live token (the reply's
    /// keyexpr is the token's keyexpr; a liveliness reply carries no
    /// payload), terminated by exactly one `on_final`. Mirrors
    /// zenoh-pico's `z_liveliness_get`
    /// (`vendor/zenoh-pico/src/api/liveliness.c:119`).
    ///
    /// Wire = the declaration plane, NOT the query (Request/Response)
    /// plane: the request is an `Interest`, the replies are
    /// `Declare(DeclToken)` records, the terminator a
    /// `Declare(DeclFinal)` — all `interest_id`-correlated. The
    /// application *surface* is reply-shaped (the same `on_reply` +
    /// `on_final` seam as [`Self::query`]), matching zenoh's reply-stream
    /// get API, but there is no `Request(Query)` on the wire and no
    /// dependency on the query plane.
    ///
    /// `options.timeout_ms == 0` registers the pending get with no
    /// deadline (it stays pending until the peer's `DeclFinal` arrives);
    /// a non-zero value arms a timeout the host sweeps via
    /// `LivelinessGetRegistry::sweep_timed_out` (the wz-ap-demo sweep
    /// ticker drives it alongside the reply registry; F3), firing
    /// `on_final` if the peer never terminates the snapshot so the
    /// pending slot cannot leak. Because a get is one-shot (unlike a
    /// re-fireable subscription) this surface enforces the
    /// [`Self::is_established`] gate — an Interest emitted mid-handshake
    /// is silently discarded by the peer and the snapshot would hang
    /// until timeout — returning [`LivelinessGetError::NotEstablished`]
    /// rather than best-effort emitting (the asymmetry with the literal
    /// `declare_liveliness_subscriber` is deliberate: a lost subscription
    /// Interest can be re-declared, a lost one-shot get cannot).
    ///
    /// R311g1 — signature-stability: body cfg, signature stable. Returns
    /// [`LivelinessGetError::FeatureDisabled`] when `liveliness-get` is
    /// off (both the wire-emit and observer-dispatch paths are elided).
    pub fn liveliness_get(
        &self,
        keyexpr: impl Into<String>,
        options: LivelinessGetOptions,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<(), LivelinessGetError> {
        #[cfg(feature = "liveliness-get")]
        {
            if !self.is_established() {
                return Err(LivelinessGetError::NotEstablished);
            }
            let keyexpr_string = keyexpr.into();
            let interest_id = self.actions().alloc_next_interest_id();
            // R262 — absolute monotonic-ms deadline (same epoch contract
            // as `Session::query`: the application threads one `Arc<T>`
            // clock through both `Session::new` and
            // `drive_session_until_terminal`). timeout_ms == 0 → None
            // (never expires).
            let deadline_ms = (options.timeout_ms > 0)
                .then(|| self.clock.now_monotonic_ms() + options.timeout_ms as u64);
            // Register the pending get first, emit the Interest second —
            // the order matters against a peer reply whose Interest
            // reached it before we recorded the pending entry (same race
            // reasoning as `declare_liveliness_subscriber`).
            // R311lk — install a DEFERRED reply sink (the same staging
            // seam z_get uses since R311lg) rather than the raw user
            // closures: `on_reply` / `on_final` then run at the
            // post-dispatch drain OUTSIDE the observer lock, not inside
            // `LivelinessGetRegistry::dispatch_*` / `sweep_timed_out`
            // under it, so a get callback may re-enter any
            // observer-locking session API (e.g. issue another get).
            // Both fire paths already drain `fires` after releasing the
            // lock: the inbound DeclToken/DeclFinal dispatch via
            // `dispatch_iteration_event{_with}`, the timeout sweep via
            // the host sweep task's trailing `drain_deferred_fires`. The
            // sink is built before the lock (a pure construction over the
            // cloned `fires` handle; it never touches the observer).
            let sink = self.deferred_reply_sink(on_reply, on_final);
            R::with_mutex_mut(&self.observer, |observer| {
                observer
                    .liveliness_gets
                    .register(interest_id, deadline_ms, sink)
                    .expect("register on the alloc backing never exceeds declared capacity");
            });
            // R311ll (Finding B) — roll the pending get back if the wire
            // emit fails. Unlike the keyexpr-matched subscriber slot, a
            // get correlates by FRESH interest_id, so no solicited reply
            // can exist before this Interest is sent: nothing could have
            // staged in the register->send window, and `unregister` alone
            // is a complete rollback (it drops the entry, and with it the
            // deferred sink's cell). Without this the orphaned entry leaks
            // — or, with a deadline, fires a spurious sweep on_final for a
            // get the caller got no success from.
            if let Err(e) = self.actions().send_interest_liveliness_get(
                interest_id,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            ) {
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_gets.unregister(interest_id);
                });
                return Err(e.into());
            }
            Ok(())
        }
        #[cfg(not(feature = "liveliness-get"))]
        {
            let _ = (keyexpr, options, on_reply, on_final);
            Err(LivelinessGetError::FeatureDisabled)
        }
    }
}

#[cfg(test)]
mod tests;
