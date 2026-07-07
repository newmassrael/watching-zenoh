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
//! (`wz-runtime-coop` / `wz-runtime-embassy`) will rebind the alias
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

/// R311y94 (review V2) — build the loopback Query carrying the GET's selector
/// parameters (`_sn` / `_max`) so a `SessionLocal` queryable's handler observes the
/// same selector the wire path delivers. Before this the loopback fan built
/// `Query::default()` with empty params, so a queryable's `answer_from_ring` never
/// filtered on loopback: `_max` over-returned and `_sn` only "worked" because the
/// advanced subscriber's reorder buffer masked the cache's over-return. Mirrors the
/// wire `query_metadata().parameters` threading.
///
/// R311y96 (review-arbiter MED) — `try_into_owned` is INFALLIBLE on this `alloc`
/// runtime profile: the owned `parameters` is `SceBytes<256>` whose `from_slice` is
/// an unbounded heap copy under `alloc` (`N` advisory), so the conversion never
/// rejects. The prior `unwrap_or_else` degrade-to-no-selector branch was dead code
/// documenting an impossible case (and, had this fn ever compiled on a no-alloc
/// profile, silently dropping the selector would over-return, not "gracefully
/// degrade"). Resolved to a named `.expect` of the real invariant.
#[cfg(all(feature = "query-get", feature = "query-queryable"))]
fn build_loopback_query(opts: &QueryOptions) -> wz_codecs::query::QueryOwned {
    #[cfg_attr(not(feature = "query-selector-parameters"), allow(unused_mut))]
    let mut q = Query::default();
    #[cfg(feature = "query-selector-parameters")]
    if let Some(params) = opts.parameters.as_deref() {
        q.parameters = Some(params);
        q.parameters_len = Some(params.len() as u64);
        q.set_p(true);
    }
    #[cfg(not(feature = "query-selector-parameters"))]
    let _ = opts;
    q.try_into_owned()
        .expect("loopback Query owns its selector by the infallible alloc SceBytes copy")
}
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
// R311nb (Level B, B5b-2b tail) — import each `Sample` metadata-hint enum to
// exactly where it has a consumer so every feature subset stays unused-import
// clean after the publish convergence:
//   * `SampleKind` — the Put/Del discriminator the now-AGNOSTIC
//     `Session::publish` remote leg matches (codec-push) and the
//     `transport-unicast` `Publisher` / `publish_aliased` set (via `super::*`);
//     gated on either so a multicast-only + codec-push build still sees it.
//   * `EncodingHint` / `SourceInfo` — named by the `transport-unicast`
//     `querier` / `queryable` `QueryOptions` struct fields (unconditional in a
//     `transport-unicast` build, consumed via `super::*`).
//   * `Reliability` / `TimestampHint` / `QosLevel` — named only by the
//     `cfg(test)` module now (their former lib consumer `PublishOptions` moved
//     to `publish_common`, which carries its own imports). `Reliability` rides
//     the always-compiled option tests; `TimestampHint` / `QosLevel` ride only
//     the feature-gated `with_timestamp` / `with_qos` loopback tests, so each
//     ANDs in the populator's own feature gate to stay subset-clean.
#[cfg(all(
    test,
    any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    )
))]
use crate::sample::QosLevel;
#[cfg(test)]
use crate::sample::Reliability;
#[cfg(any(feature = "transport-unicast", feature = "codec-push"))]
use crate::sample::SampleKind;
#[cfg(all(test, feature = "pubsub-timestamp"))]
use crate::sample::TimestampHint;
#[cfg(feature = "transport-unicast")]
use crate::sample::{EncodingHint, SourceInfo};
// R311gb-2b / R311nb — `declare_subscriber` takes `impl FnMut(&dyn
// SampleView)` and the `pubsub-allow-loop` loopback assembly
// (`build_loopback_sample`) moved to `publish_common` (importing `Sample`
// itself), so the only remaining mod.rs consumer of the owned `Sample` type
// is the `cfg(test)` module (via `super::*`); `subscriber.rs` names it by the
// full `crate::sample::Sample` path. Gate the import to `test` to keep every
// non-test lib build unused-import clean.
#[cfg(test)]
use crate::sample::Sample;
// R311mn (B2) — every `session_glue` import gains a `transport-unicast`
// conjunct: `session_glue` is `#[cfg(feature = "transport-unicast")]`, so
// in a multicast-only build the module (and these types) do not exist.
// The consumers (the gated unicast `Session` methods + the gated
// submodules) all carry the same `transport-unicast` gate, so ANDing it in
// here is a no-op in a unicast-on build and elides a dangling import in a
// multicast-only build.
// R311pb — `SendDeclareError` is named by THREE error projectors, each with its
// own feature gate: `map_decl_err` (liveliness-token, declare_token{,_aliased}),
// `map_subscribe_err` (declare-subscriber, announce_subscriber), and
// `map_queryable_err` (declare-queryable AND query-queryable, since
// announce_queryable is query-queryable-gated). The import gate is the EXACT
// union of those three so the type is in scope iff at least one projector
// compiles — no missing-import (a `declare-subscriber`/`declare-queryable` build
// with liveliness-token OFF previously failed E0425, the R311ou/ow latent gate
// bug this round fixes) and no unused-import (a `declare-queryable` build with
// query-queryable OFF must NOT pull it in, since `announce_queryable` is absent).
#[cfg(all(
    feature = "transport-unicast",
    any(
        feature = "liveliness-token",
        feature = "declare-subscriber",
        all(feature = "query-queryable", feature = "declare-queryable")
    )
))]
use crate::session_glue::SendDeclareError;
#[cfg(feature = "transport-unicast")]
use crate::session_glue::SendWireError;
#[cfg(feature = "transport-unicast")]
use crate::session_glue::SessionLinkActions;
// R311nb — the `PushMetadata` import is retired here: its sole mod.rs
// consumer was `PublishOptions::push_metadata`, which moved to
// `publish_common` (importing `PushMetadata` from its ungated real home
// `wz_session_core::metadata`). `Session::publish` only handles the *value*
// `opts.push_metadata()` returns, never naming the type.
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
// R311nf — `decl_listener` / `matching_listener` are UNICAST-only features
// (declare-listeners + publisher/querier matching status; a multicast session
// has no declares / publishers / queriers), so the typestate gates them
// `transport-unicast` and they store a `Session<R, T, Unicast>`.
#[cfg(feature = "transport-unicast")]
mod decl_listener;
#[cfg(feature = "transport-unicast")]
mod liveliness;
#[cfg(feature = "transport-unicast")]
mod matching_listener;
// R311nb (Level B, B5b-2b tail) — the transport-AGNOSTIC publish value
// surface (`PublishOptions` / `PublishError` / `build_loopback_sample`),
// ungated so the unified `Session::publish` reaches it on every transport.
// The `transport-unicast` `publisher` cluster (handles + aliased path) is
// split below.
mod publish_common;
#[cfg(feature = "transport-unicast")]
mod publisher;
#[cfg(feature = "transport-unicast")]
mod querier;
#[cfg(feature = "transport-unicast")]
mod queryable;
mod subscriber;
// R311nf — the per-session transport TYPESTATE (was the R311mm `SessionTransport`
// runtime sum). Internal module; the public surface is re-exported below.
mod transport;
// R311nf — the transport typestate (was the `SessionTransport` runtime sum).
// `TransportState` is the ungated trait surface (struct bound + agnostic impl
// bound); the `Unicast` / `Multicast` markers are each gated on their catalog
// atom, named only by the matching transport-gated alias + impl block.
#[cfg(feature = "transport-unicast")]
pub use decl_listener::*;
#[cfg(feature = "transport-unicast")]
pub use liveliness::*;
#[cfg(feature = "transport-unicast")]
pub use matching_listener::*;
pub use publish_common::*;
#[cfg(feature = "transport-unicast")]
pub use publisher::*;
#[cfg(feature = "transport-unicast")]
pub use querier::*;
#[cfg(feature = "transport-unicast")]
pub use queryable::*;
pub use subscriber::*;
#[cfg(feature = "transport-multicast")]
pub use transport::Multicast;
pub use transport::TransportState;
#[cfg(feature = "transport-unicast")]
pub use transport::Unicast;

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
pub struct Session<R: SessionRuntime, T: TimeSource, Tp>
where
    Tp: TransportState<R, T>,
{
    /// The transport-specific payload, projected from the [`Tp`](TransportState)
    /// typestate marker: the unicast [`SessionLinkActions`] bundle on a
    /// `Session<R, T, Unicast>`, or the multicast TX seam on a
    /// `Session<R, T, Multicast>`. R311nf lifted this from the R311mm runtime
    /// sum `SessionTransport<R, T>` to the `<Tp as TransportState<R, T>>::Payload`
    /// projection: the transport is now known at the type level, so the
    /// transport-specific surface (unicast `actions` / `dispatch_iteration_event`,
    /// multicast `dispatch_multicast_iteration_event`) lives on transport-gated
    /// `impl` blocks and an illegal cross-transport call is a compile error,
    /// not a runtime `Err(UnsupportedVariant)` / silent no-op. R311di-pre-f1b
    /// binds the unicast payload's TimeSource parameter to the same `T` as the
    /// surrounding Session so the action bundle's `clock` field shares the
    /// monotonic epoch with the Session's own `clock: Arc<T>` slot (the R311cw
    /// single-epoch invariant).
    transport: <Tp as TransportState<R, T>>::Payload,
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
    /// `wz_runtime_coop::CoopTime<C>` once Session moves to a
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
// R311nf — `where <Tp as TransportState>::Payload: Clone` replaces the
// old enum's hand-written cfg'd `Clone` match. Both concrete payloads
// satisfy it: the unicast `Arc<SessionLinkActions<R, T>>` is `Clone` for any
// inner; the multicast `MulticastPayload` derives `Clone` (its `tx` sender is
// `Clone`, and the no-`codec-push` form is field-less).
impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Clone for Session<R, T, Tp>
where
    <Tp as TransportState<R, T>>::Payload: Clone,
{
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            observer: self.observer.clone(),
            fires: self.fires.clone(),
            clock: self.clock.clone(),
        }
    }
}

/// R311cq — explicit alias for the tokio-runtime-bound UNICAST Session.
/// R311nf dropped the bare-`Session` default-param ergonomic (the transport
/// typestate `Tp` has no safe default: a `Tp = Unicast` default would name a
/// `transport-unicast`-gated marker that is absent in a multicast-only build,
/// and the "defaults must be trailing" rule forbids a non-defaulted `Tp` after
/// the defaulted `R` / `T`). So the bare `Session` name no longer resolves;
/// call sites name the transport explicitly through this alias (unicast) or
/// [`TokioMulticastSession`] (multicast). Gated `transport-unicast` because it
/// names the `Unicast` marker; a future wz-runtime-coop surfaces its own
/// `CoopSession<C> = Session<CoopRuntime<C>, CoopTime<C>, Unicast>` alias.
#[cfg(feature = "transport-unicast")]
pub type TokioSession = Session<TokioRuntime, TokioTime, Unicast>;

/// R311nf — explicit alias for the tokio-runtime-bound MULTICAST Session (the
/// multicast counterpart of [`TokioSession`]). Gated `transport-multicast`.
/// A both-transport build exposes both aliases side by side; the typestate
/// keeps their surfaces disjoint (no `dispatch_iteration_event` on this one,
/// no `dispatch_multicast_iteration_event` on [`TokioSession`]).
#[cfg(feature = "transport-multicast")]
pub type TokioMulticastSession = Session<TokioRuntime, TokioTime, Multicast>;

// R311mn (Level B, B2) — the TRANSPORT-AGNOSTIC `Session` surface. These
// methods read the transport-independent fields (`observer` / `fires` /
// `clock`) without ever projecting the transport sum's unicast variant
// (no `self.actions()`, no `session_glue` type), so they compile in EVERY
// transport configuration — unicast-only, both, AND the new
// multicast-only build. They are split out of the (now `transport-unicast`-
// gated) big impl block below precisely so a multicast-only `Session` still
// exposes observer / clock / deferred-fire-drain / zid-dedup. The unicast
// publish / query / declare surface stays on the `Unicast` block.
//
// R311nf — the block is generic over the transport typestate
// `Tp: TransportState<R, T>`, so every method here compiles for BOTH a
// `Session<R, T, Unicast>` and a `Session<R, T, Multicast>`. The send seam
// (`send_network_message`) dispatches through `Tp::send_network_message` at
// compile time; the loopback / observer / clock / zid surface touches no
// transport payload at all.
impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Session<R, T, Tp> {
    /// R311nb (Level B, B5b-2b tail) — publish a literal-keyexpr Sample. The
    /// single, TRANSPORT-AGNOSTIC publish SSOT: it supersedes BOTH the prior
    /// `transport-unicast` `publish` and the multicast-only
    /// `publish(keyexpr, payload)` (R311mo/mp), because neither leg needs to
    /// know the transport.
    ///
    /// * **Remote leg** (`codec-push`-gated): builds the Put / Del as a
    ///   transport-agnostic `NetworkMessage::Push` and hands it to
    ///   [`Self::send_network_message`] (the `_z_send_n_msg`-analogue send
    ///   seam), which runtime-dispatches to the owned transport — the unicast
    ///   `SessionLinkActions` `dispatch_push` + express batch-flush, or the
    ///   multicast TX channel the
    ///   [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    ///   loop drains. Fire-and-forget (the seam swallows a dead unicast link /
    ///   a closed multicast receiver). Routed only when
    ///   `opts.allowed_destination` allows remote; a build without `codec-push`
    ///   elides the leg entirely (loopback still runs) rather than `?`-aborting
    ///   on a `FeatureDisabled` reject.
    /// * **Local loopback leg** (`pubsub-allow-loop`-gated): builds the Sample
    ///   via [`build_loopback_sample`] (threading every `opts` metadata field —
    ///   timestamp / encoding / source_info / attachment / qos, R232), delivers
    ///   it in-process through
    ///   [`crate::pubsub::SubscriberRegistry::local_publish`], then drains the
    ///   deferred-fire queue so the subscriber callbacks run on the caller
    ///   thread OUTSIDE the observer lock (R227+ / R311lh / R311lj). Routed only
    ///   when `opts.allowed_destination` allows local. A
    ///   `Locality::SessionLocal`/`Any` subscriber fires; a `Remote`-only one
    ///   is suppressed.
    ///
    /// Returns the number of loopback subscriber callbacks fired (0 when
    /// `allows_local()` is false, no subscriber matches, or `pubsub-allow-loop`
    /// is off). Wire-leg outcomes are fire-and-forget, not reported here.
    ///
    /// Mirrors zenoh-pico's `_z_write` (`vendor/zenoh-pico/src/net/primitives.c`
    /// 170-205): wire branch under `allows_remote()`, loopback under
    /// `allows_local()`, both under the `Locality::Any` default. The transport
    /// split lives in [`Self::send_network_message`], NOT at this API boundary —
    /// the north-star pico shape (build a `NetworkMessage`, call the one seam).
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> Result<usize, PublishError> {
        // W3 — the remote wire leg is `codec-push`-gated (symmetric with the
        // `pubsub-allow-loop` loopback gate below). On a build without
        // `codec-push` the Push codec is statically absent, so the remote leg
        // is elided entirely and the loopback leg still runs. With `codec-push`
        // on, the only runtime reject is a payload/keyexpr that overflows the
        // declared codec capacity (`PublishError::ExceedsCapacity`).
        #[cfg(feature = "codec-push")]
        if opts.allowed_destination.allows_remote() {
            // R311nb — `SendWireError` imported locally from its ungated real
            // home: the module-level import is `transport-unicast`-gated, absent
            // in a multicast-only build where this agnostic leg still compiles.
            use wz_session_core::send_wire_error::SendWireError;
            let reliable = opts.reliable_bool();
            let meta = opts.push_metadata();
            // R311mv (session review) — `express` is the SSOT projection on
            // `PushMetadata` (`meta.is_express()`); the seam gates its *effect*
            // on `transport-batching` (the unicast arm drains the open batch
            // window after an express send; the multicast arm ignores it — UDP
            // multicast has no batch window).
            let express = meta.is_express();
            // R311ms / R311nb — build the Put / Del as a `NetworkMessage::Push`
            // (the transport-agnostic outbound currency) and route it through
            // the [`Self::send_network_message`] seam, which runtime-dispatches
            // to the owned transport. The builder's `CodecError` maps to
            // `SendWireError::Codec` -> `ExceedsCapacity` via
            // `From<SendWireError> for PublishError`.
            let push = match opts.kind {
                SampleKind::Put => wz_session_core::push_build::build_push_literal_with_meta(
                    keyexpr, payload, &meta,
                ),
                SampleKind::Del => {
                    wz_session_core::push_build::build_push_del_literal_with_meta(keyexpr, &meta)
                }
            }
            .map_err(SendWireError::Codec)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Push(Box::new(push)),
                reliable,
                express,
            )?;
        }
        // R311cc — pubsub-allow-loop gates the local_publish loopback branch.
        // cfg-off short-circuits to 0 (only remote dispatch fires; the
        // `Locality::Any` default becomes effectively Remote-only). R311db —
        // observer access via the R::with_mutex_mut closure form (R311ct API).
        #[cfg(feature = "pubsub-allow-loop")]
        {
            let delivered = if opts.allowed_destination.allows_local() {
                let sample = build_loopback_sample(keyexpr, payload, &opts);
                let delivered = R::with_mutex_mut(&self.observer, |observer| {
                    observer.subscribers.local_publish(&sample)
                });
                // R311lh / R311lj — drain the fires THIS publish staged (the
                // loopback `local_publish`) so the local subscriber callbacks
                // run synchronously on the caller thread, outside the observer
                // lock, before `publish` returns. Gated on the local-delivery
                // path (a Remote-only publish stages nothing). The
                // observer-serialized take keeps a concurrent drive-loop batch
                // atomic (R311lj).
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

    /// R311mr (B5b-1) / R311ms (B5b-2) — the transport-dispatch SEND SEAM, the
    /// wz analogue of zenoh-pico's `_z_send_n_msg`
    /// (`zenoh-pico/src/transport/transport.c:29` — `switch (zt->_type)` over
    /// the unicast / multicast transport tag, called by every put / get /
    /// declare primitive in `src/net/primitives.c`). Takes a fully-built
    /// [`NetworkMessage`](wz_session_core::network_message::NetworkMessage) (the
    /// transport-agnostic outbound currency, pico's `_z_network_message_t`) plus
    /// the channel `reliable` flag and the batching `express` hint, and routes
    /// it to the owned transport's send path. The whole point is that the
    /// application API above it (`publish`, later query / declare / reply) stays
    /// transport-agnostic — it builds a `NetworkMessage` and calls this seam;
    /// the transport split lives HERE, not at every call site (the north-star
    /// pico shape, not a fallible `actions()` projection exposed everywhere).
    ///
    /// `express` mirrors pico `_z_send_n_msg`'s `cong_ctrl` arm: the UNICAST arm
    /// drains its open batch window after an express-flagged send (the
    /// `flush_batch_if_express` parity); the MULTICAST arm ignores it (UDP
    /// multicast is best-effort with no per-session batch window).
    ///
    /// B5b-2 scope: both arms now exist, but they never COEXIST in one build —
    /// the unicast arm is `transport-unicast`-gated and the multicast arm
    /// `all(transport-multicast, not(transport-unicast))`-gated, so the `match`
    /// is a degenerate single arm in every build (unicast in a unicast-only /
    /// both-transports build; multicast in a multicast-only build). Dropping
    /// the `not(transport-unicast)` gate so a both-transports build holds a
    /// multicast `Session` and the `match` runtime-dispatches is B5b-2b — that
    /// round also dismantles [`Self::actions`] across its remaining call sites
    /// (publish having moved here).
    ///
    /// Origination on the unicast arm is Push (publish) + Request (z_get, added
    /// R311mu / B5b-2b-2) + Declare (liveliness-token declare/undeclare, added
    /// R311mw / B5b-2b-3) + Interest (liveliness subscriber/get/final, added
    /// R311mx / B5b-2b-4); the remaining outbound variant (Response) migrates
    /// as its operations move onto the seam. The multicast
    /// arm stays Push-only and exposes only
    /// `publish` (the reply messages are emitted by the drive-loop
    /// [`MulticastReplySink`](crate::multicast_glue::MulticastReplySink), not
    /// this seam). A non-`Push` reaching the MULTICAST arm returns
    /// [`SendWireError::UnsupportedVariant`](wz_session_core::send_wire_error::SendWireError)
    /// — the one transport-variant mismatch the seam reports (a multicast
    /// session originates only Push); a build whose transport has no wire codec
    /// returns [`SendWireError::FeatureDisabled`] instead (the build-time codec
    /// elision, kept distinct from the variant mismatch per #3b). Both are
    /// honest no-emit rejects, never a panic. `SendWireError` is the SAME error
    /// the unicast `dispatch_*` family returns and lives ungated in
    /// `wz_session_core` (the `transport-unicast`-gated `session_glue` re-export
    /// is just a path), so the seam's `Result` is already transport-uniform.
    // R311nf — the send seam is now a thin forwarder to the typestate's
    // [`TransportState::send_network_message`]: the per-transport send body
    // lives in `session::transport` (one place each — the unicast
    // `SessionLinkActions` dispatch family, the multicast `MulticastTxItem`
    // enqueue), and this agnostic method dispatches by type at compile time
    // (no runtime `match`, no `_ =>` arm, no transport-mismatch projection).
    // The gate is unchanged from R311nd — it pins the seam to exactly the
    // builds with a caller: the unicast publish + query + liveliness surface
    // (`any(codec-push, codec-request, codec-declare, declare-interest)`) and
    // the multicast publish (`all(transport-multicast, codec-push)`).
    #[cfg(any(
        all(
            feature = "transport-unicast",
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-declare",
                feature = "declare-interest"
            )
        ),
        all(feature = "transport-multicast", feature = "codec-push")
    ))]
    pub fn send_network_message(
        &self,
        msg: wz_session_core::network_message::NetworkMessage,
        reliable: bool,
        express: bool,
    ) -> Result<(), wz_session_core::send_wire_error::SendWireError> {
        Tp::send_network_message(&self.transport, msg, reliable, express)
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

    /// Sweep expired pending queries (reply-registry deadline enforcement)
    /// using the Session's own monotonic clock, then drain any resulting
    /// `on_final` fires. A `query` registered with a `query-timeout` deadline
    /// leaks its pending entry unless something sweeps it once the deadline
    /// passes — the drive loop no longer ticks the reply sweep (it was
    /// relocated to a dedicated peer task, `session_glue.rs`). A long-running
    /// query driver (e.g. wz-ap-demo's sweep task, or the REST bridge's
    /// `serve` loop) periodically calls this. Idempotent + cheap when nothing
    /// is expired; safe to call alongside another sweeper (a swept entry is a
    /// no-op the second time). Returns the number of entries swept.
    #[cfg(feature = "query-get")]
    pub fn sweep_expired_queries(&self) -> usize {
        let now_ms = self.clock.now_monotonic_ms();
        let swept = R::with_mutex_mut(&self.observer, |observer| {
            observer.replies.sweep_timed_out(now_ms)
        });
        // Drain OUTSIDE the observer lock (the standing drain-after-dispatch
        // contract) — a timed-out query's staged `on_final` runs here.
        self.drain_deferred_fires();
        swept
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

    /// transport-shm — install the AP SHM resolver onto the subscriber registry
    /// (the std mmap-open `PosixShmResolver`). Call once at bring-up so an inbound
    /// SHM Put's descriptor can be resolved off /dev/shm; absent the resolver an
    /// SHM Put drops. The registry forwarder (the `set_own_zid` sibling).
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_resolver(
        &self,
        resolver: Box<dyn wz_session_core::extshm::ShmResolver + Send + Sync>,
    ) {
        R::with_mutex_mut(&self.observer, |observer| {
            observer.subscribers.set_shm_resolver(resolver);
        });
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

    /// R311ou — the transport-agnostic LOCAL-registration half of
    /// `declare_subscriber`, shared by the unicast (routed, emitting —
    /// [`Session::declare_subscriber`] on `impl Session<R, T, Unicast>`) and
    /// the multicast (local-only — the same name on `impl Session<R, T,
    /// Multicast>`) entry points. Builds the deferred-fire cell + the staging
    /// sink and registers them in the observer's subscriber registry under the
    /// caller's locality, returning the assigned [`SubscriptionId`] + the cell
    /// so the caller assembles the [`Subscriber`] handle — with a wire
    /// retraction on the unicast routed path, without one on the
    /// session-local / multicast path.
    ///
    /// Mirrors the local subscriber-table insert in zenoh-pico's
    /// `_z_register_subscriber` that runs BEFORE the
    /// `_z_locality_allows_remote` wire-emit gate
    /// (`vendor/zenoh-pico/src/net/primitives.c:213-234`). The wire emit half
    /// lives in [`Session::announce_subscriber`] (unicast only).
    ///
    /// R311lh — the registry stores a staging sink that copies each matched
    /// sample to the owned retention form and stages it on the deferred-fire
    /// queue; `callback` runs at a drain site OUTSIDE the observer lock and may
    /// re-enter any observer-locking session API (publish loopback, queries,
    /// declares, handle Drop, even its own handle's `undeclare`).
    fn register_subscriber_local(
        &self,
        keyexpr: &str,
        options: &SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> (SubscriptionId, SampleCell<R>) {
        let (cell, sink) = self.deferred_sample_sink(callback);
        // R311de — observer access via R::with_mutex_mut closure form.
        let id = R::with_mutex_mut(&self.observer, |observer| {
            observer.subscribers.register_with_locality(
                keyexpr.to_string(),
                options.allowed_origin,
                sink,
            )
        });
        (id, cell)
    }
}

// R311nf — the MULTICAST `Session` surface: `impl Session<R, T, Multicast>`.
// The handshake-free constructor + the multicast dispatch SSOT. A
// `Session<R, T, Unicast>` does not have these methods, and a
// `Session<R, T, Multicast>` does not have the unicast
// `dispatch_iteration_event` / declare / query surface — the typestate keeps
// the two disjoint, so the review's illegal-state-representable
// (`dispatch_iteration_event` silently no-op on multicast) is now a compile
// error rather than a runtime guard.
#[cfg(feature = "transport-multicast")]
impl<R: SessionRuntime, T: TimeSource> Session<R, T, Multicast> {
    /// R311mn (Level B, B2) / R311nf — construct a multicast `Session` from the
    /// shared observer + clock (the handshake-free multicast transport has no
    /// `SessionLinkActions` bundle). R311mo (B3) adds the `codec-push`-gated
    /// `tx` argument: the sender half of the channel
    /// [`drive_multicast_session`](crate::multicast_glue::drive_multicast_session)
    /// drains, so [`Self::publish`] can enqueue onto it (a bare multicast build
    /// with no data plane omits `tx` and gets an RX-only session). R311nf —
    /// returns the `Multicast` typestate; the `transport` field IS the
    /// `MulticastPayload` (no enum-variant wrap, no `PhantomData`).
    pub fn new_multicast(
        observer: Arc<<R as Runtime>::Mutex<ApplicationLayerObserver>>,
        clock: Arc<T>,
        #[cfg(feature = "codec-push")] tx: tokio::sync::mpsc::UnboundedSender<
            wz_session_core::multicast_tx::MulticastTxItem,
        >,
    ) -> Self {
        Self {
            transport: transport::MulticastPayload {
                #[cfg(feature = "codec-push")]
                tx,
            },
            observer,
            fires: wz_session_core::deferred_fire::DeferredFireQueue::new(),
            clock,
        }
    }

    /// R311mq (Level B, B5a) — the MULTICAST dispatch SSOT: fan one drive-loop
    /// [`IterationEvent`](wz_session_core::driver_loop::IterationEvent) into THIS
    /// session's observer under its lock, then drain the deferred-fire queue
    /// after the lock drops. The multicast analogue of the unicast
    /// [`Session::dispatch_iteration_event`], MINUS the unicast reply flush (a
    /// multicast session has no `SessionLinkActions`; the multicast reply plane
    /// drains separately through
    /// [`MulticastReplySink`](crate::multicast_glue::MulticastReplySink)). Carries
    /// only the `dispatch -> (lock drops) -> drain` pairing the deferred
    /// subscriber plane needs (the F-6 contract). Wire the multicast drive
    /// loop's `on_event` to this:
    ///
    /// ```text
    /// drive_multicast_session(
    ///     .., |event| session.dispatch_multicast_iteration_event(event), ..)
    /// ```
    pub fn dispatch_multicast_iteration_event(
        &self,
        event: wz_session_core::driver_loop::IterationEvent<'_>,
    ) {
        R::with_mutex_mut(&self.observer, |obs| {
            obs.dispatch_event(event);
        });
        self.drain_deferred_fires();
    }

    /// R311ou — declare a LOCAL-only [`Subscriber`] on a MULTICAST session.
    /// Registers the callback in the observer's subscriber registry (fired by
    /// the multicast RX leg + the loopback leg of [`Self::publish`]); emits NO
    /// wire frame. A multicast session is connectionless and has no router to
    /// announce a subscription to — the B4 local-filter model — so unlike the
    /// unicast [`Session::declare_subscriber`] there is no
    /// `Declare(DeclSubscriber)` emit and no RAII retraction (`retraction:
    /// None`). Infallible: the keyexpr never reaches the outbound wire, so the
    /// R300 outbound pico-safety gate (run by the unicast routed path) does not
    /// apply. Whole-group subscriber-declaration exchange among multicast peers
    /// is a separate, later concern.
    pub fn declare_subscriber(
        &self,
        keyexpr: impl Into<String>,
        options: SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Subscriber<R> {
        let keyexpr_string = keyexpr.into();
        let (id, cell) = self.register_subscriber_local(&keyexpr_string, &options, callback);
        Subscriber {
            observer: self.observer.clone(),
            id,
            keyexpr: keyexpr_string,
            options,
            cell,
            armed: true,
            retraction: None,
        }
    }
}

// R311nf — the UNICAST `Session` surface: `impl Session<R, T, Unicast>`. Every
// method here is unicast-only (it borrows the `SessionLinkActions` bundle via
// the now-infallible `self.actions()`, or names a `session_glue` type), so the
// typestate confines it to a `Session<R, T, Unicast>` — a `Session<R, T,
// Multicast>` simply does not have `dispatch_iteration_event` / `query` /
// `declare_*` (the illegal call is a compile error, not a runtime reject). The
// transport-agnostic surface (publish / observer / clock / drain / zid + the
// `register_subscriber_local` core) lives in the `impl<R, T, Tp> Session<R, T,
// Tp>` block above; the multicast-only surface lives in the `impl Session<R, T,
// Multicast>` block below. R311ou — `declare_subscriber` is now per-transport
// (it shares `register_subscriber_local`): the unicast one emits the routed
// `Declare(DeclSubscriber)`, the multicast one is local-only.
#[cfg(feature = "transport-unicast")]
impl<R: SessionRuntime, T: TimeSource> Session<R, T, Unicast> {
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
        // R236 — read the local zid from SessionInitParams BEFORE moving
        // `actions` into the transport sum, so the dedup install below needs
        // no fallible re-projection of a value this ctor builds as `Unicast`
        // by construction (R311ne — drops the defensive `if let Ok` that
        // re-asked a known-`Ok` question).
        let zid = actions.params.zid.clone();
        let session = Self {
            // R311nf — on `Session<R, T, Unicast>` the `transport` field IS the
            // `Arc<SessionLinkActions<R, T>>` payload (`<Unicast as
            // TransportState<R, T>>::Payload`); no enum-variant wrap.
            transport: actions,
            observer,
            // R311kz — fresh deferred-fire queue per logical session;
            // every deferred sink (matching, decl listeners, data
            // planes) clones a handle out of it at registration.
            // R311lh — unconditional, see the field doc.
            fires: wz_session_core::deferred_fire::DeferredFireQueue::new(),
            clock,
        };
        // Forward the zid into the subscriber registry so wire-arrived
        // self-echo Pushes are dedup'd from session creation onward. The
        // `1..=16` range check inside `set_own_zid` quietly rejects an
        // out-of-range value (returns `false`); empty zid skipped here so the
        // registry stays in its pre-R231 default state for test fixtures that
        // don't supply a zid.
        if !zid.is_empty() {
            let _ = session.set_own_zid(zid);
        }
        session
    }

    /// Borrow the outbound action handle. Useful when the caller
    /// needs to invoke non-publish methods like `send_declare_*` or
    /// `send_request_query` directly on the actions surface.
    ///
    /// R311nf — INFALLIBLE on `Session<R, T, Unicast>`: the `transport` field
    /// IS the `Arc<SessionLinkActions<R, T>>` payload, so this is a plain field
    /// borrow. The R311nc fallible `Result<_, SendWireError>` projection (whose
    /// `Err(UnsupportedVariant)` arm signalled "called on a multicast session")
    /// is retired: a multicast session is now a distinct type
    /// `Session<R, T, Multicast>` that simply has no `actions()` method, so the
    /// transport mismatch is a compile error rather than a runtime reject.
    pub fn actions(&self) -> &Arc<SessionLinkActions<R, T>> {
        &self.transport
    }

    /// transport-shm — publish a SHM-backed payload. When this session has
    /// NEGOTIATED SHM, the REMOTE leg carries only the segment DESCRIPTOR (+ the
    /// 0x2 ext_shm marker) instead of the bytes — the receiver mmaps the segment
    /// off /dev/shm (zero-copy on the wire). The LOCAL loopback leg delivers the
    /// bytes directly (same-host). Without negotiation, this is the ordinary
    /// inline `publish` of the bytes read back from the segment, so the API is
    /// always usable. The caller must keep `payload` alive until the round-trip
    /// completes (the scoped lifecycle: the owner backs the segment, Drop
    /// unlinks).
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm(
        &self,
        keyexpr: &str,
        payload: &crate::shm_provider::ShmBackedPayload,
        opts: PublishOptions,
    ) -> Result<usize, PublishError> {
        #[cfg(feature = "codec-push")]
        if self.actions().is_shm() && opts.allowed_destination.allows_remote() {
            use wz_session_core::send_wire_error::SendWireError;
            let meta = opts.push_metadata();
            let push = wz_session_core::push_build::build_push_shm_literal(
                keyexpr,
                &payload.descriptor(),
                &meta,
            )
            .map_err(SendWireError::Codec)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Push(Box::new(push)),
                opts.reliable_bool(),
                meta.is_express(),
            )?;
            // The remote leg fired the descriptor; deliver the bytes to any LOCAL
            // subscriber (same-host) directly.
            #[cfg(feature = "pubsub-allow-loop")]
            if opts.allowed_destination.allows_local() {
                let sample = build_loopback_sample(keyexpr, payload.bytes(), &opts);
                let delivered =
                    R::with_mutex_mut(&self.observer, |o| o.subscribers.local_publish(&sample));
                self.drain_deferred_fires();
                return Ok(delivered);
            }
            return Ok(0);
        }
        // Not negotiated (or remote disabled) -> ordinary inline publish of the
        // bytes read back out of the segment.
        self.publish(keyexpr, payload.bytes(), opts)
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
            // R311nf — the unicast reply flush + ResponseFinal staging run
            // UNCONDITIONALLY now: this method lives on `Session<R, T, Unicast>`,
            // so `actions()` is the infallible unicast bundle borrow. The
            // R311nd `if let Ok(actions)` guard (which silently skipped these
            // legs on a multicast session — the illegal-state-representable the
            // review flagged) is gone: a multicast session is a distinct type
            // that does not have this method, and is driven by
            // `dispatch_multicast_iteration_event` instead.
            obs.flush_pending_replies(self.actions().as_ref());
            under_lock(obs);
            #[cfg(feature = "query-queryable")]
            {
                let actions = self.actions();
                for rid in obs.take_pending_final_rids() {
                    let actions = actions.clone();
                    self.fires.stage(Box::new(move || {
                        // `actions` is the concrete `Arc<SessionLinkActions>`,
                        // so call its inherent `send_response_final` directly —
                        // the `ResponseSink` trait method (session_actions.rs)
                        // is a pure forward to this same inherent fn, so the
                        // `use ResponseSink as _` seam added nothing here and
                        // went unused under feature-unification builds where
                        // the trait method's `codec-response-final` arm is
                        // absent (the `--all-targets` deny-warnings break).
                        actions.send_response_final(rid);
                    }));
                }
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
        // R311nf — on `Session<R, T, Unicast>` `actions()` is the infallible
        // bundle borrow, so this is a direct proxy (the R311ne
        // `.unwrap_or(false)` that absorbed the multicast projection is gone;
        // a multicast session has no `is_established` — it has no unicast FSM).
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
            // R311mt (B5b-2b-1) — express batch-flush hint for the send
            // seam's unicast arm: the `flush_batch_if_express(meta)` parity
            // the prior `send_push_*_with_meta_aliased` carried inline now
            // rides the seam's `express` arm (drains the open batch window
            // after an express-flagged send). Moot without
            // `transport-batching`. Derivation byte-identical to the literal
            // `publish` (R311ms).
            // R311mv (session review) — `express` is the SSOT projection on
            // `PushMetadata` (`meta.is_express()`); the seam gates its *effect*
            // on `transport-batching`, so this site no longer forks on the
            // feature (the flag is always computable, only its batch-flush
            // effect is batching-gated). The prior inline derivation was
            // duplicated across `publish` (R311ms) and `publish_aliased`
            // (R311mt).
            let express = meta.is_express();
            // R311mt (B5b-2b-1) — build the aliased Put / Del as a
            // `NetworkMessage::Push` and route it through the
            // [`Self::send_network_message`] send seam instead of
            // `self.actions().send_push_*_with_meta_aliased` — the SECOND
            // data-plane op lifted off the unicast action bundle and onto the
            // seam (after the literal `publish`, R311ms), a further step
            // toward the B5b-2b `actions()` dismantling. Behaviour-preserving:
            // the seam's unicast arm runs the same `dispatch_push` + express
            // flush the `send_push_*_with_meta_aliased` pair did, and the
            // builder's `CodecError` maps to `SendWireError::Codec` exactly as
            // before (`From<SendWireError> for PublishError`). The
            // `resolve_outbound_mapping` lookup in `publish_aliased_auto`
            // stays on `actions()` — it is unicast keyexpr-table bookkeeping,
            // not a wire send.
            let push = match opts.kind {
                SampleKind::Put => wz_session_core::push_build::build_push_aliased_with_meta(
                    mapping_id,
                    inline_suffix,
                    payload,
                    &meta,
                ),
                SampleKind::Del => wz_session_core::push_build::build_push_del_aliased_with_meta(
                    mapping_id,
                    inline_suffix,
                    &meta,
                ),
            }
            .map_err(SendWireError::Codec)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Push(Box::new(push)),
                reliable,
                express,
            )?;
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
        use crate::reply_sink::BoxedReplySink;
        let cell: wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedReplySink> =
            wz_session_core::deferred_fire::DeferredListenerCell::new(BoxedReplySink::new(
                on_reply, on_final,
            ));
        let queue = self.fires.clone();
        let cell_for_reply = cell.clone();
        let staged_reply = move |view: &dyn ReplyView| {
            // Owned copy — a deferred fire outlives the dispatch borrow. The
            // projection is the wz-session-core SSOT (InboundReply::from_view),
            // so the attachment / encoding side-bands (A8b) thread through
            // here without this duplicating the per-arm projection.
            let owned = InboundReply::from_view(view);
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
                // R311mu (B5b-2b-2) — build the Query as a
                // `NetworkMessage::Request` and route through the
                // [`Self::send_network_message`] send seam instead of
                // `self.actions().send_request_query[_with_meta]` — the Request
                // family lifted onto the seam (after the Push family,
                // R311ms/mt). The rid alloc + reply-pending register (above) +
                // the unregister-only rollback (below) stay session-level: the
                // seam emits the wire Query only, mirroring zenoh-pico keeping
                // `_z_register_pending_query` outside `_z_send_n_msg`.
                // reliable=true / express=false match the prior
                // `send_request_query` (dispatch_request reliable, no flush);
                // the builder's `CodecError` maps to `SendWireError::Codec`.
                let emit = if meta.is_empty() {
                    wz_session_core::request_build::build_request_query(rid, 0, Some(keyexpr))
                } else {
                    wz_session_core::request_build::build_request_query_with_meta(
                        rid,
                        0,
                        Some(keyexpr),
                        &meta,
                    )
                }
                .map_err(SendWireError::Codec)
                .and_then(|request| {
                    self.send_network_message(
                        wz_session_core::network_message::NetworkMessage::Request(Box::new(
                            request,
                        )),
                        /*reliable=*/ true,
                        /*express=*/ false,
                    )
                });
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
                        // R311y94 (review V2) — carry the GET's selector params
                        // (`_sn` / `_max`) into the loopback Query so a SessionLocal
                        // queryable filters identically to the wire path.
                        let query = build_loopback_query(&opts);
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
                // R311mu (B5b-2b-2) — aliased Query onto the send seam; same
                // shape as `Session::query`, routed by (mapping_id,
                // inline_suffix) instead of (0, literal). The seam emits the
                // wire Query only; the unregister-only rollback below stays
                // session-level.
                let emit = if meta.is_empty() {
                    wz_session_core::request_build::build_request_query(
                        rid,
                        mapping_id,
                        inline_suffix,
                    )
                } else {
                    wz_session_core::request_build::build_request_query_with_meta(
                        rid,
                        mapping_id,
                        inline_suffix,
                        &meta,
                    )
                }
                .map_err(SendWireError::Codec)
                .and_then(|request| {
                    self.send_network_message(
                        wz_session_core::network_message::NetworkMessage::Request(Box::new(
                            request,
                        )),
                        /*reliable=*/ true,
                        /*express=*/ false,
                    )
                });
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
                        // R311y94 (review V2) — carry the GET's selector params
                        // (`_sn` / `_max`) into the loopback Query so a SessionLocal
                        // queryable filters identically to the wire path.
                        let query = build_loopback_query(&opts);
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
    /// `DeclarePublisher` record. That record is a router-side
    /// optimization hint (it lets a router pre-resolve the
    /// publisher's keyexpr), not a routing precondition: a
    /// publisher's `Put` carries its keyexpr inline, so a router
    /// (zenohd) routes wz's Puts whether or not a `DeclarePublisher`
    /// preceded them — verified e2e against zenohd (the Layer Z
    /// publish leg, `wz_publish_routes_through_zenohd_to_pico_zsub`).
    /// wz elides the declaration; the data plane is unaffected.
    /// (R311pb — the prior "wz is router-less today" justification
    /// predated the R311ou+ routed-declare zenohd interop.)
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
    ) -> Result<Subscriber<R>, SubscribeAliasError>
    where
        // R311ou — same honest bound as the literal `declare_subscriber` it
        // delegates to: the routed subscriber's RAII retraction box captures the
        // `SessionLinkActions<R, T>`, so a `Send` handle needs a `Send + Sync`
        // link sink and a `'static` clock.
        <R as SessionRuntime>::LinkSink: Send + Sync,
        T: 'static,
    {
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
        // R311ou — route the aliased subscriber by delegating to the emitting
        // literal `declare_subscriber` on the resolved keyexpr: register the
        // local callback AND emit `Declare(DeclSubscriber)` (locality-gated) so a
        // router routes matching Pushes back, with the RAII `UndeclSubscriber` on
        // Drop. The `SubscribeError` reject family projects to the alias surface
        // via `From` (so `SubscribeAliasError` mirrors `LivelinessAliasError`),
        // giving the literal + aliased subscriber declares ONE routed SSOT — and
        // the same local-registration rollback on a gate reject.
        self.declare_subscriber(resolved, options, callback)
            .map_err(SubscribeAliasError::from)
    }

    /// R246 / R311ow — declare a ROUTED [`Queryable`] for `keyexpr` + `options`
    /// that fires `callback` on every matching inbound `Request(Query)`, AND
    /// announces the queryable to the peer/router by emitting a
    /// `Declare(DeclQueryable)` on the outbound link (when
    /// `options.allowed_origin` allows remote). The responder/replier-side
    /// mirror of [`Self::declare_subscriber`], and the wz analogue of
    /// zenoh-pico's `z_declare_queryable` / `_z_register_queryable`
    /// (`vendor/zenoh-pico/src/net/primitives.c:320`): register the local
    /// callback table entry, then — iff `_z_locality_allows_remote(allowed_origin)`
    /// — emit the wire `DeclQueryable` so a router routes matching `Query`
    /// requests to this session. The callback fires synchronously inside
    /// [`crate::query::QueryableRegistry::dispatch_request`] (wire arrival) and
    /// [`crate::query::QueryableRegistry::local_query`] (loopback, R238+).
    ///
    /// Returns a [`Queryable`] handle whose `Drop` (RAII) unregisters the local
    /// callback AND, for a routed queryable, emits the matching
    /// `Declare(UndeclQueryable)` retraction so the router stops routing. A
    /// session-local queryable (`Locality::SessionLocal`) registers locally
    /// only and emits nothing, exactly as pico gates the emit on
    /// `_z_locality_allows_remote`.
    ///
    /// Fallible (pico `z_result_t` parity): the keyexpr now reaches the outbound
    /// wire, so it runs the R300 outbound pico-safety gate. A non-canonical /
    /// R299-bug-#3 keyexpr returns [`QueryableError::InvalidKeyexpr`] with the
    /// local registration ROLLED BACK (pico unregisters on `_z_send_declare`
    /// failure, primitives.c:359), so a rejected declare leaves no orphan
    /// queryable. `ExceedsCapacity` / `FeatureDisabled` / `TransportUnavailable`
    /// mirror the [`Self::declare_subscriber`] reject family. There is no
    /// `UnknownMapping` (the literal path resolves no mapping id — that reject
    /// belongs to [`Self::declare_queryable_aliased`]) and no `RequiresUnicast`
    /// (this method lives on `impl Session<R, T, Unicast>`, so a multicast call
    /// is a compile error).
    ///
    /// R311ow — the wire emit routes through the [`Self::send_network_message`]
    /// transport send seam (the B5b SSOT, uniform with [`Self::declare_subscriber`]
    /// / [`Self::declare_token`]); the build half + reconnect-replay cache are
    /// the `SessionLinkActions::prepare_declare_queryable` /
    /// `cache_queryable_declaration` SSOTs shared with the
    /// `send_declare_queryable` wrapper. The wire queryable id IS the local
    /// [`QueryableId`] (one entity id for the local table key + the
    /// `DeclQueryable` + the `UndeclQueryable`), mirroring pico's single
    /// `_z_get_entity_id` — no separate wire-id counter. The handler still fires
    /// via the R311li DEFERRED-FIRE path (the registry stages a sink; the
    /// handler runs at a drain site OUTSIDE the observer lock over a job-local
    /// responder, and its replies precede the matching ResponseFinal on the
    /// wire).
    pub fn declare_queryable(
        &self,
        keyexpr: impl Into<String>,
        options: QueryableOptions,
        callback: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
    ) -> Result<Queryable<R, T>, QueryableError>
    where
        // R311ow — the routed queryable's RAII `Drop` emits the
        // `Declare(UndeclQueryable)` from the type-erased retraction closure,
        // which captures the `Arc<SessionLinkActions<R, T>>`; for that closure
        // (and so the handle) to be `Send` the bundle must be `Send + Sync`.
        // The deferred-fire sink already required this bound, so the routed
        // path adds no new constraint.
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        #[cfg(feature = "query-queryable")]
        {
            let keyexpr_string = keyexpr.into();
            // R311nf — this method lives on `impl Session<R, T, Unicast>`, so
            // the unicast guarantee is structural: `actions()` is the
            // infallible bundle borrow (a multicast session has no
            // SessionLinkActions for the wire-reply leg, and no
            // `declare_queryable` — a compile error, not a runtime reject).
            // Thread the resolved bundle into the sink builder.
            let actions = self.actions().clone();
            let (cell, sink) = self.deferred_query_sink(actions, callback);
            // R311df — observer access via R::with_mutex_mut closure form.
            let id = R::with_mutex_mut(&self.observer, |observer| {
                observer.queryables.register_with_locality(
                    keyexpr_string.clone(),
                    options.allowed_origin,
                    sink,
                )
            });
            // R311ow — announce the queryable to the router iff the locality
            // allows remote (pico `_z_register_queryable`, primitives.c:348),
            // rolling the just-registered local entry back on a gate / transport
            // reject so a rejected declare leaves no orphan queryable
            // (primitives.c:359). `cell.kill()` suppresses any query staged
            // between the register and this rollback.
            let retraction = match self.announce_queryable(id, &keyexpr_string, &options) {
                Ok(retraction) => retraction,
                Err(e) => {
                    cell.kill();
                    R::with_mutex_mut(&self.observer, |observer| {
                        observer.queryables.unregister(id)
                    });
                    return Err(e);
                }
            };
            Ok(Queryable {
                session: self.clone(),
                id,
                keyexpr: keyexpr_string,
                options,
                cell,
                // R311lo — armed: Drop/undeclare teardown frees this handle.
                armed: true,
                retraction,
            })
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = (keyexpr, options, callback);
            Err(QueryableError::FeatureDisabled)
        }
    }

    /// §5.23 `adminspace-core` — register the built-in admin queryable on
    /// `@/<zid>/<whatami>/**` and answer a GET under it with the node's
    /// `local_data` JSON (`{zid, version, locators, sessions, ...}`,
    /// `application/json`). The wz mirror of zenoh `AdminSpace::start`
    /// (`net/runtime/adminspace.rs:155`) + `local_data` (`:561`).
    ///
    /// zenoh's `AdminSpace` is owned by the `Runtime`, which supplies the node
    /// `version` and reads the listening `locators` off
    /// `transport_mgr.get_locators()` (`AdminSpace::start(runtime, version)`).
    /// wz is session-centric, so the embedder that opens this session — the
    /// analogue of zenoh's `Runtime` — passes both in here rather than the
    /// `Session` reading them off transport state it does not own. The
    /// `sessions` array is this session's connected peer
    /// (`SessionLinkActions::peer_zid` + `peer_whatami_wire`), resolved live per
    /// query — the session-centric mirror of zenoh's `get_transports_unicast()`
    /// enumeration (`adminspace.rs:664`). The `read` GET-permission gate
    /// (`:457`), the `config/**` write path (`:392`), the per-entity
    /// (subscriber/publisher/queryable) + `metrics` + router `linkstate`
    /// handlers, and the per-link `{src,dst}` detail are SEPARATE §5.23 catalog
    /// atoms layered on this core.
    ///
    /// Returns the [`Queryable`] handle; dropping it undeclares the admin
    /// queryable (RAII). Without the `adminspace-core` feature this is a
    /// signature-stable `Err(QueryableError::FeatureDisabled)`.
    pub fn declare_adminspace(
        &self,
        version: impl Into<String>,
        locators: Vec<String>,
    ) -> Result<Queryable<R, T>, QueryableError>
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        #[cfg(feature = "adminspace-core")]
        {
            // Permissive default = zenoh's `PermissionsConf` default (read=true).
            self.declare_adminspace_with_permissions(
                version,
                locators,
                wz_session_core::adminspace::AdminSpacePermissions::default(),
            )
        }
        #[cfg(not(feature = "adminspace-core"))]
        {
            let _ = (version, locators);
            Err(QueryableError::FeatureDisabled)
        }
    }

    /// §5.23 `adminspace-read` — the permission-gated form of
    /// [`Self::declare_adminspace`]: `permissions.read` gates the admin GET
    /// (zenoh `if !conf.adminspace.permissions().read { send ResponseFinal }`,
    /// `adminspace.rs:457-467`). With `read = false` (and the `adminspace-read`
    /// feature on) the admin queryable answers nothing — the querier receives
    /// only the terminating Final. Without `adminspace-read` the `read` field is
    /// a signature-stable no-op (the gate is compiled out, the queryable always
    /// serves). [`Self::declare_adminspace`] delegates here with the permissive
    /// default. This method exists only under `adminspace-core` (its parameter
    /// type does), so it carries no `FeatureDisabled` arm.
    #[cfg(feature = "adminspace-core")]
    pub fn declare_adminspace_with_permissions(
        &self,
        version: impl Into<String>,
        locators: Vec<String>,
        permissions: wz_session_core::adminspace::AdminSpacePermissions,
    ) -> Result<Queryable<R, T>, QueryableError>
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        use wz_codecs::whatami::WhatAmI;
        use wz_session_core::adminspace::{
            admin_queryable_key, answer_admin_query, AdminAnswerCtx, AdminSession,
        };
        use wz_session_core::zid_hex::zid_to_zenoh_hex;

        // R311xy idiom — the read permission is a PER-CALL gate carried in the
        // AdminAnswerCtx: with adminspace-read OFF `read` is `true` (the queryable
        // always serves), so the signature stays feature-toggle-independent.
        #[cfg(feature = "adminspace-read")]
        let read = permissions.read;
        #[cfg(not(feature = "adminspace-read"))]
        let read = {
            let _ = permissions;
            true
        };

        let zid_hex = zid_to_zenoh_hex(&self.actions().params.zid);
        let whatami = self.actions().params.whatami.to_str();
        let queryable_key = admin_queryable_key(&zid_hex, whatami);
        // R311y40/y45 — the typed WzConfig read-at-open mirror, serialized once at
        // declare time (the handshake params are fixed for the session's life).
        let config_json =
            crate::config::WzConfig::from_init_params(&self.actions().params).to_admin_json();
        let version: String = version.into();
        let actions = self.actions().clone();

        let handler = move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
            // The connected peer is the session-centric `sessions[]` entry,
            // resolved LIVE per query off the captured bundle so a reconnect / peer
            // change is reflected (zenoh's `get_transports_unicast`,
            // adminspace.rs:664). A routing peer would enumerate its faces instead —
            // the forwarder-hosted §5.23 admin (R311y45) currently passes an EMPTY
            // `sessions[]` (the live forwarder-faces enumeration is a deferral).
            let mut sessions = Vec::new();
            if let Some(peer) = actions.peer_zid() {
                let peer_whatami = actions
                    .peer_whatami_wire()
                    .and_then(WhatAmI::from_wire)
                    .map(|w| String::from(w.to_str()));
                sessions.push(AdminSession {
                    peer_zid_hex: zid_to_zenoh_hex(&peer),
                    whatami: peer_whatami,
                    links: Vec::new(),
                });
            }
            // The match+reply SSOT (root local_data / metrics / config + the read
            // gate) — the SAME answerer the §5.23 routing-peer forwarder host calls
            // (R311y45), so both emit byte-identical admin replies.
            let ctx = AdminAnswerCtx {
                zid_hex: &zid_hex,
                whatami,
                version: &version,
                locators: &locators,
                read,
            };
            // The pure-Session admin host does not enumerate declarations (its admin
            // sink fires while the observer is locked mid-`iter_mut`, so it cannot
            // re-read the declaration registries — the introspection materialization
            // for this host is a NAMED follow-up). The forwarder-hosted demo admin
            // (`--config-queryable`) is the wired introspection host for §5.23.
            answer_admin_query(view, out, &ctx, &sessions, &[], &config_json);
        };

        self.declare_queryable(queryable_key, QueryableOptions::default(), handler)
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
            // R311ow — delegate to the routed literal declare_queryable, which
            // registers locally + emits the wire `Declare(DeclQueryable)` (the
            // alias resolved once here, at declare time). Its `QueryableError`
            // reject variants project into `QueryableAliasError` via the `From`
            // impl, giving the literal + aliased queryable declares ONE routed
            // SSOT — and the same local-registration rollback on a gate reject.
            self.declare_queryable(resolved, options, callback)
                .map_err(QueryableAliasError::from)
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = (mapping_id, inline_suffix, options, callback);
            Err(QueryableAliasError::FeatureDisabled)
        }
    }

    /// R311ow — the wire-announce half of [`Self::declare_queryable`] (pico
    /// `_z_register_queryable` lines 348-362): emit `Declare(DeclQueryable)`
    /// through the transport send seam iff `allowed_origin.allows_remote()`,
    /// returning the matching type-erased retraction closure for the
    /// [`Queryable`] handle's `Drop`. `Ok(None)` for a session-local queryable
    /// (no router announce). On a build without the `declare-queryable` codec,
    /// `Ok(None)` — the local queryable stays valid for loopback /
    /// directly-connected delivery; only the router announce is elided
    /// (signature-stability: the routed-declare path is the cfg-gated half, the
    /// local registration is always available). The queryable sibling of
    /// [`Self::announce_subscriber`].
    ///
    /// R311ow — gated on `query-queryable` (not just the impl block's
    /// `transport-unicast`): the sole call site is [`Self::declare_queryable`]'s
    /// `query-queryable`-gated body, so a `transport-unicast` build WITHOUT
    /// `query-queryable` (the handshake-only subset lane) would otherwise carry
    /// this method as dead code. Unlike [`Self::announce_subscriber`], whose
    /// caller (`declare_subscriber`) is always compiled in the unicast impl, the
    /// queryable registry — and thus its declare entry — is `query-queryable`-gated.
    #[cfg(feature = "query-queryable")]
    fn announce_queryable(
        &self,
        id: QueryableId,
        keyexpr: &str,
        options: &QueryableOptions,
    ) -> Result<Option<QueryableRetraction>, QueryableError>
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        #[cfg(feature = "declare-queryable")]
        {
            // pico (`_z_register_queryable`, primitives.c:348): emit only when
            // the locality allows remote; a SessionLocal queryable is loopback
            // only.
            if !options.allowed_origin.allows_remote() {
                return Ok(None);
            }
            fn map_queryable_err(e: SendDeclareError) -> QueryableError {
                match e {
                    SendDeclareError::Keyexpr(inner) => QueryableError::InvalidKeyexpr(inner),
                    // W3 — literal keyexpr over MAX_KEYEXPR_BYTES, typed through.
                    SendDeclareError::Codec(_) => QueryableError::ExceedsCapacity,
                    // F2 — reconnect-window reject, typed through.
                    SendDeclareError::TransportUnavailable => QueryableError::TransportUnavailable,
                    // R311g1 — reachable only in a feature combo where
                    // `declare-queryable` is ON but the send-seam codec
                    // (`codec-declare`) is OFF; honest projection.
                    SendDeclareError::FeatureDisabled => QueryableError::FeatureDisabled,
                    // Literal mode (mapping_id=0, suffix=Some) cannot hit the
                    // mapping-id arms; and `declare_queryable` lives on `impl
                    // Session<R, T, Unicast>`, so the seam takes the unicast arm
                    // and never returns RequiresUnicast (a multicast session is a
                    // distinct type without this method).
                    SendDeclareError::RequiresUnicast
                    | SendDeclareError::UnknownMappingId(_)
                    | SendDeclareError::ReservedMappingIdZero
                    | SendDeclareError::MissingKeyexpr => unreachable!(
                        "declare_queryable literal-mode prepare/seam returned \
                         {e:?} unexpectedly"
                    ),
                }
            }
            let actions = self.actions();
            // R311ow — pico parity: the wire queryable id IS the local
            // QueryableId (one entity id, mirroring `_z_get_entity_id`).
            let wire_id = id.as_u64();
            let declare = actions
                .prepare_declare_queryable(
                    wire_id,
                    /*mapping_id=*/ 0,
                    Some(keyexpr),
                    options.complete,
                )
                .map_err(map_queryable_err)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Declare(Box::new(declare)),
                /*reliable=*/ true,
                /*express=*/ false,
            )
            .map_err(|e| map_queryable_err(SendDeclareError::from(e)))?;
            // A4 — reconnect-replay cache (pico `_z_cache_declaration`);
            // session-state bookkeeping AROUND the seam emit, like
            // declare_subscriber.
            actions.cache_queryable_declaration(
                wire_id,
                /*mapping_id=*/ 0,
                Some(keyexpr),
                options.complete,
            );
            // The retraction captures the unicast actions Arc + the wire id;
            // type-erased so `Queryable` stays free of the wire-codec types.
            let actions_for_drop = actions.clone();
            Ok(Some(Box::new(move || {
                actions_for_drop.send_undeclare_queryable(wire_id)
            })))
        }
        #[cfg(not(feature = "declare-queryable"))]
        {
            let _ = (id, keyexpr, options);
            Ok(None)
        }
    }

    /// R311ou — declare a ROUTED [`Subscriber`] on `keyexpr` + `options` that
    /// fires `callback` on every matching inbound `Sample`, AND announces the
    /// subscription to the peer/router by emitting a `Declare(DeclSubscriber)`
    /// on the outbound link (when `options.allowed_origin` allows remote). The
    /// wz analogue of zenoh-pico's `z_declare_subscriber` /
    /// `_z_register_subscriber` (`vendor/zenoh-pico/src/net/primitives.c:210`):
    /// register the local callback table entry, then — iff
    /// `_z_locality_allows_remote(allowed_origin)` — emit the wire
    /// `DeclSubscriber` so a router routes matching Pushes back to this session.
    /// Verified end-to-end against `zenohd` v1.5.0 (the R311ou Layer Z interop
    /// test); the prior R311or "router-mode subscriber out of scope" finding was
    /// empirically falsified.
    ///
    /// Returns a [`Subscriber`] handle whose `Drop` (RAII) unregisters the local
    /// callback AND, for a routed subscriber, emits the matching
    /// `Declare(UndeclSubscriber)` retraction so the router stops routing. A
    /// session-local subscriber (`Locality::SessionLocal`) registers locally
    /// only and emits nothing, exactly as pico gates the emit on
    /// `_z_locality_allows_remote`.
    ///
    /// Fallible (pico `z_result_t` parity): the keyexpr now reaches the outbound
    /// wire, so it runs the R300 outbound pico-safety gate. A non-canonical /
    /// R299-bug-#3 keyexpr returns [`SubscribeError::InvalidKeyexpr`] with the
    /// local registration ROLLED BACK (pico unregisters on `_z_send_declare`
    /// failure, primitives.c:243), so a rejected declare leaves no orphan
    /// subscriber. `ExceedsCapacity` / `FeatureDisabled` / `TransportUnavailable`
    /// mirror the [`Self::declare_token`] reject family; there is no
    /// `RequiresUnicast` (this method lives on `impl Session<R, T, Unicast>`, so
    /// a multicast call is a compile error — the multicast `declare_subscriber`
    /// is the infallible local-only sibling).
    ///
    /// R311ou — the wire emit routes through the [`Self::send_network_message`]
    /// transport send seam (the B5b SSOT, uniform with [`Self::declare_token`]);
    /// the build half + reconnect-replay cache are the
    /// `SessionLinkActions::prepare_declare_subscriber` /
    /// `cache_subscriber_declaration` SSOTs shared with the
    /// `send_declare_subscriber` wrapper. The wire subscriber id IS the local
    /// [`SubscriptionId`] (one entity id for the local table key + the
    /// `DeclSubscriber` + the `UndeclSubscriber`), mirroring pico's single
    /// `_z_get_entity_id` — no separate wire-id counter.
    pub fn declare_subscriber(
        &self,
        keyexpr: impl Into<String>,
        options: SubscribeOptions,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<Subscriber<R>, SubscribeError>
    where
        // R311ou — honest bound: a ROUTED subscriber's RAII `Drop` emits the
        // `Declare(UndeclSubscriber)` from the type-erased retraction closure,
        // which captures the `Arc<SessionLinkActions<R, T>>`. For that closure
        // (and so the `Subscriber<R>` handle) to be `Send` — droppable from any
        // thread — the runtime's link sink must be `Send + Sync`. Satisfied by
        // `TokioRuntime`; the same requirement `declare_token` carries
        // implicitly via its concrete `LivelinessToken<R, T>` handle's auto
        // `Send`. `T: 'static` so the captured `SessionLinkActions<R, T>`
        // outlives the `'static` retraction box.
        <R as SessionRuntime>::LinkSink: Send + Sync,
        T: 'static,
    {
        let keyexpr_string = keyexpr.into();
        let (id, cell) = self.register_subscriber_local(&keyexpr_string, &options, callback);
        let retraction = match self.announce_subscriber(id, &keyexpr_string, &options) {
            Ok(retraction) => retraction,
            Err(e) => {
                // pico parity (`_z_register_subscriber`, primitives.c:243): roll
                // back the just-registered local entry when the wire announce
                // fails, so a gate-rejected keyexpr leaves no orphan local
                // subscriber. `cell.kill()` suppresses any sample staged between
                // the register and this rollback.
                cell.kill();
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.subscribers.unregister(id)
                });
                return Err(e);
            }
        };
        Ok(Subscriber {
            observer: self.observer.clone(),
            id,
            keyexpr: keyexpr_string,
            options,
            cell,
            armed: true,
            retraction,
        })
    }

    /// R311ou — the wire-announce half of [`Self::declare_subscriber`] (pico
    /// `_z_register_subscriber` lines 235-246): emit `Declare(DeclSubscriber)`
    /// through the transport send seam iff `allowed_origin.allows_remote()`,
    /// returning the matching type-erased retraction closure for the
    /// [`Subscriber`] handle's `Drop`. `Ok(None)` for a session-local
    /// subscriber (no router announce). On a build without the
    /// `declare-subscriber` codec, `Ok(None)` — the local subscriber stays valid
    /// for loopback / directly-connected delivery; only the router announce is
    /// elided (signature-stability: the routed-declare path is the cfg-gated
    /// half, the local registration is always available).
    fn announce_subscriber(
        &self,
        id: SubscriptionId,
        keyexpr: &str,
        options: &SubscribeOptions,
    ) -> Result<Option<SubscriberRetraction>, SubscribeError>
    where
        <R as SessionRuntime>::LinkSink: Send + Sync,
        T: 'static,
    {
        #[cfg(feature = "declare-subscriber")]
        {
            // pico (`_z_register_subscriber`, primitives.c:235): emit only when
            // the locality allows remote; a SessionLocal subscriber is loopback
            // only.
            if !options.allowed_origin.allows_remote() {
                return Ok(None);
            }
            fn map_subscribe_err(e: SendDeclareError) -> SubscribeError {
                match e {
                    SendDeclareError::Keyexpr(inner) => SubscribeError::InvalidKeyexpr(inner),
                    // W3 — literal keyexpr over MAX_KEYEXPR_BYTES, typed through.
                    SendDeclareError::Codec(_) => SubscribeError::ExceedsCapacity,
                    // F2 — reconnect-window reject, typed through.
                    SendDeclareError::TransportUnavailable => SubscribeError::TransportUnavailable,
                    // R311g1 — reachable only in a feature combo where
                    // `declare-subscriber` is ON but the send-seam codec
                    // (`codec-declare`) is OFF; honest projection.
                    SendDeclareError::FeatureDisabled => SubscribeError::FeatureDisabled,
                    // Literal mode (mapping_id=0, suffix=Some) cannot hit the
                    // mapping-id arms; and `declare_subscriber` lives on `impl
                    // Session<R, T, Unicast>`, so the seam takes the unicast arm
                    // and never returns RequiresUnicast (a multicast session is a
                    // distinct type without this method).
                    SendDeclareError::RequiresUnicast
                    | SendDeclareError::UnknownMappingId(_)
                    | SendDeclareError::ReservedMappingIdZero
                    | SendDeclareError::MissingKeyexpr => unreachable!(
                        "declare_subscriber literal-mode prepare/seam returned \
                         {e:?} unexpectedly"
                    ),
                }
            }
            let actions = self.actions();
            // R311ou — pico parity: the wire subscriber id IS the local
            // SubscriptionId (one entity id, mirroring `_z_get_entity_id`).
            let wire_id = id.as_u64();
            let declare = actions
                .prepare_declare_subscriber(wire_id, /*mapping_id=*/ 0, Some(keyexpr))
                .map_err(map_subscribe_err)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Declare(Box::new(declare)),
                /*reliable=*/ true,
                /*express=*/ false,
            )
            .map_err(|e| map_subscribe_err(SendDeclareError::from(e)))?;
            // A4 — reconnect-replay cache (pico `_z_cache_declaration`);
            // session-state bookkeeping AROUND the seam emit, like declare_token.
            actions.cache_subscriber_declaration(wire_id, /*mapping_id=*/ 0, Some(keyexpr));
            // The retraction captures the unicast actions Arc + the wire id;
            // type-erased so `Subscriber<R>` stays free of the `T` clock param.
            let actions_for_drop = actions.clone();
            Ok(Some(Box::new(move || {
                actions_for_drop.send_undeclare_subscriber(wire_id)
            })))
        }
        #[cfg(not(feature = "declare-subscriber"))]
        {
            let _ = (id, keyexpr, options);
            Ok(None)
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
    /// Like [`Self::declare_subscriber`] / [`Self::declare_queryable`] (R311ou /
    /// R311ow routed those declares), the Liveliness Token emits a `Declare` at
    /// declare time. The distinction is in what the declaration MEANS and in the
    /// undeclare semantics: a `DeclSubscriber` / `DeclQueryable` registers
    /// ROUTING INTEREST on the router (so matching Pushes / Queries route back to
    /// this session, retracted by the handle's `Drop` only when remote-local),
    /// whereas a `DeclToken` drives the liveliness fan-out — it MUST emit wire on
    /// both declare AND undeclare so the peer's liveliness subscribers receive
    /// PUT + DELETE samples (per zenoh-pico's `z_liveliness_declare_token`
    /// doc-comment: "subscribers on an intersecting key expression will receive a
    /// PUT sample when connectivity is achieved, and a DELETE sample if it's
    /// lost").
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
            // B5b-2b — the declare family needs the unicast action bundle;
            // a multicast session has none, so reject honestly here (before
            // the seam) rather than letting the multicast send arm's
            // UnsupportedVariant reach map_decl_err's `other => unreachable!`.
            let actions = self.actions();
            let token_id = actions.alloc_next_token_id();
            // declare_token always builds in literal mode (mapping_id = 0,
            // suffix = Some(_)), so the alias-resolution reject variants
            // cannot fire; the `unreachable!()` guards future refactors that
            // change the call shape. The seam's `SendWireError` folds into the
            // same `SendDeclareError` projection via `From`, so the error
            // mapping is shared (and unchanged) across the build + emit halves.
            fn map_decl_err(e: SendDeclareError) -> LivelinessAliasError {
                match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
                    // W3 — a literal keyexpr longer than MAX_KEYEXPR_BYTES
                    // is a reachable caller-data condition (not a
                    // protocol invariant), so it projects to the typed
                    // public reject rather than the unreachable guard.
                    SendDeclareError::Codec(_) => LivelinessAliasError::ExceedsCapacity,
                    other => unreachable!(
                        "declare_token literal-mode prepare/seam returned \
                         {other:?} unexpectedly"
                    ),
                }
            }
            // R311mw (B5b-2b-3) — build the `Declare(DeclToken)` via the
            // prepare SSOT (resolve + R300 pico-safety gate + envelope) and
            // route the emit through the [`Self::send_network_message`] send
            // seam instead of `self.actions().send_declare_token` — the Declare
            // family lifted onto the seam (after the Push + Request families,
            // R311ms/mt/mu). The token-id alloc (above) + the reconnect-replay
            // cache + the declarer-side registry register (below) stay
            // session-level: the seam emits the wire Declare only, mirroring
            // zenoh-pico keeping `_z_cache_declaration` / the liveliness
            // registration outside `_z_send_n_msg`. reliable=true / express=false
            // match the prior `send_declare_token` (dispatch_declare reliable,
            // no flush — a Declare carries no express window).
            let declare = actions
                .prepare_declare_token(token_id, /*mapping_id=*/ 0, Some(&keyexpr_string))
                .map_err(map_decl_err)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Declare(Box::new(declare)),
                /*reliable=*/ true,
                /*express=*/ false,
            )
            .map_err(|e| map_decl_err(SendDeclareError::from(e)))?;
            // A4 — record for post-reconnect replay (pico `_z_cache_declaration`
            // on `_Z_RES_OK`); session-state bookkeeping AROUND the seam emit.
            actions.cache_token_declaration(
                token_id,
                /*mapping_id=*/ 0,
                Some(&keyexpr_string),
            );
            // R311mz — the held-token registration (R283) now lives inside
            // LivelinessToken::new_held, the sole constructor, so the literal
            // and aliased declare paths register identically by construction.
            Ok(LivelinessToken::new_held(
                self.clone(),
                token_id,
                keyexpr_string,
                options,
            ))
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
            // B5b-2b — bind the unicast action bundle once (a multicast
            // session has none, so reject honestly before resolving the
            // outbound mapping table the alias needs).
            let actions = self.actions();
            let base = actions
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
            let token_id = actions.alloc_next_token_id();
            // R311mw (B5b-2b-3) — aliased Declare onto the send seam; same
            // shape as `Session::declare_token`, routed by (mapping_id,
            // inline_suffix) instead of (0, literal). The seam's
            // `SendWireError` folds into the same `SendDeclareError` projection
            // via `From` so the error mapping is shared across the build + emit
            // halves and unchanged from the prior `send_declare_token` path.
            fn map_decl_err(e: SendDeclareError) -> LivelinessAliasError {
                match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
                    // W3 — reconstructed keyexpr over MAX_KEYEXPR_BYTES is a
                    // reachable caller-data condition projecting to the
                    // typed public reject.
                    SendDeclareError::Codec(_) => LivelinessAliasError::ExceedsCapacity,
                    // F2 — reconnect-window reject, typed through.
                    SendDeclareError::TransportUnavailable => {
                        LivelinessAliasError::TransportUnavailable
                    }
                    // B5b-2b — multicast-session declare reject (the send seam
                    // returns UnsupportedVariant; SendDeclareError::from maps it
                    // to RequiresUnicast), typed through to the declare surface.
                    // R311nf — UNREACHABLE on this method: it lives on `impl
                    // Session<R, T, Unicast>`, so the seam takes the unicast arm
                    // (which forwards to the actions bundle and never returns
                    // RequiresUnicast); a multicast session is a distinct type
                    // without this method. The exhaustive arm is kept as an
                    // honest typed projection (not `unreachable!`) so the
                    // `From<SendDeclareError>` mapping stays total.
                    SendDeclareError::RequiresUnicast => LivelinessAliasError::RequiresUnicast,
                    SendDeclareError::UnknownMappingId(id) => {
                        // Race against a concurrent send_undeclare_kexpr
                        // between the pre-check resolve_outbound_mapping
                        // above and the prepare reconstruct below.
                        LivelinessAliasError::UnknownMapping(id)
                    }
                    SendDeclareError::ReservedMappingIdZero | SendDeclareError::MissingKeyexpr => {
                        unreachable!(
                            "declare_token_aliased aliased-mode prepare/seam \
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
                         prepare_declare_token returned FeatureDisabled despite \
                         liveliness-token-gated caller"
                    ),
                }
            }
            let declare = actions
                .prepare_declare_token(token_id, mapping_id, inline_suffix)
                .map_err(map_decl_err)?;
            self.send_network_message(
                wz_session_core::network_message::NetworkMessage::Declare(Box::new(declare)),
                /*reliable=*/ true,
                /*express=*/ false,
            )
            .map_err(|e| map_decl_err(SendDeclareError::from(e)))?;
            // A4 — record for post-reconnect replay (pico `_z_cache_declaration`
            // on `_Z_RES_OK`); session-state bookkeeping AROUND the seam emit.
            actions.cache_token_declaration(token_id, mapping_id, inline_suffix);
            // R311mz — new_held registers the RESOLVED literal in the
            // declarer-side LocalTokenRegistry. The prior code constructed the
            // handle WITHOUT registering, so an aliased-declared token was
            // never replayed to a peer that subscribed later (the asymmetry
            // with the literal declare_token path; pico always registers —
            // net/liveliness.c:77). The shared constructor makes the two paths
            // register identically by construction.
            Ok(LivelinessToken::new_held(
                self.clone(),
                token_id,
                resolved,
                options,
            ))
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
            // R311y1 — the CURRENT-state-replay request gate, consolidated
            // into LivelinessSubscriberOptions::effective_history (the SSOT;
            // was a 4-line `#[cfg]` block duplicated per declare path,
            // R311cl's "per-call gate, not field gate"). Off -> future-only;
            // options.history / with_history() stay signature-stable no-ops.
            let history = options.effective_history();
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
                    .register(interest_id, &keyexpr_string, history, sink)
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
            // R311mx (B5b-2b-4) — build the liveliness subscriber Interest and
            // route the emit through the [`Self::send_network_message`] send
            // seam instead of
            // `self.actions().send_interest_liveliness_subscriber` — the
            // Interest family lifted onto the seam after the Push / Request /
            // Declare families. The interest-id alloc + slot register (above) +
            // the Finding-B rollback (below) + the reconnect-replay cache stay
            // session-level; the seam emits the wire Interest only. reliable=true
            // / express=false match the prior wrapper (dispatch_interest
            // reliable, no flush); the builder's CodecError maps to
            // SendWireError::Codec, and both fold into the same
            // `SendWireError -> LivelinessSubscriberAliasError` projection the
            // prior `.into()` used.
            let emit = wz_session_core::interest_build::build_interest_liveliness_subscriber(
                interest_id,
                history,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            )
            .map_err(SendWireError::Codec)
            .and_then(|interest| {
                self.send_network_message(
                    wz_session_core::network_message::NetworkMessage::Interest(interest),
                    /*reliable=*/ true,
                    /*express=*/ false,
                )
            });
            if let Err(e) = emit {
                cell.kill();
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_subscribers.unregister(interest_id);
                });
                return Err(e.into());
            }
            // A4 — record for post-reconnect replay; session-state bookkeeping
            // AROUND the seam emit.
            self.actions().cache_subscriber_interest(
                interest_id,
                history,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            );
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
            // R311y1 — CURRENT-state-replay request gate via the
            // effective_history SSOT (mirror of the literal path).
            let history = options.effective_history();
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
                    .register(interest_id, &resolved, history, sink)
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
            // R311mx (B5b-2b-4) — aliased liveliness subscriber Interest onto
            // the send seam; same shape as `declare_liveliness_subscriber`,
            // routed by (mapping_id, inline_suffix) instead of (0, literal). The
            // wire frame carries the alias form; the slot register + rollback +
            // reconnect-replay cache stay session-level.
            let emit = wz_session_core::interest_build::build_interest_liveliness_subscriber(
                interest_id,
                history,
                mapping_id,
                inline_suffix,
            )
            .map_err(SendWireError::Codec)
            .and_then(|interest| {
                self.send_network_message(
                    wz_session_core::network_message::NetworkMessage::Interest(interest),
                    /*reliable=*/ true,
                    /*express=*/ false,
                )
            });
            if let Err(e) = emit {
                cell.kill();
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_subscribers.unregister(interest_id);
                });
                return Err(e.into());
            }
            // A4 — record for post-reconnect replay; session-state bookkeeping
            // AROUND the seam emit.
            self.actions().cache_subscriber_interest(
                interest_id,
                history,
                mapping_id,
                inline_suffix,
            );
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
            // R311nf — `liveliness_get` lives on `impl Session<R, T, Unicast>`,
            // so `actions()` is the infallible unicast bundle borrow and the
            // establishment gate is the sole precondition. The R311ne
            // transport-first reject ordering (which front-ran a multicast
            // `RequiresUnicast` projection ahead of the misleading
            // NotEstablished gate) is retired: a multicast session is a
            // distinct type with no `liveliness_get` method, so the transport
            // mismatch is a compile error, not a runtime reject to order.
            let actions = self.actions();
            if !actions.is_established() {
                return Err(LivelinessGetError::NotEstablished);
            }
            let keyexpr_string = keyexpr.into();
            let interest_id = actions.alloc_next_interest_id();
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
            // R311mx (B5b-2b-4) — build the one-shot CURRENT liveliness get
            // Interest and route the emit through the
            // [`Self::send_network_message`] send seam instead of
            // `self.actions().send_interest_liveliness_get`. The interest-id
            // alloc + pending-get register (above) + the unregister-only
            // rollback (below) + the reconnect-replay cache stay session-level;
            // the seam emits the wire Interest only.
            let emit = wz_session_core::interest_build::build_interest_liveliness_get(
                interest_id,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            )
            .map_err(SendWireError::Codec)
            .and_then(|interest| {
                self.send_network_message(
                    wz_session_core::network_message::NetworkMessage::Interest(interest),
                    /*reliable=*/ true,
                    /*express=*/ false,
                )
            });
            if let Err(e) = emit {
                R::with_mutex_mut(&self.observer, |observer| {
                    observer.liveliness_gets.unregister(interest_id);
                });
                return Err(e.into());
            }
            // A4 — record for post-reconnect replay; session-state bookkeeping
            // AROUND the seam emit (reuses the `actions` bound above).
            actions.cache_get_interest(
                interest_id,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            );
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
