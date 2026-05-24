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
//! The observer is wrapped in [`std::sync::Mutex`] (not
//! [`tokio::sync::Mutex`]) because the loopback branch runs the
//! subscriber callbacks synchronously — exactly the semantic of a
//! locally-published Sample under zenoh-pico's
//! `_z_session_deliver_push_locally`
//! (`vendor/zenoh-pico/src/session/loopback.c` 70-100) which fires
//! the subscription callbacks in-line under the session lock. A
//! `tokio::sync::Mutex` would force `publish` to be `async`, which
//! would in turn force callers to be `async`, propagating a
//! coloring change for no measurable benefit — the lock window is
//! the time it takes to walk the subscriber table once.
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

use std::sync::{Arc, Mutex};

// R307 — `wz_codecs::query::Query` is referenced bare only by the
// loopback fan inside `Session::query` (`Query::default()`); the
// `declare_queryable` callback signature uses the fully-qualified
// path so it does not consume this `use`. The import therefore
// follows the `query-get` gate, matching its sole bare-name call
// site.
#[cfg(feature = "query-get")]
use wz_codecs::query::Query;
// R311s — `TimeSource` is the generic-parameter bound on the
// type-ungated `Session::query` + `Querier::get` + `QuerierAliased::get`
// surfaces; the import stays unconditional alongside those methods.
use wz_runtime_core::TimeSource;

// R311q — `LivelinessSample` is type-ungated because the unconditional
// `Session::declare_liveliness_subscriber{_aliased}` Result-form
// signatures bind it as the callback parameter type. The
// `LivelinessSampleCallback` boxed-trait alias is only referenced
// inside the cfg-gated body of those methods (the `Box::new(...) as
// LivelinessSampleCallback` cast), so it follows the body gate; the
// split prevents an `unused import` lint on the feature-OFF build.
use crate::declare::LivelinessSample;
#[cfg(feature = "liveliness-subscriber")]
use crate::declare::LivelinessSampleCallback;
// R311o — `OutboundKeyexprError` is wrapped by
// `LivelinessAliasError::InvalidKeyexpr` which is itself unconditional
// after the R311o type-ungating cascade; the import must therefore be
// unconditional too.
use crate::keyexpr_canon::OutboundKeyexprError;
use crate::locality::Locality;
use crate::observer::ApplicationLayerObserver;
use crate::pubsub::SubscriptionId;
// R311r — `crate::query` is type-ungated; `QueryableId` follows the
// same shape (always available). `QueryResponder` is the legacy
// internal type that the R311r ReplyEmitter wraps; it stays imported
// here for the body of `Session::query`'s loopback fan (R246).
// `QueryReply` is only referenced from `Session::query`'s loopback
// fan; it stays gated on `query-get` to match that sole call site.
#[cfg(feature = "query-get")]
use crate::query::QueryReply;
use crate::query::QueryableId;
// R311r — consumer-facing wrappers introduced to decouple the
// queryable callback signature from wz-codecs wire types. The
// signature uses [`QueryEvent`] + [`ReplyEmitter`] regardless of
// `query-queryable` feature state; both types are unconditional so
// the type-ungated `Session::declare_queryable{_aliased}` Result-form
// signatures compile in any consumer-feature subset.
use crate::query_event::{QueryEvent, ReplyEmitter};
// R311s — `crate::reply` is type-ungated; `InboundReply` flows into
// the z_get caller's callback and `ReplyHandle` is the inner success
// value of [`Session::query`]'s `Result<ReplyHandle, QueryAliasError>`
// (R311t Result-form transition replaced the R311s stub-form
// fall-through). Both signatures stay type-ungated so the imports
// remain unconditional.
use crate::reply::{InboundReply, ReplyHandle};
use crate::sample::{
    EncodingHint, QosLevel, Reliability, Sample, SampleKind, SourceInfo, TimestampHint,
};
#[cfg(feature = "liveliness-token")]
use crate::session_glue::SendDeclareError;
use crate::session_glue::{PushMetadata, SessionLinkActions};
// R311o — `QueryTarget` / `ConsolidationMode` are referenced from
// the now-unconditional `QueryOptions` struct fields + builder
// bodies, so they import unconditionally. `QueryMetadata` is only
// returned by the private `query_metadata` helper which stays gated
// on `query-get` (the helper is dead-code under the lower gate), so
// its import follows the same gate.
#[cfg(feature = "query-get")]
use crate::session_glue::QueryMetadata;
use crate::session_glue::{ConsolidationMode, QueryTarget};

/// Options bundle for [`Session::publish`]. Carries the locality
/// routing predicate (`allowed_destination`), the reliability hint
/// for the wire frame and the loopback `Sample.reliability` field,
/// and the [`SampleKind`] discriminator that selects Put vs Del
/// dispatch.
///
/// Construct via [`PublishOptions::put`] / [`PublishOptions::del`]
/// plus optional `with_*` setters; defaults to a Put publish that
/// fans both branches (`Locality::Any`) with `Reliability::Reliable`
/// matching zenoh-pico's `Z_RELIABILITY_DEFAULT`.
///
/// Future-additive: this struct is `#[non_exhaustive]` so R229+ can
/// add metadata fields (`qos`, `attachment`, `timestamp`, `encoding`,
/// `source_info`) without breaking external callers when the wire-side
/// `send_push_literal` learns to accept them. Construct through the
/// builder API rather than struct-literal so the future-additive
/// contract holds.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PublishOptions {
    /// Publisher-side locality predicate (zenoh-pico
    /// `allowed_destination` parameter to `_z_write`). `Any` routes
    /// to both wire and loopback branches; `Remote` to wire only;
    /// `SessionLocal` to loopback only. Default: `Any`.
    pub allowed_destination: Locality,
    /// Link-layer reliability hint propagated to (a) the wire frame's
    /// reliable-flag (zenoh-pico `FLAG_T_FRAME_R`) and (b) the
    /// loopback `Sample.reliability` field. Default: `Reliable`.
    pub reliability: Reliability,
    /// Sample discriminator. `Put` carries the caller payload; `Del`
    /// carries an empty payload (the keyexpr is the entire payload).
    /// Default: `Put`.
    pub kind: SampleKind,
    /// R232 — body-level timestamp propagated to subscribers via
    /// `Sample.timestamp`. On the loopback branch the value lands
    /// verbatim. On the wire branch the value will encode into the
    /// `MsgPut`/`MsgDel` body (R233 carry — current wire branch drops
    /// this field). `None` (default) means no timestamp attached.
    pub timestamp: Option<TimestampHint>,
    /// R232 — body-level encoding propagated to Put-kind subscribers
    /// via `Sample.encoding`. Del-kind ignores this field (zenoh-pico
    /// `_z_msg_del_t` has no encoding slot). Wire-side propagation is
    /// the R233 carry; loopback honours it from R232.
    pub encoding: Option<EncodingHint>,
    /// R232 — body-level source identification propagated to
    /// `Sample.source_info`. Cooperates with the R231 self-echo dedup:
    /// when the dispatcher fires on a wire-arrived Push whose
    /// `source_info.zid` matches the session's own zid, the dedup
    /// suppresses the duplicate fire so a `Locality::Any` publish only
    /// invokes any-locality subscribers once. Wire-side propagation is
    /// the R233 carry; loopback honours it from R232.
    pub source_info: Option<SourceInfo>,
    /// R232 — body-level attachment blob propagated to
    /// `Sample.attachment`. Wire-side propagation is the R233 carry;
    /// loopback honours it from R232.
    pub attachment: Option<Vec<u8>>,
    /// R232 — outer-level QoS metadata propagated to `Sample.qos`.
    /// zenoh-pico mirror: the Push outer `_Z_MSG_EXT_ENC_ZINT | 0x01`
    /// extension carrying priority + congestion-control + express
    /// packed into one byte. Wire-side propagation is the R233 carry;
    /// loopback honours it from R232.
    pub qos: Option<QosLevel>,
}

impl PublishOptions {
    /// Default Put-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`.
    pub fn put() -> Self {
        Self::default()
    }

    /// Default Del-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`, `kind = Del`. The payload argument
    /// to [`Session::publish`] is ignored for Del kind (zenoh-pico
    /// `_z_n_msg_make_push_del` does not carry payload).
    pub fn del() -> Self {
        Self {
            kind: SampleKind::Del,
            ..Self::default()
        }
    }

    /// Pin the publisher-side locality predicate.
    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Pin the reliability hint.
    pub fn with_reliability(mut self, reliability: Reliability) -> Self {
        self.reliability = reliability;
        self
    }

    /// Pin the Sample kind.
    pub fn with_kind(mut self, kind: SampleKind) -> Self {
        self.kind = kind;
        self
    }

    /// R232 — attach a body-level timestamp. The loopback branch
    /// propagates this into `Sample.timestamp` for the subscriber
    /// callback. Wire-side propagation lands in R233.
    pub fn with_timestamp(mut self, timestamp: TimestampHint) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// R232 — attach a body-level encoding (Put kind only; Del kind
    /// ignores the field per zenoh-pico `_z_msg_del_t` layout).
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// R232 — attach a body-level source identification. Pairs with
    /// the R231 self-echo dedup: when the wire receives a publish
    /// whose `source_info.zid` matches the session's own zid, the
    /// dispatch suppresses to avoid double-firing local subscribers
    /// in mesh / router-echo topologies.
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// R232 — attach a body-level attachment blob.
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// R232 — attach outer-level QoS metadata (priority / congestion
    /// control / express byte). Mirrors zenoh-pico's
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01` Push outer extension.
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// Translate [`Reliability`] into the bool flag the legacy
    /// `send_push_*` outbound API expects (it predates the typed
    /// enum). Exposed inside the crate so [`Session::publish`] does
    /// the conversion in exactly one place.
    fn reliable_bool(&self) -> bool {
        matches!(self.reliability, Reliability::Reliable)
    }

    /// R233 — extract the wire-encoder-facing metadata bundle from a
    /// PublishOptions instance so [`Session::publish`] can hand it
    /// to [`crate::session_glue::SessionLinkActions::send_push_with_meta_literal`]
    /// without the lower module learning about
    /// [`Locality`] / [`Reliability`] / [`SampleKind`] (those stay
    /// on the dispatch-time surface). Clones each owned slot — the
    /// expected publish path performs one extraction per publish
    /// call so the allocation cost is amortised against the wire
    /// frame's existing copies.
    fn push_metadata(&self) -> PushMetadata {
        PushMetadata {
            timestamp: self.timestamp.clone(),
            encoding: self.encoding.clone(),
            source_info: self.source_info.clone(),
            attachment: self.attachment.clone(),
            qos: self.qos,
        }
    }
}

/// R239 — options bundle for [`Session::query`]. Mirrors zenoh-pico's
/// `z_get_options_t` (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`
/// 487-497, defaulted by `z_get_options_default`
/// `vendor/zenoh-pico/src/api/api.c:1723`).
///
/// At R239 the *load-bearing* knob is `allowed_destination`: it
/// selects which branches of [`Session::query`] actually run (wire,
/// loopback, or both). The remaining slots (target, consolidation,
/// payload, encoding, attachment, timeout_ms) are captured for
/// future-additive propagation — the AP MVP `send_request_query`
/// path takes none of them today, and the loopback path's
/// in-process [`crate::query::QueryableRegistry::local_query`]
/// only inspects the keyexpr. The R232 → R233 split precedent
/// applies: loopback-side propagation lands first (the in-process
/// `Query` shape exposes these fields), wire-side propagation
/// follows in a subsequent round when the layered
/// `RequestQueryBuilder` is wired through
/// `Session::query`.
///
/// `#[non_exhaustive]` so future rounds add fields without breaking
/// callers. Construct via [`QueryOptions::get`] (or `default`) plus
/// optional `with_*` setters — never struct-literal externally.
///
/// R307 — `#[cfg(feature = "query-get")]`. The struct + impl + every
/// setter elide when `query-get` is off; `with_target` /
/// `with_consolidation` / `with_timeout_ms` carry their own narrower
/// gates so an `--features query-get` (no extras) build still
/// compiles QueryOptions without those setters.
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Struct + builders always defined regardless of the
/// `query-get` family; the per-feature setters (`with_target`,
/// `with_consolidation`, `with_timeout_ms`) keep their signature
/// stable across builds via body cfg-gates that silently no-op when
/// the underlying feature is off (the field stays at its `None` /
/// zero sentinel which is the equivalent wire-elision shape).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct QueryOptions {
    /// Query-side locality predicate. `Any` (default) routes both
    /// wire and loopback; `Remote` to wire only; `SessionLocal` to
    /// loopback only. Mirrors zenoh-pico's `opt.allowed_destination`
    /// in `z_get_with_parameters_substr`.
    pub allowed_destination: Locality,
    /// Reply target hint propagated to the peer. `None` (default)
    /// elides the wire byte → zenoh-pico decodes
    /// `Z_QUERY_TARGET_DEFAULT` = `BEST_MATCHING`. `Some(target)`
    /// sets the Q_T flag and emits the target byte per
    /// [`crate::session_glue::QueryTarget`]. Loopback ignores
    /// target (single-host fan-out has no selection axis).
    pub target: Option<QueryTarget>,
    /// Reply consolidation hint propagated to the peer. `None`
    /// (default) elides → zenoh-pico decodes
    /// `Z_CONSOLIDATION_MODE_AUTO`. `Some(mode)` sets the Q_C flag
    /// and emits the consolidation byte per
    /// [`crate::session_glue::ConsolidationMode`]. Loopback ignores
    /// consolidation (single-source replies have no duplicate to
    /// fold).
    pub consolidation: Option<ConsolidationMode>,
    /// Optional Query-body payload propagated to the queryable
    /// callback. R239 carry — current `send_request_query` wire
    /// builder does not thread the Q_B payload byte; loopback's
    /// `Query` struct does not surface `payload` to the responder
    /// callback either. The slot is reserved so a future round that
    /// adds the wire builder + the `Query.payload` field lands
    /// without an API break.
    pub payload: Option<Vec<u8>>,
    /// Optional encoding metadata for the Query body. Mirror of
    /// `z_get_options_t.encoding`. R239 carry on both wire and
    /// loopback propagation — see `payload`.
    pub encoding: Option<EncodingHint>,
    /// Optional Query-level attachment blob. Mirror of
    /// `z_get_options_t.attachment`. R239 carry.
    pub attachment: Option<Vec<u8>>,
    /// Query timeout in milliseconds (`0` = default = use
    /// `Z_GET_TIMEOUT_DEFAULT`). Used by a future R240+
    /// ReplyRegistry-side timeout sweep that cancels the pending
    /// entry and fires `on_final` synthetically when the deadline
    /// passes without a peer Final. Loopback is synchronous so the
    /// timeout never trips on the loopback branch.
    pub timeout_ms: u32,
}

impl QueryOptions {
    /// Default `Locality::Any` options — fans both wire and loopback
    /// branches. Mirror of zenoh-pico's `z_get_options_default`
    /// in semantic intent (everything cleared / unset).
    pub fn get() -> Self {
        Self::default()
    }

    /// Pin the query-side locality predicate.
    pub fn with_allowed_destination(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Pin the reply target hint. `Some(target)` flips the Q_T flag
    /// on the outbound Query so the peer respects the selection.
    ///
    /// R311o — signature-stable per `feedback_signature_stability`
    /// MEMORY anchor: body cfg-gated on `feature = "query-target"`;
    /// silent no-op when the feature is off (the field stays at its
    /// `None` sentinel which elides the Q_T flag on the wire — same
    /// shape as the default-constructed QueryOptions, so callers can
    /// chain this builder unconditionally without per-feature cfg at
    /// the call site).
    #[cfg_attr(not(feature = "query-target"), allow(unused_mut))]
    pub fn with_target(mut self, target: QueryTarget) -> Self {
        #[cfg(feature = "query-target")]
        {
            self.target = Some(target);
        }
        #[cfg(not(feature = "query-target"))]
        {
            let _ = target;
        }
        self
    }

    /// Pin the reply consolidation hint. `Some(mode)` flips the Q_C
    /// flag on the outbound Query so the peer applies the mode.
    ///
    /// R311o — signature-stable; body cfg-gated on
    /// `feature = "query-consolidation"`; silent no-op when off (field
    /// stays at `None`, Q_C elided — same wire shape as
    /// default-constructed).
    #[cfg_attr(not(feature = "query-consolidation"), allow(unused_mut))]
    pub fn with_consolidation(mut self, consolidation: ConsolidationMode) -> Self {
        #[cfg(feature = "query-consolidation")]
        {
            self.consolidation = Some(consolidation);
        }
        #[cfg(not(feature = "query-consolidation"))]
        {
            let _ = consolidation;
        }
        self
    }

    /// Attach a Query-body payload. Wire + loopback propagation
    /// lands in a follow-up round (current R239 wire builder does
    /// not encode Q_B; loopback's `Query` does not surface payload
    /// to the responder callback either).
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Attach Query-body encoding metadata. Wire + loopback
    /// propagation lands in a follow-up round.
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// Attach a Query-level attachment blob. Wire + loopback
    /// propagation lands in a follow-up round.
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// Pin a per-query timeout in milliseconds. `0` leaves the
    /// default in place. Wire-side enforcement lands with the R240+
    /// ReplyRegistry timeout sweep; loopback ignores the value
    /// (synchronous round-trip).
    ///
    /// R311o — signature-stable; body cfg-gated on
    /// `feature = "query-timeout"`; silent no-op when off (field
    /// stays at the `0` "never-expire" sentinel). The `deadline_ms`
    /// register-time computation in `Session::query` stays
    /// unconditional under `query-get`; this setter is the only user
    /// surface that can flip `timeout_ms` above zero, so disabling
    /// the feature pins the field to the sentinel without breaking
    /// the builder chain.
    #[cfg_attr(not(feature = "query-timeout"), allow(unused_mut))]
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        #[cfg(feature = "query-timeout")]
        {
            self.timeout_ms = timeout_ms;
        }
        #[cfg(not(feature = "query-timeout"))]
        {
            let _ = timeout_ms;
        }
        self
    }

    /// R239 — compute the `expected_finals` count for the
    /// [`crate::reply::ReplyRegistry::register`] call. Mirrors
    /// zenoh-pico's `_z_pending_query_t._remaining_finals`
    /// initialisation in `_z_query`
    /// (`vendor/zenoh-pico/src/net/query.c`): one final per
    /// branch that will eventually emit a Final on this rid.
    ///
    /// * `Locality::Remote` → 1 (peer Final only).
    /// * `Locality::SessionLocal` → 1 (loopback Final only).
    /// * `Locality::Any` → 2 (loopback Final + peer Final).
    ///
    /// R311o — private helper, cfg-gated to its sole caller
    /// [`Session::query`] which already gates on `query-get`. Keeps
    /// the unconditional `impl QueryOptions` block free of dead-code
    /// warnings on `--no-default-features` builds.
    #[cfg(feature = "query-get")]
    fn expected_finals(&self) -> u32 {
        let mut n = 0u32;
        if self.allowed_destination.allows_remote() {
            n += 1;
        }
        if self.allowed_destination.allows_local() {
            n += 1;
        }
        n
    }

    /// R240 — extract the wire-encoder-facing metadata bundle from a
    /// QueryOptions instance so [`Session::query`] can hand it to
    /// [`crate::session_glue::SessionLinkActions::send_request_query_with_meta`]
    /// without the lower module learning about [`Locality`] /
    /// `allowed_destination` (those stay on the dispatch-time
    /// surface). The `payload` and `encoding` slots are intentionally
    /// not threaded here — current wz codec has no Q_B / Q_E slot
    /// on the outbound `Request(Query)`, so they stay on
    /// [`QueryOptions`] as future-additive carries (R241+ when the
    /// codec lands them).
    ///
    /// Clones owned slots (attachment Vec); the expected query path
    /// performs one extraction per Session::query call so the
    /// allocation cost is amortised against the wire frame's existing
    /// copies. Mirrors R233's
    /// [`PublishOptions::push_metadata`] pattern verbatim.
    ///
    /// R311o — private helper, cfg-gated like [`Self::expected_finals`].
    #[cfg(feature = "query-get")]
    fn query_metadata(&self) -> QueryMetadata {
        QueryMetadata {
            target: self.target,
            consolidation: self.consolidation,
            attachment: self.attachment.clone(),
            timeout_ms: self.timeout_ms,
        }
    }
}

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
#[derive(Clone)]
pub struct Session {
    /// Outbound action handle. Cloned `Arc` — multiple `Session`s
    /// can share the same actions if the application binds several
    /// publish surfaces to the same physical session.
    actions: Arc<SessionLinkActions>,
    /// Inbound observer wrapped in [`Mutex`] so [`Session::publish`]'s
    /// loopback branch can borrow the subscriber registry through
    /// the same handle the main dispatch loop uses.
    observer: Arc<Mutex<ApplicationLayerObserver>>,
}

impl Session {
    /// Construct a new session bundle from existing handles.
    /// `actions` typically comes from
    /// [`SessionLinkActions::new`](crate::session_glue::SessionLinkActions::new);
    /// `observer` is a freshly-wrapped
    /// [`ApplicationLayerObserver::new`](crate::observer::ApplicationLayerObserver::new).
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
    pub fn new(
        actions: Arc<SessionLinkActions>,
        observer: Arc<Mutex<ApplicationLayerObserver>>,
    ) -> Self {
        let session = Self { actions, observer };
        // R236 — forward the local zid from SessionInitParams into
        // the subscriber registry so wire-arrived self-echo Pushes
        // are dedup'd from session creation onward. The `1..=16`
        // range check inside `set_own_zid` quietly rejects an
        // out-of-range value (returns `false`); empty zid skipped
        // here so the registry stays in its pre-R231 default state
        // for test fixtures that don't supply a zid.
        if !session.actions.params.zid.is_empty() {
            let _ = session.set_own_zid(session.actions.params.zid.clone());
        }
        session
    }

    /// Borrow the outbound action handle. Useful when the caller
    /// needs to invoke non-publish methods like `send_declare_*` or
    /// `send_request_query` directly on the actions surface.
    pub fn actions(&self) -> &Arc<SessionLinkActions> {
        &self.actions
    }

    /// Borrow the observer handle. Application code registers
    /// callbacks on the contained registries through this — typically
    /// `session.observer().lock().unwrap().subscribers.register(...)`.
    pub fn observer(&self) -> &Arc<Mutex<ApplicationLayerObserver>> {
        &self.observer
    }

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
        self.actions.is_established()
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
    pub fn set_own_zid(&self, zid: Vec<u8>) -> bool {
        let mut observer = self
            .observer
            .lock()
            .expect("ApplicationLayerObserver mutex poisoned");
        observer.subscribers.set_own_zid(zid)
    }

    /// R231 — release the previously-installed own zid (paired with
    /// [`Session::set_own_zid`]). After clear, every wire-arrived
    /// Push fires its matching subscribers; the self-echo guard
    /// stays disabled until a fresh `set_own_zid` install. Useful
    /// in session re-init / close scenarios where the prior zid
    /// must not bleed into a new session's dispatch state.
    pub fn clear_own_zid(&self) {
        let mut observer = self
            .observer
            .lock()
            .expect("ApplicationLayerObserver mutex poisoned");
        observer.subscribers.clear_own_zid();
    }

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
    pub fn publish(&self, keyexpr: &str, payload: &[u8], opts: PublishOptions) -> usize {
        let reliable = opts.reliable_bool();
        if opts.allowed_destination.allows_remote() {
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions
                        .send_push_with_meta_literal(keyexpr, payload, reliable, &meta);
                }
                SampleKind::Del => {
                    self.actions
                        .send_push_del_with_meta_literal(keyexpr, reliable, &meta);
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let sample = build_loopback_sample(keyexpr, payload, &opts);
            self.observer
                .lock()
                .expect("Session observer mutex poisoned — a subscriber callback panicked")
                .subscribers
                .local_publish(&sample)
        } else {
            0
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
    ) -> usize {
        let reliable = opts.reliable_bool();
        if opts.allowed_destination.allows_remote() {
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions.send_push_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        payload,
                        reliable,
                        &meta,
                    );
                }
                SampleKind::Del => {
                    self.actions.send_push_del_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        reliable,
                        &meta,
                    );
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let sample = build_loopback_sample(loopback_keyexpr, payload, &opts);
            self.observer
                .lock()
                .expect("Session observer mutex poisoned — a subscriber callback panicked")
                .subscribers
                .local_publish(&sample)
        } else {
            0
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
            .actions
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
        Ok(self.publish_aliased(mapping_id, inline_suffix, &loopback_keyexpr, payload, opts))
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
    pub fn query<T: TimeSource>(
        &self,
        keyexpr: &str,
        opts: QueryOptions,
        clock: &T,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (keyexpr, opts, clock, on_reply, on_final);
            return Err(QueryAliasError::FeatureDisabled);
        }
        #[cfg(feature = "query-get")]
        {
            let rid = self.actions.alloc_next_request_id();
            let expected_finals = opts.expected_finals();
            let allows_remote = opts.allowed_destination.allows_remote();
            let allows_local = opts.allowed_destination.allows_local();
            // R262 — compute the absolute monotonic-ms deadline from
            // `clock.now_monotonic_ms()` + `opts.timeout_ms`. timeout_ms == 0
            // is the "no timeout" sentinel; the pending entry is registered
            // with deadline_ms = None and survives every sweep until a
            // wire/loopback Final arrives. The same clock instance MUST be
            // used by `drive_session_until_terminal` so the sweep call
            // shares monotonic epoch with this register-time deadline (see
            // `drive_session_until_terminal`'s clock parameter doc).
            let deadline_ms =
                (opts.timeout_ms > 0).then(|| clock.now_monotonic_ms() + opts.timeout_ms as u64);

            let handle = {
                let mut observer = self
                    .observer
                    .lock()
                    .expect("Session observer mutex poisoned — a reply callback panicked");
                let handle = observer.replies.register(
                    rid,
                    expected_finals,
                    deadline_ms,
                    on_reply,
                    on_final,
                );
                if allows_local {
                    let mut replies: Vec<QueryReply> = Vec::new();
                    let query = Query::default();
                    observer
                        .queryables
                        .local_query(rid, keyexpr, &query, &mut replies);
                    for reply in replies.drain(..) {
                        let inbound: InboundReply = reply.into();
                        observer.replies.deliver_local_reply(&inbound);
                    }
                    // Synthetic Final closes the loopback half of the
                    // pending entry's `remaining_finals` counter so a
                    // SessionLocal-only z_get finalises immediately and a
                    // Locality::Any z_get still needs the peer Final to
                    // finalise (matching zenoh-pico
                    // `_z_session_deliver_query_locally`'s emit-final
                    // step at the tail of the local deliver path).
                    observer.replies.deliver_local_final(rid);
                }
                handle
            };

            if allows_remote {
                // R240 — thread QueryOptions metadata (target /
                // consolidation / attachment / timeout_ms) through the
                // wire branch. The R233 PushMetadata pattern is mirrored
                // here: empty bundle short-circuits to the no-metadata
                // builder so the byte-stable
                // `send_request_query` wire shape stays unchanged for
                // callers that pass `QueryOptions::default()`.
                let meta = opts.query_metadata();
                if meta.is_empty() {
                    self.actions.send_request_query(rid, 0, Some(keyexpr));
                } else {
                    self.actions
                        .send_request_query_with_meta(rid, 0, Some(keyexpr), &meta);
                }
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
    #[allow(clippy::too_many_arguments)]
    pub fn query_aliased<T: TimeSource>(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        loopback_keyexpr: &str,
        opts: QueryOptions,
        clock: &T,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (
                mapping_id,
                inline_suffix,
                loopback_keyexpr,
                opts,
                clock,
                on_reply,
                on_final,
            );
            return Err(QueryAliasError::FeatureDisabled);
        }
        #[cfg(feature = "query-get")]
        {
            let rid = self.actions.alloc_next_request_id();
            let expected_finals = opts.expected_finals();
            let allows_remote = opts.allowed_destination.allows_remote();
            let allows_local = opts.allowed_destination.allows_local();
            // R262 — same deadline_ms computation as `Session::query`.
            // The clock must share monotonic epoch with the sweep caller
            // (typically `drive_session_until_terminal`).
            let deadline_ms =
                (opts.timeout_ms > 0).then(|| clock.now_monotonic_ms() + opts.timeout_ms as u64);

            let handle = {
                let mut observer = self
                    .observer
                    .lock()
                    .expect("Session observer mutex poisoned — a reply callback panicked");
                let handle = observer.replies.register(
                    rid,
                    expected_finals,
                    deadline_ms,
                    on_reply,
                    on_final,
                );
                if allows_local {
                    let mut replies: Vec<QueryReply> = Vec::new();
                    let query = Query::default();
                    observer
                        .queryables
                        .local_query(rid, loopback_keyexpr, &query, &mut replies);
                    for reply in replies.drain(..) {
                        let inbound: InboundReply = reply.into();
                        observer.replies.deliver_local_reply(&inbound);
                    }
                    observer.replies.deliver_local_final(rid);
                }
                handle
            };

            if allows_remote {
                let meta = opts.query_metadata();
                if meta.is_empty() {
                    self.actions
                        .send_request_query(rid, mapping_id, inline_suffix);
                } else {
                    self.actions.send_request_query_with_meta(
                        rid,
                        mapping_id,
                        inline_suffix,
                        &meta,
                    );
                }
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
    pub fn query_aliased_auto<T: TimeSource>(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        opts: QueryOptions,
        clock: &T,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        #[cfg(not(feature = "query-get"))]
        {
            let _ = (mapping_id, inline_suffix, opts, clock, on_reply, on_final);
            return Err(QueryAliasError::FeatureDisabled);
        }
        #[cfg(feature = "query-get")]
        {
            let base = self
                .actions
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
            self.query_aliased(
                mapping_id,
                inline_suffix,
                &loopback_keyexpr,
                opts,
                clock,
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
    pub fn declare_querier(&self, keyexpr: impl Into<String>, options: QueryOptions) -> Querier {
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
    ) -> QuerierAliased {
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
    ) -> Publisher {
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
    ) -> PublisherAliased {
        PublisherAliased {
            session: self.clone(),
            mapping_id,
            inline_suffix: inline_suffix.map(str::to_string),
            options,
        }
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
    pub fn declare_subscriber(
        &self,
        keyexpr: impl Into<String>,
        options: SubscribeOptions,
        callback: impl FnMut(&Sample) + Send + 'static,
    ) -> Subscriber {
        let keyexpr_string = keyexpr.into();
        let id = self
            .observer
            .lock()
            .expect("Session observer mutex poisoned — a subscriber callback panicked")
            .subscribers
            .register_with_locality(keyexpr_string.clone(), options.allowed_origin, callback);
        Subscriber {
            session: self.clone(),
            id,
            keyexpr: keyexpr_string,
            options,
        }
    }

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
        callback: impl FnMut(&Sample) + Send + 'static,
    ) -> Result<Subscriber, SubscribeAliasError> {
        let base = self
            .actions
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
    /// with [`Self::declare_queryable_aliased`]; callback signature
    /// switched to `FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>)`
    /// (R311r wrapper types) so the application callback no longer
    /// directly references the wz-codecs wire types. The new Err
    /// variant a caller sees on this method (over the prior `->
    /// Queryable` form) is `QueryableAliasError::FeatureDisabled`
    /// when the build elides `query-queryable`; default-feature
    /// builds always observe `Ok(...)`. Body cfg-wrap follows the
    /// R311g1 signature-stability principle.
    pub fn declare_queryable(
        &self,
        keyexpr: impl Into<String>,
        options: QueryableOptions,
        callback: impl FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>) + Send + 'static,
    ) -> Result<Queryable, QueryableAliasError> {
        #[cfg(feature = "query-queryable")]
        {
            let keyexpr_string = keyexpr.into();
            let id = self
                .observer
                .lock()
                .expect("Session observer mutex poisoned — a queryable callback panicked")
                .queryables
                .register_with_locality(keyexpr_string.clone(), options.allowed_origin, callback);
            Ok(Queryable {
                session: self.clone(),
                id,
                keyexpr: keyexpr_string,
                options,
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
        callback: impl FnMut(&QueryEvent<'_>, &mut ReplyEmitter<'_>) + Send + 'static,
    ) -> Result<Queryable, QueryableAliasError> {
        #[cfg(feature = "query-queryable")]
        {
            let base = self
                .actions
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
    ) -> Result<LivelinessToken, LivelinessAliasError> {
        #[cfg(feature = "liveliness-token")]
        {
            let keyexpr_string = keyexpr.into();
            let token_id = self.actions.alloc_next_token_id();
            self.actions
                .send_declare_token(token_id, /*mapping_id=*/ 0, Some(&keyexpr_string))
                .map_err(|e| match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
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
            Ok(LivelinessToken {
                session: self.clone(),
                id: token_id,
                keyexpr: keyexpr_string,
                options,
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
    ) -> Result<LivelinessToken, LivelinessAliasError> {
        #[cfg(feature = "liveliness-token")]
        {
            let base = self
                .actions
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
            let token_id = self.actions.alloc_next_token_id();
            self.actions
                .send_declare_token(token_id, mapping_id, inline_suffix)
                .map_err(|e| match e {
                    SendDeclareError::Keyexpr(inner) => LivelinessAliasError::InvalidKeyexpr(inner),
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
            })
        }
        #[cfg(not(feature = "liveliness-token"))]
        {
            let _ = (mapping_id, inline_suffix, options);
            Err(LivelinessAliasError::FeatureDisabled)
        }
    }

    /// R280 — declare a liveliness subscriber on a literal `keyexpr`
    /// pattern, registering a [`LivelinessSampleCallback`] that fires
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
    ) -> Result<LivelinessSubscriber, LivelinessSubscriberAliasError> {
        #[cfg(feature = "liveliness-subscriber")]
        {
            let keyexpr_string = keyexpr.into();
            let interest_id = self.actions.alloc_next_interest_id();
            // Register first, emit Interest second — the order matters for
            // races against an inbound DeclToken whose Interest reached
            // the peer earlier (e.g. a re-declared subscriber after a
            // session-layer Reconnect, R267+ topology). The wire-emit
            // panic-free invariant from `send_declare_token` applies
            // equally to `send_interest_liveliness_subscriber`.
            self.observer
                .lock()
                .expect("observer mutex poisoned by an earlier panicked callback")
                .liveliness_subscribers
                .register(
                    interest_id,
                    keyexpr_string.clone(),
                    options.history,
                    Box::new(callback) as LivelinessSampleCallback,
                );
            self.actions.send_interest_liveliness_subscriber(
                interest_id,
                options.history,
                /*keyexpr_mapping_id=*/ 0,
                Some(&keyexpr_string),
            );
            Ok(LivelinessSubscriber {
                session: self.clone(),
                interest_id,
                keyexpr: keyexpr_string,
                options,
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
    ) -> Result<LivelinessSubscriber, LivelinessSubscriberAliasError> {
        #[cfg(feature = "liveliness-subscriber")]
        {
            // Mapping check first — FSM-state-independent, surfaces a
            // bug-class error (caller forgot send_declare_keyexpr) before
            // the state-dependent retry loop. R282 + R283 ordering rule.
            let base = self
                .actions
                .resolve_outbound_mapping(mapping_id)
                .ok_or(LivelinessSubscriberAliasError::UnknownMapping(mapping_id))?;
            // R283 Established gate. Done after mapping resolution so a
            // pre-Established call with a bad mapping surfaces the bad
            // mapping (the bug) rather than the transient state. No
            // interest-id is burned on the early-return path.
            if !self.actions.is_established() {
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
            let interest_id = self.actions.alloc_next_interest_id();
            // Register first against the resolved literal so any racing
            // inbound dispatch (peer responding to an earlier
            // session-arming Interest, an out-of-order DeclToken that
            // arrives before our Interest is processed by the peer) finds
            // the slot ready and fires the callback. Same ordering rule
            // as `declare_liveliness_subscriber`.
            self.observer
                .lock()
                .expect("observer mutex poisoned by an earlier panicked callback")
                .liveliness_subscribers
                .register(
                    interest_id,
                    resolved.clone(),
                    options.history,
                    Box::new(callback) as LivelinessSampleCallback,
                );
            // Wire emit carries the alias form so the peer pays the
            // mapping_id + optional inline_suffix cost rather than the
            // full literal each time — bandwidth parity with
            // `declare_token_aliased`'s aliased wire emit.
            self.actions.send_interest_liveliness_subscriber(
                interest_id,
                options.history,
                mapping_id,
                inline_suffix,
            );
            Ok(LivelinessSubscriber {
                session: self.clone(),
                interest_id,
                keyexpr: resolved,
                options,
            })
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            let _ = (mapping_id, inline_suffix, options, callback);
            Err(LivelinessSubscriberAliasError::FeatureDisabled)
        }
    }
}

/// R241 — typed error returned by [`Session::query_aliased_auto`]
/// when the requested mapping id was never declared on this
/// session's outbound link (or was retracted via
/// [`SessionLinkActions::send_undeclare_kexpr`]). Mirror of
/// [`PublishAliasError`] on the z_get side — the caller's contract
/// is "declare before query"; this enum names the violation
/// explicitly so a buggy caller does not silently emit wire frames
/// the peer will reject and run loopback on a guessed literal that
/// hands replies to a pending entry the application never
/// registered for the correct keyexpr.
///
/// R311s — type-ungated alongside the Querier surface; gains a
/// `FeatureDisabled` variant for surface consistency with the
/// LivelinessSubscriberAliasError + QueryableAliasError families
/// (R311q/R311r).
///
/// R311t — Result-form transition activates the `FeatureDisabled`
/// variant across [`Session::query`], [`Session::query_aliased`],
/// [`Session::query_aliased_auto`], [`Querier::get`], and
/// [`QuerierAliased::get`]. Callers branch uniformly on the same
/// enum across all five entry points and across all
/// consumer-feature subsets. The R311s stub-form fall-through
/// (sentinel `ReplyHandle(0)`) was retired because silent no-op was
/// an honest-signal anti-pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it). The wrapped value is the offending mapping id.
    UnknownMapping(u64),
    /// R311s — the `query-get` feature is OFF at compile time.
    /// Reserved for a future Result-form transition (R311s minimal
    /// scope keeps the stub-form fall-through to a sentinel handle
    /// for callsite stability; this variant lets callers branch on
    /// FeatureDisabled uniformly once the transition lands).
    FeatureDisabled,
}

impl std::fmt::Display for QueryAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryAliasError::UnknownMapping(id) => write!(
                f,
                "QueryAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            QueryAliasError::FeatureDisabled => write!(
                f,
                "QueryAliasError: query-get feature is OFF at compile time; the \
                 outbound query / reply-registry paths are elided on this build"
            ),
        }
    }
}

impl std::error::Error for QueryAliasError {}

/// R242 — reusable query target with pre-set keyexpr + options.
/// Mirror of zenoh-pico's `z_querier_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/types.h:266`): a
/// caller declares the querier once
/// ([`Session::declare_querier`]) and emits repeated outbound
/// `Request(Query)` records through [`Self::get`] without
/// restating the keyexpr or options on every call.
///
/// The Rust API collapses zenoh-pico's `z_querier_options_t`
/// (declare-time) and `z_querier_get_options_t` (get-time) into a
/// single [`QueryOptions`] held by the Querier — Rust's owned
/// borrow model makes the c-ergonomic split unnecessary. Callers
/// who want a per-call options override can clone the Querier's
/// options, mutate, and call [`Session::query`] directly.
///
/// `Clone` is cheap (the inner `Session` is itself Clone-cheap
/// `Arc`s, and `QueryOptions` is a `Clone` value struct). A
/// background task can hold a per-task Querier clone without
/// touching shared state on every get call.
///
/// `#[non_exhaustive]` so future rounds add fields (e.g. a
/// declare-time matching_status callback hook) without breaking
/// callers. Construct only through [`Session::declare_querier`].
///
/// R311s — type-ungated. The struct + impl are always defined so
/// callers can hold a `Querier` value across builds; the `.get()`
/// method internally calls [`Session::query`] whose Result-form OFF
/// arm returns `Err(QueryAliasError::FeatureDisabled)` (R311t — no
/// wire frame, no callback registration). The aggregator-only body
/// of [`Session::declare_querier`] means no observer access happens
/// at construction, so the type stays usable across all
/// consumer-feature subsets.
#[derive(Clone)]
#[non_exhaustive]
pub struct Querier {
    session: Session,
    keyexpr: String,
    options: QueryOptions,
}

impl Querier {
    /// Borrow the declared keyexpr. The literal form supplied to
    /// [`Session::declare_querier`]; identical to what each
    /// [`Self::get`] call threads to [`Session::query`].
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options. Useful when a caller wants to
    /// derive an override (`.clone().with_*()`) for a single
    /// [`Session::query`] call without disturbing the Querier's
    /// baseline.
    pub fn options(&self) -> &QueryOptions {
        &self.options
    }

    /// Emit one outbound query through the declared keyexpr +
    /// options. Returns the [`ReplyHandle`] inside `Ok(...)` from the
    /// underlying [`Session::query`] call so the caller can
    /// [`crate::reply::ReplyRegistry::unregister`] before the Final
    /// arrives if the application cancels the pending z_get.
    ///
    /// Each call allocates a fresh rid (via
    /// [`SessionLinkActions::alloc_next_request_id`]) so successive
    /// calls are independent pending entries — concurrent gets on
    /// the same Querier do not collide on the rid keyspace.
    ///
    /// Returns `Err(QueryAliasError::FeatureDisabled)` when the
    /// `query-get` feature is OFF (R311t — propagated verbatim from
    /// [`Session::query`]'s Result-form OFF arm). No wire frame, no
    /// callback registration on the feature-disabled path.
    ///
    /// Mirrors zenoh-pico's `z_querier_get`
    /// (`vendor/zenoh-pico/src/api/api.c:1902` —
    /// `_z_query(&sess_rc, _z_optional_id_make_some(querier->_id), ...)`).
    pub fn get<T: TimeSource>(
        &self,
        clock: &T,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        self.session.query(
            &self.keyexpr,
            self.options.clone(),
            clock,
            on_reply,
            on_final,
        )
    }

    /// R288 — mirror of zenoh-pico's `z_querier_get_matching_status`
    /// (`vendor/zenoh-pico/src/api/api.c:1988`). Returns a
    /// [`MatchingStatus`] whose `matching` field is `true` iff at
    /// least one peer has currently declared a queryable whose
    /// keyexpr matches the querier's keyexpr.
    ///
    /// The match is computed against the
    /// [`crate::declare::RemoteQueryableRegistry`] inside the
    /// session's observer; the registry tracks the
    /// `{peer_decl_id -> resolved keyexpr}` membership maintained by
    /// the drive_session loop dispatch of inbound
    /// `Declare(DeclQueryable)` / `Declare(UndeclQueryable)`
    /// records. Lock contention is the single observer mutex held
    /// briefly to consult the membership; no wire frame is emitted.
    ///
    /// The match algorithm is the bidirectional asymmetric
    /// pattern-match approximation described on
    /// [`crate::declare::RemoteQueryableRegistry::has_matching`].
    /// Honest two-pattern wildcard intersection is a future-round
    /// carry; the wz keyexpr v1 spec currently locks intersect to
    /// exact uint32 ID equality for MVP (RFC §5.A line 311).
    ///
    /// R310.5c — the method signature is always visible whenever
    /// `Querier` exists (i.e. whenever `feature = "query-get"` is
    /// enabled), preserving the zenoh-cpp API parity. The body
    /// branches on `feature = "declare-queryable"`: when the
    /// `RemoteQueryableRegistry` observer field is elided (the
    /// feature is off), the method conservatively returns
    /// `MatchingStatus { matching: false }` rather than disappearing
    /// from the surface. R310 previously gated the entire signature
    /// on `declare-queryable`, which broke the zenoh-cpp parity
    /// (consumers had to themselves cfg-gate every call site).
    pub fn get_matching_status(&self) -> MatchingStatus {
        #[cfg(feature = "declare-queryable")]
        let matching = {
            let observer = self.session.observer();
            let obs = match observer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            obs.remote_queryables.has_matching(&self.keyexpr)
        };
        #[cfg(not(feature = "declare-queryable"))]
        let matching = false;
        MatchingStatus { matching }
    }
}

/// R288 — return type of [`Querier::get_matching_status`]. Mirror
/// of zenoh-pico's `z_matching_status_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/session/matching.h:26`)
/// which carries a single `matching: bool` field. The `#[non_exhaustive]`
/// attribute reserves the API shape for future fields (peer count,
/// per-peer-id matches, recheck timestamp) without breaking callers
/// that pattern-match on the struct.
///
/// `Clone + Copy` so the value can be cheaply returned by value and
/// captured by callbacks; `Debug` so the demo binary's log lines and
/// integration test asserts can stringify it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MatchingStatus {
    /// `true` iff at least one peer-declared queryable matches the
    /// querier's keyexpr at consult time.
    pub matching: bool,
}

/// R243 — aliased-keyexpr counterpart of [`Querier`]. Mirror of
/// [`Querier`] holding `(mapping_id, inline_suffix, options)`
/// rather than a literal keyexpr; each [`Self::get`] call
/// delegates to [`Session::query_aliased_auto`] which resolves the
/// loopback literal through the session's outbound mapping table
/// before fanning both wire and loopback branches.
///
/// Returns `Err(QueryAliasError::UnknownMapping(id))` from
/// [`Self::get`] when the declared mapping id was never registered
/// on the outbound table (or was retracted via
/// [`SessionLinkActions::send_undeclare_kexpr`] between
/// [`Session::declare_querier_aliased`] and [`Self::get`]). The
/// caller treats this as a contract violation matching the
/// declare-before-query invariant.
///
/// Like [`Querier`], the declaration is a caller-side aggregation
/// and emits NO wire frame at declare time — declare_querier_aliased
/// does not register a peer-side resource (the
/// [`SessionLinkActions::send_declare_keyexpr`] call that populates
/// the outbound mapping is a separate, earlier step under the
/// caller's control).
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_querier_aliased`].
///
/// R311s — type-ungated. Same shape as [`Querier`] with mapping id
/// alongside inline suffix added; aggregator-only construction means
/// the struct is always usable regardless of `query-get` feature
/// state.
#[derive(Clone)]
#[non_exhaustive]
pub struct QuerierAliased {
    session: Session,
    mapping_id: u64,
    inline_suffix: Option<String>,
    options: QueryOptions,
}

impl QuerierAliased {
    /// The declared mapping id. Must have been previously registered
    /// via [`SessionLinkActions::send_declare_keyexpr`] for
    /// [`Self::get`] to succeed.
    pub fn mapping_id(&self) -> u64 {
        self.mapping_id
    }

    /// The optional inline suffix. `None` emits a pure-aliased
    /// query (declared literal is the full keyexpr); `Some(s)`
    /// emits a composite query (declared prefix + `s`).
    pub fn inline_suffix(&self) -> Option<&str> {
        self.inline_suffix.as_deref()
    }

    /// Borrow the declared options. Same accessor shape as
    /// [`Querier::options`].
    pub fn options(&self) -> &QueryOptions {
        &self.options
    }

    /// Emit one outbound aliased query. Returns
    /// `Err(QueryAliasError::UnknownMapping(id))` when the declared
    /// `mapping_id` is no longer present on the outbound mapping
    /// table — neither wire nor loopback branch fires in that case
    /// (matching [`Session::query_aliased_auto`]'s no-silent-partial
    /// contract).
    ///
    /// On the success path each call allocates a fresh rid; the
    /// returned [`ReplyHandle`] tracks the pending entry on
    /// [`crate::reply::ReplyRegistry`].
    pub fn get<T: TimeSource>(
        &self,
        clock: &T,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        self.session.query_aliased_auto(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            self.options.clone(),
            clock,
            on_reply,
            on_final,
        )
    }

    /// R289 — aliased-keyexpr counterpart of
    /// [`Querier::get_matching_status`]. Resolves the declared
    /// `mapping_id` through the outbound keyexpr table to a base
    /// literal, composes the optional `inline_suffix` to the
    /// effective keyexpr, and consults
    /// [`crate::declare::RemoteQueryableRegistry::has_matching`].
    /// Returns `Err(QueryAliasError::UnknownMapping(id))` when the
    /// declared `mapping_id` is not present on the outbound mapping
    /// table — same contract as [`Self::get`], mirroring the
    /// declare-before-query invariant for the matching-status
    /// consult path.
    ///
    /// On the success path the returned [`MatchingStatus`] reflects
    /// the registry membership at the moment of the consult; the
    /// observer mutex is held only across the resolve + has_matching
    /// arms (no wire emit, no allocation beyond the small
    /// `effective_keyexpr` composition).
    ///
    /// R310.5c — same shape pattern as
    /// [`Querier::get_matching_status`]: the method signature is
    /// always visible whenever `QuerierAliased` exists, body branches
    /// on `feature = "declare-queryable"`. The
    /// `UnknownMapping(id)` validation always fires (so callers still
    /// see the declare-before-query invariant); only the actual
    /// registry consult is skipped when the feature is off, yielding
    /// `Ok(MatchingStatus { matching: false })` on the success path.
    pub fn get_matching_status(&self) -> Result<MatchingStatus, QueryAliasError> {
        let base = self
            .session
            .actions()
            .resolve_outbound_mapping(self.mapping_id)
            .ok_or(QueryAliasError::UnknownMapping(self.mapping_id))?;
        let _effective_keyexpr = match self.inline_suffix.as_deref() {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        #[cfg(feature = "declare-queryable")]
        let matching = {
            let observer = self.session.observer();
            let obs = match observer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            obs.remote_queryables.has_matching(&_effective_keyexpr)
        };
        #[cfg(not(feature = "declare-queryable"))]
        let matching = false;
        Ok(MatchingStatus { matching })
    }
}

/// R244 — reusable publish target with pre-set keyexpr + options.
/// Pub-side mirror of [`Querier`]. A caller declares the publisher
/// once ([`Session::declare_publisher`]) and emits repeated
/// outbound `Push` records through [`Self::put`] / [`Self::delete`]
/// without restating the keyexpr or options on every call.
///
/// `Clone` is cheap (Arc-backed Session + value-clone of
/// PublishOptions). Background tasks can hold per-task Publisher
/// clones; all clones share the same observer + actions handle so
/// loopback dispatches still reach the main drive_session loop.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_publisher`].
///
/// Mirrors zenoh-pico's `z_publisher_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`) with
/// `z_declare_publisher` + `z_publisher_put` + `z_publisher_delete`.
#[derive(Clone)]
#[non_exhaustive]
pub struct Publisher {
    session: Session,
    keyexpr: String,
    options: PublishOptions,
}

impl Publisher {
    /// Borrow the declared keyexpr.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &PublishOptions {
        &self.options
    }

    /// Emit one outbound Put through the declared keyexpr + options.
    /// Returns the loopback fire count (number of matching local
    /// subscribers that fired), matching [`Session::publish`]'s
    /// return contract.
    ///
    /// Per-call `opts.kind` is overridden to [`SampleKind::Put`] —
    /// the declared options retain the caller's reliability /
    /// locality / metadata choices; only the discriminator that
    /// selects put vs delete is overridden by the call shape.
    pub fn put(&self, payload: &[u8]) -> usize {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Put;
        self.session.publish(&self.keyexpr, payload, opts)
    }

    /// Emit one outbound Del (delete-keyexpr signal) through the
    /// declared keyexpr + options. Payload is the empty slice (Del
    /// kind carries none on the wire — `MsgDel` body has no payload
    /// slot per zenoh-pico `_z_msg_del_t`).
    ///
    /// Per-call `opts.kind` is overridden to [`SampleKind::Del`].
    pub fn delete(&self) -> usize {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Del;
        self.session.publish(&self.keyexpr, &[], opts)
    }

    /// R290 — pub-side mirror of [`Querier::get_matching_status`].
    /// Mirror of zenoh-pico's `z_publisher_get_matching_status`
    /// (`vendor/zenoh-pico/src/api/api.c`): returns a
    /// [`MatchingStatus`] whose `matching` field is `true` iff at
    /// least one peer has currently declared a subscriber whose
    /// keyexpr matches the publisher's keyexpr.
    ///
    /// Consults
    /// [`crate::declare::RemoteSubscriberRegistry::has_matching`]
    /// inside the session's observer (the registry tracks the
    /// `{peer_decl_id -> resolved keyexpr}` membership maintained
    /// by the drive_session loop dispatch of inbound
    /// `Declare(DeclSubscriber)` / `Declare(UndeclSubscriber)`
    /// records). Lock contention is the single observer mutex held
    /// briefly to consult the membership; no wire frame is emitted.
    ///
    /// Match algorithm is the same bidirectional asymmetric pattern-
    /// match approximation used by [`Querier::get_matching_status`]
    /// — see that doc-comment for the boundary description and the
    /// R291 honest-intersection carry.
    ///
    /// R310.5c — the method signature is always visible whenever
    /// `Publisher` exists (always, since `Publisher` has no cfg
    /// gate), preserving zenoh-cpp API parity. The body branches on
    /// `feature = "declare-subscriber"`: when the
    /// `RemoteSubscriberRegistry` observer field is elided (the
    /// feature is off), the method conservatively returns
    /// `MatchingStatus { matching: false }` rather than disappearing
    /// from the surface. R310 previously gated the entire signature
    /// on `declare-subscriber`, which broke the zenoh-cpp parity
    /// (consumers had to themselves cfg-gate every call site).
    pub fn get_matching_status(&self) -> MatchingStatus {
        #[cfg(feature = "declare-subscriber")]
        let matching = {
            let observer = self.session.observer();
            let obs = match observer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            obs.remote_subscribers.has_matching(&self.keyexpr)
        };
        #[cfg(not(feature = "declare-subscriber"))]
        let matching = false;
        MatchingStatus { matching }
    }
}

/// R244 — aliased-keyexpr counterpart of [`Publisher`]. Holds
/// `(mapping_id, inline_suffix, options)` so subsequent [`Self::put`]
/// / [`Self::delete`] calls route through
/// [`Session::publish_aliased_auto`] which resolves the loopback
/// literal through the outbound mapping table.
///
/// Returns `Err(PublishAliasError::UnknownMapping(id))` from
/// [`Self::put`] / [`Self::delete`] when the declared mapping id
/// was never registered (or was retracted via
/// [`SessionLinkActions::send_undeclare_kexpr`]). Mirror of
/// [`QuerierAliased`] on the pub side.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_publisher_aliased`].
#[derive(Clone)]
#[non_exhaustive]
pub struct PublisherAliased {
    session: Session,
    mapping_id: u64,
    inline_suffix: Option<String>,
    options: PublishOptions,
}

impl PublisherAliased {
    /// The declared mapping id.
    pub fn mapping_id(&self) -> u64 {
        self.mapping_id
    }

    /// The optional inline suffix (composite-aliased keyexpr).
    pub fn inline_suffix(&self) -> Option<&str> {
        self.inline_suffix.as_deref()
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &PublishOptions {
        &self.options
    }

    /// Emit one outbound Put through the aliased mapping. Returns
    /// `Err(PublishAliasError::UnknownMapping(id))` when the declared
    /// `mapping_id` is no longer present on the outbound mapping
    /// table — neither wire nor loopback branch fires.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishAliasError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Put;
        self.session.publish_aliased_auto(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            payload,
            opts,
        )
    }

    /// Emit one outbound Del through the aliased mapping. Returns
    /// `Err(PublishAliasError::UnknownMapping(id))` on mapping
    /// absence per [`Self::put`]'s contract.
    pub fn delete(&self) -> Result<usize, PublishAliasError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Del;
        self.session
            .publish_aliased_auto(self.mapping_id, self.inline_suffix.as_deref(), &[], opts)
    }

    /// R290 — aliased-keyexpr counterpart of
    /// [`Publisher::get_matching_status`]. Mirrors
    /// [`QuerierAliased::get_matching_status`] on the pub side:
    /// resolves the declared `mapping_id` through the outbound
    /// keyexpr table, composes the optional `inline_suffix` to the
    /// effective keyexpr, and consults
    /// [`crate::declare::RemoteSubscriberRegistry::has_matching`].
    /// Returns `Err(PublishAliasError::UnknownMapping(id))` when
    /// the declared `mapping_id` is not present on the outbound
    /// mapping table — same contract as [`Self::put`] /
    /// [`Self::delete`], mirroring the declare-before-publish
    /// invariant for the matching-status consult path.
    ///
    /// R310.5c — same shape pattern as
    /// [`Publisher::get_matching_status`] /
    /// [`QuerierAliased::get_matching_status`]: signature always
    /// visible, body branches on `feature = "declare-subscriber"`.
    /// The `UnknownMapping(id)` validation always fires (callers
    /// still see the declare-before-publish invariant); only the
    /// actual registry consult is skipped when the feature is off,
    /// yielding `Ok(MatchingStatus { matching: false })` on the
    /// success path.
    pub fn get_matching_status(&self) -> Result<MatchingStatus, PublishAliasError> {
        let base = self
            .session
            .actions()
            .resolve_outbound_mapping(self.mapping_id)
            .ok_or(PublishAliasError::UnknownMapping(self.mapping_id))?;
        let _effective_keyexpr = match self.inline_suffix.as_deref() {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        #[cfg(feature = "declare-subscriber")]
        let matching = {
            let observer = self.session.observer();
            let obs = match observer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            obs.remote_subscribers.has_matching(&_effective_keyexpr)
        };
        #[cfg(not(feature = "declare-subscriber"))]
        let matching = false;
        Ok(MatchingStatus { matching })
    }
}

/// R245 — options bundle for [`Session::declare_subscriber`].
/// Mirrors zenoh-pico's `z_subscriber_options_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`) which
/// today carries only `allowed_origin`. `#[non_exhaustive]` so
/// future rounds add fields (e.g. `complete` for queryable-side
/// fast-path, or a callback-drop-sync handle) without an API break.
///
/// Construct via [`Self::default`] / [`Self::new`] plus optional
/// [`Self::with_allowed_origin`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SubscribeOptions {
    /// Subscriber-side locality predicate. `Any` (default) fires on
    /// every matching Sample regardless of origin; `Remote` fires
    /// only on wire-arrived Samples; `SessionLocal` fires only on
    /// loopback Samples (R227+
    /// [`crate::pubsub::SubscriberRegistry::local_publish`]).
    pub allowed_origin: Locality,
}

impl SubscribeOptions {
    /// Default options — `allowed_origin = Locality::Any`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the subscriber-side locality predicate.
    pub fn with_allowed_origin(mut self, locality: Locality) -> Self {
        self.allowed_origin = locality;
        self
    }
}

/// R245 — handle for a subscription declared through
/// [`Session::declare_subscriber`] / [`Session::declare_subscriber_aliased`].
/// Holds the [`SubscriptionId`] returned by the underlying
/// [`crate::pubsub::SubscriberRegistry::register_with_locality`]
/// call so [`Drop`] can auto-unregister.
///
/// ## Lifetime
///
/// The subscription stays active as long as this handle is alive.
/// Dropping the handle auto-unregisters (RAII); calling
/// [`Self::undeclare`] explicitly is the early-unregister
/// alternative (consumes the handle so the `Drop` does not run
/// a second time).
///
/// `!Clone` by construction — the underlying `SubscriptionId` is a
/// unique handle; cloning would let two drops race to unregister
/// the same id, and the second would silently no-op. Callers
/// wanting "multiple subscriptions on the same keyexpr" should
/// call [`Session::declare_subscriber`] multiple times instead
/// (the registry supports duplicate-keyexpr subscribers and fires
/// each callback in registration order).
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_subscriber`] / [`Session::declare_subscriber_aliased`].
#[non_exhaustive]
pub struct Subscriber {
    session: Session,
    id: SubscriptionId,
    keyexpr: String,
    options: SubscribeOptions,
}

impl Subscriber {
    /// The stable id assigned by
    /// [`crate::pubsub::SubscriberRegistry::register_with_locality`].
    /// Exposed for diagnostics; callers should not rely on the
    /// exact value across runs.
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// The keyexpr the subscription was registered against. For
    /// [`Session::declare_subscriber_aliased`] this is the resolved
    /// literal form (the alias was resolved at declare time and
    /// stored).
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &SubscribeOptions {
        &self.options
    }

    /// Explicitly unregister this subscription. Consumes the
    /// handle so the [`Drop`] impl will not run a second time
    /// against an already-removed id. Returns `true` if the
    /// registry had the id and removed it; `false` if a concurrent
    /// caller already removed it (currently no public API exposes
    /// raw `unregister(id)` outside this handle, so the false case
    /// is reachable only via a future round adding such a surface).
    pub fn undeclare(self) -> bool {
        let removed = self
            .session
            .observer
            .lock()
            .expect("Session observer mutex poisoned — a subscriber callback panicked")
            .subscribers
            .unregister(self.id);
        // Skip the Drop impl so it does not no-op-unregister an
        // already-removed id (cosmetic — second unregister is a
        // boolean false, not a panic, but std::mem::forget makes
        // the intent explicit at the call site).
        std::mem::forget(self);
        removed
    }
}

impl Drop for Subscriber {
    fn drop(&mut self) {
        // RAII unregister. A poisoned observer mutex (a subscriber
        // callback panicked) is recovered with `into_inner` —
        // panicking again from Drop would abort the whole process
        // with a double-panic, which is strictly worse than
        // running unregister against possibly-inconsistent state.
        // The `unregister` call itself is panic-free (boolean
        // return), so the worst-case observable outcome is "id
        // stays registered" — caller can manually
        // re-poison-recover and re-call `undeclare` if it matters.
        match self.session.observer.lock() {
            Ok(mut obs) => {
                let _ = obs.subscribers.unregister(self.id);
            }
            Err(poisoned) => {
                let mut obs = poisoned.into_inner();
                let _ = obs.subscribers.unregister(self.id);
            }
        }
    }
}

/// R245 — typed error returned by
/// [`Session::declare_subscriber_aliased`] when the requested
/// mapping id was never declared on the outbound mapping table
/// (or was retracted before declare time). Mirror of
/// [`PublishAliasError`] / [`QueryAliasError`] on the sub side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_subscriber_aliased call).
    UnknownMapping(u64),
}

impl std::fmt::Display for SubscribeAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscribeAliasError::UnknownMapping(id) => write!(
                f,
                "SubscribeAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
        }
    }
}

impl std::error::Error for SubscribeAliasError {}

/// R246 — options bundle for [`Session::declare_queryable`].
/// Mirrors zenoh-pico's `z_queryable_options_t` minus the
/// `complete` flag (which lands as a follow-up when the
/// queryable-side completeness signal is wired). `#[non_exhaustive]`.
///
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Struct + builder always defined regardless of the
/// `query-queryable` feature so caller-side option construction
/// compiles unconditionally.
///
/// R311r closure — the prior carry ("deferred to a future round when
/// the observer.queryables field + `crate::query` module become
/// unconditional") is now closed: the [`Queryable`] handle, the
/// [`Session::declare_queryable{_aliased}`] surface (Result form with
/// `FeatureDisabled` variant), the `observer.queryables` field, and
/// the `crate::query` module are all type-ungated. The only remaining
/// feature gates are the BODY of the two declare entry points, the
/// dispatch fan-out in `ApplicationLayerObserver`, and the wire-emit
/// drain in `flush_pending` (where `QueryReply::into_response` lives).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct QueryableOptions {
    /// Queryable-side locality predicate. `Any` (default) fires on
    /// every matching Query regardless of origin; `Remote` fires
    /// only on wire-arrived Queries; `SessionLocal` fires only on
    /// loopback Queries (R238+
    /// [`crate::query::QueryableRegistry::local_query`]).
    pub allowed_origin: Locality,
}

impl QueryableOptions {
    /// Default options — `allowed_origin = Locality::Any`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the queryable-side locality predicate.
    pub fn with_allowed_origin(mut self, locality: Locality) -> Self {
        self.allowed_origin = locality;
        self
    }
}

/// R246 — handle for a queryable declared through
/// [`Session::declare_queryable`] / [`Session::declare_queryable_aliased`].
/// Responder-side mirror of [`Subscriber`]. Holds the
/// [`QueryableId`] returned by
/// [`crate::query::QueryableRegistry::register_with_locality`]
/// so [`Drop`] can auto-unregister.
///
/// `!Clone` by construction for the same reason as [`Subscriber`]:
/// the underlying id is a unique handle; cloning would race two
/// drops to unregister the same id.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_queryable`] / [`Session::declare_queryable_aliased`].
///
/// R311r — type-ungated. The struct, impl, and Drop are always defined
/// so the [`Session::declare_queryable{_aliased}`] Result-form signature
/// compiles regardless of feature state; a feature-OFF call returns
/// `Err(QueryableAliasError::FeatureDisabled)` without ever
/// constructing this handle. Drop calls `observer.queryables.unregister`
/// — unconditionally available after R311r observer field ungate.
#[non_exhaustive]
pub struct Queryable {
    session: Session,
    id: QueryableId,
    keyexpr: String,
    options: QueryableOptions,
}

impl Queryable {
    /// The stable id assigned by
    /// [`crate::query::QueryableRegistry::register_with_locality`].
    pub fn id(&self) -> QueryableId {
        self.id
    }

    /// The keyexpr the queryable was registered against. For
    /// [`Session::declare_queryable_aliased`] this is the resolved
    /// literal form.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &QueryableOptions {
        &self.options
    }

    /// Explicitly unregister this queryable. Consumes the handle so
    /// the [`Drop`] impl will not run a second time. Mirrors
    /// [`Subscriber::undeclare`].
    pub fn undeclare(self) -> bool {
        let removed = self
            .session
            .observer
            .lock()
            .expect("Session observer mutex poisoned — a queryable callback panicked")
            .queryables
            .unregister(self.id);
        std::mem::forget(self);
        removed
    }
}

impl Drop for Queryable {
    fn drop(&mut self) {
        // RAII unregister with poison-recover, mirroring Subscriber.
        // unregister is panic-free (boolean return), so the
        // worst-case observable outcome on a corrupted observer is
        // "queryable stays registered" — caller can manually
        // poison-recover and re-undeclare if it matters.
        match self.session.observer.lock() {
            Ok(mut obs) => {
                let _ = obs.queryables.unregister(self.id);
            }
            Err(poisoned) => {
                let mut obs = poisoned.into_inner();
                let _ = obs.queryables.unregister(self.id);
            }
        }
    }
}

/// R246 — typed error returned by
/// [`Session::declare_queryable_aliased`] when the requested
/// mapping id was never declared on the outbound mapping table
/// (or was retracted before declare time). Mirror of
/// [`SubscribeAliasError`] / [`PublishAliasError`] /
/// [`QueryAliasError`] on the queryable side.
///
/// R311r — type-ungated + [`Self::FeatureDisabled`] variant added.
/// The enum is always defined so the
/// [`Session::declare_queryable{_aliased}`] Result-form signature
/// compiles regardless of feature state; a feature-OFF call returns
/// `Err(FeatureDisabled)` so caller code can branch on it uniformly.
/// Mirrors the `FeatureDisabled` variant pattern already established
/// on the LivelinessSubscriberAliasError family at R311q.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryableAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_queryable_aliased call).
    UnknownMapping(u64),
    /// R311r — the `query-queryable` feature is OFF at compile time.
    /// Returned by both [`Session::declare_queryable`] and
    /// [`Session::declare_queryable_aliased`] when the build elides
    /// the queryable wire-emit + dispatch path. Caller must
    /// feature-detect at the consumer-crate level before relying on
    /// queryable callbacks; no callback would ever fire even if a
    /// stub handle were constructed because the registry-side
    /// dispatch is gated on the same feature.
    FeatureDisabled,
}

impl std::fmt::Display for QueryableAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryableAliasError::UnknownMapping(id) => write!(
                f,
                "QueryableAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            QueryableAliasError::FeatureDisabled => write!(
                f,
                "QueryableAliasError: query-queryable feature is OFF at compile time; \
                 the queryable dispatch + reply emit paths are elided, so no \
                 callback can be installed on this build"
            ),
        }
    }
}

impl std::error::Error for QueryableAliasError {}

/// R248 — options bundle for [`Session::declare_token`] /
/// [`Session::declare_token_aliased`]. Mirrors zenoh-pico's
/// `z_liveliness_token_options_t` which carries only a single
/// `uint8_t __dummy` placeholder field today
/// (`vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h:44-46`)
/// — the struct exists in the C ABI as a forward-compatible
/// placeholder for future per-token options that the upstream Zenoh
/// protocol has not yet defined.
///
/// Empty `#[non_exhaustive]` so a future round can add per-token
/// fields (e.g. completeness flag, expiry hint, attachment) without
/// breaking external callers. Construct via [`Self::default`] /
/// [`Self::new`].
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Always defined regardless of the `liveliness-token`
/// feature so consumer-side declare_token call-sites can compile
/// unconditionally; the wire-emit path is gated inside
/// [`Session::declare_token`] which returns
/// `Err(LivelinessAliasError::FeatureDisabled)` when off.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LivelinessOptions {}

impl LivelinessOptions {
    /// Default options — currently empty, mirroring zenoh-pico's
    /// `z_liveliness_token_options_default` which zeroes out the
    /// `__dummy` slot.
    pub fn new() -> Self {
        Self::default()
    }
}

/// R248 — handle for a liveliness token declared through
/// [`Session::declare_token`] / [`Session::declare_token_aliased`].
/// Holds the `token_id` allocated by
/// [`SessionLinkActions::alloc_next_token_id`] so `Drop` can emit
/// the matching `Declare(UndeclToken)` retraction on the outbound
/// link.
///
/// ## Lifetime + wire emit on Drop
///
/// The token stays declared on the peer for as long as this handle
/// is alive on the local session. `Drop` emits
/// `Declare(UndeclToken)` so the peer's liveliness subscribers
/// receive the DELETE sample at retraction time — that is the
/// whole purpose of the liveliness signal. This differs from
/// [`Subscriber`] / [`Queryable`] `Drop` which only unregister
/// from the local registry (no wire emit), because zenoh-pico's
/// router-mode subscriber/queryable declarations are out of scope
/// for wz while the liveliness path is end-to-end peer-driven.
///
/// `!Clone` by construction — the underlying `token_id` is a
/// unique handle; cloning would let two drops race to emit
/// `UndeclToken` for the same id, and the peer would treat the
/// second as a no-op against a now-absent entry (zenoh-pico
/// `_z_liveliness_handle_undecl_token` ignores absent ids). Code
/// wanting "the same liveliness keyexpr from two places" should
/// call [`Session::declare_token`] twice and accept two distinct
/// token ids — that matches zenoh-pico semantics, where each
/// `z_liveliness_declare_token` call allocates a fresh entity id.
///
/// ## Panic semantics on Drop
///
/// [`SessionLinkActions::send_undeclare_token`] runs the encode +
/// `driver.send_blocking` chain without taking any wz-level
/// `Mutex::lock` that could be poison-recovered the way
/// [`Subscriber::drop`] handles the observer mutex. The
/// `driver.send_blocking` path is panic-free under normal AP MVP
/// operation, so this `Drop` does not wrap the call in
/// `catch_unwind`. If a future round surfaces a panic from the
/// driver path (e.g. a poisoned internal mutex on a TLS / lwIP
/// driver), wrapping this call defensively is the textbook
/// follow-up — carry note on the audit ledger.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_token`] / [`Session::declare_token_aliased`].
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Struct + impl + Drop always defined; the wire-emit at
/// declare time is gated inside [`Session::declare_token`] (returns
/// `Err(LivelinessAliasError::FeatureDisabled)` when
/// `liveliness-token` is off so no handle ever exists in that build),
/// and the [`Drop`] wire-emit calls into
/// [`crate::session_glue::SessionLinkActions::send_undeclare_token`]
/// which is itself signature-stable (silent no-op when the underlying
/// declare-* gate is off).
#[non_exhaustive]
pub struct LivelinessToken {
    session: Session,
    id: u64,
    keyexpr: String,
    options: LivelinessOptions,
}

impl LivelinessToken {
    /// The stable token id allocated at declare time by
    /// [`SessionLinkActions::alloc_next_token_id`]. Exposed for
    /// diagnostics; callers should not rely on the exact value
    /// across runs since the counter is session-scoped + Relaxed
    /// ordering.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The keyexpr the token was declared against. For
    /// [`Session::declare_token_aliased`] this is the resolved
    /// literal form (the alias was resolved at declare time via
    /// [`SessionLinkActions::resolve_outbound_mapping`] and the
    /// literal stored here for introspection symmetry with R245
    /// [`Subscriber::keyexpr`] / R246 [`Queryable::keyexpr`]). The
    /// wire frame may carry either the literal or the alias form
    /// depending on which constructor was used — see the
    /// [`Session::declare_token_aliased`] doc-comment for the wire
    /// shape detail.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &LivelinessOptions {
        &self.options
    }

    /// Explicitly retract this liveliness token. Emits
    /// `Declare(UndeclToken)` on the outbound link
    /// (`SessionLinkActions::send_undeclare_token`) and consumes
    /// the handle so the [`Drop`] impl will not emit a second
    /// duplicate undeclare against an already-retracted id. Mirrors
    /// [`Subscriber::undeclare`] / [`Queryable::undeclare`].
    ///
    /// `std::mem::forget(self)` keeps the intent explicit — the
    /// peer ignoring a second `UndeclToken` for the same id is the
    /// expected zenoh-pico behaviour but the cosmetic "do not emit
    /// a duplicate" rule matches the textbook RAII consume contract
    /// across the wz handle family.
    pub fn undeclare(self) {
        self.session.actions.send_undeclare_token(self.id);
        std::mem::forget(self);
    }
}

impl Drop for LivelinessToken {
    fn drop(&mut self) {
        // R248 RAII — emit Declare(UndeclToken) so the peer's
        // liveliness subscribers receive the DELETE sample. See
        // the struct-level doc-comment on panic semantics: the
        // wire path is panic-free under normal operation so no
        // catch_unwind wrapping; a poisoned driver path is a
        // future-round carry.
        //
        // R311o — call is unconditional; send_undeclare_token is
        // signature-stable (silent no-op when declare-* off). When
        // `liveliness-token` is off, Session::declare_token returns
        // Err(FeatureDisabled) so no LivelinessToken instance can
        // exist on this build, and this Drop never runs.
        self.session.actions.send_undeclare_token(self.id);
    }
}

/// R248 — typed error returned by [`Session::declare_token`] /
/// [`Session::declare_token_aliased`]. Mirror of
/// [`SubscribeAliasError`] / [`QueryableAliasError`] /
/// [`QueryAliasError`] / [`PublishAliasError`] on the liveliness
/// token side.
///
/// R311o — unified error for both literal and aliased declare paths.
/// Previously `declare_token` returned `Result<_, OutboundKeyexprError>`
/// directly; the aliased form already returned this enum. The
/// non-aliased form now wraps its keyexpr-gate rejection in
/// [`Self::InvalidKeyexpr`] for symmetry with the aliased form and so
/// the [`Self::FeatureDisabled`] variant (R311o type-ungating cascade)
/// covers both call sites uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelinessAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_token_aliased call).
    UnknownMapping(u64),
    /// R300 — the keyexpr (literal for [`Session::declare_token`], or
    /// reconstructed `outbound_mapping[id] || inline_suffix` for
    /// [`Session::declare_token_aliased`]) failed the outbound
    /// pico-safety gate ([`OutboundKeyexprError`]). Either non-canonical
    /// per the zenoh keyexpr grammar OR matching the R299 bug #3 SIGABRT
    /// pattern family (`**` chunk + non-`*` chunk + `*`-shape chunk).
    /// The wire emit was suppressed pre-send.
    InvalidKeyexpr(OutboundKeyexprError),
    /// R311o — the `liveliness-token` feature was disabled at the
    /// `wz-runtime-tokio` crate level so no LivelinessToken instance
    /// can be constructed. Signature-stability per
    /// `feedback_signature_stability` MEMORY anchor: the declare_token
    /// surface stays callable from consumer code (no cfg cascade) but
    /// returns this variant instead of attempting a wire emit on a
    /// build whose declare-token / declare-undeclare runtime path is
    /// absent.
    FeatureDisabled,
}

impl std::fmt::Display for LivelinessAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivelinessAliasError::UnknownMapping(id) => write!(
                f,
                "LivelinessAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            LivelinessAliasError::InvalidKeyexpr(inner) => write!(
                f,
                "LivelinessAliasError: keyexpr failed outbound gate — {inner}"
            ),
            LivelinessAliasError::FeatureDisabled => write!(
                f,
                "LivelinessAliasError: `liveliness-token` feature is disabled \
                 on this wz-runtime-tokio build; rebuild with the feature \
                 enabled (or its preset) to obtain a LivelinessToken handle"
            ),
        }
    }
}

impl std::error::Error for LivelinessAliasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LivelinessAliasError::InvalidKeyexpr(inner) => Some(inner),
            LivelinessAliasError::UnknownMapping(_) | LivelinessAliasError::FeatureDisabled => None,
        }
    }
}

/// R280 — options bundle for
/// [`Session::declare_liveliness_subscriber`]. Mirrors zenoh-pico's
/// `z_liveliness_subscriber_options_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h:88-90`):
/// a single `history` boolean today; `#[non_exhaustive]` so a
/// future round can add fields without breaking external callers.
///
/// `history = true` instructs the peer to immediately replay the
/// matching liveliness-token snapshot through `Decl*Token` records
/// before any future-only signal arrives — sets the `CURRENT` bit
/// (`_Z_INTEREST_FLAG_CURRENT`) on the outbound Interest header per
/// `vendor/zenoh-pico/src/net/liveliness.c:198`. `history = false`
/// (default) only subscribes for future events.
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. The struct + builder are always defined regardless of the
/// `liveliness-subscriber` feature so caller-side option construction
/// compiles unconditionally.
///
/// R311q closure — the prior carry ("deferred to a future round when
/// the observer.liveliness_subscribers field + declare::liveliness_subscriber
/// module become unconditional") is now closed: the
/// [`LivelinessSubscriber`] handle, the
/// [`Session::declare_liveliness_subscriber{_aliased}`] surface
/// (Result form with `FeatureDisabled` variant), the
/// `observer.liveliness_subscribers` field, and the
/// `declare::liveliness_subscriber` module are all type-ungated. The
/// only remaining feature gate is the BODY of the two declare entry
/// points + the dispatch fan-out in `ApplicationLayerObserver`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LivelinessSubscriberOptions {
    /// `true` to request a current-state replay from the peer at
    /// declare time, `false` to subscribe only to future events.
    pub history: bool,
}

impl LivelinessSubscriberOptions {
    /// Default options — `history = false`. Mirrors zenoh-pico's
    /// `z_liveliness_subscriber_options_default`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set the `history` flag explicitly.
    pub fn with_history(mut self, history: bool) -> Self {
        self.history = history;
        self
    }
}

/// R280 — handle for a liveliness subscriber declared through
/// [`Session::declare_liveliness_subscriber`]. Holds the
/// `interest_id` allocated by
/// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`]
/// so `Drop` can emit the matching `Interest(Final)` retraction on
/// the outbound link AND remove the slot from the local
/// [`crate::declare::LivelinessSubscriberRegistry`].
///
/// ## Lifetime + wire emit on Drop
///
/// The subscriber stays declared on the peer for as long as this
/// handle is alive on the local session. `Drop` emits
/// `Interest(Final)` so the peer's
/// `_z_interest_process_interest_final` removes our entry from its
/// remote-interests table — mirror of zenoh-pico's
/// `_z_undeclare_liveliness_subscriber` at
/// `vendor/zenoh-pico/src/net/liveliness.c:232-243`. Local slot
/// removal runs first so any inbound dispatch racing the wire emit
/// does not fire a callback against a slot that is about to
/// disappear from the registry.
///
/// `!Clone` by construction — the underlying `interest_id` is a
/// unique handle; cloning would let two drops race to emit
/// `InterestFinal` for the same id, and the peer would treat the
/// second as a no-op. Code wanting "the same liveliness subscription
/// from two places" should call
/// [`Session::declare_liveliness_subscriber`] twice and accept two
/// distinct interest ids — that matches zenoh-pico semantics.
///
/// ## Panic semantics on Drop
///
/// The wire-emit path (`send_interest_final`) is panic-free under
/// normal AP MVP operation, matching the [`LivelinessToken`]
/// contract. The observer mutex lock could in principle be poisoned
/// by an earlier callback panic; the Drop impl `map`s over the
/// `Result` so a poisoned mutex still produces an idempotent
/// no-op rather than a double panic (same shape as
/// [`crate::pubsub::Subscriber::drop`] guard).
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_liveliness_subscriber`].
///
/// R311q — type-ungated. The struct, impl, and Drop are always defined
/// so the [`Session::declare_liveliness_subscriber{_aliased}`]
/// Result-form signature compiles regardless of feature state; a
/// feature-OFF call returns `Err(LivelinessSubscriberAliasError::FeatureDisabled)`
/// without ever constructing this handle (so the Drop-path wire emit
/// never fires from a stub). The Drop body calls `send_interest_final`
/// alongside `observer.liveliness_subscribers.unregister`, both of
/// which are unconditionally available after the R311g1 signature-
/// stability sweep + the R311q observer field ungate.
#[non_exhaustive]
pub struct LivelinessSubscriber {
    session: Session,
    interest_id: u64,
    keyexpr: String,
    options: LivelinessSubscriberOptions,
}

impl LivelinessSubscriber {
    /// The stable interest id allocated at declare time by
    /// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`].
    /// Exposed for diagnostics; callers should not rely on the exact
    /// value across runs since the counter is session-scoped +
    /// Relaxed ordering.
    pub fn interest_id(&self) -> u64 {
        self.interest_id
    }

    /// The keyexpr pattern the subscriber was declared on. Useful
    /// for debug logging and matching the handle back to its
    /// originating call site.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &LivelinessSubscriberOptions {
        &self.options
    }

    /// `true` when the subscriber requested `history = true` AND the
    /// peer has signaled history-complete by emitting
    /// `Interest(Final)` for our `interest_id`. Returns `false` for a
    /// `history = false` subscriber (no replay was requested → the
    /// flag is meaningless and stays `false`) and for a
    /// history-enabled subscriber that has not yet observed its
    /// matching `InterestFinal`.
    ///
    /// Mirrors zenoh-pico's `_z_interest_process_interest_final`
    /// post-condition (`vendor/zenoh-pico/src/session/interest.c:524`):
    /// `InterestFinal` arrival marks the subscription's historical
    /// replay complete; subsequent `Decl*Token` records arrive as
    /// new (future) events.
    pub fn history_complete(&self) -> bool {
        self.session
            .observer()
            .lock()
            .map(|observer| {
                observer
                    .liveliness_subscribers
                    .history_complete(self.interest_id)
            })
            .unwrap_or(false)
    }

    /// Explicitly retract this liveliness subscriber. Emits
    /// `Interest(Final)` on the outbound link and consumes the
    /// handle so the [`Drop`] impl will not emit a second duplicate
    /// against an already-retracted id. Mirror of
    /// [`LivelinessToken::undeclare`]; same `std::mem::forget(self)`
    /// pattern keeps the intent explicit.
    pub fn undeclare(self) {
        if let Ok(mut observer) = self.session.observer().lock() {
            observer.liveliness_subscribers.unregister(self.interest_id);
        }
        self.session.actions().send_interest_final(self.interest_id);
        std::mem::forget(self);
    }
}

impl Drop for LivelinessSubscriber {
    fn drop(&mut self) {
        // R280 RAII — unregister the local slot first so any racing
        // inbound dispatch sees no slot, then emit Interest(Final) so
        // the peer drops its end of the subscription. Poisoned mutex
        // (an earlier callback panicked) is treated as idempotent
        // no-op — `map` over the lock Result rather than panicking.
        if let Ok(mut observer) = self.session.observer.lock() {
            observer.liveliness_subscribers.unregister(self.interest_id);
        }
        self.session.actions.send_interest_final(self.interest_id);
    }
}

/// R282 / R283 — typed error returned by
/// [`Session::declare_liveliness_subscriber_aliased`]. Two variants
/// cover the two declare-time pre-conditions:
///
/// - [`Self::UnknownMapping`] (R282) — the aliased mapping id is not
///   present in the outbound mapping table; resolution would emit a
///   wire frame the peer cannot decode.
/// - [`Self::NotEstablished`] (R283) — the session-FSM has not yet
///   entered `Established`; an outbound `Interest` emit before
///   handshake completion is silently discarded by the peer
///   (no `remote-interests` table entry yet).
///
/// Variant ordering at the call site is: `UnknownMapping` checked
/// first (mapping resolution is FSM-state-independent and cheaper),
/// then `NotEstablished`. So a pre-Established call with an unknown
/// mapping returns `UnknownMapping`, not `NotEstablished` — the
/// caller fixes the bug-class error before retrying the
/// session-state-dependent retry loop.
///
/// Mirror of [`SubscribeAliasError`] / [`QueryableAliasError`] /
/// [`QueryAliasError`] / [`PublishAliasError`] /
/// [`LivelinessAliasError`] on the liveliness subscriber side, plus
/// the R283 `NotEstablished` extension. The sibling errors do not yet
/// carry the `NotEstablished` variant — uniform extension to the rest
/// of the declare_* surface is a future-round carry (see
/// [`Session::declare_liveliness_subscriber`] doc-comment on the
/// asymmetric gate).
///
/// R311q — type-ungated + [`Self::FeatureDisabled`] variant added.
/// The enum is always defined so the
/// [`Session::declare_liveliness_subscriber{_aliased}`] Result-form
/// signature compiles regardless of feature state; a feature-OFF call
/// returns `Err(FeatureDisabled)` so caller code can branch on it
/// uniformly. Mirrors the `FeatureDisabled` variant pattern already
/// established on other declare_* AliasError families during the
/// R311 signature-stability sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelinessSubscriberAliasError {
    /// R282 — no prior `send_declare_keyexpr` registered this id on
    /// the outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_liveliness_subscriber_aliased
    /// call).
    UnknownMapping(u64),
    /// R283 — the session-FSM has not yet entered `Established`. The
    /// outbound `Interest` frame would be emitted into a session that
    /// is mid-handshake (InitSyn / InitAck / OpenSyn / OpenAck) and
    /// the peer would discard it (no `remote-interests` table entry
    /// yet). Caller should wait for
    /// [`crate::Session::is_established`] (or the equivalent
    /// session-level signal in higher-tier wrappers) to flip to
    /// `true` before retrying the declare. Mirrors zenoh-pico's
    /// implicit "declare AFTER z_open returns Z_OK" sequencing
    /// contract.
    NotEstablished,
    /// R311q — the `liveliness-subscriber` feature is OFF at compile
    /// time. Returned by both
    /// [`Session::declare_liveliness_subscriber`] and
    /// [`Session::declare_liveliness_subscriber_aliased`] when the
    /// build elides the wire-emit + observer-dispatch path. Caller
    /// must feature-detect at the consumer-crate level (e.g. via a
    /// `#[cfg]` branch on the same feature) before relying on a
    /// liveliness subscription; the registry-side dispatch is also
    /// disabled so no callback would ever fire even if a stub handle
    /// were constructed.
    FeatureDisabled,
}

impl std::fmt::Display for LivelinessSubscriberAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivelinessSubscriberAliasError::UnknownMapping(id) => write!(
                f,
                "LivelinessSubscriberAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            LivelinessSubscriberAliasError::NotEstablished => write!(
                f,
                "LivelinessSubscriberAliasError: session-FSM not yet Established; \
                 wait for Session::is_established() to flip to true (or for the \
                 session-layer Established signal) before retrying the declare"
            ),
            LivelinessSubscriberAliasError::FeatureDisabled => write!(
                f,
                "LivelinessSubscriberAliasError: liveliness-subscriber feature is OFF at \
                 compile time; the wire-emit and observer-dispatch paths are elided, \
                 so no subscription can be established on this build"
            ),
        }
    }
}

impl std::error::Error for LivelinessSubscriberAliasError {}

/// R234 — typed error returned by
/// [`Session::publish_aliased_auto`] when the requested mapping id
/// was never declared on this session's outbound link (or was
/// retracted via [`SessionLinkActions::send_undeclare_kexpr`]). The
/// caller's contract is "declare before publish"; this enum names
/// the violation explicitly so a buggy caller does not silently
/// emit wire frames the peer will reject + run loopback on a
/// guessed literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it). The wrapped value is the offending mapping id.
    UnknownMapping(u64),
}

impl std::fmt::Display for PublishAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishAliasError::UnknownMapping(id) => write!(
                f,
                "PublishAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
        }
    }
}

impl std::error::Error for PublishAliasError {}

/// R232 — shared loopback Sample assembly for [`Session::publish`] and
/// [`Session::publish_aliased`]. Constructs a Put or Del Sample on the
/// supplied keyexpr + payload, threads every metadata field the caller
/// attached to [`PublishOptions`] via `with_*` setters, and leaves the
/// Del-encoding slot empty (zenoh-pico `_z_msg_del_t` carries no
/// encoding so the loopback parity mirrors that wire constraint).
///
/// Keeps the metadata-threading rules in one place so a future R232
/// follow-up that adjusts the propagation policy (e.g. validating QoS
/// bits or trimming an over-long attachment) only edits this function.
fn build_loopback_sample(keyexpr: &str, payload: &[u8], opts: &PublishOptions) -> Sample {
    let mut sample = match opts.kind {
        SampleKind::Put => Sample::new_put(keyexpr, payload.to_vec()),
        SampleKind::Del => Sample::new_del(keyexpr),
    };
    sample = sample.with_reliability(opts.reliability);
    if let Some(ts) = opts.timestamp.clone() {
        sample = sample.with_timestamp(ts);
    }
    // Encoding is Put-only on the wire; mirror the constraint on
    // loopback so a caller mis-attaching encoding to a Del kind sees
    // the same "encoding=None" the wire path would project.
    if opts.kind == SampleKind::Put {
        if let Some(enc) = opts.encoding.clone() {
            sample = sample.with_encoding(enc);
        }
    }
    if let Some(si) = opts.source_info.clone() {
        sample = sample.with_source_info(si);
    }
    if let Some(att) = opts.attachment.clone() {
        sample = sample.with_attachment(att);
    }
    if let Some(qos) = opts.qos {
        sample = sample.with_qos(qos);
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::ApplicationLayerObserver;
    use crate::reply::InboundReplyBody;
    use crate::runtime_impl::TokioTime;
    use crate::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wz_runtime_core::TimeSource;

    /// R283 test helper — force the session-FSM `Established` stamp
    /// without driving the full handshake. The production path
    /// populates `established_at` via the `record_established_at` Lua
    /// action wired to `Established.onentry` in
    /// `session_fsm_unicast.scxml`; pure-Rust unit tests skip the
    /// SCXML driver and stamp the field directly. Mirror of any
    /// other test fixture that needs to bypass FSM driving (e.g. the
    /// keyexpr mapping is populated via `send_declare_keyexpr` rather
    /// than driving the peer's `DeclKexpr` inbound).
    fn mark_session_established(session: &Session) {
        *session
            .actions()
            .established_at
            .lock()
            .expect("established_at poisoned in test fixture") =
            Some(session.actions().clock.now_monotonic_ms());
    }

    /// Captures every outbound wire send so tests can assert wire
    /// branch fires only when `allows_remote()` holds. Mirrors the
    /// `RecordingDriver` shape already used by session_glue tests.
    struct RecordingDriver {
        frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
    }

    impl RecordingDriver {
        fn new() -> Self {
            Self {
                frames: Mutex::new(Vec::new()),
            }
        }

        fn frame_count(&self) -> usize {
            self.frames.lock().unwrap().len()
        }

        fn frame_reliability(&self, idx: usize) -> Reliability {
            self.frames.lock().unwrap()[idx].1
        }
    }

    impl BoxedLinkDriver for RecordingDriver {
        fn send_blocking(&self, bytes: &[u8], r: Reliability) {
            self.frames.lock().unwrap().push((bytes.to_vec(), r));
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    fn fixture_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 1,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        }
    }

    /// Convenience constructor that returns a (Session,
    /// driver_handle) pair so tests can assert against both the
    /// outbound wire branch (via the driver) and the loopback branch
    /// (via the observer borrowed off the session).
    fn build_session() -> (Session, Arc<RecordingDriver>) {
        let driver = Arc::new(RecordingDriver::new());
        let actions = SessionLinkActions::new(driver.clone(), fixture_params(), TokioTime::new());
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        (Session::new(actions, observer), driver)
    }

    #[test]
    fn publish_options_default_is_put_any_reliable() {
        let opts = PublishOptions::default();
        assert_eq!(opts.kind, SampleKind::Put);
        assert_eq!(opts.allowed_destination, Locality::Any);
        assert_eq!(opts.reliability, Reliability::Reliable);
    }

    #[test]
    fn publish_options_put_and_del_constructors() {
        let put = PublishOptions::put();
        assert_eq!(put.kind, SampleKind::Put);
        let del = PublishOptions::del();
        assert_eq!(del.kind, SampleKind::Del);
    }

    #[test]
    fn publish_options_with_setters_chain() {
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort)
            .with_kind(SampleKind::Del);
        assert_eq!(opts.allowed_destination, Locality::SessionLocal);
        assert_eq!(opts.reliability, Reliability::BestEffort);
        assert_eq!(opts.kind, SampleKind::Del);
    }

    #[test]
    fn publish_locality_any_fires_wire_and_loopback() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let fired = session.publish("home/temp", b"22.5", PublishOptions::put());
        assert_eq!(fired, 1, "Locality::Any fires loopback subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "Locality::Any also fires wire branch (one frame on the driver)"
        );
    }

    #[test]
    fn publish_locality_remote_fires_wire_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback branch entirely"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch still fires under allows_remote()"
        );
    }

    #[test]
    fn publish_locality_session_local_fires_loopback_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1, "loopback branch fires the Any-default subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            0,
            "wire branch is suppressed under Locality::SessionLocal"
        );
    }

    #[test]
    fn publish_loopback_sample_carries_options_reliability_and_kind() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<Sample>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.clone());
            });

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1);
        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "home/temp");
        assert_eq!(observed.kind, SampleKind::Put);
        assert_eq!(observed.payload, b"22.5");
        assert_eq!(
            observed.reliability,
            Reliability::BestEffort,
            "PublishOptions.reliability propagates into Sample.reliability"
        );
    }

    #[test]
    fn publish_del_kind_routes_to_del_loopback_with_empty_payload() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>)>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some((sample.kind, sample.payload.clone()));
            });

        let opts = PublishOptions::del().with_locality(Locality::SessionLocal);
        // Payload argument is ignored for Del kind — the Sample observed
        // by the subscriber carries an empty payload regardless.
        let fired = session.publish("home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload) = captured.lock().unwrap().clone().expect("fired");
        assert_eq!(kind, SampleKind::Del);
        assert!(payload.is_empty(), "Del Sample carries no payload");
    }

    #[test]
    fn publish_reliability_propagates_to_wire_frame_flag() {
        let (session, driver) = build_session();
        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::BestEffort);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 1);
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::BestEffort,
            "PublishOptions.reliability sets the wire-frame reliability hint"
        );

        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::Reliable);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 2);
        assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
    }

    #[test]
    fn publish_with_no_subscribers_returns_zero_on_loopback() {
        let (session, _driver) = build_session();
        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "empty registry yields zero fired subscribers without panic"
        );
    }

    #[test]
    fn publish_locality_remote_only_returns_zero_even_with_matching_subscriber() {
        let (session, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote never enters the loopback branch, so fired count is always 0"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publish_returns_multi_subscriber_fired_count() {
        let (session, _driver) = build_session();
        let hits_a = Arc::new(AtomicUsize::new(0));
        let hits_b = Arc::new(AtomicUsize::new(0));
        {
            let clone = hits_a.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/temp", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = hits_b.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/*", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 2, "both matching subscribers fire on loopback");
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_locality_session_local_skips_remote_subscribers() {
        // Mixed locality on the same keyexpr — Session::publish with
        // SessionLocal routes only to loopback (no wire), and only
        // SessionLocal + Any subscribers fire on that branch. The
        // Remote subscriber is silent because its allows_local() is
        // false.
        let (session, driver) = build_session();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let clone = any_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Any, move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Remote, move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 2,
            "Session::publish(SessionLocal) fires Any + SessionLocal, suppresses Remote"
        );
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            0,
            "Locality::SessionLocal suppresses the wire branch"
        );
    }

    // ── R229 publish_aliased (mapping-id keyexpr) ──

    #[test]
    fn publish_aliased_locality_any_fires_wire_and_loopback() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        // Caller has previously (in prod) called send_declare_keyexpr(7,
        // "home/temp"); the loopback_keyexpr argument restates that
        // resolved form so loopback fires on "home/temp" even though
        // the wire side carries only mapping_id = 7.
        let fired = session.publish_aliased(7, None, "home/temp", b"22.5", PublishOptions::put());
        assert_eq!(fired, 1, "loopback fires on resolved literal");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch emits one aliased Push frame"
        );
    }

    #[test]
    fn publish_aliased_locality_remote_fires_wire_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish_aliased(7, None, "home/temp", b"22.5", opts);
        assert_eq!(fired, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 1);
    }

    #[test]
    fn publish_aliased_locality_session_local_fires_loopback_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish_aliased(7, None, "home/temp", b"22.5", opts);
        assert_eq!(fired, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal suppresses the wire-aliased branch"
        );
    }

    #[test]
    fn publish_aliased_del_kind_routes_to_del_aliased_with_empty_payload() {
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>, String)>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() =
                    Some((sample.kind, sample.payload.clone(), sample.keyexpr.clone()));
            });

        let opts = PublishOptions::del();
        let fired = session.publish_aliased(7, None, "home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload, keyexpr) = captured.lock().unwrap().clone().expect("fired");
        assert_eq!(kind, SampleKind::Del);
        assert!(payload.is_empty(), "Del Sample carries no payload");
        assert_eq!(keyexpr, "home/temp", "loopback uses resolved literal");
        assert_eq!(driver.frame_count(), 1, "send_push_del_aliased fired once");
    }

    #[test]
    fn publish_aliased_reliability_propagates_to_wire_and_sample() {
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.reliability);
            });

        let opts = PublishOptions::put().with_reliability(Reliability::BestEffort);
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 1);
        assert_eq!(
            *captured.lock().unwrap(),
            Some(Reliability::BestEffort),
            "Sample.reliability mirrors opts.reliability"
        );
        assert_eq!(driver.frame_count(), 1);
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::BestEffort,
            "wire-frame reliability mirrors opts.reliability"
        );
    }

    #[test]
    fn publish_aliased_inline_suffix_passes_through_to_wire() {
        // The wire builder appends the inline suffix to the
        // mapping-id-prefixed Push; the loopback branch uses
        // `loopback_keyexpr` verbatim and does not auto-concatenate.
        // This test pins the contract: caller is responsible for the
        // loopback literal even when an inline suffix is present.
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<String>));
        let captured_clone = captured.clone();
        session.observer().lock().unwrap().subscribers.register(
            "home/temp/kitchen",
            move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.keyexpr.clone());
            },
        );

        let fired = session.publish_aliased(
            7,
            Some("/kitchen"),
            "home/temp/kitchen",
            b"x",
            PublishOptions::put(),
        );
        assert_eq!(fired, 1);
        assert_eq!(
            *captured.lock().unwrap(),
            Some(String::from("home/temp/kitchen")),
            "loopback keyexpr is the caller-resolved literal"
        );
        assert_eq!(driver.frame_count(), 1, "wire send fires once");
    }

    #[test]
    fn publish_aliased_returns_zero_with_no_loopback_subscriber() {
        let (session, driver) = build_session();
        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 0, "empty registry yields zero fired callbacks");
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal locality still suppresses wire branch"
        );
    }

    #[test]
    fn publish_aliased_loopback_independent_of_wire_keyexpr_form() {
        // Pathological-but-instructive contract assertion: the
        // loopback_keyexpr argument is structurally independent of the
        // (mapping_id, inline_suffix) wire-side pair. Production
        // callers will pass the matching resolved form, but the
        // mechanism does not enforce equivalence — that responsibility
        // sits with the caller per the documented precondition.
        let (session, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session.observer().lock().unwrap().subscribers.register(
            "intentionally_decoupled",
            move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

        let fired = session.publish_aliased(
            42,
            Some("/whatever"),
            "intentionally_decoupled",
            b"x",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(
            fired, 1,
            "loopback fires on the caller-asserted literal regardless of the wire pair"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_aliased_mixed_locality_isolation_matches_publish_literal() {
        // Symmetric to publish_locality_session_local_skips_remote_subscribers:
        // mixed Any + SessionLocal + Remote subscribers on the loopback
        // literal, publish_aliased with SessionLocal fires Any +
        // SessionLocal, suppresses Remote, no wire frame.
        let (session, driver) = build_session();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let clone = any_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Any, move |_s| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::SessionLocal, move |_s| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Remote, move |_s| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 2);
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 0);
    }

    // ── R231 own_zid forwarding ──

    #[test]
    fn set_own_zid_forwards_to_subscriber_registry() {
        // Session::set_own_zid is a thin forwarder onto
        // observer.subscribers.set_own_zid. This pins the wiring so a
        // future refactor that splits the observer mutex or renames
        // the subscriber field surfaces here as a compile / runtime
        // error rather than silently disabling the dedup.
        //
        // R236 — `Session::new` now auto-wires own_zid from
        // `actions.params.zid`, so a fresh `build_session()` already
        // carries the fixture zid. Clear it before exercising the
        // forwarder so this test targets `set_own_zid`'s explicit
        // path rather than measuring the constructor's auto-install.
        let (session, _driver) = build_session();
        session.clear_own_zid();
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "post-clear session has no own_zid installed"
        );

        let zid = vec![0x01, 0x02, 0x03, 0x04];
        assert!(session.set_own_zid(zid.clone()));
        assert_eq!(
            session.observer().lock().unwrap().subscribers.own_zid(),
            Some(&zid[..])
        );
    }

    #[test]
    fn set_own_zid_rejects_invalid_length_without_mutating_registry() {
        // Length-0 and length-17 inputs must be rejected (return
        // false) AND must not mutate the registry's slot. Silent
        // accept of length 0 would store an empty own_zid that
        // could match an empty source_info.zid_prefix() — breaking
        // the cautious-default contract from the registry layer.
        let (session, _driver) = build_session();
        let initial = vec![0x42];
        assert!(session.set_own_zid(initial.clone()));

        assert!(!session.set_own_zid(vec![]));
        assert_eq!(
            session.observer().lock().unwrap().subscribers.own_zid(),
            Some(&initial[..]),
            "rejected length-0 install must not mutate previously-installed zid"
        );

        assert!(!session.set_own_zid(vec![0u8; 17]));
        assert_eq!(
            session.observer().lock().unwrap().subscribers.own_zid(),
            Some(&initial[..]),
            "rejected length-17 install must not mutate previously-installed zid"
        );
    }

    #[test]
    fn clear_own_zid_forwards_to_subscriber_registry() {
        let (session, _driver) = build_session();
        assert!(session.set_own_zid(vec![0x09, 0x08, 0x07, 0x06]));
        assert!(session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .own_zid()
            .is_some());

        session.clear_own_zid();
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "Session::clear_own_zid must forward the release down to the registry"
        );
    }

    // ── R236 Session::new auto-wire from SessionInitParams.zid ──

    #[test]
    fn session_new_auto_wires_set_own_zid_from_params() {
        // R236 — Session::new forwards `actions.params.zid` into the
        // subscriber registry's own_zid slot at construction time so
        // the application is shielded by the R231 self-echo dedup
        // guard without an explicit hook against the FSM
        // open-handshake completion event. Mirrors zenoh-pico's
        // `_z_session_init` which stamps `_local_zid` at session
        // creation (vendor/zenoh-pico/src/session/session.c).
        let (session, _driver) = build_session();
        let fixture_zid: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(
            session.observer().lock().unwrap().subscribers.own_zid(),
            Some(&fixture_zid[..]),
            "Session::new auto-wires own_zid from SessionInitParams.zid"
        );
    }

    #[test]
    fn session_new_with_empty_zid_skips_auto_wire() {
        // R236 — empty zid in SessionInitParams (test fixtures or a
        // pre-handshake placeholder) results in no auto-install. The
        // registry stays in its pre-R231 default state, dedup is
        // disabled, and every wire-arrived Push fires its matching
        // subscribers (the safe default that preserves
        // backwards-compatible behavior for callers who never opt
        // into dedup).
        let driver = Arc::new(RecordingDriver::new());
        let mut params = fixture_params();
        params.zid = Vec::new();
        let actions = SessionLinkActions::new(driver.clone(), params, TokioTime::new());
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let session = Session::new(actions, observer);
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "Session::new with empty params.zid leaves own_zid uninstalled"
        );
    }

    #[test]
    fn session_new_with_overlength_zid_silently_skips_auto_wire() {
        // R236 — params.zid.len() > 16 violates the wire-form
        // `_z_id_t` range (transport.h: zid_len ∈ 1..=16).
        // `set_own_zid`'s internal range check rejects the install
        // (returns false) and the constructor swallows the
        // rejection — no panic, no log noise at construction
        // boundary. The registry stays uninstalled; the application
        // can still call `set_own_zid` later with a valid zid to
        // opt into dedup.
        let driver = Arc::new(RecordingDriver::new());
        let mut params = fixture_params();
        params.zid = vec![0u8; 17];
        let actions = SessionLinkActions::new(driver.clone(), params, TokioTime::new());
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let session = Session::new(actions, observer);
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "Session::new with len-17 params.zid silently skips auto-wire"
        );
    }

    // ── R232 PublishOptions metadata propagation ──

    /// Capture every sample fired through the loopback path so the
    /// metadata-propagation tests can assert against the projected
    /// Sample without racing the subscriber callback.
    fn record_loopback_samples(session: &Session, pattern: &str) -> Arc<Mutex<Vec<Sample>>> {
        let captured = Arc::new(Mutex::new(Vec::<Sample>::new()));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register(pattern, move |s| {
                captured_clone.lock().unwrap().push(s.clone());
            });
        captured
    }

    #[test]
    fn publish_options_with_metadata_setters_chain() {
        // Builder ergonomics: every R232 with_* setter is chainable
        // and pins exactly the field it names, leaving the other
        // four metadata slots untouched.
        let opts = PublishOptions::put()
            .with_timestamp(TimestampHint {
                time: 0x1122_3344_5566_7788,
                zid: vec![0xAA, 0xBB],
            })
            .with_encoding(EncodingHint {
                packed_id: 13,
                schema: Some("application/json".into()),
            })
            .with_source_info(SourceInfo::new(&[0x01, 0x02, 0x03, 0x04], 7, 42))
            .with_attachment(b"meta".to_vec())
            .with_qos(QosLevel::from_raw(0b0001_1010));
        let ts = opts.timestamp.as_ref().unwrap();
        assert_eq!(ts.time, 0x1122_3344_5566_7788);
        assert_eq!(ts.zid, vec![0xAA, 0xBB]);
        let enc = opts.encoding.as_ref().unwrap();
        assert_eq!(enc.packed_id, 13);
        assert_eq!(enc.schema.as_deref(), Some("application/json"));
        let si = opts.source_info.as_ref().unwrap();
        assert_eq!(si.zid_len, 4);
        assert_eq!(si.eid, 7);
        assert_eq!(si.sn, 42);
        assert_eq!(opts.attachment.as_deref(), Some(&b"meta"[..]));
        assert_eq!(opts.qos.unwrap().raw, 0b0001_1010);
    }

    #[test]
    fn publish_loopback_propagates_timestamp_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_timestamp(TimestampHint {
                time: 0xDEAD_BEEF,
                zid: vec![1, 2, 3],
            });
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        let ts = s[0].timestamp.as_ref().unwrap();
        assert_eq!(ts.time, 0xDEAD_BEEF);
        assert_eq!(ts.zid, vec![1, 2, 3]);
    }

    #[test]
    fn publish_loopback_propagates_encoding_to_put_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_encoding(EncodingHint {
                packed_id: 5,
                schema: Some("text/plain".into()),
            });
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        let enc = s[0].encoding.as_ref().unwrap();
        assert_eq!(enc.packed_id, 5);
        assert_eq!(enc.schema.as_deref(), Some("text/plain"));
    }

    #[test]
    fn publish_loopback_omits_encoding_for_del_kind_even_when_opts_supplied() {
        // Mirror zenoh-pico's wire constraint: _z_msg_del_t has no
        // encoding field. The wire-arrival dispatch projects Del with
        // encoding=None unconditionally; the loopback path must
        // match so caller code that mistakenly attaches encoding to
        // a Del publish sees the same projection on either origin.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::del()
            .with_locality(Locality::SessionLocal)
            .with_encoding(EncodingHint {
                packed_id: 5,
                schema: None,
            });
        session.publish("home/temp", b"", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].kind, SampleKind::Del);
        assert!(
            s[0].encoding.is_none(),
            "Del kind must drop encoding on loopback to mirror wire-arrival projection"
        );
    }

    #[test]
    fn publish_loopback_propagates_source_info_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let si = SourceInfo::new(&[0xDE, 0xAD, 0xBE, 0xEF], 7, 42);
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_source_info(si.clone());
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        let got = s[0].source_info.as_ref().unwrap();
        assert_eq!(got.zid_len, 4);
        assert_eq!(got.zid_prefix(), &[0xDE, 0xAD, 0xBE, 0xEF][..]);
        assert_eq!(got.eid, 7);
        assert_eq!(got.sn, 42);
    }

    #[test]
    fn publish_loopback_propagates_attachment_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_attachment(b"attach-payload".to_vec());
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].attachment.as_deref(), Some(&b"attach-payload"[..]));
    }

    #[test]
    fn publish_loopback_propagates_qos_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_qos(QosLevel::from_raw(0b0001_1010));
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].qos.unwrap().raw, 0b0001_1010);
        assert!(
            s[0].qos.unwrap().is_express(),
            "raw bit 4 set must surface through is_express()"
        );
    }

    #[test]
    fn publish_loopback_propagates_all_metadata_in_one_chain() {
        // Composition: every R232 metadata field set together must
        // surface together on the projected Sample, in the same
        // shape the wire-arrival dispatcher produces. Mirrors what a
        // production caller does on a metadata-rich publish.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort)
            .with_timestamp(TimestampHint {
                time: 0x0102_0304,
                zid: vec![0x11],
            })
            .with_encoding(EncodingHint {
                packed_id: 9,
                schema: None,
            })
            .with_source_info(SourceInfo::new(&[0xAA, 0xBB], 1, 2))
            .with_attachment(vec![0xCC, 0xDD])
            .with_qos(QosLevel::from_raw(0x10));
        session.publish("home/temp", b"payload", opts);

        let s = captured.lock().unwrap();
        let got = &s[0];
        assert_eq!(got.keyexpr, "home/temp");
        assert_eq!(got.kind, SampleKind::Put);
        assert_eq!(got.payload, b"payload");
        assert_eq!(got.reliability, Reliability::BestEffort);
        assert_eq!(got.timestamp.as_ref().unwrap().time, 0x0102_0304);
        assert_eq!(got.encoding.as_ref().unwrap().packed_id, 9);
        assert_eq!(got.source_info.as_ref().unwrap().eid, 1);
        assert_eq!(got.attachment.as_deref(), Some(&[0xCC, 0xDD][..]));
        assert_eq!(got.qos.unwrap().raw, 0x10);
    }

    // ── R234 publish_aliased_auto (outbound mapping table) ──

    #[test]
    fn publish_aliased_auto_resolves_loopback_from_outbound_table() {
        let (session, driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        // Declare 7 → "home/temp", then publish_aliased_auto without
        // restating the literal — the table lookup feeds loopback.
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let fired = session
            .publish_aliased_auto(7, None, b"22.5", PublishOptions::put())
            .expect("declared mapping resolves cleanly");
        assert_eq!(fired, 1, "loopback fires on resolved literal");

        let s = captured.lock().unwrap();
        assert_eq!(s[0].keyexpr, "home/temp");
        // Wire branch fired too: declare frame + push frame = 2.
        assert_eq!(
            driver.frame_count(),
            2,
            "declare frame then aliased push frame on the wire"
        );
    }

    #[test]
    fn publish_aliased_auto_composes_inline_suffix_with_table_base() {
        // Composition rule: declared prefix + inline_suffix forms the
        // loopback literal. Mirrors the manual publish_aliased path
        // where the caller would have asserted the composition by
        // hand.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/**");

        session
            .actions()
            .send_declare_keyexpr(7, "home")
            .expect("hardcoded canonical literal keyexpr");
        let fired = session
            .publish_aliased_auto(7, Some("/temp/kitchen"), b"22.5", PublishOptions::put())
            .expect("declared mapping resolves");
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].keyexpr, "home/temp/kitchen");
    }

    #[test]
    fn publish_aliased_auto_returns_unknown_mapping_when_never_declared() {
        // Mapping id 42 was never declared on this session. The
        // typed error path fires; neither wire nor loopback emit.
        let (session, driver) = build_session();
        let captured = record_loopback_samples(&session, "home/**");

        let err = session
            .publish_aliased_auto(42, None, b"x", PublishOptions::put())
            .expect_err("undeclared mapping must error out");
        assert_eq!(err, PublishAliasError::UnknownMapping(42));

        assert!(
            captured.lock().unwrap().is_empty(),
            "loopback must not fire on the error path"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "wire must not emit on the error path"
        );
    }

    #[test]
    fn publish_aliased_auto_returns_unknown_mapping_after_undeclare() {
        // The error path fires whether the id was never declared OR
        // was declared and then retracted. Both share the same
        // "table lookup returned None" failure mode.
        let (session, _driver) = build_session();

        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        // First publish OK.
        session
            .publish_aliased_auto(7, None, b"a", PublishOptions::put())
            .expect("first publish succeeds after declare");

        // Retract the mapping.
        session.actions().send_undeclare_kexpr(7);

        // Second publish fails typed.
        let err = session
            .publish_aliased_auto(7, None, b"b", PublishOptions::put())
            .expect_err("retracted mapping must error out");
        assert_eq!(err, PublishAliasError::UnknownMapping(7));
    }

    #[test]
    fn publish_aliased_auto_error_display_names_the_violating_id() {
        // Display impl must surface the id so a logged error line is
        // diagnosable without reflection.
        let err = PublishAliasError::UnknownMapping(123);
        let s = err.to_string();
        assert!(
            s.contains("123"),
            "error message must contain the mapping id"
        );
        assert!(
            s.contains("send_declare_keyexpr"),
            "error message hints at the remediation API"
        );
    }

    #[test]
    fn publish_aliased_loopback_propagates_metadata_to_sample() {
        // Parity check: publish_aliased's loopback branch shares the
        // same build_loopback_sample helper as publish, so metadata
        // must flow identically. This pins the shared-helper contract
        // — a future refactor that splits the helper or re-implements
        // either path independently surfaces here.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_timestamp(TimestampHint {
                time: 0xAABB_CCDD,
                zid: vec![0x42],
            })
            .with_attachment(b"aliased-meta".to_vec());
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].timestamp.as_ref().unwrap().time, 0xAABB_CCDD);
        assert_eq!(s[0].attachment.as_deref(), Some(&b"aliased-meta"[..]));
    }

    // ── R239 QueryOptions + Session::query ──

    #[test]
    fn query_options_default_is_any_locality_unset_metadata() {
        let opts = QueryOptions::default();
        assert_eq!(opts.allowed_destination, Locality::Any);
        assert!(opts.target.is_none());
        assert!(opts.consolidation.is_none());
        assert!(opts.payload.is_none());
        assert!(opts.encoding.is_none());
        assert!(opts.attachment.is_none());
        assert_eq!(opts.timeout_ms, 0);
    }

    #[test]
    fn query_options_get_constructor_matches_default() {
        let get = QueryOptions::get();
        let dflt = QueryOptions::default();
        assert_eq!(get.allowed_destination, dflt.allowed_destination);
        assert_eq!(get.target, dflt.target);
        assert_eq!(get.consolidation, dflt.consolidation);
    }

    #[test]
    fn query_options_with_setters_chain() {
        let opts = QueryOptions::get()
            .with_allowed_destination(Locality::SessionLocal)
            .with_target(QueryTarget::All)
            .with_consolidation(ConsolidationMode::Latest)
            .with_payload(b"q-payload".to_vec())
            .with_attachment(b"q-attach".to_vec())
            .with_timeout_ms(5_000);
        assert_eq!(opts.allowed_destination, Locality::SessionLocal);
        assert_eq!(opts.target, Some(QueryTarget::All));
        assert_eq!(opts.consolidation, Some(ConsolidationMode::Latest));
        assert_eq!(opts.payload.as_deref(), Some(&b"q-payload"[..]));
        assert_eq!(opts.attachment.as_deref(), Some(&b"q-attach"[..]));
        assert_eq!(opts.timeout_ms, 5_000);
    }

    #[test]
    fn query_options_expected_finals_matches_locality() {
        assert_eq!(
            QueryOptions::default()
                .with_allowed_destination(Locality::Any)
                .expected_finals(),
            2,
            "Locality::Any expects loopback final + peer final"
        );
        assert_eq!(
            QueryOptions::default()
                .with_allowed_destination(Locality::Remote)
                .expected_finals(),
            1,
            "Locality::Remote expects peer final only"
        );
        assert_eq!(
            QueryOptions::default()
                .with_allowed_destination(Locality::SessionLocal)
                .expected_finals(),
            1,
            "Locality::SessionLocal expects loopback final only"
        );
    }

    #[test]
    fn query_locality_session_local_fires_loopback_only_and_completes_inline() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_query, responder| {
                responder.reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            &clock,
            move |reply| {
                r.fetch_add(1, Ordering::SeqCst);
                assert_eq!(reply.keyexpr_literal, "home/temp");
                assert_eq!(
                    reply.body,
                    InboundReplyBody::Put {
                        payload: b"22.5".to_vec()
                    }
                );
            },
            move |_rid| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(
            reply_count.load(Ordering::SeqCst),
            1,
            "loopback reply fires inline"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "SessionLocal final completes inline"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal must NOT touch the wire"
        );
        assert!(
            session.observer().lock().unwrap().replies.is_empty(),
            "expected_finals=1 closes the pending entry on the loopback final"
        );
    }

    #[test]
    fn query_locality_remote_fires_wire_only_and_keeps_pending_until_wire_final() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        // Local queryable that would fire on a loopback round must
        // stay dormant on Locality::Remote — verifies the loopback
        // branch is entirely skipped.
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"loopback-should-not-fire");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            &clock,
            move |_reply| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_rid| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        );

        assert_eq!(
            reply_count.load(Ordering::SeqCst),
            0,
            "Remote suppresses loopback"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "wire Final has not arrived yet"
        );
        assert_eq!(
            driver.frame_count(),
            1,
            "wire Request(Query) frame on the driver"
        );
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            1,
            "pending entry preserved waiting for the peer's Final"
        );
    }

    #[test]
    fn query_locality_any_fires_both_branches_and_waits_for_wire_final() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get(),
            &clock,
            // Any (default)
            move |_reply| {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |_rid| {
                f.fetch_add(1, Ordering::SeqCst);
            },
        );

        // Inline observations:
        assert_eq!(
            reply_count.load(Ordering::SeqCst),
            1,
            "loopback reply fires inline"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "Locality::Any on_final must wait for the wire Final too (expected_finals=2)"
        );
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch dispatched one Request(Query)"
        );
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            1,
            "pending entry preserved waiting for the remaining wire Final"
        );

        // Simulate the peer's ResponseFinal — the second of the two
        // expected finals — and observe on_final fire then.
        use wz_codecs::response_final::ResponseFinal;
        let mut observer = session.observer().lock().unwrap();
        observer.replies.dispatch_response_final(&ResponseFinal {
            request_id: 0,
            ..ResponseFinal::default()
        });
        drop(observer);

        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "second Final closes the chain"
        );
        assert!(
            session.observer().lock().unwrap().replies.is_empty(),
            "pending entry dropped after the closing Final"
        );
    }

    #[test]
    fn query_handle_carries_rid_zero_for_first_call_then_monotonic() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let h0 = session
            .query(
                "k",
                QueryOptions::get().with_allowed_destination(Locality::Remote),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        let h1 = session
            .query(
                "k",
                QueryOptions::get().with_allowed_destination(Locality::Remote),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(h0.rid(), 0);
        assert_eq!(
            h1.rid(),
            1,
            "alloc_next_request_id increments monotonically"
        );
    }

    #[test]
    fn query_loopback_propagates_del_body() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("clear/me", |_q, responder| {
                responder.reply_del();
            });

        session
            .query(
                "clear/me",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("on_reply must fire");
        assert_eq!(got.body, InboundReplyBody::Del);
        assert_eq!(got.keyexpr_literal, "clear/me");
    }

    #[test]
    fn query_loopback_propagates_err_body_with_encoding_tuple() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("error/path", |_q, responder| {
                responder.reply_err(Some(4), Some("schema_v1"), b"oops");
            });

        session
            .query(
                "error/path",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("on_reply must fire");
        assert_eq!(got.keyexpr_literal, "error/path");
        match &got.body {
            InboundReplyBody::Err { encoding, payload } => {
                assert_eq!(*encoding, Some((4, Some("schema_v1".to_string()))));
                assert_eq!(payload, b"oops");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn query_with_no_matching_queryable_completes_loopback_with_zero_replies() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        // Register a queryable on a different keyexpr; the query's
        // pattern won't match → zero replies, but the loopback's
        // synthetic Final still closes the SessionLocal pending entry.
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/humidity", |_q, responder| {
                responder.reply(b"99");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(reply_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "loopback Final still fires even when no queryable matched"
        );
        assert!(session.observer().lock().unwrap().replies.is_empty());
    }

    #[test]
    fn query_session_local_skips_remote_only_queryable() {
        let clock = TokioTime::new();
        // A Locality::Remote-only queryable must NOT fire on a
        // Locality::SessionLocal query (loopback path uses
        // allows_local() — Remote returns false). Mirrors the
        // publish-side suppression pattern at the queryable side.
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register_with_locality("home/temp", Locality::Remote, move |_q, _responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        let f = final_count.clone();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Remote-only queryable must skip loopback"
        );
        assert_eq!(reply_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "loopback Final still fires"
        );
    }

    #[test]
    fn query_session_local_with_session_local_queryable_fires() {
        let clock = TokioTime::new();
        // SessionLocal queryable on SessionLocal query: both
        // allows_local() — must fire. Verifies the loopback path is
        // not accidentally gated on allows_remote().
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register_with_locality("home/temp", Locality::SessionLocal, move |_q, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"22.5");
            });

        let reply_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(reply_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn query_locality_remote_alone_skips_local_queryable() {
        let clock = TokioTime::new();
        // A local Locality::Any queryable does fire on its own
        // session's Remote-only query? NO — the loopback branch is
        // gated on opts.allowed_destination.allows_local(); Remote
        // sets that to false. Mirrors the publish-side
        // publish_locality_remote_fires_wire_only invariant for the
        // queryable side.
        let (session, driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session.observer().lock().unwrap().queryables.register(
            "home/temp",
            move |_q, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"22.5");
            },
        );

        let reply_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::Remote),
                &clock,
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Remote query does NOT trigger local queryable through the loopback branch"
        );
        assert_eq!(reply_count.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 1, "wire branch sent");
    }

    #[test]
    fn alloc_next_request_id_increments_and_starts_at_zero() {
        let driver = Arc::new(RecordingDriver::new());
        let actions = SessionLinkActions::new(driver, fixture_params(), TokioTime::new());
        assert_eq!(actions.alloc_next_request_id(), 0);
        assert_eq!(actions.alloc_next_request_id(), 1);
        assert_eq!(actions.alloc_next_request_id(), 2);
    }

    // ── R240 wire-side QueryOptions propagation ──

    #[test]
    fn query_options_query_metadata_extracts_wire_fields() {
        // R240 — QueryOptions::query_metadata must surface the
        // wire-propagatable subset (target / consolidation /
        // attachment / timeout_ms). payload / encoding stay on
        // QueryOptions as future-additive carries until the wz
        // codec lands the Q_B / Q_E slots; the extracted
        // QueryMetadata MUST NOT carry them.
        let opts = QueryOptions::get()
            .with_target(QueryTarget::AllComplete)
            .with_consolidation(ConsolidationMode::Monotonic)
            .with_attachment(b"q-att".to_vec())
            .with_timeout_ms(5_000)
            .with_payload(b"unused-payload".to_vec())
            .with_encoding(EncodingHint {
                packed_id: 1,
                schema: None,
            });
        let meta = opts.query_metadata();
        assert_eq!(meta.target, Some(QueryTarget::AllComplete));
        assert_eq!(meta.consolidation, Some(ConsolidationMode::Monotonic));
        assert_eq!(meta.attachment.as_deref(), Some(&b"q-att"[..]));
        assert_eq!(meta.timeout_ms, 5_000);
    }

    #[test]
    fn query_options_default_query_metadata_is_empty() {
        let meta = QueryOptions::default().query_metadata();
        assert!(
            meta.is_empty(),
            "default options produce empty wire metadata"
        );
    }

    #[test]
    fn query_wire_branch_with_empty_meta_emits_no_meta_fast_path_frame() {
        let clock = TokioTime::new();
        // Session::query with default options (Locality::Any, no
        // metadata) MUST take the no-meta fast path → wire frame is
        // byte-identical to a standalone send_request_query call.
        // Pins the R240 short-circuit invariant at the Session
        // level.
        let (session, driver) = build_session();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::Remote),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        let session_frame = driver.frames.lock().unwrap()[0].0.clone();

        // Mirror the call against an independent recording driver +
        // SessionLinkActions, using the bare no-metadata API, and
        // assert byte parity. Construct a fresh session so the
        // outbound Frame SN starts from the same initial_sn=1; the
        // alloc_next_request_id counter also starts at 0 so the
        // request_id matches.
        let driver2 = Arc::new(RecordingDriver::new());
        let actions2 = SessionLinkActions::new(driver2.clone(), fixture_params(), TokioTime::new());
        let rid = actions2.alloc_next_request_id();
        actions2.send_request_query(rid, 0, Some("home/temp"));
        let baseline = driver2.frames.lock().unwrap()[0].0.clone();

        assert_eq!(
            session_frame, baseline,
            "Session::query with default options must produce byte-stable parity"
        );
    }

    #[test]
    fn query_wire_branch_with_target_threads_target_through_with_meta() {
        let clock = TokioTime::new();
        // QueryOptions::with_target lands on the outbound Request via
        // the with-meta path. Pins the R240 Session-level integration
        // between QueryOptions.target → QueryMetadata.target →
        // RequestQueryBuilder::request_target.
        let (session, driver) = build_session();
        session
            .query(
                "home/temp",
                QueryOptions::get()
                    .with_allowed_destination(Locality::Remote)
                    .with_target(QueryTarget::AllComplete),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        // Re-encode an equivalent standalone Request with target=All
        // and assert the wire bytes appear verbatim in the recorded
        // frame.
        use crate::session_glue::build_request_query_with_target;
        let standalone =
            build_request_query_with_target(0, 0, Some("home/temp"), QueryTarget::AllComplete);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "Session::query wire frame must contain with-target Request bytes"
        );
    }

    #[test]
    fn query_wire_branch_with_attachment_threads_attachment_through_with_meta() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .query(
                "home/temp",
                QueryOptions::get()
                    .with_allowed_destination(Locality::Remote)
                    .with_attachment(b"q-att".to_vec()),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        use crate::session_glue::build_request_query_with_attachment;
        let standalone = build_request_query_with_attachment(0, 0, Some("home/temp"), b"q-att");
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "wire frame must contain with-attachment Request bytes"
        );
    }

    #[test]
    fn query_wire_branch_with_consolidation_threads_consolidation_through_with_meta() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .query(
                "home/temp",
                QueryOptions::get()
                    .with_allowed_destination(Locality::Remote)
                    .with_consolidation(ConsolidationMode::Latest),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        use crate::session_glue::build_request_query_with_consolidation;
        let standalone = build_request_query_with_consolidation(
            0,
            0,
            Some("home/temp"),
            ConsolidationMode::Latest,
        );
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "wire frame must contain with-consolidation Request bytes"
        );
    }

    #[test]
    fn query_session_local_with_any_metadata_skips_wire_branch_entirely() {
        let clock = TokioTime::new();
        // R240 invariance: even with non-empty QueryMetadata, a
        // Locality::SessionLocal query MUST NOT touch the wire. The
        // meta extraction happens regardless but the actions surface
        // is never invoked.
        let (session, driver) = build_session();
        session
            .query(
                "home/temp",
                QueryOptions::get()
                    .with_allowed_destination(Locality::SessionLocal)
                    .with_target(QueryTarget::All)
                    .with_attachment(b"q-att".to_vec())
                    .with_timeout_ms(1_000),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal must skip the wire branch regardless of metadata"
        );
    }

    // ── R241 query_aliased + query_aliased_auto ──

    #[test]
    fn query_aliased_locality_session_local_fires_loopback_only() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        session
            .query_aliased(
                7,
                None,
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |_reply| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_rid| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(reply_count.load(Ordering::SeqCst), 1);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert_eq!(driver.frame_count(), 0, "SessionLocal skips wire");
    }

    #[test]
    fn query_aliased_locality_remote_fires_wire_with_mapping_id() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .query_aliased(
                7,
                None,
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::Remote),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(driver.frame_count(), 1, "wire frame emitted");

        // Verify the recorded frame is byte-equivalent to a standalone
        // build_request_query with mapping_id=7.
        use crate::session_glue::build_request_query;
        let standalone = build_request_query(0, 7, None);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "wire frame must encode the (mapping_id=7, suffix=None) aliased pair"
        );
    }

    #[test]
    fn query_aliased_locality_any_fires_both_branches() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        session
            .query_aliased(
                7,
                None,
                "home/temp",
                QueryOptions::get(),
                &clock,
                // Any
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(reply_count.load(Ordering::SeqCst), 1, "loopback fires");
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "Any expects 2 finals; only loopback final has fired so far"
        );
        assert_eq!(driver.frame_count(), 1, "wire branch also fires");
    }

    #[test]
    fn query_aliased_inline_suffix_passes_through_to_wire_and_loopback() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();

        // Local queryable matches the COMPOSITE literal (the
        // loopback path uses loopback_keyexpr verbatim).
        session.observer().lock().unwrap().queryables.register(
            "home/temp/kitchen",
            |_q, responder| {
                responder.reply(b"21.0");
            },
        );

        session
            .query_aliased(
                7,
                Some("/kitchen"),
                "home/temp/kitchen",
                QueryOptions::get(),
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("loopback reply fired");
        assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch sent the composite pair"
        );
    }

    #[test]
    fn query_aliased_auto_resolves_loopback_from_outbound_mapping_table() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let handle = session
            .query_aliased_auto(
                7,
                None,
                QueryOptions::get(),
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("declared mapping resolves");

        assert_eq!(handle.rid(), 0, "first auto-resolved query gets rid=0");
        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("loopback reply fired");
        assert_eq!(got.keyexpr_literal, "home/temp");
        // 2 wire frames: one DeclKexpr, one Request(Query).
        assert_eq!(driver.frame_count(), 2);
    }

    #[test]
    fn query_aliased_auto_unknown_mapping_returns_err_and_skips_both_branches() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", move |_q, _r| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let err = session.query_aliased_auto(99, None, QueryOptions::get(), &clock, |_| {}, |_| {});
        assert_eq!(err, Err(QueryAliasError::UnknownMapping(99)));
        assert_eq!(fired.load(Ordering::SeqCst), 0, "loopback skipped on err");
        assert_eq!(driver.frame_count(), 0, "wire skipped on err");
        assert!(
            session.observer().lock().unwrap().replies.is_empty(),
            "no pending entry on err"
        );
    }

    #[test]
    fn query_aliased_auto_with_inline_suffix_concatenates_for_loopback() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        session.observer().lock().unwrap().queryables.register(
            "home/temp/kitchen",
            |_q, responder| {
                responder.reply(b"21.0");
            },
        );

        session
            .query_aliased_auto(
                7,
                Some("/kitchen"),
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("declared mapping resolves");

        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("composite literal matched");
        assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
    }

    #[test]
    fn query_aliased_with_meta_threads_attachment_through_wire() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .query_aliased(
                7,
                None,
                "home/temp",
                QueryOptions::get()
                    .with_allowed_destination(Locality::Remote)
                    .with_attachment(b"q-att".to_vec()),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        use crate::session_glue::build_request_query_with_attachment;
        let standalone = build_request_query_with_attachment(0, 7, None, b"q-att");
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "aliased + with-meta routing must thread attachment onto wire"
        );
    }

    #[test]
    fn query_alias_error_display_message_hints_remediation() {
        let err = QueryAliasError::UnknownMapping(42);
        let msg = format!("{err}");
        assert!(
            msg.contains("42"),
            "error message includes the offending id"
        );
        assert!(
            msg.contains("send_declare_keyexpr"),
            "error message hints at the remediation API"
        );
    }

    // ── R242 Querier (z_querier_t mirror) ──

    #[test]
    fn declare_querier_returns_handle_with_keyexpr_and_options() {
        let (session, _driver) = build_session();
        let opts = QueryOptions::get()
            .with_target(QueryTarget::All)
            .with_consolidation(ConsolidationMode::Latest)
            .with_timeout_ms(5_000);
        let querier = session.declare_querier("home/temp", opts.clone());
        assert_eq!(querier.keyexpr(), "home/temp");
        assert_eq!(querier.options().target, opts.target);
        assert_eq!(querier.options().consolidation, opts.consolidation);
        assert_eq!(querier.options().timeout_ms, opts.timeout_ms);
    }

    #[test]
    fn declare_querier_does_not_emit_wire_frame_at_declare_time() {
        // The querier "declaration" is purely a caller-side
        // aggregation; the Query side has no peer-side state to
        // register (unlike DeclareSubscriber / DeclareQueryable).
        let (session, driver) = build_session();
        let _querier = session.declare_querier("home/temp", QueryOptions::get());
        assert_eq!(
            driver.frame_count(),
            0,
            "declare_querier is a no-op on the wire"
        );
    }

    #[test]
    fn querier_get_fires_loopback_through_session_query_session_local() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let querier = session.declare_querier(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
        );
        let r = reply_count.clone();
        let f = final_count.clone();
        querier
            .get(
                &clock,
                move |_| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                move |_| {
                    f.fetch_add(1, Ordering::SeqCst);
                },
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(reply_count.load(Ordering::SeqCst), 1);
        assert_eq!(final_count.load(Ordering::SeqCst), 1);
        assert_eq!(driver.frame_count(), 0, "SessionLocal skips wire");
    }

    #[test]
    fn querier_get_called_twice_allocates_independent_rids() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let querier = session.declare_querier(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
        );
        let h0 = querier
            .get(&clock, |_| {}, |_| {})
            .expect("query-get feature is ON in this test build");
        let h1 = querier
            .get(&clock, |_| {}, |_| {})
            .expect("query-get feature is ON in this test build");
        assert_eq!(h0.rid(), 0);
        assert_eq!(
            h1.rid(),
            1,
            "successive querier.get() calls get monotonic rids"
        );
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            2,
            "both pending entries preserved (Locality::Remote awaits wire Final)"
        );
    }

    #[test]
    fn querier_get_threads_target_option_into_wire() {
        let clock = TokioTime::new();
        // Single-knob verification: declare with target=All, observe
        // the wire frame containing the with-target Request encoding.
        // (Multi-knob composite verify lives in R240's
        // send_request_query_with_meta tests — we don't duplicate it
        // here; the contract this test pins is "Querier::get really
        // does thread its declare-time options through to
        // Session::query and onward to the wire".)
        let (session, driver) = build_session();
        let querier = session.declare_querier(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_target(QueryTarget::All),
        );
        querier
            .get(&clock, |_| {}, |_| {})
            .expect("query-get feature is ON in this test build");

        use crate::session_glue::build_request_query_with_target;
        let standalone = build_request_query_with_target(0, 0, Some("home/temp"), QueryTarget::All);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame
                .windows(standalone_bytes.len())
                .any(|w| w == standalone_bytes),
            "Querier::get must thread declare-time target option into the wire frame"
        );
    }

    #[test]
    fn querier_clone_shares_session_and_options() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        let clone = querier.clone();
        assert_eq!(clone.keyexpr(), querier.keyexpr());
        assert_eq!(
            clone.options().allowed_destination,
            querier.options().allowed_destination
        );
        // Both clones can issue independent gets — verify by emitting
        // through both and checking the pending count.
        let q1 = querier
            .clone()
            .get(&clock, |_| {}, |_| {})
            .expect("query-get feature is ON in this test build");
        let q2 = clone
            .get(&clock, |_| {}, |_| {})
            .expect("query-get feature is ON in this test build");
        assert_eq!(q1.rid(), 0);
        assert_eq!(q2.rid(), 1, "clones share the same rid allocator");
    }

    // ── R288 Querier::get_matching_status ──

    /// Local construction helper for inbound `DeclQueryable` /
    /// `UndeclQueryable` records that exercise the
    /// `remote_queryables` registry from session.rs tests. The
    /// `crate::declare::test_helpers` versions are
    /// `pub(super)`-scoped to the declare module so we cannot import
    /// them here; the constructors are intentionally small so
    /// inlining is cheaper than relaxing the helper visibility.
    fn make_decl_queryable(id: u64, keyexpr_literal: &str) -> wz_codecs::declare::DeclareVariant {
        use wz_codecs::decl_queryable::DeclQueryable;
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_local::WireexprLocal;
        let suffix = keyexpr_literal.to_string();
        let suffix_len = Some(suffix.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix),
            }),
        };
        wz_codecs::declare::DeclareVariant::CodecZenohDeclQueryable(DeclQueryable {
            id,
            keyexpr,
            ..DeclQueryable::default()
        })
    }

    fn make_undecl_queryable(id: u64) -> wz_codecs::declare::DeclareVariant {
        use wz_codecs::undecl_queryable::UndeclQueryable;
        wz_codecs::declare::DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable {
            id,
            ..UndeclQueryable::default()
        })
    }

    #[test]
    fn querier_get_matching_status_false_on_fresh_session_with_no_peers() {
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: false },
            "no peer DeclQueryable dispatched yet — matching is false"
        );
    }

    #[test]
    fn querier_get_matching_status_true_after_peer_decl_with_matching_keyexpr() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        // Drive a DeclQueryable into the registry directly (no FSM
        // dispatch needed for this assertion — the registry's
        // dispatch_declare is the contract surface).
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(42, "home/temp"), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true },
            "peer DeclQueryable for the literal keyexpr — matching is true"
        );
    }

    #[test]
    fn querier_get_matching_status_true_when_peer_pattern_covers_querier_literal() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(43, "home/**"), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true },
            "peer pattern home/** covers the literal home/temp — matching is true"
        );
    }

    #[test]
    fn querier_get_matching_status_true_when_querier_pattern_covers_peer_literal() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/**", QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(44, "home/door"), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true },
            "querier pattern home/** covers peer literal home/door — matching is true"
        );
    }

    #[test]
    fn querier_get_matching_status_false_after_peer_undeclare() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(45, "home/temp"), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true }
        );
        // Peer retracts the queryable.
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_undecl_queryable(45), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: false },
            "post-UndeclQueryable — matching falls back to false"
        );
    }

    #[test]
    fn querier_get_matching_status_false_with_non_matching_peer_keyexpr() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(46, "other/foo"), &HashMap::new());
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: false },
            "peer keyexpr does not intersect querier keyexpr — matching is false"
        );
    }

    #[test]
    fn querier_get_matching_status_true_when_any_of_many_peer_decls_matches() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        let mut obs = session.observer().lock().unwrap();
        obs.remote_queryables
            .dispatch_declare(&make_decl_queryable(50, "other/foo"), &HashMap::new());
        obs.remote_queryables
            .dispatch_declare(&make_decl_queryable(51, "home/temp"), &HashMap::new());
        obs.remote_queryables
            .dispatch_declare(&make_decl_queryable(52, "a/b/c"), &HashMap::new());
        assert_eq!(obs.remote_queryables.declared_count(), 3);
        drop(obs);
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true },
            "any one matching peer decl suffices — matching is true"
        );
    }

    #[test]
    fn querier_clone_shares_matching_status_view() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let querier = session.declare_querier("home/temp", QueryOptions::get());
        let querier_clone = querier.clone();
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: false }
        );
        assert_eq!(
            querier_clone.get_matching_status(),
            MatchingStatus { matching: false }
        );
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(60, "home/temp"), &HashMap::new());
        // Both clones observe the same registry membership change.
        assert_eq!(
            querier.get_matching_status(),
            MatchingStatus { matching: true }
        );
        assert_eq!(
            querier_clone.get_matching_status(),
            MatchingStatus { matching: true }
        );
    }

    // ── R243 QuerierAliased ──

    #[test]
    fn declare_querier_aliased_returns_handle_with_mapping_id_and_options() {
        let (session, _driver) = build_session();
        let opts = QueryOptions::get().with_target(QueryTarget::All);
        let qa = session.declare_querier_aliased(7, Some("/kitchen"), opts.clone());
        assert_eq!(qa.mapping_id(), 7);
        assert_eq!(qa.inline_suffix(), Some("/kitchen"));
        assert_eq!(qa.options().target, opts.target);
    }

    #[test]
    fn declare_querier_aliased_does_not_emit_wire_frame() {
        let (session, driver) = build_session();
        let _qa = session.declare_querier_aliased(7, None, QueryOptions::get());
        assert_eq!(
            driver.frame_count(),
            0,
            "declare_querier_aliased is a no-op on the wire"
        );
    }

    #[test]
    fn querier_aliased_get_resolves_loopback_through_outbound_mapping_table() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.reply(b"22.5");
            });

        let qa = session.declare_querier_aliased(
            7,
            None,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
        );
        let handle = qa
            .get(
                &clock,
                move |reply| {
                    *cap_cb.lock().unwrap() = Some(reply.clone());
                },
                |_| {},
            )
            .expect("declared mapping resolves");

        assert_eq!(handle.rid(), 0);
        let got = captured.lock().unwrap().clone().expect("loopback fired");
        assert_eq!(got.keyexpr_literal, "home/temp");
        assert_eq!(
            driver.frame_count(),
            1,
            "DeclKexpr frame only (SessionLocal skips Query wire)"
        );
    }

    #[test]
    fn querier_aliased_get_unknown_mapping_returns_err_and_skips_both_branches() {
        let clock = TokioTime::new();
        let (session, driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", move |_q, _r| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let qa = session.declare_querier_aliased(99, None, QueryOptions::get());
        let err = qa.get(&clock, |_| {}, |_| {});
        assert_eq!(err, Err(QueryAliasError::UnknownMapping(99)));
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 0);
    }

    #[test]
    fn querier_aliased_get_threads_inline_suffix_into_composite_literal() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();
        session.observer().lock().unwrap().queryables.register(
            "home/temp/kitchen",
            |_q, responder| {
                responder.reply(b"21.0");
            },
        );

        let qa = session.declare_querier_aliased(
            7,
            Some("/kitchen"),
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
        );
        qa.get(
            &clock,
            move |reply| {
                *cap_cb.lock().unwrap() = Some(reply.clone());
            },
            |_| {},
        )
        .expect("declared mapping resolves");

        let got = captured
            .lock()
            .unwrap()
            .clone()
            .expect("composite literal matched");
        assert_eq!(got.keyexpr_literal, "home/temp/kitchen");
    }

    #[test]
    fn querier_aliased_get_twice_allocates_independent_rids() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let qa = session.declare_querier_aliased(
            7,
            None,
            QueryOptions::get().with_allowed_destination(Locality::Remote),
        );
        let h0 = qa.get(&clock, |_| {}, |_| {}).unwrap();
        let h1 = qa.get(&clock, |_| {}, |_| {}).unwrap();
        assert_eq!(h0.rid(), 0);
        assert_eq!(h1.rid(), 1);
    }

    #[test]
    fn querier_aliased_clone_shares_session_and_options() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let qa = session.declare_querier_aliased(
            7,
            None,
            QueryOptions::get().with_allowed_destination(Locality::Remote),
        );
        let clone = qa.clone();
        assert_eq!(clone.mapping_id(), qa.mapping_id());
        assert_eq!(clone.inline_suffix(), qa.inline_suffix());
        let h0 = qa.get(&clock, |_| {}, |_| {}).unwrap();
        let h1 = clone.get(&clock, |_| {}, |_| {}).unwrap();
        assert_eq!(h0.rid(), 0);
        assert_eq!(h1.rid(), 1, "clones share the same rid allocator");
    }

    // ── R289 QuerierAliased::get_matching_status ──

    #[test]
    fn querier_aliased_get_matching_status_returns_err_on_unknown_mapping() {
        let (session, _driver) = build_session();
        // No send_declare_keyexpr for id=88 — mapping is unknown.
        let qa = session.declare_querier_aliased(88, None, QueryOptions::get());
        assert_eq!(
            qa.get_matching_status(),
            Err(QueryAliasError::UnknownMapping(88)),
            "unresolvable mapping surfaces as QueryAliasError::UnknownMapping"
        );
    }

    #[test]
    fn querier_aliased_get_matching_status_false_after_declare_with_no_peer() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
        assert_eq!(
            qa.get_matching_status(),
            Ok(MatchingStatus { matching: false }),
            "mapping resolved but no peer DeclQueryable — matching is false"
        );
    }

    #[test]
    fn querier_aliased_get_matching_status_true_when_peer_decl_matches_base_literal() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(70, "home/temp"), &HashMap::new());
        assert_eq!(
            qa.get_matching_status(),
            Ok(MatchingStatus { matching: true }),
            "base mapping resolves to home/temp; peer DeclQueryable on home/temp matches"
        );
    }

    #[test]
    fn querier_aliased_get_matching_status_threads_inline_suffix_into_consult() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        // QuerierAliased with inline_suffix produces effective
        // keyexpr "home/temp/kitchen"; peer DeclQueryable on
        // "home/**" should match via the peer-pattern asymmetric
        // arm.
        let qa = session.declare_querier_aliased(7, Some("/kitchen"), QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(71, "home/**"), &HashMap::new());
        assert_eq!(
            qa.get_matching_status(),
            Ok(MatchingStatus { matching: true }),
            "inline_suffix-composed effective keyexpr matches peer pattern home/**"
        );

        // Peer pattern home/door/** does NOT cover home/temp/kitchen
        // — verify the inline_suffix actually narrows the consult
        // (a literal-without-suffix consult against "home/door/**"
        // also fails to match home/temp, but the composed
        // home/temp/kitchen + home/door/** case is the more
        // diagnostic one).
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_undecl_queryable(71), &HashMap::new());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(72, "home/door/**"), &HashMap::new());
        assert_eq!(
            qa.get_matching_status(),
            Ok(MatchingStatus { matching: false }),
            "peer pattern home/door/** does not cover effective home/temp/kitchen"
        );
    }

    #[test]
    fn querier_aliased_get_matching_status_false_after_undeclared_mapping_drop() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let qa = session.declare_querier_aliased(7, None, QueryOptions::get());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_queryables
            .dispatch_declare(&make_decl_queryable(73, "home/temp"), &HashMap::new());
        assert_eq!(
            qa.get_matching_status(),
            Ok(MatchingStatus { matching: true })
        );
        // Local-side retracts the keyexpr mapping — subsequent
        // get_matching_status surfaces UnknownMapping just like
        // QuerierAliased::get does.
        session.actions().send_undeclare_kexpr(7);
        assert_eq!(
            qa.get_matching_status(),
            Err(QueryAliasError::UnknownMapping(7)),
            "post-undeclare_kexpr — mapping unresolvable, surfaces UnknownMapping"
        );
    }

    // ── R244 Publisher + PublisherAliased ──

    #[test]
    fn declare_publisher_returns_handle_with_keyexpr_and_options() {
        let (session, _driver) = build_session();
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort);
        let pubr = session.declare_publisher("home/temp", opts.clone());
        assert_eq!(pubr.keyexpr(), "home/temp");
        assert_eq!(pubr.options().allowed_destination, opts.allowed_destination);
        assert_eq!(pubr.options().reliability, opts.reliability);
    }

    #[test]
    fn declare_publisher_does_not_emit_wire_frame() {
        let (session, driver) = build_session();
        let _pubr = session.declare_publisher("home/temp", PublishOptions::put());
        assert_eq!(
            driver.frame_count(),
            0,
            "declare_publisher is a no-op on the wire"
        );
    }

    #[test]
    fn publisher_put_fires_loopback_subscriber() {
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let pubr = session.declare_publisher(
            "home/temp",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        let count = pubr.put(b"22.5");
        assert_eq!(count, 1);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publisher_delete_routes_to_del_kind_and_drops_payload() {
        let (session, _driver) = build_session();
        let kind_seen: Arc<Mutex<Option<SampleKind>>> = Arc::new(Mutex::new(None));
        let kind_cb = kind_seen.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("clear/me", move |sample| {
                *kind_cb.lock().unwrap() = Some(sample.kind);
            });

        let pubr = session.declare_publisher(
            "clear/me",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        pubr.delete();
        assert_eq!(*kind_seen.lock().unwrap(), Some(SampleKind::Del));
    }

    #[test]
    fn publisher_clone_shares_session_and_driver() {
        let (session, driver) = build_session();
        let pubr = session.declare_publisher(
            "home/temp",
            PublishOptions::put().with_locality(Locality::Remote),
        );
        let clone = pubr.clone();
        assert_eq!(clone.keyexpr(), pubr.keyexpr());
        pubr.put(b"a");
        clone.put(b"b");
        assert_eq!(driver.frame_count(), 2, "both clones share the wire driver");
    }

    #[test]
    fn declare_publisher_aliased_returns_handle_with_mapping_id_and_options() {
        let (session, _driver) = build_session();
        let opts = PublishOptions::put().with_reliability(Reliability::BestEffort);
        let pa = session.declare_publisher_aliased(7, Some("/kitchen"), opts.clone());
        assert_eq!(pa.mapping_id(), 7);
        assert_eq!(pa.inline_suffix(), Some("/kitchen"));
        assert_eq!(pa.options().reliability, opts.reliability);
    }

    #[test]
    fn declare_publisher_aliased_does_not_emit_wire_frame() {
        let (session, driver) = build_session();
        let _pa = session.declare_publisher_aliased(7, None, PublishOptions::put());
        assert_eq!(driver.frame_count(), 0);
    }

    #[test]
    fn publisher_aliased_put_resolves_loopback_through_outbound_table() {
        let (session, driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let pa = session.declare_publisher_aliased(
            7,
            None,
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        let count = pa.put(b"22.5").expect("declared mapping resolves");
        assert_eq!(count, 1);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "DeclKexpr only (SessionLocal skips Push wire)"
        );
    }

    #[test]
    fn publisher_aliased_unknown_mapping_returns_err_and_skips_both_branches() {
        let (session, driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        let pa = session.declare_publisher_aliased(99, None, PublishOptions::put());
        let err = pa.put(b"x");
        assert_eq!(err, Err(PublishAliasError::UnknownMapping(99)));
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 0);
    }

    #[test]
    fn publisher_aliased_delete_routes_to_del_kind() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "clear/me")
            .expect("hardcoded canonical literal keyexpr");
        let kind_seen: Arc<Mutex<Option<SampleKind>>> = Arc::new(Mutex::new(None));
        let kind_cb = kind_seen.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("clear/me", move |sample| {
                *kind_cb.lock().unwrap() = Some(sample.kind);
            });

        let pa = session.declare_publisher_aliased(
            7,
            None,
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        pa.delete().expect("declared mapping resolves");
        assert_eq!(*kind_seen.lock().unwrap(), Some(SampleKind::Del));
    }

    // ── R290 Publisher / PublisherAliased::get_matching_status ──

    /// R290 — local DeclSubscriber / UndeclSubscriber constructors
    /// for session.rs tests. Mirror of the R288 make_decl_queryable /
    /// make_undecl_queryable helpers; the
    /// crate::declare::test_helpers versions are pub(super)-scoped
    /// to the declare module and not visible here.
    fn make_decl_subscriber(id: u64, keyexpr_literal: &str) -> wz_codecs::declare::DeclareVariant {
        use wz_codecs::decl_subscriber::DeclSubscriber;
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_local::WireexprLocal;
        let suffix = keyexpr_literal.to_string();
        let suffix_len = Some(suffix.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix),
            }),
        };
        wz_codecs::declare::DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber {
            id,
            keyexpr,
            ..DeclSubscriber::default()
        })
    }

    fn make_undecl_subscriber(id: u64) -> wz_codecs::declare::DeclareVariant {
        use wz_codecs::undecl_subscriber::UndeclSubscriber;
        wz_codecs::declare::DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
            id,
            ..UndeclSubscriber::default()
        })
    }

    #[test]
    fn publisher_get_matching_status_false_on_fresh_session_with_no_peers() {
        let (session, _driver) = build_session();
        let publisher = session.declare_publisher("home/temp", PublishOptions::put());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: false },
            "no peer DeclSubscriber dispatched yet — matching is false"
        );
    }

    #[test]
    fn publisher_get_matching_status_true_after_peer_decl_with_matching_keyexpr() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let publisher = session.declare_publisher("home/temp", PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(42, "home/temp"), &HashMap::new());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: true },
            "peer DeclSubscriber for the literal keyexpr — matching is true"
        );
    }

    #[test]
    fn publisher_get_matching_status_true_when_peer_pattern_covers_publisher_literal() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let publisher = session.declare_publisher("home/temp", PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(43, "home/**"), &HashMap::new());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: true },
            "peer pattern home/** covers the literal home/temp — matching is true"
        );
    }

    #[test]
    fn publisher_get_matching_status_false_after_peer_undeclare() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let publisher = session.declare_publisher("home/temp", PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(45, "home/temp"), &HashMap::new());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: true }
        );
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_undecl_subscriber(45), &HashMap::new());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: false },
            "post-UndeclSubscriber — matching falls back to false"
        );
    }

    #[test]
    fn publisher_get_matching_status_false_with_non_matching_peer_keyexpr() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        let publisher = session.declare_publisher("home/temp", PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(46, "other/foo"), &HashMap::new());
        assert_eq!(
            publisher.get_matching_status(),
            MatchingStatus { matching: false }
        );
    }

    #[test]
    fn publisher_aliased_get_matching_status_returns_err_on_unknown_mapping() {
        let (session, _driver) = build_session();
        let pa = session.declare_publisher_aliased(88, None, PublishOptions::put());
        assert_eq!(
            pa.get_matching_status(),
            Err(PublishAliasError::UnknownMapping(88)),
            "unresolvable mapping surfaces as PublishAliasError::UnknownMapping"
        );
    }

    #[test]
    fn publisher_aliased_get_matching_status_threads_inline_suffix_into_consult() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let pa = session.declare_publisher_aliased(7, Some("/kitchen"), PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(71, "home/**"), &HashMap::new());
        assert_eq!(
            pa.get_matching_status(),
            Ok(MatchingStatus { matching: true }),
            "inline_suffix-composed effective keyexpr matches peer pattern home/**"
        );
    }

    #[test]
    fn publisher_aliased_get_matching_status_false_after_undeclared_mapping_drop() {
        use std::collections::HashMap;
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let pa = session.declare_publisher_aliased(7, None, PublishOptions::put());
        session
            .observer()
            .lock()
            .unwrap()
            .remote_subscribers
            .dispatch_declare(&make_decl_subscriber(73, "home/temp"), &HashMap::new());
        assert_eq!(
            pa.get_matching_status(),
            Ok(MatchingStatus { matching: true })
        );
        session.actions().send_undeclare_kexpr(7);
        assert_eq!(
            pa.get_matching_status(),
            Err(PublishAliasError::UnknownMapping(7)),
            "post-undeclare_kexpr — mapping unresolvable, surfaces UnknownMapping"
        );
    }

    // ── R245 Subscriber + SubscribeOptions + declare_subscriber{_aliased} ──

    #[test]
    fn subscribe_options_default_is_any_locality() {
        let opts = SubscribeOptions::default();
        assert_eq!(opts.allowed_origin, Locality::Any);
    }

    #[test]
    fn subscribe_options_with_allowed_origin_pins_locality() {
        let opts = SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal);
        assert_eq!(opts.allowed_origin, Locality::SessionLocal);
    }

    #[test]
    fn declare_subscriber_returns_handle_with_keyexpr_and_options() {
        let (session, _driver) = build_session();
        let sub = session.declare_subscriber(
            "home/temp",
            SubscribeOptions::new().with_allowed_origin(Locality::SessionLocal),
            |_sample| {},
        );
        assert_eq!(sub.keyexpr(), "home/temp");
        assert_eq!(sub.options().allowed_origin, Locality::SessionLocal);
    }

    #[test]
    fn declare_subscriber_does_not_emit_wire_frame() {
        let (session, driver) = build_session();
        let _sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), |_| {});
        assert_eq!(
            driver.frame_count(),
            0,
            "declare_subscriber is a no-op on the wire"
        );
    }

    #[test]
    fn declared_subscriber_fires_on_loopback_publish() {
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let _sub =
            session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_sample| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            });

        session.publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn subscriber_drop_auto_unregisters() {
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        {
            let _sub =
                session.declare_subscriber("home/temp", SubscribeOptions::default(), move |_| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                });
            // First publish fires.
            session.publish(
                "home/temp",
                b"21.0",
                PublishOptions::put().with_locality(Locality::SessionLocal),
            );
            assert_eq!(fired.load(Ordering::SeqCst), 1);
        } // Subscriber drops here -> auto-unregister
          // Second publish must NOT fire — the callback is gone.
        session.publish(
            "home/temp",
            b"22.0",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "Drop auto-unregistered the callback"
        );
    }

    #[test]
    fn subscriber_undeclare_returns_true_and_skips_drop() {
        let (session, _driver) = build_session();
        let sub = session.declare_subscriber("home/temp", SubscribeOptions::default(), |_| {});
        let removed = sub.undeclare();
        assert!(removed, "first undeclare returns true");
        // Empty registry: subsequent publish fires no callback (no panic).
        session.publish(
            "home/temp",
            b"22.0",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
    }

    #[test]
    fn declare_subscriber_with_locality_remote_skips_loopback_publish() {
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let _sub = session.declare_subscriber(
            "home/temp",
            SubscribeOptions::new().with_allowed_origin(Locality::Remote),
            move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        session.publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Remote-only subscriber must NOT fire on loopback publish"
        );
    }

    #[test]
    fn declare_subscriber_aliased_resolves_literal_at_declare_time() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");

        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let sub = session
            .declare_subscriber_aliased(7, None, SubscribeOptions::default(), move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            })
            .expect("declared mapping resolves");
        assert_eq!(
            sub.keyexpr(),
            "home/temp",
            "resolved literal stored on handle"
        );

        session.publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn declare_subscriber_aliased_with_inline_suffix_composes_literal() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let sub = session
            .declare_subscriber_aliased(7, Some("/kitchen"), SubscribeOptions::default(), |_| {})
            .expect("declared mapping resolves");
        assert_eq!(sub.keyexpr(), "home/temp/kitchen");
    }

    #[test]
    fn declare_subscriber_aliased_unknown_mapping_returns_err() {
        let (session, _driver) = build_session();
        let err = session.declare_subscriber_aliased(99, None, SubscribeOptions::default(), |_| {});
        assert!(
            matches!(err, Err(SubscribeAliasError::UnknownMapping(99))),
            "expected Err(UnknownMapping(99))"
        );
        // Registry stays empty.
        assert_eq!(
            session.observer().lock().unwrap().subscribers.len(),
            0,
            "no subscriber registered on declare failure"
        );
    }

    #[test]
    fn declare_subscriber_aliased_survives_mapping_retract_after_declare() {
        // Mapping resolved at declare time; later send_undeclare_kexpr
        // must not affect the already-registered subscriber (zenoh-pico
        // _z_register_subscription mirror: resolution happens once).
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let _sub = session
            .declare_subscriber_aliased(7, None, SubscribeOptions::default(), move |_| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            })
            .expect("declared mapping resolves");

        // Retract the mapping.
        session.actions().send_undeclare_kexpr(7);

        // Publish on the literal — subscriber still fires (already
        // registered against the resolved literal).
        session.publish(
            "home/temp",
            b"22.5",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn subscribe_alias_error_display_message_hints_remediation() {
        let err = SubscribeAliasError::UnknownMapping(42);
        let msg = format!("{err}");
        assert!(msg.contains("42"));
        assert!(msg.contains("send_declare_keyexpr"));
    }

    // ── R246 Queryable + QueryableOptions + declare_queryable{,_aliased} ──

    #[test]
    fn queryable_options_default_is_any_locality() {
        let opts = QueryableOptions::default();
        assert_eq!(opts.allowed_origin, Locality::Any);
    }

    #[test]
    fn queryable_options_with_allowed_origin_pins_locality() {
        let opts = QueryableOptions::new().with_allowed_origin(Locality::SessionLocal);
        assert_eq!(opts.allowed_origin, Locality::SessionLocal);
    }

    #[test]
    fn declare_queryable_returns_handle_with_keyexpr_and_options() {
        let (session, _driver) = build_session();
        let q = session
            .declare_queryable(
                "home/temp",
                QueryableOptions::new().with_allowed_origin(Locality::SessionLocal),
                |_query, _responder| {},
            )
            .expect("query-queryable feature is ON in this test build");
        assert_eq!(q.keyexpr(), "home/temp");
        assert_eq!(q.options().allowed_origin, Locality::SessionLocal);
    }

    #[test]
    fn declare_queryable_does_not_emit_wire_frame() {
        let (session, driver) = build_session();
        let _q = session.declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {});
        assert_eq!(driver.frame_count(), 0);
    }

    #[test]
    fn declared_queryable_fires_on_loopback_query() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let _q = session.declare_queryable(
            "home/temp",
            QueryableOptions::default(),
            move |_query, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.reply(b"22.5");
            },
        );

        let replies = Arc::new(AtomicUsize::new(0));
        let r = replies.clone();
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                move |_reply| {
                    r.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            )
            .expect("query-get feature is ON in this test build");

        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(replies.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queryable_drop_auto_unregisters() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        {
            let _q = session.declare_queryable(
                "home/temp",
                QueryableOptions::default(),
                move |_q, responder| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                    responder.reply(b"22.5");
                },
            );
            session
                .query(
                    "home/temp",
                    QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                    &clock,
                    |_| {},
                    |_| {},
                )
                .expect("query-get feature is ON in this test build");
            assert_eq!(fired.load(Ordering::SeqCst), 1, "first query fires");
        } // Drop unregisters

        // Second query: no queryable matches.
        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "Drop auto-unregistered the queryable"
        );
    }

    #[test]
    fn queryable_undeclare_returns_true_and_skips_drop() {
        let (session, _driver) = build_session();
        let q = session
            .declare_queryable("home/temp", QueryableOptions::default(), |_q, _r| {})
            .expect("query-queryable feature is ON in this test build");
        assert!(q.undeclare(), "first undeclare returns true");
    }

    #[test]
    fn declare_queryable_with_locality_remote_skips_loopback_query() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let _q = session.declare_queryable(
            "home/temp",
            QueryableOptions::new().with_allowed_origin(Locality::Remote),
            move |_q, _r| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
            },
        );

        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Remote-only queryable must NOT fire on loopback query"
        );
    }

    #[test]
    fn declare_queryable_aliased_resolves_literal_at_declare_time() {
        let clock = TokioTime::new();
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let q = session
            .declare_queryable_aliased(
                7,
                None,
                QueryableOptions::default(),
                move |_q, responder| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                    responder.reply(b"22.5");
                },
            )
            .expect("declared mapping resolves");
        assert_eq!(q.keyexpr(), "home/temp");

        session
            .query(
                "home/temp",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                &clock,
                |_| {},
                |_| {},
            )
            .expect("query-get feature is ON in this test build");
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn declare_queryable_aliased_with_inline_suffix_composes_literal() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "home/temp")
            .expect("hardcoded canonical literal keyexpr");
        let q = session
            .declare_queryable_aliased(
                7,
                Some("/kitchen"),
                QueryableOptions::default(),
                |_q, _r| {},
            )
            .expect("declared mapping resolves");
        assert_eq!(q.keyexpr(), "home/temp/kitchen");
    }

    #[test]
    fn declare_queryable_aliased_unknown_mapping_returns_err() {
        let (session, _driver) = build_session();
        let err =
            session.declare_queryable_aliased(99, None, QueryableOptions::default(), |_q, _r| {});
        assert!(matches!(err, Err(QueryableAliasError::UnknownMapping(99))));
        assert_eq!(
            session.observer().lock().unwrap().queryables.len(),
            0,
            "no queryable registered on declare failure"
        );
    }

    #[test]
    fn queryable_alias_error_display_message_hints_remediation() {
        let err = QueryableAliasError::UnknownMapping(42);
        let msg = format!("{err}");
        assert!(msg.contains("42"));
        assert!(msg.contains("send_declare_keyexpr"));
    }

    // ── R248 LivelinessToken + LivelinessOptions + declare_token{,_aliased} ──

    #[test]
    fn liveliness_options_default_is_constructible() {
        // Empty options today (mirror zenoh-pico
        // z_liveliness_token_options_t::__dummy placeholder). The
        // contract is that both ::default() and ::new() construct
        // without arguments and are interchangeable; future fields
        // arrive via with_* setters per the R245/R246 pattern.
        let a = LivelinessOptions::default();
        let b = LivelinessOptions::new();
        // Empty struct → fmt::Debug round-trip is the cheapest
        // equivalence proxy without deriving PartialEq.
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn declare_token_returns_handle_with_keyexpr_and_id_zero() {
        let (session, _driver) = build_session();
        let token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            token.id(),
            0,
            "first allocation returns id=0 per zenoh-pico convention"
        );
        assert_eq!(token.keyexpr(), "liveliness/devA");
        // Options accessor — empty struct just confirms the borrow shape.
        let _: &LivelinessOptions = token.options();
    }

    #[test]
    fn declare_token_emits_exactly_one_reliable_wire_frame() {
        let (session, driver) = build_session();
        let _token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            driver.frame_count(),
            1,
            "declare emits one outbound Declare(DeclToken)"
        );
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::Reliable,
            "Declare frames travel on the reliable channel per send_declare_token contract",
        );
        // Hold the handle until end-of-scope; the drop is exercised in
        // a dedicated test below.
        std::mem::forget(_token);
    }

    #[test]
    fn declare_token_wire_frame_contains_decl_token_bytes() {
        use crate::session_glue::build_declare_token;
        let (session, driver) = build_session();
        let _token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");

        let expected =
            build_declare_token(0, /*mapping_id=*/ 0, Some("liveliness/devA")).encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame.windows(expected.len()).any(|w| w == expected),
            "Session::declare_token wire frame must contain the build_declare_token byte stream"
        );
        // Cancel drop emit — wire-shape test does not care about the
        // retraction path.
        std::mem::forget(_token);
    }

    #[test]
    fn declare_token_assigns_monotonic_ids_per_session() {
        let (session, _driver) = build_session();
        let t0 = session
            .declare_token("liveliness/x", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        let t1 = session
            .declare_token("liveliness/y", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        let t2 = session
            .declare_token("liveliness/z", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!((t0.id(), t1.id(), t2.id()), (0, 1, 2));
        // Avoid drop wire emits in this counter-only test.
        std::mem::forget(t0);
        std::mem::forget(t1);
        std::mem::forget(t2);
    }

    #[test]
    fn liveliness_token_drop_emits_undeclare_wire_frame() {
        let (session, driver) = build_session();
        {
            let _token = session
                .declare_token("liveliness/devA", LivelinessOptions::default())
                .expect("hardcoded canonical literal keyexpr");
            assert_eq!(driver.frame_count(), 1, "declare emit before scope end");
        }
        assert_eq!(
            driver.frame_count(),
            2,
            "Drop must emit Declare(UndeclToken) so peer liveliness subscribers see DELETE"
        );
        assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
    }

    #[test]
    fn liveliness_token_drop_wire_frame_contains_undecl_token_bytes() {
        use crate::session_glue::build_undeclare_token;
        let (session, driver) = build_session();
        {
            let _token = session
                .declare_token("liveliness/devA", LivelinessOptions::default())
                .expect("hardcoded canonical literal keyexpr");
            // Token id 0 was just allocated; drop will retract it.
        }
        let expected = build_undeclare_token(0).encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[1].0;
        assert!(
            frame.windows(expected.len()).any(|w| w == expected),
            "Drop must emit a Declare(UndeclToken) carrying the allocated token_id"
        );
    }

    #[test]
    fn liveliness_token_undeclare_consumes_handle_and_does_not_double_emit() {
        let (session, driver) = build_session();
        let token = session
            .declare_token("liveliness/devA", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(driver.frame_count(), 1);
        token.undeclare();
        assert_eq!(
            driver.frame_count(),
            2,
            "explicit undeclare emits the retraction"
        );
        // After undeclare(self), the handle is forgotten via
        // std::mem::forget, so Drop does NOT run — frame_count stays
        // at 2 even after the scope ends.
        assert_eq!(
            driver.frame_count(),
            2,
            "consumed handle must not emit a duplicate UndeclToken via Drop",
        );
    }

    #[test]
    fn declare_token_aliased_resolves_literal_at_declare_time() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        let token = session
            .declare_token_aliased(7, None, LivelinessOptions::default())
            .expect("declared mapping resolves");
        assert_eq!(
            token.keyexpr(),
            "liveliness/dev7",
            "aliased declare stores the resolved literal on the handle for introspection",
        );
        std::mem::forget(token);
    }

    #[test]
    fn declare_token_aliased_with_inline_suffix_composes_literal() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        let token = session
            .declare_token_aliased(7, Some("/sensor"), LivelinessOptions::default())
            .expect("declared mapping resolves");
        assert_eq!(token.keyexpr(), "liveliness/dev7/sensor");
        std::mem::forget(token);
    }

    #[test]
    fn declare_token_aliased_unknown_mapping_returns_err_without_wire_emit() {
        let (session, driver) = build_session();
        let err = session.declare_token_aliased(99, None, LivelinessOptions::default());
        assert!(
            matches!(err, Err(LivelinessAliasError::UnknownMapping(99))),
            "expected Err(UnknownMapping(99))",
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "no wire emit on unknown-mapping early-return path",
        );
    }

    #[test]
    fn declare_token_aliased_wire_frame_uses_alias_form() {
        // Aliased declare emits the bandwidth-efficient alias-form
        // wire (Declare(DeclToken) with WireexprLocal { id=mapping_id,
        // suffix }), matching zenoh-pico's
        // _z_declared_keyexpr_alias_to_wire behaviour when the caller
        // hands a previously-declared keyexpr to
        // z_liveliness_declare_token.
        use crate::session_glue::build_declare_token;
        let (session, driver) = build_session();
        // Send the keyexpr declare so the mapping table holds (7 ->
        // "liveliness/dev7"); first wire frame is this Declare(DeclKexpr).
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        let baseline_frames = driver.frame_count();

        let _token = session
            .declare_token_aliased(7, Some("/sensor"), LivelinessOptions::default())
            .expect("declared mapping resolves");

        assert_eq!(
            driver.frame_count(),
            baseline_frames + 1,
            "aliased declare emits exactly one Declare(DeclToken) frame",
        );
        let expected = build_declare_token(
            /*token_id=*/ 0,
            /*mapping_id=*/ 7,
            Some("/sensor"),
        )
        .encode_to_vec();
        let token_frame = &driver.frames.lock().unwrap()[baseline_frames].0;
        assert!(
            token_frame.windows(expected.len()).any(|w| w == expected),
            "wire frame must carry alias-form DeclToken bytes (mapping_id=7, suffix=/sensor)",
        );
        std::mem::forget(_token);
    }

    #[test]
    fn liveliness_alias_error_display_message_hints_remediation() {
        let err = LivelinessAliasError::UnknownMapping(42);
        let msg = format!("{err}");
        assert!(msg.contains("42"));
        assert!(msg.contains("send_declare_keyexpr"));
    }

    // ── R282 declare_liveliness_subscriber_aliased — mirrors the
    // R245 declare_subscriber_aliased and R248 declare_token_aliased
    // test patterns: resolve-at-declare-time, alias-form wire emit,
    // mapping-retract survival, and error-shape Display. ───────────

    #[test]
    fn declare_liveliness_subscriber_aliased_resolves_literal_at_declare_time() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        mark_session_established(&session);
        let sub = session
            .declare_liveliness_subscriber_aliased(
                7,
                None,
                LivelinessSubscriberOptions::default(),
                |_| {},
            )
            .expect("declared mapping resolves");
        assert_eq!(
            sub.keyexpr(),
            "liveliness/dev7",
            "aliased declare stores the resolved literal on the handle for introspection",
        );
        // Slot is keyed by the freshly-allocated interest id and stores
        // the resolved literal for inbound DeclToken matching.
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .keyexpr(sub.interest_id()),
            Some("liveliness/dev7"),
            "slot stores resolved literal for keyexpr-pattern matching",
        );
    }

    #[test]
    fn declare_liveliness_subscriber_aliased_with_inline_suffix_composes_literal() {
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        mark_session_established(&session);
        let sub = session
            .declare_liveliness_subscriber_aliased(
                7,
                Some("/sensor"),
                LivelinessSubscriberOptions::default(),
                |_| {},
            )
            .expect("declared mapping resolves");
        assert_eq!(sub.keyexpr(), "liveliness/dev7/sensor");
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .keyexpr(sub.interest_id()),
            Some("liveliness/dev7/sensor"),
        );
    }

    #[test]
    fn declare_liveliness_subscriber_aliased_unknown_mapping_returns_err_without_wire_emit() {
        let (session, driver) = build_session();
        let err = session.declare_liveliness_subscriber_aliased(
            99,
            None,
            LivelinessSubscriberOptions::default(),
            |_| {},
        );
        assert!(
            matches!(err, Err(LivelinessSubscriberAliasError::UnknownMapping(99))),
            "expected Err(UnknownMapping(99))",
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "no wire emit on unknown-mapping early-return path",
        );
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .slot_count(),
            0,
            "no slot registered on declare failure",
        );
    }

    #[test]
    fn declare_liveliness_subscriber_aliased_wire_frame_uses_alias_form() {
        // Aliased declare emits the bandwidth-efficient alias-form
        // wire (Interest with WireexprLocal { id=mapping_id,
        // suffix }), matching zenoh-pico's
        // _z_n_interest_encode behaviour when the caller hands a
        // previously-declared keyexpr to z_liveliness_declare_subscriber.
        use crate::session_glue::build_interest_liveliness_subscriber;
        let (session, driver) = build_session();
        // Install the keyexpr mapping (7 -> "liveliness/dev7"); first
        // wire frame is this Declare(DeclKexpr).
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        mark_session_established(&session);
        let baseline_frames = driver.frame_count();

        let _sub = session
            .declare_liveliness_subscriber_aliased(
                7,
                Some("/sensor"),
                LivelinessSubscriberOptions::default(),
                |_| {},
            )
            .expect("declared mapping resolves");

        assert_eq!(
            driver.frame_count(),
            baseline_frames + 1,
            "aliased declare emits exactly one Interest frame",
        );
        let expected = build_interest_liveliness_subscriber(
            /*interest_id=*/ 0,
            /*history=*/ false,
            /*mapping_id=*/ 7,
            Some("/sensor"),
        )
        .encode_to_vec();
        let interest_frame = &driver.frames.lock().unwrap()[baseline_frames].0;
        assert!(
            interest_frame
                .windows(expected.len())
                .any(|w| w == expected),
            "wire frame must carry alias-form Interest bytes (mapping_id=7, suffix=/sensor)",
        );
    }

    #[test]
    fn declare_liveliness_subscriber_aliased_survives_mapping_retract_after_declare() {
        // Mapping resolved at declare time; later send_undeclare_kexpr
        // must not affect the already-registered slot (R245 one-shot
        // resolution contract). The slot still holds the resolved
        // literal, matching is unaffected.
        let (session, _driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        mark_session_established(&session);
        let sub = session
            .declare_liveliness_subscriber_aliased(
                7,
                None,
                LivelinessSubscriberOptions::default(),
                |_| {},
            )
            .expect("declared mapping resolves");
        let interest_id = sub.interest_id();

        // Retract the mapping.
        session.actions().send_undeclare_kexpr(7);

        // Slot still keyed against the resolved literal.
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .keyexpr(interest_id),
            Some("liveliness/dev7"),
            "slot survives mapping retract — resolution is one-shot at declare time",
        );
    }

    // ── R283 Established gate — pre-Established declines, ordering
    // rule (UnknownMapping precedes NotEstablished), and predicate
    // behavior. ────────────────────────────────────────────────────

    #[test]
    fn declare_liveliness_subscriber_aliased_pre_established_returns_err_without_wire_emit() {
        // Session-FSM has not yet entered Established. The Interest
        // would be emitted into a mid-handshake session; the peer's
        // remote-interests table is empty so the frame would be
        // silently discarded. R283 surfaces the bug at the API
        // boundary instead.
        let (session, driver) = build_session();
        session
            .actions()
            .send_declare_keyexpr(7, "liveliness/dev7")
            .expect("hardcoded canonical literal keyexpr");
        let baseline_frames = driver.frame_count();
        // NOTE: NO mark_session_established(&session) — that's the
        // condition under test.
        let err = session.declare_liveliness_subscriber_aliased(
            7,
            None,
            LivelinessSubscriberOptions::default(),
            |_| {},
        );
        assert!(
            matches!(err, Err(LivelinessSubscriberAliasError::NotEstablished)),
            "expected Err(NotEstablished) when session is mid-handshake",
        );
        assert_eq!(
            driver.frame_count(),
            baseline_frames,
            "no wire emit on pre-Established early-return path",
        );
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .slot_count(),
            0,
            "no slot registered when the Established gate refuses the declare",
        );
    }

    #[test]
    fn declare_liveliness_subscriber_aliased_unknown_mapping_takes_precedence_over_not_established()
    {
        // Pin the variant ordering: when the session is pre-Established
        // AND the mapping is unknown, the caller sees UnknownMapping
        // (the bug-class error) — not NotEstablished (the transient
        // state). Retrying post-Established with the same bad mapping
        // would still fail; surfacing UnknownMapping first short-
        // circuits the futile retry loop.
        let (session, driver) = build_session();
        // No send_declare_keyexpr — mapping 99 is genuinely unknown.
        // No mark_session_established — Established is also false.
        let err = session.declare_liveliness_subscriber_aliased(
            99,
            None,
            LivelinessSubscriberOptions::default(),
            |_| {},
        );
        assert!(
            matches!(err, Err(LivelinessSubscriberAliasError::UnknownMapping(99))),
            "unknown mapping must precede the NotEstablished gate",
        );
        assert_eq!(driver.frame_count(), 0, "no wire emit");
    }

    #[test]
    fn is_established_predicate_flips_after_record_established_at() {
        // The Session::is_established proxy reads the same field the
        // record_established_at Lua action sets at Established.onentry.
        // A freshly-built session is mid-handshake (established_at =
        // None); the test fixture flips the field to verify the
        // predicate tracks it.
        let (session, _driver) = build_session();
        assert!(
            !session.is_established(),
            "freshly-built session is pre-Established (no record_established_at fired)",
        );
        assert!(
            !session.actions().is_established(),
            "Session::is_established proxy reads the same source",
        );
        mark_session_established(&session);
        assert!(
            session.is_established(),
            "post record_established_at, is_established() is true",
        );
        assert!(
            session.actions().is_established(),
            "actions-layer predicate flips in lockstep",
        );
    }

    #[test]
    fn liveliness_subscriber_alias_error_display_message_hints_remediation() {
        // R282 UnknownMapping variant.
        let err = LivelinessSubscriberAliasError::UnknownMapping(42);
        let msg = format!("{err}");
        assert!(msg.contains("42"));
        assert!(msg.contains("send_declare_keyexpr"));

        // R283 NotEstablished variant.
        let err = LivelinessSubscriberAliasError::NotEstablished;
        let msg = format!("{err}");
        assert!(msg.contains("not yet Established"));
        assert!(msg.contains("is_established"));
    }

    #[test]
    fn liveliness_token_id_counter_independent_of_request_id() {
        // Token id space is a separate AtomicU64 from the request id
        // counter (R239) — declaring a token before any query must
        // still start the token counter at 0 regardless of how many
        // request ids were burned, and vice versa. This pins the
        // independent-counter invariant documented on
        // SessionLinkActions::next_outbound_token_id.
        let (session, _driver) = build_session();
        // Burn three request ids first.
        let r0 = session.actions().alloc_next_request_id();
        let r1 = session.actions().alloc_next_request_id();
        let r2 = session.actions().alloc_next_request_id();
        assert_eq!((r0, r1, r2), (0, 1, 2));
        // Token allocation still starts from 0.
        let t = session
            .declare_token("liveliness/x", LivelinessOptions::default())
            .expect("hardcoded canonical literal keyexpr");
        assert_eq!(
            t.id(),
            0,
            "token id counter independent from request id counter"
        );
        std::mem::forget(t);
    }
}
