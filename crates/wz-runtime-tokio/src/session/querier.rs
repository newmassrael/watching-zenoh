// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Querier handle cluster split out of `session/mod.rs` (pure
//! refactor): [`QueryOptions`], the [`Querier`] / [`QuerierAliased`]
//! handles, [`MatchingStatus`], [`QueryAliasError`],
//! [`LivelinessGetOptions`], and [`LivelinessGetError`]. The parent
//! module re-exports the public types via `pub use querier::*;` so the
//! path `wz_runtime_tokio::session::Querier` etc. is unchanged.

use super::*;

/// R239 — options bundle for [`Session::query`]. Mirrors zenoh-pico's
/// `z_get_options_t` (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`
/// 487-497, defaulted by `z_get_options_default`
/// `vendor/zenoh-pico/src/api/api.c:1723`).
///
/// At R239 the *load-bearing* knob is `allowed_destination`: it
/// selects which branches of [`Session::query`] actually run (wire,
/// loopback, or both). R240 wired the layered `RequestQueryBuilder`
/// through `Session::query` -> `send_request_query_with_meta` (via
/// `QueryOptions::query_metadata` -> `build_request_query_with_meta`),
/// so `target` / `consolidation` / `attachment` / `parameters` /
/// `source_info` / `timeout_ms` now propagate on the outbound Query.
/// `payload` / `encoding` stay captured as future-additive slots —
/// R311y248 landed the Q_B / Q_E codec extension itself
/// (`RequestQueryBuilder::query_value`), but threading `QueryOptions` →
/// `build_request_query_with_meta` is still pending, so they do not yet
/// propagate on the outbound Query. The loopback path's in-process
/// [`crate::query::QueryableRegistry::local_query`] still only inspects the
/// keyexpr.
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
    /// callback. The Q_B codec builder landed R311y248
    /// (`RequestQueryBuilder::query_value` encodes the value ext 0x03);
    /// what is still pending is threading this captured `payload` through
    /// `send_request_query_with_meta` onto that builder, plus loopback's
    /// `Query` surfacing `payload` to the responder callback. The slot is
    /// reserved so that a follow-up threading round lands it
    /// without an API break.
    pub payload: Option<Vec<u8>>,
    /// Optional encoding metadata for the Query body. Mirror of
    /// `z_get_options_t.encoding`. R239 carry on both wire and
    /// loopback propagation — see `payload`.
    pub encoding: Option<EncodingHint>,
    /// Optional Query-level attachment blob. Mirror of
    /// `z_get_options_t.attachment`. Propagated on the outbound Query
    /// since R240 (`build_request_query_with_meta` ->
    /// `RequestQueryBuilder::query_attachment`); an empty blob elides
    /// the ext.
    pub attachment: Option<Vec<u8>>,
    /// Optional Query selector parameters (the `_sn=START..&_max=N`
    /// URL-style selector after `?`). `None` (or empty) elides the `Q_P`
    /// flag + params slice on the outbound Query body. What an
    /// `ext-pubsub-advanced-subscriber` recovery / history GET carries so
    /// the advanced cache's `answer_from_ring` filters its ring. Mirror of
    /// zenoh's `z_get(keyexpr, parameters, ..)`.
    pub parameters: Option<Vec<u8>>,
    /// Optional Query-level source-info (querier identity: zid / eid /
    /// sn) stamped on the outbound Query body (ext 0x01 ZBUF). `None`
    /// elides the ext. Symmetric to `PublishOptions::source_info`, and
    /// foreign-proven on the QUERY carrier — R311y244
    /// (`wz_query_source_info_to_pico_zqueryable`, pico
    /// `z_query_source_info` decodes `eid: 77 sn: 88`).
    pub source_info: Option<SourceInfo>,
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

    /// Attach a Query-body payload. The Q_B codec builder landed R311y248
    /// (`RequestQueryBuilder::query_value` encodes it); wire + loopback
    /// PROPAGATION (threading this captured payload through
    /// `send_request_query_with_meta` onto the builder, and loopback's
    /// `Query` surfacing it to the responder callback) lands in a follow-up
    /// threading round.
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

    /// Attach a Query-level attachment blob. Gated on `query-attachment`
    /// (wire-data helper): the get path threads this into the Query
    /// attachment ext only when query-attachment is composed, so the
    /// setter gates with it. The field stays (struct stability).
    #[cfg(feature = "query-attachment")]
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// Attach Query selector parameters (the `_sn=START..&_max=N` URL-style
    /// selector). Gated on `query-selector-parameters` (the same wire feature
    /// the receive side gates the inbound parameters projection on, query.rs):
    /// the get path threads this onto the Query body's `Q_P` flag + params
    /// slice only when the feature is composed, so the setter gates with it.
    /// The field stays (struct stability). What an
    /// `ext-pubsub-advanced-subscriber` recovery GET carries so the advanced
    /// cache's `answer_from_ring` filters its ring.
    #[cfg(feature = "query-selector-parameters")]
    pub fn with_parameters(mut self, parameters: Vec<u8>) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Stamp the querier's source-info (zid / eid / sn) on the outbound
    /// Query body (ext 0x01 ZBUF). Gated on `query-source-info`
    /// (wire-data helper): the get path threads this into the Query
    /// source-info ext only when the feature is composed, so the setter
    /// gates with it. The field stays (struct stability). Symmetric to
    /// `PublishOptions::with_source_info`.
    #[cfg(feature = "query-source-info")]
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
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
    pub(super) fn expected_finals(&self) -> u32 {
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
    /// not threaded here yet — the Q_B / Q_E codec slot landed R311y248
    /// (`RequestQueryBuilder::query_value`), but threading `QueryOptions`
    /// onto it is a follow-up round, so they stay captured on
    /// [`QueryOptions`] as future-additive carries.
    ///
    /// Clones owned slots (attachment Vec); the expected query path
    /// performs one extraction per Session::query call so the
    /// allocation cost is amortised against the wire frame's existing
    /// copies. Mirrors R233's
    /// [`PublishOptions::push_metadata`] pattern verbatim.
    ///
    /// R311o — private helper, cfg-gated like [`Self::expected_finals`].
    #[cfg(feature = "query-get")]
    pub(super) fn query_metadata(&self) -> QueryMetadata {
        QueryMetadata {
            target: self.target,
            consolidation: self.consolidation,
            attachment: self.attachment.clone(),
            parameters: self.parameters.clone(),
            source_info: self.source_info.clone(),
            timeout_ms: self.timeout_ms,
        }
    }
}

/// liveliness-get — options for [`Session::liveliness_get`]. Mirrors
/// zenoh-pico's `z_liveliness_get_options_t` (currently the timeout
/// only). `timeout_ms == 0` is the "no timeout" sentinel (the pending
/// get never expires; it is removed only by the peer's `DeclFinal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LivelinessGetOptions {
    /// Snapshot timeout in milliseconds. `0` = no timeout. A non-zero
    /// value arms the driver-loop sweep to fire `on_final` if the peer
    /// never terminates the snapshot, so the pending slot cannot leak.
    pub timeout_ms: u32,
}

impl LivelinessGetOptions {
    /// Default options — `timeout_ms = 0` (no timeout). Mirrors
    /// zenoh-pico's `z_liveliness_get_options_default`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set the snapshot `timeout_ms`.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// liveliness-get — typed error returned by [`Session::liveliness_get`].
/// Mirror of the [`LivelinessSubscriberAliasError`] family on the
/// snapshot-get side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelinessGetError {
    /// The session-FSM has not yet entered `Established`. A CURRENT
    /// liveliness `Interest` emitted mid-handshake is discarded by the
    /// peer (no `remote-interests` table entry yet), so the one-shot
    /// snapshot would hang until timeout. Poll [`Session::is_established`]
    /// before retrying. Enforced here (unlike the literal
    /// `declare_liveliness_subscriber`) because a one-shot get cannot be
    /// transparently re-fired.
    NotEstablished,
    /// The `liveliness-get` feature is OFF at compile time; the
    /// wire-emit and observer-dispatch paths are elided, so no snapshot
    /// can complete on this build. Caller must feature-detect at the
    /// consumer-crate level before relying on a liveliness get.
    FeatureDisabled,
    /// The resolved keyexpr exceeded the declared bounded-codec capacity
    /// (`MAX_KEYEXPR_BYTES`) while being copied into the no-alloc owned
    /// `Interest` mirror, so no wire bytes were emitted. Semantic
    /// projection of the codec-layer reject.
    ExceedsCapacity,
    /// B5b-2b (R311nc) — a liveliness get was attempted on a session whose
    /// transport is not unicast. The interest/get path needs the per-peer
    /// `SessionLinkActions` handshake bundle, which a multicast session has
    /// no analogue of; the `Session::actions()` projection rejects with
    /// `SendWireError::UnsupportedVariant`. Distinct from `NotEstablished`
    /// (a unicast session still mid-handshake — that one resolves; this
    /// one never will on multicast).
    RequiresUnicast,
}

impl std::fmt::Display for LivelinessGetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivelinessGetError::NotEstablished => write!(
                f,
                "LivelinessGetError: session-FSM not yet Established; wait for \
                 Session::is_established() to flip to true before retrying the get"
            ),
            LivelinessGetError::FeatureDisabled => write!(
                f,
                "LivelinessGetError: liveliness-get feature is OFF at compile time; \
                 the wire-emit and observer-dispatch paths are elided, so no \
                 snapshot can complete on this build"
            ),
            LivelinessGetError::ExceedsCapacity => write!(
                f,
                "LivelinessGetError: keyexpr exceeded the declared codec capacity \
                 (MAX_KEYEXPR_BYTES); the Interest was not emitted"
            ),
            LivelinessGetError::RequiresUnicast => write!(
                f,
                "LivelinessGetError: liveliness get requires a unicast transport; \
                 this session holds a multicast transport (no interest handshake \
                 bundle); the Interest was not emitted"
            ),
        }
    }
}

impl std::error::Error for LivelinessGetError {}

impl From<SendWireError> for LivelinessGetError {
    fn from(e: SendWireError) -> Self {
        match e {
            SendWireError::Codec(_) => LivelinessGetError::ExceedsCapacity,
            SendWireError::FeatureDisabled => LivelinessGetError::FeatureDisabled,
            // F2 — the reconnect window IS a not-yet-(re)Established
            // session; the existing variant names the same contract.
            SendWireError::TransportUnavailable => LivelinessGetError::NotEstablished,
            SendWireError::UnsupportedVariant => LivelinessGetError::RequiresUnicast,
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
    /// W3 (SCE pin 7a94d084a) — a query field (keyexpr suffix, selector
    /// parameters, or attachment) exceeded its declared bounded-codec
    /// capacity while being copied into the no-alloc owned
    /// `Request(Query)` mirror, so no wire bytes were emitted. Semantic
    /// projection of the codec-layer reject (keeps the SCE codec type
    /// off the public surface); the generic name avoids over-claiming
    /// which field overflowed, matching [`PublishError::ExceedsCapacity`].
    ExceedsCapacity,
    /// F2 — the transport is not currently accepting data sends (link
    /// released or reconnecting; Established not re-entered). The
    /// Request(Query) was not emitted; retry after the session
    /// re-establishes (zenoh-pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE`).
    TransportUnavailable,
    /// B5b-2b (R311nc) — an aliased query was attempted on a session whose
    /// transport is not unicast. The query path needs the per-peer
    /// `SessionLinkActions` handshake bundle (and the outbound mapping
    /// table the alias resolves against), which a multicast session has no
    /// analogue of; the `Session::actions()` projection rejects with
    /// `SendWireError::UnsupportedVariant`. No wire bytes were emitted.
    RequiresUnicast,
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
            QueryAliasError::ExceedsCapacity => write!(
                f,
                "QueryAliasError: a query field (keyexpr / parameters / attachment) \
                 exceeded the declared codec capacity; the Request(Query) was not emitted"
            ),
            QueryAliasError::TransportUnavailable => write!(
                f,
                "QueryAliasError: transport not available (link released or \
                 reconnecting); the Request(Query) was not emitted — retry after \
                 the session re-establishes"
            ),
            QueryAliasError::RequiresUnicast => write!(
                f,
                "QueryAliasError: aliased query requires a unicast transport; this \
                 session holds a multicast transport (no query handshake bundle / \
                 outbound mapping table); the Request(Query) was not emitted"
            ),
        }
    }
}

impl std::error::Error for QueryAliasError {}

impl From<SendWireError> for QueryAliasError {
    fn from(e: SendWireError) -> Self {
        match e {
            SendWireError::Codec(_) => QueryAliasError::ExceedsCapacity,
            SendWireError::FeatureDisabled => QueryAliasError::FeatureDisabled,
            SendWireError::TransportUnavailable => QueryAliasError::TransportUnavailable,
            SendWireError::UnsupportedVariant => QueryAliasError::RequiresUnicast,
        }
    }
}

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
// R311cr — R267 helper cascade. Manual Clone impl avoids derive
// auto-added `R: Clone` bound (Runtime does not require Clone; inner
// Session<R> has manual Clone too).
#[non_exhaustive]
pub struct Querier<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T, Unicast>,
    pub(super) keyexpr: String,
    pub(super) options: QueryOptions,
}

impl<R: SessionRuntime, T: TimeSource> Clone for Querier<R, T> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            keyexpr: self.keyexpr.clone(),
            options: self.options.clone(),
        }
    }
}

impl<R: SessionRuntime, T: TimeSource> Querier<R, T> {
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
    pub fn get(
        &self,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        // R311cw — clock fold-in: `Session::query` now reads the Session-
        // owned `Arc<T>` clock internally, so this delegate no longer
        // threads a `clock: &T` argument.
        self.session
            .query(&self.keyexpr, self.options.clone(), on_reply, on_final)
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
        // R311dd — observer access via R::with_mutex_mut closure form.
        // Replaces the AP-only `.lock()` + PoisonError::into_inner
        // recovery pattern; per-profile poison-recovery semantics now
        // live inside the Runtime impl.
        #[cfg(feature = "declare-queryable")]
        let matching = R::with_mutex_mut(&self.session.observer, |obs| {
            obs.remote_queryables.has_matching(&self.keyexpr)
        });
        #[cfg(not(feature = "declare-queryable"))]
        let matching = false;
        MatchingStatus { matching }
    }

    /// R311kh — callback counterpart of [`Self::get_matching_status`]
    /// (zenoh-pico querier matching listener, `Z_FEATURE_MATCHING`):
    /// `callback` fires on every matching-status TRANSITION of this
    /// querier's keyexpr against the remote QUERYABLE set. Registration
    /// itself never fires (pico transition-only semantics; poll
    /// [`Self::get_matching_status`] for the current value).
    ///
    /// R311kz — DEFERRED FIRE (the F-6 fix; supersedes the R311kj
    /// callback constraint): the registry sink only stages the
    /// transition; `callback` runs from
    /// [`Session::drain_deferred_fires`] AFTER the observer lock drops
    /// and may re-enter any observer-locking session API (see
    /// `Publisher::declare_matching_listener` for the full contract).
    ///
    /// R310.5c / R311g1 — signature always visible; typed
    /// `Err(FeatureDisabled)` when `session-matching` or the backing
    /// `declare-queryable` registry is off.
    pub fn declare_matching_listener(
        &self,
        callback: impl FnMut(MatchingStatus) + Send + 'static,
    ) -> Result<MatchingListener<R, T>, MatchingListenerError> {
        #[cfg(all(feature = "session-matching", feature = "declare-queryable"))]
        {
            use super::matching_listener::{BoxedMatchingCallback, MatchingListenerCell};
            let erased: BoxedMatchingCallback = Box::new(callback);
            let cell: MatchingListenerCell<R> =
                wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
            let queue = self.session.fires.clone();
            let cell_for_sink = cell.clone();
            let sink = wz_session_core::declare::matching::BoxedMatchingSink::new(move |m| {
                let cell = cell_for_sink.clone();
                queue.stage(Box::new(move || {
                    cell.invoke(move |cb| cb(MatchingStatus { matching: m }));
                }));
            });
            let id = R::with_mutex_mut(&self.session.observer, |obs| {
                obs.remote_queryables
                    .declare_matching_listener(&self.keyexpr, sink)
            });
            Ok(MatchingListener {
                session: self.session.clone(),
                id,
                scope: MatchingScope::RemoteQueryables,
                cell,
            })
        }
        #[cfg(not(all(feature = "session-matching", feature = "declare-queryable")))]
        {
            let _ = callback;
            Err(MatchingListenerError::FeatureDisabled)
        }
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
// R311cr — R267 helper cascade. Manual Clone impl mirrors Querier
// pattern (no derive auto-added R: Clone bound on Runtime).
#[non_exhaustive]
pub struct QuerierAliased<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T, Unicast>,
    pub(super) mapping_id: u64,
    pub(super) inline_suffix: Option<String>,
    pub(super) options: QueryOptions,
}

impl<R: SessionRuntime, T: TimeSource> Clone for QuerierAliased<R, T> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            mapping_id: self.mapping_id,
            inline_suffix: self.inline_suffix.clone(),
            options: self.options.clone(),
        }
    }
}

impl<R: SessionRuntime, T: TimeSource> QuerierAliased<R, T> {
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
    pub fn get(
        &self,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        // R311cw — clock fold-in: delegate path no longer threads
        // `clock: &T`; `Session::query_aliased_auto` reads `self.clock`.
        self.session.query_aliased_auto(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            self.options.clone(),
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
        // R311dd — observer access via R::with_mutex_mut closure form.
        #[cfg(feature = "declare-queryable")]
        let matching = R::with_mutex_mut(&self.session.observer, |obs| {
            obs.remote_queryables.has_matching(&_effective_keyexpr)
        });
        #[cfg(not(feature = "declare-queryable"))]
        let matching = false;
        Ok(MatchingStatus { matching })
    }
}

#[cfg(all(test, feature = "query-get", feature = "query-selector-parameters"))]
mod tests {
    use super::*;

    /// R311y77 — `QueryOptions::with_parameters` threads onto the
    /// `query_metadata` parameters slot, so a recovery GET's `_sn`-range
    /// selector reaches the wire builder (`build_request_query_with_meta` ->
    /// `Q_P`). The QueryOptions -> QueryMetadata half of the recovery-GET
    /// selector path (the wire half is locked in request_build.rs).
    #[test]
    fn with_parameters_threads_into_query_metadata() {
        let opts = QueryOptions::get().with_parameters(b"_sn=1..".to_vec());
        let meta = opts.query_metadata();
        assert_eq!(meta.parameters.as_deref(), Some(b"_sn=1..".as_slice()));
        assert!(!meta.is_empty(), "parameters make the metadata non-empty");
    }
}
