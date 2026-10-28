// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one query asks for, independent of the runtime that sends it: `QueryOptions`, the
//! platform default timeout (`DEFAULT_QUERY_TIMEOUT_MS`) and the consolidation a requester
//! puts on the wire and installs at its sink (`wire_consolidation`, `resolved_consolidation`).
//!
//! Moved down from `wz-runtime-tokio` (`session::querier` and `query`, which re-export it), so
//! a session on any runtime reads one set of rules: the C ABI's cooperative engine asks its
//! queries with the same options, deadlines, consolidation and wire metadata as the tokio
//! engine. The three request slots a build may not honour (`query-target`, `query-timeout`,
//! `query-consolidation`) and asking at all (`query-get`) are this crate's features now; the
//! runtime's same-named features forward to them, so every gate below means what it meant
//! there.

use alloc::vec::Vec;

use crate::locality::Locality;
#[cfg(feature = "query-get")]
use crate::metadata::QueryMetadata;
use crate::qos::{CongestionControl, Priority};
use crate::query_mode::{ConsolidationMode, QueryTarget};
// The two consumers are `with_accept_replies` (`query-selector-parameters`) and
// `effective_accept_replies` (`query-get`); with neither composed the name is unused, which is
// the cfg-gated-import shape Layer C1cf exists to catch.
#[cfg(any(feature = "query-get", feature = "query-selector-parameters"))]
use crate::reply_acceptance::ReplyKeyExpr;
use crate::sample::{EncodingHint, QosLevel, SourceInfo};

/// R311y326 — the platform default per-query timeout, in milliseconds.
///
/// Mirrors zenoh-pico's `Z_GET_TIMEOUT_DEFAULT`
/// (`vendor/zenoh-pico/include/zenoh-pico/config.h.in:208`) and zenoh's
/// `queries_default_timeout` (`zenoh-config-1.5.0/src/defaults.rs:151`). Both
/// upstreams apply it at EVERY query-issuing surface and NEITHER offers a
/// never-expire client query: pico rewrites `timeout_ms == 0` to this value
/// before it builds the message (`z_get` `api/api.c:1762-1763`, `z_querier`
/// `:1830-1831`, `z_liveliness_get` `api/liveliness.c:132-133`), and zenoh
/// eagerly fills `GetBuilder::timeout: Duration` from config and then emits
/// `ext_timeout: Some(..)` unconditionally (`api/session.rs:2314`).
///
/// Deliberately NOT inside either `effective_timeout_ms` accessor: the z_get
/// accessor is `query-get`-gated and the liveliness leg composes WITHOUT
/// `query-get` (the `liveliness-get-only` subset), so a constant scoped to one
/// atom's gate would be absent on the other's lane. One constant, one resolution
/// site per atom — the same split zenoh has, where `queries_default_timeout()` is
/// a shared defaulting convenience consulted by three otherwise-independent
/// surfaces (R311y325 §LEG B).
///
/// NOT unified with the router relay's identical 10s
/// (`wz-runtime-tokio`'s `LinkstateForwarder::DEFAULT_QUERY_TIMEOUT`). zenoh keeps
/// ONE config key for both legs (`tables.rs` router-side, `conf` client-side), so
/// two constants for one concept IS a divergence — a NAMED residual, because
/// unifying them means deciding whether wz grows a client config plane.
///
/// Gated to the union of its two consumers — the z_get accessor
/// ([`QueryOptions::effective_timeout_ms`], `query-timeout`) and the liveliness
/// accessor (`wz-runtime-tokio`'s `LivelinessGetOptions::effective_timeout_ms`,
/// `liveliness-get`). A `query-get`-only build (both atoms off) has no reader, so
/// an ungated const would be `-D dead-code`.
#[cfg(any(feature = "query-timeout", feature = "liveliness-get"))]
pub const DEFAULT_QUERY_TIMEOUT_MS: u32 = 10_000;

/// Round 2442 (open-debt item 675) — WHAT A REQUESTER PUTS ON THE WIRE for
/// consolidation, as a free function its callers share.
///
/// # Why this is public and not a method
///
/// R311y836/y837 built the resolution and put it behind
/// `QueryOptions::wire_consolidation`, which only a caller that HAS a
/// `QueryOptions` reaches. `wz-ap-demo`'s `--query` hand-builds a
/// `metadata::QueryMetadata` and calls
/// `send_request_query_with_meta` directly, so it rode the `Option::None`
/// default and transmitted no consolidation byte at all — measured, and named
/// as a residual on this atom since R311y837.
///
/// The fix is not for the demo to resolve the mode itself. Both upstreams keep
/// this rule in exactly one place (zenoh inside `get()`, pico inside
/// `_z_query_encode`'s caller), and a second copy in a demo is the shape this
/// workspace spends rounds removing. So the judgement lives HERE and
/// `QueryOptions` is one of its callers.
///
/// # The feature gate is INSIDE, deliberately
///
/// `query-consolidation` is the consolidation capability, and R311y317 settled
/// where its gate belongs: the last hop that knows. A caller that had to write
/// `#[cfg(feature = "query-consolidation")]` itself would be a second place the
/// OFF-arm decision is made — and `wz-ap-demo` cannot write it at all, because
/// the key is not in that crate's manifest. Callers pass their inputs and get
/// the honest answer for the build they are in.
///
/// `None` out means ELIDE the field, which both upstreams' decoders read as
/// `Auto`. On an OFF build that is the truthful statement: this binary
/// consolidates nothing, so it must not claim a mode it cannot honour.
pub fn wire_consolidation(
    requested: Option<ConsolidationMode>,
    parameters: Option<&[u8]>,
) -> Option<ConsolidationMode> {
    #[cfg(feature = "query-consolidation")]
    {
        Some(resolved_consolidation(requested, parameters))
    }
    #[cfg(not(feature = "query-consolidation"))]
    {
        let _ = (requested, parameters);
        None
    }
}

/// Round 2442 (open-debt item 675) — the same resolution, for the LOCAL sink.
///
/// The wire and the sink must be told the same thing or a query consolidates
/// one way and reports another, which is why they share this function rather
/// than each calling [`ConsolidationMode::resolve_auto`] with their own idea of
/// the inputs. zenoh does the same thing for the same reason: it resolves `Auto`
/// ONCE and feeds both.
///
/// Differs from [`wire_consolidation`] only in the OFF arm, and the difference
/// is not cosmetic: the wire ELIDES (no claim), while the sink must still be
/// handed a mode, and on a build with no consolidation capability that mode is
/// `None` — pass everything through.
pub fn resolved_consolidation(
    requested: Option<ConsolidationMode>,
    parameters: Option<&[u8]>,
) -> ConsolidationMode {
    #[cfg(feature = "query-consolidation")]
    {
        let params = parameters
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("");
        ConsolidationMode::resolve_auto(requested, params)
    }
    #[cfg(not(feature = "query-consolidation"))]
    {
        let _ = (requested, parameters);
        ConsolidationMode::None
    }
}

/// R239 — the options of one query. Mirrors zenoh-pico's `z_get_options_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/types.h` 487-497, defaulted by
/// `z_get_options_default` `vendor/zenoh-pico/src/api/api.c:1723`).
///
/// The *load-bearing* knob is `allowed_destination`: it selects which branches
/// of a session's query actually run (wire, loopback, or both). R240 wired the
/// layered `RequestQueryBuilder` through `QueryOptions::query_metadata` ->
/// `build_request_query_with_meta`, so `target` / `consolidation` /
/// `attachment` / `parameters` / `source_info` / `timeout_ms` propagate on the
/// outbound Query. R311y250 extended that threading to `payload` / `encoding`:
/// they collapse into the [`QueryMetadata::value`](crate::metadata::QueryMetadata::value)
/// wire unit (`RequestQueryBuilder::query_value`, value ext 0x03; codec landed
/// R311y248), so a querier's attached value propagates on the outbound Query.
/// R311y252 closed the last gap: the loopback path's in-process
/// `QueryableRegistry::local_query` surfaces `parameters` / `attachment` /
/// `source_info` / `value` to a SessionLocal queryable identically to the wire
/// path — the runtime's `build_loopback_query` reuses the same
/// `build_request_query_with_meta` SSOT and lifts out its Query body, so both
/// origins carry the same ext chain. `consolidation` is applied at the
/// requester's sink, on both origins; `target` is applied to the loopback's
/// queryables as zenoh applies it (see the field).
///
/// `#[non_exhaustive]` so future rounds add fields without breaking callers.
/// Construct via [`QueryOptions::get`] (or `default`) plus optional `with_*`
/// setters — never struct-literal externally.
///
/// R311o — type-ungated per `feedback_signature_stability`. Struct + builders
/// are always defined regardless of the `query-get` family; the per-feature
/// setters (`with_target`, `with_consolidation`, `with_timeout_ms`) keep their
/// signature stable across builds via body cfg-gates that silently no-op when
/// the underlying feature is off (the field stays at its `None` / zero sentinel
/// which is the equivalent wire-elision shape).
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
    /// sets the Q_T flag and emits the target byte per [`QueryTarget`].
    ///
    /// R311y321 — the claim "Loopback ignores target (single-host
    /// fan-out has no selection axis)" is REFUTED, by direct read of
    /// zenoh 1.5.0 rather than by argument: `Session::handle_query`
    /// applies `(queryable.complete || target != AllComplete)`
    /// UNCONDITIONALLY — its `local` flag gates only the LOCALITY leg —
    /// and the SessionLocal call site passes the caller's real target,
    /// not a default. So the selection axis exists on a single host:
    /// `AllComplete` means "only queryables that declared themselves
    /// complete", which is a property of the queryable, not of the
    /// topology.
    ///
    /// R311y334 — that divergence is now CLOSED. The loopback applies the
    /// completeness filter: the runtime's query paths pass the target into
    /// `QueryableRegistry::local_query`, which runs zenoh's
    /// `(queryable.complete || target != AllComplete)` on the SessionLocal
    /// queryables. Critically, the loopback reads the GATED
    /// [`Self::effective_target`], NOT this raw `pub` field: with `query-target`
    /// OFF the field is a bypassable pub write (R311y317), so reading it directly
    /// on the local path would re-arm the selection axis in a build that cannot
    /// emit a target. Never read `self.target` on a dispatch path; go through
    /// `effective_target()`.
    pub target: Option<QueryTarget>,
    /// Reply consolidation hint. `None` (default) elides → zenoh-pico
    /// decodes `Z_CONSOLIDATION_MODE_AUTO`. `Some(mode)` sets the Q_C
    /// flag and emits the consolidation byte per [`ConsolidationMode`].
    ///
    /// R311y321 — RETRACTED: "Loopback ignores consolidation
    /// (single-source replies have no duplicate to fold)". Both halves
    /// were wrong. The mode is APPLIED on receive (the `ConsolidatingSink`
    /// decorator wraps the pending's sink, which serves BOTH origins), and a
    /// single local queryable can perfectly well answer one keyexpr with
    /// several versions — that is what a `History::All` storage does, and it
    /// is the case consolidation exists for.
    pub consolidation: Option<ConsolidationMode>,
    /// Optional Query-body payload — the querier's attached VALUE (with the
    /// optional `encoding` below). `query_metadata` collapses the `payload`
    /// and `encoding` slots into the value unit routed through
    /// `build_request_query_with_meta`. Set via [`QueryOptions::with_payload`].
    pub payload: Option<Vec<u8>>,
    /// Optional encoding metadata for the Query body VALUE. Mirror of
    /// `z_get_options_t.encoding`; rides the value ext beside `payload`. An
    /// encoding-only value (no payload) is valid. Set via
    /// [`QueryOptions::with_encoding`].
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
    /// elides the ext. Symmetric to
    /// [`PublishOptions::source_info`](crate::publish_options::PublishOptions::source_info),
    /// and foreign-proven on the QUERY carrier — R311y244
    /// (`wz_query_source_info_to_pico_zqueryable`, pico
    /// `z_query_source_info` decodes `eid: 77 sn: 88`).
    pub source_info: Option<SourceInfo>,
    /// Query timeout in milliseconds (`0` = default = use
    /// `Z_GET_TIMEOUT_DEFAULT`). Loopback is synchronous so the timeout never
    /// trips on the loopback branch.
    ///
    /// The runtime's expired-query sweep cancels the pending entry once the
    /// deadline passes, delivering a synthetic `Err("Timeout")` and THEN its
    /// final, and a relay hop honours the wire ext through
    /// `read_request_timeout_ms`. Do NOT read this field directly —
    /// [`QueryOptions::effective_timeout_ms`] is the gate; a raw read is what
    /// let a `query-timeout`-off build arm the deadline (R311y317).
    pub timeout_ms: u32,
    /// Request-level QoS — priority + congestion-control + express packed into
    /// the single `_z_n_qos_create` byte carried by the Request outer extension
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01`. The query-side twin of
    /// [`PublishOptions::qos`](crate::publish_options::PublishOptions::qos), and
    /// the mirror of zenoh-c's `z_get_options_t.{priority, congestion_control,
    /// is_express}` / zenoh-pico's identically-named fields.
    ///
    /// `None` elides the ext, and so does a value equal to
    /// [`QosLevel::DEFAULT`] — the suppression lives in
    /// `build_request_query_with_meta`, so "options default" and "no options"
    /// are wire-identical. Set via [`Self::with_priority`] /
    /// [`Self::with_congestion_control`] / [`Self::with_express`], which merge
    /// per-field through [`QosLevel`]'s SSOT masks, or wholesale via
    /// [`Self::with_qos`].
    ///
    /// UNGATED, like the field it mirrors: there is no `query-qos` cargo atom
    /// because the Request outer QoS ext is part of the Request envelope every
    /// query build emits into, not a separately composable codec vertical.
    pub qos: Option<QosLevel>,
    /// The timestamp stack the query has for the session's own queryables, on the loopback leg: the
    /// interceptions of the node that asks, which the node that answers adds to. `None` (default)
    /// is a query that is not instrumented.
    #[cfg(feature = "pubsub-ts-stack")]
    pub ts_stack: Option<crate::ts_stack::TsStack>,
    /// The timestamp stack the query leaves with, as extension `0x7` of the Request, when it is not
    /// the one of the loopback leg: the node records one more interception on a message it routes
    /// out. `None` is the same stack as [`Self::ts_stack`].
    #[cfg(feature = "pubsub-ts-stack")]
    pub wire_ts_stack: Option<crate::ts_stack::TsStack>,
    /// What the node records on the timestamp stack of each reply as it arrives: see
    /// [`Self::with_reply_arrival`].
    #[cfg(feature = "pubsub-ts-stack")]
    reply_arrival: Option<crate::reply_sink::ReplyArrival>,
    /// Whether the callback sees the timestamp of the replies: see [`Self::with_expose_timestamp`].
    expose_timestamp: crate::timestamp_visibility::ExposeTimestamp,
    /// Whether the matching status of a querier made with these options counts a queryable of a
    /// peer only when its key includes the querier's: see [`Self::with_remote_inclusion`].
    remote_inclusion: bool,
}

impl QueryOptions {
    /// Default `Locality::Any` options — fans both wire and loopback
    /// branches. Mirror of zenoh-pico's `z_get_options_default`
    /// in semantic intent (everything cleared / unset).
    pub fn get() -> Self {
        Self::default()
    }

    /// Whether the replies this query is answered with show their timestamp to the callback. When
    /// they do not, each reply reads as one with no timestamp and is the same in every other way;
    /// the consolidation of the replies still orders them by the timestamp, which is hidden only
    /// from the callback that is handed the result.
    ///
    /// What a query that does not say gets is the build's `entity-timestamp-opt-in` policy: they
    /// show it when the policy is off, which is upstream's behaviour.
    pub fn with_expose_timestamp(mut self, expose: bool) -> Self {
        self.expose_timestamp = crate::timestamp_visibility::ExposeTimestamp(expose);
        self
    }

    /// See [`Self::with_expose_timestamp`].
    pub fn expose_timestamp(&self) -> bool {
        self.expose_timestamp.0
    }

    /// Count a queryable a PEER declared toward the matching status of a querier made with these
    /// options only when its key includes the querier's, as zenoh's router tables count them,
    /// and not when it merely intersects it, as zenoh-pico does and as is the default. See
    /// [`QuerierCriterion::remote_includes`](crate::declare::queryable::QuerierCriterion::remote_includes).
    pub fn with_remote_inclusion(mut self, includes: bool) -> Self {
        self.remote_inclusion = includes;
        self
    }

    /// See [`Self::with_remote_inclusion`].
    pub fn remote_inclusion(&self) -> bool {
        self.remote_inclusion
    }

    /// Pin the query-side locality predicate.
    pub fn with_allowed_destination(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Set the whole packed Request QoS byte at once. The escape hatch for a
    /// caller that already holds a [`QosLevel`] (e.g. one relayed from an
    /// inbound message); prefer the three per-field setters below, which
    /// preserve the sub-fields they do not name.
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// Give the query the timestamp stack `local` for the session's own queryables and `wire` for
    /// the Request that leaves (`None` for the same stack as `local`), so that the nodes it crosses
    /// record on it. `None` for both is a query that is not instrumented.
    #[cfg(feature = "pubsub-ts-stack")]
    pub fn with_ts_stack(
        mut self,
        local: Option<crate::ts_stack::TsStack>,
        wire: Option<crate::ts_stack::TsStack>,
    ) -> Self {
        self.ts_stack = local;
        self.wire_ts_stack = wire;
        self
    }

    /// Have the node complete the timestamp stack of each reply to the query when the reply
    /// arrives, with `arrival`: its routing and its receive are recorded then, ahead of the
    /// consolidation that may hold the reply back until the query is final, which is when
    /// upstream's node records them.
    #[cfg(feature = "pubsub-ts-stack")]
    pub fn with_reply_arrival(mut self, arrival: crate::reply_sink::ReplyArrival) -> Self {
        self.reply_arrival = Some(arrival);
        self
    }

    /// See [`Self::with_reply_arrival`].
    #[cfg(feature = "pubsub-ts-stack")]
    pub fn reply_arrival(&self) -> Option<&crate::reply_sink::ReplyArrival> {
        self.reply_arrival.as_ref()
    }

    /// Set the query's transmission priority, merging it into the low 3 bits of
    /// the packed QoS byte and PRESERVING any congestion / express bits a prior
    /// setter attached. Mirror of `z_get_options_t.priority`.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.qos = Some(self.qos_base().with_priority(priority));
        self
    }

    /// Set the query's congestion-control mode, merging it into the `nodrop`
    /// bit (3) and PRESERVING the priority / express bits. Mirror of
    /// `z_get_options_t.congestion_control`.
    pub fn with_congestion_control(mut self, congestion: CongestionControl) -> Self {
        self.qos = Some(self.qos_base().with_congestion(congestion));
        self
    }

    /// Set the query's express flag, merging it into bit 4 and PRESERVING the
    /// priority / congestion bits. Mirror of `z_get_options_t.is_express`.
    pub fn with_express(mut self, express: bool) -> Self {
        self.qos = Some(self.qos_base().with_express(express));
        self
    }

    /// The base byte the three per-field QoS setters merge into: whatever a
    /// prior setter attached, else the wire DEFAULT ([`QosLevel::DEFAULT`] =
    /// 0x05 = Data / Drop / no-express) rather than the zeroed
    /// `Control`-priority `QosLevel::default()`. Same choice, and same trap
    /// avoided, as `PublishOptions::qos_base`: starting from raw 0 would
    /// silently demote an unset priority to `Control`.
    fn qos_base(&self) -> QosLevel {
        self.qos.unwrap_or(QosLevel::DEFAULT)
    }

    /// Pin the reply target hint. `Some(target)` flips the Q_T flag
    /// on the outbound Query so the peer respects the selection.
    ///
    /// R311o — signature-stable per `feedback_signature_stability`:
    /// body cfg-gated on `feature = "query-target"`; silent no-op when
    /// the feature is off (the field stays at its `None` sentinel which
    /// elides the Q_T flag on the wire — same shape as the
    /// default-constructed QueryOptions, so callers can chain this
    /// builder unconditionally without per-feature cfg at the call site).
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

    /// Attach a Query-body payload — the querier's VALUE (paired with the
    /// optional [`Self::with_encoding`]), stamped on the outbound Query body
    /// VALUE ext (id 0x03 ENC_ZBUF, the "Q_B / Q_E" wire slot):
    /// [`QueryOptions::query_metadata`] collapses `payload` + `encoding` into
    /// one value unit, which `build_request_query_with_meta` stamps onto
    /// `RequestQueryBuilder::query_value` behind the `query-value` gate. The
    /// loopback path surfaces the value too, so a SessionLocal queryable
    /// observes it identically to a wire queryable.
    ///
    /// R311y250 — signature-stable (ungated) with an UNCONDITIONAL store.
    /// Three sibling setter shapes coexist on `QueryOptions`: hard-gated
    /// wire-data setters whose fn disappears when off (`with_source_info` /
    /// `with_attachment`); ungated setters whose store no-ops when off
    /// (`with_target` / `with_consolidation`); and this shape — ungated with
    /// an unconditional store. The unconditional store is REQUIRED because
    /// the `query_options_with_setters_chain` unit test exercises this setter
    /// in a feature set WITHOUT `query-value` and asserts capture. Consequence
    /// on a `query-value`-OFF build: the field is captured but inert — the
    /// gated wire threading elides it (a no-op, bytes unchanged); the only cost
    /// is that a value-only query forfeits the runtime's `is_empty()` fast path
    /// there (see [`QueryOptions::query_metadata`]).
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Attach Query-body encoding metadata — the content-type of the
    /// [`Self::with_payload`] value (an encoding-only value with no payload is
    /// valid; zenoh-pico's `_z_encoding_check` emits the ext for a non-default
    /// encoding). Mirror of `z_get_options_t.encoding`. Threaded onto the wire
    /// VALUE ext alongside `payload` (see [`Self::with_payload`] for the
    /// propagation path + the signature-stability rationale).
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
    /// the receive side gates the inbound parameters projection on): the get
    /// path threads this onto the Query body's `Q_P` flag + params slice only
    /// when the feature is composed, so the setter gates with it. The field
    /// stays (struct stability). What an `ext-pubsub-advanced-subscriber`
    /// recovery GET carries so the advanced cache's `answer_from_ring` filters
    /// its ring.
    #[cfg(feature = "query-selector-parameters")]
    pub fn with_parameters(mut self, parameters: Vec<u8>) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// R311y833 — opt out of (or back into) the matching-reply guarantee.
    ///
    /// zenoh: "By default, `get` guarantees that it will only receive replies
    /// whose key expressions intersect with the queried key expression. If
    /// allowed to through `accept_replies(ReplyKeyExpr::Any)`, queryables may
    /// also reply on key expressions that don't intersect with the query's."
    /// (`zenoh/src/api/builders/query.rs:281-287`.)
    ///
    /// [`ReplyKeyExpr::Any`] APPENDS the bare `_anyke` selector parameter, and
    /// that is the entire effect — the same single write zenoh's builder makes
    /// (`builders/query.rs:288-300`, via `Parameters::set_reply_key_expr_any`).
    /// It is what the responder reads to stop refusing such replies, and what
    /// [`QueryOptions::effective_accept_replies`] reads back to stop refusing
    /// them locally; one value, both sides. Idempotent: a parameter list that
    /// already carries the flag is left alone, mirroring pico's `implicit_anyke
    /// = _anyke_option && !_anyke_in_parameters`
    /// (`vendor/zenoh-pico/src/net/primitives.c:575-578`).
    ///
    /// [`ReplyKeyExpr::MatchingQuery`] is the default and this setter does NOT
    /// strip an `_anyke` a caller put in its own parameters — zenoh's builder
    /// has no such arm either, and removing a parameter the caller wrote would
    /// be a second, invisible edit of their selector.
    ///
    /// Gated on `query-selector-parameters` because the flag IS a selector
    /// parameter: on a build that cannot put parameters on the wire there is no
    /// honest way to ask a responder for this, so the knob does not exist
    /// rather than half-working. The local gate in
    /// `QueryOptions::effective_accept_replies` stays ungated — it must read
    /// whatever the `pub` field holds, on every build.
    #[cfg(feature = "query-selector-parameters")]
    pub fn with_accept_replies(mut self, accept: ReplyKeyExpr) -> Self {
        if accept == ReplyKeyExpr::MatchingQuery {
            return self;
        }
        let existing = self.parameters.take().unwrap_or_default();
        // Non-UTF-8 parameters cannot spell the ASCII flag, so they cannot
        // already carry it; appending is still correct, and the `;` join keeps
        // the byte list a valid parameter list either way.
        let has_flag = core::str::from_utf8(&existing).is_ok_and(|params| {
            crate::selector_params::has_param(params, crate::selector_params::ANYKE_PARAM)
        });
        if has_flag {
            self.parameters = Some(existing);
            return self;
        }
        let mut next = existing;
        if !next.is_empty() {
            next.push(crate::selector_params::PARAM_LIST_SEPARATOR as u8);
        }
        next.extend_from_slice(crate::selector_params::ANYKE_PARAM.as_bytes());
        self.parameters = Some(next);
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

    /// Pin a per-query timeout in milliseconds. `0` leaves the default in
    /// place. Loopback ignores the value (synchronous round-trip).
    ///
    /// The runtime's expired-query sweep enforces it, and every relay hop
    /// honours the wire ext via `read_request_timeout_ms`.
    ///
    /// R311o — signature-stable; body cfg-gated on
    /// `feature = "query-timeout"`; a no-op when off, so the builder chain
    /// stays callable unconditionally.
    ///
    /// R311y317 RETRACTS this doc's prior claim that "this setter is the only
    /// user surface that can flip `timeout_ms` above zero". It is not: the
    /// field is `pub`, and `#[non_exhaustive]` does not block assignment. That
    /// claim is why the gate sat here alone; measured, a pub-field write put
    /// the timeout ext on the wire AND armed the local deadline with the atom
    /// off. Both consumers now read [`QueryOptions::effective_timeout_ms`],
    /// which is the enforcement point — this setter is a convenience, not a
    /// gate.
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

    /// R239 — the number of Finals a query owes before it is over: what its
    /// pending entry is registered with. Mirrors zenoh-pico's
    /// `_z_pending_query_t._remaining_finals` initialisation in `_z_query`
    /// (`vendor/zenoh-pico/src/net/query.c`): one final per branch that will
    /// eventually emit a Final on this rid.
    ///
    /// `remote_targets` is how many peers the transport reaches, each of which owes one Final
    /// (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `size_t remaining_finals = (allow_local ? 1 : 0) + remote_targets;`): one for a unicast
    /// session, the group's members for a multicast one.
    ///
    /// * `Locality::Remote` → `remote_targets` (peer Finals only).
    /// * `Locality::SessionLocal` → 1 (loopback Final only).
    /// * `Locality::Any` → `remote_targets` + 1.
    ///
    /// Gated on `query-get`, the capability its callers have.
    #[cfg(feature = "query-get")]
    pub fn expected_finals(&self, remote_targets: u32) -> u32 {
        let mut n = 0u32;
        if self.allowed_destination.allows_remote() {
            n += remote_targets;
        }
        if self.allowed_destination.allows_local() {
            n += 1;
        }
        n
    }

    /// R311y317 — the three runtime-only atoms' slots as every consumer must
    /// read them: the field when the atom is on, its wire-elision sentinel when
    /// off. R311y326 — `timeout_ms`'s accessor
    /// ([`QueryOptions::effective_timeout_ms`]) additionally resolves its `0` to
    /// [`DEFAULT_QUERY_TIMEOUT_MS`] when the atom is on (a default query inherits
    /// the platform timeout, not never-expire); `target` / `consolidation` keep
    /// the plain field-or-None shape described here.
    ///
    /// WHY an accessor rather than the setter's body gate. `target` /
    /// `consolidation` / `timeout_ms` are `pub` fields, and `#[non_exhaustive]`
    /// blocks only struct-literal construction, NOT assignment onto a
    /// `QueryOptions::get()` value — so `with_target` & kin's body gates are
    /// bypassable. Measured, not argued: with each atom off, a pub-field write
    /// put Q_T (`0x34`), Q_C (`0x23`) and the timeout ext (`0x26`) on the wire.
    ///
    /// WHY HERE. `query-target` / `-consolidation` / `-timeout` were
    /// runtime-only features when this was written, which is why the accessor
    /// lived in the runtime as "the last hop that knows these three atoms
    /// exist". They are this crate's features now (the runtime's forward here),
    /// so the type that carries the slots is also the hop that knows.
    ///
    /// The query twin of the push side's `metadata_gated!` / `push_metadata`
    /// pair — an accessor rather than `metadata_gated!` because `timeout_ms` has
    /// a SECOND consumer that never touches [`Self::query_metadata`]: the pending
    /// entry's deadline. A `query_metadata`-local gate would fix the wire and
    /// leave the local deadline armed — with every wire-byte test green.
    #[cfg(feature = "query-get")]
    pub fn effective_target(&self) -> Option<QueryTarget> {
        #[cfg(feature = "query-target")]
        {
            self.target
        }
        #[cfg(not(feature = "query-target"))]
        {
            None
        }
    }

    /// R311y797 — whether a querier carrying these options demands
    /// COMPLETE responders, i.e. zenoh's
    /// `MatchingStatusType::Queryables(target == QueryTarget::AllComplete)`
    /// discriminant (`zenoh/src/api/querier.rs:225`). The single place the
    /// matching plane asks that question: the literal poll, the aliased
    /// poll and the watch registration all route here, and three copies of
    /// one comparison is exactly how a poll and its watch drift apart.
    ///
    /// It reads `effective_target` rather than the raw `pub target` field,
    /// for the reason that accessor exists: with `query-target` OFF the
    /// field is still writable and would otherwise select a matching
    /// semantic in a build that cannot put a target on the wire.
    ///
    /// UNGATED by `query-get`, unlike its two neighbours, and that is
    /// deliberate: the ALIASED matching poll compiles without `query-get`, so a
    /// `query-get`-gated helper is one that caller cannot reach. Without
    /// `query-get` there is no query to target at all, so `false` is the
    /// structural answer rather than a fallback.
    ///
    /// The gate is its CONSUMERS' own: both matching polls elide when
    /// neither queryable registry is compiled in, and under `-D warnings`
    /// a helper with no caller is an error.
    #[cfg(any(feature = "declare-queryable", feature = "query-queryable"))]
    pub fn matching_needs_complete(&self) -> bool {
        #[cfg(feature = "query-get")]
        {
            self.effective_target() == Some(QueryTarget::AllComplete)
        }
        #[cfg(not(feature = "query-get"))]
        {
            false
        }
    }

    /// R311y833 — which replies this get accepts: zenoh's `accept_replies`
    /// (`zenoh/src/api/builders/query.rs:287`), pico's
    /// `z_get_options_t.accept_replies`.
    ///
    /// THERE IS NO `accept_replies` FIELD, DELIBERATELY. Upstream keeps the
    /// state in the SELECTOR PARAMETERS and nowhere else: zenoh's builder
    /// writes `_anyke` into the parameters when asked for
    /// [`ReplyKeyExpr::Any`] (`builders/query.rs:288-300`) and its receive-side
    /// gate reads the parameters back (`session.rs:2846`), while pico spells
    /// the union out — `pq->_anyke = _anyke_in_parameters || _anyke_option`
    /// (`vendor/zenoh-pico/src/net/primitives.c:598`). Storing a second flag
    /// beside the parameters would make the two disagree, and it is the
    /// PARAMETERS that reach the responder.
    ///
    /// That also makes this accessor unbypassable for free. The `pub`
    /// `parameters` field is the state; a caller that writes `_anyke` by hand
    /// and one that asks for [`ReplyKeyExpr::Any`] are the same caller, which
    /// is exactly pico's rule rather than a wz simplification. Non-UTF-8
    /// parameters read as [`ReplyKeyExpr::MatchingQuery`]: the flag is an ASCII
    /// token, so bytes that cannot spell it do not carry it.
    ///
    /// GATED ON `query-get`, like its three `effective_*` siblings, and NOT on
    /// `query-selector-parameters` — that asymmetry is the point. The setter
    /// carries the selector-parameter gate because writing the flag is a wire
    /// act; this accessor must read whatever the `pub` field holds on any build
    /// that has a getter at all.
    #[cfg(feature = "query-get")]
    pub fn effective_accept_replies(&self) -> ReplyKeyExpr {
        match self.parameters.as_deref() {
            Some(bytes) => match core::str::from_utf8(bytes) {
                Ok(params) => ReplyKeyExpr::from_parameters(params),
                Err(_) => ReplyKeyExpr::MatchingQuery,
            },
            None => ReplyKeyExpr::MatchingQuery,
        }
    }

    /// See [`Self::effective_target`]. THE CALLER'S READING: exactly what this
    /// get named, with `None` meaning it named nothing.
    ///
    /// R311y837 — this is not the wire reading. It is the INPUT to the two
    /// readings that are: [`Self::resolved_consolidation`] (local) and
    /// [`Self::wire_consolidation`] (wire), which agree, because zenoh resolves
    /// once and feeds the result to both (`zenoh/src/api/session.rs:2294` and
    /// `:2316`).
    ///
    /// GATED ON `query-consolidation` TOO: with the field's only two readers both
    /// short-circuiting on that feature, an accessor gated on `query-get` alone
    /// is dead code there. The gate is the honest shape rather than an `allow` —
    /// a build with no consolidation capability has no reading of the caller's
    /// slot to take.
    #[cfg(all(feature = "query-get", feature = "query-consolidation"))]
    pub fn effective_consolidation(&self) -> Option<ConsolidationMode> {
        self.consolidation
    }

    /// R311y836 — THE LOCAL READING: the mode this get's `ConsolidatingSink`
    /// is installed with, which for a caller who named none is zenoh's
    /// `Auto -> Latest` (`zenoh/src/api/session.rs:2247-2252`).
    ///
    /// It routes through [`resolved_consolidation`], the one place both readings
    /// resolve; this method's job is only to supply the two inputs. On a build
    /// with no consolidation capability there is no
    /// [`Self::effective_consolidation`] to call (it would be dead code there),
    /// so `None` is what the caller named and the resolution's OFF arm answers.
    #[cfg(feature = "query-get")]
    pub fn resolved_consolidation(&self) -> ConsolidationMode {
        #[cfg(feature = "query-consolidation")]
        let requested = self.effective_consolidation();
        #[cfg(not(feature = "query-consolidation"))]
        let requested = None;
        resolved_consolidation(requested, self.parameters.as_deref())
    }

    /// R311y837 — THE WIRE READING, which is the LOCAL one transmitted rather
    /// than a second, quieter policy.
    ///
    /// zenoh resolves `Auto` once and feeds the resolved mode to both its local
    /// cache (`zenoh/src/api/session.rs:2294`) and the outbound Query body
    /// (`:2316`), so a stock default get puts `Latest` on the wire.
    ///
    /// STILL AN `Option`, AND THE `None` ARM IS NOT A DEFAULT: it is the
    /// `query-consolidation`-OFF build, which has no consolidation capability at
    /// all and must not acquire zenoh's default through the wire when it cannot
    /// honour it locally. That arm elides the field, which both upstreams'
    /// decoders read as `Auto`. The OFF-arm elision is made in one place for
    /// every requester, [`wire_consolidation`].
    #[cfg(feature = "query-get")]
    pub fn wire_consolidation(&self) -> Option<ConsolidationMode> {
        #[cfg(feature = "query-consolidation")]
        let requested = self.effective_consolidation();
        #[cfg(not(feature = "query-consolidation"))]
        let requested = None;
        wire_consolidation(requested, self.parameters.as_deref())
    }

    /// See [`Self::effective_target`]. Resolves the `0` sentinel this type's
    /// field + setter docs have always specified — `0` = "use the default" —
    /// to [`DEFAULT_QUERY_TIMEOUT_MS`], so a caller who sets no timeout gets
    /// zenoh's and pico's 10s rather than a query that never expires.
    ///
    /// R311y326 — the two meanings of `0` (the wire-elision sentinel and
    /// "never expire") never coexist on pico's client path: its elision
    /// predicate is UNREACHABLE from `z_get` / `z_querier` / `z_liveliness_get`,
    /// because all three rewrite `0` to the default BEFORE building the message
    /// (`api/api.c:1762-1763`, `:1830-1831`, `api/liveliness.c:132-133`). The
    /// sentinel survives only for internally-generated requests, which in wz is
    /// the relay-forwarded meta, never `QueryOptions`.
    ///
    /// The `0` that remains is the OFF arm's, and it means what it always did
    /// on that build: no ext, no deadline. Never-expire is therefore
    /// unrepresentable when `query-timeout` is ON — matching both upstreams,
    /// neither of which can express it — and remains the ONLY behaviour when it
    /// is OFF. That OFF-build residual is real and this type does not close it.
    ///
    /// Shape precedent, not invention:
    /// [`SessionInitParams::effective_batch_size`](crate::session_init_params::SessionInitParams::effective_batch_size)
    /// already resolves a `0` sentinel to its real default in an `effective_*`
    /// accessor.
    #[cfg(feature = "query-get")]
    pub fn effective_timeout_ms(&self) -> u32 {
        #[cfg(feature = "query-timeout")]
        {
            match self.timeout_ms {
                0 => DEFAULT_QUERY_TIMEOUT_MS,
                n => n,
            }
        }
        #[cfg(not(feature = "query-timeout"))]
        {
            0
        }
    }

    /// R240 — extract the wire-encoder-facing metadata bundle, so a session's
    /// query can hand it to `send_request_query_with_meta` without the lower
    /// module learning about [`Locality`] / `allowed_destination` (those stay
    /// on the dispatch-time surface). R311y250 — the `payload` + `encoding`
    /// slots collapse into the single
    /// [`QueryMetadata::value`](crate::metadata::QueryMetadata::value) wire unit
    /// `(encoding, payload)` that `build_request_query_with_meta` stamps onto
    /// `RequestQueryBuilder::query_value` (the Q_B / Q_E value ext 0x03).
    ///
    /// Clones owned slots (attachment Vec), so the allocation cost is
    /// amortised against the wire frame's existing copies. A `Locality::Any`
    /// query extracts TWICE per query on the tokio runtime: once for the wire
    /// branch, and once inside its `build_loopback_query`, which trims the
    /// bundle to the queryable-observable Query-body slots before reusing the
    /// same `build_request_query_with_meta` SSOT.
    ///
    /// It reads the `effective_*` accessors above, as the push side's
    /// `push_metadata` reads `metadata_gated!` (R311y309, R311y317).
    #[cfg(feature = "query-get")]
    pub fn query_metadata(&self) -> QueryMetadata {
        QueryMetadata {
            target: self.effective_target(),
            // R311y837 — the RESOLVED mode, not the caller's raw slot. zenoh
            // transmits what it resolved (`api/session.rs:2316`).
            consolidation: self.wire_consolidation(),
            attachment: self.attachment.clone(),
            parameters: self.parameters.clone(),
            source_info: self.source_info.clone(),
            // R311y250 — collapse the two ergonomic QueryOptions slots
            // (`payload` / `encoding`, each independently optional) into the
            // single wire VALUE unit `(encoding, payload)`. `(None, None)`
            // stays `None` so a default QueryOptions is `is_empty()` and takes
            // the no-meta fast path; any set slot yields a value with the
            // unset half defaulted (zero encoding / empty payload), and the
            // builder's `build()` `.body` predicate still elides a fully-empty
            // value on the wire. Population is ungated (mirroring
            // `push_metadata`); the `query-value` gate lives at the wire
            // threading in `build_request_query_with_meta`.
            value: match (&self.payload, &self.encoding) {
                (None, None) => None,
                _ => Some((
                    self.encoding.clone().unwrap_or_default(),
                    self.payload.clone().unwrap_or_default(),
                )),
            },
            timeout_ms: self.effective_timeout_ms(),
            // Ungated, like the field. The DEFAULT suppression lives one layer
            // down in `build_request_query_with_meta` so both this path and any
            // direct `QueryMetadata` construction get it.
            qos: self.qos,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: self.wire_ts_stack.clone().or_else(|| self.ts_stack.clone()),
        }
    }

    /// The Query body a get delivers to the session's OWN queryables (zenoh-pico's
    /// `_z_session_deliver_query_locally`, `vendor/zenoh-pico/src/session/loopback.c`): the
    /// slots a queryable can observe (the selector's parameters, the value, the source info, the
    /// attachment), built by the wire builder, so a local queryable reads what a remote one
    /// would. Shared by every engine's loopback leg, as [`PublishOptions::loopback_sample`] is the
    /// publish side's.
    ///
    /// What a queryable cannot observe is not in the body: the target and the QoS ride the
    /// dispatch beside it (`QueryEnvelope`), the consolidation is applied at the requester's sink
    /// on both origins, and the timeout arms the pending entry's deadline.
    ///
    /// The wire builder's `rid = 0` / literal-key envelope is discarded: the loopback's request id
    /// and key ride the dispatch's arguments. Its caller-error asserts are the wire's too, so a
    /// selector longer than the wire's bound panics here as it would on the link: a selector that
    /// no wire queryable could receive is not one a local queryable should.
    ///
    /// [`PublishOptions::loopback_sample`]: crate::publish_options::PublishOptions::loopback_sample
    #[cfg(all(
        feature = "query-get",
        feature = "query-queryable",
        feature = "codec-request",
        feature = "alloc"
    ))]
    pub fn loopback_query(&self) -> crate::wire::parts::QueryOwned {
        let full = self.query_metadata();
        let meta = QueryMetadata {
            parameters: full.parameters,
            source_info: full.source_info,
            attachment: full.attachment,
            value: full.value,
            ..Default::default()
        };
        let request = crate::request_build::build_request_query_with_meta(0, 0, None, &meta)
            .expect("a loopback Query body builds on the heap profile");
        match request.body {
            wz_codecs::request::RequestOwnedVariant::CodecZenohQuery(query) => query,
            _ => unreachable!("build_request_query_with_meta always produces a Query body"),
        }
    }
}
