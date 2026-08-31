// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Querier handle cluster split out of `session/mod.rs` (pure
//! refactor): [`QueryOptions`], the [`Querier`] / [`QuerierAliased`]
//! handles, [`MatchingStatus`], [`QueryAliasError`],
//! [`LivelinessGetOptions`], and [`LivelinessGetError`]. The parent
//! module re-exports the public types via `pub use querier::*;` so the
//! path `wz_runtime_tokio::session::Querier` etc. is unchanged.

use super::*;

// R311y551 — the Request-side QoS trio. Imported here rather than relied on
// through the `super::*` glob because the glob re-exports the session module's
// own surface, not `wz-session-core`'s qos vocabulary; `publish_common.rs`
// names the same three for the same reason.
use crate::sample::QosLevel;
use wz_session_core::qos::CongestionControl;
use wz_session_core::qos::Priority;
// R311y833 — the two consumers are `with_accept_replies`
// (`query-selector-parameters`) and `effective_accept_replies` (`query-get`);
// with neither composed the name is unused, which is the cfg-gated-import shape
// Layer C1cf exists to catch.
#[cfg(any(feature = "query-get", feature = "query-selector-parameters"))]
use wz_session_core::reply_acceptance::ReplyKeyExpr;

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
/// `query-get` (the `liveliness-get-only` subset, `scripts/run-ci.sh:3534`), so
/// a constant scoped to one atom's gate would be absent on the other's lane.
/// One constant, one resolution site per atom — the same split zenoh has, where
/// `queries_default_timeout()` is a shared defaulting convenience consulted by
/// three otherwise-independent surfaces (R311y325 §LEG B).
///
/// NOT unified with `LinkstateForwarder::DEFAULT_QUERY_TIMEOUT`
/// (`linkstate_forward.rs:661`), the RELAY's identical 10s. zenoh keeps ONE
/// config key for both legs (`tables.rs` router-side, `conf` client-side), so
/// two constants for one concept IS a divergence — a NAMED residual, because
/// unifying them means deciding whether wz grows a client config plane, which
/// this round deliberately does not.
///
/// Gated to the union of its two consumers — the z_get accessor
/// ([`QueryOptions::effective_timeout_ms`], `query-timeout`) and the liveliness
/// accessor ([`LivelinessGetOptions::effective_timeout_ms`], `liveliness-get`).
/// A `query-get`-only build (both atoms off) has no reader, so an ungated const
/// would be `-D dead-code`.
#[cfg(any(feature = "query-timeout", feature = "liveliness-get"))]
pub(crate) const DEFAULT_QUERY_TIMEOUT_MS: u32 = 10_000;

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
/// R311y250 extended that threading to `payload` / `encoding`: they
/// collapse into the [`QueryMetadata::value`] wire unit
/// (`RequestQueryBuilder::query_value`, value ext 0x03; codec landed
/// R311y248), so a querier's attached value now propagates on the
/// outbound Query. R311y252 closed the last gap: the loopback path's
/// in-process [`crate::query::QueryableRegistry::local_query`] now surfaces
/// `parameters` / `attachment` / `source_info` / `value` to a SessionLocal
/// queryable identically to the wire path — `build_loopback_query` reuses the
/// same `build_request_query_with_meta` SSOT and lifts out its Query body, so
/// both origins carry the same ext chain. R311y321 — the parenthetical here
/// used to read "(`target` / `consolidation` / `timeout_ms` stay loopback-inert
/// by design)"; see `build_loopback_query`'s own doc comment (session/mod.rs)
/// for the per-slot truth. In short: `consolidation` is no longer inert (it is
/// applied at the requester's sink, on both origins), and `target`'s inertness
/// was never "by design" — it is the `query-target` atom's PARTIAL residual.
///
/// `#[non_exhaustive]` so future rounds add fields without breaking
/// callers. Construct via [`QueryOptions::get`] (or `default`) plus
/// optional `with_*` setters — never struct-literal externally.
///
/// R311y330 — this doc used to open: "R307 — `#[cfg(feature = "query-get")]`.
/// The struct + impl + every setter elide when `query-get` is off; `with_target`
/// / `with_consolidation` / `with_timeout_ms` carry their own narrower gates so
/// an `--features query-get` (no extras) build still compiles QueryOptions
/// without those setters." RETRACTED, and it had been self-contradicting for
/// rounds: `QueryOptions` (`:95`) and `Querier` (`:844`) carry NO cfg, and the
/// R311o paragraph immediately below says so — "type-ungated ... Struct +
/// builders always defined regardless of the `query-get` family". R311o
/// superseded R307's design and the R307 sentence was never marked retracted,
/// so the file asserted both. Only the narrower-gate half survived contact with
/// the code, and R311o restates it correctly.
///
/// Found by review, not by me, and it is the same class this round retracted in
/// `session/mod.rs` (`Session::query`'s implication chain) one commit earlier —
/// I swept the claim family for the exact phrases I had just read and never
/// looked at the sibling file. That is `retraction-lands-where-you-look`
/// verbatim: a retraction closes where you GREP, not where the claim lives.
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
    /// [`crate::session_glue::QueryTarget`].
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
    /// completeness filter: `Session::query` / `query_aliased` pass the target
    /// into `QueryableRegistry::local_query`, which runs zenoh's
    /// `(queryable.complete || target != AllComplete)` on the SessionLocal
    /// queryables. It rides the call argument, NOT `build_loopback_query`'s body
    /// (target is a Request-level slot, not a Query-body slot). Critically, the
    /// loopback reads the GATED [`Self::effective_target`], NOT this raw `pub`
    /// field: with `query-target` OFF the field is a bypassable pub write
    /// (R311y317), so reading it directly on the local path would re-arm the
    /// selection axis in a build that cannot emit a target — the exact
    /// last-hop-that-knows leak `effective_target` exists to close. Never read
    /// `self.target` on a dispatch path; go through `effective_target()`.
    pub target: Option<QueryTarget>,
    /// Reply consolidation hint. `None` (default) elides → zenoh-pico
    /// decodes `Z_CONSOLIDATION_MODE_AUTO`. `Some(mode)` sets the Q_C
    /// flag and emits the consolidation byte per
    /// [`crate::session_glue::ConsolidationMode`].
    ///
    /// R311y321 — RETRACTED: "Loopback ignores consolidation
    /// (single-source replies have no duplicate to fold)". Both halves
    /// were wrong. The mode is APPLIED on receive now (the
    /// `ConsolidatingSink` decorator wraps the pending's sink, which
    /// serves BOTH origins), and a single local queryable can perfectly
    /// well answer one keyexpr with several versions — that is what a
    /// `History::All` storage does, and it is the case consolidation
    /// exists for. zenoh consolidates its own SessionLocal replies for
    /// the same reason: they re-enter through the querying session's
    /// reply path like any other.
    pub consolidation: Option<ConsolidationMode>,
    /// Optional Query-body payload — the querier's attached VALUE (with
    /// the optional `encoding` below). The Q_B codec landed R311y248
    /// (`RequestQueryBuilder::query_value`, value ext 0x03); R311y250
    /// threaded the WIRE propagation (`query_metadata` collapses the
    /// `payload` and `encoding` slots into [`QueryMetadata::value`], routed
    /// through `build_request_query_with_meta`). R311y252 surfaces the value to
    /// a SessionLocal queryable on the loopback path too (alongside attachment /
    /// source_info / parameters — `build_loopback_query` reuses the same wire
    /// SSOT Query body). Set via [`QueryOptions::with_payload`].
    pub payload: Option<Vec<u8>>,
    /// Optional encoding metadata for the Query body VALUE. Mirror of
    /// `z_get_options_t.encoding`; rides the value ext beside `payload`
    /// (wire propagation R311y250 — see `payload`). An encoding-only value
    /// (no payload) is valid. Set via [`QueryOptions::with_encoding`].
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
    /// `Z_GET_TIMEOUT_DEFAULT`). Loopback is synchronous so the timeout never
    /// trips on the loopback branch.
    ///
    /// R311y317 — this said the sweep was "a future R240+" one. It is not
    /// future: [`Session::sweep_expired_queries`] cancels the pending entry once
    /// the deadline passes, and a relay hop honours the wire ext through
    /// `read_request_timeout_ms`. R311y323 — y317's own wording here, "fires
    /// `on_final` synthetically", is now stale: the sweep fires `on_timeout`, so
    /// an expired query delivers a synthetic `Err("Timeout")` and THEN its final.
    /// (This field's doc has now been the site of two retractions and y318 left a
    /// warning 144 lines down saying a retraction lands where the author is
    /// looking. y323 read that warning only after review caught it here.) Do NOT
    /// read this
    /// field directly — [`QueryOptions::effective_timeout_ms`] is the gate; a
    /// raw read is what let a `query-timeout`-off build arm the deadline.
    pub timeout_ms: u32,
    /// Request-level QoS — priority + congestion-control + express packed into
    /// the single `_z_n_qos_create` byte carried by the Request outer extension
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01`. The query-side twin of
    /// [`PublishOptions::qos`](super::PublishOptions::qos), and the mirror of
    /// zenoh-c's `z_get_options_t.{priority, congestion_control, is_express}` /
    /// zenoh-pico's identically-named fields.
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
    /// query build emits into, not a separately composable codec vertical. The
    /// packer ([`QosLevel::from_parts`]) and the emitter
    /// ([`RequestQueryBuilder::request_qos_typed`](wz_session_core::request_build::RequestQueryBuilder::request_qos_typed))
    /// were both already built and ungated; this field is the caller-facing
    /// slot that had been missing between them.
    pub qos: Option<QosLevel>,
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

    /// Set the whole packed Request QoS byte at once. The escape hatch for a
    /// caller that already holds a [`QosLevel`] (e.g. one relayed from an
    /// inbound message); prefer the three per-field setters below, which
    /// preserve the sub-fields they do not name.
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
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

    /// Attach a Query-body payload — the querier's VALUE (paired with the
    /// optional [`Self::with_encoding`]), stamped on the outbound Query body
    /// VALUE ext (id 0x03 ENC_ZBUF, the "Q_B / Q_E" wire slot). The codec
    /// landed R311y248; R311y250 threaded the WIRE propagation:
    /// [`QueryOptions::query_metadata`] collapses `payload` + `encoding` into
    /// the [`QueryMetadata::value`] unit, which `build_request_query_with_meta`
    /// stamps onto `RequestQueryBuilder::query_value` behind the `query-value`
    /// gate. R311y252 surfaces the value on the loopback path too (alongside
    /// attachment / source_info / parameters), so a SessionLocal queryable
    /// observes it identically to a wire queryable.
    ///
    /// R311y250 — signature-stable (ungated) with an UNCONDITIONAL store.
    /// Three sibling setter shapes coexist on `QueryOptions`: hard-gated
    /// wire-data setters whose fn disappears when off (`with_source_info` /
    /// `with_attachment`); ungated setters whose store no-ops when off
    /// (`with_target` / `with_consolidation`); and this shape — ungated with
    /// an unconditional store. The unconditional store is REQUIRED because
    /// the `query_options_with_setters_chain` unit test exercises this setter
    /// in a feature set WITHOUT `query-value` and asserts capture (per the
    /// `feedback_signature_stability` anchor). Consequence on a
    /// `query-value`-OFF build: the field is captured but inert — the gated
    /// wire threading in `build_request_query_with_meta` elides it (a no-op,
    /// bytes unchanged); the only cost is that a value-only query forfeits
    /// `Session::query`'s `is_empty()` fast path there (see
    /// [`QueryOptions::query_metadata`]).
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Attach Query-body encoding metadata — the content-type of the
    /// [`Self::with_payload`] value (an encoding-only value with no payload is
    /// valid; zenoh-pico's `_z_encoding_check` emits the ext for a non-default
    /// encoding). Mirror of `z_get_options_t.encoding`. Threaded onto the wire
    /// VALUE ext alongside `payload` since R311y250 (see [`Self::with_payload`]
    /// for the propagation path + the signature-stability rationale).
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
    /// `QueryOptions::effective_accept_replies` (crate-internal) reads back to stop refusing them
    /// locally; one value, both sides. Idempotent: a parameter list that
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
    /// `QueryOptions::effective_accept_replies` stays ungated — it must read whatever
    /// the `pub` field holds, on every build.
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
            wz_session_core::selector_params::has_param(
                params,
                wz_session_core::selector_params::ANYKE_PARAM,
            )
        });
        if has_flag {
            self.parameters = Some(existing);
            return self;
        }
        let mut next = existing;
        if !next.is_empty() {
            next.push(wz_session_core::selector_params::PARAM_LIST_SEPARATOR as u8);
        }
        next.extend_from_slice(wz_session_core::selector_params::ANYKE_PARAM.as_bytes());
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
    /// R311y318 — this said "Wire-side enforcement lands with the R240+
    /// ReplyRegistry timeout sweep", i.e. future work. It is not: the sweep
    /// ships as [`Session::sweep_expired_queries`], and every relay hop honours
    /// the wire ext via `request_routing_context::read_request_timeout_ms`.
    /// R311y317 retracted the SAME fossil on the field doc 144 lines up and
    /// missed this one — a retraction lands where the author is looking.
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

    /// R311y317 — the three runtime-only atoms' slots as every consumer must
    /// read them: the field when the atom is on, its wire-elision sentinel when
    /// off. R311y326 — `timeout_ms`'s accessor
    /// ([`QueryOptions::effective_timeout_ms`]) additionally resolves its `0` to
    /// `DEFAULT_QUERY_TIMEOUT_MS` when the atom is on (a default query inherits
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
    /// WHY HERE and not downstream, which is the whole reason this domain
    /// diverged from its siblings: `query-target` / `-consolidation` /
    /// `-timeout` are runtime-tokio-only features (`Cargo.toml`: terminal, no
    /// `wz-session-core/` forward), so session-core's TX SSOT
    /// `build_request_query_with_meta` CANNOT gate them — it gates the other
    /// four slots (value / source-info / attachment / selector-parameters)
    /// precisely because those forward to features it owns. This accessor is
    /// the last hop that knows these three atoms exist.
    ///
    /// Same shape R311y308/y309 closed on the push side after an ungated
    /// pub-field `qos` changed Frame count + SN with the feature off; the
    /// `metadata_gated!` / `push_metadata` pair is that fix. This is its query
    /// twin, in the [`crate::session::liveliness`] `effective_history` idiom —
    /// an accessor rather than `metadata_gated!` because `timeout_ms` has a
    /// SECOND consumer that never touches [`Self::query_metadata`]: the
    /// `deadline_ms` computation in `Session::query` / the aliased get path
    /// reads the field directly. A `query_metadata`-local gate would fix the
    /// wire and leave the local ReplyRegistry deadline armed — with every
    /// wire-byte test green.
    #[cfg(feature = "query-get")]
    pub(super) fn effective_target(&self) -> Option<QueryTarget> {
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
    /// semantic in a build that cannot put a target on the wire — the poll
    /// would answer about a query the peer will never be asked.
    ///
    /// UNGATED, unlike its two neighbours, and that is deliberate: the
    /// ALIASED matching poll compiles without `query-get` (the aliased
    /// handle does), so a `query-get`-gated helper is one this caller
    /// cannot reach. Without `query-get` there is no query to target at
    /// all, so `false` is the structural answer rather than a fallback.
    /// R311y797 measured that the hard way — the pre-push doc-link gate,
    /// reaching wz-replay and wz-runtime-tokio-test-support because they
    /// link INTO this crate, is what surfaced the E0599.
    ///
    /// The gate is its CONSUMERS' own: both matching polls elide when
    /// neither queryable registry is compiled in, and under `-D warnings`
    /// a helper with no caller is an error. Gating it rather than
    /// `allow(dead_code)`-ing it keeps the elision honest.
    #[cfg(any(feature = "declare-queryable", feature = "query-queryable"))]
    pub(super) fn matching_needs_complete(&self) -> bool {
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
    /// PARAMETERS that reach the responder — a local flag the wire never
    /// carries would let a caller believe it had opted out while every remote
    /// queryable kept refusing.
    ///
    /// That also makes this accessor unbypassable for free. The `pub`
    /// `parameters` field is the state; a caller that writes `_anyke` by hand
    /// and one that calls [`Self::with_accept_replies`] are the same caller,
    /// which is exactly pico's rule rather than a wz simplification. Non-UTF-8
    /// parameters read as [`ReplyKeyExpr::MatchingQuery`]: the flag is an ASCII
    /// token, so bytes that cannot spell it do not carry it.
    ///
    /// GATED ON `query-get`, like its three `effective_*` siblings, and NOT on
    /// `query-selector-parameters` — that asymmetry is the point. The SETTER
    /// carries the selector-parameter gate because writing the flag is a wire
    /// act; this accessor must read whatever the `pub` field holds on any build
    /// that has a getter at all, or the enforcement point would be bypassable
    /// exactly as `timeout_ms` was before R311y317. With `query-get` off there
    /// is no getter and no pending registration, so nothing is left unguarded —
    /// the method simply has no caller, and Layer C1cf (the
    /// `--no-default-features` build) is what said so.
    #[cfg(feature = "query-get")]
    pub(super) fn effective_accept_replies(&self) -> ReplyKeyExpr {
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
    /// R311y837 — this is no longer the wire reading. It is the INPUT to the
    /// two readings that are: [`Self::resolved_consolidation`] (local) and
    /// [`Self::wire_consolidation`] (wire), which since this round agree,
    /// because zenoh resolves once and feeds the result to both
    /// (`zenoh/src/api/session.rs:2294` and `:2316`).
    ///
    /// GATED ON `query-consolidation` TOO since R311y837, and the OFF build is
    /// what said so: with the field's only two readers both short-circuiting on
    /// that feature, an accessor gated on `query-get` alone is dead code there,
    /// and Layer C1cf / the `zget-reply-only` subset build rejected it as such.
    /// The gate is the honest shape rather than an `allow` — a build with no
    /// consolidation capability has no reading of the caller's slot to take.
    #[cfg(all(feature = "query-get", feature = "query-consolidation"))]
    pub(super) fn effective_consolidation(&self) -> Option<ConsolidationMode> {
        self.consolidation
    }

    /// R311y836 — THE LOCAL READING: the mode this get's `ConsolidatingSink`
    /// is installed with, which for a caller who named none is zenoh's
    /// `Auto -> Latest` (`zenoh/src/api/session.rs:2247-2252`) rather than the
    /// pass-through `None` wz delivered until this round.
    ///
    /// It routes through [`ConsolidationMode::resolve_auto`], the SSOT that owns
    /// both upstream arms including the `_time` carve-out; this method's job is
    /// only to supply the two inputs and to carry the feature gate.
    ///
    /// GATED ON `query-consolidation`, and that is the honest boundary: the
    /// feature IS the consolidation capability, so a build without it keeps the
    /// pre-y836 pass-through instead of acquiring zenoh's default through a back
    /// door. Layer C1cf and the `not(query-consolidation)` NEG tests are what
    /// hold that arm; the A3 `active <=> cfg-site` invariant is unaffected.
    ///
    /// The parameters are read through the same `pub` field
    /// [`Self::effective_accept_replies`] reads, and for the same R311y317
    /// reason: a caller can assign the field directly, so the gate must sit on
    /// the last hop that knows rather than on a setter.
    #[cfg(feature = "query-get")]
    pub(super) fn resolved_consolidation(&self) -> ConsolidationMode {
        #[cfg(feature = "query-consolidation")]
        {
            let params = self
                .parameters
                .as_deref()
                .and_then(|bytes| core::str::from_utf8(bytes).ok())
                .unwrap_or("");
            ConsolidationMode::resolve_auto(self.effective_consolidation(), params)
        }
        #[cfg(not(feature = "query-consolidation"))]
        {
            ConsolidationMode::None
        }
    }

    /// R311y837 — THE WIRE READING, and since this round it is the LOCAL one
    /// transmitted rather than a second, quieter policy.
    ///
    /// zenoh resolves `Auto` once and feeds the resolved mode to both its local
    /// cache (`zenoh/src/api/session.rs:2294`) and the outbound Query body
    /// (`:2316`), so a stock default get puts `Latest` on the wire. wz elided it
    /// until now, and R311y836 said why in as many words: transmitting was
    /// blocked on the wire BYTE being pico's rather than zenoh's, so a
    /// transmitted `Latest` would have been read as `Monotonic` by the router it
    /// was sent to. R311y837 measured the byte on both planes and moved
    /// [`ConsolidationMode::wire_byte`] onto zenoh's numbering, which is what
    /// unblocks this half — the two are one change in two steps and the order
    /// between them is load-bearing.
    ///
    /// STILL AN `Option`, AND THE `None` ARM IS NOT THE OLD BEHAVIOUR: it is the
    /// `query-consolidation`-OFF build, which has no consolidation capability at
    /// all and must not acquire zenoh's default through the wire when it cannot
    /// honour it locally. That arm elides the field, which both upstreams' decoders
    /// read as `Auto` — the honest statement for a build that consolidates nothing.
    #[cfg(feature = "query-get")]
    pub(super) fn wire_consolidation(&self) -> Option<ConsolidationMode> {
        #[cfg(feature = "query-consolidation")]
        {
            Some(self.resolved_consolidation())
        }
        #[cfg(not(feature = "query-consolidation"))]
        {
            None
        }
    }

    /// See [`Self::effective_target`]. Resolves the `0` sentinel this type's
    /// field + setter docs have always specified — `0` = "use the default" —
    /// to [`DEFAULT_QUERY_TIMEOUT_MS`], so a caller who sets no timeout gets
    /// zenoh's and pico's 10s rather than a query that never expires.
    ///
    /// R311y326 — this doc used to close with: "`0` is the wire-elision
    /// sentinel (zenoh-pico's `_z_n_msg_request_needed_exts` predicate
    /// `msg->_ext_timeout_ms != 0`) AND the 'never-expire' sentinel the
    /// `deadline_ms` computation keys on — one accessor covers both consumers,
    /// which is the point." RETRACTED: that rationale is inverted. The two
    /// meanings never coexist on pico's client path either — its elision
    /// predicate is UNREACHABLE from `z_get` / `z_querier` / `z_liveliness_get`,
    /// because all three rewrite `0` to the default BEFORE building the message
    /// (`api/api.c:1762-1763`, `:1830-1831`, `api/liveliness.c:132-133`). The
    /// sentinel survives only for internally-generated requests, which in wz is
    /// the relay-forwarded meta (`request_build.rs:230`), never `QueryOptions`.
    /// Carrying both meanings on one value was not "the point"; it was the
    /// defect (R311y325 §LEG A), and it made the `Err("Timeout")` synthesis
    /// R311y323 built unreachable on wz's own default path.
    ///
    /// The `0` that remains is the OFF arm's, and it means what it always did
    /// on that build: no ext, no deadline. Never-expire is therefore
    /// unrepresentable when `query-timeout` is ON — matching both upstreams,
    /// neither of which can express it — and remains the ONLY behaviour when it
    /// is OFF. That OFF-build residual is real and this round does not close it.
    ///
    /// Shape precedent, not invention: [`SessionInitParams::effective_batch_size`]
    /// (`wz-session-core/src/session_init_params.rs:98-103`) already resolves a
    /// `0` sentinel to its real default in an `effective_*` accessor, and
    /// `session_actions.rs:1481` / `:1565` read it load-bearing.
    #[cfg(feature = "query-get")]
    pub(super) fn effective_timeout_ms(&self) -> u32 {
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

    /// R240 — extract the wire-encoder-facing metadata bundle from a
    /// QueryOptions instance so [`Session::query`] can hand it to
    /// [`crate::session_glue::SessionLinkActions::send_request_query_with_meta`]
    /// without the lower module learning about [`Locality`] /
    /// `allowed_destination` (those stay on the dispatch-time
    /// surface). R311y250 — the `payload` + `encoding` slots now thread
    /// too: they collapse into the single [`QueryMetadata::value`] wire
    /// unit `(encoding, payload)` that `build_request_query_with_meta`
    /// stamps onto `RequestQueryBuilder::query_value` (the Q_B / Q_E value
    /// ext 0x03; codec landed R311y248).
    ///
    /// Clones owned slots (attachment Vec), so the allocation cost is
    /// amortised against the wire frame's existing copies. R311y252 — a
    /// `Locality::Any` query now extracts TWICE per [`Session::query`] call: once
    /// for the wire branch, and once inside `build_loopback_query`, which trims
    /// the bundle to the queryable-observable Query-body slots before reusing the
    /// same `build_request_query_with_meta` SSOT. (A `Remote`-only or
    /// `SessionLocal`-only query still extracts once — only the branch it routes
    /// to runs.) The second extraction is one struct clone on the non-hot
    /// loopback branch, taken deliberately so the loopback does not re-derive the
    /// Query ext-chain assembly.
    ///
    /// R311y317 — this used to claim it "mirrors R233's
    /// `PublishOptions::push_metadata` pattern verbatim". That had stopped
    /// being true: R311y309 moved `push_metadata` onto `metadata_gated!` after
    /// an ungated pub-field `qos` changed Frame count + SN with the feature
    /// off, and the query side never followed. It mirrors it again now, via
    /// the `effective_*` accessors above.
    ///
    /// R311o — private helper, cfg-gated like [`Self::expected_finals`].
    #[cfg(feature = "query-get")]
    pub(super) fn query_metadata(&self) -> QueryMetadata {
        QueryMetadata {
            target: self.effective_target(),
            // R311y837 — the RESOLVED mode, not the caller's raw slot. zenoh
            // transmits what it resolved (`api/session.rs:2316`); wz elided
            // until the wire byte was measured and corrected this round.
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
            // threading in `build_request_query_with_meta`, so on a
            // `query-value`-OFF build a captured value is derived here but
            // never emitted. (Ungated-not-gated is deliberate: gating this
            // derivation would break the non-`query-value`-gated
            // `query_options_query_metadata_extracts_wire_fields` test, which
            // asserts the collapse. The one cost is that a value-only query on
            // a `query-value`-OFF build forfeits the `is_empty()` fast path —
            // the emitted bytes are identical either way since the value can't
            // emit on that build.)
            value: match (&self.payload, &self.encoding) {
                (None, None) => None,
                _ => Some((
                    self.encoding.clone().unwrap_or_default(),
                    self.payload.clone().unwrap_or_default(),
                )),
            },
            timeout_ms: self.effective_timeout_ms(),
            // Ungated, like the field (see `QueryOptions::qos`). The DEFAULT
            // suppression lives one layer down in
            // `build_request_query_with_meta` so both this path and any direct
            // `QueryMetadata` construction get it.
            qos: self.qos,
        }
    }
}

/// liveliness-get — options for [`Session::liveliness_get`]. Mirrors
/// zenoh-pico's `z_liveliness_get_options_t` (currently the timeout only).
///
/// R311y326 — `timeout_ms == 0` is the "use the default" sentinel, resolved by
/// [`Self::effective_timeout_ms`] to [`DEFAULT_QUERY_TIMEOUT_MS`]. This doc
/// previously called `0` a "no timeout" sentinel under which "the pending get
/// never expires". RETRACTED: that was the liveliness twin of the R311y325
/// §LEG A client-default defect. pico does NOT offer a never-expire liveliness
/// get — `z_liveliness_get` rewrites `0` to `Z_GET_TIMEOUT_DEFAULT` before
/// issuing (`vendor/zenoh-pico/src/api/liveliness.c:132-133`), and zenoh reads
/// the same `queries_default_timeout()` (`api/liveliness.rs:201-203`). A default
/// liveliness get now expires at the platform default, matching both — and
/// `wz-ap-demo/src/tasks.rs` (which issues `LivelinessGetOptions::default()`)
/// gains that bound instead of hanging until the peer's `DeclFinal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LivelinessGetOptions {
    /// Snapshot timeout in milliseconds. `0` = use the platform default
    /// ([`DEFAULT_QUERY_TIMEOUT_MS`], via [`Self::effective_timeout_ms`]); any
    /// value arms the driver-loop sweep to terminate the get if the peer never
    /// terminates the snapshot, so the pending slot cannot leak.
    /// R311y323 — the sweep fires `on_timeout`, not a bare `on_final`: an
    /// expired snapshot delivers a synthetic `Err("Timeout")` and then its
    /// final, matching zenoh's liveliness timeout arm.
    pub timeout_ms: u32,
}

impl LivelinessGetOptions {
    /// Default options — `timeout_ms = 0` (the "use the default" sentinel;
    /// [`Self::effective_timeout_ms`] resolves it to
    /// [`DEFAULT_QUERY_TIMEOUT_MS`]). Mirrors zenoh-pico's
    /// `z_liveliness_get_options_default`, whose `0` `z_liveliness_get` likewise
    /// rewrites to the default before issuing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set the snapshot `timeout_ms`. `0` selects the platform
    /// default rather than never-expire (see [`Self::effective_timeout_ms`]).
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Resolve the `0` = "use the default" sentinel to
    /// [`DEFAULT_QUERY_TIMEOUT_MS`], so [`Session::liveliness_get`] arms a
    /// deadline for a default snapshot get exactly as its z_get sibling does
    /// (`QueryOptions::effective_timeout_ms`). Separate accessor because this is
    /// `liveliness-get`'s leg, not `query-timeout`'s (R311y325 §LEG B): the two
    /// atoms are independent, and `liveliness-get` composes without `query-get`
    /// (the `liveliness-get-only` subset, `scripts/run-ci.sh:3534`), so the
    /// z_get accessor — item-gated on `query-get` — does not exist on this leg's
    /// lane. The shared thing is the constant, matching zenoh, whose
    /// `queries_default_timeout()` both surfaces read.
    #[cfg(feature = "liveliness-get")]
    pub(crate) fn effective_timeout_ms(&self) -> u32 {
        match self.timeout_ms {
            0 => DEFAULT_QUERY_TIMEOUT_MS,
            n => n,
        }
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
    /// R2238 (open-debt item 580) — the session's fragment TX budget ran out
    /// while this Interest's chain was being emitted, so it was abandoned.
    /// Wire bytes MAY have been emitted (followed by a `0x3 Drop` stop
    /// fragment), which is why this is not folded into
    /// [`Self::ExceedsCapacity`]; retry once the budget is refilled.
    FragmentChainAbandoned,
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
            LivelinessGetError::FragmentChainAbandoned => write!(
                f,
                "LivelinessGetError: the session's fragment TX budget ran out while \
                 emitting this Interest's chain, so it was abandoned (a 0x3 Drop \
                 stop fragment followed any fragments already sent); retry once \
                 the budget is refilled"
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
            // Both mean "too large to send; no wire bytes emitted" — one
            // bound is the codec's, the other the reassembly slot's.
            SendWireError::ExceedsReassemblyCap => LivelinessGetError::ExceedsCapacity,
            // R2238 — NOT folded in above: that pair's shared claim includes
            // "no wire bytes emitted", which this one breaks.
            SendWireError::FragmentTxBudgetExhausted => LivelinessGetError::FragmentChainAbandoned,
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
    /// R2238 (open-debt item 580) — the session's fragment TX budget ran out
    /// while this query's chain was being emitted, so it was abandoned.
    /// Unlike every variant above, wire bytes MAY have been emitted (followed
    /// by a `0x3 Drop` stop fragment); retry once the budget is refilled.
    FragmentChainAbandoned,
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
            QueryAliasError::FragmentChainAbandoned => write!(
                f,
                "QueryAliasError: the session's fragment TX budget ran out while \
                 emitting this Request(Query)'s chain, so it was abandoned (a 0x3 \
                 Drop stop fragment followed any fragments already sent); retry \
                 once the budget is refilled"
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
            // Both mean "too large to send; no wire bytes emitted" — one
            // bound is the codec's, the other the reassembly slot's.
            SendWireError::ExceedsReassemblyCap => QueryAliasError::ExceedsCapacity,
            // R2238 — NOT folded in above: that pair's shared claim includes
            // "no wire bytes emitted", which this one breaks.
            SendWireError::FragmentTxBudgetExhausted => QueryAliasError::FragmentChainAbandoned,
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
    ///
    /// R311y797 — THE VERDICT NOW HAS TWO HALVES AND READS THE TARGET,
    /// the queryable-plane completion of what R311y788 did for the
    /// publisher.
    ///
    /// * SESSION-LOCAL half — a queryable declared on THIS session is a
    ///   real answerer: `Session::query` dispatches into that table on the
    ///   loopback leg whenever the locality allows it, and until this
    ///   round the poll consulted the REMOTE registry alone, so a querier
    ///   whose only queryable sat on its own session reported `false`
    ///   while its own `get` was answered. pico counts both halves
    ///   (`local_targets` beside `targets`,
    ///   `vendor/zenoh-pico/src/net/filtering.c:71`,`:141-155`).
    /// * TARGET — `AllComplete` asks for responders that can answer the
    ///   WHOLE keyexpr alone, so both halves switch predicate under it
    ///   (`complete` AND inclusion, rather than plain intersection). That
    ///   is zenoh's `MatchingStatusType::Queryables(target ==
    ///   AllComplete)` (`zenoh/src/api/querier.rs:225`) and pico's
    ///   `ctx->is_complete` (`vendor/zenoh-pico/src/api/api.c:1843-1844`).
    ///   The target is read through
    ///   [`QueryOptions::effective_target`](super::QueryOptions), never
    ///   the raw `pub` field, so a build without `query-target` cannot be
    ///   pushed into an AllComplete verdict it could not emit.
    ///
    /// Each half is additionally gated by this querier's own
    /// `allowed_destination` — the knob prior rounds recorded here as
    /// typed but unread (pico's `allow_local` / `allow_remote`,
    /// `filtering.c:261-262`). The remote half needs
    /// `declare-queryable`, the local half `query-queryable`; a build
    /// missing one contributes a structural `false` for that half rather
    /// than a stub, because in such a build the corresponding table
    /// cannot hold anything.
    pub fn get_matching_status(&self) -> MatchingStatus {
        // R311dd — observer access via R::with_mutex_mut closure form.
        // Replaces the AP-only `.lock()` + PoisonError::into_inner
        // recovery pattern; per-profile poison-recovery semantics now
        // live inside the Runtime impl.
        #[cfg(any(feature = "declare-queryable", feature = "query-queryable"))]
        let matching = {
            let locality = self.options.allowed_destination;
            let complete_required = self.complete_required();
            R::with_mutex_mut(&self.session.observer, |obs| {
                #[cfg(feature = "declare-queryable")]
                let remote = obs.remote_queryables.has_matching_for(
                    &wz_session_core::declare::queryable::QuerierCriterion::new(
                        &self.keyexpr,
                        locality,
                        complete_required,
                    ),
                );
                #[cfg(not(feature = "declare-queryable"))]
                let remote = false;
                #[cfg(feature = "query-queryable")]
                let local = locality.allows_local()
                    && obs
                        .queryables
                        .has_local_matching(&self.keyexpr, complete_required);
                #[cfg(not(feature = "query-queryable"))]
                let local = false;
                remote || local
            })
        };
        #[cfg(not(any(feature = "declare-queryable", feature = "query-queryable")))]
        let matching = false;
        MatchingStatus { matching }
    }

    /// R311y797 — whether this querier's target demands COMPLETE
    /// responders, i.e. zenoh's `Queryables(self.target ==
    /// QueryTarget::AllComplete)` discriminant
    /// (`zenoh/src/api/querier.rs:225`).
    ///
    /// A one-line forward to `QueryOptions::matching_needs_complete`,
    /// which is where the rule and its citations live; the aliased poll
    /// calls that same accessor directly. Same consumer-derived gate as
    /// that accessor carries.
    #[cfg(any(feature = "declare-queryable", feature = "query-queryable"))]
    fn complete_required(&self) -> bool {
        self.options.matching_needs_complete()
    }

    /// R311kh — callback counterpart of [`Self::get_matching_status`]
    /// (zenoh-pico querier matching listener, `Z_FEATURE_MATCHING`):
    /// `callback` fires on every matching-status TRANSITION of this
    /// querier's keyexpr against the remote QUERYABLE set.
    ///
    /// Registration fires `true` IMMEDIATELY when already matching, and
    /// is silent otherwise — pico's fire-before-insert at
    /// `vendor/zenoh-pico/src/net/filtering.c:341-357`, shared with the
    /// publisher form. The former "registration itself never fires"
    /// wording here misread pico; see
    /// [`wz_session_core::declare::matching::MatchingWatchList::register`].
    /// [`Self::get_matching_status`] remains the poll.
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
            // R311y797 — seed with the SAME verdict the poll reports, and
            // store the SAME criterion the poll computes, so registration
            // and `get_matching_status` cannot disagree at the instant the
            // listener is created and cannot drift afterwards: the watch
            // keeps re-evaluating under this querier's own target.
            let complete_required = self.complete_required();
            let locality = self.options.allowed_destination;
            let id = R::with_mutex_mut(&self.session.observer, |obs| {
                #[cfg(feature = "query-queryable")]
                let local = locality.allows_local()
                    && obs
                        .queryables
                        .has_local_matching(&self.keyexpr, complete_required);
                #[cfg(not(feature = "query-queryable"))]
                let local = false;
                obs.remote_queryables.declare_matching_listener_seeded(
                    wz_session_core::declare::queryable::QuerierCriterion::new(
                        &self.keyexpr,
                        locality,
                        complete_required,
                    ),
                    local,
                    sink,
                )
            });
            // R311y771 — the QUERYABLE-plane twin of the emit in
            // `Publisher::declare_matching_listener`; read its comment for
            // the register-first ordering, the rollback, and the recorded
            // divergence from zenoh's emit site. The router gate here is
            // `hat/router/queries.rs:255-259`, which requires
            // `options.queryables()`, and zenoh's own emit is in
            // `declare_querier_inner` (`api/session.rs:1428-1435`).
            #[cfg(feature = "declare-interest")]
            let interest_id = {
                let interest_id = self.session.actions().alloc_next_interest_id();
                let emit = wz_session_core::interest_build::build_interest_queryables(
                    interest_id,
                    /*current=*/ true,
                    /*future=*/ true,
                    /*keyexpr_mapping_id=*/ 0,
                    Some(&self.keyexpr),
                )
                .map_err(wz_session_core::send_wire_error::SendWireError::Codec)
                .and_then(|interest| {
                    self.session.send_network_message(
                        wz_session_core::network_message::NetworkMessage::Interest(interest),
                        /*reliable=*/ true,
                        /*express=*/ false,
                    )
                });
                if let Err(e) = emit {
                    cell.kill();
                    R::with_mutex_mut(&self.session.observer, |obs| {
                        obs.remote_queryables.undeclare_matching_listener(id)
                    });
                    return Err(MatchingListenerError::Wire(e));
                }
                self.session.actions().cache_matching_interest(
                    interest_id,
                    wz_session_core::interest_build::InterestKinds::QUERYABLES,
                    /*current=*/ true,
                    /*future=*/ true,
                    /*keyexpr_mapping_id=*/ 0,
                    Some(&self.keyexpr),
                );
                interest_id
            };
            let listener = MatchingListener {
                session: self.session.clone(),
                id,
                scope: MatchingScope::RemoteQueryables,
                cell,
                #[cfg(feature = "declare-interest")]
                interest_id,
            };
            // Deliver an already-matching registration's staged fire on the
            // registering thread; see `Publisher::declare_matching_listener`
            // for the pico contract this mirrors and why the drain is
            // unconditional and placed after the handle exists.
            self.session.drain_deferred_fires();
            Ok(listener)
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
        // R311y797 — the literal twin's rule verbatim, over the composed
        // effective keyexpr: both halves, each gated by this querier's own
        // `allowed_destination`, under the criterion its target selects.
        // See `Querier::get_matching_status` for every upstream citation;
        // the two must not diverge, which is why the target question is
        // asked through the shared `complete_required` helper rather than
        // re-derived here.
        #[cfg(any(feature = "declare-queryable", feature = "query-queryable"))]
        let matching = {
            let locality = self.options.allowed_destination;
            let complete_required = self.options.matching_needs_complete();
            R::with_mutex_mut(&self.session.observer, |obs| {
                #[cfg(feature = "declare-queryable")]
                let remote = obs.remote_queryables.has_matching_for(
                    &wz_session_core::declare::queryable::QuerierCriterion::new(
                        &_effective_keyexpr,
                        locality,
                        complete_required,
                    ),
                );
                #[cfg(not(feature = "declare-queryable"))]
                let remote = false;
                #[cfg(feature = "query-queryable")]
                let local = locality.allows_local()
                    && obs
                        .queryables
                        .has_local_matching(&_effective_keyexpr, complete_required);
                #[cfg(not(feature = "query-queryable"))]
                let local = false;
                remote || local
            })
        };
        #[cfg(not(any(feature = "declare-queryable", feature = "query-queryable")))]
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

#[cfg(all(test, feature = "query-get", feature = "query-value"))]
mod value_threading_tests {
    use super::*;

    /// R311y250 — `QueryOptions::with_payload` collapses onto the
    /// `QueryMetadata::value` slot so a querier's attached value reaches the
    /// wire builder (`build_request_query_with_meta` ->
    /// `RequestQueryBuilder::query_value`). The QueryOptions -> QueryMetadata
    /// half of the query-value send path (the wire half is locked in
    /// request_build.rs). A payload-only value fills the zero-encoding half.
    #[test]
    fn with_payload_threads_into_query_metadata_value() {
        let opts = QueryOptions::get().with_payload(b"q-value".to_vec());
        let meta = opts.query_metadata();
        assert_eq!(
            meta.value,
            Some((EncodingHint::default(), b"q-value".to_vec())),
            "payload-only value fills the zero encoding half",
        );
        assert!(!meta.is_empty(), "a value makes the metadata non-empty");
    }

    /// `with_encoding` composes with `with_payload` into the single value
    /// unit; an encoding-only value (no payload) is valid (zenoh-pico
    /// `_z_encoding_check` emits the ext for a non-default encoding).
    #[test]
    fn with_encoding_threads_into_query_metadata_value() {
        let enc = EncodingHint {
            packed_id: 0x0A, // id 5, no schema flag (non-default id)
            schema: None,
        };
        let meta = QueryOptions::get()
            .with_encoding(enc.clone())
            .query_metadata();
        assert_eq!(
            meta.value,
            Some((enc, Vec::new())),
            "encoding-only value fills the empty payload half",
        );
        assert!(!meta.is_empty());
    }

    /// The `(None, None) -> None` collapse: a default QueryOptions (no
    /// payload, no encoding) yields `value = None`.
    ///
    /// R311y326 — the trailing `is_empty()` assertion is now build-dependent:
    /// with `query-timeout` ON, default options resolve the timeout to
    /// `DEFAULT_QUERY_TIMEOUT_MS`, so the metadata is non-empty even though the
    /// value slot is `None`. The value-collapse this test names is unaffected;
    /// only the incidental emptiness check splits by build.
    #[test]
    fn default_options_yield_no_value() {
        let meta = QueryOptions::get().query_metadata();
        assert_eq!(meta.value, None);
        #[cfg(not(feature = "query-timeout"))]
        assert!(meta.is_empty());
        #[cfg(feature = "query-timeout")]
        assert_eq!(
            meta.timeout_ms, DEFAULT_QUERY_TIMEOUT_MS,
            "the only non-empty slot on default options is the resolved timeout"
        );
    }
}
