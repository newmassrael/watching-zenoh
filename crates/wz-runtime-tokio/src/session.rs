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

use wz_codecs::query::Query;

use crate::locality::Locality;
use crate::observer::ApplicationLayerObserver;
use crate::query::QueryReply;
use crate::reply::{InboundReply, ReplyHandle};
use crate::sample::{
    EncodingHint, QosLevel, Reliability, Sample, SampleKind, SourceInfo, TimestampHint,
};
use crate::session_glue::{
    ConsolidationMode, PushMetadata, QueryMetadata, QueryTarget, SessionLinkActions,
};

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
    pub fn with_target(mut self, target: QueryTarget) -> Self {
        self.target = Some(target);
        self
    }

    /// Pin the reply consolidation hint. `Some(mode)` flips the Q_C
    /// flag on the outbound Query so the peer applies the mode.
    pub fn with_consolidation(mut self, consolidation: ConsolidationMode) -> Self {
        self.consolidation = Some(consolidation);
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
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
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
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> usize {
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
    pub fn query(
        &self,
        keyexpr: &str,
        opts: QueryOptions,
        on_reply: impl FnMut(&InboundReply) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> ReplyHandle {
        let rid = self.actions.alloc_next_request_id();
        let expected_finals = opts.expected_finals();
        let allows_remote = opts.allowed_destination.allows_remote();
        let allows_local = opts.allowed_destination.allows_local();

        let handle = {
            let mut observer = self
                .observer
                .lock()
                .expect("Session observer mutex poisoned — a reply callback panicked");
            let handle = observer
                .replies
                .register(rid, expected_finals, on_reply, on_final);
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

        handle
    }
}

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
    use crate::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let actions = SessionLinkActions::new(driver.clone(), fixture_params());
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
                *captured_clone.lock().unwrap() =
                    Some((sample.kind, sample.payload.clone()));
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
                .register_with_locality(
                    "home/temp",
                    Locality::SessionLocal,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Remote,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
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
        let fired = session.publish_aliased(
            7,
            None,
            "home/temp",
            b"22.5",
            PublishOptions::put(),
        );
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
                *captured_clone.lock().unwrap() = Some((
                    sample.kind,
                    sample.payload.clone(),
                    sample.keyexpr.clone(),
                ));
            });

        let opts = PublishOptions::del();
        let fired = session.publish_aliased(7, None, "home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload, keyexpr) =
            captured.lock().unwrap().clone().expect("fired");
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
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp/kitchen", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.keyexpr.clone());
            });

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
        let fired =
            session.publish_aliased(7, None, "home/temp", b"x", opts);
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
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("intentionally_decoupled", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

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
                .register_with_locality(
                    "home/temp",
                    Locality::Any,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::SessionLocal,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Remote,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
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
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
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
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
            Some(&initial[..]),
            "rejected length-0 install must not mutate previously-installed zid"
        );

        assert!(!session.set_own_zid(vec![0u8; 17]));
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
            Some(&initial[..]),
            "rejected length-17 install must not mutate previously-installed zid"
        );
    }

    #[test]
    fn clear_own_zid_forwards_to_subscriber_registry() {
        let (session, _driver) = build_session();
        assert!(session.set_own_zid(vec![0x09, 0x08, 0x07, 0x06]));
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_some()
        );

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
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
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
        let actions = SessionLinkActions::new(driver.clone(), params);
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
        let actions = SessionLinkActions::new(driver.clone(), params);
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
        session.actions().send_declare_keyexpr(7, "home/temp");
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

        session.actions().send_declare_keyexpr(7, "home");
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

        session.actions().send_declare_keyexpr(7, "home/temp");
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
        assert!(s.contains("123"), "error message must contain the mapping id");
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
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_query, responder| {
                responder.send_reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| {
                r.fetch_add(1, Ordering::SeqCst);
                assert_eq!(reply.keyexpr_literal, "home/temp");
                assert_eq!(reply.body, InboundReplyBody::Put { payload: b"22.5".to_vec() });
            },
            move |_rid| { f.fetch_add(1, Ordering::SeqCst); },
        );

        assert_eq!(reply_count.load(Ordering::SeqCst), 1, "loopback reply fires inline");
        assert_eq!(final_count.load(Ordering::SeqCst), 1, "SessionLocal final completes inline");
        assert_eq!(driver.frame_count(), 0, "SessionLocal must NOT touch the wire");
        assert!(
            session.observer().lock().unwrap().replies.is_empty(),
            "expected_finals=1 closes the pending entry on the loopback final"
        );
    }

    #[test]
    fn query_locality_remote_fires_wire_only_and_keeps_pending_until_wire_final() {
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
                responder.send_reply(b"loopback-should-not-fire");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            move |_reply| { r.fetch_add(1, Ordering::SeqCst); },
            move |_rid| { f.fetch_add(1, Ordering::SeqCst); },
        );

        assert_eq!(reply_count.load(Ordering::SeqCst), 0, "Remote suppresses loopback");
        assert_eq!(final_count.load(Ordering::SeqCst), 0, "wire Final has not arrived yet");
        assert_eq!(driver.frame_count(), 1, "wire Request(Query) frame on the driver");
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            1,
            "pending entry preserved waiting for the peer's Final"
        );
    }

    #[test]
    fn query_locality_any_fires_both_branches_and_waits_for_wire_final() {
        let (session, driver) = build_session();
        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", |_q, responder| {
                responder.send_reply(b"22.5");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        let _handle = session.query(
            "home/temp",
            QueryOptions::get(), // Any (default)
            move |_reply| { r.fetch_add(1, Ordering::SeqCst); },
            move |_rid| { f.fetch_add(1, Ordering::SeqCst); },
        );

        // Inline observations:
        assert_eq!(reply_count.load(Ordering::SeqCst), 1, "loopback reply fires inline");
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "Locality::Any on_final must wait for the wire Final too (expected_finals=2)"
        );
        assert_eq!(driver.frame_count(), 1, "wire branch dispatched one Request(Query)");
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            1,
            "pending entry preserved waiting for the remaining wire Final"
        );

        // Simulate the peer's ResponseFinal — the second of the two
        // expected finals — and observe on_final fire then.
        use wz_codecs::response_final::ResponseFinal;
        let mut observer = session.observer().lock().unwrap();
        observer
            .replies
            .dispatch_response_final(&ResponseFinal { request_id: 0, ..ResponseFinal::default() });
        drop(observer);

        assert_eq!(final_count.load(Ordering::SeqCst), 1, "second Final closes the chain");
        assert!(
            session.observer().lock().unwrap().replies.is_empty(),
            "pending entry dropped after the closing Final"
        );
    }

    #[test]
    fn query_handle_carries_rid_zero_for_first_call_then_monotonic() {
        let (session, _driver) = build_session();
        let h0 = session.query(
            "k",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        );
        let h1 = session.query(
            "k",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        );
        assert_eq!(h0.rid(), 0);
        assert_eq!(h1.rid(), 1, "alloc_next_request_id increments monotonically");
    }

    #[test]
    fn query_loopback_propagates_del_body() {
        let (session, _driver) = build_session();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("clear/me", |_q, responder| {
                responder.send_reply_del();
            });

        session.query(
            "clear/me",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| { *cap_cb.lock().unwrap() = Some(reply.clone()); },
            |_| {},
        );

        let got = captured.lock().unwrap().clone().expect("on_reply must fire");
        assert_eq!(got.body, InboundReplyBody::Del);
        assert_eq!(got.keyexpr_literal, "clear/me");
    }

    #[test]
    fn query_loopback_propagates_err_body_with_encoding_tuple() {
        let (session, _driver) = build_session();
        let captured: Arc<Mutex<Option<InboundReply>>> = Arc::new(Mutex::new(None));
        let cap_cb = captured.clone();

        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("error/path", |_q, responder| {
                responder.send_err(Some(4), Some("schema_v1"), b"oops");
            });

        session.query(
            "error/path",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply| { *cap_cb.lock().unwrap() = Some(reply.clone()); },
            |_| {},
        );

        let got = captured.lock().unwrap().clone().expect("on_reply must fire");
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
                responder.send_reply(b"99");
            });

        let r = reply_count.clone();
        let f = final_count.clone();
        session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| { r.fetch_add(1, Ordering::SeqCst); },
            move |_| { f.fetch_add(1, Ordering::SeqCst); },
        );

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
            .register_with_locality(
                "home/temp",
                Locality::Remote,
                move |_q, _responder| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                },
            );

        let reply_count = Arc::new(AtomicUsize::new(0));
        let final_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        let f = final_count.clone();
        session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| { r.fetch_add(1, Ordering::SeqCst); },
            move |_| { f.fetch_add(1, Ordering::SeqCst); },
        );

        assert_eq!(fired.load(Ordering::SeqCst), 0, "Remote-only queryable must skip loopback");
        assert_eq!(reply_count.load(Ordering::SeqCst), 0);
        assert_eq!(final_count.load(Ordering::SeqCst), 1, "loopback Final still fires");
    }

    #[test]
    fn query_session_local_with_session_local_queryable_fires() {
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
            .register_with_locality(
                "home/temp",
                Locality::SessionLocal,
                move |_q, responder| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                    responder.send_reply(b"22.5");
                },
            );

        let reply_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |_| { r.fetch_add(1, Ordering::SeqCst); },
            |_| {},
        );

        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert_eq!(reply_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn query_locality_remote_alone_skips_local_queryable() {
        // A local Locality::Any queryable does fire on its own
        // session's Remote-only query? NO — the loopback branch is
        // gated on opts.allowed_destination.allows_local(); Remote
        // sets that to false. Mirrors the publish-side
        // publish_locality_remote_fires_wire_only invariant for the
        // queryable side.
        let (session, driver) = build_session();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .queryables
            .register("home/temp", move |_q, responder| {
                fired_cb.fetch_add(1, Ordering::SeqCst);
                responder.send_reply(b"22.5");
            });

        let reply_count = Arc::new(AtomicUsize::new(0));
        let r = reply_count.clone();
        session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            move |_| { r.fetch_add(1, Ordering::SeqCst); },
            |_| {},
        );

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
        let actions = SessionLinkActions::new(driver, fixture_params());
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
            .with_encoding(EncodingHint { packed_id: 1, schema: None });
        let meta = opts.query_metadata();
        assert_eq!(meta.target, Some(QueryTarget::AllComplete));
        assert_eq!(meta.consolidation, Some(ConsolidationMode::Monotonic));
        assert_eq!(meta.attachment.as_deref(), Some(&b"q-att"[..]));
        assert_eq!(meta.timeout_ms, 5_000);
    }

    #[test]
    fn query_options_default_query_metadata_is_empty() {
        let meta = QueryOptions::default().query_metadata();
        assert!(meta.is_empty(), "default options produce empty wire metadata");
    }

    #[test]
    fn query_wire_branch_with_empty_meta_emits_no_meta_fast_path_frame() {
        // Session::query with default options (Locality::Any, no
        // metadata) MUST take the no-meta fast path → wire frame is
        // byte-identical to a standalone send_request_query call.
        // Pins the R240 short-circuit invariant at the Session
        // level.
        let (session, driver) = build_session();
        session.query(
            "home/temp",
            QueryOptions::get().with_allowed_destination(Locality::Remote),
            |_| {},
            |_| {},
        );
        let session_frame = driver.frames.lock().unwrap()[0].0.clone();

        // Mirror the call against an independent recording driver +
        // SessionLinkActions, using the bare no-metadata API, and
        // assert byte parity. Construct a fresh session so the
        // outbound Frame SN starts from the same initial_sn=1; the
        // alloc_next_request_id counter also starts at 0 so the
        // request_id matches.
        let driver2 = Arc::new(RecordingDriver::new());
        let actions2 = SessionLinkActions::new(driver2.clone(), fixture_params());
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
        // QueryOptions::with_target lands on the outbound Request via
        // the with-meta path. Pins the R240 Session-level integration
        // between QueryOptions.target → QueryMetadata.target →
        // RequestQueryBuilder::request_target.
        let (session, driver) = build_session();
        session.query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_target(QueryTarget::AllComplete),
            |_| {},
            |_| {},
        );

        // Re-encode an equivalent standalone Request with target=All
        // and assert the wire bytes appear verbatim in the recorded
        // frame.
        use crate::session_glue::build_request_query_with_target;
        let standalone =
            build_request_query_with_target(0, 0, Some("home/temp"), QueryTarget::AllComplete);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame.windows(standalone_bytes.len()).any(|w| w == standalone_bytes),
            "Session::query wire frame must contain with-target Request bytes"
        );
    }

    #[test]
    fn query_wire_branch_with_attachment_threads_attachment_through_with_meta() {
        let (session, driver) = build_session();
        session.query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_attachment(b"q-att".to_vec()),
            |_| {},
            |_| {},
        );

        use crate::session_glue::build_request_query_with_attachment;
        let standalone = build_request_query_with_attachment(0, 0, Some("home/temp"), b"q-att");
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame.windows(standalone_bytes.len()).any(|w| w == standalone_bytes),
            "wire frame must contain with-attachment Request bytes"
        );
    }

    #[test]
    fn query_wire_branch_with_consolidation_threads_consolidation_through_with_meta() {
        let (session, driver) = build_session();
        session.query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::Remote)
                .with_consolidation(ConsolidationMode::Latest),
            |_| {},
            |_| {},
        );

        use crate::session_glue::build_request_query_with_consolidation;
        let standalone =
            build_request_query_with_consolidation(0, 0, Some("home/temp"), ConsolidationMode::Latest);
        let standalone_bytes = standalone.encode_to_vec();
        let frame = &driver.frames.lock().unwrap()[0].0;
        assert!(
            frame.windows(standalone_bytes.len()).any(|w| w == standalone_bytes),
            "wire frame must contain with-consolidation Request bytes"
        );
    }

    #[test]
    fn query_session_local_with_any_metadata_skips_wire_branch_entirely() {
        // R240 invariance: even with non-empty QueryMetadata, a
        // Locality::SessionLocal query MUST NOT touch the wire. The
        // meta extraction happens regardless but the actions surface
        // is never invoked.
        let (session, driver) = build_session();
        session.query(
            "home/temp",
            QueryOptions::get()
                .with_allowed_destination(Locality::SessionLocal)
                .with_target(QueryTarget::All)
                .with_attachment(b"q-att".to_vec())
                .with_timeout_ms(1_000),
            |_| {},
            |_| {},
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal must skip the wire branch regardless of metadata"
        );
    }
}
