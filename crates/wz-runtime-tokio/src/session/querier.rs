// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Querier handle cluster split out of `session/mod.rs` (pure
//! refactor): [`QueryOptions`], the [`Querier`] / [`QuerierAliased`]
//! handles, [`MatchingStatus`], [`QueryAliasError`],
//! [`LivelinessGetOptions`], and [`LivelinessGetError`]. The parent
//! module re-exports the public types via `pub use querier::*;` so the
//! path `wz_runtime_tokio::session::Querier` etc. is unchanged.

use super::*;

// The options of one query are session-core's (`wz_session_core::query_options`): moved down so a
// session on any runtime asks with one set of rules. Re-exported here so
// `wz_runtime_tokio::session::QueryOptions` keeps its path. The platform default timeout is read
// here by the liveliness get, and by the tests that pin it; the z_get path reads it through
// `effective_timeout_ms`.
pub use wz_session_core::query_options::QueryOptions;
#[cfg(any(feature = "liveliness-get", all(test, feature = "query-timeout")))]
pub(crate) use wz_session_core::query_options::DEFAULT_QUERY_TIMEOUT_MS;

/// liveliness-get — options for [`Session::liveliness_get`]. Mirrors
/// zenoh-pico's `z_liveliness_get_options_t` (currently the timeout only).
///
/// R311y326 — `timeout_ms == 0` is the "use the default" sentinel, resolved by
/// `Self::effective_timeout_ms` to [`DEFAULT_QUERY_TIMEOUT_MS`]. This doc
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
    /// ([`DEFAULT_QUERY_TIMEOUT_MS`], via `Self::effective_timeout_ms`); any
    /// value arms the driver-loop sweep to terminate the get if the peer never
    /// terminates the snapshot, so the pending slot cannot leak.
    /// R311y323 — the sweep fires `on_timeout`, not a bare `on_final`: an
    /// expired snapshot delivers a synthetic `Err("Timeout")` and then its
    /// final, matching zenoh's liveliness timeout arm.
    pub timeout_ms: u32,
}

impl LivelinessGetOptions {
    /// Default options — `timeout_ms = 0` (the "use the default" sentinel;
    /// `Self::effective_timeout_ms` resolves it to
    /// [`DEFAULT_QUERY_TIMEOUT_MS`]). Mirrors zenoh-pico's
    /// `z_liveliness_get_options_default`, whose `0` `z_liveliness_get` likewise
    /// rewrites to the default before issuing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set the snapshot `timeout_ms`. `0` selects the platform
    /// default rather than never-expire (see `Self::effective_timeout_ms`).
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
    /// R2674 — [`Session::liveliness_get_with_channel`] spawns the snapshot's
    /// timeout reaper, so it must be called from within a tokio runtime
    /// context. Fail-clear instead of a `tokio::spawn` panic, exactly as
    /// `GroupError::NoRuntime` does for the group watchdog.
    ///
    /// Only the CHANNEL form can return this. The callback
    /// [`Session::liveliness_get`] spawns nothing and is unaffected, which is
    /// the seam a driver-run profile keeps: it reaps through
    /// [`Session::sweep_expired_liveliness_gets`] instead of an executor.
    NoRuntime,
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
            LivelinessGetError::NoRuntime => write!(
                f,
                "LivelinessGetError: the channel form spawns the snapshot's \
                 timeout reaper and must be called from within a tokio runtime; \
                 no snapshot was registered. Use the callback `liveliness_get` \
                 and drive `sweep_expired_liveliness_gets` yourself off-runtime"
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
    /// The `QUERIER_MAX_PENDING_QUERIES` quota: this declared querier already has as many
    /// queries in flight as its bound allows. Nothing was sent and nothing was registered;
    /// a place comes back when a pending query ends, so the same call can succeed later.
    /// `limit` is the bound that was reached.
    QuotaExceeded {
        /// The bound that was reached.
        limit: usize,
    },
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
            QueryAliasError::QuotaExceeded { limit } => write!(
                f,
                "QueryAliasError: this querier already has {limit} quer(ies) in flight, \
                 its bound; the Request(Query) was not emitted — retry once one ends"
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

/// The places one declared querier has for queries in flight: the `QUERIER_MAX_PENDING_QUERIES`
/// quota of that declaration. Shared by every clone of the handle, because a clone is another
/// handle to the same declaration and not another querier, so the bound is per declaration and
/// one busy querier cannot take the places of another.
#[derive(Clone)]
pub(crate) struct QuerierSlots {
    quota: Arc<std::sync::Mutex<wz_session_core::quota::Quota>>,
}

impl QuerierSlots {
    /// The places of a querier declared now: the build's bound.
    pub(crate) fn new() -> Self {
        Self::with_limit(wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES)
    }

    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            quota: Arc::new(std::sync::Mutex::new(wz_session_core::quota::Quota::new(
                limit,
            ))),
        }
    }

    /// Take a place for one query, or say the bound is reached. A refusal takes no place and
    /// changes nothing. The place goes back when the query ends: see [`QueryPlace`].
    pub(crate) fn take(&self) -> Result<QueryPlace, QueryAliasError> {
        Ok(QueryPlace(Arc::new(QuerySlot::acquire(&self.quota)?)))
    }

    /// Replace the bound; test-only, and takes effect for the queries asked after it. Gated on
    /// `query-get` as well as `test`: its callers are the query tests, so a test build without
    /// that feature would carry it unused.
    #[cfg(all(test, feature = "query-get"))]
    pub(crate) fn set_limit(&self, limit: usize) {
        let mut held = match self.quota.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        held.set_limit(limit);
    }

    /// The queries in flight now. Gated as [`Self::set_limit`] is.
    #[cfg(all(test, feature = "query-get"))]
    pub(crate) fn pending(&self) -> usize {
        match self.quota.lock() {
            Ok(held) => held.live(),
            Err(poisoned) => poisoned.into_inner().live(),
        }
    }
}

/// The place one query in flight holds, handed to its two callbacks. It goes back exactly once:
/// after the query's final has run, or, when no final runs (the pending entry was unregistered,
/// or the send failed before the entry was kept), when the last callback is dropped.
pub(crate) struct QueryPlace(Arc<QuerySlot>);

impl QueryPlace {
    /// `on_reply` as the pending entry holds it: it keeps the place alive for as long as the
    /// entry holds the callback, so dropping the entry returns the place.
    pub(crate) fn guard_reply(
        &self,
        mut on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
    ) -> impl FnMut(&dyn ReplyView) + Send + 'static {
        let held = self.0.clone();
        move |reply: &dyn ReplyView| {
            let _held = &held;
            on_reply(reply);
        }
    }

    /// `on_final` as the pending entry holds it: the place goes back once it has run.
    pub(crate) fn guard_final(
        &self,
        mut on_final: impl FnMut(u64) + Send + 'static,
    ) -> impl FnMut(u64) + Send + 'static {
        let held = self.0.clone();
        move |rid: u64| {
            on_final(rid);
            held.release();
        }
    }
}

/// One place of a [`QuerierSlots`], held by one query in flight and given back exactly once.
struct QuerySlot {
    quota: Arc<std::sync::Mutex<wz_session_core::quota::Quota>>,
    returned: std::sync::atomic::AtomicBool,
}

impl QuerySlot {
    fn acquire(
        quota: &Arc<std::sync::Mutex<wz_session_core::quota::Quota>>,
    ) -> Result<Self, QueryAliasError> {
        let mut held = match quota.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        held.try_acquire()
            .map_err(|full| QueryAliasError::QuotaExceeded { limit: full.limit })?;
        drop(held);
        Ok(Self {
            quota: quota.clone(),
            returned: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn release(&self) {
        if self
            .returned
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        let mut held = match self.quota.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        held.release();
    }
}

impl Drop for QuerySlot {
    fn drop(&mut self) {
        self.release();
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
    /// This declaration's places for queries in flight, shared by every clone.
    pub(super) slots: QuerierSlots,
}

impl<R: SessionRuntime, T: TimeSource> Clone for Querier<R, T> {
    fn clone(&self) -> Self {
        // R2577 — a clone is another live querier on this keyexpr, so it takes
        // its own reference on the session's QUERYABLES Interest. See
        // `Publisher`'s pair for why the count cannot live on the handle.
        #[cfg(all(feature = "session-matching", feature = "declare-interest"))]
        self.session
            .acquire_matching_interest(crate::session::MatchingPlane::Queryables, &self.keyexpr);
        Self {
            session: self.session.clone(),
            keyexpr: self.keyexpr.clone(),
            options: self.options.clone(),
            slots: self.slots.clone(),
        }
    }
}

/// R2577 — the querier's half of the Interest lifecycle, the mirror of
/// `Publisher`'s. Only the LAST live handle on a keyexpr retracts, because the
/// count lives on the session rather than on this handle.
impl<R: SessionRuntime, T: TimeSource> Drop for Querier<R, T> {
    fn drop(&mut self) {
        #[cfg(all(feature = "session-matching", feature = "declare-interest"))]
        self.session
            .release_matching_interest(crate::session::MatchingPlane::Queryables, &self.keyexpr);
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
        let place = self.slots.take()?;
        let (on_reply, on_final) = (place.guard_reply(on_reply), place.guard_final(on_final));
        self.session
            .query(&self.keyexpr, self.options.clone(), on_reply, on_final)
    }

    /// transport-shm -- [`Self::get`] whose VALUE is a shared-memory buffer, as
    /// upstream's `querier.get().payload(shm_buf)`. The buffer is the query's value
    /// and replaces `options.payload`; see [`Session::query_shm`] for what the wire
    /// carries and for the legs that carry the bytes instead.
    #[cfg(all(feature = "transport-shm", feature = "query-value"))]
    pub fn get_shm(
        &self,
        value: &crate::shm_provider::ShmBackedPayload,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        let place = self.slots.take()?;
        let (on_reply, on_final) = (place.guard_reply(on_reply), place.guard_final(on_final));
        self.session.query_shm(
            &self.keyexpr,
            self.options.clone(),
            value,
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
                    )
                    .with_remote_inclusion(self.options.remote_inclusion()),
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
                cell.stage(&queue, move |cb| cb(MatchingStatus { matching: m }));
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
                    )
                    .with_remote_inclusion(self.options.remote_inclusion()),
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
                // Recorded for reconnect replay and sent through the seam, as one step.
                let emit = self.session.actions().declare_matching_interest_recorded(
                    interest_id,
                    wz_session_core::interest_build::InterestKinds::QUERYABLES,
                    /*current=*/ true,
                    /*future=*/ true,
                    /*aggregate=*/ false,
                    /*keyexpr_mapping_id=*/ 0,
                    Some(&self.keyexpr),
                    || {
                        wz_session_core::interest_build::build_interest_queryables(
                            interest_id,
                            /*current=*/ true,
                            /*future=*/ true,
                            /*keyexpr_mapping_id=*/ 0,
                            Some(&self.keyexpr),
                        )
                        .map_err(wz_session_core::send_wire_error::SendWireError::Codec)
                        .and_then(|interest| {
                            self.session.send_network_message(
                                wz_session_core::network_message::NetworkMessage::Interest(
                                    interest,
                                ),
                                /*reliable=*/ true,
                                /*express=*/ false,
                            )
                        })
                    },
                );
                if let Err(e) = emit {
                    cell.kill();
                    R::with_mutex_mut(&self.session.observer, |obs| {
                        obs.remote_queryables.undeclare_matching_listener(id)
                    });
                    return Err(MatchingListenerError::Wire(e));
                }
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
    /// This declaration's places for queries in flight, shared by every clone.
    pub(super) slots: QuerierSlots,
}

impl<R: SessionRuntime, T: TimeSource> Clone for QuerierAliased<R, T> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            mapping_id: self.mapping_id,
            inline_suffix: self.inline_suffix.clone(),
            options: self.options.clone(),
            slots: self.slots.clone(),
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
        let place = self.slots.take()?;
        let (on_reply, on_final) = (place.guard_reply(on_reply), place.guard_final(on_final));
        self.session.query_aliased_auto(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            self.options.clone(),
            on_reply,
            on_final,
        )
    }

    /// transport-shm -- [`Self::get`] whose VALUE is a shared-memory buffer; the
    /// aliased counterpart of [`Querier::get_shm`], through
    /// [`Session::query_aliased_auto_shm`].
    #[cfg(all(feature = "transport-shm", feature = "query-value"))]
    pub fn get_shm(
        &self,
        value: &crate::shm_provider::ShmBackedPayload,
        on_reply: impl FnMut(&dyn ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<ReplyHandle, QueryAliasError> {
        let place = self.slots.take()?;
        let (on_reply, on_final) = (place.guard_reply(on_reply), place.guard_final(on_final));
        self.session.query_aliased_auto_shm(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            self.options.clone(),
            value,
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
                    )
                    .with_remote_inclusion(self.options.remote_inclusion()),
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
