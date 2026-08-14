// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Queryable handle cluster split out of `session/mod.rs` (pure
//! refactor): [`QueryableOptions`], the RAII [`Queryable`] handle,
//! and [`QueryableAliasError`]. The parent module re-exports these
//! via `pub use queryable::*;` so the public path
//! `wz_runtime_tokio::session::Queryable` is unchanged.

use super::*;

/// R246 — options bundle for [`Session::declare_queryable`].
/// Mirrors zenoh-pico's `z_queryable_options_t` — R311up wired the
/// `complete` flag (the BestMatching producer signal). `#[non_exhaustive]`.
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
    /// Whether this queryable declares itself COMPLETE — it can FULLY
    /// answer queries for its keyexpr (e.g. a storage holding the whole
    /// key space). zenoh-pico's `z_queryable_options_t::complete`. The
    /// flag rides the declared `DeclareQueryable`'s `QueryableInfo` ext
    /// and drives a router's BestMatching routing: a complete queryable
    /// is the preferred (nearest-complete) target, and the sole target an
    /// `AllComplete` query reaches. Default `false` (incomplete) — the
    /// DEFAULT `QueryableInfo`, omitted on the wire (byte-identical to a
    /// plain declaration).
    pub complete: bool,
}

impl QueryableOptions {
    /// Default options — `allowed_origin = Locality::Any`, `complete = false`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the queryable-side locality predicate.
    pub fn with_allowed_origin(mut self, locality: Locality) -> Self {
        self.allowed_origin = locality;
        self
    }

    /// Declare this queryable COMPLETE (it can fully answer its keyexpr —
    /// the BestMatching producer signal). See
    /// [`complete`](QueryableOptions::complete).
    pub fn with_complete(mut self, complete: bool) -> Self {
        self.complete = complete;
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
// R311cu — R267 helper cascade. Same pattern as Subscriber: `!Clone`
// by construction; Drop is generic via R::with_mutex_mut.
/// R311li — the type-erased user handler a deferred queryable's cell
/// holds: erased at registration so the [`Queryable`] handle has a
/// nameable cell type (the [`Subscriber`] / [`DeclListener`]
/// convention).
#[cfg(feature = "query-queryable")]
pub(super) type BoxedQueryHandler =
    Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static>;

/// R311li — the per-queryable deferred-fire cell (take-call-restore
/// with the lossless backlog; see [`wz_session_core::deferred_fire`]).
/// The registry-installed staging sink fires against it;
/// [`Queryable::undeclare`] / `Drop` kill it so a staged-but-undrained
/// query never reaches a removed queryable's handler.
#[cfg(feature = "query-queryable")]
pub(super) type QueryHandlerCell<R> =
    wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedQueryHandler>;

/// R311li — owned copy of one matched inbound query, staged for the
/// deferred handler job (a deferred fire outlives the dispatch
/// borrow). The job rebuilds a [`crate::query_sink::BorrowedQuery`]
/// over these fields when it runs the handler.
#[cfg(feature = "query-queryable")]
struct OwnedQueryEvent {
    keyexpr: String,
    parameters: Option<Vec<u8>>,
    attachment: Option<Vec<u8>>,
    source_info: Option<SourceInfo>,
    // R311y248 — the querier's VALUE ext (payload + encoding), owned so the
    // deferred handler can read it at drain time (the borrowed view is gone by
    // then, mirroring the attachment/source_info owned-copy shape).
    payload: Option<Vec<u8>>,
    encoding: Option<EncodingHint>,
    rid: u64,
    is_local: bool,
}

impl<R: SessionRuntime, T: TimeSource> Session<R, T, Unicast> {
    /// R311li — build the deferred cell + the staging sink one
    /// `declare_queryable{_aliased}` call installs in the registry: the
    /// sink copies the matched query out (owned) and stages one queue
    /// job; the job runs the user handler OUTSIDE the observer lock
    /// over a [`wz_session_core::query::QueryResponder`] bound to a
    /// job-local reply buffer, then routes the accumulated replies by
    /// query origin — wire queries emit each reply through the actions
    /// layer directly (the [`Self::dispatch_iteration_event_with`]
    /// SSOT emits the matching ResponseFinal after the drain, so
    /// Reply-before-Final holds), local queries deliver back into the
    /// local reply registry (whose own deferred reply fires drain in
    /// the same pass). The handler signature is unchanged — deferral
    /// is invisible at the type level.
    ///
    /// B5b-2b / R311nf — the wire-reply leg of the sink emits through the
    /// UNICAST action bundle (`actions.send_response`), which a multicast
    /// session has no analogue of. The resolved unicast `actions` is threaded
    /// in by the caller rather than projected from a fallible `actions()` (an
    /// `impl FnMut`-in-`Result` would trip `clippy::type_complexity`). The
    /// unicast guarantee is now STRUCTURAL, not a runtime reject: this helper
    /// lives on the `impl Session<R, T, Unicast>` block, so it can only ever be
    /// reached on a unicast transport (a `Session<R, T, Multicast>` does not
    /// have it — a compile error, not an `UnsupportedVariant` projection). The
    /// `actions` argument is therefore the infallible `self.actions().clone()`.
    #[cfg(feature = "query-queryable")]
    pub(super) fn deferred_query_sink(
        &self,
        actions: std::sync::Arc<SessionLinkActions<R, T>>,
        handler: impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
    ) -> (
        QueryHandlerCell<R>,
        impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static,
    )
    where
        SessionLinkActions<R, T>: Send + Sync + 'static,
    {
        let erased: BoxedQueryHandler = Box::new(handler);
        let cell: QueryHandlerCell<R> =
            wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
        let queue = self.fires.clone();
        let cell_for_sink = cell.clone();
        let observer = self.observer.clone();
        let sink = move |view: &dyn QueryView, _out: &mut dyn ReplyOut| {
            // The registry-provided responder (`_out`, bound to the
            // observer's pending_replies) is deliberately unused: the
            // deferred handler's replies are emitted at the drain, and
            // the registry's Final trigger keys on the MATCH count
            // (R311li), not on staged replies.
            let owned = OwnedQueryEvent {
                keyexpr: view.keyexpr().to_string(),
                parameters: view.parameters().map(<[u8]>::to_vec),
                attachment: view.attachment().map(<[u8]>::to_vec),
                source_info: view.source_info().cloned(),
                payload: view.payload().map(<[u8]>::to_vec),
                encoding: view.encoding().cloned(),
                rid: view.rid(),
                is_local: view.is_local(),
            };
            let cell = cell_for_sink.clone();
            let observer = observer.clone();
            let actions = actions.clone();
            queue.stage(Box::new(move || {
                cell.invoke(move |handler| {
                    let view = crate::query_sink::BorrowedQuery {
                        keyexpr: &owned.keyexpr,
                        parameters: owned.parameters.as_deref(),
                        attachment: owned.attachment.as_deref(),
                        source_info: owned.source_info.as_ref(),
                        payload: owned.payload.as_deref(),
                        encoding: owned.encoding.as_ref(),
                        rid: owned.rid,
                        is_local: owned.is_local,
                    };
                    let mut replies: Vec<crate::query::QueryReply> = Vec::new();
                    {
                        let mut responder = wz_session_core::query::QueryResponder::new(
                            owned.rid,
                            owned.keyexpr.clone(),
                            &mut replies,
                        );
                        handler(&view, &mut responder);
                    }
                    if owned.is_local {
                        // Loopback origin: deliver into the local reply
                        // registry (the requester's pending entry). The
                        // reply plane's own deferred fires staged here
                        // drain in the same outer pass.
                        R::with_mutex_mut(&observer, |obs| {
                            for reply in replies.drain(..) {
                                let inbound: crate::reply::InboundReply = reply.into();
                                obs.replies.deliver_local_reply(&inbound);
                            }
                        });
                    } else {
                        // Wire origin: emit each reply now (lock-free);
                        // the dispatch SSOT emits the ResponseFinal
                        // after the drain. Overflow-rejected replies
                        // are skipped, mirroring flush_pending.
                        use wz_session_core::response_sink::ResponseSink as _;
                        for reply in replies.drain(..) {
                            if let Ok(response) = reply.into_response() {
                                actions.send_response(response);
                            }
                        }
                    }
                })
            }));
        };
        (cell, sink)
    }
}

/// R311ow — the type-erased wire retraction a ROUTED queryable carries, the
/// queryable sibling of
/// [`SubscriberRetraction`](crate::session::subscriber::SubscriberRetraction).
/// `Session<_, _, Unicast>::declare_queryable` emitted a
/// `Declare(DeclQueryable)` to announce the queryable to the router, so on
/// teardown this closure emits the matching `Declare(UndeclQueryable)` (RAII),
/// capturing the unicast `SessionLinkActions` Arc + the wire queryable id.
/// Type-erased so the [`Queryable`] handle stays free of the wire-codec types
/// the captured `SessionLinkActions<R, T>` would otherwise name.
pub(super) type QueryableRetraction = Box<dyn FnMut() + Send + 'static>;

#[non_exhaustive]
pub struct Queryable<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    // R311ek — `session` is read only by the `query-queryable`-gated
    // observer-unregister in `undeclare` / `Drop`; the handle is only
    // ever constructed inside the same gate (`declare_queryable` returns
    // `Err(FeatureDisabled)` otherwise), so a `query-queryable`-off build
    // would carry this field unread. Gating it on the feature keeps the
    // struct dead-code-clean under `deny(warnings)` without an `#[allow]`.
    #[cfg(feature = "query-queryable")]
    pub(super) session: Session<R, T, Unicast>,
    // R311ek — `query-queryable`-OFF `PhantomData` arm keeps the `R` / `T`
    // type parameters live (their only field-level carrier is the gated
    // `session` above). PhantomData fields are exempt from the dead-code
    // lint, so this composes under `deny(warnings)`.
    #[cfg(not(feature = "query-queryable"))]
    pub(super) _marker: core::marker::PhantomData<(R, T)>,
    pub(super) id: QueryableId,
    pub(super) keyexpr: String,
    pub(super) options: QueryableOptions,
    /// R311li — the deferred-fire cell holding the user handler (the
    /// registry-installed sink only stages; the drain runs the handler
    /// outside the observer lock — the R311lf lock-free callback
    /// invariant on the queryable plane). Gated like the `session`
    /// field: the handle is only constructed under the feature.
    #[cfg(feature = "query-queryable")]
    pub(super) cell: QueryHandlerCell<R>,
    /// R311lo — RAII disarm flag. [`Self::undeclare`] runs the teardown
    /// once and clears this so the natural [`Drop`] frees the owned
    /// fields (keyexpr String, the Session Arc clone, the handler cell
    /// Arc) instead of the prior `mem::forget(self)` leaking them.
    /// Unconditional (the OFF build never constructs a Queryable but the
    /// struct must compile). `true` at construction; `false` once
    /// teardown has run.
    pub(super) armed: bool,
    /// R311ow — the wire retraction for a ROUTED queryable; see
    /// [`QueryableRetraction`]. `Some` exactly when
    /// [`Session::declare_queryable`] emitted a `Declare(DeclQueryable)` to
    /// announce this queryable to the router (`query-queryable` +
    /// `declare-queryable` AND `options.allowed_origin.allows_remote()`), so the
    /// retraction exists precisely when there is something to retract — the
    /// emit/retract pairing is unrepresentable-by-construction, not a runtime
    /// flag. `None` for a session-local queryable (no wire announce) or a build
    /// without the `declare-queryable` codec, mirroring zenoh-pico's
    /// `_z_undeclare_queryable` gating the `UndeclQueryable` emit on
    /// `_z_locality_allows_remote` (`vendor/zenoh-pico/src/net/primitives.c:404`).
    /// Unconditional (read in every build by `teardown`, so it is not dead-code
    /// under `deny(warnings)` even on a `query-queryable`-off build).
    pub(super) retraction: Option<QueryableRetraction>,
}

impl<R: SessionRuntime, T: TimeSource> Queryable<R, T> {
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
    pub fn undeclare(mut self) -> bool {
        self.teardown()
    }

    /// R311lo — shared teardown for [`Self::undeclare`] + [`Drop`], the
    /// single source of the kill-then-unregister discipline (R311li
    /// previously kept the two bodies in lock-step by hand). Idempotent
    /// via `armed`: the first caller kills the deferred cell FIRST (so a
    /// query staged before this call but not yet drained is suppressed —
    /// the handler never observes a post-undeclare query; the requester
    /// still receives its registry-staged Final) then unregisters under
    /// the observer lock and disarms; a second call is a no-op. Returns
    /// whether THIS call removed the registry entry. `unregister` is
    /// panic-free, so a corrupted observer leaves the queryable
    /// registered rather than panicking — caller can re-`undeclare`.
    /// R311dz — the observer's `queryables` field gates on
    /// `query-queryable`; a build without it never constructs a
    /// Queryable (`declare_queryable` returns `Err(FeatureDisabled)`),
    /// so the off-branch is unreachable at runtime but must compile.
    fn teardown(&mut self) -> bool {
        if !self.armed {
            return false;
        }
        self.armed = false;
        #[cfg(feature = "query-queryable")]
        self.cell.kill();
        // R311ow — emit the wire `Declare(UndeclQueryable)` for a ROUTED
        // queryable BEFORE the local unregister, mirroring zenoh-pico's
        // `_z_undeclare_queryable` (`_z_send_undeclare` then
        // `_z_unregister_session_queryable`,
        // `vendor/zenoh-pico/src/net/primitives.c:404-417`). `Some` exactly when
        // `declare_queryable` announced this queryable to the router; a
        // session-local queryable (or a build without the declare-queryable
        // codec) has `None` and skips the wire emit, the same gating pico
        // applies via `_z_locality_allows_remote`. Read in every build so the
        // field is not dead-code under `deny(warnings)`. `take()` so the
        // `armed`-guarded second teardown cannot double-emit.
        if let Some(mut retract) = self.retraction.take() {
            retract();
        }
        #[cfg(feature = "query-queryable")]
        {
            R::with_mutex_mut(&self.session.observer, |observer| {
                let removed = observer.queryables.unregister(self.id);
                // R311y797 — the undeclare twin of the declare-side
                // re-evaluation (pico `_z_write_filter_notify_queryable`
                // with `add = false` ->
                // `_z_write_filter_ctx_remove_local_match`,
                // `vendor/zenoh-pico/src/net/filtering.c:94-101`): dropping
                // the last local queryable must flip a querier's matching
                // status back to false. Runs even when `removed` is false —
                // an already absent id leaves the verdict unchanged, so the
                // re-evaluation fires nothing, and branching on it would
                // only add a way to skip it.
                #[cfg(all(feature = "declare-queryable", feature = "session-matching"))]
                {
                    let queryables = &observer.queryables;
                    observer.remote_queryables.reevaluate_matching(&|c| {
                        c.locality.allows_local()
                            && queryables.has_local_matching(&c.keyexpr, c.complete_required)
                    });
                }
                removed
            })
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            false
        }
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for Queryable<R, T> {
    fn drop(&mut self) {
        // R311lo — RAII teardown; disarmed after an explicit
        // `undeclare`, so this frees the owned fields without a second
        // unregister.
        let _ = self.teardown();
    }
}

/// R246 / R311ow — typed error returned by
/// [`Session::declare_queryable_aliased`]. `transport-unicast`-gated (it names
/// [`OutboundKeyexprError`] and the aliased declare lives on
/// `impl Session<R, T, Unicast>`). Structurally identical to
/// [`SubscribeAliasError`]: the alias resolution can miss (`UnknownMapping`),
/// and — since R311ow routed the aliased queryable by delegating to the
/// emitting literal [`Session::declare_queryable`] — the wire
/// `Declare(DeclQueryable)` can fail the same way as the literal path. Those
/// reject variants are projected verbatim from [`QueryableError`] via the
/// [`From`] impl below, so the literal and aliased routed-queryable paths share
/// ONE error surface (SSOT) rather than diverging. R311r had type-ungated this
/// enum while `declare_queryable` was still a local-only wire-no-op; R311ow
/// re-gates it on `transport-unicast` now that it names the unicast-only
/// outbound-keyexpr gate type, mirroring the subscriber re-gate in R311ou.
#[cfg(feature = "transport-unicast")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryableAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_queryable_aliased call).
    UnknownMapping(u64),
    /// R311ow — the resolved keyexpr (`outbound_mapping[id] || inline_suffix`)
    /// failed the R300 outbound pico-safety gate. Projected from
    /// [`QueryableError::InvalidKeyexpr`]; the local registration was rolled
    /// back, so no orphan queryable lingers.
    InvalidKeyexpr(OutboundKeyexprError),
    /// R311ow — the resolved keyexpr exceeded the bounded-codec capacity.
    /// Projected from [`QueryableError::ExceedsCapacity`].
    ExceedsCapacity,
    /// R311r / R311ow — a feature needed for this declare is OFF at compile
    /// time: either `query-queryable` (no local registry — the
    /// [`Session::declare_queryable_aliased`] cfg-off arm) or the
    /// `declare-queryable` send-seam codec (projected from
    /// [`QueryableError::FeatureDisabled`]). Caller must feature-detect at the
    /// consumer-crate level before relying on queryable callbacks.
    FeatureDisabled,
    /// R311ow — the transport is not currently accepting sends (link released /
    /// reconnecting). Projected from [`QueryableError::TransportUnavailable`].
    TransportUnavailable,
}

#[cfg(feature = "transport-unicast")]
impl From<QueryableError> for QueryableAliasError {
    fn from(e: QueryableError) -> Self {
        match e {
            QueryableError::InvalidKeyexpr(inner) => QueryableAliasError::InvalidKeyexpr(inner),
            QueryableError::ExceedsCapacity => QueryableAliasError::ExceedsCapacity,
            QueryableError::FeatureDisabled => QueryableAliasError::FeatureDisabled,
            QueryableError::TransportUnavailable => QueryableAliasError::TransportUnavailable,
        }
    }
}

#[cfg(feature = "transport-unicast")]
impl std::fmt::Display for QueryableAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryableAliasError::UnknownMapping(id) => write!(
                f,
                "QueryableAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            QueryableAliasError::InvalidKeyexpr(e) => write!(
                f,
                "QueryableAliasError: resolved keyexpr failed the outbound pico-safety gate: {e}"
            ),
            QueryableAliasError::ExceedsCapacity => write!(
                f,
                "QueryableAliasError: resolved keyexpr exceeds the bounded-codec capacity \
                 (MAX_KEYEXPR_BYTES)"
            ),
            QueryableAliasError::FeatureDisabled => write!(
                f,
                "QueryableAliasError: a feature needed for the queryable declare \
                 (query-queryable or declare-queryable) is OFF at compile time"
            ),
            QueryableAliasError::TransportUnavailable => write!(
                f,
                "QueryableAliasError: transport not accepting sends (link released / reconnecting)"
            ),
        }
    }
}

#[cfg(feature = "transport-unicast")]
impl std::error::Error for QueryableAliasError {}

/// R311ow — typed error from the routed (emitting) [`Session::declare_queryable`].
/// Mirrors zenoh-pico's `z_result_t` return from `_z_register_queryable`
/// (`vendor/zenoh-pico/src/net/primitives.c:320`): the local registration
/// always succeeds, but the wire `Declare(DeclQueryable)` that announces the
/// queryable to the router can fail. The queryable sibling of
/// [`SubscribeError`]. There is no `UnknownMapping` variant: the literal
/// `declare_queryable` never resolves a mapping id (only
/// [`Session::declare_queryable_aliased`] does, and a miss there maps to
/// [`QueryableAliasError::UnknownMapping`]) — making the literal path's error
/// surface unable to express a reject it can never produce. There is no
/// `RequiresUnicast` variant either: `declare_queryable` lives on
/// `impl Session<R, T, Unicast>`, so a multicast call is a compile error, not a
/// runtime reject (typestate makes the transport mismatch unrepresentable).
///
/// `transport-unicast`-gated: it names [`OutboundKeyexprError`] (the
/// `transport-unicast`-gated R300 gate type) and is returned only by the
/// unicast `Session::declare_queryable`.
#[cfg(feature = "transport-unicast")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryableError {
    /// R300 — the keyexpr failed the outbound pico-safety gate: either
    /// non-canonical per the zenoh keyexpr grammar, OR matching the R299 bug #3
    /// SIGABRT pattern family. The wire bytes never left; the local
    /// registration was rolled back so no orphan queryable lingers.
    InvalidKeyexpr(OutboundKeyexprError),
    /// W3 — the literal keyexpr exceeded the declared bounded-codec capacity
    /// (`MAX_KEYEXPR_BYTES`) while copying into the no-alloc owned DECLARE
    /// mirror, so no wire bytes were emitted. The local registration was
    /// rolled back.
    ExceedsCapacity,
    /// R311g1 — a feature needed for the queryable declare is disabled on this
    /// build: either `query-queryable` (the registry — the
    /// [`Session::declare_queryable`] cfg-off arm) or the `declare-queryable`
    /// send-seam codec. The signature stays available (signature-stability) but
    /// the queryable cannot be installed / announced.
    FeatureDisabled,
    /// F2 — the transport is not currently accepting data sends (link released
    /// or reconnecting; Established not re-entered). The DECLARE was not
    /// emitted; re-declare after the session re-establishes (zenoh-pico
    /// `_Z_ERR_TRANSPORT_NOT_AVAILABLE`).
    TransportUnavailable,
}

#[cfg(feature = "transport-unicast")]
impl std::fmt::Display for QueryableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryableError::InvalidKeyexpr(e) => {
                write!(
                    f,
                    "QueryableError: keyexpr failed the outbound pico-safety gate: {e}"
                )
            }
            QueryableError::ExceedsCapacity => write!(
                f,
                "QueryableError: keyexpr exceeds the bounded-codec capacity (MAX_KEYEXPR_BYTES)"
            ),
            QueryableError::FeatureDisabled => write!(
                f,
                "QueryableError: a feature needed for the queryable declare \
                 (query-queryable or declare-queryable) is disabled on this build"
            ),
            QueryableError::TransportUnavailable => write!(
                f,
                "QueryableError: transport not accepting sends (link released / reconnecting)"
            ),
        }
    }
}

#[cfg(feature = "transport-unicast")]
impl std::error::Error for QueryableError {}
