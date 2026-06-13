// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Queryable handle cluster split out of `session/mod.rs` (pure
//! refactor): [`QueryableOptions`], the RAII [`Queryable`] handle,
//! and [`QueryableAliasError`]. The parent module re-exports these
//! via `pub use queryable::*;` so the public path
//! `wz_runtime_tokio::session::Queryable` is unchanged.

use super::*;

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
    /// B5b-2b — the wire-reply leg of the sink emits through the UNICAST
    /// action bundle (`actions.send_response`), which a multicast session has
    /// no analogue of. Rather than make the return type fallible (an
    /// `impl FnMut`-in-`Result` trips `clippy::type_complexity`), the resolved
    /// unicast `actions` is threaded in by the caller: `declare_queryable`
    /// projects `Session::actions()`'s `SendWireError::UnsupportedVariant` into
    /// `QueryableAliasError::RequiresUnicast` BEFORE calling this, so the sink
    /// is only ever built on a unicast transport. Keeps the honest fallibility
    /// at the API boundary without a panic form here.
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
        {
            self.cell.kill();
            R::with_mutex_mut(&self.session.observer, |observer| {
                observer.queryables.unregister(self.id)
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
    /// B5b-2b (R311nc) — the aliased queryable declare resolves the
    /// unicast outbound keyexpr-mapping table, which a multicast session
    /// has no analogue of; the `Session::actions()` projection rejects.
    /// No queryable was declared.
    RequiresUnicast,
}

impl std::fmt::Display for QueryableAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryableAliasError::UnknownMapping(id) => write!(
                f,
                "QueryableAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            QueryableAliasError::RequiresUnicast => write!(
                f,
                "QueryableAliasError: aliased queryable declare requires a unicast \
                 transport; this session holds a multicast transport (no outbound \
                 keyexpr-mapping table); no queryable was declared"
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
