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
#[non_exhaustive]
pub struct Queryable<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    // R311ek — `session` is read only by the `query-queryable`-gated
    // observer-unregister in `undeclare` / `Drop`; the handle is only
    // ever constructed inside the same gate (`declare_queryable` returns
    // `Err(FeatureDisabled)` otherwise), so a `query-queryable`-off build
    // would carry this field unread. Gating it on the feature keeps the
    // struct dead-code-clean under `deny(warnings)` without an `#[allow]`.
    #[cfg(feature = "query-queryable")]
    pub(super) session: Session<R, T>,
    // R311ek — `query-queryable`-OFF `PhantomData` arm keeps the `R` / `T`
    // type parameters live (their only field-level carrier is the gated
    // `session` above). PhantomData fields are exempt from the dead-code
    // lint, so this composes under `deny(warnings)`.
    #[cfg(not(feature = "query-queryable"))]
    pub(super) _marker: core::marker::PhantomData<(R, T)>,
    pub(super) id: QueryableId,
    pub(super) keyexpr: String,
    pub(super) options: QueryableOptions,
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
    pub fn undeclare(self) -> bool {
        // R311df — observer access via R::with_mutex_mut closure form.
        // R311dz — the observer's `queryables` field gates on
        // `query-queryable`. A build without it never constructs a
        // Queryable (declare_queryable returns Err(FeatureDisabled)), so
        // this off-branch is unreachable at runtime but must compile.
        #[cfg(feature = "query-queryable")]
        let removed = R::with_mutex_mut(&self.session.observer, |observer| {
            observer.queryables.unregister(self.id)
        });
        #[cfg(not(feature = "query-queryable"))]
        let removed = false;
        std::mem::forget(self);
        removed
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for Queryable<R, T> {
    fn drop(&mut self) {
        // R311cu — RAII unregister via R::with_mutex_mut. Per-profile
        // poison-recovery lives inside the runtime impl. unregister is
        // panic-free (boolean return), so the worst-case observable
        // outcome on a corrupted observer is "queryable stays
        // registered" — caller can manually re-call undeclare.
        // R311dz — gated on `query-queryable` (the observer's queryables
        // field). Unreachable at runtime when off (no Queryable is ever
        // constructed) but must compile.
        #[cfg(feature = "query-queryable")]
        R::with_mutex_mut(&self.session.observer, |obs| {
            let _ = obs.queryables.unregister(self.id);
        });
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
