// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Subscriber handle cluster split out of `session/mod.rs` (pure
//! refactor): [`SubscribeOptions`], the RAII [`Subscriber`] handle,
//! and [`SubscribeAliasError`]. The parent module re-exports these
//! via `pub use subscriber::*;` so the public path
//! `wz_runtime_tokio::session::Subscriber` is unchanged.

use super::*;

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
// R311cu — R267 helper cascade. `!Clone` by construction (per doc);
// Drop is generic via R::with_mutex_mut (R311ct API) so per-profile
// poison-recovery semantics stay inside the runtime impl.
#[non_exhaustive]
pub struct Subscriber<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    pub(super) id: SubscriptionId,
    pub(super) keyexpr: String,
    pub(super) options: SubscribeOptions,
}

impl<R: SessionRuntime, T: TimeSource> Subscriber<R, T> {
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
        // R311de — observer access via R::with_mutex_mut closure form.
        let removed = R::with_mutex_mut(&self.session.observer, |observer| {
            observer.subscribers.unregister(self.id)
        });
        // Skip the Drop impl so it does not no-op-unregister an
        // already-removed id (cosmetic — second unregister is a
        // boolean false, not a panic, but std::mem::forget makes
        // the intent explicit at the call site).
        std::mem::forget(self);
        removed
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for Subscriber<R, T> {
    fn drop(&mut self) {
        // R311cu — RAII unregister via R::with_mutex_mut. Per-profile
        // poison-recovery lives inside the runtime impl (AP: recover
        // PoisonError via into_inner; MCU: no poison concept under
        // panic = abort). The `unregister` call itself is panic-free
        // (boolean return), so the worst-case observable outcome on
        // a corrupted observer is "id stays registered" — caller can
        // manually re-call `undeclare` if it matters.
        R::with_mutex_mut(&self.session.observer, |obs| {
            let _ = obs.subscribers.unregister(self.id);
        });
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
