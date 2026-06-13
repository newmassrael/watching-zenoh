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
    /// R311lh — the deferred-fire cell holding the user callback (the
    /// registry-installed sink only stages an owned `Sample` copy; the
    /// drain runs the callback outside the observer lock — the R311lf
    /// lock-free callback invariant on the subscriber-sample plane).
    /// Unconditional like the plane itself (the subscriber registry is
    /// always compiled).
    pub(super) cell: SampleCell<R>,
    /// R311lo — RAII disarm flag. [`Self::undeclare`] runs the teardown
    /// once and clears this so the natural [`Drop`] frees the owned
    /// fields (keyexpr String, the Session Arc clone, the cell Arc)
    /// instead of the prior `mem::forget(self)` leaking them. `true` at
    /// construction; `false` once teardown has run.
    pub(super) armed: bool,
}

/// R311lh — the type-erased user callback a deferred subscriber's cell
/// holds: erased at registration so the [`Subscriber`] handle has a
/// nameable cell type (the [`DeclListener`] / [`MatchingListener`]
/// convention).
pub(super) type BoxedSampleCallback = Box<dyn FnMut(&dyn SampleView) + Send + 'static>;

/// R311lh — the per-subscriber deferred-fire cell (take-call-restore
/// with the lossless backlog; see [`wz_session_core::deferred_fire`]).
/// The registry-installed staging sink fires against it;
/// [`Subscriber::undeclare`] / `Drop` kill it so a
/// staged-but-undrained sample is suppressed and self-undeclare from
/// inside the callback is safe.
pub(super) type SampleCell<R> =
    wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedSampleCallback>;

// R311mp (Level B, B4) — `deferred_sample_sink` is the helper
// [`Session::declare_subscriber`] installs; that declare method became
// TRANSPORT-AGNOSTIC in B4 (it reads only `self.fires` + the observer's
// subscriber registry, never `self.actions()`), so this helper's `impl`
// block is ungated too — it compiles in EVERY transport configuration
// (unicast-only / both / the multicast-only build a multicast `Session`
// declares subscribers in). B2 had gated it `transport-unicast` only
// because `declare_subscriber` was still in the unicast block then; B4
// lifted both. (The aliased counterpart `declare_subscriber_aliased` stays
// unicast: it resolves through the unicast outbound mapping table, which a
// connectionless multicast session has no analogue of.)
impl<R: SessionRuntime, T: TimeSource> Session<R, T> {
    /// R311lh — build the deferred cell + the staging sink one
    /// `declare_subscriber{_aliased}` call installs in the registry:
    /// the sink materializes each matched borrowed view into the owned
    /// retention [`crate::sample::Sample`] (via `Sample::from_view` —
    /// full-fidelity copy including the five rich metadata fields) and
    /// stages one queue job per sample; the job redelivers the owned
    /// sample as `&dyn SampleView` when it invokes the user callback
    /// OUTSIDE the observer lock. The callback signature is unchanged —
    /// deferral is invisible at the type level.
    pub(super) fn deferred_sample_sink(
        &self,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> (SampleCell<R>, impl FnMut(&dyn SampleView) + Send + 'static) {
        let erased: BoxedSampleCallback = Box::new(callback);
        let cell: SampleCell<R> = wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
        let queue = self.fires.clone();
        let cell_for_sink = cell.clone();
        let sink = move |view: &dyn SampleView| {
            let owned = crate::sample::Sample::from_view(view);
            let cell = cell_for_sink.clone();
            queue.stage(Box::new(move || cell.invoke(move |cb| cb(&owned))));
        };
        (cell, sink)
    }
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
    pub fn undeclare(mut self) -> bool {
        self.teardown()
    }

    /// R311lo — shared teardown for [`Self::undeclare`] + [`Drop`], the
    /// single source of the kill-then-unregister discipline (R311lh
    /// previously had to keep the `undeclare` and `Drop` bodies in
    /// lock-step by hand). Idempotent via `armed`: the first caller
    /// kills the deferred cell FIRST (suppressing a sample staged before
    /// this call but not yet drained, so the callback never observes a
    /// post-undeclare sample) then unregisters the staging sink under
    /// the observer lock and disarms; a second call is a no-op. Returns
    /// whether THIS call removed the registry entry. `unregister` is
    /// panic-free (boolean return), so the worst-case observable outcome
    /// on a corrupted observer is "id stays registered" — caller can
    /// re-`undeclare`.
    fn teardown(&mut self) -> bool {
        if !self.armed {
            return false;
        }
        self.armed = false;
        self.cell.kill();
        // R311de — observer access via R::with_mutex_mut closure form;
        // per-profile poison-recovery lives inside the runtime impl (AP:
        // PoisonError::into_inner; MCU: no poison concept under panic =
        // abort).
        R::with_mutex_mut(&self.session.observer, |observer| {
            observer.subscribers.unregister(self.id)
        })
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for Subscriber<R, T> {
    fn drop(&mut self) {
        // R311lo — RAII teardown; disarmed after an explicit
        // `undeclare`, so this frees the owned fields without a second
        // unregister.
        let _ = self.teardown();
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
