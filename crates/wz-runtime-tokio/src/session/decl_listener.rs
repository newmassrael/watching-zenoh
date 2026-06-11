// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311lc — Session-tier deferred decl listeners: the callback surface
//! over the three peer-declaration observer registries
//! (`remote_subscribers` / `remote_queryables` / `liveliness`), riding
//! the F-6 deferred-fire infra ([`wz_session_core::deferred_fire`])
//! so the user callback runs OUTSIDE the session observer mutex.
//!
//! Before this round the only way to observe peer `Declare(Decl*)` /
//! `Declare(Undecl*)` records was a direct registry install through the
//! observer lock (`observer().lock().unwrap().remote_subscribers
//! .on_subscriber_declared(...)`) — an INLINE sink carrying the R311kj
//! re-entrancy constraint (the callback fires under the observer mutex
//! and must not call back into any observer-locking session API). The
//! Session-tier listeners here install STAGING sinks instead: the
//! registry-installed pair only records the fire onto the session's
//! deferred-fire queue, and the drive loop's
//! [`Session::drain_deferred_fires`] runs the user callback after the
//! lock drops — full re-entrancy, the same contract as
//! [`MatchingListener`] (R311kz). The raw registry surface (and its
//! documented inline constraint) remains for hand-installed sinks.
//!
//! One listener = one callback observing BOTH event directions of one
//! plane as a [`DeclEvent`] (`Declared { id, keyexpr }` /
//! `Undeclared { id }`) — the two wire records share the `id` currency
//! and a consumer almost always wants the pair, so the handle installs
//! one decl + one undecl staging sink over a single listener cell and
//! [`DeclListener::undeclare`] removes both (the R311lb id-keyed
//! registry currency).

use super::*;

/// R311lc — one peer-declaration event delivered to a Session-tier
/// decl listener. The OWNED projection of the inline seam's
/// `&dyn DeclView` / bare-`u64` pair: a deferred fire outlives the
/// dispatch borrow, so the staging sink copies the two fields out.
/// Which entity kind the event describes (subscriber / queryable /
/// liveliness token) is carried by which `declare_remote_*_listener`
/// surface the listener was registered through, exactly as the inline
/// seam carries it by registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeclEvent {
    /// Peer declared an entity: the peer-assigned declaration id + the
    /// resolved keyexpr literal it was declared on.
    Declared {
        /// Peer-assigned declaration id (the `DeclX.id` wire field).
        id: u64,
        /// Resolved keyexpr literal (peer DECLARE-table lookup applied).
        keyexpr: String,
    },
    /// Peer undeclared the entity it previously declared under `id`.
    /// The wire `UndeclX` body carries no keyexpr.
    Undeclared {
        /// Peer-assigned declaration id of the prior declaration.
        id: u64,
    },
}

/// R311lc — the type-erased user callback a decl listener's deferred
/// cell holds: erased at registration so the [`DeclListener`] handle
/// has a nameable cell type (the [`MatchingListener`] convention).
#[cfg(any(
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "liveliness-token"
))]
pub(super) type BoxedDeclEventCallback = Box<dyn FnMut(DeclEvent) + Send + 'static>;

/// R311lc — the per-listener deferred-fire cell (take-call-restore;
/// see [`wz_session_core::deferred_fire`]). The registry-installed
/// staging sinks fire against it; [`DeclListener::undeclare`] kills it
/// so a staged-but-undrained fire is suppressed and self-undeclare
/// from inside the callback is safe.
#[cfg(any(
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "liveliness-token"
))]
pub(super) type DeclListenerCell<R> =
    wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedDeclEventCallback>;

/// Which observer registry a [`DeclListener`]'s staging sinks live in.
/// Each variant is gated on the feature that can CONSTRUCT it (the
/// `declare_remote_*_listener` arm that returns the handle), the
/// [`MatchingScope`] R311kk convention: under a subset where a registry
/// is off its variant is uninhabitable rather than dead code, and with
/// all three off the enum is empty ([`DeclListener::undeclare`]'s match
/// is the zero-arm match on an uninhabited type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeclListenerScope {
    #[cfg(feature = "declare-subscriber")]
    RemoteSubscribers,
    #[cfg(feature = "declare-queryable")]
    RemoteQueryables,
    #[cfg(feature = "liveliness-token")]
    LivelinessTokens,
}

/// Live decl-listener registration. Returned by
/// [`Session::declare_remote_subscriber_listener`] /
/// [`Session::declare_remote_queryable_listener`] /
/// [`Session::declare_remote_token_listener`]; the callback keeps
/// firing on peer declaration activity until
/// [`undeclare`](Self::undeclare). Explicit undeclare only — no Drop
/// hook, consistent with the other wz handles (a dropped handle leaves
/// the observers installed).
pub struct DeclListener<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    /// R311lb registry-local id of the installed declaration observer.
    pub(super) decl_id: u64,
    /// R311lb registry-local id of the installed undeclaration observer.
    pub(super) undecl_id: u64,
    pub(super) scope: DeclListenerScope,
    /// The deferred-fire cell holding the user callback (the registry
    /// sinks only stage; the drive loop's drain fires through this cell
    /// outside the observer lock). Gated like the scope variants'
    /// union: the field exists iff a listener can be constructed.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-token"
    ))]
    pub(super) cell: DeclListenerCell<R>,
}

impl<R: SessionRuntime, T: TimeSource> DeclListener<R, T> {
    /// Remove both staging sinks — the callback will not fire again.
    /// Returns whether the observers were removed (`false` = already
    /// removed, e.g. a racing removal through the raw registry surface).
    ///
    /// Kills the deferred cell FIRST, so a fire staged before this call
    /// but not yet drained is suppressed (the callback never observes a
    /// post-undeclare event), then unregisters both observers under the
    /// observer lock. Callable from INSIDE the listener's own callback
    /// (the take-call-restore cell makes self-undeclare deadlock-free).
    pub fn undeclare(self) -> bool {
        // R311g1 / R311kk — bind the handle state unconditionally:
        // under a subset where all three registry variants are cfg-off
        // the zero-arm match below reads none of these fields and the
        // deny-warnings build would reject them.
        let _ = (&self.session, self.decl_id, self.undecl_id);
        #[cfg(any(
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "liveliness-token"
        ))]
        self.cell.kill();
        // Each arm rides its variant's gate (see [`DeclListenerScope`]).
        match self.scope {
            #[cfg(feature = "declare-subscriber")]
            DeclListenerScope::RemoteSubscribers => {
                R::with_mutex_mut(self.session.observer(), |obs| {
                    let d = obs
                        .remote_subscribers
                        .remove_subscriber_declared_sink(self.decl_id);
                    let u = obs
                        .remote_subscribers
                        .remove_subscriber_undeclared_sink(self.undecl_id);
                    d && u
                })
            }
            #[cfg(feature = "declare-queryable")]
            DeclListenerScope::RemoteQueryables => {
                R::with_mutex_mut(self.session.observer(), |obs| {
                    let d = obs
                        .remote_queryables
                        .remove_queryable_declared_sink(self.decl_id);
                    let u = obs
                        .remote_queryables
                        .remove_queryable_undeclared_sink(self.undecl_id);
                    d && u
                })
            }
            #[cfg(feature = "liveliness-token")]
            DeclListenerScope::LivelinessTokens => {
                R::with_mutex_mut(self.session.observer(), |obs| {
                    let d = obs.liveliness.remove_token_declared_sink(self.decl_id);
                    let u = obs.liveliness.remove_token_undeclared_sink(self.undecl_id);
                    d && u
                })
            }
        }
    }
}

/// Typed reject from the `declare_remote_*_listener` surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclListenerError {
    /// R311g1 signature-stability — the registry feature the listener's
    /// observers would live in (`declare-subscriber` /
    /// `declare-queryable` / `liveliness-token` per surface) is OFF in
    /// this build. The method signature stays visible so callers
    /// observe the build-time choice as a runtime reject instead of a
    /// missing symbol.
    FeatureDisabled,
}

impl core::fmt::Display for DeclListenerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FeatureDisabled => f.write_str(
                "declare_remote_*_listener: the backing registry Cargo feature \
                 (declare-subscriber / declare-queryable / liveliness-token \
                 per surface) is OFF in this build (signature-stability \
                 contract — build-time choice observed as runtime reject)",
            ),
        }
    }
}

impl core::error::Error for DeclListenerError {}

impl<R: SessionRuntime, T: TimeSource> Session<R, T> {
    /// R311lc — build the listener cell + the two staging sinks one
    /// `declare_remote_*_listener` surface installs: the decl sink
    /// stages an owned [`DeclEvent::Declared`] (copying the borrowed
    /// view out — a deferred fire outlives the dispatch borrow), the
    /// undecl sink stages [`DeclEvent::Undeclared`]; both run through
    /// the shared take-call-restore cell so wire order across the two
    /// directions is preserved by the queue's stage order.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-token"
    ))]
    fn deferred_decl_sinks(
        &self,
        callback: impl FnMut(DeclEvent) + Send + 'static,
    ) -> (
        DeclListenerCell<R>,
        wz_session_core::decl_sink::BoxedDeclSink,
        wz_session_core::decl_sink::BoxedUndeclSink,
    ) {
        let erased: BoxedDeclEventCallback = Box::new(callback);
        let cell: DeclListenerCell<R> =
            wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
        let queue = self.fires.clone();
        let cell_for_decl = cell.clone();
        let decl_sink = wz_session_core::decl_sink::BoxedDeclSink::new(move |view| {
            let event = DeclEvent::Declared {
                id: view.id(),
                keyexpr: view.keyexpr().to_string(),
            };
            let cell = cell_for_decl.clone();
            queue.stage(Box::new(move || cell.invoke(|cb| cb(event))));
        });
        let queue = self.fires.clone();
        let cell_for_undecl = cell.clone();
        let undecl_sink = wz_session_core::decl_sink::BoxedUndeclSink::new(move |id| {
            let cell = cell_for_undecl.clone();
            queue.stage(Box::new(move || {
                cell.invoke(|cb| cb(DeclEvent::Undeclared { id }))
            }));
        });
        (cell, decl_sink, undecl_sink)
    }

    /// R311lc — observe peer SUBSCRIBER declaration activity: `callback`
    /// fires with [`DeclEvent::Declared`] on every inbound
    /// `Declare(DeclSubscriber)` whose keyexpr resolves, and with
    /// [`DeclEvent::Undeclared`] on the matching `UndeclSubscriber`.
    /// The deferred counterpart of the raw
    /// `remote_subscribers.on_subscriber_declared` registry install.
    ///
    /// DEFERRED FIRE (the F-6 contract, R311kz): the registry-installed
    /// sinks only STAGE the event onto the session's deferred-fire
    /// queue, and the drive loop's [`Session::drain_deferred_fires`]
    /// runs `callback` AFTER the observer lock drops. The callback may
    /// therefore call any observer-locking session API — declares,
    /// registry consults, further listener registration, even its own
    /// handle's `undeclare` — without self-deadlocking. Events arrive
    /// in stage order; an event staged before `undeclare` but drained
    /// after it is suppressed. A custom drive closure that dispatches
    /// this session's observer directly must pair each dispatch with a
    /// `drain_deferred_fires()` call or deferred listeners starve.
    ///
    /// R310.5c / R311g1 — the signature is always visible; the body
    /// rejects typed (`Err(FeatureDisabled)`) when `declare-subscriber`
    /// is off.
    pub fn declare_remote_subscriber_listener(
        &self,
        callback: impl FnMut(DeclEvent) + Send + 'static,
    ) -> Result<DeclListener<R, T>, DeclListenerError> {
        #[cfg(feature = "declare-subscriber")]
        {
            let (cell, decl_sink, undecl_sink) = self.deferred_decl_sinks(callback);
            let (decl_id, undecl_id) = R::with_mutex_mut(&self.observer, |obs| {
                let d = obs
                    .remote_subscribers
                    .on_subscriber_declared_sink(decl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                let u = obs
                    .remote_subscribers
                    .on_subscriber_undeclared_sink(undecl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                (d, u)
            });
            Ok(DeclListener {
                session: self.clone(),
                decl_id,
                undecl_id,
                scope: DeclListenerScope::RemoteSubscribers,
                cell,
            })
        }
        #[cfg(not(feature = "declare-subscriber"))]
        {
            let _ = callback;
            Err(DeclListenerError::FeatureDisabled)
        }
    }

    /// R311lc — observe peer QUERYABLE declaration activity (inbound
    /// `Declare(DeclQueryable)` / `Declare(UndeclQueryable)`). Same
    /// deferred-fire contract as
    /// [`Self::declare_remote_subscriber_listener`]; rejects typed when
    /// `declare-queryable` is off.
    pub fn declare_remote_queryable_listener(
        &self,
        callback: impl FnMut(DeclEvent) + Send + 'static,
    ) -> Result<DeclListener<R, T>, DeclListenerError> {
        #[cfg(feature = "declare-queryable")]
        {
            let (cell, decl_sink, undecl_sink) = self.deferred_decl_sinks(callback);
            let (decl_id, undecl_id) = R::with_mutex_mut(&self.observer, |obs| {
                let d = obs
                    .remote_queryables
                    .on_queryable_declared_sink(decl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                let u = obs
                    .remote_queryables
                    .on_queryable_undeclared_sink(undecl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                (d, u)
            });
            Ok(DeclListener {
                session: self.clone(),
                decl_id,
                undecl_id,
                scope: DeclListenerScope::RemoteQueryables,
                cell,
            })
        }
        #[cfg(not(feature = "declare-queryable"))]
        {
            let _ = callback;
            Err(DeclListenerError::FeatureDisabled)
        }
    }

    /// R311lc — observe peer LIVELINESS-TOKEN declaration activity
    /// (inbound `Declare(DeclToken)` / `Declare(UndeclToken)` — the
    /// generic-observer plane that fans EVERY peer token, unlike the
    /// keyexpr-filtered `declare_liveliness_subscriber`). Same
    /// deferred-fire contract as
    /// [`Self::declare_remote_subscriber_listener`]; rejects typed when
    /// `liveliness-token` is off.
    pub fn declare_remote_token_listener(
        &self,
        callback: impl FnMut(DeclEvent) + Send + 'static,
    ) -> Result<DeclListener<R, T>, DeclListenerError> {
        #[cfg(feature = "liveliness-token")]
        {
            let (cell, decl_sink, undecl_sink) = self.deferred_decl_sinks(callback);
            let (decl_id, undecl_id) = R::with_mutex_mut(&self.observer, |obs| {
                let d = obs
                    .liveliness
                    .on_token_declared_sink(decl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                let u = obs
                    .liveliness
                    .on_token_undeclared_sink(undecl_sink)
                    .expect("observer install on the alloc backing never exceeds capacity");
                (d, u)
            });
            Ok(DeclListener {
                session: self.clone(),
                decl_id,
                undecl_id,
                scope: DeclListenerScope::LivelinessTokens,
                cell,
            })
        }
        #[cfg(not(feature = "liveliness-token"))]
        {
            let _ = callback;
            Err(DeclListenerError::FeatureDisabled)
        }
    }
}
