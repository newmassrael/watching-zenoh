// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Liveliness handle cluster split out of `session/mod.rs` (pure
//! refactor): [`LivelinessOptions`], the RAII [`LivelinessToken`]
//! handle, [`LivelinessAliasError`], [`LivelinessSubscriberOptions`],
//! the RAII [`LivelinessSubscriber`] handle, and
//! [`LivelinessSubscriberAliasError`]. The parent module re-exports
//! these via `pub use liveliness::*;` so the public paths
//! `wz_runtime_tokio::session::LivelinessToken` etc. are unchanged.

use super::*;

/// R248 — options bundle for [`Session::declare_token`] /
/// [`Session::declare_token_aliased`]. Mirrors zenoh-pico's
/// `z_liveliness_token_options_t` which carries only a single
/// `uint8_t __dummy` placeholder field today
/// (`vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h:44-46`)
/// — the struct exists in the C ABI as a forward-compatible
/// placeholder for future per-token options that the upstream Zenoh
/// protocol has not yet defined.
///
/// Empty `#[non_exhaustive]` so a future round can add per-token
/// fields (e.g. completeness flag, expiry hint, attachment) without
/// breaking external callers. Construct via [`Self::default`] /
/// [`Self::new`].
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Always defined regardless of the `liveliness-token`
/// feature so consumer-side declare_token call-sites can compile
/// unconditionally; the wire-emit path is gated inside
/// [`Session::declare_token`] which returns
/// `Err(LivelinessAliasError::FeatureDisabled)` when off.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LivelinessOptions {}

impl LivelinessOptions {
    /// Default options — currently empty, mirroring zenoh-pico's
    /// `z_liveliness_token_options_default` which zeroes out the
    /// `__dummy` slot.
    pub fn new() -> Self {
        Self::default()
    }
}

/// R248 — handle for a liveliness token declared through
/// [`Session::declare_token`] / [`Session::declare_token_aliased`].
/// Holds the `token_id` allocated by
/// [`SessionLinkActions::alloc_next_token_id`] so `Drop` can emit
/// the matching `Declare(UndeclToken)` retraction on the outbound
/// link.
///
/// ## Lifetime + wire emit on Drop
///
/// The token stays declared on the peer for as long as this handle
/// is alive on the local session. `Drop` emits
/// `Declare(UndeclToken)` so the peer's liveliness subscribers
/// receive the DELETE sample at retraction time — that is the
/// whole purpose of the liveliness signal. This differs from
/// [`Subscriber`] / [`Queryable`] `Drop` which only unregister
/// from the local registry (no wire emit), because zenoh-pico's
/// router-mode subscriber/queryable declarations are out of scope
/// for wz while the liveliness path is end-to-end peer-driven.
///
/// `!Clone` by construction — the underlying `token_id` is a
/// unique handle; cloning would let two drops race to emit
/// `UndeclToken` for the same id, and the peer would treat the
/// second as a no-op against a now-absent entry (zenoh-pico
/// `_z_liveliness_handle_undecl_token` ignores absent ids). Code
/// wanting "the same liveliness keyexpr from two places" should
/// call [`Session::declare_token`] twice and accept two distinct
/// token ids — that matches zenoh-pico semantics, where each
/// `z_liveliness_declare_token` call allocates a fresh entity id.
///
/// ## Panic semantics on Drop
///
/// [`SessionLinkActions::send_undeclare_token`] runs the encode +
/// `driver.send_blocking` chain without taking any wz-level
/// `Mutex::lock` that could be poison-recovered the way
/// [`Subscriber::drop`] handles the observer mutex. The
/// `driver.send_blocking` path is panic-free under normal AP MVP
/// operation, so this `Drop` does not wrap the call in
/// `catch_unwind`. If a future round surfaces a panic from the
/// driver path (e.g. a poisoned internal mutex on a TLS / lwIP
/// driver), wrapping this call defensively is the textbook
/// follow-up — carry note on the audit ledger.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_token`] / [`Session::declare_token_aliased`].
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. Struct + impl + Drop always defined; the wire-emit at
/// declare time is gated inside [`Session::declare_token`] (returns
/// `Err(LivelinessAliasError::FeatureDisabled)` when
/// `liveliness-token` is off so no handle ever exists in that build),
/// and the [`Drop`] wire-emit calls into
/// [`crate::session_glue::SessionLinkActions::send_undeclare_token`]
/// which is itself signature-stable (silent no-op when the underlying
/// declare-* gate is off).
// R311cu — R267 helper cascade. `!Clone`; Drop body touches only
// session.actions (concrete Arc<SessionLinkActions>, R-independent)
// so Drop is generic over R without needing R::with_mutex_mut.
#[non_exhaustive]
pub struct LivelinessToken<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    pub(super) id: u64,
    pub(super) keyexpr: String,
    pub(super) options: LivelinessOptions,
    /// R311lo — RAII disarm flag. [`Self::undeclare`] emits the
    /// `Declare(UndeclToken)` once and clears this so the natural
    /// [`Drop`] frees the owned fields (keyexpr String, the Session Arc
    /// clone) instead of the prior `mem::forget(self)` leaking them, and
    /// so no duplicate `UndeclToken` is emitted. `true` at construction;
    /// `false` once teardown has run.
    pub(super) armed: bool,
}

impl<R: SessionRuntime, T: TimeSource> LivelinessToken<R, T> {
    /// The stable token id allocated at declare time by
    /// [`SessionLinkActions::alloc_next_token_id`]. Exposed for
    /// diagnostics; callers should not rely on the exact value
    /// across runs since the counter is session-scoped + Relaxed
    /// ordering.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The keyexpr the token was declared against. For
    /// [`Session::declare_token_aliased`] this is the resolved
    /// literal form (the alias was resolved at declare time via
    /// [`SessionLinkActions::resolve_outbound_mapping`] and the
    /// literal stored here for introspection symmetry with R245
    /// [`Subscriber::keyexpr`] / R246 [`Queryable::keyexpr`]). The
    /// wire frame may carry either the literal or the alias form
    /// depending on which constructor was used — see the
    /// [`Session::declare_token_aliased`] doc-comment for the wire
    /// shape detail.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &LivelinessOptions {
        &self.options
    }

    /// Explicitly retract this liveliness token. Emits
    /// `Declare(UndeclToken)` on the outbound link
    /// (`SessionLinkActions::send_undeclare_token`) and consumes
    /// the handle so the [`Drop`] impl will not emit a second
    /// duplicate undeclare against an already-retracted id. Mirrors
    /// [`Subscriber::undeclare`] / [`Queryable::undeclare`].
    ///
    /// The disarm-flag teardown (R311lo) emits the `UndeclToken`
    /// exactly once: a second `UndeclToken` for the same id would be
    /// ignored by the peer anyway, but suppressing it matches the
    /// textbook RAII consume contract across the wz handle family and
    /// frees the owned fields rather than `mem::forget` leaking them.
    pub fn undeclare(mut self) {
        self.teardown();
    }

    /// R311lo — shared teardown for [`Self::undeclare`] + [`Drop`], the
    /// single source of the emit-then-unregister discipline (R248/R283
    /// previously kept the two bodies in lock-step by hand). Idempotent
    /// via `armed`: the first caller emits `Declare(UndeclToken)` so the
    /// peer's liveliness subscribers receive the DELETE sample, drops
    /// the declarer-side registration (so a later inbound Interest no
    /// longer replies with this now-undeclared token), and disarms; a
    /// second call is a no-op (no duplicate wire frame). R311o —
    /// `send_undeclare_token` is signature-stable (silent no-op when
    /// declare-* off); when `liveliness-token` is off no LivelinessToken
    /// is ever constructed so this never runs at runtime. The wire path
    /// is panic-free under normal operation; a poisoned driver path is a
    /// future-round carry.
    fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        self.session.actions().send_undeclare_token(self.id);
        #[cfg(feature = "liveliness-token")]
        R::with_mutex_mut(&self.session.observer, |obs| {
            obs.local_tokens.unregister(self.id);
        });
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for LivelinessToken<R, T> {
    fn drop(&mut self) {
        // R311lo — RAII teardown; disarmed after an explicit
        // `undeclare`, so this frees the owned fields without emitting a
        // duplicate UndeclToken.
        self.teardown();
    }
}

/// R248 — typed error returned by [`Session::declare_token`] /
/// [`Session::declare_token_aliased`]. Mirror of
/// [`SubscribeAliasError`] / [`QueryableAliasError`] /
/// [`QueryAliasError`] / [`PublishAliasError`] on the liveliness
/// token side.
///
/// R311o — unified error for both literal and aliased declare paths.
/// Previously `declare_token` returned `Result<_, OutboundKeyexprError>`
/// directly; the aliased form already returned this enum. The
/// non-aliased form now wraps its keyexpr-gate rejection in
/// [`Self::InvalidKeyexpr`] for symmetry with the aliased form and so
/// the [`Self::FeatureDisabled`] variant (R311o type-ungating cascade)
/// covers both call sites uniformly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelinessAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_token_aliased call).
    UnknownMapping(u64),
    /// R300 — the keyexpr (literal for [`Session::declare_token`], or
    /// reconstructed `outbound_mapping[id] || inline_suffix` for
    /// [`Session::declare_token_aliased`]) failed the outbound
    /// pico-safety gate ([`OutboundKeyexprError`]). Either non-canonical
    /// per the zenoh keyexpr grammar OR matching the R299 bug #3 SIGABRT
    /// pattern family (`**` chunk + non-`*` chunk + `*`-shape chunk).
    /// The wire emit was suppressed pre-send.
    InvalidKeyexpr(OutboundKeyexprError),
    /// R311o — the `liveliness-token` feature was disabled at the
    /// `wz-runtime-tokio` crate level so no LivelinessToken instance
    /// can be constructed. Signature-stability per
    /// `feedback_signature_stability` MEMORY anchor: the declare_token
    /// surface stays callable from consumer code (no cfg cascade) but
    /// returns this variant instead of attempting a wire emit on a
    /// build whose declare-token / declare-undeclare runtime path is
    /// absent.
    FeatureDisabled,
    /// W3 (SCE pin 7a94d084a) — the resolved keyexpr exceeded the
    /// declared bounded-codec capacity (`MAX_KEYEXPR_BYTES`) while
    /// being copied into the no-alloc owned DECLARE mirror, so no wire
    /// bytes were emitted. Semantic projection of the codec-layer
    /// `CodecError` (the public surface stays free of the SCE codec
    /// type, mirroring how the other variants expose wz-level causes).
    ExceedsCapacity,
    /// F2 — the transport is not currently accepting data sends (link
    /// released or reconnecting; Established not re-entered). The
    /// DECLARE was not emitted; re-declare after the session
    /// re-establishes (zenoh-pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE`).
    TransportUnavailable,
}

impl std::fmt::Display for LivelinessAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivelinessAliasError::UnknownMapping(id) => write!(
                f,
                "LivelinessAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            LivelinessAliasError::InvalidKeyexpr(inner) => write!(
                f,
                "LivelinessAliasError: keyexpr failed outbound gate — {inner}"
            ),
            LivelinessAliasError::FeatureDisabled => write!(
                f,
                "LivelinessAliasError: `liveliness-token` feature is disabled \
                 on this wz-runtime-tokio build; rebuild with the feature \
                 enabled (or its preset) to obtain a LivelinessToken handle"
            ),
            LivelinessAliasError::ExceedsCapacity => write!(
                f,
                "LivelinessAliasError: keyexpr exceeded the declared codec \
                 capacity (MAX_KEYEXPR_BYTES); the DECLARE was not emitted"
            ),
            LivelinessAliasError::TransportUnavailable => write!(
                f,
                "LivelinessAliasError: transport not available (link released \
                 or reconnecting); the DECLARE was not emitted — re-declare \
                 after the session re-establishes"
            ),
        }
    }
}

impl std::error::Error for LivelinessAliasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LivelinessAliasError::InvalidKeyexpr(inner) => Some(inner),
            LivelinessAliasError::UnknownMapping(_)
            | LivelinessAliasError::FeatureDisabled
            | LivelinessAliasError::ExceedsCapacity
            | LivelinessAliasError::TransportUnavailable => None,
        }
    }
}

/// R280 — options bundle for
/// [`Session::declare_liveliness_subscriber`]. Mirrors zenoh-pico's
/// `z_liveliness_subscriber_options_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h:88-90`):
/// a single `history` boolean today; `#[non_exhaustive]` so a
/// future round can add fields without breaking external callers.
///
/// `history = true` instructs the peer to immediately replay the
/// matching liveliness-token snapshot through `Decl*Token` records
/// before any future-only signal arrives — sets the `CURRENT` bit
/// (`_Z_INTEREST_FLAG_CURRENT`) on the outbound Interest header per
/// `vendor/zenoh-pico/src/net/liveliness.c:198`. `history = false`
/// (default) only subscribes for future events.
///
/// R311o — type-ungated per `feedback_signature_stability` MEMORY
/// anchor. The struct + builder are always defined regardless of the
/// `liveliness-subscriber` feature so caller-side option construction
/// compiles unconditionally.
///
/// R311q closure — the prior carry ("deferred to a future round when
/// the observer.liveliness_subscribers field + declare::liveliness_subscriber
/// module become unconditional") is now closed: the
/// [`LivelinessSubscriber`] handle, the
/// [`Session::declare_liveliness_subscriber{_aliased}`] surface
/// (Result form with `FeatureDisabled` variant), the
/// `observer.liveliness_subscribers` field, and the
/// `declare::liveliness_subscriber` module are all type-ungated. The
/// only remaining feature gate is the BODY of the two declare entry
/// points + the dispatch fan-out in `ApplicationLayerObserver`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LivelinessSubscriberOptions {
    /// `true` to request a current-state replay from the peer at
    /// declare time, `false` to subscribe only to future events.
    pub history: bool,
}

impl LivelinessSubscriberOptions {
    /// Default options — `history = false`. Mirrors zenoh-pico's
    /// `z_liveliness_subscriber_options_default`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder — set the `history` flag explicitly.
    pub fn with_history(mut self, history: bool) -> Self {
        self.history = history;
        self
    }
}

/// R280 — handle for a liveliness subscriber declared through
/// [`Session::declare_liveliness_subscriber`]. Holds the
/// `interest_id` allocated by
/// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`]
/// so `Drop` can emit the matching `Interest(Final)` retraction on
/// the outbound link AND remove the slot from the local
/// [`crate::declare::LivelinessSubscriberRegistry`].
///
/// ## Lifetime + wire emit on Drop
///
/// The subscriber stays declared on the peer for as long as this
/// handle is alive on the local session. `Drop` emits
/// `Interest(Final)` so the peer's
/// `_z_interest_process_interest_final` removes our entry from its
/// remote-interests table — mirror of zenoh-pico's
/// `_z_undeclare_liveliness_subscriber` at
/// `vendor/zenoh-pico/src/net/liveliness.c:232-243`. Local slot
/// removal runs first so any inbound dispatch racing the wire emit
/// does not fire a callback against a slot that is about to
/// disappear from the registry.
///
/// `!Clone` by construction — the underlying `interest_id` is a
/// unique handle; cloning would let two drops race to emit
/// `InterestFinal` for the same id, and the peer would treat the
/// second as a no-op. Code wanting "the same liveliness subscription
/// from two places" should call
/// [`Session::declare_liveliness_subscriber`] twice and accept two
/// distinct interest ids — that matches zenoh-pico semantics.
///
/// ## Panic semantics on Drop
///
/// The wire-emit path (`send_interest_final`) is panic-free under
/// normal AP MVP operation, matching the [`LivelinessToken`]
/// contract. The observer mutex lock could in principle be poisoned
/// by an earlier callback panic; the Drop impl `map`s over the
/// `Result` so a poisoned mutex still produces an idempotent
/// no-op rather than a double panic (same shape as
/// [`crate::pubsub::Subscriber::drop`] guard).
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_liveliness_subscriber`].
///
/// R311q — type-ungated. The struct, impl, and Drop are always defined
/// so the [`Session::declare_liveliness_subscriber{_aliased}`]
/// Result-form signature compiles regardless of feature state; a
/// feature-OFF call returns `Err(LivelinessSubscriberAliasError::FeatureDisabled)`
/// without ever constructing this handle (so the Drop-path wire emit
/// never fires from a stub). The Drop body calls `send_interest_final`
/// alongside `observer.liveliness_subscribers.unregister`, both of
/// which are unconditionally available after the R311g1 signature-
/// stability sweep + the R311q observer field ungate.
// R311cu — R267 helper cascade. `!Clone`; Drop is generic via
// R::with_mutex_mut so per-profile poison-recovery stays inside the
// runtime impl. Behavior tightens vs. prior `if let Ok(...)` form: a
// poisoned observer now also runs unregister (poison recovery via
// into_inner on AP; no poison concept on MCU). The peer-side
// Interest(Final) emit was already unconditional.
#[non_exhaustive]
pub struct LivelinessSubscriber<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    pub(super) interest_id: u64,
    pub(super) keyexpr: String,
    pub(super) options: LivelinessSubscriberOptions,
    /// R311lg — the deferred-fire cell holding the user callback (the
    /// registry-installed sink only stages; the drive loop's drain
    /// fires through this cell outside the observer lock — the R311lf
    /// lock-free callback invariant on the liveliness-sample plane).
    /// Gated like the registry slot: the field exists iff a subscriber
    /// can be constructed.
    #[cfg(feature = "liveliness-subscriber")]
    pub(super) cell: LivelinessSampleCell<R>,
    /// R311lo — RAII disarm flag. [`Self::undeclare`] runs the teardown
    /// once and clears this so the natural [`Drop`] frees the owned
    /// fields (keyexpr String, the Session Arc clone, the cell Arc)
    /// instead of the prior `mem::forget(self)` leaking them, and so no
    /// duplicate `Interest(Final)` is emitted. `true` at construction;
    /// `false` once teardown has run.
    pub(super) armed: bool,
}

/// R311lg — the type-erased user callback a deferred liveliness
/// subscriber's cell holds: erased at registration so the
/// [`LivelinessSubscriber`] handle has a nameable cell type (the
/// [`DeclListener`] / [`MatchingListener`] convention).
#[cfg(feature = "liveliness-subscriber")]
pub(super) type BoxedLivelinessSampleCallback =
    Box<dyn FnMut(LivelinessSample<'_>) + Send + 'static>;

/// R311lg — the per-subscriber deferred-fire cell (take-call-restore
/// with the lossless backlog; see [`wz_session_core::deferred_fire`]).
/// The registry-installed staging sink fires against it;
/// [`LivelinessSubscriber::undeclare`] / `Drop` kill it so a
/// staged-but-undrained sample is suppressed and self-undeclare from
/// inside the callback is safe.
#[cfg(feature = "liveliness-subscriber")]
pub(super) type LivelinessSampleCell<R> =
    wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedLivelinessSampleCallback>;

impl<R: SessionRuntime, T: TimeSource> Session<R, T> {
    /// R311lg — build the deferred cell + the staging sink one
    /// `declare_liveliness_subscriber{_aliased}` call installs in the
    /// registry: the sink copies the borrowed [`LivelinessSample`] out
    /// to its owned fields (a deferred fire outlives the dispatch
    /// borrow) and stages one queue job per sample; the job
    /// reconstructs the borrowed sample over the owned copy when it
    /// invokes the user callback OUTSIDE the observer lock. The
    /// callback signature is unchanged — deferral is invisible at the
    /// type level.
    #[cfg(feature = "liveliness-subscriber")]
    pub(super) fn deferred_liveliness_sample_sink(
        &self,
        callback: impl FnMut(LivelinessSample<'_>) + Send + 'static,
    ) -> (LivelinessSampleCell<R>, BoxedLivelinessSampleSink) {
        let erased: BoxedLivelinessSampleCallback = Box::new(callback);
        let cell: LivelinessSampleCell<R> =
            wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
        let queue = self.fires.clone();
        let cell_for_sink = cell.clone();
        let sink = BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
            let kind = sample.kind;
            let keyexpr = sample.keyexpr.to_string();
            let token_id = sample.token_id;
            let cell = cell_for_sink.clone();
            queue.stage(Box::new(move || {
                cell.invoke(move |cb| {
                    cb(LivelinessSample {
                        kind,
                        keyexpr: &keyexpr,
                        token_id,
                    })
                })
            }));
        });
        (cell, sink)
    }
}

impl<R: SessionRuntime, T: TimeSource> LivelinessSubscriber<R, T> {
    /// The stable interest id allocated at declare time by
    /// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`].
    /// Exposed for diagnostics; callers should not rely on the exact
    /// value across runs since the counter is session-scoped +
    /// Relaxed ordering.
    pub fn interest_id(&self) -> u64 {
        self.interest_id
    }

    /// The keyexpr pattern the subscriber was declared on. Useful
    /// for debug logging and matching the handle back to its
    /// originating call site.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &LivelinessSubscriberOptions {
        &self.options
    }

    /// `true` when the subscriber requested `history = true` AND the
    /// peer has signaled history-complete by emitting
    /// `Interest(Final)` for our `interest_id`. Returns `false` for a
    /// `history = false` subscriber (no replay was requested → the
    /// flag is meaningless and stays `false`) and for a
    /// history-enabled subscriber that has not yet observed its
    /// matching `InterestFinal`.
    ///
    /// Mirrors zenoh-pico's `_z_interest_process_interest_final`
    /// post-condition (`vendor/zenoh-pico/src/session/interest.c:524`):
    /// `InterestFinal` arrival marks the subscription's historical
    /// replay complete; subsequent `Decl*Token` records arrive as
    /// new (future) events.
    pub fn history_complete(&self) -> bool {
        // R311dh — observer access via R::with_mutex_mut closure form.
        // Per-profile poison-recovery lives inside the runtime impl; the
        // pre-R311dh code returned `false` on poisoned-lock via the
        // `.unwrap_or(false)` arm. The closure form propagates the
        // recovered guard so the inner closure always sees an exclusive
        // `&mut ApplicationLayerObserver` borrow.
        //
        // R311ek — the `observer.liveliness_subscribers` slot exists only
        // under `liveliness-subscriber`; on the feature-OFF build the
        // handle can never be constructed (`declare_liveliness_subscriber`
        // returns `Err(FeatureDisabled)`), so this dead-but-compiled path
        // returns the `false` default (signature-stability).
        #[cfg(feature = "liveliness-subscriber")]
        {
            R::with_mutex_mut(&self.session.observer, |observer| {
                observer
                    .liveliness_subscribers
                    .history_complete(self.interest_id)
            })
        }
        #[cfg(not(feature = "liveliness-subscriber"))]
        {
            false
        }
    }

    /// Explicitly retract this liveliness subscriber. Emits
    /// `Interest(Final)` on the outbound link exactly once (R311lo
    /// disarm-flag teardown) and frees the owned fields rather than
    /// `mem::forget` leaking them. Mirror of
    /// [`LivelinessToken::undeclare`].
    pub fn undeclare(mut self) {
        self.teardown();
    }

    /// R311lo — shared teardown for [`Self::undeclare`] + [`Drop`], the
    /// single source of the kill-then-unregister-then-final discipline
    /// (R280/R311lg previously kept the two bodies in lock-step by
    /// hand). Idempotent via `armed`: the first caller kills the
    /// deferred cell FIRST (so a sample staged before this call but not
    /// yet drained is suppressed — the callback never observes a
    /// post-undeclare sample), unregisters the local slot so a racing
    /// inbound dispatch sees no slot, emits `Interest(Final)` so the
    /// peer drops its end, and disarms; a second call is a no-op (no
    /// duplicate wire frame). R311ek — the registry slot exists only
    /// under `liveliness-subscriber`; `send_interest_final` is
    /// signature-stable so the wire-retract stays unconditional.
    /// Per-profile poison-recovery lives inside the `R::with_mutex_mut`
    /// impl.
    fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        #[cfg(feature = "liveliness-subscriber")]
        {
            self.cell.kill();
            R::with_mutex_mut(&self.session.observer, |observer| {
                observer.liveliness_subscribers.unregister(self.interest_id);
            });
        }
        self.session.actions().send_interest_final(self.interest_id);
    }
}

impl<R: SessionRuntime, T: TimeSource> Drop for LivelinessSubscriber<R, T> {
    fn drop(&mut self) {
        // R311lo — RAII teardown; disarmed after an explicit
        // `undeclare`, so this frees the owned fields without emitting a
        // duplicate Interest(Final).
        self.teardown();
    }
}

/// R282 / R283 — typed error returned by
/// [`Session::declare_liveliness_subscriber_aliased`]. Two variants
/// cover the two declare-time pre-conditions:
///
/// - [`Self::UnknownMapping`] (R282) — the aliased mapping id is not
///   present in the outbound mapping table; resolution would emit a
///   wire frame the peer cannot decode.
/// - [`Self::NotEstablished`] (R283) — the session-FSM has not yet
///   entered `Established`; an outbound `Interest` emit before
///   handshake completion is silently discarded by the peer
///   (no `remote-interests` table entry yet).
///
/// Variant ordering at the call site is: `UnknownMapping` checked
/// first (mapping resolution is FSM-state-independent and cheaper),
/// then `NotEstablished`. So a pre-Established call with an unknown
/// mapping returns `UnknownMapping`, not `NotEstablished` — the
/// caller fixes the bug-class error before retrying the
/// session-state-dependent retry loop.
///
/// Mirror of [`SubscribeAliasError`] / [`QueryableAliasError`] /
/// [`QueryAliasError`] / [`PublishAliasError`] /
/// [`LivelinessAliasError`] on the liveliness subscriber side, plus
/// the R283 `NotEstablished` extension. The sibling errors do not yet
/// carry the `NotEstablished` variant — uniform extension to the rest
/// of the declare_* surface is a future-round carry (see
/// [`Session::declare_liveliness_subscriber`] doc-comment on the
/// asymmetric gate).
///
/// R311q — type-ungated + [`Self::FeatureDisabled`] variant added.
/// The enum is always defined so the
/// [`Session::declare_liveliness_subscriber{_aliased}`] Result-form
/// signature compiles regardless of feature state; a feature-OFF call
/// returns `Err(FeatureDisabled)` so caller code can branch on it
/// uniformly. Mirrors the `FeatureDisabled` variant pattern already
/// established on other declare_* AliasError families during the
/// R311 signature-stability sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelinessSubscriberAliasError {
    /// R282 — no prior `send_declare_keyexpr` registered this id on
    /// the outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it before the declare_liveliness_subscriber_aliased
    /// call).
    UnknownMapping(u64),
    /// R283 — the session-FSM has not yet entered `Established`. The
    /// outbound `Interest` frame would be emitted into a session that
    /// is mid-handshake (InitSyn / InitAck / OpenSyn / OpenAck) and
    /// the peer would discard it (no `remote-interests` table entry
    /// yet). Caller should wait for
    /// [`crate::Session::is_established`] (or the equivalent
    /// session-level signal in higher-tier wrappers) to flip to
    /// `true` before retrying the declare. Mirrors zenoh-pico's
    /// implicit "declare AFTER z_open returns Z_OK" sequencing
    /// contract.
    NotEstablished,
    /// R311q — the `liveliness-subscriber` feature is OFF at compile
    /// time. Returned by both
    /// [`Session::declare_liveliness_subscriber`] and
    /// [`Session::declare_liveliness_subscriber_aliased`] when the
    /// build elides the wire-emit + observer-dispatch path. Caller
    /// must feature-detect at the consumer-crate level (e.g. via a
    /// `#[cfg]` branch on the same feature) before relying on a
    /// liveliness subscription; the registry-side dispatch is also
    /// disabled so no callback would ever fire even if a stub handle
    /// were constructed.
    FeatureDisabled,
    /// W3 (SCE pin 7a94d084a) — the resolved keyexpr exceeded the
    /// declared bounded-codec capacity (`MAX_KEYEXPR_BYTES`) while
    /// being copied into the no-alloc owned `Interest` mirror, so no
    /// wire bytes were emitted. Semantic projection of the codec-layer
    /// reject.
    ExceedsCapacity,
}

impl std::fmt::Display for LivelinessSubscriberAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LivelinessSubscriberAliasError::UnknownMapping(id) => write!(
                f,
                "LivelinessSubscriberAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            LivelinessSubscriberAliasError::NotEstablished => write!(
                f,
                "LivelinessSubscriberAliasError: session-FSM not yet Established; \
                 wait for Session::is_established() to flip to true (or for the \
                 session-layer Established signal) before retrying the declare"
            ),
            LivelinessSubscriberAliasError::FeatureDisabled => write!(
                f,
                "LivelinessSubscriberAliasError: liveliness-subscriber feature is OFF at \
                 compile time; the wire-emit and observer-dispatch paths are elided, \
                 so no subscription can be established on this build"
            ),
            LivelinessSubscriberAliasError::ExceedsCapacity => write!(
                f,
                "LivelinessSubscriberAliasError: keyexpr exceeded the declared codec \
                 capacity (MAX_KEYEXPR_BYTES); the Interest was not emitted"
            ),
        }
    }
}

impl std::error::Error for LivelinessSubscriberAliasError {}

impl From<SendWireError> for LivelinessSubscriberAliasError {
    fn from(e: SendWireError) -> Self {
        match e {
            SendWireError::Codec(_) => LivelinessSubscriberAliasError::ExceedsCapacity,
            SendWireError::FeatureDisabled => LivelinessSubscriberAliasError::FeatureDisabled,
            // F2 — the reconnect window IS a not-yet-(re)Established
            // session; the existing variant names the same contract.
            SendWireError::TransportUnavailable => LivelinessSubscriberAliasError::NotEstablished,
        }
    }
}
