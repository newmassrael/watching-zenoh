// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311kh — matching-listener session surface (zenoh-pico
//! `Z_FEATURE_MATCHING` parity: `z_publisher_declare_matching_listener`
//! / the querier form): the callback counterpart of the polling
//! [`Publisher::get_matching_status`](super::Publisher::get_matching_status)
//! / [`Querier::get_matching_status`](super::Querier::get_matching_status).
//! The callback fires on every matching-status TRANSITION caused by an
//! inbound remote `Declare(Decl*/Undecl*)` — never on registration (pico
//! transition-only; `get_matching_status` remains the poll for the
//! current value).
//!
//! The watch state lives in the wz-session-core registries
//! (`RemoteSubscriberRegistry` / `RemoteQueryableRegistry` matching
//! watch lists, re-evaluated at the declare dispatch); this module is
//! the handle + the typed feature-off reject.

use super::*;

/// R311kz — the type-erased user callback a matching listener's
/// deferred cell holds: erased at registration so the
/// [`MatchingListener`] handle has a nameable cell type.
#[cfg(all(
    feature = "session-matching",
    any(feature = "declare-subscriber", feature = "declare-queryable")
))]
pub(super) type BoxedMatchingCallback = Box<dyn FnMut(MatchingStatus) + Send + 'static>;

/// R311kz — the per-listener deferred-fire cell (take-call-restore;
/// see [`wz_session_core::deferred_fire`]). The registry-installed
/// sink stages fires against it; [`MatchingListener::undeclare`] kills
/// it so a staged-but-undrained fire is suppressed and self-undeclare
/// from inside the callback is safe.
#[cfg(all(
    feature = "session-matching",
    any(feature = "declare-subscriber", feature = "declare-queryable")
))]
pub(super) type MatchingListenerCell<R> =
    wz_session_core::deferred_fire::DeferredListenerCell<R, BoxedMatchingCallback>;

/// Which observer registry a [`MatchingListener`]'s watch lives in.
/// Publisher listeners watch remote SUBSCRIBERS; querier listeners watch
/// remote QUERYABLES — the same split as the two `get_matching_status`
/// consults.
///
/// R311kk — each variant is gated on the features that can CONSTRUCT it
/// (the `declare_matching_listener` arm that returns the handle): under
/// a subset where a registry is off, its variant is uninhabitable
/// rather than dead code (the C1j/C4c deny-warnings lanes reject a
/// never-constructed variant). With both off the enum is empty and
/// [`MatchingListener::undeclare`]'s match is the zero-arm match on an
/// uninhabited type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MatchingScope {
    #[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
    RemoteSubscribers,
    #[cfg(all(feature = "session-matching", feature = "declare-queryable"))]
    RemoteQueryables,
}

/// Live matching-listener registration. Returned by
/// [`Publisher::declare_matching_listener`](super::Publisher::declare_matching_listener)
/// / [`Querier::declare_matching_listener`](super::Querier::declare_matching_listener);
/// the callback keeps firing on status transitions until
/// [`undeclare`](Self::undeclare) (pico
/// `_z_matching_listener_undeclare`). Explicit undeclare only — no Drop
/// hook, consistent with the other wz handles (a dropped handle leaves
/// the watch installed, exactly as a dropped pico listener struct whose
/// owner never called undeclare).
pub struct MatchingListener<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T, Unicast>,
    pub(super) id: u64,
    pub(super) scope: MatchingScope,
    /// R311kz — the deferred-fire cell holding the user callback (the
    /// registry sink only stages; the drive loop's drain fires through
    /// this cell outside the observer lock). Gated like the scope
    /// variants' union: the field exists iff a listener can be
    /// constructed.
    #[cfg(all(
        feature = "session-matching",
        any(feature = "declare-subscriber", feature = "declare-queryable")
    ))]
    pub(super) cell: MatchingListenerCell<R>,
    /// R311y771 — the id of the `Interest` this listener's declare emitted to
    /// ask the peer for the declarations the watch is fed by, so
    /// [`undeclare`](Self::undeclare) can terminate it with the matching
    /// `Interest(Final)`.
    ///
    /// A SEPARATE id space from the handle's `id` field, which is the registry's
    /// watch-list slot and never leaves the process. Reusing the watch id on
    /// the wire would collide with the session's own interest counter (both
    /// start low and count up) and retract somebody else's interest —
    /// `alloc_next_interest_id` is the only issuer of the wire id.
    ///
    /// Gated with the emit itself: without `declare-interest` no Interest was
    /// sent, so there is no id to hold and nothing to Final.
    #[cfg(all(
        feature = "session-matching",
        feature = "declare-interest",
        any(feature = "declare-subscriber", feature = "declare-queryable")
    ))]
    pub(super) interest_id: u64,
}

impl<R: SessionRuntime, T: TimeSource> MatchingListener<R, T> {
    /// R311y771 — the wire id of the `Interest` this listener declared, the
    /// one [`undeclare`](Self::undeclare) retracts. Mirrors
    /// `LivelinessSubscriber::interest_id`.
    ///
    /// Public because it is the only handle on a per-listener piece of PEER
    /// state: a caller correlating an inbound `interest_id`-tagged
    /// `Declare(DeclFinal)` — the terminator of the CURRENT-mode replay this
    /// interest requested — has nothing else to match it against.
    #[cfg(all(
        feature = "session-matching",
        feature = "declare-interest",
        any(feature = "declare-subscriber", feature = "declare-queryable")
    ))]
    pub fn interest_id(&self) -> u64 {
        self.interest_id
    }

    /// Remove the watch — the callback will not fire again. Returns
    /// whether a watch was removed (`false` = already removed, e.g. a
    /// clone of the underlying session undeclared it first).
    ///
    /// R311kz — kills the deferred cell FIRST, so a fire staged before
    /// this call but not yet drained is suppressed (the callback never
    /// observes a post-undeclare transition), then unregisters the
    /// watch under the observer lock. Callable from INSIDE the
    /// listener's own callback (the take-call-restore cell makes
    /// self-undeclare deadlock-free).
    pub fn undeclare(self) -> bool {
        // R311g1 / R311kk — bind the handle state unconditionally: under
        // a feature subset where both registry variants are cfg-off (e.g.
        // the C1j handshake-only lane) the zero-arm match below reads
        // neither field and the deny-warnings build would reject them.
        let _ = (&self.session, self.id);
        #[cfg(all(
            feature = "session-matching",
            any(feature = "declare-subscriber", feature = "declare-queryable")
        ))]
        self.cell.kill();
        // R311y771 — retract the Interest the declare emitted, BEFORE the
        // watch comes off. Ordering matters in one direction only: a
        // declaration that races in after the Final but before the
        // unregister lands on a watch that is still installed and fires a
        // legitimate transition, whereas the reverse order would leave a
        // window in which the peer is still streaming into a registry no
        // watch reads — the same leak the missing Final would be permanently.
        //
        // No error channel: `undeclare` answers "was a watch removed", and a
        // transport already down cannot be told about the retract anyway —
        // the peer's interest table dies with the session. This mirrors
        // `send_interest_final`'s own F2 contract.
        #[cfg(all(
            feature = "session-matching",
            feature = "declare-interest",
            any(feature = "declare-subscriber", feature = "declare-queryable")
        ))]
        self.session.actions().send_interest_final(self.interest_id);
        // Each arm rides its variant's gate (see [`MatchingScope`]); a
        // variant that cannot be constructed has no arm, and with both
        // off this is the zero-arm match on an uninhabited enum.
        match self.scope {
            #[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
            MatchingScope::RemoteSubscribers => R::with_mutex_mut(self.session.observer(), |obs| {
                obs.remote_subscribers.undeclare_matching_listener(self.id)
            }),
            #[cfg(all(feature = "session-matching", feature = "declare-queryable"))]
            MatchingScope::RemoteQueryables => R::with_mutex_mut(self.session.observer(), |obs| {
                obs.remote_queryables.undeclare_matching_listener(self.id)
            }),
        }
    }
}

/// Typed reject from `declare_matching_listener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingListenerError {
    /// R311g1 signature-stability — the `session-matching` Cargo feature
    /// (or the registry feature the watch would live in:
    /// `declare-subscriber` for publishers, `declare-queryable` for
    /// queriers) is OFF in this build; no watch list exists to register
    /// into. The method signature stays visible so callers observe the
    /// build-time choice as a runtime reject instead of a missing symbol.
    FeatureDisabled,
    /// R311y771 — the Interest that asks the peer for the declarations this
    /// watch is FED BY could not be emitted, so no listener was registered.
    ///
    /// Surfaced rather than swallowed because the failure is invisible from
    /// the application's side: a listener whose Interest never reached a
    /// zenoh router is registered against a registry the router will never
    /// feed (`hat/router/pubsub.rs:120-125` gates propagation on the face's
    /// own interest), so it simply never fires — indistinguishable from
    /// "nothing matched yet".
    Wire(wz_session_core::send_wire_error::SendWireError),
}

impl core::fmt::Display for MatchingListenerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FeatureDisabled => f.write_str(
                "declare_matching_listener: the session-matching Cargo feature \
                 (or the backing declare-subscriber / declare-queryable \
                 registry feature) is OFF in this build (signature-stability \
                 contract — build-time choice observed as runtime reject)",
            ),
            Self::Wire(e) => write!(
                f,
                "declare_matching_listener: the backing Interest emit failed \
                 ({e}); no watch was registered",
            ),
        }
    }
}

impl core::error::Error for MatchingListenerError {}
