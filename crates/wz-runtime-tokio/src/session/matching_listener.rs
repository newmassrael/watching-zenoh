// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    pub(super) session: Session<R, T>,
    pub(super) id: u64,
    pub(super) scope: MatchingScope,
}

impl<R: SessionRuntime, T: TimeSource> MatchingListener<R, T> {
    /// Remove the watch — the callback will not fire again. Returns
    /// whether a watch was removed (`false` = already removed, e.g. a
    /// clone of the underlying session undeclared it first).
    pub fn undeclare(self) -> bool {
        // R311g1 / R311kk — bind the handle state unconditionally: under
        // a feature subset where both registry variants are cfg-off (e.g.
        // the C1j handshake-only lane) the zero-arm match below reads
        // neither field and the deny-warnings build would reject them.
        let _ = (&self.session, self.id);
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
        }
    }
}

impl core::error::Error for MatchingListenerError {}
