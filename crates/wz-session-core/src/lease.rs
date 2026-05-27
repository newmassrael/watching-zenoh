// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Lease-deadline check outcome surfaced by the R77 `check_lease_deadline`
//! helper. The helper itself stays in wz-runtime-tokio (it mutates the
//! generated SCXML engine via `engine.process_event`); the outcome enum
//! is no_std + no_alloc clean and migrates here so MCU profiles can
//! type-equality-compare lease verdicts without dragging in tokio.

/// R77 — outcome of a single lease-deadline check against
/// `SessionLinkActions`' baseline stamps.
///
/// Baseline selection (R84): the lease counts from
/// `max(established_at, last_inbound_keepalive_at)` — whichever is
/// most recent. Both slots being `None` means the FSM has not
/// reached Established yet AND no peer KeepAlive has been
/// observed (e.g. pre-handshake), and the helper defers via
/// `NoBaseline`. The prior R77 baseline was `last_inbound_keepalive_at`
/// alone, which left `NoBaseline` pinned indefinitely until the
/// first peer KeepAlive — violating session-fsm §2.5 ("lease
/// counts from Established entry").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCheckOutcome {
    /// Both `established_at` and `last_inbound_keepalive_at` are
    /// `None`. The helper makes no decision and does NOT inject
    /// `LeaseExpired`. In practice this surfaces only pre-Established
    /// (since `Established.onentry` populates `established_at` per
    /// R84). Production callers treat this as "still polling".
    NoBaseline,
    /// `now.duration_since(baseline) < params.lease` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper performed no FSM mutation; engine state is
    /// unchanged.
    WithinLease,
    /// `now.duration_since(baseline) >= params.lease` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper has invoked
    /// `engine.process_event(SessionFsmUnicastEvent::LeaseExpired)`
    /// so the session-fsm `lease.expired -> Closing(Expired)`
    /// transition fires.
    Expired,
}
