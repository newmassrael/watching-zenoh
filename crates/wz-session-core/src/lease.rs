// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Lease-deadline check outcome surfaced by the R77 `check_lease_deadline`
//! helper, plus the lease wire-unit projection SSOT (R311ku). Stage 4b
//! hoisted the helper itself into the runtime-agnostic
//! [`crate::drive::check_lease_deadline`] (generic over `R: SessionRuntime`,
//! reading the baseline stamps through `R::with_mutex_mut`) so the AP tokio
//! loop and the lwIP MCU sync loop share one comparator; wz-runtime-tokio
//! re-exports it. This module is no_std + no_alloc clean (the enum predates
//! the helper hoist — migrated here at R311di-7 so MCU profiles could
//! type-equality-compare lease verdicts without dragging in tokio).

/// R311ku — encode-side lease wire-unit projection, the one home for the
/// `_Z_FLAG_T_*_T` rule both transports' encoders consume (OPEN and the
/// multicast JOIN carry the same flag semantics). zenoh-pico parity: every
/// `_z_t_msg_make_*` sets T for a whole-second lease and the codec then
/// divides (definitions/transport.c:113-115 / 196-214; codec divide
/// 59-62 / 293), so the pico-default 10000ms lease rides the wire as
/// `T=1 + VLE 10`. Returns `(lease_in_seconds, wire_value)`.
pub const fn lease_to_wire(lease_ms: u64) -> (bool, u64) {
    if lease_ms % 1000 == 0 {
        (true, lease_ms / 1000)
    } else {
        (false, lease_ms)
    }
}

/// R311ku — decode-side lease wire-unit projection: the wire value plus
/// the received `T` flag back to the milliseconds every wz consumer
/// speaks (zenoh-pico `_lease = _lease * 1000`, codec/transport.c:163 /
/// 314). Saturating: pico multiplies unchecked, but a hostile VLE near
/// `u64::MAX` must not panic an RX loop.
pub const fn lease_from_wire(in_seconds: bool, wire_value: u64) -> u64 {
    if in_seconds {
        wire_value.saturating_mul(1000)
    } else {
        wire_value
    }
}

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
    /// `now.duration_since(baseline) < params.lease_ms` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper performed no FSM mutation; engine state is
    /// unchanged.
    WithinLease,
    /// `now.duration_since(baseline) >= params.lease_ms` where
    /// `baseline = max(established_at, last_inbound_keepalive_at)`.
    /// The helper has invoked
    /// `engine.process_event(SessionFsmUnicastEvent::LeaseExpired)`
    /// so the session-fsm `lease.expired -> Closing(Expired)`
    /// transition fires.
    Expired,
}

#[cfg(test)]
mod tests {
    use super::{lease_from_wire, lease_to_wire};

    /// pico `make_*` parity: whole-second leases ride the seconds form
    /// (the default 10000ms compacts to T=1 + 10), fractional leases the
    /// raw-ms form; the decode projection inverts both exactly.
    #[test]
    fn lease_wire_unit_round_trips() {
        assert_eq!(lease_to_wire(10_000), (true, 10));
        assert_eq!(lease_to_wire(1_500), (false, 1_500));
        assert_eq!(lease_to_wire(0), (true, 0));
        for ms in [0u64, 999, 1_000, 1_500, 10_000, 86_400_000] {
            let (t, wire) = lease_to_wire(ms);
            assert_eq!(lease_from_wire(t, wire), ms, "round trip {ms}");
        }
    }

    /// A hostile near-MAX seconds VLE saturates instead of panicking.
    #[test]
    fn lease_from_wire_saturates() {
        assert_eq!(lease_from_wire(true, u64::MAX), u64::MAX);
    }
}
