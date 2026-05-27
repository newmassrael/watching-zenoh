// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Reliability hint forwarded to the driver per session-fsm §6
//! outbound table; also surfaces as the link-layer reliability
//! classification on inbound samples (zenoh-pico `z_reliability_t`
//! mirror). R51 baseline TCP impl ignores the hint on the outbound
//! path (TCP is reliable by definition); UDP/best-effort impl will
//! honor it. R226 added `Default` / `Hash` / `repr(u8)` so the same
//! enum can carry inbound `Sample.reliability` per the zenoh-pico
//! `_z_trigger_push` argument shape.
//!
//! The default value matches zenoh-pico's
//! `Z_RELIABILITY_DEFAULT = Z_RELIABILITY_RELIABLE` contract — a
//! subscriber that does not inspect the field observes the most
//! permissive delivery guarantee.

/// Reliability hint shared by LinkDriver outbound path + Sample
/// inbound projection. See module doc for zenoh-pico parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Reliability {
    /// Best-effort delivery — samples may be dropped (zenoh-pico
    /// `Z_RELIABILITY_BEST_EFFORT`).
    BestEffort = 0,
    /// Reliable delivery — link layer guarantees ordering and delivery
    /// (zenoh-pico `Z_RELIABILITY_RELIABLE`, the default).
    #[default]
    Reliable = 1,
}

impl Reliability {
    /// Map a `reliable: bool` discriminator (the
    /// `DriverLoopOutcome::FramePayload.reliable` field shape) to the
    /// typed enum. Inbound dispatch uses this to project the
    /// frame-level bool into a `Sample.reliability` value.
    pub fn from_reliable_bool(reliable: bool) -> Self {
        if reliable {
            Reliability::Reliable
        } else {
            Reliability::BestEffort
        }
    }
}
