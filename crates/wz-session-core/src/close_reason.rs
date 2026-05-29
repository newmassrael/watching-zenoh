// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ed — session close-reason discriminator lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! Pure no_std + no_alloc value type (a byte-valued enum), so it sits on
//! the runtime-agnostic side alongside [`crate::reliability`] /
//! [`crate::qos`]: an MCU profile that drives the session FSM closes with
//! the same typed reason as the tokio AP profile. The wire encode
//! (`reason as u8` into the Close codec body) stays in `session_glue.rs`
//! next to the rest of the Close codec path; `session_glue.rs` keeps a
//! `pub use` re-export so the `crate::session_glue::CloseReason`
//! callsites (`SessionLinkActions::send_close_with_reason`, the Close
//! codec tests, and `wz-ap-demo::teardown`) resolve unchanged. A DP3
//! leaf out of session_glue.

/// Discrete close-reason discriminator. Mirrors the four close-reason
/// mutator actions emitted by `session_fsm_unicast.scxml`
/// (`set_close_reason_generic / invalid / expired / unresponsive`).
/// Encoded as a single byte in the Close codec body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseReason {
    /// Default close (set via `session.close` transition).
    #[default]
    Generic = 0,
    /// Framing error close.
    Invalid = 1,
    /// Lease expired close.
    Expired = 2,
    /// TX congestion / peer unresponsive close.
    Unresponsive = 3,
}
