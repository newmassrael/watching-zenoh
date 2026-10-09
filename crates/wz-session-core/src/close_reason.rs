// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// Discrete close-reason discriminator, encoded as a single byte in the
/// Close codec body.
///
/// The discriminants ARE the wire values, and they are upstream's:
/// `commons/zenoh-protocol/src/transport/close.rs` @ `pub const UNRESPONSIVE`
/// declares `GENERIC` 0 through `CONNECTION_TO_SELF` 7, and zenoh-pico's
/// `_Z_CLOSE_*` agree on the six it defines (0 through 5; it has no
/// UNRESPONSIVE or CONNECTION_TO_SELF, and calls 3 `MAX_TRANSPORTS`). The enum
/// used to number only the four reasons the session FSM sets
/// (`set_close_reason_generic / invalid / expired / unresponsive`) 0 to 3, so
/// wz's `Invalid`, `Expired` and `Unresponsive` went out as the bytes upstream
/// names `UNSUPPORTED`, `INVALID` and `MAX_SESSIONS`: a stock zenohd logs the
/// reason it names, and wz to wz was symmetric, which is why no wz test saw
/// it. `scripts/lib/close_reason_gate.py` holds this table to the pinned
/// upstream source and to the vendored pico header.
///
/// The FSM action names are unchanged; only the numbers behind them moved. The
/// variants the FSM never sets are here because the table is the wire's, not
/// the FSM's: `MaxLinks` is what the multilink reject sends
/// ([`crate::extmultilink::CLOSE_REASON_MAX_LINKS`]), and the others are the
/// remainder of upstream's set, so a reader that names a received reason has
/// one table to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseReason {
    /// Default close (set via `session.close` transition).
    #[default]
    Generic = 0,
    /// The peer asked for something this node does not support.
    Unsupported = 1,
    /// Framing error / invalid parameters close.
    Invalid = 2,
    /// The acceptor already holds `max_sessions` sessions.
    MaxSessions = 3,
    /// The session already holds `max_links` links.
    MaxLinks = 4,
    /// Lease expired close.
    Expired = 5,
    /// TX congestion / peer unresponsive close.
    Unresponsive = 6,
    /// The dialled node is this node.
    ConnectionToSelf = 7,
}

#[cfg(test)]
mod tests {
    use super::CloseReason;

    /// The literal wire values, written out once so a renumbering is a
    /// visible edit here and not only in the enum. The comparison with the
    /// upstream source itself is `scripts/lib/close_reason_gate.py`; this
    /// pins the same eight numbers where `cargo test` can see them.
    #[test]
    fn the_discriminants_are_the_upstream_wire_values() {
        for (reason, wire) in [
            (CloseReason::Generic, 0u8),
            (CloseReason::Unsupported, 1),
            (CloseReason::Invalid, 2),
            (CloseReason::MaxSessions, 3),
            (CloseReason::MaxLinks, 4),
            (CloseReason::Expired, 5),
            (CloseReason::Unresponsive, 6),
            (CloseReason::ConnectionToSelf, 7),
        ] {
            assert_eq!(reason as u8, wire, "{reason:?}");
        }
        assert_eq!(CloseReason::default(), CloseReason::Generic);
    }
}
