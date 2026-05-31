// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Query-side enums shared by the Request(Query) builder and the
//! application-layer query API: [`ConsolidationMode`] (Z_CONSOLIDATION_*
//! parity) and [`QueryTarget`] (Z_QUERY_TARGET_* parity).
//!
//! Both enums are pure value types with no codec / runtime
//! dependencies — `no_std + no_alloc` clean. The wire-byte helpers
//! return raw u8 ready for the codec layer's `_z_uint8_encode` /
//! `_z_zsize_encode` consumption (no fallible path because the AUTO /
//! BEST_MATCHING sentinels are intentionally NOT representable here;
//! callers wanting those cases call the plain builder so the wire
//! shape stays minimal-baseline).

/// R121j-1a — explicit consolidation mode for the Query body. Mirrors
/// zenoh-pico's `z_consolidation_mode_t` enum
/// (vendor/zenoh-pico/include/zenoh-pico/api/constants.h:184-188) for
/// the three emitted modes; `AUTO` / `DEFAULT` (the encoder's "do not
/// transmit" sentinel `Z_CONSOLIDATION_MODE_DEFAULT =
/// Z_CONSOLIDATION_MODE_AUTO = -1`) is intentionally NOT representable
/// here — callers wanting that case call `build_request_query`
/// directly so the Q_C flag stays clear and the wire-byte count is
/// the minimal-shape baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsolidationMode {
    /// `Z_CONSOLIDATION_MODE_NONE = 0` — no consolidation; the
    /// peer forwards every reply in arrival order.
    None,
    /// `Z_CONSOLIDATION_MODE_MONOTONIC = 1` — the peer guarantees
    /// each reply for a given keyexpr is monotonic in some local
    /// ordering (typically timestamp).
    Monotonic,
    /// `Z_CONSOLIDATION_MODE_LATEST = 2` — the peer keeps only
    /// the latest reply per keyexpr; duplicates earlier in the
    /// stream are dropped.
    Latest,
}

impl ConsolidationMode {
    /// Wire byte value as written by zenoh-pico's `_z_uint8_encode`
    /// invocation in `_z_query_encode` (message.c:412). The mapping
    /// follows the enum literal values verbatim.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::None => 0u8,
            Self::Monotonic => 1u8,
            Self::Latest => 2u8,
        }
    }
}

/// R121j-1e — explicit query-target enum for cross-router Query
/// dispatch. Mirrors zenoh-pico's `z_query_target_t`
/// (vendor/zenoh-pico/include/zenoh-pico/api/constants.h:262-266) for
/// the two transmitted values. `BEST_MATCHING (0)` is intentionally
/// NOT representable here — zenoh-pico's encoder predicate
/// `ext_target = _ext_target != Z_QUERY_TARGET_BEST_MATCHING`
/// (vendor/zenoh-pico/src/protocol/definitions/network.c:27) clears
/// the ext when the value is BEST_MATCHING, so callers wanting that
/// case use plain `build_request_query` and the wire bytes carry
/// no target ext (peer infers BEST_MATCHING from absence).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryTarget {
    /// `Z_QUERY_TARGET_ALL = 1` — every matching queryable
    /// receives the query and may reply.
    All,
    /// `Z_QUERY_TARGET_ALL_COMPLETE = 2` — only the queryables
    /// declared `complete = true` receive the query; useful when
    /// the client wants authoritative answers from peers that
    /// claim full coverage of the keyexpr.
    AllComplete,
}

impl QueryTarget {
    /// Wire byte value as written by zenoh-pico's `_z_zsize_encode`
    /// invocation in the `_z_request_encode` target-ext branch
    /// (network.c:142 `_z_zsize_encode(wbf, msg->_ext_target)`).
    /// `BEST_MATCHING (0)` is not present in this enum, so the
    /// wire byte is always `1` or `2`.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::All => 1u8,
            Self::AllComplete => 2u8,
        }
    }
}

// R311fs — ConsolidationMode / QueryTarget wire-byte mapping tests,
// relocated from wz-runtime-tokio::session_glue to their SSOT home
// (these enums live here). The enums + `wire_byte` are unconditionally
// compiled (no codec gate on this module), and ConsolidationMode is
// consumed by codec-response too, so the tests are `#[cfg(test)]`-only:
// the old session_glue `codec-request` gate was incidental to that
// cluster's location, not to these types' compilation domain.
#[cfg(test)]
mod tests {
    use super::*;

    /// R121j-1a — wire byte mapping invariant for `ConsolidationMode`.
    /// The mapping mirrors zenoh-pico's `z_consolidation_mode_t` enum
    /// integer values (constants.h:185-187). A regression here would
    /// silently miswire the consolidation policy at the peer — the
    /// dedicated test guards the mapping independently of the encode
    /// path so a refactor that touches the `wire_byte` method without
    /// touching the encoder gets caught.
    #[test]
    fn consolidation_mode_wire_byte_matches_zenoh_pico_enum_values() {
        assert_eq!(ConsolidationMode::None.wire_byte(), 0u8);
        assert_eq!(ConsolidationMode::Monotonic.wire_byte(), 1u8);
        assert_eq!(ConsolidationMode::Latest.wire_byte(), 2u8);
    }

    /// R121j-1e — wire byte mapping invariant for `QueryTarget`. The
    /// mapping mirrors zenoh-pico's `z_query_target_t` enum integer
    /// values (constants.h:263-264). BEST_MATCHING (0) is absent by
    /// design (the encoder predicate clears the ext on default).
    #[test]
    fn query_target_wire_byte_matches_zenoh_pico_enum_values() {
        assert_eq!(QueryTarget::All.wire_byte(), 1u8);
        assert_eq!(QueryTarget::AllComplete.wire_byte(), 2u8);
    }
}
