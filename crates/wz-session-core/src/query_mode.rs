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
    /// No consolidation; every reply is delivered in arrival order.
    /// `Z_CONSOLIDATION_MODE_NONE` / `ConsolidationMode::None`; wire byte 1
    /// (see [`Self::wire_byte`] — the API enums agree, the two upstreams'
    /// wire numbering does not).
    None,
    /// Each reply for a given keyexpr is monotonic in some local ordering
    /// (typically timestamp). `Z_CONSOLIDATION_MODE_MONOTONIC` /
    /// `ConsolidationMode::Monotonic`; wire byte 2.
    Monotonic,
    /// Only the latest reply per keyexpr survives; earlier duplicates are
    /// dropped. `Z_CONSOLIDATION_MODE_LATEST` /
    /// `ConsolidationMode::Latest`; wire byte 3.
    Latest,
}

impl ConsolidationMode {
    /// Wire byte value, in ZENOH'S numbering:
    /// `Auto => 0, None => 1, Monotonic => 2, Latest => 3`
    /// (`commons/zenoh-codec/src/zenoh/query.rs:38-44`). `Auto` has no variant
    /// here (see [`Self::resolve_auto`]), so this method returns 1..=3 and slot
    /// 0 is reachable only by ELIDING the field, which is what an unset Q_C
    /// flag means to both upstreams' decoders.
    ///
    /// R311y837 — THIS MOVED, AND IT MOVED ONTO MEASURED GROUND. R311y836 named
    /// the divergence and left the mapping on pico's numbering; the byte was
    /// then witnessed on both planes by execution, one real foreign encoder per
    /// leg, in
    /// `wz-integration-tests/tests/query_consolidation_wire_byte_divergence.rs`:
    ///
    /// * a stock `zenohd` 1.5.0, asked through its REST plugin for a get that
    ///   names no mode (which that plugin resolves to `Latest`), wrote **3**;
    /// * a stock zenoh-pico `z_get`, whose AUTO resolves client-side to LATEST,
    ///   wrote **2**.
    ///
    /// So the two references genuinely disagree, and the disagreement is pico's
    /// one-off: pico encodes its API enum raw (`_z_uint8_encode(wbf,
    /// msg->_consolidation)`, `vendor/zenoh-pico/src/protocol/codec/message.c:412`,
    /// over `constants.h:184-188` NONE=0/MONOTONIC=1/LATEST=2) and its `AUTO =
    /// -1` sentinel is never written, so every mode lands one slot low. wz
    /// follows ZENOH because zenoh-protocol is the wire's normative definition
    /// and a zenohd is the router a deployment actually has — a wz `Latest` on
    /// pico's numbering was read as `Monotonic` by every zenohd it ever met.
    ///
    /// WHAT THIS COSTS, STATED RATHER THAN HIDDEN: wz is now deliberately NOT
    /// byte-equal to zenoh-pico on this one field. That is a divergence from an
    /// implementation wz also replaces, taken knowingly, and it is the better
    /// half of the trade only because the field is requester-side and no
    /// decoder on either plane acts on it (which is also why pico's bug has
    /// survived). A wz that matched pico here would be wrong against the
    /// reference router; a wz that matches zenoh is wrong only against pico's
    /// own defect.
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::None => 1u8,
            Self::Monotonic => 2u8,
            Self::Latest => 3u8,
        }
    }

    /// The inverse of [`wire_byte`](Self::wire_byte), mirroring zenoh's decoder
    /// (`commons/zenoh-codec/src/zenoh/query.rs:55-64`): `1 -> None`,
    /// `2 -> Monotonic`, `3 -> Latest`, and ANY other value — including `0`,
    /// which is zenoh's `Auto` — yields `None`, the "the peer named no mode"
    /// reading a decoder also infers from an absent field.
    ///
    /// Zenoh's decoder falls back to `Auto` on an unknown value rather than
    /// erroring, and this mirrors that rather than being stricter: a reader
    /// that rejected a byte the reference implementation accepts would drop
    /// sessions the reference keeps.
    pub const fn from_wire_byte(byte: u64) -> Option<Self> {
        match byte {
            1 => Some(Self::None),
            2 => Some(Self::Monotonic),
            3 => Some(Self::Latest),
            _ => Option::None,
        }
    }

    /// Resolve the mode a get will APPLY LOCALLY from the mode its caller named
    /// (or did not) plus the selector parameters, mirroring zenoh's `get()`:
    ///
    /// ```text
    /// ConsolidationMode::Auto if parameters.time_range().is_some() => ConsolidationMode::None,
    /// ConsolidationMode::Auto => ConsolidationMode::Latest,
    /// mode => mode,
    /// ```
    ///
    /// (`zenoh/src/api/session.rs:2247-2252`, tag 1.5.0 / 49c8a53.)
    ///
    /// BOTH UPSTREAMS CARRY THE SAME RULE, which is what makes it the protocol's
    /// and not one implementation's habit: zenoh-pico resolves AUTO on the client
    /// before encoding — `_time=` in the selector yields NONE, otherwise LATEST
    /// (`vendor/zenoh-pico/src/net/primitives.c:567-573`). wz-capi-pico has
    /// mirrored pico's copy since R311y321 (`wz-capi-pico/src/get.rs:945-953`) and
    /// KEEPS it rather than delegating here: it must resolve BEFORE the wire,
    /// because pico's get always emits Q_C with the resolved byte and never
    /// elides it. Of the three request paths wz owns, the native Rust one was the
    /// only one without this rule until R311y836.
    ///
    /// `None` IS wz's spelling of zenoh's `Auto`. wz deliberately has no `Auto`
    /// VARIANT — this enum only names the three modes that are transmitted, and
    /// "the caller named nothing" is carried by the `Option` exactly as both
    /// upstreams carry it by an out-of-band sentinel that is never written
    /// (zenoh's header flag is set only when the mode `!= DEFAULT`,
    /// `commons/zenoh-codec/src/zenoh/query.rs:84`; pico's `has_consolidation`
    /// predicate is `!= Z_CONSOLIDATION_MODE_DEFAULT`,
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:402`). So the argument
    /// here is `Option<Self>`, not a fourth variant.
    ///
    /// WHY THIS IS A SEPARATE READING FROM THE WIRE'S. zenoh resolves ONCE and
    /// feeds the resolved value to both its local cache (`session.rs:2294`) and
    /// the outbound Query body (`session.rs:2316`), so a zenoh default get puts
    /// LATEST on the wire. wz keeps eliding the ext when the caller named no
    /// mode, because the alternative is transmitting a byte that the divergence
    /// documented on [`Self::wire_byte`] makes WRONG for a zenoh peer — an
    /// elided ext reads as `Auto` on both upstreams, which is what the caller
    /// actually said. Converging the two readings is this atom's residual and
    /// it is blocked on the byte, not on this function.
    pub fn resolve_auto(requested: Option<Self>, parameters: &str) -> Self {
        match requested {
            Some(mode) => mode,
            None if crate::selector_params::has_param(
                parameters,
                crate::selector_params::TIME_RANGE_PARAM,
            ) =>
            {
                Self::None
            }
            None => Self::Latest,
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

/// The `ext_target` extension id — zenoh-pico's Request target ext
/// (`_z_request_encode`, `network.c`), iext id `0x04`. The single definition
/// shared by the `request_target` writer (`request_build.rs`) and the
/// [`read_request_target`](crate::request_routing_context::read_request_target)
/// reader, so the magic id lives in ONE place.
pub const TARGET_EXT_ID: u8 = 0x04;

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

    /// The inverse of [`wire_byte`](Self::wire_byte): map a decoded `ext_target`
    /// wire byte back to the enum. `1 -> All`, `2 -> AllComplete`; ANY other
    /// value — including `0 = BEST_MATCHING`, which is never transmitted (the
    /// ext is omitted) — yields `None`, the BestMatching wire default a reader
    /// infers from absence. Mirrors zenoh-pico's decode predicate (an absent /
    /// `0` target ext means BEST_MATCHING).
    pub const fn from_wire_byte(byte: u64) -> Option<Self> {
        match byte {
            1 => Some(Self::All),
            2 => Some(Self::AllComplete),
            _ => None,
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

    /// R311y837 — wire byte mapping invariant for `ConsolidationMode`, on
    /// ZENOH's numbering. The three values are anchored to what a stock zenohd
    /// was MEASURED writing, not to a source file: the `Latest => 3` line is
    /// the byte
    /// `query_consolidation_wire_byte_divergence::a_real_zenohd_writes_latest_as_the_consolidation_byte_zenoh_numbers_it`
    /// relayed off a real router's wire, and the same file's pico leg is why
    /// the other numbering is NOT what this asserts.
    ///
    /// Kept as its own test rather than folded into an encoder test (the R121j-1a
    /// rationale, unchanged): a refactor that touches this method without
    /// touching the encode path would otherwise silently miswire the policy at
    /// the peer.
    #[test]
    fn consolidation_mode_wire_byte_matches_zenoh_enum_values() {
        assert_eq!(ConsolidationMode::None.wire_byte(), 1u8);
        assert_eq!(ConsolidationMode::Monotonic.wire_byte(), 2u8);
        assert_eq!(ConsolidationMode::Latest.wire_byte(), 3u8);
    }

    /// R311y837 — `from_wire_byte` is the inverse of `wire_byte` over the three
    /// transmitted modes, and maps everything else — `0` (zenoh's `Auto`) and
    /// any unknown value — to `None`, which is what an ABSENT field also means.
    ///
    /// The unknown arm is pinned deliberately: zenoh's decoder falls back to
    /// `Auto` instead of erroring, so a stricter reader here would reject a
    /// message the reference implementation accepts.
    #[test]
    fn consolidation_mode_from_wire_byte_round_trips_and_reads_auto_as_unnamed() {
        for mode in [
            ConsolidationMode::None,
            ConsolidationMode::Monotonic,
            ConsolidationMode::Latest,
        ] {
            assert_eq!(
                ConsolidationMode::from_wire_byte(mode.wire_byte() as u64),
                Some(mode)
            );
        }
        assert_eq!(ConsolidationMode::from_wire_byte(0), Option::None);
        assert_eq!(ConsolidationMode::from_wire_byte(4), Option::None);
        assert_eq!(ConsolidationMode::from_wire_byte(255), Option::None);
    }

    /// R311y836 — an explicitly named mode passes through untouched. This is
    /// zenoh's `mode => mode` arm (`session.rs:2251`) and it is what keeps the
    /// resolution from being a policy that overrides callers.
    #[test]
    fn an_explicit_mode_resolves_to_itself() {
        for mode in [
            ConsolidationMode::None,
            ConsolidationMode::Monotonic,
            ConsolidationMode::Latest,
        ] {
            assert_eq!(ConsolidationMode::resolve_auto(Some(mode), ""), mode);
            // ... and the `_time` arm must not reach an explicit mode either:
            // upstream's guard is `ConsolidationMode::Auto if ..`, so the range
            // only ever redirects the UNNAMED case.
            assert_eq!(
                ConsolidationMode::resolve_auto(Some(mode), "_time=[now(-3s)..]"),
                mode,
                "a caller who named a mode keeps it even under a `_time` range"
            );
        }
    }

    /// The default path, and the whole point: no mode named resolves to LATEST
    /// (`zenoh/src/api/session.rs:2250`).
    #[test]
    fn an_unnamed_mode_resolves_to_latest() {
        assert_eq!(
            ConsolidationMode::resolve_auto(None, ""),
            ConsolidationMode::Latest
        );
        // Other parameters must not disturb it — only `_time` is the carve-out.
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "_max=5;_anyke"),
            ConsolidationMode::Latest
        );
    }

    /// The carve-out (`session.rs:2249`), including the two shapes that would
    /// slip past a naive `contains("_time")`.
    #[test]
    fn an_unnamed_mode_under_a_time_range_resolves_to_none() {
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "_time=[now(-3s)..]"),
            ConsolidationMode::None
        );
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "_max=5;_time=[now(-3s)..];_anyke"),
            ConsolidationMode::None
        );
        // Upstream tests `is_some()`, not "parses" — a malformed range still
        // holds the resolution at None rather than truncating the window.
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "_time=nonsense"),
            ConsolidationMode::None
        );
        // A key that merely CONTAINS the token is not the token.
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "_timeout=5"),
            ConsolidationMode::Latest
        );
        assert_eq!(
            ConsolidationMode::resolve_auto(None, "no_time=1"),
            ConsolidationMode::Latest
        );
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

    /// `from_wire_byte` is the inverse of `wire_byte` and maps the absent /
    /// `0 = BEST_MATCHING` (and any unknown) value to `None` — the wire default
    /// a forwarder's target dispatch (atom 4b) reads.
    #[test]
    fn query_target_from_wire_byte_round_trips_and_defaults_to_best_matching() {
        for t in [QueryTarget::All, QueryTarget::AllComplete] {
            assert_eq!(QueryTarget::from_wire_byte(t.wire_byte() as u64), Some(t));
        }
        assert_eq!(
            QueryTarget::from_wire_byte(0),
            None,
            "0 = BEST_MATCHING is never transmitted -> None (absent default)",
        );
        assert_eq!(
            QueryTarget::from_wire_byte(99),
            None,
            "an unknown target byte falls back to the BestMatching default",
        );
    }
}
