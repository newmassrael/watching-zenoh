// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the transport-message extension CHAIN codec — the Z-flag-gated list
//! of `ExtEntry` records that trails an Init / Open / Close / KeepAlive / Frame
//! body, and (nested) the per-method sub-ext chain INSIDE the Z_EXT_AUTH ext.
//!
//! One encode / decode pair so the outbound establishment path
//! (`handshake_encode`), the inbound parser (`inbound`), and the extauth
//! dispatch (`auth_dispatch`, the auth ext's inner method chain) share one
//! definition of the Z-bit continuation loop rather than each re-deriving it.
//! Each function is gated on the union of its consumers' features so a subset
//! that needs only one half does not drag the other in (and never trips
//! dead-code under `-D warnings`).

use alloc::vec::Vec;
use wz_codecs::ext_entry::ExtEntryOwned;

/// The `max-depth` every entry-flag ext chain in the network and zenoh-payload
/// layers is generated with (`sources/codecs/*.scxml`).
///
/// R311y582 — this constant exists because the hand-written walker in
/// [`crate::dissect`] has to be told the bound the generated decode gets from
/// its container type, and it was told fourteen times, as the literal `4`. One
/// fact reachable by two paths always drifts (this workspace has paid for that
/// four times in one session before), and here the drift would be silent in the
/// worst way: a walker whose bound is LOWER than the codec's rejects wire the
/// codec accepts, and one whose bound is HIGHER walks into bytes the codec
/// never read.
///
/// It is not derived from the generated type because a const generic parameter
/// has no name to import. What closes the loop instead is
/// `the_generated_chain_capacities_match_the_constants` in [`crate::dissect`],
/// which asks each generated container for its own `capacity()` — so a
/// regenerated codec with a different depth reds a test rather than silently
/// disagreeing with the walker.
// Callers, exactly: the `dissect` walkers, and this crate's own
// chain-saturation tests — which live in `network_message` behind
// `all(test, codec-frame, codec-push)`.
//
// R311y588 — the gate was `any(dissect, test)`, and a full local sweep found
// the hole in SEVEN lanes: a `--lib` TEST build without `dissect` makes `test`
// true, so the constant compiles, while its only test-side consumer needs
// `codec-push` and is absent. Dead code under `-D warnings`. Third instance of
// the R311y579 (G7) class in one session, and the first one no per-crate check
// could have seen — every arm run by hand had either `dissect` or `codec-push`
// in it.
#[cfg(any(
    feature = "dissect",
    all(test, feature = "codec-frame", feature = "codec-push")
))]
pub const NETWORK_EXT_CHAIN_DEPTH: usize = 8;

/// `Query`'s chain is generated with the fill-to-end strategy and its own,
/// larger depth. Separate constant rather than a second use of
/// [`NETWORK_EXT_CHAIN_DEPTH`]: the two are different numbers in the SCXML for
/// different reasons, and collapsing them would make a future divergence
/// invisible.
#[cfg(feature = "dissect")]
pub const QUERY_EXT_CHAIN_DEPTH: usize = 8;

/// Encode an ext chain to bytes: each entry's `ExtEntry` encoding with the
/// chain-continuation Z bit (`0x80`) set on every entry but the last (Z clear =
/// terminator). An empty slice encodes to no bytes (the "no extensions" case).
/// The non-Z header bits (`ext_id`, `M`, `enc`) stay author-set; the helper
/// only patches the Z bit per chain position (`ExtEntry::encode` pushes the
/// header byte first).
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "session-extauth"
))]
pub(crate) fn encode_ext_chain(entries: &[ExtEntryOwned]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(entries.len() * 4);
    let last = entries.len() - 1;
    for (i, entry) in entries.iter().enumerate() {
        let mut bytes = entry.as_borrowed().encode_to_vec();
        if i == last {
            bytes[0] &= !0x80;
        } else {
            bytes[0] |= 0x80;
        }
        buf.extend_from_slice(&bytes);
    }
    buf
}

/// Decode the Z-flag-gated ext chain into the lifetime-free owned mirror,
/// bounded by [`MAX_EXT_CHAIN_DEPTH`](crate::parse_error::MAX_EXT_CHAIN_DEPTH)
/// so a malformed peer cannot pin the decoder into an unbounded loop.
///
/// UNCONDITIONAL within this `alloc`-gated module since transport OAM joined
/// `parse_inbound`: that arm carries no `codec-*` gate, so every build that
/// compiles this module calls this function. The `any(codec-*)` union it used
/// to carry had to be grown twice by feature-SUBSET builds (R311y605,
/// R311y607) and each growth was a defect until it was found; there is no
/// longer a list to be short of.
pub(crate) fn decode_ext_chain(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Result<Vec<ExtEntryOwned>, crate::parse_error::InboundParseError> {
    use crate::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};
    use wz_codecs::ext_entry::ExtEntry;

    let mut entries = Vec::new();
    for _ in 0..MAX_EXT_CHAIN_DEPTH {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        // Deep-copy the borrowed decode view into the lifetime-free owned mirror
        // so the parsed chain can outlive the input buffer.
        entries.push(entry.try_into_owned().map_err(InboundParseError::Codec)?);
        if !z {
            return Ok(entries);
        }
    }
    Err(InboundParseError::ExtChainOverflow)
}
