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

/// R2437 (§5.4 `session-unicast-open`) — refuse a decoded chain that carries an
/// extension `known` does not list with the M (mandatory) bit SET.
///
/// ## Why this is a separate pass rather than part of the decode
///
/// [`decode_ext_chain`] is CARRIER-BLIND on purpose: the establishment chain,
/// the zenoh-body chain and the scouting chain reuse the same numeric ids for
/// different extensions (`ext_header` says so in as many words), so "is this id
/// known" is a question only the caller — which knows the carrier — can answer.
/// Folding a known-set into the decoder would either hard-code one carrier's
/// table or make every caller pass one, and only the establishment caller has a
/// rule to enforce today.
///
/// ## The rule, and where it comes from
///
/// Upstream's unknown-extension reader logs and CONTINUES when M is clear, and
/// returns `DidntRead` when M is set
/// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory()`).
/// That is the whole semantics of the bit: the SENDER declares whether a
/// receiver that does not understand the extension may proceed anyway. Measured
/// at the 1.10.0 pin, and measured in wz too — before this round the M bit had
/// exactly three readers in the tree, all of them assertions inside one
/// integration test, so no production path consulted it and wz would complete a
/// handshake on terms it had not understood.
///
/// Non-mandatory unknowns are ACCEPTED and left in the chain for the caller to
/// ignore, which is what keeps a newer peer interoperable.
///
/// ⚠ R2539 — the example this sentence used to carry, `RegionName` (id `0x8`)
/// as an extension "wz implements nothing for", is no longer one:
/// [`crate::extregion`] implements it. The RULE is unchanged and its subject is
/// any id absent from [`crate::ext_header::ESTABLISHMENT_EXT_IDS`]; what moved
/// is only that this particular id stopped being an instance of it.
#[allow(dead_code)]
pub(crate) fn reject_unknown_mandatory_ext(
    entries: &[ExtEntryOwned],
    known: &[u8],
) -> Result<(), crate::parse_error::InboundParseError> {
    for entry in entries {
        let id = entry.ext_id();
        if entry.m() && !known.contains(&id) {
            return Err(crate::parse_error::InboundParseError::UnknownMandatoryExt { ext_id: id });
        }
    }
    Ok(())
}

// R2437 (§5.4 `session-unicast-open`) — the unknown-MANDATORY-extension rule,
// which is upstream's `if u.is_mandatory()` arm and had no wz production reader
// until this round. Both directions are pinned: the bit must REFUSE what it
// names and must not refuse anything else, since an over-tight version of this
// rule breaks the handshake with every peer newer than wz.
#[cfg(test)]
mod unknown_mandatory_ext_tests {
    use super::*;
    use crate::ext_header::{establishment_ext_id, ESTABLISHMENT_EXT_IDS};
    use crate::parse_error::InboundParseError;

    /// One chain entry with the given id and M bit. Built through the generated
    /// setters rather than a byte literal, so the test cannot drift from the
    /// header layout the decoder actually reads.
    fn entry(ext_id: u8, mandatory: bool) -> ExtEntryOwned {
        let mut e = wz_codecs::ext_entry::ExtEntry::new();
        e.set_ext_id(ext_id);
        e.set_m(mandatory);
        e.set_z(false);
        e.try_into_owned().expect("owned mirror")
    }

    /// THE DEFECT: an id wz does not recognise, sent as mandatory, is REFUSED
    /// and the refusal names it. `0x0d` is outside the establishment table in
    /// both directions -- upstream does not define it either, so no future
    /// upstream release turns this case into a recognised extension by accident.
    #[test]
    fn an_unknown_mandatory_ext_is_refused_and_names_itself() {
        let err = reject_unknown_mandatory_ext(&[entry(0x0d, true)], &ESTABLISHMENT_EXT_IDS)
            .expect_err("unknown + mandatory must refuse");
        assert_eq!(err, InboundParseError::UnknownMandatoryExt { ext_id: 0x0d });
    }

    /// THE INTEROP HALF, and the reason the rule is not simply "refuse unknown":
    /// an unknown NON-mandatory extension is accepted, because the sender has
    /// declared it skippable. Refusing here would break every peer that speaks a
    /// newer wire than wz -- which upstream's own reader avoids by logging and
    /// continuing on exactly this branch.
    #[test]
    fn an_unknown_non_mandatory_ext_is_accepted() {
        assert_eq!(
            reject_unknown_mandatory_ext(&[entry(0x0d, false)], &ESTABLISHMENT_EXT_IDS),
            Ok(())
        );
    }

    /// The concrete peer this protects: a stock node announces `RegionName` on
    /// id `0x8`. It is in the recognised set and non-mandatory, so it must pass
    /// BOTH ways -- this is the case that would have made the new rule an
    /// interop regression if the id had been left out of the table.
    ///
    /// ⚠ R2539 CORRECTION — this assertion's message used to read "wz IGNORES
    /// region_name -- nothing in this tree honours the key or the extension
    /// carrying it". The second half is now FALSE: [`crate::extregion`] emits
    /// the extension and reads the peer's, and a malformed value is REFUSED.
    /// What this test still says is narrower and unchanged: the
    /// unknown-mandatory rule does not fire on it, which is a statement about
    /// the id being RECOGNISED and not about what wz does with the value.
    #[test]
    fn the_pins_region_name_ext_does_not_break_the_handshake() {
        for mandatory in [false, true] {
            assert_eq!(
                reject_unknown_mandatory_ext(
                    &[entry(establishment_ext_id::REGION_NAME, mandatory)],
                    &ESTABLISHMENT_EXT_IDS
                ),
                Ok(()),
                "region_name is RECOGNISED, so the unknown-mandatory rule never \
                 fires on a stock peer's announcement -- whether or not wz acts \
                 on the value, which since R2539 it does"
            );
        }
    }

    /// Every extension wz itself speaks passes, mandatory or not. Derived by
    /// iterating the table rather than by listing ids again, so an id added to
    /// `ESTABLISHMENT_EXT_IDS` is covered here without editing this test -- and
    /// an id REMOVED from it fails here rather than silently starting to refuse
    /// a live peer.
    #[test]
    fn every_recognised_establishment_ext_passes() {
        for id in ESTABLISHMENT_EXT_IDS {
            for mandatory in [false, true] {
                assert_eq!(
                    reject_unknown_mandatory_ext(&[entry(id, mandatory)], &ESTABLISHMENT_EXT_IDS),
                    Ok(()),
                    "recognised id {id:#04x} must never be refused"
                );
            }
        }
    }

    /// The rule scans the WHOLE chain, not just its head. A mandatory unknown
    /// hidden behind recognised entries is the shape a peer would actually send,
    /// since the chain is built in id order and `0x0d` sorts last.
    #[test]
    fn a_mandatory_unknown_is_found_behind_recognised_entries() {
        let chain = [
            entry(establishment_ext_id::QOS, false),
            entry(establishment_ext_id::PATCH, false),
            entry(0x0d, true),
        ];
        let err = reject_unknown_mandatory_ext(&chain, &ESTABLISHMENT_EXT_IDS)
            .expect_err("a later entry must still be reached");
        assert_eq!(err, InboundParseError::UnknownMandatoryExt { ext_id: 0x0d });
    }

    /// An empty chain is not an error -- an Init with no extensions at all is a
    /// conforming handshake and the commonest one.
    #[test]
    fn an_empty_chain_passes() {
        assert_eq!(
            reject_unknown_mandatory_ext(&[], &ESTABLISHMENT_EXT_IDS),
            Ok(())
        );
    }
}
