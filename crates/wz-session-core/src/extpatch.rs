// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the `0x7` PATCH establishment extension — the protocol patch
//! LEVEL announced on Init, and the `min()` negotiation over it.
//!
//! wz has emitted this extension since R121f1
//! ([`crate::session_actions::default_init_patch_ext_entry`]) because
//! zenoh-pico's accept side wedges its InitAck without it. What it never
//! did was READ the peer's half. The value matters: zenoh types it as
//!
//! ```text
//! pub struct PatchType<const ID: u8>(u8);
//! impl<const ID: u8> PatchType<ID> {
//!     pub const NONE: Self = Self(0);
//!     pub const CURRENT: Self = Self(1);
//!     pub fn has_fragmentation_markers(&self) -> bool { self.0 >= 1 }
//! }
//! ```
//!
//! (`commons/zenoh-protocol/src/transport/mod.rs:319-336`), and
//! `has_fragmentation_markers` is the sole guard on the Fragment
//! chain-boundary rules in the RX path
//! (`io/zenoh-transport/src/unicast/universal/rx.rs:155-170`, and the
//! multicast twin at `multicast/rx.rs:216-228`). Reading the peer's level
//! is therefore a precondition for honouring [`crate::extfragment`]'s
//! `First` / `Drop` markers at all: enforce them against a patch-0 peer
//! and every chain it sends is refused.
//!
//! ## Negotiation
//!
//! `min(local, peer)`, taken on BOTH sides, exactly as zenoh-pico writes
//! it (`src/transport/unicast/transport.c:237-241`):
//!
//! ```c
//! if (iam._body._init._patch > tmsg._body._init._patch) {
//!     iam._body._init._patch = tmsg._body._init._patch;
//! }
//! ```
//!
//! wz's local level is [`CURRENT_PATCH`], so the negotiated value is the
//! peer's, capped at 1. An Init carrying NO patch ext means
//! [`NO_PATCH`] — a pre-patch peer, markers off.
//!
//! ## Why its own module rather than a field on `PeerInitCaps`
//!
//! [`crate::peer_init_caps::PeerInitCaps`] decodes the INIT BODY (the
//! packed `sn_res` byte and `batch_size`). The patch level is not in the
//! body — it rides the ext chain, which the body decoder never sees. The
//! split follows the existing establishment-ext modules
//! ([`crate::extlowlatency`] `0x5`, [`crate::extcompression`] `0x6`):
//! one module per id, each owning its encode + its projector, with the
//! per-session state and the merge living in
//! [`crate::session_actions`] / [`crate::drive`].

use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};

/// `_Z_MSG_EXT_ID_INIT_PATCH` — the patch extension's id in the
/// establishment (Init / Open) ext space (`0x1` QoS, `0x2` Shm, `0x3`
/// Auth, `0x4` MultiLink, `0x5` LowLatency, `0x6` Compression, `0x7`
/// Patch).
pub const PATCH_EXT_ID: u8 = crate::ext_header::establishment_ext_id::PATCH;

/// zenoh `PatchType::NONE` — a peer that announced no patch extension.
/// Fragment chain-boundary markers are OFF against such a peer.
pub const NO_PATCH: u8 = 0;

/// zenoh `PatchType::CURRENT` / zenoh-pico `_Z_CURRENT_PATCH` — the level
/// wz announces, and the ceiling the `min()` negotiation caps at.
pub const CURRENT_PATCH: u8 = 1;

/// Project the peer's announced patch level out of an INIT ext chain.
///
/// The entry is ZINT-encoded (`header = 0x07 | ENC_ZINT`), so the match is
/// on the extension IDENTITY — the id field AND the encoding bits — not on
/// the 4-bit id alone. A unit- or zbuf-bodied entry parked on `0x7` is a
/// different extension and reads as [`NO_PATCH`], the same discipline
/// [`crate::unit_ext::chain_has_ext_eid`] applies in the other direction
/// (R311y505).
///
/// A value wider than a `u8` is saturated rather than truncated: zenoh's
/// `PatchType` is a `u8` and a peer announcing `256` means "newer than
/// anything I know", which must not wrap to `NO_PATCH`.
pub fn peer_patch(extensions: &[ExtEntryOwned]) -> u8 {
    let want = crate::ext_header::ext_eid(PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64);
    for ext in extensions {
        if crate::ext_header::ext_eid(ext.header) != want {
            continue;
        }
        if let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &ext.body {
            return u8::try_from(z.value).unwrap_or(u8::MAX);
        }
    }
    NO_PATCH
}

/// R311y605 — the ENTRY wz puts on an Init, now built here.
///
/// The emit is not new; it has existed since R121f1, seeded into the InitSyn
/// and InitAck chain slots by
/// [`crate::session_actions::default_init_patch_ext_entry`]. What is new is
/// that it is built from the NAMED constants this module already uses to READ
/// the peer's half. It was a literal `0x07 | 0x20` in `session_actions` while
/// [`peer_patch`] matched on `PATCH_EXT_ID | EXT_ENC_Z64` here — two spellings
/// of one wire fact, on the two sides of the same extension, with nothing
/// putting either through the other. A move on either side would have shipped
/// an extension wz emits and wz ignores, and the only witness would have been
/// a foreign peer.
///
/// The literal also cost a reader: `grep extpatch` over this crate finds a
/// complete READER and no emit, which is how "the Patch ext is not attached"
/// survived in the §5.27 inventory reason, and how THIS round first
/// re-derived the same wrong answer before a test corrected it.
///
/// Wire form per both references, read directly: id `0x7`, Z64 / ZINT
/// encoding, NOT mandatory — zenoh `init::ext::Patch = zextz64!(0x7, false)`
/// (`commons/zenoh-protocol/src/transport/init.rs:174`), zenoh-pico
/// `_Z_MSG_EXT_ID_INIT_PATCH (0x07 | _Z_MSG_EXT_ENC_ZINT)`
/// (`include/zenoh-pico/protocol/ext.h:48`). Non-mandatory is the load-bearing
/// bit: with `M` set a pre-patch peer must REJECT the handshake rather than
/// skip the entry.
pub fn encode_patch_ext_at(level: u8) -> ExtEntryOwned {
    ExtEntryOwned {
        header: PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64,
        body: ExtEntryOwnedVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint {
            value: u64::from(level),
        }),
    }
}

/// The entry wz puts on an Init: its own [`CURRENT_PATCH`].
///
/// Unconditional, which is what both references do. zenoh's opener returns
/// `Ok(PatchType::CURRENT)` from `send_init_syn` without consulting any state
/// (`io/zenoh-transport/src/unicast/establishment/ext/patch.rs:63-68`);
/// zenoh-pico sets `_patch = _Z_CURRENT_PATCH` in both
/// `_z_t_msg_make_init_syn` and `_z_t_msg_make_init_ack`
/// (`src/protocol/definitions/transport.c:147,178`). An acceptor's answer is
/// the `min`, so announcing the ceiling is how a patch-0 peer still settles
/// on 0.
///
/// ⚠ A DIVERGENCE worth naming: zenoh's ACCEPTOR answers `min(CURRENT, peer)`
/// (`patch.rs::send_init_ack`) while pico answers `_Z_CURRENT_PATCH`
/// unconditionally, and wz seeds its InitAck slot with CURRENT — so wz matches
/// PICO here, not zenoh. Benign in both directions (the ext is advisory and
/// wz's own negotiated level is still the `min`), and recorded rather than
/// silently picked.
pub fn encode_patch_ext() -> ExtEntryOwned {
    encode_patch_ext_at(CURRENT_PATCH)
}

/// The `min(local, peer)` negotiation both sides run. wz's local level is
/// [`CURRENT_PATCH`]; the helper takes it as a parameter so a test can
/// pin the asymmetric cases without reaching for a session.
pub const fn negotiate_patch(local: u8, peer: u8) -> u8 {
    if local < peer {
        local
    } else {
        peer
    }
}

/// zenoh `PatchType::has_fragmentation_markers` — the sole gate on the
/// Fragment `First` / `Drop` chain-boundary rules. `level >= 1`.
pub const fn has_fragmentation_markers(level: u8) -> bool {
    level >= CURRENT_PATCH
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y605 — the fixture is now the PRODUCTION builder rather than a
    /// second copy of the layout. It was a copy while the emit lived in
    /// `session_actions` under a literal, so three spellings of one wire fact
    /// existed and no test crossed any two of them.
    fn patch_ext(value: u64) -> ExtEntryOwned {
        encode_patch_ext_at(u8::try_from(value).unwrap_or(u8::MAX))
    }

    fn unit_ext_at(id: u8) -> ExtEntryOwned {
        ExtEntryOwned {
            header: id,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit::default()),
        }
    }

    /// The entry wz itself emits must read back as `CURRENT_PATCH` through
    /// this projector — the encode side and the decode side are one wire
    /// contract, so the round trip is over the PRODUCTION builder rather
    /// than a hand-built twin. (`session_actions` is
    /// `session-unicast`-gated; the ungated half of the assertion runs in
    /// every lane below.)
    #[cfg(all(feature = "alloc", feature = "session-unicast"))]
    #[test]
    fn wz_own_patch_entry_projects_to_current() {
        let own = crate::session_actions::default_init_patch_ext_entry();
        assert_eq!(own.header, PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64);
        assert_eq!(peer_patch(&[own]), CURRENT_PATCH);
    }

    /// The same wire shape, hand-built, so the projector is pinned in
    /// every feature lane and not only where `session_actions` compiles.
    #[test]
    fn the_wire_shape_wz_emits_projects_to_current() {
        assert_eq!(
            peer_patch(&[patch_ext(u64::from(CURRENT_PATCH))]),
            CURRENT_PATCH
        );
    }

    /// An Init with no patch ext is a pre-patch peer: `NO_PATCH`, and the
    /// fragmentation markers are off.
    #[test]
    fn absent_patch_ext_is_no_patch() {
        assert_eq!(peer_patch(&[]), NO_PATCH);
        assert!(!has_fragmentation_markers(peer_patch(&[])));
        // A FOREIGN establishment ext (0x5 LowLatency, unit) is not read
        // as the patch level.
        assert_eq!(peer_patch(&[unit_ext_at(0x05)]), NO_PATCH);
    }

    /// The encoding bits are part of the identity: a UNIT-bodied entry on
    /// id `0x7` is not the patch extension.
    #[test]
    fn a_unit_entry_on_the_patch_id_is_not_the_patch_ext() {
        assert_eq!(peer_patch(&[unit_ext_at(PATCH_EXT_ID)]), NO_PATCH);
    }

    /// `min()` on both sides, and the saturation rule for a peer newer
    /// than anything wz knows.
    #[test]
    fn negotiation_is_min_and_saturates() {
        assert_eq!(negotiate_patch(CURRENT_PATCH, NO_PATCH), NO_PATCH);
        assert_eq!(negotiate_patch(CURRENT_PATCH, CURRENT_PATCH), CURRENT_PATCH);
        // A peer announcing a FUTURE level is capped to ours, not adopted.
        assert_eq!(negotiate_patch(CURRENT_PATCH, 7), CURRENT_PATCH);
        // ...and a wire value beyond u8 saturates rather than wrapping to 0.
        assert_eq!(peer_patch(&[patch_ext(300)]), u8::MAX);
        assert_eq!(
            negotiate_patch(CURRENT_PATCH, peer_patch(&[patch_ext(300)])),
            CURRENT_PATCH
        );
    }

    /// The gate itself, at the boundary zenoh draws it.
    #[test]
    fn fragmentation_markers_gate_at_one() {
        assert!(!has_fragmentation_markers(0));
        assert!(has_fragmentation_markers(1));
        assert!(has_fragmentation_markers(u8::MAX));
    }

    /// R311y605 — wz's own EMIT read back by wz's own READER.
    ///
    /// The two halves of this extension were written against each other in
    /// PROSE and never in code: the emit spelled its header `0x07 | 0x20` as a
    /// literal in `session_actions`, and `peer_patch` matches on
    /// `PATCH_EXT_ID | EXT_ENC_Z64` through the named constants. Nothing put
    /// one through the other, so a move on either side would have shipped an
    /// extension wz emits and wz ignores, with a foreign peer as the only
    /// witness.
    ///
    /// It is also the round trip that answers the question a grep cannot. This
    /// round FIRST concluded, from `grep extpatch` over the crate, that no
    /// emit existed at all — because the emit did not name this module — and
    /// was wrong. A test over the actual entry cannot be answered wrongly.
    #[cfg(all(feature = "alloc", feature = "session-unicast"))]
    #[test]
    fn the_entry_wz_emits_is_the_entry_wz_reads() {
        let emitted = crate::session_actions::default_init_patch_ext_entry();
        assert_eq!(
            peer_patch(&[emitted]),
            CURRENT_PATCH,
            "wz's own Init ext entry must project back to its own level"
        );

        // The DISCRIMINATOR: `peer_patch` matches on extension IDENTITY, so an
        // entry on the same id with a different ENCODING reads as NO_PATCH.
        // That is what makes the assertion above a check on the whole header
        // rather than on the id nibble.
        let wrong_encoding = ExtEntryOwned {
            header: PATCH_EXT_ID,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit::default()),
        };
        assert_eq!(peer_patch(&[wrong_encoding]), NO_PATCH);
    }

    /// R311y605 — the emitted header is both references' wire form, bit for
    /// bit, and is NOT mandatory.
    ///
    /// The M bit is the load-bearing one, and it is the bit whose absence a
    /// reader relies on: with `M` set a pre-patch peer must REJECT the whole
    /// handshake rather than skip the entry, so a stray `0x10` here would break
    /// exactly the peers this extension exists to stay compatible with. Both
    /// references leave it clear — zenoh `zextz64!(0x7, false)` and pico's
    /// `_Z_MSG_EXT_ID_INIT_PATCH`, whose definition omits `_Z_MSG_EXT_FLAG_M`.
    #[test]
    fn the_emitted_header_is_id_seven_zint_and_not_mandatory() {
        let e = encode_patch_ext();
        assert_eq!(e.header & 0x0F, 0x07, "ext id 0x7");
        assert_eq!(e.header & 0x10, 0x00, "M (mandatory) must be CLEAR");
        assert_eq!(e.header & 0x60, 0x20, "encoding bits = ZINT / Z64");
        assert_eq!(
            e.header & 0x80,
            0x00,
            "the chain-continuation Z bit belongs to encode_ext_chain"
        );
        match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => assert_eq!(z.value, 1),
            other => panic!("the patch ext body must be a zint: {other:?}"),
        }
    }
}
