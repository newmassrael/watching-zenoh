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
pub const PATCH_EXT_ID: u8 = 0x07;

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
    use wz_codecs::ext_zint::ExtZint;

    fn patch_ext(value: u64) -> ExtEntryOwned {
        ExtEntryOwned {
            header: PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        }
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
}
