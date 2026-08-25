// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the `T_MID_FRAGMENT` message's OWN extension id space — the
//! chain-start marker (`0x2 First`) and the chain-abandon marker
//! (`0x3 Drop`).
//!
//! This is a DIFFERENT id space from the establishment (Init / Open) one
//! that [`crate::extlowlatency`] / [`crate::extcompression`] live in. On a
//! Fragment the ids are: `0x1` QoS (z64, the priority — projected by
//! [`crate::inbound`]), `0x2` First (unit), `0x3` Drop (unit). zenoh
//! declares the pair as
//!
//! ```text
//! /// Mark the first fragment of a fragmented message
//! pub type First = zextunit!(0x2, false);
//! /// Indicate that the remaining fragments has been dropped
//! pub type Drop  = zextunit!(0x3, false);
//! ```
//!
//! (`commons/zenoh-protocol/src/transport/fragment.rs:88-97`), and
//! zenoh-pico names the same two `_Z_MSG_EXT_ID_FRAGMENT_FIRST` /
//! `_Z_MSG_EXT_ID_FRAGMENT_DROP` (`include/zenoh-pico/protocol/ext.h`).
//! Both are non-mandatory (`M = 0`), so a peer that does not understand
//! them drops them silently rather than rejecting the transport.
//!
//! ## Why the markers exist (and what reads them)
//!
//! A fragment chain is otherwise identified only by
//! `(peer, reliable, priority)` plus SN consecutiveness. That is enough to
//! ASSEMBLE a chain but not enough to know a chain was ENTERED at its
//! start: a receiver that joins mid-chain — a link that dropped the
//! leading fragments, a reader attached to a live flow, a peer whose
//! previous chain was superseded — would otherwise stage a headless tail
//! and hand the upstream decoder a message that begins in the middle of a
//! network message. The markers make the chain boundary explicit:
//!
//! - `First` says "this fragment starts a chain" — the receiver discards
//!   whatever it had staged on that key and starts fresh, and a fragment
//!   arriving WITHOUT the marker onto an idle key is not a chain start
//!   and is dropped.
//! - `Drop` says "the sender abandoned this chain" — the receiver clears
//!   the staged bytes rather than waiting for a continuation that will
//!   never come (zenoh's TX pipeline mints exactly this on an ephemeral
//!   batch when it cannot obtain a batch mid-fragmentation,
//!   `io/zenoh-transport/src/common/pipeline.rs:400-404`).
//!
//! Both rules are gated on the negotiated protocol PATCH level being
//! `>= 1` ([`crate::extpatch`]) — zenoh's
//! `PatchType::has_fragmentation_markers`
//! (`commons/zenoh-protocol/src/transport/mod.rs:333`) guards exactly the
//! block that applies them (`unicast/universal/rx.rs:155-170`). A patch-0
//! peer emits no markers, so enforcing them against one would refuse every
//! chain it sends; the gate is what keeps the rules from becoming an
//! interop regression.
//!
//! The wz TX side has emitted the `First` marker since R311y206
//! ([`crate::frame_encode`]); this module is the SSOT the emit and the
//! interpretation now share, plus the `Drop` half neither side had.

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::unit_ext::{chain_has_ext_eid, encode_unit_ext};

/// `fragment::ext::First` — `zextunit!(0x2, false)`. Marks the leading
/// fragment of a chain. Header byte on the wire is exactly `0x02` (UNIT
/// encoding `0b00`, M clear; the chain codec owns the `Z` continuation
/// bit).
pub const FRAGMENT_FIRST_EXT_ID: u8 = 0x02;

/// `fragment::ext::Drop` — `zextunit!(0x3, false)`. Announces that the
/// sender abandoned the chain and no continuation will follow.
pub const FRAGMENT_DROP_EXT_ID: u8 = 0x03;

/// The two chain-boundary markers projected out of one Fragment's ext
/// chain. A `Copy` value type so the no-alloc reassembly descriptor
/// ([`crate::reassembly_dispatch::Fragment`]) can carry it on the MCU
/// profile — the projection happens once at decode, where the owned ext
/// chain already exists, and only the two bits travel onward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FragmentMarkers {
    /// The `0x2 First` marker was present: this fragment starts a chain.
    pub first: bool,
    /// The `0x3 Drop` marker was present: the sender abandoned the chain.
    pub dropped: bool,
}

impl FragmentMarkers {
    /// Neither marker present — a continuation fragment, or any fragment
    /// from a patch-0 peer. Named rather than `Default::default()` at the
    /// callsites so a marker-less descriptor reads as a deliberate state.
    pub const NONE: Self = Self {
        first: false,
        dropped: false,
    };
}

/// Build the `0x2 First` marker entry (the [`crate::unit_ext`] mechanism
/// at the fragment-first id). zenoh `zextunit!(0x2, false)`; the
/// surrounding [`crate::ext_chain::encode_ext_chain`] applies the
/// chain-continuation `Z` bit.
pub fn encode_fragment_first_ext() -> ExtEntryOwned {
    encode_unit_ext(FRAGMENT_FIRST_EXT_ID)
}

/// Build the `0x3 Drop` marker entry — the chain-abandon announcement.
/// zenoh `zextunit!(0x3, false)`.
pub fn encode_fragment_drop_ext() -> ExtEntryOwned {
    encode_unit_ext(FRAGMENT_DROP_EXT_ID)
}

/// Project both chain-boundary markers out of a decoded Fragment ext
/// chain. Matches on the extension IDENTITY (encoding bits included, see
/// [`crate::unit_ext::chain_has_ext_eid`]), so a z64-bodied entry that
/// merely shares the 4-bit id field is not read as the unit marker.
pub fn project_markers(extensions: &[ExtEntryOwned]) -> FragmentMarkers {
    FragmentMarkers {
        first: chain_has_ext_eid(extensions, FRAGMENT_FIRST_EXT_ID),
        dropped: chain_has_ext_eid(extensions, FRAGMENT_DROP_EXT_ID),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    use wz_codecs::ext_zint::ExtZint;

    /// Locks the on-the-wire header bytes against the zenoh declarations:
    /// `First` is `0x02` and `Drop` is `0x03`, both UNIT-encoded with the
    /// mandatory bit clear, both exactly one byte.
    #[test]
    fn marker_headers_match_the_zenoh_declarations() {
        let first = encode_fragment_first_ext();
        assert_eq!(first.header, 0x02, "UNIT enc (0b00) | id 0x2, M clear");
        assert_eq!(first.as_borrowed().encode_to_vec().len(), 1);
        let dropped = encode_fragment_drop_ext();
        assert_eq!(dropped.header, 0x03, "UNIT enc (0b00) | id 0x3, M clear");
        assert_eq!(dropped.as_borrowed().encode_to_vec().len(), 1);
    }

    /// Each marker projects independently, and a chain carrying both
    /// projects both — the ext chain is a set, not an either/or.
    #[test]
    fn markers_project_independently() {
        assert_eq!(project_markers(&[]), FragmentMarkers::NONE);
        assert_eq!(
            project_markers(&[encode_fragment_first_ext()]),
            FragmentMarkers {
                first: true,
                dropped: false
            }
        );
        assert_eq!(
            project_markers(&[encode_fragment_drop_ext()]),
            FragmentMarkers {
                first: false,
                dropped: true
            }
        );
        assert_eq!(
            project_markers(&[encode_fragment_first_ext(), encode_fragment_drop_ext()]),
            FragmentMarkers {
                first: true,
                dropped: true
            }
        );
    }

    /// The R311y505 shape, at the fragment id space: an entry that shares
    /// the 4-bit ID FIELD but carries the z64 encoding is a DIFFERENT
    /// extension. On a Fragment the neighbour that matters is `0x1` QoS
    /// (z64) — reading it as a unit marker would turn every prioritized
    /// fragment into a chain start.
    #[test]
    fn a_z64_entry_sharing_the_id_field_is_not_a_marker() {
        // `ext_qos` as it actually arrives: id 0x1, ZINT encoding (0x20).
        let qos = ExtEntryOwned {
            header: 0x01 | 0x20,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 5 }),
        };
        assert_eq!(project_markers(&[qos]), FragmentMarkers::NONE);
        // A z64 entry parked on the First id is likewise not the marker.
        let z64_at_first = ExtEntryOwned {
            header: FRAGMENT_FIRST_EXT_ID | 0x20,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 1 }),
        };
        assert_eq!(project_markers(&[z64_at_first]), FragmentMarkers::NONE);
    }
}
