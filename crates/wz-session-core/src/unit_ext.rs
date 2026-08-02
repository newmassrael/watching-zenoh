// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the zero-payload UNIT capability-ext MECHANISM shared by the
//! establishment capability negotiations — lowlatency (0x5), compression (0x6),
//! and the SHM establishment offer (0x2) — the wz mirror of zenoh's
//! `zextunit!(id, false)` capability extensions.
//!
//! Each per-capability module ([`crate::extlowlatency`] /
//! [`crate::extcompression`] / [`crate::extshm`]) keeps its OWN id constant + its
//! named encode / detect wrapper (the discoverable per-capability SSOT, with the
//! distinct zenoh citation), and delegates the IDENTICAL encode + presence-detect
//! mechanism here. R311xr review remediation: before, the
//! `{header: id, body: CodecZenohExtUnit}` struct-literal and the
//! `iter().any(|e| e.ext_id() == id)` presence scan were written four times
//! (0x5, 0x6, the 0x2 establishment offer, and the 0x2 body-marker detect) --
//! identical control flow that the project's "SSOT over DRY-cheapness" north star
//! says to abstract as the MECHANISM while keeping the DATA (the id constant + the
//! zenoh-cited wrapper) per-capability.

use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_unit::ExtUnit;

/// Encode a zero-payload UNIT capability ext with `ext_id` (UNIT encoding, no
/// mandatory bit; the surrounding chain codec applies the `Z` continuation bit).
/// The wz mirror of zenoh `zextunit!(ext_id, false)`. The header is exactly
/// `ext_id` (encoding bits + M bit clear); a one-byte entry on the wire.
pub fn encode_unit_ext(ext_id: u8) -> ExtEntryOwned {
    ExtEntryOwned {
        header: ext_id,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
    }
}

/// `true` iff `extensions` carries the extension whose encoded header is
/// `expected_header` — the presence test the capability `&=` merges and the SHM
/// body-marker detect share.
///
/// Matches on the extension IDENTITY ([`ext_eid`]: the header minus only the
/// chain flag), NOT on the 4-bit id field. R311y505 replaced an id-only match
/// here, and the difference is a measured cross-impl defect rather than a
/// tidiness point: zenoh's id field is four bits wide and two DIFFERENT
/// extensions may share it, told apart by their encoding bits — which zenoh
/// itself relies on (`QoS = zextunit!(0x1)` beside `QoSLink = zextz64!(0x1)`;
/// `init::ext::Shm = zextzbuf!(0x2)` beside wz's UNIT offer at 0x2). Under the
/// old id-only match a real `zenohd --features shared-memory` dialling wz
/// negotiated `is_shm = true` off zenoh's `Shm` ZBuf, and the same shape sat
/// under `peer_offered_qos`, where stock zenohd enables QoS by DEFAULT.
///
/// Callers pass the header they ENCODE, so a capability offer
/// ([`encode_unit_ext`], header == id) and an M-flagged body marker (header ==
/// `id | EXT_FLAG_M`) each match only their own form.
pub fn chain_has_ext_eid(extensions: &[ExtEntryOwned], expected_header: u8) -> bool {
    let want = crate::ext_header::ext_eid(expected_header);
    extensions
        .iter()
        .any(|e| crate::ext_header::ext_eid(e.header) == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit ext encodes to a single byte whose header IS the id (no encoding /
    /// M bits), and `chain_has_ext_eid` finds it but not a foreign id.
    #[test]
    fn unit_ext_round_trips_and_detects() {
        let ext = encode_unit_ext(0x05);
        assert_eq!(ext.header, 0x05);
        assert_eq!(ext.ext_id(), 0x05);
        assert_eq!(ext.as_borrowed().encode_to_vec().len(), 1);
        assert!(chain_has_ext_eid(&[ext], 0x05));
        assert!(!chain_has_ext_eid(&[encode_unit_ext(0x06)], 0x05));
        assert!(!chain_has_ext_eid(&[], 0x05));
    }

    /// R311y505 — the regression this round exists for: an entry that shares the
    /// 4-bit ID FIELD but carries a different ENCODING is a DIFFERENT extension
    /// and must not be read as the capability.
    ///
    /// Both cases below are real zenoh 1.5.0 extensions, not hypotheticals:
    /// `init::ext::Shm = zextzbuf!(0x2, false)` (header 0x42) against wz's UNIT
    /// offer at 0x2, and `init::ext::QoSLink = zextz64!(0x1, false)` (header
    /// 0x21) against wz's UNIT QoS at 0x1 — and a stock zenohd enables QoS by
    /// default, so the second one is on every zenoh link. Under the id-only match
    /// this replaced, BOTH returned true and wz negotiated a capability its peer
    /// had not offered.
    #[test]
    fn a_shared_id_with_another_encoding_is_a_different_extension() {
        // A zenoh ZBuf ext at id 0x2 (its establishment `Shm`).
        let zbuf_at_2 = ExtEntryOwned {
            header: 0x02 | crate::ext_header::EXT_ENC_ZBUF,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(!chain_has_ext_eid(&[zbuf_at_2], 0x02));

        // A zenoh Z64 ext at id 0x1 (its establishment `QoSLink`).
        let z64_at_1 = ExtEntryOwned {
            header: 0x01 | crate::ext_header::EXT_ENC_Z64,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(!chain_has_ext_eid(&[z64_at_1], 0x01));

        // The M bit is part of the identity too: a body MARKER (id | M) and a
        // capability OFFER (bare id) at the same id do not match each other.
        let marker = ExtEntryOwned {
            header: 0x02 | crate::ext_header::EXT_FLAG_M,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(chain_has_ext_eid(
            core::slice::from_ref(&marker),
            0x02 | crate::ext_header::EXT_FLAG_M
        ));
        assert!(!chain_has_ext_eid(&[marker], 0x02));

        // The CHAIN flag is not part of the identity: a non-final entry still
        // matches (that is the one bit `eid` drops).
        let chained = ExtEntryOwned {
            header: 0x05 | crate::ext_header::EXT_FLAG_Z,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(chain_has_ext_eid(&[chained], 0x05));
    }
}
