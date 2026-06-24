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

/// `true` iff `extensions` carries an ext whose id is `ext_id` — the presence
/// test the capability `&=` merges and the SHM body-marker detect share. Matches
/// on the id only (`ext_id()` masks the encoding / M / Z flag bits off the
/// header), so it is agnostic to whether the entry is a UNIT or M-flagged ext.
pub fn chain_has_ext_id(extensions: &[ExtEntryOwned], ext_id: u8) -> bool {
    extensions.iter().any(|e| e.ext_id() == ext_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit ext encodes to a single byte whose header IS the id (no encoding /
    /// M bits), and `chain_has_ext_id` finds it but not a foreign id.
    #[test]
    fn unit_ext_round_trips_and_detects() {
        let ext = encode_unit_ext(0x05);
        assert_eq!(ext.header, 0x05);
        assert_eq!(ext.ext_id(), 0x05);
        assert_eq!(ext.as_borrowed().encode_to_vec().len(), 1);
        assert!(chain_has_ext_id(&[ext], 0x05));
        assert!(!chain_has_ext_id(&[encode_unit_ext(0x06)], 0x05));
        assert!(!chain_has_ext_id(&[], 0x05));
    }
}
