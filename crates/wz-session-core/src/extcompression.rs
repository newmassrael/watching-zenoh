// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_COMPRESSION establishment extension wire shape
//! (`session-extcompression`).
//!
//! zenoh advertises transport compression as a zero-length UNIT extension on the
//! Init and Open transport messages: `pub type Compression = zextunit!(0x6,
//! false)` at BOTH `commons/zenoh-protocol/src/transport/init.rs:168` and
//! `open.rs:134` — ext id `0x6`, the `ExtUnit` encoding (no payload — presence IS
//! the signal), and NO mandatory bit, so a peer that does not support compression
//! drops the extension silently. The capability is negotiated by AND of both
//! sides: `io/zenoh-transport/src/unicast/establishment/ext/compression.rs:79`
//! (OpenFsm) and `:165` (AcceptFsm) -- `state.is_compression &= other_ext.is_some()`
//! -- and rides the Init exchange (the Open stages are NOP). When both peers
//! signal it, every post-establishment batch is lz4-wrapped (the
//! [`crate::compression`] data path).
//!
//! This module is the codec LAYER only -- the `(0x6, ENC_UNIT, empty body)`
//! envelope on Init / Open + the peer-offer projector. The per-session
//! `is_compression` runtime state, the offer staging, the `&=` merge, and the
//! lz4 tx / rx wrap live in [`crate::session_actions`] / [`crate::drive`] /
//! [`crate::compression`]. The exact sibling of [`crate::extlowlatency`] (a
//! distinct establishment UNIT ext in the neighbouring 0x6 id slot), reusing the
//! same `ExtUnit` codec -- zero new codec work.

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::unit_ext::{chain_has_ext_eid, encode_unit_ext};

/// Z_EXT_COMPRESSION ext id on the Init / Open establishment messages -- zenoh
/// `init.rs:168` / `open.rs:134` `zextunit!(0x6, false)`. The establishment
/// messages have their own ext id space (0x1 QoS, 0x2 Shm, 0x3 Auth,
/// 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression, 0x7 Patch).
pub const COMPRESSION_EXT_ID: u8 = crate::ext_header::establishment_ext_id::COMPRESSION;

/// Build the Z_EXT_COMPRESSION `ExtEntry`: the unit (zero-length) marker that
/// advertises compression capability (the [`crate::unit_ext`] mechanism at the
/// compression id). zenoh `zextunit!(0x6, false)`; the surrounding
/// [`crate::ext_chain::encode_ext_chain`] applies the chain-continuation `Z` bit.
pub fn encode_compression_ext() -> ExtEntryOwned {
    encode_unit_ext(COMPRESSION_EXT_ID)
}

/// Project the peer's compression capability from an establishment ext chain:
/// `true` iff the chain carries the Z_EXT_COMPRESSION id. The merge side
/// (`negotiate_compression_against_peer`) ANDs this against the local offer,
/// reproducing zenoh `is_compression &= other_ext.is_some()`.
pub fn peer_offered_compression(extensions: &[ExtEntryOwned]) -> bool {
    chain_has_ext_eid(extensions, COMPRESSION_EXT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the on-the-wire header byte (`0x06` = UNIT encoding | id 0x06, no M,
    /// Z patched by the chain codec) -- the shape zenoh emits for
    /// `init::ext::Compression` / `open::ext::Compression`.
    #[test]
    fn compression_ext_header_is_unit_id_six() {
        let ext = encode_compression_ext();
        assert_eq!(
            ext.header, 0x06,
            "UNIT enc (0x00) | COMPRESSION_EXT_ID (0x06)"
        );
        assert_eq!(ext.ext_id(), COMPRESSION_EXT_ID);
        assert_eq!(
            ext.as_borrowed().encode_to_vec().len(),
            1,
            "a unit ext is one byte"
        );
    }

    /// A chain carrying the compression ext projects to `true`; a chain with only
    /// the NEIGHBOURING lowlatency ext (0x5) -- or nothing -- projects to `false`,
    /// so the id is not confused with its neighbour in the id space.
    #[test]
    fn peer_offer_detected_and_not_confused_with_neighbour() {
        assert!(peer_offered_compression(&[encode_compression_ext()]));
        assert!(!peer_offered_compression(&[]));
        // The NEIGHBOURING lowlatency ext (0x5) is not mistaken for 0x6.
        assert!(!peer_offered_compression(&[encode_unit_ext(0x05)]));
    }
}
