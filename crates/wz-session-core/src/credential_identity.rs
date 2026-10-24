// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zid a credential's public key names (decision D1 of
//! `docs/session-lifecycle-intent.md`).
//!
//! A zid is sixteen bytes a node chooses for itself, so on its own it proves
//! nothing: any peer can claim any zid. This module fixes the one derivation
//! that makes a zid a claim a peer can only make by holding a private key: the
//! first sixteen bytes of SHA-256 over the DER `SubjectPublicKeyInfo` of the key
//! the peer authenticated with. It is the self-certifying identifier of HIP
//! (RFC 7401, the Host Identity Tag) and of SFS, and it needs no certificate
//! authority: whoever proved possession of the key also proved the zid.
//!
//! The input is the `SubjectPublicKeyInfo` and not a key type, so one rule
//! covers every secure channel that carries a public key, whatever its
//! algorithm (decision D9): today the key of a TLS or QUIC certificate. The key
//! of the public-key authentication extension is deliberately not one: that
//! proof is not bound to the frames after the handshake. A peer whose zid is not
//! derived this way still exchanges data as before; it is only never
//! [`zid_is_bound`](crate::credential_identity::zid_is_bound).
//!
//! No allocation and no feature gate: the MCU profile shares the rule, and the
//! hash is the `sha2` the cookie path already links. For the same reason the
//! module holds the rule every comparison of two zids rests on, that two
//! spellings of one zid are one zid ([`crate::credential_identity::canonical_zid`],
//! [`crate::credential_identity::zid_from_wire`]).

use sha2::{Digest, Sha256};

/// The width of a zid on the wire at its widest, and of every derived one.
pub const CREDENTIAL_ZID_BYTES: usize = 16;

/// The zid the key in `spki_der` names: the first [`CREDENTIAL_ZID_BYTES`]
/// bytes of SHA-256 over the DER `SubjectPublicKeyInfo`.
pub fn zid_from_spki_der(spki_der: &[u8]) -> [u8; CREDENTIAL_ZID_BYTES] {
    let digest = Sha256::digest(spki_der);
    let mut zid = [0u8; CREDENTIAL_ZID_BYTES];
    zid.copy_from_slice(&digest[..CREDENTIAL_ZID_BYTES]);
    zid
}

/// The canonical, length-trimmed form of a zid: the little-endian bytes with the
/// trailing zero high bytes dropped, which is how zenoh sends one.
///
/// The ONE place that rule is written, and in this module because every profile
/// builds it. Two spellings of one zid are the same zid to zenoh, so a comparison
/// of raw bytes would call them two nodes; a caller matching a zid it READ against
/// a zid it PARSED or was given compares both through this
/// ([`crate::zid_hex::same_zid`], [`zid_from_wire`]).
pub fn canonical_zid(zid: &[u8]) -> &[u8] {
    let end = zid.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &zid[..end]
}

/// The zid `wire_zid` spells, read back to sixteen bytes, or `None` for bytes
/// that spell no zid (longer than sixteen, or zero, which no node is).
///
/// The wire form drops a zid's high zero bytes: zenoh writes the little-endian
/// bytes of a non-zero `u128` up to its last non-zero byte
/// (`commons/zenoh-codec/src/core/zenohid.rs` @
/// `self.write(&mut *writer, &x.to_le_bytes()[..x.size()])`), so a zid whose
/// last bytes are zero arrives shorter than sixteen bytes, and two spellings of
/// one zid differ only in those zeros. Upstream compares the `u128`s. The rule
/// that two spellings are one zid is [`canonical_zid`]'s; this writes its value
/// in the sixteen-byte form a derived zid has.
pub fn zid_from_wire(wire_zid: &[u8]) -> Option<[u8; CREDENTIAL_ZID_BYTES]> {
    if wire_zid.len() > CREDENTIAL_ZID_BYTES {
        return None;
    }
    let canonical = canonical_zid(wire_zid);
    if canonical.is_empty() {
        return None;
    }
    let mut padded = [0u8; CREDENTIAL_ZID_BYTES];
    padded[..canonical.len()].copy_from_slice(canonical);
    Some(padded)
}

/// Whether the zid a peer claimed on the wire is the zid `credential_zid` names,
/// compared as [`zid_from_wire`] reads it. A claim that spells no zid is never
/// bound.
pub fn zid_is_bound(claimed_wire_zid: &[u8], credential_zid: &[u8; CREDENTIAL_ZID_BYTES]) -> bool {
    zid_from_wire(claimed_wire_zid).is_some_and(|claimed| claimed == *credential_zid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wire_zid_is_read_back_to_sixteen_bytes_and_one_that_spells_none_is_refused() {
        let mut sixteen = [0u8; CREDENTIAL_ZID_BYTES];
        sixteen[..2].copy_from_slice(&[0x0a, 0x0b]);
        assert_eq!(zid_from_wire(&[0x0a, 0x0b]), Some(sixteen));
        assert_eq!(zid_from_wire(&sixteen), Some(sixteen));
        assert_eq!(zid_from_wire(&[]), None);
        assert_eq!(zid_from_wire(&[0x00, 0x00]), None, "zero is no node's zid");
        assert_eq!(zid_from_wire(&[0x01; CREDENTIAL_ZID_BYTES + 1]), None);
    }

    // The oracle is FIPS 180-2's own SHA-256 vectors, not this module: the
    // digests of "" and "abc" are published, and the derivation must be their
    // first sixteen bytes.
    #[test]
    fn the_derivation_is_the_first_sixteen_bytes_of_sha256() {
        assert_eq!(
            zid_from_spki_der(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24
            ]
        );
        assert_eq!(
            zid_from_spki_der(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23
            ]
        );
    }

    #[test]
    fn a_full_width_claim_is_bound_only_to_its_own_derivation() {
        let zid = zid_from_spki_der(b"abc");
        assert!(zid_is_bound(&zid, &zid));
        let mut other = zid;
        other[0] ^= 1;
        assert!(!zid_is_bound(&other, &zid));
    }

    // The wire trims high zero bytes, so a derived zid ending in zeros arrives
    // short and must still be bound; a claim that differs only by a missing
    // NON-zero byte must not be.
    #[test]
    fn a_trimmed_claim_is_read_back_to_sixteen_bytes() {
        let mut zid = [0x11u8; CREDENTIAL_ZID_BYTES];
        zid[14] = 0;
        zid[15] = 0;
        assert!(zid_is_bound(&zid[..14], &zid));
        let full = [0x11u8; CREDENTIAL_ZID_BYTES];
        assert!(!zid_is_bound(&full[..14], &full));
    }

    #[test]
    fn an_empty_or_oversized_claim_is_never_bound() {
        let zid = zid_from_spki_der(b"abc");
        assert!(!zid_is_bound(&[], &zid));
        let mut long = [0u8; CREDENTIAL_ZID_BYTES + 1];
        long[..CREDENTIAL_ZID_BYTES].copy_from_slice(&zid);
        assert!(!zid_is_bound(&long, &zid));
    }
}
