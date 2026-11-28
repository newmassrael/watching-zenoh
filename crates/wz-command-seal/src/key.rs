// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The commander's key and the zid it names: a self-certifying name (Mazieres et al., SFS, 1999),
//! with no authority between the key and the name.
//!
//! The zid of a key is the first sixteen bytes of the SHA-256 of its DER SubjectPublicKeyInfo,
//! decision D1 of `docs/session-lifecycle-intent.md`, the zid a link's key proves
//! (`wz_session_core::credential_identity::zid_from_spki_der`) and the one
//! `scripts/lib/wz_node.py` `zid_of` prints. A P-256 key in the uncompressed form has one DER
//! SubjectPublicKeyInfo (RFC 5480, section 2): a fixed prefix naming `id-ecPublicKey` and
//! `prime256v1`, then the point. So a node rebuilds those bytes from the point the sealed command
//! carries and hashes the same bytes a link would, and two encodings of one key never name two
//! commanders.

use sha2::{Digest, Sha256};

/// A zid in the sixteen-byte form: the little-endian bytes of the id, as a key spells it.
pub type Zid = [u8; ZID_LEN];

/// The length of a zid in the sixteen-byte form.
pub const ZID_LEN: usize = 16;

/// The length of an uncompressed P-256 point: `0x04`, then x and y of 32 bytes each.
pub const POINT_LEN: usize = 65;

/// The length of one coordinate of a P-256 point.
pub const COORDINATE_LEN: usize = 32;

/// The first byte of an uncompressed point (SEC 1, section 2.3.3).
pub const UNCOMPRESSED: u8 = 0x04;

/// The DER of a P-256 SubjectPublicKeyInfo up to its point: `SEQUENCE { SEQUENCE {
/// id-ecPublicKey, prime256v1 }, BIT STRING` of 66 bytes with no unused bits `}`.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The length of the DER SubjectPublicKeyInfo of a P-256 key.
pub const P256_SPKI_LEN: usize = 91;

/// The DER SubjectPublicKeyInfo of the P-256 key `point`. Every byte is fixed by the point, so
/// the same key always has these bytes, whoever writes them.
pub fn spki_of_point(point: &[u8; POINT_LEN]) -> [u8; P256_SPKI_LEN] {
    let mut spki = [0u8; P256_SPKI_LEN];
    let (prefix, rest) = spki.split_at_mut(P256_SPKI_PREFIX.len());
    prefix.copy_from_slice(&P256_SPKI_PREFIX);
    rest.copy_from_slice(point);
    spki
}

/// The point of a DER SubjectPublicKeyInfo, or `None` unless it is the one encoding of an
/// uncompressed P-256 key: what a tool reads from the PEM of a commander's public key.
pub fn point_of_spki(spki: &[u8]) -> Option<[u8; POINT_LEN]> {
    let point = spki.strip_prefix(P256_SPKI_PREFIX.as_slice())?;
    let point = <[u8; POINT_LEN]>::try_from(point).ok()?;
    (point.first() == Some(&UNCOMPRESSED)).then_some(point)
}

/// The zid a DER SubjectPublicKeyInfo names: the first sixteen bytes of its SHA-256.
pub fn zid_of_spki(spki: &[u8]) -> Zid {
    let digest = Sha256::digest(spki);
    let mut zid = [0u8; ZID_LEN];
    for (into, byte) in zid.iter_mut().zip(digest.iter()) {
        *into = *byte;
    }
    zid
}

/// The zid the P-256 key `point` names, as a link that proved the same key would name it.
pub fn zid_of_point(point: &[u8; POINT_LEN]) -> Zid {
    zid_of_spki(&spki_of_point(point))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;

    /// A P-256 public key made once with `openssl genpkey` for this test; its private half was
    /// not kept.
    pub(crate) const PINNED_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMz9e5vx5bF5gRfdvr9WnNhxLdVf4
72EiSBkwQ85i3L45nQilPQjpY+wtqT18QUJJ70qA2AHZwyHQvW2n6xL9OA==
-----END PUBLIC KEY-----
";

    /// What `scripts/lib/wz_node.py` `zid_of` gives for [`PINNED_PUBLIC_KEY_PEM`], worked from
    /// its definition: SHA-256 of the DER is `92764932a7d8044f5657b385494905ff...`, the first
    /// sixteen bytes read as a little-endian integer and printed in lowercase hex.
    pub(crate) const PINNED_ZID_TEXT: &str = "ff05494985b357564f04d8a732497692";

    /// The pinned key's point.
    pub(crate) const PINNED_X: [u8; COORDINATE_LEN] = [
        0x33, 0x3f, 0x5e, 0xe6, 0xfc, 0x79, 0x6c, 0x5e, 0x60, 0x45, 0xf7, 0x6f, 0xaf, 0xd5, 0xa7,
        0x36, 0x1c, 0x4b, 0x75, 0x57, 0xf8, 0xef, 0x61, 0x22, 0x48, 0x19, 0x30, 0x43, 0xce, 0x62,
        0xdc, 0xbe,
    ];
    pub(crate) const PINNED_Y: [u8; COORDINATE_LEN] = [
        0x39, 0x9d, 0x08, 0xa5, 0x3d, 0x08, 0xe9, 0x63, 0xec, 0x2d, 0xa9, 0x3d, 0x7c, 0x41, 0x42,
        0x49, 0xef, 0x4a, 0x80, 0xd8, 0x01, 0xd9, 0xc3, 0x21, 0xd0, 0xbd, 0x6d, 0xa7, 0xeb, 0x12,
        0xfd, 0x38,
    ];

    pub(crate) fn pinned_point() -> [u8; POINT_LEN] {
        let mut point = [0u8; POINT_LEN];
        point[0] = UNCOMPRESSED;
        point[1..=COORDINATE_LEN].copy_from_slice(&PINNED_X);
        point[COORDINATE_LEN + 1..].copy_from_slice(&PINNED_Y);
        point
    }

    /// The DER of a PEM public key, as `wz_node.py` `spki_of` reads one.
    fn spki_of_pem(pem: &str) -> std::vec::Vec<u8> {
        let body: std::string::String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("the pinned PEM is base64")
    }

    pub(crate) fn zid_text(zid: &Zid) -> std::string::String {
        std::format!("{:x}", u128::from_le_bytes(*zid))
    }

    #[test]
    fn the_spki_rebuilt_from_the_point_is_the_pems_and_names_the_zid_wz_node_prints() {
        let spki = spki_of_pem(PINNED_PUBLIC_KEY_PEM);
        assert_eq!(spki_of_point(&pinned_point()).as_slice(), spki.as_slice());
        assert_eq!(zid_text(&zid_of_spki(&spki)), PINNED_ZID_TEXT);
        assert_eq!(zid_text(&zid_of_point(&pinned_point())), PINNED_ZID_TEXT);
    }

    #[test]
    fn the_point_is_read_back_from_its_spki_and_any_other_encoding_is_refused() {
        let spki = spki_of_point(&pinned_point());
        assert_eq!(point_of_spki(&spki), Some(pinned_point()));

        let mut compressed_tag = spki;
        compressed_tag[P256_SPKI_PREFIX.len()] = 0x02;
        assert_eq!(point_of_spki(&compressed_tag), None);

        let mut other_curve = spki;
        other_curve[22] = 0x22;
        assert_eq!(
            point_of_spki(&other_curve),
            None,
            "a curve other than prime256v1"
        );

        assert_eq!(point_of_spki(&spki[..P256_SPKI_LEN - 1]), None);
        let mut longer = spki.to_vec();
        longer.push(0);
        assert_eq!(point_of_spki(&longer), None);
    }
}
