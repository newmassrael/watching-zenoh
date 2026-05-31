// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ek — shared `source_info` extension-body encoder.
//!
//! [`encode_source_info_ext_body`] builds the value bytes of a
//! `source_info` body-extension (the `(zid, eid, sn)` triple a Put / Del
//! / Reply emits inside an `ExtZbuf`). It was first lifted with the
//! Response-builder cluster (R311dv) into [`crate::response_build`], but
//! the same encoder is consumed by the `codec-push` body-extension path
//! (`session_glue::build_body_extensions`) as well as the
//! `codec-response` responder path. Housing it under the
//! `codec-response`-gated `response_build` module made it unreachable in
//! a `codec-push`-only subset (the north-star arbitrary-composition gap
//! mechanism ①). Relocating it to this `alloc`-only module — with no
//! codec-feature gate — lets every codec path that emits a `source_info`
//! ext reach the one encoder.
//!
//! [`encode_vle_u64_into`] is the base-128 VLE u64 primitive both this
//! encoder and the sibling `encode_responder_ext_body` (kept in
//! `response_build`) share; it is `pub(crate)` so the response path can
//! continue to borrow it without duplicating the loop.

use alloc::vec::Vec;

/// R121j-4b — encode the value bytes of a `source_info` extension per
/// zenoh-pico's `_z_source_info_encode`.
///
/// Wire layout (the bytes this fn returns; the surrounding ExtZbuf
/// codec prepends its own `VLE(value_len)` length prefix):
///
///   [byte 0]            `((zid_len - 1) << 4)` — high nibble carries
///                        `zid_len - 1` (1..=16 valid, encoded 0..=15).
///   [byte 1..1+zid_len] raw zid bytes.
///   [VLE u64]            `eid`.
///   [VLE u64]            `sn`.
///
/// Panics if `zid.len()` is outside `1..=16` (the caller's setter
/// guards this; the inner assertion is defence-in-depth).
pub fn encode_source_info_ext_body(zid: &[u8], eid: u32, sn: u32) -> Vec<u8> {
    assert!(
        (1..=16).contains(&zid.len()),
        "source_info zid length must be 1..=16 (zenoh-pico ZenohId wire constraint)"
    );
    // Capacity = 1 leading byte + zid + VLE(u32) worst-case (5 bytes) ×2.
    let mut out = Vec::with_capacity(1 + zid.len() + 5 + 5);
    out.push(((zid.len() as u8) - 1) << 4);
    out.extend_from_slice(zid);
    encode_vle_u64_into(&mut out, eid as u64);
    encode_vle_u64_into(&mut out, sn as u64);
    out
}

/// R121j-4b — base-128 VLE u64 emit into a `Vec<u8>`. Mirrors the
/// inline loop in `encode_frame_envelope` and zenoh-pico's
/// `_z_zsize_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/core.c`. Free-function shape
/// because ext-body construction happens before any `SceSink` is in
/// scope — the ext body lives inside `ExtZbuf.value` and the
/// surrounding codec sink only sees the already-built `Vec`.
pub(crate) fn encode_vle_u64_into(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

// R311fs — encode_source_info_ext_body wire-layout test, relocated
// from wz-runtime-tokio::session_glue to its SSOT home (R311ek moved
// the encoder here). This module is `#[cfg(feature = "alloc")]` and
// codec-agnostic (R311ek lifted the encoder out of codec-response
// gating precisely so the codec-push body-extension path can reach it),
// so the test is `#[cfg(test)]`-only — gating it on `codec-response`
// would reintroduce, on the test side, the asymmetry R311ek removed
// (codec-push-only builds would exercise the encoder untested).
#[cfg(test)]
mod tests {
    use super::*;

    /// R121j-4b — direct check on the helper that builds the
    /// source_info ext-body bytes. Locks the wire shape independently
    /// of the builder so future helpers (Push.source_info, Query
    /// source_info) can re-use the helper with the same guarantees.
    #[test]
    fn encode_source_info_ext_body_matches_zenoh_pico_layout() {
        // zid_len=2 → leading byte = (2-1)<<4 = 0x10
        let bytes = encode_source_info_ext_body(&[0xDE, 0xAD], 0x80, 0x4000);
        // Expected: [0x10, 0xDE, 0xAD, VLE(0x80)..., VLE(0x4000)...]
        // VLE(0x80): 0x80 needs 2 bytes (first 0x80|0x00=0x80, second 0x01)
        // VLE(0x4000): 0x4000 needs 3 bytes (0x80, 0x80, 0x01)
        assert_eq!(
            bytes[0], 0x10,
            "leading byte packs zid_len-1 in high nibble"
        );
        assert_eq!(
            &bytes[1..3],
            &[0xDE, 0xAD],
            "raw zid follows the leading byte"
        );
        // VLE(128) = 0x80, 0x01 (continuation bit on first byte, value 1 in second)
        assert_eq!(
            &bytes[3..5],
            &[0x80, 0x01],
            "VLE(eid=128) = 0x80 0x01 (2 bytes)"
        );
        // VLE(16384) = 0x80, 0x80, 0x01
        assert_eq!(
            &bytes[5..8],
            &[0x80, 0x80, 0x01],
            "VLE(sn=16384) = 0x80 0x80 0x01 (3 bytes)"
        );
        assert_eq!(
            bytes.len(),
            8,
            "total = 1 leading + 2 zid + 2 VLE(eid) + 3 VLE(sn) = 8"
        );
    }
}
