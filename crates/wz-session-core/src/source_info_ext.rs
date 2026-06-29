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
//! The base-128 VLE u64 primitive this encoder + the sibling
//! `encode_responder_ext_body` (in `response_build`) share is
//! [`crate::vle::encode_vle_u64_into`] — the VLE codec SSOT (read + write).

use alloc::vec::Vec;

use crate::codec_owned::owned_bytes;
use crate::vle::encode_vle_u64_into;
use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

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

/// ENC_ZBUF marker packed into the ext header high bits (`0b10 << 5 = 0x40`);
/// source_info never sets the mandatory (`0x10`) bit — it is an informational
/// hint a peer drops silently if unknown. Mirror of
/// [`crate::attachment`]'s `ATTACHMENT_EXT_HEADER_ENC_ZBUF`.
const SOURCE_INFO_EXT_HEADER_ENC_ZBUF: u8 = 0x40;

/// source_info body-ext id — zenoh-pico matches `0x01`
/// (`_z_push_body_decode_extensions`, message.c:309). The SAME id carries
/// source_info on every message kind: the Push / Del body, the Reply body, the
/// Query body, and the Err body.
pub const SOURCE_INFO_EXT_ID: u8 = 0x01;

/// R311y80 — build the single `source_info` `ExtEntry` (the `(zid, eid, sn)`
/// triple in an `ExtZbuf` body under header `ENC_ZBUF | 0x01`): the full-entry
/// SSOT, parallel to [`crate::attachment::encode_attachment_ext`]. Wraps the
/// value-bytes [`encode_source_info_ext_body`] in the ext envelope every
/// source_info carrier shares (Push / Del body, Reply body, Query body, Err
/// body), so the `0x40 | 0x01` header constant and the `ExtZbuf` wrap live in
/// ONE place instead of being re-hand-rolled at each carrier's encode site.
/// The surrounding codec applies the chain-continuation `Z` bit
/// (`crate::ext_nodeid::apply_chain_z_bits` for body chains, the per-builder
/// finalize loop for Query / Err); this helper emits the entry with `Z` clear.
/// Fallible (the owned ext-zbuf copy; unbounded under `alloc`).
pub fn encode_source_info_ext_entry(
    zid: &[u8],
    eid: u32,
    sn: u32,
) -> Result<ExtEntryOwned, CodecError> {
    let value = encode_source_info_ext_body(zid, eid, sn);
    Ok(ExtEntryOwned {
        header: SOURCE_INFO_EXT_HEADER_ENC_ZBUF | SOURCE_INFO_EXT_ID,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: value.len() as u64,
            value: owned_bytes(&value)?,
        }),
    })
}

// `encode_vle_u64_into` moved to the `crate::vle` SSOT (imported above) so the
// VLE-u64 writer has one home alongside its reader; this module and
// `response_build` + `extauth_usrpwd` all share it.

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

    /// R311y80 — the full-entry SSOT wraps the value bytes in the shared
    /// `ENC_ZBUF | 0x01` envelope (header `0x41`; the surrounding codec applies
    /// the chain-continuation `Z` bit, so this entry is Z-clear). The same one
    /// encoder serves every source_info carrier (Push / Reply / Query / Err
    /// body), so the `0x40 | 0x01` header is no longer re-hand-rolled per site.
    #[test]
    fn encode_source_info_ext_entry_wraps_value_in_enc_zbuf_envelope() {
        let entry = encode_source_info_ext_entry(&[0xDE, 0xAD], 0x80, 0x4000).unwrap();
        // ENC_ZBUF(0x40) | source_info id(0x01); no M flag, Z clear.
        assert_eq!(entry.header, 0x41);
        match entry.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                // value_len == the encode_source_info_ext_body length (8 here:
                // 1 leading + 2 zid + VLE(0x80)=2 + VLE(0x4000)=3).
                assert_eq!(
                    z.value_len as usize,
                    encode_source_info_ext_body(&[0xDE, 0xAD], 0x80, 0x4000).len()
                );
                assert_eq!(z.value_len, 8);
            }
            _ => panic!("expected ExtZbuf body"),
        }
    }
}
