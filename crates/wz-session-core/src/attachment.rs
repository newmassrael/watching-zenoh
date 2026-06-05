// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the zenoh attachment extension wire shape (`attachment-bytes`).
//!
//! zenoh numbers the attachment extension differently per carrier — the
//! PUSH body uses ext_id `0x03` (zenoh-pico `_z_push_body_*_extensions`,
//! `vendor/zenoh-pico/src/protocol/codec/message.c` 314-322) while a
//! Query uses ext_id `0x05` (`_z_query_*_extensions`, message.c 446-448).
//! Both encode the opaque payload as an `ExtZbuf` body with the ENC_ZBUF
//! encoding marker (header high bits `0b10`, i.e. `0x40`) and NO mandatory
//! (`_Z_MSG_EXT_FLAG_M` = `0x10`) bit, so a peer that does not understand
//! the extension drops it silently rather than rejecting the frame.
//!
//! Before this module the same `(ext_id, ENC_ZBUF, ExtZbuf body)` shape
//! was re-derived at four sites — Push decode (`sample::extract_attachment`),
//! Query decode (`query::extract_query_attachment`), Query encode
//! (`request_build`), and Push encode (`session_glue::build_body_extensions`).
//! Housing the encode / decode pair here gives every attachment path one
//! source of truth, mirroring the [`crate::source_info_ext`] precedent for
//! the sibling `source_info` ext. The module is gated on `attachment-bytes`,
//! the catalog primitive the `pubsub-attachment` / `query-attachment`
//! consumer features select.

use crate::codec_bound::bounded_bytes;
use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

/// Attachment ext id inside a PUSH body (Put / Del) — zenoh-pico
/// `_z_push_body_decode_extensions` matches `0x03` at message.c 314-322.
pub const ATTACHMENT_EXT_ID_PUSH: u8 = 0x03;

/// Attachment ext id inside a Query — zenoh-pico `_z_query_encode_ext`
/// emits `0x05` at message.c 446-448.
pub const ATTACHMENT_EXT_ID_QUERY: u8 = 0x05;

/// ENC_ZBUF marker packed into the ext header high bits: the 2-bit
/// encoding field (`0b10`) shifted into bits 5..6 (`0b10 << 5 = 0x40`).
/// The attachment ext never sets the mandatory bit (`0x10`).
const ATTACHMENT_EXT_HEADER_ENC_ZBUF: u8 = 0x40;

/// Build the single attachment `ExtEntry` for the given carrier `ext_id`
/// ([`ATTACHMENT_EXT_ID_PUSH`] or [`ATTACHMENT_EXT_ID_QUERY`]). The
/// surrounding codec applies the chain-continuation `Z` bit; this helper
/// emits the entry with `Z` clear (terminator) so a caller appending it
/// as the sole / last entry needs no fix-up.
pub fn encode_attachment_ext(ext_id: u8, payload: &[u8]) -> Result<ExtEntryOwned, CodecError> {
    // W3: the ext_zbuf value owned mirror is bounded `heapless::Vec<u8, 32>`
    // (the codec's declared max-size); copy in, fallible past 32 bytes.
    Ok(ExtEntryOwned {
        header: ATTACHMENT_EXT_HEADER_ENC_ZBUF | ext_id,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: payload.len() as u64,
            value: bounded_bytes(payload)?,
        }),
    })
}

/// Project the first attachment payload from an ext chain for the given
/// carrier `ext_id`. Matches on `(ext_id, ExtZbuf body)`; the `ExtZbuf`
/// variant is exactly the decode-time witness that the header carried the
/// ENC_ZBUF encoding, so no separate `enc()` test is needed. Returns the
/// borrowed body slice; callers needing ownership map with `<[u8]>::to_vec`.
pub fn decode_attachment_ext(extensions: &[ExtEntryOwned], ext_id: u8) -> Option<&[u8]> {
    for ext in extensions {
        if ext.ext_id() == ext_id {
            if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body {
                return Some(z.value.as_slice());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips the encode helper against the decode helper for the
    /// PUSH carrier and locks the on-the-wire header byte (`0x40 | 0x03`).
    #[test]
    fn push_encode_decode_round_trip() {
        let ext = encode_attachment_ext(ATTACHMENT_EXT_ID_PUSH, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(
            ext.header, 0x43,
            "ENC_ZBUF | id_attachment(push) = 0x40 | 0x03"
        );
        let chain = [ext];
        assert_eq!(
            decode_attachment_ext(&chain, ATTACHMENT_EXT_ID_PUSH),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]),
        );
    }

    /// Same round-trip for the Query carrier (`0x40 | 0x05`).
    #[test]
    fn query_encode_decode_round_trip() {
        let ext = encode_attachment_ext(ATTACHMENT_EXT_ID_QUERY, &[0x01, 0x02]).unwrap();
        assert_eq!(
            ext.header, 0x45,
            "ENC_ZBUF | id_attachment(query) = 0x40 | 0x05"
        );
        let chain = [ext];
        assert_eq!(
            decode_attachment_ext(&chain, ATTACHMENT_EXT_ID_QUERY),
            Some(&[0x01, 0x02][..]),
        );
    }

    /// Decode is carrier-scoped: a PUSH-id attachment is invisible to a
    /// Query-id lookup and vice versa (the two carriers never share a chain
    /// but the predicate must still discriminate).
    #[test]
    fn decode_discriminates_carrier_ext_id() {
        let chain = [encode_attachment_ext(ATTACHMENT_EXT_ID_PUSH, &[0xAA]).unwrap()];
        assert_eq!(decode_attachment_ext(&chain, ATTACHMENT_EXT_ID_QUERY), None);
    }

    /// An empty chain (and a chain with no matching ext) yields `None`.
    #[test]
    fn decode_returns_none_on_empty_chain() {
        assert_eq!(decode_attachment_ext(&[], ATTACHMENT_EXT_ID_PUSH), None);
    }
}
