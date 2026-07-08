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

use crate::codec_owned::owned_bytes;
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
    // W3: the ext_zbuf `value` owned mirror is `SceBytes<32>` — under `alloc`
    // an UNBOUNDED `Vec` (the `32` is advisory; proven by the 200-byte reply
    // (A8a) + query (A8c-1) attachment tests), under `no_std` a
    // `heapless::Vec<u8, 32>` that returns `TooManyElements` past 32. So this
    // is fallible only on the `no_std` profile; under `alloc` any length rides.
    Ok(ExtEntryOwned {
        header: ATTACHMENT_EXT_HEADER_ENC_ZBUF | ext_id,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: payload.len() as u64,
            value: owned_bytes(payload)?,
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

/// Serialize an ordered list of `(key, value)` byte-string pairs into the
/// zenoh `ze_serializer` attachment kv-sequence wire form — the payload a
/// zenoh / zenoh-pico consumer's attachment loop decodes with
/// `ze_deserializer_deserialize_sequence_length` then a per-element
/// `ze_deserializer_deserialize_string` key/value pair
/// (`vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c` 70-83). This is
/// the wz counterpart of zenoh's `ZBytes::from_iter([(k, v), ..])`: the wire
/// ext (encoded by [`encode_attachment_ext`]) carries an OPAQUE blob, and this
/// is the standard *structured* payload a peer expects inside it.
///
/// Layout: `VLE(pair_count)` then, per pair, `VLE(key_len) key VLE(val_len)
/// value`. Each string is a `ze_serializer_serialize_string`
/// (`vendor/zenoh-pico/src/api/serialization.c:102`) = a `serialize_buf` =
/// length-prefixed bytes (serialization.c:72); the leading count is a
/// `serialize_sequence_length` (serialization.c:62). Both the count and each
/// length are the zenoh `zsize` VLE (`_z_zsize_encode`), which wz's [`crate::vle`]
/// SSOT (`encode_vle_u64_into` / `write_zbuf`) emits byte-identically, so the
/// blob is decode-compatible by construction — no second varint here.
pub fn serialize_kv_attachment(pairs: &[(&[u8], &[u8])]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    crate::vle::encode_vle_u64_into(&mut out, pairs.len() as u64);
    for (key, value) in pairs {
        crate::vle::write_zbuf(&mut out, key);
        crate::vle::write_zbuf(&mut out, value);
    }
    out
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

    /// Locks the exact `ze_serializer` kv-sequence wire bytes for a single
    /// pair against what zenoh-pico's `z_sub_attachment` decoder expects:
    /// `VLE(1)` count, then per string a `VLE(len)` prefix + raw bytes. Pinning
    /// the bytes (not a self-round-trip) is the stronger gate — a symmetric
    /// encode/decode bug would survive a round-trip but fail against pico here.
    #[test]
    fn serialize_kv_attachment_locks_single_pair_wire_bytes() {
        // [("hi", "yo")] -> 01  02 'h' 'i'  02 'y' 'o'
        let blob = serialize_kv_attachment(&[(b"hi", b"yo")]);
        assert_eq!(
            blob,
            [0x01, 0x02, b'h', b'i', 0x02, b'y', b'o'],
            "VLE(1) count, then serialize_string('hi'), serialize_string('yo')"
        );
    }

    /// Two pairs: the count VLE is `2` and the four length-prefixed strings
    /// follow in key,value,key,value order — the exact decode order of
    /// `z_sub_attachment.c`'s `for` loop (deserialize key then value per i).
    #[test]
    fn serialize_kv_attachment_locks_two_pair_order() {
        let blob = serialize_kv_attachment(&[(b"a", b"bb"), (b"ccc", b"")]);
        assert_eq!(
            blob,
            [
                0x02, // count = 2
                0x01, b'a', // key "a"
                0x02, b'b', b'b', // value "bb"
                0x03, b'c', b'c', b'c', // key "ccc"
                0x00, // value "" (zero-length, still length-prefixed)
            ],
        );
    }

    /// An empty pair list serializes to just the `VLE(0)` count — the form
    /// `z_sub_attachment` reads as `attachment_len == 0` (prints nothing).
    #[test]
    fn serialize_kv_attachment_empty_is_just_the_zero_count() {
        assert_eq!(serialize_kv_attachment(&[]), [0x00]);
    }

    /// A value whose length crosses the single-byte VLE boundary (200 > 127)
    /// emits the 2-byte `zsize` length `0xC8 0x01`, proving the count/length
    /// prefixes ride the multi-byte VLE the same way pico's `_z_zsize_encode`
    /// does (the reader in `vle.rs` pins `0xC8 0x01 == 200`).
    #[test]
    fn serialize_kv_attachment_multibyte_length_prefix() {
        let big = alloc::vec![0xEE_u8; 200];
        let blob = serialize_kv_attachment(&[(b"k", &big)]);
        // 01 (count) | 01 'k' (key) | C8 01 (len 200) | 200 bytes
        assert_eq!(&blob[..5], &[0x01, 0x01, b'k', 0xC8, 0x01]);
        assert_eq!(blob.len(), 5 + 200);
        assert!(blob[5..].iter().all(|&b| b == 0xEE));
    }
}
