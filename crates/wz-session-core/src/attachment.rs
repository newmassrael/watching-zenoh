// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// Attachment ext id inside a PUT push body — zenoh-pico
/// `_z_push_body_decode_extensions` matches `0x03` at message.c 314-322, and
/// zenoh 1.5.0 declares the same id on the Put body
/// (`zenoh-protocol/src/zenoh/put.rs:78`, `zextzbuf!(0x3, false)`).
///
/// R311y769 renamed the concept from "PUSH body (Put / Del)" to PUT
/// specifically, because the two arms do NOT share an id — see
/// [`ATTACHMENT_EXT_ID_DEL`].
pub const ATTACHMENT_EXT_ID_PUSH: u8 = 0x03;

/// Attachment ext id inside a DEL push body — `0x02`, NOT the Put's `0x03`.
///
/// R311y769. THE TWO UPSTREAMS DISAGREE HERE and the disagreement is on the
/// wire, so it cannot be papered over:
///
/// * zenoh 1.5.0 declares the Del body's attachment at id `0x2`
///   (`zenoh-protocol/src/zenoh/del.rs:60`, `zextzbuf!(0x2, false)`) against
///   the Put body's `0x3` (`put.rs:78`). Its `ReplyBody` IS a `PushBody`, so a
///   Del REPLY carries one too.
/// * zenoh-pico never EMITS an attachment on a Del at all — `has_attachment`
///   is `pshb->_is_put && ..` (`src/protocol/codec/message.c:263`) — and its
///   decoder is shared between the arms, recognising only `0x03`
///   (`:313-322`).
///
/// So no single byte satisfies both, and wz emits **zenoh's**. That choice is
/// SAFE against pico rather than a coin flip: `zextzbuf!(0x2, false)` is
/// non-mandatory, and pico's `default` arm errors only when the `M` bit is set
/// (`:325-327`), so a pico peer silently ignores the ext and lands on exactly
/// the behaviour it has today — the attachment dropped. Emitting `0x03`
/// instead would please pico and make zenoh read the ext as
/// `ext_unknown`, which is the same loss pointed the other way, with the
/// protocol SSOT on the losing side.
///
/// R2370 — the PUSH Del arm honours this only from that round. R311y769 fixed
/// the REPLY arm and left `push_build::build_body_extensions` hardcoding the
/// Put id, so the sentence above about landing on today's behaviour was true
/// of a Del REPLY and false of a Del PUSH, which pico did decode at `0x03`.
/// Both arms emit `0x02` now, so the wire changed for a pico subscriber of a
/// wz `del()`: it saw the attachment before and does not now. That is the
/// accepted side of the trade above rather than a regression to repair, and
/// pico cannot send the reciprocal message either — `has_attachment` is
/// `pshb->_is_put && ..` (`src/protocol/codec/message.c:263`).
pub const ATTACHMENT_EXT_ID_DEL: u8 = 0x02;

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

/// Parse a `ze_serializer` attachment kv-sequence blob (the inverse of
/// [`serialize_kv_attachment`]) into owned `(key, value)` byte-string pairs.
/// This is the wz decode twin for the reverse cross-impl direction: a foreign
/// zenoh / zenoh-pico publisher (e.g. pico's `z_pub_attachment`,
/// `vendor/zenoh-pico/examples/unix/c11/z_pub_attachment.c:109-117`) emits the
/// kv-sequence, and a wz subscriber recovers the structured pairs from the
/// delivered `Sample`'s opaque attachment.
///
/// Reads `VLE(pair_count)` then, per pair, two length-prefixed strings — the
/// exact decode `z_sub_attachment.c`'s loop performs
/// (`ze_deserializer_deserialize_sequence_length` +
/// `ze_deserializer_deserialize_string` × 2 per element). Faithful to the pico
/// decoder, it reads EXACTLY `pair_count` pairs and ignores any trailing bytes
/// (pico does not check for full consumption). Returns `None` on a truncated /
/// malformed blob (a length prefix that overruns the buffer), never panicking
/// and never over-allocating on a bogus count — a short blob claiming many
/// pairs fails on the first read that runs out. Composed from the
/// [`crate::vle`] SSOT (`read_zbuf` = `ze_deserializer_deserialize_string`),
/// the read twin of the [`crate::vle::write_zbuf`] `serialize_kv_attachment`
/// builds from.
pub fn deserialize_kv_attachment(
    blob: &[u8],
) -> Option<alloc::vec::Vec<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>> {
    let mut cursor = sce_forge_runtime::codec::SceCursor::new(blob);
    let count = cursor.read_vle_u64().ok()?;
    let mut pairs = alloc::vec::Vec::new();
    for _ in 0..count {
        let key = crate::vle::read_zbuf(&mut cursor)?;
        let value = crate::vle::read_zbuf(&mut cursor)?;
        pairs.push((key, value));
    }
    Some(pairs)
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

    /// deserialize_kv_attachment recovers the pairs from the exact locked
    /// single-pair wire bytes — the reverse of the serialize byte-lock, i.e.
    /// what a wz subscriber gets from a foreign publisher's attachment.
    #[test]
    fn deserialize_kv_attachment_reads_locked_single_pair() {
        let pairs = deserialize_kv_attachment(&[0x01, 0x02, b'h', b'i', 0x02, b'y', b'o']).unwrap();
        assert_eq!(pairs, [(b"hi".to_vec(), b"yo".to_vec())]);
    }

    /// serialize -> deserialize round-trips for the representative shapes:
    /// two pairs, a zero-length value, an empty list, and a multi-byte length.
    #[test]
    fn kv_attachment_serialize_deserialize_round_trips() {
        let big = alloc::vec![0xEE_u8; 200];
        let cases: &[&[(&[u8], &[u8])]] = &[
            &[(b"source", b"C"), (b"index", b"0")],
            &[(b"a", b"bb"), (b"ccc", b"")],
            &[],
            &[(b"k", &big)],
        ];
        for pairs in cases {
            let blob = serialize_kv_attachment(pairs);
            let back = deserialize_kv_attachment(&blob).expect("well-formed blob decodes");
            let expected: alloc::vec::Vec<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> = pairs
                .iter()
                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                .collect();
            assert_eq!(back, expected, "round-trip for {pairs:?}");
        }
    }

    /// A truncated blob (claims a pair whose value length overruns the buffer)
    /// yields `None`, never a panic, a partial pair, an over-allocation, or an
    /// unbounded loop.
    #[test]
    fn deserialize_kv_attachment_none_on_truncation() {
        // count=1, key len=1 'k', value len=5 but only 1 byte present -> the
        // value's `read_zbuf` overruns the buffer.
        assert_eq!(
            deserialize_kv_attachment(&[0x01, 0x01, b'k', 0x05, b'x']),
            None
        );
        // An unterminated count VLE (three continuation-flagged bytes, no
        // terminator) fails at the `read_vle_u64` for the COUNT, before the
        // pair loop is ever entered.
        assert_eq!(deserialize_kv_attachment(&[0xFF, 0xFF, 0xFF]), None);
        // The load-bearing no-OOM / bounded-loop case: a VALID large count
        // (200 = VLE `0xC8 0x01`) followed by NO pair bytes. The loop is capped
        // by the buffer, not by `count`, so the first pair's key `read_zbuf`
        // runs out and `?` bails to `None` — no per-`count` pre-allocation, no
        // unbounded spin (contrast pico's `malloc(sizeof(kv) * count)`).
        assert_eq!(deserialize_kv_attachment(&[0xC8, 0x01]), None);
        // An empty blob has not even the count VLE.
        assert_eq!(deserialize_kv_attachment(&[]), None);
    }

    /// Faithful to pico's decoder: reads EXACTLY `count` pairs and ignores
    /// trailing bytes (z_sub_attachment.c does not check for full consumption).
    #[test]
    fn deserialize_kv_attachment_ignores_trailing_bytes() {
        // count=1, ("hi","yo"), then a stray trailing byte 0xAB.
        let pairs =
            deserialize_kv_attachment(&[0x01, 0x02, b'h', b'i', 0x02, b'y', b'o', 0xAB]).unwrap();
        assert_eq!(pairs, [(b"hi".to_vec(), b"yo".to_vec())]);
    }
}
