// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y248 — SSOT for the zenoh Query body VALUE extension (the querier's
//! attached value: payload + encoding, historically the "Q_B / Q_E" wire codec
//! slots).
//!
//! A querier may attach a VALUE to its query — `session.get(sel).payload(bytes)
//! .encoding(enc)` in zenoh — which the queryable reads back as
//! `query.payload()` / `query.encoding()`. On the wire this rides the Query
//! body extension `ENC_ZBUF | 0x03` (zenoh-pico `_z_query_encode` at
//! `vendor/zenoh-pico/src/protocol/codec/message.c:433-436`, decoded by
//! `_z_query_decode_extensions` case `0x03` at message.c:461-465). The ext body
//! is a `_z_value_t` = `{ encoding, payload }`, encoded by `_z_value_encode`
//! (`vendor/zenoh-pico/src/protocol/codec.c:383`) as:
//!
//!   `_z_zsize_encode(encoding_len + payload_len)` — the total value length
//!   `_z_encoding_encode(encoding)`                — zint32(id<<1 | schema_flag) [+ schema]
//!   `_z_bytes_encode_val(payload)`                — raw payload bytes (NO length)
//!
//! The leading `zsize(total_len)` IS the `ExtZbuf` length prefix the ext
//! framework reads (`_z_value_decode` operates on the already-delimited ZBuf
//! slice, reading the encoding then taking the remaining bytes as the payload),
//! so this module does NOT re-emit that size inside the ext body — the value
//! bytes are exactly `encoding_encode || payload`, and the surrounding
//! [`ExtZbufOwned`] `value_len` prefix supplies pico's `total_len`. This makes
//! the wz emit byte-identical to `_z_query_encode`'s value arm.
//!
//! Mirrors the [`crate::source_info_ext`] (id 0x01) / [`crate::attachment`]
//! (id 0x05) precedents for the two sibling Query body exts; the module is
//! gated on `query-value`, the catalog primitive the querier's
//! `RequestQueryBuilder::query_value` (encode) and the queryable's
//! `query::extract_query_value` (decode) select.

use alloc::vec::Vec;

use crate::codec_owned::owned_bytes;
use crate::sample::EncodingHint;
use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::encoding::Encoding;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

/// Query body VALUE ext id — zenoh-pico `_z_query_encode` emits `0x03`
/// (`message.c:433`) and `_z_query_decode_extensions` matches it at
/// `message.c:461`. Distinct from the sibling Query body exts source_info
/// (`0x01`, [`crate::source_info_ext::SOURCE_INFO_EXT_ID`]) and attachment
/// (`0x05`, [`crate::attachment::ATTACHMENT_EXT_ID_QUERY`]).
pub const QUERY_VALUE_EXT_ID: u8 = 0x03;

/// ENC_ZBUF marker packed into the ext header high bits (`0b10 << 5 = 0x40`).
/// The value ext never sets the mandatory bit (`0x10`) — a peer that does not
/// understand it drops it silently. Mirror of the source_info / attachment
/// header constant.
const QUERY_VALUE_EXT_HEADER_ENC_ZBUF: u8 = 0x40;

/// Build the value-ext body bytes: pico `_z_value_encode`'s inner content =
/// `encoding_encode || payload`. The `zsize(total_len)` pico writes first is
/// supplied by the surrounding [`ExtZbufOwned`] `value_len` prefix (which the
/// ext-zbuf codec emits as the same VLE), so it is NOT re-emitted here.
pub fn encode_query_value_ext_body(encoding: &EncodingHint, payload: &[u8]) -> Vec<u8> {
    // `encode_to_vec` is the generated Encoding codec's byte-parity emit
    // (proven against `_z_encoding_encode` by the Put / Reply E-flag tests);
    // the payload follows raw, exactly as `_z_bytes_encode_val` writes it.
    let mut out = encoding.to_codec().encode_to_vec();
    out.extend_from_slice(payload);
    out
}

/// Build the single Query VALUE `ExtEntry` (header `ENC_ZBUF | 0x03`, body =
/// `encoding || payload` in an `ExtZbuf`). The surrounding builder applies the
/// chain-continuation `Z` bit; this helper emits the entry with `Z` clear
/// (terminator). Mirror of [`crate::attachment::encode_attachment_ext`] /
/// [`crate::source_info_ext::encode_source_info_ext_entry`]. Fallible only on
/// the `no_std` profile (the owned ext-zbuf copy is unbounded under `alloc`).
pub fn encode_query_value_ext(
    encoding: &EncodingHint,
    payload: &[u8],
) -> Result<ExtEntryOwned, CodecError> {
    let value = encode_query_value_ext_body(encoding, payload);
    Ok(ExtEntryOwned {
        header: QUERY_VALUE_EXT_HEADER_ENC_ZBUF | QUERY_VALUE_EXT_ID,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: value.len() as u64,
            value: owned_bytes(&value)?,
        }),
    })
}

/// Project the first Query VALUE ext (`0x03`) from an ext chain into
/// `(encoding, payload)`. Decodes the leading `encoding` (zint32 id + optional
/// schema, via the generated codec — the inverse of `to_codec().encode_to_vec`)
/// and returns the REMAINING bytes as the payload, exactly as pico's
/// `_z_value_decode` takes `_z_zbuf_len` bytes after the encoding. Returns
/// `None` when the chain carries no `0x03` ext or the encoding prefix is
/// malformed (a corrupt value ext is dropped, not surfaced). Mirror of
/// [`crate::attachment::decode_attachment_ext`].
pub fn decode_query_value_ext(extensions: &[ExtEntryOwned]) -> Option<(EncodingHint, &[u8])> {
    for ext in extensions {
        if ext.ext_id() == QUERY_VALUE_EXT_ID {
            if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body {
                let slice = z.value.as_slice();
                let mut cursor = SceCursor::new(slice);
                let enc = Encoding::decode(&mut cursor).ok()?;
                // Bytes the encoding consumed = slice.len() - what is left; the
                // remainder is the payload (pico takes `_z_zbuf_len(zbf)` after
                // `_z_encoding_decode`).
                let consumed = slice.len() - cursor.remaining();
                let payload = &slice[consumed..];
                let hint = EncodingHint::from_codec(&enc.try_into_owned().ok()?);
                return Some((hint, payload));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    // A default (id 0, no schema) encoding — the common `zenoh::get` value
    // shape when the querier attaches only a payload. `packed_id = 0` = id 0,
    // schema flag clear, so `encode_to_vec` is a single `0x00` zint32.
    fn default_encoding() -> EncodingHint {
        EncodingHint {
            packed_id: 0,
            schema: None,
        }
    }

    /// The value-ext body is exactly `encoding_encode || payload` — a default
    /// encoding is one `0x00` byte, then the raw payload. Locks the layout
    /// independently of the ExtZbuf wrap (the byte pico's `_z_value_encode`
    /// writes after its `zsize`).
    #[test]
    fn encode_query_value_ext_body_is_encoding_then_payload() {
        let body = encode_query_value_ext_body(&default_encoding(), b"hi");
        assert_eq!(
            body,
            [0x00, b'h', b'i'],
            "default encoding zint32(0) then raw payload"
        );
    }

    /// The full entry wraps the body in the shared `ENC_ZBUF | 0x03` envelope
    /// (header `0x43`, `value_len` = the ExtZbuf/pico `zsize` covering
    /// `encoding || payload`, Z clear).
    #[test]
    fn encode_query_value_ext_wraps_in_enc_zbuf_envelope() {
        let entry = encode_query_value_ext(&default_encoding(), b"hi").unwrap();
        assert_eq!(entry.header, 0x43, "ENC_ZBUF(0x40) | value id(0x03)");
        match entry.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                // value_len covers encoding(1) + payload(2) = 3 = pico total_len.
                assert_eq!(z.value_len, 3);
                assert_eq!(z.value.as_slice(), &[0x00, b'h', b'i']);
            }
            _ => panic!("expected ExtZbuf body"),
        }
    }

    /// Round-trip: a value ext built by the encoder decodes back to the same
    /// `(encoding, payload)` — the encoding prefix is consumed exactly and the
    /// remainder is the payload.
    #[test]
    fn query_value_encode_decode_round_trip() {
        let enc = default_encoding();
        let entry = encode_query_value_ext(&enc, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let chain = [entry];
        let (got_enc, got_payload) =
            decode_query_value_ext(&chain).expect("value ext decodes back");
        assert_eq!(got_enc.packed_id, 0);
        assert_eq!(got_enc.schema, None);
        assert_eq!(got_payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// Round-trip with a schema-bearing encoding (packed_id odd = schema flag
    /// set): the schema string sits between the id and the payload, so a
    /// correct decode must consume the WHOLE encoding (id + schema) before the
    /// payload — a mis-split would fold schema bytes into the payload.
    #[test]
    fn query_value_round_trip_with_schema_encoding() {
        // packed_id = (5 << 1) | 1 = 0x0B : id 5, schema flag set.
        let enc = EncodingHint {
            packed_id: 0x0B,
            schema: Some("json".to_string()),
        };
        let entry = encode_query_value_ext(&enc, b"payload-bytes").unwrap();
        let chain = [entry];
        let (got_enc, got_payload) =
            decode_query_value_ext(&chain).expect("schema-encoding value ext decodes");
        assert_eq!(got_enc.packed_id, 0x0B);
        assert_eq!(got_enc.schema.as_deref(), Some("json"));
        assert_eq!(got_payload, b"payload-bytes");
    }

    /// An empty payload (a value that is encoding-only) round-trips: the
    /// remainder after the encoding is a zero-length slice.
    #[test]
    fn query_value_round_trip_empty_payload() {
        let entry = encode_query_value_ext(&default_encoding(), b"").unwrap();
        let chain = [entry];
        let (_enc, payload) = decode_query_value_ext(&chain).expect("empty-payload value decodes");
        assert_eq!(payload, b"");
    }

    /// Decode is ext-id-scoped: a sibling Query body ext (here source_info
    /// `0x01`) in the chain is invisible to the value (`0x03`) lookup.
    #[test]
    fn decode_ignores_non_value_exts() {
        let si = crate::source_info_ext::encode_source_info_ext_entry(&[0xAA], 1, 2).unwrap();
        let chain = [si];
        assert!(decode_query_value_ext(&chain).is_none());
    }

    /// An empty chain yields `None`.
    #[test]
    fn decode_returns_none_on_empty_chain() {
        assert!(decode_query_value_ext(&[]).is_none());
    }
}
