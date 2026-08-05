// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh ENCODING id table, and the two conversions every ABI needs over it.
//!
//! ## Why this is ABI-neutral and therefore lives here
//!
//! The table index IS the wire value. It is a property of the zenoh protocol,
//! not of either C ABI: `zenoh-pico`'s `ENCODING_VALUES_ID_TO_STR`
//! (`src/api/encoding.c:89`) and zenoh-c's `Encoding` constants agree on it
//! entry for entry, because a publisher on one and a subscriber on the other
//! have to mean the same thing by id 4. Two transcriptions of one wire table
//! is exactly the shape that drifts silently — the divergence is invisible to
//! every test either crate writes about itself, and visible to every peer.
//!
//! `wz-capi-pico` owned this table first, under an oracle
//! (`wz-capi-pico/tests/pico_pure_function_oracle.rs` walks every id and every
//! entry through BOTH that crate and the real `libzenohpico.so`). Hoisting it
//! here keeps that oracle pointed at the same constant — the pico crate
//! re-exports this one rather than holding a copy — and gives `wz-capi-c` the
//! id its `z_encoding_*` constants had no way to reach.
//!
//! ## The id lives PACKED, because that is what wz already had
//!
//! [`EncodingHint::packed_id`] is the WIRE word — `(id << 1) | has_schema` —
//! and both conversions below produce and consume exactly that, so the
//! schema-present flag can never disagree with the schema actually stored.

use wz_runtime_tokio::sample::EncodingHint;

/// zenoh-pico's `ENCODING_VALUES_ID_TO_STR` (`src/api/encoding.c:89`), 53
/// entries, index = encoding id.
///
/// Order IS the contract — the index is what goes on the wire — so it is
/// pinned entry-for-entry against `libzenohpico.so` rather than eyeballed. A
/// `from_str -> to_string` round trip reads this table in BOTH directions and
/// is therefore invariant under any permutation, which a damage probe
/// demonstrated by swapping two entries and staying green; the oracle test
/// feeds entry `i` to the REAL pico and asserts pico assigns it id `i`, which
/// is the only non-circular check.
pub const ENCODING_ID_TO_STR: [&str; 53] = [
    "zenoh/bytes",
    "zenoh/string",
    "zenoh/serialized",
    "application/octet-stream",
    "text/plain",
    "application/json",
    "text/json",
    "application/cdr",
    "application/cbor",
    "application/yaml",
    "text/yaml",
    "text/json5",
    "application/python-serialized-object",
    "application/protobuf",
    "application/java-serialized-object",
    "application/openmetrics-text",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/webp",
    "application/xml",
    "application/x-www-form-urlencoded",
    "text/html",
    "text/xml",
    "text/css",
    "text/javascript",
    "text/markdown",
    "text/csv",
    "application/sql",
    "application/coap-payload",
    "application/json-patch+json",
    "application/json-seq",
    "application/jsonpath",
    "application/jwt",
    "application/mp4",
    "application/soap+xml",
    "application/yang",
    "audio/aac",
    "audio/flac",
    "audio/mp4",
    "audio/ogg",
    "audio/vorbis",
    "video/h261",
    "video/h263",
    "video/h264",
    "video/h265",
    "video/h266",
    "video/mp4",
    "video/ogg",
    "video/raw",
    "video/vp8",
    "video/vp9",
];

/// zenoh-pico's `ENCODING_SCHEMA_SEPARATOR` (`src/api/encoding.c:25`).
pub const SCHEMA_SEPARATOR: char = ';';

/// zenoh-pico's `_Z_ENCODING_ID_DEFAULT` — `zenoh/bytes`, id 0.
pub const ENCODING_ID_DEFAULT: u16 = 0;

/// The table index for `prefix`, or `None`.
///
/// zenoh-pico compares with `strncmp(schema, TABLE[i], len)` — a PREFIX compare
/// of exactly `len` bytes — so a candidate shorter than the table entry can
/// match it (`"text/j"` matches `"text/json"`). That is upstream's behaviour and
/// it is reproduced rather than corrected: a lookup that disagreed with pico
/// about which id a string means would put a different byte on the wire, which
/// is the one thing this module exists to prevent.
pub fn lookup_id(candidate: &str) -> Option<u16> {
    ENCODING_ID_TO_STR
        .iter()
        .position(|entry| entry.as_bytes().starts_with(candidate.as_bytes()))
        .map(|i| i as u16)
}

/// Pack an `(id, schema)` pair into the wire word.
///
/// The schema-present bit is DERIVED here rather than passed in, so it cannot
/// disagree with the schema actually stored.
pub fn hint_from_parts(id: u16, schema: &str) -> EncodingHint {
    let has_schema = !schema.is_empty();
    EncodingHint {
        packed_id: (u32::from(id) << 1) | u32::from(has_schema),
        schema: has_schema.then(|| schema.to_owned()),
    }
}

/// Build a hint from an `id;schema` string exactly as zenoh-pico's
/// `_z_encoding_convert_from_substr` does (`src/api/encoding.c:154`).
///
/// The split is on the FIRST separator, and an unrecognised prefix is NOT an
/// error: the whole string becomes the schema under the default id. That
/// fallback is why `z_encoding_from_str` has no invalid input.
pub fn hint_from_str(s: &str) -> EncodingHint {
    if let Some(pos) = s.find(SCHEMA_SEPARATOR) {
        let (prefix, rest) = s.split_at(pos);
        // Skip the separator itself.
        let schema = &rest[SCHEMA_SEPARATOR.len_utf8()..];
        if let Some(id) = lookup_id(prefix) {
            return hint_from_parts(id, schema);
        }
    } else if let Some(id) = lookup_id(s) {
        return hint_from_parts(id, "");
    }
    hint_from_parts(ENCODING_ID_DEFAULT, s)
}

/// Render as zenoh-pico's `_z_encoding_convert_into_string` does: the id's table
/// entry, then `;schema` when a schema is present. An id past the table renders
/// as the empty prefix, which is pico's behaviour too (its bounds check leaves
/// `prefix` NULL and `prefix_len` 0).
pub fn hint_to_string(hint: &EncodingHint) -> String {
    let id = (hint.packed_id >> 1) as usize;
    let mut out = String::new();
    if let Some(prefix) = ENCODING_ID_TO_STR.get(id) {
        out.push_str(prefix);
    }
    if let Some(schema) = hint.schema.as_deref() {
        if !schema.is_empty() {
            out.push(SCHEMA_SEPARATOR);
            out.push_str(schema);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one entry every witness in this repo keys off: `text/plain` is id 4,
    /// so the wire word is 8. Both ABIs' `text/plain` constant resolves through
    /// this, and a real zenoh-pico prints `with encoding: text/plain` for it.
    #[test]
    fn text_plain_is_id_four_and_packs_to_eight() {
        let hint = hint_from_str("text/plain");
        assert_eq!(hint.packed_id, 8);
        assert_eq!(hint.packed_id >> 1, 4);
        assert_eq!(hint.schema, None);
        assert_eq!(hint_to_string(&hint), "text/plain");
    }

    /// An unrecognised prefix is not an error — the whole string becomes the
    /// schema under id 0, which is why `z_encoding_from_str` cannot fail.
    #[test]
    fn an_unknown_label_falls_back_to_the_default_id_with_the_string_as_schema() {
        let hint = hint_from_str("not/a/real/encoding");
        // id 0 (`zenoh/bytes`) in the high bits, schema-present in bit 0.
        assert_eq!(hint.packed_id, 1);
        assert_eq!(hint.schema.as_deref(), Some("not/a/real/encoding"));
        assert_eq!(hint_to_string(&hint), "zenoh/bytes;not/a/real/encoding");
    }

    /// The separator splits on the FIRST `;`, and the prefix is looked up.
    #[test]
    fn a_schema_suffix_keeps_the_prefixs_id() {
        let hint = hint_from_str("text/plain;utf8");
        assert_eq!(hint.packed_id, (4 << 1) | 1);
        assert_eq!(hint.schema.as_deref(), Some("utf8"));
        assert_eq!(hint_to_string(&hint), "text/plain;utf8");
    }
}
