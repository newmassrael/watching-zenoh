// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh ENCODING id table — the wire vocabulary, hoisted here in R311y617.
//!
//! ## Why it moved
//!
//! The table INDEX is the wire value, so this is protocol vocabulary in exactly
//! the sense [`crate::wire_const`] is, and it lived in `wz-capi-core` only
//! because the C ABIs needed it first. That crate sits on `wz-runtime-tokio`,
//! which put the table out of reach of every `no_std` consumer — including
//! `wz-capture`, whose payload sub-decoder has to name the encoding a Put
//! DECLARES before it can say whether the bytes match the declaration.
//!
//! The alternative was a second transcription, which is the one thing the
//! table's own documentation refuses: two copies of one wire table drift
//! silently, invisible to every test either crate writes about itself and
//! visible to every peer. So the table moved DOWN to the crate both halves
//! already depend on, and `wz_capi_core::encoding_ids` re-exports it — the
//! pico oracle (`wz-capi-pico/tests/pico_pure_function_oracle.rs`, which feeds
//! entry `i` to the REAL `libzenohpico.so` and asserts pico assigns id `i`)
//! keeps its grip on the SAME constant rather than on a copy of it.
//!
//! ## What did NOT move
//!
//! `EncodingHint` construction and `EncodingDialect` stay in `wz-capi-core`.
//! They are ABI-shaped: the dialect exists because zenoh-c and zenoh-pico
//! disagree about how to render an unrecognised label, which is a question
//! about the two C libraries and not about the wire.

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

/// zenoh-c's sentinel for a label that names no table entry.
///
/// MEASURED, not assumed: `zc_internal_encoding_get_data` on the real
/// `libzenohc.so` reports `id=65535` for `wz/unknown` and for `text/pla`,
/// against `id=4` for `text/plain`.
pub const ENCODING_ID_UNKNOWN: u16 = 65535;

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
