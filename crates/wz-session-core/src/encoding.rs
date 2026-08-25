// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Predefined Encoding constants + the MIME id<->str table — the wz mirror of
//! zenoh's high-level Encoding API (`zenoh/src/api/encoding.rs`).
//!
//! FOUNDATIONAL (always-on, no cfg toggle): the typed [`EncodingHint`]
//! constructors for the well-known encodings + the predefined-id <-> MIME-string
//! table, layered ON TOP of the already-active `pubsub-encoding` wire field
//! codec. The encoding identity is a DATA value (a numeric id + an optional
//! free-form schema string), so there is no per-encoding composable CODE path to
//! cfg-gate -- the §5.19 audit (R311cg / R311hr) ratified that cfg-gating an
//! encoding NAME would be a dead-code stub. This module is the convenience layer
//! that the 7 §5.19 encoding atoms (encoding-empty / -bytes / -utf8 / -json /
//! -cbor / -protobuf / -mime) name; they stay status=reserved + FOUNDATIONAL,
//! exactly as keyexpr-canon / pubsub-sample do (implemented, always compiled, not
//! a knob).
//!
//! The wz [`EncodingHint::packed_id`] is the WIRE-packed form
//! (`id << 1 | schema_present_bit`, zenoh RFC §5.B), so a predefined encoding
//! with no schema is `id << 1`. zenoh's predefined ids are `0..=52` (53 MIME
//! types) plus `0xFFFF` for a custom encoding whose whole string rides the schema
//! field (`zenoh/src/api/encoding.rs:88-628`).

use alloc::string::String;

use crate::sample::EncodingHint;

/// zenoh `EncodingId` (`commons/zenoh-protocol/src/core/encoding.rs:18`).
pub type EncodingId = u16;

/// The custom-encoding marker id: a MIME string not in the predefined table
/// rides the schema field under this id (zenoh `api/encoding.rs` `0xFFFF`).
pub const ID_CUSTOM: EncodingId = 0xFFFF;

// ── Predefined encoding ids (zenoh `api/encoding.rs:88-464`). The 53 well-known
//    MIME types, sequential 0..=52. The six the §5.19 atoms name are commented.
pub const ID_ZENOH_BYTES: EncodingId = 0; // encoding-empty (default / no hint)
pub const ID_ZENOH_STRING: EncodingId = 1;
pub const ID_ZENOH_SERIALIZED: EncodingId = 2;
pub const ID_APPLICATION_OCTET_STREAM: EncodingId = 3; // encoding-bytes
pub const ID_TEXT_PLAIN: EncodingId = 4; // encoding-utf8
pub const ID_APPLICATION_JSON: EncodingId = 5; // encoding-json
pub const ID_APPLICATION_CBOR: EncodingId = 8; // encoding-cbor
pub const ID_APPLICATION_PROTOBUF: EncodingId = 13; // encoding-protobuf

/// Pack a raw predefined id into the wire `packed_id` for a schema-less encoding
/// (`id << 1`, schema-present bit clear).
const fn packed_no_schema(id: EncodingId) -> u32 {
    (id as u32) << 1
}

impl EncodingHint {
    /// zenoh `Encoding::ZENOH_BYTES` (id 0) — the default/empty encoding (raw
    /// bytes, no interpretation). The wz mirror of `encoding-empty`.
    pub const ZENOH_BYTES: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_ZENOH_BYTES),
        schema: None,
    };
    /// zenoh `Encoding::APPLICATION_OCTET_STREAM` (id 3). The wz mirror of
    /// `encoding-bytes`.
    pub const APPLICATION_OCTET_STREAM: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_APPLICATION_OCTET_STREAM),
        schema: None,
    };
    /// zenoh `Encoding::TEXT_PLAIN` (id 4) — UTF-8 text. The wz mirror of
    /// `encoding-utf8`.
    pub const TEXT_PLAIN: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_TEXT_PLAIN),
        schema: None,
    };
    /// zenoh `Encoding::APPLICATION_JSON` (id 5). The wz mirror of
    /// `encoding-json`.
    pub const APPLICATION_JSON: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_APPLICATION_JSON),
        schema: None,
    };
    /// zenoh `Encoding::APPLICATION_CBOR` (id 8). The wz mirror of
    /// `encoding-cbor`.
    pub const APPLICATION_CBOR: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_APPLICATION_CBOR),
        schema: None,
    };
    /// zenoh `Encoding::APPLICATION_PROTOBUF` (id 13). The wz mirror of
    /// `encoding-protobuf`.
    pub const APPLICATION_PROTOBUF: EncodingHint = EncodingHint {
        packed_id: packed_no_schema(ID_APPLICATION_PROTOBUF),
        schema: None,
    };

    /// The raw predefined id (`packed_id >> 1`), dropping the schema-present bit.
    pub const fn id(&self) -> EncodingId {
        (self.packed_id >> 1) as EncodingId
    }
}

/// The predefined-id -> MIME string table (zenoh `ID_TO_STR`,
/// `api/encoding.rs:466-523`). `None` for an id outside the 53 predefined values
/// (a custom `0xFFFF` carries its string in the schema field, not here).
pub fn mime_for_id(id: EncodingId) -> Option<&'static str> {
    Some(match id {
        0 => "zenoh/bytes",
        1 => "zenoh/string",
        2 => "zenoh/serialized",
        3 => "application/octet-stream",
        4 => "text/plain",
        5 => "application/json",
        6 => "text/json",
        7 => "application/cdr",
        8 => "application/cbor",
        9 => "application/yaml",
        10 => "text/yaml",
        11 => "text/json5",
        12 => "application/python-serialized-object",
        13 => "application/protobuf",
        14 => "application/java-serialized-object",
        15 => "application/openmetrics-text",
        16 => "image/png",
        17 => "image/jpeg",
        18 => "image/gif",
        19 => "image/bmp",
        20 => "image/webp",
        21 => "application/xml",
        22 => "application/x-www-form-urlencoded",
        23 => "text/html",
        24 => "text/xml",
        25 => "text/css",
        26 => "text/javascript",
        27 => "text/markdown",
        28 => "text/csv",
        29 => "application/sql",
        30 => "application/coap-payload",
        31 => "application/json-patch+json",
        32 => "application/json-seq",
        33 => "application/jsonpath",
        34 => "application/jwt",
        35 => "application/mp4",
        36 => "application/soap+xml",
        37 => "application/yang",
        38 => "audio/aac",
        39 => "audio/flac",
        40 => "audio/mp4",
        41 => "audio/ogg",
        42 => "audio/vorbis",
        43 => "video/h261",
        44 => "video/h263",
        45 => "video/h264",
        46 => "video/h265",
        47 => "video/h266",
        48 => "video/mp4",
        49 => "video/ogg",
        50 => "video/raw",
        51 => "video/vp8",
        52 => "video/vp9",
        _ => return None,
    })
}

/// The MIME string -> predefined id lookup (zenoh `STR_TO_ID`,
/// `api/encoding.rs:525-579`). `None` for an unknown MIME (which maps to the
/// custom id in [`encoding_from_mime`]).
pub fn id_for_mime(mime: &str) -> Option<EncodingId> {
    // Linear scan over the 53-entry table; the table is the SSOT (mime_for_id),
    // so the reverse direction stays consistent by construction.
    (0..=52).find(|&id| mime_for_id(id) == Some(mime))
}

/// Parse a MIME string into an [`EncodingHint`] (zenoh `Encoding::from_str`,
/// `api/encoding.rs:604-628`): a known MIME maps to its predefined id; a
/// `"mime;schema"` form splits the schema off; an UNKNOWN MIME falls back to the
/// custom id ([`ID_CUSTOM`]) carrying the WHOLE string as the schema.
pub fn encoding_from_mime(s: &str) -> EncodingHint {
    let (mime, schema) = s.split_once(';').unwrap_or((s, ""));
    match id_for_mime(mime) {
        Some(id) => {
            let has_schema = !schema.is_empty();
            EncodingHint {
                packed_id: (packed_no_schema(id)) | (has_schema as u32),
                schema: has_schema.then(|| String::from(schema)),
            }
        }
        None => EncodingHint {
            packed_id: packed_no_schema(ID_CUSTOM) | 1,
            schema: Some(String::from(s)),
        },
    }
}

/// Render an [`EncodingHint`] back to its MIME string (zenoh `Encoding::to_string`):
/// a predefined id -> its MIME name (plus `";schema"` when a schema is set); the
/// custom id -> the schema string verbatim; an unknown predefined id -> empty.
pub fn encoding_to_mime(e: &EncodingHint) -> String {
    let id = e.id();
    if id == ID_CUSTOM {
        return e.schema.clone().unwrap_or_default();
    }
    let base = mime_for_id(id).unwrap_or("");
    match e.schema.as_deref() {
        Some(schema) if !schema.is_empty() => {
            let mut out = String::with_capacity(base.len() + 1 + schema.len());
            out.push_str(base);
            out.push(';');
            out.push_str(schema);
            out
        }
        _ => String::from(base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The named constants pack the right wire id (`id << 1`, no schema) — the
    /// six the §5.19 atoms name.
    #[test]
    fn named_constants_pack_the_predefined_id() {
        assert_eq!(EncodingHint::ZENOH_BYTES.packed_id, 0); // id 0 << 1
        assert_eq!(EncodingHint::APPLICATION_OCTET_STREAM.packed_id, 6); // 3 << 1
        assert_eq!(EncodingHint::TEXT_PLAIN.packed_id, 8); // 4 << 1
        assert_eq!(EncodingHint::APPLICATION_JSON.packed_id, 10); // 5 << 1
        assert_eq!(EncodingHint::APPLICATION_CBOR.packed_id, 16); // 8 << 1
        assert_eq!(EncodingHint::APPLICATION_PROTOBUF.packed_id, 26); // 13 << 1
        assert!(EncodingHint::APPLICATION_JSON.schema.is_none());
        assert_eq!(EncodingHint::APPLICATION_JSON.id(), ID_APPLICATION_JSON);
    }

    /// The id <-> MIME table round-trips across the full 53-entry range, and an
    /// out-of-range id has no MIME name.
    #[test]
    fn mime_table_round_trips() {
        for id in 0u16..=52 {
            let mime = mime_for_id(id).expect("every 0..=52 id has a MIME name");
            assert_eq!(id_for_mime(mime), Some(id), "{mime} round-trips to id {id}");
        }
        assert_eq!(mime_for_id(53), None);
        assert_eq!(mime_for_id(ID_CUSTOM), None);
        assert_eq!(id_for_mime("application/json"), Some(5));
        assert_eq!(id_for_mime("not/a-real-type"), None);
    }

    /// A known MIME parses to its predefined id (no schema); the `to_mime` inverse
    /// reproduces the string.
    #[test]
    fn from_to_mime_known() {
        let e = encoding_from_mime("application/json");
        assert_eq!(e, EncodingHint::APPLICATION_JSON);
        assert_eq!(encoding_to_mime(&e), "application/json");
    }

    /// A known MIME WITH a schema suffix splits the schema off and sets the bit.
    #[test]
    fn from_to_mime_known_with_schema() {
        let e = encoding_from_mime("application/json;utf-8");
        assert_eq!(e.id(), ID_APPLICATION_JSON);
        assert_eq!(e.packed_id & 0x1, 1, "schema-present bit set");
        assert_eq!(e.schema.as_deref(), Some("utf-8"));
        assert_eq!(encoding_to_mime(&e), "application/json;utf-8");
    }

    /// An UNKNOWN MIME falls back to the custom id carrying the whole string as
    /// the schema, and round-trips verbatim.
    #[test]
    fn from_to_mime_unknown_is_custom() {
        let e = encoding_from_mime("custom/format;v1");
        assert_eq!(e.id(), ID_CUSTOM);
        assert_eq!(e.schema.as_deref(), Some("custom/format;v1"));
        assert_eq!(encoding_to_mime(&e), "custom/format;v1");
    }
}
