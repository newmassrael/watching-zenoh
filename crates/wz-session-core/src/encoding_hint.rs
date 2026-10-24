// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An [`EncodingHint`](crate::sample::EncodingHint) from an encoding label and back, under the
//! rule each upstream library assigns a wire id by.
//!
//! ## Why it lives here
//!
//! The id table (`wz_codecs::encoding_ids`) is wire vocabulary; these conversions are what every
//! C ABI needs over it, and the id they produce is what goes on the WIRE. They lived in
//! `wz-capi-core`, the session model both C ABIs share, beside the table until R311y617 moved the
//! table down. They moved down too when the pico ABI over the cooperative engine
//! (`docs/capi-pico-on-coop-engine.md`) had to reach them without the tokio engine that crate
//! sits on, and they sit beside the type they build. `wz-capi-core::encoding_ids` re-exports this
//! module, so every caller reads the one implementation.
//!
//! ## The id lives PACKED, because that is what wz already had
//!
//! [`EncodingHint::packed_id`](crate::sample::EncodingHint::packed_id) is the WIRE word — `(id << 1) | has_schema` — and both conversions
//! below produce and consume exactly that, so the schema-present flag can never disagree with the
//! schema actually stored.

use alloc::borrow::ToOwned;
use alloc::string::String;

use wz_codecs::encoding_ids::{
    lookup_id, ENCODING_ID_DEFAULT, ENCODING_ID_TO_STR, ENCODING_ID_UNKNOWN, SCHEMA_SEPARATOR,
};

use crate::sample::EncodingHint;

/// Which upstream's encoding string rules to apply.
///
/// # R311y564 — the two references disagree about BOTH halves
///
/// A C probe was compiled once and linked against the real `libzenohc.so`
/// and the real `libzenohpico.so`, and handed eleven labels. They split on
/// two independent rules:
///
/// | label | zenoh-c renders | zenoh-pico renders |
/// |---|---|---|
/// | `text/pla` | `text/pla` (id 65535) | `text/plain` (id 4) |
/// | `wz/unknown` | `wz/unknown` (id 65535) | `zenoh/bytes;wz/unknown` (id 0) |
///
/// So zenoh-c matches the prefix EXACTLY and files an unrecognised label
/// under a sentinel id carrying the whole string, while zenoh-pico matches
/// by `strncmp` PREFIX and files the leftover under the default id. Neither
/// is a wz choice: each ABI has to answer what the library it stands in for
/// answers, and the id is what goes on the WIRE, so this is not a rendering
/// preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingDialect {
    /// zenoh-pico's rules. wz's own wire path uses them.
    Pico,
    /// zenoh-c's rules, for the `wz-capi-c` drop-in.
    ZenohC,
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
    hint_from_str_in(s, EncodingDialect::Pico)
}

/// [`hint_from_str`] in an explicit dialect.
///
/// The zenoh-c arm is not a variation on the pico one: an unrecognised prefix
/// takes [`ENCODING_ID_UNKNOWN`] with the WHOLE input as its schema, so the
/// label survives a round trip verbatim rather than acquiring a
/// `zenoh/bytes;` head. The empty input is the one shared special case — both
/// references report the default id for it.
pub fn hint_from_str_in(s: &str, dialect: EncodingDialect) -> EncodingHint {
    if dialect == EncodingDialect::ZenohC {
        if s.is_empty() {
            return hint_from_parts(ENCODING_ID_DEFAULT, "");
        }
        let (prefix, schema) = match s.split_once(SCHEMA_SEPARATOR) {
            Some((prefix, schema)) => (prefix, schema),
            None => (s, ""),
        };
        return match ENCODING_ID_TO_STR.iter().position(|e| *e == prefix) {
            Some(id) => hint_from_parts(id as u16, schema),
            // The whole input, separator and all — that is what makes
            // `wz/unknown;x` render back as `wz/unknown;x`.
            None => hint_from_parts(ENCODING_ID_UNKNOWN, s),
        };
    }
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
    hint_to_string_in(hint, EncodingDialect::Pico)
}

/// [`hint_to_string`] in an explicit dialect.
///
/// Under [`EncodingDialect::ZenohC`] the sentinel id renders its schema ALONE
/// — no table name and no separator — which is the half that makes the round
/// trip verbatim. Every recognised id renders identically in both dialects.
pub fn hint_to_string_in(hint: &EncodingHint, dialect: EncodingDialect) -> String {
    let id = (hint.packed_id >> 1) as usize;
    let mut out = String::new();
    let unknown = dialect == EncodingDialect::ZenohC && id == usize::from(ENCODING_ID_UNKNOWN);
    if !unknown {
        if let Some(prefix) = ENCODING_ID_TO_STR.get(id) {
            out.push_str(prefix);
        }
    }
    if let Some(schema) = hint.schema.as_deref() {
        if !schema.is_empty() {
            if !unknown {
                out.push(SCHEMA_SEPARATOR);
            }
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
