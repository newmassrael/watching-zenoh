// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

/// The names of [`ENCODING_ID_TO_STR`] one after another, built from it when the crate is
/// compiled: what a library reads at run time. An array of `&str` holds a pointer for each name,
/// which the loader of a shared library relocates, so the 53 of them would be words a process
/// writes and keeps resident; these bytes and their ends hold no pointer.
static NAMES: [u8; NAMES_LEN] = joined(&ENCODING_ID_TO_STR);

/// The bytes of every name together.
const NAMES_LEN: usize = joined_len(&ENCODING_ID_TO_STR);

/// Where each name ends in [`NAMES`], after the first name's start: name `id` is
/// `NAME_ENDS[id]..NAME_ENDS[id + 1]`.
static NAME_ENDS: [u16; ENCODING_ID_TO_STR.len() + 1] = name_ends(&ENCODING_ID_TO_STR);

/// The bytes of every name of `names`.
const fn joined_len(names: &[&str]) -> usize {
    let mut len = 0;
    let mut i = 0;
    while i < names.len() {
        len += names[i].len();
        i += 1;
    }
    len
}

/// The names of `names` one after another, `N` bytes of them.
const fn joined<const N: usize>(names: &[&str]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut at = 0;
    let mut i = 0;
    while i < names.len() {
        let name = names[i].as_bytes();
        let mut j = 0;
        while j < name.len() {
            out[at] = name[j];
            at += 1;
            j += 1;
        }
        i += 1;
    }
    assert!(at == N, "the names fill the bytes they are joined into");
    out
}

/// Where each name of `names` ends when they are joined, after a first end of zero; the ends fit
/// a `u16`, or the table does not compile.
const fn name_ends<const M: usize>(names: &[&str]) -> [u16; M] {
    assert!(M == names.len() + 1, "one end for each name and the start");
    let mut ends = [0u16; M];
    let mut at: usize = 0;
    let mut i = 0;
    while i < names.len() {
        at += names[i].len();
        assert!(at <= u16::MAX as usize, "the names fit ends of 16 bits");
        ends[i + 1] = at as u16;
        i += 1;
    }
    ends
}

/// The names, in id order, read out of [`NAMES`].
fn names() -> impl Iterator<Item = &'static [u8]> {
    NAME_ENDS.windows(2).map(|ends| match *ends {
        [start, end] => NAMES
            .get(usize::from(start)..usize::from(end))
            .unwrap_or_default(),
        _ => &[],
    })
}

/// The name of encoding `id`, [`ENCODING_ID_TO_STR`]`[id]`'s bytes, or `None` for an id past
/// the table.
pub fn name_of(id: usize) -> Option<&'static [u8]> {
    let start = usize::from(*NAME_ENDS.get(id)?);
    let end = usize::from(*NAME_ENDS.get(id.checked_add(1)?)?);
    NAMES.get(start..end)
}

/// The id whose name is `name`, the whole of it, or `None`.
pub fn id_of_name(name: &[u8]) -> Option<u16> {
    names().position(|entry| entry == name).map(|i| i as u16)
}

/// The table index for `prefix`, or `None`.
///
/// zenoh-pico compares with `strncmp(schema, TABLE[i], len)` — a PREFIX compare
/// of exactly `len` bytes — so a candidate shorter than the table entry can
/// match it (`"text/j"` matches `"text/json"`). That is upstream's behaviour and
/// it is reproduced rather than corrected: a lookup that disagreed with pico
/// about which id a string means would put a different byte on the wire, which
/// is the one thing this module exists to prevent.
pub fn lookup_id(candidate: &str) -> Option<u16> {
    names()
        .position(|entry| entry.starts_with(candidate.as_bytes()))
        .map(|i| i as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The joined names read back as the table, entry for entry, and nothing past it. Turned red
    /// by an end one off, or a name joined out of its id's place.
    #[test]
    fn every_name_reads_back_as_its_table_entry() {
        for (id, entry) in ENCODING_ID_TO_STR.iter().enumerate() {
            assert_eq!(name_of(id), Some(entry.as_bytes()), "id {id}");
            assert_eq!(id_of_name(entry.as_bytes()), Some(id as u16), "id {id}");
        }
        assert_eq!(name_of(ENCODING_ID_TO_STR.len()), None);
        assert_eq!(name_of(usize::MAX), None);
        assert_eq!(names().count(), ENCODING_ID_TO_STR.len());
        assert_eq!(
            NAMES.len(),
            ENCODING_ID_TO_STR.iter().map(|e| e.len()).sum::<usize>()
        );
    }

    /// A whole name is one id and a part of one is none; the prefix lookup keeps zenoh-pico's
    /// compare, the first entry the candidate begins, the empty candidate included. Turned red by a
    /// lookup that walks the ends as whole names, or one that stops past the first match.
    #[test]
    fn a_name_is_whole_and_a_lookup_is_a_prefix() {
        assert_eq!(id_of_name(b"text/plain"), Some(4));
        assert_eq!(id_of_name(b"text/pla"), None);
        assert_eq!(id_of_name(b"text/plainx"), None);
        assert_eq!(id_of_name(b""), None);
        assert_eq!(lookup_id("text/j"), Some(6));
        assert_eq!(lookup_id("text/plain"), Some(4));
        assert_eq!(lookup_id(""), Some(0));
        assert_eq!(lookup_id("wz/unknown"), None);
    }
}
