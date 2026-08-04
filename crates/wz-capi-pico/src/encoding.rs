// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ENCODING plane — pico's `z_owned_encoding_t`, the `id;schema` string
//! form, and the wire projection wz already carries as
//! [`wz_runtime_tokio::sample::EncodingHint`].
//!
//! ## Why the id table is transcribed, and why that is safe here
//!
//! `Z_FEATURE_ENCODING_VALUES` is **1** in the CMake-generated `config.h` these
//! programs compile against, so pico's `z_encoding_from_str` is not a
//! store-the-whole-string operation: it splits on the FIRST `;`, looks the
//! prefix up in a 53-entry table, and stores `(id, schema)`; `z_encoding_to_string`
//! renders that back as `prefix[;schema]`. An implementation that stored the
//! whole string as a schema would round-trip through ITSELF perfectly and put a
//! different id on the wire — invisible to any wz-authored test, and visible to
//! every peer.
//!
//! So the table below is transcribed from `src/api/encoding.c:89`, and it is
//! transcribed **under an oracle**: `tests/pico_pure_function_oracle.rs` walks
//! every id and every table string through BOTH this library and the real
//! `libzenohpico.so`, comparing `z_encoding_to_string` and the
//! `from_str -> to_string` round trip. A transcription checked against upstream's
//! compiled code is a measurement; one checked against itself is not.
//!
//! ## The id lives PACKED, because that is what wz already had
//!
//! [`EncodingHint::packed_id`] is the WIRE word — `(id << 1) | has_schema` — and
//! this module keeps encodings in exactly that shape rather than unpacking to a
//! `(u16, Option<String>)` pair. Two reasons, and the second is the load-bearing
//! one: the sample accessors hand a decoded `EncodingHint` straight through, so
//! an unpacked intermediate would be a second representation to keep in step;
//! and a schema-present flag that disagreed with the schema actually stored is
//! unrepresentable when the flag is derived at pack time.

use std::ffi::{c_char, c_void, CStr};

use wz_runtime_tokio::sample::EncodingHint;

use crate::abi::{handle_ref, impl_handle_ownership7, z_owned_string_t};
use crate::bytes::store_owned_string;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// pico's `ENCODING_VALUES_ID_TO_STR` (`src/api/encoding.c:89`), 53 entries,
/// index = encoding id.
///
/// Order IS the contract — the index is what goes on the wire — so this is
/// pinned entry-for-entry against `libzenohpico.so` rather than eyeballed.
///
/// `pub` deliberately, and NOT part of the C ABI: it is a Rust constant so the
/// cross-impl test can feed entry `i` to the REAL pico and assert pico assigns
/// it id `i`. That is the only non-circular way to check the order — a
/// `from_str -> to_string` round trip reads the same table in both directions,
/// so it is invariant under ANY permutation, which a damage probe demonstrated
/// by swapping two entries and staying green. See
/// `tests/pico_pure_function_oracle.rs::encoding_ids_agree_with_the_real_pico_library`.
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

/// pico's `ENCODING_SCHEMA_SEPARATOR` (`src/api/encoding.c:25`).
const SCHEMA_SEPARATOR: char = ';';

/// pico's `_Z_ENCODING_ID_DEFAULT` — `zenoh/bytes`, id 0.
const ENCODING_ID_DEFAULT: u16 = 0;

/// Behind a `z_owned_encoding_t`: the wire projection, in the SAME shape the
/// decode path produces.
pub(crate) struct EncodingState {
    pub(crate) hint: EncodingHint,
}

impl EncodingState {
    /// Build from an `id;schema` string exactly as pico's
    /// `_z_encoding_convert_from_substr` does (`src/api/encoding.c:154`).
    ///
    /// The split is on the FIRST separator, and an unrecognised prefix is NOT an
    /// error: the whole string becomes the schema under the default id. That
    /// fallback is why `z_encoding_from_str` has no invalid input.
    pub(crate) fn from_str(s: &str) -> Self {
        if let Some(pos) = s.find(SCHEMA_SEPARATOR) {
            let (prefix, rest) = s.split_at(pos);
            // Skip the separator itself.
            let schema = &rest[SCHEMA_SEPARATOR.len_utf8()..];
            if let Some(id) = lookup_id(prefix) {
                return Self::make(id, schema);
            }
        } else if let Some(id) = lookup_id(s) {
            return Self::make(id, "");
        }
        Self::make(ENCODING_ID_DEFAULT, s)
    }

    fn make(id: u16, schema: &str) -> Self {
        let has_schema = !schema.is_empty();
        Self {
            hint: EncodingHint {
                // The wire word: id in the high bits, schema-present in bit 0.
                // Derived here, so the flag can never disagree with the schema.
                packed_id: (u32::from(id) << 1) | u32::from(has_schema),
                schema: has_schema.then(|| schema.to_owned()),
            },
        }
    }

    /// Render as pico's `_z_encoding_convert_into_string` does: the id's table
    /// entry, then `;schema` when a schema is present. An id past the table
    /// renders as the empty prefix, which is pico's behaviour too (its bounds
    /// check leaves `prefix` NULL and `prefix_len` 0).
    pub(crate) fn to_string(hint: &EncodingHint) -> String {
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
}

/// The table index for `prefix`, or `None`.
///
/// pico compares with `strncmp(schema, TABLE[i], len)` — a PREFIX compare of
/// exactly `len` bytes — so a candidate shorter than the table entry can match
/// it (`"text/j"` matches `"text/json"`). That is upstream's behaviour and it is
/// reproduced rather than corrected: a from_str that disagreed with pico about
/// which id a string means would put a different byte on the wire, which is the
/// one thing this module exists to prevent. The oracle test walks it.
fn lookup_id(candidate: &str) -> Option<u16> {
    ENCODING_ID_TO_STR
        .iter()
        .position(|entry| entry.as_bytes().starts_with(candidate.as_bytes()))
        .map(|i| i as u16)
}

/// Owned encoding (pico `z_owned_encoding_t`, 40 B measured).
#[repr(C)]
pub struct z_owned_encoding_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Loaned encoding (pico `z_loaned_encoding_t`), same footprint.
#[repr(C)]
pub struct z_loaned_encoding_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 4],
}

/// Moved encoding (pico `z_moved_encoding_t`).
#[repr(C)]
pub struct z_moved_encoding_t {
    pub(crate) _this: z_owned_encoding_t,
}

impl z_owned_encoding_t {
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [std::ptr::null_mut(); 4],
        }
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<EncodingState>` pointer.
unsafe fn free_encoding(h: *mut c_void) {
    drop(Box::from_raw(h as *mut EncodingState));
}

impl_handle_ownership7!(
    z_owned_encoding_t,
    z_loaned_encoding_t,
    z_moved_encoding_t,
    free_encoding,
    z_internal_encoding_null,
    z_internal_encoding_check,
    z_encoding_loan,
    z_encoding_loan_mut,
    z_encoding_move,
    z_encoding_take,
    z_encoding_drop
);

/// Store a hint into a caller-provided owned encoding slot.
pub(crate) unsafe fn store_encoding(dst: *mut z_owned_encoding_t, hint: EncodingHint) {
    *dst = z_owned_encoding_t {
        handle: Box::into_raw(Box::new(EncodingState { hint })) as *mut c_void,
        _pad: [std::ptr::null_mut(); 4],
    };
}

/// Read the hint behind a loaned encoding.
pub(crate) unsafe fn encoding_hint<'a>(
    ptr: *const z_loaned_encoding_t,
) -> Option<&'a EncodingHint> {
    handle_ref::<z_loaned_encoding_t, EncodingState>(ptr).map(|state| &state.hint)
}

/// Duplicate an owned encoding into a fresh independent one.
///
/// Needed by the OWNED element families (`z_sample_take_from_loaned` and its
/// siblings): the escaped element must not share the callback marshal's
/// `EncodingState` box, or dropping either would dangle the other. A `null`
/// source yields a `null` result, which is the "carried no encoding" case.
///
/// # Safety
/// `src` must be a live owned encoding this crate produced, or null-valued.
pub(crate) unsafe fn clone_owned_encoding(src: &z_owned_encoding_t) -> z_owned_encoding_t {
    let mut dst = z_owned_encoding_t::null_value();
    let loaned = (src as *const z_owned_encoding_t).cast::<z_loaned_encoding_t>();
    if let Some(hint) = encoding_hint(loaned) {
        store_encoding(&mut dst, hint.clone());
    }
    dst
}

/// Consume a moved encoding, returning its hint and nulling the source so the
/// caller's value cannot be released twice.
///
/// The moved pointer is typed `*mut c_void` at the call sites that receive it
/// inside an options struct, so this takes the concrete type and the callers
/// cast — keeping the unsafe cast at ONE place rather than at each option
/// struct that carries an encoding slot.
pub(crate) unsafe fn take_moved_encoding(moved: *mut c_void) -> Option<EncodingHint> {
    if moved.is_null() {
        return None;
    }
    let slot = moved as *mut *mut c_void;
    let handle = *slot;
    if handle.is_null() {
        return None;
    }
    *slot = std::ptr::null_mut();
    Some(Box::from_raw(handle as *mut EncodingState).hint)
}

// --- exports ---------------------------------------------------------------

/// Build an encoding from a NUL-terminated `id;schema` string (pico
/// `z_encoding_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_str(
    encoding: *mut z_owned_encoding_t,
    s: *const c_char,
) -> ZResult {
    guarded(|| {
        if encoding.is_null() {
            return Z_ERR_NULL;
        }
        // pico nulls the slot first and treats a NULL string as "leave it
        // null", which is a SUCCESS there — an encoding a program never set.
        *encoding = z_owned_encoding_t::null_value();
        if s.is_null() {
            return Z_OK;
        }
        let text = match CStr::from_ptr(s).to_str() {
            Ok(t) => t,
            // Non-UTF-8 cannot be a schema; pico would store the bytes, but wz's
            // `EncodingHint::schema` is a `String`. Reported rather than
            // lossily transcoded.
            Err(_) => return crate::result::Z_ERR_INVALID,
        };
        store_encoding(encoding, EncodingState::from_str(text).hint);
        Z_OK
    })
}

/// Build an encoding from an explicitly-sized `id;schema` substring (pico
/// `z_encoding_from_substr`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_substr(
    encoding: *mut z_owned_encoding_t,
    s: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if encoding.is_null() {
            return Z_ERR_NULL;
        }
        *encoding = z_owned_encoding_t::null_value();
        if s.is_null() {
            return Z_OK;
        }
        let bytes = std::slice::from_raw_parts(s as *const u8, len);
        let text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => return crate::result::Z_ERR_INVALID,
        };
        store_encoding(encoding, EncodingState::from_str(text).hint);
        Z_OK
    })
}

/// Render an encoding as `id;schema` (pico `z_encoding_to_string`).
///
/// A NULL / spent encoding renders as the DEFAULT id's string rather than as an
/// empty one: pico's loaned encoding is never null in a program that got here
/// through `z_sample_encoding`, and reporting `zenoh/bytes` is what a
/// default-constructed encoding means.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_to_string(
    encoding: *const z_loaned_encoding_t,
    string: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if string.is_null() {
            return Z_ERR_NULL;
        }
        let rendered = match encoding_hint(encoding) {
            Some(hint) => EncodingState::to_string(hint),
            None => ENCODING_ID_TO_STR[usize::from(ENCODING_ID_DEFAULT)].to_owned(),
        };
        store_owned_string(string, rendered.as_bytes());
        Z_OK
    })
}

/// Whether two encodings are the same id AND the same schema (pico
/// `z_encoding_equals`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_equals(
    left: *const z_loaned_encoding_t,
    right: *const z_loaned_encoding_t,
) -> bool {
    match (encoding_hint(left), encoding_hint(right)) {
        (Some(a), Some(b)) => a.packed_id == b.packed_id && a.schema == b.schema,
        (None, None) => true,
        _ => false,
    }
}

/// Replace an encoding's schema from a NUL-terminated string (pico
/// `z_encoding_set_schema_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_str(
    encoding: *mut z_loaned_encoding_t,
    schema: *const c_char,
) -> ZResult {
    let len = if schema.is_null() {
        0
    } else {
        CStr::from_ptr(schema).to_bytes().len()
    };
    z_encoding_set_schema_from_substr(encoding, schema, len)
}

/// Replace an encoding's schema from an explicitly-sized substring (pico
/// `z_encoding_set_schema_from_substr`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_substr(
    encoding: *mut z_loaned_encoding_t,
    schema: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        let state = match handle_ref::<z_loaned_encoding_t, EncodingState>(encoding as *const _) {
            Some(s) => s,
            None => return Z_ERR_NULL,
        };
        // `handle_ref` hands back a shared reference; the state behind it is
        // uniquely owned by this handle, and pico's own setter mutates in
        // place through a `z_loaned_*` pointer.
        let state = state as *const EncodingState as *mut EncodingState;
        let text = if schema.is_null() || len == 0 {
            String::new()
        } else {
            let bytes = std::slice::from_raw_parts(schema as *const u8, len);
            match std::str::from_utf8(bytes) {
                Ok(t) => t.to_owned(),
                Err(_) => return crate::result::Z_ERR_INVALID,
            }
        };
        let id = (*state).hint.packed_id >> 1;
        let has_schema = !text.is_empty();
        (*state).hint.packed_id = (id << 1) | u32::from(has_schema);
        (*state).hint.schema = has_schema.then_some(text);
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI size a C program stack-allocates through pico's own header.
    #[test]
    fn encoding_abi_size_matches_pico() {
        assert_eq!(std::mem::size_of::<z_owned_encoding_t>(), 40);
        assert_eq!(std::mem::size_of::<z_moved_encoding_t>(), 40);
    }

    /// The packed id is the WIRE word, and bit 0 is derived from the schema
    /// rather than stored beside it — so the two cannot disagree.
    #[test]
    fn the_schema_flag_is_derived_not_stored() {
        let bare = EncodingState::from_str("text/plain");
        assert_eq!(bare.hint.packed_id & 1, 0, "no schema, flag clear");
        assert_eq!(bare.hint.packed_id >> 1, 4, "text/plain is id 4");
        assert!(bare.hint.schema.is_none());

        let with = EncodingState::from_str("text/plain;utf8");
        assert_eq!(with.hint.packed_id & 1, 1, "schema present, flag set");
        assert_eq!(with.hint.packed_id >> 1, 4);
        assert_eq!(with.hint.schema.as_deref(), Some("utf8"));
    }

    /// An UNRECOGNISED prefix is not an error — the whole string becomes the
    /// schema under the default id, which is pico's fallback and the reason
    /// `z_encoding_from_str` cannot fail on content.
    #[test]
    fn an_unknown_prefix_becomes_a_schema_on_the_default_id() {
        let e = EncodingState::from_str("application/x-made-up-thing-entirely");
        assert_eq!(e.hint.packed_id >> 1, u32::from(ENCODING_ID_DEFAULT));
        assert_eq!(
            e.hint.schema.as_deref(),
            Some("application/x-made-up-thing-entirely")
        );
    }

    /// Round trip through the rendering, for the shapes the attachment
    /// programs actually use. The ORACLE test compares against upstream; this
    /// one keeps the intent readable without a built pico.
    #[test]
    fn to_string_round_trips_the_common_shapes() {
        for s in ["zenoh/bytes", "text/plain", "application/json"] {
            let e = EncodingState::from_str(s);
            assert_eq!(EncodingState::to_string(&e.hint), s);
        }
        let e = EncodingState::from_str("text/plain;utf8");
        assert_eq!(EncodingState::to_string(&e.hint), "text/plain;utf8");
    }
}
