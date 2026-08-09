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
/// R311y545 — the table itself moved to
/// [`wz_capi_core::encoding_ids`](wz_capi_core::encoding_ids), which is where
/// an ABI-neutral wire fact belongs: `wz-capi-c`'s `z_encoding_*` constants
/// need the SAME ids, and two transcriptions of one wire table drift in a way
/// neither crate's own tests can see. This stays as a re-export so the
/// cross-impl oracle keeps naming the constant it always named — and so it
/// keeps gating the SSOT rather than a copy of it.
///
/// `pub` deliberately, and NOT part of the C ABI: it is a Rust constant so the
/// cross-impl test can feed entry `i` to the REAL pico and assert pico assigns
/// it id `i`. That is the only non-circular way to check the order — a
/// `from_str -> to_string` round trip reads the same table in both directions,
/// so it is invariant under ANY permutation, which a damage probe demonstrated
/// by swapping two entries and staying green. See
/// `wz-integration-tests/tests/pico_pure_function_oracle.rs::encoding_ids_agree_with_the_real_pico_library`
/// — R311y618 corrected the crate this path names: it said `tests/` of THIS
/// crate, where the oracle has never lived, and a reader following it found
/// nothing. The oracle needs the real `libzenohpico.so`, so it can only live
/// where the interop harness does.
pub use wz_capi_core::encoding_ids::ENCODING_ID_TO_STR;

/// pico's `_Z_ENCODING_ID_DEFAULT` — `zenoh/bytes`, id 0. Re-exported from the
/// same SSOT as the table it indexes.
use wz_capi_core::encoding_ids::ENCODING_ID_DEFAULT;

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
        Self {
            hint: wz_capi_core::encoding_ids::hint_from_str(s),
        }
    }

    /// Render as pico's `_z_encoding_convert_into_string` does: the id's table
    /// entry, then `;schema` when a schema is present. An id past the table
    /// renders as the empty prefix, which is pico's behaviour too (its bounds
    /// check leaves `prefix` NULL and `prefix_len` 0).
    pub(crate) fn to_string(hint: &EncodingHint) -> String {
        wz_capi_core::encoding_ids::hint_to_string(hint)
    }
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

// --- the well-known constants ----------------------------------------------

/// A loaned encoding view that lives for the whole program.
///
/// `z_loaned_encoding_t` holds a raw pointer, so it is not `Sync` and cannot be
/// a `static` on its own. This newtype carries the argument that makes it safe:
/// the value is written ONCE at compile time, never mutated, and its handle
/// points at a `'static` [`EncodingState`] — so every thread reads the same
/// immutable bytes pointing at the same immutable state.
#[repr(transparent)]
pub(crate) struct StaticLoanedEncoding(z_loaned_encoding_t);

// SAFETY: see the type's docs — immutable after compile time, pointing at a
// `'static`.
unsafe impl Sync for StaticLoanedEncoding {}

/// Build the `'static` loaned view for a `'static` state.
const fn static_view(state: &'static EncodingState) -> StaticLoanedEncoding {
    StaticLoanedEncoding(z_loaned_encoding_t {
        handle: state as *const EncodingState as *mut c_void,
        _pad: [std::ptr::null_mut(); 4],
    })
}

/// Emit one of pico's `ENCODING_CONSTANT_MACRO` entries
/// (`src/api/encoding.c:27-33`): a `'static` state at the given wire id, its
/// `'static` loaned view, and the exported accessor.
///
/// The state and the view are function-scoped statics rather than module-level
/// ones so the macro needs only the pair upstream's own macro needs — the
/// exported name and the id — instead of two invented Rust identifiers per
/// entry. A hand-maintained second name list is a transcription with no oracle,
/// which is the failure class this crate has already paid for once.
///
/// The MIME string is NOT repeated here. It lives once in
/// [`wz_capi_core::encoding_ids::ENCODING_ID_TO_STR`], indexed by the same id,
/// so `z_encoding_to_string` on a constant renders through the identical table
/// the wire codec uses. The (name -> id) pairing below is the only transcribed
/// fact, and it is adjudicated against upstream's COMPILED library by
/// `tests/pico_pure_function_oracle.rs::encoding_constants_agree_with_the_real_pico_library`,
/// which walks every accessor in both implementations and compares the rendered
/// string. A wrong id there is a visible mismatch, not a silent one.
macro_rules! encoding_constant {
    ($fname:ident, $id:expr) => {
        /// A well-known encoding constant (pico `ENCODING_CONSTANT_MACRO`).
        ///
        /// The returned pointer is valid for the whole program: it points at a
        /// `'static`, so a caller may hold it past any session, and there is
        /// nothing to release.
        #[no_mangle]
        pub extern "C" fn $fname() -> *const z_loaned_encoding_t {
            static STATE: EncodingState = EncodingState {
                hint: EncodingHint {
                    // The wire word is `(id << 1) | has_schema`, and a constant
                    // never carries a schema — so bit 0 is clear by
                    // construction rather than by a second field agreeing with
                    // the first.
                    packed_id: ($id as u32) << 1,
                    schema: None,
                },
            };
            static VIEW: StaticLoanedEncoding = static_view(&STATE);
            &VIEW.0 as *const z_loaned_encoding_t
        }
    };
}

encoding_constant!(z_encoding_zenoh_bytes, 0);
encoding_constant!(z_encoding_zenoh_string, 1);
encoding_constant!(z_encoding_zenoh_serialized, 2);
encoding_constant!(z_encoding_application_octet_stream, 3);
encoding_constant!(z_encoding_text_plain, 4);
encoding_constant!(z_encoding_application_json, 5);
encoding_constant!(z_encoding_text_json, 6);
encoding_constant!(z_encoding_application_cdr, 7);
encoding_constant!(z_encoding_application_cbor, 8);
encoding_constant!(z_encoding_application_yaml, 9);
encoding_constant!(z_encoding_text_yaml, 10);
encoding_constant!(z_encoding_text_json5, 11);
encoding_constant!(z_encoding_application_python_serialized_object, 12);
encoding_constant!(z_encoding_application_protobuf, 13);
encoding_constant!(z_encoding_application_java_serialized_object, 14);
encoding_constant!(z_encoding_application_openmetrics_text, 15);
encoding_constant!(z_encoding_image_png, 16);
encoding_constant!(z_encoding_image_jpeg, 17);
encoding_constant!(z_encoding_image_gif, 18);
encoding_constant!(z_encoding_image_bmp, 19);
encoding_constant!(z_encoding_image_webp, 20);
encoding_constant!(z_encoding_application_xml, 21);
encoding_constant!(z_encoding_application_x_www_form_urlencoded, 22);
encoding_constant!(z_encoding_text_html, 23);
encoding_constant!(z_encoding_text_xml, 24);
encoding_constant!(z_encoding_text_css, 25);
encoding_constant!(z_encoding_text_javascript, 26);
encoding_constant!(z_encoding_text_markdown, 27);
encoding_constant!(z_encoding_text_csv, 28);
encoding_constant!(z_encoding_application_sql, 29);
encoding_constant!(z_encoding_application_coap_payload, 30);
encoding_constant!(z_encoding_application_json_patch_json, 31);
encoding_constant!(z_encoding_application_json_seq, 32);
encoding_constant!(z_encoding_application_jsonpath, 33);
encoding_constant!(z_encoding_application_jwt, 34);
encoding_constant!(z_encoding_application_mp4, 35);
encoding_constant!(z_encoding_application_soap_xml, 36);
encoding_constant!(z_encoding_application_yang, 37);
encoding_constant!(z_encoding_audio_aac, 38);
encoding_constant!(z_encoding_audio_flac, 39);
encoding_constant!(z_encoding_audio_mp4, 40);
encoding_constant!(z_encoding_audio_ogg, 41);
encoding_constant!(z_encoding_audio_vorbis, 42);
encoding_constant!(z_encoding_video_h261, 43);
encoding_constant!(z_encoding_video_h263, 44);
encoding_constant!(z_encoding_video_h264, 45);
encoding_constant!(z_encoding_video_h265, 46);
encoding_constant!(z_encoding_video_h266, 47);
encoding_constant!(z_encoding_video_mp4, 48);
encoding_constant!(z_encoding_video_ogg, 49);
encoding_constant!(z_encoding_video_raw, 50);
encoding_constant!(z_encoding_video_vp8, 51);
encoding_constant!(z_encoding_video_vp9, 52);

/// The encoding a default-constructed value means (pico
/// `z_encoding_loan_default`, `src/api/encoding.c:266`) — literally upstream's
/// own body, `zenoh/bytes`.
#[no_mangle]
pub extern "C" fn z_encoding_loan_default() -> *const z_loaned_encoding_t {
    z_encoding_zenoh_bytes()
}

/// Duplicate an encoding into a fresh owned one (pico `z_encoding_clone`).
///
/// A DEEP copy, unlike the sibling zenoh-c ABI's handle copy. It has to be: the
/// source may be one of the `'static` constants above OR a heap
/// [`EncodingState`] a program built with [`z_encoding_from_str`], and
/// [`z_encoding_drop`] frees its handle. Copying the hint makes those two
/// sources indistinguishable to the caller, which is what upstream's
/// `_z_encoding_copy` does.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_clone(
    dst: *mut z_owned_encoding_t,
    this_: *const z_loaned_encoding_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_encoding_t::null_value();
        match encoding_hint(this_) {
            Some(hint) => {
                store_encoding(dst, hint.clone());
                Z_OK
            }
            // A null / spent source clones to a null destination, which is the
            // shape `z_internal_encoding_check` reports as absent. Upstream
            // copies an empty encoding here rather than failing.
            None => Z_OK,
        }
    })
}

/// Adopt a loaned encoding into an owned one, emptying the source (pico
/// `z_encoding_take_from_loaned`).
///
/// Hand-written rather than emitted by
/// [`impl_value_ownership`](crate::abi::impl_value_ownership) because that
/// macro clears a THREE-slot pad and `z_owned_encoding_t` carries four; a
/// wrong-width clear would leave a stale pointer word in the source the caller
/// is entitled to reuse.
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a valid loaned
/// encoding this crate produced.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_take_from_loaned(
    dst: *mut z_owned_encoding_t,
    src: *mut z_loaned_encoding_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_encoding_t {
            handle: (*src).handle,
            _pad: (*src)._pad,
        };
        (*src).handle = std::ptr::null_mut();
        (*src)._pad = [std::ptr::null_mut(); 4];
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every constant renders through the SAME table the wire codec uses, so a
    /// constant and a `z_encoding_from_str` of its own string are one value.
    ///
    /// This is the LOCAL half of the claim — it cannot catch a wrong (name ->
    /// id) pairing, because both sides of the comparison read the same table.
    /// The oracle leg in `tests/pico_pure_function_oracle.rs` is what pins the
    /// pairing against upstream's compiled library.
    #[test]
    fn every_constant_round_trips_through_the_id_table() {
        // SAFETY: each accessor returns a `'static` view.
        let cases: [(*const z_loaned_encoding_t, u32); 5] = [
            (z_encoding_zenoh_bytes(), 0),
            (z_encoding_text_plain(), 4),
            (z_encoding_application_json(), 5),
            (z_encoding_application_octet_stream(), 3),
            (z_encoding_video_vp9(), 52),
        ];
        for (view, id) in cases {
            // SAFETY: a `'static` view this module minted.
            let hint = unsafe { encoding_hint(view) }.expect("a constant is never absent");
            assert_eq!(hint.packed_id >> 1, id, "wire id");
            assert_eq!(hint.packed_id & 1, 0, "a constant carries no schema");
            let rendered = EncodingState::to_string(hint);
            assert_eq!(
                rendered, ENCODING_ID_TO_STR[id as usize],
                "a constant renders as its table entry"
            );
            assert_eq!(
                EncodingState::from_str(&rendered).hint.packed_id,
                hint.packed_id,
                "and parsing that string back lands on the same id"
            );
        }
    }

    /// `z_encoding_loan_default` is `zenoh/bytes`, and it is the SAME pointer —
    /// upstream's body delegates, so a caller comparing the two by identity (as
    /// `z_encoding_equals` callers do by value) sees agreement either way.
    #[test]
    fn loan_default_is_zenoh_bytes() {
        assert_eq!(z_encoding_loan_default(), z_encoding_zenoh_bytes());
        // SAFETY: two `'static` views.
        assert!(unsafe { z_encoding_equals(z_encoding_loan_default(), z_encoding_zenoh_bytes()) });
    }

    /// A clone of a `'static` constant is an INDEPENDENT owned value: dropping
    /// it must not attempt to free the constant. Pinned by cloning, dropping,
    /// and then reading the constant again — a handle copy would have freed a
    /// `'static` and this would be a use-after-free under any sanitizer.
    #[test]
    fn cloning_a_constant_yields_an_independently_droppable_value() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: a live local and a `'static` view.
        unsafe {
            assert_eq!(z_encoding_clone(&mut owned, z_encoding_text_plain()), Z_OK);
            assert!(z_internal_encoding_check(&owned));
            let loaned = z_encoding_loan(&owned);
            assert_eq!(
                encoding_hint(loaned).expect("cloned").packed_id,
                encoding_hint(z_encoding_text_plain())
                    .expect("constant")
                    .packed_id
            );
            z_encoding_drop(z_encoding_move(&mut owned));
            assert!(!z_internal_encoding_check(&owned));
            // The constant is still readable, which a handle copy would have
            // made false.
            assert_eq!(
                encoding_hint(z_encoding_text_plain())
                    .expect("the constant survived its clone's drop")
                    .packed_id
                    >> 1,
                4
            );
        }
    }

    /// `take_from_loaned` moves the handle and EMPTIES the source, including
    /// the fourth pad slot the shared macro would have left behind.
    #[test]
    fn take_from_loaned_empties_all_four_pad_slots() {
        let mut src = z_owned_encoding_t::null_value();
        let mut dst = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            store_encoding(&mut src, EncodingState::from_str("text/plain;utf8").hint);
            // Dirty every pad slot so an under-wide clear is visible.
            src._pad = [1usize as *mut c_void; 4];
            let loaned = z_encoding_loan_mut(&mut src);
            assert_eq!(z_encoding_take_from_loaned(&mut dst, loaned), Z_OK);
            assert!(!z_internal_encoding_check(&src), "source emptied");
            assert!(src._pad.iter().all(|p| p.is_null()), "all four pad slots");
            assert_eq!(
                encoding_hint(z_encoding_loan(&dst))
                    .expect("moved")
                    .schema
                    .as_deref(),
                Some("utf8")
            );
            z_encoding_drop(z_encoding_move(&mut dst));
        }
    }

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
