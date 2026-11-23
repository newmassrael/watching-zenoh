// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ENCODING plane — pico's `z_owned_encoding_t`, the `id;schema` string
//! form, and the wire projection wz already carries as
//! [`wz_session_core::sample::EncodingHint`].
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
//!
//! A received message's encoding is not copied into a hint: its state keeps the packed word and
//! reads the schema where the message holds it ([`EncodingState::lent`]), and a copy is made only
//! where a program keeps the sample, the reply or the query.

use core::ffi::{c_char, c_void, CStr};

use crate::prelude::*;

use wz_session_core::sample::EncodingHint;

use crate::abi::{handle_ref, impl_handle_ownership7, z_owned_string_t};
use crate::bytes::store_owned_string;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// pico's `ENCODING_VALUES_ID_TO_STR` (`src/api/encoding.c:89`), 53 entries,
/// index = encoding id.
///
/// R311y545 — the table itself moved out of this crate, and it lives in
/// [`wz_codecs::encoding_ids`] since R311y617, which is where
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
pub use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;

/// pico's `_Z_ENCODING_ID_DEFAULT` — `zenoh/bytes`, id 0. Re-exported from the
/// same SSOT as the table it indexes.
use wz_codecs::encoding_ids::ENCODING_ID_DEFAULT;

/// Behind a `z_owned_encoding_t`, and behind the loaned encoding a sample, a reply or a query
/// hands out: the packed wire word and where the schema lies.
pub(crate) struct EncodingState {
    packed_id: u32,
    schema: Schema,
}

/// Where an encoding's schema lies.
enum Schema {
    /// The encoding carries none.
    Absent,
    /// Bytes of the encoding's own: one a program built or kept.
    Owned(Vec<u8>),
    /// Bytes a received message holds, read where they lie for as long as the marshal that holds
    /// this state does ([`EncodingState::lent`]).
    Lent { start: *const u8, len: usize },
}

// SAFETY: a lent schema is its message's, valid and unchanged for as long as the state lives
// (`EncodingState::lent`), and nothing writes through the pointer, so it is shared between threads
// as the message's own borrow would be; an owned one is a `Vec`.
unsafe impl Send for Schema {}
unsafe impl Sync for Schema {}

/// An encoding as its readers see it: the packed wire word and the schema's bytes, wherever the
/// state keeps them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EncodingView<'a> {
    pub(crate) packed_id: u32,
    pub(crate) schema: Option<&'a [u8]>,
}

impl EncodingView<'_> {
    /// The hint of these parts, its schema a copy: what an encoding a program keeps holds.
    pub(crate) fn to_hint(self) -> EncodingHint {
        EncodingHint {
            packed_id: self.packed_id,
            schema: self.schema.map(<[u8]>::to_vec),
        }
    }

    /// Render as pico's `_z_encoding_convert_into_string` does: the id's table
    /// entry, then `;schema` when a schema is present, the schema copied as the
    /// bytes it is (UTF-8 or not). An id past the table renders as the empty
    /// prefix, which is pico's behaviour too (its bounds check leaves `prefix`
    /// NULL and `prefix_len` 0).
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        wz_session_core::encoding_hint::parts_to_bytes(self.packed_id, self.schema)
    }
}

impl EncodingState {
    /// The state of an encoding of its own.
    pub(crate) fn owned(hint: EncodingHint) -> Self {
        Self {
            packed_id: hint.packed_id,
            schema: match hint.schema {
                Some(schema) => Schema::Owned(schema),
                None => Schema::Absent,
            },
        }
    }

    /// A well-known encoding: its id, no schema.
    const fn constant(id: u16) -> Self {
        Self {
            // The wire word is `(id << 1) | has_schema`, and a constant never carries a schema, so
            // bit 0 is clear by construction rather than by a second field agreeing with the first.
            packed_id: (id as u32) << 1,
            schema: Schema::Absent,
        }
    }

    /// The encoding a received message carried, its schema read where the message holds it, as
    /// zenoh-pico hands its callback the encoding its receive decoded: nothing is copied for it.
    ///
    /// # Safety
    /// The state is dropped before the borrow of `schema` ends.
    pub(crate) unsafe fn lent(packed_id: u32, schema: Option<&[u8]>) -> Self {
        Self {
            packed_id,
            schema: match schema {
                Some(schema) => Schema::Lent {
                    start: schema.as_ptr(),
                    len: schema.len(),
                },
                None => Schema::Absent,
            },
        }
    }

    /// The encoding as its readers see it.
    pub(crate) fn view(&self) -> EncodingView<'_> {
        let schema = match &self.schema {
            Schema::Absent => None,
            Schema::Owned(schema) => Some(schema.as_slice()),
            // SAFETY: a lent schema outlives the state that holds it (`Self::lent`), and a slice's
            // start is never null.
            Schema::Lent { start, len } => {
                Some(unsafe { core::slice::from_raw_parts(*start, *len) })
            }
        };
        EncodingView {
            packed_id: self.packed_id,
            schema,
        }
    }

    /// A state of its own with the same encoding: what a sample, a reply or a query kept past its
    /// callback holds, whose message's bytes it may outlive.
    pub(crate) fn kept(&self) -> Self {
        Self::owned(self.view().to_hint())
    }

    /// The encoding as a hint, the schema moved out of an owned state rather than copied.
    fn into_hint(self) -> EncodingHint {
        let packed_id = self.packed_id;
        match self.schema {
            Schema::Owned(schema) => EncodingHint {
                packed_id,
                schema: Some(schema),
            },
            schema => {
                let state = Self { packed_id, schema };
                state.view().to_hint()
            }
        }
    }

    /// Replace the schema with `bytes`, the flag of the wire word following it; empty bytes take
    /// the schema away.
    fn set_schema(&mut self, bytes: &[u8]) {
        let id = self.packed_id >> 1;
        let has_schema = !bytes.is_empty();
        self.packed_id = (id << 1) | u32::from(has_schema);
        self.schema = if has_schema {
            Schema::Owned(bytes.to_vec())
        } else {
            Schema::Absent
        };
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
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 4],
        }
    }
}

impl z_loaned_encoding_t {
    /// A loaned view not yet pointed at anything: what a marshal holds until it binds the view to
    /// the encoding it keeps in itself, at its final address.
    pub(crate) const fn unbound() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 4],
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
        handle: Box::into_raw(Box::new(EncodingState::owned(hint))) as *mut c_void,
        _pad: [core::ptr::null_mut(); 4],
    };
}

/// Read the encoding behind a loaned encoding, where its state keeps it.
pub(crate) unsafe fn encoding_view<'a>(
    ptr: *const z_loaned_encoding_t,
) -> Option<EncodingView<'a>> {
    handle_ref::<z_loaned_encoding_t, EncodingState>(ptr).map(EncodingState::view)
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
    *slot = core::ptr::null_mut();
    Some(Box::from_raw(handle as *mut EncodingState).into_hint())
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
        // pico stores the bytes it is handed, UTF-8 or not, and so does this.
        let bytes = CStr::from_ptr(s).to_bytes();
        store_encoding(
            encoding,
            wz_session_core::encoding_hint::hint_from_bytes(bytes),
        );
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
        let bytes = core::slice::from_raw_parts(s.cast::<u8>(), len);
        store_encoding(
            encoding,
            wz_session_core::encoding_hint::hint_from_bytes(bytes),
        );
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
        let rendered = match encoding_view(encoding) {
            Some(view) => view.to_bytes(),
            None => ENCODING_ID_TO_STR
                .get(usize::from(ENCODING_ID_DEFAULT))
                .copied()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
        };
        store_owned_string(string, &rendered)
    })
}

/// Whether two encodings are the same id AND the same schema (pico
/// `z_encoding_equals`).
#[no_mangle]
pub unsafe extern "C" fn z_encoding_equals(
    left: *const z_loaned_encoding_t,
    right: *const z_loaned_encoding_t,
) -> bool {
    encoding_view(left) == encoding_view(right)
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
        // pico copies the bytes it is handed and asks nothing of them
        // (`src/api/encoding.c`, `z_encoding_set_schema_from_substr` ->
        // `_z_string_copy_from_substr`), so a schema that is not UTF-8 is set.
        let bytes: &[u8] = if schema.is_null() || len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(schema.cast::<u8>(), len)
        };
        (*state).set_schema(bytes);
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
        _pad: [core::ptr::null_mut(); 4],
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
/// [`wz_codecs::encoding_ids::ENCODING_ID_TO_STR`], indexed by the same id,
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
            static STATE: EncodingState = EncodingState::constant($id);
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
/// `EncodingState` a program built with [`z_encoding_from_str`], and
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
        match encoding_view(this_) {
            Some(view) => {
                store_encoding(dst, view.to_hint());
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
/// `impl_value_ownership` because that
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
        (*src).handle = core::ptr::null_mut();
        (*src)._pad = [core::ptr::null_mut(); 4];
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `z_encoding_from_str` stores for `s`: its bytes, split as pico's
    /// `_z_encoding_convert_from_substr` splits them.
    fn parsed(s: &str) -> EncodingHint {
        wz_session_core::encoding_hint::hint_from_bytes(s.as_bytes())
    }

    /// What `z_encoding_to_string` hands back for `hint`, read as text.
    fn rendered(hint: &EncodingHint) -> String {
        String::from_utf8(wz_session_core::encoding_hint::hint_to_bytes(hint))
            .expect("a UTF-8 encoding renders as text")
    }

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
            let hint = unsafe { encoding_view(view) }.expect("a constant is never absent");
            assert_eq!(hint.packed_id >> 1, id, "wire id");
            assert_eq!(hint.packed_id & 1, 0, "a constant carries no schema");
            let text = rendered(&hint.to_hint());
            assert_eq!(
                text, ENCODING_ID_TO_STR[id as usize],
                "a constant renders as its table entry"
            );
            assert_eq!(
                parsed(&text).packed_id,
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
                encoding_view(loaned).expect("cloned").packed_id,
                encoding_view(z_encoding_text_plain())
                    .expect("constant")
                    .packed_id
            );
            z_encoding_drop(z_encoding_move(&mut owned));
            assert!(!z_internal_encoding_check(&owned));
            // The constant is still readable, which a handle copy would have
            // made false.
            assert_eq!(
                encoding_view(z_encoding_text_plain())
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
            store_encoding(&mut src, parsed("text/plain;utf8"));
            // Dirty every pad slot so an under-wide clear is visible.
            src._pad = [1usize as *mut c_void; 4];
            let loaned = z_encoding_loan_mut(&mut src);
            assert_eq!(z_encoding_take_from_loaned(&mut dst, loaned), Z_OK);
            assert!(!z_internal_encoding_check(&src), "source emptied");
            assert!(src._pad.iter().all(|p| p.is_null()), "all four pad slots");
            assert_eq!(
                encoding_view(z_encoding_loan(&dst)).expect("moved").schema,
                Some(&b"utf8"[..])
            );
            z_encoding_drop(z_encoding_move(&mut dst));
        }
    }

    /// The ABI size a C program stack-allocates through pico's own header: five words, 40 B on a
    /// 64-bit host (`csrc/pico_layout_pins.c` holds the count against the header on any other).
    #[test]
    fn encoding_abi_size_matches_pico() {
        let words = 5 * core::mem::size_of::<*mut c_void>();
        assert_eq!(core::mem::size_of::<z_owned_encoding_t>(), words);
        assert_eq!(core::mem::size_of::<z_moved_encoding_t>(), words);
    }

    /// The packed id is the WIRE word, and bit 0 is derived from the schema
    /// rather than stored beside it — so the two cannot disagree.
    #[test]
    fn the_schema_flag_is_derived_not_stored() {
        let bare = parsed("text/plain");
        assert_eq!(bare.packed_id & 1, 0, "no schema, flag clear");
        assert_eq!(bare.packed_id >> 1, 4, "text/plain is id 4");
        assert!(bare.schema.is_none());

        let with = parsed("text/plain;utf8");
        assert_eq!(with.packed_id & 1, 1, "schema present, flag set");
        assert_eq!(with.packed_id >> 1, 4);
        assert_eq!(with.schema.as_deref(), Some(&b"utf8"[..]));
    }

    /// An UNRECOGNISED prefix is not an error — the whole string becomes the
    /// schema under the default id, which is pico's fallback and the reason
    /// `z_encoding_from_str` cannot fail on content.
    #[test]
    fn an_unknown_prefix_becomes_a_schema_on_the_default_id() {
        let e = parsed("application/x-made-up-thing-entirely");
        assert_eq!(e.packed_id >> 1, u32::from(ENCODING_ID_DEFAULT));
        assert_eq!(
            e.schema.as_deref(),
            Some(&b"application/x-made-up-thing-entirely"[..])
        );
    }

    /// zenoh-pico's contract for a schema that is not UTF-8: the setter copies
    /// the bytes it is handed (`src/api/encoding.c`,
    /// `z_encoding_set_schema_from_substr`), and `z_encoding_to_string` hands
    /// them back as they are after the id's name and `;`.
    #[test]
    fn a_schema_that_is_not_utf8_is_set_and_rendered_as_its_bytes() {
        let raw: &[u8] = &[0xFF, 0xFE, b'x'];
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: live locals.
        unsafe {
            store_encoding(&mut owned, parsed("text/plain"));
            assert_eq!(
                z_encoding_set_schema_from_substr(
                    z_encoding_loan_mut(&mut owned),
                    raw.as_ptr().cast(),
                    raw.len()
                ),
                Z_OK
            );
            let hint = encoding_view(z_encoding_loan(&owned)).expect("set");
            assert_eq!(hint.schema, Some(raw));
            let mut want = b"text/plain;".to_vec();
            want.extend_from_slice(raw);
            assert_eq!(hint.to_bytes(), want);
            z_encoding_drop(z_encoding_move(&mut owned));
        }
    }

    /// A received encoding's schema is read where the message holds it, not copied; a kept copy
    /// owns its bytes and reads the same after the message is gone; a schema set on the received
    /// encoding is the encoding's own; one with no schema reads as none.
    #[test]
    fn a_received_schema_is_read_where_it_lies_and_kept_as_a_copy() {
        let message = b"utf8".to_vec();
        // SAFETY: the state is dropped before `message`.
        let mut received = unsafe { EncodingState::lent((4 << 1) | 1, Some(message.as_slice())) };
        let view = received.view();
        assert_eq!(view.packed_id, (4 << 1) | 1);
        assert_eq!(
            view.schema.map(<[u8]>::as_ptr),
            Some(message.as_ptr()),
            "the schema is the message's own bytes"
        );
        assert_eq!(view.to_bytes(), b"text/plain;utf8".to_vec());

        let kept = received.kept();
        let kept_schema = kept.view().schema.expect("kept");
        assert_ne!(
            kept_schema.as_ptr(),
            message.as_ptr(),
            "a kept copy owns its bytes"
        );
        assert_eq!(kept_schema, b"utf8");

        received.set_schema(b"other");
        let set = received.view().schema.expect("set");
        assert_ne!(
            set.as_ptr(),
            message.as_ptr(),
            "a set schema is the state's own"
        );
        assert_eq!(set, b"other");
        received.set_schema(&[]);
        assert_eq!(
            received.view(),
            EncodingView {
                packed_id: 4 << 1,
                schema: None
            }
        );
        drop(received);
        drop(message);
        assert_eq!(kept.view().to_bytes(), b"text/plain;utf8".to_vec());
        assert_eq!(kept.into_hint(), parsed("text/plain;utf8"));

        // SAFETY: a state of no schema borrows nothing.
        let bare = unsafe { EncodingState::lent(4 << 1, None) };
        assert_eq!(bare.view().schema, None);
    }

    /// Round trip through the rendering, for the shapes the attachment
    /// programs actually use. The ORACLE test compares against upstream; this
    /// one keeps the intent readable without a built pico.
    #[test]
    fn to_string_round_trips_the_common_shapes() {
        for s in ["zenoh/bytes", "text/plain", "application/json"] {
            assert_eq!(rendered(&parsed(s)), s);
        }
        assert_eq!(rendered(&parsed("text/plain;utf8")), "text/plain;utf8");
    }
}
