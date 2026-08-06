// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Encodings — the MIME-ish label a publisher attaches to its payload.
//!
//! ## The constants are generated FROM the wire table, not transcribed beside it
//!
//! Upstream exports 53 constants (`z_encoding_text_plain`, `z_encoding_zenoh_bytes`,
//! …) as functions returning a `const z_loaned_encoding_t*`. Each names one entry
//! of the zenoh encoding table, and that table already lives once in
//! [`wz_capi_core::encoding_ids::ENCODING_ID_TO_STR`], pinned entry-for-entry
//! against the real `libzenohpico.so` by `wz-capi-pico`'s oracle.
//!
//! So [`encoding_constants!`] takes a function name and a table INDEX, and the
//! label is read out of the shared table. A constant whose label were written
//! here would be a second transcription of a wire value — the exact shape this
//! workspace has watched drift — and the index is the wire id, so getting it
//! wrong is a wire defect rather than a cosmetic one. The index is checked by
//! `upstream_encoding_constants_on_wz_capi_c_match_real_libzenohc`, which asks
//! BOTH libraries what each constant renders as and diffs the two lists.
//!
//! R311y564 — this family used to export THREE of the 53. The scope rule for
//! this crate is a PROGRAM rather than a symbol list, and under that rule the
//! other fifty looked like a hand-picked list. They are not: they are the rest
//! of one table, they are what `libzenohc.so` DEFINES, and a C program naming
//! any of them did not link. That is the census question, and it is not the
//! corpus question.
//!
//! ## An encoding can now be HEAP-OWNED, and that changes drop
//!
//! [`z_encoding_from_str`] builds a label the caller supplied, so the "every
//! label is `'static`, drop frees nothing" invariant this module used to rest
//! on is gone. [`EncodingState::heap`] carries the distinction and the three
//! places that care — [`z_encoding_clone`], [`z_encoding_drop`] and
//! [`take_moved_encoding`] — all read it, so a constant is still never freed
//! and a caller's string is still never leaked.

use std::borrow::Cow;
use std::ffi::{c_char, c_void};

use wz_runtime_tokio::sample::EncodingHint;

use crate::abi::{z_loaned_encoding_t, z_moved_encoding_t, z_owned_encoding_t, Handle};
use crate::ffi::{guard_val, guarded};
use crate::result::{Z_ENULL, Z_OK};

/// The label behind an encoding handle.
///
/// `Cow` rather than `&'static str`: the 53 constants below are `'static` and
/// must never be freed, while [`z_encoding_from_str`] owns a caller-supplied
/// string that must be. `heap` is the discriminant the free path reads — it is
/// not derivable from the `Cow` variant, because a heap state may legitimately
/// hold a `Borrowed` label after a schema-free clone.
pub(crate) struct EncodingState {
    pub(crate) label: Cow<'static, str>,
    /// `false` for the 53 constant statics; `true` for a `Box`ed state.
    heap: bool,
}

impl EncodingState {
    /// The `'static` state for table entry `id`.
    const fn constant(id: usize) -> Self {
        Self {
            label: Cow::Borrowed(wz_capi_core::encoding_ids::ENCODING_ID_TO_STR[id]),
            heap: false,
        }
    }

    /// A heap state carrying a caller-supplied label.
    fn owned(label: String) -> Self {
        Self {
            label: Cow::Owned(label),
            heap: true,
        }
    }
}

/// A loaned encoding view that lives for the whole program.
///
/// `z_loaned_encoding_t` holds a raw pointer, so it is not `Sync` and cannot be a
/// `static` on its own. This newtype carries the argument that makes it safe:
/// the value is written ONCE at compile time, never mutated, and its handle
/// points at a `'static` [`EncodingState`] — so every thread reads the same
/// immutable bytes pointing at the same immutable state.
///
/// The alternative — minting a view per call — would hand the C side a pointer
/// whose lifetime nothing owns, and upstream's constants are documented as valid
/// indefinitely.
#[repr(transparent)]
struct StaticLoanedEncoding(z_loaned_encoding_t);

// SAFETY: see the type's docs — immutable after compile time, pointing at a
// `'static`.
unsafe impl Sync for StaticLoanedEncoding {}

/// Build the `'static` loaned view for a `'static` state.
const fn static_view(state: &'static EncodingState) -> StaticLoanedEncoding {
    StaticLoanedEncoding(z_loaned_encoding_t {
        handle: state as *const EncodingState as *mut c_void,
        // Sized from the SAME constant `define_opaque!` uses, not a repeated
        // literal: `z_owned_encoding_t` moves with `Z_FEATURE_SHARED_MEMORY`
        // (40 -> 48), and a second copy of the number here compiled fine on the
        // default arm while breaking the SHM one.
        _pad: [0u8; crate::abi::ENCODING_SIZE - std::mem::size_of::<Handle>()],
    })
}

/// Emit one upstream encoding constant per `(name, table index)` pair.
///
/// The index is the WIRE id, so it is the whole content of each entry; the label
/// is read out of [`wz_capi_core::encoding_ids::ENCODING_ID_TO_STR`] rather than
/// repeated here. Both the state and its view are function-local `static`s, so
/// the pointer a caller receives is stable for the life of the process — which is
/// what upstream documents and what a C program comparing two calls relies on.
macro_rules! encoding_constants {
    ($($name:ident => $id:expr),+ $(,)?) => {
        $(
            #[doc = concat!(
                "zenoh-c `", stringify!($name), "` — the shared encoding table's \
                 entry at wire id ", stringify!($id), "."
            )]
            #[no_mangle]
            pub extern "C" fn $name() -> *const z_loaned_encoding_t {
                static STATE: EncodingState = EncodingState::constant($id);
                static VIEW: StaticLoanedEncoding = static_view(&STATE);
                &VIEW.0 as *const z_loaned_encoding_t
            }
        )+

        /// Every constant this crate exports, paired with the table index it
        /// claims — the list the oracle differential walks.
        #[cfg(test)]
        const CONSTANTS: &[(&str, usize, extern "C" fn() -> *const z_loaned_encoding_t)] = &[
            $((stringify!($name), $id, $name)),+
        ];
    };
}

encoding_constants! {
    z_encoding_zenoh_bytes => 0,
    z_encoding_zenoh_string => 1,
    z_encoding_zenoh_serialized => 2,
    z_encoding_application_octet_stream => 3,
    z_encoding_text_plain => 4,
    z_encoding_application_json => 5,
    z_encoding_text_json => 6,
    z_encoding_application_cdr => 7,
    z_encoding_application_cbor => 8,
    z_encoding_application_yaml => 9,
    z_encoding_text_yaml => 10,
    z_encoding_text_json5 => 11,
    z_encoding_application_python_serialized_object => 12,
    z_encoding_application_protobuf => 13,
    z_encoding_application_java_serialized_object => 14,
    z_encoding_application_openmetrics_text => 15,
    z_encoding_image_png => 16,
    z_encoding_image_jpeg => 17,
    z_encoding_image_gif => 18,
    z_encoding_image_bmp => 19,
    z_encoding_image_webp => 20,
    z_encoding_application_xml => 21,
    z_encoding_application_x_www_form_urlencoded => 22,
    z_encoding_text_html => 23,
    z_encoding_text_xml => 24,
    z_encoding_text_css => 25,
    z_encoding_text_javascript => 26,
    z_encoding_text_markdown => 27,
    z_encoding_text_csv => 28,
    z_encoding_application_sql => 29,
    z_encoding_application_coap_payload => 30,
    z_encoding_application_json_patch_json => 31,
    z_encoding_application_json_seq => 32,
    z_encoding_application_jsonpath => 33,
    z_encoding_application_jwt => 34,
    z_encoding_application_mp4 => 35,
    z_encoding_application_soap_xml => 36,
    z_encoding_application_yang => 37,
    z_encoding_audio_aac => 38,
    z_encoding_audio_flac => 39,
    z_encoding_audio_mp4 => 40,
    z_encoding_audio_ogg => 41,
    z_encoding_audio_vorbis => 42,
    z_encoding_video_h261 => 43,
    z_encoding_video_h263 => 44,
    z_encoding_video_h264 => 45,
    z_encoding_video_h265 => 46,
    z_encoding_video_h266 => 47,
    z_encoding_video_mp4 => 48,
    z_encoding_video_ogg => 49,
    z_encoding_video_raw => 50,
    z_encoding_video_vp8 => 51,
    z_encoding_video_vp9 => 52,
}

/// Read the label behind a loaned encoding.
///
/// # Safety
/// `this_` must be null, or a valid loaned encoding whose handle slot holds a
/// live `EncodingState` pointer.
pub(crate) unsafe fn encoding_label<'a>(this_: *const z_loaned_encoding_t) -> Option<&'a str> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(&unsafe { &*(handle as *const EncodingState) }.label)
}

/// The WIRE projection of a loaned encoding, or `None` when the handle is a
/// gravestone.
///
/// R311y545 — the bridge between this crate's labels and
/// [`PublishOptions::with_encoding`](wz_runtime_tokio::session::PublishOptions).
/// The lookup runs per call rather than being baked into the statics because
/// [`EncodingHint`] owns an `Option<String>` schema, which no `const` can
/// build; the table walk is 53 prefix compares against a label the caller
/// already had to allocate an options struct for.
///
/// # Safety
/// `this_` must be null, or a valid loaned encoding whose handle slot holds a
/// live [`EncodingState`] pointer.
pub(crate) unsafe fn encoding_hint(this_: *const z_loaned_encoding_t) -> Option<EncodingHint> {
    // SAFETY: the caller's contract.
    let label = unsafe { encoding_label(this_) }?;
    Some(wz_capi_core::encoding_ids::hint_from_str_in(
        label,
        wz_capi_core::encoding_ids::EncodingDialect::ZenohC,
    ))
}

/// CONSUME a moved encoding: read its wire projection, gravestone the caller's
/// slot, and free the state when it was heap-owned.
///
/// Every options struct carries the encoding as `z_moved_encoding_t*`, which
/// upstream documents as consumed on every path including the error ones. Before
/// R311y564 this was a READ, justified by every label being `'static`; that
/// justification expired with [`z_encoding_from_str`], and a read would now leak
/// the caller's string and leave their owned value non-null.
///
/// # Safety
/// `moved` must be null, or a valid, writable moved encoding.
pub(crate) unsafe fn take_moved_encoding(moved: *mut z_moved_encoding_t) -> Option<EncodingHint> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract — `z_owned_encoding_t` and
    // `z_loaned_encoding_t` are the same footprint, and the owned value is the
    // first (only) field of the moved wrapper.
    let handle = unsafe { (*moved)._this.handle };
    unsafe { (*moved)._this = z_owned_encoding_t::null_value() };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a non-null handle always points at a live `EncodingState`.
    let state = unsafe { &*(handle as *const EncodingState) };
    let hint = wz_capi_core::encoding_ids::hint_from_str_in(
        &state.label,
        wz_capi_core::encoding_ids::EncodingDialect::ZenohC,
    );
    if state.heap {
        // SAFETY: `heap` is set only by `EncodingState::owned`, whose state is
        // always a `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle as *mut EncodingState) });
    }
    Some(hint)
}

/// Install a fresh heap state into an owned encoding slot, freeing whatever was
/// there.
///
/// # Safety
/// `slot` must be valid and writable, and its current handle must be null or a
/// live `EncodingState`.
unsafe fn replace_state(slot: *mut z_owned_encoding_t, label: String) {
    // SAFETY: the caller's contract.
    let old = unsafe { (*slot).handle };
    if !old.is_null() {
        // SAFETY: a non-null handle always points at a live `EncodingState`.
        let state = unsafe { &*(old as *const EncodingState) };
        if state.heap {
            // SAFETY: as in `take_moved_encoding`.
            drop(unsafe { Box::from_raw(old as *mut EncodingState) });
        }
    }
    let boxed = Box::into_raw(Box::new(EncodingState::owned(label))) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *slot = z_owned_encoding_t::from_handle(boxed) };
}

/// Borrow `len` bytes at `s` as UTF-8, lossily, or `None` when `s` is null.
///
/// Lossy rather than rejecting: upstream takes a `const char*` and never
/// validates it, and a `z_encoding_from_substr` that failed on a non-UTF-8 byte
/// would refuse input upstream accepts.
///
/// # Safety
/// `s` must be null, or point at `len` readable bytes.
unsafe fn substr_to_string(s: *const c_char, len: usize) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Borrow a NUL-terminated string, or `None` when `s` is null.
///
/// # Safety
/// `s` must be null, or a valid NUL-terminated C string.
unsafe fn cstr_to_string(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let bytes = unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The DEFAULT encoding, borrowed (zenoh-c `z_encoding_loan_default`).
///
/// `zenoh/bytes`, table entry 0 — the same constant [`z_encoding_zenoh_bytes`]
/// returns, deliberately by calling it rather than by minting a second static:
/// upstream's two entry points hand out one value, and a C program may compare
/// the pointers.
#[no_mangle]
pub extern "C" fn z_encoding_loan_default() -> *const z_loaned_encoding_t {
    z_encoding_zenoh_bytes()
}

/// Parse an encoding from a NUL-terminated label (zenoh-c `z_encoding_from_str`).
///
/// Cannot fail on a non-null input: an unrecognised prefix becomes the SCHEMA
/// under the default id, which is upstream's documented fallback and what
/// [`hint_from_str`](wz_capi_core::encoding_ids::hint_from_str) reproduces.
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_str(
    this_: *mut z_owned_encoding_t,
    s: *const c_char,
) -> crate::result::ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_encoding_t::null_value() };
        // SAFETY: as above.
        let Some(label) = (unsafe { cstr_to_string(s) }) else {
            return Z_ENULL;
        };
        // SAFETY: the slot was just gravestoned, so there is nothing to free.
        unsafe { replace_state(this_, label) };
        Z_OK
    })
}

/// Parse an encoding from a counted label (zenoh-c `z_encoding_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_from_substr(
    this_: *mut z_owned_encoding_t,
    s: *const c_char,
    len: usize,
) -> crate::result::ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_encoding_t::null_value() };
        // SAFETY: as above.
        let Some(label) = (unsafe { substr_to_string(s, len) }) else {
            return Z_ENULL;
        };
        // SAFETY: the slot was just gravestoned.
        unsafe { replace_state(this_, label) };
        Z_OK
    })
}

/// Whether two encodings mean the same thing (zenoh-c `z_encoding_equals`).
///
/// Compares the WIRE projections rather than the labels: `text/plain` and
/// `text/pla` resolve to the same id through upstream's prefix lookup, so a
/// label comparison would call two encodings different that put the identical
/// bytes on the wire.
///
/// # Safety
/// Both arguments must be null or valid loaned encodings.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_equals(
    this_: *const z_loaned_encoding_t,
    other: *const z_loaned_encoding_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        unsafe { encoding_hint(this_) == encoding_hint(other) }
    })
}

/// Replace an encoding's schema suffix from a NUL-terminated string (zenoh-c
/// `z_encoding_set_schema_from_str`).
///
/// # Safety
/// `this_` must be null or a valid, writable loaned encoding obtained from
/// [`z_encoding_loan_mut`]; `s` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_str(
    this_: *mut z_loaned_encoding_t,
    s: *const c_char,
) -> crate::result::ZResult {
    // SAFETY: the caller's contract.
    let Some(schema) = (unsafe { cstr_to_string(s) }) else {
        return Z_ENULL;
    };
    // SAFETY: as above.
    unsafe { set_schema(this_, schema) }
}

/// Replace an encoding's schema suffix from a counted string (zenoh-c
/// `z_encoding_set_schema_from_substr`).
///
/// # Safety
/// `this_` must be null or a valid, writable loaned encoding obtained from
/// [`z_encoding_loan_mut`]; `s` must be null or point at `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_set_schema_from_substr(
    this_: *mut z_loaned_encoding_t,
    s: *const c_char,
    len: usize,
) -> crate::result::ZResult {
    // SAFETY: the caller's contract.
    let Some(schema) = (unsafe { substr_to_string(s, len) }) else {
        return Z_ENULL;
    };
    // SAFETY: as above.
    unsafe { set_schema(this_, schema) }
}

/// The shared body of the two `set_schema` entry points.
///
/// Writes a NEW heap state into the caller's slot rather than mutating the one
/// behind the handle. That is not an optimisation dodge — the handle may point
/// at one of the 53 `'static` constants, and mutating through it would rewrite a
/// process-global that every other caller shares. Because `z_loaned_encoding_t`
/// and `z_owned_encoding_t` are the same footprint and a mutable loan is only
/// ever obtained from [`z_encoding_loan_mut`] on a caller-owned value, writing
/// the new handle back through the loan updates exactly that owned value, whose
/// eventual [`z_encoding_drop`] then frees the heap state.
///
/// # Safety
/// `this_` must be null, or a valid, writable loaned encoding aliasing an owned
/// one.
unsafe fn set_schema(this_: *mut z_loaned_encoding_t, schema: String) -> crate::result::ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let prefix = unsafe { encoding_label(this_) }
            .unwrap_or("")
            .split(wz_capi_core::encoding_ids::SCHEMA_SEPARATOR)
            .next()
            .unwrap_or("")
            .to_owned();
        let label = if schema.is_empty() {
            prefix
        } else {
            format!(
                "{prefix}{}{schema}",
                wz_capi_core::encoding_ids::SCHEMA_SEPARATOR
            )
        };
        // SAFETY: the two types share a footprint, so the loan aliases the owned
        // value's slot; `replace_state` frees whatever heap state was there.
        unsafe { replace_state(this_ as *mut z_owned_encoding_t, label) };
        Z_OK
    })
}

/// The `(id, schema)` pair behind an encoding (zenoh-c
/// `zc_internal_encoding_get_data`).
///
/// Upstream's own internal accessor, exported because its `zc_` sibling below is
/// how a program round-trips an encoding without a string. The schema pointer
/// borrows the state behind `this_`, so it is valid exactly as long as that
/// encoding is.
#[repr(C)]
pub struct zc_internal_encoding_data_t {
    /// The wire id — the encoding table index, NOT the packed word.
    pub id: u16,
    /// The schema bytes, or null when the encoding carries none.
    pub schema_ptr: *const u8,
    /// The schema length in bytes.
    pub schema_len: usize,
}

/// Read an encoding's `(id, schema)` pair (zenoh-c
/// `zc_internal_encoding_get_data`).
///
/// The returned schema pointer aliases the label behind `this_` — a SUFFIX of
/// it, so no allocation is made and nothing has to be freed. A null or
/// gravestoned input reads as the default id with no schema, which is what an
/// unset encoding means.
///
/// # Safety
/// `this_` must be null or a valid loaned encoding.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_encoding_get_data(
    this_: *const z_loaned_encoding_t,
) -> zc_internal_encoding_data_t {
    let empty = zc_internal_encoding_data_t {
        id: wz_capi_core::encoding_ids::ENCODING_ID_DEFAULT,
        schema_ptr: std::ptr::null(),
        schema_len: 0,
    };
    guard_val(empty, || {
        // SAFETY: the caller's contract.
        let Some(label) = (unsafe { encoding_label(this_) }) else {
            return zc_internal_encoding_data_t {
                id: wz_capi_core::encoding_ids::ENCODING_ID_DEFAULT,
                schema_ptr: std::ptr::null(),
                schema_len: 0,
            };
        };
        let hint = wz_capi_core::encoding_ids::hint_from_str_in(
            label,
            wz_capi_core::encoding_ids::EncodingDialect::ZenohC,
        );
        // The schema is a SUFFIX of the label the state already owns, so it is
        // located rather than copied — a copy would need an owner this signature
        // has nowhere to put.
        let (schema_ptr, schema_len) = match label
            .find(wz_capi_core::encoding_ids::SCHEMA_SEPARATOR)
            .map(|pos| &label[pos + wz_capi_core::encoding_ids::SCHEMA_SEPARATOR.len_utf8()..])
        {
            Some(schema) if !schema.is_empty() => (schema.as_ptr(), schema.len()),
            _ => (std::ptr::null(), 0),
        };
        zc_internal_encoding_data_t {
            id: (hint.packed_id >> 1) as u16,
            schema_ptr,
            schema_len,
        }
    })
}

/// Build an encoding from an `(id, schema)` pair (zenoh-c
/// `zc_internal_encoding_from_data`).
///
/// # Safety
/// `this_` must be valid and writable; `data.schema_ptr` must be null or point
/// at `data.schema_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_internal_encoding_from_data(
    this_: *mut z_owned_encoding_t,
    data: zc_internal_encoding_data_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_encoding_t::null_value() };
        // A sentinel id carries the whole label in its schema, so there is no
        // table prefix to prepend — that is the shape `get_data` produced for
        // an unrecognised label and the round trip has to preserve it.
        let prefix = wz_capi_core::encoding_ids::ENCODING_ID_TO_STR
            .get(usize::from(data.id))
            .copied()
            .unwrap_or("");
        let known = data.id != wz_capi_core::encoding_ids::ENCODING_ID_UNKNOWN;
        // SAFETY: the caller's contract.
        let schema = unsafe { substr_to_string(data.schema_ptr.cast(), data.schema_len) };
        let label = match schema {
            Some(schema) if !schema.is_empty() && known => format!(
                "{prefix}{}{schema}",
                wz_capi_core::encoding_ids::SCHEMA_SEPARATOR
            ),
            Some(schema) if !schema.is_empty() => schema,
            _ => prefix.to_owned(),
        };
        // SAFETY: the slot was just gravestoned.
        unsafe { replace_state(this_, label) };
    });
}

/// Construct an owned copy of an encoding (zenoh-c `z_encoding_clone`).
///
/// A constant is copied by HANDLE — its state is `'static`, so two owned values
/// pointing at it are both correct and neither will free it. A heap-owned label
/// is copied by VALUE, because the source may be dropped first.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_clone(
    dst: *mut z_owned_encoding_t,
    this_: *const z_loaned_encoding_t,
) {
    let _ = guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        unsafe { *dst = z_owned_encoding_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle } as Handle;
        if handle.is_null() {
            return Z_ENULL;
        }
        // SAFETY: a non-null handle always points at a live `EncodingState`.
        let state = unsafe { &*(handle as *const EncodingState) };
        if state.heap {
            let label = state.label.clone().into_owned();
            // SAFETY: `dst` was just gravestoned.
            unsafe { replace_state(dst, label) };
        } else {
            unsafe { *dst = z_owned_encoding_t::from_handle(handle) };
        }
        Z_OK
    });
}

/// Render an encoding's label into an owned string (zenoh-c
/// `z_encoding_to_string`).
///
/// This is what makes the label a VALUE rather than an internal tag: without it
/// the constants would be distinguishable only by pointer identity, which a
/// C program cannot rely on across a `z_encoding_clone`.
///
/// The rendering goes through the WIRE projection rather than printing the label
/// verbatim, so `z_encoding_from_str("text/pla")` reads back as upstream renders
/// it — the canonical `text/plain` its id names — instead of echoing the input.
///
/// # Safety
/// `this_` must be null or a valid loaned encoding; `out_str` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_to_string(
    this_: *const z_loaned_encoding_t,
    out_str: *mut crate::abi::z_owned_string_t,
) {
    guard_val((), || {
        if out_str.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let rendered = unsafe { encoding_hint(this_) }
            .map(|hint| {
                wz_capi_core::encoding_ids::hint_to_string_in(
                    &hint,
                    wz_capi_core::encoding_ids::EncodingDialect::ZenohC,
                )
            })
            .unwrap_or_default();
        unsafe { *out_str = crate::string::owned_string_from(rendered.as_bytes()) };
    });
}

/// Borrow an encoding (zenoh-c `z_encoding_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_loan(
    this_: *const z_owned_encoding_t,
) -> *const z_loaned_encoding_t {
    this_ as *const z_loaned_encoding_t
}

/// Borrow an encoding mutably (zenoh-c `z_encoding_loan_mut`).
///
/// The mutable loan is what [`z_encoding_set_schema_from_str`] needs, and it
/// aliases the owned value's slot — see that function for why the write lands
/// there rather than behind the handle.
///
/// # Safety
/// `this_` must be null or a valid, writable owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_loan_mut(
    this_: *mut z_owned_encoding_t,
) -> *mut z_loaned_encoding_t {
    this_ as *mut z_loaned_encoding_t
}

/// Reset an encoding to its default (zenoh-c `z_encoding_drop`).
///
/// Frees the state only when it was heap-owned; the 53 constants are `'static`
/// and a caller who cloned one and dropped the clone must not free them.
///
/// # Safety
/// `this_` must be null or a valid moved encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_drop(this_: *mut z_moved_encoding_t) {
    // SAFETY: the caller's contract; the hint is discarded, the free is the point.
    let _ = unsafe { take_moved_encoding(this_) };
}

/// `true` iff the owned encoding carries a label (zenoh-c
/// `z_internal_encoding_check`).
///
/// # Safety
/// `this_` must be null or a valid owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_internal_encoding_check(this_: *const z_owned_encoding_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned encoding (zenoh-c `z_internal_encoding_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_internal_encoding_null(this_: *mut z_owned_encoding_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_encoding_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each constant is a STABLE pointer — a program may hold one indefinitely,
    /// and two calls must agree or a C-side comparison would be meaningless.
    #[test]
    fn a_constant_encoding_is_the_same_pointer_every_time() {
        assert_eq!(z_encoding_text_plain(), z_encoding_text_plain());
        assert_ne!(z_encoding_text_plain(), z_encoding_zenoh_bytes());
    }

    /// Every exported constant renders as the table entry at the index it
    /// claims, and the 53 are DISTINCT — a duplicated index would otherwise
    /// pass the per-constant check while silently aliasing two labels.
    #[test]
    fn every_constant_renders_as_its_own_table_entry() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, id, ctor) in CONSTANTS {
            // SAFETY: the constants are live `'static` values.
            let label = unsafe { encoding_label(ctor()) };
            assert_eq!(
                label,
                Some(wz_capi_core::encoding_ids::ENCODING_ID_TO_STR[*id]),
                "{name} claims table index {id}"
            );
            assert!(seen.insert(*id), "{name} reuses table index {id}");
        }
        assert_eq!(
            seen.len(),
            wz_capi_core::encoding_ids::ENCODING_ID_TO_STR.len(),
            "the constants must cover the whole wire table"
        );
    }

    /// A clone reads back the same label, and a null source leaves a gravestone
    /// rather than a stale stack value.
    #[test]
    fn a_cloned_encoding_reads_back_and_a_null_source_gravestones() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: local values, valid for the calls.
        unsafe {
            z_encoding_clone(&mut owned, z_encoding_text_plain());
            assert!(z_internal_encoding_check(&owned));
            assert_eq!(encoding_label(z_encoding_loan(&owned)), Some("text/plain"));

            z_encoding_clone(&mut owned, std::ptr::null());
            assert!(!z_internal_encoding_check(&owned));
        }
    }

    /// A parsed encoding round-trips through the wire projection, and dropping
    /// it gravestones the caller's value.
    #[test]
    fn a_parsed_encoding_round_trips_and_drops() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: local values, valid for the calls.
        unsafe {
            let label = std::ffi::CString::new("text/plain;utf8").unwrap();
            assert_eq!(z_encoding_from_str(&mut owned, label.as_ptr()), Z_OK);
            assert!(z_internal_encoding_check(&owned));

            let mut rendered = crate::abi::z_owned_string_t::null_value();
            z_encoding_to_string(z_encoding_loan(&owned), &mut rendered);
            let loaned = crate::string::z_string_loan(&rendered);
            let text = std::slice::from_raw_parts(
                crate::string::z_string_data(loaned).cast::<u8>(),
                crate::string::z_string_len(loaned),
            );
            assert_eq!(std::str::from_utf8(text).unwrap(), "text/plain;utf8");
            crate::string::z_string_drop(&mut *(&mut rendered as *mut _ as *mut _));

            z_encoding_drop(&mut *(&mut owned as *mut _ as *mut z_moved_encoding_t));
            assert!(!z_internal_encoding_check(&owned));
        }
    }

    /// A cloned HEAP encoding survives the source being dropped — the clone owns
    /// its own label, so this is a use-after-free if the copy were by handle.
    #[test]
    fn a_clone_of_a_parsed_encoding_outlives_its_source() {
        // SAFETY: local values, valid for the calls.
        unsafe {
            let mut src = z_owned_encoding_t::null_value();
            let label = std::ffi::CString::new("application/json;v1").unwrap();
            assert_eq!(z_encoding_from_str(&mut src, label.as_ptr()), Z_OK);

            let mut copy = z_owned_encoding_t::null_value();
            z_encoding_clone(&mut copy, z_encoding_loan(&src));
            z_encoding_drop(&mut *(&mut src as *mut _ as *mut z_moved_encoding_t));

            assert_eq!(
                encoding_label(z_encoding_loan(&copy)),
                Some("application/json;v1")
            );
            z_encoding_drop(&mut *(&mut copy as *mut _ as *mut z_moved_encoding_t));
        }
    }

    /// Setting a schema on a CONSTANT must not rewrite the process-global the
    /// constant points at — the whole reason `set_schema` writes a new state.
    #[test]
    fn setting_a_schema_on_a_clone_of_a_constant_leaves_the_constant_alone() {
        // SAFETY: local values, valid for the calls.
        unsafe {
            let mut owned = z_owned_encoding_t::null_value();
            z_encoding_clone(&mut owned, z_encoding_text_plain());
            let schema = std::ffi::CString::new("utf8").unwrap();
            assert_eq!(
                z_encoding_set_schema_from_str(z_encoding_loan_mut(&mut owned), schema.as_ptr()),
                Z_OK
            );
            assert_eq!(
                encoding_label(z_encoding_loan(&owned)),
                Some("text/plain;utf8")
            );
            // The constant itself is untouched.
            assert_eq!(encoding_label(z_encoding_text_plain()), Some("text/plain"));
            z_encoding_drop(&mut *(&mut owned as *mut _ as *mut z_moved_encoding_t));
        }
    }

    /// Equality is over the WIRE projection, in the ZENOH-C dialect: the
    /// prefix lookup is EXACT, so `text/pla` is its own unknown encoding
    /// rather than an alias for `text/plain`. The sibling pico ABI answers
    /// the other way and is right to — see
    /// [`wz_capi_core::encoding_ids::EncodingDialect`].
    #[test]
    fn equality_compares_the_wire_projection_under_the_zenoh_c_dialect() {
        // SAFETY: local values, valid for the calls.
        unsafe {
            let mut prefix = z_owned_encoding_t::null_value();
            let text = std::ffi::CString::new("text/pla").unwrap();
            assert_eq!(z_encoding_from_str(&mut prefix, text.as_ptr()), Z_OK);
            assert!(!z_encoding_equals(
                z_encoding_loan(&prefix),
                z_encoding_text_plain()
            ));

            let mut exact = z_owned_encoding_t::null_value();
            let full = std::ffi::CString::new("text/plain").unwrap();
            assert_eq!(z_encoding_from_str(&mut exact, full.as_ptr()), Z_OK);
            assert!(z_encoding_equals(
                z_encoding_loan(&exact),
                z_encoding_text_plain()
            ));
            assert!(!z_encoding_equals(
                z_encoding_loan(&exact),
                z_encoding_application_json()
            ));
            z_encoding_drop(&mut *(&mut exact as *mut _ as *mut z_moved_encoding_t));
            z_encoding_drop(&mut *(&mut prefix as *mut _ as *mut z_moved_encoding_t));
        }
    }

    /// The internal `(id, schema)` accessor agrees with the label, and the
    /// round trip through `from_data` reproduces it.
    #[test]
    fn the_internal_data_pair_round_trips() {
        // SAFETY: local values, valid for the calls.
        unsafe {
            let mut owned = z_owned_encoding_t::null_value();
            let label = std::ffi::CString::new("application/cbor;v2").unwrap();
            assert_eq!(z_encoding_from_str(&mut owned, label.as_ptr()), Z_OK);

            let data = zc_internal_encoding_get_data(z_encoding_loan(&owned));
            assert_eq!(data.id, 8);
            assert_eq!(
                std::str::from_utf8(std::slice::from_raw_parts(data.schema_ptr, data.schema_len))
                    .unwrap(),
                "v2"
            );

            let mut rebuilt = z_owned_encoding_t::null_value();
            zc_internal_encoding_from_data(&mut rebuilt, data);
            assert_eq!(
                encoding_label(z_encoding_loan(&rebuilt)),
                Some("application/cbor;v2")
            );
            z_encoding_drop(&mut *(&mut rebuilt as *mut _ as *mut z_moved_encoding_t));
            z_encoding_drop(&mut *(&mut owned as *mut _ as *mut z_moved_encoding_t));
        }
    }
}
