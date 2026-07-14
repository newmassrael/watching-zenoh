// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_bytes_*`, `z_slice_*`, `z_string_*` — the payload value types.
//!
//! `z_bytes_t` is the wire payload (`z_put` / `z_publisher_put` consume it and
//! the subscriber callback reads it back). A subscriber reads a delivered
//! payload the pico way: `z_sample_payload` → `z_bytes_to_slice` →
//! `z_slice_data` / `z_slice_len` (or `z_bytes_to_string` → `z_string_data` /
//! `z_string_len`).
//!
//! bytes and slice use the handle model (owned == loaned layout, `loan` is a
//! cast; the accessor reads the heap `Vec<u8>`). string uses the borrowed-view
//! model: an owned string holds a heap `StringState` and hands out a cached
//! `{ start, len }` self-view on `loan`, so `z_loaned_string_t` is the same
//! borrowed shape a view string (from `z_keyexpr_as_view_string`) produces.

use std::ffi::{c_char, c_void, CStr};

use crate::abi::{
    handle_ref, impl_value_ownership, z_loaned_bytes_t, z_loaned_slice_t, z_loaned_string_t,
    z_moved_bytes_t, z_moved_slice_t, z_moved_string_t, z_owned_bytes_t, z_owned_slice_t,
    z_owned_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

// --- payloads -------------------------------------------------------------

/// Behind a `z_owned_bytes_t` / `z_owned_slice_t` handle: the raw bytes.
pub(crate) type ByteBuf = Vec<u8>;

/// Behind a `z_owned_string_t` handle. `data` is NUL-terminated so a C caller
/// treating `z_string_data` as a C string is safe; `len` is the logical
/// length (excluding the terminator). `self_view` is the cached borrowed
/// `{ start, len }` that `z_string_loan` returns (stable: it points at
/// `data`'s heap buffer, which does not move when the box does).
pub(crate) struct StringState {
    /// Owns the NUL-terminated heap buffer that `self_view` borrows. Never
    /// read directly — kept alive for the borrow and freed on drop.
    #[allow(dead_code)]
    data: Vec<u8>,
    self_view: z_loaned_string_t,
}

impl StringState {
    fn boxed(bytes: &[u8]) -> Box<StringState> {
        let mut data = Vec::with_capacity(bytes.len() + 1);
        data.extend_from_slice(bytes);
        data.push(0);
        let len = bytes.len();
        let start = data.as_ptr();
        Box::new(StringState {
            data,
            self_view: z_loaned_string_t {
                _start: start,
                _len: len,
            },
        })
    }
}

/// # Safety
/// `h` must be a live `Box::into_raw::<ByteBuf>` pointer.
unsafe fn free_bytes(h: *mut c_void) {
    drop(Box::from_raw(h as *mut ByteBuf));
}
/// # Safety
/// `h` must be a live `Box::into_raw::<ByteBuf>` pointer.
unsafe fn free_slice(h: *mut c_void) {
    drop(Box::from_raw(h as *mut ByteBuf));
}

impl_value_ownership!(
    z_owned_bytes_t,
    z_loaned_bytes_t,
    z_moved_bytes_t,
    free_bytes,
    z_internal_bytes_null,
    z_internal_bytes_check,
    z_bytes_loan,
    z_bytes_loan_mut,
    z_bytes_move,
    z_bytes_take,
    z_bytes_drop,
    z_bytes_take_from_loaned
);

impl_value_ownership!(
    z_owned_slice_t,
    z_loaned_slice_t,
    z_moved_slice_t,
    free_slice,
    z_internal_slice_null,
    z_internal_slice_check,
    z_slice_loan,
    z_slice_loan_mut,
    z_slice_move,
    z_slice_take,
    z_slice_drop,
    z_slice_take_from_loaned
);

// --- helpers to box a payload into an owned value -------------------------

unsafe fn store_bytes(dst: *mut z_owned_bytes_t, buf: ByteBuf) {
    *dst = z_owned_bytes_t {
        handle: Box::into_raw(Box::new(buf)) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}
unsafe fn store_slice(dst: *mut z_owned_slice_t, buf: ByteBuf) {
    *dst = z_owned_slice_t {
        handle: Box::into_raw(Box::new(buf)) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}
unsafe fn store_string(dst: *mut z_owned_string_t, s: Box<StringState>) {
    *dst = z_owned_string_t {
        handle: Box::into_raw(s) as *mut c_void,
        _pad: [std::ptr::null_mut(); 3],
    };
}

/// Read the raw bytes behind a loaned bytes/slice value (both wrap `ByteBuf`).
pub(crate) unsafe fn bytes_ref<'a>(ptr: *const z_loaned_bytes_t) -> Option<&'a ByteBuf> {
    handle_ref::<z_loaned_bytes_t, ByteBuf>(ptr)
}

// --- bytes constructors ---------------------------------------------------

/// Copy a buffer into an owned payload (pico `z_bytes_copy_from_buf`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_buf(
    bytes: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let buf = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        store_bytes(bytes, buf);
        Z_OK
    })
}

/// Copy a C string's bytes into an owned payload (pico `z_bytes_copy_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_str(
    bytes: *mut z_owned_bytes_t,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let buf = CStr::from_ptr(value).to_bytes().to_vec();
        store_bytes(bytes, buf);
        Z_OK
    })
}

// --- conversions ----------------------------------------------------------

/// Copy a payload into an owned slice (pico `z_bytes_to_slice`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_slice(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            Some(buf) => {
                store_slice(dst, buf.clone());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Copy a payload into an owned string (pico `z_bytes_to_string`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_string(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            Some(buf) => {
                store_string(dst, StringState::boxed(buf));
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

// --- slice accessors ------------------------------------------------------

/// Pointer to a slice's bytes (pico `z_slice_data`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_data(slice: *const z_loaned_slice_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        match handle_ref::<z_loaned_slice_t, ByteBuf>(slice) {
            Some(buf) => buf.as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// Length of a slice (pico `z_slice_len`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_len(slice: *const z_loaned_slice_t) -> usize {
    guard_val(0, || match handle_ref::<z_loaned_slice_t, ByteBuf>(slice) {
        Some(buf) => buf.len(),
        None => 0,
    })
}

// --- string ownership + accessors -----------------------------------------

/// Zero an owned string (pico `z_internal_string_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_null(obj: *mut z_owned_string_t) {
    if !obj.is_null() {
        *obj = z_owned_string_t::null_value();
    }
}

/// `true` iff the owned string holds a live handle (pico
/// `z_internal_string_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_check(obj: *const z_owned_string_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow an owned string immutably (pico `z_string_loan`). Returns the
/// state's cached `{ start, len }` self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_loan(obj: *const z_owned_string_t) -> *const z_loaned_string_t {
    guard_val(std::ptr::null(), || {
        match handle_ref::<z_owned_string_t, StringState>(obj) {
            Some(state) => &state.self_view as *const z_loaned_string_t,
            None => std::ptr::null(),
        }
    })
}

/// Borrow an owned string mutably (pico `z_string_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_string_loan_mut(obj: *mut z_owned_string_t) -> *mut z_loaned_string_t {
    if obj.is_null() || (*obj).handle.is_null() {
        return std::ptr::null_mut();
    }
    let state = &mut *((*obj).handle as *mut StringState);
    &mut state.self_view as *mut z_loaned_string_t
}

/// Move-cast an owned string (pico `z_string_move`).
#[no_mangle]
pub unsafe extern "C" fn z_string_move(obj: *mut z_owned_string_t) -> *mut z_moved_string_t {
    obj as *mut z_moved_string_t
}

/// Take an owned string out of `src` into `dst` (pico `z_string_take`).
#[no_mangle]
pub unsafe extern "C" fn z_string_take(dst: *mut z_owned_string_t, src: *mut z_moved_string_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_string_t::null_value();
}

/// Drop an owned string (pico `z_string_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_string_drop(obj: *mut z_moved_string_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let h = (*obj)._this.handle;
        if !h.is_null() {
            drop(Box::from_raw(h as *mut StringState));
            (*obj)._this = z_owned_string_t::null_value();
        }
        Z_OK
    });
}

/// Pointer to a string's (NUL-terminated) bytes (pico `z_string_data`).
#[no_mangle]
pub unsafe extern "C" fn z_string_data(string: *const z_loaned_string_t) -> *const c_char {
    guard_val(std::ptr::null(), || {
        if string.is_null() {
            std::ptr::null()
        } else {
            (*string)._start as *const c_char
        }
    })
}

/// Logical length of a string, excluding the NUL terminator (pico
/// `z_string_len`).
#[no_mangle]
pub unsafe extern "C" fn z_string_len(string: *const z_loaned_string_t) -> usize {
    guard_val(0, || if string.is_null() { 0 } else { (*string)._len })
}

/// Adopt a loaned string into an owned one, emptying the source view (pico
/// `z_string_take_from_loaned`). The string loaned form is a borrowed
/// `{ start, len }`, so "take" copies the borrowed bytes into a fresh owned
/// `StringState` (there is no transferable handle in a borrow) and clears the
/// source view.
///
/// Caveat: if `src` was obtained via `z_string_loan[_mut]` on an owned string,
/// it points at that owned string's cached self-view; clearing it here leaves
/// that owned string's subsequent `z_string_loan` returning an empty
/// `{ null, 0 }` view (the owned `StringState` box is untouched and still
/// freed on drop — no leak, no double-free). Idiomatic pico "take from loaned"
/// is applied to a fresh loaned handle, not an owned string's self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_take_from_loaned(
    dst: *mut z_owned_string_t,
    src: *mut z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::slice::from_raw_parts(start, len);
        store_string(dst, StringState::boxed(bytes));
        (*src)._start = std::ptr::null();
        (*src)._len = 0;
        Z_OK
    })
}

// --- clone (deep copy) ----------------------------------------------------

/// Deep-copy a payload (pico `z_bytes_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_clone(
    dst: *mut z_owned_bytes_t,
    src: *const z_loaned_bytes_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(src) {
            Some(buf) => {
                store_bytes(dst, buf.clone());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Deep-copy a slice (pico `z_slice_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_clone(
    dst: *mut z_owned_slice_t,
    src: *const z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match handle_ref::<z_loaned_slice_t, ByteBuf>(src) {
            Some(buf) => {
                store_slice(dst, buf.clone());
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Deep-copy a string (pico `z_string_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_string_clone(
    dst: *mut z_owned_string_t,
    src: *const z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = std::slice::from_raw_parts(start, len);
        store_string(dst, StringState::boxed(bytes));
        Z_OK
    })
}
