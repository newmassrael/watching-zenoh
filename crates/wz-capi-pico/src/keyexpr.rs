// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_view_keyexpr_*` + `z_keyexpr_as_view_string` — the keyexpr view type.
//!
//! pico `z_view_keyexpr_t` is a VIEW: it aliases the caller's `const char*`
//! (no allocation, no drop). Round 1 reproduces that borrow: the view stores
//! `{ start, len }` into the caller's NUL-terminated string, which the caller
//! must keep alive while the keyexpr is used (the pico contract). `z_put` /
//! `z_declare_*` read the borrowed UTF-8 back via [`keyexpr_str`].

use std::ffi::{c_char, CStr};

use crate::abi::{
    view_bytes, z_loaned_keyexpr_t, z_loaned_string_t, z_view_keyexpr_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};

/// Resolve a loaned keyexpr to its borrowed UTF-8 string, or `None` if null /
/// not valid UTF-8.
///
/// # Safety
/// `ke` must be a live `z_loaned_keyexpr_t` pointer (or null).
pub(crate) unsafe fn keyexpr_str<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a str> {
    if ke.is_null() {
        return None;
    }
    let bytes = view_bytes((*ke)._start, (*ke)._len)?;
    std::str::from_utf8(bytes).ok()
}

/// Build a view keyexpr borrowing the caller's C string (pico
/// `z_view_keyexpr_from_str`). The keyexpr must be valid UTF-8; the caller
/// keeps `name` alive for the view's lifetime.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str(
    keyexpr: *mut z_view_keyexpr_t,
    name: *const c_char,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || name.is_null() {
            return Z_ERR_NULL;
        }
        let cstr = CStr::from_ptr(name);
        // Validate UTF-8 up front; the borrowed bytes are read as `&str` later.
        if cstr.to_str().is_err() {
            return Z_ERR_INVALID;
        }
        let bytes = cstr.to_bytes();
        *keyexpr = z_view_keyexpr_t {
            _start: bytes.as_ptr(),
            _len: bytes.len(),
            _pad: [0usize; 4],
        };
        Z_OK
    })
}

/// `true` iff the view keyexpr is empty (pico `z_view_keyexpr_is_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_is_empty(keyexpr: *const z_view_keyexpr_t) -> bool {
    guard_val(true, || keyexpr.is_null() || (*keyexpr)._len == 0)
}

/// Borrow a view keyexpr immutably (pico `z_view_keyexpr_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan(
    keyexpr: *const z_view_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    keyexpr as *const z_loaned_keyexpr_t
}

/// Borrow a view keyexpr mutably (pico `z_view_keyexpr_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan_mut(
    keyexpr: *mut z_view_keyexpr_t,
) -> *mut z_loaned_keyexpr_t {
    keyexpr as *mut z_loaned_keyexpr_t
}

/// Reset a view keyexpr to empty (pico `z_view_keyexpr_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_empty(keyexpr: *mut z_view_keyexpr_t) {
    if !keyexpr.is_null() {
        *keyexpr = z_view_keyexpr_t {
            _start: std::ptr::null(),
            _len: 0,
            _pad: [0usize; 4],
        };
    }
}

/// Expose a loaned keyexpr as a borrowed view string (pico
/// `z_keyexpr_as_view_string`). The string view aliases the keyexpr's bytes.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_as_view_string(
    keyexpr: *const z_loaned_keyexpr_t,
    string: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        if keyexpr.is_null() || string.is_null() {
            return Z_ERR_NULL;
        }
        *string = z_view_string_t {
            _start: (*keyexpr)._start,
            _len: (*keyexpr)._len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Borrow a view string (pico `z_view_string_loan`). The loaned form is a
/// `{ start, len }` borrow, read by `z_string_data` / `z_string_len`.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_loan(
    string: *const z_view_string_t,
) -> *const z_loaned_string_t {
    string as *const z_loaned_string_t
}
