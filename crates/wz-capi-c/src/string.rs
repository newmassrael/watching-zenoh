// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The string family — owned, view, and the loaned shape both of them cast to.
//!
//! ## One repr, because upstream's loans are pointer casts
//!
//! `z_string_loan` takes a `z_owned_string_t*` and `z_view_string_loan` takes a
//! `z_view_string_t*`, and both return the SAME `const z_loaned_string_t*`. In
//! zenoh-c those are casts, so an owned string and a view string are already
//! required to be readable as one loaned shape. [`StringRepr`](crate::abi::StringRepr)
//! makes that a single definition here rather than three layouts that agree by
//! coincidence — the accessors then have exactly one thing to read.
//!
//! The only difference between the two is the `owned` slot: a leaked
//! `Box<Vec<u8>>` for the owned string, null for the view. `z_string_drop` frees
//! whatever is there and a view therefore drops to a no-op, which is upstream's
//! behaviour and not a shortcut.
//!
//! ## The buffer is NUL-terminated even though the contract does not ask
//!
//! zenoh-c documents these as *non-null-terminated* and pairs `z_string_data`
//! with `z_string_len` — `z_sub.c` prints with `%.*s`. wz appends a NUL anyway
//! and keeps it OUT of `len`. That is a strict superset: a caller honouring the
//! documented contract cannot observe it, and a caller who reaches for `printf
//! ("%s")` gets a terminated buffer instead of a read past the end.

use std::ffi::c_char;

use crate::abi::{z_loaned_string_t, z_moved_string_t, z_owned_string_t, z_view_string_t, Handle};
use crate::ffi::{guard_val, guarded};
use crate::result::Z_OK;

/// Build an OWNED string from bytes, taking a copy the caller then owns.
///
/// The trailing NUL is appended here and excluded from `len` (see the module
/// note), so every owned string this crate mints is terminated.
pub(crate) fn owned_string_from(bytes: &[u8]) -> z_owned_string_t {
    let mut buf = bytes.to_vec();
    let len = buf.len();
    buf.push(0);
    let boxed = Box::new(buf);
    let ptr = boxed.as_ptr();
    z_owned_string_t {
        ptr,
        len,
        owned: Box::into_raw(boxed) as Handle,
        _pad: 0,
    }
}

/// Build a VIEW string borrowing `text`, which must outlive every use of it.
pub(crate) fn view_string_over(text: &str) -> z_view_string_t {
    z_view_string_t {
        ptr: text.as_ptr(),
        len: text.len(),
        owned: std::ptr::null_mut(),
        _pad: 0,
    }
}

/// The bytes behind a loaned string, or `None` for a gravestone.
///
/// # Safety
/// `this_` must be null or a valid loaned string.
unsafe fn string_bytes<'a>(this_: *const z_loaned_string_t) -> Option<&'a [u8]> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let (ptr, len) = unsafe { ((*this_).ptr, (*this_).len) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr`/`len` describe a buffer this crate minted (owned) or a
    // caller-provided borrow whose lifetime is the caller's obligation.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// The string's bytes as a `const char*` (zenoh-c `z_string_data`).
///
/// # Safety
/// `this_` must be null or a valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_data(this_: *const z_loaned_string_t) -> *const c_char {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).ptr as *const c_char }
    })
}

/// The string's length in bytes, excluding wz's trailing NUL (zenoh-c
/// `z_string_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_len(this_: *const z_loaned_string_t) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { string_bytes(this_) }.map_or(0, <[u8]>::len)
    })
}

/// Borrow an owned string (zenoh-c `z_string_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_loan(this_: *const z_owned_string_t) -> *const z_loaned_string_t {
    this_
}

/// Borrow a view string (zenoh-c `z_view_string_loan`).
///
/// # Safety
/// `this_` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_loan(
    this_: *const z_view_string_t,
) -> *const z_loaned_string_t {
    this_
}

/// Free an owned string and reset it to its gravestone (zenoh-c
/// `z_string_drop`).
///
/// A VIEW string reaching here has a null `owned` slot and drops to a no-op,
/// which is upstream's behaviour: a view never owned the bytes.
///
/// # Safety
/// `this_` must be null or a valid moved string.
#[no_mangle]
pub unsafe extern "C" fn z_string_drop(this_: *mut z_moved_string_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let owned = unsafe { (*this_)._this.owned };
        if !owned.is_null() {
            // SAFETY: a live `Box<Vec<u8>>` this crate leaked in
            // `owned_string_from`; reclaimed here exactly once because the slot
            // is nulled immediately after.
            drop(unsafe { Box::from_raw(owned as *mut Vec<u8>) });
        }
        // Nulled on EVERY path, not just the owning one, so a defensive second
        // drop is a no-op rather than a double free.
        unsafe { (*this_)._this = z_owned_string_t::null_value() };
        Z_OK
    });
}
