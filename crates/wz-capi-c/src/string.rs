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
use crate::result::{ZResult, Z_OK};

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

/// Build an owned string by TAKING OWNERSHIP of a caller buffer (zenoh-c
/// `z_string_from_str`).
///
/// wz copies the bytes and then invokes the caller's `drop` IMMEDIATELY, on
/// every path including the failure ones — the same unconditional-transfer rule
/// [`crate::bytes::z_bytes_from_buf`] records. A path that skipped it would leak
/// the caller's buffer, a divergence visible only in their code.
///
/// `z_bytes.c` passes `NULL, NULL` for the pair, which is upstream's "the string
/// is static, there is nothing to free".
///
/// # Safety
/// `this_` must be null or valid and writable; `str_` must be null or
/// NUL-terminated; `drop` must be null or a valid C function pointer, and owns
/// `str_` after this call.
#[no_mangle]
pub unsafe extern "C" fn z_string_from_str(
    this_: *mut z_owned_string_t,
    str_: *mut c_char,
    drop: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) -> ZResult {
    let rc = guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_string_t::null_value() };
        if str_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract — NUL-terminated.
        let bytes = unsafe { std::ffi::CStr::from_ptr(str_) }.to_bytes();
        // SAFETY: as above.
        unsafe { *this_ = owned_string_from(bytes) };
        Z_OK
    });
    // UNCONDITIONAL, and outside the `guarded` body so it runs on the error
    // returns above too.
    if let Some(free) = drop {
        // SAFETY: upstream's contract — the deleter owns `str_` from here, and
        // an unwind across the C boundary is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            free(str_ as *mut std::ffi::c_void, context);
        }));
    }
    rc
}

// --- R311y564: the rest of upstream's string surface ------------------------

/// The GRAVESTONE owned string — a null buffer, which is what
/// `z_internal_string_check` reads as absent.
///
/// Distinct from an EMPTY string, which upstream's `z_string_empty` produces
/// and which checks as PRESENT. Two different states, and a C program that
/// tests one for the other gets the wrong answer, so both are constructed
/// explicitly rather than by zeroing.
pub(crate) fn null_string() -> z_owned_string_t {
    z_owned_string_t {
        ptr: std::ptr::null(),
        len: 0,
        owned: std::ptr::null_mut(),
        _pad: 0,
    }
}

/// Construct an EMPTY owned string (zenoh-c `z_string_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_string_empty(this_: *mut z_owned_string_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract. Empty rather than gravestoned: an
        // empty string CHECKS, and `owned_string_from` mints the NUL that makes
        // `z_string_data` a valid `const char*`.
        unsafe { *this_ = owned_string_from(b"") };
    }
}

/// `true` iff the loaned string has zero length (zenoh-c `z_string_is_empty`).
///
/// A gravestone reads as empty, which is upstream's behaviour and the reason
/// this is not the negation of `z_internal_string_check`.
///
/// # Safety
/// `this_` must be null or a valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_is_empty(this_: *const z_loaned_string_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract.
        unsafe { string_bytes(this_) }.map_or(true, <[u8]>::is_empty)
    })
}

/// Copy a NUL-terminated string into an owned one (zenoh-c
/// `z_string_copy_from_str`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_str(
    this_: *mut z_owned_string_t,
    str_: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = null_string() };
        if str_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above.
        let bytes = unsafe { std::ffi::CStr::from_ptr(str_) }.to_bytes();
        unsafe { *this_ = owned_string_from(bytes) };
        Z_OK
    })
}

/// Copy `len` bytes into an owned string (zenoh-c `z_string_copy_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_substr(
    this_: *mut z_owned_string_t,
    str_: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = null_string() };
        if str_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(str_.cast::<u8>(), len) };
        unsafe { *this_ = owned_string_from(bytes) };
        Z_OK
    })
}

/// Deep-copy a string (zenoh-c `z_string_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// string.
#[no_mangle]
pub unsafe extern "C" fn z_string_clone(
    dst: *mut z_owned_string_t,
    this_: *const z_loaned_string_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = null_string() };
        // SAFETY: as above.
        let Some(bytes) = (unsafe { string_bytes(this_) }) else {
            return;
        };
        unsafe { *dst = owned_string_from(bytes) };
    });
}

/// View a string's bytes as a slice (zenoh-c `z_string_as_slice`).
///
/// A POINTER CAST, not a copy. The two types have the same `(ptr, len, owned)`
/// prefix here, which is what makes the borrow free — and it is also why the
/// returned slice must never be dropped: it does not own the buffer, the string
/// does.
///
/// # Safety
/// `this_` must be null or a valid loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_as_slice(
    this_: *const z_loaned_string_t,
) -> *const crate::abi::z_loaned_slice_t {
    this_ as *const crate::abi::z_loaned_slice_t
}

/// `true` iff the owned string holds a buffer (zenoh-c
/// `z_internal_string_check`).
///
/// # Safety
/// `this_` must be null or a valid owned string.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_check(this_: *const z_owned_string_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).ptr }.is_null()
    })
}

/// Gravestone an owned string (zenoh-c `z_internal_string_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_null(this_: *mut z_owned_string_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = null_string() };
    }
}

/// Gravestone a view string (zenoh-c `z_view_string_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_empty(this_: *mut z_view_string_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = view_string_over("") };
    }
}

/// `true` iff the view string is empty (zenoh-c `z_view_string_is_empty`).
///
/// # Safety
/// `this_` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_is_empty(this_: *const z_view_string_t) -> bool {
    guard_val(true, || {
        // SAFETY: the caller's contract — the two types share a footprint.
        unsafe { z_string_is_empty(this_ as *const z_loaned_string_t) }
    })
}

/// Build a view string ALIASING a NUL-terminated buffer (zenoh-c
/// `z_view_string_from_str`).
///
/// The caller keeps the buffer alive; nothing is copied, which is the whole
/// point of the view family.
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or NUL-terminated
/// and must outlive every use of the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_str(
    this_: *mut z_view_string_t,
    str_: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = view_string_over("") };
        if str_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above.
        let bytes = unsafe { std::ffi::CStr::from_ptr(str_) }.to_bytes();
        unsafe {
            *this_ = z_view_string_t {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                owned: std::ptr::null_mut(),
                _pad: 0,
            }
        };
        Z_OK
    })
}

/// The counted form of [`z_view_string_from_str`] (zenoh-c
/// `z_view_string_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be null or point at `len`
/// readable bytes that outlive every use of the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_substr(
    this_: *mut z_view_string_t,
    str_: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = view_string_over("") };
        if str_.is_null() {
            return crate::result::Z_ENULL;
        }
        // SAFETY: as above.
        unsafe {
            *this_ = z_view_string_t {
                ptr: str_.cast::<u8>(),
                len,
                owned: std::ptr::null_mut(),
                _pad: 0,
            }
        };
        Z_OK
    })
}
