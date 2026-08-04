// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Payload bytes.
//!
//! `z_bytes_from_static_str` is the one upstream's `z_put.c` calls, and its
//! contract is that the string is `'static` so nothing needs copying. wz copies
//! anyway: the payload has to reach a bounded wire codec on another thread, and
//! a borrow whose lifetime is asserted by the CALLER is not something this side
//! can verify. Copying is the safe direction — a caller who honours the static
//! contract loses only an allocation.

use std::ffi::{c_char, c_void, CStr};

use crate::abi::{z_loaned_bytes_t, z_moved_bytes_t, z_owned_bytes_t, z_owned_string_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::owned_string_from;

/// The owned payload behind a bytes handle.
pub(crate) struct BytesState {
    pub(crate) payload: Vec<u8>,
}

/// Read the bytes behind a LOANED handle.
///
/// Every loaned bytes in this crate — the one `z_sample_payload` hands out and
/// the one `z_sample_attachment` does — points at a [`BytesState`], so there is
/// one meaning for the handle slot and this one reader serves all of them.
///
/// # Safety
/// `this_` must be null, or a valid loaned bytes whose handle slot holds a live
/// `BytesState` pointer.
pub(crate) unsafe fn bytes_slice<'a>(this_: *const z_loaned_bytes_t) -> Option<&'a [u8]> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `BytesState`, either leaked by this crate or
    // borrowed from a `SampleMarshal` that outlives the callback.
    Some(&unsafe { &*(handle as *const BytesState) }.payload)
}

/// Take the payload out of a MOVED bytes, leaving a gravestone.
///
/// `z_put` consumes its payload, so this both reads and invalidates — a
/// defensive later `z_bytes_drop` on the same value is then a safe no-op.
///
/// # Safety
/// `moved` must be null or a valid moved bytes whose handle is live.
pub(crate) unsafe fn take_payload(moved: *mut z_moved_bytes_t) -> Option<Vec<u8>> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*moved)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<BytesState>` this crate leaked; reclaimed here.
    let state = unsafe { Box::from_raw(handle as *mut BytesState) };
    unsafe { (*moved)._this = z_owned_bytes_t::null_value() };
    Some(state.payload)
}

/// Build a payload from a NUL-terminated string (zenoh-c
/// `z_bytes_from_static_str`).
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_str(
    this_: *mut z_owned_bytes_t,
    str_: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || str_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(str_) }).to_str() else {
            return Z_EPARSE;
        };
        let handle = Box::into_raw(Box::new(BytesState {
            payload: text.as_bytes().to_vec(),
        })) as Handle;
        unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    })
}

/// Build a payload by COPYING a NUL-terminated string (zenoh-c
/// `z_bytes_copy_from_str`).
///
/// The sibling of [`z_bytes_from_static_str`], and here the two are the same
/// implementation because wz copies either way — see the module note for why the
/// static contract cannot be honoured on this side.
///
/// # Safety
/// `this_` must be valid and writable; `str_` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_str(
    this_: *mut z_owned_bytes_t,
    str_: *const c_char,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_bytes_from_static_str(this_, str_) }
}

/// Build a payload by TAKING OWNERSHIP of a caller buffer (zenoh-c
/// `z_bytes_from_buf`).
///
/// wz copies the bytes and then invokes the caller's `deleter` IMMEDIATELY, on
/// every path including the failure ones. That is not a shortcut: upstream's
/// ownership transfer is unconditional, so a path that skipped the deleter would
/// LEAK the caller's buffer — a divergence visible only in their code. The
/// sibling `wz-capi-pico` records the same decision for the same reason.
///
/// # Safety
/// `this_` must be valid and writable; `data` must be null or point at `len`
/// readable bytes; `deleter` must be null or a valid C function pointer, and owns
/// `data` after this call.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_buf(
    this_: *mut z_owned_bytes_t,
    data: *mut u8,
    len: usize,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    let rc = guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        // A null buffer with a non-zero length is the caller's error; a null
        // buffer with length 0 is the legitimate empty payload.
        let payload = if data.is_null() {
            if len != 0 {
                return Z_ENULL;
            }
            Vec::new()
        } else {
            // SAFETY: the caller's contract — `len` readable bytes at `data`.
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        let handle = Box::into_raw(Box::new(BytesState { payload })) as Handle;
        unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    });
    // UNCONDITIONAL, and outside the `guarded` body so it runs even on the error
    // returns above.
    if let Some(free) = deleter {
        // SAFETY: upstream's contract — the deleter owns `data` from here, and an
        // unwind across the C boundary is UB, so it is caught.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            free(data as *mut c_void, context);
        }));
    }
    rc
}

/// Deep-copy a payload (zenoh-c `z_bytes_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_clone(dst: *mut z_owned_bytes_t, this_: *const z_loaned_bytes_t) {
    let _ = guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        unsafe { *dst = z_owned_bytes_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            // Upstream returns void here, so a null source leaves the gravestone
            // already written above rather than reporting anything.
            return Z_ENULL;
        };
        let handle = Box::into_raw(Box::new(BytesState {
            payload: bytes.to_vec(),
        })) as Handle;
        unsafe { *dst = z_owned_bytes_t::from_handle(handle) };
        Z_OK
    });
}

/// Borrow a payload (zenoh-c `z_bytes_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_loan(this_: *const z_owned_bytes_t) -> *const z_loaned_bytes_t {
    this_ as *const z_loaned_bytes_t
}

/// Mutably borrow a payload (zenoh-c `z_bytes_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_loan_mut(this_: *mut z_owned_bytes_t) -> *mut z_loaned_bytes_t {
    this_ as *mut z_loaned_bytes_t
}

/// The payload's length in bytes (zenoh-c `z_bytes_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_len(this_: *const z_loaned_bytes_t) -> usize {
    crate::ffi::guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { bytes_slice(this_) }.map_or(0, <[u8]>::len)
    })
}

/// `true` iff the owned bytes holds a live payload (zenoh-c
/// `z_internal_bytes_check`).
///
/// # Safety
/// `this_` must be null or a valid owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_check(this_: *const z_owned_bytes_t) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned bytes (zenoh-c `z_internal_bytes_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned bytes.
#[no_mangle]
pub unsafe extern "C" fn z_internal_bytes_null(this_: *mut z_owned_bytes_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
    }
}

/// Construct the empty payload (zenoh-c `z_bytes_empty`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_empty(this_: *mut z_owned_bytes_t) {
    if this_.is_null() {
        return;
    }
    let handle = Box::into_raw(Box::new(BytesState {
        payload: Vec::new(),
    })) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_bytes_t::from_handle(handle) };
}

/// Copy the payload into an owned string (zenoh-c `z_bytes_to_string`).
///
/// The bytes are NOT validated as UTF-8, deliberately: upstream converts a byte
/// run to a *non-null-terminated* string and prints it with `%.*s`, so rejecting
/// a non-UTF-8 payload here would make wz refuse a sample zenoh-c delivers. wz's
/// string carries bytes and a length for the same reason.
///
/// # Safety
/// `this_` must be null or a valid loaned bytes; `dst` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_string(
    this_: *const z_loaned_bytes_t,
    dst: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        // Initialised before any fallible work, so a caller that ignores the code
        // sees an empty string rather than a stale stack value.
        unsafe { *dst = z_owned_string_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(bytes) = (unsafe { bytes_slice(this_) }) else {
            return Z_ENULL;
        };
        unsafe { *dst = owned_string_from(bytes) };
        Z_OK
    })
}

/// Free a payload and reset it to its gravestone state (zenoh-c
/// `z_bytes_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved bytes.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_drop(this_: *mut z_moved_bytes_t) {
    // SAFETY: the caller's contract, delegated — `take_payload` nulls the slot,
    // so a double drop is a no-op.
    let _ = unsafe { take_payload(this_) };
}
