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

use std::ffi::{c_char, CStr};

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
