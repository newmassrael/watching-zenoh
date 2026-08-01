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

use crate::abi::{z_moved_bytes_t, z_owned_bytes_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_EPARSE, Z_OK};

/// The owned payload behind a bytes handle.
pub(crate) struct BytesState {
    pub(crate) payload: Vec<u8>,
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
