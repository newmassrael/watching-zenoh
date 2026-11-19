// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the end-to-end protection doors share: the argument readers, the refusal slot and the
//! handle word. The doors are each capability's own module, as every wz door of this ABI is:
//! `crate::e2e_sender` (`e2e-sender`) and `crate::e2e_receiver` (`e2e-receiver`, with its
//! sender slots under `e2e-sender-demux`).
//!
//! The mechanism is `wz-app-frame`'s ([`wz_app_frame::e2e_stream_sender`],
//! [`wz_app_frame::e2e_receiver`]); the two door modules are the pico ABI's names, result codes and
//! ownership around it. The profile, the header values and the expected identifier are runtime data
//! the program hands over as JSON text: the library holds no deployment's constants.
//!
//! # Ownership and threads
//!
//! `*_new` makes an owned handle, every door that uses it takes the loan, and `*_drop` releases it
//! through the moved form and leaves the gravestone, so a second drop does nothing. One handle may
//! be called from several threads: each call holds the handle's lock for its whole work.

use core::ffi::{c_char, c_void, CStr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::abi::z_owned_string_t;
use crate::bytes::store_owned_string;

/// Write the gravestone into the caller's refusal slot, when it gave one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
pub(crate) unsafe fn clear_refusal(out: *mut z_owned_string_t) {
    if !out.is_null() {
        *out = z_owned_string_t::null_value();
    }
}

/// Write `text` as the caller's refusal, when it gave a slot for one.
///
/// # Safety
/// `out` is null or writable for a `z_owned_string_t`.
pub(crate) unsafe fn write_refusal(out: *mut z_owned_string_t, text: &str) {
    if !out.is_null() {
        store_owned_string(out, text.as_bytes());
    }
}

/// A NUL-terminated UTF-8 argument; `None` when it is not UTF-8.
///
/// # Safety
/// `text` is a valid C string.
pub(crate) unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    CStr::from_ptr(text).to_str().ok()
}

/// A byte argument as a slice.
///
/// # Safety
/// `bytes` is readable for `len` bytes when `len` is not 0, and non-null then.
pub(crate) unsafe fn bytes_arg<'a>(bytes: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(bytes, len)
    }
}

/// The lock, past a poison: a panic inside a call was caught at the door, and the state behind
/// the lock moves only once a call has succeeded.
pub(crate) fn locked<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The value behind a loaned handle; `None` for a null pointer or the gravestone.
///
/// # Safety
/// `handle` is null or points at a handle word these modules wrote, whose value is null or a live
/// `Mutex<T>` they boxed.
pub(crate) unsafe fn behind<'a, T>(handle: *const *mut c_void) -> Option<&'a Mutex<T>> {
    if handle.is_null() {
        return None;
    }
    let value = *handle;
    if value.is_null() {
        return None;
    }
    Some(&*value.cast::<Mutex<T>>())
}

/// Box `value` behind a handle word.
pub(crate) fn adopt<T>(value: T) -> *mut c_void {
    Box::into_raw(Box::new(Mutex::new(value))).cast::<c_void>()
}

/// Release what a handle word holds and leave it null.
///
/// # Safety
/// `handle` is null or points at a handle word whose value is null or a live `Mutex<T>` these
/// modules boxed.
pub(crate) unsafe fn release<T>(handle: *mut *mut c_void) {
    if handle.is_null() {
        return;
    }
    let value = *handle;
    *handle = core::ptr::null_mut();
    if !value.is_null() {
        drop(Box::from_raw(value.cast::<Mutex<T>>()));
    }
}
