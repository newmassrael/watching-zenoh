// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SENDING side of an end-to-end protected message, reachable from the
//! library a resident participant links.
//!
//! # What this is, and the road not taken
//!
//! `wz_dissect_e2e_wrap` (in `wz-capi-dissect`) builds ONE protected frame from
//! values the caller writes, the counter among them. A participant process that
//! stays up and repeats a message needs the counter to advance on every send, and
//! a caller that keeps the counter itself holds a second copy of the rule for when
//! it advances. This module is the one copy: an owned sender made for ONE message
//! under ONE profile, which writes the profile's counter field itself.
//!
//! It is a sender and not a copy of the stateless door. The frame comes out of
//! the same writer (`wz_capture::e2e_json`), so this library and the dissect
//! library cannot disagree about a header; what is new is only the counter
//! the handle keeps. A caller that numbers its own frames keeps using
//! `wz_dissect_e2e_wrap`.
//!
//! # One sender per message
//!
//! Two messages that share a profile keep two senders and so two counters. A
//! periodic message is one sender called again and again.
//!
//! # The counter
//!
//! * [`wz_capi_c_e2e_sender_new`] takes the value the FIRST frame carries. A
//!   process restarted on reconnect passes it again.
//! * A frame that is built carries the next value, and the next value moves by
//!   one. A frame that is refused (the values text, the body, the length, the
//!   counter) builds nothing and consumes no value.
//! * The counter does NOT wrap by default. The frame that carries the largest
//!   value the counter field holds is built; the next call is refused, with a
//!   reason that names the field and the value. A wrapped counter would put a
//!   value on the wire nobody asked for, and whether a receiver treats the step
//!   down as a legitimate wrap or a fault is the receiver's rule.
//!   [`WZ_CAPI_C_E2E_ROLLOVER_WRAP`] counts on from zero instead and is chosen by
//!   name.
//! * A start value that does not fit the field is refused by the first frame,
//!   like any value that does not fit, and consumes nothing.
//! * The values text must NOT state the counter field: a text that does is
//!   refused, because there is no rule for which of the two would win.
//!
//! # Refusals are documents
//!
//! A text this library was handed and refused is a successful DIAGNOSIS, the rule
//! every document door in this tree keeps: [`wz_capi_c_e2e_sender_wrap`] returns
//! `Z_OK` and writes the `e2e_wrap` document, `"ok":false` with the reason and
//! the place, so the return value says whether the call was well formed and the
//! document says whether a frame was built. The constructor is the exception that
//! proves it: a sender that does not exist cannot be handed back, so a profile
//! that is not one is `Z_EPARSE` with the same document in `refusal`.
//!
//! # Threads
//!
//! One handle may be called from several threads: the counter and the frame
//! are taken under one lock, so two calls get two values.
//!
//! The doors carry wz's own prefix and no `zenoh-c-no-unstable-api` gate, for the
//! reason `config_verdict` gives: upstream zenoh-c has nothing of the kind to be a
//! drop-in for.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, CStr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use wz_capture::e2e_sender::{Rollover, Sender};

use crate::abi::{z_owned_string_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::{null_string, owned_string_from};

/// What the counter does after the frame that carried its largest value.
pub type wz_capi_c_e2e_rollover_t = i32;

/// Refuse the next frame. The default a caller should pass unless it has a rule
/// that says otherwise.
pub const WZ_CAPI_C_E2E_ROLLOVER_REFUSE: wz_capi_c_e2e_rollover_t = 0;
/// Count on from zero.
pub const WZ_CAPI_C_E2E_ROLLOVER_WRAP: wz_capi_c_e2e_rollover_t = 1;

/// An owned sender. One handle; wz-own, so there is no upstream size to pad to.
#[repr(C)]
pub struct wz_capi_c_owned_e2e_sender_t {
    pub(crate) handle: Handle,
}

/// A loaned sender: the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct wz_capi_c_loaned_e2e_sender_t {
    pub(crate) handle: Handle,
}

/// A moved sender.
#[repr(C)]
pub struct wz_capi_c_moved_e2e_sender_t {
    pub(crate) _this: wz_capi_c_owned_e2e_sender_t,
}

impl wz_capi_c_owned_e2e_sender_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }

    fn adopt(sender: Sender) -> Self {
        Self {
            handle: Box::into_raw(Box::new(Mutex::new(sender))) as Handle,
        }
    }
}

/// The sender behind a loaned handle.
///
/// # Safety
/// `this_` must be null or a valid loaned sender.
unsafe fn sender_of<'a>(this_: *const wz_capi_c_loaned_e2e_sender_t) -> Option<&'a Mutex<Sender>> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: a live `Mutex<Sender>` this crate boxed in `adopt`.
    (!handle.is_null()).then(|| unsafe { &*(handle as *const Mutex<Sender>) })
}

/// The lock, past a poison: a panic inside a call was caught at the door, and
/// the sender's own state is only ever replaced whole.
fn locked(sender: &Mutex<Sender>) -> MutexGuard<'_, Sender> {
    sender.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Write `text` as the owned string `out`.
///
/// # Safety
/// `out` must be valid and writable for a `z_owned_string_t`.
unsafe fn write_string(out: *mut z_owned_string_t, text: &str) {
    // SAFETY: the caller's contract.
    unsafe { *out = owned_string_from(text.as_bytes()) };
}

/// Read a NUL-terminated UTF-8 argument.
///
/// # Safety
/// `text` must be a valid C string.
unsafe fn utf8_arg<'a>(text: *const c_char) -> Option<&'a str> {
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(text) }.to_str().ok()
}

/// A sender for the message `profile_json` describes, whose first frame carries
/// `first_counter`.
///
/// `this_` holds a gravestone on every error. `refusal` may be NULL; when it is
/// not, it is set to an empty string on success, and on `Z_EPARSE` it holds the
/// `e2e_wrap` document that says why the profile was refused.
///
/// Returns `Z_ENULL` for a null `this_` or `profile_json`, `Z_EINVAL` for text
/// that is not UTF-8 or a `rollover` this library does not know, `Z_EPARSE` for
/// a profile that is not one, and `Z_OK` otherwise.
///
/// # Safety
/// `this_` must be writable; `profile_json` a NUL-terminated C string; `refusal`
/// null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_new(
    this_: *mut wz_capi_c_owned_e2e_sender_t,
    profile_json: *const c_char,
    first_counter: u64,
    rollover: wz_capi_c_e2e_rollover_t,
    refusal: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if !refusal.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *refusal = null_string() };
        }
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_e2e_sender_t::null_value() };
        if profile_json.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(profile) = (unsafe { utf8_arg(profile_json) }) else {
            return Z_EINVAL;
        };
        let rollover = match rollover {
            WZ_CAPI_C_E2E_ROLLOVER_REFUSE => Rollover::Refuse,
            WZ_CAPI_C_E2E_ROLLOVER_WRAP => Rollover::Wrap,
            _ => return Z_EINVAL,
        };
        match Sender::new(profile, first_counter, rollover) {
            Ok(sender) => {
                // SAFETY: checked non-null above.
                unsafe { *this_ = wz_capi_c_owned_e2e_sender_t::adopt(sender) };
                Z_OK
            }
            Err(document) => {
                if !refusal.is_null() {
                    // SAFETY: checked non-null just now.
                    unsafe { write_string(refusal, &document) };
                }
                Z_EPARSE
            }
        }
    })
}

/// Build the next frame of the message: the `e2e_wrap` document, the frame as
/// hex in `frame` when `"ok":true`, with the counter the sender kept written in
/// the profile's counter field.
///
/// `values_json` holds every header field the sender and the mechanism do not
/// supply (the CRC and the length are computed, the counter is the sender's),
/// and may carry the body as an `@body` member, as for `wz_dissect_e2e_wrap`.
/// `payload` is the body already serialized, and may be NULL only when
/// `payload_len` is zero; giving a body both ways is refused.
///
/// `Z_OK` for any call that was well formed, whether or not a frame was built:
/// read `"ok"` in the document. A refused frame consumes no counter value.
/// `out` holds a gravestone on every error return.
///
/// Returns `Z_ENULL` for a null argument (or a null `payload` with a length) and
/// `Z_EINVAL` for text that is not UTF-8.
///
/// # Safety
/// `this_` null or a valid loaned sender; `values_json` a NUL-terminated C
/// string; `payload` readable for `payload_len` bytes; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_wrap(
    this_: *const wz_capi_c_loaned_e2e_sender_t,
    values_json: *const c_char,
    payload: *const u8,
    payload_len: usize,
    out: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = null_string() };
        // SAFETY: the caller's contract.
        let Some(sender) = (unsafe { sender_of(this_) }) else {
            return Z_ENULL;
        };
        if values_json.is_null() || (payload.is_null() && payload_len != 0) {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(values) = (unsafe { utf8_arg(values_json) }) else {
            return Z_EINVAL;
        };
        let body: &[u8] = if payload_len == 0 {
            &[]
        } else {
            // SAFETY: the caller's contract; non-null was checked above.
            unsafe { std::slice::from_raw_parts(payload, payload_len) }
        };
        let document = locked(sender).wrap(values, body);
        // SAFETY: checked non-null above.
        unsafe { write_string(out, &document) };
        Z_OK
    })
}

/// The value the next frame carries. Returns `false`, and writes nothing, when
/// the largest value was sent and the sender does not wrap, or when `this_` or
/// `out` is null.
///
/// # Safety
/// `this_` null or a valid loaned sender; `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_next(
    this_: *const wz_capi_c_loaned_e2e_sender_t,
    out: *mut u64,
) -> bool {
    if out.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    let Some(sender) = (unsafe { sender_of(this_) }) else {
        return false;
    };
    let Some(next) = locked(sender).next() else {
        return false;
    };
    // SAFETY: checked non-null above.
    unsafe { *out = next };
    true
}

/// Make `value` the one the next frame carries. A value past the counter field's
/// width is accepted here and refused by the frame, as a start value is.
///
/// Returns `Z_ENULL` for a null or empty handle and `Z_OK` otherwise.
///
/// # Safety
/// `this_` null or a valid loaned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_set(
    this_: *const wz_capi_c_loaned_e2e_sender_t,
    value: u64,
) -> ZResult {
    // SAFETY: the caller's contract.
    let Some(sender) = (unsafe { sender_of(this_) }) else {
        return Z_ENULL;
    };
    locked(sender).set(value);
    Z_OK
}

/// Borrow a sender.
///
/// # Safety
/// `this_` null or a valid owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_loan(
    this_: *const wz_capi_c_owned_e2e_sender_t,
) -> *const wz_capi_c_loaned_e2e_sender_t {
    this_ as *const wz_capi_c_loaned_e2e_sender_t
}

/// Release a sender. A second drop is a no-op.
///
/// # Safety
/// `this_` null or a valid moved sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_e2e_sender_drop(this_: *mut wz_capi_c_moved_e2e_sender_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        // SAFETY: the caller's contract.
        unsafe { (*this_)._this = wz_capi_c_owned_e2e_sender_t::null_value() };
        if !handle.is_null() {
            // SAFETY: a live `Box<Mutex<Sender>>` this crate leaked in `adopt`.
            drop(unsafe { Box::from_raw(handle as *mut Mutex<Sender>) });
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_e2e_sender_null(
    this_: *mut wz_capi_c_owned_e2e_sender_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_e2e_sender_t::null_value() };
    }
}

/// Whether the slot holds a sender.
///
/// # Safety
/// `this_` null or a valid owned sender.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_e2e_sender_check(
    this_: *const wz_capi_c_owned_e2e_sender_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}
