// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VIEW keyexpr — a keyexpr that borrows the caller's string.
//!
//! zenoh-c's `z_view_keyexpr_from_str` ALIASES the `const char*` it is given
//! rather than copying it, and upstream's `z_put.c` relies on that: the string it
//! passes is `args.keyexpr`, which outlives the put. wz stores an owned copy
//! behind the handle instead, which is a strict superset of the contract (a
//! caller whose string dies early is served correctly here and would be a
//! use-after-free upstream) and costs one allocation per view.
//!
//! The divergence is recorded rather than hidden because it is observable in one
//! direction: a program that mutates its buffer AFTER constructing the view and
//! expects the put to see the new bytes gets the OLD bytes here. Upstream's
//! examples do not do that, and a copy is the safe direction to differ in.

use std::ffi::{c_char, CStr};

use crate::abi::{z_loaned_keyexpr_t, z_view_keyexpr_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_EPARSE, Z_OK};

/// The owned copy behind a view keyexpr's handle.
pub(crate) struct KeyexprState {
    pub(crate) keyexpr: String,
}

/// Read the keyexpr behind a loaned handle.
///
/// # Safety
/// `ke` must be null or a valid loaned keyexpr whose handle is live.
pub(crate) unsafe fn keyexpr_str<'a>(ke: *const z_loaned_keyexpr_t) -> Option<&'a str> {
    if ke.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*ke).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<KeyexprState>` this crate leaked.
    Some(&unsafe { &*(handle as *const KeyexprState) }.keyexpr)
}

/// Construct a view keyexpr from a NUL-terminated string (zenoh-c
/// `z_view_keyexpr_from_str`).
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str(
    this_: *mut z_view_keyexpr_t,
    expr: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || expr.is_null() {
            return Z_ENULL;
        }
        // Always initialise the out-param before any fallible work, so a caller
        // that ignores the code sees a gravestone rather than a stale stack value.
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        // SAFETY: the caller's contract.
        let Ok(text) = (unsafe { CStr::from_ptr(expr) }).to_str() else {
            return Z_EPARSE;
        };
        if text.is_empty() {
            return Z_EPARSE;
        }
        let handle = Box::into_raw(Box::new(KeyexprState {
            keyexpr: text.to_owned(),
        })) as Handle;
        unsafe { *this_ = z_view_keyexpr_t::from_handle(handle) };
        Z_OK
    })
}

/// Borrow a view keyexpr (zenoh-c `z_view_keyexpr_loan`).
///
/// # Safety
/// `this_` must be null or a valid view keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan(
    this_: *const z_view_keyexpr_t,
) -> *const z_loaned_keyexpr_t {
    this_ as *const z_loaned_keyexpr_t
}

/// Construct a view keyexpr WITHOUT canonicity validation (zenoh-c
/// `z_view_keyexpr_from_str_unchecked`).
///
/// Upstream returns `void`: the whole point of the export is that the caller has
/// asserted the string is already canonical, so there is no verdict to report.
/// `z_pong.c` uses it for its compile-time literal.
///
/// wz still refuses a NULL or non-UTF-8 pointer, because those are not "skipped
/// validation" but an unreadable argument — there is no keyexpr to alias at all.
/// The out-param is left in its gravestone state on that path, which is what a
/// caller's later `z_loan` reads as invalid.
///
/// # Safety
/// `this_` must be null or valid and writable; `s` must be null or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_str_unchecked(
    this_: *mut z_view_keyexpr_t,
    s: *const c_char,
) {
    // SAFETY: the caller's contract, delegated. The checked constructor performs
    // no canonicity check of its own either — this crate's canonicity gate is
    // applied at DECLARATION and PUBLISH time, where a verdict can be reported —
    // so the two differ only in upstream's return type.
    let _ = unsafe { z_view_keyexpr_from_str(this_, s) };
}

/// Borrow a view keyexpr mutably (zenoh-c `z_view_keyexpr_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid view keyexpr.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_loan_mut(
    this_: *mut z_view_keyexpr_t,
) -> *mut z_loaned_keyexpr_t {
    this_ as *mut z_loaned_keyexpr_t
}
