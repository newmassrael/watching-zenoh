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

/// Construct a view keyexpr from a pointer plus LENGTH (zenoh-c
/// `z_view_keyexpr_from_substr`).
///
/// The length form rather than the NUL-terminated one, which `z_get.c` uses to
/// take a keyexpr out of the middle of a `keyexpr?parameters` selector its own
/// argument parser split — so the source bytes are NOT terminated at `len` and
/// reading them as a C string would swallow the parameters.
///
/// # Safety
/// `this_` must be valid and writable; `expr` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_view_keyexpr_from_substr(
    this_: *mut z_view_keyexpr_t,
    expr: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || expr.is_null() {
            return Z_ENULL;
        }
        // The gravestone before any fallible work.
        unsafe { *this_ = z_view_keyexpr_t::null_value() };
        // SAFETY: the caller's contract — `len` readable bytes at `expr`.
        let bytes = unsafe { std::slice::from_raw_parts(expr as *const u8, len) };
        let Ok(text) = std::str::from_utf8(bytes) else {
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

/// `true` iff the two keyexprs INTERSECT (zenoh-c `z_keyexpr_intersects`).
///
/// Intersection, not inclusion and not equality: `z_storage.c` uses it to decide
/// which of its stored keys a wildcard query covers, so `demo/**` must intersect
/// `demo/a` in BOTH argument orders. Routed through the one matching SSOT
/// ([`wz_runtime_tokio::keyexpr_match`]) that the reply gate uses, rather than
/// re-derived.
///
/// # Safety
/// `left` and `right` must be null or valid loaned keyexprs.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_intersects(
    left: *const z_loaned_keyexpr_t,
    right: *const z_loaned_keyexpr_t,
) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract, delegated.
        let (Some(a), Some(b)) = (unsafe { keyexpr_str(left) }, unsafe { keyexpr_str(right) })
        else {
            return false;
        };
        let a_chunks: Vec<&str> = a.split('/').collect();
        let b_chunks: Vec<&str> = b.split('/').collect();
        wz_runtime_tokio::keyexpr_match::keyexpr_intersect_patterns(&a_chunks, &b_chunks)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The substring constructor stops at `len` rather than at a NUL — the
    /// property `z_get.c` depends on when it points at the middle of a
    /// `keyexpr?parameters` selector.
    #[test]
    fn the_substr_constructor_stops_at_the_length_not_at_a_nul() {
        let selector = c"demo/example/**?value=1";
        let mut view = z_view_keyexpr_t::null_value();
        // SAFETY: `selector` is a live C string and `view` a live local.
        unsafe {
            assert_eq!(
                z_view_keyexpr_from_substr(&mut view, selector.as_ptr(), 15),
                Z_OK
            );
            let loaned = z_view_keyexpr_loan(&view);
            assert_eq!(
                keyexpr_str(loaned),
                Some("demo/example/**"),
                "the constructor read past its length into the parameters"
            );
        }
    }

    /// Intersection is SYMMETRIC and is not equality — the two properties
    /// `z_storage.c`'s wildcard get rests on.
    #[test]
    fn keyexpr_intersection_is_symmetric_and_is_not_equality() {
        let mut wild = z_view_keyexpr_t::null_value();
        let mut concrete = z_view_keyexpr_t::null_value();
        let mut other = z_view_keyexpr_t::null_value();
        // SAFETY: live locals and live C strings.
        unsafe {
            assert_eq!(
                z_view_keyexpr_from_str(&mut wild, c"demo/**".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_view_keyexpr_from_str(&mut concrete, c"demo/a/b".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_view_keyexpr_from_str(&mut other, c"other/a".as_ptr()),
                Z_OK
            );
            let (w, c, o) = (
                z_view_keyexpr_loan(&wild),
                z_view_keyexpr_loan(&concrete),
                z_view_keyexpr_loan(&other),
            );
            assert!(z_keyexpr_intersects(w, c));
            assert!(z_keyexpr_intersects(c, w), "intersection must be symmetric");
            assert!(!z_keyexpr_intersects(w, o));
            assert!(!z_keyexpr_intersects(std::ptr::null(), c));
            assert!(!z_keyexpr_intersects(c, std::ptr::null()));
        }
    }
}
