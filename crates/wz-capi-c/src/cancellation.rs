// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Cancellation tokens — the plane three option structs already reserve a slot
//! for, and that nothing could fill.
//!
//! ## Why this existed as a hole rather than as an absence
//!
//! `z_get_options_t`, `z_querier_get_options_t` and the liveliness get carry a
//! `cancellation_token` field, and wz has been declaring it `*mut c_void` — a
//! slot of the right size holding nothing. A C program that built a token and
//! passed it got a SILENT no-op: the field was read as an opaque pointer and
//! dropped on the floor, which is the shape R2203 named. The reason the field
//! could not be typed is that `z_moved_cancellation_token_t` names a family of
//! seven public functions plus its internal check/null pair, and declaring the
//! type without defining them is a header that promises a link that fails.
//!
//! R2256's census re-measurement (open-debt item 594) put a number on it: nine
//! symbols, missing on BOTH the `unstable` and `unstable-shm` arms, and one of
//! only four self-contained planes in the 103 that upstream 1.10.0 grew and wz
//! had not built.
//!
//! ## The layout is READ, not guessed
//!
//! `zenoh_opaque.h` gives `z_owned_cancellation_token_t` as `ALIGN(8) uint8_t
//! _0[24]`, so the owned form is a pointer plus 16 bytes of reserve, exactly
//! the shape [`z_owned_matching_listener_t`](crate::matching) uses for the same
//! 24/8 contract. The static assertions below are the check; the header is the
//! source.
//!
//! ## What a token DOES here
//!
//! It carries a flag two sides can see: the holder cancels, and whoever was
//! handed a loan observes it. That is the whole of upstream's contract on this
//! type — `cancel` sets, `is_cancelled` reads, `clone` shares the same flag
//! rather than copying its value, and `drop` releases one reference. Wiring a
//! token into a running query is the NEXT question and is deliberately not
//! answered here: the option fields keep their `*mut c_void` spelling until a
//! round can honour them end to end, and this module is what makes such a
//! round possible at all.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::result::{ZResult, Z_ENULL, Z_OK};

/// The shared flag an owned token points at.
///
/// `Arc` rather than a raw box because `clone` must SHARE — a token cloned and
/// then cancelled has to be observed as cancelled through the original, which
/// is what makes the type worth having.
struct TokenState {
    cancelled: AtomicBool,
}

/// Owned cancellation token (zenoh-c `z_owned_cancellation_token_t`,
/// `zenoh_opaque.h`: `ALIGN(8) uint8_t _0[24]`).
#[repr(C)]
pub struct z_owned_cancellation_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 16],
}

/// Loaned cancellation token — the same bytes, borrowed.
#[repr(C)]
pub struct z_loaned_cancellation_token_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [u8; 16],
}

/// Moved cancellation token.
#[repr(C)]
pub struct z_moved_cancellation_token_t {
    pub(crate) _this: z_owned_cancellation_token_t,
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_cancellation_token_t>() == 24);
    assert!(std::mem::align_of::<z_owned_cancellation_token_t>() == 8);
    assert!(std::mem::size_of::<z_loaned_cancellation_token_t>() == 24);
    assert!(std::mem::size_of::<z_moved_cancellation_token_t>() == 24);
};

impl z_owned_cancellation_token_t {
    /// The gravestone value.
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _pad: [0u8; 16],
        }
    }
}

/// Borrow the state behind a loaned token.
///
/// # Safety
/// `this_` must be a valid loaned token whose handle this crate created.
#[inline]
unsafe fn state<'a>(handle: *mut c_void) -> Option<&'a Arc<TokenState>> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract — the handle is an `Arc<TokenState>` this
    // module leaked in `z_cancellation_token_new`.
    Some(unsafe { &*(handle as *const Arc<TokenState>) })
}

/// zenoh-c `z_cancellation_token_new` — construct an uncancelled token.
///
/// # Safety
/// `this_` must be writable.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_new(
    this_: *mut z_owned_cancellation_token_t,
) -> ZResult {
    if this_.is_null() {
        return Z_ENULL;
    }
    let state = Arc::new(TokenState {
        cancelled: AtomicBool::new(false),
    });
    let handle = Box::into_raw(Box::new(state)) as *mut c_void;
    // SAFETY: checked non-null above.
    unsafe {
        *this_ = z_owned_cancellation_token_t {
            handle,
            _pad: [0u8; 16],
        };
    }
    Z_OK
}

/// zenoh-c `z_cancellation_token_cancel` — set the flag.
///
/// # Safety
/// `this_` must be a valid loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_cancel(
    this_: *mut z_loaned_cancellation_token_t,
) -> ZResult {
    if this_.is_null() {
        return Z_ENULL;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: the handle came from `z_cancellation_token_new`.
    match unsafe { state(handle) } {
        Some(st) => {
            st.cancelled.store(true, Ordering::SeqCst);
            Z_OK
        }
        None => Z_ENULL,
    }
}

/// zenoh-c `z_cancellation_token_is_cancelled`.
///
/// # Safety
/// `this_` must be a valid loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_is_cancelled(
    this_: *const z_loaned_cancellation_token_t,
) -> bool {
    if this_.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: the handle came from `z_cancellation_token_new`.
    match unsafe { state(handle) } {
        Some(st) => st.cancelled.load(Ordering::SeqCst),
        None => false,
    }
}

/// zenoh-c `z_cancellation_token_clone` — SHARE the flag, do not copy it.
///
/// # Safety
/// `dst` must be writable and `this_` a valid loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_clone(
    dst: *mut z_owned_cancellation_token_t,
    this_: *const z_loaned_cancellation_token_t,
) {
    if dst.is_null() {
        return;
    }
    let cloned = if this_.is_null() {
        None
    } else {
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        // SAFETY: the handle came from `z_cancellation_token_new`.
        unsafe { state(handle) }.map(Arc::clone)
    };
    // SAFETY: checked non-null above.
    unsafe {
        *dst = match cloned {
            Some(st) => z_owned_cancellation_token_t {
                handle: Box::into_raw(Box::new(st)) as *mut c_void,
                _pad: [0u8; 16],
            },
            None => z_owned_cancellation_token_t::null_value(),
        };
    }
}

/// zenoh-c `z_cancellation_token_loan`.
///
/// # Safety
/// `this_` must be a valid owned token that outlives the returned borrow.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan(
    this_: *const z_owned_cancellation_token_t,
) -> *const z_loaned_cancellation_token_t {
    this_ as *const z_loaned_cancellation_token_t
}

/// zenoh-c `z_cancellation_token_loan_mut`.
///
/// # Safety
/// `this_` must be a valid owned token that outlives the returned borrow.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan_mut(
    this_: *mut z_owned_cancellation_token_t,
) -> *mut z_loaned_cancellation_token_t {
    this_ as *mut z_loaned_cancellation_token_t
}

/// zenoh-c `z_cancellation_token_drop` — release one reference and gravestone.
///
/// # Safety
/// `this_` must be a valid moved token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_drop(this_: *mut z_moved_cancellation_token_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let owned = unsafe { &mut (*this_)._this };
    if !owned.handle.is_null() {
        // SAFETY: the handle came from `Box::into_raw` in `new` or `clone`.
        drop(unsafe { Box::from_raw(owned.handle as *mut Arc<TokenState>) });
    }
    *owned = z_owned_cancellation_token_t::null_value();
}

/// zenoh-c `z_internal_cancellation_token_check`.
///
/// # Safety
/// `this_` must be a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_check(
    this_: *const z_owned_cancellation_token_t,
) -> bool {
    if this_.is_null() {
        return false;
    }
    // SAFETY: the caller's contract.
    !unsafe { (*this_).handle }.is_null()
}

/// zenoh-c `z_internal_cancellation_token_null` — write the gravestone.
///
/// # Safety
/// `this_` must be writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_null(
    this_: *mut z_owned_cancellation_token_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: checked non-null above.
    unsafe {
        *this_ = z_owned_cancellation_token_t::null_value();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token starts uncancelled, cancels once, and reads back cancelled.
    #[test]
    fn cancel_is_observable() {
        let mut owned = z_owned_cancellation_token_t::null_value();
        assert_eq!(unsafe { z_cancellation_token_new(&mut owned) }, Z_OK);
        assert!(unsafe { z_internal_cancellation_token_check(&owned) });

        let loaned = unsafe { z_cancellation_token_loan_mut(&mut owned) };
        assert!(!unsafe { z_cancellation_token_is_cancelled(loaned) });
        assert_eq!(unsafe { z_cancellation_token_cancel(loaned) }, Z_OK);
        assert!(unsafe { z_cancellation_token_is_cancelled(loaned) });

        let mut moved = z_moved_cancellation_token_t { _this: owned };
        unsafe { z_cancellation_token_drop(&mut moved) };
        assert!(!unsafe { z_internal_cancellation_token_check(&moved._this) });
    }

    /// A CLONE shares the flag. Copying the value instead would make the type
    /// useless — the point of handing a token to a callee is that the caller
    /// can cancel it afterwards.
    #[test]
    fn clone_shares_the_flag_rather_than_its_value() {
        let mut a = z_owned_cancellation_token_t::null_value();
        assert_eq!(unsafe { z_cancellation_token_new(&mut a) }, Z_OK);
        let mut b = z_owned_cancellation_token_t::null_value();
        unsafe { z_cancellation_token_clone(&mut b, z_cancellation_token_loan(&a)) };
        assert!(unsafe { z_internal_cancellation_token_check(&b) });

        // Cancel through A, observe through B.
        assert_eq!(
            unsafe { z_cancellation_token_cancel(z_cancellation_token_loan_mut(&mut a)) },
            Z_OK
        );
        assert!(unsafe { z_cancellation_token_is_cancelled(z_cancellation_token_loan(&b)) });

        // Dropping A leaves B readable — the state is shared, not owned by one.
        let mut moved_a = z_moved_cancellation_token_t { _this: a };
        unsafe { z_cancellation_token_drop(&mut moved_a) };
        assert!(unsafe { z_cancellation_token_is_cancelled(z_cancellation_token_loan(&b)) });

        let mut moved_b = z_moved_cancellation_token_t { _this: b };
        unsafe { z_cancellation_token_drop(&mut moved_b) };
    }

    /// The gravestone answers every accessor without a token behind it, which
    /// is what a C caller gets from `z_internal_cancellation_token_null`.
    #[test]
    fn a_gravestone_is_safe_to_read() {
        let mut owned = z_owned_cancellation_token_t::null_value();
        unsafe { z_internal_cancellation_token_null(&mut owned) };
        assert!(!unsafe { z_internal_cancellation_token_check(&owned) });
        assert!(!unsafe { z_cancellation_token_is_cancelled(z_cancellation_token_loan(&owned)) });
        assert_eq!(
            unsafe { z_cancellation_token_cancel(z_cancellation_token_loan_mut(&mut owned)) },
            Z_ENULL
        );
        // Dropping a gravestone is a no-op rather than a double free.
        let mut moved = z_moved_cancellation_token_t { _this: owned };
        unsafe { z_cancellation_token_drop(&mut moved) };
    }

    /// A null clone SOURCE yields a gravestone rather than a dangling handle.
    #[test]
    fn cloning_nothing_yields_a_gravestone() {
        let mut dst = z_owned_cancellation_token_t {
            handle: 1 as *mut c_void,
            _pad: [0u8; 16],
        };
        unsafe { z_cancellation_token_clone(&mut dst, std::ptr::null()) };
        assert!(!unsafe { z_internal_cancellation_token_check(&dst) });
    }
}
