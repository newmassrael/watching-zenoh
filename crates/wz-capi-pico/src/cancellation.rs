// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_cancellation_token_*` — pico's cancellation token, which both of its header arms declare.
//!
//! It lived in [`crate::sync`] until that module became what it documents, the multi-threaded
//! arm's host surface (mutex, condvar, task), which a build without `multi-thread` does not
//! have. The token does not depend on the arm.

use std::ffi::c_void;
use std::sync::Arc;

use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// The shared state behind a `z_owned_cancellation_token_t`.
///
/// Behind an `Arc`, which is what makes upstream's semantics
/// reproducible: pico's token is a REFCOUNTED value (`_Z_OWNED_TYPE_RC`), so a
/// clone and its original name the SAME cancellation state and cancelling
/// either cancels both. A plain copy of a bool would give each holder its own
/// flag and `z_cancellation_token_clone` would silently stop working.
///
/// R311y575 — the token also carries the ON-CANCEL HANDLER storage, which is
/// what makes it a cancellation plane rather than a flag two API calls agree
/// about. Upstream's token is exactly this pair: a sync group plus an intmap of
/// `_z_cancellation_token_on_cancel_handler_t`
/// (`vendor/zenoh-pico/src/session/cancellation.c:49-66`), and a get registers
/// one so that cancelling the token unregisters the get's pending query
/// (`src/session/query.c:306-334`).
///
/// R2949 — the model now lives in `wz_capi_core::cancellation`, shared with the
/// zenoh-c ABI, and it gained what this crate's copy lacked: `cancel` WAITS for
/// every registered get's callbacks to be dropped, which pico's
/// `_z_cancellation_token_cancel` does (`_z_sync_group_wait` after running the
/// handlers). The take-once handler storage and the registration refusal after
/// cancel has started are unchanged in meaning.
pub(crate) use wz_capi_core::cancellation::CancellationToken;

/// Consume a MOVED cancellation token, yielding the state it named.
///
/// Upstream's option structs declare this field as `z_moved_cancellation_token_t
/// *`, and both `z_get` and `z_liveliness_get` drop it unconditionally once the
/// call is made (`src/api/api.c:1783`, `src/api/liveliness.c:146`). So the field
/// is an ownership transfer, not a borrow: a caller that hands over a token must
/// not be left holding a live handle, and a callee that merely READ the pointer
/// would leak one per get. This takes the handle and nulls the caller's owned
/// struct, exactly as [`z_cancellation_token_drop`] does, and returns the `Arc`
/// so the caller keeps the state alive for as long as the get needs it.
///
/// # Safety
/// `moved` must be null or a valid moved token this crate produced.
#[cfg(feature = "query")]
pub(crate) unsafe fn take_moved_cancellation_token(
    moved: *mut z_moved_cancellation_token_t,
) -> Option<Arc<CancellationToken>> {
    if moved.is_null() {
        return None;
    }
    let handle = (*moved)._this.handle;
    (*moved)._this = z_owned_cancellation_token_t::null_value();
    if handle.is_null() {
        return None;
    }
    Some(*Box::from_raw(handle as *mut Arc<CancellationToken>))
}

/// pico `z_owned_cancellation_token_t` — `{ _z_cancellation_token_rc_t _rc }`,
/// 16 B MEASURED. Slot 0 carries this crate's `Arc` handle; slot 1 is the
/// refcount word upstream keeps there and wz leaves zero.
#[repr(C)]
pub struct z_owned_cancellation_token_t {
    handle: *mut c_void,
    _cnt: *mut c_void,
}

/// Loaned cancellation token — same footprint.
#[repr(C)]
pub struct z_loaned_cancellation_token_t {
    handle: *mut c_void,
    _cnt: *mut c_void,
}

/// Moved cancellation token.
#[repr(C)]
pub struct z_moved_cancellation_token_t {
    _this: z_owned_cancellation_token_t,
}

const _: () = {
    assert!(std::mem::size_of::<z_owned_cancellation_token_t>() == 16);
};

impl z_owned_cancellation_token_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
            _cnt: std::ptr::null_mut(),
        }
    }
}

/// The `Arc` behind a token handle, or `None` on a null / spent one.
///
/// # Safety
/// `ptr` must be null or a token this crate produced.
unsafe fn token_ref<'a>(
    ptr: *const z_loaned_cancellation_token_t,
) -> Option<&'a Arc<CancellationToken>> {
    if ptr.is_null() || (*ptr).handle.is_null() {
        return None;
    }
    Some(&*((*ptr).handle as *const Arc<CancellationToken>))
}

/// Build a fresh, uncancelled token (pico `z_cancellation_token_new`).
///
/// # Safety
/// `token` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_new(
    token: *mut z_owned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if token.is_null() {
            return Z_ERR_NULL;
        }
        let arc = CancellationToken::new();
        *token = z_owned_cancellation_token_t {
            handle: Box::into_raw(Box::new(arc)) as *mut c_void,
            _cnt: std::ptr::null_mut(),
        };
        Z_OK
    })
}

/// Cancel a token (pico `z_cancellation_token_cancel`).
///
/// Visible through every CLONE, which is the whole point of the type — see
/// [`CancellationToken`].
///
/// R311y575 — this also RUNS the registered on-cancel handlers, which is what
/// makes a cancelled token stop the gets it was handed to. The handlers are run
/// AFTER the lock is released (upstream does the same: `_z_cancellation_token_
/// call_handlers` swaps the storage out under the mutex and only then calls
/// them, `src/session/cancellation.c:128-144`) because a handler unregisters a
/// pending query, whose sink drop runs the C `drop(context)`, and a C callback
/// is explicitly allowed to re-enter the session.
///
/// R2949 — and it then WAITS until every get registered on the token has
/// dropped its callbacks, as pico's `_z_cancellation_token_cancel` does
/// (`_z_sync_group_wait` after the handler run). Before R2949 it returned as
/// soon as the handlers had run, so a reply callback already executing on a
/// drive task could still be running when `cancel` returned.
///
/// # Safety
/// `token` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_cancel(
    token: *mut z_loaned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| match token_ref(token as *const _) {
        Some(arc) => {
            arc.cancel();
            Z_OK
        }
        None => Z_ERR_NULL,
    })
}

/// Whether a token has been cancelled (pico
/// `z_cancellation_token_is_cancelled`).
///
/// # Safety
/// `token` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_is_cancelled(
    token: *const z_loaned_cancellation_token_t,
) -> bool {
    crate::ffi::guard_val(false, || match token_ref(token) {
        Some(arc) => arc.is_cancelled(),
        None => false,
    })
}

/// Clone a token so both handles name the SAME cancellation state (pico
/// `z_cancellation_token_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `src` must be null or a live loaned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_clone(
    dst: *mut z_owned_cancellation_token_t,
    src: *const z_loaned_cancellation_token_t,
) -> ZResult {
    crate::ffi::guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_cancellation_token_t::null_value();
        match token_ref(src) {
            Some(arc) => {
                *dst = z_owned_cancellation_token_t {
                    handle: Box::into_raw(Box::new(Arc::clone(arc))) as *mut c_void,
                    _cnt: std::ptr::null_mut(),
                };
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Release a token handle (pico `z_cancellation_token_drop`).
///
/// Drops THIS handle's `Arc`; the state survives while any clone holds one.
///
/// # Safety
/// `token` must be null or a valid moved token this crate produced.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_drop(token: *mut z_moved_cancellation_token_t) {
    let _ = crate::ffi::guarded(|| {
        if token.is_null() {
            return Z_OK;
        }
        let handle = (*token)._this.handle;
        (*token)._this = z_owned_cancellation_token_t::null_value();
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut Arc<CancellationToken>));
        }
        Z_OK
    });
}

/// Borrow a token (pico `z_cancellation_token_loan`) — offset-0 identity.
///
/// # Safety
/// `token` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan(
    token: *const z_owned_cancellation_token_t,
) -> *const z_loaned_cancellation_token_t {
    token as *const z_loaned_cancellation_token_t
}

/// Mutably borrow a token (pico `z_cancellation_token_loan_mut`).
///
/// # Safety
/// As [`z_cancellation_token_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_loan_mut(
    token: *mut z_owned_cancellation_token_t,
) -> *mut z_loaned_cancellation_token_t {
    token as *mut z_loaned_cancellation_token_t
}

/// Move-cast a token (pico `z_cancellation_token_move`).
///
/// # Safety
/// As [`z_cancellation_token_loan`].
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_move(
    token: *mut z_owned_cancellation_token_t,
) -> *mut z_moved_cancellation_token_t {
    token as *mut z_moved_cancellation_token_t
}

/// Take a token out of a moved wrapper (pico `z_cancellation_token_take`).
///
/// # Safety
/// Both pointers must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_cancellation_token_take(
    dst: *mut z_owned_cancellation_token_t,
    src: *mut z_moved_cancellation_token_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    *dst = z_owned_cancellation_token_t {
        handle: (*src)._this.handle,
        _cnt: (*src)._this._cnt,
    };
    (*src)._this = z_owned_cancellation_token_t::null_value();
}

/// Zero an owned token (pico `z_internal_cancellation_token_null`).
///
/// # Safety
/// `token` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_null(
    token: *mut z_owned_cancellation_token_t,
) {
    if !token.is_null() {
        *token = z_owned_cancellation_token_t::null_value();
    }
}

/// `true` iff the owned token holds a live state (pico
/// `z_internal_cancellation_token_check`).
///
/// # Safety
/// `token` must be null or a valid owned token.
#[no_mangle]
pub unsafe extern "C" fn z_internal_cancellation_token_check(
    token: *const z_owned_cancellation_token_t,
) -> bool {
    crate::ffi::guard_val(false, || !token.is_null() && !(*token).handle.is_null())
}
