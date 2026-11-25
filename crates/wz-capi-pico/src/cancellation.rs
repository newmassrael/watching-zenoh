// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_cancellation_token_*` — pico's cancellation token, which both of its header arms declare.
//!
//! It lived in [`crate::sync`] until that module became what it documents, the multi-threaded
//! arm's host surface (mutex, condvar, task), which a build without `multi-thread` does not
//! have. The token does not depend on the arm.

use core::ffi::c_void;

use wz_capi_port::lodge::Strong;

use crate::result::{ZResult, Z_ERR_NULL, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK};

/// The shared state behind a `z_owned_cancellation_token_t`.
///
/// Shared by counts ([`Strong`]), which is what makes upstream's semantics
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
/// R2949 — the model now lives in the C ABI's engine port (`wz_capi_port::cancellation`,
/// written in `wz-capi-core`), shared with the zenoh-c ABI and with every engine that issues a
/// get, and it gained what this crate's copy lacked: `cancel` WAITS for every registered get's
/// callbacks to be dropped, which pico's `_z_cancellation_token_cancel` does
/// (`_z_sync_group_wait` after running the handlers). A get's registration is its fan, which
/// lies in the get's place and is linked into the token's list there, and a registration is
/// still refused once a cancel has started. The token a program creates is shared by its handles,
/// in a place of the process's table of tokens in a kernel's build, so the plane asks no heap
/// there; a token with no place left is refused as pico refuses one its heap cannot hold.
pub(crate) use wz_capi_port::cancellation::CancellationToken;

/// Consume a MOVED cancellation token, yielding the state it named.
///
/// Upstream's option structs declare this field as `z_moved_cancellation_token_t
/// *`, and both `z_get` and `z_liveliness_get` drop it unconditionally once the
/// call is made (`src/api/api.c:1783`, `src/api/liveliness.c:146`). So the field
/// is an ownership transfer, not a borrow: a caller that hands over a token must
/// not be left holding a live handle, and a callee that merely READ the pointer
/// would leak one per get. This takes the handle and nulls the caller's owned
/// struct, exactly as [`z_cancellation_token_drop`] does, and returns the count
/// so the caller keeps the state alive for as long as the get needs it.
///
/// # Safety
/// `moved` must be null or a valid moved token this crate produced.
#[cfg(feature = "query")]
pub(crate) unsafe fn take_moved_cancellation_token(
    moved: *mut z_moved_cancellation_token_t,
) -> Option<Strong<CancellationToken>> {
    if moved.is_null() {
        return None;
    }
    let handle = (*moved)._this.handle;
    (*moved)._this = z_owned_cancellation_token_t::null_value();
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's: a live handle is a count `Strong::into_raw` gave up, taken once here.
    Some(unsafe { Strong::from_raw(handle) })
}

/// pico `z_owned_cancellation_token_t` — `{ _z_cancellation_token_rc_t _rc }`,
/// 16 B MEASURED on a 64-bit host: the rc's value pointer and its count pointer, two
/// words on any host. Slot 0 carries a count of this crate's token; slot 1 is the
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
    assert!(
        core::mem::size_of::<z_owned_cancellation_token_t>()
            == 2 * core::mem::size_of::<*mut c_void>()
    );
};

impl z_owned_cancellation_token_t {
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _cnt: core::ptr::null_mut(),
        }
    }
}

/// The count a token handle holds, or `None` on a null / spent one.
///
/// # Safety
/// `ptr` must be null or a token this crate produced.
unsafe fn token_raw(ptr: *const z_loaned_cancellation_token_t) -> Option<*mut c_void> {
    if ptr.is_null() || (*ptr).handle.is_null() {
        return None;
    }
    Some((*ptr).handle)
}

/// The token behind a token handle, or `None` on a null / spent one.
///
/// # Safety
/// `ptr` must be null or a token this crate produced, held for `'a`.
unsafe fn token_ref<'a>(
    ptr: *const z_loaned_cancellation_token_t,
) -> Option<&'a CancellationToken> {
    let raw = token_raw(ptr)?;
    // SAFETY: the caller's: the handle holds a count of the token.
    Some(unsafe { Strong::<CancellationToken>::value_of(raw) })
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
        match CancellationToken::new() {
            Ok(shared) => {
                *token = z_owned_cancellation_token_t {
                    handle: Strong::into_raw(shared),
                    _cnt: core::ptr::null_mut(),
                };
                Z_OK
            }
            Err(_) => {
                *token = z_owned_cancellation_token_t::null_value();
                Z_ERR_SYSTEM_OUT_OF_MEMORY
            }
        }
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
        Some(shared) => {
            shared.cancel();
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
        Some(shared) => shared.is_cancelled(),
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
        match token_raw(src) {
            Some(raw) => {
                // SAFETY: the handle's count, read and left held: `src` still owns it.
                let held = core::mem::ManuallyDrop::new(unsafe {
                    Strong::<CancellationToken>::from_raw(raw)
                });
                *dst = z_owned_cancellation_token_t {
                    handle: Strong::into_raw((*held).clone()),
                    _cnt: core::ptr::null_mut(),
                };
                Z_OK
            }
            None => Z_ERR_NULL,
        }
    })
}

/// Release a token handle (pico `z_cancellation_token_drop`).
///
/// Lets go of THIS handle's count; the state survives while any clone holds one.
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
            // SAFETY: the caller's: a live handle is a count, let go of once here.
            drop(unsafe { Strong::<CancellationToken>::from_raw(handle) });
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A token and its clone are counts of one state: cancelling through the clone is seen through
    /// the original, and the clone asks the heap for nothing; a full heap refuses a new token with
    /// `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, its handle left null, where it would end the program.
    ///
    /// # Control
    ///
    /// The first token is made with room on the heap. A clone that boxes its count reds the clone
    /// under the refusing heap; a `new` that does not answer a refused box ends the test binary.
    #[test]
    fn a_token_and_its_clone_share_one_state_and_a_full_heap_refuses_a_new_one() {
        let mut token = z_owned_cancellation_token_t::null_value();
        // SAFETY: a local handle.
        let made = unsafe { z_cancellation_token_new(&mut token) };
        assert_eq!(made, Z_OK, "CONTROL: a token is made with room on the heap");
        let mut copy = z_owned_cancellation_token_t::null_value();
        // SAFETY: a live token and a local handle.
        let cloned = crate::test_heap::refused(|| unsafe {
            z_cancellation_token_clone(&mut copy, z_cancellation_token_loan(&token))
        });
        assert_eq!(cloned, Z_OK, "a clone asks the heap for nothing");
        // SAFETY: the clone is live.
        let cancelled =
            unsafe { z_cancellation_token_cancel(z_cancellation_token_loan_mut(&mut copy)) };
        assert_eq!(cancelled, Z_OK);
        // SAFETY: the original is live.
        let seen = unsafe { z_cancellation_token_is_cancelled(z_cancellation_token_loan(&token)) };
        assert!(seen, "the clone and the original are one state");

        let mut spare = z_owned_cancellation_token_t::null_value();
        // SAFETY: a local handle.
        let refused = crate::test_heap::refused(|| unsafe { z_cancellation_token_new(&mut spare) });
        assert_eq!(refused, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(
            spare.handle.is_null(),
            "a refused token leaves its handle null"
        );

        // SAFETY: both handles are live, each let go of once.
        unsafe {
            z_cancellation_token_drop(z_cancellation_token_move(&mut copy));
            z_cancellation_token_drop(z_cancellation_token_move(&mut token));
        }
        assert!(token.handle.is_null() && copy.handle.is_null());
    }
}
