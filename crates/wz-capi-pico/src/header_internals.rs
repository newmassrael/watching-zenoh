// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pico internals that the unstable arm's headers call from code a compiler emits into a
//! program that names none of them.
//!
//! pico's session header defines `_z_pending_query_cancellation_data_clear` as `static inline`
//! (`vendor/zenoh-pico/include/zenoh-pico/session/session.h` @
//! `static inline void _z_pending_query_cancellation_data_clear`, inside
//! `#ifdef Z_FEATURE_UNSTABLE_API`) and then declares it again without `inline`
//! (`vendor/zenoh-pico/include/zenoh-pico/session/session.h` @
//! `void _z_pending_query_cancellation_data_clear(_z_pending_query_cancellation_data_t *data);`). clang reads the
//! second declaration as making the function an ordinary internal one and emits it into every
//! object that includes `zenoh-pico.h`, used or not (measured with clang 19 and 22 at `-O0`, and
//! on the hosted macOS runner's Apple clang; gcc emits nothing). Its body, and the
//! `_z_cancellation_token_rc_*` code `_Z_REFCOUNT_DEFINE` generates in
//! `zenoh-pico/session/cancellation.h`, call three functions pico's library defines in every
//! build (`src/session/cancellation.c`, `src/collections/sync_group.c`). An empty program
//! compiled by clang against the unstable arm therefore links only against a library that exports
//! them. upstream's does; wz's has to, or wz does not stand in for it there.
//!
//! The rest of that closure is exported elsewhere: `_z_rc_decrease_strong` (`handlers`) and
//! `z_free` (`platform`). `pico_header_arm_layout::an_empty_program_of_each_arm_links_when_clang_compiles_it`
//! in wz-integration-tests links the program per arm, so an addition to the closure in a pin
//! bump fails there instead of on a consumer's compiler.
//!
//! ## What each one does here
//!
//! A wz token is `{ handle, _cnt }`: slot 0 (pico's `_val`) is this crate's handle to the
//! token's shared state, and the counter slot stays null (`cancellation`). Pico's header code
//! reaches `_z_cancellation_token_clear` only through `_z_cancellation_token_rc_drop`, after
//! `_z_rc_decrease_strong` on the counter slot returns `true`; on a null counter it returns
//! `false`, so that path never runs for a wz token. wz hands out no pending query's cancellation
//! data and no sync group notifier: its gets hold their registration on the token as a value
//! that unregisters when it is dropped (`wz_capi_port::cancellation::Registration`), not under
//! an id a program can name. The functions keep pico's contract over what wz can hand them.

use core::ffi::c_void;

use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// Release what a token holds, not its storage (pico `_z_cancellation_token_clear`).
///
/// `ct` is a token's slot 0. In pico the rc code frees that storage after the clear
/// (`z_free(p->_val)`); here the slot holds this crate's handle, and releasing its reference to
/// the shared state is the clear. A null `ct` is nothing to clear.
///
/// # Safety
/// `ct` must be null or slot 0 of a token this crate produced and that nothing else releases.
#[cfg(feature = "query")]
#[no_mangle]
pub unsafe extern "C" fn _z_cancellation_token_clear(ct: *mut c_void) {
    let _ = crate::ffi::guarded(|| {
        if !ct.is_null() {
            core::ptr::drop_in_place(
                ct as *mut alloc::sync::Arc<crate::cancellation::CancellationToken>,
            );
        }
        Z_OK
    });
}

/// Release what a token holds (pico `_z_cancellation_token_clear`), in a build without the query
/// plane. Pico has no token API there (`src/api/api.c` puts it under `Z_FEATURE_QUERY == 1`)
/// and wz produces no token, so there is nothing this could be handed to release.
///
/// # Safety
/// None: the pointer is not read.
#[cfg(not(feature = "query"))]
#[no_mangle]
pub unsafe extern "C" fn _z_cancellation_token_clear(_ct: *mut c_void) {}

/// Remove an on-cancel handler by its id (pico `_z_cancellation_token_remove_on_cancel_handler`).
///
/// wz registers no handler under an id: a get's registration is a value that unregisters itself
/// when dropped. Every id is therefore absent, and pico removes an absent id from its handler
/// map without error. A null token is refused, as this crate's token functions refuse one.
///
/// # Safety
/// `ct` is not read beyond its null check.
#[no_mangle]
pub unsafe extern "C" fn _z_cancellation_token_remove_on_cancel_handler(
    ct: *mut c_void,
    _handler_id: usize,
) -> ZResult {
    if ct.is_null() {
        Z_ERR_NULL
    } else {
        Z_OK
    }
}

/// Drop a sync group notifier (pico `_z_sync_group_notifier_drop`).
///
/// A notifier is pico's `{ _z_sync_group_state_weak_t _state }`, two words, and pico's drop
/// releases the weak reference and nulls it. wz creates none (pico creates them in
/// `_z_sync_group_create_notifier`, which wz does not export), so every notifier a program can
/// hold is one it zeroed itself, the value pico's drop returns early on. The drop leaves the
/// notifier null, as pico's does.
///
/// # Safety
/// `notifier` must be null or point to two writable words.
#[no_mangle]
pub unsafe extern "C" fn _z_sync_group_notifier_drop(notifier: *mut [*mut c_void; 2]) {
    if !notifier.is_null() {
        *notifier = [core::ptr::null_mut(); 2];
    }
}
