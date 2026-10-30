// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_capi_c_clock_source_register`, `wz_capi_c_clock_source_unregister` and
//! `wz_capi_c_clock_report`: the clock a program registers, and what it tells the library about
//! whether that clock is synchronised (`docs/observation-plane.md` M1).
//!
//! A door wz has and zenoh-c has not, so each carries the `wz_capi_c_` prefix and is declared in
//! `wz_capi_c.h`, not in upstream's header. A zenoh-c node stamps with its own clock; a device
//! often has a better one, a disciplined hardware clock or a time master on its bus. A program
//! registers it as a read callback and `z_timestamp_new` then stamps with it.
//!
//! What the registry does is [`wz_capi_port::observation::clock`]'s, which the pico ABI's
//! `wz_ext_clock_*` doors act on too; this file is this ABI's names and result codes for it.
//!
//! The library cannot know whether the registered clock follows a reference. The program can, so
//! it reports it (`wz_capi_c_clock_report`), and a build whose `clock-quality-stamping` policy is
//! `trusted-only` stamps nothing until it has said so.

use std::ffi::c_void;

use wz_capi_port::observation::{clock, Refusal};

use crate::ffi::guarded;
use crate::result::{ZResult, WZ_CAPI_C_E_FULL, Z_EINVAL, Z_ENULL, Z_OK};

/// What a registered clock is read through: the time since the Unix epoch, as whole seconds and
/// the nanoseconds within the second. Returns 0 with both outputs written, or any other value
/// when the clock cannot say what time it is. It is called from whichever thread stamps,
/// possibly several at once, and must be safe to call that way.
#[allow(non_camel_case_types)]
pub type wz_capi_c_clock_read_fn = clock::ReadFn;

/// The event `wz_capi_c_clock_report` carries.
#[allow(non_camel_case_types)]
pub type wz_capi_c_clock_event_t = u8;

/// The clock follows a reference, for the first time or again after a loss.
pub const WZ_CAPI_C_CLOCK_SYNC_ACQUIRED: wz_capi_c_clock_event_t = clock::SYNC_ACQUIRED;
/// The reference is gone.
pub const WZ_CAPI_C_CLOCK_SYNC_LOST: wz_capi_c_clock_event_t = clock::SYNC_LOST;
/// The program's bound on running without a reference has passed.
pub const WZ_CAPI_C_CLOCK_HOLDOVER_EXPIRED: wz_capi_c_clock_event_t = clock::HOLDOVER_EXPIRED;

/// This ABI's code for a refusal of the clock doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Full => WZ_CAPI_C_E_FULL,
        Refusal::Invalid | Refusal::Unavailable => Z_EINVAL,
    }
}

/// Register a clock the library reads in place of the system clock, after those already
/// registered (the first that can say what time it is answers). `out_handle` receives the handle
/// `wz_capi_c_clock_source_unregister` takes; it may be null.
///
/// `Z_ENULL` for a null `read`; `WZ_CAPI_C_E_FULL` when the build's `CLOCK_SOURCES` are all taken.
///
/// # Safety
/// `read` must be a function that is safe to call from any thread for as long as the source is
/// registered, and `context` must stay valid for as long. `out_handle` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_clock_source_register(
    read: Option<wz_capi_c_clock_read_fn>,
    context: *mut c_void,
    out_handle: *mut u32,
) -> ZResult {
    guarded(|| {
        let Some(read) = read else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract.
        match unsafe { clock::register(read, context) } {
            Ok(handle) => {
                if !out_handle.is_null() {
                    // SAFETY: non-null and writable, by the contract.
                    unsafe { *out_handle = handle };
                }
                Z_OK
            }
            Err(refusal) => code(refusal),
        }
    })
}

/// Remove a clock registered earlier. `Z_EINVAL` for a handle that is not registered.
///
/// After it returns the library no longer calls the callback, and the program may release the
/// context. A call already running on another thread may still be inside the callback.
#[no_mangle]
pub extern "C" fn wz_capi_c_clock_source_unregister(handle: u32) -> ZResult {
    guarded(|| match clock::unregister(handle) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Tell the library whether the registered clock follows a reference: one of
/// `WZ_CAPI_C_CLOCK_SYNC_ACQUIRED`, `WZ_CAPI_C_CLOCK_SYNC_LOST` and
/// `WZ_CAPI_C_CLOCK_HOLDOVER_EXPIRED`. `Z_EINVAL` for another value. Reporting what is already so
/// is not an error.
#[no_mangle]
pub extern "C" fn wz_capi_c_clock_report(event: wz_capi_c_clock_event_t) -> ZResult {
    guarded(|| match clock::report(event) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn reads_a_fixed_time(
        _context: *mut c_void,
        secs: *mut u64,
        nanos: *mut u32,
    ) -> i8 {
        *secs = 1_700_000_000;
        *nanos = 7;
        0
    }

    #[test]
    fn a_null_callback_is_null_and_an_unknown_handle_and_event_are_invalid() {
        // SAFETY: a null callback and a null handle slot, which the door takes.
        let rc = unsafe {
            wz_capi_c_clock_source_register(None, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(rc, Z_ENULL);
        assert_eq!(wz_capi_c_clock_source_unregister(u32::MAX), Z_EINVAL);
        assert_eq!(wz_capi_c_clock_report(99), Z_EINVAL);
    }

    #[test]
    fn a_registered_clock_is_given_a_handle_and_removed_by_it() {
        let mut handle = u32::MAX;
        // SAFETY: a function safe to call from any thread, no context, a writable handle.
        let rc = unsafe {
            wz_capi_c_clock_source_register(
                Some(reads_a_fixed_time),
                std::ptr::null_mut(),
                &mut handle,
            )
        };
        assert_eq!(rc, Z_OK);
        assert_ne!(handle, u32::MAX, "the handle was written");
        assert_eq!(wz_capi_c_clock_source_unregister(handle), Z_OK);
        assert_eq!(
            wz_capi_c_clock_source_unregister(handle),
            Z_EINVAL,
            "a handle is spent once it is removed"
        );
    }

    #[test]
    fn the_three_reports_a_program_may_make_are_accepted() {
        for event in [
            WZ_CAPI_C_CLOCK_SYNC_ACQUIRED,
            WZ_CAPI_C_CLOCK_SYNC_LOST,
            WZ_CAPI_C_CLOCK_HOLDOVER_EXPIRED,
        ] {
            assert_eq!(wz_capi_c_clock_report(event), Z_OK);
        }
    }
}
