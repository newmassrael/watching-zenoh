// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_clock_source_register`, `wz_ext_clock_source_unregister` and `wz_ext_clock_report`: the
//! clock a program registers, and what it tells the library about whether that clock is
//! synchronised (`docs/observation-plane.md` M1).
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`
//! (docs/build-configuration.md, decision C10), and part of the unstable surface: a build without
//! `unstable-api` carries none of it.
//!
//! A device often has a better clock than the system's, a disciplined hardware clock or a time
//! master on its bus. A program registers it as a read callback, and `z_timestamp_new` then stamps
//! with it. What the registry does is [`wz_capi_port::observation::clock`]'s, which the zenoh-c
//! ABI's doors act on too; this file is the pico ABI's names and result codes for it.
//!
//! The library cannot know whether the registered clock follows a reference. The program can, so it
//! reports it (`wz_ext_clock_report`), and a build whose `clock-quality-stamping` policy is
//! `trusted-only` stamps nothing until it has said so.

use std::ffi::c_void;

use wz_capi_port::observation::{clock, Refusal};

use crate::result::{ZResult, Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};

/// What a registered clock is read through: the time since the Unix epoch, as whole seconds and
/// the nanoseconds within the second.
///
/// Returns 0 with both outputs written, or any other value when the clock cannot say what time it
/// is (not set, not yet synchronised, its bus silent). It is called from whichever thread
/// stamps, possibly several at once, and must be safe to call that way.
#[allow(non_camel_case_types)]
pub type wz_ext_clock_read_fn = clock::ReadFn;

/// The event `wz_ext_clock_report` carries.
#[allow(non_camel_case_types)]
pub type wz_ext_clock_event_t = u8;

/// The clock follows a reference, for the first time or again after a loss.
pub const WZ_EXT_CLOCK_SYNC_ACQUIRED: wz_ext_clock_event_t = clock::SYNC_ACQUIRED;
/// The reference is gone.
pub const WZ_EXT_CLOCK_SYNC_LOST: wz_ext_clock_event_t = clock::SYNC_LOST;
/// The program's bound on running without a reference has passed.
pub const WZ_EXT_CLOCK_HOLDOVER_EXPIRED: wz_ext_clock_event_t = clock::HOLDOVER_EXPIRED;

/// The pico code of a refusal of the clock doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Full => Z_ERR_OVERFLOW,
        Refusal::Invalid | Refusal::Unavailable => Z_ERR_INVALID,
    }
}

/// Register a clock the library reads in place of the system clock, after those already
/// registered (the first that can say what time it is answers). `out_handle` receives the handle
/// `wz_ext_clock_source_unregister` takes; it may be null.
///
/// `Z_ERR_OVERFLOW` when the build's `CLOCK_SOURCES` are all taken.
///
/// # Safety
/// `read` must be a function that is safe to call from any thread for as long as the source is
/// registered, and `context` must stay valid for as long. `out_handle` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_clock_source_register(
    read: Option<wz_ext_clock_read_fn>,
    context: *mut c_void,
    out_handle: *mut u32,
) -> ZResult {
    crate::ffi::guarded(|| {
        let Some(read) = read else {
            return Z_ERR_NULL;
        };
        match clock::register(read, context) {
            Ok(handle) => {
                if !out_handle.is_null() {
                    *out_handle = handle;
                }
                Z_OK
            }
            Err(refusal) => code(refusal),
        }
    })
}

/// Remove a clock registered earlier. `Z_ERR_INVALID` for a handle that is not registered.
///
/// After it returns the library no longer calls the callback, and the program may release the
/// context. A call already running on another thread may still be inside the callback.
#[no_mangle]
pub extern "C" fn wz_ext_clock_source_unregister(handle: u32) -> ZResult {
    crate::ffi::guarded(|| match clock::unregister(handle) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Tell the library whether the registered clock follows a reference: one of
/// `WZ_EXT_CLOCK_SYNC_ACQUIRED`, `WZ_EXT_CLOCK_SYNC_LOST` and `WZ_EXT_CLOCK_HOLDOVER_EXPIRED`.
/// `Z_ERR_INVALID` for another value. Reporting what is already so is not an error.
#[no_mangle]
pub extern "C" fn wz_ext_clock_report(event: wz_ext_clock_event_t) -> ZResult {
    crate::ffi::guarded(|| match clock::report(event) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_callback_is_refused_and_an_unknown_handle_and_event_are_invalid() {
        unsafe {
            assert_eq!(
                wz_ext_clock_source_register(None, std::ptr::null_mut(), std::ptr::null_mut()),
                Z_ERR_NULL
            );
        }
        assert_eq!(wz_ext_clock_source_unregister(u32::MAX), Z_ERR_INVALID);
        assert_eq!(wz_ext_clock_report(99), Z_ERR_INVALID);
    }
}
