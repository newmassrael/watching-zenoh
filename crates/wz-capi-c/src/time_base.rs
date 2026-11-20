// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_capi_c_time_base_*` and `wz_capi_c_config_time_base`: a time base the program supplies,
//! which the timers of a session opened from a config naming it run on in place of the system's
//! monotonic clock.
//!
//! A door wz has and zenoh-c has not, so each carries the `wz_capi_c_` prefix and is declared in
//! `wz_capi_c.h`, not in upstream's header. A program that runs its sessions on a time of its own
//! (a network simulator's, paused, or faster or slower than the wall clock) hands the library a
//! read of that time; a session opened from a config given it times its lease, its keep-alive,
//! its handshake, its opens and its other deadlines by it, and a wait for one of them ends when
//! the program says its time has moved on (`wz_capi_c_time_base_advanced`).
//!
//! The time base is made by the port both C ABIs share (`wz_capi_port::time_base`), as the pico
//! ABI's `wz_ext_time_base_*` doors make theirs; this file is this ABI's names, result codes and
//! ownership around it. The program makes the time base and holds it; a config given it holds a
//! reference, and so does a session opened from that config, for as long as it runs; the
//! program's `drop(context)` runs once, when the last of them goes. A node that forwards between
//! its faces (a router) is not timed by one: an open of such a node from a config that names a
//! time base is refused.

use std::ffi::c_void;

use wz_capi_core::runtime::time_base::TimeBaseHold;

use crate::abi::{z_loaned_config_t, Handle};
use crate::config::config_state;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_OK};

/// The program's read of its time: nanoseconds since an epoch of its choosing. Called from
/// whichever thread reads a session's clock, possibly several at once.
pub type wz_capi_c_time_base_now_fn = wz_capi_port::time_base::NowFn;

/// The program's `drop(context)`, run once when the time base is gone.
pub type wz_capi_c_time_base_drop_fn = wz_capi_port::time_base::DropFn;

/// The calls the program supplies. `now_ns` is required; `drop` may be NULL.
#[repr(C)]
pub struct wz_capi_c_time_base_t {
    pub context: *mut c_void,
    pub now_ns: Option<wz_capi_c_time_base_now_fn>,
    pub drop: Option<wz_capi_c_time_base_drop_fn>,
}

/// An owned time base. One handle; wz-own, so there is no upstream size to pad to.
#[repr(C)]
pub struct wz_capi_c_owned_time_base_t {
    pub(crate) handle: Handle,
}

/// A loaned time base: the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct wz_capi_c_loaned_time_base_t {
    pub(crate) handle: Handle,
}

/// A moved time base.
#[repr(C)]
pub struct wz_capi_c_moved_time_base_t {
    pub(crate) _this: wz_capi_c_owned_time_base_t,
}

impl wz_capi_c_owned_time_base_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }
}

/// The hold behind a loan, or `None` for a null loan or the gravestone.
///
/// # Safety
/// `this_` is null or a loan of a live owned time base.
unsafe fn hold_of<'a>(this_: *const wz_capi_c_loaned_time_base_t) -> Option<&'a TimeBaseHold> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<TimeBaseHold>` this crate leaked in `wz_capi_c_time_base_new`.
    Some(unsafe { &*(handle as *const TimeBaseHold) })
}

/// A time base over the program's calls in `time_base`, which are copied. `this_` holds the
/// gravestone on every error.
///
/// `Z_OK`; `Z_ENULL` for a null `this_` or `time_base`, or a null `now_ns`.
///
/// # Safety
/// `this_` is writable; `time_base` is null or readable; `now_ns` is safe to call with `context`
/// from any thread for as long as the time base lives.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_time_base_new(
    this_: *mut wz_capi_c_owned_time_base_t,
    time_base: *const wz_capi_c_time_base_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_time_base_t::null_value() };
        if time_base.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above.
        let calls = unsafe { &*time_base };
        let Some(now_ns) = calls.now_ns else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract on `now_ns`, `drop` and `context`.
        let hold =
            unsafe { wz_capi_port::time_base::over_calls(calls.context, now_ns, calls.drop) };
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = wz_capi_c_owned_time_base_t {
                handle: Box::into_raw(Box::new(hold)) as Handle,
            }
        };
        Z_OK
    })
}

/// The session opened from `config` times its deadlines by `time_base`. A second call replaces
/// the first. The config holds a reference: the program may drop its own after this.
///
/// `Z_OK`; `Z_ENULL` for a null config, a null time base or the gravestone.
///
/// # Safety
/// `config` is null or a loaned config; `time_base` is null or a loan of a live time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_time_base(
    config: *mut z_loaned_config_t,
    time_base: *const wz_capi_c_loaned_time_base_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { config_state(config) }) else {
            return Z_ENULL;
        };
        // SAFETY: as above.
        let Some(hold) = (unsafe { hold_of(time_base) }) else {
            return Z_ENULL;
        };
        state.time_base = Some(hold.clone());
        Z_OK
    })
}

/// The program's time has moved on: every wait of a session on `time_base` whose time has come by
/// the program's reading now ends.
///
/// `Z_OK`; `Z_ENULL` for a null time base or the gravestone.
///
/// # Safety
/// `time_base` is null or a loan of a live time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_time_base_advanced(
    time_base: *const wz_capi_c_loaned_time_base_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(hold) = (unsafe { hold_of(time_base) }) else {
            return Z_ENULL;
        };
        hold.advanced();
        Z_OK
    })
}

/// Borrow a time base.
///
/// # Safety
/// `this_` null or a valid owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_time_base_loan(
    this_: *const wz_capi_c_owned_time_base_t,
) -> *const wz_capi_c_loaned_time_base_t {
    this_ as *const wz_capi_c_loaned_time_base_t
}

/// The moved form of a time base, for `wz_capi_c_time_base_drop`: a cast, which nulls nothing.
///
/// # Safety
/// `this_` null or a valid owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_time_base_move(
    this_: *mut wz_capi_c_owned_time_base_t,
) -> *mut wz_capi_c_moved_time_base_t {
    this_ as *mut wz_capi_c_moved_time_base_t
}

/// Release the program's reference and leave the gravestone. The configs and sessions that hold
/// the time base keep it; the program's `drop(context)` runs when the last of them goes. A second
/// drop is a no-op.
///
/// # Safety
/// `this_` null or a valid moved time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_time_base_drop(this_: *mut wz_capi_c_moved_time_base_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        // SAFETY: as above.
        unsafe { (*this_)._this = wz_capi_c_owned_time_base_t::null_value() };
        if !handle.is_null() {
            // SAFETY: a live `Box<TimeBaseHold>` this crate leaked in `wz_capi_c_time_base_new`.
            drop(unsafe { Box::from_raw(handle as *mut TimeBaseHold) });
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_time_base_null(
    this_: *mut wz_capi_c_owned_time_base_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_time_base_t::null_value() };
    }
}

/// Whether the slot holds a time base.
///
/// # Safety
/// `this_` null or a valid owned time base.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_time_base_check(
    this_: *const wz_capi_c_owned_time_base_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use crate::abi::z_owned_config_t;
    use crate::config::{z_config_default, z_config_drop, z_config_loan_mut};

    /// The program's time and how often its drop ran.
    #[derive(Default)]
    struct Program {
        now_ns: AtomicU64,
        drops: AtomicUsize,
    }

    unsafe extern "C" fn read(context: *mut c_void) -> u64 {
        // SAFETY: the test's own context, alive for the test.
        unsafe { (*(context as *const Program)).now_ns.load(Ordering::SeqCst) }
    }

    unsafe extern "C" fn dropped(context: *mut c_void) {
        // SAFETY: as above.
        unsafe {
            (*(context as *const Program))
                .drops
                .fetch_add(1, Ordering::SeqCst)
        };
    }

    fn calls(program: &Program) -> wz_capi_c_time_base_t {
        wz_capi_c_time_base_t {
            context: program as *const Program as *mut c_void,
            now_ns: Some(read),
            drop: Some(dropped),
        }
    }

    #[test]
    fn a_null_slot_calls_or_read_is_refused_and_a_null_loan_is_refused() {
        let program = Program::default();
        // SAFETY: every pointer is null or the test's own.
        unsafe {
            assert_eq!(
                wz_capi_c_time_base_new(std::ptr::null_mut(), &calls(&program)),
                Z_ENULL
            );
            let mut time_base = wz_capi_c_owned_time_base_t::null_value();
            assert_eq!(
                wz_capi_c_time_base_new(&mut time_base, std::ptr::null()),
                Z_ENULL
            );
            let no_read = wz_capi_c_time_base_t {
                now_ns: None,
                ..calls(&program)
            };
            assert_eq!(wz_capi_c_time_base_new(&mut time_base, &no_read), Z_ENULL);
            assert!(!wz_capi_c_internal_time_base_check(&time_base));
            assert_eq!(wz_capi_c_time_base_advanced(std::ptr::null()), Z_ENULL);
            assert_eq!(
                wz_capi_c_time_base_advanced(wz_capi_c_time_base_loan(&time_base)),
                Z_ENULL
            );
            let mut config: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut config), Z_OK);
            assert_eq!(
                wz_capi_c_config_time_base(
                    z_config_loan_mut(&mut config),
                    wz_capi_c_time_base_loan(&time_base)
                ),
                Z_ENULL
            );
            z_config_drop((&mut config as *mut z_owned_config_t).cast());
        }
        assert_eq!(program.drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_config_holds_the_time_base_until_it_goes_and_the_programs_drop_runs_once() {
        let program = Program::default();
        program.now_ns.store(42, Ordering::SeqCst);
        // SAFETY: every pointer is null or the test's own; `program` outlives every hold.
        unsafe {
            let mut time_base = wz_capi_c_owned_time_base_t::null_value();
            assert_eq!(
                wz_capi_c_time_base_new(&mut time_base, &calls(&program)),
                Z_OK
            );
            let mut config: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut config), Z_OK);
            assert_eq!(
                wz_capi_c_config_time_base(
                    z_config_loan_mut(&mut config),
                    wz_capi_c_time_base_loan(&time_base)
                ),
                Z_OK
            );
            let held = config_state(z_config_loan_mut(&mut config))
                .and_then(|state| state.time_base.as_ref().map(TimeBaseHold::now_ns));
            assert_eq!(held, Some(42), "the config's reference reads the program");
            wz_capi_c_time_base_drop(wz_capi_c_time_base_move(&mut time_base));
            assert_eq!(
                program.drops.load(Ordering::SeqCst),
                0,
                "the config holds it"
            );
            z_config_drop((&mut config as *mut z_owned_config_t).cast());
        }
        assert_eq!(program.drops.load(Ordering::SeqCst), 1);
    }
}
