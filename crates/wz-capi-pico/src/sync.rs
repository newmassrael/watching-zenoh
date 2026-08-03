// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_mutex_*` / `z_condvar_*` — pico's MULTI-THREAD sync surface.
//!
//! Like [`crate::platform`], these carry no zenoh semantics. They are here
//! because upstream's programs block on them while waiting for a zenoh event:
//! `z_get.c` arms a condvar, fires the query, and waits for the reply closure
//! to signal it. Measured against the 32 upstream examples, the ten symbols of
//! this module are the COMPLETE missing set for `z_get.c` — the canonical
//! querier program links with nothing else added.
//!
//! ## Why these operate on the caller's bytes, and why that is not a shortcut
//!
//! Every other owned type in this crate hides a `Box::into_raw` handle in the
//! value's leading pointer slot (see [`crate::abi`]). These two cannot, and the
//! reason is measured rather than stylistic: pico's `z_owned_mutex_t` is 40 B
//! and `z_owned_condvar_t` is 48 B, which on this target are exactly
//! `sizeof(pthread_mutex_t)` and `sizeof(pthread_cond_t)`. That is not a
//! coincidence — pico's unix backend types `_z_mutex_t` AS `pthread_mutex_t`
//! (`vendor/zenoh-pico/include/zenoh-pico/system/platform/unix.h`), and the C
//! program stack-allocates the struct through pico's own header before wz sees
//! it. The layout is therefore already decided by the header the program
//! compiled against, and the only implementation that can be correct is the one
//! pico itself ships: call libc's pthread primitives on those bytes
//! (`src/system/unix/system.c:132-204`).
//!
//! A handle-in-slot-0 design would *compile* and then corrupt: the C side is
//! entitled to copy the struct by value (`z_mutex_take` is literally
//! `*obj = src->_this`), which is well-defined for a pthread object being moved
//! before first use and meaningless for a boxed Rust handle whose address the
//! map keyed on.
//!
//! ## The condvar clock is load-bearing
//!
//! `z_condvar_init` sets `CLOCK_MONOTONIC` on the condattr before
//! `pthread_cond_init`, mirroring pico (`system.c:160-166`). Skipping it leaves
//! glibc's default `CLOCK_REALTIME`, and since [`crate::platform::z_clock_now`]
//! is `CLOCK_MONOTONIC`, a deadline computed from it would be interpreted
//! against a different epoch — `z_condvar_wait_until` would return immediately
//! or hang for the wall-clock/uptime skew. The two calls only agree because
//! both name the same clock.

use std::ffi::c_int;

use crate::ffi::guard_val;
use crate::platform::z_clock_t;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

/// pico `_Z_ERR_SYSTEM_GENERIC` (`utils/result.h:84`) — what
/// `_Z_CHECK_SYS_ERR` returns for any non-zero `pthread_*` result. Reproduced
/// exactly rather than collapsed onto [`crate::result::Z_ERR_GENERIC`]: a
/// caller distinguishing "the system refused" from "zenoh refused" reads this
/// code, and pico's own value is the only one that answers correctly.
pub const Z_ERR_SYSTEM_GENERIC: ZResult = -80;

/// pico `Z_ETIMEDOUT` (`utils/result.h:96`) — the ONE non-generic outcome
/// `z_condvar_wait_until` reports, and the reason it exists as a distinct
/// export from `z_condvar_wait`.
pub const Z_ETIMEDOUT: ZResult = -71;

/// pico's `_Z_CHECK_SYS_ERR` in Rust: 0 is `Z_OK`, anything else is
/// [`Z_ERR_SYSTEM_GENERIC`]. pico additionally logs the raw `errno`; the code
/// handed to C is the same either way.
#[inline]
fn sys(rc: c_int) -> ZResult {
    if rc == 0 {
        Z_OK
    } else {
        Z_ERR_SYSTEM_GENERIC
    }
}

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// pico `z_owned_mutex_t` — `{ _z_mutex_t _val }`, and `_z_mutex_t` is
/// `pthread_mutex_t` on unix. 40 B measured against the vendored headers.
///
/// `z_loaned_mutex_t` and `z_moved_mutex_t` are the same 40 bytes at the same
/// address (`_val` is at offset 0 and `_this` is the whole owned struct), so
/// the loan / move / drop family below is pointer identity — pico's own macro
/// expansion is `return &obj->_val` and `return (z_moved_*_t *)(obj)`
/// (`api/olv_macros.h:102-103, 211-212`).
pub type z_owned_mutex_t = libc::pthread_mutex_t;
/// Loaned mutex — see [`z_owned_mutex_t`]; identical layout at offset 0.
pub type z_loaned_mutex_t = libc::pthread_mutex_t;
/// Moved mutex — see [`z_owned_mutex_t`]; identical layout at offset 0.
pub type z_moved_mutex_t = libc::pthread_mutex_t;

/// Initialise a mutex in the caller's storage (pico `z_mutex_init`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_init(m: *mut z_owned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_mutex_init(m, std::ptr::null()))
    })
}

/// Destroy a mutex (pico `z_mutex_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_drop(m: *mut z_moved_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_mutex_destroy(m))
    })
}

/// Loan a mutex immutably (pico `z_mutex_loan`) — `&obj->_val`, offset 0.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_loan(m: *const z_owned_mutex_t) -> *const z_loaned_mutex_t {
    m
}

/// Loan a mutex mutably (pico `z_mutex_loan_mut`) — `&obj->_val`, offset 0.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_loan_mut(m: *mut z_owned_mutex_t) -> *mut z_loaned_mutex_t {
    m
}

/// Move a mutex (pico `z_mutex_move`) — the identity cast pico's macro emits.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_move(m: *mut z_owned_mutex_t) -> *mut z_moved_mutex_t {
    m
}

/// Take ownership out of a moved mutex (pico `z_mutex_take`).
///
/// pico's expansion is `*obj = src->_this;` followed by the null-ing hook,
/// which for a SYSTEM type is `{ (void)obj; }` — a deliberate no-op, because a
/// pthread object has no null value to write. So this is the struct copy and
/// nothing else, which is what makes the source safe to leave untouched.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_take(
    obj: *mut z_owned_mutex_t,
    src: *mut z_moved_mutex_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if obj.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        std::ptr::copy_nonoverlapping(src, obj, 1);
        Z_OK
    })
}

/// Lock, blocking (pico `z_mutex_lock`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_lock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_mutex_lock(m))
    })
}

/// Try to lock without blocking (pico `z_mutex_try_lock`).
///
/// Exported even though no upstream example calls it. The asymmetry this crate
/// was bitten by — `z_put_options_default` absent while the get/queryable
/// siblings were present — comes from shipping only the members a witness
/// happened to exercise, so the family goes out whole.
#[no_mangle]
pub unsafe extern "C" fn z_mutex_try_lock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_mutex_trylock(m))
    })
}

/// Unlock (pico `z_mutex_unlock`).
#[no_mangle]
pub unsafe extern "C" fn z_mutex_unlock(m: *mut z_loaned_mutex_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_mutex_unlock(m))
    })
}

// ---------------------------------------------------------------------------
// Condition variable
// ---------------------------------------------------------------------------

/// pico `z_owned_condvar_t` — `{ _z_condvar_t _val }`, `pthread_cond_t` on
/// unix. 48 B measured. Loan / move share the address, as for the mutex.
pub type z_owned_condvar_t = libc::pthread_cond_t;
/// Loaned condvar — see [`z_owned_condvar_t`].
pub type z_loaned_condvar_t = libc::pthread_cond_t;
/// Moved condvar — see [`z_owned_condvar_t`].
pub type z_moved_condvar_t = libc::pthread_cond_t;

/// Initialise a condvar on `CLOCK_MONOTONIC` (pico `z_condvar_init`).
///
/// The clock is set through a `pthread_condattr_t` exactly as pico does
/// (`system.c:160-166`); see this module's header for why the choice is
/// load-bearing rather than incidental. The attr is destroyed on every path,
/// including the failure one — `pthread_condattr_init` may allocate.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_init(cv: *mut z_owned_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
        let rc = libc::pthread_condattr_init(&mut attr);
        if rc != 0 {
            return sys(rc);
        }
        let rc = libc::pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC);
        let out = if rc != 0 {
            sys(rc)
        } else {
            sys(libc::pthread_cond_init(cv, &attr))
        };
        libc::pthread_condattr_destroy(&mut attr);
        out
    })
}

/// Destroy a condvar (pico `z_condvar_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_drop(cv: *mut z_moved_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_cond_destroy(cv))
    })
}

/// Loan a condvar immutably (pico `z_condvar_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_loan(cv: *const z_owned_condvar_t) -> *const z_loaned_condvar_t {
    cv
}

/// Loan a condvar mutably (pico `z_condvar_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_loan_mut(cv: *mut z_owned_condvar_t) -> *mut z_loaned_condvar_t {
    cv
}

/// Move a condvar (pico `z_condvar_move`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_move(cv: *mut z_owned_condvar_t) -> *mut z_moved_condvar_t {
    cv
}

/// Take ownership out of a moved condvar (pico `z_condvar_take`); the struct
/// copy, for the reason given on [`z_mutex_take`].
#[no_mangle]
pub unsafe extern "C" fn z_condvar_take(
    obj: *mut z_owned_condvar_t,
    src: *mut z_moved_condvar_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if obj.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        std::ptr::copy_nonoverlapping(src, obj, 1);
        Z_OK
    })
}

/// Wake one waiter (pico `z_condvar_signal`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_signal(cv: *mut z_loaned_condvar_t) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_cond_signal(cv))
    })
}

/// Wait, releasing `m` (pico `z_condvar_wait`).
#[no_mangle]
pub unsafe extern "C" fn z_condvar_wait(
    cv: *mut z_loaned_condvar_t,
    m: *mut z_loaned_mutex_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() || m.is_null() {
            return Z_ERR_NULL;
        }
        sys(libc::pthread_cond_wait(cv, m))
    })
}

/// Wait until an ABSOLUTE `CLOCK_MONOTONIC` deadline (pico
/// `z_condvar_wait_until`).
///
/// A timeout is [`Z_ETIMEDOUT`] and NOT the generic system error, because that
/// distinction is the whole point of the call: pico special-cases `ETIMEDOUT`
/// ahead of `_Z_CHECK_SYS_ERR` (`system.c:199-203`), and a caller that cannot
/// tell "deadline reached" from "the system refused" has no way to decide
/// whether to retry.
#[no_mangle]
pub unsafe extern "C" fn z_condvar_wait_until(
    cv: *mut z_loaned_condvar_t,
    m: *mut z_loaned_mutex_t,
    abstime: *const z_clock_t,
) -> ZResult {
    guard_val(Z_ERR_SYSTEM_GENERIC, || {
        if cv.is_null() || m.is_null() || abstime.is_null() {
            return Z_ERR_NULL;
        }
        let rc = libc::pthread_cond_timedwait(cv, m, abstime);
        if rc == libc::ETIMEDOUT {
            return Z_ETIMEDOUT;
        }
        sys(rc)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI claim this module rests on, asserted rather than assumed: the
    /// owned structs a C program stack-allocates through pico's header are 40
    /// and 48 bytes, and those are the sizes the pthread objects wz initialises
    /// in place occupy. Measured against the vendored headers by
    /// `scratchpad/abi_probe.c`; pinned here so a target whose pthread layout
    /// differs fails the build instead of silently writing past the caller's
    /// storage.
    #[test]
    fn owned_sync_types_match_picos_measured_sizes() {
        assert_eq!(std::mem::size_of::<z_owned_mutex_t>(), 40);
        assert_eq!(std::mem::size_of::<z_owned_condvar_t>(), 48);
    }

    /// loan / loan_mut / move are pointer identity in pico's macro expansion,
    /// so a round trip must return the address it was handed. A future
    /// "improvement" that boxed the value would break the C side's own
    /// `z_loan`/`z_move` `_Generic` dispatch silently; this catches it.
    #[test]
    fn mutex_loan_and_move_are_pointer_identity() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let p = &mut m as *mut z_owned_mutex_t;
        unsafe {
            assert_eq!(z_mutex_loan(p), p as *const _);
            assert_eq!(z_mutex_loan_mut(p), p);
            assert_eq!(z_mutex_move(p), p);
        }
    }

    /// A real lock/unlock cycle through the exported entry points, which is
    /// what `z_get.c` performs around its condvar wait. `try_lock` is expected
    /// to REFUSE while the mutex is held — the discriminator that separates a
    /// working mutex from one whose `lock` is a no-op returning `Z_OK`.
    #[test]
    fn mutex_lock_excludes_and_try_lock_refuses_while_held() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let p = &mut m as *mut z_owned_mutex_t;
        unsafe {
            assert_eq!(z_mutex_init(p), Z_OK);
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(p)), Z_OK);
            assert_ne!(
                z_mutex_try_lock(z_mutex_loan_mut(p)),
                Z_OK,
                "try_lock must refuse a mutex this thread already holds"
            );
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_try_lock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(p)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(p)), Z_OK);
        }
    }

    /// The `z_get.c` shape end to end: a waiter blocks on the condvar under the
    /// mutex and a second thread signals it. Green proves the pair actually
    /// blocks and wakes; a `z_condvar_wait` that returned immediately would
    /// also pass, which is why the signalling thread sets the flag FIRST and
    /// the waiter loops on it — the assertion is on the flag, not on reaching
    /// the line.
    #[test]
    fn condvar_signal_wakes_a_real_waiter() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct Pair(z_owned_mutex_t, z_owned_condvar_t);
        // SAFETY: pthread objects are explicitly shareable across threads; the
        // pointer wrapper exists only because raw pointers are not `Send`.
        struct Ptr(*mut Pair);
        unsafe impl Send for Ptr {}

        let mut pair = Box::new(Pair(unsafe { std::mem::zeroed() }, unsafe {
            std::mem::zeroed()
        }));
        let raw = &mut *pair as *mut Pair;
        unsafe {
            assert_eq!(z_mutex_init(&mut (*raw).0), Z_OK);
            assert_eq!(z_condvar_init(&mut (*raw).1), Z_OK);
        }

        let ready = Arc::new(AtomicBool::new(false));
        let signalled = Arc::new(AtomicBool::new(false));
        let (r2, s2) = (Arc::clone(&ready), Arc::clone(&signalled));
        let moved = Ptr(raw);
        let signaller = std::thread::spawn(move || {
            let p = moved;
            while !r2.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            unsafe {
                assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut (*p.0).0)), Z_OK);
                s2.store(true, Ordering::SeqCst);
                assert_eq!(z_condvar_signal(z_condvar_loan_mut(&mut (*p.0).1)), Z_OK);
                assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut (*p.0).0)), Z_OK);
            }
        });

        unsafe {
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut (*raw).0)), Z_OK);
            ready.store(true, Ordering::SeqCst);
            while !signalled.load(Ordering::SeqCst) {
                assert_eq!(
                    z_condvar_wait(
                        z_condvar_loan_mut(&mut (*raw).1),
                        z_mutex_loan_mut(&mut (*raw).0)
                    ),
                    Z_OK
                );
            }
            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut (*raw).0)), Z_OK);
        }
        signaller.join().expect("signalling thread");
        assert!(signalled.load(Ordering::SeqCst));

        unsafe {
            assert_eq!(z_condvar_drop(z_condvar_move(&mut (*raw).1)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(&mut (*raw).0)), Z_OK);
        }
    }

    /// `wait_until` with a deadline already in the past must report
    /// [`Z_ETIMEDOUT`], not the generic system error and not `Z_OK`. This is
    /// also the assertion that catches a condvar initialised on the WRONG
    /// clock: `z_clock_now` is `CLOCK_MONOTONIC`, so a `CLOCK_REALTIME`
    /// condvar reads this deadline as ~55 years in the past on a typical
    /// host — still a timeout, but a deadline one second in the FUTURE would
    /// then also time out instantly, which the second half asserts against.
    #[test]
    fn wait_until_times_out_and_respects_the_monotonic_clock() {
        let mut m: z_owned_mutex_t = unsafe { std::mem::zeroed() };
        let mut cv: z_owned_condvar_t = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(z_mutex_init(&mut m), Z_OK);
            assert_eq!(z_condvar_init(&mut cv), Z_OK);
            assert_eq!(z_mutex_lock(z_mutex_loan_mut(&mut m)), Z_OK);

            let mut past = crate::platform::z_clock_now();
            past.tv_sec -= 1;
            assert_eq!(
                z_condvar_wait_until(z_condvar_loan_mut(&mut cv), z_mutex_loan_mut(&mut m), &past),
                Z_ETIMEDOUT
            );

            // A FUTURE monotonic deadline must actually wait. Measured, because
            // "it returned Z_ETIMEDOUT" alone cannot tell a correct clock from
            // a wrong one — only the elapsed time can.
            let started = std::time::Instant::now();
            let mut soon = crate::platform::z_clock_now();
            soon.tv_nsec += 150_000_000;
            if soon.tv_nsec >= 1_000_000_000 {
                soon.tv_nsec -= 1_000_000_000;
                soon.tv_sec += 1;
            }
            assert_eq!(
                z_condvar_wait_until(z_condvar_loan_mut(&mut cv), z_mutex_loan_mut(&mut m), &soon),
                Z_ETIMEDOUT
            );
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(100),
                "a future CLOCK_MONOTONIC deadline returned in {:?}; the condvar \
                 is not on CLOCK_MONOTONIC",
                started.elapsed()
            );

            assert_eq!(z_mutex_unlock(z_mutex_loan_mut(&mut m)), Z_OK);
            assert_eq!(z_condvar_drop(z_condvar_move(&mut cv)), Z_OK);
            assert_eq!(z_mutex_drop(z_mutex_move(&mut m)), Z_OK);
        }
    }
}
