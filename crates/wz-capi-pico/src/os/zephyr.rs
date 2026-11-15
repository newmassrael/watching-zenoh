// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Zephyr host layer: the kernel heap, the POSIX clocks and objects of Zephyr's POSIX layer,
//! as zenoh-pico's own `system/zephyr/system.c` uses them.
//!
//! Every value here is the bytes the C program's header says it is.
//! `vendor/zenoh-pico/include/zenoh-pico/system/platform/zephyr.h` types the mutex as
//! `pthread_mutex_t`, the condvar as `pthread_cond_t`, the task as `pthread_t`, its attribute as
//! `pthread_attr_t`, the clock as `struct timespec` and the wall time as `struct timeval`, as the
//! Unix header does; on Zephyr the first four are the kernel POSIX layer's
//! (`include/zephyr/posix/posix_types.h`: a 32-bit handle each for the mutex, the condvar and the
//! task, and an attribute of a stack pointer and two words), and the two times are the C
//! library's, whose `time_t` is 64-bit and whose `long` is 32-bit on the kit's Cortex-M7. The image
//! pins each of these sizes, and each constant below, against the headers it compiles
//! (`deploy/zephyr-common/wz_pico_os_zephyr.c`), so a kernel or a C library whose layout differs
//! fails the image's build instead of writing past a C program's storage.
//!
//! What the kernel offers only as a `static inline` or a system call wrapper (its sleeps, its
//! random source, a condvar on the monotonic clock) is reached through that same file. The rest is
//! called directly: `k_malloc` and `k_free`, as pico's `z_malloc` and `z_free` are; `clock_gettime`,
//! `localtime` and `strftime`; and the `pthread_*` functions.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use super::zephyr_arith as arith;
use super::Unit;

/// The parts of a second a `struct timespec` and a `struct timeval` count.
const NANOS_PER_SECOND: i64 = 1_000_000_000;
const MICROS_PER_SECOND: i64 = 1_000_000;

/// pico `z_clock_t`: `struct timespec`, a 64-bit `time_t` and a `long`, 16 B. Returned BY VALUE
/// from `clock_now`, which the Arm procedure call standard returns through memory the caller
/// provides, as it does a C function's of the same type.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub tv_sec: i64,
    pub tv_nsec: c_long,
}

/// pico `z_time_t`: `struct timeval`, the WALL clock, a 64-bit `time_t` and a `long`, 16 B.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallTime {
    pub tv_sec: i64,
    pub tv_usec: c_long,
}

/// Zephyr's `CLOCK_REALTIME` (`include/zephyr/sys/clock.h`, `SYS_CLOCK_REALTIME`).
const CLOCK_REALTIME: c_ulong = 1;
/// Zephyr's `CLOCK_MONOTONIC` (`SYS_CLOCK_MONOTONIC`).
const CLOCK_MONOTONIC: c_ulong = 4;

extern "C" {
    fn k_malloc(size: usize) -> *mut c_void;
    fn k_free(ptr: *mut c_void);
    fn clock_gettime(clock_id: c_ulong, ts: *mut Clock) -> c_int;
    fn localtime(time: *const i64) -> *mut c_void;
    fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const c_void) -> usize;
    fn wz_pico_sleep_us(us: i32) -> i32;
    fn wz_pico_sleep_ms(ms: i32) -> i32;
    fn wz_pico_sleep_s(s: i32) -> i32;
    fn wz_pico_random_fill(buf: *mut c_void, len: usize);
}

// ---------------------------------------------------------------------------
// Memory and sleep
// ---------------------------------------------------------------------------

/// pico `z_malloc`: the kernel heap's `k_malloc`, as pico's Zephyr backend's is.
pub unsafe fn malloc(size: usize) -> *mut c_void {
    k_malloc(size)
}

/// pico `z_free`: `k_free`, null-tolerant as it is.
pub unsafe fn free(ptr: *mut c_void) {
    k_free(ptr)
}

/// pico `z_realloc`: NULL, always. The kernel heap has no `k_realloc`, and pico's Zephyr backend
/// answers NULL for that reason; an answer that moved the bytes here would be a heap pico's own
/// program never has.
pub unsafe fn realloc(_ptr: *mut c_void, _size: usize) -> *mut c_void {
    core::ptr::null_mut()
}

/// Sleep at least `time` of `unit`. The kernel's sleeps answer what is left of one a wake cut
/// short, and that is slept again, as pico's Zephyr backend does; the remainder is in the unit
/// asked (`wz_pico_sleep_s` rounds the kernel's milliseconds up to seconds).
pub fn sleep(unit: Unit, time: usize) {
    let mut rem = i32::try_from(time).unwrap_or(i32::MAX);
    while rem > 0 {
        // SAFETY: the image's contract (the module doc): any thread, any duration.
        rem = unsafe {
            match unit {
                Unit::Micro => wz_pico_sleep_us(rem),
                Unit::Milli => wz_pico_sleep_ms(rem),
                Unit::Second => wz_pico_sleep_s(rem),
            }
        };
    }
}

// ---------------------------------------------------------------------------
// Monotonic clock
// ---------------------------------------------------------------------------

/// Read the monotonic clock: `clock_gettime(CLOCK_MONOTONIC)`, as pico does.
pub fn clock_now() -> Clock {
    let mut now = Clock {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a live local the call writes.
    unsafe { clock_gettime(CLOCK_MONOTONIC, &mut now) };
    now
}

/// Elapsed time in `unit` between two readings, clamped to 0 when negative, as pico's
/// `zp_clock_elapsed_*_since` are. pico computes in a 32-bit `long`, which overflows past 35
/// minutes of microseconds; this computes in 64 bits and answers the largest `unsigned long` past
/// it, where pico's answer is undefined.
pub fn clock_elapsed_between(instant: &Clock, epoch: &Clock, unit: Unit) -> c_ulong {
    let elapsed = arith::elapsed(
        (instant.tv_sec, i64::from(instant.tv_nsec)),
        (epoch.tv_sec, i64::from(epoch.tv_nsec)),
        NANOS_PER_SECOND,
        unit,
    );
    c_ulong::try_from(arith::clamped(elapsed)).unwrap_or(c_ulong::MAX)
}

/// Move a reading FORWARD by `duration` units, with pico's one carry (`tv_nsec` starts below 1e9
/// and gains less than a second, which a 32-bit `long` holds).
pub fn clock_advance(clock: &mut Clock, unit: Unit, duration: c_ulong) {
    let (secs, nanos) = arith::advance(
        (clock.tv_sec, i64::from(clock.tv_nsec)),
        unit,
        u64::from(duration),
    );
    clock.tv_sec = secs;
    // Below a second, so a `long` of any width holds it.
    clock.tv_nsec = nanos as c_long;
}

// ---------------------------------------------------------------------------
// Wall clock
// ---------------------------------------------------------------------------

/// Read the wall clock: `clock_gettime(CLOCK_REALTIME)` in microseconds, which is pico's
/// `_z_gettimeofday` on Zephyr.
pub fn wall_now() -> WallTime {
    let mut now = Clock {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a live local the call writes.
    unsafe { clock_gettime(CLOCK_REALTIME, &mut now) };
    WallTime {
        tv_sec: now.tv_sec,
        tv_usec: now.tv_nsec / 1_000,
    }
}

/// Elapsed time in `unit` on the WALL clock since `time`, with no clamp: pico casts the signed
/// difference to `unsigned long`, so a `time` in the future wraps, and so does this.
pub fn wall_elapsed(time: &WallTime, unit: Unit) -> c_ulong {
    let now = wall_now();
    let elapsed = arith::elapsed(
        (now.tv_sec, i64::from(now.tv_usec)),
        (time.tv_sec, i64::from(time.tv_usec)),
        MICROS_PER_SECOND,
        unit,
    );
    // The wrapping cast IS the contract here.
    elapsed as c_ulong
}

/// Render `time` as LOCAL time in `buf` as `%Y-%m-%dT%H:%M:%SZ` with the C library's
/// `localtime` and `strftime`, as pico does, and say whether it fit.
///
/// # Safety
/// `buf` must point at `buflen` writable bytes.
pub unsafe fn wall_render_local(time: &WallTime, buf: *mut c_char, buflen: usize) -> bool {
    let secs = time.tv_sec;
    let tm = localtime(&secs);
    if tm.is_null() {
        return false;
    }
    let fmt = c"%Y-%m-%dT%H:%M:%SZ";
    strftime(buf, buflen, fmt.as_ptr(), tm) != 0
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill `len` bytes of `buf` from the kernel's random source, `sys_rand_get`, as pico's Zephyr
/// backend does.
///
/// # Safety
/// `buf` must point at `len` writable bytes.
pub unsafe fn random_fill(buf: *mut c_void, len: usize) {
    wz_pico_random_fill(buf, len)
}

/// The host primitives of pico's multi-threaded arm on Zephyr's POSIX layer: mutex, condvar and
/// task, compiled under `multi-thread` as pico compiles its own under `Z_FEATURE_MULTI_THREAD`.
#[cfg(feature = "multi-thread")]
mod threads {
    use core::ffi::{c_int, c_uint, c_void};

    use super::Clock;
    use crate::result::{ZResult, Z_OK};
    use crate::sync::{Z_ERR_SYSTEM_GENERIC, Z_ETIMEDOUT};

    /// pico `_z_mutex_t`: Zephyr's `pthread_mutex_t`, a 32-bit handle.
    pub type RawMutex = u32;
    /// pico `_z_condvar_t`: Zephyr's `pthread_cond_t`, a 32-bit handle.
    pub type RawCondvar = u32;
    /// pico `_z_task_t`: Zephyr's `pthread_t`, a 32-bit handle.
    pub type RawTask = u32;

    /// pico `z_task_attr_t`: Zephyr's `pthread_attr_t`, the stack and two words of details,
    /// 12 B on a 32-bit core.
    #[repr(C)]
    pub struct TaskAttr {
        pub stack: *mut c_void,
        pub details: [c_uint; 2],
    }

    /// The value of a task that was never started or has been joined or detached.
    pub const TASK_NULL: RawTask = 0;

    /// Zephyr's `ETIMEDOUT` (its C library's `errno.h`), pinned by the image.
    const ETIMEDOUT: c_int = 116;

    extern "C" {
        fn pthread_mutex_init(m: *mut RawMutex, attr: *const c_void) -> c_int;
        fn pthread_mutex_destroy(m: *mut RawMutex) -> c_int;
        fn pthread_mutex_lock(m: *mut RawMutex) -> c_int;
        fn pthread_mutex_trylock(m: *mut RawMutex) -> c_int;
        fn pthread_mutex_unlock(m: *mut RawMutex) -> c_int;
        fn pthread_cond_destroy(cv: *mut RawCondvar) -> c_int;
        fn pthread_cond_signal(cv: *mut RawCondvar) -> c_int;
        fn pthread_cond_wait(cv: *mut RawCondvar, m: *mut RawMutex) -> c_int;
        fn pthread_cond_timedwait(
            cv: *mut RawCondvar,
            m: *mut RawMutex,
            abstime: *const Clock,
        ) -> c_int;
        fn pthread_create(
            task: *mut RawTask,
            attr: *const TaskAttr,
            fun: extern "C" fn(*mut c_void) -> *mut c_void,
            arg: *mut c_void,
        ) -> c_int;
        fn pthread_join(task: RawTask, status: *mut *mut c_void) -> c_int;
        fn pthread_detach(task: RawTask) -> c_int;
        fn wz_pico_condvar_init(cv: *mut RawCondvar) -> c_int;
    }

    /// pico's `_Z_CHECK_SYS_ERR`: 0 is `Z_OK`, anything else is the system-error code.
    #[inline]
    fn sys(rc: c_int) -> ZResult {
        if rc == 0 {
            Z_OK
        } else {
            Z_ERR_SYSTEM_GENERIC
        }
    }

    /// Initialise a mutex in place, with no attribute, as pico does.
    ///
    /// # Safety
    /// `m` must point at storage for a `RawMutex`.
    pub unsafe fn mutex_init(m: *mut RawMutex) -> ZResult {
        sys(pthread_mutex_init(m, core::ptr::null()))
    }

    /// Destroy a mutex.
    ///
    /// # Safety
    /// `m` must point at an initialised, unlocked `RawMutex`.
    pub unsafe fn mutex_destroy(m: *mut RawMutex) -> ZResult {
        sys(pthread_mutex_destroy(m))
    }

    /// Lock, blocking.
    ///
    /// # Safety
    /// `m` must point at an initialised `RawMutex`.
    pub unsafe fn mutex_lock(m: *mut RawMutex) -> ZResult {
        sys(pthread_mutex_lock(m))
    }

    /// Try to lock without blocking.
    ///
    /// # Safety
    /// As `mutex_lock`.
    pub unsafe fn mutex_try_lock(m: *mut RawMutex) -> ZResult {
        sys(pthread_mutex_trylock(m))
    }

    /// Unlock.
    ///
    /// # Safety
    /// As `mutex_lock`, and the caller holds the lock.
    pub unsafe fn mutex_unlock(m: *mut RawMutex) -> ZResult {
        sys(pthread_mutex_unlock(m))
    }

    /// Initialise a condvar on `CLOCK_MONOTONIC`, through an attribute, as pico does: an absolute
    /// deadline taken from `clock_now` must mean the same instant to the wait.
    ///
    /// # Safety
    /// `cv` must point at storage for a `RawCondvar`.
    pub unsafe fn condvar_init(cv: *mut RawCondvar) -> ZResult {
        sys(wz_pico_condvar_init(cv))
    }

    /// Destroy a condvar.
    ///
    /// # Safety
    /// `cv` must point at an initialised `RawCondvar` nobody waits on.
    pub unsafe fn condvar_destroy(cv: *mut RawCondvar) -> ZResult {
        sys(pthread_cond_destroy(cv))
    }

    /// Wake one waiter.
    ///
    /// # Safety
    /// `cv` must point at an initialised `RawCondvar`.
    pub unsafe fn condvar_signal(cv: *mut RawCondvar) -> ZResult {
        sys(pthread_cond_signal(cv))
    }

    /// Wait, releasing `m`.
    ///
    /// # Safety
    /// `cv` and `m` must be initialised, and the caller holds `m`.
    pub unsafe fn condvar_wait(cv: *mut RawCondvar, m: *mut RawMutex) -> ZResult {
        sys(pthread_cond_wait(cv, m))
    }

    /// Wait until an ABSOLUTE monotonic deadline; a timeout is `Z_ETIMEDOUT`, as pico's is.
    ///
    /// # Safety
    /// As `condvar_wait`.
    pub unsafe fn condvar_wait_until(
        cv: *mut RawCondvar,
        m: *mut RawMutex,
        abstime: &Clock,
    ) -> ZResult {
        let rc = pthread_cond_timedwait(cv, m, abstime);
        if rc == ETIMEDOUT {
            return Z_ETIMEDOUT;
        }
        sys(rc)
    }

    /// Start a thread running `fun(arg)` with `pthread_create`. pico's Zephyr backend keeps a
    /// table of stacks of its own for a task started with no attribute; here the kernel's POSIX
    /// layer gives one from its dynamic thread stacks, which the image sizes.
    ///
    /// # Safety
    /// `task` must be valid and writable; `attr` must be null or a valid `pthread_attr_t`.
    pub unsafe fn task_spawn(
        task: *mut RawTask,
        attr: *mut TaskAttr,
        fun: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> ZResult {
        sys(pthread_create(task, attr, fun, arg))
    }

    /// Wait for a started task to finish.
    ///
    /// # Safety
    /// `handle` must be a task `task_spawn` started and nothing has joined or detached.
    pub unsafe fn task_join(handle: RawTask) -> ZResult {
        sys(pthread_join(handle, core::ptr::null_mut()))
    }

    /// Release a started task WITHOUT waiting.
    ///
    /// # Safety
    /// As `task_join`.
    pub unsafe fn task_detach(handle: RawTask) -> ZResult {
        sys(pthread_detach(handle))
    }

    // The sizes a 32-bit core gives these, which the image pins against its own headers.
    #[cfg(target_pointer_width = "32")]
    const _: () = {
        assert!(core::mem::size_of::<TaskAttr>() == 12);
        assert!(core::mem::size_of::<RawMutex>() == 4);
        assert!(core::mem::size_of::<RawCondvar>() == 4);
    };
}
#[cfg(feature = "multi-thread")]
pub use threads::*;

const _: () = {
    assert!(core::mem::size_of::<Clock>() == 16);
    assert!(core::mem::size_of::<WallTime>() == 16);
};
