// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host layer: Win32 synchronisation objects and the performance counter,
//! as zenoh-pico's own `system/windows/system.c` uses them.
//!
//! Every value here is the bytes the C program's header says it is.
//! `vendor/zenoh-pico/include/zenoh-pico/system/platform/windows.h` types the mutex as
//! `SRWLOCK`, the condvar as `CONDITION_VARIABLE`, the clock as `LARGE_INTEGER`, the
//! wall time as `struct timeb` and the task as a thread `HANDLE`, and the C program
//! stack-allocates them before wz sees them. As on a Unix, the only correct
//! implementation is the host's own primitives acting on those bytes.
//!
//! The rules that are plain arithmetic live in `arith.rs`, which a Linux build compiles
//! and tests; this file is the Win32 calls around them and cannot be compiled by
//! anything but a Windows toolchain or a cross-check against one.

use std::ffi::{c_char, c_ulong, c_void};
use std::sync::atomic::{AtomicI64, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_TIMEOUT, FILETIME, HANDLE, SYSTEMTIME, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows_sys::Win32::System::Threading::{
    AcquireSRWLockExclusive, CreateThread, InitializeConditionVariable, InitializeSRWLock,
    ReleaseSRWLockExclusive, SleepConditionVariableSRW, TryAcquireSRWLockExclusive,
    WaitForSingleObject, WakeConditionVariable, CONDITION_VARIABLE, INFINITE, SRWLOCK,
};
use windows_sys::Win32::System::Time::{
    FileTimeToSystemTime, GetTimeZoneInformation, SystemTimeToTzSpecificLocalTime,
    TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION,
};

use super::{arith, Unit};
use crate::result::{ZResult, Z_ERR_GENERIC, Z_OK};
use crate::sync::Z_ETIMEDOUT;

/// What `GetTimeZoneInformation` returns while daylight saving time is in effect
/// (documented as 2, with 0 unknown, 1 standard and `TIME_ZONE_ID_INVALID` failure).
/// windows-sys keeps this one constant in a namespace this file has no other use
/// for, so it is named here instead of enabling that namespace for one number.
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

/// pico `_Z_ERR_SYSTEM_TASK_FAILED` (`utils/result.h:87`): what pico's Windows
/// `_z_task_init` reports when `CreateThread` returns no handle.
const Z_ERR_SYSTEM_TASK_FAILED: ZResult = -79;

/// pico `z_clock_t`: `LARGE_INTEGER`, a union of which `QuadPart` is the only member
/// pico reads. Eight bytes, passed and returned in one integer register, exactly as
/// the union is, so the by-value return of `clock_now` matches without a shim.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    pub quad_part: i64,
}

/// pico `z_time_t`: the C runtime's `struct timeb`, 16 B on both 32- and 64-bit
/// Windows: the 64-bit seconds, the milliseconds, and the two zone fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallTime {
    pub time: i64,
    pub millitm: u16,
    pub timezone: i16,
    pub dstflag: i16,
}

/// pico `_z_mutex_t`: `SRWLOCK`, one pointer. It needs no destroy and zero is its
/// initial state.
pub type RawMutex = SRWLOCK;
/// pico `_z_condvar_t`: `CONDITION_VARIABLE`, one pointer.
pub type RawCondvar = CONDITION_VARIABLE;
/// pico `_z_task_t`: a thread `HANDLE`. pico declares it `HANDLE *` and stores the
/// handle in the pointer-sized slot, so the owned value is pointer-sized either way.
pub type RawTask = HANDLE;
/// pico `z_task_attr_t`: `void *`, "not used in Windows".
pub type TaskAttr = *mut c_void;

/// The value of a task that was never started or has been joined or detached.
pub const TASK_NULL: RawTask = std::ptr::null_mut();

const _: () = {
    assert!(std::mem::size_of::<RawMutex>() == std::mem::size_of::<*mut c_void>());
    assert!(std::mem::size_of::<RawCondvar>() == std::mem::size_of::<*mut c_void>());
    assert!(std::mem::size_of::<RawTask>() == std::mem::size_of::<*mut c_void>());
    assert!(std::mem::size_of::<TaskAttr>() == std::mem::size_of::<*mut c_void>());
    assert!(std::mem::size_of::<Clock>() == 8);
    assert!(std::mem::size_of::<WallTime>() == 16);
};

// ---------------------------------------------------------------------------
// Monotonic clock
// ---------------------------------------------------------------------------

/// Ticks per second of the performance counter, 0 when the host has none. Fixed at
/// boot, so it is read once; a failed read is not remembered and is asked again, as
/// pico asks every time.
fn frequency() -> i64 {
    static CACHE: AtomicI64 = AtomicI64::new(0);
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let mut ticks_per_second = 0_i64;
    // SAFETY: a live local the call writes.
    unsafe { QueryPerformanceFrequency(&mut ticks_per_second) };
    CACHE.store(ticks_per_second, Ordering::Relaxed);
    ticks_per_second
}

/// Read the performance counter, which is what pico's `z_clock_now` reads.
pub fn clock_now() -> Clock {
    let mut ticks = 0_i64;
    // SAFETY: a live local the call writes.
    unsafe { QueryPerformanceCounter(&mut ticks) };
    Clock { quad_part: ticks }
}

/// Elapsed time in `unit` between two readings, in pico's arithmetic.
pub fn clock_elapsed_between(instant: &Clock, epoch: &Clock, unit: Unit) -> c_ulong {
    arith::ticks_elapsed(instant.quad_part, epoch.quad_part, frequency(), unit)
}

/// Move a reading forward by `duration` units. A host with no counter leaves it
/// alone, as pico does.
pub fn clock_advance(clock: &mut Clock, unit: Unit, duration: c_ulong) {
    let frequency = frequency();
    if frequency == 0 {
        return;
    }
    clock.quad_part += arith::ticks_advance(duration, frequency, unit);
}

// ---------------------------------------------------------------------------
// Wall clock
// ---------------------------------------------------------------------------

/// Read the wall clock as the C runtime's `ftime` does: the UTC seconds and
/// milliseconds from the system time, and the zone fields from the host's time zone.
/// pico reads only the first two; the others are filled as `ftime` documents them,
/// the minutes west of UTC for standard time and whether daylight time is in effect.
pub fn wall_now() -> WallTime {
    let mut filetime = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: a live local the call writes.
    unsafe { GetSystemTimeAsFileTime(&mut filetime) };
    let ticks = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    let (time, millitm) = arith::unix_time_of_filetime(ticks);

    // SAFETY: a zeroed `TIME_ZONE_INFORMATION` is plain data, and the call writes it.
    let mut zone: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a live local the call writes.
    let id = unsafe { GetTimeZoneInformation(&mut zone) };
    let (timezone, dstflag) = if id == TIME_ZONE_ID_INVALID {
        // The call failed: report UTC rather than invent an offset.
        (0, 0)
    } else {
        (
            i16::try_from(zone.Bias + zone.StandardBias).unwrap_or(0),
            i16::from(id == TIME_ZONE_ID_DAYLIGHT),
        )
    };
    WallTime {
        time,
        millitm,
        timezone,
        dstflag,
    }
}

/// The stamp the wall-time arithmetic runs on.
fn stamp(time: &WallTime) -> arith::Stamp {
    (time.time, time.millitm)
}

/// Elapsed time in `unit` on the wall clock since `time`, in pico's arithmetic: no
/// clamp, in the 32-bit `unsigned long` of this host.
pub fn wall_elapsed(time: &WallTime, unit: Unit) -> c_ulong {
    let now = stamp(&wall_now());
    let then = stamp(time);
    match unit {
        Unit::Micro => arith::wall_elapsed_us(now, then),
        Unit::Milli => arith::wall_elapsed_ms(now, then),
        Unit::Second => arith::wall_elapsed_s(now, then),
    }
}

/// Render `time` as LOCAL time in `buf` as `%Y-%m-%dT%H:%M:%SZ`, and say whether it
/// fit.
///
/// pico calls `localtime` and `strftime`. The C runtime's zone rules and Win32's are
/// the same host database, so this converts through `SystemTimeToTzSpecificLocalTime`
/// and writes the digits itself, which keeps the one format string pico has and drops
/// the runtime's non-reentrant `localtime`. (The trailing `Z` on a LOCAL time is
/// upstream's; reproducing it is fidelity, not endorsement.) `false` means the caller
/// must NUL-terminate.
///
/// # Safety
/// `buf` must point at `buflen` writable bytes.
pub unsafe fn wall_render_local(time: &WallTime, buf: *mut c_char, buflen: usize) -> bool {
    let Some(ticks) = arith::filetime_of_unix_secs(time.time) else {
        return false;
    };
    let filetime = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let mut utc: SYSTEMTIME = std::mem::zeroed();
    if FileTimeToSystemTime(&filetime, &mut utc) == 0 {
        return false;
    }
    let mut local: SYSTEMTIME = std::mem::zeroed();
    if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
        return false;
    }
    let Some(text) = arith::format_iso(
        local.wYear,
        local.wMonth,
        local.wDay,
        local.wHour,
        local.wMinute,
        local.wSecond,
    ) else {
        return false;
    };
    if buflen < text.len() {
        return false;
    }
    std::ptr::copy_nonoverlapping(text.as_ptr().cast::<c_char>(), buf, text.len());
    true
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill `len` bytes of `buf` with the operating system's random source, which is
/// what pico's `RtlGenRandom` is: the `getrandom` crate already in this crate's graph
/// draws from it on Windows.
///
/// A failure is retried, as the Unix backend retries `EINTR`, because the export has
/// no error channel and a half-filled buffer would hand a caller predictable bytes
/// where it asked for random ones; the failure does not happen on a working host.
///
/// # Safety
/// `buf` must point at `len` writable bytes.
pub unsafe fn random_fill(buf: *mut c_void, len: usize) {
    let bytes = std::slice::from_raw_parts_mut(buf.cast::<u8>(), len);
    while getrandom::getrandom(bytes).is_err() {
        std::thread::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// Initialise a mutex in place (`InitializeSRWLock`).
///
/// # Safety
/// `m` must point at storage for a `RawMutex`.
pub unsafe fn mutex_init(m: *mut RawMutex) -> ZResult {
    InitializeSRWLock(m);
    Z_OK
}

/// Destroy a mutex: an SRW lock has nothing to release, as in pico.
///
/// # Safety
/// `m` must point at a `RawMutex`.
pub unsafe fn mutex_destroy(_m: *mut RawMutex) -> ZResult {
    Z_OK
}

/// Lock, blocking (exclusive).
///
/// # Safety
/// `m` must point at an initialised `RawMutex`.
pub unsafe fn mutex_lock(m: *mut RawMutex) -> ZResult {
    AcquireSRWLockExclusive(m);
    Z_OK
}

/// Try to lock without blocking. A refusal is pico's generic error on Windows.
///
/// # Safety
/// As `mutex_lock`.
pub unsafe fn mutex_try_lock(m: *mut RawMutex) -> ZResult {
    if TryAcquireSRWLockExclusive(m) {
        Z_OK
    } else {
        Z_ERR_GENERIC
    }
}

/// Unlock.
///
/// # Safety
/// As `mutex_lock`, and the caller holds the lock.
pub unsafe fn mutex_unlock(m: *mut RawMutex) -> ZResult {
    ReleaseSRWLockExclusive(m);
    Z_OK
}

// ---------------------------------------------------------------------------
// Condition variable
// ---------------------------------------------------------------------------

/// Initialise a condvar in place (`InitializeConditionVariable`). There is no clock
/// to choose: the wait takes a relative timeout.
///
/// # Safety
/// `cv` must point at storage for a `RawCondvar`.
pub unsafe fn condvar_init(cv: *mut RawCondvar) -> ZResult {
    InitializeConditionVariable(cv);
    Z_OK
}

/// Destroy a condvar: nothing to release, as in pico.
///
/// # Safety
/// `cv` must point at a `RawCondvar`.
pub unsafe fn condvar_destroy(_cv: *mut RawCondvar) -> ZResult {
    Z_OK
}

/// Wake one waiter.
///
/// # Safety
/// `cv` must point at an initialised `RawCondvar`.
pub unsafe fn condvar_signal(cv: *mut RawCondvar) -> ZResult {
    WakeConditionVariable(cv);
    Z_OK
}

/// Wait, releasing `m`. pico ignores the wait's result and so does this: the only
/// failure `SleepConditionVariableSRW` has without a timeout is a bad argument.
///
/// # Safety
/// `cv` and `m` must be initialised, and the caller holds `m` exclusively.
pub unsafe fn condvar_wait(cv: *mut RawCondvar, m: *mut RawMutex) -> ZResult {
    SleepConditionVariableSRW(cv, m, INFINITE, 0);
    Z_OK
}

/// Wait until an ABSOLUTE performance-counter deadline.
///
/// `SleepConditionVariableSRW` takes a relative timeout, so the deadline becomes the
/// milliseconds from now, as pico does (`system.c:210-232`); a timeout is
/// `Z_ETIMEDOUT` and any other failure is pico's generic error. A host with no
/// counter cannot make the conversion and is an error, as in pico.
///
/// # Safety
/// As `condvar_wait`.
pub unsafe fn condvar_wait_until(
    cv: *mut RawCondvar,
    m: *mut RawMutex,
    abstime: &Clock,
) -> ZResult {
    let frequency = frequency();
    if frequency == 0 {
        return Z_ERR_GENERIC;
    }
    let block = arith::remaining_millis(abstime.quad_part, clock_now().quad_part, frequency);
    if SleepConditionVariableSRW(cv, m, block, 0) == 0 {
        if GetLastError() == ERROR_TIMEOUT {
            Z_ETIMEDOUT
        } else {
            Z_ERR_GENERIC
        }
    } else {
        Z_OK
    }
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

/// What a started thread needs, handed through the one pointer `CreateThread` passes.
struct Start {
    fun: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
}

/// The thread entry point, in the calling convention `CreateThread` uses. pico casts
/// the C function to it; that is the same call on 64-bit Windows and a corrupted
/// stack on 32-bit, where the two conventions differ, so wz enters through a function
/// that is the right type and calls the C one itself. The C function's return value
/// has nowhere to go (pico's thread exit code is the low half of that pointer and
/// nothing reads it), so the exit code is 0.
unsafe extern "system" fn thread_main(start: *mut c_void) -> u32 {
    let Start { fun, arg } = *Box::from_raw(start.cast::<Start>());
    fun(arg);
    0
}

/// Start a thread running `fun(arg)` (`CreateThread`). `attr` is unused on Windows, as
/// in pico. No handle is pico's `_Z_ERR_SYSTEM_TASK_FAILED`.
///
/// # Safety
/// `task` must be valid and writable.
pub unsafe fn task_spawn(
    task: *mut RawTask,
    _attr: *mut TaskAttr,
    fun: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> ZResult {
    let start = Box::into_raw(Box::new(Start { fun, arg }));
    let handle = CreateThread(
        std::ptr::null(),
        0,
        Some(thread_main),
        start.cast::<c_void>(),
        0,
        std::ptr::null_mut(),
    );
    if handle.is_null() {
        drop(Box::from_raw(start));
        return Z_ERR_SYSTEM_TASK_FAILED;
    }
    *task = handle;
    Z_OK
}

/// Wait for a started task to finish and release its handle. The handle is not null.
/// pico leaves the handle for a later free; wz's join consumes the task, so it closes
/// it here, on every path.
///
/// # Safety
/// `handle` must be a task `task_spawn` started and nothing has joined or detached.
pub unsafe fn task_join(handle: RawTask) -> ZResult {
    let waited = WaitForSingleObject(handle, INFINITE);
    CloseHandle(handle);
    if waited == WAIT_OBJECT_0 {
        Z_OK
    } else {
        Z_ERR_GENERIC
    }
}

/// Release a started task WITHOUT waiting: closing the handle is what detaches a
/// Windows thread, which keeps running. The handle is not null.
///
/// # Safety
/// As `task_join`.
pub unsafe fn task_detach(handle: RawTask) -> ZResult {
    if CloseHandle(handle) == 0 {
        Z_ERR_GENERIC
    } else {
        Z_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wall clock reads the same instant the standard library does, which is the
    /// one thing the FILETIME-to-Unix conversion can be wrong about without any
    /// arithmetic test noticing.
    #[test]
    fn the_wall_clock_is_the_unix_time_of_now() {
        let std_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs() as i64;
        let wall = wall_now();
        assert!(
            (wall.time - std_secs).abs() <= 2,
            "wall {} vs std {}",
            wall.time,
            std_secs
        );
        assert!(wall.millitm < 1000);
    }

    /// The WALL clock family does NOT clamp: a future timestamp wraps, as upstream's
    /// unsigned cast does.
    #[test]
    fn a_future_wall_time_wraps_rather_than_clamping() {
        let now = wall_now();
        let future = WallTime {
            time: now.time + 3_600,
            ..now
        };
        assert!(wall_elapsed(&future, Unit::Second) > c_ulong::MAX / 2);
    }

    /// The counter is monotonic and has a frequency, and an interval measured across a
    /// real sleep is at least the sleep.
    #[test]
    fn the_performance_counter_measures_a_real_interval() {
        assert!(frequency() > 0, "this host has no performance counter");
        let before = clock_now();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let after = clock_now();
        assert!(after.quad_part > before.quad_part);
        assert!(clock_elapsed_between(&after, &before, Unit::Milli) >= 40);
    }

    /// A thread started through `CreateThread` runs the C function with its argument
    /// and a join waits for it, which is what the trampoline exists to guarantee.
    #[test]
    fn the_trampoline_runs_the_function_and_join_waits() {
        use std::sync::atomic::AtomicBool;
        static RAN: AtomicBool = AtomicBool::new(false);
        extern "C" fn body(arg: *mut c_void) -> *mut c_void {
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!(arg as usize, 0x5eed);
            RAN.store(true, Ordering::SeqCst);
            std::ptr::null_mut()
        }
        let mut task = TASK_NULL;
        // SAFETY: a live local, and a function with the right C signature.
        unsafe {
            assert_eq!(
                task_spawn(&mut task, std::ptr::null_mut(), body, 0x5eed as *mut c_void),
                Z_OK
            );
            assert!(!task.is_null());
            assert_eq!(task_join(task), Z_OK);
        }
        assert!(
            RAN.load(Ordering::SeqCst),
            "join returned before the thread ran"
        );
    }
}
