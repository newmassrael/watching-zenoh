// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's calls: the slim reader/writer lock and condition variable of the parking
//! place, the threads, and the sleep.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{
    AcquireSRWLockExclusive, CreateThread, GetCurrentThreadId, ReleaseSRWLockExclusive, Sleep,
    SleepConditionVariableSRW, WaitForSingleObject, WakeAllConditionVariable, CONDITION_VARIABLE,
    CONDITION_VARIABLE_INIT, INFINITE, SRWLOCK, SRWLOCK_INIT,
};

/// The parking place's lock, held exclusively.
pub(crate) struct ParkLock(UnsafeCell<SRWLOCK>);

// SAFETY: a slim reader/writer lock is made to be shared between threads; it is reached only
// through the calls below.
unsafe impl Sync for ParkLock {}

impl ParkLock {
    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new(SRWLOCK_INIT))
    }

    pub(crate) fn lock(&self) {
        // SAFETY: an initialised lock that never moves.
        unsafe { AcquireSRWLockExclusive(self.0.get()) };
    }

    /// # Safety
    /// The calling thread holds it.
    pub(crate) unsafe fn unlock(&self) {
        ReleaseSRWLockExclusive(self.0.get());
    }
}

/// The parking place's condition variable, waited on with [`ParkLock`].
pub(crate) struct ParkCond(UnsafeCell<CONDITION_VARIABLE>);

// SAFETY: as for `ParkLock`.
unsafe impl Sync for ParkCond {}

impl ParkCond {
    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new(CONDITION_VARIABLE_INIT))
    }

    /// # Safety
    /// The calling thread holds `lock` exclusively.
    pub(crate) unsafe fn wait(&self, lock: &ParkLock) {
        SleepConditionVariableSRW(self.0.get(), lock.0.get(), INFINITE, 0);
    }

    /// Wait until notified or until the performance counter reads `deadline_ns`: the wait takes
    /// the milliseconds left, rounded up so that it does not end before the deadline.
    ///
    /// # Safety
    /// The calling thread holds `lock` exclusively.
    pub(crate) unsafe fn wait_until(&self, lock: &ParkLock, deadline_ns: u64) {
        let left_ms = deadline_ns
            .saturating_sub(monotonic_ns())
            .div_ceil(1_000_000)
            .min(u64::from(INFINITE - 1));
        SleepConditionVariableSRW(self.0.get(), lock.0.get(), left_ms as u32, 0);
    }

    /// # Safety
    /// The calling thread holds the parking place's lock.
    pub(crate) unsafe fn notify_all(&self) {
        WakeAllConditionVariable(self.0.get());
    }
}

/// The hundreds of nanoseconds from 1601-01-01, where a `FILETIME` counts from, to the Unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// The precise system time: the seconds and nanoseconds since the Unix epoch, `None` before it.
pub(crate) fn wall_clock() -> Option<(u64, u32)> {
    let mut now = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: a live local the call writes.
    unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
    let ticks = (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime);
    let since = ticks.checked_sub(FILETIME_UNIX_EPOCH)?;
    Some((since / 10_000_000, ((since % 10_000_000) * 100) as u32))
}

/// The performance counter in nanoseconds.
pub(crate) fn monotonic_ns() -> u64 {
    let mut ticks = 0_i64;
    let mut per_second = 0_i64;
    // SAFETY: live locals the calls write.
    unsafe {
        QueryPerformanceCounter(&mut ticks);
        QueryPerformanceFrequency(&mut per_second);
    }
    if per_second <= 0 || ticks < 0 {
        return 0;
    }
    (u128::from(ticks as u64) * 1_000_000_000 / u128::from(per_second as u64)) as u64
}

/// A thread of the system, by its handle.
pub(crate) type Thread = HANDLE;

unsafe extern "system" fn entry(arg: *mut c_void) -> u32 {
    crate::enter(arg);
    0
}

/// Start a thread that calls `crate::enter` with `arg`.
///
/// # Safety
/// `arg` is what `crate::enter` is to be called with, valid until it has run.
pub(crate) unsafe fn spawn(arg: *mut c_void) -> Option<(Thread, usize)> {
    let mut id = 0u32;
    let handle = CreateThread(
        core::ptr::null(),
        0,
        Some(entry),
        arg.cast_const(),
        0,
        &mut id,
    );
    if handle.is_null() {
        return None;
    }
    // The number `GetCurrentThreadId` answers on the new thread.
    Some((handle, id as usize))
}

pub(crate) fn current_thread() -> usize {
    // SAFETY: no argument; any thread.
    unsafe { GetCurrentThreadId() as usize }
}

/// # Safety
/// `thread` is a started thread's handle that nothing has joined or detached.
pub(crate) unsafe fn join(thread: Thread) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

/// Closing the handle is what lets a Windows thread go; it runs on.
///
/// # Safety
/// As [`join`].
pub(crate) unsafe fn detach(thread: Thread) {
    CloseHandle(thread);
}

/// `Sleep` takes a 32-bit count whose largest value is `INFINITE`, so a longer sleep is taken in
/// parts.
pub(crate) fn sleep_ms(ms: u64) {
    let mut left = ms;
    loop {
        let part = left.min(u64::from(INFINITE - 1));
        // SAFETY: any thread, any count below `INFINITE`.
        unsafe { Sleep(part as u32) };
        left -= part;
        if left == 0 {
            break;
        }
    }
}
