// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's calls: the slim reader/writer lock and condition variable of the parking
//! place, the threads, and the sleep.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    AcquireSRWLockExclusive, CreateThread, GetCurrentThreadId, ReleaseSRWLockExclusive, Sleep,
    SleepConditionVariableSRW, WaitForSingleObject, WakeAllConditionVariable, CONDITION_VARIABLE,
    CONDITION_VARIABLE_INIT, INFINITE, SRWLOCK, SRWLOCK_INIT,
};

use crate::ThreadStart;

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

    pub(crate) fn notify_all(&self) {
        // SAFETY: an initialised condition variable that never moves.
        unsafe { WakeAllConditionVariable(self.0.get()) };
    }
}

/// A thread of the system, by its handle.
pub(crate) type Thread = HANDLE;

unsafe extern "system" fn entry(arg: *mut c_void) -> u32 {
    crate::enter(arg);
    0
}

/// # Safety
/// As [`crate::spawn`].
pub(crate) unsafe fn spawn(start: *mut ThreadStart) -> Option<(Thread, usize)> {
    let mut id = 0u32;
    let handle = CreateThread(
        core::ptr::null(),
        0,
        Some(entry),
        start.cast_const().cast::<c_void>(),
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
