// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The POSIX host's calls: the pthread mutex and condition variable of the parking place, the
//! threads, and the sleep.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use crate::ThreadStart;

/// The parking place's mutex. It lives in a `static` and never moves, which a pthread mutex needs.
pub(crate) struct ParkLock(UnsafeCell<libc::pthread_mutex_t>);

// SAFETY: a pthread mutex is made to be shared between threads; it is reached only through the
// calls below.
unsafe impl Sync for ParkLock {}

impl ParkLock {
    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER))
    }

    pub(crate) fn lock(&self) {
        // SAFETY: an initialised mutex that never moves.
        unsafe { libc::pthread_mutex_lock(self.0.get()) };
    }

    /// # Safety
    /// The calling thread holds it.
    pub(crate) unsafe fn unlock(&self) {
        libc::pthread_mutex_unlock(self.0.get());
    }
}

/// The parking place's condition variable, waited on with [`ParkLock`].
pub(crate) struct ParkCond(UnsafeCell<libc::pthread_cond_t>);

// SAFETY: as for `ParkLock`.
unsafe impl Sync for ParkCond {}

impl ParkCond {
    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER))
    }

    /// # Safety
    /// The calling thread holds `lock`.
    pub(crate) unsafe fn wait(&self, lock: &ParkLock) {
        libc::pthread_cond_wait(self.0.get(), lock.0.get());
    }

    pub(crate) fn notify_all(&self) {
        // SAFETY: an initialised condition variable that never moves.
        unsafe { libc::pthread_cond_broadcast(self.0.get()) };
    }
}

/// A thread of the system, by its pthread.
pub(crate) type Thread = libc::pthread_t;

extern "C" fn entry(arg: *mut c_void) -> *mut c_void {
    // SAFETY: `arg` is the record `spawn` handed `pthread_create`.
    unsafe { crate::enter(arg) };
    core::ptr::null_mut()
}

/// # Safety
/// As [`crate::spawn`].
pub(crate) unsafe fn spawn(start: *mut ThreadStart) -> Option<(Thread, usize)> {
    let mut thread: libc::pthread_t = core::mem::zeroed();
    if libc::pthread_create(
        &mut thread,
        core::ptr::null(),
        entry,
        start.cast::<c_void>(),
    ) != 0
    {
        return None;
    }
    // The number `pthread_self` answers on the new thread.
    Some((thread, thread as usize))
}

pub(crate) fn current_thread() -> usize {
    // SAFETY: no argument; any thread.
    unsafe { libc::pthread_self() as usize }
}

/// # Safety
/// `thread` is a started thread that nothing has joined or detached.
pub(crate) unsafe fn join(thread: Thread) {
    libc::pthread_join(thread, core::ptr::null_mut());
}

/// # Safety
/// As [`join`].
pub(crate) unsafe fn detach(thread: Thread) {
    libc::pthread_detach(thread);
}

/// `nanosleep`, slept again for what is left when a signal cuts it short, as the standard
/// library's sleep does.
pub(crate) fn sleep_ms(ms: u64) {
    let mut ask = libc::timespec {
        tv_sec: libc::time_t::try_from(ms / 1_000).unwrap_or(libc::time_t::MAX),
        tv_nsec: ((ms % 1_000) * 1_000_000) as libc::c_long,
    };
    let mut left = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: both are live locals the call reads and writes.
    while unsafe { libc::nanosleep(&ask, &mut left) } != 0 {
        ask = left;
    }
}
