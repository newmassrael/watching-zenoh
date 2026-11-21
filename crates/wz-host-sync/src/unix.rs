// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The POSIX host's calls: the pthread mutex and condition variable of the parking place, the
//! threads, and the sleep.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// The parking place's condition variable, waited on with [`ParkLock`]. Its timed waits are on
/// the monotonic clock, which a static initialiser cannot ask for: it is made again with that clock
/// on its first use, under `ParkLock` as every use is, so it is made once.
pub(crate) struct ParkCond {
    cond: UnsafeCell<libc::pthread_cond_t>,
    monotonic: AtomicBool,
}

// SAFETY: as for `ParkLock`.
unsafe impl Sync for ParkCond {}

impl ParkCond {
    pub(crate) const fn new() -> Self {
        Self {
            cond: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER),
            monotonic: AtomicBool::new(false),
        }
    }

    /// The condition variable, timed on the monotonic clock.
    ///
    /// # Safety
    /// The calling thread holds the parking place's lock.
    unsafe fn get(&self) -> *mut libc::pthread_cond_t {
        // The lock orders the first use before every other, so the flag needs no ordering of its
        // own.
        if !self.monotonic.load(Ordering::Relaxed) {
            on_the_monotonic_clock(self.cond.get());
            self.monotonic.store(true, Ordering::Relaxed);
        }
        self.cond.get()
    }

    /// # Safety
    /// The calling thread holds `lock`.
    pub(crate) unsafe fn wait(&self, lock: &ParkLock) {
        libc::pthread_cond_wait(self.get(), lock.0.get());
    }

    /// Wait until notified or until the monotonic clock reads `deadline_ns`.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    #[cfg(not(target_os = "macos"))]
    pub(crate) unsafe fn wait_until(&self, lock: &ParkLock, deadline_ns: u64) {
        let at = libc::timespec {
            tv_sec: libc::time_t::try_from(deadline_ns / 1_000_000_000)
                .unwrap_or(libc::time_t::MAX),
            tv_nsec: (deadline_ns % 1_000_000_000) as libc::c_long,
        };
        libc::pthread_cond_timedwait(self.get(), lock.0.get(), &at);
    }

    /// macOS times a wait by an interval, as it has no clock to set on a condition variable.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe fn wait_until(&self, lock: &ParkLock, deadline_ns: u64) {
        let left = deadline_ns.saturating_sub(monotonic_ns());
        let interval = libc::timespec {
            tv_sec: libc::time_t::try_from(left / 1_000_000_000).unwrap_or(libc::time_t::MAX),
            tv_nsec: (left % 1_000_000_000) as libc::c_long,
        };
        libc::pthread_cond_timedwait_relative_np(self.get(), lock.0.get(), &interval);
    }

    /// # Safety
    /// The calling thread holds the parking place's lock.
    pub(crate) unsafe fn notify_all(&self) {
        libc::pthread_cond_broadcast(self.get());
    }
}

/// Make `cond` again, its timed waits on `CLOCK_MONOTONIC`, the clock [`monotonic_ns`] reads.
#[cfg(not(target_os = "macos"))]
unsafe fn on_the_monotonic_clock(cond: *mut libc::pthread_cond_t) {
    let mut attr: libc::pthread_condattr_t = core::mem::zeroed();
    libc::pthread_condattr_init(&mut attr);
    libc::pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC);
    libc::pthread_cond_init(cond, &attr);
    libc::pthread_condattr_destroy(&mut attr);
}

/// macOS keeps the statically made condition variable: its timed wait takes an interval.
#[cfg(target_os = "macos")]
unsafe fn on_the_monotonic_clock(_cond: *mut libc::pthread_cond_t) {}

/// `CLOCK_MONOTONIC` in nanoseconds.
pub(crate) fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a live local the call writes; the clock always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    (now.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now.tv_nsec as u64)
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
