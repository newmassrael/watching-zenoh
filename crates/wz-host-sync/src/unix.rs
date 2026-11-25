// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The POSIX host's calls: the wait on a word that the locks, the condition variables and the
//! parker sleep on, the clocks, the threads, and the sleep.

use core::ffi::c_void;

// The wait on a word: the futex on Linux and Android, libSystem's address wait on Apple's systems,
// and on a host with neither a few pthread pairs that a word's address picks.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use futex::{wait, wake_all, wake_one};
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
pub(crate) use pairs::{wait, wake_all, wake_one};
#[cfg(target_vendor = "apple")]
pub(crate) use ulock::{wait, wake_all, wake_one};

/// `ns` nanoseconds as the `timespec` the system's calls take, its seconds held to the largest
/// a `time_t` holds.
fn timespec_of(ns: u64) -> libc::timespec {
    libc::timespec {
        tv_sec: libc::time_t::try_from(ns / 1_000_000_000).unwrap_or(libc::time_t::MAX),
        tv_nsec: (ns % 1_000_000_000) as libc::c_long,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod futex {
    use core::sync::atomic::AtomicU32;

    /// The bit set of a wait that any wake wakes: with it `FUTEX_WAIT_BITSET` is the plain wait,
    /// with a deadline on the absolute `CLOCK_MONOTONIC` in place of an interval.
    const ANY: u32 = u32::MAX;

    /// Sleep while `word` reads `expected`, until a wake on it or, with a deadline, until the
    /// monotonic clock reads `deadline_ns`. It may end sooner (a signal, or a wake meant for a
    /// value the word no longer holds): the caller reads the word again.
    pub(crate) fn wait(word: &AtomicU32, expected: u32, deadline_ns: Option<u64>) {
        match deadline_ns {
            None => {
                wait_on::<libc::timespec>(libc::SYS_futex, word, expected, None);
            }
            Some(deadline) => wait_until(word, expected, deadline),
        }
    }

    /// A wait with a deadline, on a host whose `timespec` has a 64-bit `time_t`.
    #[cfg(not(all(
        target_pointer_width = "32",
        any(target_arch = "x86", target_arch = "arm")
    )))]
    fn wait_until(word: &AtomicU32, expected: u32, deadline_ns: u64) {
        wait_on(
            libc::SYS_futex,
            word,
            expected,
            Some(&super::timespec_of(deadline_ns)),
        );
    }

    #[cfg(all(
        target_pointer_width = "32",
        any(target_arch = "x86", target_arch = "arm")
    ))]
    use time64::wait_until;

    /// A 32-bit x86 or Arm host, whose `timespec` has a 32-bit `time_t`: a deadline is handed
    /// to the call with 64-bit time (Linux 5.1 and later), and to the one with the 32-bit
    /// `timespec` on a kernel that has no such call.
    #[cfg(all(
        target_pointer_width = "32",
        any(target_arch = "x86", target_arch = "arm")
    ))]
    mod time64 {
        use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        /// `futex_time64`, one number on every 32-bit x86 and Arm kernel; `libc` names none.
        const SYS_FUTEX_TIME64: libc::c_long = 422;

        /// The kernel answered the 64-bit time call as one it does not have.
        static WITHOUT: AtomicBool = AtomicBool::new(false);

        /// The kernel's `__kernel_timespec`: both fields 64 bits on every host.
        #[repr(C)]
        struct Timespec64 {
            tv_sec: i64,
            tv_nsec: i64,
        }

        pub(super) fn wait_until(word: &AtomicU32, expected: u32, deadline_ns: u64) {
            if !WITHOUT.load(Ordering::Relaxed) {
                let at = Timespec64 {
                    tv_sec: i64::try_from(deadline_ns / 1_000_000_000).unwrap_or(i64::MAX),
                    tv_nsec: (deadline_ns % 1_000_000_000) as i64,
                };
                if super::wait_on(SYS_FUTEX_TIME64, word, expected, Some(&at)) != -1
                    || errno() != libc::ENOSYS
                {
                    return;
                }
                WITHOUT.store(true, Ordering::Relaxed);
            }
            super::wait_on(
                libc::SYS_futex,
                word,
                expected,
                Some(&super::super::timespec_of(deadline_ns)),
            );
        }

        #[cfg(target_os = "linux")]
        fn errno() -> libc::c_int {
            // SAFETY: the calling thread's `errno`, which lives as long as the thread.
            unsafe { *libc::__errno_location() }
        }

        #[cfg(target_os = "android")]
        fn errno() -> libc::c_int {
            // SAFETY: as on Linux.
            unsafe { *libc::__errno() }
        }
    }

    /// The wait call `number` on `word`, with the time `at` of the call's own `timespec` or
    /// none: what the call answers, -1 with `errno` set when it failed.
    fn wait_on<T>(
        number: libc::c_long,
        word: &AtomicU32,
        expected: u32,
        at: Option<&T>,
    ) -> libc::c_long {
        let at = at.map_or(core::ptr::null(), core::ptr::from_ref);
        // SAFETY: the kernel reads the word as the 32-bit integer an `AtomicU32` is, and the time
        // is a live value of the layout the call takes, or null for none; the word is this
        // process's alone (`PRIVATE`).
        unsafe {
            libc::syscall(
                number,
                word.as_ptr(),
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                expected,
                at,
                core::ptr::null::<u32>(),
                ANY,
            )
        }
    }

    /// Wake one thread asleep on `word`.
    pub(crate) fn wake_one(word: &AtomicU32) {
        wake(word, 1);
    }

    /// Wake every thread asleep on `word`.
    pub(crate) fn wake_all(word: &AtomicU32) {
        wake(word, i32::MAX);
    }

    fn wake(word: &AtomicU32, count: i32) {
        // SAFETY: a wake reads no memory; the address only names the threads asleep on it.
        unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
                count,
            );
        }
    }
}

#[cfg(target_vendor = "apple")]
mod ulock {
    use core::ffi::{c_int, c_void};
    use core::sync::atomic::AtomicU32;

    // libSystem's wait on an address, which the C++ library's `std::atomic::wait` is made of on
    // these systems.
    extern "C" {
        fn __ulock_wait(operation: u32, addr: *mut c_void, value: u64, timeout_us: u32) -> c_int;
        fn __ulock_wake(operation: u32, addr: *mut c_void, wake_value: u64) -> c_int;
    }

    /// Compare the 32-bit word at the address and sleep while it holds the value.
    const UL_COMPARE_AND_WAIT: u32 = 1;
    /// Wake every thread asleep on the address, not one.
    const ULF_WAKE_ALL: u32 = 0x0000_0100;
    /// Answer an error as the return value and leave `errno` alone.
    const ULF_NO_ERRNO: u32 = 0x0100_0000;

    /// As Linux's (`futex::wait`). The wait takes microseconds left, 0 for no timeout: the
    /// time left is rounded up and is at least 1, so a deadline never reads as none, and a
    /// longer one than the count holds is waited in parts by the caller's loop.
    pub(crate) fn wait(word: &AtomicU32, expected: u32, deadline_ns: Option<u64>) {
        let timeout_us = deadline_ns.map_or(0, |deadline| {
            let left = deadline
                .saturating_sub(super::monotonic_ns())
                .div_ceil(1_000);
            u32::try_from(left).unwrap_or(u32::MAX).max(1)
        });
        // SAFETY: the system reads the word as the 32-bit integer an `AtomicU32` is.
        unsafe {
            __ulock_wait(
                UL_COMPARE_AND_WAIT | ULF_NO_ERRNO,
                word.as_ptr().cast(),
                u64::from(expected),
                timeout_us,
            );
        }
    }

    /// Wake one thread asleep on `word`.
    pub(crate) fn wake_one(word: &AtomicU32) {
        wake(word, 0);
    }

    /// Wake every thread asleep on `word`.
    pub(crate) fn wake_all(word: &AtomicU32) {
        wake(word, ULF_WAKE_ALL);
    }

    fn wake(word: &AtomicU32, flags: u32) {
        // SAFETY: a wake reads no memory; the address only names the threads asleep on it.
        unsafe {
            __ulock_wake(
                UL_COMPARE_AND_WAIT | ULF_NO_ERRNO | flags,
                word.as_ptr().cast(),
                0,
            );
        }
    }
}

/// A POSIX host with no wait on an address: a word sleeps on one of a few pthread mutex and
/// condition variable pairs, the one its address picks, and a wake wakes every thread asleep on
/// that pair, each of which reads its own word again. Built in a test of every host, so a host
/// that has a wait of its own still runs it.
#[cfg(any(
    test,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
mod pairs {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// How many pairs the words share: words that pick one pair wake each other's threads, which
    /// read their words again and sleep again.
    const PAIRS: usize = 64;

    /// One mutex and condition variable, in a `static` that never moves, which a pthread object
    /// needs.
    struct Pair {
        lock: UnsafeCell<libc::pthread_mutex_t>,
        cond: UnsafeCell<libc::pthread_cond_t>,
        /// Whether `cond` was made again on the monotonic clock (`Self::cond`).
        monotonic: AtomicBool,
    }

    // SAFETY: a pthread mutex and condition variable are made to be shared between threads; they
    // are reached only through the calls below, and `cond` with `lock` held.
    unsafe impl Sync for Pair {}

    static PAIRED: [Pair; PAIRS] = [const { Pair::new() }; PAIRS];

    impl Pair {
        const fn new() -> Self {
            Self {
                lock: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
                cond: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER),
                monotonic: AtomicBool::new(false),
            }
        }

        /// The pair `word` sleeps on. A word is four bytes aligned, so the bits below that are
        /// the same for every word and pick nothing.
        fn of(word: &AtomicU32) -> &'static Self {
            &PAIRED[((word.as_ptr() as usize) >> 2) % PAIRS]
        }

        /// The condition variable, its timed waits on the monotonic clock, which a static
        /// initialiser cannot ask for: made again with that clock on its first use, under the
        /// lock as every use is, so it is made once.
        ///
        /// # Safety
        /// The calling thread holds `lock`.
        unsafe fn cond(&self) -> *mut libc::pthread_cond_t {
            // The lock orders the first use before every other, so the flag needs no ordering of
            // its own.
            if !self.monotonic.load(Ordering::Relaxed) {
                on_the_monotonic_clock(self.cond.get());
                self.monotonic.store(true, Ordering::Relaxed);
            }
            self.cond.get()
        }
    }

    /// As Linux's (`futex::wait`): the word is read with its pair's lock held, and a waker
    /// changes the word before it takes that lock to wake, so either this thread reads the
    /// change and does not sleep, or it sleeps before the wake and the wake reaches it.
    pub(crate) fn wait(word: &AtomicU32, expected: u32, deadline_ns: Option<u64>) {
        let pair = Pair::of(word);
        // SAFETY: the pair's objects are initialised and never move; `cond` is reached with
        // `lock` held, which the waits let go and take back.
        unsafe {
            libc::pthread_mutex_lock(pair.lock.get());
            if word.load(Ordering::Relaxed) == expected {
                let cond = pair.cond();
                match deadline_ns {
                    None => {
                        libc::pthread_cond_wait(cond, pair.lock.get());
                    }
                    Some(deadline) => wait_until(cond, pair.lock.get(), deadline),
                }
            }
            libc::pthread_mutex_unlock(pair.lock.get());
        }
    }

    /// Wake the threads asleep on `word`'s pair: a pair is shared, so one thread asleep on it
    /// may be another word's, and every one is woken.
    pub(crate) fn wake_one(word: &AtomicU32) {
        wake_all(word);
    }

    /// Wake every thread asleep on `word`'s pair.
    pub(crate) fn wake_all(word: &AtomicU32) {
        let pair = Pair::of(word);
        // SAFETY: as in `wait`.
        unsafe {
            libc::pthread_mutex_lock(pair.lock.get());
            libc::pthread_cond_broadcast(pair.cond());
            libc::pthread_mutex_unlock(pair.lock.get());
        }
    }

    /// Wait on `cond` until notified or until the monotonic clock reads `deadline_ns`.
    ///
    /// # Safety
    /// The calling thread holds `lock`, and `cond` is on the monotonic clock.
    #[cfg(not(target_vendor = "apple"))]
    unsafe fn wait_until(
        cond: *mut libc::pthread_cond_t,
        lock: *mut libc::pthread_mutex_t,
        deadline_ns: u64,
    ) {
        libc::pthread_cond_timedwait(cond, lock, &super::timespec_of(deadline_ns));
    }

    /// Apple's systems time a wait by an interval, as they have no clock to set on a condition
    /// variable.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    #[cfg(target_vendor = "apple")]
    unsafe fn wait_until(
        cond: *mut libc::pthread_cond_t,
        lock: *mut libc::pthread_mutex_t,
        deadline_ns: u64,
    ) {
        let left = deadline_ns.saturating_sub(super::monotonic_ns());
        libc::pthread_cond_timedwait_relative_np(cond, lock, &super::timespec_of(left));
    }

    /// Make `cond` again, its timed waits on `CLOCK_MONOTONIC`, the clock `monotonic_ns` reads.
    #[cfg(not(target_vendor = "apple"))]
    unsafe fn on_the_monotonic_clock(cond: *mut libc::pthread_cond_t) {
        let mut attr: libc::pthread_condattr_t = core::mem::zeroed();
        libc::pthread_condattr_init(&mut attr);
        libc::pthread_condattr_setclock(&mut attr, libc::CLOCK_MONOTONIC);
        libc::pthread_cond_init(cond, &attr);
        libc::pthread_condattr_destroy(&mut attr);
    }

    /// Apple's systems keep the statically made condition variable: their timed wait takes an
    /// interval.
    #[cfg(target_vendor = "apple")]
    unsafe fn on_the_monotonic_clock(_cond: *mut libc::pthread_cond_t) {}

    #[cfg(test)]
    mod tests {
        extern crate std;

        use super::*;

        use std::sync::Arc;
        use std::time::{Duration, Instant};

        /// A word that no longer reads the value is not waited on, and a word another thread
        /// changes and wakes ends the wait; a word nothing changes is waited on until its
        /// deadline. Turned red by a wait that does not read the word under the pair's lock (the
        /// first wait sleeps to its deadline) or a wake that misses a thread asleep on the pair
        /// (the second wait runs to its five seconds).
        #[test]
        fn a_word_sleeps_on_its_pair_until_it_changes_and_is_woken() {
            let word = Arc::new(AtomicU32::new(1));
            let started = Instant::now();
            wait(&word, 0, Some(super::super::monotonic_ns() + 5_000_000_000));
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "a word that moved is not waited on"
            );

            word.store(0, Ordering::SeqCst);
            let waker = {
                let word = word.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    word.store(1, Ordering::SeqCst);
                    wake_one(&word);
                })
            };
            let deadline = super::super::monotonic_ns() + 5_000_000_000;
            let started = Instant::now();
            while word.load(Ordering::SeqCst) == 0 && super::super::monotonic_ns() < deadline {
                wait(&word, 0, Some(deadline));
            }
            waker.join().expect("the waker ran");
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "the wake ended the wait"
            );

            let still = AtomicU32::new(0);
            let deadline = super::super::monotonic_ns() + 30_000_000;
            while super::super::monotonic_ns() < deadline {
                wait(&still, 0, Some(deadline));
            }
            assert!(super::super::monotonic_ns() >= deadline);
        }
    }
}

/// `CLOCK_REALTIME`: the seconds and nanoseconds since the Unix epoch, `None` before it.
pub(crate) fn wall_clock() -> Option<(u64, u32)> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a live local the call writes; the clock always exists.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) } != 0 {
        return None;
    }
    let secs = u64::try_from(now.tv_sec).ok()?;
    let nanos = u32::try_from(now.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    Some((secs, nanos))
}

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
    // SAFETY: `arg` is what `spawn` handed `pthread_create`.
    unsafe { crate::enter(arg) };
    core::ptr::null_mut()
}

/// Start a thread that calls `crate::enter` with `arg`.
///
/// # Safety
/// `arg` is what `crate::enter` is to be called with, valid until it has run.
pub(crate) unsafe fn spawn(arg: *mut c_void) -> Option<(Thread, usize)> {
    let mut thread: libc::pthread_t = core::mem::zeroed();
    if libc::pthread_create(&mut thread, core::ptr::null(), entry, arg) != 0 {
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

pub(crate) fn sleep_ms(ms: u64) {
    sleep_us(ms.saturating_mul(1_000));
}

/// `nanosleep`, slept again for what is left when a signal cuts it short, as the standard
/// library's sleep does. Out of line: the millisecond sleep is this body too.
#[inline(never)]
pub(crate) fn sleep_us(us: u64) {
    let mut ask = timespec_of(us.saturating_mul(1_000));
    let mut left = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: both are live locals the call reads and writes.
    while unsafe { libc::nanosleep(&ask, &mut left) } != 0 {
        ask = left;
    }
}
