// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A host's lock, condition variable and threads over its own system calls, for a build without
//! `std`.
//!
//! [`RawLock`] and [`RawCondvar`] are one word each, made in a `const` context and movable while no
//! thread holds or waits on them: what a `static` and a value that moves both need, and what a
//! pthread object, which must not move once it has been used, is not. A thread that has to wait for
//! either parks on one place of the process: the system's own mutex and condition variable, which
//! live in `static`s and never move. A release wakes the parked threads only when there are any,
//! so a lock nobody waits for costs one atomic operation to take and one to give back.
//!
//! The parking place is the whole process's, so a release wakes every parked thread and each checks
//! its own condition again. That is the price of a lock with no system object of its own; a wake
//! that finds its lock still held parks again.
//!
//! [`spawn`] starts a thread of the system, and [`current_thread`] names the calling thread by the
//! number [`Thread::id`] gives the thread a spawn started.

#![no_std]
#![cfg(any(unix, windows))]

#[cfg(test)]
extern crate std;

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

/// How many times a lock that is held is tried again before the thread parks: a lock is held for
/// a short step far more often than for a wait, and a step ends sooner than a park and a wake.
const SPINS: u32 = 64;

/// The one place a thread of the process waits for a lock or a condition variable of this crate.
static PARK_LOCK: sys::ParkLock = sys::ParkLock::new();
static PARK_COND: sys::ParkCond = sys::ParkCond::new();
/// How many threads are parked, so that a release with none to wake takes no system lock.
static PARKED: AtomicUsize = AtomicUsize::new(0);

/// Wait on the process's parking place for as long as `blocked` answers true.
///
/// A waker writes what `blocked` reads and then reads `PARKED`; this thread counts itself in
/// `PARKED` and then reads what `blocked` reads, each with `SeqCst`. So either the waker sees
/// this thread counted and wakes it (under `PARK_LOCK`, which this thread holds until its wait has
/// begun), or this thread sees the write and does not wait: no wake is lost.
fn park_while(blocked: impl Fn() -> bool) {
    PARK_LOCK.lock();
    PARKED.fetch_add(1, Ordering::SeqCst);
    while blocked() {
        // SAFETY: this thread holds `PARK_LOCK`, which the wait releases and takes back.
        unsafe { PARK_COND.wait(&PARK_LOCK) };
    }
    PARKED.fetch_sub(1, Ordering::SeqCst);
    // SAFETY: this thread took it above.
    unsafe { PARK_LOCK.unlock() };
}

/// Wake every parked thread, if one is.
fn unpark_all() {
    if PARKED.load(Ordering::SeqCst) != 0 {
        PARK_LOCK.lock();
        PARK_COND.notify_all();
        // SAFETY: this thread took it above.
        unsafe { PARK_LOCK.unlock() };
    }
}

/// A lock of one word, not reentrant: a thread that holds it and takes it again waits for itself.
pub struct RawLock {
    held: AtomicBool,
}

impl RawLock {
    /// A lock no thread holds.
    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
        }
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) {
        let mut spins = 0;
        while !self.try_lock() {
            if spins < SPINS {
                spins += 1;
                core::hint::spin_loop();
            } else {
                park_while(|| self.held.load(Ordering::SeqCst));
            }
        }
    }

    /// Take the lock if no thread holds it, without waiting: whether it was taken.
    pub fn try_lock(&self) -> bool {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Let the lock go, and wake the threads that wait for it.
    ///
    /// # Safety
    /// The calling thread holds the lock.
    pub unsafe fn unlock(&self) {
        self.held.store(false, Ordering::SeqCst);
        unpark_all();
    }
}

impl Default for RawLock {
    fn default() -> Self {
        Self::new()
    }
}

/// A condition variable of one word, waited on with a [`RawLock`] held.
pub struct RawCondvar {
    /// How many notifications there have been: a waiter waits until it moves.
    epoch: AtomicUsize,
}

impl RawCondvar {
    /// A condition variable no thread waits on.
    pub const fn new() -> Self {
        Self {
            epoch: AtomicUsize::new(0),
        }
    }

    /// Release `lock`, wait until a notification comes after this call began, and take `lock`
    /// again. A wake may come without a notification, so the caller waits in a loop on its own
    /// condition.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    pub unsafe fn wait(&self, lock: &RawLock) {
        let seen = self.epoch.load(Ordering::SeqCst);
        lock.unlock();
        park_while(|| self.epoch.load(Ordering::SeqCst) == seen);
        lock.lock();
    }

    /// Wake a waiting thread. Every waiter is woken, which the waiters' loops allow.
    pub fn notify_one(&self) {
        self.notify_all();
    }

    /// Wake every waiting thread.
    pub fn notify_all(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        unpark_all();
    }
}

impl Default for RawCondvar {
    fn default() -> Self {
        Self::new()
    }
}

/// What a thread [`spawn`] starts runs: the first field of the starter's own record, which the new
/// thread is handed, so the record is reached from it.
#[repr(C)]
pub struct ThreadStart {
    /// Called once, on the new thread, with the record's address; it owns the record from then on.
    pub run: unsafe fn(*mut ThreadStart),
}

/// Run what a spawn was handed: the one call every system's thread entry makes.
///
/// # Safety
/// `arg` is the record [`spawn`] was handed.
unsafe fn enter(arg: *mut c_void) {
    let start = arg.cast::<ThreadStart>();
    ((*start).run)(start);
}

/// A thread [`spawn`] started, until it is joined. Dropped unjoined it is detached: it runs on, and
/// the system lets it go when it ends.
pub struct Thread {
    handle: sys::Thread,
    id: usize,
}

// SAFETY: a thread of the system may be joined or detached from any other thread.
unsafe impl Send for Thread {}
// SAFETY: as for `Send`; a shared reference only reads the id.
unsafe impl Sync for Thread {}

impl Thread {
    /// The thread's number, which [`current_thread`] answers on it.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Wait until the thread has ended.
    pub fn join(self) {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY: the handle is a started thread's, joined once: `this` is never dropped.
        unsafe { sys::join(this.handle) }
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: the handle is a started thread's that nothing has joined (`join` consumes it).
        unsafe { sys::detach(self.handle) }
    }
}

/// Start a thread of the system that calls `run` of the record `start` points at with its
/// address. `None` when the system gives no thread: the record is then still the caller's.
///
/// # Safety
/// `start` points at a [`ThreadStart`] that stays valid until its `run` takes it, and `run` may be
/// called on the new thread before this returns.
pub unsafe fn spawn(start: *mut ThreadStart) -> Option<Thread> {
    sys::spawn(start).map(|(handle, id)| Thread { handle, id })
}

/// The calling thread's number, by which [`Thread::id`] names a thread a spawn started; never 0.
pub fn current_thread() -> usize {
    sys::current_thread()
}

/// Sleep the calling thread for at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    sys::sleep_ms(ms);
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::cell::UnsafeCell;
    use std::boxed::Box;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::vec::Vec;

    /// A counter behind a lock, shared by threads.
    struct Counted {
        lock: RawLock,
        count: UnsafeCell<u32>,
    }

    // SAFETY: `count` is read and written only with `lock` held.
    unsafe impl Sync for Counted {}

    /// A flag a thread sets and another waits for.
    struct Flag {
        lock: RawLock,
        changed: RawCondvar,
        set: UnsafeCell<bool>,
    }

    // SAFETY: `set` is read and written only with `lock` held.
    unsafe impl Sync for Flag {}

    /// Eight threads add a thousand each to one counter read and written apart under the lock,
    /// with a yield between the read and the write: no addition is lost, so the lock excluded.
    #[test]
    fn a_lock_excludes_across_threads() {
        let shared = Arc::new(Counted {
            lock: RawLock::new(),
            count: UnsafeCell::new(0),
        });
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        shared.lock.lock();
                        // SAFETY: this thread holds the lock.
                        unsafe {
                            let now = *shared.count.get();
                            std::thread::yield_now();
                            *shared.count.get() = now + 1;
                            shared.lock.unlock();
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("the thread ran");
        }
        shared.lock.lock();
        // SAFETY: this thread holds the lock.
        let total = unsafe { *shared.count.get() };
        // SAFETY: as above.
        unsafe { shared.lock.unlock() };
        assert_eq!(total, 8000);
    }

    /// A held lock is not taken by a try; once let go it is, and a lock moved after use still
    /// locks, which a pthread mutex would not promise.
    #[test]
    fn a_held_lock_refuses_a_try_and_a_moved_lock_still_locks() {
        let lock = RawLock::new();
        assert!(lock.try_lock(), "CONTROL: a free lock is taken");
        assert!(!lock.try_lock(), "a held lock is not");
        // SAFETY: this thread holds it.
        unsafe { lock.unlock() };
        let moved = Box::new(lock);
        assert!(moved.try_lock(), "taken again after it moved");
        // SAFETY: this thread holds it.
        unsafe { moved.unlock() };
    }

    /// A thread that waits on the condition variable wakes when the other thread has set the flag
    /// under the lock and notified, and sees the flag set.
    #[test]
    fn a_waiter_wakes_on_the_notification_and_sees_the_write() {
        let flag = Arc::new(Flag {
            lock: RawLock::new(),
            changed: RawCondvar::new(),
            set: UnsafeCell::new(false),
        });
        let setter = {
            let flag = flag.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                flag.lock.lock();
                // SAFETY: this thread holds the lock.
                unsafe {
                    *flag.set.get() = true;
                    flag.lock.unlock();
                }
                flag.changed.notify_one();
            })
        };
        flag.lock.lock();
        // SAFETY: this thread holds the lock around every read and the wait.
        unsafe {
            while !*flag.set.get() {
                flag.changed.wait(&flag.lock);
            }
            flag.lock.unlock();
        }
        setter.join().expect("the setter ran");
    }

    /// The record a test thread is started with.
    #[repr(C)]
    struct Record {
        head: ThreadStart,
        seen: Arc<AtomicUsize>,
    }

    /// The test thread's body: it waits a little, so a join that did not wait is seen, and writes
    /// down which thread it runs on.
    unsafe fn record_where_it_runs(head: *mut ThreadStart) {
        let record = Box::from_raw(head.cast::<Record>());
        std::thread::sleep(Duration::from_millis(20));
        record.seen.store(current_thread(), Ordering::SeqCst);
    }

    fn start_recording(seen: &Arc<AtomicUsize>) -> Thread {
        let record = Box::into_raw(Box::new(Record {
            head: ThreadStart {
                run: record_where_it_runs,
            },
            seen: seen.clone(),
        }));
        // SAFETY: the record is leaked to the thread, which takes it back in its body.
        unsafe { spawn(record.cast::<ThreadStart>()) }.expect("a host gives a thread")
    }

    /// A spawned thread runs its record, names itself by the number its spawn gave, which is not
    /// the caller's and not 0, and a join returns after it has run.
    #[test]
    fn a_spawned_thread_runs_under_its_own_number_and_join_waits() {
        let seen = Arc::new(AtomicUsize::new(0));
        let thread = start_recording(&seen);
        let id = thread.id();
        thread.join();
        assert_eq!(
            seen.load(Ordering::SeqCst),
            id,
            "the thread is the one its spawn named"
        );
        assert_ne!(id, current_thread(), "the thread is not the caller");
        assert_ne!(id, 0);
        assert_ne!(current_thread(), 0);
    }

    /// A thread dropped unjoined runs on to its end.
    #[test]
    fn a_thread_dropped_unjoined_runs_on() {
        let seen = Arc::new(AtomicUsize::new(0));
        drop(start_recording(&seen));
        let started = Instant::now();
        while seen.load(Ordering::SeqCst) == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the detached thread never ran"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_sleep_lasts_at_least_its_milliseconds() {
        let started = Instant::now();
        sleep_ms(30);
        assert!(started.elapsed() >= Duration::from_millis(30));
    }
}
