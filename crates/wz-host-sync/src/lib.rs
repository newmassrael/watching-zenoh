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
//! [`spawn_fn`] starts a thread of the system, its body moved into a record of a pool of
//! [`THREADS`] and not into memory of the heap, and [`current_thread`] names the calling thread by
//! the number [`Thread::id`] gives the thread a spawn started. [`Parker`] is what one thread waits on
//! until another wakes it, with or without a timeout on [`monotonic_ns`], the host's monotonic
//! clock; a timed wait is on that clock, so a date set on the host moves no deadline.

#![no_std]
#![cfg(any(unix, windows))]

// Nothing here allocates: a lock and a condition variable are a word of their owner's, and a
// thread's body lies in a record of a static pool.

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use core::time::Duration;

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
    park_until(blocked, None);
}

/// [`park_while`], and no later than when the monotonic clock ([`monotonic_ns`]) reads
/// `deadline_ns`, if one is given: whether `blocked` cleared (false: the deadline came first).
fn park_until(blocked: impl Fn() -> bool, deadline_ns: Option<u64>) -> bool {
    PARK_LOCK.lock();
    PARKED.fetch_add(1, Ordering::SeqCst);
    let mut cleared = true;
    while blocked() {
        match deadline_ns {
            // SAFETY: this thread holds `PARK_LOCK`, which the wait releases and takes back.
            None => unsafe { PARK_COND.wait(&PARK_LOCK) },
            Some(deadline) => {
                if monotonic_ns() >= deadline {
                    cleared = false;
                    break;
                }
                // SAFETY: as above.
                unsafe { PARK_COND.wait_until(&PARK_LOCK, deadline) };
            }
        }
    }
    PARKED.fetch_sub(1, Ordering::SeqCst);
    // SAFETY: this thread took it above.
    unsafe { PARK_LOCK.unlock() };
    cleared
}

/// Wake every parked thread, if one is.
fn unpark_all() {
    if PARKED.load(Ordering::SeqCst) != 0 {
        PARK_LOCK.lock();
        // SAFETY: this thread holds `PARK_LOCK`; it lets it go below.
        unsafe {
            PARK_COND.notify_all();
            PARK_LOCK.unlock();
        }
    }
}

/// The host's wall clock: the seconds and nanoseconds since the Unix epoch, `None` for a clock set
/// before it. `CLOCK_REALTIME` on a POSIX host, the precise system time on Windows. Set by the
/// host's administrator, so it may step; a deadline is on [`monotonic_ns`] instead.
pub fn wall_clock() -> Option<(u64, u32)> {
    sys::wall_clock()
}

/// The host's monotonic clock in nanoseconds: `CLOCK_MONOTONIC` on a POSIX host, the performance
/// counter on Windows. It never steps back, and a date set on the host moves it not at all.
pub fn monotonic_ns() -> u64 {
    sys::monotonic_ns()
}

/// What a thread waits on until another wakes it: one word, made in a `const` context. A wake
/// that comes before the wait is kept, so the wait that follows returns at once, as
/// `std::thread::park` keeps an `unpark`.
pub struct Parker {
    woken: AtomicBool,
}

impl Parker {
    /// A parker no wake has reached.
    pub const fn new() -> Self {
        Self {
            woken: AtomicBool::new(false),
        }
    }

    /// Wait until woken, and take the wake.
    pub fn park(&self) {
        park_while(|| !self.woken.swap(false, Ordering::SeqCst));
    }

    /// [`Self::park`] for at most `timeout_ns`: whether a wake came (false: the time ran out).
    pub fn park_timeout_ns(&self, timeout_ns: u64) -> bool {
        let deadline = monotonic_ns().saturating_add(timeout_ns);
        park_until(|| !self.woken.swap(false, Ordering::SeqCst), Some(deadline))
    }

    /// Wake the thread that waits, or the next wait.
    pub fn unpark(&self) {
        self.woken.store(true, Ordering::SeqCst);
        unpark_all();
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
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

    /// [`Self::wait`], and no later than when the monotonic clock ([`monotonic_ns`]) reads
    /// `deadline_ns`: whether a notification came (false: the deadline came first).
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    pub unsafe fn wait_until(&self, lock: &RawLock, deadline_ns: u64) -> bool {
        raw_wait_until(self, lock, deadline_ns)
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

/// [`RawCondvar::wait`], and no later than when the monotonic clock reads `deadline_ns`: whether
/// a notification came (false: the deadline came first).
///
/// # Safety
/// The calling thread holds `lock`.
unsafe fn raw_wait_until(cv: &RawCondvar, lock: &RawLock, deadline_ns: u64) -> bool {
    let seen = cv.epoch.load(Ordering::SeqCst);
    lock.unlock();
    let notified = park_until(
        || cv.epoch.load(Ordering::SeqCst) == seen,
        Some(deadline_ns),
    );
    lock.lock();
    notified
}

/// A value behind a [`RawLock`], reached through a guard: the shape of `std::sync::Mutex` with
/// no poisoning (nothing here unwinds), made in a `const` context.
pub struct Mutex<T> {
    raw: RawLock,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a guard, and the lock lets one thread hold a guard at
// a time.
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// `value`, behind a lock no thread holds.
    pub const fn new(value: T) -> Self {
        Self {
            raw: RawLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.raw.lock();
        MutexGuard { mutex: self }
    }

    /// The lock, when no thread holds it: `None` without waiting when one does.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self.raw.try_lock() {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// The value, through the only reference there is.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// The value, the lock gone.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// What [`Mutex::lock`] hands back; the lock is let go when it is dropped.
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock, so no other reference to the value is live.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`, and `&mut self` makes this the only one.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: this guard holds the lock it lets go.
        unsafe { self.mutex.raw.unlock() }
    }
}

/// A condition variable waited on with a [`Mutex`]'s guard: the shape of `std::sync::Condvar`.
pub struct Condvar {
    raw: RawCondvar,
}

impl Condvar {
    /// A condition variable no thread waits on.
    pub const fn new() -> Self {
        Self {
            raw: RawCondvar::new(),
        }
    }

    /// Let the guard's lock go, wait until notified, and take it again. A wake may come without
    /// a notification, so the caller waits in a loop on its own condition.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        // SAFETY: the guard holds its lock, which the wait lets go and takes again.
        unsafe { self.raw.wait(&guard.mutex.raw) };
        guard
    }

    /// Wait while `condition` holds of the value, for at most `timeout`: the guard, and whether
    /// the time ran out with the condition still holding.
    pub fn wait_timeout_while<'a, T>(
        &self,
        mut guard: MutexGuard<'a, T>,
        timeout: Duration,
        mut condition: impl FnMut(&mut T) -> bool,
    ) -> (MutexGuard<'a, T>, bool) {
        let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
        let deadline = monotonic_ns().saturating_add(timeout_ns);
        while condition(&mut guard) {
            if monotonic_ns() >= deadline {
                return (guard, true);
            }
            // SAFETY: as in `wait`.
            unsafe { raw_wait_until(&self.raw, &guard.mutex.raw, deadline) };
        }
        (guard, false)
    }

    /// Wake a waiting thread (every waiter, which their loops allow).
    pub fn notify_one(&self) {
        self.raw.notify_one();
    }

    /// Wake every waiting thread.
    pub fn notify_all(&self) {
        self.raw.notify_all();
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

/// A reading of the monotonic clock ([`monotonic_ns`]): the shape of `std::time::Instant`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl Instant {
    /// The clock now.
    pub fn now() -> Self {
        Self(monotonic_ns())
    }

    /// The time since this reading; zero for a reading not yet passed.
    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    /// The time from `earlier` to this reading; zero when `earlier` is later.
    pub fn duration_since(&self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// How many threads [`spawn_fn`] runs at once in the process: the records of its pool, each the
/// place of one thread's body until it runs it and of the word that says it has ended. The
/// engine's read task is one for each session that started it, and a reception supervisor's
/// polling task one for each that polls on a task; a spawn past them is refused as a system that
/// gives no thread is, which the C ABI answers with the code zenoh-pico's start of a task has for
/// it. A Zephyr image sizes the same pool by `CONFIG_WZ_OS_THREADS`
/// (`deploy/zephyr-common/Kconfig.wz`); a host's records are a few kilobytes of static memory
/// whatever it runs, so the bound is a host's and not a program's statement. The stack is the
/// system's, reserved by the thread's own creation as zenoh-pico's tasks' are
/// (`vendor/zenoh-pico/src/system/windows/system.c` @
/// `*task = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fun, arg, 0, NULL);`).
pub const THREADS: usize = 64;

/// The bytes a thread's body may take: a body is moved into its record whole, so one that does
/// not fit is refused when it is compiled ([`spawn_fn`]). A multiple of eight.
pub const BODY_BYTES: usize = 64;

/// [`ThreadRecord::holders`]: the [`Thread`] that names the thread has not been joined or dropped.
const HELD_BY_HANDLE: u8 = 1;
/// [`ThreadRecord::holders`]: the thread's body has not returned.
const HELD_BY_THREAD: u8 = 2;

/// The room of a thread's body: [`BODY_BYTES`] aligned as a `u64` is, which is at least a
/// pointer's alignment on every host.
type BodyRoom = MaybeUninit<[u64; BODY_BYTES / 8]>;

/// One thread's place in the pool: its body until the thread moves it out and runs it, and the
/// word that says the body has returned. The thread reaches it through the one pointer its
/// system's call hands it, so a thread takes no memory but its record and the stack the system
/// gives it.
struct ThreadRecord {
    /// Which ends still hold the record ([`HELD_BY_HANDLE`], [`HELD_BY_THREAD`]); a record no end
    /// holds is free. Each end lets go once, in either order, so a thread dropped unjoined gives
    /// its record back when it ends and a joined one when it is joined.
    holders: AtomicU8,
    /// Set once the body has returned.
    finished: AtomicBool,
    /// Moves the body out of [`Self::room`] and runs it; written with it, before the thread
    /// starts.
    run: UnsafeCell<Option<unsafe fn(*mut u8)>>,
    room: UnsafeCell<BodyRoom>,
}

// SAFETY: `run` and `room` are written by the one thread that took the record (`holders` from 0)
// before the thread it starts reads them, the system's start of a thread ordering the two; the
// rest are atomics.
unsafe impl Sync for ThreadRecord {}

impl ThreadRecord {
    /// A record no end holds.
    const fn new() -> Self {
        Self {
            holders: AtomicU8::new(0),
            finished: AtomicBool::new(false),
            run: UnsafeCell::new(None),
            room: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Let go of the record for `ends`. The release orders what the end did with the record
    /// before the next spawn that takes it.
    fn let_go(&self, ends: u8) {
        self.holders.fetch_and(!ends, Ordering::AcqRel);
    }
}

/// The process's pool of thread records.
static RECORDS: [ThreadRecord; THREADS] = [const { ThreadRecord::new() }; THREADS];

/// A record of `pool` no end holds, now held by both, its thread not yet finished; `None` when
/// every record is held.
fn take_record(pool: &'static [ThreadRecord]) -> Option<&'static ThreadRecord> {
    let record = pool.iter().find(|record| {
        record
            .holders
            .compare_exchange(
                0,
                HELD_BY_HANDLE | HELD_BY_THREAD,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    })?;
    record.finished.store(false, Ordering::Relaxed);
    Some(record)
}

/// What every system's thread entry calls with the pointer it was handed: run the body of the
/// record, say it has ended, and let go of the record for the thread.
///
/// # Safety
/// `arg` is the record [`start`] started this thread with.
unsafe fn enter(arg: *mut c_void) {
    let record = &*arg.cast_const().cast::<ThreadRecord>();
    if let Some(run) = *record.run.get() {
        run(record.room.get().cast::<u8>());
    }
    record.finished.store(true, Ordering::Release);
    record.let_go(HELD_BY_THREAD);
}

/// Moves the body of type `F` out of the room at `room` and runs it.
///
/// # Safety
/// `room` holds an `F` that nothing else reads or drops.
unsafe fn run_body<F: FnOnce()>(room: *mut u8) {
    let body = room.cast::<F>().read();
    body();
}

/// Start the thread of `record`, which holds its body and `run`: the thread, or `None` when the
/// system gave none, the body then still in the record.
///
/// # Safety
/// `record` was taken by [`take_record`] and its body and `run` written.
unsafe fn start(record: &'static ThreadRecord) -> Option<Thread> {
    let arg = core::ptr::from_ref(record).cast_mut().cast::<c_void>();
    sys::spawn(arg).map(|(handle, id)| Thread { handle, id, record })
}

/// A thread [`spawn_fn`] started, until it is joined. Dropped unjoined it is detached: it runs on,
/// and the system lets it go when it ends, and its record comes back to the pool then.
pub struct Thread {
    handle: sys::Thread,
    id: usize,
    record: &'static ThreadRecord,
}

// SAFETY: a thread of the system may be joined or detached from any other thread, and its record
// is reached through atomics alone.
unsafe impl Send for Thread {}
// SAFETY: as for `Send`; a shared reference reads the id and the record's word.
unsafe impl Sync for Thread {}

impl Thread {
    /// The thread's number, which [`current_thread`] answers on it.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Whether the thread's body has returned, without waiting for it.
    pub fn is_finished(&self) -> bool {
        self.record.finished.load(Ordering::Acquire)
    }

    /// Wait until the thread has ended.
    pub fn join(self) {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY: the handle is a started thread's, joined once: `this` is never dropped.
        unsafe { sys::join(this.handle) };
        this.record.let_go(HELD_BY_HANDLE);
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // SAFETY: the handle is a started thread's that nothing has joined (`join` consumes it).
        unsafe { sys::detach(self.handle) };
        self.record.let_go(HELD_BY_HANDLE);
    }
}

/// Run `body` on a thread of the system: the thread, or `None` when the pool has no free record
/// ([`THREADS`]) or the system gave no thread, `body` then dropped here. Nothing is allocated:
/// the body is moved into the record. A body larger than [`BODY_BYTES`] or aligned past a `u64`
/// is refused when it is compiled.
pub fn spawn_fn<F: FnOnce() + Send + 'static>(body: F) -> Option<Thread> {
    spawn_in(&RECORDS, body)
}

/// [`spawn_fn`] on the records of `pool`. The part that depends on the body's type is the move
/// into the room and the pointer to its run; taking a record and starting the thread are one
/// function for every body.
fn spawn_in<F: FnOnce() + Send + 'static>(
    pool: &'static [ThreadRecord],
    body: F,
) -> Option<Thread> {
    const {
        assert!(
            core::mem::size_of::<F>() <= BODY_BYTES
                && core::mem::align_of::<F>() <= core::mem::align_of::<BodyRoom>(),
            "a thread's body fits the room of its record"
        );
    }
    let record = take_record(pool)?;
    // SAFETY: the record was just taken, so nothing else reads or writes its room or its run; the
    // room holds an `F` (asserted above), which the thread moves out once, or which is moved out
    // here when no thread was started, before the record is let go.
    unsafe {
        record.room.get().cast::<F>().write(body);
        record.run.get().write(Some(run_body::<F>));
        let thread = start(record);
        if thread.is_none() {
            drop(record.room.get().cast::<F>().read());
            record.let_go(HELD_BY_HANDLE | HELD_BY_THREAD);
        }
        thread
    }
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

    /// A thread whose body waits a little, so a join that did not wait is seen, and writes down
    /// which thread it runs on.
    fn start_recording(seen: &Arc<AtomicUsize>) -> Thread {
        let seen = seen.clone();
        spawn_fn(move || {
            std::thread::sleep(Duration::from_millis(20));
            seen.store(current_thread(), Ordering::SeqCst);
        })
        .expect("a host gives a thread")
    }

    /// How many records of `pool` no end holds.
    fn free_records(pool: &[ThreadRecord]) -> usize {
        pool.iter()
            .filter(|record| record.holders.load(Ordering::SeqCst) == 0)
            .count()
    }

    /// A body that runs until `go` is set.
    fn held_until(go: &Arc<AtomicBool>) -> impl FnOnce() + Send + 'static {
        let go = go.clone();
        move || {
            while !go.load(Ordering::SeqCst) {
                sleep_ms(1);
            }
        }
    }

    /// A spawned thread runs its body, names itself by the number its spawn gave, which is not
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

    /// A timed wait waits at least its timeout when nothing wakes it, and its clock is the one
    /// `monotonic_ns` reads: a condition variable timed on another clock (the wall clock a
    /// statically made pthread one has) would read the deadline against the wrong epoch and end
    /// at once or wait for the skew.
    #[test]
    fn a_timed_park_waits_at_least_its_timeout() {
        let parker = Parker::new();
        let started = Instant::now();
        let from = monotonic_ns();
        assert!(!parker.park_timeout_ns(30_000_000), "nothing woke it");
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "{:?}",
            started.elapsed()
        );
        assert!(monotonic_ns() - from >= 30_000_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait ended near its deadline"
        );
    }

    /// A wake ends a wait, a wake that comes first is kept for the next wait, and it is taken by
    /// it: the wait after that waits again.
    #[test]
    fn a_wake_ends_a_wait_and_one_that_comes_first_is_kept() {
        let parker = Arc::new(Parker::new());
        let waker = {
            let parker = parker.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                parker.unpark();
            })
        };
        parker.park();
        waker.join().expect("the waker ran");
        parker.unpark();
        assert!(
            parker.park_timeout_ns(5_000_000_000),
            "the earlier wake was kept"
        );
        assert!(!parker.park_timeout_ns(10_000_000), "and taken");
    }

    #[test]
    fn the_monotonic_clock_moves_and_does_not_step_back() {
        let first = monotonic_ns();
        let mut last = first;
        for _ in 0..1000 {
            let now = monotonic_ns();
            assert!(now >= last);
            last = now;
        }
        sleep_ms(5);
        assert!(monotonic_ns() >= first + 4_000_000);
    }

    /// A wait that nothing ends waits its timeout and says so; a notification after the value
    /// changed ends one early, and the condition is read under the lock.
    #[test]
    fn a_timed_condvar_wait_waits_its_timeout_and_a_notification_ends_it() {
        let shared = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Instant::now();
        let (guard, timed_out) =
            shared
                .1
                .wait_timeout_while(shared.0.lock(), Duration::from_millis(30), |set| !*set);
        assert!(timed_out && !*guard);
        drop(guard);
        assert!(started.elapsed() >= Duration::from_millis(30));
        let setter = {
            let shared = shared.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                *shared.0.lock() = true;
                shared.1.notify_all();
            })
        };
        let (guard, timed_out) =
            shared
                .1
                .wait_timeout_while(shared.0.lock(), Duration::from_secs(5), |set| !*set);
        assert!(!timed_out && *guard, "the notification ended the wait");
        drop(guard);
        setter.join().expect("the setter ran");
    }

    /// The typed lock excludes and hands its value out, and the monotonic reading moves.
    #[test]
    fn the_typed_mutex_and_instant_answer_as_std_s_do() {
        let mut mutex = Mutex::new(3);
        *mutex.lock() += 1;
        assert!(mutex.try_lock().is_some());
        let held = mutex.lock();
        assert!(mutex.try_lock().is_none(), "held");
        drop(held);
        *mutex.get_mut() += 1;
        assert_eq!(mutex.into_inner(), 5);
        let from = super::Instant::now();
        sleep_ms(5);
        assert!(from.elapsed() >= Duration::from_millis(4));
        assert_eq!(from.duration_since(super::Instant::now()), Duration::ZERO);
    }

    #[test]
    fn a_closure_runs_on_a_thread_of_its_own() {
        let seen = Arc::new(AtomicUsize::new(0));
        let thread = {
            let seen = seen.clone();
            spawn_fn(move || seen.store(current_thread(), Ordering::SeqCst))
                .expect("a host gives a thread")
        };
        let id = thread.id();
        thread.join();
        assert_eq!(seen.load(Ordering::SeqCst), id);
        assert_ne!(id, current_thread());
    }

    /// A thread reads as running while its body runs and as finished once it has returned, before
    /// it is joined. Turned red by a word never set, or set before the body ran.
    #[test]
    fn a_thread_reads_as_finished_only_once_its_body_has_returned() {
        let go = Arc::new(AtomicBool::new(false));
        let thread = spawn_fn(held_until(&go)).expect("a host gives a thread");
        sleep_ms(20);
        assert!(!thread.is_finished(), "the body still runs");
        go.store(true, Ordering::SeqCst);
        let started = Instant::now();
        while !thread.is_finished() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the thread never read as finished"
            );
            sleep_ms(1);
        }
        thread.join();
    }

    /// A pool whose records are all held gives no thread and drops the body it was handed; a
    /// joined thread gives its record back at the join, a thread dropped unjoined when its body
    /// returns, and the records are taken again. CONTROL: both records are free before the first
    /// spawn.
    #[test]
    fn a_full_pool_refuses_a_thread_and_its_records_come_back() {
        static POOL: [ThreadRecord; 2] = [const { ThreadRecord::new() }; 2];
        assert_eq!(free_records(&POOL), 2, "CONTROL: no record is held");
        let go = Arc::new(AtomicBool::new(false));
        let joined = spawn_in(&POOL, held_until(&go)).expect("a free record");
        let detached = spawn_in(&POOL, held_until(&go)).expect("a free record");
        assert_eq!(free_records(&POOL), 0);
        let witness = Arc::new(());
        let refused = {
            let witness = witness.clone();
            spawn_in(&POOL, move || drop(witness))
        };
        assert!(
            refused.is_none(),
            "a pool with no free record gives no thread"
        );
        assert_eq!(
            Arc::strong_count(&witness),
            1,
            "the refused body was dropped"
        );
        drop(detached);
        go.store(true, Ordering::SeqCst);
        joined.join();
        let started = Instant::now();
        while free_records(&POOL) < 2 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the detached thread never gave its record back"
            );
            sleep_ms(1);
        }
        let seen = Arc::new(AtomicUsize::new(0));
        let again = {
            let seen = seen.clone();
            spawn_in(&POOL, move || {
                seen.store(current_thread(), Ordering::SeqCst)
            })
        }
        .expect("a record given back is taken again");
        let id = again.id();
        again.join();
        assert_eq!(seen.load(Ordering::SeqCst), id);
        assert_eq!(free_records(&POOL), 2);
    }

    /// A body as large as the room reaches its thread whole: every byte it was made with. Turned
    /// red by a room that keeps less than `BODY_BYTES` or a move that copies less.
    #[test]
    fn a_body_as_large_as_the_room_reaches_its_thread_whole() {
        const FILL: usize = BODY_BYTES - core::mem::size_of::<usize>();
        let mut bytes = [0u8; FILL];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        let seen = Arc::new(AtomicUsize::new(0));
        let thread = {
            let seen = seen.clone();
            spawn_fn(move || {
                let sum = bytes.iter().map(|byte| usize::from(*byte)).sum();
                seen.store(sum, Ordering::SeqCst);
            })
        }
        .expect("a host gives a thread");
        thread.join();
        assert_eq!(seen.load(Ordering::SeqCst), FILL * (FILL + 1) / 2);
    }

    /// The wall clock reads the date the standard library reads, within a second.
    #[test]
    fn the_wall_clock_is_the_date() {
        let (secs, nanos) = wall_clock().expect("the host's date is after 1970");
        let std_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        assert!(secs.abs_diff(std_secs) <= 1, "{secs} against {std_secs}");
        assert!(nanos < 1_000_000_000);
    }

    #[test]
    fn a_sleep_lasts_at_least_its_milliseconds() {
        let started = Instant::now();
        sleep_ms(30);
        assert!(started.elapsed() >= Duration::from_millis(30));
    }
}
