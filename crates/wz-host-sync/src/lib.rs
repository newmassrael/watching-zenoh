// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A host's lock, condition variable and threads over its own system calls, for a build without
//! `std`.
//!
//! [`RawLock`] and [`RawCondvar`] are one 32-bit word each, made in a `const` context and movable
//! while no thread holds or waits on them: what a `static` and a value that moves both need, and
//! what a pthread object, which must not move once it has been used, is not. A thread that has to
//! wait sleeps on the word itself, through the host's wait on an address (the futex of Linux and
//! Android, the address wait of Apple's systems and of Windows), so a release wakes a thread that
//! waits on that word and no other. Each word also says whether a thread waits on it, so a lock
//! nobody waits for costs one atomic operation to take and one to give back, and no call of the
//! system. A POSIX host with no wait on an address waits on one of a few pthread pairs that the
//! word's address picks.
//!
//! [`spawn_fn`] starts a thread of the system, its body moved into a record of a pool of
//! [`THREADS`] and not into memory of the heap, and [`current_thread`] names the calling thread by
//! the number [`Thread::id`] gives the thread a spawn started. [`Parker`] is what one thread waits on
//! until another wakes it, with or without a timeout on [`monotonic_ns`], the host's monotonic
//! clock; a timed wait is on that clock, so a date set on the host moves no deadline.
//!
//! [`Mutex`], [`Condvar`] and [`RwLock`] are the typed forms, in the shape of `std`'s, that every
//! crate of a C ABI's graph holds for a lock it makes while a session is open: making, taking,
//! waiting on and notifying one takes no memory on any host. They are the in-place ones
//! ([`in_place`]), or in a build with `std` (the `std` feature) `std`'s where `std`'s lie in
//! their own bytes as well. A lock whose holder panicked is handed out as it was left, and in a
//! build with `std` reads as poisoned ([`Mutex::is_poisoned`]).
//!
//! [`OnceLock`] is a process-wide value made by its first caller at run time, in the shape of
//! `std`'s, filled and read without memory of the heap.
//!
//! [`env_var`] reads the text the process's environment holds for a name, from the host's own copy
//! of it, so a setting stated there means the same to a library without `std` as to one with it.
//!
//! [`pages`] maps a block of the system's fresh pages, zero as handed and resident only once
//! written, for memory whose untouched bytes must read zero without being written.

#![no_std]
#![cfg(any(unix, windows))]

// Nothing here allocates: a lock and a condition variable are a word of their owner's, and a
// thread's body lies in a record of a static pool.

#[cfg(any(test, feature = "std"))]
extern crate std;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use core::time::Duration;

// Each host's wait and wake on a word are out of line (`#[inline(never)]` in its module): each is a
// call of the system, beside which a call of a function costs nothing, and a lock, a condition
// variable or a parker that inlined it would carry a copy of it at every take, release and wait.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(any(windows, test))]
mod counter;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

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

/// [`Parker`]'s word: no wake is kept and no thread waits.
const EMPTY: u32 = 0;
/// [`Parker`]'s word: a wake came and no wait has taken it yet.
const NOTIFIED: u32 = 1;
/// [`Parker`]'s word: its thread waits, so a wake must wake it.
const PARKED: u32 = u32::MAX;

/// What a thread waits on until another wakes it: one word, made in a `const` context. A wake
/// that comes before the wait is kept, so the wait that follows returns at once, as
/// `std::thread::park` keeps an `unpark`. One thread waits on a parker, the one it is for, as on
/// `std`'s; any thread wakes it.
pub struct Parker {
    state: AtomicU32,
}

impl Parker {
    /// A parker no wake has reached.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(EMPTY),
        }
    }

    /// Wait until woken, and take the wake.
    pub fn park(&self) {
        self.park_until(None);
    }

    /// [`Self::park`] for at most `timeout_ns`: whether a wake came (false: the time ran out).
    pub fn park_timeout_ns(&self, timeout_ns: u64) -> bool {
        self.park_until(Some(monotonic_ns().saturating_add(timeout_ns)))
    }

    /// Take a kept wake, or wait for one until the monotonic clock reads `deadline_ns`, if one is
    /// given: whether a wake was taken. The word goes from `NOTIFIED` to `EMPTY` (a kept wake) or
    /// from `EMPTY` to `PARKED` in one step, so a wake either finds the thread marked as waiting
    /// and wakes it, or is kept for it.
    fn park_until(&self, deadline_ns: Option<u64>) -> bool {
        if self.state.fetch_sub(1, Ordering::Acquire) == NOTIFIED {
            return true;
        }
        while self.state.load(Ordering::Relaxed) == PARKED
            && deadline_ns.is_none_or(|deadline| monotonic_ns() < deadline)
        {
            sys::wait(&self.state, PARKED, deadline_ns);
        }
        self.state.swap(EMPTY, Ordering::Acquire) == NOTIFIED
    }

    /// Wake the thread that waits, or the next wait.
    pub fn unpark(&self) {
        if self.state.swap(NOTIFIED, Ordering::Release) == PARKED {
            sys::wake_one(&self.state);
        }
    }
}

impl Default for Parker {
    fn default() -> Self {
        Self::new()
    }
}

/// [`RawLock`]'s word: no thread holds it.
const UNLOCKED: u32 = 0;
/// [`RawLock`]'s word: a thread holds it and none has waited for it since it was taken.
const LOCKED: u32 = 1;
/// [`RawLock`]'s word: a thread holds it and another may be waiting, so the release wakes one.
const CONTENDED: u32 = 2;
/// How many times a lock held with nobody waiting is read again before the thread sleeps: a step
/// under a lock ends sooner than a sleep and a wake, which are two calls of the system and a
/// switch of threads.
const SPINS: u32 = 100;

/// A lock of one word, not reentrant: a thread that holds it and takes it again waits for itself.
///
/// The three-state lock of Drepper's "Futexes Are Tricky": a thread that finds it held spins a
/// bounded while, as `std`'s futex lock does, then marks it contended and sleeps on the word, and only a release that finds the mark wakes a thread, one.
/// A thread woken takes the lock marked contended again, since it cannot know whether another
/// still waits: a wake too many is the price, never one too few.
pub struct RawLock {
    state: AtomicU32,
}

impl RawLock {
    /// A lock no thread holds.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
        }
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) {
        if !self.try_lock() {
            self.lock_contended();
        }
    }

    /// The lock was held when it was tried: spin a little while its holder has it and nobody
    /// waits, then mark it contended in the same step that takes it if it is free, and otherwise
    /// sleep until the word moves from the mark. Out of line, so a take inlines its exchange alone.
    #[cold]
    #[inline(never)]
    fn lock_contended(&self) {
        let mut state = self.spin();
        if state == UNLOCKED {
            match self.state.compare_exchange(
                UNLOCKED,
                LOCKED,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(now) => state = now,
            }
        }
        loop {
            if state != CONTENDED && self.state.swap(CONTENDED, Ordering::Acquire) == UNLOCKED {
                return;
            }
            sys::wait(&self.state, CONTENDED, None);
            state = self.spin();
        }
    }

    /// Read the word while a holder that nobody waits for has it, at most [`SPINS`] times: the
    /// word as last read. A lock marked contended is not spun on, as a thread already sleeps
    /// for it and the holder's release goes to that thread.
    fn spin(&self) -> u32 {
        let mut left = SPINS;
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state != LOCKED || left == 0 {
                return state;
            }
            core::hint::spin_loop();
            left -= 1;
        }
    }

    /// Take the lock if no thread holds it, without waiting: whether it was taken.
    pub fn try_lock(&self) -> bool {
        self.state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Let the lock go, and wake a thread that waits for it, if one may.
    ///
    /// # Safety
    /// The calling thread holds the lock.
    pub unsafe fn unlock(&self) {
        if self.state.swap(UNLOCKED, Ordering::Release) == CONTENDED {
            self.wake_waiter();
        }
    }

    /// Wake a thread that waits for the lock. Out of line, so a release inlines its exchange
    /// alone, as a take does.
    #[cold]
    #[inline(never)]
    fn wake_waiter(&self) {
        sys::wake_one(&self.state);
    }
}

impl Default for RawLock {
    fn default() -> Self {
        Self::new()
    }
}

/// [`RawCondvar`]'s word: the low bit says a thread waits; the rest counts notifications.
const WAITERS: u32 = 1;

/// A condition variable of one word, waited on with a [`RawLock`] held.
///
/// The word counts the notifications that found a thread waiting, and its low bit says whether
/// one waits. A waiter sets the bit with the lock held and sleeps while the word reads what it
/// left; a notification with the bit clear touches nothing, and one with the bit set moves the
/// count, clears the bit and wakes every waiter, each of which sets the bit again if it waits
/// again. A notifier changes the condition with the lock held before it notifies, so it reads a
/// bit a waiter set before that waiter let the lock go.
pub struct RawCondvar {
    epoch: AtomicU32,
}

impl RawCondvar {
    /// A condition variable no thread waits on.
    pub const fn new() -> Self {
        Self {
            epoch: AtomicU32::new(0),
        }
    }

    /// Mark a waiter: the word as the wait leaves it, which a notification moves.
    fn waiting(&self) -> u32 {
        self.epoch.fetch_or(WAITERS, Ordering::Relaxed) | WAITERS
    }

    /// Release `lock`, wait until a notification comes after this call began, and take `lock`
    /// again. A wake may come without a notification, so the caller waits in a loop on its own
    /// condition.
    ///
    /// Out of line: the wait sleeps, and a caller that inlined it would carry its release, its
    /// sleep and its take again.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    #[inline(never)]
    pub unsafe fn wait(&self, lock: &RawLock) {
        let seen = self.waiting();
        lock.unlock();
        sys::wait(&self.epoch, seen, None);
        lock.lock();
    }

    /// [`Self::wait`], and no later than when the monotonic clock ([`monotonic_ns`]) reads
    /// `deadline_ns`: whether a notification came (false: the deadline came first). Out of line,
    /// as [`Self::wait`] is.
    ///
    /// # Safety
    /// The calling thread holds `lock`.
    #[inline(never)]
    pub unsafe fn wait_until(&self, lock: &RawLock, deadline_ns: u64) -> bool {
        let seen = self.waiting();
        lock.unlock();
        let notified = loop {
            if self.epoch.load(Ordering::Relaxed) != seen {
                break true;
            }
            if monotonic_ns() >= deadline_ns {
                break false;
            }
            sys::wait(&self.epoch, seen, Some(deadline_ns));
        };
        lock.lock();
        notified
    }

    /// Wake a waiting thread. Every waiter is woken, which the waiters' loops allow: the word
    /// keeps no count of its waiters, only whether there are any.
    pub fn notify_one(&self) {
        self.notify_all();
    }

    /// Wake every waiting thread. Nothing is called when none waits.
    pub fn notify_all(&self) {
        let seen = self.epoch.load(Ordering::Relaxed);
        // A word that moved under the exchange was moved by another notification, which woke
        // every waiter marked in it.
        if seen & WAITERS != 0
            && self
                .epoch
                .compare_exchange(
                    seen,
                    seen.wrapping_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            sys::wake_all(&self.epoch);
        }
    }
}

impl Default for RawCondvar {
    fn default() -> Self {
        Self::new()
    }
}

// The typed forms: the in-place ones, or `std`'s where those lie in their own bytes too (Linux's,
// Android's and the BSDs' futex, Windows' slim lock and address wait). `std`'s are pthread objects
// elsewhere (macOS, QNX), which must not move once used, so `std` boxes each the first time it is
// taken: a lock made after a session opened would allocate on its first take. One name, one
// contract, whichever answers it.
#[cfg(all(
    feature = "std",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )
))]
mod std_lock;
#[cfg(not(all(
    feature = "std",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )
)))]
use in_place as chosen;
#[cfg(all(
    feature = "std",
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        windows
    )
))]
use std_lock as chosen;

pub mod in_place;
mod once;
pub mod pages;

pub use chosen::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use once::OnceLock;

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

/// The text the process's environment holds for `name`, handed to `read` while it reads it, or
/// `None` for a name the environment does not hold: the C library's `getenv` on a POSIX host, and
/// the system's copy of the environment block on Windows, whose names are matched without regard
/// to ASCII case as the system matches them. A program that changes its environment while another
/// thread reads it races here as it does in C, since no lock of the C library's is reachable.
pub fn env_var<R>(name: &core::ffi::CStr, read: impl FnOnce(Option<&[u8]>) -> R) -> R {
    sys::env_var(name, read)
}

/// Sleep the calling thread for at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    sys::sleep_ms(ms);
}

/// Sleep the calling thread for at least `us` microseconds, the finest a C program's sleep asks
/// for, so a library's sleeps of every unit are this one body. Windows sleeps whole milliseconds,
/// a part of one rounded up.
pub fn sleep_us(us: u64) {
    sys::sleep_us(us);
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::AtomicUsize;
    use std::boxed::Box;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::vec::Vec;

    /// The text the environment holds for a name is handed over whole, and a name it does not hold
    /// reads as none. Turned red by an `env_var` that answers none, or the text of another name.
    #[test]
    fn the_environment_s_text_is_read_by_its_name() {
        std::env::set_var("WZ_HOST_SYNC_ENV_READ_BACK", "512");
        assert_eq!(
            env_var(c"WZ_HOST_SYNC_ENV_READ_BACK", |value| value
                .map(<[u8]>::to_vec)),
            Some(b"512".to_vec())
        );
        assert!(!env_var(c"WZ_HOST_SYNC_ENV_NEVER_SET", |value| value.is_some()));
    }

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

    /// A lock taken and let go with no other thread about leaves its word unmarked, so its release
    /// wakes nobody; a thread that waits for a held lock marks it contended, and the release that
    /// finds the mark wakes it, and it takes the lock. Turned red by a waiter that sleeps without
    /// the mark (the word never reads contended) or a release that does not wake on it (the waiter
    /// never ends).
    #[test]
    fn a_waiter_marks_the_lock_contended_and_its_release_wakes_it() {
        let lock = Arc::new(RawLock::new());
        lock.lock();
        assert_eq!(
            lock.state.load(Ordering::SeqCst),
            LOCKED,
            "CONTROL: taken with no waiter"
        );
        // SAFETY: this thread holds it.
        unsafe { lock.unlock() };
        assert_eq!(lock.state.load(Ordering::SeqCst), UNLOCKED);

        lock.lock();
        let waiter = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                lock.lock();
                // SAFETY: this thread holds it.
                unsafe { lock.unlock() };
            })
        };
        let started = Instant::now();
        while lock.state.load(Ordering::SeqCst) != CONTENDED {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the waiter never marked the lock"
            );
            std::thread::yield_now();
        }
        // SAFETY: this thread holds it.
        unsafe { lock.unlock() };
        let started = Instant::now();
        while !waiter.is_finished() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the release never woke the waiter"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        waiter.join().expect("the waiter ran");
        assert_eq!(
            lock.state.load(Ordering::SeqCst),
            UNLOCKED,
            "nothing holds it"
        );
    }

    /// A spin ends at once on a lock that is free or marked contended, and on one held with
    /// nobody waiting after its bound, answering the word as it read it. Turned red by a spin
    /// with no bound (the held read never ends).
    #[test]
    fn a_spin_reads_a_plain_hold_a_bounded_while_and_nothing_else() {
        let lock = RawLock::new();
        assert_eq!(lock.spin(), UNLOCKED);
        assert!(lock.try_lock(), "CONTROL: a free lock is taken");
        assert_eq!(
            lock.spin(),
            LOCKED,
            "a hold nobody lets go ends at the bound"
        );
        lock.state.store(CONTENDED, Ordering::SeqCst);
        assert_eq!(lock.spin(), CONTENDED);
        // SAFETY: this thread holds it.
        unsafe { lock.unlock() };
        assert_eq!(lock.state.load(Ordering::SeqCst), UNLOCKED);
    }

    /// A notification with no thread waiting leaves the word as it was, and so calls nothing; a
    /// waiter marks the word, and the notification that finds the mark moves the count, clears
    /// the mark and ends the wait. Turned red by a notification that skips a marked word or a
    /// waiter that sleeps unmarked (the wait runs to its five seconds and reads as not notified).
    #[test]
    fn a_notification_moves_the_word_only_when_a_thread_waits() {
        let flag = Arc::new(Flag {
            lock: RawLock::new(),
            changed: RawCondvar::new(),
            set: UnsafeCell::new(false),
        });
        flag.changed.notify_one();
        flag.changed.notify_all();
        assert_eq!(
            flag.changed.epoch.load(Ordering::SeqCst),
            0,
            "no waiter, nothing moved"
        );
        let setter = {
            let flag = flag.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                while flag.changed.epoch.load(Ordering::SeqCst) & WAITERS == 0 {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "the waiter never marked the word"
                    );
                    std::thread::yield_now();
                }
                flag.lock.lock();
                // SAFETY: this thread holds the lock.
                unsafe {
                    *flag.set.get() = true;
                    flag.lock.unlock();
                }
                flag.changed.notify_one();
            })
        };
        let deadline = monotonic_ns() + 5_000_000_000;
        flag.lock.lock();
        let mut notified = true;
        // SAFETY: this thread holds the lock around every read and the wait.
        unsafe {
            while notified && !*flag.set.get() {
                notified = flag.changed.wait_until(&flag.lock, deadline);
            }
            flag.lock.unlock();
        }
        setter.join().expect("the setter ran");
        assert!(notified, "the notification ended the wait");
        assert_eq!(
            flag.changed.epoch.load(Ordering::SeqCst),
            2,
            "moved once, the mark cleared"
        );
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

    /// A sleep in microseconds lasts at least what it asks, below a millisecond and past one. Turned
    /// red by a sleep that reads its count in a coarser unit or drops the part below a second.
    #[cfg(unix)]
    #[test]
    fn a_sleep_in_microseconds_lasts_at_least_what_it_asks() {
        for us in [700u64, 1_300_000] {
            let started = Instant::now();
            sleep_us(us);
            assert!(
                started.elapsed() >= Duration::from_micros(us),
                "slept {us} us"
            );
        }
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
    /// A lock, a condition variable and a reader-writer lock made, each taken for the first time,
    /// tried, waited on with a timeout and notified: what a value made after a session opened does
    /// with its own.
    macro_rules! first_use {
        ($mutex:ident, $condvar:ident, $rwlock:ident) => {
            || {
                let mutex = $mutex::new(0_u32);
                let condvar = $condvar::new();
                *mutex.lock() += 1;
                drop(mutex.try_lock());
                let (guard, _) = condvar.wait_timeout_ms(mutex.lock(), 1);
                drop(guard);
                condvar.notify_one();
                condvar.notify_all();
                let rwlock = $rwlock::new(0_u32);
                *rwlock.write() += 1;
                let (first, second) = (rwlock.read(), rwlock.read());
                assert_eq!(*first + *second, 2);
            }
        };
    }

    /// Every allocation of the calling thread while `run` runs, counted.
    fn allocations(run: impl FnOnce()) -> usize {
        COUNTING.with(|count| count.set(Some(0)));
        run();
        COUNTING.with(|count| count.take()).unwrap_or(0)
    }

    std::thread_local! {
        static COUNTING: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
    }

    /// The test binary's allocator: the system's, counting on a thread that asked
    /// ([`allocations`]).
    struct Counting;

    // SAFETY: every call is the system allocator's; the count is a thread's own cell.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let _ = COUNTING.try_with(|count| {
                if let Some(seen) = count.get() {
                    count.set(Some(seen.saturating_add(1)));
                }
            });
            // SAFETY: the caller's.
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, at: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller's.
            unsafe { std::alloc::System.dealloc(at, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

    /// The crate's lock, condition variable and reader-writer lock take no memory when first
    /// taken, waited on or notified, whichever form the build chose for the host, and neither do
    /// the in-place ones.
    ///
    /// # Control
    ///
    /// A `std` build on macOS that chose `std`'s lock, which boxes a pthread mutex on its first
    /// take, counts an allocation; the box the control makes is counted.
    #[test]
    fn the_locks_take_no_memory_when_first_taken() {
        use crate::in_place::{
            Condvar as InPlaceCondvar, Mutex as InPlaceMutex, RwLock as InPlaceRwLock,
        };
        assert_eq!(
            allocations(first_use!(Mutex, Condvar, RwLock)),
            0,
            "the chosen locks live in their own bytes"
        );
        assert_eq!(
            allocations(first_use!(InPlaceMutex, InPlaceCondvar, InPlaceRwLock)),
            0,
            "the in-place locks live in their own bytes"
        );
        let control = allocations(|| drop(core::hint::black_box(Box::new(1_u64))));
        assert_eq!(control, 1, "the allocator counts");
    }

    /// A lock whose holder panicked reads as poisoned and still hands out the value as the holder
    /// left it, whichever form the build chose; one no holder panicked in does not.
    #[cfg(feature = "std")]
    #[test]
    fn a_lock_its_holder_panicked_in_reads_as_poisoned_and_is_handed_out() {
        let mutex = Arc::new(Mutex::new(1_u32));
        let holder = {
            let mutex = mutex.clone();
            std::thread::spawn(move || {
                let mut value = mutex.lock();
                *value = 2;
                panic!("the holder panics with the lock held");
            })
        };
        assert!(holder.join().is_err(), "the holder panicked");
        assert!(mutex.is_poisoned());
        assert_eq!(*mutex.lock(), 2, "the value as the holder left it");
        assert!(!Mutex::new(0_u32).is_poisoned());
    }
}
