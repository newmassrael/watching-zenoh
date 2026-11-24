// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock, the condition variable and the reader-writer lock in their own bytes: a word or two
//! of their owner's over [`RawLock`]'s parking place, so making, taking, waiting on and notifying
//! one takes no memory, and a value that is one may move while no thread holds it. A build without
//! `std` holds these, and so does a build with `std` on a host whose `std` lock is a pthread
//! object, which `std` boxes the first time it is taken (the crate root's names).
//!
//! A holder that panics lets the lock go when its guard drops. In a build with `std` the lock then
//! reads as poisoned ([`Mutex::is_poisoned`]) and is still handed out, as `std`'s is by a caller
//! that recovers it; without `std` a panic aborts and never lets a lock go.

use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::addr_of_mut;
#[cfg(feature = "std")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use crate::{monotonic_ns, park_while, unpark_all, RawCondvar, RawLock, SPINS};

/// A value behind a [`RawLock`], reached through a guard: the shape of `std::sync::Mutex`, whose
/// poisoning it keeps as a flag beside a value it still hands out.
pub struct Mutex<T> {
    raw: RawLock,
    #[cfg(feature = "std")]
    poisoned: AtomicBool,
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
            #[cfg(feature = "std")]
            poisoned: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// A new mutex written in `place` around the value `make` writes in the place it is handed
    /// and lends back: neither the value nor the mutex is a value of its own on a stack. A maker
    /// that lends back anything but the place it was handed has not written it there, and is
    /// refused with a panic. `place` is overwritten without dropping what it held.
    pub fn new_in(
        place: &mut MaybeUninit<Self>,
        make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
    ) -> &mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once through a
        // pointer to it: the value in its cell (`UnsafeCell<T>` and `MaybeUninit<T>` each have the
        // layout of `T`) by `make`, which lent the cell back and so wrote it, then the lock.
        unsafe {
            let cell = &mut *addr_of_mut!((*at).value).cast::<MaybeUninit<T>>();
            let field: *const T = cell.as_ptr();
            let made: *const T = make(cell);
            assert!(
                core::ptr::eq(made, field),
                "the value is written in the place it was handed"
            );
            addr_of_mut!((*at).raw).write(RawLock::new());
            #[cfg(feature = "std")]
            addr_of_mut!((*at).poisoned).write(AtomicBool::new(false));
            &mut *at
        }
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.raw.lock();
        MutexGuard::taken(self)
    }

    /// The lock, when no thread holds it: `None` without waiting when one does (this one
    /// included: the lock is not reentrant).
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self.raw.try_lock() {
            Some(MutexGuard::taken(self))
        } else {
            None
        }
    }

    /// Whether a holder panicked while it held the lock. Always false without `std`, where a
    /// panic aborts.
    pub fn is_poisoned(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.poisoned.load(Ordering::Relaxed)
        }
        #[cfg(not(feature = "std"))]
        {
            false
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

impl<T> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex").finish_non_exhaustive()
    }
}

/// What [`Mutex::lock`] hands back; the lock is let go when it is dropped. Shared between threads
/// only when the value is (`&mut T` is `Sync` exactly when `T` is), as `std`'s guard is.
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
    /// Whether the thread was already panicking when it took the lock: a guard dropped by the
    /// unwind of a panic that began after poisons the lock, as `std`'s does.
    #[cfg(feature = "std")]
    panicking: bool,
    _value: PhantomData<&'a mut T>,
}

impl<'a, T> MutexGuard<'a, T> {
    /// The guard of `mutex`, which the calling thread has just taken.
    fn taken(mutex: &'a Mutex<T>) -> Self {
        Self {
            mutex,
            #[cfg(feature = "std")]
            panicking: std::thread::panicking(),
            _value: PhantomData,
        }
    }
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
        #[cfg(feature = "std")]
        {
            if !self.panicking && std::thread::panicking() {
                self.mutex.poisoned.store(true, Ordering::Relaxed);
            }
        }
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
        // SAFETY: the guard holds its lock, which the wait lets go and takes again before it
        // returns, so the guard still holds it after.
        unsafe { self.raw.wait(&guard.mutex.raw) };
        guard
    }

    /// [`Self::wait`] for at most `ms` milliseconds of the host's monotonic clock: the guard, and
    /// whether the time ran out with no notification. A wake may come early, so the caller waits
    /// in a loop on its own condition and its own deadline.
    pub fn wait_timeout_ms<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        ms: u64,
    ) -> (MutexGuard<'a, T>, bool) {
        let deadline = monotonic_ns().saturating_add(ms.saturating_mul(1_000_000));
        // SAFETY: as in `wait`.
        let notified = unsafe { self.raw.wait_until(&guard.mutex.raw, deadline) };
        (guard, !notified)
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
            unsafe { self.raw.wait_until(&guard.mutex.raw, deadline) };
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

impl fmt::Debug for Condvar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Condvar").finish_non_exhaustive()
    }
}

/// [`RwLock`]'s word: a writer holds it.
const WRITER: usize = 1 << (usize::BITS - 1);
/// [`RwLock`]'s word: a writer waits for it, so a reader that comes now waits behind the writer.
const WRITER_WAITING: usize = 1 << (usize::BITS - 2);
/// [`RwLock`]'s word: how many readers hold it.
const READERS: usize = WRITER_WAITING - 1;

/// A value many threads read at once or one writes, behind one word: the shape of
/// `std::sync::RwLock`. A writer that waits holds off the readers that come after it, so a stream
/// of readers does not keep it waiting for good.
pub struct RwLock<T> {
    state: AtomicUsize,
    value: UnsafeCell<T>,
}

// SAFETY: readers share `&T` across threads (`T: Sync`) and a writer has the value alone, which
// may be another thread than the one that made it (`T: Send`); the word lets in readers or one
// writer, never both.
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// `value`, behind a lock no thread holds.
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Wait until no writer holds the lock or waits for it, and read.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let mut spins = 0;
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (WRITER | WRITER_WAITING) == 0 {
                if self
                    .state
                    .compare_exchange_weak(
                        state,
                        state.wrapping_add(1),
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return RwLockReadGuard { lock: self };
                }
            } else if spins < SPINS {
                spins += 1;
                core::hint::spin_loop();
            } else {
                park_while(|| self.state.load(Ordering::SeqCst) & (WRITER | WRITER_WAITING) != 0);
            }
        }
    }

    /// Wait until no thread holds the lock, and write.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let mut spins = 0;
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & !WRITER_WAITING == 0 {
                if self
                    .state
                    .compare_exchange_weak(state, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return RwLockWriteGuard { lock: self };
                }
            } else if spins < SPINS {
                spins += 1;
                core::hint::spin_loop();
            } else {
                self.state.fetch_or(WRITER_WAITING, Ordering::SeqCst);
                park_while(|| self.state.load(Ordering::SeqCst) & !WRITER_WAITING != 0);
            }
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

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RwLock").finish_non_exhaustive()
    }
}

/// What [`RwLock::read`] hands back; the read ends when it is dropped.
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard is one of the readers the word counts, so no writer has the value.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        // The last reader out wakes the writer that waits for none to be left.
        if self.lock.state.fetch_sub(1, Ordering::SeqCst) & READERS == 1 {
            unpark_all();
        }
    }
}

/// What [`RwLock::write`] hands back; the write ends when it is dropped.
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard is the writer the word names, so no other reference to the value is live.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`, and `&mut self` makes this the only one.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        // A writer that waits keeps its mark, so the readers that wait behind it still do.
        self.lock.state.fetch_and(!WRITER, Ordering::SeqCst);
        unpark_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Instant;

    /// A mutex made in its place holds the value its maker wrote there, and its lock is the lock a
    /// mutex made by value has.
    #[test]
    fn a_mutex_made_in_its_place_holds_what_its_maker_wrote() {
        let mut place = MaybeUninit::<Mutex<u32>>::uninit();
        let mutex = Mutex::new_in(&mut place, |value| value.write(7));
        let guard = mutex.lock();
        assert!(mutex.try_lock().is_none(), "a held mutex is not given");
        drop(guard);
        assert_eq!(mutex.try_lock().map(|value| *value), Some(7));
        assert!(!mutex.is_poisoned(), "made in place, not poisoned");
        // SAFETY: `new_in` wrote the whole mutex into `place`, and it is dropped once.
        unsafe { place.assume_init_drop() };
    }

    /// A maker that lends back a place other than the one it was handed is refused.
    #[test]
    #[should_panic(expected = "the value is written in the place it was handed")]
    fn a_maker_that_writes_elsewhere_is_refused() {
        let elsewhere: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(0));
        let mut place = MaybeUninit::<Mutex<u32>>::uninit();
        Mutex::new_in(&mut place, |_| elsewhere);
    }

    /// A waiter on the condition variable sees what its notifier wrote under the mutex, by
    /// `notify_one` and by `notify_all`, and a timed wait no notification ends runs out. Turned
    /// red by a wait that misses a notification (the test does not end) or a timed wait that reads
    /// the time running out as a notification.
    #[test]
    fn a_waiter_sees_what_its_notifier_wrote_and_a_timed_wait_runs_out() {
        let shared = Arc::new((Mutex::new(false), Condvar::new()));
        let (guard, timed_out) = shared.1.wait_timeout_ms(shared.0.lock(), 20);
        assert!(timed_out, "nothing notified");
        drop(guard);
        for all in [false, true] {
            *shared.0.lock() = false;
            let notifier = Arc::clone(&shared);
            let thread = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                *notifier.0.lock() = true;
                if all {
                    notifier.1.notify_all();
                } else {
                    notifier.1.notify_one();
                }
            });
            let mut ready = shared.0.lock();
            if all {
                let mut ran_out = false;
                while !*ready && !ran_out {
                    (ready, ran_out) = shared.1.wait_timeout_ms(ready, 5_000);
                }
                assert!(!ran_out, "the notification ended the wait");
            } else {
                while !*ready {
                    ready = shared.1.wait(ready);
                }
            }
            assert!(*ready, "the wait ends once the flag is set");
            drop(ready);
            thread.join().expect("the notifier");
        }
    }

    /// Two readers hold the lock at once; a writer waits for both to leave, and a reader that
    /// comes while it waits waits behind it, so it reads what the writer wrote; once every guard
    /// is gone the word is clear. Turned red by a lock that lets a writer in beside a reader (the
    /// first read changes), a waiting writer that sets no mark (the late reader reads 1 or never
    /// waits), or a release that loses a wake (the test does not end).
    #[test]
    fn readers_share_and_a_waiting_writer_comes_before_a_later_reader() {
        let lock = Arc::new(RwLock::new(1_u32));
        let first = lock.read();
        let second = lock.read();
        assert_eq!(*first + *second, 2, "two readers at once");
        let writer = {
            let lock = Arc::clone(&lock);
            std::thread::spawn(move || *lock.write() = 2)
        };
        let started = Instant::now();
        while lock.state.load(Ordering::SeqCst) & WRITER_WAITING == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the writer never waited"
            );
            std::thread::yield_now();
        }
        let late = {
            let lock = Arc::clone(&lock);
            std::thread::spawn(move || *lock.read())
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            !late.is_finished(),
            "a reader behind a waiting writer waits"
        );
        assert_eq!(*first, 1, "no write while readers hold the lock");
        drop(first);
        drop(second);
        writer.join().expect("the writer");
        assert_eq!(
            late.join().expect("the late reader"),
            2,
            "read after the write"
        );
        assert_eq!(*lock.read(), 2);
        assert_eq!(
            lock.state.load(Ordering::SeqCst),
            0,
            "nothing holds or waits"
        );
    }

    /// A writer excludes another writer: eight threads add a thousand each, the read and the write
    /// apart with a yield between, and no addition is lost.
    #[test]
    fn writers_exclude_each_other() {
        let lock = Arc::new(RwLock::new(0_u32));
        let threads: std::vec::Vec<_> = (0..8)
            .map(|_| {
                let lock = Arc::clone(&lock);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        let mut value = lock.write();
                        let seen = *value;
                        std::thread::yield_now();
                        *value = seen + 1;
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("a writer");
        }
        assert_eq!(*lock.read(), 8000);
    }

    /// A lock whose holder panicked reads as poisoned and still hands out the value as the holder
    /// left it; a lock taken by a thread that was already unwinding is not poisoned by it.
    #[cfg(feature = "std")]
    #[test]
    fn a_holder_that_panics_poisons_the_in_place_lock() {
        let mutex = Arc::new(Mutex::new(1_u32));
        let holder = {
            let mutex = Arc::clone(&mutex);
            std::thread::spawn(move || {
                let mut value = mutex.lock();
                *value = 2;
                panic!("the holder panics with the lock held");
            })
        };
        assert!(holder.join().is_err(), "the holder panicked");
        assert!(mutex.is_poisoned());
        assert_eq!(*mutex.lock(), 2, "the value as the holder left it");

        /// Takes and lets go of the lock while the thread unwinds.
        struct TakesOnUnwind(Arc<Mutex<u32>>);
        impl Drop for TakesOnUnwind {
            fn drop(&mut self) {
                *self.0.lock() += 1;
            }
        }
        let calm = Arc::new(Mutex::new(0_u32));
        let unwinding = {
            let calm = Arc::clone(&calm);
            std::thread::spawn(move || {
                let _takes = TakesOnUnwind(calm);
                panic!("the thread unwinds before it takes the lock");
            })
        };
        assert!(unwinding.join().is_err(), "the thread panicked");
        assert_eq!(*calm.lock(), 1, "the lock was taken during the unwind");
        assert!(
            !calm.is_poisoned(),
            "a guard taken while unwinding poisons nothing"
        );
    }
}
