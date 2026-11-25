// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock, the condition variable and the reader-writer lock of a host whose `std` ones lie in
//! their own bytes: `std`'s, each a word the system waits on by its address (a futex, Windows'
//! slim lock and address wait), so making and taking one takes no memory, as the in-place ones
//! take none. The shape is the in-place ones' ([`crate::in_place`]): a lock whose holder panicked
//! is handed out as it was left and reads as poisoned.

use core::fmt;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::time::Duration;
use std::sync::{PoisonError, TryLockError};

/// A value behind `std`'s lock, handed out whether or not a holder panicked. The lock holds the
/// value's place and not the value, so a mutex can be written where it stays before its value is
/// ([`Self::init_at`]); from then until it drops the place holds a written `T`.
pub struct Mutex<T>(std::sync::Mutex<MaybeUninit<T>>);

/// What [`Mutex::lock`] hands back; the lock is let go when it is dropped.
pub struct MutexGuard<'a, T>(std::sync::MutexGuard<'a, MaybeUninit<T>>);

impl<T> Mutex<T> {
    /// `value`, behind a lock no thread holds.
    pub const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(MaybeUninit::new(value)))
    }

    /// A mutex made in `place` around the value `make` writes in the place it is handed and
    /// lends back, which is the lock's own cell: neither the value nor the mutex is a value of its
    /// own on a stack, as the in-place one's and a kernel's are not. A maker that lends back
    /// anything but the place it was handed has not written it there, and is refused with a panic.
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self` and aligned for it, and what it held is
    /// overwritten without being dropped. A maker that panics leaves `place` as unwritten, so it
    /// is not dropped as a mutex.
    pub unsafe fn init_at(place: NonNull<Self>, make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T) {
        let at = place.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (the caller's contract). The lock written
        // first holds a place no byte of which is written, so writing it moves no value; the
        // cell it lends back is that place inside the lock, which `make` writes and lends back.
        unsafe {
            at.write(Self(std::sync::Mutex::new(MaybeUninit::uninit())));
            let cell = (*at).0.get_mut().unwrap_or_else(PoisonError::into_inner);
            let field: *const T = cell.as_ptr();
            let made: *const T = make(cell);
            assert!(
                core::ptr::eq(made, field),
                "the value is written in the place it was handed"
            );
        }
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        MutexGuard(self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The lock, when no thread holds it: `None` without waiting when one does.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.0.try_lock() {
            Ok(guard) => Some(MutexGuard(guard)),
            Err(TryLockError::Poisoned(poisoned)) => Some(MutexGuard(poisoned.into_inner())),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Whether a holder panicked while it held the lock.
    pub fn is_poisoned(&self) -> bool {
        self.0.is_poisoned()
    }

    /// The value, through the only reference there is.
    pub fn get_mut(&mut self) -> &mut T {
        let cell = self.0.get_mut().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the value is written before the mutex can be reached (`new`, `init_at`) and
        // stays written until it drops.
        unsafe { cell.assume_init_mut() }
    }

    /// The value, the lock gone.
    pub fn into_inner(self) -> T {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so its lock is read out of it once, and the value the
        // lock holds is written (as for `get_mut`) and moved out here, not dropped.
        unsafe {
            core::ptr::read(&this.0)
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .assume_init()
        }
    }
}

impl<T> Drop for Mutex<T> {
    fn drop(&mut self) {
        let cell = self.0.get_mut().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the value is written (as for `get_mut`), and dropped once, here.
        unsafe { cell.assume_init_drop() }
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

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the mutex's value is written while it can be reached (as for `Mutex::get_mut`).
        unsafe { self.0.assume_init_ref() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`.
        unsafe { self.0.assume_init_mut() }
    }
}

/// `std`'s condition variable, waited on with a [`Mutex`]'s guard.
pub struct Condvar(std::sync::Condvar);

impl Condvar {
    /// A condition variable no thread waits on.
    pub const fn new() -> Self {
        Self(std::sync::Condvar::new())
    }

    /// Let the guard's lock go, wait until notified, and take it again. A wake may come without
    /// a notification, so the caller waits in a loop on its own condition.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        MutexGuard(self.0.wait(guard.0).unwrap_or_else(PoisonError::into_inner))
    }

    /// [`Self::wait`] for at most `ms` milliseconds: the guard, and whether the time ran out with
    /// no notification. A wake may come early, so the caller waits in a loop on its own condition
    /// and its own deadline.
    pub fn wait_timeout_ms<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        ms: u64,
    ) -> (MutexGuard<'a, T>, bool) {
        let (guard, waited) = self
            .0
            .wait_timeout(guard.0, Duration::from_millis(ms))
            .unwrap_or_else(PoisonError::into_inner);
        (MutexGuard(guard), waited.timed_out())
    }

    /// Wait while `condition` holds of the value, for at most `timeout`: the guard, and whether
    /// the time ran out with the condition still holding.
    pub fn wait_timeout_while<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
        mut condition: impl FnMut(&mut T) -> bool,
    ) -> (MutexGuard<'a, T>, bool) {
        let (guard, waited) = self
            .0
            .wait_timeout_while(guard.0, timeout, |cell| {
                // SAFETY: the value is written while the mutex can be reached (as for
                // `Mutex::get_mut`), and the wait hands it with the lock held.
                condition(unsafe { cell.assume_init_mut() })
            })
            .unwrap_or_else(PoisonError::into_inner);
        (MutexGuard(guard), waited.timed_out())
    }

    /// Wake one waiting thread, if one waits.
    pub fn notify_one(&self) {
        self.0.notify_one();
    }

    /// Wake every waiting thread.
    pub fn notify_all(&self) {
        self.0.notify_all();
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

/// A value behind `std`'s reader-writer lock, handed out whether or not a writer panicked.
pub struct RwLock<T>(std::sync::RwLock<T>);

/// What [`RwLock::read`] hands back; the read ends when it is dropped.
pub type RwLockReadGuard<'a, T> = std::sync::RwLockReadGuard<'a, T>;

/// What [`RwLock::write`] hands back; the write ends when it is dropped.
pub type RwLockWriteGuard<'a, T> = std::sync::RwLockWriteGuard<'a, T>;

impl<T> RwLock<T> {
    /// `value`, behind a lock no thread holds.
    pub const fn new(value: T) -> Self {
        Self(std::sync::RwLock::new(value))
    }

    /// Wait until no writer holds the lock, and read.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait until no thread holds the lock, and write.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// The value, through the only reference there is.
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut().unwrap_or_else(PoisonError::into_inner)
    }

    /// The value, the lock gone.
    pub fn into_inner(self) -> T {
        self.0.into_inner().unwrap_or_else(PoisonError::into_inner)
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

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A mutex made in its place has its value written inside the place by its maker, not in a
    /// frame and moved in: the address the maker is handed lies within the mutex's own bytes, and
    /// the lock then hands out what was written there.
    #[test]
    fn init_at_writes_the_value_inside_the_locks_place() {
        let mut place = MaybeUninit::<Mutex<[u64; 4]>>::uninit();
        let start = place.as_ptr() as usize;
        let end = start + core::mem::size_of::<Mutex<[u64; 4]>>();
        let mut written = 0_usize;
        // SAFETY: the place is this frame's, unmoved until it is dropped below.
        unsafe {
            Mutex::<[u64; 4]>::init_at(NonNull::from(&mut place).cast(), |value| {
                written = value.as_ptr() as usize;
                value.write([1, 2, 3, 4])
            });
        }
        assert!(
            written >= start && written + core::mem::size_of::<[u64; 4]>() <= end,
            "the value is written in the lock's place"
        );
        // SAFETY: made above.
        let mutex = unsafe { place.assume_init_ref() };
        let guard = mutex.lock();
        assert!(mutex.try_lock().is_none(), "a held mutex is not given");
        assert_eq!(*guard, [1, 2, 3, 4]);
        drop(guard);
        assert!(!mutex.is_poisoned(), "made in place, not poisoned");
        // SAFETY: made above, dropped once, in its place.
        unsafe { place.assume_init_drop() };
    }

    /// A maker that lends back a place other than the one it was handed is refused.
    #[test]
    #[should_panic(expected = "the value is written in the place it was handed")]
    fn a_maker_that_writes_elsewhere_is_refused() {
        let elsewhere: &'static mut u32 = std::boxed::Box::leak(std::boxed::Box::new(0));
        let mut place = MaybeUninit::<Mutex<u32>>::uninit();
        // SAFETY: the place is this frame's; the panic leaves it unwritten and undropped.
        unsafe { Mutex::<u32>::init_at(NonNull::from(&mut place).cast(), |_| elsewhere) };
    }

    /// Counts its drops.
    struct Dropped(Arc<AtomicUsize>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A mutex drops its value once when it drops, whether made by value or in place, and hands
    /// it out whole without dropping it when taken apart.
    #[test]
    fn the_value_is_dropped_once_with_its_mutex_and_not_when_taken_out() {
        let drops = Arc::new(AtomicUsize::new(0));
        drop(Mutex::new(Dropped(Arc::clone(&drops))));
        assert_eq!(drops.load(Ordering::SeqCst), 1, "dropped with its mutex");

        let mut place = MaybeUninit::<Mutex<Dropped>>::uninit();
        // SAFETY: the place is this frame's, unmoved until it is dropped below.
        unsafe {
            Mutex::<Dropped>::init_at(NonNull::from(&mut place).cast(), |value| {
                value.write(Dropped(Arc::clone(&drops)))
            });
            place.assume_init_drop();
        }
        assert_eq!(
            drops.load(Ordering::SeqCst),
            2,
            "made in place, dropped once"
        );

        let inner = Mutex::new(Dropped(Arc::clone(&drops))).into_inner();
        assert_eq!(drops.load(Ordering::SeqCst), 2, "taken out, not dropped");
        drop(inner);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    /// A timed wait on a condition that holds runs out with the value as it was, and one whose
    /// condition a notifier clears ends with the value the notifier wrote.
    #[test]
    fn a_wait_while_reads_the_value_the_lock_holds() {
        let shared = Arc::new((Mutex::new(0_u32), Condvar::new()));
        let (guard, ran_out) =
            shared
                .1
                .wait_timeout_while(shared.0.lock(), Duration::from_millis(10), |value| {
                    *value == 0
                });
        assert!(ran_out, "nothing changed the value");
        assert_eq!(*guard, 0);
        drop(guard);
        let notifier = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            *notifier.0.lock() = 5;
            notifier.1.notify_all();
        });
        let (guard, ran_out) =
            shared
                .1
                .wait_timeout_while(shared.0.lock(), Duration::from_secs(5), |value| *value == 0);
        assert!(!ran_out, "the notification ended the wait");
        assert_eq!(*guard, 5);
        drop(guard);
        thread.join().expect("the notifier");
    }
}
