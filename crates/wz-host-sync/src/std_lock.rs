// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock, the condition variable and the reader-writer lock of a host whose `std` ones lie in
//! their own bytes: `std`'s, each a word the system waits on by its address (a futex, Windows'
//! slim lock and address wait), so making and taking one takes no memory, as the in-place ones
//! take none. The shape is the in-place ones' ([`crate::in_place`]): a lock whose holder panicked
//! is handed out as it was left and reads as poisoned.

use core::fmt;
use core::mem::MaybeUninit;
use core::time::Duration;
use std::sync::{PoisonError, TryLockError};

/// A value behind `std`'s lock, handed out whether or not a holder panicked.
pub struct Mutex<T>(std::sync::Mutex<T>);

/// What [`Mutex::lock`] hands back; the lock is let go when it is dropped.
pub type MutexGuard<'a, T> = std::sync::MutexGuard<'a, T>;

impl<T> Mutex<T> {
    /// `value`, behind a lock no thread holds.
    pub const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    /// A new mutex written in `place` around the value `make` writes in the place it is handed
    /// and lends back. `std`'s lock is not written field by field, so the value is made in a place
    /// of this frame and moved into the lock once. A maker that lends back anything but the place
    /// it was handed has not written it there, and is refused with a panic. `place` is
    /// overwritten without dropping what it held.
    pub fn new_in(
        place: &mut MaybeUninit<Self>,
        make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
    ) -> &mut Self {
        let mut value = MaybeUninit::uninit();
        let cell: *const T = value.as_ptr();
        let made: *const T = make(&mut value);
        assert!(
            core::ptr::eq(made, cell),
            "the value is written in the place it was handed"
        );
        // SAFETY: `make` lent back this place as a `T`, which safe code does only by writing a
        // `T` there (`MaybeUninit::write`).
        place.write(Self::new(unsafe { value.assume_init() }))
    }

    /// Wait until the lock is the calling thread's.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The lock, when no thread holds it: `None` without waiting when one does.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.0.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Whether a holder panicked while it held the lock.
    pub fn is_poisoned(&self) -> bool {
        self.0.is_poisoned()
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
        self.0.wait(guard).unwrap_or_else(PoisonError::into_inner)
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
            .wait_timeout(guard, Duration::from_millis(ms))
            .unwrap_or_else(PoisonError::into_inner);
        (guard, waited.timed_out())
    }

    /// Wait while `condition` holds of the value, for at most `timeout`: the guard, and whether
    /// the time ran out with the condition still holding.
    pub fn wait_timeout_while<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        timeout: Duration,
        condition: impl FnMut(&mut T) -> bool,
    ) -> (MutexGuard<'a, T>, bool) {
        let (guard, waited) = self
            .0
            .wait_timeout_while(guard, timeout, condition)
            .unwrap_or_else(PoisonError::into_inner);
        (guard, waited.timed_out())
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
