// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock of a session's state in a build of one thread (no `threads`): a flag, where
//! zenoh-pico's session lock is nothing in a build without its threads
//! (`vendor/zenoh-pico/include/zenoh-pico/session/utils.h` @
//! `static inline void _z_session_mutex_unlock(_z_session_t *zn) { _ZP_UNUSED(zn); }`).
//!
//! Every call of such a build comes from one thread at a time: its rows count their calls for that
//! thread alone (`crate::form::CoopForm`), and it starts no read task. So the lock keeps no other
//! thread out and calls nothing of the host. It says whether the state is held, which a droppable
//! publish asks ([`OneThreadLock::try_lock`]); a take while it is held waits as a held lock does,
//! which on the one thread is for good, as the take of a host's lock on the thread that holds it
//! is. The flag is read and written with loads and stores, no read-modify-write. A debug build
//! fails a take while it is held, and takes it with a swap, so a second thread that enters beside
//! the first against the build's contract fails there too.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

/// A value behind the flag of a build of one thread. Seen by the crate, as the form's lock type
/// that names it (`LockForm::Lock` of `OneThread`) is.
pub(crate) struct OneThreadLock<T> {
    held: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the value is reached only through a guard, and a guard is made only by a take that found
// the flag clear; the guard's drop clears it with a release store and a take reads it with an
// acquire load, so each hold is ordered after the one before it, on whichever thread. No two takes
// run at once in a build of one thread (its contract, as zenoh-pico's without threads); a debug
// build fails two that do.
unsafe impl<T: Send> Sync for OneThreadLock<T> {}

impl<T> OneThreadLock<T> {
    /// A clear flag made in `place`, before the value `make` writes in the place it is handed
    /// and lends back. A maker that lends back anything but the place it was handed has not
    /// written it there, and is refused with a panic.
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self` and aligned for it, and what it held is
    /// overwritten without being dropped.
    pub(super) unsafe fn init_at(
        place: NonNull<Self>,
        make: impl FnOnce(&mut MaybeUninit<T>) -> &mut T,
    ) {
        let at = place.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (the caller's contract), so each field is
        // too, and each is written once: the value in its cell (`UnsafeCell<T>` and
        // `MaybeUninit<T>` each have the layout of `T`) by `make`, which lent the cell back and
        // so wrote it.
        unsafe {
            addr_of_mut!((*at).held).write(AtomicBool::new(false));
            let cell = &mut *addr_of_mut!((*at).value).cast::<MaybeUninit<T>>();
            let field: *const T = cell.as_ptr();
            let made: *const T = make(cell);
            assert!(
                core::ptr::eq(made, field),
                "the value is written in the place it was handed"
            );
        }
    }

    /// `value`, behind a clear flag.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn new(value: T) -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// The value, held until the guard drops. A take while it is held waits until it is not.
    /// Out of line: each door of the session takes it, as each called the host's lock it stands
    /// in for, and its guard is let go out of line too (`CoreGuard`'s drop).
    #[inline(never)]
    pub(super) fn lock(&self) -> OneThreadGuard<'_, T> {
        debug_assert!(
            !self.held.load(Ordering::Relaxed),
            "a session of a build of one thread is taken while it is held"
        );
        while !self.take() {
            core::hint::spin_loop();
        }
        OneThreadGuard { lock: self }
    }

    /// The value, held until the guard drops; `None` while it is held.
    pub(super) fn try_lock(&self) -> Option<OneThreadGuard<'_, T>> {
        self.take().then(|| OneThreadGuard { lock: self })
    }

    /// The value, owned whole.
    pub(super) fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    /// Mark the value held, when it is not: whether it was taken.
    fn take(&self) -> bool {
        if self.held.load(Ordering::Acquire) {
            return false;
        }
        #[cfg(debug_assertions)]
        {
            let raced = self.held.swap(true, Ordering::Acquire);
            debug_assert!(
                !raced,
                "a session of a build of one thread is taken on two threads at once"
            );
        }
        #[cfg(not(debug_assertions))]
        self.held.store(true, Ordering::Relaxed);
        true
    }
}

/// A hold of a [`OneThreadLock`], let go as it drops.
pub(crate) struct OneThreadGuard<'a, T> {
    lock: &'a OneThreadLock<T>,
}

impl<T> Deref for OneThreadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard's take found the flag clear and set it, and no other guard is made
        // until this one clears it.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for OneThreadGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` keeps this guard's own borrows apart.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for OneThreadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::OneThreadLock;

    /// A lock made in place is clear and holds the value written in its own place. Turned red by
    /// a make that writes the value anywhere but inside the lock, or leaves the flag set.
    #[test]
    fn a_lock_made_in_place_holds_the_value_written_there() {
        let mut place = core::mem::MaybeUninit::<OneThreadLock<[u8; 32]>>::uninit();
        let start = place.as_ptr() as usize;
        let lock_bytes = start..start + core::mem::size_of::<OneThreadLock<[u8; 32]>>();
        let mut handed = 0usize;
        // SAFETY: the place is valid for writes of the lock, which stays there.
        unsafe {
            OneThreadLock::init_at(
                core::ptr::NonNull::from(&mut place).cast::<OneThreadLock<[u8; 32]>>(),
                |value: &mut core::mem::MaybeUninit<[u8; 32]>| {
                    handed = value.as_ptr() as usize;
                    value.write([3; 32])
                },
            );
        }
        assert!(
            lock_bytes.contains(&handed),
            "the value is written inside the lock's place"
        );
        // SAFETY: made above.
        let lock = unsafe { place.assume_init_ref() };
        assert_eq!(
            lock.try_lock().map(|value| value[31]),
            Some(3),
            "made clear"
        );
    }

    /// A take holds the value until its guard drops: a try meanwhile finds it held, and one after
    /// takes it with what the first hold wrote. Turned red by a guard whose drop leaves the flag
    /// set, or a try that takes a held value.
    #[test]
    fn a_take_holds_the_value_until_its_guard_drops() {
        let lock = OneThreadLock::new(1_u8);
        let mut held = lock.lock();
        *held = 2;
        assert!(lock.try_lock().is_none(), "held, a try takes nothing");
        drop(held);
        let again = lock.try_lock().map(|value| *value);
        assert_eq!(again, Some(2), "let go, a try takes what the hold wrote");
        assert!(
            lock.try_lock().is_some(),
            "CONTROL: the try's own guard let it go"
        );
    }

    /// A take on the thread that holds the value fails a debug build at once, where a release
    /// build would wait on itself. Turned red by a take that does not look at the flag first.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "taken while it is held")]
    fn a_take_while_held_fails_a_debug_build() {
        let lock = OneThreadLock::new(0_u8);
        let _held = lock.lock();
        let _again = lock.lock();
    }

    /// A second thread that takes the value while the first holds it fails a debug build, the
    /// first thread's hold left as it was. Turned red by a take that waits instead.
    #[cfg(debug_assertions)]
    #[test]
    fn a_take_on_a_second_thread_while_held_fails_a_debug_build() {
        let lock = std::sync::Arc::new(OneThreadLock::new(0_u8));
        let held = lock.lock();
        let other = std::sync::Arc::clone(&lock);
        let taken = std::thread::spawn(move || {
            let _taken = other.lock();
        })
        .join();
        assert!(taken.is_err(), "the second thread's take failed");
        assert!(lock.try_lock().is_none(), "the first hold still stands");
        drop(held);
    }
}
