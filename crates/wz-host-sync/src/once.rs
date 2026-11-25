// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A value made the first time it is reached and the same one ever after, in its owner's bytes:
//! the shape of `std::sync::OnceLock`, for a process-wide value whose maker runs at run time (it
//! reads the runtime limits, or the time the first call came), which a `static` cannot make in a
//! `const` context. Making the cell, filling it and reading it take no memory.
//!
//! A filled cell is read with one atomic load. The threads that find it empty take a
//! [`RawLock`] of the cell's own, so one of them runs the maker and the rest wait for its value
//! rather than make a second. A maker that panics leaves the cell empty and lets the lock go, and
//! the next caller makes the value again, as `std`'s does; without `std` a panic aborts.

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::RawLock;

/// A value made once, by the first caller of [`Self::get_or_init`].
pub struct OnceLock<T> {
    /// Set once `value` holds the value, never cleared while the cell lives.
    filled: AtomicBool,
    /// Taken by a caller that found the cell empty, for as long as it makes the value.
    making: RawLock,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: a value is written once, under `making`, before `filled` is released, and only shared
// references to it are handed out after that, so the cell shares a `T` between threads (`Sync`)
// and may be filled on any thread with a value made there (`Send`).
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
// SAFETY: the cell owns its value; moving the cell moves it.
unsafe impl<T: Send> Send for OnceLock<T> {}

impl<T> OnceLock<T> {
    /// A cell no value has been made in.
    pub const fn new() -> Self {
        Self {
            filled: AtomicBool::new(false),
            making: RawLock::new(),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// The value, or `None` while none has been made.
    pub fn get(&self) -> Option<&T> {
        if self.filled.load(Ordering::Acquire) {
            // SAFETY: `filled` is set only after the value was written, and the acquire orders
            // that write before this read; the value is never written again.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    /// The value, made by `make` if no caller has made it yet. A caller that finds another
    /// making it waits for that value. `make` that reaches this cell again waits for itself.
    pub fn get_or_init(&self, make: impl FnOnce() -> T) -> &T {
        match self.get() {
            Some(value) => value,
            None => self.make(make),
        }
    }

    #[cold]
    fn make(&self, make: impl FnOnce() -> T) -> &T {
        self.making.lock();
        let _held = Held(&self.making);
        if !self.filled.load(Ordering::Acquire) {
            let value = make();
            // SAFETY: the lock is held and the cell is empty, so no reference to the value
            // exists and no other thread writes it.
            unsafe { (*self.value.get()).write(value) };
            self.filled.store(true, Ordering::Release);
        }
        // SAFETY: the cell was filled above or by the caller that held the lock before.
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if *self.filled.get_mut() {
            // SAFETY: the cell holds a value, which nothing borrows (`&mut self`), dropped once.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OnceLock").field(&self.get()).finish()
    }
}

/// Lets the cell's lock go when the maker returns or unwinds.
struct Held<'a>(&'a RawLock);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        // SAFETY: the lock was taken by the caller that made this.
        unsafe { self.0.unlock() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn an_empty_cell_reads_none_and_the_first_maker_fills_it() {
        let cell = OnceLock::new();
        assert_eq!(cell.get(), None);
        assert_eq!(*cell.get_or_init(|| 7_u32), 7);
        assert_eq!(*cell.get_or_init(|| 8_u32), 7, "a second maker is not run");
        assert_eq!(cell.get(), Some(&7));
    }

    /// Threads that find the cell empty at once make one value between them, and every one reads
    /// that value. Turned red by a cell that lets two makers run, or hands out a value before it
    /// is written.
    #[test]
    fn racing_callers_make_one_value() {
        let cell = Arc::new(OnceLock::new());
        let made = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let made = Arc::clone(&made);
                std::thread::spawn(move || {
                    *cell.get_or_init(|| {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        made.fetch_add(1, Ordering::SeqCst)
                    })
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(
                thread.join().expect("a caller"),
                0,
                "every caller read the one value"
            );
        }
        assert_eq!(made.load(Ordering::SeqCst), 1, "one maker ran");
    }

    /// A maker that panics leaves the cell empty and its lock free: the next caller makes the
    /// value. Turned red by a lock the unwinding maker kept, which makes the next caller wait.
    #[test]
    fn a_maker_that_panics_leaves_the_cell_empty_for_the_next() {
        let cell = OnceLock::<u32>::new();
        let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            cell.get_or_init(|| panic!("the maker fails"));
        }));
        assert!(unwound.is_err());
        assert_eq!(cell.get(), None, "nothing was made");
        assert_eq!(*cell.get_or_init(|| 3), 3, "the next maker runs");
    }

    /// The value is dropped with the cell, once; an empty cell drops nothing.
    #[test]
    fn the_value_is_dropped_with_the_cell() {
        let witness = Arc::new(());
        let cell = OnceLock::new();
        cell.get_or_init(|| Arc::clone(&witness));
        assert_eq!(Arc::strong_count(&witness), 2);
        drop(cell);
        assert_eq!(
            Arc::strong_count(&witness),
            1,
            "the cell's value was dropped"
        );
        drop(OnceLock::<Arc<()>>::new());
    }
}
