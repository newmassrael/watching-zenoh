// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The runtime's critical sections: the one door every lock of this crate goes through.
//!
//! The runtime's shared cells are `critical_section::Mutex<RefCell<T>>` (see [`crate::sync`]),
//! and a critical section is what grants their borrows. What a critical section IS belongs to
//! the platform:
//!
//! - on an MCU, interrupts masked, by the `critical-section` implementation the image links (the
//!   default here: [`with`] is `critical_section::with`);
//! - on a host (`host-lock`), a lock of the process, reentrant on its thread, which this module
//!   takes itself. A host program then links no `critical-section` implementation at all, and a
//!   C library built over this runtime exports no `_critical_section_1_0_*` symbol beside its C
//!   ABI, where another library's implementation could interpose it
//!   (`docs/capi-pico-on-coop-engine.md`, section 5).
//!
//! The token a critical section hands out ([`CriticalSection`]) is `critical-section`'s in both,
//! so the cells are the same type on every platform. The two must not be mixed over one cell:
//! every borrow of this crate's cells goes through [`with`], and nothing outside the crate
//! reaches them.

pub use critical_section::{CriticalSection, Mutex};

/// Run `f` inside a critical section; see the module doc.
#[inline]
pub fn with<R>(f: impl FnOnce(CriticalSection<'_>) -> R) -> R {
    #[cfg(feature = "host-lock")]
    {
        host::with(f)
    }
    #[cfg(not(feature = "host-lock"))]
    {
        critical_section::with(f)
    }
}

#[cfg(feature = "host-lock")]
mod host {
    extern crate std;

    use core::cell::{Cell, RefCell};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::CriticalSection;

    /// The process's critical section.
    static LOCK: Mutex<()> = Mutex::new(());

    std::thread_local! {
        /// How deep this thread is in critical sections: the lock is taken at the outermost.
        static DEPTH: Cell<usize> = const { Cell::new(0) };
        /// The lock while this thread holds it, from its outermost section to that section's end.
        static HELD: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
    }

    /// One level of this thread's critical sections, from [`Section::enter`] to drop, on return
    /// and on unwind alike.
    ///
    /// It holds nothing, and entering and leaving are out of line: `with` is instantiated at every
    /// call site of the runtime, and a section that held the guard would have each of them carry
    /// the guard's release (measured: 16 KB of text over the cooperative pico client, against a
    /// `critical-section` implementation's two calls).
    struct Section;

    impl Section {
        #[inline(never)]
        fn enter() -> Self {
            if DEPTH.with(Cell::get) == 0 {
                // A panic inside a critical section does not leave the runtime's cells
                // half-written in a way a later section could observe (each borrow is a
                // `RefCell`'s), so a poisoned lock is taken as it is.
                let guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
                HELD.with(|held| *held.borrow_mut() = Some(guard));
            }
            DEPTH.with(|depth| depth.set(depth.get() + 1));
            Self
        }
    }

    impl Drop for Section {
        #[inline(never)]
        fn drop(&mut self) {
            let depth = DEPTH.with(|depth| {
                depth.set(depth.get() - 1);
                depth.get()
            });
            if depth == 0 {
                // The outermost section ends: the lock goes with the guard.
                drop(HELD.with(|held| held.borrow_mut().take()));
            }
        }
    }

    pub(super) fn with<R>(f: impl FnOnce(CriticalSection<'_>) -> R) -> R {
        let section = Section::enter();
        // SAFETY: this thread holds `LOCK`, taken at its outermost section, and keeps it until
        // that section ends; every critical section of this crate is entered through `with`, so
        // no other thread holds a token while this one does.
        let token = unsafe { CriticalSection::new() };
        let result = f(token);
        drop(section);
        result
    }
}

#[cfg(all(test, feature = "host-lock"))]
mod tests {
    extern crate std;

    use core::cell::RefCell;
    use std::sync::Arc;
    use std::vec::Vec;

    use super::*;

    /// A section nested in another on the same thread does not wait on itself, and two threads'
    /// sections exclude each other: a cell updated under them loses no update.
    #[test]
    fn sections_nest_on_a_thread_and_exclude_across_threads() {
        let cell = Arc::new(Mutex::new(RefCell::new(0u32)));
        assert_eq!(with(|_| with(|cs| *cell.borrow(cs).borrow())), 0);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let cell = cell.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        with(|cs| {
                            let now = *cell.borrow(cs).borrow();
                            std::thread::yield_now();
                            *cell.borrow(cs).borrow_mut() = now + 1;
                        });
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("the thread ran");
        }
        assert_eq!(with(|cs| *cell.borrow(cs).borrow()), 8000);
    }
}
