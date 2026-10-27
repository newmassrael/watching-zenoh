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
//!
//! The one exception is what the runtime lends the session (`Runtime::Mutex`, `Runtime::RwLock`).
//! The session runs I/O inside those, and a host's process-wide lock held through a blocking
//! write stops every session of the program, so on a host each such value has a lock of its own
//! (`HostMutex`, which only a `host-lock` build has, and [`crate::sync`]); the crate's own cells (the timers, the tasks, the joins) do
//! no I/O and stay on the process's section.

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

    use core::cell::{Cell, RefCell, UnsafeCell};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::vec::Vec;

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

    /// A lock of its own around one value, for what the runtime hands the session
    /// ([`crate::sync::Mutex`]).
    ///
    /// The session's code runs I/O inside such a lock: a link's transmit queue is held while its
    /// bytes are written, and a write on a full socket waits for the peer to read. Held through
    /// the process's critical section that wait would stop every other session of the process,
    /// the very session whose read task is the peer to drain it included (two sessions of one
    /// program, one that sends more than the socket holds and one that listens, each wait on the
    /// other for good). So each value is guarded by itself and a wait inside one stops only what
    /// uses that value, which is what the tokio runtime's `std::sync::Mutex` is.
    ///
    /// Not reentrant: the session's code never nests one value's lock in itself (the MCU's
    /// critical section forbids it too).
    pub struct HostMutex<T> {
        lock: std::sync::Mutex<()>,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only inside `with`, with `lock` held, so one thread at a time
    // has it, which is what `Sync` asks of a value that is `Send`.
    unsafe impl<T: Send> Sync for HostMutex<T> {}

    std::thread_local! {
        /// The cell locks this thread holds, innermost last. A cell's `with` nests in another's
        /// the way calls do, so a lock is released in the reverse of the order it was taken.
        static CELLS: RefCell<Vec<MutexGuard<'static, ()>>> = const { RefCell::new(Vec::new()) };
    }

    /// One cell's lock held by this thread, from [`Held::enter`] to drop, on return and on unwind
    /// alike. Like [`Section`] it holds nothing and enters and leaves out of line, because `with`
    /// is instantiated for every value and closure of the session's code and a guard held in each
    /// would carry the lock's release (and its poison check) into every one of them.
    struct Held;

    impl Held {
        #[inline(never)]
        fn enter(lock: &std::sync::Mutex<()>) -> Self {
            // A panic inside a cell leaves the value as the closure left it, which is all a
            // later `with` can ask of it (the value is not a lock's invariant), so a poisoned
            // lock is taken as it is, as the critical section above does.
            let guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
            // SAFETY: the guard is dropped by this thread's `Held` before `with` returns, and
            // `with` borrows the cell, so the lock outlives the guard.
            let guard: MutexGuard<'static, ()> = unsafe { core::mem::transmute(guard) };
            CELLS.with(|held| held.borrow_mut().push(guard));
            Self
        }
    }

    impl Drop for Held {
        #[inline(never)]
        fn drop(&mut self) {
            drop(CELLS.with(|held| held.borrow_mut().pop()));
        }
    }

    impl<T> HostMutex<T> {
        pub const fn new(value: T) -> Self {
            Self {
                lock: std::sync::Mutex::new(()),
                value: UnsafeCell::new(value),
            }
        }

        /// Run `f` on the value with its lock held.
        pub fn with<U>(&self, f: impl FnOnce(&mut T) -> U) -> U {
            let _held = Held::enter(&self.lock);
            // SAFETY: this thread holds `lock` until `_held` drops, after `f` returns or
            // unwinds, so no other thread has the value meanwhile.
            f(unsafe { &mut *self.value.get() })
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

#[cfg(feature = "host-lock")]
pub use host::HostMutex;

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

    /// A wait inside one value's lock stops what uses that value and nothing else: a thread that
    /// holds one cell (as a session does through a write that waits for its peer to read) does
    /// not keep another thread from a second cell or from the process's critical section. Held
    /// through the process's section, as every cell once was, the second thread would wait for
    /// the first, which is two sessions of one program each waiting on the other.
    #[test]
    fn a_wait_inside_one_cell_does_not_stop_another_cell_or_the_section() {
        let held = Arc::new(HostMutex::new(0u32));
        let other = Arc::new(HostMutex::new(0u32));
        let (inside_tx, inside_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let held = held.clone();
            std::thread::spawn(move || {
                held.with(|value| {
                    *value += 1;
                    inside_tx.send(()).expect("the test is listening");
                    release_rx.recv().expect("the test releases");
                });
            })
        };
        inside_rx.recv().expect("the holder is inside its cell");
        other.with(|value| *value += 1);
        assert_eq!(with(|_| other.with(|value| *value)), 1);
        release_tx.send(()).expect("the holder is waiting");
        holder.join().expect("the holder ran");
        assert_eq!(held.with(|value| *value), 1);
    }
}
