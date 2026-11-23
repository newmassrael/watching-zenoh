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
//!   takes itself: `std`'s, or the host's own calls' in a library built without `std`
//!   (`host-lock-sys`). A host program then links no `critical-section` implementation at all, and a
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
    #[cfg(all(not(feature = "host-lock"), not(feature = "single-context")))]
    {
        critical_section::with(f)
    }
    #[cfg(all(not(feature = "host-lock"), feature = "single-context"))]
    {
        // SAFETY: the image that selects `single-context` states that no interrupt handler and
        // no other thread calls into this runtime or a session of it (the feature's doc in
        // Cargo.toml), so the one context that runs its loop is the only one that borrows a cell
        // and a critical section against another has nothing to keep out. The token is a
        // zero-sized proof, so it is made here and carries no state to restore.
        f(unsafe { CriticalSection::new() })
    }
}

// The host's section has two makings, each a module of its own name, and the build names the one it
// has `host`: `std`'s, or the host's own calls' (`host-lock-sys`).
#[cfg(all(feature = "host-lock", not(feature = "host-lock-sys")))]
use host_std as host;
#[cfg(feature = "host-lock-sys")]
use host_sys as host;

#[cfg(all(feature = "host-lock", not(feature = "host-lock-sys")))]
mod host_std {
    extern crate std;

    use core::cell::{Cell, RefCell, UnsafeCell};
    use core::mem::ManuallyDrop;
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
            DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
            Self
        }
    }

    impl Drop for Section {
        #[inline(never)]
        fn drop(&mut self) {
            // A section is made only by `enter`, so the count is at least one here.
            let depth = DEPTH.with(|depth| {
                depth.set(depth.get().saturating_sub(1));
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

    /// One cell's lock held by this thread, from [`Held::enter`] to drop, on return and on unwind
    /// alike. It owns the lock's guard, as the `host-lock-sys` form's owns its lock: a cell's lock
    /// is not reentrant, so nothing needs to know which locks a thread holds, and each is let go
    /// by the `Held` that took it, in the reverse of the order they were taken because `with`
    /// nests the way calls do. Entered and left out of line, and the guard dropped only inside the
    /// out-of-line drop (`ManuallyDrop`), because `with` is instantiated for every value and
    /// closure of the session's code and a guard dropped in each would carry the lock's release
    /// (and its poison check) into every one of them.
    struct Held<'a>(ManuallyDrop<MutexGuard<'a, ()>>);

    impl<'a> Held<'a> {
        #[inline(never)]
        fn enter(lock: &'a std::sync::Mutex<()>) -> Self {
            // A panic inside a cell leaves the value as the closure left it, which is all a
            // later `with` can ask of it (the value is not a lock's invariant), so a poisoned
            // lock is taken as it is, as the critical section above does.
            Self(ManuallyDrop::new(
                lock.lock().unwrap_or_else(PoisonError::into_inner),
            ))
        }

        /// [`Self::enter`] that does not wait: `None` when another thread holds `lock` now (or
        /// this one does: the lock is not reentrant).
        #[inline(never)]
        fn try_enter(lock: &'a std::sync::Mutex<()>) -> Option<Self> {
            let guard = match lock.try_lock() {
                Ok(guard) => guard,
                // Poisoned, as `enter` takes it.
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return None,
            };
            Some(Self(ManuallyDrop::new(guard)))
        }
    }

    impl Drop for Held<'_> {
        #[inline(never)]
        fn drop(&mut self) {
            // SAFETY: the guard is dropped here and only here, once, and `self` is not used
            // after its drop.
            unsafe { ManuallyDrop::drop(&mut self.0) };
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

        /// [`Self::with`] that does not wait: `None` when another thread holds the lock now,
        /// and `f` has not run.
        pub fn try_with<U>(&self, f: impl FnOnce(&mut T) -> U) -> Option<U> {
            let _held = Held::try_enter(&self.lock)?;
            // SAFETY: as in `with`: this thread holds `lock` until `_held` drops.
            Some(f(unsafe { &mut *self.value.get() }))
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

/// The host's, over its own calls (`host-lock-sys`): the same section and the same lock of each
/// value as the module above, made of `wz-host-sync`'s one-word lock, for a library built without
/// `std`, which has neither `std::sync` nor thread-locals. The section knows its owner by the
/// thread's number in place of a thread-local depth, and a value's lock is let go by the guard
/// that took it in place of a stack of guards.
#[cfg(feature = "host-lock-sys")]
mod host_sys {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use wz_host_sync::{current_thread, RawLock};

    use super::CriticalSection;

    /// The process's critical section.
    static LOCK: RawLock = RawLock::new();
    /// The thread inside the section, 0 when none is (no thread's number is 0). A thread writes
    /// its own number here only while it holds `LOCK` and clears it before letting go, so a thread
    /// that reads its own number back is the one inside, in a nested section.
    static OWNER: AtomicUsize = AtomicUsize::new(0);
    /// How deep the owner is in sections. Only the thread that holds `LOCK` reads or writes it, and
    /// the lock orders one owner's writes before the next one's reads.
    static DEPTH: AtomicUsize = AtomicUsize::new(0);

    /// One level of this thread's critical sections, from [`Section::enter`] to drop. Entered and
    /// left out of line, for the reason the module above gives.
    struct Section;

    impl Section {
        #[inline(never)]
        fn enter() -> Self {
            let me = current_thread();
            if OWNER.load(Ordering::Relaxed) != me {
                LOCK.lock();
                OWNER.store(me, Ordering::Relaxed);
            }
            DEPTH.store(
                DEPTH.load(Ordering::Relaxed).saturating_add(1),
                Ordering::Relaxed,
            );
            Self
        }
    }

    impl Drop for Section {
        #[inline(never)]
        fn drop(&mut self) {
            // A section is made only by `enter`, so the count is at least one here.
            let depth = DEPTH.load(Ordering::Relaxed).saturating_sub(1);
            DEPTH.store(depth, Ordering::Relaxed);
            if depth == 0 {
                // The outermost section ends: the lock goes, its owner cleared first.
                OWNER.store(0, Ordering::Relaxed);
                // SAFETY: this thread took `LOCK` at its outermost section, which ends here.
                unsafe { LOCK.unlock() };
            }
        }
    }

    /// A lock of its own around one value, for what the runtime hands the session
    /// ([`crate::sync::Mutex`]), for the reason the module above gives. Not reentrant.
    pub struct HostMutex<T> {
        lock: RawLock,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only inside `with` and `try_with`, with `lock` held, so one
    // thread at a time has it, which is what `Sync` asks of a value that is `Send`.
    unsafe impl<T: Send> Sync for HostMutex<T> {}

    /// One value's lock held by this thread, from [`Held::enter`] to drop. Entered and left out of
    /// line, for the reason [`Section`] is.
    struct Held<'a>(&'a RawLock);

    impl<'a> Held<'a> {
        #[inline(never)]
        fn enter(lock: &'a RawLock) -> Self {
            lock.lock();
            Self(lock)
        }

        /// [`Self::enter`] that does not wait: `None` when another thread holds `lock` now (or
        /// this one does: the lock is not reentrant).
        #[inline(never)]
        fn try_enter(lock: &'a RawLock) -> Option<Self> {
            if lock.try_lock() {
                Some(Self(lock))
            } else {
                None
            }
        }
    }

    impl Drop for Held<'_> {
        #[inline(never)]
        fn drop(&mut self) {
            // SAFETY: this `Held` took the lock it lets go.
            unsafe { self.0.unlock() };
        }
    }

    impl<T> HostMutex<T> {
        pub const fn new(value: T) -> Self {
            Self {
                lock: RawLock::new(),
                value: UnsafeCell::new(value),
            }
        }

        /// Run `f` on the value with its lock held.
        pub fn with<U>(&self, f: impl FnOnce(&mut T) -> U) -> U {
            let _held = Held::enter(&self.lock);
            // SAFETY: this thread holds `lock` until `_held` drops, after `f` returns.
            f(unsafe { &mut *self.value.get() })
        }

        /// [`Self::with`] that does not wait: `None` when another thread holds the lock now,
        /// and `f` has not run.
        pub fn try_with<U>(&self, f: impl FnOnce(&mut T) -> U) -> Option<U> {
            let _held = Held::try_enter(&self.lock)?;
            // SAFETY: as in `with`: this thread holds `lock` until `_held` drops.
            Some(f(unsafe { &mut *self.value.get() }))
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

#[cfg(all(test, feature = "single-context", not(feature = "host-lock")))]
mod single_context_tests {
    use core::cell::RefCell;

    use super::*;

    /// With no lock a section still runs its closure once, returns its value, nests, and hands out
    /// the cells' borrows: the guard the borrow rules give is the `RefCell`'s, and it stays.
    #[test]
    fn a_section_runs_nests_and_leaves_the_cells_borrow_rules() {
        let cell = Mutex::new(RefCell::new(1u32));
        let mut runs = 0;
        let value = with(|outer| {
            runs += 1;
            *cell.borrow(outer).borrow_mut() += 1;
            with(|inner| {
                runs += 1;
                *cell.borrow(inner).borrow()
            })
        });
        assert_eq!((value, runs), (2, 2));
        // A borrow held across a second section is a re-entrant borrow, refused as it is with a lock.
        with(|cs| {
            let held = cell.borrow(cs).borrow_mut();
            let second = cell.borrow(cs).try_borrow_mut();
            assert!(second.is_err());
            drop(held);
            assert!(cell.borrow(cs).try_borrow_mut().is_ok());
        });
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

    /// A cell tried while another thread holds it answers `None` at once and runs nothing; once
    /// the holder lets go it is taken and the closure runs. A cell this thread already holds is
    /// held too: the lock is not reentrant.
    #[test]
    fn a_held_cell_is_tried_without_waiting() {
        let held = Arc::new(HostMutex::new(0u32));
        let (inside_tx, inside_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let held = held.clone();
            std::thread::spawn(move || {
                held.with(|value| {
                    *value += 1;
                    inside_tx.send(()).expect("the test is listening");
                    // Bounded, so a try that waited for the holder reads as a wrong answer and
                    // not as a test that never ends.
                    let _ = release_rx.recv_timeout(std::time::Duration::from_secs(3));
                });
            })
        };
        inside_rx.recv().expect("the holder is inside its cell");
        let mut ran = false;
        assert_eq!(
            held.try_with(|value| {
                ran = true;
                *value
            }),
            None
        );
        assert!(!ran, "nothing ran under a cell another thread holds");
        let _ = release_tx.send(());
        holder.join().expect("the holder ran");
        assert_eq!(held.try_with(|value| *value), Some(1));
        assert_eq!(
            held.with(|_| held.try_with(|value| *value)),
            None,
            "a cell this thread holds is held"
        );
    }

    /// A cell's lock is let go when the closure inside it unwinds, as when it returns: a try on
    /// this thread finds it free, with what the closure wrote before it unwound, and another
    /// thread takes it after. The lock is poisoned by the unwind, and taken as it is.
    #[test]
    fn a_cell_is_let_go_when_its_closure_unwinds() {
        let cell = Arc::new(HostMutex::new(0u32));
        let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            cell.with(|value| {
                *value = 1;
                panic!("inside the cell");
            })
        }));
        assert!(unwound.is_err(), "CONTROL: the closure did unwind");
        assert_eq!(
            cell.try_with(|value| *value),
            Some(1),
            "the cell is free again, with what the closure wrote"
        );
        let other = {
            let cell = cell.clone();
            std::thread::spawn(move || {
                cell.with(|value| {
                    *value += 1;
                    *value
                })
            })
        };
        assert_eq!(other.join().expect("the other thread ran"), 2);
    }

    /// Cells nested on one thread are held together and let go in turn: inside the inner cell the
    /// outer one is still held, and once both closures return both are free.
    #[test]
    fn nested_cells_are_held_together_and_let_go_in_turn() {
        let outer = HostMutex::new(1u32);
        let inner = HostMutex::new(2u32);
        let sum = outer.with(|o| {
            inner.with(|i| {
                assert_eq!(outer.try_with(|_| ()), None, "the outer cell is held");
                *o + *i
            })
        });
        assert_eq!(sum, 3);
        assert_eq!(outer.try_with(|value| *value), Some(1), "the outer is free");
        assert_eq!(inner.try_with(|value| *value), Some(2), "the inner is free");
    }
}
