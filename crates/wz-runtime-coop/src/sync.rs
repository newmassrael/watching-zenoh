// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Per-runtime synchronization primitive aliases for the lwIP / MCU
//! profile (R311au scope C).
//!
//! R311w decision lock (per §5.P caveat) selected **option (a) —
//! per-runtime type alias** over option (b) a `MutexFamily` GAT (HKT
//! ergonomics) and option (c) AP/MCU source-tree fork (single-source-
//! tree violation). The tokio profile binds through
//! `wz_runtime_tokio::sync` (`std::sync::Mutex<T>` /
//! `std::sync::RwLock<T>`); this module is the matching MCU-profile
//! binding so future cross-runtime code reading `use
//! wz_runtime_coop::sync::Mutex` lands on a real per-arch primitive.
//!
//! ## Why `critical_section::Mutex<RefCell<T>>`
//!
//! The MCU profile assumes a single-core, interrupt-driven execution
//! model (lwIP's `tcpip_thread` running cooperatively with hardware
//! ISRs). `critical_section::Mutex<T>` acquires its lock by disabling
//! interrupts in a critical section, which is the canonical
//! single-core IRQ-safe primitive for this environment:
//!
//! **Send + Sync**: `critical_section::Mutex<T>: Send + Sync where T:
//! Send`. The trait-level `Runtime::Mutex` bound (`Send + Sync +
//! 'static where T: Send + 'static`) is satisfied via the `RefCell<T>`
//! interior — `RefCell<T>: Send where T: Send`, and the outer
//! `critical_section::Mutex` adds the `Sync` half by interrupt-
//! disabling lock acquisition. The `T: Send + 'static` trait bound
//! propagates to `T: Send + 'static` for the inner value, matching
//! tokio's `std::sync::Mutex<T>: Sync where T: Send` shape one-to-one.
//!
//! **No allocator dep**: the `RefCell<T>` interior keeps the primitive
//! `#![no_std]`-compatible without `alloc`. Consumers that want owned
//! `Arc<R::Mutex<...>>` storage layer `alloc` on top, same as the
//! tokio profile.
//!
//! **API divergence from `std::sync::Mutex` is expected**:
//! `critical_section::Mutex::lock(|cs| { /* &RefCell access */ })` is
//! a closure-shaped API, distinct from `std::sync::Mutex::lock()`
//! which returns a `MutexGuard`. The per-runtime alias surface
//! intentionally leaves the call-site API profile-specific — generic
//! code over `R: Runtime` parameterises the *storage type*
//! `R::Mutex<T>` but locks against profile-aware wrappers (this is
//! the same shape `Session<R: Runtime>` will pick up when its
//! `Arc<R::Mutex<...>>` field migrates per the §5.P "Session struct
//! last" gate).
//!
//! ## Why `RwLock` collapses to `Mutex`
//!
//! Single-core, interrupt-driven execution means there is no
//! observable multi-reader concurrency: any "reader" runs atomically
//! within the critical section (interrupts disabled). The shared-read
//! semantic that distinguishes `RwLock` from `Mutex` on multi-core AP
//! is therefore unobservable on this profile; aliasing both to the
//! same `critical_section::Mutex<RefCell<T>>` is the textbook
//! collapse. The trait-level bound difference (`T: Send + Sync` for
//! `RwLock` vs `T: Send` for `Mutex`) is conservatively preserved at
//! the alias declaration — call sites that rely on the looser Mutex
//! bound still compile, and sites that read shared `&T` through the
//! RwLock alias retain the `Sync` requirement on `T` they would have
//! had under a true reader-writer lock.
//!
//! ## Future MCU profile fork
//!
//! A separate `wz-runtime-embassy` crate (if it lands) would expose
//! the same `sync::Mutex` / `sync::RwLock` names bound to
//! `embassy_sync::Mutex<RawMutex, T>` / `embassy_sync::RwLock<RawMutex,
//! T>` for the async-executor flavour of the MCU profile. The
//! per-runtime alias surface keeps both flavours composable through a
//! cfg switch at the consumer's import line.

#[cfg(all(feature = "runtime", debug_assertions))]
use core::cell::Cell;
#[cfg(not(feature = "host-lock"))]
use core::cell::RefCell;
#[cfg(feature = "runtime")]
use core::cell::UnsafeCell;
#[cfg(feature = "runtime")]
use core::marker::PhantomData;

/// MCU-profile mutual-exclusion lock alias (R311w option (a),
/// R311au scope C realisation).
///
/// Binds to `critical_section::Mutex<RefCell<T>>` — interrupt-
/// disabling lock with `RefCell<T>` interior for shared-mutable
/// access inside the critical section. See module doc for the full
/// rationale (Send + Sync bound, API divergence from
/// `std::sync::Mutex`, single-core IRQ-safe semantics).
///
/// Use this alias for new MCU-side code that wants to migrate
/// cleanly when the future `CoopRuntime` impl lands and `R::Mutex<T>`
/// generic dispatch becomes available. Direct
/// `critical_section::Mutex<RefCell<T>>` references should be
/// avoided in favour of this alias so a future
/// `wz-runtime-embassy::sync::Mutex` (or another MCU profile flavour)
/// can substitute without call-site churn.
#[cfg(not(feature = "host-lock"))]
pub type Mutex<T> = critical_section::Mutex<RefCell<T>>;

/// On a host (`host-lock`) the lock is the value's own ([`crate::cs::HostMutex`]), because the
/// session runs I/O inside it and a lock of the whole process held through a blocking write
/// would stop every other session of the program.
#[cfg(feature = "host-lock")]
pub type Mutex<T> = crate::cs::HostMutex<T>;

/// How a [`CoopRuntime`](crate::CoopRuntime) locks the values it lends a session
/// (`Runtime::Mutex`): the profile's own lock ([`Shared`]), or none, where one lock of the
/// engine that owns every session already keeps each value to one thread at a time
/// ([`Confined`]).
#[cfg(feature = "runtime")]
pub trait LockKind: 'static {
    /// The form a value of `T` is lent in.
    type Mutex<T>: Send + Sync + 'static
    where
        T: Send + 'static;

    /// `value`, in this kind's form.
    fn wrap<T: Send + 'static>(value: T) -> Self::Mutex<T>;

    /// Run `f` on the value of `mutex`, held.
    fn with<T: Send + 'static, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U;

    /// [`Self::with`] that does not wait: `None` when another thread holds `mutex` now, and `f`
    /// has not run.
    fn try_with<T: Send + 'static, U>(
        mutex: &Self::Mutex<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Option<U>;
}

/// The profile's lock ([`Mutex`]): a critical section, or on a host (`host-lock`) the value's
/// own lock. What every runtime that is not told otherwise lends.
#[cfg(feature = "runtime")]
pub struct Shared;

#[cfg(feature = "runtime")]
impl LockKind for Shared {
    type Mutex<T>
        = crate::sync::Mutex<T>
    where
        T: Send + 'static;

    #[inline]
    fn wrap<T: Send + 'static>(value: T) -> Self::Mutex<T> {
        #[cfg(not(feature = "host-lock"))]
        {
            critical_section::Mutex::new(RefCell::new(value))
        }
        #[cfg(feature = "host-lock")]
        {
            crate::cs::HostMutex::new(value)
        }
    }

    #[inline]
    fn with<T: Send + 'static, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U {
        #[cfg(not(feature = "host-lock"))]
        {
            crate::cs::with(|cs| f(&mut *mutex.borrow(cs).borrow_mut()))
        }
        #[cfg(feature = "host-lock")]
        {
            mutex.with(f)
        }
    }

    /// On a host each value has its lock and another thread may hold it; under a critical
    /// section no other context runs while this one does, so there is never a holder to find and
    /// `f` always runs.
    #[inline]
    fn try_with<T: Send + 'static, U>(
        mutex: &Self::Mutex<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Option<U> {
        #[cfg(not(feature = "host-lock"))]
        {
            Some(Self::with(mutex, f))
        }
        #[cfg(feature = "host-lock")]
        {
            mutex.try_with(f)
        }
    }
}

/// The owner of every value a runtime of [`Confined<Self>`](Confined) lends: an engine that
/// reaches each of its sessions only under one lock of its own.
///
/// # Safety
///
/// Every value made by a `CoopRuntime<_, _, Confined<Self>>` is reached by one thread at a time
/// for as long as it lives: each `Runtime::with_mutex_mut` / `try_with_mutex_mut` on it runs
/// under one lock the implementor's engine holds around every path to the session's state, or in
/// the one frame that owns the value, and nothing that holds such a value is handed out of that
/// lock to be used without it. A runtime the engine confines to its lock
/// (`CoopRuntime::confine_tasks`) is reached the same way from that call on: its spawns, its
/// passes, its local set and the handles of its tasks, all under the lock; only a waker of one of
/// its tasks, which raises a flag, is woken from anywhere.
#[cfg(feature = "runtime")]
pub unsafe trait ConfinedOwner: 'static {}

/// No lock of the value's own: the values are [`OwnerHeld`], reached under the lock of `O`'s
/// engine ([`ConfinedOwner`]). A lock here would be a second one around what that lock already
/// keeps to one thread, taken and let go at every one of the session's accesses.
#[cfg(feature = "runtime")]
pub struct Confined<O: ConfinedOwner>(PhantomData<fn() -> O>);

#[cfg(feature = "runtime")]
impl<O: ConfinedOwner> LockKind for Confined<O> {
    type Mutex<T>
        = OwnerHeld<T, O>
    where
        T: Send + 'static;

    #[inline]
    fn wrap<T: Send + 'static>(value: T) -> Self::Mutex<T> {
        OwnerHeld::new(value)
    }

    #[inline]
    fn with<T: Send + 'static, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U {
        mutex.with(f)
    }

    /// No other thread reaches the value (`O`'s contract), so there is never a holder to find and
    /// `f` always runs.
    #[inline]
    fn try_with<T: Send + 'static, U>(
        mutex: &Self::Mutex<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Option<U> {
        Some(mutex.with(f))
    }
}

/// A value of a session reached only under the lock of the engine `O` that owns the session, and
/// so taking no lock of its own: [`Self::with`] is the closure called on the value.
///
/// A value is never taken inside its own hold: the session's code does not nest one value in
/// itself (a lock of the value would wait on itself there). A debug build checks it, and fails at
/// the nested take instead of handing out a second `&mut`.
#[cfg(feature = "runtime")]
pub struct OwnerHeld<T, O: ConfinedOwner> {
    value: UnsafeCell<T>,
    /// Whether a closure is inside the value now.
    #[cfg(debug_assertions)]
    inside: Cell<bool>,
    owner: PhantomData<fn() -> O>,
}

// SAFETY: the value is reached only inside `with`, and `O`'s `unsafe impl ConfinedOwner` states
// that `with` is called by one thread at a time, which is what `Sync` asks of a value that is
// `Send`. The debug build's flag is read and written inside the same calls.
#[cfg(feature = "runtime")]
unsafe impl<T: Send, O: ConfinedOwner> Sync for OwnerHeld<T, O> {}

#[cfg(feature = "runtime")]
impl<T, O: ConfinedOwner> OwnerHeld<T, O> {
    fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            #[cfg(debug_assertions)]
            inside: Cell::new(false),
            owner: PhantomData,
        }
    }

    /// Run `f` on the value.
    #[inline]
    pub fn with<U>(&self, f: impl FnOnce(&mut T) -> U) -> U {
        #[cfg(debug_assertions)]
        let _inside = Inside::enter(&self.inside);
        // SAFETY: one thread at a time calls this (`O`'s contract), and the value is not taken
        // inside its own hold (checked in a debug build), so no other reference to it lives while
        // `f` runs.
        f(unsafe { &mut *self.value.get() })
    }
}

/// A closure inside an [`OwnerHeld`], from [`Inside::enter`] to drop, on return and on unwind
/// alike: what lets a debug build fail a take nested in the hold of the same value.
#[cfg(all(feature = "runtime", debug_assertions))]
struct Inside<'a>(&'a Cell<bool>);

#[cfg(all(feature = "runtime", debug_assertions))]
impl<'a> Inside<'a> {
    fn enter(inside: &'a Cell<bool>) -> Self {
        assert!(
            !inside.replace(true),
            "a session's value is taken again inside its own hold"
        );
        Self(inside)
    }
}

#[cfg(all(feature = "runtime", debug_assertions))]
impl Drop for Inside<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// MCU-profile reader-writer lock alias (R311w option (a)).
///
/// Aliased to the same `critical_section::Mutex<RefCell<T>>` as
/// [`Mutex`] — see module doc on why the shared-read semantic
/// collapses on a single-core, interrupt-driven profile. The
/// trait-level bound difference (`T: Send + Sync` for `RwLock` vs
/// `T: Send` for `Mutex`) is preserved at the call-site contract;
/// the alias body is the same primitive.
pub type RwLock<T> = Mutex<T>;

#[cfg(all(test, feature = "runtime"))]
pub(crate) mod tests {
    use super::{Confined, ConfinedOwner, LockKind};

    /// The owner of the values the tests below make: each test's one thread is the only one that
    /// reaches them.
    pub(crate) struct TestOwner;

    // SAFETY: a value of a `Confined<TestOwner>` runtime is made and reached by one test's thread
    // alone and never handed to another.
    unsafe impl ConfinedOwner for TestOwner {}

    type Held = Confined<TestOwner>;

    /// Each closure runs on the value and sees what the one before it left, and two values nest,
    /// one inside the other's hold.
    #[test]
    fn a_value_its_owner_holds_runs_each_closure_on_it() {
        let value = Held::wrap(1u32);
        assert_eq!(
            Held::with(&value, |held| {
                *held += 1;
                *held
            }),
            2
        );
        let other = Held::wrap(10u32);
        assert_eq!(
            Held::with(&value, |first| Held::with(&other, |second| *first
                + *second)),
            12
        );
        assert_eq!(
            Held::try_with(&value, |held| *held),
            Some(2),
            "the nested hold left the value, and a try always runs"
        );
    }

    /// A debug build fails a value taken inside its own hold, where a lock would wait on itself.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "taken again inside its own hold")]
    fn a_debug_build_fails_a_value_taken_inside_its_own_hold() {
        let value = Held::wrap(0u8);
        Held::with(&value, |_| Held::with(&value, |_| ()));
    }

    /// A hold that unwound leaves the value free for the next one.
    #[cfg(debug_assertions)]
    #[test]
    fn a_hold_that_unwound_leaves_the_value_free() {
        extern crate std;
        let value = Held::wrap(3u8);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Held::with(&value, |held| {
                if *held == 3 {
                    panic!("inside the hold");
                }
            });
        }));
        assert!(unwound.is_err());
        assert_eq!(Held::with(&value, |held| *held), 3);
    }
}
