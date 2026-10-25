// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Per-runtime synchronization primitive aliases.
//!
//! R311w decision lock: `Mutex<T>` and `RwLock<T>` are surfaced as
//! per-runtime **type aliases**, not as a `MutexFamily` GAT trait
//! (option (b), rejected on HKT ergonomics) and not as parallel
//! AP/MCU direct call sites (option (c), rejected on single-source-
//! tree violation). The tokio profile aliases land here; the eventual
//! `wz-runtime-embassy` crate will define the matching
//! `pub type Mutex<T> = embassy_sync::Mutex<RawMutex, T>` shape from
//! its own `sync` module.
//!
//! This round (R311y) introduces the aliases without changing any
//! call site. R311z+ rounds will migrate
//! `Session::observer: Arc<std::sync::Mutex<...>>` and the ap-demo
//! 16 sites to `wz_runtime_tokio::sync::Mutex` so the eventual
//! Session-last reparam (`Session<R: Runtime, T: TimeSource>`) sees
//! a uniform import surface.
//!
//! ## Why a separate module (not an inline re-export at crate root)
//!
//! Two reasons:
//!
//! 1. **Cross-runtime symmetry**: future `wz-runtime-embassy::sync`
//!    will expose the same `Mutex<T>` / `RwLock<T>` names. Keeping
//!    the alias in a dedicated `sync` submodule means migration code
//!    can switch `use wz_runtime_tokio::sync::Mutex` ↔ `use
//!    wz_runtime_embassy::sync::Mutex` cleanly via a cfg gate without
//!    fighting crate-root namespace collisions.
//! 2. **Discoverability**: a consumer reading the wz-runtime-tokio
//!    surface sees the §5.P-driven sync primitives grouped together
//!    rather than scattered as crate-root re-exports.

/// Per-runtime mutual-exclusion lock alias (R311w option (a)).
///
/// Tokio profile binds to `std::sync::Mutex<T>` — synchronous, poison-
/// on-panic, fair queueing not guaranteed. The MCU profile will
/// re-bind this name to `embassy_sync::Mutex<RawMutex, T>` in the
/// future `wz-runtime-embassy::sync` module.
///
/// Use this alias for new code in wz-runtime-tokio + downstream
/// crates that want their `Mutex<T>` use to migrate cleanly across
/// runtime profiles. Direct `std::sync::Mutex<T>` references inside
/// wz-runtime-tokio are progressively replaced by this alias in
/// R311z+ rounds; the §5.P "Session struct last" gate covers the
/// `Session::observer` field migration as the terminal step.
pub type Mutex<T> = std::sync::Mutex<T>;

/// The lock the session's own state sits behind (`Runtime::Mutex` of the tokio profile): a mutex
/// that is NOT poisoned by a panic in a holder.
///
/// Every access to that state goes through `Runtime::with_mutex_mut`, which already RECOVERED
/// from poison and carried on (a panicking holder must not stop a `Drop` from unregistering its
/// id), so the poison state was never read for anything: what it cost was a check of the
/// process's panic count when the guard was taken and again when it was released, about a dozen
/// instructions a lock, on a path that locks four or five times for one put. This lock keeps the
/// protected value as the panic left it, which is what recovering from the poison did.
///
/// `parking_lot`'s, which tokio already links: a guard is one compare-and-swap to take and one to
/// release, and nothing else on the uncontended path.
pub struct PlainMutex<T>(parking_lot::Mutex<T>);

impl<T> PlainMutex<T> {
    /// A lock over `value`.
    pub const fn new(value: T) -> Self {
        Self(parking_lot::const_mutex(value))
    }

    /// Run `f` over the value, waiting for the lock.
    pub fn with<U>(&self, f: impl FnOnce(&mut T) -> U) -> U {
        f(&mut *self.0.lock())
    }

    /// The guard, waiting for the lock, for a caller that holds the value across several
    /// statements and has no use for the error arm of [`Self::lock`].
    pub fn guard(&self) -> PlainGuard<'_, T> {
        self.0.lock()
    }

    /// Run `f` over the value if the lock is free; `None` when it is held.
    pub fn try_with<U>(&self, f: impl FnOnce(&mut T) -> U) -> Option<U> {
        self.0.try_lock().map(|mut guard| f(&mut *guard))
    }

    /// The guard, waiting for the lock, in the shape `std::sync::Mutex::lock` answers so that a
    /// caller that holds the state of a session across several statements (and wrote
    /// `.lock().unwrap()`, or matched the poisoned arm to recover) reads the same. The error arm
    /// is never taken: it is a type with no value, so `Result` is the guard and costs nothing.
    pub fn lock(&self) -> Result<PlainGuard<'_, T>, NeverPoisoned<PlainGuard<'_, T>>> {
        Ok(self.0.lock())
    }

    /// [`Self::lock`] without waiting: `None` when the lock is held.
    pub fn try_lock_guard(&self) -> Option<PlainGuard<'_, T>> {
        self.0.try_lock()
    }
}

/// What [`PlainMutex::lock`] holds the lock with.
pub type PlainGuard<'a, T> = parking_lot::MutexGuard<'a, T>;

/// The error of a lock that is never poisoned: it cannot be made, so a `match` on it has the one
/// arm that is ever taken. It carries the guard type only so that `into_inner`, which a caller
/// that recovered from `std`'s poison calls, answers the guard as `std`'s does.
pub struct NeverPoisoned<G>(core::convert::Infallible, core::marker::PhantomData<G>);

impl<G> NeverPoisoned<G> {
    /// What `std::sync::PoisonError::into_inner` answers: the guard.
    pub fn into_inner(self) -> G {
        match self.0 {}
    }
}

impl<G> core::fmt::Debug for NeverPoisoned<G> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {}
    }
}

impl<G> core::fmt::Display for NeverPoisoned<G> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {}
    }
}

impl<T: Default> Default for PlainMutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> core::fmt::Debug for PlainMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlainMutex")
    }
}

/// Per-runtime reader-writer lock alias (R311w option (a)).
///
/// Tokio profile binds to `std::sync::RwLock<T>` — synchronous,
/// poison-on-panic. The MCU profile will re-bind this to
/// `embassy_sync::RwLock<RawMutex, T>` (or an equivalent if Embassy
/// surfaces a different RwLock shape) when `wz-runtime-embassy`
/// lands.
///
/// Same migration discipline as [`Mutex`]: introduced this round for
/// future call sites; existing `std::sync::RwLock<T>` references are
/// progressively replaced in R311z+ rounds.
pub type RwLock<T> = std::sync::RwLock<T>;

/// A small `Copy` value that is read and replaced as a whole from any thread: what a `Cell<T>` was
/// for single-threaded state, behind a [`PlainMutex`]'s lock.
///
/// For a setting a builder or an operator sets and the data path reads (the policy of autoconnect,
/// the query timeout, whether multicast is governed), not for a count: a count is a `Counter` or
/// a `Gauge` (`counter.rs`), whose updates are one atomic instruction and do not lose a
/// concurrent addition.
pub struct PlainCell<T: Copy>(parking_lot::Mutex<T>);

impl<T: Copy> PlainCell<T> {
    /// A cell holding `value`.
    pub const fn new(value: T) -> Self {
        Self(parking_lot::const_mutex(value))
    }

    /// The value now.
    pub fn get(&self) -> T {
        *self.0.lock()
    }

    /// Replace the value.
    pub fn set(&self, value: T) {
        *self.0.lock() = value;
    }

    /// Replace the value, answering the one it had: a flag that is read and cleared in one step.
    pub fn replace(&self, value: T) -> T {
        core::mem::replace(&mut *self.0.lock(), value)
    }

    /// Replace the value with what `f` makes of it, under the one lock, and answer the new value:
    /// a read and a write that no other thread's write can come between, for a value that is a
    /// successor of the last (a version, a generation).
    pub fn update(&self, f: impl FnOnce(T) -> T) -> T {
        let mut value = self.0.lock();
        *value = f(*value);
        *value
    }
}

impl<T: Copy + Default> Default for PlainCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Copy> core::fmt::Debug for PlainCell<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlainCell")
    }
}

/// The reader-writer lock a table that many threads read and few write sits behind: [`PlainMutex`]'s
/// counterpart, `parking_lot`'s, not poisoned by a panic in a holder.
///
/// Its first user is the router's route memo (`docs/router-task-per-face.md`, phase 2), which is read
/// on every message and written on a miss: a read guard is one atomic add to take and one to release,
/// where `std`'s also reads the process's panic count on both. A holder that panics leaves the value
/// as it was, which is what every caller of the `std` lock here recovered to.
pub struct PlainRwLock<T>(parking_lot::RwLock<T>);

impl<T> PlainRwLock<T> {
    /// A lock over `value`.
    pub const fn new(value: T) -> Self {
        Self(parking_lot::const_rwlock(value))
    }

    /// The value for reading, waiting for a writer to finish. Any number of readers hold it at once.
    ///
    /// A thread that already holds a read guard may take another, which is what the `RefCell`s
    /// this replaces allowed and what the router's code relies on (a method that reads calls one
    /// that reads the same table): the recursive form, which does not queue behind a writer that is
    /// waiting for the first guard, so the pair cannot deadlock. The price is that a steady stream
    /// of readers can keep a writer waiting; the writers here are declarations and configuration.
    pub fn read(&self) -> PlainReadGuard<'_, T> {
        self.0.read_recursive()
    }

    /// The value for writing, waiting for every reader and writer to finish.
    pub fn write(&self) -> PlainWriteGuard<'_, T> {
        self.0.write()
    }
}

/// What [`PlainRwLock::read`] holds the lock with.
pub type PlainReadGuard<'a, T> = parking_lot::RwLockReadGuard<'a, T>;

/// What [`PlainRwLock::write`] holds the lock with.
pub type PlainWriteGuard<'a, T> = parking_lot::RwLockWriteGuard<'a, T>;

impl<T: Default> Default for PlainRwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> core::fmt::Debug for PlainRwLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PlainRwLock")
    }
}
