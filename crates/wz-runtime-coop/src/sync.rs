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

    /// Whether [`Self::with`] can wait for a hold another thread has: a lock of the value's own
    /// can, a kind whose values one engine's lock keeps to one thread ([`Confined`]) never does.
    /// A face's place asks it before a lend that waits ([`FacePlace::lend`]).
    const WAITS: bool = true;

    /// How the handles on the parts of one link of a session of this kind are counted (its pump,
    /// its actions, its sink): each such handle is held by its face alone, so they are counted for
    /// one task even where several threads drive the session's faces, whose parts then move
    /// between threads only whole (`crate::link_cells::FaceHeld`). Its table flag is
    /// [`Self::Flag`], and what the links share is counted as [`Self::SharedCount`].
    #[cfg(all(feature = "session-unicast", not(feature = "session-slot")))]
    type LinkCount: crate::link_cells::CountKind<Flag = Self::Flag, Shared = Self::SharedCount>;

    /// How the handles on what a session's faces share are counted (the session's entropy, a
    /// port several links read from): for one task, or across threads where several threads
    /// drive the faces. Its table flag is [`Self::Flag`].
    #[cfg(all(feature = "session-unicast", not(feature = "session-slot")))]
    type SharedCount: crate::link_cells::CountKind<Flag = Self::Flag>
        + crate::session_runtime::EntropyCount;

    /// A flag the session's holders write without a lock, and the flag of a table's cell
    /// (`SessionRuntime::Flag`): a cell where one task holds them, an atomic where threads do.
    #[cfg(feature = "session-unicast")]
    type Flag: wz_session_core::byte_cells::CellFlag + Send;

    /// A word the session's holders write without a lock (`SessionRuntime::Word`), in the form
    /// [`Self::Flag`] is.
    #[cfg(feature = "session-unicast")]
    type Word: wz_session_core::runtime_cell::WordCell + Send;

    /// A value the session's holders reach one at a time (`SessionRuntime::Local`): a
    /// `RefCell` where one task holds them, a lock of its own where threads do.
    #[cfg(feature = "session-unicast")]
    type Local<T>
    where
        T: Send + 'static;

    /// `value` in a new [`Self::Local`].
    #[cfg(feature = "session-unicast")]
    fn new_local<T: Send + 'static>(value: T) -> Self::Local<T>;

    /// Run `f` on the value of `local`, which no other holder reaches meanwhile.
    /// [`LocalHeld`](wz_session_core::link::LocalHeld), and `f` not run, when this task reaches
    /// the value again from inside its own access, which one task's `RefCell` can tell.
    #[cfg(feature = "session-unicast")]
    fn with_local<T: Send + 'static, U>(
        local: &Self::Local<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Result<U, wz_session_core::link::LocalHeld>;
}

/// What one task at a time holds ([`Shared`] and [`Confined`]): handles counted with plain loads
/// and stores, flags and words that are cells, a value reached through a `RefCell`. A session's
/// handles are not `Send` here, so nothing written without a lock is reached by two threads.
#[cfg(feature = "session-unicast")]
macro_rules! one_task_holders {
    () => {
        #[cfg(not(feature = "session-slot"))]
        type LinkCount = crate::link_cells::OneTask;
        #[cfg(not(feature = "session-slot"))]
        type SharedCount = crate::link_cells::OneTask;
        type Flag = core::cell::Cell<bool>;
        type Word = core::cell::Cell<u64>;
        type Local<T>
            = core::cell::RefCell<T>
        where
            T: Send + 'static;

        #[inline]
        fn new_local<T: Send + 'static>(value: T) -> Self::Local<T> {
            core::cell::RefCell::new(value)
        }

        #[inline]
        fn with_local<T: Send + 'static, U>(
            local: &Self::Local<T>,
            f: impl FnOnce(&mut T) -> U,
        ) -> Result<U, wz_session_core::link::LocalHeld> {
            match local.try_borrow_mut() {
                Ok(mut value) => Ok(f(&mut value)),
                Err(_) => Err(wz_session_core::link::LocalHeld),
            }
        }
    };
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

    #[cfg(feature = "session-unicast")]
    one_task_holders!();
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
/// lock to be used without it. A runtime the engine confines to its lock is bound by the contract
/// of `CoopRuntime::confine_tasks`, which its call states.
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

    // No other thread reaches the value (`O`'s contract), so a lend never waits on one.
    const WAITS: bool = false;

    /// No other thread reaches the value (`O`'s contract), so there is never another holder to
    /// find and `f` always runs. The one holder a try could meet is a hold of the value the
    /// calling thread is inside, which the session's code never tries; a face's place, whose
    /// handles do, marks its own lends ([`FacePlace::try_lend`]).
    #[inline]
    fn try_with<T: Send + 'static, U>(
        mutex: &Self::Mutex<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Option<U> {
        Some(mutex.with(f))
    }

    #[cfg(feature = "session-unicast")]
    one_task_holders!();
}

/// A kind whose hold of a value can be a value of its own, let go of as it drops, beside the
/// closure [`LockKind::with`] runs the value in: what a holder that keeps the value across
/// calls of its own takes ([`FacePlace::hold_lent`]). A kind whose hold is a section of the
/// whole program, entered and left around a closure, has none.
#[cfg(feature = "runtime")]
pub trait HoldKind: LockKind {
    /// A hold of a value of `T`, which reaches it until it drops.
    type Hold<'a, T>: core::ops::DerefMut<Target = T>
    where
        T: Send + 'static;

    /// Hold the value of `mutex`, waiting for whatever holds it now, as [`LockKind::with`]
    /// waits.
    fn hold<T: Send + 'static>(mutex: &Self::Mutex<T>) -> Self::Hold<'_, T>;
}

#[cfg(feature = "runtime")]
impl<O: ConfinedOwner> HoldKind for Confined<O> {
    type Hold<'a, T>
        = OwnerHold<'a, T>
    where
        T: Send + 'static;

    #[inline]
    fn hold<T: Send + 'static>(mutex: &Self::Mutex<T>) -> OwnerHold<'_, T> {
        mutex.hold()
    }
}

/// Several threads of a host, each reaching a session's values on its own: each value has its own
/// lock ([`crate::cs::HostMutex`]), the handles on what the session's faces share are counted as
/// an `Arc`'s are, a face's own link handles for one task and moved with the face whole, and its
/// flags and words are atomics. What an engine whose sessions are driven by
/// several threads at once lends, where [`Shared`] stays the kind of a single-core build, whose
/// one task holds its handles and pays no atomic instruction for them.
#[cfg(all(
    feature = "runtime",
    feature = "host-lock",
    target_has_atomic = "8",
    target_has_atomic = "64"
))]
pub enum ManyThreads {}

#[cfg(all(
    feature = "runtime",
    feature = "host-lock",
    target_has_atomic = "8",
    target_has_atomic = "64"
))]
impl LockKind for ManyThreads {
    type Mutex<T>
        = crate::cs::HostMutex<T>
    where
        T: Send + 'static;

    #[inline]
    fn wrap<T: Send + 'static>(value: T) -> Self::Mutex<T> {
        crate::cs::HostMutex::new(value)
    }

    #[inline]
    fn with<T: Send + 'static, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U {
        mutex.with(f)
    }

    #[inline]
    fn try_with<T: Send + 'static, U>(
        mutex: &Self::Mutex<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Option<U> {
        mutex.try_with(f)
    }

    #[cfg(all(feature = "session-unicast", not(feature = "session-slot")))]
    type LinkCount = crate::link_cells::OneFace;
    #[cfg(all(feature = "session-unicast", not(feature = "session-slot")))]
    type SharedCount = crate::link_cells::Atomic;
    #[cfg(feature = "session-unicast")]
    type Flag = core::sync::atomic::AtomicBool;
    #[cfg(feature = "session-unicast")]
    type Word = core::sync::atomic::AtomicU64;
    #[cfg(feature = "session-unicast")]
    type Local<T>
        = crate::cs::HostMutex<T>
    where
        T: Send + 'static;

    #[cfg(feature = "session-unicast")]
    #[inline]
    fn new_local<T: Send + 'static>(value: T) -> Self::Local<T> {
        crate::cs::HostMutex::new(value)
    }

    #[cfg(feature = "session-unicast")]
    #[inline]
    fn with_local<T: Send + 'static, U>(
        local: &Self::Local<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Result<U, wz_session_core::link::LocalHeld> {
        Ok(local.with(f))
    }
}

/// A hold of a value of several threads is a hold of the value's own lock, let go of as it drops.
#[cfg(all(
    feature = "runtime",
    feature = "host-lock",
    target_has_atomic = "8",
    target_has_atomic = "64"
))]
impl HoldKind for ManyThreads {
    type Hold<'a, T>
        = crate::cs::HostHold<'a, T>
    where
        T: Send + 'static;

    #[inline]
    fn hold<T: Send + 'static>(mutex: &Self::Mutex<T>) -> crate::cs::HostHold<'_, T> {
        mutex.hold()
    }
}

/// A value of a session reached only under the lock of the engine `O` that owns the session, and
/// so taking no lock of its own: [`Self::with`] is the closure called on the value.
///
/// A value is never taken inside its own hold: the session's code does not nest one value in
/// itself (a lock of the value would wait on itself there). A debug build checks it, and fails at
/// the nested take instead of handing out a second `&mut`. A release build keeps no mark of a
/// hold on the value, so its every take is the closure's call alone; the one value whose handles
/// try it from inside its own hold, a face's place, keeps its own ([`FacePlace::try_lend`]).
#[cfg(feature = "runtime")]
pub struct OwnerHeld<T, O: ConfinedOwner> {
    value: UnsafeCell<T>,
    /// Whether a closure is inside the value now.
    #[cfg(debug_assertions)]
    inside: Cell<bool>,
    owner: PhantomData<fn() -> O>,
}

// SAFETY: the value is reached only inside `with` and a hold, and `O`'s `unsafe impl
// ConfinedOwner` states that they are made by one thread at a time, which is what `Sync` asks of
// a value that is `Send`. The debug build's flag is read and written inside the same calls.
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

/// A hold of an [`OwnerHeld`] value as a value of its own ([`OwnerHeld::hold`]): the value is
/// reached through it until it drops, and not taken again meanwhile, as inside
/// [`OwnerHeld::with`] (checked in a debug build).
#[cfg(feature = "runtime")]
pub struct OwnerHold<'a, T> {
    value: &'a UnsafeCell<T>,
    #[cfg(debug_assertions)]
    _inside: Inside<'a>,
}

#[cfg(feature = "runtime")]
impl<T, O: ConfinedOwner> OwnerHeld<T, O> {
    /// [`Self::with`] as a value, let go of as it drops.
    #[inline]
    pub fn hold(&self) -> OwnerHold<'_, T> {
        OwnerHold {
            value: &self.value,
            #[cfg(debug_assertions)]
            _inside: Inside::enter(&self.inside),
        }
    }
}

#[cfg(feature = "runtime")]
impl<T> core::ops::Deref for OwnerHold<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: as in `OwnerHeld::with`: one thread at a time reaches the value (`O`'s
        // contract), and it is not taken again while the hold lives (checked in a debug build),
        // so no other reference to it is made meanwhile; the borrow is the hold's own.
        unsafe { &*self.value.get() }
    }
}

#[cfg(feature = "runtime")]
impl<T> core::ops::DerefMut for OwnerHold<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `Deref`, the hold borrowed mutably, so this is the one reference.
        unsafe { &mut *self.value.get() }
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

/// The transport of one face of a session that keeps one for each face, behind a lock of kind
/// `K`: the place the face policy keeps for a face, lent under the lock
/// ([`TransportPlace`](wz_session_core::transport_place::TransportPlace)). A face whose link is
/// not up holds none. The lock is the face's own, so a face's receive and a send on another face
/// do not wait for each other, and a send on this face waits only for what holds this face.
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
pub struct FacePlace<K: LockKind, X: Send + 'static> {
    place: K::Mutex<Option<X>>,
    /// Whether a lend of the place is under way (`LentMark`), marked only for a kind whose lend
    /// never waits ([`LockKind::WAITS`]): such a kind's values are reached by one thread,
    /// so the one holder a try can meet is a lend of the calling thread, which the kind's own try
    /// does not see. A lock's try finds its holder itself, and its kind marks nothing here.
    lent: core::sync::atomic::AtomicBool,
}

/// What a lend of a [`FacePlace`] that does not wait came to ([`FacePlace::try_lend`]).
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lend<U> {
    /// The face's transport was lent, and the call answered this.
    Lent(U),
    /// The face holds no transport: its link is not up. Nothing ran.
    Empty,
    /// Another thread holds the face now, or the calling thread is inside a hold of it. Nothing
    /// ran, and nothing waited.
    Held,
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<K: LockKind, X: Send + 'static> FacePlace<K, X> {
    /// A place that holds no transport yet.
    pub fn empty() -> Self {
        Self {
            place: K::wrap(None),
            lent: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Put `transport` in the place, as the face's link comes up, and answer the one it held.
    pub fn hold(&self, transport: X) -> Option<X> {
        K::with(&self.place, |place| place.replace(transport))
    }

    /// Take the transport out of the place, as the face goes; `None` when it held none.
    pub fn take(&self) -> Option<X> {
        K::with(&self.place, Option::take)
    }

    /// `f` on the place itself, waiting for whatever holds it now: a change of the transport
    /// made together with what lies beside the place, with no holder of the transport between.
    pub fn with_place<U>(&self, f: impl FnOnce(&mut Option<X>) -> U) -> U {
        K::with(&self.place, f)
    }

    /// Lend the transport to `f` when no other thread holds the face now, and wait for nothing:
    /// a droppable send that finds the face held is dropped on this face alone, as zenoh-pico
    /// drops one that finds its transmit lock held
    /// (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
    /// `return _z_mutex_try_lock(&ztc->_mutex_tx);`). A try made inside a lend of the place on
    /// the calling thread finds it held, on every kind: a handle that reaches the place from inside
    /// the holder's own step (a read of the face's facts) tries it.
    pub fn try_lend<U>(&self, f: impl FnOnce(&mut X) -> U) -> Lend<U> {
        if !K::WAITS && self.lent.load(core::sync::atomic::Ordering::Relaxed) {
            return Lend::Held;
        }
        let lent = K::try_with(&self.place, |place| {
            let _lent = LentMark::enter::<K>(&self.lent);
            place.as_mut().map(f)
        });
        match lent {
            None => Lend::Held,
            Some(None) => Lend::Empty,
            Some(Some(answer)) => Lend::Lent(answer),
        }
    }

    /// Run `f` on what the place holds, a transport or none, when no other thread holds the face
    /// now, and wait for nothing: `None`, with `f` not run, while another thread holds it or the
    /// calling thread is inside a hold of it, as [`Self::try_lend`] finds it. What a holder that
    /// must not wait for the face (one that holds the session's lock) puts in the place or takes
    /// out of it goes through here.
    pub fn try_with_place<U>(&self, f: impl FnOnce(&mut Option<X>) -> U) -> Option<U> {
        if !K::WAITS && self.lent.load(core::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        K::try_with(&self.place, |place| {
            let _lent = LentMark::enter::<K>(&self.lent);
            f(place)
        })
    }

    /// Lend the transport to `f`, waiting for whatever holds the face now; `None`, with `f` not
    /// run, while the place holds none. A debug build fails a wait made under a lock that bars
    /// one ([`NoFaceWait`]): the session's lock is waited on inside a face's lend, so its holder
    /// only tries a face. A kind whose lend never waits ([`LockKind::WAITS`]) is lent anywhere.
    #[inline]
    pub fn lend<U>(&self, f: impl FnOnce(&mut X) -> U) -> Option<U> {
        debug_assert!(
            !(K::WAITS && NoFaceWait::any_here()),
            "a face's place is waited on under a lock that bars it"
        );
        K::with(&self.place, |place| {
            let _lent = LentMark::enter::<K>(&self.lent);
            place.as_mut().map(f)
        })
    }
}

/// A lend of a [`FacePlace`] under way, marked in the place from its making to its drop, on return
/// and on unwind alike, for a kind whose lend never waits ([`FacePlace::try_lend`]); nothing is
/// marked for any other kind.
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
struct LentMark<'a>(Option<&'a core::sync::atomic::AtomicBool>);

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<'a> LentMark<'a> {
    /// Mark `lent`, a place's, for a lend of kind `K`.
    #[inline(always)]
    fn enter<K: LockKind>(lent: &'a core::sync::atomic::AtomicBool) -> Self {
        if K::WAITS {
            return Self(None);
        }
        // Read by the one thread that reaches the place's values, the one writing it.
        lent.store(true, core::sync::atomic::Ordering::Relaxed);
        Self(Some(lent))
    }
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl Drop for LentMark<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        if let Some(lent) = self.0 {
            lent.store(false, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A hold of a [`FacePlace`]'s values as a value of its own ([`FacePlace::hold_lent`]): the
/// kind's hold of them, and the place's mark of a lend under way, both let go of as it drops, the
/// mark first.
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
pub struct PlaceHold<'a, K: HoldKind, X: Send + 'static> {
    _lent: LentMark<'a>,
    hold: K::Hold<'a, Option<X>>,
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<K: HoldKind, X: Send + 'static> core::ops::Deref for PlaceHold<'_, K, X> {
    type Target = Option<X>;

    #[inline]
    fn deref(&self) -> &Option<X> {
        &self.hold
    }
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<K: HoldKind, X: Send + 'static> core::ops::DerefMut for PlaceHold<'_, K, X> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Option<X> {
        &mut self.hold
    }
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<K: HoldKind, X: Send + 'static> FacePlace<K, X> {
    /// [`Self::lend`] as a value: the transport, held until the hold drops, waiting for
    /// whatever holds the face now; `None`, let go of at once, while the place holds none. A
    /// debug build fails a wait made under a lock that bars one, as [`Self::lend`] does.
    #[inline]
    pub fn hold_lent(&self) -> Option<PlaceHold<'_, K, X>> {
        debug_assert!(
            !(K::WAITS && NoFaceWait::any_here()),
            "a face's place is waited on under a lock that bars it"
        );
        let hold = K::hold(&self.place);
        if hold.is_none() {
            return None;
        }
        Some(PlaceHold {
            _lent: LentMark::enter::<K>(&self.lent),
            hold,
        })
    }
}

/// A face's place lends its transport under the face's lock, waiting for whatever holds it
/// ([`FacePlace::lend`]).
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl<K: LockKind, X: Send + 'static> wz_session_core::transport_place::TransportPlace
    for &FacePlace<K, X>
{
    type Transport = X;

    #[inline]
    fn lend<U>(&mut self, f: impl FnOnce(&mut X) -> U) -> Option<U> {
        FacePlace::lend(self, f)
    }
}

/// The mark of a lock held on the calling thread under which no face's place is waited on, from
/// [`Self::enter`] to drop, on return and on unwind alike: the session's state lock, whose holder
/// lends a face by [`FacePlace::try_lend`] alone. A read waits for that lock inside its face's
/// lend, so the one wait between the two runs from a face to the session's lock and no cycle can
/// close; a wait on a face under the lock is the edge that would close one, which
/// [`FacePlace::lend`] fails a debug build on. Kept in a debug build whose critical sections count
/// on `std`'s thread-locals (`host-lock` without `host-lock-sys`); every other build keeps
/// nothing and reads that none is held.
#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
#[must_use = "the mark bars a wait on a face only while it is held"]
pub struct NoFaceWait {
    #[cfg(all(
        debug_assertions,
        feature = "host-lock",
        not(feature = "host-lock-sys")
    ))]
    _marked: (),
}

/// How many holds that bar a wait on a face the calling thread is inside: one inside another is
/// two.
#[cfg(all(
    debug_assertions,
    feature = "host-lock",
    not(feature = "host-lock-sys"),
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
mod no_face_wait {
    extern crate std;

    std::thread_local! {
        pub(super) static DEPTH: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
}

#[cfg(all(
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl NoFaceWait {
    /// Mark the calling thread as holding a lock under which no face is waited on.
    #[inline]
    pub fn enter() -> Self {
        #[cfg(all(
            debug_assertions,
            feature = "host-lock",
            not(feature = "host-lock-sys")
        ))]
        {
            no_face_wait::DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
            Self { _marked: () }
        }
        #[cfg(not(all(
            debug_assertions,
            feature = "host-lock",
            not(feature = "host-lock-sys")
        )))]
        {
            Self {}
        }
    }

    /// Whether the calling thread holds such a lock, as far as the marks say.
    #[inline]
    fn any_here() -> bool {
        #[cfg(all(
            debug_assertions,
            feature = "host-lock",
            not(feature = "host-lock-sys")
        ))]
        {
            no_face_wait::DEPTH.with(|depth| depth.get() != 0)
        }
        #[cfg(not(all(
            debug_assertions,
            feature = "host-lock",
            not(feature = "host-lock-sys")
        )))]
        {
            false
        }
    }
}

#[cfg(all(
    debug_assertions,
    feature = "host-lock",
    not(feature = "host-lock-sys"),
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
impl Drop for NoFaceWait {
    fn drop(&mut self) {
        no_face_wait::DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
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
            "the nested hold left the value, and a try outside every hold of it runs"
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

#[cfg(all(
    test,
    feature = "host-lock",
    feature = "session-unicast",
    target_has_atomic = "8",
    target_has_atomic = "64"
))]
mod many_threads_tests {
    use super::{LockKind, ManyThreads};
    use wz_session_core::runtime_cell::{FlagCell, WordCell};

    type Kind = ManyThreads;

    /// What a session of several threads holds crosses threads, and a value reached one holder
    /// at a time, a flag and a word written by four threads at once keep every write. Turned red
    /// by a kind whose flag, word or local is a cell, which is not `Sync` and loses writes.
    #[test]
    fn what_several_threads_hold_keeps_every_write() {
        extern crate std;
        fn crosses<T: Send + Sync>() {}
        crosses::<<Kind as LockKind>::Flag>();
        crosses::<<Kind as LockKind>::Word>();
        crosses::<<Kind as LockKind>::Local<u32>>();
        crosses::<<Kind as LockKind>::Mutex<u32>>();
        let local = Kind::new_local(0u32);
        let word = <<Kind as LockKind>::Word as WordCell>::new(0);
        let flag = <<Kind as LockKind>::Flag as FlagCell>::new(false);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..1000 {
                        Kind::with_local(&local, |count| *count += 1)
                            .expect("no access is made inside another");
                        word.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                    flag.store(true, core::sync::atomic::Ordering::Release);
                });
            }
        });
        assert_eq!(Kind::with_local(&local, |count| *count), Ok(4000));
        assert_eq!(word.load(core::sync::atomic::Ordering::Relaxed), 4000);
        assert!(flag.load(core::sync::atomic::Ordering::Acquire));
    }

    /// What the faces of a session of several threads share is counted as an `Arc`'s is, and a
    /// face's own link handles are counted for one task, their cells given back to tables of
    /// atomic flags. Turned red by a kind that counts the shared handles for one task, or a link's
    /// handles atomically.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn a_session_of_several_threads_counts_shared_handles_atomically() {
        use crate::link_cells::{Atomic, CellRc, OneFace};
        let handle: CellRc<u32, <Kind as LockKind>::SharedCount> =
            CellRc::<u32, Atomic>::try_on_heap(5).expect("the heap has room");
        assert_eq!(*handle, 5);
        let link: CellRc<u32, <Kind as LockKind>::LinkCount> =
            CellRc::<u32, OneFace>::try_on_heap(6).expect("the heap has room");
        assert_eq!(*link, 6);
    }

    /// What a session runtime of several threads shares between a link's parts is a handle of
    /// the link's face, held with the face's parts and moved with them whole, so the parts' clones
    /// keep one count; the session's entropy, which every face draws from, is counted as an
    /// `Arc`'s is. Turned red by a runtime whose `SessionRuntime::Shared` is not counted as
    /// [`LockKind::LinkCount`], or whose entropy is not counted across threads (`session_runtime`).
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn a_runtime_of_several_threads_shares_a_links_parts_within_its_face() {
        extern crate std;
        use crate::link_cells::{Atomic, CellRc, FaceHeld, FaceParts, OneFace};
        use wz_session_core::link::{BoxedLinkDriver, SessionRuntime, ShareValues};

        struct Still;

        impl crate::ClockSource for Still {
            fn now_us(&self) -> u64 {
                0
            }
        }

        /// A link's two parts that share one value.
        struct Halves(CellRc<u32, OneFace>, CellRc<u32, OneFace>);

        // SAFETY: both handles on the cell are the two halves, and nothing is bound to a thread.
        unsafe impl FaceParts for Halves {}

        type Runtime = crate::CoopRuntime<Still, dyn BoxedLinkDriver, Kind>;
        let mut face = FaceHeld::gather(|| {
            let shared: CellRc<u32, OneFace> =
                <Runtime as ShareValues>::share(7).expect("the heap has room");
            Halves(shared.clone(), shared)
        });
        let read = std::thread::spawn(move || {
            let read = face.lend(|halves| (*halves.0, CellRc::handles(&halves.1)));
            drop(face);
            read
        })
        .join()
        .expect("the other thread read the face's value");
        assert_eq!(read, (7, 2));
        fn crosses<T: Send + Sync>() {}
        crosses::<<Runtime as SessionRuntime>::EntropyDraw>();
        let _: core::marker::PhantomData<crate::session_runtime::SessionEntropy<Atomic>> =
            core::marker::PhantomData::<<Runtime as SessionRuntime>::EntropyDraw>;
    }
}

#[cfg(all(
    test,
    feature = "runtime",
    feature = "session-unicast",
    any(feature = "alloc", feature = "session-slot")
))]
mod face_place_tests {
    use super::tests::TestOwner;
    use super::{Confined, FacePlace, Lend};
    use wz_session_core::transport_place::TransportPlace;

    type Place = FacePlace<Confined<TestOwner>, u32>;

    /// A face whose lend can wait is tried, and not waited on, while the calling thread holds a
    /// mark that bars a wait on a face, one nested in another as well; a kind whose lend never
    /// waits is lent under it, and a mark dropped or unwound bars nothing after. Turned red by a
    /// wait the mark does not fail (`FacePlace::lend`'s check), a try it fails, or a mark left set
    /// once it is gone, which would fail every later wait on a face on the thread.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_face_is_tried_and_not_waited_on_under_a_mark_that_bars_it() {
        extern crate std;
        use super::NoFaceWait;
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let marked = cfg!(all(debug_assertions, not(feature = "host-lock-sys")));
        let waits = FacePlace::<super::Shared, u32>::empty();
        let confined = Place::empty();
        waits.hold(1);
        confined.hold(2);
        assert_eq!(waits.lend(|transport| *transport), Some(1));
        {
            let _bar = NoFaceWait::enter();
            assert_eq!(waits.try_lend(|transport| *transport), Lend::Lent(1));
            assert_eq!(
                confined.lend(|transport| *transport),
                Some(2),
                "a lend that never waits runs under the mark"
            );
            let waited = catch_unwind(AssertUnwindSafe(|| waits.lend(|transport| *transport)));
            assert_eq!(waited.is_err(), marked, "a wait under the mark");
            drop(NoFaceWait::enter());
            let again = catch_unwind(AssertUnwindSafe(|| waits.lend(|transport| *transport)));
            assert_eq!(
                again.is_err(),
                marked,
                "an inner mark's drop leaves the outer one"
            );
        }
        assert_eq!(
            waits.lend(|transport| *transport),
            Some(1),
            "a dropped mark"
        );
        let unwound = catch_unwind(|| {
            let _bar = NoFaceWait::enter();
            panic!("under the mark");
        });
        assert!(unwound.is_err());
        assert_eq!(
            waits.lend(|transport| *transport),
            Some(1),
            "a mark that unwound bars nothing"
        );
    }

    /// A place lends nothing before its link is up, lends what it holds after, and keeps what a
    /// lend did; taken out, it lends nothing again. Turned red by a lend that runs on an empty
    /// place, or a place that loses what a lend wrote.
    #[test]
    fn a_face_place_lends_what_it_holds_and_nothing_once_emptied() {
        let place = Place::empty();
        let mut ran = false;
        assert_eq!(place.lend(|_| ran = true), None);
        assert!(!ran, "no transport, no call");
        assert_eq!(place.try_lend(|_| ()), Lend::Empty);
        assert_eq!(place.hold(7), None, "the place held nothing before");
        // The session's policy lends a face through the place it keeps, the trait's lend.
        let mut kept = &place;
        assert_eq!(
            TransportPlace::lend(&mut kept, |transport| {
                *transport += 1;
                *transport
            }),
            Some(8)
        );
        assert_eq!(place.try_lend(|transport| *transport), Lend::Lent(8));
        assert_eq!(place.hold(1), Some(8), "a second link answers the first");
        assert_eq!(place.take(), Some(1));
        assert_eq!(place.try_lend(|_| ()), Lend::Empty);
    }

    /// A try on a confined face inside the face's own lend finds it held and runs nothing, as a
    /// handle that reaches the face from inside a read that holds it does; the lend that holds it
    /// keeps what it wrote. Turned red by a try that lends the face it is inside (the place's
    /// mark of its lend, `FacePlace::try_lend`), a second `&mut` of the values.
    #[test]
    fn a_try_inside_a_confined_faces_own_lend_finds_it_held() {
        let place = Place::empty();
        place.hold(4);
        let inside = place.lend(|transport| {
            *transport += 1;
            place.try_lend(|transport| *transport)
        });
        assert_eq!(inside, Some(Lend::Held));
        assert_eq!(place.try_lend(|transport| *transport), Lend::Lent(5));
    }

    /// A try on a confined face inside a hold of its values (`FacePlace::hold_lent`) finds it
    /// held and runs nothing, and lends it again once the hold drops, as once a lend that unwound
    /// is gone; what the hold wrote stays. Turned red by a hold that marks no lend
    /// (`PlaceHold`), a mark that a dropped hold or an unwound lend leaves set, or a try that
    /// lends the values a hold of the thread has.
    #[test]
    fn a_try_inside_a_confined_faces_hold_finds_it_held_until_it_drops() {
        extern crate std;
        let place = Place::empty();
        place.hold(6);
        {
            let mut held = place.hold_lent().expect("the place holds a value");
            if let Some(value) = held.as_mut() {
                *value += 1;
            }
            assert_eq!(place.try_lend(|transport| *transport), Lend::Held);
        }
        assert_eq!(place.try_lend(|transport| *transport), Lend::Lent(7));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            place.lend(|transport| {
                if *transport == 7 {
                    panic!("inside the lend");
                }
            });
        }));
        assert!(unwound.is_err());
        assert_eq!(
            place.try_lend(|transport| *transport),
            Lend::Lent(7),
            "an unwound lend is not found"
        );
    }

    /// A place that holds nothing is held by no hold, and marks no lend: a try after it lends
    /// the value put in the place then. Turned red by a hold of an empty place that leaves the
    /// place marked as lent (`FacePlace::hold_lent`).
    #[test]
    fn a_hold_of_an_empty_confined_face_marks_nothing() {
        let place = Place::empty();
        assert!(place.hold_lent().is_none());
        place.hold(2);
        assert_eq!(place.try_lend(|transport| *transport), Lend::Lent(2));
    }

    /// A send that does not wait finds a face another thread holds and runs nothing, and finds
    /// it again once that thread lets go. Turned red by a try that waits, or one that lends a
    /// held face.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_try_on_a_face_another_thread_holds_runs_nothing() {
        extern crate std;
        let place = FacePlace::<super::Shared, u32>::empty();
        place.hold(3);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let shared = &place;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                shared.lend(|_| {
                    held_tx.send(()).ok();
                    go_rx.recv().ok();
                });
            });
            held_rx.recv().ok();
            assert_eq!(place.try_lend(|transport| *transport), Lend::Held);
            go_tx.send(()).ok();
        });
        assert_eq!(place.try_lend(|transport| *transport), Lend::Lent(3));
    }
}
