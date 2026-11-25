// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine's form: how its calls stand to its threads, chosen once here, and what that choice
//! decides of the locks the engine's state lies behind.
//!
//! A build with `threads` runs a read task beside the program's calls, so the session's state is
//! behind the host's or the kernel's lock and its rows count their calls on an atomic latch. A
//! build without it makes every call from one thread at a time: the state is behind a flag
//! (`one_thread_lock`) and the latches count with no read-modify-write. Everything that differs
//! between the two is a type of [`LockForm`], so a lock the engine adds (a face's, a link's send
//! half) is the form's lock and not a choice of its own; both forms are compiled in every build
//! and only [`CoopForm`] names the one in force.

mod one_thread_lock;

use core::ops::DerefMut;

use wz_capi_port::os::{Mutex, MutexGuard};
use wz_runtime_coop::sync::{Confined, ConfinedOwner, LockKind};
use wz_session_core::row_callback::{OneThread, ThreadForm, Threads};

use one_thread_lock::{OneThreadGuard, OneThreadLock};

/// How the engine's calls stand to its threads: a read task may deliver beside the program's calls
/// (`threads`), or every call runs on the thread that steps the session.
#[cfg(feature = "threads")]
pub(crate) type CoopForm = Threads;
/// How the engine's calls stand to its threads: a read task may deliver beside the program's calls
/// (`threads`), or every call runs on the thread that steps the session.
#[cfg(not(feature = "threads"))]
pub(crate) type CoopForm = OneThread;

/// The latch each row of the engine's tables counts its calls on: [`CoopForm`]'s.
#[cfg(feature = "threads")]
pub(crate) type Latch = wz_session_core::row_callback::CallLatch;
/// The latch each row of the engine's tables counts its calls on: [`CoopForm`]'s.
#[cfg(not(feature = "threads"))]
pub(crate) type Latch = wz_session_core::row_callback::LocalLatch;

// The latch named above is the one the form names, so a row and the round agree on the form.
const _: fn(Latch) -> <CoopForm as ThreadForm>::Latch = |latch| latch;

/// The lock of a form: what keeps a value of the engine to one thread at a time, held through a
/// guard until it drops.
pub(crate) trait LockForm: ThreadForm {
    /// A value behind the lock.
    type Lock<T>;
    /// A hold of a [`Self::Lock`], let go as it drops.
    type Guard<'a, T: 'a>: DerefMut<Target = T>;

    /// `value`, behind a lock nobody holds.
    fn new<T>(value: T) -> Self::Lock<T>;

    /// The value, held until the guard drops; a take while it is held waits until it is not.
    fn lock<'a, T: 'a>(lock: &'a Self::Lock<T>) -> Self::Guard<'a, T>;

    /// The value, held until the guard drops; `None`, without waiting, while it is held.
    fn try_lock<'a, T: 'a>(lock: &'a Self::Lock<T>) -> Option<Self::Guard<'a, T>>;

    /// The value, through the only reference there is.
    fn get_mut<T>(lock: &mut Self::Lock<T>) -> &mut T;

    /// How the session's runtime holds what it lends each link's session ([`SessionLock`]).
    type SessionLock: LockKind;
}

/// Other threads may call in: the host's lock, or the kernel's.
impl LockForm for Threads {
    type Lock<T> = Mutex<T>;
    type Guard<'a, T: 'a> = MutexGuard<'a, T>;
    // Several threads drive the session's faces: each value a link's session is lent has a lock of
    // its own, what the faces share is counted across threads, and a link's own handles are
    // counted for one task and move between threads with their face whole. A host lock is what
    // makes those locks; a build with none keeps every value under the session's one lock.
    #[cfg(all(
        any(feature = "std", feature = "host-sys"),
        target_has_atomic = "8",
        target_has_atomic = "64"
    ))]
    type SessionLock = wz_runtime_coop::sync::ManyThreads;
    #[cfg(not(all(
        any(feature = "std", feature = "host-sys"),
        target_has_atomic = "8",
        target_has_atomic = "64"
    )))]
    type SessionLock = Confined<UnderCoreLock>;

    #[inline]
    fn new<T>(value: T) -> Mutex<T> {
        Mutex::new(value)
    }

    #[inline]
    fn lock<'a, T: 'a>(lock: &'a Mutex<T>) -> MutexGuard<'a, T> {
        lock.lock()
    }

    #[inline]
    fn try_lock<'a, T: 'a>(lock: &'a Mutex<T>) -> Option<MutexGuard<'a, T>> {
        lock.try_lock()
    }

    #[inline]
    fn get_mut<T>(lock: &mut Mutex<T>) -> &mut T {
        lock.get_mut()
    }
}

/// One thread at a time: a flag, as zenoh-pico's lock is nothing without its threads.
impl LockForm for OneThread {
    type Lock<T> = OneThreadLock<T>;
    type Guard<'a, T: 'a> = OneThreadGuard<'a, T>;
    type SessionLock = Confined<UnderCoreLock>;

    #[inline]
    fn new<T>(value: T) -> OneThreadLock<T> {
        OneThreadLock::new(value)
    }

    #[inline]
    fn lock<'a, T: 'a>(lock: &'a OneThreadLock<T>) -> OneThreadGuard<'a, T> {
        lock.lock()
    }

    #[inline]
    fn try_lock<'a, T: 'a>(lock: &'a OneThreadLock<T>) -> Option<OneThreadGuard<'a, T>> {
        lock.try_lock()
    }

    #[inline]
    fn get_mut<T>(lock: &mut OneThreadLock<T>) -> &mut T {
        lock.get_mut()
    }
}

/// A value behind the lock of the engine's form.
pub(crate) type StateLock<T> = <CoopForm as LockForm>::Lock<T>;

/// A hold of a [`StateLock`].
pub(crate) type StateGuard<'a, T> = <CoopForm as LockForm>::Guard<'a, T>;

/// The owner of the values the session's runtime lends its links' sessions: the session's lock
/// (`CoreLock`), under which alone they are reached, so they take no lock of their own
/// ([`SessionLock`]).
pub(crate) enum UnderCoreLock {}

// SAFETY: the values a runtime of `Confined<UnderCoreLock>` lends are the state of the session's
// links (their actions, link states and kernels), all owned by the `Core` inside a `Confined` and
// reached by one thread at a time on the ground the engine's `Send` of `Confined` states: every
// path to them holds the session's `CoreLock` (the links' tasks run in `Core::run_tasks`, under
// `&mut Core`), the engine's drop reaches them with the lock's value owned (`CoreLock::dropping`),
// and no handle of them is handed out of the lock. The session's runtime is confined to the lock
// the same way (the open's `confine_tasks`): it and its local set are the `Core`'s, its tasks are
// spawned and run and their handles held by the `Core` alone, and the group's pace holds the set
// in an `Rc`.
unsafe impl ConfinedOwner for UnderCoreLock {}

/// How the session's runtime holds what it lends a link's session: the form's choice
/// ([`LockForm::SessionLock`]), made here once for the engine.
pub(crate) type SessionLock = <CoopForm as LockForm>::SessionLock;

/// How the handles on the parts of one link are counted under [`SessionLock`]: the stacks the
/// engine opens its links over serve sessions counted so. Named by the crate's concrete kind
/// rather than as the lock kind's projection, so a bound that names it (`CoopLinks`) states one
/// trait: a supertrait over the projection is seen beside its normalized form, and a shorthand
/// such as `L::Pump` in a body is then ambiguous between the two.
pub(crate) use crate::LinkCount;

// The crate's kind is the one the form's lock kind counts a link's parts by, in every build.
const _: fn(
    core::marker::PhantomData<<SessionLock as LockKind>::LinkCount>,
) -> core::marker::PhantomData<LinkCount> = core::convert::identity;

/// How the handles on what the session's faces share are counted under [`SessionLock`]: the
/// session's entropy handle is counted so.
pub(crate) type SharedCount = <SessionLock as LockKind>::SharedCount;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{CoopForm, LockForm, UnderCoreLock};
    use core::marker::PhantomData;
    use wz_runtime_coop::sync::{Confined, LockKind};
    use wz_session_core::row_callback::{OneThread, ThreadForm, Threads};

    /// A take of `F`'s lock holds the value until its guard drops: a try meanwhile finds it
    /// held, one after takes it with what the hold wrote, and the value owned whole is that too.
    fn a_take_holds_until_its_guard_drops<F: LockForm>() {
        let mut lock = F::new(1_u8);
        let mut held = F::lock(&lock);
        *held = 2;
        assert!(F::try_lock(&lock).is_none(), "held, a try takes nothing");
        drop(held);
        assert_eq!(
            F::try_lock(&lock).map(|value| *value),
            Some(2),
            "let go, a try takes what the hold wrote"
        );
        assert_eq!(
            *F::get_mut(&mut lock),
            2,
            "owned whole, the value is the last written"
        );
    }

    /// Both forms' locks keep a value as a lock does. Turned red by a form whose guard does not
    /// let go as it drops, or whose try takes a held value.
    #[test]
    fn each_forms_lock_holds_its_value_until_the_guard_drops() {
        a_take_holds_until_its_guard_drops::<Threads>();
        a_take_holds_until_its_guard_drops::<OneThread>();
    }

    /// A stack that serves the sessions the form's lock counts is a stack the engine opens its
    /// links over, whichever form is in force. Turned red by an engine bound that does not follow
    /// the link count of `SessionLock`.
    #[cfg(feature = "app-transport")]
    #[test]
    fn a_stack_of_the_session_locks_count_is_an_engines_stack() {
        fn opens_over<L: crate::CoopLinks>() -> bool {
            true
        }
        assert!(opens_over::<crate::app_link::AppLinks<super::LinkCount>>());
    }

    /// The form in force is the one the build's `threads` names: other threads call in exactly
    /// when it is on. Turned red by a choice of the form that does not follow the feature.
    #[test]
    fn the_form_in_force_follows_the_threads_feature() {
        assert_eq!(
            <CoopForm as ThreadForm>::OTHER_THREADS,
            cfg!(feature = "threads")
        );
    }

    /// The one-thread form lends a link's session its values under the session's one lock, with no
    /// lock of their own; the form of several threads gives each value its own lock, counts what
    /// the faces share across threads and a link's own handles for one task. Turned red, at
    /// build, by a form whose `SessionLock` is another kind.
    #[test]
    fn each_form_lends_a_links_values_under_its_own_lock_kind() {
        fn same<T>(_: PhantomData<T>, _: PhantomData<T>) {}
        same(
            PhantomData::<<Threads as LockForm>::SessionLock>,
            PhantomData::<wz_runtime_coop::sync::ManyThreads>,
        );
        same(
            PhantomData::<<<Threads as LockForm>::SessionLock as LockKind>::LinkCount>,
            PhantomData::<wz_runtime_coop::link_cells::OneFace>,
        );
        same(
            PhantomData::<<<Threads as LockForm>::SessionLock as LockKind>::SharedCount>,
            PhantomData::<wz_runtime_coop::link_cells::Atomic>,
        );
        same(
            PhantomData::<<super::SessionLock as LockKind>::LinkCount>,
            PhantomData::<crate::LinkCount>,
        );
        same(
            PhantomData::<<OneThread as LockForm>::SessionLock>,
            PhantomData::<Confined<UnderCoreLock>>,
        );
    }
}
