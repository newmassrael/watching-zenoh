// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The holders of a session's engine. The engine lies in its session's own arena, counted by its
//! holders there ([`EngineHold`]), so the open takes no memory of the heap for it; it is reached
//! without being held ([`EngineHandle`]) through the row of the process's table it was put in at
//! its open (`wz_capi_port::reach`), which its close takes it out of, so a handle kept past the
//! close reaches nothing, whatever still holds the engine.

use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;

#[cfg(feature = "query")]
use wz_capi_port::cancellation::FanCanceller;
use wz_capi_port::reach::{ReachEngine, Reachable};
use wz_capi_port::EngineHolder;
use wz_runtime_coop::kept::Shared;

use super::{ClockSource, CoopEngine, CoopLinks};

/// A holder of a session's engine: cloning takes a count of the engine, dropping gives it back,
/// and the last holder drops the engine where it lies and gives the session's arena back.
pub struct EngineHold<E>(Shared<E>);

impl<E> EngineHold<E> {
    /// The holder `shared` is, of an engine the open placed.
    pub(super) fn of(shared: Shared<E>) -> Self {
        Self(shared)
    }

    /// Where the engine lies.
    pub fn as_ptr(this: &Self) -> *const E {
        Shared::as_ptr(&this.0).as_ptr().cast_const()
    }

    /// Whether the two hold the same engine.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Shared::ptr_eq(&this.0, &other.0)
    }

    /// How many holders the engine has now, `this` among them.
    pub fn holders(this: &Self) -> usize {
        Shared::holders(&this.0)
    }
}

impl<E> Clone for EngineHold<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E> Deref for EngineHold<E> {
    type Target = E;

    fn deref(&self) -> &E {
        &self.0
    }
}

impl<E> AsRef<E> for EngineHold<E> {
    fn as_ref(&self) -> &E {
        &self.0
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> EngineHold<CoopEngine<L, C>> {
    /// A reach of the engine that keeps nothing of it standing.
    pub fn downgrade(this: &Self) -> EngineHandle<CoopEngine<L, C>> {
        EngineHandle::reaching(this.reach)
    }
}

/// A reach of a session's engine that keeps nothing of it standing: a row of the process's table
/// and the generation the row was at when the engine was put in it, two words copied freely.
/// It reaches the engine while the session is open and one of the engine's holders is left.
pub struct EngineHandle<E> {
    reach: ReachEngine,
    engine: PhantomData<fn() -> E>,
}

impl<E> Clone for EngineHandle<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for EngineHandle<E> {}

impl<E> EngineHandle<E> {
    /// A handle of no engine, which reaches nothing: what a holder made with no session holds.
    pub const fn vacant() -> Self {
        Self::reaching(ReachEngine::vacant())
    }

    /// The handle of the engine `reach` reaches.
    pub(super) const fn reaching(reach: ReachEngine) -> Self {
        Self {
            reach,
            engine: PhantomData,
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> EngineHandle<CoopEngine<L, C>> {
    /// A holder of the engine, while its session is open and one of its holders is left.
    pub fn upgrade(&self) -> Option<EngineHold<CoopEngine<L, C>>> {
        let engine = self.reach.reach()?.into_raw().cast::<CoopEngine<L, C>>();
        // SAFETY: the row holds, at the generation the handle names, the engine the handle was
        // made of, which is of this type and lies where its open placed it (`engine_of`); the
        // count the reach took is handed over.
        Some(EngineHold(unsafe { Shared::from_counted(engine) }))
    }

    /// Whether the engine's session is open: the engine is in its row and no close or step ended
    /// the session. Read from the row's mark, with no lock and no count of the engine
    /// ([`ReachEngine::is_current`]).
    pub fn is_open(&self) -> bool {
        self.reach.is_current()
    }

    /// Whether this is a handle of `engine`, open or closed.
    pub fn is_of(&self, engine: &CoopEngine<L, C>) -> bool {
        self.reach == engine.reach
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> EngineHolder
    for EngineHold<CoopEngine<L, C>>
{
    type Handle = EngineHandle<CoopEngine<L, C>>;

    fn downgrade(this: &Self) -> Self::Handle {
        Self::downgrade(this)
    }

    fn upgrade(handle: &Self::Handle) -> Option<Self> {
        handle.upgrade()
    }

    /// The row's mark answers, with no lock and no count of the engine ([`EngineHandle::is_open`]).
    fn handle_closed(handle: &Self::Handle) -> bool {
        !handle.is_open()
    }

    fn ptr_eq(this: &Self, other: &Self) -> bool {
        Self::ptr_eq(this, other)
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// A holder of this engine, taken while one of its holders is left.
    #[cfg(feature = "threads")]
    pub(super) fn hold(&self) -> Option<EngineHold<Self>> {
        // SAFETY: every engine lies where its open placed it, the value of a `Shared`, and its
        // place stands while `self` is borrowed.
        unsafe { Shared::retain_live(NonNull::from(self)) }.map(EngineHold)
    }
}

// SAFETY: every engine lies where its open placed it (`engine_of`), the value of a `Shared` counted
// by its holders: a count is taken only while one is held. The engine is taken out of its row at
// its close and first in its drop, before its place is given back.
unsafe impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Reachable
    for CoopEngine<L, C>
{
    fn retain_live(&self) -> bool {
        // SAFETY: as the impl's: the engine is the value of a `Shared` whose place stands.
        match unsafe { Shared::retain_live(NonNull::from(self)) } {
            Some(held) => {
                // The count is the caller's now, given back by `release`.
                core::mem::forget(held);
                true
            }
            None => false,
        }
    }

    unsafe fn release(&self) {
        // SAFETY: the caller's: the count `retain_live` took, given back once.
        drop(unsafe { Shared::from_counted(NonNull::from(self)) });
    }

    #[cfg(feature = "query")]
    fn canceller(&self) -> Option<&dyn FanCanceller> {
        Some(self)
    }
}
