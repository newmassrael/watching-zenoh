// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `CoopLocalSet`: the runtime's task table taking futures that need not be `Send`.
//!
//! The MCU session's action bundle is `Rc`-backed and `!Send` on purpose (that `Rc` is what
//! reaches ARMv6-M, where `alloc::sync::Arc` does not exist), so the `Runtime::spawn` contract,
//! whose futures are `Send`, cannot host a session. A cell of the task table
//! ([`crate::executor`]) holds a future as bytes and its type is not part of the cell, so there is
//! ONE pool: `spawn_local` writes a future that need not be `Send` into the same table
//! `Runtime::spawn` writes one that is, and one pass of [`CoopLocalSet::run_until_idle`] polls
//! both. What keeps a local task local is the set itself, which is `!Send` and whose handles are
//! `!Send`: nothing that can move a `!Send` future across threads can reach it.
//!
//! A table that cannot take a task (a fixed one that is full, or a task too large for its cells)
//! refuses it, counted. On the slot profile `spawn_local` hands the refusal back
//! ([`SpawnRefused`]); on the heap profile, whose callers were written against a table that
//! always grew, `spawn_local` answers a handle that reads `Err(Shutdown)` as `Runtime::spawn`
//! does, and [`CoopLocalSet::try_spawn_local`] hands the refusal back.

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use wz_runtime_core::RuntimeError;

use crate::atomic::{AtomicBool, Ordering};
use crate::executor::{flag_waker, SpawnRefusal, SpawnRefused, TaskJoin};
use crate::runtime_impl::CoopRuntime;
use crate::time::ClockSource;

/// Handle returned by [`CoopLocalSet::spawn_local`]. Implements
/// `Future<Output = Result<T, RuntimeError>>`, mirroring
/// [`crate::CoopJoinHandle`], with NO `T: Send` bound, and `!Send` itself.
pub struct CoopLocalJoinHandle<T> {
    join: TaskJoin<T>,
    /// A local handle stays on the thread of its set.
    local: PhantomData<*const ()>,
}

impl<T> CoopLocalJoinHandle<T> {
    fn new(join: TaskJoin<T>) -> Self {
        Self {
            join,
            local: PhantomData,
        }
    }

    /// Abort the local task. Same two-step cooperative semantic as
    /// [`crate::CoopJoinHandle::abort`]: the next [`CoopLocalSet::run_until_idle`]
    /// drops the task body, and this handle resolves to `JoinCancelled` at once.
    pub fn abort(&self) {
        self.join.abort();
    }

    /// True once the task has produced a result (natural completion or abort)
    /// that no poll has taken yet, and for a spawn the table refused.
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }
}

impl<T> Future for CoopLocalJoinHandle<T> {
    type Output = Result<T, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.join.poll_join(cx)
    }
}

impl<T> Unpin for CoopLocalJoinHandle<T> {}

/// A `!Send` task pool bound to one [`CoopRuntime`]: a view of the runtime's task
/// table that takes futures that need not be `Send`.
pub struct CoopLocalSet<C: ClockSource> {
    runtime: CoopRuntime<C>,
    local: PhantomData<*const ()>,
}

/// A second handle to the same task pool, on the same thread (the type stays `!Send`): what is
/// spawned through either is polled by a pass of either. A holder that must let the pool's tasks
/// run while it waits, with no reference to the set's owner, keeps one.
impl<C: ClockSource> Clone for CoopLocalSet<C> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            local: PhantomData,
        }
    }
}

impl<C: ClockSource> CoopLocalSet<C> {
    /// Bind a local task pool to `runtime`. The runtime handle is copied, so the
    /// local set and any other holder of the same runtime share one task table and
    /// one timer table.
    pub fn new<D: ?Sized>(runtime: &CoopRuntime<C, D>) -> Self {
        Self {
            runtime: runtime.with_driver(),
            local: PhantomData,
        }
    }

    /// Borrow the runtime this local set pumps.
    pub fn runtime(&self) -> &CoopRuntime<C> {
        &self.runtime
    }

    /// Spawn a `!Send` future as a local task, returning a handle that resolves to
    /// its output, or the future back when no cell takes it.
    ///
    /// The `'static` bound is the same one `Runtime::spawn` carries and for the
    /// same reason: a detached task cannot borrow from the caller's stack.
    pub fn try_spawn_local<F>(
        &self,
        fut: F,
    ) -> Result<CoopLocalJoinHandle<F::Output>, SpawnRefused<F>>
    where
        F: Future + 'static,
    {
        let cell = self.runtime.inner.executor.spawn(fut, true)?;
        Ok(CoopLocalJoinHandle::new(TaskJoin::attached(cell)))
    }

    /// Spawn a `!Send` future as a local task: [`Self::try_spawn_local`], the slot profile's
    /// one form.
    #[cfg(feature = "session-slot")]
    pub fn spawn_local<F>(&self, fut: F) -> Result<CoopLocalJoinHandle<F::Output>, SpawnRefused<F>>
    where
        F: Future + 'static,
    {
        self.try_spawn_local(fut)
    }

    /// Spawn a `!Send` future as a local task, returning a handle that resolves to
    /// its output. A spawn the table refuses (a reserved table that is full) is counted, its
    /// future dropped, and its handle reads `Err(RuntimeError::Shutdown)`, as a refused
    /// `Runtime::spawn` does; a grown table never refuses.
    #[cfg(not(feature = "session-slot"))]
    pub fn spawn_local<F>(&self, fut: F) -> CoopLocalJoinHandle<F::Output>
    where
        F: Future + 'static,
    {
        match self.try_spawn_local(fut) {
            Ok(handle) => handle,
            Err(_refused) => CoopLocalJoinHandle::new(TaskJoin::refused()),
        }
    }

    /// Spawn the task `make` builds, made in its cell: the way to spawn a future that is large,
    /// since no frame holds it and a refusal gives nothing back but its reason. `make` runs only
    /// when a cell is free; a refusal drops it with what it captured.
    pub fn spawn_local_with<F>(
        &self,
        make: impl FnOnce() -> F,
    ) -> Result<CoopLocalJoinHandle<F::Output>, SpawnRefusal>
    where
        F: Future + 'static,
    {
        let cell = self.runtime.inner.executor.spawn_with(make, true)?;
        Ok(CoopLocalJoinHandle::new(TaskJoin::attached(cell)))
    }

    /// One executor pass: the runtime's timer table first, then every ready task
    /// at most once ([`CoopRuntime::run_until_idle`]).
    pub fn run_until_idle(&self) {
        self.runtime.run_until_idle();
    }

    /// Count of this runtime's local tasks that have not ended; a result waiting for its
    /// handle is not one.
    pub fn live_local_task_count(&self) -> usize {
        self.runtime.inner.executor.running_local_count()
    }

    /// True if any task that is waiting has its wake flag set.
    pub fn any_local_ready(&self) -> bool {
        self.runtime.inner.executor.any_ready()
    }

    /// Drive the pool until `handle` resolves, returning the task's output. The
    /// synchronous entry point a deploy `main()` or a host test uses to run a
    /// local task to completion. Allocates nothing.
    ///
    /// Panics if the handle is Pending while nothing can possibly wake it: no
    /// ready task, no live task and no pending timer.
    pub fn block_on_local<T>(&self, handle: CoopLocalJoinHandle<T>) -> Result<T, RuntimeError> {
        // The handle's wake flag is a local of this call, which a waker may point at only while
        // the call lasts. The handle is consumed here and stores the waker only while it is
        // Pending; it clears it on every path out of its poll that answers, and on its drop,
        // which are the only ways out of this function.
        let flag = AtomicBool::new(true);
        // SAFETY: the waker is handed only to `handle`, which gives it up before `flag` goes
        // (above).
        let waker = unsafe { flag_waker(&flag) };
        let mut cx = Context::from_waker(&waker);
        let mut handle = handle;
        loop {
            if flag.swap(false, Ordering::AcqRel) {
                if let Poll::Ready(out) = Pin::new(&mut handle).poll(&mut cx) {
                    return out;
                }
            }
            self.run_until_idle();
            if !flag.load(Ordering::Acquire)
                && !self.any_local_ready()
                && self.live_local_task_count() == 0
                && self.runtime.timers().pending_count() == 0
            {
                panic!(
                    "CoopLocalSet::block_on_local: handle Pending with no \
                     live tasks, no wakers, and no pending timers — \
                     deadlocked future?"
                );
            }
        }
    }
}

#[cfg(all(test, feature = "alloc", not(feature = "session-slot")))]
mod tests {
    use super::CoopLocalSet;
    use crate::runtime_impl::CoopRuntime;
    use crate::time::ClockSource;

    struct Still;

    impl ClockSource for Still {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A clone of a local set is the same pool: a task spawned through one is run by a pass of
    /// the other, and it no longer counts as running after.
    #[test]
    fn a_clone_runs_the_tasks_of_the_set_it_was_cloned_from() {
        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        let other = local.clone();
        let task = local.spawn_local(async { 7u8 });
        assert!(!task.is_finished(), "nothing ran it yet");
        assert_eq!(local.live_local_task_count(), 1);
        other.run_until_idle();
        assert!(task.is_finished(), "the clone's pass ran it");
        assert_eq!(local.live_local_task_count(), 0);
        assert_eq!(local.block_on_local(task).expect("not cancelled"), 7);
    }
}
