// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `CoopLocalSet` on STATIC storage (`session-slot`, fixed-memory step S6): the
//! form of [`crate::local`] the MCU session profile compiles in its place.
//!
//! The heap form kept a second pool for `!Send` futures, a `Vec` of boxed
//! futures behind an `Rc`, because a `!Send` future could not enter the `Send`
//! pool's `Box<dyn Future + Send>`. A cell of the static task table
//! ([`crate::executor::TaskTable`]) holds the future as bytes and its type is not
//! part of the cell, so the two pools are ONE here: `spawn_local` writes a
//! future that need not be `Send` into the same table `Runtime::spawn` writes
//! one that is, and one pass of [`CoopLocalSet::run_until_idle`] polls both. What
//! keeps a local task local is the set itself, which is `!Send` and whose handles
//! are `!Send`: nothing that can move a `!Send` future across threads can reach
//! it.
//!
//! `spawn_local` answers a [`SpawnRefused`] where the heap form could not fail: a
//! full table or a task too large for a cell hands the future back, counted.

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use wz_runtime_core::RuntimeError;

use crate::executor::{SpawnRefused, TaskJoin};
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
    /// Abort the local task. Same two-step cooperative semantic as
    /// [`crate::CoopJoinHandle::abort`]: the next [`CoopLocalSet::run_until_idle`]
    /// drops the task body, and this handle resolves to `JoinCancelled` at once.
    pub fn abort(&self) {
        self.join.abort();
    }

    /// True once the task has produced a result (natural completion or abort)
    /// that no poll has taken yet.
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
    pub fn spawn_local<F>(&self, fut: F) -> Result<CoopLocalJoinHandle<F::Output>, SpawnRefused<F>>
    where
        F: Future + 'static,
    {
        let cell = self.runtime.inner.executor.spawn(fut)?;
        Ok(CoopLocalJoinHandle {
            join: TaskJoin::attached(cell),
            local: PhantomData,
        })
    }

    /// One executor pass: the runtime's timer table first, then every ready task
    /// at most once ([`CoopRuntime::run_until_idle`]).
    pub fn run_until_idle(&self) {
        self.runtime.run_until_idle();
    }

    /// Count of cells that hold a task or a result nobody has read. The local twin
    /// of the heap form's count: there is one pool here, so it is the pool's.
    pub fn live_local_task_count(&self) -> usize {
        self.runtime.inner.executor.live_task_count()
    }

    /// True if any task that is waiting has its wake flag set.
    pub fn any_local_ready(&self) -> bool {
        self.runtime.inner.executor.any_ready()
    }

    /// Drive the pool until `handle` resolves, returning the task's output. The
    /// synchronous entry point a deploy `main()` or a host test uses to run a
    /// local task to completion.
    ///
    /// Panics if the handle is Pending while nothing can possibly wake it: no
    /// ready task, no live task and no pending timer.
    pub fn block_on_local<T>(&self, handle: CoopLocalJoinHandle<T>) -> Result<T, RuntimeError> {
        use crate::atomic::{AtomicBool, Ordering};
        use core::task::{RawWaker, RawWakerVTable, Waker};

        // The handle's wake flag is a local of this call, which a waker may point
        // at only while the call lasts. The handle is consumed here and stores the
        // waker only while it is Pending; it clears it on every path out of its
        // poll that answers, which is the only way out of this function but the
        // panic below.
        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            |data| RawWaker::new(data, &VTABLE),
            |data| {
                // SAFETY: `data` is the address of the flag below, alive for the call.
                unsafe { &*data.cast::<AtomicBool>() }.store(true, Ordering::Release)
            },
            |data| {
                // SAFETY: as above.
                unsafe { &*data.cast::<AtomicBool>() }.store(true, Ordering::Release)
            },
            |_| {},
        );
        let flag = AtomicBool::new(true);
        // SAFETY: the vtable's functions only store the flag, which outlives every
        // use of the waker (it is dropped, with the handle's copy, before return).
        let waker = unsafe {
            Waker::from_raw(RawWaker::new(
                (&flag as *const AtomicBool).cast::<()>(),
                &VTABLE,
            ))
        };
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
