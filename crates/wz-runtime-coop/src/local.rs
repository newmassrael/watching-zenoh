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

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::alloc::Layout;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use core::ptr::NonNull;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::kept::{Kept, Shared};

use crate::atomic::{AtomicBool, Ordering};
use crate::executor::{flag_waker, ClaimedPlace, SpawnRefusal, SpawnRefused, TaskJoin};
use crate::runtime_impl::CoopRuntime;
use crate::sync::LockKind;
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

    /// The handle of a spawn the runtime refused: it reads `Err(RuntimeError::Shutdown)`. The slot
    /// profile hands a refusal back as a value, so only the heap profile makes one.
    #[cfg(not(feature = "session-slot"))]
    pub(crate) fn refused() -> Self {
        Self::new(TaskJoin::refused())
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

/// A cell a local set took for a task of type `F`, its future not yet made in it
/// (`CoopLocalSet::claim_local`): the executor's claim, whose start answers the task's handle.
/// Let go of unstarted, it gives the cell back.
pub(crate) struct LocalPlace<F: Future + 'static>(ClaimedPlace<F>);

impl<F: Future + 'static> LocalPlace<F> {
    /// Write `fut` in this place and start the task.
    fn start_with(self, fut: F) -> CoopLocalJoinHandle<F::Output> {
        CoopLocalJoinHandle::new(TaskJoin::attached(self.0.start_with(fut)))
    }

    /// Where the task's future is written: long enough and aligned for an `F`, and reached by
    /// nothing else until the task starts.
    #[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
    pub(crate) fn as_mut_ptr(&mut self) -> *mut F {
        self.0.as_mut_ptr()
    }

    /// Start the task whose future was written in this place, and answer its handle.
    ///
    /// # Safety
    /// A whole `F` lies at `Self::as_mut_ptr`, written since the claim, and nothing else holds
    /// it.
    #[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
    pub(crate) unsafe fn start_in(self) -> CoopLocalJoinHandle<F::Output> {
        // SAFETY: the caller's contract, which is the claim's.
        let cell = unsafe { self.0.start_in() };
        CoopLocalJoinHandle::new(TaskJoin::attached(cell))
    }
}

/// A `!Send` task pool bound to one [`CoopRuntime`]: a view of the runtime's task
/// table that takes futures that need not be `Send`.
///
/// On the heap profile the set's tasks go when the set's last handle does, as they did when a set
/// kept its own list of them: a session task holds a handle of the runtime, so a task kept by the
/// runtime's table alone would keep itself, its link and its socket, for as long as the process.
/// The slot profile's runtime is a `static` that never ends, and its tasks stay.
pub struct CoopLocalSet<C: ClockSource> {
    runtime: CoopRuntime<C>,
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    owner: Shared<SetOwner<C>>,
    local: PhantomData<*const ()>,
}

/// What every handle of one local set shares: its number, and the runtime whose table its tasks
/// lie in, so the last handle to go drops them.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct SetOwner<C: ClockSource> {
    runtime: CoopRuntime<C>,
    set: u32,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<C: ClockSource> Drop for SetOwner<C> {
    fn drop(&mut self) {
        self.runtime.inner.executor.drop_tasks_of(self.set);
    }
}

/// The number the tasks of the slot profile's local sets are marked with: there is no set to
/// drop them with, so every set has the one number.
#[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
const STATIC_SET: u32 = 1;

/// A second handle to the same local set, on the same thread (the type stays `!Send`): what is
/// spawned through either is polled by a pass of either, and the set's tasks stay while either
/// does. A holder that must let the pool's tasks run while it waits, with no reference to the
/// set's owner, keeps one.
impl<C: ClockSource> Clone for CoopLocalSet<C> {
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            owner: self.owner.clone(),
            local: PhantomData,
        }
    }
}

impl<C: ClockSource> CoopLocalSet<C> {
    /// Bind a local task pool to `runtime`. The runtime handle is copied, so the
    /// local set and any other holder of the same runtime share one task table and
    /// one timer table.
    pub fn new<D: ?Sized, K: LockKind>(runtime: &CoopRuntime<C, D, K>) -> Self {
        let runtime: CoopRuntime<C> = runtime.retyped();
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        let owner = Shared::boxed(SetOwner {
            set: runtime.inner.executor.new_local_set(),
            runtime: runtime.clone(),
        });
        Self {
            runtime,
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            owner,
            local: PhantomData,
        }
    }

    /// The bytes and alignment of the place [`Self::placed`] writes the set's shared owner at.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) const fn owner_layout() -> Layout {
        Shared::<SetOwner<C>>::layout()
    }

    /// [`Self::new`] with the set's shared owner written at `at`, in memory `memory` keeps, a
    /// count of which it holds until the set's last handle lets go: nothing of the heap.
    ///
    /// # Safety
    /// `at` is aligned and valid for a write of [`Self::owner_layout`], and nothing else uses
    /// those bytes while a count of `memory` is held; `memory` is live and its memory holds `at`.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub(crate) unsafe fn placed(
        runtime: &CoopRuntime<C>,
        at: NonNull<u8>,
        memory: NonNull<Kept>,
    ) -> Self {
        let owner = SetOwner {
            set: runtime.inner.executor.new_local_set(),
            runtime: runtime.clone(),
        };
        Self {
            runtime: runtime.clone(),
            // SAFETY: the caller's contract, which is the placing's.
            owner: unsafe { Shared::placed(at, owner, memory) },
            local: PhantomData,
        }
    }

    /// Drop, where it lies, every task of this set that has not ended, whatever handles of the
    /// set are still held, one of its own tasks among them; a handle that waits for one reads
    /// `JoinCancelled`, and the set takes tasks again after. What an owner whose tasks borrow
    /// what it owns calls before it lets go of that: the last handle's drop does the same, but a
    /// handle a task keeps is never the last.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub fn drop_tasks(&self) {
        self.runtime.inner.executor.drop_tasks_of(self.owner.set);
    }

    /// The number this set's tasks are marked with.
    fn set(&self) -> u32 {
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        {
            self.owner.set
        }
        #[cfg(not(all(feature = "alloc", not(feature = "session-slot"))))]
        {
            STATIC_SET
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
        let cell = self.runtime.inner.executor.spawn(fut, self.set())?;
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
            Err(_refused) => CoopLocalJoinHandle::refused(),
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
        Ok(self.claim_local::<F>()?.start_with(make()))
    }

    /// Take a cell for a local task of type `F`, whose future the caller then makes in it, or
    /// refuse, counted: what spawns a task whose parts are written in its cell one by one, so
    /// neither the task nor a value it is built of is moved through a frame.
    pub(crate) fn claim_local<F>(&self) -> Result<LocalPlace<F>, SpawnRefusal>
    where
        F: Future + 'static,
    {
        self.runtime
            .inner
            .executor
            .claim::<F>(self.set())
            .map(LocalPlace)
    }

    /// One executor pass: the runtime's timer table first, then every ready task
    /// at most once ([`CoopRuntime::run_until_idle`]).
    pub fn run_until_idle(&self) {
        self.runtime.run_until_idle();
    }

    /// One executor pass that reads no clock: the timers due by `due_at` woken first when it is
    /// given, then every ready task at most once ([`CoopRuntime::run_ready`]).
    pub fn run_ready(&self, due_at: Option<u64>) {
        self.runtime.run_ready(due_at);
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
    /// Answers `Err(RuntimeError::Stalled)` if the handle is Pending while nothing can possibly
    /// wake it: no ready task, no live task and no pending timer.
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
                return Err(RuntimeError::Stalled);
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
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
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

    /// Marks its drop in the flag it names.
    struct Dropped(alloc::rc::Rc<core::cell::Cell<bool>>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// A set told to drop its tasks drops one that holds a handle of the set itself, which the
    /// last handle's drop never reaches, and leaves another set's task alone; the set takes and
    /// runs a task after. Turned red by a drop that waits for the set's last handle, or drops the
    /// tasks of every set.
    #[test]
    fn a_set_told_to_drop_its_tasks_drops_one_that_holds_the_set() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let other = CoopLocalSet::new(&runtime);
        let mine = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let theirs = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let kept = local.clone();
        let guard = Dropped(mine.clone());
        let task = local.spawn_local(async move {
            let _kept = kept;
            let _guard = guard;
            core::future::pending::<()>().await;
        });
        let guard = Dropped(theirs.clone());
        let _other_task = other.spawn_local(async move {
            let _guard = guard;
            core::future::pending::<()>().await;
        });
        local.run_until_idle();
        assert!(
            !mine.get(),
            "CONTROL: a pending task stays while it is not dropped"
        );
        local.drop_tasks();
        assert!(mine.get(), "the task that held its own set is dropped");
        assert!(!theirs.get(), "another set's task stays");
        assert!(task.is_finished(), "its handle reads the drop");
        let after = local.spawn_local(async { 3u8 });
        assert_eq!(local.block_on_local(after).expect("not cancelled"), 3);
    }
}
