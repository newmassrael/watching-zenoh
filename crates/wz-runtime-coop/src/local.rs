// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `CoopLocalSet` — the `!Send` task pool that lets the MCU session ride
//! the cooperative executor.
//!
//! ## Why this module exists
//!
//! [`wz_runtime_core::Runtime::spawn`] requires `F: Future + Send +
//! 'static`, and that bound is not negotiable: the trait is
//! `Runtime: Send + Sync`, so every `Runtime`-generic call site may move a
//! spawned task across threads and the AP profile actually does.
//!
//! The MCU session bundle, however, is `!Send` **by construction** and
//! deliberately so — this crate's `session_runtime` module (behind the
//! `session-unicast` feature, hence named here rather than linked) binds
//! `LinkSink = Rc<dyn BoxedLinkDriver>` and
//! `ActionsHandle<T> = Rc<SessionLinkActions<..>>`
//! because the single-task profile never sends the bundle anywhere and
//! `alloc::sync::Arc` needs `target_has_atomic = "ptr"`, which ARMv6-M
//! (Cortex-M0/M0+) does not have. Making the bundle `Send` to satisfy
//! `spawn` would wall the MCU session off the very targets the `Rc`
//! choice exists to reach.
//!
//! So the two ends are both right and simply do not meet. The consequence
//! before this module: the MCU session could not be a task at all. It ran
//! as a caller-owned synchronous pump that *called* `run_until_idle`
//! rather than running *inside* it, so the executor hosted keepalive
//! workers and timers while the session — the one thing the profile
//! exists to run — stayed outside. The AP sibling carries the whole
//! session on `TokioRuntime::spawn` by contrast.
//!
//! ## The shape
//!
//! `CoopLocalSet` is the well-established answer to exactly this split:
//! tokio solves the same `!Send`-future problem with a `LocalSet` carrying
//! its own `spawn_local`. The local set is itself `!Send` (it holds
//! `Rc<RefCell<..>>`), which is what lets its task slots drop the `Send`
//! bound without touching the `Runtime` contract or the `Send + Sync`
//! bound on `CoopRuntime`. A `!Send` handle can only ever be used from the
//! one task that owns it, so a `!Send` future parked in it can never be
//! polled from a second thread — the invariant `Send` was protecting is
//! preserved structurally rather than by a bound.
//!
//! [`CoopLocalSet::run_until_idle`] drives the runtime's shared (`Send`)
//! pool first — timers, then Send tasks — and then its own local tasks, so
//! ONE pump call advances everything and a local task that spawns a `Send`
//! task still sees it polled. That ordering is the same "deadlines before
//! the tasks they wake" rule [`CoopRuntime::run_until_idle`] documents,
//! extended one slot further.
//!
//! ## What is deliberately NOT here
//!
//! - **No `Runtime` trait impl.** `spawn_local` is an inherent method on a
//!   concrete `!Send` type, not a trait extension. Putting it on `Runtime`
//!   would oblige every profile to answer "what is a local task here?",
//!   and for the multi-threaded AP profile the honest answer needs tokio's
//!   whole `LocalSet` scheduling machinery. Profile-side capability, like
//!   [`crate::CoopJoinHandle::abort`] already is.
//! - **No slot recycling**, for the same re-entrancy reason
//!   [`crate::executor`] gives: a task polled from inside `run_until_idle`
//!   has its slot temporarily vacated, so a re-entrant `spawn_local`
//!   choosing a `None` slot would be overwritten by the Pending-restore.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use wz_runtime_core::RuntimeError;

use crate::atomic::{Arc, AtomicBool, Ordering};
use crate::executor::make_waker;
use crate::runtime_impl::CoopRuntime;
use crate::time::ClockSource;

/// Type-erased local task body. The `Send`-free twin of
/// [`crate::executor::BoxFuture`] — that is the whole point of the module.
type LocalBoxFuture = Pin<Box<dyn Future<Output = ()>>>;

struct LocalTaskSlot {
    fut: LocalBoxFuture,
    wake_flag: Arc<AtomicBool>,
    cancel_flag: Arc<AtomicBool>,
}

/// Completion / waker slot shared between a local spawn wrapper and the
/// handle the caller holds.
///
/// `Rc<RefCell<..>>`, not the `Arc<critical_section::Mutex<RefCell<..>>>`
/// the `Send` sibling uses: a local task and its handle live in the same
/// single task by construction, so there is no interrupt or thread to lock
/// against and an atomic refcount would be pure waste — the same reasoning
/// that put `Rc` in the `session_runtime` binding, and the same reason it
/// reaches ARMv6-M.
struct LocalJoinState<T> {
    result: Option<Result<T, RuntimeError>>,
    waker: Option<Waker>,
}

impl<T> LocalJoinState<T> {
    fn new() -> Self {
        Self {
            result: None,
            waker: None,
        }
    }
}

/// Handle returned by [`CoopLocalSet::spawn_local`]. Implements
/// `Future<Output = Result<T, RuntimeError>>`, mirroring
/// [`crate::CoopJoinHandle`] — but with NO `T: Send` bound, which is
/// exactly the difference that lets a local task return a `!Send` value
/// (e.g. anything carrying an `Rc`).
pub struct CoopLocalJoinHandle<T> {
    state: Rc<RefCell<LocalJoinState<T>>>,
    cancel_flag: Arc<AtomicBool>,
}

impl<T> CoopLocalJoinHandle<T> {
    /// Abort the local task. Same two-step cooperative semantic as
    /// [`crate::CoopJoinHandle::abort`]: set the shared cancel flag so the
    /// next [`CoopLocalSet::run_until_idle`] sweep drops the task body, and
    /// synchronously write `Err(RuntimeError::JoinCancelled)` so an
    /// awaiting consumer resolves without waiting for that sweep.
    ///
    /// Idempotent and race-safe against natural completion via the
    /// `result.is_none()` guard — the first result that landed is the one
    /// the handle returns.
    pub fn abort(&self) {
        self.cancel_flag.store(true, Ordering::Release);
        let mut s = self.state.borrow_mut();
        if s.result.is_none() {
            s.result = Some(Err(RuntimeError::JoinCancelled));
            if let Some(w) = s.waker.take() {
                w.wake();
            }
        }
    }

    /// True once the task has produced a result (natural completion or
    /// abort) that no poll has taken yet. Lets a synchronous driver ask
    /// "is it done?" without consuming the value.
    pub fn is_finished(&self) -> bool {
        self.state.borrow().result.is_some()
    }
}

impl<T> Future for CoopLocalJoinHandle<T> {
    type Output = Result<T, RuntimeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.borrow_mut();
        if let Some(result) = state.result.take() {
            state.waker = None;
            Poll::Ready(result)
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A `!Send` task pool bound to one [`CoopRuntime`].
///
/// Construct with [`CoopLocalSet::new`], spawn `!Send` futures with
/// [`CoopLocalSet::spawn_local`], and pump with
/// [`CoopLocalSet::run_until_idle`] (which also drives the runtime's
/// shared pool and timer queue) or [`CoopLocalSet::block_on_local`].
///
/// The type holds `Rc` and is therefore `!Send` / `!Sync`. That is the
/// load-bearing property, not an incidental one — see the module doc.
pub struct CoopLocalSet<C: ClockSource> {
    runtime: CoopRuntime<C>,
    tasks: Rc<RefCell<Vec<Option<LocalTaskSlot>>>>,
}

impl<C: ClockSource> CoopLocalSet<C> {
    /// Bind a local task pool to `runtime`. The runtime handle is cloned
    /// (it is `Arc`-backed), so the local set and any other holder of the
    /// same runtime share one executor and one timer queue.
    pub fn new(runtime: &CoopRuntime<C>) -> Self {
        Self {
            runtime: runtime.clone(),
            tasks: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Borrow the runtime this local set pumps.
    pub fn runtime(&self) -> &CoopRuntime<C> {
        &self.runtime
    }

    /// Spawn a `!Send` future as a local task, returning a handle that
    /// resolves to its output.
    ///
    /// The `'static` bound is the same one `Runtime::spawn` carries and for
    /// the same reason: a detached task cannot borrow from the caller's
    /// stack. `Send` is the only bound dropped.
    pub fn spawn_local<F>(&self, fut: F) -> CoopLocalJoinHandle<F::Output>
    where
        F: Future + 'static,
    {
        let state: Rc<RefCell<LocalJoinState<F::Output>>> =
            Rc::new(RefCell::new(LocalJoinState::new()));
        let state_for_wrapper = state.clone();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag_for_handle = cancel_flag.clone();

        // Wrapper drives the user future and publishes its output. The
        // `is_none()` guard preserves whichever of natural completion /
        // abort landed first, exactly as the Send sibling does.
        let wrapper = async move {
            let output = fut.await;
            let mut s = state_for_wrapper.borrow_mut();
            if s.result.is_none() {
                s.result = Some(Ok(output));
                if let Some(w) = s.waker.take() {
                    w.wake();
                }
            }
        };

        let slot = LocalTaskSlot {
            fut: Box::pin(wrapper),
            // Initially ready so the first pump polls it.
            wake_flag: Arc::new(AtomicBool::new(true)),
            cancel_flag,
        };
        self.tasks.borrow_mut().push(Some(slot));

        CoopLocalJoinHandle {
            state,
            cancel_flag: cancel_flag_for_handle,
        }
    }

    /// One executor pass: the runtime's timer queue and `Send` task pool
    /// first (via [`CoopRuntime::run_until_idle`]), then every ready local
    /// task at most once.
    ///
    /// Tasks spawned re-entrantly from inside a polled future are appended
    /// past this pass's snapshot and picked up by the next call — the same
    /// single-pass fairness model the `Send` pool in [`crate::executor`]
    /// uses, and for the same anti-recursion reason.
    pub fn run_until_idle(&self) {
        self.runtime.run_until_idle();

        let task_count = self.tasks.borrow().len();
        for idx in 0..task_count {
            // Cancel-first sweep. `abort()` has already published
            // `JoinCancelled` to the handle, so this side only releases
            // the task body and its captured resources.
            let cancelled = {
                let mut tasks = self.tasks.borrow_mut();
                match tasks.get_mut(idx) {
                    Some(slot) => {
                        let is_cancelled = slot
                            .as_ref()
                            .map(|t| t.cancel_flag.load(Ordering::Acquire))
                            .unwrap_or(false);
                        if is_cancelled {
                            slot.take()
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            if let Some(taken) = cancelled {
                drop(taken);
                continue;
            }

            // Ready snapshot + slot vacate. The borrow is released before
            // `poll` so a re-entrant `spawn_local` from inside the polled
            // future does not hit a `RefCell` double-borrow panic.
            let entry = {
                let mut tasks = self.tasks.borrow_mut();
                match tasks.get_mut(idx) {
                    Some(slot) => {
                        let was_ready = slot
                            .as_ref()
                            .map(|t| t.wake_flag.swap(false, Ordering::AcqRel))
                            .unwrap_or(false);
                        if was_ready {
                            slot.take()
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            };
            if let Some(mut e) = entry {
                let waker = make_waker(e.wake_flag.clone());
                let mut cx = Context::from_waker(&waker);
                match e.fut.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        // Slot stays vacated; the wrapper has already
                        // published the result into the join state.
                    }
                    Poll::Pending => {
                        if let Some(slot) = self.tasks.borrow_mut().get_mut(idx) {
                            *slot = Some(e);
                        }
                    }
                }
            }
        }
    }

    /// Count of live local task slots. Diagnostic + test helper, the local
    /// twin of `ExecutorState::live_task_count`.
    pub fn live_local_task_count(&self) -> usize {
        self.tasks.borrow().iter().filter(|s| s.is_some()).count()
    }

    /// True if any local task slot has its wake flag set.
    pub fn any_local_ready(&self) -> bool {
        self.tasks.borrow().iter().any(|s| {
            s.as_ref()
                .map(|t| t.wake_flag.load(Ordering::Acquire))
                .unwrap_or(false)
        })
    }

    /// Drive local + shared tasks until `handle` resolves, returning the
    /// local task's output. The `!Send` counterpart of
    /// [`CoopRuntime::block_on`], and the synchronous entry point a deploy
    /// `main()` or a host test uses to run a local task to completion.
    ///
    /// Panics if the handle is Pending while nothing can possibly wake it —
    /// no ready local task, no live local task, and no pending timer. That
    /// is the deadlock shape [`CoopRuntime::block_on`] panics on, surfaced
    /// here for the local pool; on a real MCU the equivalent is a `wfi()`
    /// that never returns.
    pub fn block_on_local<T>(&self, handle: CoopLocalJoinHandle<T>) -> Result<T, RuntimeError> {
        let mut handle = handle;
        let flag = Arc::new(AtomicBool::new(true));
        let waker = make_waker(flag.clone());
        let mut cx = Context::from_waker(&waker);
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
                     live local tasks, no wakers, and no pending timers — \
                     deadlocked future?"
                );
            }
        }
    }
}
