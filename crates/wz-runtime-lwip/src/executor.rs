// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Self-rolled cooperative task pool — R311av-pre Decision 1-4.
//!
//! `ExecutorState` owns a `Vec<Option<TaskSlot>>` of `Pin<Box<dyn
//! Future<Output = ()> + Send>>` futures. Each task carries an
//! `Arc<AtomicBool>` wake flag; the executor's [`run_until_idle`] pass
//! atomic-swaps every task's flag, polls those that were ready, and
//! re-stores any future that returned `Pending`. The waker handed to
//! each `poll` flips the same `AtomicBool` so wakes from outside the
//! executor (other tasks, an ISR, [`SleepFuture::poll`]'s self-wake)
//! all funnel through the same per-task ready signal.
//!
//! ## Design lock (per R311av-pre 8 decisions)
//!
//! - **D1**: `Pin<Box<dyn Future<Output = ()> + Send>>` — type-erased
//!   slot; alloc-based heap; `Send` so spawned tasks may cross
//!   future-multi-core boundaries (the AP-profile mirror requires
//!   `Send` and R311av keeps the contract uniform).
//! - **D2**: per-`LwipRuntime` `Arc<ExecutorState>`. Static singleton
//!   (`StaticCell` / `once_cell` global) was rejected because every
//!   composable preset wants the freedom to construct multiple
//!   `LwipRuntime` instances (test isolation; future multi-core
//!   per-CPU executor); the trait-level `Runtime: Clone` shape is
//!   naturally satisfied by `Arc<ExecutorState>`.
//! - **D3**: `Vec<Option<TaskSlot>>` storage with slot reuse. Fixed-
//!   size array (`heapless::Vec`) was rejected because it forces a
//!   compile-time hard cap on tasks; deploy presets get to decide
//!   slot count by heap budget (composable framework north star).
//! - **D4**: `Arc<AtomicBool>` per task + custom `RawWakerVTable`.
//!   The atomic enables ISR-side wake (cortex-m / RISC-V interrupt
//!   handlers may call `waker.wake_by_ref()` after disabling
//!   interrupts via critical_section to grant priority). Atomic
//!   read on the polling side is `AcqRel`-ordered swap so the wake
//!   signal is visible across cores if the future supports it.
//!
//! ## What is intentionally NOT here
//!
//! - **Real timer queue**: [`crate::time::SleepFuture`] busy-wakes via
//!   `cx.waker().wake_by_ref()`. The deploy main loop drives time
//!   forward by repeating `runtime.run_until_idle()` between
//!   `lwip_poll()` + `cortex_m::asm::wfi()` (or RISC-V `wfi`). A
//!   deadline-keyed timer queue is R311az+; the busy-wake shape is
//!   honest for R311av — every iteration the executor returns
//!   control to the outer driver so power-down can happen between
//!   passes.
//! - **Priorities**: tasks are polled in slot order. Round-robin
//!   fairness is fine for the cooperative model; priority-aware
//!   scheduling is a deploy-level concern outside the executor
//!   surface.
//! - **Cancellation**: see `LwipJoinHandle` doc-comment — R311az+.

use alloc::boxed::Box;
// R311bb — Arc + AtomicBool + Ordering come from the crate's
// polyfill alias module so thumbv6m (Cortex-M0+) builds substitute
// `portable_atomic_util::Arc` / `portable_atomic::AtomicBool` /
// `portable_atomic::Ordering` automatically. Native-atomic targets
// (M3+/M7/Mxx/RISC-V IMAC/AP) get the standard library types via the
// same alias — no per-call-site cfg.
use crate::atomic::{Arc, AtomicBool, Ordering};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use critical_section::Mutex;

/// Type-erased task body. R311av-pre Decision 1.
pub(crate) type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

struct TaskSlot {
    fut: BoxFuture,
    wake_flag: Arc<AtomicBool>,
}

struct Inner {
    tasks: Vec<Option<TaskSlot>>,
}

/// Per-runtime cooperative task pool. The `LwipRuntime` wraps this
/// in an `Arc` so cloned runtime handles share the same task slots.
pub struct ExecutorState {
    inner: Mutex<RefCell<Inner>>,
}

impl ExecutorState {
    /// Construct an empty executor. Task storage grows on demand
    /// when `spawn` is called.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Inner { tasks: Vec::new() })),
        }
    }

    /// Push `fut` into the task pool. The future is initially marked
    /// ready so the first `run_until_idle` call polls it.
    ///
    /// Always appends to the tail; slot recycling is intentionally
    /// not done here because `run_until_idle` temporarily vacates a
    /// slot during a polled task's iteration (the entry is held in
    /// a local variable; the slot reads `None` for the polling
    /// window). A re-entrant `spawn` from inside that polled task
    /// would steal the vacated slot if `find(is_none)` were used,
    /// and the polled task's Pending-restore would then overwrite
    /// the new spawn, silently dropping it. Vec growth is the
    /// honest tradeoff; a compaction sweep that condenses dropped
    /// slots is a R311az+ refinement.
    pub(crate) fn spawn(&self, fut: BoxFuture) {
        let wake_flag = Arc::new(AtomicBool::new(true));
        let entry = TaskSlot { fut, wake_flag };
        critical_section::with(|cs| {
            let mut inner = self.inner.borrow(cs).borrow_mut();
            inner.tasks.push(Some(entry));
        });
    }

    /// Poll every currently-ready task at most once. Tasks that
    /// return `Poll::Pending` are restored to their slot for a
    /// future call; tasks that return `Poll::Ready(())` vacate
    /// their slot (the spawn-wrapper has already stored the result
    /// into the JoinState by the time the slot is freed).
    ///
    /// The implementation snapshots the task count once at the
    /// top, then iterates indices. Re-entrant `spawn` calls from
    /// inside a polled future append to the end; those new tasks
    /// will be picked up on the next `run_until_idle` invocation,
    /// not the current one. This avoids unbounded recursion in
    /// pathological spawn-loops while keeping the single-pass
    /// fairness model.
    pub fn run_until_idle(&self) {
        let task_count = critical_section::with(|cs| self.inner.borrow(cs).borrow().tasks.len());
        for idx in 0..task_count {
            // Per-task ready snapshot + slot vacate. The combined
            // swap-and-take keeps the critical section short.
            let entry = critical_section::with(|cs| {
                let mut inner = self.inner.borrow(cs).borrow_mut();
                let slot = inner.tasks.get_mut(idx)?;
                let was_ready = slot
                    .as_ref()
                    .map(|t| t.wake_flag.swap(false, Ordering::AcqRel))
                    .unwrap_or(false);
                if was_ready {
                    slot.take()
                } else {
                    None
                }
            });
            if let Some(mut e) = entry {
                let waker = make_waker(e.wake_flag.clone());
                let mut cx = Context::from_waker(&waker);
                match e.fut.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        // Slot vacated by the take() above; do not
                        // re-store. The spawn wrapper has already
                        // pushed the result into JoinState by the
                        // time poll returns Ready.
                    }
                    Poll::Pending => {
                        critical_section::with(|cs| {
                            let mut inner = self.inner.borrow(cs).borrow_mut();
                            if let Some(slot) = inner.tasks.get_mut(idx) {
                                *slot = Some(e);
                            }
                        });
                    }
                }
            }
        }
    }

    /// Diagnostic + test helper: count of live (Some) task slots.
    pub fn live_task_count(&self) -> usize {
        critical_section::with(|cs| {
            self.inner
                .borrow(cs)
                .borrow()
                .tasks
                .iter()
                .filter(|s| s.is_some())
                .count()
        })
    }

    /// Diagnostic + test helper: true if any task slot has its
    /// wake_flag set. Used by `LwipRuntime::block_on` to decide
    /// whether spinning makes progress.
    pub(crate) fn any_ready(&self) -> bool {
        critical_section::with(|cs| {
            self.inner.borrow(cs).borrow().tasks.iter().any(|s| {
                s.as_ref()
                    .map(|t| t.wake_flag.load(Ordering::Acquire))
                    .unwrap_or(false)
            })
        })
    }
}

impl Default for ExecutorState {
    fn default() -> Self {
        Self::new()
    }
}

// Waker vtable. Data pointer = `Arc<AtomicBool>::into_raw()`.
// Reconstruct via `Arc::from_raw` in each vtable function; forget
// the reconstructed Arc in wake_by_ref / clone-borrow paths so the
// stored refcount is not decremented.

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    // SAFETY: data was produced by Arc::into_raw and the caller
    // upholds that the raw pointer remains valid for the waker's
    // lifetime. We reconstruct, clone, and forget the original.
    let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
    let cloned = arc.clone();
    core::mem::forget(arc);
    let raw = Arc::into_raw(cloned) as *const ();
    RawWaker::new(raw, &VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    // SAFETY: data was produced by Arc::into_raw; reconstruct, set
    // the flag, drop. The drop decrements the refcount (this is
    // the consuming wake() path, distinct from wake_by_ref).
    let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
    arc.store(true, Ordering::Release);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    // SAFETY: data was produced by Arc::into_raw; reconstruct
    // transiently, set the flag, forget so the refcount is not
    // decremented. This is the non-consuming wake-by-ref path.
    let arc = unsafe { Arc::from_raw(data as *const AtomicBool) };
    arc.store(true, Ordering::Release);
    core::mem::forget(arc);
}

unsafe fn waker_drop(data: *const ()) {
    // SAFETY: data was produced by Arc::into_raw; reconstruct and
    // drop to decrement the refcount.
    drop(unsafe { Arc::from_raw(data as *const AtomicBool) });
}

static VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// Build a `Waker` whose `wake` / `wake_by_ref` calls set the
/// supplied `AtomicBool` flag to true. The flag is consumed
/// (refcount transferred into the waker); reconstructing it via the
/// vtable drop is the only safe way to release the refcount.
pub(crate) fn make_waker(flag: Arc<AtomicBool>) -> Waker {
    let raw = Arc::into_raw(flag) as *const ();
    let raw_waker = RawWaker::new(raw, &VTABLE);
    // SAFETY: VTABLE upholds the RawWaker contract: clone produces
    // an Arc-backed RawWaker with the same data pointer + vtable;
    // wake / wake_by_ref do not invalidate the data pointer; drop
    // releases exactly one refcount.
    unsafe { Waker::from_raw(raw_waker) }
}
