// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipRuntime` — `impl wz_runtime_core::Runtime` for the MCU
//! profile. R311av-pre Decisions 1-6 realised in code.
//!
//! ## What this module ships
//!
//! - [`LwipRuntime`] — `Clone` (`Arc<ExecutorState>` inside) so
//!   spawned task closures can capture a runtime handle and call
//!   nested `spawn` (R311av-pre Decision 5).
//! - `impl Runtime for LwipRuntime`:
//!   - `type JoinHandle<T> = LwipJoinHandle<T>`
//!   - `type Mutex<T> = crate::sync::Mutex<T>`
//!   - `type RwLock<T> = crate::sync::RwLock<T>`
//!   - `fn spawn<F>(..) -> LwipJoinHandle<F::Output>`: heap-allocates
//!     a wrapper future that drives the user future to completion,
//!     stores its output into the shared `JoinState<T>`, and wakes
//!     the join handle's waker; pushes the wrapper into
//!     `ExecutorState`'s task vector.
//! - [`LwipRuntime::run_until_idle`] — drives the executor one
//!   single-pass step. Deploy main loop pattern:
//!
//!   ```ignore
//!   loop {
//!       lwip_poll();                  // process lwIP I/O
//!       runtime.run_until_idle();     // poll every ready task once
//!       cortex_m::asm::wfi();         // sleep until next IRQ
//!   }
//!   ```
//!
//! - [`LwipRuntime::block_on`] — drive a single outer future to
//!   completion. Used by host tests + by deploy code that needs a
//!   synchronous entry point. Polls the outer future first; if it
//!   returns `Pending`, calls `run_until_idle` to fan out work to
//!   spawned tasks; repeats until the outer future resolves. The
//!   `Pin<Box<F>>` heap allocation matches the spawn discipline —
//!   one allocation per outer call.
//!
//! ## Send + Sync chain
//!
//! The trait requires `Runtime: Send + Sync + 'static`. The
//! storage chain holds because:
//!
//! - `Arc<T>: Send + Sync where T: Send + Sync`.
//! - `ExecutorState` is `Send + Sync` because its inner
//!   `critical_section::Mutex<RefCell<Inner>>` is `Send + Sync where
//!   Inner: Send`, and `Inner` (a `Vec<Option<TaskSlot>>`) is `Send`
//!   because `TaskSlot.fut: BoxFuture` requires `Send` at the
//!   trait-object bound and `Arc<AtomicBool>` is `Send + Sync`.
//!
//! Run-time invariants:
//!
//! - Re-entrant `spawn` from inside a task's poll is safe: poll
//!   runs *outside* the critical section (`run_until_idle` takes
//!   the lock only for the take-and-restore window); the nested
//!   `spawn` call re-acquires the lock and appends.
//! - `LwipRuntime::spawn` heap-allocates twice — once for the
//!   `Box<dyn Future>` wrapper and once for the `Arc<Mutex<RefCell<
//!   JoinState<T>>>>` shared state. Both allocations are required
//!   by the trait surface (type erasure + cross-task result
//!   sharing); they cannot be elided without changing the
//!   `Runtime` contract.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::RefCell;
use core::future::Future;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use critical_section::Mutex;
use wz_runtime_core::Runtime;

use crate::executor::{make_waker, ExecutorState};
use crate::join_handle::{JoinState, LwipJoinHandle};

/// `impl Runtime` for the MCU profile. Cheap to clone — the entire
/// state lives in `Arc<ExecutorState>`. Multiple clones share the
/// same task pool; task closures may capture a `LwipRuntime` clone
/// and call nested `spawn` (R311av-pre Decision 5).
#[derive(Clone)]
pub struct LwipRuntime {
    executor: Arc<ExecutorState>,
}

impl LwipRuntime {
    /// Construct a new runtime with an empty task pool.
    pub fn new() -> Self {
        Self {
            executor: Arc::new(ExecutorState::new()),
        }
    }

    /// Poll every currently-ready spawned task at most once. The
    /// deploy main loop calls this between hardware-poll passes.
    /// See module doc for the canonical loop shape.
    pub fn run_until_idle(&self) {
        self.executor.run_until_idle();
    }

    /// Drive a single outer future to completion. Returns the
    /// future's output. Polls the outer future and, on `Pending`,
    /// fans out via `run_until_idle` so spawned tasks can make
    /// progress. Repeats until the outer future resolves.
    ///
    /// This is the synchronous entry point used by host tests and
    /// by deploy `main()` when the runtime is driving a single
    /// top-level future (the embedded equivalent of tokio's
    /// `Runtime::block_on`). The future is heap-pinned (`Box::pin`)
    /// so the polling loop can re-enter `poll` repeatedly without
    /// requiring `F: Unpin`.
    ///
    /// Panics if the outer future returns `Pending` while the
    /// executor reports no ready tasks AND no live tasks — that
    /// shape indicates a deadlocked future with no external wake
    /// source (caller bug). On real MCU deploys the equivalent
    /// situation would be `wfi()` blocking forever; the panic here
    /// surfaces the bug at test time.
    pub fn block_on<F: Future>(&self, fut: F) -> F::Output {
        let mut fut = Box::pin(fut);
        let flag = Arc::new(AtomicBool::new(true));
        let waker = make_waker(flag.clone());
        let mut cx = Context::from_waker(&waker);
        loop {
            // Poll the outer future first if its wake flag is set.
            // Initial flag = true ensures the first iteration polls.
            let outer_was_ready = flag.swap(false, Ordering::AcqRel);
            if outer_was_ready {
                if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                    return out;
                }
            }
            // Give spawned tasks a chance to make progress.
            self.executor.run_until_idle();

            // Loop progress guard. If nothing is ready and no live
            // tasks exist, we would spin forever. In practice on
            // host tests a self-waking SleepFuture keeps the flag
            // set; this guard only fires when the caller has handed
            // us a permanently-stuck future.
            if !flag.load(Ordering::Acquire)
                && !self.executor.any_ready()
                && self.executor.live_task_count() == 0
            {
                panic!(
                    "LwipRuntime::block_on: outer future Pending with no \
                     live tasks and no wakers — deadlocked future?"
                );
            }
        }
    }
}

impl Default for LwipRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime for LwipRuntime {
    type JoinHandle<T>
        = LwipJoinHandle<T>
    where
        T: Send + 'static;

    type Mutex<T>
        = crate::sync::Mutex<T>
    where
        T: Send + 'static;

    type RwLock<T>
        = crate::sync::RwLock<T>
    where
        T: Send + Sync + 'static;

    fn spawn<F>(&self, fut: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Shared JoinState between the spawn wrapper (which stores
        // the result on completion) and the LwipJoinHandle returned
        // here (which reads the result on poll).
        let state: Arc<Mutex<RefCell<JoinState<F::Output>>>> =
            Arc::new(Mutex::new(RefCell::new(JoinState::new())));
        let state_for_wrapper = state.clone();
        // Wrapper drives the user future and pushes the result into
        // JoinState + wakes any registered handle waker. The wrapper
        // returns () so it fits the type-erased BoxFuture slot.
        let wrapper = async move {
            let output = fut.await;
            critical_section::with(|cs| {
                let mut s = state_for_wrapper.borrow(cs).borrow_mut();
                s.result = Some(Ok(output));
                if let Some(w) = s.waker.take() {
                    w.wake();
                }
            });
        };
        let boxed: crate::executor::BoxFuture = Box::pin(wrapper);
        self.executor.spawn(boxed);
        LwipJoinHandle::new(state)
    }
}

#[cfg(test)]
mod compile_time_assertions {
    use super::*;
    use crate::time::{ClockSource, LwipTime};
    use wz_runtime_core::TimeSource;

    // Mirror of wz_runtime_tokio::runtime_impl::compile_time_assertions
    // (R258 / R311ar). Pins the bounds the trait surface requires so
    // a future regression on Send / Sync / Mutex GAT bound surfaces
    // as a compile error rather than at the first concrete-impl swap.

    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}
    fn _assert_send_sync<T: Send + Sync>() {}

    #[allow(dead_code)]
    fn lwip_runtime_trait_bounds_compile() {
        _assert_send_sync::<LwipRuntime>();
        // LwipJoinHandle: trait-required Send (Sync is a happy
        // accident of the storage chain; not asserted here so a
        // future single-consumer redesign that drops Sync stays
        // valid against the trait contract).
        _assert_send::<LwipJoinHandle<()>>();
        _assert_send::<LwipJoinHandle<u64>>();
    }

    #[allow(dead_code)]
    fn lwip_runtime_mutex_rwlock_bounds_compile() {
        _assert_send_sync::<<LwipRuntime as Runtime>::Mutex<u32>>();
        _assert_send_sync::<<LwipRuntime as Runtime>::Mutex<u64>>();
        _assert_send_sync::<<LwipRuntime as Runtime>::RwLock<u32>>();
        _assert_send_sync::<<LwipRuntime as Runtime>::RwLock<u64>>();
    }

    // R258 / R311av — generic-composition smoke fn. Validates
    // R: Runtime + T: TimeSource compose for production-shaped
    // generic code (Session<R, T> reparam trajectory). Body
    // exercises every trait method against generic R + T so a
    // wrong-bound regression at any concrete-impl swap surfaces
    // at the first build.
    #[allow(dead_code)]
    fn runtime_and_time_compose_in_generic_code<R, T>(rt: &R, clock: &T)
    where
        R: Runtime,
        T: TimeSource + Clone + Send + 'static,
    {
        let clock_for_task = clock.clone();
        let _handle: R::JoinHandle<u64> = rt.spawn(async move {
            clock_for_task.sleep(0).await;
            clock_for_task.now_monotonic_ms()
        });
        let _ts: u64 = clock.now_monotonic_ms();

        fn _generic_mutex_bound_holds<R, T>()
        where
            R: Runtime,
            T: Send + 'static,
        {
            fn inner<X: Send + Sync + 'static>() {}
            inner::<R::Mutex<T>>();
        }
        fn _generic_rwlock_bound_holds<R, T>()
        where
            R: Runtime,
            T: Send + Sync + 'static,
        {
            fn inner<X: Send + Sync + 'static>() {}
            inner::<R::RwLock<T>>();
        }
        _generic_mutex_bound_holds::<R, u32>();
        _generic_rwlock_bound_holds::<R, u32>();
    }

    // Concrete instantiation so the generic above is actually
    // monomorphised at build time (otherwise dead code
    // elimination can let bound violations slip).
    #[allow(dead_code)]
    fn instantiate_compose_for_lwip() {
        let rt = LwipRuntime::new();
        let clock = LwipTime::new(NopClock);
        runtime_and_time_compose_in_generic_code(&rt, &clock);
    }

    #[derive(Clone)]
    struct NopClock;
    impl ClockSource for NopClock {
        fn now_us(&self) -> u64 {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::{ClockSource, LwipTime};
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU64, Ordering};
    use wz_runtime_core::TimeSource;

    // Host-side ClockSource: monotonic, no real time progression.
    // Tests advance the clock manually via tick(); guarantees no
    // wall-clock dependence so the suite is flake-free.
    #[derive(Clone)]
    struct TestClock {
        now: Arc<AtomicU64>,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now: Arc::new(AtomicU64::new(0)),
            }
        }

        fn tick_us(&self, by: u64) {
            self.now.fetch_add(by, Ordering::Release);
        }
    }

    impl ClockSource for TestClock {
        fn now_us(&self) -> u64 {
            self.now.load(Ordering::Acquire)
        }
    }

    #[test]
    fn spawn_resolves_to_future_output() {
        let rt = LwipRuntime::new();
        let h = rt.spawn(async { 42_u32 });
        let result = rt.block_on(h);
        assert_eq!(result.expect("spawn ok"), 42);
    }

    #[test]
    fn spawn_unit_output_resolves_to_ok_unit() {
        let rt = LwipRuntime::new();
        let h = rt.spawn(async {});
        rt.block_on(h).expect("spawn returns Ok(())");
    }

    #[test]
    fn spawn_string_output_round_trips() {
        let rt = LwipRuntime::new();
        let h = rt.spawn(async { alloc::string::String::from("payload") });
        let s = rt.block_on(h).expect("spawn ok");
        assert_eq!(s, "payload");
    }

    #[test]
    fn nested_spawn_resolves_inner_first() {
        // R311av-pre Decision 5 — LwipRuntime.clone() captured into
        // a task closure can spawn nested tasks. Pin the contract:
        // outer task spawns an inner task, awaits it, and returns
        // inner+1.
        let rt = LwipRuntime::new();
        let rt2 = rt.clone();
        let h = rt.spawn(async move {
            let inner = rt2.spawn(async { 100_u32 });
            inner.await.expect("inner ok") + 1
        });
        assert_eq!(rt.block_on(h).expect("outer ok"), 101);
    }

    #[test]
    fn time_now_monotonic_ms_reflects_clock_advance() {
        let clock = TestClock::new();
        let time = LwipTime::new(clock.clone());
        let t0 = time.now_monotonic_ms();
        clock.tick_us(2_500); // 2.5ms
        let t1 = time.now_monotonic_ms();
        assert_eq!(t0, 0);
        assert_eq!(t1, 2);
    }

    #[test]
    fn sleep_completes_when_clock_advances_past_deadline() {
        // SleepFuture self-wakes via wake_by_ref; on each polling
        // round it re-checks clock.now_us() against the deadline.
        // We spawn a tiny driver task that advances the clock once
        // per executor pass so the sleep can complete.
        let rt = LwipRuntime::new();
        let clock = TestClock::new();
        let time = LwipTime::new(clock.clone());
        let advance_clock = clock.clone();
        // Driver task: every poll, bump the clock by 10ms. Will be
        // re-polled until the sleep target releases the executor.
        rt.spawn(async move {
            // Loop forever — driver task. block_on exits when the
            // outer (the sleep_then_42 task) resolves; this driver
            // task remains spawned but is harmless.
            loop {
                advance_clock.tick_us(10_000);
                // Yield to give the sleep future a chance to poll.
                // Without an explicit yield the executor would re-
                // enter this same driver before any other task. We
                // implement yield-once as a custom future.
                YieldOnce::default().await;
            }
        });
        let h = rt.spawn(async move {
            time.sleep(5).await; // 5ms; clock bumps 10ms per pass
            7_u32
        });
        assert_eq!(rt.block_on(h).expect("ok"), 7);
    }

    /// Yield once: returns `Pending` on the first poll (registering
    /// the waker for wake-by-ref) and `Ready(())` on subsequent
    /// polls. Used in the sleep test to break the driver task out
    /// of an infinite tight loop.
    #[derive(Default)]
    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[test]
    fn timeout_inner_ready_returns_ok() {
        // Trait `timeout` contract: inner future Ready before
        // deadline elapsed → Ok(output). With TestClock not
        // advancing, the deadline never elapses; an immediately-
        // ready inner future resolves Ok.
        let rt = LwipRuntime::new();
        let clock = TestClock::new();
        let time = LwipTime::new(clock);
        let h = rt.spawn(async move { time.timeout(1000, async { 99_u32 }).await });
        let result = rt.block_on(h).expect("spawn ok");
        assert_eq!(result.expect("inner ok"), 99);
    }

    #[test]
    fn timeout_inner_pending_past_deadline_returns_elapsed() {
        // Trait `timeout` contract: inner Pending after deadline
        // elapsed → Err(TimeoutElapsed). We arrange this by making
        // the inner future a pending YieldOnce (re-wakes once) and
        // advancing the clock past the deadline via a driver.
        let rt = LwipRuntime::new();
        let clock = TestClock::new();
        let time = LwipTime::new(clock.clone());
        let advance_clock = clock.clone();
        rt.spawn(async move {
            loop {
                advance_clock.tick_us(10_000);
                YieldOnce::default().await;
            }
        });
        let h = rt.spawn(async move {
            // 1ms timeout; clock bumps 10ms per pass → first re-poll
            // will see clock > deadline → Err(TimeoutElapsed).
            time.timeout(1, NeverReady).await
        });
        let result = rt.block_on(h).expect("spawn ok");
        assert!(
            result.is_err(),
            "timeout should resolve to Err(TimeoutElapsed) but got Ok"
        );
    }

    /// Always Pending. Self-wakes so the timeout future can re-poll.
    struct NeverReady;

    impl Future for NeverReady {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
