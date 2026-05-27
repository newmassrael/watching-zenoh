// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipRuntime<C>` — `impl wz_runtime_core::Runtime` for the MCU
//! profile. R311av-pre Decisions 1-6 realised in code; R311bc adds
//! the deadline-keyed [`crate::timer::TimerQueue`] + clock ownership.
//!
//! ## What this module ships
//!
//! - [`LwipRuntime<C: ClockSource>`] — `Clone` (`Arc<RuntimeInner<C>>`
//!   inside) so spawned task closures can capture a runtime handle
//!   and call nested `spawn` (R311av-pre Decision 5).
//! - `impl Runtime for LwipRuntime<C>`:
//!   - `type JoinHandle<T> = LwipJoinHandle<T>`
//!   - `type Mutex<T> = crate::sync::Mutex<T>`
//!   - `type RwLock<T> = crate::sync::RwLock<T>`
//!   - `fn spawn<F>(..) -> LwipJoinHandle<F::Output>`: heap-allocates
//!     a wrapper future that drives the user future to completion,
//!     stores its output into the shared `JoinState<T>`, and wakes
//!     the join handle's waker; pushes the wrapper into the inner
//!     `ExecutorState`'s task vector.
//! - [`LwipRuntime::run_until_idle`] — drives one executor step.
//!   R311bc adds a `pop_expired(clock.now_us())` pass *before* the
//!   task-pool sweep so wake-on-deadline timers fire ahead of the
//!   tasks they wake. Deploy main loop pattern:
//!
//!   ```ignore
//!   loop {
//!       lwip_poll();                  // process lwIP I/O
//!       runtime.run_until_idle();     // pop_expired + poll ready tasks
//!       cortex_m::asm::wfi();         // sleep until next IRQ
//!   }
//!   ```
//!
//!   Because R311bc closes the self-wake busy-poll, the `wfi()` line
//!   actually sleeps now — under R311av the executor was always
//!   ready and `wfi()` returned immediately on the next pass.
//!
//! - [`LwipRuntime::block_on`] — drive a single outer future to
//!   completion. Used by host tests + by deploy code that needs a
//!   synchronous entry point. Polls the outer future first; if it
//!   returns `Pending`, calls `run_until_idle` to fan out work to
//!   spawned tasks; repeats until the outer future resolves. The
//!   `Pin<Box<F>>` heap allocation matches the spawn discipline —
//!   one allocation per outer call.
//!
//! ## Why `LwipRuntime` is generic over `C: ClockSource`
//!
//! R311bc Decision: runtime owns the clock + timer queue, time
//! source borrows from runtime. The alternatives:
//!
//! - **(a) Clock owned by `LwipTime`, runtime stateless**: would
//!   force `LwipTime::sleep` to register its waker with a queue
//!   owned somewhere else — either a global (`once_cell` singleton,
//!   rejected per R311av-pre Decision 2) or a separately-passed
//!   handle (every caller of `sleep` would need both `LwipTime` AND
//!   `LwipRuntime`, defeating the trait abstraction).
//! - **(b) Clock as runtime trait method**: would extend the
//!   §5.P Runtime trait surface beyond the cross-profile contract.
//!   AP-side `TokioRuntime` does not need a clock parameter (tokio
//!   has its own internal time driver); putting `ClockSource` on
//!   `Runtime` is a leaky MCU-profile detail.
//! - **(c) Chosen: runtime generic over C, time source borrows
//!   `Arc<RuntimeInner<C>>` from the runtime**: keeps the §5.P
//!   trait clean (`impl Runtime for LwipRuntime<C>` where C is the
//!   MCU profile's free parameter, mirroring tokio's `TokioRuntime`
//!   single-type shape but with the MCU-specific clock injection at
//!   construction time). `LwipTime::new(&runtime)` shares the
//!   `Arc<RuntimeInner<C>>` so the timer queue and clock are the
//!   same physical instance the runtime polls.
//!
//! ## Send + Sync chain (post-R311bc)
//!
//! The trait requires `Runtime: Send + Sync + 'static`. The
//! storage chain holds because:
//!
//! - `Arc<T>: Send + Sync where T: Send + Sync`.
//! - `RuntimeInner<C>` is `Send + Sync` because `ExecutorState`
//!   (R311av), [`crate::timer::TimerQueue`] (R311bc, same Mutex
//!   shape) and `C: ClockSource` (trait requires `Send + Sync +
//!   'static`) all are.
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

// R311bb — Arc + AtomicBool + Ordering routed through the crate's
// polyfill alias so thumbv6m builds engage portable-atomic{,-util}
// while native-atomic targets stay on the standard library types.
use crate::atomic::{Arc, AtomicBool, Ordering};
use alloc::boxed::Box;
use core::cell::RefCell;
use core::future::Future;
use core::task::{Context, Poll};

use critical_section::Mutex;
use wz_runtime_core::Runtime;

use crate::executor::{make_waker, ExecutorState};
use crate::join_handle::{JoinState, LwipJoinHandle};
use crate::time::ClockSource;
use crate::timer::TimerQueue;

/// Shared inner state held inside an `Arc` so `LwipRuntime` clones
/// + `LwipTime::new(&runtime)` all reference the same executor,
/// timer queue, and clock instance. R311bc consolidation: the three
/// fields are siblings because they need to be polled / updated
/// from `run_until_idle` in a single atomic step (timer fire +
/// task wake + task poll).
pub(crate) struct RuntimeInner<C: ClockSource> {
    pub(crate) executor: ExecutorState,
    pub(crate) timers: TimerQueue,
    pub(crate) clock: C,
}

/// `impl Runtime` for the MCU profile. Cheap to clone — the entire
/// state lives in `Arc<RuntimeInner<C>>`. Multiple clones share the
/// same task pool, timer queue, and clock; task closures may capture
/// a `LwipRuntime` clone and call nested `spawn` (R311av-pre
/// Decision 5).
pub struct LwipRuntime<C: ClockSource> {
    pub(crate) inner: Arc<RuntimeInner<C>>,
}

impl<C: ClockSource> Clone for LwipRuntime<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C: ClockSource> LwipRuntime<C> {
    /// Construct a new runtime backed by `clock`. The clock is moved
    /// into the runtime; `LwipTime::new(&runtime)` then borrows the
    /// shared `Arc<RuntimeInner<C>>` so time-source ops and runtime
    /// ops see the same instance.
    ///
    /// R311bc breaking sig — R311av's parameterless `new()` is
    /// retired because the runtime now owns the timer queue and
    /// timer-queue evaluation needs a clock reference at every
    /// `run_until_idle` pass.
    pub fn new(clock: C) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                executor: ExecutorState::new(),
                timers: TimerQueue::new(),
                clock,
            }),
        }
    }

    /// Borrow the runtime's clock source. Used internally by
    /// [`crate::time::LwipTime::new`] to snapshot the construction
    /// epoch; deploy code typically reads time via `LwipTime`
    /// rather than this method.
    pub fn clock(&self) -> &C {
        &self.inner.clock
    }

    /// Borrow the runtime's timer queue. Crate-internal accessor for
    /// [`crate::time::SleepFuture`] / [`crate::time::TimeoutFuture`]
    /// to register deadline-keyed wakes; the public surface for
    /// deploy diagnostics is via [`crate::timer::TimerQueue`]
    /// methods on this return value.
    pub fn timers(&self) -> &TimerQueue {
        &self.inner.timers
    }

    /// Poll every currently-ready spawned task at most once.
    ///
    /// R311bc pass shape:
    ///
    /// 1. Sample `clock.now_us()` once.
    /// 2. `timers.pop_expired(now)` — wake every registered waker
    ///    whose deadline has elapsed. Each wake sets a task slot's
    ///    `wake_flag = true`, making that task ready for step 3.
    /// 3. `executor.run_until_idle()` — poll every ready task once,
    ///    re-store Pending futures.
    ///
    /// The ordering (timers before tasks) ensures a task waiting on
    /// a sleep that elapsed *this* pass is polled the same pass,
    /// not the next one. The opposite ordering would cost one
    /// `run_until_idle` cycle of latency per deadline.
    ///
    /// The deploy main loop calls this between hardware-poll passes.
    /// See module doc for the canonical loop shape.
    pub fn run_until_idle(&self) {
        let now = self.inner.clock.now_us();
        self.inner.timers.pop_expired(now);
        self.inner.executor.run_until_idle();
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
    /// executor reports no ready tasks AND no live tasks AND no
    /// pending timers — that shape indicates a deadlocked future
    /// with no external wake source (caller bug). On real MCU
    /// deploys the equivalent situation would be `wfi()` blocking
    /// forever; the panic here surfaces the bug at test time.
    ///
    /// R311bc extension: the pending-timer check distinguishes
    /// "legitimately waiting for a deadline" from "permanently
    /// stuck". A test that registers a sleep but never advances its
    /// clock will hang in `block_on` (not panic) — the runtime
    /// cannot tell the difference between "deploy waiting for a
    /// timer to fire" and "test forgot to drive the clock".
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
            // Give spawned tasks a chance to make progress (and let
            // any expired timers fire ahead of them).
            self.run_until_idle();

            // Deadlock detection. If the outer flag is unset, no
            // task is ready, no live spawned tasks exist, AND no
            // timer is pending — there is no possible future wake
            // source. Panic surfaces the bug at test time. On a
            // real MCU deploy `wfi()` outside this loop would block
            // forever in the same situation.
            if !flag.load(Ordering::Acquire)
                && !self.inner.executor.any_ready()
                && self.inner.executor.live_task_count() == 0
                && self.inner.timers.pending_count() == 0
            {
                panic!(
                    "LwipRuntime::block_on: outer future Pending with no \
                     live tasks, no wakers, and no pending timers — \
                     deadlocked future?"
                );
            }
        }
    }
}

impl<C: ClockSource + Default> Default for LwipRuntime<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: ClockSource> Runtime for LwipRuntime<C> {
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
        // R311bd — cancel_flag shared between the executor task
        // slot and the LwipJoinHandle returned here. Initial value
        // = false; set to true by `LwipJoinHandle::abort()`.
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_flag_for_handle = cancel_flag.clone();
        // Wrapper drives the user future and pushes the result into
        // JoinState + wakes any registered handle waker. The wrapper
        // returns () so it fits the type-erased BoxFuture slot.
        //
        // R311bd: the `is_none()` guard preserves the result that
        // landed first. If `LwipJoinHandle::abort()` raced ahead of
        // this wrapper and stored `Err(JoinCancelled)`, the natural
        // `Ok(output)` write here becomes a no-op; the handle
        // returns the cancellation. Conversely, if the wrapper
        // completes first and stores `Ok(output)`, a later abort
        // sees the populated result and is a no-op. Either order
        // is honest about which event landed first.
        let wrapper = async move {
            let output = fut.await;
            critical_section::with(|cs| {
                let mut s = state_for_wrapper.borrow(cs).borrow_mut();
                if s.result.is_none() {
                    s.result = Some(Ok(output));
                    if let Some(w) = s.waker.take() {
                        w.wake();
                    }
                }
            });
        };
        let boxed: crate::executor::BoxFuture = Box::pin(wrapper);
        self.inner.executor.spawn(boxed, cancel_flag);
        LwipJoinHandle::new(state, cancel_flag_for_handle)
    }

    // R311ct — closure-scoped mutex access. MCU profile binds through
    // `critical_section::with` (interrupt-disabling) + `RefCell::borrow_mut`
    // (interior-mutable shared access inside the critical section). No
    // poison concept on this profile: a panicking observer task would
    // abort the whole executor under `panic = "abort"` (MCU default),
    // so the only observable lock-failure mode is the runtime never
    // resuming — recovery is not meaningful.
    fn with_mutex_mut<T, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U
    where
        T: Send + 'static,
    {
        critical_section::with(|cs| {
            let mut borrow = mutex.borrow(cs).borrow_mut();
            f(&mut *borrow)
        })
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
    fn _assert_send_sync<T: Send + Sync>() {}

    #[allow(dead_code)]
    fn lwip_runtime_trait_bounds_compile() {
        _assert_send_sync::<LwipRuntime<NopClock>>();
        // LwipJoinHandle: trait-required Send (Sync is a happy
        // accident of the storage chain; not asserted here so a
        // future single-consumer redesign that drops Sync stays
        // valid against the trait contract).
        _assert_send::<LwipJoinHandle<()>>();
        _assert_send::<LwipJoinHandle<u64>>();
    }

    #[allow(dead_code)]
    fn lwip_runtime_mutex_rwlock_bounds_compile() {
        _assert_send_sync::<<LwipRuntime<NopClock> as Runtime>::Mutex<u32>>();
        _assert_send_sync::<<LwipRuntime<NopClock> as Runtime>::Mutex<u64>>();
        _assert_send_sync::<<LwipRuntime<NopClock> as Runtime>::RwLock<u32>>();
        _assert_send_sync::<<LwipRuntime<NopClock> as Runtime>::RwLock<u64>>();
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
        let rt: LwipRuntime<NopClock> = LwipRuntime::new(NopClock);
        let clock = LwipTime::new(&rt);
        runtime_and_time_compose_in_generic_code(&rt, &clock);
    }

    #[derive(Clone, Default)]
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
    use crate::atomic::AtomicU64;
    use crate::time::{ClockSource, LwipTime};
    use core::pin::Pin;
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

    /// Default trivial clock for tests that do not care about time
    /// (spawn / nested-spawn / unit-output / string-round-trip).
    #[derive(Clone, Default)]
    struct NopClock;
    impl ClockSource for NopClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    #[test]
    fn spawn_resolves_to_future_output() {
        let rt = LwipRuntime::new(NopClock);
        let h = rt.spawn(async { 42_u32 });
        let result = rt.block_on(h);
        assert_eq!(result.expect("spawn ok"), 42);
    }

    #[test]
    fn spawn_unit_output_resolves_to_ok_unit() {
        let rt = LwipRuntime::new(NopClock);
        let h = rt.spawn(async {});
        rt.block_on(h).expect("spawn returns Ok(())");
    }

    #[test]
    fn spawn_string_output_round_trips() {
        let rt = LwipRuntime::new(NopClock);
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
        let rt = LwipRuntime::new(NopClock);
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
        let rt = LwipRuntime::new(clock.clone());
        let time = LwipTime::new(&rt);
        let t0 = time.now_monotonic_ms();
        clock.tick_us(2_500); // 2.5ms
        let t1 = time.now_monotonic_ms();
        assert_eq!(t0, 0);
        assert_eq!(t1, 2);
    }

    #[test]
    fn sleep_completes_when_clock_advances_past_deadline() {
        // R311bc: SleepFuture registers its waker on the timer
        // queue on first Pending poll. The driver task ticks the
        // clock once per executor pass + yields; each
        // run_until_idle calls pop_expired(now), and once the
        // clock crosses the 5ms deadline the registered waker
        // fires and the sleep task is polled to Ready.
        let rt = LwipRuntime::new(TestClock::new());
        let clock = rt.clock().clone();
        let time = LwipTime::new(&rt);
        let advance_clock = clock.clone();
        rt.spawn(async move {
            loop {
                advance_clock.tick_us(10_000);
                YieldOnce::default().await;
            }
        });
        let h = rt.spawn(async move {
            time.sleep(5).await; // 5ms; clock bumps 10ms per pass
            7_u32
        });
        assert_eq!(rt.block_on(h).expect("ok"), 7);
    }

    #[test]
    fn sleep_zero_resolves_immediately() {
        // R311bc edge: ms=0 yields to runtime; with clock at
        // construction-time t=0 the deadline is exactly now and
        // the first poll sees `now_us >= deadline_us` and returns
        // Ready without ever registering on the timer queue.
        let rt = LwipRuntime::new(TestClock::new());
        let time = LwipTime::new(&rt);
        let h = rt.spawn(async move {
            time.sleep(0).await;
            123_u32
        });
        assert_eq!(rt.block_on(h).expect("ok"), 123);
    }

    #[test]
    fn timer_queue_pending_count_tracks_registered_sleeps() {
        // R311bc diagnostic surface: while a sleep is pending the
        // queue's pending_count() reports >= 1. Drives the runtime
        // through one executor pass (so the sleep registers via
        // its first Pending poll) and then samples the count.
        let rt = LwipRuntime::new(TestClock::new());
        let time = LwipTime::new(&rt);
        let _h = rt.spawn(async move {
            time.sleep(100).await;
        });
        // Single pass: the spawned task is initially ready (wake
        // flag = true on spawn), polls, registers a sleep on the
        // queue, returns Pending.
        rt.run_until_idle();
        assert!(
            rt.timers().pending_count() >= 1,
            "after first run_until_idle the sleep should have \
             registered a timer entry, pending_count was {}",
            rt.timers().pending_count()
        );
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
        let rt = LwipRuntime::new(TestClock::new());
        let time = LwipTime::new(&rt);
        let h = rt.spawn(async move { time.timeout(1000, async { 99_u32 }).await });
        let result = rt.block_on(h).expect("spawn ok");
        assert_eq!(result.expect("inner ok"), 99);
    }

    #[test]
    fn timeout_inner_pending_past_deadline_returns_elapsed() {
        // Trait `timeout` contract: inner Pending after deadline
        // elapsed → Err(TimeoutElapsed). We arrange this by making
        // the inner future a NeverReady self-waker and advancing
        // the clock past the deadline via a driver. R311bc: the
        // outer TimeoutFuture registers its waker on the timer
        // queue exactly once; subsequent polls re-check the inner
        // + the deadline without re-registering.
        let rt = LwipRuntime::new(TestClock::new());
        let clock = rt.clock().clone();
        let time = LwipTime::new(&rt);
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

    #[test]
    fn abort_resolves_handle_to_join_cancelled() {
        // R311bd: spawn a task that never completes (NeverReady
        // self-waker would dominate the executor; instead use a
        // sleep on a never-advanced clock so the registered timer
        // queue waiter never fires). Abort the handle; the await
        // should resolve immediately to Err(JoinCancelled) via
        // the synchronous JoinState write inside abort().
        use wz_runtime_core::RuntimeError;
        let rt = LwipRuntime::new(TestClock::new());
        let time = LwipTime::new(&rt);
        let h = rt.spawn(async move {
            time.sleep(u64::MAX / 2).await; // effectively forever
            999_u32
        });
        h.abort();
        // After abort, the next iteration of the executor will
        // sweep the slot and drop the task body; the handle itself
        // already resolved synchronously inside abort. block_on
        // polls the handle once, sees JoinCancelled, returns.
        let result = rt.block_on(h);
        assert!(
            matches!(result, Err(RuntimeError::JoinCancelled)),
            "expected JoinCancelled, got {result:?}"
        );
    }

    #[test]
    fn abort_after_completion_is_noop() {
        // R311bd: a task that completes naturally before abort
        // arrives stores its Ok(output) in JoinState; the later
        // abort sees result.is_some() and skips the JoinCancelled
        // write. The handle resolves to Ok(output).
        let rt = LwipRuntime::new(NopClock);
        let h = rt.spawn(async { 17_u32 });
        // First drive the task to completion via block_on. We
        // can't await the handle here because we need to keep it
        // alive for the post-completion abort call; instead we
        // run_until_idle until JoinState has a result.
        // The spawned task is ready (wake_flag=true on spawn); a
        // single run_until_idle pass polls it to Ready.
        rt.run_until_idle();
        // Now abort — the wrapper has already stored Ok(17), so
        // abort's is_none() guard short-circuits.
        h.abort();
        let result = rt.block_on(h);
        assert_eq!(result.expect("ok preserved"), 17);
    }

    #[test]
    fn abort_is_idempotent() {
        // R311bd: repeated abort calls are no-ops after the first.
        // The first abort writes JoinCancelled; subsequent calls
        // see result.is_some() and skip the write (and the
        // cancel_flag.store(true) is itself idempotent).
        use wz_runtime_core::RuntimeError;
        let rt = LwipRuntime::new(TestClock::new());
        let time = LwipTime::new(&rt);
        let h = rt.spawn(async move {
            time.sleep(u64::MAX / 2).await;
            42_u32
        });
        h.abort();
        h.abort();
        h.abort();
        let result = rt.block_on(h);
        assert!(matches!(result, Err(RuntimeError::JoinCancelled)));
    }
}
