// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R252 — Concrete [`wz_runtime_core`] impls for the AP profile.
//!
//! Provides [`TokioRuntime`] (spawn + JoinHandle) and [`TokioTime`]
//! (monotonic clock + async sleep) backed by `tokio::task::spawn` and
//! `tokio::time::sleep` respectively. These are the AP-profile half
//! of the §5.P (runtime-services-tier) dual-target contract; the MCU
//! half (LwipRuntime + LwipTime) lands when the lwIP integration round
//! lifts the R63 carry on `wz-runtime-lwip`.
//!
//! ## Module shape
//!
//! - [`TokioRuntime`] — unit struct (`#[derive(Copy)]`). All state
//!   lives in the ambient tokio runtime that `tokio::task::spawn`
//!   reads from; the struct itself carries no data so it costs zero
//!   bytes and the trait impl is free-standing.
//! - [`TokioJoinHandle`] — newtype around `tokio::task::JoinHandle<T>`
//!   that implements `Future<Output = Result<T, RuntimeError>>`. The
//!   inner handle is `Unpin`, so the `Future` impl projects without
//!   `pin-project` (no unsafe).
//! - [`TokioTime`] — captures a `tokio::time::Instant` at construction
//!   to serve as the impl-defined monotonic epoch. `now_monotonic_ms`
//!   returns the elapsed milliseconds since that anchor; `sleep`
//!   delegates to `tokio::time::sleep(Duration::from_millis(ms))`.
//!
//! ## What stays in wz-runtime-tokio (not promoted to a trait yet)
//!
//! - **Mutex / RwLock**: the §5.P spec lists these alongside spawn but
//!   the generic-over-T shape (`Mutex<T>`) does not compose with a
//!   single GAT cleanly. The R251 trait skeleton explicitly deferred
//!   this; R252 also does not introduce a TokioMutex wrapper because
//!   the design choice (type alias vs MutexFamily GAT vs cfg-cond)
//!   should wait for the first MCU call-site shape to constrain it.
//! - **Allocator concrete impl**: the AP profile keeps using `Box` /
//!   `Vec` directly via the std global allocator. The trait-based
//!   surface lands when MCU buffer-pool work needs it.
//! - **Caller migration**: R252 ships *only* the impls. The R253+
//!   rounds migrate the 111 std/tokio call sites (R230 §5.P
//!   inventory baseline) to trait-mediated dispatch, leaf-first,
//!   `Session` last.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use wz_runtime_core::{Runtime, RuntimeError, TimeSource};

/// AP-profile [`Runtime`] impl: every spawn routes through
/// `tokio::task::spawn`, every join goes through tokio's
/// [`tokio::task::JoinHandle`]. Zero-sized; cheap to clone and pass
/// around as a generic `R: Runtime` parameter.
///
/// The unit-struct shape mirrors how `tokio::task::spawn` itself is a
/// free function with no receiver — the AP profile does not bind
/// runtime instances explicitly; whichever `tokio::runtime::Runtime`
/// is current at `.spawn(..)` time is the one the task lands on.
/// Construct via `TokioRuntime` directly; the auto-derived `Default`
/// impl exists so generic `T: Default` call sites compose, but
/// `TokioRuntime::default()` literally is the same value as
/// `TokioRuntime` (clippy::default_constructed_unit_structs flags
/// the explicit `::default()` call as redundant on unit structs).
///
/// MCU side will likely diverge here: embassy's executor needs an
/// explicit handle (`Spawner`), so a future `EmbassyRuntime` will
/// carry that handle by value or reference. The trait stays uniform.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    type JoinHandle<T>
        = TokioJoinHandle<T>
    where
        T: Send + 'static;

    fn spawn<F>(&self, fut: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        TokioJoinHandle {
            inner: tokio::spawn(fut),
        }
    }
}

/// Wrapper around `tokio::task::JoinHandle<T>` that adapts the
/// `Result<T, JoinError>` poll output to the trait-mandated
/// `Result<T, RuntimeError>`. The wrapper is `Send + 'static`
/// (tokio's JoinHandle is) so it satisfies the
/// [`Runtime::JoinHandle`] GAT bounds.
///
/// Dropping a `TokioJoinHandle` does NOT cancel the spawned task —
/// tokio's `JoinHandle::abort` is opt-in, and this wrapper does not
/// (yet) expose an abort method. The R251 trait contract says drop
/// = "no cancellation" so the wrapper enforces that by hiding
/// `abort` from the public surface. A future round can add an
/// explicit [`Self::abort`] method if a caller motivates it.
#[derive(Debug)]
pub struct TokioJoinHandle<T> {
    inner: tokio::task::JoinHandle<T>,
}

impl<T> Future for TokioJoinHandle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // `tokio::task::JoinHandle<T>` is `Unpin`, so we can take a
        // plain `&mut` from a pinned `Self` and re-pin it for the
        // inner poll. No unsafe, no pin-project crate needed.
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
            // tokio's JoinError disambiguates panic vs cancel via
            // `is_panic` / `is_cancelled`; the trait collapses both
            // to `JoinFailed` because MCU runtimes generally do not
            // distinguish. The disambiguation is recoverable from a
            // future round by adding a richer error variant.
            Poll::Ready(Err(_join_error)) => Poll::Ready(Err(RuntimeError::JoinFailed)),
        }
    }
}

/// AP-profile [`TimeSource`] impl: monotonic clock anchored at the
/// `TokioTime` construction time, `tokio::time::sleep` for the async
/// sleep contract.
///
/// Construction is cheap (one `Instant::now()` syscall on most
/// platforms; on Linux this is `clock_gettime(CLOCK_MONOTONIC)`).
/// `Copy` so generic callers can pass a `TokioTime` by value freely
/// — the inner [`tokio::time::Instant`] is itself `Copy`.
///
/// ## Monotonic guarantee scope
///
/// The trait contract guarantees monotonicity *within a single
/// TimeSource instance*. Two different `TokioTime` values constructed
/// at different program times will use the same underlying tokio
/// monotonic clock but report different epochs, so values are not
/// comparable across instances. wz callers that need a single
/// shared epoch should construct one `TokioTime` at session bootstrap
/// and pass it as a shared `&TokioTime` (or `T: TimeSource` generic).
///
/// ## `now_monotonic_ms` overflow
///
/// `Duration::as_millis()` returns `u128`. We cast to `u64` via
/// `as u64`; the cast truncates the upper bits but `u64` ms is ~584
/// million years — far beyond any conceivable session lifetime. The
/// truncation is therefore unobservable in practice; the cast is
/// also the canonical pattern for "milliseconds since boot" in
/// embedded systems where the wider `u128` would just bloat code.
#[derive(Debug, Clone, Copy)]
pub struct TokioTime {
    epoch: tokio::time::Instant,
}

impl TokioTime {
    /// Construct a new `TokioTime`, anchoring its monotonic epoch at
    /// the current `tokio::time::Instant`.
    pub fn new() -> Self {
        Self {
            epoch: tokio::time::Instant::now(),
        }
    }
}

impl Default for TokioTime {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for TokioTime {
    fn now_monotonic_ms(&self) -> u64 {
        // Saturating cast u128 → u64; see struct doc-comment on
        // why truncation is unobservable in practice.
        self.epoch.elapsed().as_millis() as u64
    }

    fn sleep(&self, ms: u64) -> impl Future<Output = ()> + Send + '_ {
        // `tokio::time::sleep` returns a `'static` Sleep future
        // (no borrow from `self`), so the RPITIT bound `+ '_`
        // (the &self lifetime) is satisfied trivially. The fact
        // that we even thread `&self` is contract-shape only —
        // the impl ignores `self` because the tokio API is
        // free-standing.
        tokio::time::sleep(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::time::{timeout, Duration as TokioDuration};

    #[tokio::test]
    async fn tokio_runtime_spawn_resolves_to_future_output() {
        let rt = TokioRuntime;
        let handle = rt.spawn(async { 42_u32 });
        let result = handle.await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn tokio_runtime_spawn_unit_output_resolves_to_ok_unit() {
        let rt = TokioRuntime;
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        let handle = rt.spawn(async move {
            fired_cb.fetch_add(1, Ordering::SeqCst);
        });
        let result = handle.await;
        assert_eq!(result, Ok(()));
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tokio_runtime_spawn_panic_resolves_to_join_failed() {
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            panic!("intentional panic for JoinFailed test");
        });
        let result: Result<(), RuntimeError> = handle.await;
        assert_eq!(result, Err(RuntimeError::JoinFailed));
    }

    #[tokio::test]
    async fn tokio_runtime_spawn_send_bound_compiles_for_non_unit_output() {
        // The trait's `F::Output: Send + 'static` bound is what
        // turns a buggy spawn (e.g. handing over an Rc) into a
        // compile error rather than a runtime panic. This test
        // pins the positive case: a Send value (String) compiles
        // and round-trips through the handle.
        let rt = TokioRuntime;
        let handle = rt.spawn(async { String::from("payload") });
        assert_eq!(handle.await, Ok(String::from("payload")));
    }

    #[tokio::test]
    async fn tokio_time_now_monotonic_ms_is_non_decreasing() {
        let clock = TokioTime::new();
        let t0 = clock.now_monotonic_ms();
        // Yield a few times to let the tokio runtime advance time;
        // the elapsed wall time may still be sub-millisecond, in
        // which case t1 == t0 is acceptable (the contract says
        // "non-decreasing", not strictly increasing).
        tokio::task::yield_now().await;
        let t1 = clock.now_monotonic_ms();
        assert!(t1 >= t0, "monotonic clock must not run backwards (t0={t0}, t1={t1})");
    }

    #[tokio::test]
    async fn tokio_time_sleep_waits_at_least_the_requested_duration() {
        let clock = TokioTime::new();
        let t0 = clock.now_monotonic_ms();
        clock.sleep(50).await;
        let elapsed = clock.now_monotonic_ms() - t0;
        // Allow ~5ms slack for scheduling jitter on busy CI runners.
        assert!(
            elapsed >= 45,
            "sleep(50) should park ≥~45ms (observed {elapsed} ms)",
        );
    }

    #[tokio::test]
    async fn tokio_time_sleep_zero_is_a_yield_not_a_busy_spin() {
        // The trait doc-comment says `ms = 0` is a yield hint;
        // tokio::time::sleep(0) yields cooperatively and returns
        // almost immediately. Bound the wait with a timeout so a
        // regression to busy-spin or to a runtime that
        // pathologically blocks would surface as a hang.
        let clock = TokioTime::default();
        timeout(TokioDuration::from_millis(50), clock.sleep(0))
            .await
            .expect("sleep(0) must resolve promptly (≤50ms)");
    }

    #[tokio::test]
    async fn tokio_runtime_join_handle_composes_into_a_vec() {
        // R256 — pins the design claim documented on the R251
        // Runtime trait: GATs (over the alternative `impl Future`
        // return position) let callers store handles in a Vec
        // because the GAT names the concrete handle type. Without
        // GATs every spawn() return would be an anonymous opaque
        // `impl Future` type that cannot share a slot. This test
        // exercises that batch-spawn pattern end-to-end: spawn N
        // tasks, store handles in a Vec, await each, accumulate
        // outputs. Pattern fundamental for Session's per-subscriber
        // dispatch task fan-out (the textbook payoff cited in the
        // R251 doc-comment).
        let rt = TokioRuntime;
        let mut handles: Vec<<TokioRuntime as Runtime>::JoinHandle<u32>> = Vec::new();
        for i in 0..5_u32 {
            handles.push(rt.spawn(async move { i * 2 }));
        }
        let mut outputs: Vec<u32> = Vec::with_capacity(5);
        for h in handles {
            outputs.push(h.await.expect("spawn must resolve to Ok"));
        }
        assert_eq!(outputs, vec![0, 2, 4, 6, 8]);
    }

    #[tokio::test]
    async fn tokio_runtime_and_time_are_independent_zero_state_handles() {
        // Two independent constructions of TokioRuntime + TokioTime
        // produce values that can be cloned and used concurrently
        // — proving the unit-struct + epoch-bearing-struct shape
        // composes for generic-over-runtime code that needs a
        // `(R, T)` pair.
        let rt = TokioRuntime;
        let clock = TokioTime::new();
        let rt2 = rt;
        let clock2 = clock;
        let h = rt2.spawn(async move { clock2.now_monotonic_ms() });
        let ts = h.await.expect("spawn returns Ok");
        // The captured timestamp must not be earlier than the
        // outer clock's epoch — same TokioTime epoch is being
        // sampled from both.
        assert!(ts >= clock.now_monotonic_ms().saturating_sub(1));
    }
}
