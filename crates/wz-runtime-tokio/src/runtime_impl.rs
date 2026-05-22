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
/// matches tokio's own `JoinHandle` semantics where `abort` is
/// opt-in and `drop` only releases the join channel. For deliberate
/// task cancellation, call [`Self::abort`] explicitly (R257).
///
/// ## R257 — JoinError disambiguation
///
/// The [`Future`] impl maps `tokio::task::JoinError` to one of two
/// [`RuntimeError`] variants based on `JoinError::is_cancelled()`
/// vs `JoinError::is_panic()`:
///
/// - panic → [`RuntimeError::JoinFailed`]
/// - cancellation → [`RuntimeError::JoinCancelled`]
///
/// Prior rounds collapsed both into JoinFailed; the disambiguation
/// lets shutdown paths distinguish "code broke" from "we asked the
/// task to stop". The trait-level contract (`Result<T,
/// RuntimeError>`) is unchanged; only the variant routing
/// sharpened.
///
/// ## R266 — JoinFailed panic payload capture
///
/// When `is_panic()` matches, the impl extracts the panic payload
/// via `JoinError::into_panic()` and stuffs it into
/// `RuntimeError::JoinFailed { payload: Some(box) }` (available
/// under `feature = "alloc"`, which the AP profile transitively
/// enables via `wz-runtime-core`'s `std` feature). Callers
/// downcast the payload through
/// [`RuntimeError::panic_payload`] to recover the original panic
/// message — typically `String` (from `panic!("{}", msg)`) or
/// `&'static str` (from `panic!("literal")`). Display surfaces
/// the message inline when one of those two types matches; an
/// unknown payload type falls back to the plain "panicked"
/// message string.
#[derive(Debug)]
pub struct TokioJoinHandle<T> {
    inner: tokio::task::JoinHandle<T>,
}

impl<T> TokioJoinHandle<T> {
    /// R257 — abort the spawned task. Cooperative cancellation:
    /// the task receives a cancellation signal at its next yield
    /// point (every `.await` is a yield point under tokio). After
    /// abort, polling the handle eventually resolves to
    /// `Err(RuntimeError::JoinCancelled)`. Idempotent — calling
    /// abort on an already-completed task is a no-op.
    ///
    /// Mirrors `tokio::task::JoinHandle::abort` with the trait
    /// crate's error vocabulary. Not exposed on the
    /// [`crate::runtime_impl::TokioRuntime`] trait surface
    /// because the [`Runtime`] trait skeleton (R251) deliberately
    /// scoped abort out — adding it would require either a trait
    /// extension or a separate `Cancellable` trait. The
    /// struct-level abort here is the pragmatic AP-profile escape
    /// hatch zenoh-pico shutdown paths need.
    pub fn abort(&self) {
        self.inner.abort();
    }
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
            Poll::Ready(Err(join_error)) => {
                // R257 — disambiguate JoinError. `is_cancelled()`
                // wins over `is_panic()` when both happen to be
                // true (zenoh-pico semantic: shutdown intent
                // dominates even if the task also panicked mid-
                // cancellation). The two are mutually exclusive in
                // practice; the ordering is a defence-in-depth.
                if join_error.is_cancelled() {
                    Poll::Ready(Err(RuntimeError::JoinCancelled))
                } else {
                    // R266 — extract the panic payload via
                    // JoinError::into_panic(). This consumes the
                    // JoinError (the ownership transfer is
                    // explicit: into_panic moves the boxed Any
                    // out of the JoinError). The matching
                    // !is_cancelled branch above guarantees
                    // is_panic() == true, so into_panic does not
                    // panic on a non-panic JoinError.
                    let payload = join_error.into_panic();
                    Poll::Ready(Err(RuntimeError::join_failed_with_payload(Some(
                        payload,
                    ))))
                }
            }
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
mod compile_time_assertions {
    use super::*;

    // R258 — public Phase W contract trait-bound fixity. Same
    // pattern as wz_runtime_core::error::compile_time_assertions:
    // never-called functions whose body is the bound-check; a
    // regression on Send / Sync / Copy / Default fails the build.
    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}
    fn _assert_send_sync<T: Send + Sync>() {}

    #[allow(dead_code)]
    fn tokio_runtime_trait_bounds_compile() {
        _assert_send_sync::<TokioRuntime>();
        _assert_send_sync::<TokioTime>();
        // TokioJoinHandle is Send (matches tokio's JoinHandle)
        // but NOT Sync — single-consumer join semantic; mirror
        // tokio::task::JoinHandle which is Send + !Sync.
        _assert_send::<TokioJoinHandle<()>>();
        _assert_send::<TokioJoinHandle<String>>();
    }

    // R258 — generic composition smoke test. Validates that the
    // R: Runtime + T: TimeSource trait pair is actually usable
    // from production-shaped generic code (the trajectory toward
    // Session<R, T> reparameterisation per the §5.P leaf-first
    // guidance). This function never executes; its body just
    // exercises every public trait method against generic R + T.
    #[allow(dead_code)]
    fn runtime_and_time_compose_in_generic_code<R, T>(rt: &R, clock: &T)
    where
        R: Runtime,
        T: TimeSource + Clone + Send + 'static,
    {
        let clock_for_task = clock.clone();
        let _handle: R::JoinHandle<u64> = rt.spawn(async move {
            clock_for_task.sleep(1).await;
            clock_for_task.now_monotonic_ms()
        });
        let _ts: u64 = clock.now_monotonic_ms();
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
        // R266 — RuntimeError no longer impls PartialEq under
        // `feature = "alloc"`, so `Result<T, RuntimeError>` is
        // not PartialEq either. Switch to unwrap + value compare;
        // the unwrap panics surface the actual error variant in
        // the test output for diagnosis.
        assert_eq!(result.expect("spawn succeeded"), 42);
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
        // R266 — see panic_resolves_to_join_failed comment.
        result.expect("spawn returned RuntimeError");
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tokio_runtime_spawn_panic_resolves_to_join_failed() {
        // R257 — JoinFailed now means panic specifically (not the
        // earlier collapsed panic+cancel union). Cancellation
        // resolves to JoinCancelled per the sibling abort test.
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            panic!("intentional panic for JoinFailed test");
        });
        let result: Result<(), RuntimeError> = handle.await;
        // R266 — RuntimeError no longer implements PartialEq under
        // `feature = "alloc"` (the JoinFailed payload `Box<dyn Any
        // + Send>` is not comparable); switch the assertion to
        // matches! which keys on the variant shape. The payload
        // is verified separately by the panic_payload downcast
        // test below.
        assert!(
            matches!(result, Err(RuntimeError::JoinFailed { .. })),
            "expected JoinFailed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn tokio_runtime_panic_payload_round_trips_through_join_handle() {
        // R266 — the panic payload extracted from
        // JoinError::into_panic must round-trip through
        // RuntimeError::panic_payload and downcast to the
        // original `&'static str`. Pins the wire contract that
        // `panic!("literal")` panics surface their message bytes
        // via the payload accessor.
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            panic!("payload-round-trip-marker");
        });
        let result: Result<(), RuntimeError> = handle.await;
        let err = result.expect_err("task should have panicked");
        let payload = err
            .panic_payload()
            .expect("JoinFailed carries the captured panic payload");
        let msg = payload
            .downcast_ref::<&'static str>()
            .expect("panic from a string literal downcasts to &'static str");
        assert_eq!(*msg, "payload-round-trip-marker");
        // Also pin Display surface: the message must appear in
        // the formatted error so log-grep callers can pull it
        // out without a separate downcast call.
        assert!(
            err.to_string().contains("payload-round-trip-marker"),
            "Display should embed the payload string, got {err}"
        );
    }

    #[tokio::test]
    async fn tokio_runtime_panic_string_payload_round_trips() {
        // R266 — companion to the `&'static str` test: panics
        // produced via `panic!("{}", formatted)` surface a
        // `String` payload (allocated by the panic formatter).
        // The same panic_payload accessor downcasts to String
        // and Display extracts the suffix.
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            let dynamic = "formatted-payload-marker".to_string();
            panic!("{}", dynamic);
        });
        let result: Result<(), RuntimeError> = handle.await;
        let err = result.expect_err("task should have panicked");
        let payload = err
            .panic_payload()
            .expect("JoinFailed carries the captured panic payload");
        let msg = payload
            .downcast_ref::<String>()
            .expect("panic from a formatted message downcasts to String");
        assert_eq!(msg, "formatted-payload-marker");
        assert!(err.to_string().contains("formatted-payload-marker"));
    }

    #[tokio::test]
    async fn tokio_runtime_abort_after_completion_is_noop() {
        // R259 — abort against an already-completed task is a
        // no-op (tokio contract: "If the task has already
        // completed, calling abort will not have any effect.").
        // Pin the contract from the wz wrapper's perspective: a
        // post-completion abort does NOT flip Ok(value) into
        // Err(JoinCancelled).
        let rt = TokioRuntime;
        let handle = rt.spawn(async { 42_u32 });
        // Generous wait to let the trivial task complete.
        tokio::time::sleep(TokioDuration::from_millis(50)).await;
        handle.abort();
        // R266 — Result<T, RuntimeError> not PartialEq under
        // alloc; unwrap + value compare.
        assert_eq!(handle.await.expect("post-completion abort no-op"), 42);
    }

    #[tokio::test]
    async fn tokio_runtime_abort_is_idempotent_across_repeated_calls() {
        // R259 — repeated abort calls collapse to a single
        // cancellation outcome. The first abort signals the
        // task; subsequent abort calls are silent no-ops at the
        // tokio layer. Pin from the wz wrapper: triple-abort
        // still resolves to a single JoinCancelled, never
        // panicking or surfacing a different variant.
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            tokio::time::sleep(TokioDuration::from_secs(60)).await;
        });
        handle.abort();
        handle.abort();
        handle.abort();
        let result: Result<(), RuntimeError> = handle.await;
        assert!(
            matches!(result, Err(RuntimeError::JoinCancelled)),
            "expected JoinCancelled, got {result:?}"
        );
    }

    #[tokio::test]
    async fn tokio_runtime_aborted_handle_resolves_to_join_cancelled() {
        // R257 — abort() routes to RuntimeError::JoinCancelled
        // (distinct from JoinFailed which is panic-only). Spawn a
        // task that would never complete on its own; abort it
        // immediately; the join returns the cancellation variant.
        // The task body's `tokio::time::sleep` reaches a yield
        // point where the cancellation signal lands.
        let rt = TokioRuntime;
        let handle = rt.spawn(async {
            tokio::time::sleep(TokioDuration::from_secs(60)).await;
        });
        handle.abort();
        let result: Result<(), RuntimeError> = handle.await;
        assert!(
            matches!(result, Err(RuntimeError::JoinCancelled)),
            "expected JoinCancelled, got {result:?}"
        );
    }

    #[tokio::test]
    async fn tokio_runtime_join_error_routes_panic_vs_cancel_distinctly() {
        // R257 — JoinFailed vs JoinCancelled disambiguation is
        // observable from the trait surface; pin the contract
        // with side-by-side spawns.
        let rt = TokioRuntime;
        let panic_handle = rt.spawn(async {
            panic!("panic path");
        });
        let cancel_handle = rt.spawn(async {
            tokio::time::sleep(TokioDuration::from_secs(60)).await;
        });
        cancel_handle.abort();
        let panic_outcome: Result<(), RuntimeError> = panic_handle.await;
        let cancel_outcome: Result<(), RuntimeError> = cancel_handle.await;
        assert!(
            matches!(panic_outcome, Err(RuntimeError::JoinFailed { .. })),
            "expected JoinFailed for panic path, got {panic_outcome:?}"
        );
        assert!(
            matches!(cancel_outcome, Err(RuntimeError::JoinCancelled)),
            "expected JoinCancelled for abort path, got {cancel_outcome:?}"
        );
        // Sanity: the two outcomes route to structurally distinct
        // variants — the whole point of the R257 split, preserved
        // by R266's payload-bearing JoinFailed reshape.
        assert!(!matches!(panic_outcome, Err(RuntimeError::JoinCancelled)));
        assert!(!matches!(cancel_outcome, Err(RuntimeError::JoinFailed { .. })));
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
        // R266 — Result<T, RuntimeError> not PartialEq under alloc.
        assert_eq!(
            handle.await.expect("spawn succeeded"),
            String::from("payload")
        );
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
