// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! TimeSource trait — monotonic clock + async sleep + budgeted timeout.

use core::future::Future;

/// Error returned by [`TimeSource::timeout`] when the millisecond
/// budget elapses before the inner future resolves.
///
/// Runtime-neutral by design: tokio's own
/// `tokio::time::error::Elapsed` is intentionally NOT re-exported
/// because the wz upper layer wants embassy / lwIP profiles to
/// satisfy the contract without pulling tokio into their dependency
/// graph. The unit value carries the only information a timeout
/// offers ("did it elapse") — `Ok(F::Output)` vs `Err(TimeoutElapsed)`
/// is sufficient at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutElapsed;

/// Time-related primitives the runtime layer needs.
///
/// Implementations: the tokio profile wraps `tokio::time::Instant`
/// (`elapsed() -> Duration`) and `tokio::time::sleep(Duration)`; the
/// embassy profile uses `embassy_time::Instant::now()` and
/// `embassy_time::Timer::after(Duration)`; an lwIP / FreeRTOS profile
/// can sample `xTaskGetTickCount()` and yield via
/// `vTaskDelay(pdMS_TO_TICKS(ms))` inside a host-scheduler-aware
/// future-shim. All three return `'static` futures (the sleep target
/// is owned, no borrow from `self`) so the RPITIT bound `+ Send +
/// '_` is satisfiable across profiles without lifetime gymnastics.
///
/// ## Why `now_monotonic_ms() -> u64`, not `Duration`
///
/// Two reasons:
///
/// 1. **MCU-friendly**: `core::time::Duration` is 16 bytes (u64 +
///    u32 nanoseconds). A raw `u64` millisecond is half the size and
///    needs no arithmetic to compare. The wz call sites that need
///    sub-ms resolution are zero today and most are explicitly
///    quantised to the ms grid (`QueryOptions.timeout_ms`, lease
///    intervals, retry budgets).
/// 2. **Wraparound discipline**: `u64` ms gives ~584 million years of
///    monotonic range, far beyond any reasonable session lifetime.
///    `Duration` adds wraparound ambiguity if the underlying clock
///    source itself rolls over (32-bit tick counters on small MCUs).
///    The contract document for any concrete impl can pin the
///    wraparound behaviour explicitly; the trait stays simple.
///
/// ## Why no `now_wall_clock()`
///
/// Wall-clock time is intentionally not part of this contract. wz
/// protocol logic uses monotonic intervals only (timeout, retry,
/// lease). Wall clock is needed for log timestamps + audit trail
/// metadata, which the caller obtains directly from a wall-clock
/// source it already has access to (`std::time::SystemTime` on AP,
/// `time-rs` on MCU profiles that need it). Keeping wall clock out
/// of the trait avoids the "every TimeSource must answer 'what
/// timezone'" rabbit hole.
pub trait TimeSource: Send + Sync {
    /// Monotonic time in milliseconds since an unspecified, impl-
    /// defined epoch. The only guarantee is monotonicity within a
    /// single TimeSource instance: subsequent calls return values
    /// that are non-decreasing. Different instances may use
    /// different epochs.
    fn now_monotonic_ms(&self) -> u64;

    /// Sleep for `ms` milliseconds asynchronously. The returned
    /// future is owned (`'static`) so it can be moved into a task
    /// spawned via [`crate::Runtime::spawn`]. A `ms = 0` sleep is
    /// allowed and behaves as a yield-to-runtime hint; impls SHOULD
    /// not busy-spin on `ms = 0` (tokio yields cooperatively;
    /// embassy may schedule the lowest-priority slot).
    ///
    /// The `+ '_` lifetime ties the future to `&self` lifetime for
    /// RPITIT bound completeness; real impls return `'static`
    /// futures (tokio + embassy + FreeRTOS shim all do) so the `'_`
    /// elision degrades naturally to `'static` for usage that needs
    /// it.
    fn sleep(&self, ms: u64) -> impl Future<Output = ()> + Send + '_;

    /// Race `fut` against an `ms`-millisecond budget. Resolves to
    /// `Ok(fut_output)` if the future completes first, or to
    /// `Err(TimeoutElapsed)` if the budget elapses first. The
    /// in-flight future is dropped on timeout — callers needing a
    /// graceful-shutdown handshake instead of cancellation must
    /// design that into `fut` itself; this contract only guarantees
    /// budget enforcement, not cooperative-cancel propagation.
    ///
    /// Constraints on `F`:
    ///
    /// - `Future + Send + 'static` because timeout typically wraps an
    ///   owned future (a spawned task `JoinHandle`, an `oneshot::
    ///   Receiver`, an in-flight RPC) that has no borrow from the
    ///   caller's stack. The `'static` bound matches the spawn
    ///   contract on [`crate::Runtime::spawn`] for the same reason.
    /// - `F::Output: Send` so the success arm can be moved across a
    ///   tokio scheduler boundary (the timeout future itself is
    ///   `Send`, and tokio's `select!`-style impl polls both arms
    ///   from the same task — without the bound, the success value
    ///   could not flow out of the timeout combinator).
    ///
    /// Tokio profile delegates to `tokio::time::timeout` (which is
    /// implemented as a `select!` between the wrapped future and a
    /// `sleep` future). Embassy profile composes
    /// `embassy_futures::select::select` over `Timer::after` + the
    /// inner future, mapping the timer arm to `TimeoutElapsed`.
    /// FreeRTOS / lwIP profiles compose a `vTaskDelay`-driven race
    /// future against the inner. The contract stays uniform so wz
    /// upper layers consuming timeout do not branch on profile.
    fn timeout<F>(
        &self,
        ms: u64,
        fut: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send + '_
    where
        F: Future + Send + 'static,
        F::Output: Send;
}
