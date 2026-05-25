// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipTime<C>` — `impl wz_runtime_core::TimeSource` for the MCU
//! profile. R311av-pre Decision 7 finalize: own [`ClockSource`]
//! trait only; the `embedded-time` v0.13 crate has been stalled
//! since 2024 and an external ecosystem dep would surface as a
//! leaky abstraction against the composable-framework north star
//! (zero external coupling for the runtime contract). An optional
//! `embedded-time` adapter feature can land in R311az+ if a deploy
//! reports an ecosystem-alignment need.
//!
//! ## What the deploy crate must provide
//!
//! A type implementing [`ClockSource`] — a single method
//! `now_us(&self) -> u64` that returns the current monotonic time
//! in microseconds since an impl-defined epoch. Typical sources:
//!
//! - Cortex-M: read `SysTick->VAL` against a known reload + a
//!   wraparound counter incremented by the SysTick ISR.
//! - RISC-V: read the `mtime` MMIO register against the platform's
//!   tick frequency.
//! - host tests: an `Arc<AtomicU64>` advanced manually (see
//!   `runtime_impl.rs` test module).
//!
//! [`LwipTime`] wraps the source + an epoch (captured at
//! construction) and exposes the trait-required methods:
//! `now_monotonic_ms` (microseconds → ms with epoch subtraction),
//! `sleep(ms)` (returns a [`SleepFuture`] that self-wakes until the
//! clock crosses the deadline), and `timeout<F>(ms, fut)` (returns
//! a [`TimeoutFuture`] that polls the inner future and races it
//! against the same self-waking deadline check).
//!
//! ## Self-wake busy-poll vs. real timer queue
//!
//! [`SleepFuture::poll`] and [`TimeoutFuture::poll`] use the
//! `cx.waker().wake_by_ref()` pattern when the deadline has not
//! yet elapsed: return `Pending` after marking the task ready for
//! the next executor pass. This is correct but wastes power on
//! battery-constrained MCU deploys — every executor pass re-polls
//! the sleep future even when nothing has happened. A real timer
//! queue (deadline-keyed wake list registered with the executor)
//! is R311az+; the deploy can compensate in the interim by
//! gating its main-loop iteration on `lwip_poll()` events +
//! `wfi()` so executor passes only happen on real interrupts.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use wz_runtime_core::{TimeSource, TimeoutElapsed};

/// Deploy-supplied monotonic clock source.
///
/// The single method [`now_us`](Self::now_us) returns microseconds
/// since an impl-defined epoch. Monotonic (non-decreasing across
/// successive calls on the same instance); wraparound is the
/// impl's responsibility — `u64` µs gives ~584,000 years of range,
/// so a tick-source with a 64-bit wraparound counter (or a 32-bit
/// counter wrapped against a software extension) is sufficient.
///
/// `Send + Sync + 'static` so a `&ClockSource` can be threaded
/// through async state-machines that themselves require `Send`.
pub trait ClockSource: Send + Sync + 'static {
    /// Current monotonic time in microseconds.
    fn now_us(&self) -> u64;
}

/// `impl TimeSource` backed by a user-supplied [`ClockSource`].
///
/// The construction snapshot captures the source's current `now_us`
/// as the epoch; subsequent `now_monotonic_ms` calls subtract the
/// epoch and divide by 1000. Two independently-constructed
/// `LwipTime` instances will report different epochs even on the
/// same `ClockSource`, mirroring [`wz_runtime_tokio::TokioTime`]
/// per-instance epoch semantics.
pub struct LwipTime<C: ClockSource> {
    source: C,
    epoch_us: u64,
}

impl<C: ClockSource> LwipTime<C> {
    /// Build a new `LwipTime`. Snapshots the source's current
    /// `now_us()` as the epoch for this instance.
    pub fn new(source: C) -> Self {
        let epoch_us = source.now_us();
        Self { source, epoch_us }
    }
}

impl<C: ClockSource + Clone> Clone for LwipTime<C> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            epoch_us: self.epoch_us,
        }
    }
}

impl<C: ClockSource> TimeSource for LwipTime<C> {
    fn now_monotonic_ms(&self) -> u64 {
        // Saturating subtraction so a buggy ClockSource that
        // momentarily reports a past time does not wrap into a
        // huge ms value.
        self.source.now_us().saturating_sub(self.epoch_us) / 1000
    }

    fn sleep(&self, ms: u64) -> impl Future<Output = ()> + Send + '_ {
        SleepFuture {
            deadline_us: self.source.now_us().saturating_add(ms.saturating_mul(1000)),
            source: &self.source,
        }
    }

    fn timeout<F>(
        &self,
        ms: u64,
        fut: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send + '_
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        TimeoutFuture {
            deadline_us: self.source.now_us().saturating_add(ms.saturating_mul(1000)),
            source: &self.source,
            fut: Box::pin(fut),
        }
    }
}

/// Future returned by [`LwipTime::sleep`]. Self-wakes via
/// `cx.waker().wake_by_ref()` on each `Pending` return so the
/// executor re-polls it on the next pass; resolves to `()` once
/// the clock crosses the deadline.
///
/// Borrows `&'a C` from the parent `LwipTime`; `Send` carries
/// because `ClockSource: Send + Sync` guarantees `&C: Send`.
pub struct SleepFuture<'a, C: ClockSource> {
    deadline_us: u64,
    source: &'a C,
}

impl<'a, C: ClockSource> Future for SleepFuture<'a, C> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.source.now_us() >= self.deadline_us {
            Poll::Ready(())
        } else {
            // R311av busy-wake. R311az+ replaces with a real timer
            // queue registration so this Pending lands without
            // re-polling on every executor pass.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Future returned by [`LwipTime::timeout`]. Polls the inner
/// future first on every pass; if the inner future resolves before
/// the deadline elapses, returns `Ok(inner_output)`. If the
/// deadline elapses first, returns `Err(TimeoutElapsed)`. If
/// neither — re-arms via `wake_by_ref` and returns `Pending`.
pub struct TimeoutFuture<'a, C: ClockSource, F: Future> {
    deadline_us: u64,
    source: &'a C,
    fut: Pin<Box<F>>,
}

impl<'a, C: ClockSource, F: Future> Future for TimeoutFuture<'a, C, F> {
    type Output = Result<F::Output, TimeoutElapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll inner first — fastest-path: inner Ready before the
        // deadline check matters.
        match self.fut.as_mut().poll(cx) {
            Poll::Ready(out) => return Poll::Ready(Ok(out)),
            Poll::Pending => {}
        }
        if self.source.now_us() >= self.deadline_us {
            Poll::Ready(Err(TimeoutElapsed))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
