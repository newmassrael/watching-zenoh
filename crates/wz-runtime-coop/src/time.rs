// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `CoopTime<C>` — `impl wz_runtime_core::TimeSource` for the MCU
//! profile. R311av-pre Decision 7 finalize: own [`ClockSource`]
//! trait only; the `embedded-time` v0.13 crate has been stalled
//! since 2024 and an external ecosystem dep would surface as a
//! leaky abstraction against the composable-framework north star
//! (zero external coupling for the runtime contract). An optional
//! `embedded-time` adapter feature can land in a later round if a
//! deploy reports an ecosystem-alignment need.
//!
//! ## R311bc rework: time source borrows from runtime
//!
//! Construction sig changed from R311av:
//!
//! - R311av: `CoopTime::new(source: C)` — owned the ClockSource;
//!   `SleepFuture<'a, C>` borrowed `&'a C` directly.
//! - R311bc: `CoopTime::new(rt: &CoopRuntime<C>)` — clones the
//!   shared `Arc<RuntimeInner<C>>`; `SleepFuture<C>` is `'static`
//!   (owns the Arc) and registers its waker with the runtime's
//!   timer queue on first Pending poll.
//!
//! The breaking change is intentional. Under R311av the clock and
//! the timer source were two different physical objects (clock
//! owned by `CoopTime`, no timer source at all — sleep futures
//! self-waked). Under R311bc both live in the same
//! `Arc<RuntimeInner<C>>` so a deadline registered by one sleep
//! and a `now_us()` sample taken by `run_until_idle` necessarily
//! agree.
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
//! The deploy passes its `ClockSource` instance to
//! [`crate::CoopRuntime::new`]; both `CoopTime` and the timer
//! queue read from that one instance via the shared `Arc`.
//!
//! ## Wake-on-deadline (R311bc) vs self-wake (R311av retired)
//!
//! [`SleepFuture::poll`] and [`TimeoutFuture::poll`] no longer use
//! the `cx.waker().wake_by_ref()` self-wake pattern. On first poll
//! that returns `Pending`, the future calls
//! `runtime.timers().register(deadline_us, cx.waker().clone())`;
//! subsequent polls (re-triggered by the inner future in the case
//! of `TimeoutFuture`) check `registered` to avoid duplicate heap
//! entries.
//!
//! The deploy `wfi()`-sleep semantics now hold: when no task is
//! ready and no timer has elapsed, the executor pass is idle, and
//! `wfi()` actually sleeps until the next IRQ (HAL timer expiry,
//! lwIP RX, etc.). Under R311av the executor's self-wake busy-poll
//! kept every pass active.

use crate::atomic::Arc;
use crate::runtime_impl::{CoopRuntime, RuntimeInner};
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

/// `impl TimeSource` backed by the runtime's shared [`ClockSource`].
///
/// R311bc: construction borrows from [`CoopRuntime`] so the time
/// source, the runtime's timer queue, and the runtime's task pool
/// all reference the same `Arc<RuntimeInner<C>>`. The construction
/// snapshot captures the source's current `now_us` as the epoch;
/// subsequent `now_monotonic_ms` calls subtract the epoch and
/// divide by 1000. Two independently-constructed `CoopTime`
/// instances on the same runtime will report different epochs,
/// mirroring [`wz_runtime_tokio::TokioTime`] per-instance epoch
/// semantics.
pub struct CoopTime<C: ClockSource> {
    inner: Arc<RuntimeInner<C>>,
    epoch_us: u64,
}

impl<C: ClockSource> CoopTime<C> {
    /// Build a new `CoopTime` sharing the runtime's clock + timer
    /// queue. Snapshots the clock's current `now_us()` as the
    /// epoch for this instance.
    pub fn new(rt: &CoopRuntime<C>) -> Self {
        let epoch_us = rt.clock().now_us();
        Self {
            inner: rt.inner.clone(),
            epoch_us,
        }
    }
}

impl<C: ClockSource> Clone for CoopTime<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            epoch_us: self.epoch_us,
        }
    }
}

impl<C: ClockSource> TimeSource for CoopTime<C> {
    fn now_monotonic_ms(&self) -> u64 {
        // Saturating subtraction so a buggy ClockSource that
        // momentarily reports a past time does not wrap into a
        // huge ms value.
        self.inner.clock.now_us().saturating_sub(self.epoch_us) / 1000
    }

    fn sleep(&self, ms: u64) -> impl Future<Output = ()> + Send + '_ {
        SleepFuture {
            deadline_us: self
                .inner
                .clock
                .now_us()
                .saturating_add(ms.saturating_mul(1000)),
            inner: self.inner.clone(),
            registered: false,
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
            deadline_us: self
                .inner
                .clock
                .now_us()
                .saturating_add(ms.saturating_mul(1000)),
            inner: self.inner.clone(),
            fut: Box::pin(fut),
            registered: false,
        }
    }
}

/// Future returned by [`CoopTime::sleep`]. R311bc: registers its
/// waker with the runtime's [`crate::timer::TimerQueue`] on first
/// Pending poll instead of self-waking. Resolves to `()` once the
/// clock crosses the deadline.
///
/// Owns an `Arc<RuntimeInner<C>>` so the future is `'static` and
/// composes naturally into `tokio::spawn`-shaped contracts (the
/// `'static` bound on `Runtime::spawn` matches automatically). The
/// `Send` half carries because the inner Arc is `Send + Sync`
/// (which holds when `C: ClockSource` since the trait requires
/// `Send + Sync + 'static`).
pub struct SleepFuture<C: ClockSource> {
    deadline_us: u64,
    inner: Arc<RuntimeInner<C>>,
    registered: bool,
}

// SleepFuture has no self-referential storage; the Arc is movable
// and the bool / u64 are trivially Unpin. Explicit Unpin lets
// `poll` access fields via the safe `Pin::get_mut` path rather
// than `unsafe { Pin::into_inner_unchecked }`.
impl<C: ClockSource> Unpin for SleepFuture<C> {}

impl<C: ClockSource> Future for SleepFuture<C> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.inner.clock.now_us() >= this.deadline_us {
            return Poll::Ready(());
        }
        if !this.registered {
            this.inner
                .timers
                .register(this.deadline_us, cx.waker().clone());
            this.registered = true;
        }
        Poll::Pending
    }
}

/// Future returned by [`CoopTime::timeout`]. Polls the inner
/// future first on every pass; if the inner future resolves before
/// the deadline elapses, returns `Ok(inner_output)`. If the
/// deadline elapses first, returns `Err(TimeoutElapsed)`.
///
/// R311bc: registers its waker on the timer queue exactly once
/// (the `registered` flag) instead of re-arming via wake_by_ref.
/// The inner future's own wakers drive most re-polls; the timer
/// queue's deadline wake is the fallback when the inner stays
/// Pending past the deadline.
pub struct TimeoutFuture<C: ClockSource, F: Future> {
    deadline_us: u64,
    inner: Arc<RuntimeInner<C>>,
    fut: Pin<Box<F>>,
    registered: bool,
}

// Pin<Box<F>> contains the pinning guarantee for F internally; the
// outer wrapper struct itself can be moved freely because moving
// it copies the Box pointer, not F. Explicit Unpin to enable safe
// field access in poll().
impl<C: ClockSource, F: Future> Unpin for TimeoutFuture<C, F> {}

impl<C: ClockSource, F: Future> Future for TimeoutFuture<C, F> {
    type Output = Result<F::Output, TimeoutElapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Poll inner first — fastest-path: inner Ready before the
        // deadline check matters.
        match this.fut.as_mut().poll(cx) {
            Poll::Ready(out) => return Poll::Ready(Ok(out)),
            Poll::Pending => {}
        }
        if this.inner.clock.now_us() >= this.deadline_us {
            return Poll::Ready(Err(TimeoutElapsed));
        }
        if !this.registered {
            this.inner
                .timers
                .register(this.deadline_us, cx.waker().clone());
            this.registered = true;
        }
        Poll::Pending
    }
}
