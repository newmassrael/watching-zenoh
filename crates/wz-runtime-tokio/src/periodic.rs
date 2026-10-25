// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A job that runs every period: a task of the process's `net` runtime that sleeps on a clock and
//! calls a function, over and over.
//!
//! It is the one such loop of this runtime. The advanced publisher's heartbeat beacon runs on it,
//! and so does every periodic job a C ABI hands its engine (`SessionEngine::start_ticker` of
//! `wz-capi-port`), so the clamp and the stop are written once.

use std::sync::Arc;
use std::time::Duration;

use wz_runtime_core::TimeSource;

/// A running periodic job. Dropping it aborts the loop, so a job whose owner is gone stops.
pub struct PeriodicTask {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for PeriodicTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Start a [`PeriodicTask`]: sleep `period` on `clock`, then call `tick`, until `tick` answers
/// `false` or the returned handle is dropped.
///
/// The task is spawned on the `net` runtime, which is where upstream puts the periodic upkeep of
/// its advanced publisher (`zenoh-ext/src/advanced_publisher.rs` @ `TerminatableTask::spawn_abortable(`):
/// work the application never waits on belongs beside gossip and not beside the API surface, and
/// the thread that starts it need not be inside a tokio runtime (R3064). `period` is clamped to a
/// millisecond, so a sub-millisecond `Duration` (which truncates to zero) cannot turn the loop into a
/// busy spin (R311y87, review C4).
pub fn spawn_periodic<T: TimeSource + Send + Sync + 'static>(
    clock: Arc<T>,
    period: Duration,
    tick: Arc<dyn Fn() -> bool + Send + Sync>,
) -> PeriodicTask {
    spawn_periodic_ms(clock, (period.as_millis() as u64).max(1), tick)
}

/// [`spawn_periodic`] for a period already in milliseconds, which is clamped to one.
pub fn spawn_periodic_ms<T: TimeSource + Send + Sync + 'static>(
    clock: Arc<T>,
    period_ms: u64,
    tick: Arc<dyn Fn() -> bool + Send + Sync>,
) -> PeriodicTask {
    let period_ms = period_ms.max(1);
    PeriodicTask {
        handle: crate::runtime_pool::WzRuntime::Net.spawn(async move {
            loop {
                clock.sleep(period_ms).await;
                if !tick() {
                    return;
                }
            }
        }),
    }
}
