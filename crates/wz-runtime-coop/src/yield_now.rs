// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`yield_now`]: hand control back to the executor once, then continue. Shared
//! by both task pools of this crate (the heap-backed one and the static one the
//! `session-slot` profile compiles), which is why it lives in neither.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Hand control back to the executor once, then continue.
///
/// The cooperative analog of `tokio::task::yield_now`: the first poll
/// wakes its own waker (so the task is marked ready again) and returns
/// `Pending`, letting `run_until_idle` finish its pass over the other
/// slots; the next poll returns `Ready`. A task that owns a polling loop
/// — the MCU session pump is the motivating one — awaits this at the end
/// of each iteration so it runs AS a task instead of monopolising the
/// thread.
///
/// This is deliberately a self-wake, not a timer registration: the caller
/// is asking to be re-polled as soon as the executor has gone round once,
/// which is a different question from "wake me at a deadline"
/// ([`wz_runtime_core::TimeSource::sleep`], which `CoopTime` implements,
/// answers that one). A loop that wants to idle the CPU between iterations
/// should sleep, not yield.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Future returned by [`yield_now`].
#[derive(Debug)]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            // Mark ready again before returning Pending: without this the
            // task's wake_flag stays false after `run_until_idle`'s swap
            // and the task would never be polled again.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
