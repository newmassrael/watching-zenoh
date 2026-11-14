// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tracing span of the code that opens a session, carried onto the threads and the tasks the
//! drive runs the session on, when `tracing-instrument` is on.
//!
//! Upstream's `open` starts its runtime from the caller's context (`zenoh/src/api/session.rs` @
//! `runtime.start().await?;`), and the runtime spawns its listeners, dials and scouting through its
//! task controller (`zenoh/src/net/runtime/mod.rs` @
//! `.spawn_with_rt(zenoh_runtime::ZRuntime::Net, future)`, called as
//! `zenoh/src/net/runtime/orchestrator.rs` @ `self.spawn_abortable(async move {`), which wraps each
//! future in the span current at the spawn (`commons/zenoh-task/src/lib.rs` @
//! `let future = tracing::Instrument::instrument(future, tracing::Span::current());`). A scout is
//! a task of the same controller's kind (`zenoh/src/api/scouting.rs` @
//! `let task = TerminatableTask::spawn(`). So everything a session does on the network happens
//! in the span its opener was in.
//!
//! This drive runs a session on a thread of its own, and a face on a thread of its own or a local
//! task of the drive thread. A span is current per thread, so neither crossing carries it by
//! itself: the span is taken where the crossing starts ([`CallerSpan::current`]) and entered again
//! on the far side, around the thread's work ([`CallerSpan::in_scope`]) or around a task's every
//! poll ([`CallerSpan::carry`]). What runs inside then spawns on the runtime crate, whose spawns
//! carry the span current at the spawn on from there.
//!
//! Without the feature the type holds nothing and each method is the identity, so a build that
//! does not ask pays nothing.

use core::future::Future;

/// The span current where a session's work crosses onto another thread or task.
#[cfg(feature = "tracing-instrument")]
#[derive(Clone, Debug)]
pub(crate) struct CallerSpan(tracing::Span);

/// Without `tracing-instrument` there is no span to carry.
#[cfg(not(feature = "tracing-instrument"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct CallerSpan;

#[cfg(feature = "tracing-instrument")]
impl CallerSpan {
    /// The span current on this thread.
    pub(crate) fn current() -> Self {
        Self(tracing::Span::current())
    }

    /// `future`, polled inside this span wherever it is polled.
    pub(crate) fn carry<F: Future>(self, future: F) -> impl Future<Output = F::Output> {
        tracing::Instrument::instrument(future, self.0)
    }

    /// `f`, run inside this span on the calling thread.
    pub(crate) fn in_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        self.0.in_scope(f)
    }
}

#[cfg(not(feature = "tracing-instrument"))]
impl CallerSpan {
    /// Nothing to take.
    pub(crate) fn current() -> Self {
        Self
    }

    /// `future` as it was given.
    pub(crate) fn carry<F: Future>(self, future: F) -> impl Future<Output = F::Output> {
        future
    }

    /// `f`, run as it is.
    pub(crate) fn in_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        f()
    }
}

#[cfg(all(test, feature = "tracing-instrument"))]
mod tests {
    use super::*;

    /// The two crossings carry the span taken before them: a task polled after the span was left
    /// and a closure run on another thread both find it current. With the feature off the type
    /// carries nothing, which the facade's test of an open holds as its control.
    #[test]
    fn a_task_and_a_thread_run_in_the_span_taken_before_they_cross() {
        let subscriber = tracing_subscriber::registry();
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            let caller = tracing::info_span!("caller");
            assert!(caller.id().is_some(), "the subscriber gives spans ids");
            let taken = caller.in_scope(CallerSpan::current);
            let task = taken.clone().carry(async { tracing::Span::current().id() });
            let polled = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("a runtime")
                .block_on(task);
            assert_eq!(polled, caller.id(), "the task is polled in the span");
            let on_thread = std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        tracing::dispatcher::with_default(&dispatch, || {
                            taken.in_scope(|| tracing::Span::current().id())
                        })
                    })
                    .join()
                    .expect("the thread ends")
            });
            assert_eq!(on_thread, caller.id(), "the thread runs in the span");
        });
    }
}
