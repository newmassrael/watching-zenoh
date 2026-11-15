// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tracing span of the code that opens or closes a session, carried onto the threads and the
//! tasks the engine does that work on, when `tracing-instrument` is on.
//!
//! Upstream's `open` starts its runtime from the caller's context (`zenoh/src/api/session.rs` @
//! `runtime.start().await?;`), and the runtime spawns its listeners, dials and scouting through its
//! task controller (`zenoh/src/net/runtime/mod.rs` @
//! `.spawn_with_rt(zenoh_runtime::ZRuntime::Net, future)`, called as
//! `zenoh/src/net/runtime/orchestrator.rs` @ `self.spawn_abortable(async move {`), which wraps each
//! future in the span current at the spawn (`commons/zenoh-task/src/lib.rs` @
//! `let future = tracing::Instrument::instrument(future, tracing::Span::current());`). A scout is
//! a task of the same controller's kind (`zenoh/src/api/scouting.rs` @
//! `let task = TerminatableTask::spawn(`). Its close runs on the runtime's pool through
//! `zenoh/src/api/builders/close.rs` @ `ZRuntime::Net.block_in_place(self.into_future())`, which
//! carries the caller's span onto the future (`commons/zenoh-runtime/src/lib.rs` @
//! `let f = tracing::Instrument::instrument(f, tracing::Span::current());`), and closes the task
//! controller and the transports inside it (`zenoh/src/api/session.rs` @
//! `self.0.task_controller.terminate_all_async().await;`). So everything a session does on the
//! network, from its open to its close, happens in the span of the code that asked for it.
//!
//! This engine runs a session on a thread of its own, a face on a thread of its own or a local
//! task of the drive thread, and the facade crate runs a close where blocking is allowed. A span
//! is current per thread, so no such crossing carries it by itself: the span is taken where the
//! crossing starts ([`CallerSpan::current`](crate::caller_span::CallerSpan::current)) and entered
//! again on the far side, around the thread's work
//! ([`CallerSpan::in_scope`](crate::caller_span::CallerSpan::in_scope)) or around a task's every
//! poll ([`CallerSpan::carry`](crate::caller_span::CallerSpan::carry)).
//! What runs inside then spawns on the runtime crate, whose spawns carry the span current at the
//! spawn on from there.
//!
//! One public shape in every build, the feature deciding only what is inside, as upstream writes
//! its own (`#[cfg]` on the statement that wraps the future): without the feature the type holds
//! nothing and each method is the identity, so a build that does not ask pays nothing.

use core::future::Future;

/// The span current where a session's work crosses onto another thread or task.
#[derive(Clone, Debug)]
pub struct CallerSpan {
    #[cfg(feature = "tracing-instrument")]
    span: tracing::Span,
}

impl CallerSpan {
    /// The span current on this thread.
    pub fn current() -> Self {
        Self {
            #[cfg(feature = "tracing-instrument")]
            span: tracing::Span::current(),
        }
    }

    /// `future`, polled inside this span wherever it is polled.
    pub fn carry<F: Future>(self, future: F) -> impl Future<Output = F::Output> {
        #[cfg(feature = "tracing-instrument")]
        {
            tracing::Instrument::instrument(future, self.span)
        }
        #[cfg(not(feature = "tracing-instrument"))]
        {
            future
        }
    }

    /// `f`, run inside this span on the calling thread.
    pub fn in_scope<R>(&self, f: impl FnOnce() -> R) -> R {
        #[cfg(feature = "tracing-instrument")]
        let _inside = self.span.enter();
        f()
    }
}

#[cfg(all(test, feature = "tracing-instrument"))]
mod tests {
    use super::*;

    /// The two crossings carry the span taken before them: a task polled after the span was left
    /// and a closure run on another thread both find it current. With the feature off the type
    /// carries nothing, which the facade's test of an open and a close holds as its control.
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
