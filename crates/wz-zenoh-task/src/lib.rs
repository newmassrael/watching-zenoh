//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-task 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! ⚠️ WARNING ⚠️
//!
//! This module is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The task controller of the zenoh family (`zenoh-task` 1.10.2), over watching-zenoh: upstream's by
//! name, version, library name and public surface (inventory atom `api-compat-rust`). A
//! [`TaskController`] tracks the tasks it spawns and ends them together; a [`TerminatableTask`] is one
//! task that ends when it is dropped. A task runs on the tokio runtime the caller is on, or on the
//! role of `zenoh-runtime`'s pool the caller names, and with `tracing-instrument` every spawn carries
//! the caller's tracing span onto the runtime that polls it.

use std::{future::Future, time::Duration};

use tokio::task::JoinHandle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use zenoh_core::{ResolveFuture, Wait};
use zenoh_runtime::ZRuntime;

/// The caller's span, carried onto the runtime that polls `future`, when `tracing-instrument` is on.
#[cfg(feature = "tracing-instrument")]
fn in_caller_span<F: Future>(future: F) -> impl Future<Output = F::Output> {
    tracing::Instrument::instrument(future, tracing::Span::current())
}

/// Without `tracing-instrument` the future is spawned as it was given.
#[cfg(not(feature = "tracing-instrument"))]
fn in_caller_span<F: Future>(future: F) -> impl Future<Output = F::Output> {
    future
}

#[derive(Clone)]
pub struct TaskController {
    tracker: TaskTracker,
    token: CancellationToken,
}

impl std::fmt::Debug for TaskController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskController")
            .field("is_cancelled", &self.token.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Default for TaskController {
    fn default() -> Self {
        TaskController {
            tracker: TaskTracker::new(),
            token: CancellationToken::new(),
        }
    }
}

impl TaskController {
    /// Converts a task to abortable one, which can later be terminated by call to [`TaskController::terminate_all()`].
    pub fn into_abortable<'a, F, T>(&self, future: F) -> impl Future<Output = Option<T>> + Send + 'a
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'static,
    {
        self.token.child_token().run_until_cancelled_owned(future)
    }

    /// Spawns a task that can be later terminated by call to [`TaskController::terminate_all()`].
    /// Task output is ignored.
    pub fn spawn_abortable<F, T>(&self, future: F) -> JoinHandle<Option<T>>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let future = in_caller_span(future);
        self.tracker.spawn(self.into_abortable(future))
    }

    /// Spawns a task using a specified runtime that can be later terminated by call to [`TaskController::terminate_all()`].
    pub fn spawn_abortable_with_rt<F, T>(&self, rt: ZRuntime, future: F) -> JoinHandle<Option<T>>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let future = in_caller_span(future);
        self.tracker.spawn_on(self.into_abortable(future), &rt)
    }

    pub fn get_cancellation_token(&self) -> CancellationToken {
        self.token.child_token()
    }

    /// Spawns a task that can be cancelled cancellation of a token obtained by [`TaskController::get_cancellation_token()`],
    /// was created via [`TaskController::into_abortable()`],
    /// or can run to completion in finite amount of time, using a specified runtime.
    /// It can be later terminated by call to [`TaskController::terminate_all()`].
    pub fn spawn<F, T>(&self, future: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tracker.spawn(in_caller_span(future))
    }

    /// Spawns a task which can be cancelled via cancellation of a token obtained by [`TaskController::get_cancellation_token()`],
    /// was created via [`TaskController::into_abortable()`],
    /// or can run to completion in finite amount of time, using a specified runtime.
    /// It can be later aborted by call to [`TaskController::terminate_all()`].
    pub fn spawn_with_rt<F, T>(&self, rt: ZRuntime, future: F) -> JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.tracker.spawn_on(in_caller_span(future), &rt)
    }

    /// Attempts tp terminate all previously spawned tasks
    /// The caller must ensure that all tasks spawned with [`TaskController::spawn()`]
    /// or [`TaskController::spawn_with_rt()`] can yield in finite amount of time either because they will run to completion
    /// or due to cancellation of token acquired via [`TaskController::get_cancellation_token()`].
    /// Tasks spawned with [`TaskController::spawn_abortable()`] or [`TaskController::spawn_abortable_with_rt()`] will be aborted (i.e. terminated upon next await call).
    /// The call blocks until all tasks yield or timeout duration expires.
    /// Returns 0 in case of success, number of non terminated tasks otherwise.
    pub fn terminate_all(&self, timeout: Duration) -> usize {
        ResolveFuture::new(async move {
            if tokio::time::timeout(timeout, self.terminate_all_async())
                .await
                .is_err()
            {
                tracing::error!("Failed to terminate {} tasks", self.tracker.len());
            }
            self.tracker.len()
        })
        .wait()
    }

    /// Async version of [`TaskController::terminate_all()`].
    pub async fn terminate_all_async(&self) {
        self.tracker.close();
        self.token.cancel();
        self.tracker.wait().await
    }
}

pub struct TerminatableTask {
    handle: Option<JoinHandle<()>>,
    token: CancellationToken,
}

impl std::fmt::Debug for TerminatableTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminatableTask")
            .field("has_handle", &self.handle.is_some())
            .field("is_cancelled", &self.token.is_cancelled())
            .finish()
    }
}

impl Drop for TerminatableTask {
    fn drop(&mut self) {
        self.terminate(std::time::Duration::from_secs(10));
    }
}

impl TerminatableTask {
    pub fn create_cancellation_token() -> CancellationToken {
        CancellationToken::new()
    }

    /// Spawns a task that can be later terminated by [`TerminatableTask::terminate()`].
    /// Prior to termination attempt the specified cancellation token will be cancelled.
    pub fn spawn<F, T>(rt: ZRuntime, future: F, token: CancellationToken) -> TerminatableTask
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        TerminatableTask {
            handle: Some(rt.spawn(async move {
                future.await;
            })),
            token,
        }
    }

    /// Spawns a task that can be later aborted by [`TerminatableTask::terminate()`].
    pub fn spawn_abortable<F, T>(rt: ZRuntime, future: F) -> TerminatableTask
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let token = CancellationToken::new();
        let token2 = token.clone();
        let task = async move {
            tokio::select! {
                _ = token2.cancelled() => {},
                _ = future => {}
            }
        };

        TerminatableTask {
            handle: Some(rt.spawn(task)),
            token,
        }
    }

    /// Attempts to terminate the task.
    /// Returns true if task completed / aborted within timeout duration, false otherwise.
    pub fn terminate(&mut self, timeout: Duration) -> bool {
        ResolveFuture::new(async move {
            if tokio::time::timeout(timeout, self.terminate_async())
                .await
                .is_err()
            {
                tracing::error!("Failed to terminate the task");
                return false;
            };
            true
        })
        .wait()
    }

    /// Async version of [`TerminatableTask::terminate()`].
    pub async fn terminate_async(&mut self) {
        self.token.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tracing-instrument` carries the caller's span onto the task the controller spawns: the
    /// span is entered while the task is SPAWNED and left before it is polled, so a task that sees
    /// it saw it through the feature. The same test runs with the feature off and then the task must
    /// see no span, which is the control.
    ///
    /// The runtime has one thread and the subscriber is this thread's, so the task is polled where
    /// the subscriber is and nothing is installed for the process.
    #[tokio::test]
    async fn the_feature_decides_whether_a_spawned_task_runs_in_its_callers_span() {
        let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
        let caller = tracing::info_span!("caller");
        assert!(caller.id().is_some(), "the subscriber gives spans ids");
        let controller = TaskController::default();
        let (plain, abortable) = {
            let _inside = caller.enter();
            (
                controller.spawn(async { tracing::Span::current().id() }),
                controller.spawn_abortable(async { tracing::Span::current().id() }),
            )
        };
        let plain = plain.await.expect("the task ends");
        let abortable = abortable
            .await
            .expect("the task ends")
            .expect("nothing cancelled it");
        let want = if cfg!(feature = "tracing-instrument") {
            caller.id()
        } else {
            None
        };
        assert_eq!(plain, want, "spawn");
        assert_eq!(abortable, want, "spawn_abortable");
    }

    /// `terminate_all_async` cancels the token every abortable task runs under and waits for the
    /// tracked tasks: a task that would never end is ended, and the tracker is empty after.
    #[tokio::test]
    async fn terminate_all_ends_an_abortable_task_that_would_never_end() {
        let controller = TaskController::default();
        let handle = controller.spawn_abortable(std::future::pending::<()>());
        controller.terminate_all_async().await;
        assert_eq!(
            handle.await.expect("the task ends"),
            None,
            "it was cancelled"
        );
        assert_eq!(controller.tracker.len(), 0);
    }
}
