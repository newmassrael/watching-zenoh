// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `CoopJoinHandle<T>` on STATIC storage (`session-slot`, fixed-memory step S6):
//! the form of [`crate::join_handle`] the MCU session profile compiles in its
//! place.
//!
//! The heap form shared an `Arc<Mutex<RefCell<JoinState<T>>>>` with the spawn
//! wrapper. Here the result is written into the task's own cell
//! ([`crate::executor`]'s `TaskCell`) and the handle is a reference to that cell:
//! reading the result, aborting the task and dropping the handle are each one
//! critical section on it, and the cell is freed for the next task only when the
//! handle is done with it.
//!
//! A spawn that was refused (every cell taken, or the future too large) is a
//! handle too, because the `Runtime::spawn` contract has no failure to return: it
//! answers `Err(RuntimeError::Shutdown)` ("new work refused") the first time it is
//! polled, and the refusal is counted by the executor.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use wz_runtime_core::RuntimeError;

use crate::executor::TaskJoin;

/// Handle returned by `CoopRuntime::spawn`. Implements
/// `Future<Output = Result<T, RuntimeError>>` per the
/// [`wz_runtime_core::Runtime::JoinHandle`] GAT contract.
pub struct CoopJoinHandle<T> {
    join: TaskJoin<T>,
}

impl<T> CoopJoinHandle<T> {
    pub(crate) fn new(join: TaskJoin<T>) -> Self {
        Self { join }
    }

    /// Abort the spawned task. Cooperative cancellation: the task's future is
    /// dropped at the next `run_until_idle` pass and its cell freed; an awaiting
    /// consumer of the handle resolves to `Err(RuntimeError::JoinCancelled)` at
    /// once. Idempotent, and a task that already ended keeps its result.
    pub fn abort(&self) {
        self.join.abort();
    }
}

impl<T> Future for CoopJoinHandle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, RuntimeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.join.poll_join(cx)
    }
}

impl<T> Unpin for CoopJoinHandle<T> {}
