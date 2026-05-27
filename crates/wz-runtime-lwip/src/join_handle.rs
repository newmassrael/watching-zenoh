// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipJoinHandle<T>` — R311av-pre Decision 6 + R311bd abort surface.
//!
//! Shared `JoinState<T>` between the spawn wrapper (the future
//! actually running inside the executor) and the handle the caller
//! holds. The wrapper writes the user future's output into
//! `JoinState::result` on completion + wakes any registered waker;
//! the handle's `Future` impl reads that result + registers the
//! caller's waker if no result is ready yet.
//!
//! ## R311bd — abort cancellation
//!
//! Each `LwipJoinHandle<T>` carries a `cancel_flag:
//! Arc<AtomicBool>` shared with the corresponding executor task
//! slot (see [`crate::executor`]). `LwipJoinHandle::abort()`:
//!
//! 1. Stores `true` into the shared `cancel_flag` with `Release`
//!    ordering. The next `run_until_idle` pass sweeps the
//!    cancel-set slots and drops the corresponding task futures
//!    (releasing any resources they held — see executor doc).
//! 2. Synchronously writes `Err(RuntimeError::JoinCancelled)`
//!    into `JoinState` if no result is present yet, then wakes
//!    the join-handle waker. An awaiting consumer of the handle
//!    resolves immediately on the next poll without waiting for
//!    the executor's sweep to land.
//!
//! Race resolution: if the task naturally completes between
//! abort's flag store and abort's JoinState write, the wrapper's
//! `is_none()` guard inside `LwipRuntime::spawn` runs first and
//! stores `Ok(output)`; abort's `is_none()` guard then sees the
//! result already populated and is a no-op. Result: natural
//! completion wins, matching tokio's `JoinHandle::abort` semantic
//! ("task finished before cancellation arrived"). Conversely, if
//! abort wins the race, `JoinCancelled` is the stored result and
//! the wrapper's later `is_none()` check is a no-op. Either way,
//! the first result that lands is the one the handle returns.
//!
//! Idempotent — calling `abort()` on an already-completed task
//! (Ok or Cancelled) is a no-op for both the cancel_flag write
//! and the JoinState write.
//!
//! ## Storage shape
//!
//! `Arc<critical_section::Mutex<RefCell<JoinState<T>>>>` — the same
//! per-runtime sync primitive (`crate::sync::Mutex<T>`) the public
//! [`crate::sync`] alias surfaces, just with the inner field made
//! explicit because `JoinState<T>` is not exported. The `RefCell`
//! interior is needed because `critical_section::Mutex<T>::borrow`
//! returns `&T`; mutating `JoinState` requires `borrow_mut` on a
//! `RefCell`.
//!
//! ## Send + Sync chain
//!
//! Trait bound (`wz_runtime_core::Runtime::JoinHandle`): `Send +
//! 'static where T: Send + 'static`. The `Sync` half is not
//! required, but the storage chain happens to be `Sync` too
//! (`critical_section::Mutex` is `Sync` where its `T: Send`, and
//! `RefCell<JoinState<T>>` is `Send` where `JoinState<T>: Send`,
//! which holds when `T: Send` because `Waker` is `Send + Sync` and
//! `RuntimeError` is `Send`). The looser trait bound is preserved
//! — calls satisfying only `Send + 'static` still compile. The
//! R311bd `cancel_flag: Arc<AtomicBool>` is `Send + Sync` so it
//! does not perturb the chain.

// R311bb — Arc routed through the polyfill alias for thumbv6m support.
use crate::atomic::{Arc, AtomicBool, Ordering};
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use critical_section::Mutex;
use wz_runtime_core::RuntimeError;

/// Shared completion / waker slot between the spawn wrapper and the
/// caller's join handle.
pub(crate) struct JoinState<T> {
    pub(crate) result: Option<Result<T, RuntimeError>>,
    pub(crate) waker: Option<Waker>,
}

impl<T> JoinState<T> {
    pub(crate) fn new() -> Self {
        Self {
            result: None,
            waker: None,
        }
    }
}

/// Handle returned by [`crate::LwipRuntime::spawn`]. Implements
/// `Future<Output = Result<T, RuntimeError>>` per the
/// [`wz_runtime_core::Runtime::JoinHandle`] GAT contract.
///
/// R311bd: `abort()` method mirrors
/// `wz_runtime_tokio::TokioJoinHandle::abort` — a struct-level
/// method (not on the [`wz_runtime_core::Runtime`] trait surface
/// since the trait skeleton R251 scoped abort out). The abort
/// pathway is documented at the module level above.
pub struct LwipJoinHandle<T> {
    state: Arc<Mutex<RefCell<JoinState<T>>>>,
    cancel_flag: Arc<AtomicBool>,
}

impl<T> LwipJoinHandle<T> {
    pub(crate) fn new(
        state: Arc<Mutex<RefCell<JoinState<T>>>>,
        cancel_flag: Arc<AtomicBool>,
    ) -> Self {
        Self { state, cancel_flag }
    }

    /// R311bd — abort the spawned task. Cooperative cancellation:
    /// the task's future is dropped at the next `run_until_idle`
    /// pass (the executor's sweep finds the flag and vacates the
    /// slot). Awaiting consumers of the handle resolve immediately
    /// to `Err(RuntimeError::JoinCancelled)` on the next poll
    /// because abort synchronously writes the result into the
    /// shared `JoinState` (no need to wait for the executor pass).
    ///
    /// Idempotent — calling abort on an already-completed task
    /// (natural Ok finish OR prior abort) is a no-op. The
    /// `JoinState::result.is_none()` guard preserves the first
    /// result that landed; abort never overwrites natural
    /// completion.
    ///
    /// Mirrors
    /// [`wz_runtime_tokio::TokioJoinHandle::abort`][tokio_abort]
    /// in surface and semantics; the implementation differs
    /// because the MCU cooperative executor cannot interrupt a
    /// running poll (tokio can, via its scheduler), so the abort
    /// signal lands at the next `run_until_idle` sweep rather
    /// than mid-poll.
    ///
    /// Not exposed on the [`wz_runtime_core::Runtime`] trait
    /// surface — same reasoning as the tokio side
    /// (R251 trait skeleton deliberately scoped abort out;
    /// adding it would require a trait extension or a separate
    /// `Cancellable` trait). The struct-level method is the
    /// pragmatic profile-side escape hatch for deploy shutdown
    /// paths.
    ///
    /// [tokio_abort]: ../../wz_runtime_tokio/runtime_impl/struct.TokioJoinHandle.html#method.abort
    pub fn abort(&self) {
        // Signal the executor sweep to drop the task body. Release
        // ordering pairs with the executor's Acquire load.
        self.cancel_flag.store(true, Ordering::Release);
        // Synchronously surface JoinCancelled to any awaiting
        // handle. The is_none() guard makes this idempotent + race-
        // safe against natural completion (see module doc).
        critical_section::with(|cs| {
            let mut s = self.state.borrow(cs).borrow_mut();
            if s.result.is_none() {
                s.result = Some(Err(RuntimeError::JoinCancelled));
                if let Some(w) = s.waker.take() {
                    w.wake();
                }
            }
        });
    }
}

impl<T> Future for LwipJoinHandle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, RuntimeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        critical_section::with(|cs| {
            let mut state = self.state.borrow(cs).borrow_mut();
            if let Some(result) = state.result.take() {
                // Drop any registered waker — the result is leaving.
                state.waker = None;
                Poll::Ready(result)
            } else {
                // Replace any prior waker with the current one so a
                // re-poll from a different executor frame is woken
                // by whoever stored the next result.
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}
