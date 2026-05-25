// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LwipJoinHandle<T>` — R311av-pre Decision 6.
//!
//! Shared `JoinState<T>` between the spawn wrapper (the future
//! actually running inside the executor) and the handle the caller
//! holds. The wrapper writes the user future's output into
//! `JoinState::result` on completion + wakes any registered waker;
//! the handle's `Future` impl reads that result + registers the
//! caller's waker if no result is ready yet.
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
//! — calls satisfying only `Send + 'static` still compile.
//!
//! ## Abort deferred to R311az+
//!
//! Decision 8 explicitly leaves `LwipJoinHandle::abort()` out of
//! R311av. The trait does not require abort; tokio's AP-profile
//! exposes it as a struct-level method outside the trait surface,
//! and the lwIP profile mirrors that shape — the abort method will
//! land in R311az+ along with a `CancellationToken` plumbed through
//! the TaskSlot. No abort field is reserved on `LwipJoinHandle`
//! this round; adding it later is a non-breaking struct change.

use alloc::sync::Arc;
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
pub struct LwipJoinHandle<T> {
    state: Arc<Mutex<RefCell<JoinState<T>>>>,
}

impl<T> LwipJoinHandle<T> {
    pub(crate) fn new(state: Arc<Mutex<RefCell<JoinState<T>>>>) -> Self {
        Self { state }
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
