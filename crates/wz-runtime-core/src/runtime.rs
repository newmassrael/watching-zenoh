// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Runtime trait — async-task spawn contract.

use core::future::Future;

use crate::error::RuntimeError;

/// Async-runtime contract: spawn a future as a detachable task and
/// return a handle that resolves to the task's output (or a
/// [`RuntimeError`] if the task panicked, was cancelled, or the runtime
/// is shutting down).
///
/// Mirrors the tokio `tokio::task::JoinHandle<T>` shape — that handle
/// itself implements `Future<Output = Result<T, JoinError>>`. The
/// trait's [`JoinHandle`](Self::JoinHandle) GAT is therefore declared as
/// `Future<Output = Result<T, RuntimeError>>` so tokio's `JoinHandle`
/// can satisfy the contract directly by wrapping `JoinError` into
/// [`RuntimeError::JoinFailed`]. For embassy on MCU the matching shape
/// is `embassy_executor::SpawnToken` plus a join-channel — those are
/// future R252+ design questions; this trait only pins the contract.
///
/// ## Why GAT (`type JoinHandle<T>`) instead of `impl Future`
///
/// Two reasons:
///
/// 1. **Caller composition**: code that wants to store handles in a
///    `Vec` needs a named type; an `impl Future` return position is
///    anonymous-per-call-site and cannot be collected. A `Vec<R::
///    JoinHandle<()>>` is the textbook pattern for batch-spawn flows
///    (think: `Session` spawning per-subscriber dispatch tasks) and
///    that requires the GAT form.
/// 2. **Auto-trait propagation**: a GAT lets the trait constrain
///    `Send + 'static` on the handle explicitly; an `impl Future`
///    return type carries auto-traits implicitly which surfaces as
///    cryptic "doesn't implement Send" errors deep in user code.
///
/// ## Why no `Mutex` / `RwLock` here
///
/// §5.P lists `Mutex + RwLock` on the runtime contract. They were
/// intentionally deferred from R251 — the generic-over-T shape (a
/// `Mutex<T>` is parameterised on the protected value) does not
/// compose with a single GAT, and the choice between a
/// `MutexFamily`-style trait, per-runtime type alias, or
/// straight-conditional-compilation is a R252+ design decision tied
/// to actual MCU call-site shape (Embassy uses `embassy_sync::
/// Mutex<RawMutex, T>` which carries an extra raw-mutex parameter).
/// See lib.rs module doc-comment for the carry note.
pub trait Runtime: Send + Sync + 'static {
    /// Handle type returned by [`Self::spawn`]. Must itself be a
    /// `Future` so callers can `.await` the spawned task's output.
    /// `Send + 'static` so it can move across threads (tokio) or be
    /// stored in collections that the caller passes around freely.
    type JoinHandle<T>: Future<Output = Result<T, RuntimeError>> + Send + 'static
    where
        T: Send + 'static;

    /// Spawn `fut` on the runtime, returning a handle that resolves
    /// when the task completes. The future is detached on spawn — the
    /// returned handle is for joining, not lifetime control; dropping
    /// it does NOT cancel the spawned task (matches tokio
    /// `JoinHandle::abort` contract, which is opt-in).
    ///
    /// The `'static` bound on `F` matches tokio's `spawn` contract: a
    /// detached task cannot borrow from the caller's stack. Embassy
    /// on MCU has a similar restriction via its `'static` SpawnToken
    /// model, so the bound is uniform across profiles.
    fn spawn<F>(&self, fut: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}
