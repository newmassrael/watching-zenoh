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
/// ## R311ar — `Mutex` / `RwLock` land
///
/// §5.P lists `Mutex + RwLock` on the runtime contract. R311w decision
/// lock (per §5.P caveat) selected option **(a)** — per-runtime type
/// alias — over option (b) a `MutexFamily` GAT (HKT ergonomics) and
/// option (c) AP/MCU source-tree fork (single-source-tree violation).
/// The trait therefore exposes [`Mutex<T>`](Self::Mutex) and
/// [`RwLock<T>`](Self::RwLock) as GAT associated types; the tokio
/// profile binds them to `std::sync::Mutex<T>` /
/// `std::sync::RwLock<T>` via the `wz_runtime_tokio::sync` module, and
/// future MCU profiles (`wz-runtime-lwip` / `wz-runtime-embassy`) will
/// bind their own per-profile aliases (`embassy_sync::Mutex<RawMutex,
/// T>` or `critical_section::Mutex<T>` per ISR-interleave shape) when
/// they land.
///
/// The associated-type form keeps `Session<R: Runtime, T: TimeSource>`
/// (R267 reparam target) single-parameter — `Arc<R::Mutex<...>>` does
/// not introduce an extra `M: MutexFamily` generic, sidestepping the
/// HKT-ergonomics objection that pinned the R251 deferral.
pub trait Runtime: Send + Sync + 'static {
    /// Handle type returned by [`Self::spawn`]. Must itself be a
    /// `Future` so callers can `.await` the spawned task's output.
    /// `Send + 'static` so it can move across threads (tokio) or be
    /// stored in collections that the caller passes around freely.
    type JoinHandle<T>: Future<Output = Result<T, RuntimeError>> + Send + 'static
    where
        T: Send + 'static;

    /// Per-runtime mutual-exclusion lock alias (R311ar lands; R311w
    /// option (a) — per-runtime type alias). Tokio profile binds to
    /// `std::sync::Mutex<T>` through `wz_runtime_tokio::sync::Mutex`;
    /// MCU profile will bind to `embassy_sync::Mutex<RawMutex, T>` or
    /// `critical_section::Mutex<T>` per ISR-interleave shape when
    /// `wz-runtime-lwip` / `wz-runtime-embassy` land.
    ///
    /// The `Send + Sync + 'static` bound is the minimum cross-runtime
    /// contract: AP `std::sync::Mutex<T>` satisfies it automatically
    /// for `T: Send`; MCU `critical_section::Mutex<T>` satisfies it
    /// because its lock acquisition is interrupt-disabling rather than
    /// blocking. Generic call sites (`Arc<R::Mutex<...>>` in
    /// `Session::observer`, etc.) compose against this bound without
    /// per-profile cfg.
    type Mutex<T>: Send + Sync + 'static
    where
        T: Send + 'static;

    /// Per-runtime reader-writer lock alias (R311ar lands; R311w
    /// option (a)). Same per-profile binding discipline as
    /// [`Self::Mutex`]: tokio binds to `std::sync::RwLock<T>` through
    /// `wz_runtime_tokio::sync::RwLock`; MCU profile will bind to
    /// whichever rwlock shape the executor surfaces (embassy_sync
    /// exposes `RwLock<RawMutex, T>`; lwIP single-task model can elide
    /// to `Mutex` if no real rwlock is available — that mapping is a
    /// per-MCU-profile decision when the profile lands).
    ///
    /// `T: Send + Sync + 'static` is one bound tighter than
    /// [`Self::Mutex`] (which only requires `T: Send`). Reason:
    /// `std::sync::RwLock<T>: Sync` requires `T: Send + Sync`
    /// (shared-read access lets `&T` cross threads, so `T` itself must
    /// be `Sync`), whereas `std::sync::Mutex<T>: Sync` only requires
    /// `T: Send` (exclusive-access lock yields `&mut T`, never `&T`,
    /// across threads). The trait bound matches the AP profile's
    /// concrete impl so the alias binding compiles directly; MCU
    /// profiles with the same shared-read semantic will inherit the
    /// same `T: Send + Sync` requirement automatically.
    type RwLock<T>: Send + Sync + 'static
    where
        T: Send + Sync + 'static;

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
