// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one-call-at-a-time rule of the library, for a host.
//!
//! Mbed TLS keeps its arena and PSA Crypto its key store and random generator in process-wide
//! state with no lock, because the profile this serves runs one thread and the image would pay
//! for a lock it never contends. A host process is not that: a C program's read task steps one
//! session while its own thread publishes on another, two engines of a test run on a thread each,
//! and each reaches this library. With `host-lock` every call into the C side
//! (`ffi::locked_calls`) holds one process-wide mutex, so calls never overlap whatever thread
//! makes them. It is held only inside a call, never across the waits a stream makes between them,
//! so a thread that waits for its peer does not keep the peer from running.
//!
//! The lock is a leaf: the C side calls back into the transport (`Transport::send`/`recv`) while
//! it is held, and a transport never calls this crate, so no cycle forms. Without `host-lock`
//! there is no lock and `locked` is the call itself.

#[cfg(feature = "host-lock")]
pub(crate) fn locked<R>(call: impl FnOnce() -> R) -> R {
    use std::sync::{Mutex, PoisonError};

    static LIBRARY: Mutex<()> = Mutex::new(());
    // A call that panicked (a transport's callback, say) leaves the library as it left it: the
    // state is the C side's, which a panic in Rust does not corrupt.
    let _held = LIBRARY.lock().unwrap_or_else(PoisonError::into_inner);
    call()
}

#[cfg(not(feature = "host-lock"))]
#[inline(always)]
pub(crate) fn locked<R>(call: impl FnOnce() -> R) -> R {
    call()
}
