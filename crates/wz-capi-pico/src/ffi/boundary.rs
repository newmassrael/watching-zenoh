// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The boundary helpers every library of the pico C ABI compiles for itself: the panic guard of an
//! export and the pointer a program asserts may move across threads.
//!
//! They hold no state of the core, so the additional library (`wz-capi-pico-ext`, the doors of the
//! additional features built apart from the core) compiles this file as its own `ffi` module, and
//! a door names `crate::ffi::guarded` in either library. What else `ffi` holds (the in-callback
//! mark, the closures' release latches) is the core's state, which the additional library reaches
//! through the extension interface instead.

use crate::result::{ZResult, Z_ERR_GENERIC};

/// Run `body`, or answer `None` when it panicked, so that no panic unwinds into the C frame that
/// called. A body that ran to the end answers `Some`.
#[cfg(feature = "std")]
#[inline]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    std::panic::catch_unwind(core::panic::AssertUnwindSafe(body)).ok()
}

/// Run `body`. Without `std` a panic does not unwind (the module doc), so a body that returns
/// ran to the end.
#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    Some(body())
}

/// Run an export body, converting a panic into a status code instead of
/// unwinding across the C ABI boundary. Returns `fallback` if the body
/// panics.
#[inline]
pub(crate) fn guard<F>(fallback: ZResult, body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    catch(body).unwrap_or(fallback)
}

/// Run an export body that returns a status code, defaulting the panic
/// fallback to [`Z_ERR_GENERIC`].
#[inline]
pub(crate) fn guarded<F>(body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    guard(Z_ERR_GENERIC, body)
}

/// Run an export body returning a value (e.g. a `usize` length); a panic
/// yields `fallback`.
#[inline]
pub(crate) fn guard_val<F, T>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    catch(body).unwrap_or(fallback)
}

/// A raw C pointer the caller has asserted is safe to move across threads.
///
/// Used for a subscriber callback's `context`: pico's contract is that the
/// callback and its `drop` never run concurrently, and the C side owns the
/// pointee. Wrapping it lets the wz drive loop (a worker thread) invoke the
/// callback. This is an FFI trust boundary — the safety obligation lives
/// with the C caller, exactly as it does in zenoh-pico.
#[derive(Clone, Copy)]
pub(crate) struct SendPtr(pub(crate) *mut core::ffi::c_void);

// SAFETY: the pico closure ABI contract makes the C `context` single-owner
// and non-aliased across the call/drop lifecycle; moving the opaque pointer
// to the drive thread is what a native pico read task already does.
unsafe impl Send for SendPtr {}
