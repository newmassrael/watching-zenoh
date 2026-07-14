// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! FFI-boundary safety helpers shared across the exported symbols.
//!
//! Two invariants every `#[no_mangle] extern "C"` export upholds:
//!
//! 1. **No unwinding across the boundary.** A Rust panic crossing an
//!    `extern "C"` frame is undefined behaviour. [`guard`] wraps the body in
//!    [`std::panic::catch_unwind`] and converts a panic into a
//!    [`crate::result::Z_ERR_GENERIC`] return (or the caller-chosen fallback).
//!
//! 2. **Raw C pointers can be moved across threads.** The wz drive loop runs
//!    on a worker thread; a subscriber's C `context` pointer must travel with
//!    it. [`SendPtr`] is the explicit, auditable assertion that the C side
//!    owns that pointer's thread-safety (the pico closure contract: the
//!    callback fires from the read task, the `drop` from teardown — never
//!    concurrently).

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::result::{ZResult, Z_ERR_GENERIC};

/// Run an export body, converting a panic into a status code instead of
/// unwinding across the C ABI boundary. Returns `fallback` if the body
/// panics.
#[inline]
pub(crate) fn guard<F>(fallback: ZResult, body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => fallback,
    }
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
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(v) => v,
        Err(_) => fallback,
    }
}

/// A raw C pointer the caller has asserted is safe to move across threads.
///
/// Used for a subscriber callback's `context`: pico's contract is that the
/// callback and its `drop` never run concurrently, and the C side owns the
/// pointee. Wrapping it lets the wz drive loop (a worker thread) invoke the
/// callback. This is an FFI trust boundary — the safety obligation lives
/// with the C caller, exactly as it does in zenoh-pico.
#[derive(Clone, Copy)]
pub(crate) struct SendPtr(pub(crate) *mut std::ffi::c_void);

// SAFETY: the pico closure ABI contract makes the C `context` single-owner
// and non-aliased across the call/drop lifecycle; moving the opaque pointer
// to the drive thread is what a native pico read task already does.
unsafe impl Send for SendPtr {}

/// A pico closure `{ context, call, drop }` adopted from the C side, generic
/// over the plane's `call` signature.
///
/// pico's closure families (`sample`, `query`, and the `reply` a later round
/// adds) are the SAME struct modulo the callback type, and share one lifecycle
/// rule: `drop(context)` runs exactly once, at teardown, never concurrently
/// with `call`. That rule is the whole mechanism, so it lives here once — a
/// second hand-written copy is a second place for the drop-once discipline to
/// drift.
///
/// **`Sync` is deliberately NOT implemented here.** Each plane must write its
/// own `unsafe impl Sync for CClosure<ItsCallbackType>`, because the safety
/// argument is per-plane and genuinely different: the subscriber plane's rests
/// on the fan-out publish being `Locality::Remote`, the queryable plane's on the
/// queryable being declared `Locality::Remote`. A blanket
/// `unsafe impl<C> Sync for CClosure<C>` would silently hand that guarantee to
/// the next plane before anyone had made its argument — which is exactly the
/// class of bug R311y288 fixed on the publish plane. Rust allows `unsafe impl`
/// on a concrete instantiation, so per-plane proofs cost nothing.
///
/// `C` is the plane's pico callback typedef, which is itself already an
/// `Option<unsafe extern "C" fn(..)>` (a nullable C function pointer), so it is
/// held directly rather than re-wrapped.
pub(crate) struct CClosure<C> {
    pub(crate) context: SendPtr,
    pub(crate) call: C,
    pub(crate) drop: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
}

impl<C> CClosure<C> {
    /// Adopt a moved C closure's fields. The caller nulls the source (pico's
    /// consume-on-all-paths contract): from here this value owns the
    /// responsibility to run `drop(context)`.
    pub(crate) fn new(
        context: *mut std::ffi::c_void,
        call: C,
        drop: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
        }
    }
}

impl<C> Drop for CClosure<C> {
    fn drop(&mut self) {
        if let Some(dropfn) = self.drop.take() {
            // SAFETY: pico contract — drop runs once, never concurrently with
            // call. A panic across the C boundary is UB, so guard it.
            let ctx = self.context.0;
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
    }
}
