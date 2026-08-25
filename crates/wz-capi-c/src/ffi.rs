// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The panic guard every exported symbol runs inside.
//!
//! A Rust panic unwinding across an `extern "C"` boundary aborts the process
//! (and, before Rust 1.71, was undefined). A C program that passed a bad
//! argument should get an error CODE, not a dead process, so every export
//! catches and maps.
//!
//! The fallback is [`Z_EINVAL`](crate::result::Z_EINVAL) rather than a dedicated
//! "we panicked" code, because zenoh-c has no such code and inventing one would
//! put a value in a C program's error handling that upstream's vocabulary does
//! not contain.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::result::{ZResult, Z_EINVAL};

/// A raw C pointer the caller has asserted is safe to move across threads.
///
/// A subscriber closure's `context` is owned by the C side, and zenoh-c's
/// contract is that `call` and `drop` never run concurrently. Wrapping it lets
/// the wz drive loop — a worker thread — invoke the callback, which is what
/// upstream's own read task does. The safety obligation stays with the C caller;
/// this is the FFI trust boundary, not a claim wz can check.
#[derive(Clone, Copy)]
pub(crate) struct SendPtr(pub(crate) *mut std::ffi::c_void);

// SAFETY: the zenoh-c closure ABI makes the C `context` single-owner and
// non-aliased across the call/drop lifecycle, so moving the opaque pointer onto
// the drive thread is exactly what a native zenoh-c subscriber already does.
unsafe impl Send for SendPtr {}

/// A zenoh-c closure `{ context, call, drop }` adopted from the C side, generic
/// over the plane's `call` signature.
///
/// zenoh-c's closure families (`sample` here; `query` / `reply` in later slices)
/// are the same struct modulo the callback type and share one lifecycle rule:
/// `drop(context)` runs exactly once, at teardown, never concurrently with
/// `call`. The rule is the whole mechanism, so it lives here once rather than
/// being re-hand-written per plane.
///
/// **`Sync` is deliberately NOT implemented here.** Each plane writes its own
/// `unsafe impl Sync` for its concrete instantiation, because the argument is
/// per-plane: the subscriber plane's rests on the fan-out publish being
/// `Locality::Remote`. A blanket impl would hand that guarantee to the next
/// plane before anyone had made its argument.
pub(crate) struct CClosure<C> {
    pub(crate) context: SendPtr,
    pub(crate) call: C,
    pub(crate) drop: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
}

impl<C> CClosure<C> {
    /// Adopt a moved C closure's fields. The caller nulls the source, so from
    /// here this value owns the responsibility to run `drop(context)`.
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
            // SAFETY: zenoh-c's contract — drop runs once, never concurrently
            // with call. An unwind across the C boundary is UB, so guard it.
            let ctx = self.context.0;
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                dropfn(ctx);
            }));
        }
    }
}

/// Run `body`, mapping a panic onto [`Z_EINVAL`].
pub(crate) fn guarded<F>(body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(Z_EINVAL)
}

/// Run `body`, returning `fallback` if it panics — for exports whose return type
/// is not a status code.
pub(crate) fn guard_val<F, T>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}
