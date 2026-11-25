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

use crate::result::ZResult;

/// Run `body`: a plain call in every build. A panic aborts at the C boundary (the owner's panic
/// policy for the C libraries, as zenoh-pico is C and upstream zenoh's release profile aborts):
/// without `std` the panic handler stops the program, and with it a panic that reaches an
/// `extern "C"` frame aborts there, as a Rust function of the C ABI cannot unwind. So no export
/// carries a landing pad, and a panic is a defect the no-panic gate finds, never an error code.
/// The answer is always `Some`; the `Option` is the shape its callers read.
#[inline(always)]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    Some(body())
}

/// Run an export body that returns a status code. It has no fallback answer, as no body stops
/// short of its end: [`catch`] is a plain call and a panic aborts.
#[inline(always)]
pub(crate) fn guarded<F>(body: F) -> ZResult
where
    F: FnOnce() -> ZResult,
{
    body()
}

/// Run an export body returning a value (e.g. a `usize` length), as [`guarded`] does.
#[inline(always)]
pub(crate) fn guard_val<F, T>(body: F) -> T
where
    F: FnOnce() -> T,
{
    body()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary is a plain call in every build: a body runs once and its value is answered,
    /// through the guards too. Turned red by a catch or a guard that drops the value or runs the
    /// body twice.
    #[test]
    fn a_body_runs_once_and_is_answered_with_its_value() {
        let mut runs = 0u8;
        assert_eq!(
            catch(|| {
                runs += 1;
                7u8
            }),
            Some(7)
        );
        assert_eq!(runs, 1);
        assert_eq!(
            guard_val(|| {
                runs += 1;
                5u8
            }),
            5
        );
        assert_eq!(runs, 2);
        assert_eq!(guarded(|| crate::result::Z_OK), crate::result::Z_OK);
        assert_eq!(guarded(|| 3), 3);
    }
}
