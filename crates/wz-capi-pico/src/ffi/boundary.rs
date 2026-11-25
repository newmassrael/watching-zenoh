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
/// called. A body that ran to the end answers `Some`. The landing of a panic is [`catch_erased`],
/// one body for every export: an export instantiates only the closure it runs, where a
/// `catch_unwind` of its own type held a call and a catch of the payload per export.
#[cfg(feature = "std")]
#[inline]
pub(crate) fn catch<R>(body: impl FnOnce() -> R) -> Option<R> {
    let mut body = Some(body);
    let mut out = None;
    catch_erased(&mut || {
        if let Some(body) = body.take() {
            out = Some(body());
        }
    });
    out
}

/// Run `body` under `catch_unwind`; a panic's payload is dropped here. Whether it ran to the end
/// is what its caller's result says.
#[cfg(feature = "std")]
#[inline(never)]
fn catch_erased(body: &mut dyn FnMut()) {
    let _ = std::panic::catch_unwind(core::panic::AssertUnwindSafe(body));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A body that runs to the end is answered with its value, through the guard too. Turned red
    /// by a catch that loses the value of a body that returned.
    #[test]
    fn a_body_that_returns_is_answered_with_its_value() {
        assert_eq!(catch(|| 7u8), Some(7));
        assert_eq!(guard_val(0u8, || 5), 5);
        assert_eq!(guarded(|| crate::result::Z_OK), crate::result::Z_OK);
    }

    /// With `std` a panicking body is caught at the boundary: the catch answers nothing and the
    /// guard its fallback. Turned red by a catch that lets the panic unwind past it.
    #[cfg(feature = "std")]
    #[test]
    fn a_body_that_panics_answers_nothing_and_the_fallback() {
        assert_eq!(catch(|| -> u8 { panic!("a panic at the boundary") }), None);
        assert_eq!(guard_val(3u8, || panic!("a panic at the boundary")), 3);
        assert_eq!(guarded(|| panic!("a panic at the boundary")), Z_ERR_GENERIC);
    }
}
