// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Encodings — the MIME-ish label a publisher attaches to its payload.
//!
//! ## The constant aliases are STATIC, and that is what makes the family cheap
//!
//! Upstream exports ~60 constants (`z_encoding_text_plain`, `z_encoding_zenoh_bytes`,
//! …) as functions returning a `const z_loaned_encoding_t*`. Each is a fixed
//! label, so each is backed here by a `'static` [`EncodingState`] and the returned
//! pointer is valid forever — no allocation, no lifetime to manage, and a caller
//! may hold one past any session.
//!
//! Only the encodings upstream's example corpus actually names are exported. The
//! scope rule for this crate is a PROGRAM, not a symbol list (see the crate
//! docs), and sixty constants nothing calls would be exactly the hand-picked list
//! that rule exists to avoid.
//!
//! ## The label does not reach the wire yet, and that is stated rather than implied
//!
//! `z_publisher_options_t::encoding` is accepted and dropped by the publisher
//! plane; wz's `PublishOptions` has no encoding field on this path. So a program
//! that sets one is not misled about the API and IS misled about the wire, which
//! is why it is written down here and carried as a named residual rather than
//! left for a reader to infer from silence.

use std::ffi::c_void;

use crate::abi::{z_loaned_encoding_t, z_moved_encoding_t, z_owned_encoding_t, Handle};
use crate::ffi::{guard_val, guarded};
use crate::result::{Z_ENULL, Z_OK};

/// The label behind an encoding handle.
///
/// A borrowed `&'static str` for the constants and an owned `String` would be two
/// states; one `Cow`-free shape is used instead — the constants point at statics
/// of this exact type, and a cloned encoding allocates its own.
pub(crate) struct EncodingState {
    pub(crate) label: &'static str,
}

/// `text/plain`.
static TEXT_PLAIN: EncodingState = EncodingState {
    label: "text/plain",
};
/// `zenoh/bytes` — upstream's default when nothing is set.
static ZENOH_BYTES: EncodingState = EncodingState {
    label: "zenoh/bytes",
};
/// `zenoh/string`.
static ZENOH_STRING: EncodingState = EncodingState {
    label: "zenoh/string",
};

/// A loaned encoding view that lives for the whole program.
///
/// `z_loaned_encoding_t` holds a raw pointer, so it is not `Sync` and cannot be a
/// `static` on its own. This newtype carries the argument that makes it safe:
/// the value is written ONCE at compile time, never mutated, and its handle
/// points at a `'static` [`EncodingState`] — so every thread reads the same
/// immutable bytes pointing at the same immutable state.
///
/// The alternative — minting a view per call — would hand the C side a pointer
/// whose lifetime nothing owns, and upstream's constants are documented as valid
/// indefinitely.
#[repr(transparent)]
struct StaticLoanedEncoding(z_loaned_encoding_t);

// SAFETY: see the type's docs — immutable after compile time, pointing at a
// `'static`.
unsafe impl Sync for StaticLoanedEncoding {}

/// Build the `'static` loaned view for a `'static` state.
const fn static_view(state: &'static EncodingState) -> StaticLoanedEncoding {
    StaticLoanedEncoding(z_loaned_encoding_t {
        handle: state as *const EncodingState as *mut c_void,
        _pad: [0u8; 40 - std::mem::size_of::<Handle>()],
    })
}

/// The loaned view for `text/plain`.
static TEXT_PLAIN_VIEW: StaticLoanedEncoding = static_view(&TEXT_PLAIN);
/// The loaned view for `zenoh/bytes`.
static ZENOH_BYTES_VIEW: StaticLoanedEncoding = static_view(&ZENOH_BYTES);
/// The loaned view for `zenoh/string`.
static ZENOH_STRING_VIEW: StaticLoanedEncoding = static_view(&ZENOH_STRING);

/// Read the label behind a loaned encoding.
///
/// # Safety
/// `this_` must be null, or a valid loaned encoding whose handle slot holds a
/// live `EncodingState` pointer.
pub(crate) unsafe fn encoding_label<'a>(this_: *const z_loaned_encoding_t) -> Option<&'a str> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above.
    Some(unsafe { &*(handle as *const EncodingState) }.label)
}

/// The `text/plain` constant (zenoh-c `z_encoding_text_plain`).
#[no_mangle]
pub extern "C" fn z_encoding_text_plain() -> *const z_loaned_encoding_t {
    &TEXT_PLAIN_VIEW.0 as *const z_loaned_encoding_t
}

/// The `zenoh/bytes` constant (zenoh-c `z_encoding_zenoh_bytes`) — upstream's
/// default.
#[no_mangle]
pub extern "C" fn z_encoding_zenoh_bytes() -> *const z_loaned_encoding_t {
    &ZENOH_BYTES_VIEW.0 as *const z_loaned_encoding_t
}

/// The `zenoh/string` constant (zenoh-c `z_encoding_zenoh_string`).
#[no_mangle]
pub extern "C" fn z_encoding_zenoh_string() -> *const z_loaned_encoding_t {
    &ZENOH_STRING_VIEW.0 as *const z_loaned_encoding_t
}

/// Construct an owned copy of an encoding (zenoh-c `z_encoding_clone`).
///
/// The label is `'static` in every encoding this crate produces, so the "copy" is
/// a handle copy. That is not a shortcut around ownership: [`z_encoding_drop`]
/// frees nothing for the same reason, and the two agree by construction rather
/// than by a comment.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_clone(
    dst: *mut z_owned_encoding_t,
    this_: *const z_loaned_encoding_t,
) {
    let _ = guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        unsafe { *dst = z_owned_encoding_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle } as Handle;
        if handle.is_null() {
            return Z_ENULL;
        }
        unsafe { *dst = z_owned_encoding_t::from_handle(handle) };
        Z_OK
    });
}

/// Render an encoding's label into an owned string (zenoh-c
/// `z_encoding_to_string`).
///
/// This is what makes the label a VALUE rather than an internal tag: without it
/// the three constants would be distinguishable only by pointer identity, which a
/// C program cannot rely on across a `z_encoding_clone`.
///
/// # Safety
/// `this_` must be null or a valid loaned encoding; `out_str` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_to_string(
    this_: *const z_loaned_encoding_t,
    out_str: *mut crate::abi::z_owned_string_t,
) {
    guard_val((), || {
        if out_str.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let label = unsafe { encoding_label(this_) }.unwrap_or("");
        unsafe { *out_str = crate::string::owned_string_from(label.as_bytes()) };
    });
}

/// Borrow an encoding (zenoh-c `z_encoding_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_loan(
    this_: *const z_owned_encoding_t,
) -> *const z_loaned_encoding_t {
    this_ as *const z_loaned_encoding_t
}

/// Reset an encoding to its default (zenoh-c `z_encoding_drop`).
///
/// Frees nothing: every label this crate hands out is `'static`. See
/// [`z_encoding_clone`].
///
/// # Safety
/// `this_` must be null or a valid moved encoding.
#[no_mangle]
pub unsafe extern "C" fn z_encoding_drop(this_: *mut z_moved_encoding_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { (*this_)._this = z_owned_encoding_t::null_value() };
    }
}

/// `true` iff the owned encoding carries a label (zenoh-c
/// `z_internal_encoding_check`).
///
/// # Safety
/// `this_` must be null or a valid owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_internal_encoding_check(this_: *const z_owned_encoding_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned encoding (zenoh-c `z_internal_encoding_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned encoding.
#[no_mangle]
pub unsafe extern "C" fn z_internal_encoding_null(this_: *mut z_owned_encoding_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_encoding_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each constant is a STABLE pointer — a program may hold one indefinitely,
    /// and two calls must agree or a C-side comparison would be meaningless.
    #[test]
    fn a_constant_encoding_is_the_same_pointer_every_time() {
        assert_eq!(z_encoding_text_plain(), z_encoding_text_plain());
        assert_ne!(z_encoding_text_plain(), z_encoding_zenoh_bytes());
    }

    /// The labels are what upstream documents them to be.
    #[test]
    fn the_constants_carry_upstreams_labels() {
        // SAFETY: the constants are live `'static` values.
        unsafe {
            assert_eq!(encoding_label(z_encoding_text_plain()), Some("text/plain"));
            assert_eq!(
                encoding_label(z_encoding_zenoh_bytes()),
                Some("zenoh/bytes")
            );
        }
    }

    /// A clone reads back the same label, and a null source leaves a gravestone
    /// rather than a stale stack value.
    #[test]
    fn a_cloned_encoding_reads_back_and_a_null_source_gravestones() {
        let mut owned = z_owned_encoding_t::null_value();
        // SAFETY: local values, valid for the calls.
        unsafe {
            z_encoding_clone(&mut owned, z_encoding_text_plain());
            assert!(z_internal_encoding_check(&owned));
            assert_eq!(encoding_label(z_encoding_loan(&owned)), Some("text/plain"));

            z_encoding_clone(&mut owned, std::ptr::null());
            assert!(!z_internal_encoding_check(&owned));
        }
    }
}
