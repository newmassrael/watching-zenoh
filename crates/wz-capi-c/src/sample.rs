// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sample a subscriber callback receives, and the four accessors
//! `z_sub.c` reads it with.
//!
//! ## The marshal IS the loaned sample
//!
//! wz delivers a [`SampleView`] that borrows the decoded frame, and its lifetime
//! ends when the callback returns. The C side gets a `z_loaned_sample_t*` and is
//! documented to copy anything it keeps, so the borrow is legal — but the wz view
//! borrows a buffer the drive loop is about to reuse, so the fields are COPIED
//! into a [`SampleMarshal`] that lives for exactly the duration of the call and
//! the C pointer is aimed at that.
//!
//! ## `bind` is separate from `new`, and the split is load-bearing
//!
//! The marshal caches loaned views that point at its OWN fields. A by-value
//! constructor returns before the value reaches its final address, so binding
//! inside `new` would hand C pointers into the dead constructor frame. `new`
//! therefore leaves the cached views unbound and [`SampleMarshal::bind`] runs
//! once the marshal is where it will stay. The sibling pico ABI records the same
//! discipline for the same reason, having once got it wrong.

use std::ffi::c_void;

use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::sink::SampleView;

use crate::abi::{
    z_loaned_bytes_t, z_loaned_keyexpr_t, z_loaned_sample_t, z_sample_kind_t, z_view_string_t,
    Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::bytes::BytesState;
use crate::ffi::guard_val;
use crate::keyexpr::KeyexprState;
use crate::string::view_string_over;

/// The zenoh-c kind constant for a wz [`SampleKind`].
pub(crate) fn sample_kind_of(kind: SampleKind) -> z_sample_kind_t {
    match kind {
        SampleKind::Put => Z_SAMPLE_KIND_PUT,
        SampleKind::Del => Z_SAMPLE_KIND_DELETE,
    }
}

/// The owned copy behind a borrowed `z_loaned_sample_t` for one callback.
///
/// Holds the payload and keyexpr in the SAME state types the rest of the ABI
/// uses ([`BytesState`] / [`KeyexprState`]), so `z_sample_payload` hands back a
/// loaned bytes that `z_bytes_to_string` reads with no special case — one
/// meaning for a handle slot across the whole crate.
pub(crate) struct SampleMarshal {
    keyexpr: KeyexprState,
    payload: BytesState,
    attachment: Option<BytesState>,
    kind: z_sample_kind_t,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
}

impl SampleMarshal {
    /// Build the marshal with its cached views still UNBOUND. See the module
    /// note for why that is not an oversight.
    pub(crate) fn new(
        keyexpr: String,
        payload: Vec<u8>,
        attachment: Option<Vec<u8>>,
        kind: z_sample_kind_t,
    ) -> Self {
        Self {
            keyexpr: KeyexprState { keyexpr },
            payload: BytesState { payload },
            attachment: attachment.map(|payload| BytesState { payload }),
            kind,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
        }
    }

    /// Point the cached views at this marshal's own fields. MUST run only once
    /// the marshal sits at its FINAL address.
    pub(crate) fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::from_handle(&self.keyexpr as *const KeyexprState as *mut c_void);
        self.loaned_payload =
            z_loaned_bytes_t::from_handle(&self.payload as *const BytesState as *mut c_void);
        self.loaned_attachment = match self.attachment.as_ref() {
            Some(state) => z_loaned_bytes_t::from_handle(state as *const BytesState as *mut c_void),
            None => z_loaned_bytes_t::null_value(),
        };
    }

    /// This marshal viewed as the borrowed `z_loaned_sample_t` the C side gets.
    pub(crate) fn as_loaned(&self) -> *const z_loaned_sample_t {
        self as *const SampleMarshal as *const z_loaned_sample_t
    }
}

/// Read the marshal behind a loaned sample.
///
/// # Safety
/// `this_` must be null, or a pointer this crate produced with
/// [`SampleMarshal::as_loaned`] and whose marshal is still alive — which, per
/// zenoh-c's contract, means "inside the callback it was handed to".
unsafe fn marshal<'a>(this_: *const z_loaned_sample_t) -> Option<&'a SampleMarshal> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(this_ as *const SampleMarshal) })
}

/// Borrow a delivered sample's keyexpr (zenoh-c `z_sample_keyexpr`).
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_keyexpr(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => &m.loaned_keyexpr as *const z_loaned_keyexpr_t,
            None => std::ptr::null(),
        }
    })
}

/// Borrow a delivered sample's payload (zenoh-c `z_sample_payload`).
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => &m.loaned_payload as *const z_loaned_bytes_t,
            None => std::ptr::null(),
        }
    })
}

/// How the sample was issued (zenoh-c `z_sample_kind`).
///
/// A gravestone reads as PUT, matching upstream's own default for the field.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_kind(this_: *const z_loaned_sample_t) -> z_sample_kind_t {
    guard_val(Z_SAMPLE_KIND_PUT, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { marshal(this_) }.map_or(Z_SAMPLE_KIND_PUT, |m| m.kind)
    })
}

/// Borrow a delivered sample's attachment, or NULL when it carries none
/// (zenoh-c `z_sample_attachment`).
///
/// NULL is the ABSENCE signal upstream specifies and `z_sub.c` branches on, so
/// this deliberately does not hand back an empty-but-present blob: a publisher
/// that attached zero bytes and one that attached nothing are different events,
/// and flattening them would make the C side print an attachment that was never
/// sent.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_attachment(
    this_: *const z_loaned_sample_t,
) -> *const z_loaned_bytes_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) if m.attachment.is_some() => &m.loaned_attachment as *const z_loaned_bytes_t,
            _ => std::ptr::null(),
        }
    })
}

/// Construct a non-owned string over a keyexpr (zenoh-c
/// `z_keyexpr_as_view_string`).
///
/// Lives here rather than in [`crate::keyexpr`] because it is a SAMPLE-plane
/// read: the only keyexpr a caller has to view is the one it just received, and
/// the borrow it hands out is valid for exactly as long as that sample is —
/// which is the marshal's lifetime, not the view's.
///
/// # Safety
/// `this_` must be null or a valid loaned keyexpr; `out_string` must be valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_keyexpr_as_view_string(
    this_: *const z_loaned_keyexpr_t,
    out_string: *mut z_view_string_t,
) {
    guard_val((), || {
        if out_string.is_null() {
            return;
        }
        // Written before the read so a caller that ignores a gravestone keyexpr
        // sees an empty string rather than a stale stack value.
        unsafe { *out_string = z_view_string_t::null_value() };
        // SAFETY: the caller's contract.
        if let Some(text) = unsafe { crate::keyexpr::keyexpr_str(this_) } {
            unsafe { *out_string = view_string_over(text) };
        }
    });
}

/// Marshal one wz [`SampleView`] and run `body` with the borrowed
/// `z_loaned_sample_t` the C side expects.
///
/// The marshal is a local, so the borrow it hands out ends when this returns —
/// which is exactly zenoh-c's contract for a callback argument.
pub(crate) fn with_marshalled<R>(
    view: &dyn SampleView,
    body: impl FnOnce(*const z_loaned_sample_t) -> R,
) -> R {
    let mut marshal = SampleMarshal::new(
        view.keyexpr().to_owned(),
        view.payload().to_vec(),
        view.attachment().map(<[u8]>::to_vec),
        sample_kind_of(view.kind()),
    );
    // Bind AFTER the move out of `new` — the marshal is at its final address
    // only here. See `SampleMarshal::bind`.
    marshal.bind();
    body(marshal.as_loaned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::z_bytes_to_string;
    use crate::string::{z_string_data, z_string_drop, z_string_len, z_view_string_loan};
    use wz_runtime_tokio::Reliability;

    /// A `SampleView` that can carry an attachment.
    ///
    /// `BorrowedSample` — the crate's own loose-bytes view — keeps the trait's
    /// `attachment() -> None` default, so it cannot exercise the PRESENT arm at
    /// all. The unit under test is this crate's marshalling of the trait, so the
    /// view is defined here rather than the accessor being tested only against
    /// the one implementation that can never return `Some`.
    struct View<'a> {
        keyexpr: &'a str,
        payload: &'a [u8],
        kind: SampleKind,
        attachment: Option<&'a [u8]>,
    }

    impl SampleView for View<'_> {
        fn keyexpr(&self) -> &str {
            self.keyexpr
        }
        fn payload(&self) -> &[u8] {
            self.payload
        }
        fn kind(&self) -> SampleKind {
            self.kind
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn attachment(&self) -> Option<&[u8]> {
            self.attachment
        }
    }

    /// Read a loaned bytes back the way upstream's `z_sub.c` does.
    fn to_string(bytes: *const z_loaned_bytes_t) -> Vec<u8> {
        let mut owned = crate::abi::z_owned_string_t::null_value();
        // SAFETY: `bytes` is a live loaned bytes from the marshal below, and
        // `owned` is a valid, writable local.
        let rc = unsafe { z_bytes_to_string(bytes, &mut owned) };
        assert_eq!(
            rc,
            crate::result::Z_OK,
            "z_bytes_to_string rejected a live payload"
        );
        // SAFETY: `owned` was just constructed by the call above.
        let out = unsafe {
            let loaned = crate::string::z_string_loan(&owned);
            std::slice::from_raw_parts(z_string_data(loaned) as *const u8, z_string_len(loaned))
                .to_vec()
        };
        let mut moved = crate::abi::z_moved_string_t { _this: owned };
        // SAFETY: `moved` wraps the owned string this test built; dropped once.
        unsafe { z_string_drop(&mut moved) };
        out
    }

    /// The accessors reproduce what the view carried — the PRESENT-attachment
    /// arm included, which no foreign CLI on this machine can drive (the only
    /// pico example that attaches, `z_pub_attachment`, publishes through a
    /// declared publisher, and that path delivers nothing even pico-to-pico in
    /// the topology the interop legs use — measured, R311y500).
    #[test]
    fn the_accessors_reproduce_a_sample_that_carries_an_attachment() {
        let view = View {
            keyexpr: "demo/capic/att",
            payload: b"BODY",
            kind: SampleKind::Put,
            attachment: Some(b"ATTACHED"),
        };
        with_marshalled(&view, |sample| {
            // SAFETY: `sample` is the marshal's borrowed view, live for this call.
            unsafe {
                assert_eq!(z_sample_kind(sample), Z_SAMPLE_KIND_PUT);
                assert_eq!(to_string(z_sample_payload(sample)), b"BODY");

                let att = z_sample_attachment(sample);
                assert!(
                    !att.is_null(),
                    "an attachment was carried but reported absent"
                );
                assert_eq!(to_string(att), b"ATTACHED");

                let mut view_string = crate::abi::z_view_string_t::null_value();
                z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view_string);
                let loaned = z_view_string_loan(&view_string);
                let text = std::slice::from_raw_parts(
                    z_string_data(loaned) as *const u8,
                    z_string_len(loaned),
                );
                assert_eq!(text, b"demo/capic/att");
            }
        });
    }

    /// NULL is the absence signal upstream's `z_sub.c` branches on, so a sample
    /// with no attachment must not hand back an empty-but-present blob. This is
    /// the arm the interop legs DO cover (they publish without attachments), and
    /// it is asserted here too so the pair is one test away from each other.
    #[test]
    fn a_sample_without_an_attachment_reports_null_not_an_empty_blob() {
        let view = View {
            keyexpr: "demo/capic/plain",
            payload: b"",
            kind: SampleKind::Del,
            attachment: None,
        };
        with_marshalled(&view, |sample| {
            // SAFETY: as above.
            unsafe {
                assert_eq!(z_sample_kind(sample), Z_SAMPLE_KIND_DELETE);
                assert!(
                    z_sample_attachment(sample).is_null(),
                    "no attachment was carried, so the accessor must report NULL — an \
                     empty blob would make upstream print an attachment never sent"
                );
            }
        });
    }

    /// A gravestone must not be dereferenced. Every accessor takes the pointer
    /// the C side was handed, and a C program that keeps one past its callback is
    /// the case upstream documents as its own error — but NULL is reachable
    /// through ordinary use (a failed declare), so it is answered rather than
    /// trusted.
    #[test]
    fn the_accessors_answer_a_null_sample_without_dereferencing_it() {
        // SAFETY: passing NULL is exactly what these guards exist for.
        unsafe {
            assert!(z_sample_keyexpr(std::ptr::null()).is_null());
            assert!(z_sample_payload(std::ptr::null()).is_null());
            assert!(z_sample_attachment(std::ptr::null()).is_null());
            assert_eq!(z_sample_kind(std::ptr::null()), Z_SAMPLE_KIND_PUT);
        }
    }
}
