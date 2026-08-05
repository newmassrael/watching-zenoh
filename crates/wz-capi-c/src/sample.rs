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
    /// R311y557 — the sample's own timestamp, or `None` when it carries none.
    ///
    /// Stored BY VALUE inside the marshal (24 bytes, `Copy`) rather than behind
    /// a box, because `z_sample_timestamp` hands out a borrowed pointer to it
    /// and that pointer's lifetime is the marshal's — the same contract
    /// `z_sample_attachment` has, reached the same way.
    timestamp: Option<crate::timestamp::z_timestamp_t>,
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
        timestamp: Option<crate::timestamp::z_timestamp_t>,
    ) -> Self {
        Self {
            keyexpr: KeyexprState { keyexpr },
            payload: BytesState::whole(payload),
            attachment: attachment.map(BytesState::whole),
            kind,
            timestamp,
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

/// Mutably borrow a delivered sample's payload (zenoh-c
/// `z_sample_payload_mut`).
///
/// UNGATED upstream — it is declared on the no-unstable header too
/// (`zenoh_commons.h:4638` there, `:4393` on the shared-memory oracle) — so it
/// is exported on every arm even though the corpus reaches it only through
/// `z_sub_shm.c`, which hands the result straight to
/// `z_bytes_as_mut_loaned_shm`.
///
/// The pointer is taken with `addr_of_mut!` rather than by reborrowing a shared
/// reference: handing back a `*mut` derived from a `&` would be a provenance
/// laundering the caller is entitled to write through.
///
/// # Safety
/// `this_` must be null or a live loaned sample. The returned pointer borrows
/// the sample and is valid for as long as it is.
#[no_mangle]
pub unsafe extern "C" fn z_sample_payload_mut(
    this_: *mut z_loaned_sample_t,
) -> *mut z_loaned_bytes_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        let m = this_ as *mut SampleMarshal;
        // SAFETY: the caller's contract — `this_` aims at a live `SampleMarshal`,
        // and the field projection creates no intermediate reference.
        unsafe { std::ptr::addr_of_mut!((*m).loaned_payload) }
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

/// Borrow a delivered sample's timestamp, or NULL when it carries none
/// (zenoh-c `z_sample_timestamp`).
///
/// R311y557. NULL is not an error and is the ordinary answer: a sample is
/// stamped only when its publisher set `z_put_options_t::timestamp` or the
/// node clock is stamping, and upstream returns NULL for the rest. The pointer
/// borrows the marshal, exactly as [`z_sample_attachment`] does.
///
/// # Safety
/// `this_` must be null or a live loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_timestamp(
    this_: *const z_loaned_sample_t,
) -> *const crate::timestamp::z_timestamp_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { marshal(this_) } {
            Some(m) => match m.timestamp.as_ref() {
                Some(ts) => ts as *const crate::timestamp::z_timestamp_t,
                None => std::ptr::null(),
            },
            None => std::ptr::null(),
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
        // R311y557 — the delivered timestamp, so `z_sample_timestamp` answers
        // what the publisher stamped rather than always NULL.
        view.timestamp()
            .map(crate::timestamp::z_timestamp_t::from_hint),
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

// --- R311y539: the OWNED sample --------------------------------------------

impl SampleMarshal {
    /// An INDEPENDENT copy with its cached views still UNBOUND, for a sample
    /// that must outlive the callback it was delivered to.
    ///
    /// The views are deliberately left unbound rather than copied: they hold
    /// the ADDRESS of the source marshal's fields, and copying them would aim
    /// the new sample's accessors at the old marshal — a use-after-free the
    /// moment the callback returns. [`Self::bind`] re-aims them at the copy's
    /// own fields once it is at its final address.
    pub(crate) fn deep_copy(&self) -> Self {
        Self {
            keyexpr: KeyexprState {
                keyexpr: self.keyexpr.keyexpr.clone(),
            },
            payload: BytesState::whole(self.payload.payload.clone()),
            attachment: self
                .attachment
                .as_ref()
                .map(|state| BytesState::whole(state.payload.clone())),
            kind: self.kind,
            // `Copy`, and owned by value — the deep copy carries the same
            // 24 bytes rather than a pointer into the source marshal, so a
            // sample that outlives its callback keeps its own timestamp.
            timestamp: self.timestamp,
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            loaned_payload: z_loaned_bytes_t::null_value(),
            loaned_attachment: z_loaned_bytes_t::null_value(),
        }
    }
}

/// Escape a borrowed sample onto the heap, bound at its final address — what a
/// sample CHANNEL does when the callback hands it a sample.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a sample callback.
pub(crate) unsafe fn escape_sample(src: *const z_loaned_sample_t) -> crate::abi::Handle {
    // SAFETY: the caller's contract, delegated.
    let Some(m) = (unsafe { marshal(src) }) else {
        return std::ptr::null_mut();
    };
    let mut boxed = Box::new(m.deep_copy());
    boxed.bind();
    Box::into_raw(boxed) as crate::abi::Handle
}

/// Borrow an owned sample (zenoh-c `z_sample_loan`).
///
/// The handle IS the marshal pointer the accessors read, so this reads slot 0
/// rather than casting the owned struct.
///
/// # Safety
/// `this_` must be null or a valid owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_loan(
    this_: *const crate::abi::z_owned_sample_t,
) -> *const z_loaned_sample_t {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        unsafe { (*this_).handle as *const z_loaned_sample_t }
    })
}

/// Deep-copy a borrowed sample into an owned one (zenoh-c `z_sample_clone`).
///
/// # Safety
/// `dst` must be null or valid and writable; `this_` must be null or a live
/// loaned sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_clone(
    dst: *mut crate::abi::z_owned_sample_t,
    this_: *const z_loaned_sample_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // The gravestone first, so a caller that clones a null sample sees an
        // empty owned value rather than a stale stack one.
        // SAFETY: the caller's contract.
        unsafe { *dst = crate::abi::z_owned_sample_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        let handle = unsafe { escape_sample(this_) };
        if !handle.is_null() {
            // SAFETY: as above.
            unsafe { *dst = crate::abi::z_owned_sample_t::from_handle(handle) };
        }
    });
}

/// `true` iff the owned sample holds a live marshal (zenoh-c
/// `z_internal_sample_check`).
///
/// # Safety
/// `this_` must be null or a valid owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_internal_sample_check(
    this_: *const crate::abi::z_owned_sample_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned sample (zenoh-c `z_internal_sample_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned sample.
#[no_mangle]
pub unsafe extern "C" fn z_internal_sample_null(this_: *mut crate::abi::z_owned_sample_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = crate::abi::z_owned_sample_t::null_value() };
    }
}

/// Free an owned sample (zenoh-c `z_sample_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved sample.
#[no_mangle]
pub unsafe extern "C" fn z_sample_drop(this_: *mut crate::abi::z_moved_sample_t) {
    let _ = crate::ffi::guarded(|| {
        if this_.is_null() {
            return crate::result::Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<SampleMarshal>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut SampleMarshal) });
            unsafe { (*this_)._this = crate::abi::z_owned_sample_t::null_value() };
        }
        crate::result::Z_OK
    });
}

#[cfg(test)]
mod owned_tests {
    use super::*;
    use wz_runtime_tokio::Reliability;

    /// A `SampleView` the escape test can build without a session.
    struct View;

    impl SampleView for View {
        fn keyexpr(&self) -> &str {
            "demo/owned"
        }
        fn payload(&self) -> &[u8] {
            b"BODY"
        }
        fn kind(&self) -> SampleKind {
            SampleKind::Put
        }
        fn reliability(&self) -> Reliability {
            Reliability::Reliable
        }
        fn attachment(&self) -> Option<&[u8]> {
            Some(b"ATT")
        }
    }

    /// An escaped sample OUTLIVES the callback and still reads correctly.
    ///
    /// The damage this guards is specific: `deep_copy` leaves the cached loaned
    /// views UNBOUND on purpose, and copying them instead would leave the
    /// escaped sample's accessors pointing into the callback's dead frame. This
    /// test reads the copy AFTER `with_marshalled` has returned, which is
    /// exactly when that would surface.
    #[test]
    fn an_escaped_sample_outlives_the_callback_that_delivered_it() {
        let mut owned = crate::abi::z_owned_sample_t::null_value();
        with_marshalled(&View, |sample| {
            // SAFETY: `sample` is live for this call.
            unsafe { z_sample_clone(&mut owned, sample) };
        });
        // SAFETY: `owned` is a live heap marshal, independent of the frame
        // above, which has now returned.
        unsafe {
            assert!(z_internal_sample_check(&owned));
            let loaned = z_sample_loan(&owned);
            assert_eq!(z_sample_kind(loaned), Z_SAMPLE_KIND_PUT);

            let mut view_string = crate::abi::z_view_string_t::null_value();
            z_keyexpr_as_view_string(z_sample_keyexpr(loaned), &mut view_string);
            let ls = crate::string::z_view_string_loan(&view_string);
            assert_eq!(
                std::slice::from_raw_parts(
                    crate::string::z_string_data(ls) as *const u8,
                    crate::string::z_string_len(ls)
                ),
                b"demo/owned"
            );
            assert_eq!(
                crate::bytes::bytes_slice(z_sample_payload(loaned)).unwrap(),
                b"BODY"
            );
            assert_eq!(
                crate::bytes::bytes_slice(z_sample_attachment(loaned)).unwrap(),
                b"ATT"
            );

            let mut moved = crate::abi::z_moved_sample_t { _this: owned };
            z_sample_drop(&mut moved);
            assert!(!z_internal_sample_check(&moved._this));
            // Idempotent — the slot was nulled.
            z_sample_drop(&mut moved);
        }
    }

    /// Cloning a NULL sample yields a gravestone, not a dereference.
    #[test]
    fn cloning_a_null_sample_yields_a_gravestone() {
        let mut owned = crate::abi::z_owned_sample_t::from_handle(1 as crate::abi::Handle);
        // SAFETY: passing NULL is exactly what this guard exists for.
        unsafe {
            z_sample_clone(&mut owned, std::ptr::null());
            assert!(!z_internal_sample_check(&owned));
            assert!(z_sample_loan(std::ptr::null()).is_null());
        }
    }
}
