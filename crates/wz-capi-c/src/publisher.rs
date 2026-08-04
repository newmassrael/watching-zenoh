// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The publisher plane: a declared handle that publishes on a fixed keyexpr.
//!
//! ## The options structs are MIRRORED FIELD FOR FIELD, not sized by hand
//!
//! `z_publisher_options_t` and `z_publisher_put_options_t` are TRANSPARENT in
//! upstream's header (`zenoh_commons.h:644-673` / `902-923`): the C side stack-
//! allocates one, calls `*_options_default` on it, then assigns to its fields. So
//! a matching total size is not enough — every field must sit at upstream's
//! offset.
//!
//! They are therefore declared here with the SAME fields in the SAME order and
//! Rust computes the layout, which is exactly how upstream's header came to exist
//! (cbindgen emitted it FROM the Rust structs). Hand-computing a byte count would
//! be re-deriving what the compiler already knows, and it is the step that gets
//! silently wrong.
//!
//! Both are FEATURE-DEPENDENT — `Z_FEATURE_UNSTABLE_API` adds `reliability` to
//! one and `source_info` to the other — so each has two arms under the crate's
//! existing `zenoh-c-no-unstable-api` feature, the same split `z_owned_bytes_t`
//! already carries. The lane measures both against the installed header.
//!
//! ## What a publisher IS here
//!
//! wz's registry has no publisher entity: a publisher is a keyexpr plus publish
//! options, and [`z_publisher_put`] fans out through the same
//! [`publish_all`](wz_capi_core::faces::SharedSession::publish_all) that
//! [`z_put`](crate::put::z_put) uses. That is deliberate rather than a shortcut —
//! one publish path means a declared publisher and a session put cannot diverge
//! on the wire, and the aliasing optimisation a real declaration would enable is
//! a named follow-up, not a correctness difference. The sibling `wz-capi-pico`
//! records the same choice.

use std::ffi::c_void;
use std::sync::Arc;

use wz_capi_core::faces::SharedSession;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::session::PublishOptions;

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_publisher_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_publisher_t, z_owned_publisher_t, Handle,
};
use crate::bytes::take_payload;
use crate::ffi::{guard_val, guarded};
use crate::keyexpr::{keyexpr_str, KeyexprState};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;

/// zenoh-c's `z_congestion_control_t` — a plain C enum, so `c_int`-sized.
pub type z_congestion_control_t = std::ffi::c_int;
/// zenoh-c's `z_priority_t`.
pub type z_priority_t = std::ffi::c_int;
/// zenoh-c's `z_reliability_t`.
pub type z_reliability_t = std::ffi::c_int;
/// zenoh-c's `zc_locality_t` (`zenoh_commons.h:273-286`).
pub type zc_locality_t = std::ffi::c_int;

/// `Z_CONGESTION_CONTROL_DROP` = 0 — upstream's publisher default.
pub const Z_CONGESTION_CONTROL_DROP: z_congestion_control_t = 0;
/// `Z_PRIORITY_DATA` = 5 — upstream's default priority.
pub const Z_PRIORITY_DATA: z_priority_t = 5;
/// `Z_RELIABILITY_RELIABLE` = 0.
pub const Z_RELIABILITY_RELIABLE: z_reliability_t = 0;
/// `ZC_LOCALITY_ANY` = 0.
pub const ZC_LOCALITY_ANY: zc_locality_t = 0;

/// Options for `z_declare_publisher` (`zenoh_commons.h:644-673`).
///
/// `encoding` is a `z_moved_encoding_t*`; this slice does not read it, so it is
/// typed as an opaque pointer rather than pulling in the encoding family. The
/// FIELD is what the layout depends on, not its pointee.
#[repr(C)]
pub struct z_publisher_options_t {
    /// Default encoding for messages published here. Consumed by upstream; not
    /// read by this slice.
    pub encoding: *mut c_void,
    /// Congestion control to apply when routing.
    pub congestion_control: z_congestion_control_t,
    /// Priority of published messages.
    pub priority: z_priority_t,
    /// Bypass batching for lower latency.
    pub is_express: bool,
    /// Publisher reliability. Present only under `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub reliability: z_reliability_t,
    /// Allowed destination for this publisher.
    pub allowed_destination: zc_locality_t,
}

/// Options for `z_publisher_put` (`zenoh_commons.h:902-923`).
#[repr(C)]
pub struct z_publisher_put_options_t {
    /// Encoding of the published data. Consumed by upstream; not read here.
    pub encoding: *mut c_void,
    /// Timestamp of the publication.
    pub timestamp: *const c_void,
    /// Source info. Present only under `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *mut c_void,
    /// Attachment to carry alongside the payload.
    pub attachment: *mut z_moved_bytes_t,
}

/// Behind a `z_owned_publisher_t` handle: the keyexpr this publisher publishes
/// on, and the session it fans out through.
///
/// The keyexpr is held as a [`KeyexprState`] rather than a bare `String` so that
/// [`z_publisher_keyexpr`] can hand back a borrowed view pointing straight at it
/// — the same trick [`SampleMarshal`](crate::sample::SampleMarshal) uses, with
/// the same `bind`-after-boxing discipline, because a cached view minted before
/// the value reaches its final address points into a dead frame.
pub(crate) struct PublisherState {
    pub(crate) shared: Arc<SharedSession>,
    pub(crate) keyexpr: KeyexprState,
    loaned_keyexpr: z_loaned_keyexpr_t,
    /// The background matching listener this publisher declared, if any.
    ///
    /// Behind a `Mutex` rather than reached through a `&mut`, because the C side
    /// declares a listener through a `const z_loaned_publisher_t*`: upstream's
    /// signature takes a shared borrow, so the mutation has to be interior. It
    /// also makes the attach thread-safe without any argument about which thread
    /// a C program declares from.
    matching: std::sync::Mutex<Option<crate::matching::MatchingHold>>,
}

impl PublisherState {
    /// Record a background matching listener, retiring any previous one.
    ///
    /// Replacing rather than appending is upstream's shape: a second background
    /// declaration on one publisher supersedes the first, and the old
    /// `MatchingHold`'s `Drop` is what undeclares it. The old value is released
    /// OUTSIDE the mutex — a retraction can re-enter the session.
    pub(crate) fn attach_matching(&self, hold: crate::matching::MatchingHold) {
        let previous = match self.matching.lock() {
            Ok(mut guard) => guard.replace(hold),
            Err(poisoned) => poisoned.into_inner().replace(hold),
        };
        drop(previous);
    }

    /// Point the cached view at this state's own field. MUST run only once the
    /// state sits at its FINAL address (i.e. after `Box::new`).
    fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::from_handle(&self.keyexpr as *const KeyexprState as *mut c_void);
    }
}

/// The publish options a C publisher uses.
///
/// `Locality::Remote` for the same structural reason
/// [`crate::put`] documents: a C session is N per-face wz sessions each holding a
/// replica of the subscription, so a local-capable publish would fire one C
/// callback once PER FACE for a single put.
fn publisher_put_options() -> PublishOptions {
    PublishOptions::put().with_locality(Locality::Remote)
}

/// Read the state behind a loaned publisher.
///
/// # Safety
/// `this_` must be null, or a valid loaned publisher whose handle slot holds a
/// live `PublisherState` pointer.
pub(crate) unsafe fn publisher_state<'a>(
    this_: *const z_loaned_publisher_t,
) -> Option<&'a PublisherState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<PublisherState>` this crate leaked.
    Some(unsafe { &*(handle as *const PublisherState) })
}

/// Fill in the default publisher options (zenoh-c `z_publisher_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_options_default(this_: *mut z_publisher_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_publisher_options_t {
            encoding: std::ptr::null_mut(),
            congestion_control: Z_CONGESTION_CONTROL_DROP,
            priority: Z_PRIORITY_DATA,
            is_express: false,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            reliability: Z_RELIABILITY_RELIABLE,
            allowed_destination: ZC_LOCALITY_ANY,
        }
    };
}

/// Fill in the default publisher-put options (zenoh-c
/// `z_publisher_put_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put_options_default(this_: *mut z_publisher_put_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_publisher_put_options_t {
            encoding: std::ptr::null_mut(),
            timestamp: std::ptr::null(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
        }
    };
}

/// Declare a publisher (zenoh-c `z_declare_publisher`).
///
/// # Safety
/// `session` must be a valid loaned session; `publisher` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr. `_options` is accepted
/// for ABI compatibility and read only for its presence — the option fields
/// (encoding, congestion control, priority, express, locality) are a later slice,
/// and this is recorded rather than implied.
#[no_mangle]
pub unsafe extern "C" fn z_declare_publisher(
    session: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    key_expr: *const z_loaned_keyexpr_t,
    _options: *mut z_publisher_options_t,
) -> ZResult {
    guarded(|| {
        if publisher.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        unsafe { *publisher = z_owned_publisher_t::null_value() };

        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(ke)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        let keyexpr = ke.to_owned();
        // The same outbound canonicity gate the session put applies, hoisted to
        // the DECLARATION so a program learns its keyexpr is unusable when it
        // declares rather than on every later put.
        if wz_runtime_tokio::keyexpr_canon::check_outbound_keyexpr_pico_safe(&keyexpr).is_err() {
            return Z_EINVAL;
        }
        let mut boxed = Box::new(PublisherState {
            shared: state.shared.clone(),
            keyexpr: KeyexprState { keyexpr },
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            matching: std::sync::Mutex::new(None),
        });
        // Bind AFTER the box, never before: the cached view must point at the
        // state's final address.
        boxed.bind();
        unsafe { *publisher = z_owned_publisher_t::from_handle(Box::into_raw(boxed) as Handle) };
        Z_OK
    })
}

/// Publish on a declared publisher's keyexpr (zenoh-c `z_publisher_put`).
///
/// The payload is CONSUMED on every path, as upstream specifies ("the payload and
/// all owned options fields are consumed upon function return") — so an error
/// return still invalidates the caller's value rather than leaving them a
/// double-free.
///
/// # Safety
/// `this_` must be null or a valid loaned publisher; `payload` must be a valid
/// moved bytes. `_options` is accepted for ABI compatibility and ignored.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put(
    this_: *const z_loaned_publisher_t,
    payload: *mut z_moved_bytes_t,
    _options: *mut z_publisher_put_options_t,
) -> ZResult {
    guarded(|| {
        // Taken FIRST and unconditionally — see the doc note.
        // SAFETY: the caller's contract.
        let payload = unsafe { take_payload(payload) };
        // SAFETY: the caller's contract.
        let (Some(state), Some(payload)) = (unsafe { publisher_state(this_) }, payload) else {
            return Z_ENULL;
        };
        match state
            .shared
            .publish_all(&state.keyexpr.keyexpr, &payload, &publisher_put_options())
        {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

/// Publish a Del on a declared publisher's keyexpr (zenoh-c
/// `z_publisher_delete`).
///
/// # Safety
/// `this_` must be null or a valid loaned publisher. `_options` is accepted for
/// ABI compatibility and ignored.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_delete(
    this_: *const z_loaned_publisher_t,
    _options: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { publisher_state(this_) }) else {
            return Z_ENULL;
        };
        let options = PublishOptions::del().with_locality(Locality::Remote);
        match state
            .shared
            .publish_all(&state.keyexpr.keyexpr, &[], &options)
        {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

/// This publisher's keyexpr (zenoh-c `z_publisher_keyexpr`).
///
/// # Safety
/// `this_` must be null or a valid loaned publisher. The returned view borrows
/// the publisher and is valid for as long as it is.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_keyexpr(
    this_: *const z_loaned_publisher_t,
) -> *const z_loaned_keyexpr_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract.
        match unsafe { publisher_state(this_) } {
            // The cached view, bound at declaration time — no second allocation
            // whose lifetime would then need managing.
            Some(state) => &state.loaned_keyexpr as *const z_loaned_keyexpr_t,
            None => std::ptr::null(),
        }
    })
}

/// Undeclare a publisher (zenoh-c `z_undeclare_publisher`).
///
/// # Safety
/// `this_` must be null or a valid moved publisher.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_publisher(this_: *mut z_moved_publisher_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<PublisherState>` this crate leaked. Nothing goes
            // on the wire: wz declares no publisher entity, so there is no
            // UndeclPublisher to emit — see the module note.
            drop(unsafe { Box::from_raw(handle as *mut PublisherState) });
            unsafe { (*this_)._this = z_owned_publisher_t::null_value() };
        }
        Z_OK
    })
}

/// Drop a publisher (zenoh-c `z_publisher_drop`) — what `z_drop(z_move(pub))`
/// dispatches to.
///
/// # Safety
/// `this_` must be null or a valid moved publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_drop(this_: *mut z_moved_publisher_t) {
    // SAFETY: the caller's contract, delegated — the slot is nulled there, so a
    // double drop is a no-op.
    let _ = unsafe { z_undeclare_publisher(this_) };
}

/// Borrow a publisher (zenoh-c `z_publisher_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_loan(
    this_: *const z_owned_publisher_t,
) -> *const z_loaned_publisher_t {
    this_ as *const z_loaned_publisher_t
}

/// Mutably borrow a publisher (zenoh-c `z_publisher_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_loan_mut(
    this_: *mut z_owned_publisher_t,
) -> *mut z_loaned_publisher_t {
    this_ as *mut z_loaned_publisher_t
}

/// `true` iff the owned publisher holds a live handle (zenoh-c
/// `z_internal_publisher_check`).
///
/// # Safety
/// `this_` must be null or a valid owned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_internal_publisher_check(this_: *const z_owned_publisher_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Zero an owned publisher (zenoh-c `z_internal_publisher_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned publisher.
#[no_mangle]
pub unsafe extern "C" fn z_internal_publisher_null(this_: *mut z_owned_publisher_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_publisher_t::null_value() };
    }
}
