// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz_runtime_tokio::qos::{CongestionControl, Priority};
use wz_runtime_tokio::session::PublishOptions;

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_publisher_t, z_loaned_session_t, z_moved_bytes_t,
    z_moved_encoding_t, z_moved_publisher_t, z_owned_publisher_t, Handle,
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

// R311y545 — THE TWO CONSTANTS BELOW WERE WRONG, AND THE ERROR HAS ONE CAUSE:
// zenoh-c's enums are NOT zenoh-pico's, and this crate was carrying the pico
// sibling's values. zenoh-pico has `Z_CONGESTION_CONTROL_BLOCK = 1` /
// `DROP = 0` (`api/constants.h`); zenoh-c INVERTS them. It was invisible while
// the fields were accepted-and-ignored — nothing read the value — and it
// becomes a wire divergence the moment they are honoured, which is what this
// round does.
//
// MEASURED, not read: a C probe compiled against the installed header and
// linked against the real `libzenohc.so` prints
// `publisher.congestion_control=1`, and the twice-and-diff leg
// `upstream_option_defaults_on_wz_capi_c_match_real_libzenohc` now runs that
// probe against BOTH libraries on every C1cc pass so a future edit cannot
// re-introduce either value.
/// `Z_CONGESTION_CONTROL_BLOCK` = 0 (`zenoh_commons.h:45-60`) — messages are
/// NOT dropped on congestion. Note the inversion against zenoh-pico.
pub const Z_CONGESTION_CONTROL_BLOCK: z_congestion_control_t = 0;
/// `Z_CONGESTION_CONTROL_DROP` = 1 — upstream's publisher default
/// (`CongestionControl::DEFAULT_PUSH`).
pub const Z_CONGESTION_CONTROL_DROP: z_congestion_control_t = 1;
/// `Z_CONGESTION_CONTROL_BLOCK_FIRST` = 2 — present only under
/// `Z_FEATURE_UNSTABLE_API`.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub const Z_CONGESTION_CONTROL_BLOCK_FIRST: z_congestion_control_t = 2;
/// `Z_PRIORITY_REAL_TIME` = 1 — upstream's highest application priority.
pub const Z_PRIORITY_REAL_TIME: z_priority_t = 1;
/// `Z_PRIORITY_DATA` = 5 — upstream's default priority.
pub const Z_PRIORITY_DATA: z_priority_t = 5;
/// `Z_PRIORITY_BACKGROUND` = 7 — upstream's lowest.
pub const Z_PRIORITY_BACKGROUND: z_priority_t = 7;
/// `Z_RELIABILITY_BEST_EFFORT` = 0 (`commons.rs:300-305`).
pub const Z_RELIABILITY_BEST_EFFORT: z_reliability_t = 0;
/// `Z_RELIABILITY_RELIABLE` = 1 — upstream's default
/// (`z_reliability_default()` = `Reliability::default()`). This was 0, the
/// second half of the pico-values transcription described above.
pub const Z_RELIABILITY_RELIABLE: z_reliability_t = 1;
/// `ZC_LOCALITY_ANY` = 0.
pub const ZC_LOCALITY_ANY: zc_locality_t = 0;
/// `ZC_LOCALITY_SESSION_LOCAL` = 1.
pub const ZC_LOCALITY_SESSION_LOCAL: zc_locality_t = 1;
/// `ZC_LOCALITY_REMOTE` = 2.
pub const ZC_LOCALITY_REMOTE: zc_locality_t = 2;

// --- R311y568: the option struct + four constant getters --------------------

/// Options for `z_publisher_delete` (`zenoh_commons.h:890-895`) — 8 bytes, one
/// field.
///
/// R311y568 — NOT DECLARED until this round; [`z_publisher_delete`] took
/// `*mut c_void`, which is the same "no signature to write against" gap y565
/// closed for `z_query_reply_del_options_t` and y545 for `z_put_options_t`.
#[repr(C)]
pub struct z_publisher_delete_options_t {
    /// The timestamp of this message. BORROWED — a concrete struct the caller
    /// keeps, as on every other option struct that carries one.
    pub timestamp: *const crate::timestamp::z_timestamp_t,
}

/// Fill default publisher-delete options (zenoh-c
/// `z_publisher_delete_options_default`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_delete_options_default(
    this_: *mut z_publisher_delete_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_publisher_delete_options_t {
            timestamp: std::ptr::null(),
        }
    };
}

// The four constant getters. Each returns a value this file already names as a
// constant, so the getter is a one-line read rather than a second transcription
// — and each value was MEASURED against the real `libzenohc.so` by a C probe
// before being written here, because this file has been wrong about exactly
// this kind of number before (see the R311y545 note above).

/// zenoh's default congestion control for PUSH messages — a put (zenoh-c
/// `z_internal_congestion_control_default_push`).
///
/// `Z_CONGESTION_CONTROL_DROP` (1), measured. Note that this is the OPPOSITE of
/// the request / response default below: a data push may be dropped under
/// congestion, while a query must not be.
#[no_mangle]
pub extern "C" fn z_internal_congestion_control_default_push() -> z_congestion_control_t {
    Z_CONGESTION_CONTROL_DROP
}

/// zenoh's default congestion control for REQUEST messages — a get (zenoh-c
/// `z_internal_congestion_control_default_request`).
///
/// `Z_CONGESTION_CONTROL_BLOCK` (0), measured.
#[no_mangle]
pub extern "C" fn z_internal_congestion_control_default_request() -> z_congestion_control_t {
    Z_CONGESTION_CONTROL_BLOCK
}

// R2239 — `z_internal_congestion_control_default_response` used to be here.
// zenoh-c 1.10.0 RETIRED it: the pinned header declares two of the family and
// the pinned `libzenohc.so` exports two (`nm -D`, push and request). A symbol
// wz defines and the reference does not is a surface that is not the ABI it
// claims to be, which is what `wz_exports_nothing_the_reference_does_not`
// measures — and nothing in this crate called it.

/// zenoh's default priority (zenoh-c `z_priority_default`).
///
/// `Z_PRIORITY_DATA` (5), measured.
#[no_mangle]
pub extern "C" fn z_priority_default() -> z_priority_t {
    Z_PRIORITY_DATA
}

/// zenoh's default RELIABILITY (zenoh-c `z_reliability_default`).
///
/// `Z_RELIABILITY_RELIABLE` (1). UNSTABLE-gated, as upstream gates both this and
/// the `reliability` option fields it supplies a default for.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub extern "C" fn z_reliability_default() -> z_reliability_t {
    Z_RELIABILITY_RELIABLE
}

/// zenoh's default destination locality (zenoh-c `zc_locality_default`).
///
/// `ZC_LOCALITY_ANY` (0), measured — both local and remote.
#[no_mangle]
pub extern "C" fn zc_locality_default() -> zc_locality_t {
    ZC_LOCALITY_ANY
}

/// The SAME default under upstream's newer spelling (zenoh-c
/// `z_locality_default`).
///
/// R2239 — zenoh-c 1.10.0 defines BOTH `z_locality_default` and
/// `zc_locality_default` (measured with `nm -D` on the pinned
/// `libzenohc.so`), so this is an addition rather than the rename its
/// `reply_keyexpr` neighbour needed. Delegates rather than repeating the
/// constant: two entry points to one answer, which is what upstream ships.
#[no_mangle]
pub extern "C" fn z_locality_default() -> zc_locality_t {
    zc_locality_default()
}

/// zenoh-c's `z_congestion_control_t` as wz's typed [`CongestionControl`].
///
/// `BLOCK_FIRST` maps to `Block`: the packed QoS byte carries a single `nodrop`
/// bit (`_z_n_qos_create`, pico `network.h:86`), so "block only the first" has
/// no distinct wire encoding to project onto. An out-of-range value takes
/// upstream's default rather than panicking, matching the permissive-decode
/// spirit of [`Priority::from_wire`].
pub(crate) fn congestion_from_c(c: z_congestion_control_t) -> CongestionControl {
    match c {
        Z_CONGESTION_CONTROL_BLOCK => CongestionControl::Block,
        Z_CONGESTION_CONTROL_DROP => CongestionControl::Drop,
        // BLOCK_FIRST (2) and anything unrecognised.
        2 => CongestionControl::Block,
        _ => CongestionControl::Drop,
    }
}

/// zenoh-c's `z_priority_t` as wz's typed [`Priority`].
///
/// zenoh-c's enum spans 1..=7; wire priority 0 (`Control`) is reserved for
/// zenoh's own control traffic and has no zenoh-c spelling, so it is accepted
/// on the wire and never produced from a C option. Anything outside 0..=7
/// cannot fit the 3-bit field and clamps to upstream's default.
pub(crate) fn priority_from_c(p: z_priority_t) -> Priority {
    match u8::try_from(p) {
        Ok(byte) if byte <= 7 => Priority::from_wire(byte),
        _ => Priority::DEFAULT,
    }
}

/// Options for `z_declare_publisher` (`zenoh_commons.h:644-673`).
///
/// `encoding` is a `z_moved_encoding_t*`, and R311y545 made it a TYPED pointer
/// because the field is now READ: the declare path resolves the label through
/// [`take_moved_encoding`](crate::encoding::take_moved_encoding) and every put
/// on this publisher carries it. The layout is unchanged — a pointer is a
/// pointer — but the type now says what the code does.
#[repr(C)]
pub struct z_publisher_options_t {
    /// Default encoding for messages published here.
    pub encoding: *mut z_moved_encoding_t,
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
    /// Encoding of the published data. Overrides the publisher's default when
    /// set, as upstream's `PutBuilder::encoding` does.
    pub encoding: *mut z_moved_encoding_t,
    /// Timestamp of the publication.
    ///
    /// Still an opaque pointer, and still UNREAD — `z_timestamp_t` is not
    /// declared by this crate and no upstream example sets the field, so
    /// declaring the type would add an unmeasured entry to the footprint gate
    /// to serve no driver. The residual is named here rather than left to be
    /// inferred from the pointer's type.
    pub timestamp: *const c_void,
    /// Source info. Present only under `Z_FEATURE_UNSTABLE_API`.
    ///
    /// R311y563 — READ and CONSUMED (a `z_moved_*` field transfers ownership on
    /// every path, including the error ones).
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *const crate::source_info::z_source_info_t,
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
    /// R311y545 — the declare-time options, resolved ONCE into the wz publish
    /// bundle every put on this publisher starts from.
    ///
    /// Resolved at declare rather than per put because that is upstream's
    /// shape: `_declare_publisher_inner` folds the options into a
    /// `PublisherBuilder` and the built `Publisher` carries them, so a caller
    /// that mutates its options struct after declaring changes nothing — and
    /// the `encoding` field is `z_moved_encoding_t*`, i.e. CONSUMED at declare,
    /// so reading it again per put would be reading a moved value.
    base: PublishOptions,
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

/// The publish options a C publisher uses when it passes NO options — the
/// values `z_publisher_options_default` writes, resolved.
///
/// R311y554 — `Locality::Any`, the value `z_publisher_options_default` writes.
/// It was `Locality::Remote` until the drive-task hand-off landed; see
/// [`crate::put::put_options`] for why that pin was a soundness workaround
/// rather than the fidelity choice its doc comment claimed, and what replaced
/// it. The one-local-delivery-per-session fan split lives in
/// `wz_capi_core::faces::SharedSession::publish_all`, so the per-face replica
/// count is no longer this function's problem.
pub(crate) fn publisher_put_options() -> PublishOptions {
    PublishOptions::put()
        .with_locality(Locality::Any)
        .with_priority(priority_from_c(Z_PRIORITY_DATA))
        .with_congestion_control(congestion_from_c(Z_CONGESTION_CONTROL_DROP))
        .with_express(false)
}

/// Fold a `z_publisher_options_t` into the wz publish bundle.
///
/// The QoS sub-fields are set through the three TYPED setters rather than a
/// hand-assembled `QosLevel`, so the packed byte's layout stays in its one
/// place (`QosLevel::from_parts`) — the same reason `with_priority` exists on
/// the Rust API.
///
/// # Safety
/// `options` must be null or a valid publisher-options struct whose `encoding`
/// field is null or a valid moved encoding.
pub(crate) unsafe fn resolve_publisher_options(
    options: *mut z_publisher_options_t,
) -> PublishOptions {
    let base = publisher_put_options();
    if options.is_null() {
        return base;
    }
    // SAFETY: the caller's contract.
    let opts = unsafe { &mut *options };
    let resolved = base
        .with_priority(priority_from_c(opts.priority))
        .with_congestion_control(congestion_from_c(opts.congestion_control))
        .with_express(opts.is_express)
        // R311y554 — HONOURED. Declared ONCE and inherited by every
        // `z_publisher_put` on this handle, which is upstream's shape:
        // `z_publisher_put_options_t` carries no locality field of its own.
        .with_locality(crate::put::locality_from_c(opts.allowed_destination));
    // SAFETY: the caller's contract for the pointee.
    match unsafe { crate::encoding::take_moved_encoding(opts.encoding) } {
        Some(hint) => resolved.with_encoding(hint),
        None => resolved,
    }
}

/// The owned halves of a `z_publisher_put_options_t`, TAKEN.
///
/// A plain value rather than a `PublishOptions` fold because the take has to
/// happen unconditionally — upstream documents every owned options field as
/// "consumed upon function return", so an early `Z_ENULL` still has to
/// invalidate the caller's values — while the base it overrides is only
/// reachable once the publisher handle is known live.
#[derive(Default)]
struct PutOverrides {
    encoding: Option<wz_runtime_tokio::sample::EncodingHint>,
    attachment: Option<Vec<u8>>,
    /// R311y563 — the per-put source identity. Owned like the attachment, and
    /// for the same reason: upstream types it `z_moved_source_info_t*`.
    source_info: Option<wz_runtime_tokio::sample::SourceInfo>,
}

impl PutOverrides {
    /// Take the owned fields out of a `z_publisher_put_options_t`.
    ///
    /// # Safety
    /// `options` must be null or a valid publisher-put-options struct whose
    /// `encoding` / `attachment` fields are null or valid moved values.
    unsafe fn take(options: *mut z_publisher_put_options_t) -> Self {
        if options.is_null() {
            return Self::default();
        }
        // SAFETY: the caller's contract.
        let opts = unsafe { &mut *options };
        // Bound before the literal so the field init stays arm-independent —
        // upstream gates the FIELD, so on the no-unstable arm there is nothing
        // to take and `crate::source_info` is not compiled.
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        // SAFETY: as above. TAKEN, for the same reason the attachment is: a
        // `z_moved_*` field transfers ownership on return, so a second put
        // through the same options struct must not see it again.
        let taken_source_info =
            unsafe { crate::source_info::borrowed_source_info(opts.source_info) };
        #[cfg(feature = "zenoh-c-no-unstable-api")]
        let taken_source_info: Option<wz_runtime_tokio::sample::SourceInfo> = None;
        Self {
            // SAFETY: as above. TAKEN — an encoding may be heap-owned since
            // R311y564 (`z_encoding_from_str`), so a read would leak the
            // caller's label and leave their owned value non-null.
            encoding: unsafe { crate::encoding::take_moved_encoding(opts.encoding) },
            // SAFETY: as above. TAKEN — `take_payload` reclaims the box and
            // gravestones the caller's slot, so a program that puts twice with
            // one options struct does not double-free.
            attachment: unsafe { take_payload(opts.attachment) },
            source_info: taken_source_info,
        }
    }

    /// Apply over a publisher's declare-time bundle.
    ///
    /// Per-put encoding OVERRIDES the publisher's default (upstream's
    /// `PutBuilder::encoding` wins over `PublisherBuilder::encoding`); an
    /// absent one leaves the publisher's in place. The attachment is per-put
    /// only — `z_publisher_options_t` carries no attachment field.
    fn apply(self, base: PublishOptions) -> PublishOptions {
        let with_encoding = match self.encoding {
            Some(hint) => base.with_encoding(hint),
            None => base,
        };
        let with_attachment = match self.attachment {
            Some(blob) => with_encoding.with_attachment(blob),
            None => with_encoding,
        };
        match self.source_info {
            Some(info) => with_attachment.with_source_info(info),
            None => with_attachment,
        }
    }
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
            // DROP, and it is 1 here — see the constant's own note. Writing 0
            // spelled BLOCK to every C program that read the field back.
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
/// R311y545 — `options` is READ. Encoding, congestion control, priority and
/// express are folded into the publish bundle every put on this publisher
/// starts from, which is what upstream's `_declare_publisher_inner` does with
/// the same four. R311y554 makes it FIVE: `allowed_destination` is honoured
/// too, declared once here and inherited by every `z_publisher_put`.
/// `reliability` remains a link-selection marker upstream itself does not put
/// on the wire ("`reliability` does not trigger any data retransmission on the
/// wire", `zenoh-c/src/commons.rs:294`).
///
/// # Safety
/// `session` must be a valid loaned session; `publisher` must be valid and
/// writable; `key_expr` must be a valid loaned keyexpr; `options` must be null
/// or a valid publisher-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_declare_publisher(
    session: *const z_loaned_session_t,
    publisher: *mut z_owned_publisher_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_publisher_options_t,
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
            // A publisher declared over a DECLARED keyexpr inherits its alias,
            // so every put on the handle rides it — upstream's shape, and the
            // reason the mapping travels with the keyexpr rather than with the
            // session.
            keyexpr: crate::keyexpr::KeyexprState {
                keyexpr,
                // SAFETY: the caller's contract for `key_expr`, already read
                // above by `keyexpr_str`.
                mapping: unsafe { crate::keyexpr::keyexpr_mapping(key_expr) },
            },
            loaned_keyexpr: z_loaned_keyexpr_t::null_value(),
            matching: std::sync::Mutex::new(None),
            // SAFETY: the caller's contract for `options`.
            base: unsafe { resolve_publisher_options(options) },
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
/// moved bytes; `options` must be null or a valid publisher-put-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_put(
    this_: *const z_loaned_publisher_t,
    payload: *mut z_moved_bytes_t,
    options: *mut z_publisher_put_options_t,
) -> ZResult {
    guarded(|| {
        // Taken FIRST and unconditionally — see the doc note. The options'
        // owned fields go the same way, and for the same reason, which is why
        // `apply_publisher_put_options` runs before the null check below.
        // SAFETY: the caller's contract.
        let payload = unsafe { take_payload(payload) };
        // SAFETY: the caller's contract for the options struct.
        let overrides = unsafe { PutOverrides::take(options) };
        // SAFETY: the caller's contract.
        let (Some(state), Some(payload)) = (unsafe { publisher_state(this_) }, payload) else {
            return Z_ENULL;
        };
        // The publisher's declare-time bundle is the base; the per-put options
        // taken above override it field by field.
        let publish = overrides.apply(state.base.clone());
        let sent = match state.keyexpr.mapping {
            Some(mapping) => state
                .shared
                .publish_aliased_all(mapping, &payload, &publish),
            None => state
                .shared
                .publish_all(&state.keyexpr.keyexpr, &payload, &publish),
        };
        match sent {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

/// Publish a Del on a declared publisher's keyexpr (zenoh-c
/// `z_publisher_delete`).
///
/// # Safety
/// `this_` must be null or a valid loaned publisher; `options` must be null or a
/// valid publisher-delete options struct.
#[no_mangle]
pub unsafe extern "C" fn z_publisher_delete(
    this_: *const z_loaned_publisher_t,
    options: *mut z_publisher_delete_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { publisher_state(this_) }) else {
            return Z_ENULL;
        };
        // R311y545 — the publisher's declare-time QoS applies to its Del as
        // well as its Put, which is upstream's shape (`z_publisher_delete`
        // resolves off the same `Publisher`). Only the kind differs; the
        // encoding is dropped because a Del body has no encoding slot
        // (`_z_msg_del_t`).
        let options = {
            let base = state
                .base
                .clone()
                .with_kind(wz_runtime_tokio::sample::SampleKind::Del);
            // R311y568 — the per-call TIMESTAMP, which is the struct's only
            // field and is now HONOURED rather than accepted-and-ignored. It
            // reaches the same `with_timestamp` seam the session-level
            // `z_delete_options_t` uses, so a publisher Del and a session Del
            // stamp the wire identically.
            if options.is_null() {
                base
            } else {
                // SAFETY: the caller's contract — BORROWED, a concrete struct
                // the caller keeps, exactly as on the put side.
                match unsafe {
                    crate::timestamp::timestamp_hint((*options).timestamp as *const c_void)
                } {
                    Some(hint) => base.with_timestamp(hint),
                    None => base,
                }
            }
        };
        let sent = match state.keyexpr.mapping {
            Some(mapping) => state.shared.publish_aliased_all(mapping, &[], &options),
            None => state
                .shared
                .publish_all(&state.keyexpr.keyexpr, &[], &options),
        };
        match sent {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

/// This publisher's GLOBAL ENTITY ID (zenoh-c `z_publisher_id`).
///
/// R311y566 — added because the `source_info` foreign adjudicator needs it:
/// `z_entity_global_id_t` is OPAQUE upstream with accessors and NO constructor,
/// so a C program cannot mint one. The only way to obtain one is to ask an
/// entity for its own, and `z_publisher_id` is the entry point a publisher-side
/// `z_source_info_new` is written against.
///
/// The zid half is the SESSION's, which is what upstream reports too — a
/// publisher is not a separate node. The eid half is wz's per-publisher id; a
/// gravestoned publisher answers the empty id rather than a stale one.
///
/// UNSTABLE-gated as upstream gates it (`#if defined(Z_FEATURE_UNSTABLE_API)`),
/// and it has to be: `z_entity_global_id_t` lives in [`crate::advanced`], which
/// is not compiled on the other arm. A helper's cfg must be the OR of every arm
/// that calls it, and this one's return TYPE fixes the arm for it.
///
/// # Safety
/// `publisher` must be null or a valid loaned publisher.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
#[no_mangle]
pub unsafe extern "C" fn z_publisher_id(
    publisher: *const z_loaned_publisher_t,
) -> crate::advanced::z_entity_global_id_t {
    // R311y568 — through the shared constructor, which is where the zid/eid
    // convention is now stated once for all five entity-id accessors.
    guard_val(crate::advanced::z_entity_global_id_t::empty(), || {
        // SAFETY: the caller's contract.
        match unsafe { publisher_state(publisher) } {
            Some(state) => crate::advanced::z_entity_global_id_t::for_entity(
                &state.shared,
                publisher as *const c_void,
            ),
            None => crate::advanced::z_entity_global_id_t::empty(),
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

#[cfg(test)]
mod locality_tests {
    use super::*;

    /// R311y554 — the publisher declares its locality ONCE and every
    /// `z_publisher_put` inherits it, which is upstream's shape:
    /// `z_publisher_put_options_t` carries no locality field of its own, so the
    /// declaration is the only place a program can express it.
    #[test]
    fn publisher_options_carry_the_callers_allowed_destination() {
        for (c_value, expected) in [
            (ZC_LOCALITY_ANY, Locality::Any),
            (ZC_LOCALITY_SESSION_LOCAL, Locality::SessionLocal),
            (ZC_LOCALITY_REMOTE, Locality::Remote),
        ] {
            let mut o = z_publisher_options_t {
                encoding: std::ptr::null_mut(),
                congestion_control: Z_CONGESTION_CONTROL_DROP,
                priority: Z_PRIORITY_DATA,
                is_express: false,
                #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
                reliability: Z_RELIABILITY_RELIABLE,
                allowed_destination: c_value,
            };
            // SAFETY: a live local whose owned field is null.
            let resolved = unsafe { resolve_publisher_options(&mut o) };
            assert_eq!(
                resolved.allowed_destination, expected,
                "z_publisher_options_t.allowed_destination = {c_value} -> {expected:?}",
            );
        }
    }
}
