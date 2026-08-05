// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_put` — the session-level publish.
//!
//! ## R311y545 — the options structs are DECLARED here, not `void*`
//!
//! `z_put_options_t` and `z_delete_options_t` are TRANSPARENT in upstream's
//! header (`zenoh_commons.h:927-970` / `732-761`): the C side stack-allocates
//! one, calls `*_options_default` on it, then assigns to its fields. Until this
//! round both entry points took `*mut c_void` and neither `_options_default`
//! existed, so a program that used the documented shape did not LINK — the
//! sibling `z_publisher_*` structs were declared and their fields ignored,
//! which is a different and milder failure.
//!
//! No upstream example passes these (`z_put.c` and `z_delete.c` both pass
//! `NULL`), which is why the gap survived the 29-of-29 link census: a census
//! measures the programs that exist. They are declared with the SAME fields in
//! the SAME order and Rust computes the layout, exactly as the publisher plane
//! does, and the sibling footprint gate measures both against the installed
//! header.

use std::ffi::c_void;

use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::PublishOptions;

use crate::abi::{z_loaned_keyexpr_t, z_loaned_session_t, z_moved_bytes_t, z_moved_encoding_t};
use crate::bytes::take_payload;
use crate::ffi::guarded;
use crate::keyexpr::keyexpr_str;
use crate::publisher::{
    congestion_from_c, priority_from_c, z_congestion_control_t, z_priority_t, zc_locality_t,
    ZC_LOCALITY_ANY, Z_CONGESTION_CONTROL_DROP, Z_PRIORITY_DATA,
};
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
use crate::publisher::{z_reliability_t, Z_RELIABILITY_RELIABLE};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;

/// Options for `z_put` (`zenoh_commons.h:927-970`).
#[repr(C)]
pub struct z_put_options_t {
    /// Encoding of the message.
    pub encoding: *mut z_moved_encoding_t,
    /// Congestion control to apply when routing this message.
    pub congestion_control: z_congestion_control_t,
    /// Priority of this message.
    pub priority: z_priority_t,
    /// Bypass batching for lower latency.
    pub is_express: bool,
    /// Timestamp of this message. UNREAD — see
    /// [`z_publisher_put_options_t::timestamp`](crate::publisher::z_publisher_put_options_t).
    pub timestamp: *const c_void,
    /// Put reliability. Present only under `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub reliability: z_reliability_t,
    /// Allowed destination of this message.
    pub allowed_destination: zc_locality_t,
    /// Source info. Present only under `Z_FEATURE_UNSTABLE_API`. UNREAD: wz's
    /// `SourceInfo` is a (zid, eid, sn) triple and `z_source_info_t` is not
    /// declared by this crate, so honouring it would need the source-info
    /// family first.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub source_info: *mut c_void,
    /// Attachment to carry alongside the payload.
    pub attachment: *mut z_moved_bytes_t,
}

/// Options for `z_delete` (`zenoh_commons.h:732-761`).
///
/// No encoding and no attachment: a Del body carries neither
/// (`_z_msg_del_t`), and upstream's struct reflects that.
#[repr(C)]
pub struct z_delete_options_t {
    /// Congestion control to apply when routing this delete.
    pub congestion_control: z_congestion_control_t,
    /// Priority of the delete message.
    pub priority: z_priority_t,
    /// Bypass batching for lower latency.
    pub is_express: bool,
    /// Timestamp of this message. UNREAD, as on [`z_put_options_t`].
    pub timestamp: *const c_void,
    /// Delete reliability. Present only under `Z_FEATURE_UNSTABLE_API`.
    #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
    pub reliability: z_reliability_t,
    /// Allowed destination of this message.
    pub allowed_destination: zc_locality_t,
}

/// `Locality::Remote`, not the `Any` default — the same choice the zenoh-pico
/// shim documents and for the same structural reason: a C session here is N
/// per-face wz sessions, each with its own observer holding a replica of the
/// subscription, so a local-capable publish would fire one C callback once PER
/// FACE for a single `z_put`. `allowed_destination` is therefore READ FOR ITS
/// LAYOUT and not honoured, which is a named residual with a structural cause
/// rather than an omission.
fn put_options() -> PublishOptions {
    PublishOptions::put()
        .with_locality(Locality::Remote)
        .with_priority(priority_from_c(Z_PRIORITY_DATA))
        .with_congestion_control(congestion_from_c(Z_CONGESTION_CONTROL_DROP))
        .with_express(false)
}

/// The Del-kind counterpart, with the same locality choice and for the same
/// reason.
fn delete_options() -> PublishOptions {
    put_options().with_kind(SampleKind::Del)
}

/// Fold a `z_put_options_t` into the wz publish bundle.
///
/// # Safety
/// `options` must be null or a valid put-options struct whose `encoding` /
/// `attachment` fields are null or valid moved values.
unsafe fn resolve_put_options(options: *mut z_put_options_t) -> PublishOptions {
    let base = put_options();
    if options.is_null() {
        return base;
    }
    // SAFETY: the caller's contract.
    let opts = unsafe { &mut *options };
    let qos = base
        .with_priority(priority_from_c(opts.priority))
        .with_congestion_control(congestion_from_c(opts.congestion_control))
        .with_express(opts.is_express);
    // SAFETY: as above. Read rather than taken — every encoding this crate
    // hands out is `'static`, the same fact that makes `z_encoding_drop` free
    // nothing.
    let with_encoding = match unsafe { crate::encoding::moved_encoding_hint(opts.encoding) } {
        Some(hint) => qos.with_encoding(hint),
        None => qos,
    };
    // SAFETY: as above. TAKEN — upstream documents every owned options field as
    // consumed on return.
    match unsafe { take_payload(opts.attachment) } {
        Some(blob) => with_encoding.with_attachment(blob),
        None => with_encoding,
    }
}

/// Fold a `z_delete_options_t` into the wz publish bundle.
///
/// # Safety
/// `options` must be null or a valid delete-options struct.
unsafe fn resolve_delete_options(options: *const z_delete_options_t) -> PublishOptions {
    let base = delete_options();
    if options.is_null() {
        return base;
    }
    // SAFETY: the caller's contract.
    let opts = unsafe { &*options };
    base.with_priority(priority_from_c(opts.priority))
        .with_congestion_control(congestion_from_c(opts.congestion_control))
        .with_express(opts.is_express)
}

/// Fill in the default put options (zenoh-c `z_put_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_put_options_default(this_: *mut z_put_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_put_options_t {
            encoding: std::ptr::null_mut(),
            congestion_control: Z_CONGESTION_CONTROL_DROP,
            priority: Z_PRIORITY_DATA,
            is_express: false,
            timestamp: std::ptr::null(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            reliability: Z_RELIABILITY_RELIABLE,
            allowed_destination: ZC_LOCALITY_ANY,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
        }
    };
}

/// Fill in the default delete options (zenoh-c `z_delete_options_default`).
///
/// # Safety
/// `this_` must be null or a valid, writable options struct.
#[no_mangle]
pub unsafe extern "C" fn z_delete_options_default(this_: *mut z_delete_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = z_delete_options_t {
            congestion_control: Z_CONGESTION_CONTROL_DROP,
            priority: Z_PRIORITY_DATA,
            is_express: false,
            timestamp: std::ptr::null(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            reliability: Z_RELIABILITY_RELIABLE,
            allowed_destination: ZC_LOCALITY_ANY,
        }
    };
}

/// Publish `payload` on `key_expr` (zenoh-c `z_put`).
///
/// The payload is CONSUMED, per zenoh-c's own doc ("the value to put (consumed
/// upon function return)"), whether or not the publish succeeds — so a caller
/// cannot reuse it either way, which is what upstream does. The options'
/// owned fields go the same way, which is why they are resolved BEFORE the
/// handle null check.
///
/// # Safety
/// `session` and `key_expr` must be valid loaned handles; `payload` must be a
/// valid moved bytes; `options` must be null or a valid put-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_put(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *mut z_put_options_t,
) -> ZResult {
    guarded(|| {
        // The payload is taken FIRST and unconditionally: zenoh-c specifies it as
        // consumed on return, so leaving it alive on an error path would hand the
        // caller a value upstream would have invalidated — a divergence that only
        // shows up as a double free in their code, not ours.
        // SAFETY: the caller's contract.
        let payload = unsafe { take_payload(payload) };
        // SAFETY: the caller's contract for the options struct.
        let publish = unsafe { resolve_put_options(options) };
        let (Some(state), Some(keyexpr), Some(payload)) = (
            // SAFETY: the caller's contract for both handles.
            unsafe { session_state(session) },
            unsafe { keyexpr_str(key_expr) },
            payload,
        ) else {
            return Z_ENULL;
        };
        match state.shared.publish_all(keyexpr, &payload, &publish) {
            Ok(_) => Z_OK,
            // The only fan-out failure is a payload/keyexpr the bounded codec
            // cannot carry, which is an invalid argument rather than a network
            // condition.
            Err(_) => Z_EINVAL,
        }
    })
}

/// Delete the data behind `key_expr` (zenoh-c `z_delete`).
///
/// ONE export, and it is not padding: it is the only way a program on this ABI
/// can put a **Del** on the wire, so it is what turns
/// [`z_sample_kind`](crate::sample::z_sample_kind) from a value only a damaged
/// build can distinguish into one a real exchange does. A foreign subscriber
/// that prints DELETE for this and PUT for `z_put` has decided the mapping from
/// outside wz.
///
/// The payload argument that `z_put` carries is absent by construction:
/// `PublishOptions::del` ignores it, matching pico's `_z_n_msg_make_push_del`,
/// which carries no payload field at all.
///
/// # Safety
/// `session` and `key_expr` must be valid loaned handles; `options` must be
/// null or a valid delete-options struct.
#[no_mangle]
pub unsafe extern "C" fn z_delete(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    options: *mut z_delete_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(keyexpr)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract for the options struct.
        let publish = unsafe { resolve_delete_options(options) };
        match state.shared.publish_all(keyexpr, &[], &publish) {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R311y552 — THE SOUNDNESS GUARD. Every publish this crate issues must be
    /// `Locality::Remote`, and this test exists because the prose saying so is
    /// not enough: it was attempted and it produced a data race.
    ///
    /// `unsafe impl Sync for CClosure` (`crate::sub`) rests on the C application
    /// thread never invoking `call`. The only thing keeping that true is that
    /// these publishes are Remote, so `Session::publish` takes the
    /// `allows_local() == false` branch and stages no loopback fire. Make them
    /// local-capable and `session/mod.rs:867` drains the staged fires
    /// SYNCHRONOUSLY ON THE CALLER THREAD — so a C-thread `z_put` whose keyexpr
    /// matches a subscription runs that callback while the drive thread may be
    /// running the same C context's callback for another face's inbound sample.
    /// Two concurrent `call(context)` on one context, which upstream's
    /// single-threaded-callback contract forbids, and which R311y288 already
    /// fixed once on this plane.
    ///
    /// So honouring `allowed_destination` is NOT the "~20 lines plus a test"
    /// the debt ledger estimated from the fan shape. The fan split is the easy
    /// half; the blocker is that the loopback drain runs on whoever called
    /// publish. Closing it needs the local delivery moved onto the drive task
    /// (stage without draining, wake the face, let the drive loop drain) —
    /// wz-runtime-tokio has no entry point for that today.
    ///
    /// The assertion is on the RESOLVED options rather than on the constant, so
    /// it catches the change wherever it is made.
    #[test]
    fn every_publish_this_crate_issues_is_remote_only() {
        for (label, opts) in [
            ("z_put default", put_options()),
            ("z_delete default", delete_options()),
            (
                "z_publisher_put default",
                crate::publisher::publisher_put_options(),
            ),
        ] {
            assert_eq!(
                opts.allowed_destination,
                Locality::Remote,
                "{label}: a local-capable publish makes `unsafe impl Sync for \
                 CClosure` false — see this test's doc before changing it",
            );
            assert!(
                !opts.allowed_destination.allows_local(),
                "{label}: allows_local() must stay false",
            );
        }

        // And the resolved-from-C path cannot smuggle one in either: a caller
        // asking for SESSION_LOCAL must not produce a local-capable bundle
        // while the drain still runs on the caller thread.
        let mut o = z_put_options_t {
            encoding: std::ptr::null_mut(),
            congestion_control: Z_CONGESTION_CONTROL_DROP,
            priority: Z_PRIORITY_DATA,
            is_express: false,
            timestamp: std::ptr::null(),
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            reliability: Z_RELIABILITY_RELIABLE,
            allowed_destination: crate::publisher::ZC_LOCALITY_SESSION_LOCAL,
            #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
            source_info: std::ptr::null_mut(),
            attachment: std::ptr::null_mut(),
        };
        // SAFETY: a live local whose owned fields are all null.
        let resolved = unsafe { resolve_put_options(&mut o) };
        assert!(
            !resolved.allowed_destination.allows_local(),
            "z_put_options_t.allowed_destination is READ FOR LAYOUT; honouring \
             it requires the drive-task hand-off this test's doc describes",
        );
    }
}
