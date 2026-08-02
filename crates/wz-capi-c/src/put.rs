// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_put` — the session-level publish.

use std::ffi::c_void;

use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::session::PublishOptions;

use crate::abi::{z_loaned_keyexpr_t, z_loaned_session_t, z_moved_bytes_t};
use crate::bytes::take_payload;
use crate::ffi::guarded;
use crate::keyexpr::keyexpr_str;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;

/// `Locality::Remote`, not the `Any` default — the same choice the zenoh-pico
/// shim documents and for the same structural reason: a C session here is N
/// per-face wz sessions, each with its own observer holding a replica of the
/// subscription, so a local-capable publish would fire one C callback once PER
/// FACE for a single `z_put`.
fn put_options() -> PublishOptions {
    PublishOptions::put().with_locality(Locality::Remote)
}

/// The Del-kind counterpart, with the same locality choice and for the same
/// reason.
fn delete_options() -> PublishOptions {
    PublishOptions::del().with_locality(Locality::Remote)
}

/// Publish `payload` on `key_expr` (zenoh-c `z_put`).
///
/// The payload is CONSUMED, per zenoh-c's own doc ("the value to put (consumed
/// upon function return)"), whether or not the publish succeeds — so a caller
/// cannot reuse it either way, which is what upstream does.
///
/// # Safety
/// `session` and `key_expr` must be valid loaned handles; `payload` must be a
/// valid moved bytes. `_options` is accepted for ABI compatibility and ignored:
/// `z_put.c` passes NULL, and the option fields (encoding, congestion control,
/// priority, express, timestamp, attachment) are later slices.
#[no_mangle]
pub unsafe extern "C" fn z_put(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    _options: *mut c_void,
) -> ZResult {
    guarded(|| {
        // The payload is taken FIRST and unconditionally: zenoh-c specifies it as
        // consumed on return, so leaving it alive on an error path would hand the
        // caller a value upstream would have invalidated — a divergence that only
        // shows up as a double free in their code, not ours.
        // SAFETY: the caller's contract.
        let payload = unsafe { take_payload(payload) };
        let (Some(state), Some(keyexpr), Some(payload)) = (
            // SAFETY: the caller's contract for both handles.
            unsafe { session_state(session) },
            unsafe { keyexpr_str(key_expr) },
            payload,
        ) else {
            return Z_ENULL;
        };
        match state.shared.publish_all(keyexpr, &payload, &put_options()) {
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
/// `session` and `key_expr` must be valid loaned handles. `_options` is accepted
/// for ABI compatibility and ignored: `z_delete.c` passes NULL, and the option
/// fields are later slices — the same treatment [`z_put`] gives them.
#[no_mangle]
pub unsafe extern "C" fn z_delete(
    session: *const z_loaned_session_t,
    key_expr: *const z_loaned_keyexpr_t,
    _options: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract for both handles.
        let (Some(state), Some(keyexpr)) = (unsafe { session_state(session) }, unsafe {
            keyexpr_str(key_expr)
        }) else {
            return Z_ENULL;
        };
        match state.shared.publish_all(keyexpr, &[], &delete_options()) {
            Ok(_) => Z_OK,
            Err(_) => Z_EINVAL,
        }
    })
}
