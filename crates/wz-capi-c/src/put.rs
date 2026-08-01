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
