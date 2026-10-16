// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one message may weigh, asked of the library before anything is sent.
//!
//! A put whose message is larger than a session sends is refused before a byte
//! leaves, with its own code (`WZ_CAPI_C_E_VALUE_TOO_LARGE`). A caller that wants
//! to say so BEFORE it builds a value, or to size a value to fit, asks here, and
//! so does not copy the number: the limit is the one the library enforces, read
//! from the constant it enforces it with.
//!
//! The limit is the reassembly slot: a chain of fragments is refused at the
//! sender when the peer's slot of the same size could not rejoin it, so the number
//! is also the largest message this library itself would accept from a peer.

use crate::abi::z_loaned_session_t;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_OK};
use crate::session::session_state;

/// The most bytes of ONE encoded message this session sends, written through
/// `out`.
///
/// The count is the whole network message: its header, the key, the extensions
/// and the payload with their own headers. A value is therefore a little
/// smaller than this, by the key and a few tens of bytes, and the exact line is
/// the refusal a put answers with; use this number to say a limit and to size
/// values, and the code to know a particular put was over it.
///
/// Z_ENULL for a null `session` (or one that is not open) or a null `out`.
///
/// # Safety
/// `session` must be null or a valid loaned session; `out` must be null or valid
/// for one `usize` write.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_session_max_message_bytes(
    session: *const z_loaned_session_t,
    out: *mut usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        if out.is_null() || unsafe { session_state(session) }.is_none() {
            return Z_ENULL;
        }
        // SAFETY: `out` is non-null and valid for one write, by the contract.
        unsafe { *out = wz_runtime_tokio::reassembly_pool_ap::SLOT_SIZE };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The door answers the slot size the sender enforces, and refuses a null
    /// session and a null destination without writing.
    #[test]
    fn the_door_reports_the_slot_and_refuses_nulls_without_writing() {
        let mut got = 7usize;
        // SAFETY: null session, valid out.
        let rc = unsafe { wz_capi_c_session_max_message_bytes(std::ptr::null(), &mut got) };
        assert_eq!(rc, Z_ENULL);
        assert_eq!(got, 7, "a refused call must not write");
        // SAFETY: null out.
        let rc = unsafe {
            wz_capi_c_session_max_message_bytes(
                std::ptr::NonNull::<z_loaned_session_t>::dangling().as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, Z_ENULL);
        assert_eq!(wz_runtime_tokio::reassembly_pool_ap::SLOT_SIZE, 1_048_576);
    }
}
