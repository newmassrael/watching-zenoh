// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one message may weigh, asked of the library before anything is sent.
//!
//! A put whose message is larger than a session sends is refused before a byte
//! leaves, with its own code (`WZ_CAPI_C_E_VALUE_TOO_LARGE`). A caller that wants
//! to say so BEFORE it builds a value, or to size a value to fit, asks here, and
//! so does not copy the number: the limit is the one the library enforces, read
//! from the constant it enforces it with.
//!
//! The limit is the bound this library's reassembly Router is built with, which
//! the sender refuses by (`wz_runtime_tokio::reassembly::REASSEMBLY_CHAIN_CAP`).
//! It is none: the number is `SIZE_MAX`, and no message is refused for its size,
//! as upstream's sender refuses none. Until the fan-in lane measured it (Round
//! 4617) it was the AP pool's 1 MiB slot, and a longer value was refused here
//! while every peer configured as upstream would have taken it. What a peer
//! accepts is its own `transport/link/rx/max_message_size` (upstream's 1 GiB by
//! default), which nothing on the wire tells a sender.

use crate::abi::z_loaned_session_t;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_OK};
use crate::session::session_handle;

/// The most bytes of ONE encoded message this session sends, written through
/// `out`.
///
/// The count is the whole network message: its header, the key, the extensions
/// and the payload with their own headers. A value is therefore a little
/// smaller than this, by the key and a few tens of bytes, and the exact line is
/// the refusal a put answers with; use this number to say a limit and to size
/// values, and the code to know a particular put was over it. `SIZE_MAX` says
/// the session refuses no message for its size, which is this build's answer.
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
        // The limit is a constant of this library's reassembly Router, which the registry and a
        // node share: a handle that is not there is the only thing with none to ask.
        // SAFETY: the caller's contract.
        if out.is_null() || unsafe { session_handle(session) }.is_none() {
            return Z_ENULL;
        }
        // SAFETY: `out` is non-null and valid for one write, by the contract.
        unsafe { *out = wz_runtime_tokio::reassembly::REASSEMBLY_CHAIN_CAP };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The door answers the bound the sender enforces, and refuses a null
    /// session and a null destination without writing.
    #[test]
    fn the_door_reports_the_senders_bound_and_refuses_nulls_without_writing() {
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
        assert_eq!(
            wz_runtime_tokio::reassembly::REASSEMBLY_CHAIN_CAP,
            usize::MAX,
            "the AP build bounds no message of its own"
        );
    }
}
