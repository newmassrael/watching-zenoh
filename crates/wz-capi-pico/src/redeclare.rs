// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_redeclare`: tell the peers of a session everything it holds again.
//!
//! A door wz has and zenoh-pico does not, so it is `wz_ext_*`, declared in `wz_ext.h` (the
//! extension namespace, apart from the drop-in headers), and part of the unstable surface: a
//! build without `unstable-api` carries none of it.
//!
//! A session tells a peer what it declared (its subscriptions, queryables, tokens and interests)
//! when the link to that peer comes up. A program that holds that a peer lost some of it (the
//! peer restarted behind a link that did not drop, or the program's own watch of the peer's
//! declarations says so) asks for the same telling again, over every link that is up, at the pace
//! the session states. Nothing the session holds changes: the entities keep their ids and their
//! routes, and the peer reads declarations it may already hold, which upstream's receive path
//! takes as the same declaration again.

use crate::result::{ZResult, WZ_EXT_ERR_UNSUPPORTED, Z_ERR_NULL, Z_ERR_SESSION_CLOSED};
use crate::session::{session_handle, z_loaned_session_t};

/// The result code of a redeclare: the count of links whose peer is told again, or why none.
pub(crate) fn result_of(told: Result<usize, wz_capi_port::RedeclareRefusal>) -> ZResult {
    match told {
        Ok(links) => ZResult::try_from(links).unwrap_or(ZResult::MAX),
        Err(wz_capi_port::RedeclareRefusal::Closed) => Z_ERR_SESSION_CLOSED,
        Err(wz_capi_port::RedeclareRefusal::Unsupported) => WZ_EXT_ERR_UNSUPPORTED,
    }
}

/// Tell the peer of every link of `session` that is up everything the session holds again.
/// The number of links told (0 when none is up), `Z_ERR_SESSION_CLOSED` for a closed session,
/// `WZ_EXT_ERR_UNSUPPORTED` for a session whose engine keeps no record of its declarations, and
/// `Z_ERR_NULL` for a null session.
///
/// # Safety
/// `session` is a loaned session of this library, or null.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_redeclare(session: *const z_loaned_session_t) -> ZResult {
    crate::ffi::guarded(|| {
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        result_of(wz_capi_port::SessionEngine::redeclare(
            crate::session::engine_ref(handle),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A null session is refused before anything is read.
    #[test]
    fn a_null_session_is_refused() {
        // SAFETY: null is the case the door handles itself.
        assert_eq!(unsafe { wz_ext_redeclare(core::ptr::null()) }, Z_ERR_NULL);
    }

    /// Each answer of an engine has its own code, and a count of links is the count.
    #[test]
    fn each_answer_of_the_engine_has_its_code() {
        use wz_capi_port::RedeclareRefusal;
        assert_eq!(result_of(Ok(0)), 0);
        assert_eq!(result_of(Ok(3)), 3);
        assert_eq!(
            result_of(Err(RedeclareRefusal::Closed)),
            Z_ERR_SESSION_CLOSED
        );
        assert_eq!(
            result_of(Err(RedeclareRefusal::Unsupported)),
            WZ_EXT_ERR_UNSUPPORTED
        );
    }
}
