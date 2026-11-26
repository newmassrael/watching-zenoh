// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_session_step`: one step of a session the program runs on its own cycle.
//!
//! A door wz has and zenoh-pico does not, so it is `zext_*`, declared in `zext.h` with the
//! periodic run API. zenoh-pico's multi-threaded arm has no call that steps a session on the
//! program's thread: its read task does that work. A library carries both ways, and the program
//! picks one when it opens the session: with the read task (`z_open_options_t`'s
//! `auto_start_read_task`, true by default), or without it, stepping the session with this door
//! once a cycle. In the step the session reads what its links hold, keeps each lease, dials a lost
//! link again, runs what is due and hands what it read to the callbacks, on the caller's thread.
//! A step is refused while the read task runs, whether the open started it or
//! `zp_start_read_task` did since.

use crate::result::{
    ZResult, ZEXT_ERR_READ_TASK_RUNS, ZEXT_ERR_UNSUPPORTED, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_OK,
};
use crate::session::{session_handle, z_loaned_session_t};
use wz_capi_port::StepRefused;

/// The result code of a step: `Z_OK`, or why the session was not stepped.
pub(crate) fn result_of(stepped: Result<(), StepRefused>) -> ZResult {
    match stepped {
        Ok(()) => Z_OK,
        Err(StepRefused::Closed) => Z_ERR_SESSION_CLOSED,
        Err(StepRefused::ReadTaskRuns) => ZEXT_ERR_READ_TASK_RUNS,
        Err(StepRefused::Unsupported) => ZEXT_ERR_UNSUPPORTED,
    }
}

/// Step `session` once on the calling thread, waiting for input at most `timeout_ms`
/// milliseconds (0: only what is ready now; the session's own wait of a quiet link bounds it as
/// well). `Z_OK` once the step ran, `ZEXT_ERR_READ_TASK_RUNS` while the session's read task
/// runs, `Z_ERR_SESSION_CLOSED` for a closed session, `ZEXT_ERR_UNSUPPORTED` for a session
/// whose engine runs it on a thread of its own, and `Z_ERR_NULL` for a null session.
///
/// # Safety
/// `session` is a loaned session of this library, or null.
#[no_mangle]
pub unsafe extern "C" fn zext_session_step(
    session: *const z_loaned_session_t,
    timeout_ms: u32,
) -> ZResult {
    crate::ffi::guarded(|| {
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        result_of(handle.drive.step_once(timeout_ms))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A null session is refused before anything is read.
    #[test]
    fn a_null_session_is_refused() {
        // SAFETY: null is the case the door handles itself.
        assert_eq!(
            unsafe { zext_session_step(core::ptr::null(), 0) },
            Z_ERR_NULL
        );
    }

    /// Each answer of an engine has its own code.
    #[test]
    fn each_answer_of_the_engine_has_its_code() {
        assert_eq!(result_of(Ok(())), Z_OK);
        assert_eq!(result_of(Err(StepRefused::Closed)), Z_ERR_SESSION_CLOSED);
        assert_eq!(
            result_of(Err(StepRefused::ReadTaskRuns)),
            ZEXT_ERR_READ_TASK_RUNS
        );
        assert_eq!(
            result_of(Err(StepRefused::Unsupported)),
            ZEXT_ERR_UNSUPPORTED
        );
    }
}
