// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_capi_c_supervision_*`: the node's supervisor, driven from C
//! (`docs/observation-plane.md` M3).
//!
//! A door wz has and zenoh-c has not, so each carries the `wz_capi_c_` prefix and is declared in
//! `wz_capi_c.h`. A program that must keep making progress starts a checkpoint with a timeout and
//! feeds it on every pass. It calls `wz_capi_c_supervision_check` on its own cadence, which finds
//! the checkpoints whose deadline has passed and runs the program's hook once for each. The
//! supervisor is healthy only while every checkpoint that is supervised has been fed in time, so
//! a node that feeds a hardware watchdog feeds it from `wz_capi_c_supervision_healthy` and from
//! nowhere else.
//!
//! The library holds no thread and no timer: `check` is the program's to call, from its main loop
//! or from a task of its own. Time is milliseconds on the monotonic clock since the first call,
//! counted in 32 bits that wrap, which the comparison of the supervisor is written to survive.
//!
//! The hook runs on the thread that called `check`, with no lock of the library held, so it may
//! call any of these doors. `wz_capi_c_supervision_stop` on the checkpoint whose hook is running
//! is refused until the hook returns.
//!
//! What the supervisor does is [`wz_capi_port::observation::supervision`]'s, which the pico ABI's
//! `wz_ext_supervision_*` doors act on too; this file is this ABI's names and result codes for it.

use std::ffi::c_void;

use wz_capi_port::observation::supervision as supervisor;
use wz_capi_port::observation::Refusal;

use crate::ffi::guarded;
use crate::result::{ZResult, Z_EGENERIC, Z_EINVAL, Z_OK};

/// The program's expiry hook: called once for each checkpoint that missed its deadline.
#[allow(non_camel_case_types)]
pub type wz_capi_c_supervision_hook_fn = supervisor::HookFn;

/// A checkpoint that is not supervised.
pub const WZ_CAPI_C_SUPERVISION_DISARMED: u8 = supervisor::STATE_DISARMED;
/// A checkpoint that is supervised and was fed in time.
pub const WZ_CAPI_C_SUPERVISION_ARMED: u8 = supervisor::STATE_ARMED;
/// A checkpoint whose expiry hook is running.
pub const WZ_CAPI_C_SUPERVISION_EXPIRING: u8 = supervisor::STATE_EXPIRING;
/// A checkpoint whose hook has run.
pub const WZ_CAPI_C_SUPERVISION_EXPIRED: u8 = supervisor::STATE_EXPIRED;
/// What `wz_capi_c_supervision_state` answers for a checkpoint there is none of.
pub const WZ_CAPI_C_SUPERVISION_NO_SUCH_CHECKPOINT: u8 = supervisor::STATE_NO_SUCH_CHECKPOINT;

/// This ABI's code for a refusal of the supervision doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Invalid => Z_EINVAL,
        Refusal::Full | Refusal::Unavailable => Z_EGENERIC,
    }
}

/// Set the hook `wz_capi_c_supervision_check` calls for a checkpoint that missed its deadline, or
/// clear it with a null `hook`. With none set, an expired checkpoint is still marked expired and
/// makes the supervisor unhealthy.
///
/// # Safety
/// `hook` must be safe to call from the thread that calls `wz_capi_c_supervision_check` for as
/// long as it is set, and `context` must stay valid as long.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_supervision_set_hook(
    hook: Option<wz_capi_c_supervision_hook_fn>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        unsafe { supervisor::set_hook(hook, context) };
        Z_OK
    })
}

/// Begin supervising `checkpoint`, with a deadline `timeout_ms` after now and after each feed.
/// `Z_EINVAL` for a checkpoint the build does not have (`SUPERVISION_CHECKPOINTS`), or a timeout
/// of 0 or past 2147483647 ms. A checkpoint that is already supervised is left as it is.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_start(checkpoint: u8, timeout_ms: u32) -> ZResult {
    guarded(|| match supervisor::start(checkpoint, timeout_ms) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// The program made progress: start `checkpoint`'s deadline again. A checkpoint that is not
/// armed ignores it. `Z_EINVAL` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_feed(checkpoint: u8) -> ZResult {
    guarded(|| match supervisor::feed(checkpoint) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Stop supervising `checkpoint`. `Z_EGENERIC` when its expiry hook is running: it does not stop
/// until the hook returns. `Z_EINVAL` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_stop(checkpoint: u8) -> ZResult {
    guarded(|| match supervisor::stop(checkpoint) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Compare the time with every deadline and run the program's hook once for each checkpoint that
/// has missed it. The expiry is written to the node's event log first, in a build that has the
/// log, so it is in the log whatever the hook does.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_check() -> ZResult {
    guarded(|| {
        supervisor::check();
        Z_OK
    })
}

/// Whether the node is healthy: 1 when at least one checkpoint is supervised and every
/// supervised one is armed, 0 otherwise. A node that feeds a hardware watchdog feeds it when this
/// is 1.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_healthy() -> u8 {
    u8::from(supervisor::healthy())
}

/// The state of `checkpoint`: `WZ_CAPI_C_SUPERVISION_DISARMED`, `_ARMED`, `_EXPIRING` or
/// `_EXPIRED`, or `WZ_CAPI_C_SUPERVISION_NO_SUCH_CHECKPOINT`.
#[no_mangle]
pub extern "C" fn wz_capi_c_supervision_state(checkpoint: u8) -> u8 {
    supervisor::state(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The last checkpoint a test's hook was told of, and how many times it ran.
    static EXPIRED_COUNT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn counts_an_expiry(_context: *mut c_void, _checkpoint: u8) {
        EXPIRED_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    /// The supervisor is the process's, so the tests that drive it take turns.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_checkpoint_the_build_does_not_have_is_invalid_and_a_missing_one_has_no_state() {
        let _turn = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(wz_capi_c_supervision_start(255, 1000), Z_EINVAL);
        assert_eq!(wz_capi_c_supervision_feed(255), Z_EINVAL);
        assert_eq!(wz_capi_c_supervision_stop(255), Z_EINVAL);
        assert_eq!(
            wz_capi_c_supervision_state(255),
            WZ_CAPI_C_SUPERVISION_NO_SUCH_CHECKPOINT
        );
    }

    #[test]
    fn a_started_checkpoint_is_armed_and_stopped_by_the_program() {
        let _turn = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(wz_capi_c_supervision_start(0, 60_000), Z_OK);
        assert_eq!(wz_capi_c_supervision_state(0), WZ_CAPI_C_SUPERVISION_ARMED);
        assert_eq!(wz_capi_c_supervision_healthy(), 1);
        assert_eq!(wz_capi_c_supervision_feed(0), Z_OK);
        assert_eq!(wz_capi_c_supervision_stop(0), Z_OK);
        assert_eq!(
            wz_capi_c_supervision_state(0),
            WZ_CAPI_C_SUPERVISION_DISARMED
        );
    }

    #[test]
    fn a_checkpoint_that_is_not_fed_expires_once_and_runs_the_hook_once() {
        let _turn = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EXPIRED_COUNT.store(0, Ordering::SeqCst);
        // SAFETY: a hook safe to call from this thread, no context.
        let rc =
            unsafe { wz_capi_c_supervision_set_hook(Some(counts_an_expiry), std::ptr::null_mut()) };
        assert_eq!(rc, Z_OK);
        assert_eq!(wz_capi_c_supervision_start(1, 1), Z_OK);
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert_eq!(wz_capi_c_supervision_check(), Z_OK);
        assert_eq!(wz_capi_c_supervision_check(), Z_OK);
        assert_eq!(
            EXPIRED_COUNT.load(Ordering::SeqCst),
            1,
            "the hook runs once for an expiry, however often the program checks"
        );
        assert_eq!(wz_capi_c_supervision_healthy(), 0);
        assert_eq!(wz_capi_c_supervision_stop(1), Z_OK);
        // SAFETY: clearing the hook.
        unsafe { wz_capi_c_supervision_set_hook(None, std::ptr::null_mut()) };
    }
}
