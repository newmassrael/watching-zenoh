// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_supervision_*`: the node's supervisor, driven from C (`docs/observation-plane.md` M3).
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`
//! (docs/build-configuration.md, decision C10), and part of the unstable surface: a build without
//! `unstable-api` carries none of it.
//!
//! A program that must keep making progress starts a checkpoint with a timeout and feeds it on every
//! pass. It calls `wz_ext_supervision_check` on its own cadence, which finds the checkpoints whose
//! deadline has passed and runs the program's hook once for each. The supervisor is healthy only
//! while every checkpoint that is supervised has been fed in time, so a node that feeds a hardware
//! watchdog feeds it from `wz_ext_supervision_healthy` and from nowhere else.
//!
//! The library holds no thread and no timer: `check` is the program's to call, from its main loop
//! or from a task of its own. Time is milliseconds on the monotonic clock since the first call,
//! counted in 32 bits that wrap, which the comparison of the supervisor is written to survive.
//!
//! The hook runs on the thread that called `check`, with no lock of the library held, so it may
//! call any of these doors. `wz_ext_supervision_stop` on the checkpoint whose hook is running is
//! refused until the hook returns.
//!
//! What the supervisor does is [`wz_capi_port::observation::supervision`]'s, which the zenoh-c
//! ABI's doors act on too; this file is the pico ABI's names and result codes for it.

use std::ffi::c_void;

use wz_capi_port::observation::supervision as supervisor;
use wz_capi_port::observation::Refusal;

use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_OK};

/// The program's expiry hook: called once for each checkpoint that missed its deadline.
#[allow(non_camel_case_types)]
pub type wz_ext_supervision_hook_fn = supervisor::HookFn;

/// A checkpoint that is not supervised.
pub const WZ_EXT_SUPERVISION_DISARMED: u8 = supervisor::STATE_DISARMED;
/// A checkpoint that is supervised and was fed in time.
pub const WZ_EXT_SUPERVISION_ARMED: u8 = supervisor::STATE_ARMED;
/// A checkpoint whose expiry hook is running.
pub const WZ_EXT_SUPERVISION_EXPIRING: u8 = supervisor::STATE_EXPIRING;
/// A checkpoint whose hook has run.
pub const WZ_EXT_SUPERVISION_EXPIRED: u8 = supervisor::STATE_EXPIRED;
/// What `wz_ext_supervision_state` answers for a checkpoint there is none of.
pub const WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT: u8 = supervisor::STATE_NO_SUCH_CHECKPOINT;

/// The pico code of a refusal of the supervision doors.
fn code(refusal: Refusal) -> ZResult {
    match refusal {
        Refusal::Invalid => Z_ERR_INVALID,
        Refusal::Full | Refusal::Unavailable => Z_ERR_GENERIC,
    }
}

/// Set the hook `wz_ext_supervision_check` calls for a checkpoint that missed its deadline, or
/// clear it with a null `hook`. With none set, an expired checkpoint is still marked expired and
/// makes the supervisor unhealthy.
///
/// # Safety
/// `hook` must be safe to call from the thread that calls `wz_ext_supervision_check` for as long
/// as it is set, and `context` must stay valid as long.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_supervision_set_hook(
    hook: Option<wz_ext_supervision_hook_fn>,
    context: *mut c_void,
) -> ZResult {
    crate::ffi::guarded(|| {
        supervisor::set_hook(hook, context);
        Z_OK
    })
}

/// Begin supervising `checkpoint`, with a deadline `timeout_ms` after now and after each feed.
/// `Z_ERR_INVALID` for a checkpoint the build does not have (`SUPERVISION_CHECKPOINTS`), or a
/// timeout of 0 or past 2147483647 ms. A checkpoint that is already supervised is left as it is.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_start(checkpoint: u8, timeout_ms: u32) -> ZResult {
    crate::ffi::guarded(|| match supervisor::start(checkpoint, timeout_ms) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// The program made progress: start `checkpoint`'s deadline again. A checkpoint that is not
/// armed ignores it. `Z_ERR_INVALID` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_feed(checkpoint: u8) -> ZResult {
    crate::ffi::guarded(|| match supervisor::feed(checkpoint) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Stop supervising `checkpoint`. `Z_ERR_GENERIC` when its expiry hook is running: it does not
/// stop until the hook returns. `Z_ERR_INVALID` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_stop(checkpoint: u8) -> ZResult {
    crate::ffi::guarded(|| match supervisor::stop(checkpoint) {
        Ok(()) => Z_OK,
        Err(refusal) => code(refusal),
    })
}

/// Compare the time with every deadline and run the program's hook once for each checkpoint that
/// has missed it. The expiry is written to the node's event log first, in a build that has the
/// log, so it is in the log whatever the hook does.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_check() -> ZResult {
    crate::ffi::guarded(|| {
        supervisor::check();
        Z_OK
    })
}

/// Whether the node is healthy: 1 when at least one checkpoint is supervised and every
/// supervised one is armed, 0 otherwise. A node that feeds a hardware watchdog feeds it when this
/// is 1.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_healthy() -> u8 {
    u8::from(supervisor::healthy())
}

/// The state of `checkpoint`: `WZ_EXT_SUPERVISION_DISARMED`, `_ARMED`, `_EXPIRING` or `_EXPIRED`,
/// or `WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT`.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_state(checkpoint: u8) -> u8 {
    supervisor::state(checkpoint)
}
