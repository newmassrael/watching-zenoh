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

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Instant;

use wz_session_core::supervision::SupervisionState;
use wz_session_core::supervisor::{BuildSupervisor, StartRefused, Stop};

use crate::result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_OK};

/// The program's expiry hook: called once for each checkpoint that missed its deadline.
#[allow(non_camel_case_types)]
pub type wz_ext_supervision_hook_fn = unsafe extern "C" fn(context: *mut c_void, checkpoint: u8);

/// A checkpoint that is not supervised.
pub const WZ_EXT_SUPERVISION_DISARMED: u8 = 0;
/// A checkpoint that is supervised and was fed in time.
pub const WZ_EXT_SUPERVISION_ARMED: u8 = 1;
/// A checkpoint whose expiry hook is running.
pub const WZ_EXT_SUPERVISION_EXPIRING: u8 = 2;
/// A checkpoint whose hook has run.
pub const WZ_EXT_SUPERVISION_EXPIRED: u8 = 3;
/// What `wz_ext_supervision_state` answers for a checkpoint there is none of.
pub const WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT: u8 = 255;

#[derive(Clone, Copy)]
struct Hook {
    run: wz_ext_supervision_hook_fn,
    context: *mut c_void,
}

// SAFETY: the program owns the hook's thread-safety and the context's lifetime; the context is
// opaque here and only handed back to the hook.
unsafe impl Send for Hook {}

struct Doors {
    supervisor: BuildSupervisor,
    hook: Option<Hook>,
    origin: Instant,
}

impl Doors {
    /// Milliseconds since the first call, in the 32 bits the supervisor compares.
    fn now(&self) -> u32 {
        self.origin.elapsed().as_millis() as u32
    }
}

fn doors() -> &'static Mutex<Doors> {
    static DOORS: OnceLock<Mutex<Doors>> = OnceLock::new();
    DOORS.get_or_init(|| {
        Mutex::new(Doors {
            supervisor: BuildSupervisor::for_build(),
            hook: None,
            origin: Instant::now(),
        })
    })
}

fn locked() -> std::sync::MutexGuard<'static, Doors> {
    doors().lock().unwrap_or_else(PoisonError::into_inner)
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
        locked().hook = hook.map(|run| Hook { run, context });
        Z_OK
    })
}

/// Begin supervising `checkpoint`, with a deadline `timeout_ms` after now and after each feed.
/// `Z_ERR_INVALID` for a checkpoint the build does not have (`SUPERVISION_CHECKPOINTS`), or a
/// timeout of 0 or past 2147483647 ms. A checkpoint that is already supervised is left as it is.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_start(checkpoint: u8, timeout_ms: u32) -> ZResult {
    crate::ffi::guarded(|| {
        let mut doors = locked();
        let now = doors.now();
        match doors
            .supervisor
            .start(usize::from(checkpoint), now, timeout_ms)
        {
            Ok(()) => Z_OK,
            Err(StartRefused::NoSuchCheckpoint | StartRefused::TimeoutOutOfRange) => Z_ERR_INVALID,
        }
    })
}

/// The program made progress: start `checkpoint`'s deadline again. A checkpoint that is not
/// armed ignores it. `Z_ERR_INVALID` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_feed(checkpoint: u8) -> ZResult {
    crate::ffi::guarded(|| {
        let mut doors = locked();
        if usize::from(checkpoint) >= wz_session_core::caps::SUPERVISION_CHECKPOINTS {
            return Z_ERR_INVALID;
        }
        let now = doors.now();
        doors.supervisor.feed(usize::from(checkpoint), now);
        Z_OK
    })
}

/// Stop supervising `checkpoint`. `Z_ERR_GENERIC` when its expiry hook is running: it does not
/// stop until the hook returns. `Z_ERR_INVALID` for a checkpoint the build does not have.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_stop(checkpoint: u8) -> ZResult {
    crate::ffi::guarded(|| match locked().supervisor.stop(usize::from(checkpoint)) {
        Stop::Stopped => Z_OK,
        Stop::Refused => Z_ERR_GENERIC,
        Stop::NoSuchCheckpoint => Z_ERR_INVALID,
    })
}

/// Look at every supervised checkpoint now, and run the program's hook once for each whose
/// deadline has passed. The hook is called with no lock of the library held.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_check() -> ZResult {
    crate::ffi::guarded(|| {
        let (check, hook) = {
            let mut doors = locked();
            let now = doors.now();
            (doors.supervisor.check(now), doors.hook)
        };
        if check.is_clear() {
            return Z_OK;
        }
        for index in 0..wz_session_core::caps::SUPERVISION_CHECKPOINTS {
            if !check.hook(index) {
                continue;
            }
            // The expiry is written to the node's event log before the program's hook runs, so
            // it is in the log whatever the hook does, and once: the supervisor reports each
            // expiry to exactly one check. A build without the log writes nothing.
            #[cfg(feature = "event-ring")]
            {
                use wz_node_time::event_log::{global, library};
                global().emit_now(
                    library::LIBRARY_LEVEL,
                    library::SUPERVISION_EXPIRED,
                    &[index as u64],
                );
            }
            if let Some(hook) = hook {
                // SAFETY: the program's hook, under the contract of `set_hook`.
                unsafe { (hook.run)(hook.context, index as u8) };
            }
            locked().supervisor.hook_done(index);
        }
        Z_OK
    })
}

/// Whether the node is healthy: 1 when at least one checkpoint is supervised and every
/// supervised one is armed, 0 otherwise. A node that feeds a hardware watchdog feeds it when this
/// is 1.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_healthy() -> u8 {
    u8::from(locked().supervisor.is_healthy())
}

/// The state of `checkpoint`: `WZ_EXT_SUPERVISION_DISARMED`, `_ARMED`, `_EXPIRING` or `_EXPIRED`,
/// or `WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT`.
#[no_mangle]
pub extern "C" fn wz_ext_supervision_state(checkpoint: u8) -> u8 {
    match locked().supervisor.state(usize::from(checkpoint)) {
        Some(SupervisionState::Disarmed) => WZ_EXT_SUPERVISION_DISARMED,
        Some(SupervisionState::Armed) => WZ_EXT_SUPERVISION_ARMED,
        Some(SupervisionState::Expiring) => WZ_EXT_SUPERVISION_EXPIRING,
        Some(SupervisionState::Expired) => WZ_EXT_SUPERVISION_EXPIRED,
        None => WZ_EXT_SUPERVISION_NO_SUCH_CHECKPOINT,
    }
}
