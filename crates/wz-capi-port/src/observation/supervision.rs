// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's supervisor, driven from C (the deadline the application feeds, an instrument of the
//! observation plane).
//!
//! An application that must keep making progress (a control loop, a task that polls a bus) feeds a
//! checkpoint on every pass. If a feed does not come in time the checkpoint expires, a hook runs
//! once, and the node can say that something it supervises has stopped. A node that feeds a
//! hardware watchdog feeds it only while every checkpoint is armed, so a hung one stops the feed.
//!
//! Nothing here runs by itself: the library holds no timer for a deadline the application chose
//! at run time. The program calls [`check`] on its own cadence, and the supervisor compares the
//! time it is given with the deadlines it holds ([`wz_session_core::supervisor`]).
//!
//! The one supervisor is the process's. Its storage is the build's `SUPERVISION_CHECKPOINTS`
//! checkpoints, and it watches as many of them as the process's runtime limits lend it
//! ([`crate::runtime_limits`]), which its first door takes.

use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

use wz_session_core::policy::SessionPolicy;
use wz_session_core::supervision::SupervisionState;
use wz_session_core::supervisor::{BuildSupervisor, StartRefused, Stop, MAX_CHECKPOINTS};

use super::Refusal;

/// The program's hook, run once for each checkpoint that expires, with the checkpoint's number.
pub type HookFn = unsafe extern "C" fn(context: *mut c_void, checkpoint: u8);

/// A checkpoint that is not supervised.
pub const STATE_DISARMED: u8 = 0;
/// A checkpoint that is supervised and fed in time.
pub const STATE_ARMED: u8 = 1;
/// A checkpoint whose expiry hook is running.
pub const STATE_EXPIRING: u8 = 2;
/// A checkpoint whose hook has run.
pub const STATE_EXPIRED: u8 = 3;
/// What [`state`] answers for a checkpoint there is none of.
pub const STATE_NO_SUCH_CHECKPOINT: u8 = 255;

#[derive(Clone, Copy)]
struct Hook {
    run: HookFn,
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

/// The policies the process's supervisor runs under: the one place its creator, the first call
/// of a door, decides them. The build defaults, until the process is handed a run-time document.
fn resolve_policy() -> SessionPolicy {
    SessionPolicy::defaults()
}

fn doors() -> &'static Mutex<Doors> {
    static DOORS: OnceLock<Mutex<Doors>> = OnceLock::new();
    DOORS.get_or_init(|| {
        Mutex::new(Doors {
            supervisor: BuildSupervisor::of_snapshots(
                &resolve_policy(),
                &crate::runtime_limits::take(),
            ),
            hook: None,
            origin: Instant::now(),
        })
    })
}

fn locked() -> MutexGuard<'static, Doors> {
    doors().lock().unwrap_or_else(PoisonError::into_inner)
}

/// Set the hook [`check`] calls for a checkpoint that missed its deadline, or clear it with
/// `None`. With none set, an expired checkpoint is still marked expired and makes the supervisor
/// unhealthy. The hook runs on the thread that calls [`check`], with no lock of the library held.
///
/// # Safety
/// `hook` must be safe to call from the thread that calls [`check`] for as long as it is set, and
/// `context` must stay valid as long.
pub unsafe fn set_hook(hook: Option<HookFn>, context: *mut c_void) {
    locked().hook = hook.map(|run| Hook { run, context });
}

/// Begin supervising `checkpoint`, with a deadline `timeout_ms` after now and after each feed.
/// [`Refusal::Invalid`] for a checkpoint the process does not watch (`SUPERVISION_CHECKPOINTS`), or
/// a timeout of 0 or past 2147483647 ms. A checkpoint that is already supervised is left as it is.
pub fn start(checkpoint: u8, timeout_ms: u32) -> Result<(), Refusal> {
    let mut doors = locked();
    let now = doors.now();
    match doors
        .supervisor
        .start(usize::from(checkpoint), now, timeout_ms)
    {
        Ok(()) => Ok(()),
        Err(StartRefused::NoSuchCheckpoint | StartRefused::TimeoutOutOfRange) => {
            Err(Refusal::Invalid)
        }
    }
}

/// The program made progress: start `checkpoint`'s deadline again. A checkpoint that is not armed
/// ignores it. [`Refusal::Invalid`] for a checkpoint the process does not watch.
pub fn feed(checkpoint: u8) -> Result<(), Refusal> {
    let mut doors = locked();
    if usize::from(checkpoint) >= doors.supervisor.checkpoints() {
        return Err(Refusal::Invalid);
    }
    let now = doors.now();
    doors.supervisor.feed(usize::from(checkpoint), now);
    Ok(())
}

/// Stop supervising `checkpoint`. [`Refusal::Unavailable`] when its expiry hook is running: it does
/// not stop until the hook returns. [`Refusal::Invalid`] for a checkpoint the process does not
/// watch.
pub fn stop(checkpoint: u8) -> Result<(), Refusal> {
    match locked().supervisor.stop(usize::from(checkpoint)) {
        Stop::Stopped => Ok(()),
        Stop::Refused => Err(Refusal::Unavailable),
        Stop::NoSuchCheckpoint => Err(Refusal::Invalid),
    }
}

/// Compare the time with every deadline and run the hook of each checkpoint that has expired,
/// once. The program calls it on its own cadence.
pub fn check() {
    let (check, hook) = {
        let mut doors = locked();
        let now = doors.now();
        (doors.supervisor.check(now), doors.hook)
    };
    if check.is_clear() {
        return;
    }
    for index in 0..MAX_CHECKPOINTS {
        if !check.hook(index) {
            continue;
        }
        // The expiry is written to the node's event log before the program's hook runs, so it is
        // in the log whatever the hook does, and once: the supervisor reports each expiry to
        // exactly one check. A build without the log writes nothing.
        #[cfg(feature = "event-ring")]
        super::events::emit_supervision_expired(index);
        if let Some(hook) = hook {
            // SAFETY: the program's hook, under the contract of `set_hook`.
            unsafe { (hook.run)(hook.context, index as u8) };
        }
        locked().supervisor.hook_done(index);
    }
}

/// Whether the node is healthy: at least one checkpoint is supervised and every supervised one is
/// armed. A node that feeds a hardware watchdog feeds it when this is so.
pub fn healthy() -> bool {
    locked().supervisor.is_healthy()
}

/// The state of `checkpoint`: [`STATE_DISARMED`], [`STATE_ARMED`], [`STATE_EXPIRING`] or
/// [`STATE_EXPIRED`], or [`STATE_NO_SUCH_CHECKPOINT`].
pub fn state(checkpoint: u8) -> u8 {
    match locked().supervisor.state(usize::from(checkpoint)) {
        Some(SupervisionState::Disarmed) => STATE_DISARMED,
        Some(SupervisionState::Armed) => STATE_ARMED,
        Some(SupervisionState::Expiring) => STATE_EXPIRING,
        Some(SupervisionState::Expired) => STATE_EXPIRED,
        None => STATE_NO_SUCH_CHECKPOINT,
    }
}
