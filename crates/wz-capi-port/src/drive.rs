// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a C ABI's session handle asks of the engine that runs the session: [`SessionDrive`].
//!
//! [`SessionEngine`](crate::SessionEngine) is what declarations and publishes go through, and an
//! entity keeps it for its life. This is the other half: the session as a C handle holds it —
//! its identity, its close, and how it is driven. zenoh-pico has two arms here. In the
//! multi-threaded one a read task drives the session, and the program starts and stops it. In
//! the single-threaded one the program drives the session itself, with `zp_read`,
//! `zp_send_keep_alive` and `zp_spin_once`; work happens in those calls and not otherwise. An
//! engine answers both: one that drives itself on a thread of its own answers the second arm's
//! calls as a live session does, and one the program steps does the work in them
//! (`docs/capi-pico-on-coop-engine.md`, decisions D2 and D7).

use core::any::Any;

/// A start or a stop of the read task was made from inside one of the session's own callbacks.
/// zenoh-pico answers `_Z_ERR_INVALID` and does nothing, and so does an ABI given this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalledFromReadTask;

/// Why a start of the read task did not start it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTaskStartRefused {
    /// The start was made from inside one of the session's own callbacks ([`CalledFromReadTask`]).
    CalledFromReadTask,
    /// The system gave no thread for the task. zenoh-pico answers the error its task creation
    /// reported, `_Z_ERR_SYSTEM_GENERIC` where `pthread_create` refuses
    /// (`vendor/zenoh-pico/src/system/unix/system.c` @ `_Z_CHECK_SYS_ERR(pthread_create(task, attr, fun, arg));`),
    /// and a session opened to start it is not opened.
    NoThread,
}

impl From<CalledFromReadTask> for ReadTaskStartRefused {
    fn from(_: CalledFromReadTask) -> Self {
        Self::CalledFromReadTask
    }
}

/// The session is closed: nothing was read, kept alive or sent. zenoh-pico answers
/// `_Z_ERR_SESSION_CLOSED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosed;

/// Why a step the program made ([`SessionDrive::step_once`]) did not step the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepRefused {
    /// The session is closed ([`SessionClosed`]).
    Closed,
    /// The session's read task runs: the task steps the session, so a program that chose its read
    /// task at the open, or started it since, does not step it as well.
    ReadTaskRuns,
    /// The session's engine runs the session on a thread of its own, so there is no step for the
    /// program to make.
    Unsupported,
}

impl From<SessionClosed> for StepRefused {
    fn from(_: SessionClosed) -> Self {
        Self::Closed
    }
}

/// One session as a C handle holds it, whatever engine runs it.
///
/// `Send + Sync` because a C program may hand its session to any thread in pico's multi-threaded
/// arm. An engine whose own state is single-threaded keeps it behind the session's lock and runs
/// no C callback while holding it (decision D8).
///
/// The engine a session's entities keep is not handed out here: each engine's own drive type
/// hands it out as the engine's own type, so a build of one engine never turns it into a trait
/// object, and an engine that is reached through a trait object hands the object out itself.
pub trait SessionDrive: Send + Sync + 'static {
    /// The session's own zid, zero-padded to 16 bytes: the id its handshakes carry, which is
    /// its engine's, so a drive and its engine cannot name two.
    fn zid(&self) -> [u8; 16];

    /// Close the session: a Close to each peer, the links shut, every callback finished.
    /// Idempotent.
    fn close(&self);

    /// Whether [`Self::close`] has run.
    fn is_closed(&self) -> bool;

    /// Start the read task (zenoh-pico `zp_start_read_task`); idempotent. A system that gives
    /// no thread is an answer, never a panic: the task is not running and a later start tries
    /// again.
    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused>;

    /// Stop the read task (zenoh-pico `zp_stop_read_task`); idempotent. It returns once no
    /// callback is running.
    fn stop_read_task(&self) -> Result<(), CalledFromReadTask>;

    /// Whether the read task runs (zenoh-pico `zp_read_task_is_running`).
    fn read_task_is_running(&self) -> bool;

    /// Read what the session's links hold and dispatch it (zenoh-pico `zp_read`); with
    /// `single`, one message at most.
    fn read(&self, single: bool) -> Result<(), SessionClosed>;

    /// Send a keep-alive on each link now (zenoh-pico `zp_send_keep_alive`).
    fn send_keep_alive(&self) -> Result<(), SessionClosed>;

    /// Run one turn of the session's work, reading, keeping alive and serving what is due
    /// (zenoh-pico `zp_spin_once`): whether it made progress, `false` for a closed session.
    fn spin_once(&self) -> bool;

    /// Step the session once on the caller's thread, as its read task steps it: read what its
    /// links hold, waiting for input at most `most_ms` milliseconds (0: only what is ready now),
    /// keep each lease, dial a lost link again, run what is due and hand what was read to the
    /// callbacks. For a program that opened the session without its read task and runs its own
    /// cycle; refused while the read task runs. An engine that runs the session on a thread of its
    /// own has no such step, which is what this answers unless the engine says otherwise.
    fn step_once(&self, most_ms: u32) -> Result<(), StepRefused> {
        let _ = most_ms;
        if self.is_closed() {
            Err(StepRefused::Closed)
        } else {
            Err(StepRefused::Unsupported)
        }
    }

    /// The session as the engine's own type, for a capability an ABI reaches only on that
    /// engine (one the port does not carry yet).
    fn as_any(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// An engine that runs its session on a thread of its own: it says nothing of a step.
    struct SelfDriven {
        closed: AtomicBool,
    }

    impl SessionDrive for SelfDriven {
        fn zid(&self) -> [u8; 16] {
            [0; 16]
        }

        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }

        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }

        fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
            Ok(())
        }

        fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
            Ok(())
        }

        fn read_task_is_running(&self) -> bool {
            true
        }

        fn read(&self, _single: bool) -> Result<(), SessionClosed> {
            Ok(())
        }

        fn send_keep_alive(&self) -> Result<(), SessionClosed> {
            Ok(())
        }

        fn spin_once(&self) -> bool {
            true
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A step on an engine that steps itself is refused as unsupported, whatever the bound, and as
    /// closed once its session is.
    #[test]
    fn an_engine_that_steps_itself_refuses_the_programs_step() {
        let drive = SelfDriven {
            closed: AtomicBool::new(false),
        };
        assert_eq!(drive.step_once(0), Err(StepRefused::Unsupported));
        assert_eq!(drive.step_once(u32::MAX), Err(StepRefused::Unsupported));
        drive.close();
        assert_eq!(drive.step_once(0), Err(StepRefused::Closed));
    }

    /// A closed session read by a step is the step's closed refusal.
    #[test]
    fn a_closed_session_is_the_steps_closed_refusal() {
        assert_eq!(StepRefused::from(SessionClosed), StepRefused::Closed);
    }
}
