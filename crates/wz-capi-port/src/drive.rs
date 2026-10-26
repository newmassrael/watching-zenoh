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

use alloc::sync::Arc;
use core::any::Any;

use crate::SessionEngine;

/// A start or a stop of the read task was made from inside one of the session's own callbacks.
/// zenoh-pico answers `_Z_ERR_INVALID` and does nothing, and so does an ABI given this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalledFromReadTask;

/// The session is closed: nothing was read, kept alive or sent. zenoh-pico answers
/// `_Z_ERR_SESSION_CLOSED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosed;

/// One session as a C handle holds it, whatever engine runs it.
///
/// `Send + Sync` because a C program may hand its session to any thread in pico's multi-threaded
/// arm. An engine whose own state is single-threaded keeps it behind the session's lock and runs
/// no C callback while holding it (decision D8).
pub trait SessionDrive: Send + Sync + 'static {
    /// The engine the session's entities keep, handed out by the engine.
    fn engine(&self) -> Arc<dyn SessionEngine>;

    /// The engine, borrowed for the length of one call.
    fn engine_ref(&self) -> &dyn SessionEngine;

    /// The session's own zid, zero-padded to 16 bytes: the id its handshakes carry.
    fn zid(&self) -> [u8; 16];

    /// Close the session: a Close to each peer, the links shut, every callback finished.
    /// Idempotent.
    fn close(&self);

    /// Whether [`Self::close`] has run.
    fn is_closed(&self) -> bool;

    /// Start the read task (zenoh-pico `zp_start_read_task`); idempotent.
    fn start_read_task(&self) -> Result<(), CalledFromReadTask>;

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

    /// The session as the engine's own type, for a capability an ABI reaches only on that
    /// engine (one the port does not carry yet).
    fn as_any(&self) -> &dyn Any;
}
