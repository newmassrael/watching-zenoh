// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative engine behind a wz C ABI.
//!
//! A C session here is ONE session-core session over one link, stepped by the program's own
//! calls: [`CoopEngine::read`](wz_capi_port::SessionDrive::read) runs the session's task until it
//! has nothing more to do, which is what zenoh-pico's `zp_read` does in its single-threaded arm,
//! and a read task, when the program starts one, is a thread that makes the same call in a loop
//! (`docs/capi-pico-on-coop-engine.md`, decisions D2 and D8). There is no runtime thread and no
//! async executor of its own: between two calls the session does not move.
//!
//! The engine implements the port's [`SessionEngine`](wz_capi_port::SessionEngine) and
//! [`SessionDrive`](wz_capi_port::SessionDrive), so the ABI over it names neither this crate's
//! types nor the tokio engine's. What it does on a session is session-core's: the application
//! layer's observer keeps the subscribers, what the peer declared and the matching watches, and
//! the session's actions send what the program asks.
//!
//! What it does not do yet, each a later step of the note: the listening role, scouting, queries,
//! liveliness, the advanced plane, and a session that redials after its link is lost.

mod engine;
#[cfg(test)]
mod tests;

pub use engine::{CoopConfig, CoopEngine, OpenError};
