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
//! A session outlives its link: a lost link is dialled again and the session declares over the
//! new one what it holds, as zenoh-pico's client reopens.
//!
//! With `queryable` it answers queries: its queryables' callbacks run outside its lock, as its
//! subscribers' do, and a query a C program keeps holds its Final until it is let go.
//!
//! With `scout` it also scouts: a window a program runs on its own thread, which needs no
//! session (`scout`).
//!
//! With `ticker` it runs a program's periodic jobs from the call that steps the session, which
//! the advanced plane's heartbeat, periodic re-ask and retention sweep are; the plane itself is
//! the neutral `wz-ext-pubsub`'s, hosted over the engine's port.
//!
//! With `listen` it also listens: the ports `CoopConfig::listen` names take inbound `tcp/` links,
//! each a face of its own beside the dial role's (`docs/capi-pico-on-coop-engine.md`, step L3).
//! What it does not do yet, a later step of the note: `udp/` and `tls/` faces, and the C ABI's
//! listener.
//!
//! ## Where it builds
//!
//! `no_std` with `alloc`, so the pico C ABI on an MCU runs on this engine and not on a copy of it
//! (`docs/upstream-parity.md` section 5a). What the engine asks of an operating system (its mutex,
//! its read task's thread, its sleep) is `wz-capi-port`'s `os`; the `std` feature, on by default,
//! gives it the host's, and the runtime's critical sections the process's lock (`host-lock`).
//! Without it the image supplies both: the kernel's answers to `os` and a `critical-section`
//! implementation. Scouting asks the host's multicast sockets and comes with `std` only.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// What `std`'s prelude gave every module and `alloc` does not: brought in by the modules that
/// use it, so a build without `std` reads the same source. A build's features decide which of
/// these it names, so one that names none of an item is not an error.
#[allow(unused_imports)]
mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::format;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec;
    pub(crate) use alloc::vec::Vec;
}

#[cfg(feature = "listen")]
mod admission_gate;
mod engine;
#[cfg(feature = "scout")]
pub mod scout;
// The tests are a host's: they run a router stand-in on threads of `std`.
#[cfg(all(test, feature = "std"))]
mod tests;

pub use engine::{CoopConfig, CoopEngine, OpenError, DEFAULT_ACCEPT_PENDING, DEFAULT_MAX_FACES};
