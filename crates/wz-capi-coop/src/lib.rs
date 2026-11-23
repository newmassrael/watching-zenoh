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
//! With `group` it also joins multicast groups: each group `CoopConfig::groups` names is a face of
//! its own, whose session is the session shell's group session hosted as a task of the session's
//! local set, over the group the network stack joins. With `group-host` the host's own sockets
//! join it (`host_group`), as the tokio engine's group link does, without `std`.
//!
//! With `remote-declaration-watch` or `declarations-synced-event` it tells a program's watch what
//! the peers of its links declare and retract (`decl_watch`), as the tokio engine does.
//!
//! With `listen` it also listens: the ports `CoopConfig::listen` names take inbound `tcp/` and
//! `udp/` links, each a face of its own beside the dial role's (`docs/capi-pico-on-coop-engine.md`,
//! step L3); a `udp/` port is one socket whose peers the stack tells apart by the address each
//! datagram came from.
//!
//! ## Where it builds
//!
//! `no_std` with `alloc`, so the pico C ABI on an MCU runs on this engine and not on a copy of it
//! (`docs/upstream-parity.md` section 5a). What the engine asks of an operating system (its mutex,
//! its read task's thread, its sleep) is `wz-capi-port`'s `os`; the `std` feature, on by default,
//! gives it the host's, and the runtime's critical sections the process's lock (`host-lock`).
//! Without it the image supplies both: the kernel's answers to `os` and a `critical-section`
//! implementation. Scouting with a socket for each interface (`scout`) and a group joined on the
//! host's sockets (`group-host`) ask a host's multicast sockets and its interface table, which
//! `wz-runtime-posix` gives without `std`; scouting over one datagram socket of the stack, as
//! zenoh-pico scouts where it has no interface iterator, needs no host at all (`scout-datagram`).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// The engine is the session shell's heap profile: a build that unified the per-session slot
// profile into its dependencies has none of the forms it is written over, and is refused here by
// name, with no item of the crate compiled to report what that profile lacks.
wz_session_core::heap_session_profile! {
"wz-capi-coop";

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

// The host's multicast sockets are the POSIX kernels' or Winsock's, and `wz-runtime-posix` is empty
// on another system: a build for one is refused here by name, rather than by the paths it lacks.
#[cfg(all(
    any(feature = "scout", feature = "group-host"),
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "nto",
        windows
    ))
))]
compile_error!(
    "wz-capi-coop: `scout` and `group-host` open a host's multicast sockets, which \
     `wz-runtime-posix` has on Linux, Android, QNX Neutrino and Windows; an image scouts with \
     `scout-datagram` over its own stack"
);

#[cfg(feature = "listen")]
mod admission_gate;
// The memory a session's open reserves for what its limits size, and the rows it is laid out by.
pub mod arena;
mod engine;
#[cfg(feature = "group-host")]
pub mod host_group;
// What the session hands its subscribers' callbacks after its lock, in a ring of its arena.
pub mod lane;
#[cfg(feature = "scout")]
pub mod scout;
#[cfg(feature = "scout-datagram")]
pub mod scout_datagram;
#[cfg(feature = "tls-mbedtls")]
pub mod tls;
/// The session shell's links over a transport the program supplies, which an ABI opens this
/// engine with in place of its host's sockets (`CoopEngine::open_with_policy` over
/// `app_link::AppLinks`).
#[cfg(feature = "app-transport")]
pub use wz_runtime_coop::app_link;
// The tests are a host's: they run a router stand-in on threads of `std`.
#[cfg(all(test, feature = "std"))]
mod tests;

pub use engine::{
    ClockMovesWord, ComposedLinks, CoopConfig, CoopDrive, CoopEngine, EndpointRefusal,
    KeyWireFormRefused, OpenError, OpenKeyIds, Refusal,
};
/// Why the session's runtime had no task for a link or a group ([`OpenError::NoTask`]).
pub use wz_runtime_coop::executor::SpawnRefusal;
#[cfg(feature = "time-base")]
pub use engine::ClockMoves;
/// The clock a session of this engine runs on, which every timer of the session reads: an ABI
/// opens the engine with its host's, or with one of its own (a time base the program supplies).
pub use wz_runtime_coop::ClockSource;
/// A wait a read of this engine makes, which an ABI gives for the word that a clock it moves has
/// moved on (`ClockMoves`, `time-base`).
pub use wz_runtime_coop::session_drive::LinkReadiness;
}
