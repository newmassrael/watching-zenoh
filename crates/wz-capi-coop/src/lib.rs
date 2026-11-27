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
//! With `listen` it also listens: the ports `CoopConfig::listen` names take inbound `tcp/` links,
//! and with `udp-listen` `udp/` ones, each a face of its own beside the dial role's
//! (`docs/capi-pico-on-coop-engine.md`, step L3); a `udp/` port is one socket whose peers the
//! stack tells apart by the address each datagram came from.
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
// Total functions in release code (docs/c-abi-architecture.md, P6): no panic is reachable from
// input. A module not yet converted is allowed by name with its row of the totality debt register
// (section 7 of that document), which scripts/lib/totality_debt_gate.py holds to these attributes.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]

extern crate alloc;

// The engine is the session shell's heap profile: a build that unified the per-session slot
// profile into its dependencies has none of the forms it is written over, and is refused here by
// name, first, while the macros expand. Called bare rather than around the items: rustfmt does
// not read a macro's body, so modules declared in one are formatted by no `cargo fmt`.
wz_session_core::heap_session_profile!("wz-capi-coop";);

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
        target_os = "macos",
        windows
    ))
))]
compile_error!(
    "wz-capi-coop: `scout` and `group-host` open a host's multicast sockets, which \
     `wz-runtime-posix` has on Linux, Android, QNX Neutrino, macOS and Windows; an image scouts \
     with `scout-datagram` over its own stack"
);

// What holds an accepted link's input back from the work form's task until the face is up; a read
// that steps each face where it lies brings the face up before it reads past the handshake.
#[cfg(all(feature = "listen", wz_round))]
mod admission_gate;
// The memory a session's open reserves for what its limits size, and the rows it is laid out by.
pub mod arena;
// The calls the engine's rows are made through, as the round, the queries' plane and the gets'
// plane name them: only a build that keeps one of them names them.
#[cfg(any(wz_round, feature = "query", feature = "queryable"))]
mod calls;
mod engine;
// The places a session's arena lends for values lodged by counts, given back from any thread.
mod lodging;
// The state of a session whose shape the build fixes, one struct the allocator hands zeroed: a
// session whose tables take their memory on use holds a state of its own instead.
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
pub mod region;
// The tables take their memory on use in a session whose shape the build fixes. Features add, so a
// build may name `tables-on-use` beside `runtime-plan` (`listen` and `group` turn it on, and
// `--all-features` names both): the session laid out at the open from its config wins, its faces'
// tables kept in the pools that arena lends, and the build is the `runtime-plan` form whole. Each
// item of the on-use form reads the feature beside `not(feature = "runtime-plan")`, and its twin
// the negation of both, so no item of the on-use form is compiled into that build
// (`form_precedence_tests`).
/// The storage policy of the session's registry, named once so every table of it and the rows each
/// is given agree on it: lent from the arena where the open lays the arena out from its config
/// (`runtime-plan`), placed in the region the build lays out otherwise (`region`), and taken from
/// the allocator at each table's first row where the tables take their memory on use
/// (`tables-on-use` without `runtime-plan`).
#[cfg(feature = "runtime-plan")]
pub(crate) type RowPolicy = wz_session_core::bounded::Lent;
/// See the form of a build with `runtime-plan`.
#[cfg(not(any(feature = "runtime-plan", feature = "tables-on-use")))]
pub(crate) type RowPolicy = wz_session_core::bounded::Region;
/// See the form of a build with `runtime-plan`.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
pub(crate) type RowPolicy = wz_session_core::bounded::OnUse;
// The session takes the memory of its tables when it opens and none after (docs/upstream-parity.md,
// D12): the moment this engine lays its tables out at, which every form above but the on-use one
// answers. A policy that takes its memory at another moment is a form of its own, chosen with the
// moment, so no form builds whose policy disagrees with its moment.
#[cfg(not(all(feature = "tables-on-use", not(feature = "runtime-plan"))))]
const _: () = assert!(
    matches!(
        <RowPolicy as wz_session_core::bounded::Storage>::TAKEN,
        wz_session_core::bounded::Taken::AtOpen
    ),
    "the session's tables take their memory at its open"
);
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
const _: () = assert!(
    matches!(
        <RowPolicy as wz_session_core::bounded::Storage>::TAKEN,
        wz_session_core::bounded::Taken::AtFirstUse
    ),
    "the session's tables take their memory at their first row"
);
// The precedence of the two forms above, held by name in the build that names both.
#[cfg(all(test, feature = "tables-on-use", feature = "runtime-plan"))]
mod form_precedence_tests {
    use core::any::TypeId;

    use wz_session_core::bounded::{Lent, Storage, Taken};

    use crate::RowPolicy;

    /// A build with `tables-on-use` and `runtime-plan` lends its tables from the arena its open
    /// lays out (`Lent`), whose memory is taken at the open. Turned red by naming `OnUse` (or
    /// any policy but `Lent`) as the `RowPolicy` of a build with both features, as a
    /// `RowPolicy` read under `tables-on-use` alone would.
    #[test]
    fn a_build_of_both_forms_lays_its_tables_out_at_the_open() {
        assert_eq!(TypeId::of::<RowPolicy>(), TypeId::of::<Lent>());
        assert_eq!(<RowPolicy as Storage>::TAKEN, Taken::AtOpen);
    }
}
/// The storage policy of the tables the session core's planes and round keep for the engine (the
/// ends of its gets' legs and their callbacks, the replies its gets hold, the Finals its queryables
/// hold and the requests they refused, the round's records, callbacks and keys) and of its note of
/// each leg pending: lent, where the open lends them from its arena or the region places them,
/// whichever policy the registry's tables are of; and taken at each table's first row where the
/// tables take their memory on use.
#[cfg(all(
    any(wz_round, feature = "query", feature = "queryable"),
    not(all(feature = "tables-on-use", not(feature = "runtime-plan")))
))]
pub(crate) type StatePolicy = wz_session_core::bounded::Lent;
/// See the form of a build without `tables-on-use`.
#[cfg(all(
    any(wz_round, feature = "query", feature = "queryable"),
    feature = "tables-on-use",
    not(feature = "runtime-plan")
))]
pub(crate) type StatePolicy = wz_session_core::bounded::OnUse;
// How the engine's calls stand to its threads, and the locks that choice decides.
mod form;

/// How the handles on the parts of one link of the engine's sessions are counted: what a stack
/// the engine opens its links over is counted by (`counted_by`) before it is handed to the open.
/// One task's count where one thread steps the session, or where the build gives no value a lock
/// of its own; one face's where several threads drive the session's faces, each face's link
/// handles moved between threads with the face whole. The terms are the form's
/// (`wz_value_locks`, the build script's), whose lock kind counts a link's parts so.
#[cfg(all(feature = "threads", wz_value_locks))]
pub type LinkCount = wz_runtime_coop::link_cells::OneFace;
/// How the handles on the parts of one link of the engine's sessions are counted: one task's.
#[cfg(not(all(feature = "threads", wz_value_locks)))]
pub type LinkCount = wz_runtime_coop::link_cells::OneTask;
#[cfg(feature = "group-host")]
pub mod host_group;
// What an open reads its session's config from, and how the endpoints' texts reach its rows.
pub mod open_source;
// What the session hands its callbacks after its lock: one table a round, read where the records lie.
// A build that puts nothing in it (`wz_round`, the crate's build script) has none.
#[cfg(wz_round)]
pub mod round;
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
/// The host's links and the program's transport as one stack, which an ABI that opens over either
/// opens this engine with, so the engine it reaches is one type (`either_links::EitherLinks`).
#[cfg(feature = "app-transport")]
pub use wz_runtime_coop::either_links;
/// The joiner of the groups over raw Ethernet (`raweth_group::RawethJoiner`), which an ABI wraps
/// the host's groups in where its build joins `reth/` groups.
#[cfg(feature = "raweth")]
pub use wz_runtime_coop::raweth_group;
// The tests are a host's: they run a router stand-in on threads of `std`.
#[cfg(all(test, feature = "std"))]
mod tests;

#[cfg(feature = "time-base")]
pub use engine::ClockMoves;
pub use engine::{
    ClockMovesWord, ComposedLinks, CoopConfig, CoopDrive, CoopEngine, CoopLinks, EndpointRefusal,
    EngineHold, KeyWireFormRefused, OpenError, OpenKeyIds, Refusal,
};
/// The process's table of engines and the reach of an engine through it, in a build with a reader
/// of it (`engine-rows`, which the requesting end, the answering end and the connectivity plane
/// turn on).
#[cfg(any(feature = "engine-rows", test))]
pub use engine::{EngineHandle, RowClaim, RowsRefused};
/// Why the session's runtime had no task for a link or a group ([`OpenError::NoTask`]).
pub use wz_runtime_coop::executor::SpawnRefusal;
/// The grammar this engine reads an endpoint's text with when it dials or listens on it, and the
/// protocols a locator it reads names: what an ABI reads an endpoint with when it answers for an
/// open of this engine without opening it.
pub use wz_runtime_coop::locator_text;
pub use wz_runtime_coop::session_drive::LinkProto;
/// The clock a session of this engine runs on, which every timer of the session reads: an ABI
/// opens the engine with its host's, or with one of its own (a time base the program supplies).
pub use wz_runtime_coop::ClockSource;
