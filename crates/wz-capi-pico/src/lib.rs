// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! # wz-capi-pico — §5.27 api-compat-pico
//!
//! A zenoh-pico-compatible C ABI (`z_*` / `zp_*` `#[no_mangle] extern "C"`
//! symbols) wrapping the wz AP `wz::runtime_tokio` `Session`, so a zenoh-pico
//! C program can link the wz cdylib as a binary drop-in. This is the reverse
//! of the `*-sys` crates (which bind TO a C library); this crate EXPORTS one.
//!
//! The binary-drop-in design is sound: pico defines the owned-type operations
//! as EXTERN symbols in `api.c` (not `static inline`), so these `#[no_mangle]`
//! exports replace them at link time, and idiomatic pico code touches the
//! owned structs only through those ops. The ABI is VALIDATED end-to-end
//! wz-to-wz over loopback TCP (`tests/pubsub_roundtrip.rs`,
//! `tests/listener_multipeer.rs`); interop against a separately-compiled
//! zenoh-pico binary is deferred to a cc round-trip test (a follow-up round).
//!
//! ## The session model
//!
//! A pico session is a PEER SET, not a single link: a `connect` session holds
//! one peer (the router it dialed), a `listen` session accepts multiple
//! concurrent inbound peers. wz's unicast `Session` is one peer by
//! construction, so the C handle here is a REGISTRY of per-face wz sessions
//! plus the C-declared subscription SSOT replayed onto each face (the `faces`
//! module). `z_open(listen)` therefore returns as soon as the endpoint is
//! bound, with zero peers and no error, exactly as pico's does. (One named
//! divergence: pico caps a listener at 10 peers and refuses the 11th; wz holds
//! unbounded — see the `faces` module doc.)
//!
//! ## Surface
//!
//! A complete core session + pub/sub slice:
//! - **config**: `z_config_default`, `zp_config_insert` (connect/listen keys
//!   pick the dial vs accept role).
//! - **session**: `z_open` / `z_close`, the 7-function session ownership
//!   family, and the `zp_*_task` shims (wz's drive loop already reads/leases).
//! - **keyexpr**: `z_view_keyexpr_from_str` + the view family +
//!   `z_keyexpr_as_view_string`.
//! - **bytes**: `z_bytes_copy_from_buf` / `_from_str`, `z_bytes_to_slice` /
//!   `_to_string`, slice/string accessors + ownership.
//! - **publisher**: `z_declare_publisher` / `z_publisher_put` /
//!   `z_undeclare_publisher`, plus session-level `z_put`.
//! - **subscriber**: `z_closure_sample`, `z_declare_subscriber` /
//!   `z_undeclare_subscriber`, `z_sample_keyexpr` / `z_sample_payload`.
//!
//! The exported symbols share the pico struct layouts for every type Round 1
//! exercises (see [`abi`]); a program compiled against this crate's own header
//! (`include/wz_capi_pico.h`) is self-consistent. Follow-up rounds add
//! get/queryable, liveliness, scouting, attachments, and the full
//! `Z_FEATURE`-dependent binary size-match audit for publisher/subscriber.
//!
//! The design and grounding are recorded in the round ledger; the async-drive
//! bridge (the crux — wz has no self-driving session) lives in [`session`].
//!
//! ## Where it builds
//!
//! On a host with `std` (a default feature), and without it `no_std` with `alloc`, so that the
//! pico C ABI on an MCU is this crate and not a copy of it (`docs/upstream-parity.md` section 5a).
//! What the ABI layer asks of an operating system beyond `alloc` (a mutex, a condition variable,
//! the calling thread's identity) is the engine port's `os`, whose host half is `std`'s; what the
//! platform exports hand to the system is the host layer of this build (`os`). A capability whose
//! module still names the host's library selects `std` in the manifest.
//!
//! A host library is built without `std` too (`os-posix` on a POSIX host, `os-windows` on
//! Windows): the MCU build over the host's own calls, the port's `os` and the runtime's locks made
//! of them, and the host's heap and `abort` in place of `std`'s allocator and panic
//! (`docs/c-abi-engine-and-memory.md`, E4).

#![cfg_attr(not(feature = "std"), no_std)]
// pico's C type names are snake_case (`z_owned_session_t`,
// `z_closure_sample_callback_t`); reproducing the ABI names verbatim is the
// point, so the camel-case convention does not apply to this crate's surface.
#![allow(non_camel_case_types)]
// Every exported symbol is an `unsafe extern "C"` boundary with the SAME
// safety contract — the zenoh-pico C ABI: pointer arguments must be either
// null or valid, non-aliased pointers to the pico-typed objects the caller
// owns (an owned struct the caller allocated, or a value this library
// produced), matching the semantics of the pico function of the same name.
// Restating that per-function `# Safety` section across ~60 ABI thunks adds
// no information, so the clippy lint is allowed crate-wide; the per-function
// doc records how each maps to its pico counterpart.
#![allow(clippy::missing_safety_doc)]
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
    // The operations of the session's engine, which a build of one engine reaches as its own
    // type rather than as a trait object.
    pub(crate) use wz_capi_port::SessionEngine as _;
}

// A session runs on an engine (`docs/capi-pico-on-coop-engine.md`, decision D4), so a build
// that names neither has no `z_open` to give; it is refused here, by name, rather than by the
// unresolved crates of the engine the open would have reached.
#[cfg(not(any(
    feature = "engine-tokio",
    feature = "engine-coop",
    feature = "os-posix",
    feature = "os-windows",
    feature = "os-zephyr"
)))]
compile_error!(
    "wz-capi-pico: a build needs an engine to run its sessions: `engine-tokio` for the session \
     on its own thread and runtime, `engine-coop` for the one the program steps, `os-posix` and \
     `os-windows` for that one in a POSIX or a Windows host library without `std`, `os-zephyr` \
     for that one in a Zephyr image"
);

// A library has one engine (`docs/c-abi-engine-and-memory.md`, E1 and E3). The cooperative forms
// read and send only what the session lends (`wz-capi-coop`'s `rx-lent-only` and `tx-lend-only`,
// which they select), and the tokio engine refuses to be built beside those, so a build that names
// both is refused here by name. A capability only the tokio engine runs selects it, and is named
// on its own, so the program is told which feature to drop rather than which engine it pulled in.
#[cfg(all(
    feature = "gossip",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `gossip` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "raweth-transport",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `raweth-transport` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "rx-busy-poll",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `rx-busy-poll` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "serial-drive-own-thread",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `serial-drive-own-thread` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "transport-link-quic",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `transport-link-quic` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "transport-link-serial",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `transport-link-serial` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "transport-link-tls",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `transport-link-tls` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
// The unixpipe link is built on a Unix host alone, so elsewhere the feature names nothing to refuse.
#[cfg(all(
    feature = "transport-link-unixpipe",
    unix,
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `transport-link-unixpipe` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "transport-link-ws",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    )
))]
compile_error!(
    "wz-capi-pico: `transport-link-ws` runs only on the tokio engine, \
     and this build names a cooperative one (`engine-coop`, `os-posix`, `os-windows` or \
     `os-zephyr`): drop it from the cooperative library, or build the tokio engine's without the \
     cooperative feature"
);
#[cfg(all(
    feature = "engine-tokio",
    any(
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows",
        feature = "os-zephyr"
    ),
    not(any(
        feature = "gossip",
        feature = "raweth-transport",
        feature = "rx-busy-poll",
        feature = "serial-drive-own-thread",
        feature = "transport-link-quic",
        feature = "transport-link-serial",
        feature = "transport-link-tls",
        feature = "transport-link-unixpipe",
        feature = "transport-link-ws"
    ))
))]
compile_error!(
    "wz-capi-pico: a library has one engine, and this build names `engine-tokio` beside a \
     cooperative one (`engine-coop`, `os-posix`, `os-windows` or `os-zephyr`): build the \
     cooperative library with `--no-default-features` and its features, or the tokio engine's \
     without the cooperative feature (`tls-mbedtls` names `engine-coop`)"
);

// `os-zephyr` is the image's engine and host, and an image has no standard library: a capability
// that still selects `std` (scouting, the requesting end of a query, the unstable surface, ...) is
// a host's alone until its module stands without it. Such a build is refused by name here, rather
// than by the missing `std` of the bare core or by a host layer the image cannot link. A build that
// names a host engine as well keeps that host's (features add, and the host wins).
#[cfg(all(
    feature = "os-zephyr",
    feature = "std",
    not(any(feature = "engine-tokio", feature = "engine-coop"))
))]
compile_error!(
    "wz-capi-pico: `os-zephyr` builds without `std`, and a feature of this build selects it; \
     the capabilities a Zephyr image carries are those whose features do not select `std` \
     (see Cargo.toml)"
);

// `os-posix` and `os-windows` are a host library without `std`: a capability that still selects
// `std` is refused beside either by name, as beside `os-zephyr`, rather than built into a library
// that has `std` after all. A build that names a host engine as well keeps `std` (features add,
// and the host wins).
#[cfg(all(
    any(feature = "os-posix", feature = "os-windows"),
    feature = "std",
    not(any(feature = "engine-tokio", feature = "engine-coop"))
))]
compile_error!(
    "wz-capi-pico: `os-posix` and `os-windows` build without `std`, and a feature of this build \
     selects it; the capabilities a host library without `std` carries are those whose features \
     do not select `std` (see Cargo.toml)"
);

// A library is for one system: `os-posix` a POSIX host's, `os-windows` a Windows host's,
// `os-zephyr` a Zephyr image's.
#[cfg(all(
    not(feature = "std"),
    any(
        all(feature = "os-posix", feature = "os-windows"),
        all(feature = "os-posix", feature = "os-zephyr"),
        all(feature = "os-windows", feature = "os-zephyr")
    )
))]
compile_error!(
    "wz-capi-pico: `os-posix`, `os-windows` and `os-zephyr` each name the system the library is \
     for; a build names one"
);

// And the system it names is the one it is built for. Asked only of a build that names one system,
// so a build that names two is told that first. `os-windows` is for the MSVC targets, whose C
// runtime the library links (`src/os/no_std_host.rs`); a GNU target's runtime and unwinder are
// others, which no build has linked.
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    not(feature = "os-windows"),
    not(feature = "os-zephyr"),
    windows
))]
compile_error!(
    "wz-capi-pico: `os-posix` is the library without `std` for a POSIX host; Windows builds it \
     with `os-windows`"
);
#[cfg(all(
    feature = "os-windows",
    not(feature = "std"),
    not(feature = "os-posix"),
    not(feature = "os-zephyr"),
    not(all(windows, target_env = "msvc"))
))]
compile_error!(
    "wz-capi-pico: `os-windows` is the library without `std` for Windows, built for an MSVC target \
     (`x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`); a POSIX host builds it with `os-posix`"
);

// The doors of the additional features hold their state behind a host's lock, and supervision
// polls on a host's thread: `std`'s, or `wz-host-sync`'s in a host library without `std`
// (`os-posix`, `os-windows`). A build with neither has no lock for them, and is refused here by
// name.
#[cfg(all(
    not(feature = "std"),
    not(feature = "os-posix"),
    not(feature = "os-windows"),
    any(
        feature = "e2e-sender",
        feature = "e2e-receiver",
        feature = "e2e-supervision",
        feature = "instance-key",
        feature = "message-catalog",
        feature = "replay-cache"
    )
))]
compile_error!(
    "wz-capi-pico: the doors of the additional features need a host's lock and threads: `std`, or \
     `os-posix` or `os-windows` for a host library without it"
);

// The advanced publisher and subscriber lock their cache and state and stamp from the wall clock:
// a host's, with `std` or beside `os-posix` or `os-windows`. An image has neither.
#[cfg(all(
    feature = "advanced",
    not(feature = "std"),
    not(feature = "os-posix"),
    not(feature = "os-windows")
))]
compile_error!(
    "wz-capi-pico: `advanced` needs a host's lock and wall clock: `std`, or `os-posix` or \
     `os-windows` for a host library without it"
);

// `scout` asks each interface of a host by a socket of its own, and `multicast-transport` joins a
// group on a host's sockets (`wz-runtime-posix`), which a Zephyr image has none of; `peer` and
// `multicast-transport` bring `scout`. Beside `os-zephyr` alone it is refused by name, rather than
// by the host's paths the image lacks.
#[cfg(all(
    feature = "os-zephyr",
    feature = "scout",
    not(any(
        feature = "engine-tokio",
        feature = "engine-coop",
        feature = "os-posix",
        feature = "os-windows"
    ))
))]
compile_error!(
    "wz-capi-pico: `scout`, which `peer` and `multicast-transport` bring, opens a host's \
     multicast sockets, and a Zephyr image has none: an image scouts with `scout-mcu`"
);

// `scout-mcu` is the cooperative engine's window over one datagram socket; the tokio engine scouts
// on the host's sockets, which is `scout`.
#[cfg(all(
    feature = "scout-mcu",
    feature = "engine-tokio",
    not(feature = "scout")
))]
compile_error!(
    "wz-capi-pico: the tokio engine scouts on the host's sockets: a build with it names `scout`, \
     and `scout-mcu` is the cooperative engine's window over one datagram socket"
);

// Totality debt TD-178 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod abi;
// The doors of the additional features (end-to-end protection, stream supervision, instance keys, the
// replay cache, the message catalog) are a layer over this core that names it only through its C
// ABI and the extension interface (`ext_interface`). The default build links them into this library.
// The same sources also build as two: this crate compiled with `--cfg wz_additional_apart` is the
// core alone, and `wz-capi-pico-ext` compiles the doors' files again as a library of its own that
// imports the core through C (`docs/capi-pico-additional-library.md`); each door module below is
// left out of the core alone.
//
// Which version of the extension interface the doors were built against, asked of them and compared
// with the core's: a wz door (`wz_ext.h`) in a build with any of those capabilities, one of the
// doors.
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "e2e-supervision",
    feature = "instance-key",
    feature = "message-catalog",
    feature = "replay-cache"
))]
#[cfg(not(wz_additional_apart))]
pub mod additional;
#[cfg(feature = "admin-space")]
// Totality debt TD-193 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing)]
pub mod admin_space;
#[cfg(feature = "advanced")]
pub mod advanced;
#[cfg(feature = "advanced")]
// Totality debt TD-184 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing)]
mod advanced_forms;
#[cfg(feature = "advanced")]
mod advanced_plane;
// A transport the program supplies, in place of the system's sockets: wz doors (`wz_ext.h`) of the
// unstable surface, over the links of the program's stack of whichever engine the build has.
#[cfg(feature = "app-transport")]
// Totality debt TD-185 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod app_transport;
// Totality debt TD-157 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod bytes;
// The width of pico's C enums in the structs a C program allocates, read from the target's C ABI.
pub mod c_enum;
// The conformance digest of this build (decision C15), handed out by `wz_ext_conformance_digest`:
// a wz door (`wz_ext.h`) in a build with `conformance-digest`, which the zenoh-pico preset leaves out.
#[cfg(feature = "conformance-digest")]
pub mod conformance;
// What the cooperative engine is given by the system the build runs on (the tokio engine brings
// its own runtime's).
#[cfg(not(feature = "engine-tokio"))]
mod coop_host;
pub mod revision;
// pico implements the token only with both the unstable API and the query plane: its
// `vendor/zenoh-pico/src/api/api.c` @ `_Z_OWNED_FUNCTIONS_RC_IMPL(cancellation_token)` sits
// inside `#ifdef Z_FEATURE_UNSTABLE_API` and `#if Z_FEATURE_QUERY == 1`.
#[cfg(all(feature = "unstable-api", feature = "query"))]
// Totality debt TD-179 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod cancellation;
pub mod codec;
// Totality debt TD-158 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod config;
// The policies a config states for its session, from code and from a zenoh document: wz doors
// (`wz_ext.h`) in a build with `config-policy`, which the zenoh-pico preset leaves out; without
// them the open runs a session under the build's policies and limits.
// Totality debt TD-163 (docs/c-abi-architecture.md section 7).
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
pub mod config_policy;
// What an open of a config would ask of the operating system: a wz door (`wz_ext.h`) of the
// unstable surface (docs/target-build-contract.md T9).
#[cfg(feature = "connectivity")]
// Totality debt TD-168 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod connectivity;
// The clock a program registers and the standing it reports: wz doors (`wz_ext.h`) of the unstable
// surface (the clock of the observation plane).
#[cfg(feature = "clock-source")]
pub mod clock_source;
// What the peers of a session declare and retract, told to C: wz doors (`wz_ext.h`) in a build with
// either capability that reads them (the declaration watch).
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
pub mod decl_watch;
#[cfg(feature = "unstable-api")]
// Totality debt TD-194 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod device_requires;
// End-to-end protection of an application's payload: what the sending and the receiving doors
// share, and the instance keys' and the message payloads' doors with them, in a build with any of
// the four capabilities.
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "instance-key",
    feature = "message-payload"
))]
#[cfg(not(wz_additional_apart))]
mod e2e;
// The receiving judge of end-to-end protected frames: wz doors (`wz_ext.h`) of the unstable
// surface.
#[cfg(feature = "e2e-receiver")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-195 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod e2e_receiver;
// The sending side of end-to-end protection: wz doors (`wz_ext.h`) of the unstable surface.
#[cfg(feature = "e2e-sender")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-196 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod e2e_sender;
// `wz_ext_redeclare`: tell a session's peers what it holds again.
#[cfg(feature = "unstable-api")]
pub mod redeclare;
// The node's event log, written and read from C: wz doors (`wz_ext.h`) of the unstable surface
// (the event ring of the observation plane).
// Totality debt TD-172 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod encoding;
// zenoh-pico's reading of an endpoint's text, for the cooperative engine's open and the link a
// group is reported by.
#[cfg(any(not(feature = "engine-tokio"), feature = "connectivity"))]
mod endpoint;
pub mod entity;
#[cfg(feature = "event-ring")]
pub mod event_log;
// What the doors of the additional features (end-to-end protection, reception supervision, instance
// keys, the replay cache, the message catalog) ask of the core beyond the pico ABI: wz doors
// (`wz_ext.h`) of a versioned interface, in a build with any of those capabilities. Those doors
// name the core through the pico ABI and this module only, and the core names none of them
// (`scripts/lib/layer_direction_gate.py`).
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "e2e-supervision",
    feature = "instance-key",
    feature = "message-catalog",
    feature = "replay-cache"
))]
// Totality debt TD-186 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod ext_interface;
// The node's supervisor, driven from C: wz doors (`wz_ext.h`) of the unstable surface
// (the supervision deadline of the observation plane).
// Totality debt TD-180 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
mod ffi;
#[cfg(feature = "query")]
// Totality debt TD-169 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod get;
// A get addressed to one node by its zenoh id: a wz door (`wz_ext.h`), refused while the build's
// `targeted-query` policy is off.
#[cfg(feature = "query")]
// Totality debt TD-187 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod get_to_peer;
// Totality debt TD-176 (docs/c-abi-architecture.md section 7).
#[allow(clippy::unreachable, clippy::arithmetic_side_effects)]
pub mod handlers;
// The pico internals the unstable arm's headers call from code clang emits into every program
// that includes them (`_z_pending_query_cancellation_data_clear`).
#[cfg(feature = "unstable-api")]
pub mod header_internals;
// The instance of a message a sample is, read from fields of its payload: wz doors (`wz_ext.h`)
// of the unstable surface.
#[cfg(feature = "instance-key")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-174 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod instance_key;
// The key ids every node of a deployment shares: a wz door (`wz_ext.h`) of the unstable surface
// with the capability, and in every build the open's judgement of the key-wire form.
pub mod key_ids;
// Totality debt TD-164 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod keyexpr;
mod last_timestamp;
#[cfg(any(feature = "connectivity", feature = "admin-space"))]
mod link_properties;
#[cfg(feature = "liveliness")]
pub mod liveliness;
pub mod locality;
// Totality debt TD-181 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod matching;
// A deployment's message catalog, read from one JSON5 declaration: wz doors (`wz_ext.h`) of the
// unstable surface, over the reader of `wz-app-frame`.
#[cfg(feature = "message-catalog")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-177 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod message_catalog;
// A catalog message's payload set and read field by field under the program's `.proto` files:
// wz doors (`wz_ext.h`) of the unstable surface, over the message payload of `wz-app-frame`.
#[cfg(feature = "message-payload")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-182 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod message_payload;
// The doors through which a program reserves the process pools itself and reads them: wz doors
// (`wz_ext.h`) of the unstable surface.
#[cfg(feature = "object-pool")]
// Totality debt TD-188 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod object_pool;
// Where an object a program holds outside a session is placed and let go: a slot of the process
// pools where the build has them, the heap's otherwise.
mod object_slot;
mod option_fields;
// Totality debt TD-155 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod os;
// Totality debt TD-197 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing)]
pub mod platform;
// The places of the objects a program holds that no session holds for it, reserved once for the
// process: in every library without the tokio engine, and in one with it that has their doors.
#[cfg(wz_process_pools)]
// Totality debt TD-156 (docs/c-abi-architecture.md section 7).
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod process_pool;
// One `.proto` file as a program hands it over (`wz_ext_proto_file_t`, `wz_ext.h`), for the doors
// that read a schema: the instance keys' and the message payloads'.
#[cfg(any(feature = "instance-key", feature = "message-payload"))]
#[cfg(not(wz_additional_apart))]
pub mod proto_file;
// Totality debt TD-165 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod pubsub;
pub mod qos;
#[cfg(feature = "query")]
// Totality debt TD-170 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod querier;
#[cfg(feature = "queryable")]
// Totality debt TD-183 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod query;
// The replay cache, the publisher's ring and answer and the subscriber's asking and order: wz
// doors (`wz_ext.h`) of the unstable surface, over the models of `wz-session-core`.
#[cfg(feature = "replay-cache")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-159 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod replay_publisher;
#[cfg(feature = "replay-cache")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-175 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod replay_subscriber;
#[cfg(any(feature = "query", feature = "queryable"))]
// Totality debt TD-173 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod reply_keyexpr;
pub mod result;
#[cfg(any(feature = "scout", feature = "scout-mcu"))]
// Totality debt TD-166 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod scout;
// The sending side of a declared segment profile: wz doors (`wz_ext.h`) of the unstable surface,
// over the piece writer the zenoh-c ABI's doors of the same capability write with.
#[cfg(feature = "segment-sender")]
// Totality debt TD-189 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod segment_sender;
// Totality debt TD-160 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod serde;
// Totality debt TD-167 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod session;
mod session_ext;
// The cooperative engine's session handle lies in a place of the session's arena.
#[cfg(not(feature = "engine-tokio"))]
mod session_place;
// The most memory a session holds, computed from the limits it opened under: wz doors
// (`wz_ext.h`) of the unstable surface, over the session core's rows.
#[cfg(feature = "session-memory")]
// Totality debt TD-171 (docs/c-abi-architecture.md section 7).
#[allow(clippy::expect_used, clippy::arithmetic_side_effects)]
pub mod session_memory;
#[cfg(feature = "resource-snapshot")]
pub mod snapshot;
// Reception supervision per stream: wz doors (`wz_ext.h`) of the unstable surface, over the
// supervisor of `wz-session-core`.
#[cfg(feature = "e2e-supervision")]
#[cfg(not(wz_additional_apart))]
// Totality debt TD-198 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod stream_supervision;
// Totality debt TD-190 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod string_array;
#[cfg(feature = "supervision")]
pub mod supervision;
// pico's multi-threaded arm's host surface: mutex, condvar and task.
#[cfg(feature = "multi-thread")]
// Totality debt TD-191 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod sync;
// A time base the program supplies, which the timers of a session run on in place of the system's
// clock: wz doors (`wz_ext.h`) of the unstable surface, over the time base of `wz-node-time`, for
// whichever engine the build has.
#[cfg(feature = "time-base")]
// Totality debt TD-199 (docs/c-abi-architecture.md section 7).
#[allow(clippy::arithmetic_side_effects)]
pub mod time_base;
// Totality debt TD-192 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing)]
pub mod whatami;
mod write_filter;
// Totality debt TD-161 (docs/c-abi-architecture.md section 7).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub mod zid;

// Re-export the ABI types and every exported function at the crate root so the
// Round-1 gate test (and any Rust consumer of the rlib) can reach them by a
// stable path; the `#[no_mangle]` symbols are exported for C linkage
// regardless.
pub use abi::{
    z_loaned_bytes_t, z_loaned_config_t, z_loaned_keyexpr_t, z_loaned_slice_t, z_loaned_string_t,
    z_moved_bytes_t, z_moved_config_t, z_moved_slice_t, z_moved_string_t, z_owned_bytes_t,
    z_owned_config_t, z_owned_slice_t, z_owned_string_t, z_view_keyexpr_t, z_view_string_t,
};
pub use bytes::*;
pub use config::*;
pub use encoding::*;
#[cfg(feature = "query")]
pub use get::*;
pub use keyexpr::*;
pub use pubsub::*;
pub use qos::*;
#[cfg(feature = "query")]
pub use querier::*;
#[cfg(feature = "queryable")]
pub use query::*;
#[cfg(any(feature = "query", feature = "queryable"))]
pub use reply_keyexpr::*;
pub use result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
pub use serde::*;
pub use session::*;

// Compile-time byte-compat guard: turn the "byte-match" size claims (see
// [`abi`]) into an enforced gate, so a future field/padding drift fails the
// build instead of silently diverging from zenoh-pico's LP64 layouts.
//
// Every number pinned this way in the crate is a measurement of pico's header on a 64-bit host,
// so each such block holds on a 64-bit target only. The types are `repr(C)` over pointer-sized
// words, as pico's are, and follow a 32-bit core by construction; what a 32-bit image's program
// allocates is pinned by that image against pico's own header as it compiles it
// (`csrc/pico_layout_pins.c`, which the tests of `layout_pins` below hold to these declarations),
// and a 32-bit host's the same way: the Windows package's test compiles that file against the
// package's own headers with the compiler of each width it ships
// (`scripts/lib/pico_windows_package.py`).
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::size_of;
    assert!(size_of::<session::z_owned_session_t>() == 16);
    assert!(size_of::<session::z_loaned_session_t>() == 16);
    assert!(size_of::<abi::z_owned_config_t>() == 32);
    assert!(size_of::<abi::z_owned_bytes_t>() == 32);
    assert!(size_of::<abi::z_owned_slice_t>() == 32);
    assert!(size_of::<abi::z_owned_string_t>() == 32);
    assert!(size_of::<abi::z_view_keyexpr_t>() == 48);
    assert!(size_of::<abi::z_view_string_t>() == 32);
    assert!(size_of::<pubsub::z_owned_closure_sample_t>() == 24);
};

// The answering end of a query. The closure families share `{ context, call, drop }`
// (`~/zenoh-pico/include/zenoh-pico/api/types.h:730-750`), so 24 B like
// closure_sample; `z_queryable_options_t` is `{ bool complete; }` in a
// default pico build (`Z_FEATURE_LOCAL_QUERYABLE` = 0) and gains a 4-byte
// `allowed_origin` with the switch.
#[cfg(all(feature = "queryable", target_pointer_width = "64"))]
const _: () = {
    use core::mem::size_of;
    assert!(size_of::<query::z_owned_closure_query_t>() == 24);
    assert!(
        size_of::<query::z_queryable_options_t>()
            == if cfg!(feature = "local-queryable") {
                8
            } else {
                1
            }
    );
    assert!(size_of::<query::z_query_reply_err_options_t>() == 8);
    // The two whose layout is `Z_FEATURE_UNSTABLE_API`-conditional (a trailing
    // `z_source_info_t *source_info`, `api/types.h:334-336,359-361`) — so the
    // two most likely to drift.
    //
    // R311y562 — these were pinned at the flag-OFF layout (40 / 32) on the
    // reasoning that "the flag defaults OFF (`CMakeLists.txt:316` = 0)". That
    // reads the DEFAULT off the cmake source instead of the GENERATED config
    // the reference build actually produced, which is the R311y466 trap named
    // in `pubsub::z_put_options_t`'s own doc — and this file fell into it while
    // the file next door avoided it. `scripts/build-zenoh-pico-cli.sh:454,512`
    // configures the reference pico with `-DZ_FEATURE_UNSTABLE_API=ON`, and
    // `target/zenoh-pico-build/zenohpico/include/zenoh-pico/config.h` carries a
    // bare `#define Z_FEATURE_UNSTABLE_API` to prove it. So the drop-in's
    // programs compile against the flag-ON layout, which is what the put plane
    // (`z_put_options_t` = 56 B, with its `reliability` + `source_info` tail)
    // has modelled all along — the crate was pinning two different pico builds
    // at once, and only the reply half was pinned to the one nobody links.
    //
    // Measured against that header (`-DZENOH_LINUX -DZ_FEATURE_UNSTABLE_API`):
    // reply 48, reply_del 40 — each 8 B larger than the old pin, the trailing
    // `z_source_info_t*`. Both builds exist now: with `unstable-api` the
    // reference layout, without it upstream's default one (40 / 32), each the
    // layout of the header a program of that arm compiles against.
    if cfg!(feature = "unstable-api") {
        assert!(size_of::<query::z_query_reply_options_t>() == 48);
        assert!(size_of::<query::z_query_reply_del_options_t>() == 40);
    } else {
        assert!(size_of::<query::z_query_reply_options_t>() == 40);
        assert!(size_of::<query::z_query_reply_del_options_t>() == 32);
    }
};

// The requesting end of a query.
#[cfg(all(feature = "query", target_pointer_width = "64"))]
const _: () = {
    use core::mem::size_of;
    // R3b get plane. `z_owned_closure_reply_t` is the same
    // `{ context, call, drop }` shape (`api/types.h:745-749`).
    assert!(size_of::<get::z_owned_closure_reply_t>() == 24);
    // `z_query_consolidation_t` wraps the mode enum in a struct
    // (`api/types.h:215-217`), so it is one `int`, not a bare enum.
    assert!(size_of::<get::z_query_consolidation_t>() == 4);
    // `z_get_options_t` (`api/types.h:479-497`) as the REFERENCE build declares
    // it — the layout most exposed to drift, because three of its fields are
    // feature-conditional: `allowed_destination` needs Z_FEATURE_LOCAL_QUERYABLE
    // (0 in the generated config, so ABSENT), `source_info` +
    // `cancellation_token` need Z_FEATURE_UNSTABLE_API (DEFINED there, so
    // PRESENT). LP64:
    //   payload@0 8 | encoding@8 8 | consolidation@16 4 | congestion@20 4 |
    //   priority@24 4 | is_express@28 1 (+3 pad) | target@32 4 (+4 pad) |
    //   timeout_ms@40 8 | attachment@48 8 | source_info@56 8 |
    //   cancellation_token@64 8 | accept_replies@72 4 (+4 tail pad) = 80.
    //
    // R311y562 — this pinned 64 (the unstable-OFF layout) and was wrong in a way
    // a size check alone cannot express: the two unstable fields sit BEFORE
    // `accept_replies`, so omitting them displaced that field from offset 72 to
    // 56 and wz read a caller's reply-keyexpr policy out of the low half of the
    // `source_info` pointer. See `get::z_get_options_t`. Without `unstable-api`
    // the pair is absent, as in upstream's default header: 64.
    assert!(
        size_of::<get::z_get_options_t>()
            == if cfg!(feature = "unstable-api") {
                80
            } else {
                64
            }
    );
    assert!(core::mem::align_of::<get::z_get_options_t>() == 8);
};

// The pins a 32-bit image compiles against pico's header (`csrc/pico_layout_pins.c`), held to the
// declarations they name: each count of words is the Rust type's size in words on this host, which
// is the same count on any word size because the types are `repr(C)` over words. The file pins
// types of both ends of a query, so the build that reads it back has both.
#[cfg(all(test, feature = "queryable", feature = "query"))]
mod layout_pins {
    use crate::prelude::Vec;
    use core::mem::{offset_of, size_of};

    const PINS: &str = include_str!("../csrc/pico_layout_pins.c");
    const WORD: usize = size_of::<*const ()>();

    /// The Rust type's size, by the C name a pin gives it.
    fn rust_bytes(name: &str) -> Option<usize> {
        Some(match name {
            "z_owned_session_t" => size_of::<crate::session::z_owned_session_t>(),
            "z_owned_config_t" => size_of::<crate::abi::z_owned_config_t>(),
            "z_owned_bytes_t" => size_of::<crate::abi::z_owned_bytes_t>(),
            "z_owned_string_t" => size_of::<crate::abi::z_owned_string_t>(),
            "z_view_keyexpr_t" => size_of::<crate::abi::z_view_keyexpr_t>(),
            "z_view_string_t" => size_of::<crate::abi::z_view_string_t>(),
            "z_owned_encoding_t" => size_of::<crate::encoding::z_owned_encoding_t>(),
            "z_owned_closure_query_t" => size_of::<crate::query::z_owned_closure_query_t>(),
            "z_owned_queryable_t" => size_of::<crate::query::z_owned_queryable_t>(),
            "z_owned_querier_t" => size_of::<crate::querier::z_owned_querier_t>(),
            _ => return None,
        })
    }

    /// The `(type, argument)` of every line of the file that opens with `pin`.
    fn pins(pin: &str) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        PINS.lines().filter_map(move |line| {
            let rest = line.trim().strip_prefix(pin)?.strip_suffix(");")?;
            Some(rest.split_once(',').unwrap_or((rest, "")))
        })
    }

    #[test]
    fn every_pinned_count_is_the_rust_declarations_size_in_words() {
        let mut checked = 0;
        for (name, words) in pins("WZ_PIN_WORDS(") {
            let words: usize = words.trim().parse().expect("a pin states a count of words");
            let bytes = rust_bytes(name.trim()).unwrap_or_else(|| panic!("{name} names no type"));
            assert_eq!(bytes % WORD, 0, "{name} is a whole number of words");
            assert_eq!(bytes / WORD, words, "{name}");
            checked += 1;
        }
        assert_eq!(checked, 10, "every pin of the file was read");
    }

    #[test]
    fn an_element_pinned_by_its_handle_holds_the_handle_first() {
        let named: Vec<&str> = pins("WZ_PIN_HANDLE(").map(|(name, _)| name).collect();
        assert_eq!(named, ["z_owned_sample_t", "z_owned_query_t"]);
        assert_eq!(offset_of!(crate::pubsub::z_owned_sample_t, handle), 0);
        assert_eq!(offset_of!(crate::query::z_owned_query_t, handle), 0);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn an_element_block_is_picos_measured_size_on_a_64_bit_host() {
        assert_eq!(crate::abi::element_bytes(224), 224);
        assert_eq!(size_of::<crate::pubsub::z_owned_sample_t>(), 224);
        assert_eq!(size_of::<crate::query::z_owned_query_t>(), 16);
    }
}

// The additional library's view of this core (`wz-capi-pico-ext/src/core_view.rs`), held to the
// core's own declarations: the layout of each type it allocates or reads, the value of each
// constant and the signature of each function it imports.
#[cfg(all(
    test,
    any(
        feature = "e2e-sender",
        feature = "e2e-receiver",
        feature = "e2e-supervision",
        feature = "instance-key",
        feature = "message-catalog",
        feature = "replay-cache"
    )
))]
mod additional_view_tests;
