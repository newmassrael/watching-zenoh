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

// A session runs on an engine (`docs/capi-pico-on-coop-engine.md`, decision D4), so a build
// that names neither has no `z_open` to give; it is refused here, by name, rather than by the
// unresolved crates of the engine the open would have reached.
#[cfg(not(any(
    feature = "engine-tokio",
    feature = "engine-coop",
    feature = "os-zephyr"
)))]
compile_error!(
    "wz-capi-pico: a build needs an engine to run its sessions: `engine-tokio` for the session \
     on its own thread and runtime, `engine-coop` for the one the program steps, `os-zephyr` for \
     that one in a Zephyr image"
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

pub mod abi;
#[cfg(feature = "admin-space")]
pub mod admin_space;
#[cfg(feature = "advanced")]
pub mod advanced;
#[cfg(feature = "advanced")]
mod advanced_forms;
#[cfg(feature = "advanced")]
mod advanced_plane;
// A transport the program supplies, in place of the system's sockets: wz doors (`wz_ext.h`) of the
// unstable surface, over the links of the program's stack of whichever engine the build has.
#[cfg(feature = "app-transport")]
pub mod app_transport;
pub mod bytes;
// The conformance digest of this build (decision C15), handed out by `wz_ext_conformance_digest`.
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
pub mod cancellation;
pub mod codec;
pub mod config;
// The policies a config states for its session, from code and from a zenoh document: wz doors
// (`wz_ext.h`) in every build.
pub mod config_policy;
// What an open of a config would ask of the operating system: a wz door (`wz_ext.h`) of the
// unstable surface (docs/target-build-contract.md T9).
#[cfg(feature = "connectivity")]
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
pub mod device_requires;
// End-to-end protection of an application's payload: what the sending and the receiving doors
// share, and the instance keys' doors with them, in a build with any of the three capabilities.
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "instance-key"
))]
mod e2e;
// The receiving judge of end-to-end protected frames: wz doors (`wz_ext.h`) of the unstable
// surface.
#[cfg(feature = "e2e-receiver")]
pub mod e2e_receiver;
// The sending side of end-to-end protection: wz doors (`wz_ext.h`) of the unstable surface.
#[cfg(feature = "e2e-sender")]
pub mod e2e_sender;
// `wz_ext_redeclare`: tell a session's peers what it holds again.
#[cfg(feature = "unstable-api")]
pub mod redeclare;
// The node's event log, written and read from C: wz doors (`wz_ext.h`) of the unstable surface
// (the event ring of the observation plane).
pub mod encoding;
pub mod entity;
#[cfg(feature = "event-ring")]
pub mod event_log;
// The node's supervisor, driven from C: wz doors (`wz_ext.h`) of the unstable surface
// (the supervision deadline of the observation plane).
mod ffi;
#[cfg(feature = "query")]
pub mod get;
// A get addressed to one node by its zenoh id: a wz door (`wz_ext.h`), refused while the build's
// `targeted-query` policy is off.
#[cfg(feature = "query")]
pub mod get_to_peer;
pub mod handlers;
// The pico internals the unstable arm's headers call from code clang emits into every program
// that includes them (`_z_pending_query_cancellation_data_clear`).
#[cfg(feature = "unstable-api")]
pub mod header_internals;
// The instance of a message a sample is, read from fields of its payload: wz doors (`wz_ext.h`)
// of the unstable surface.
#[cfg(feature = "instance-key")]
pub mod instance_key;
// The key ids every node of a deployment shares: a wz door (`wz_ext.h`) of the unstable surface
// with the capability, and in every build the open's judgement of the key-wire form.
pub mod key_ids;
pub mod keyexpr;
mod last_timestamp;
#[cfg(any(feature = "connectivity", feature = "admin-space"))]
mod link_properties;
#[cfg(feature = "liveliness")]
pub mod liveliness;
pub mod locality;
pub mod matching;
// A deployment's message catalog, read from one JSON5 declaration: wz doors (`wz_ext.h`) of the
// unstable surface, over the reader of `wz-app-frame`.
#[cfg(feature = "message-catalog")]
pub mod message_catalog;
mod option_fields;
mod os;
pub mod platform;
pub mod pubsub;
pub mod qos;
#[cfg(feature = "query")]
pub mod querier;
#[cfg(feature = "queryable")]
pub mod query;
// The replay cache, the publisher's ring and answer and the subscriber's asking and order: wz
// doors (`wz_ext.h`) of the unstable surface, over the models of `wz-session-core`.
#[cfg(feature = "replay-cache")]
pub mod replay_publisher;
#[cfg(feature = "replay-cache")]
pub mod replay_subscriber;
#[cfg(any(feature = "query", feature = "queryable"))]
pub mod reply_keyexpr;
pub mod result;
#[cfg(any(feature = "scout", feature = "scout-mcu"))]
pub mod scout;
// The sending side of a declared segment profile: wz doors (`wz_ext.h`) of the unstable surface,
// over the piece writer the zenoh-c ABI's doors of the same capability write with.
#[cfg(feature = "segment-sender")]
pub mod segment_sender;
pub mod serde;
pub mod session;
mod session_ext;
#[cfg(feature = "resource-snapshot")]
pub mod snapshot;
// Reception supervision per stream: wz doors (`wz_ext.h`) of the unstable surface, over the
// supervisor of `wz-session-core`.
#[cfg(feature = "e2e-supervision")]
pub mod stream_supervision;
pub mod string_array;
#[cfg(feature = "supervision")]
pub mod supervision;
// pico's multi-threaded arm's host surface: mutex, condvar and task.
#[cfg(feature = "multi-thread")]
pub mod sync;
pub mod whatami;
mod write_filter;
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
// (`csrc/pico_layout_pins.c`, which the tests of `layout_pins` below hold to these declarations).
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
// is the same count on any word size because the types are `repr(C)` over words.
#[cfg(all(test, feature = "queryable"))]
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
        assert_eq!(checked, 9, "every pin of the file was read");
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
