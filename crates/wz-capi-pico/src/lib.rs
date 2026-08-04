// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

pub mod abi;
pub mod bytes;
pub mod codec;
pub mod config;
pub mod encoding;
mod ffi;
pub mod get;
pub mod keyexpr;
pub mod liveliness;
pub mod matching;
pub mod platform;
pub mod pubsub;
pub mod querier;
pub mod query;
pub mod result;
pub mod serde;
pub mod session;
pub mod sync;
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
pub use get::*;
pub use keyexpr::*;
pub use pubsub::*;
pub use querier::*;
pub use query::*;
pub use result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
pub use serde::*;
pub use session::*;

// Compile-time byte-compat guard: turn the "byte-match" size claims (see
// [`abi`]) into an enforced gate, so a future field/padding drift fails the
// build instead of silently diverging from zenoh-pico's LP64 layouts.
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
    // R3 query plane. The closure families share `{ context, call, drop }`
    // (`~/zenoh-pico/include/zenoh-pico/api/types.h:730-750`), so 24 B like
    // closure_sample; `z_queryable_options_t` is `{ bool complete; }` in a
    // default pico build (`Z_FEATURE_LOCAL_QUERYABLE` = 0, CMakeLists.txt:353).
    assert!(size_of::<query::z_owned_closure_query_t>() == 24);
    assert!(size_of::<query::z_queryable_options_t>() == 1);
    assert!(size_of::<query::z_query_reply_err_options_t>() == 8);
    // The two whose layout is `Z_FEATURE_UNSTABLE_API`-conditional (a trailing
    // `z_source_info_t *source_info`, `api/types.h:334-336,359-361`) — so the
    // two most likely to drift. The flag defaults OFF (`#cmakedefine` +
    // `CMakeLists.txt:316` = 0), which is the layout pinned here.
    assert!(size_of::<query::z_query_reply_options_t>() == 40);
    assert!(size_of::<query::z_query_reply_del_options_t>() == 32);
    // R3b get plane. `z_owned_closure_reply_t` is the same
    // `{ context, call, drop }` shape (`api/types.h:745-749`).
    assert!(size_of::<get::z_owned_closure_reply_t>() == 24);
    // `z_query_consolidation_t` wraps the mode enum in a struct
    // (`api/types.h:215-217`), so it is one `int`, not a bare enum.
    assert!(size_of::<get::z_query_consolidation_t>() == 4);
    // `z_get_options_t` (`api/types.h:479-497`) in a DEFAULT build — the layout
    // most exposed to drift, because THREE of its fields are feature-gated out:
    // `allowed_destination` needs Z_FEATURE_LOCAL_QUERYABLE (=0,
    // CMakeLists.txt:353), `source_info` + `cancellation_token` need
    // Z_FEATURE_UNSTABLE_API (=0, CMakeLists.txt:316). LP64:
    //   payload@0 8 | encoding@8 8 | consolidation@16 4 | congestion@20 4 |
    //   priority@24 4 | is_express@28 1 (+3 pad) | target@32 4 (+4 pad) |
    //   timeout_ms@40 8 | attachment@48 8 | accept_replies@56 4 (+4 tail pad)
    //   = 64.
    assert!(size_of::<get::z_get_options_t>() == 64);
    assert!(core::mem::align_of::<get::z_get_options_t>() == 8);
};
