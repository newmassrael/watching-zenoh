// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! # wz-capi-pico — §5.27 api-compat-pico, Round 1
//!
//! A zenoh-pico-compatible C ABI (`z_*` / `zp_*` `#[no_mangle] extern "C"`
//! symbols) wrapping the wz AP `wz::runtime_tokio` `Session`, so a zenoh-pico
//! C program can link the wz cdylib as a binary drop-in. This is the reverse
//! of the `*-sys` crates (which bind TO a C library); this crate EXPORTS one.
//!
//! The binary-drop-in design is sound: pico defines the owned-type operations
//! as EXTERN symbols in `api.c` (not `static inline`), so these `#[no_mangle]`
//! exports replace them at link time, and idiomatic pico code touches the
//! owned structs only through those ops. Round 1 VALIDATES the ABI end-to-end
//! wz-to-wz over loopback TCP (see `tests/pubsub_roundtrip.rs`); interop
//! against a separately-compiled zenoh-pico binary is deferred to a cc
//! round-trip test (a follow-up round).
//!
//! ## Round 1 surface
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
pub mod config;
mod ffi;
pub mod keyexpr;
pub mod pubsub;
pub mod result;
pub mod session;

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
pub use keyexpr::*;
pub use pubsub::*;
pub use result::{ZResult, Z_ERR_GENERIC, Z_ERR_INVALID, Z_ERR_NULL, Z_OK};
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
};
