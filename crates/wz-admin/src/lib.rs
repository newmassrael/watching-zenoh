// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin space of a node (§5.23), the wz mirror of zenoh's admin space: the
//! `@/<zid>/<whatami>/**` keys a host reads a node's state from and writes its config through.
//!
//! The modules arrived from `wz-session-core` in the server-layer split (steps 6 and 7):
//! - `adminspace` (under `adminspace-fixed`): the `local_data` view, the key helpers and every
//!   admin leg, written into any text sink so a node with no allocator answers the same bytes;
//! - `admin_reply` (under `adminspace-fixed`): the buffers an admin reply is built in and what
//!   refusing one means;
//! - `admin_config_space` (under `adminspace-fixed` or `adminspace-write`): which sub-key a
//!   config write names, the membership both write decoders run;
//! - `admin_connect` (under `adminspace-write`): a PUT or DEL on
//!   `@/<zid>/<whatami>/config/connect/endpoints`, decided with no allocator.
//!
//! A module keeps the name it had in the core, so a downstream path changes only its crate and a
//! citation of the file still names one file. This crate is built on the core and the core never
//! names it (`scripts/lib/layer_direction_gate.py`).

#![no_std]

// The heap forms of the admin space link the allocator the core's `alloc` links; a build without
// `alloc` (the slot profile's fixed admin space, the MCU's config write) links none, and a
// `String` named by code that build compiles is refused by the compiler.
#[cfg(feature = "alloc")]
extern crate alloc;

// The tests format their payloads and collect what they read; the crate itself links no `std`,
// as the modules did in the core, which linked `std` for its tests the same way.
#[cfg(test)]
extern crate std;

/// §5.23 — admin space `local_data` view: the `@/<zid>/<whatami>/**` built-in
/// queryable keyexpr helpers + the `local_data` JSON body, the wz mirror of
/// zenoh `net/runtime/adminspace.rs`. Pure data-view (the queryable wiring lives
/// in wz-runtime-tokio); no_std, and `alloc` only for the heap forms.
#[cfg(feature = "adminspace-fixed")]
pub mod adminspace;

/// Fixed-memory step S9b — the buffers an admin reply is built in
/// ([`admin_reply::AdminBuffer`]: a `String` that grows, or a fixed buffer that
/// refuses what does not fit), the typed refusal ([`admin_reply::AdminReplyError`])
/// and its counters, and the per-process arena a node with no allocator answers
/// from ([`admin_reply::AdminReplyArena`]).
#[cfg(feature = "adminspace-fixed")]
pub mod admin_reply;

/// R2824 (§5.23) — which sub-key a config write names in a node's config
/// space, with no allocator: the membership gates the AP decoder
/// (`adminspace`) and the MCU decoder (`admin_connect`) both run.
#[cfg(any(feature = "adminspace-fixed", feature = "adminspace-write"))]
pub mod admin_config_space;

// R2824 (§5.23 `adminspace-write`) — upstream's config-WRITE surface for `connect/endpoints`,
// with no allocator, so an MCU can be told at runtime which peers to hold a session with. The
// AP half of the same surface is `adminspace`'s, which needs a heap throughout.
#[cfg(feature = "adminspace-write")]
pub mod admin_connect;
