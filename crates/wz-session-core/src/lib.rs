// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-session-core — runtime-agnostic Session + SessionLinkActions
//! + helper surface.
//!
//! R311di-1 lands the empty crate skeleton; the production surface
//! moves in incrementally from `wz-runtime-tokio::{session,
//! session_glue, observer, declare, pubsub, query, reply, sample,
//! locality, keyexpr_canon}` over subsequent sub-rounds (R311di-2+).
//! See `crates/wz-session-core/Cargo.toml` for the per-crate
//! rationale and the `wz-runtime-tokio` retained boundary (Lua
//! bindings + `SessionLinkActions::new` concrete TokioRuntime
//! constructor stay in the AP crate).

#![no_std]
#![cfg_attr(not(feature = "alloc"), allow(unused_extern_crates))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod keyexpr_canon;

/// R223 — zenoh-style locality filter (no_std + no_alloc; pure enum + helpers).
/// Mirrors zenoh-pico's `z_locality_t` and `_z_locality_allows_{local,remote}`.
/// Available unconditionally because the type carries no allocations.
pub mod locality;

/// Reliability hint shared by LinkDriver outbound + Sample inbound.
/// no_std + no_alloc clean (pure enum + helper); unconditional.
pub mod reliability;

/// R222 / R225 — application-layer `Sample` type for subscriber callbacks.
/// Mirrors zenoh-pico's `_z_sample_t` projection. Carries alloc-bound
/// fields (Vec<u8> payload, String keyexpr) so gated on the `alloc`
/// feature. Re-exported from wz-runtime-tokio for `crate::sample::*`
/// callsite compatibility.
#[cfg(feature = "alloc")]
pub mod sample;
