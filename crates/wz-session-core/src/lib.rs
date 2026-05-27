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
