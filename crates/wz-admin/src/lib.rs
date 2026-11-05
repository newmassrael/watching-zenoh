// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin space of a node (§5.23), the wz mirror of zenoh's admin space: the
//! `@/<zid>/<whatami>/**` keys a host reads a node's state from and writes its config through.
//!
//! The modules arrive from `wz-session-core` one landable step at a time (server-layer split,
//! steps 6-8). Today this crate holds the config-WRITE surface an MCU can carry,
//! `admin_connect` (under `adminspace-write`): a PUT or DEL on
//! `@/<zid>/<whatami>/config/connect/endpoints`, decided with no allocator. The read side
//! (`adminspace`, `admin_reply`) and the config-space membership both decoders share
//! (`admin_config_space`) are still the core's.
//!
//! A module keeps the name it had in the core, so a downstream path changes only its crate and a
//! citation of the file still names one file. This crate is built on the core and the core never
//! names it (`scripts/lib/layer_direction_gate.py`).

#![no_std]

// The tests format their payloads and collect what they read; the crate itself links no
// allocator, as the module did in the core, which linked `std` for its tests the same way.
#[cfg(test)]
extern crate std;

// R2824 (§5.23 `adminspace-write`) — upstream's config-WRITE surface for `connect/endpoints`,
// with no allocator, so an MCU can be told at runtime which peers to hold a session with. The
// AP half of the same surface is the core's `adminspace`, which needs a heap throughout.
#[cfg(feature = "adminspace-write")]
pub mod admin_connect;
