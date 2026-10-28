// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's time (§5.18), with no runtime in it.
//!
//! * `timestamp_source`: the wall clock as an NTP64 word, its plain-milliseconds sibling, the
//!   process's [`EpochSource`](wz_session_core::epoch::EpochSource), and the fallback stamper an
//!   auto-stamping consumer borrows the node clock through.
//! * `node_clock`: the node-scoped Hybrid Logical Clock, the per-role switch that decides whether
//!   a node has one, and the forward-path stamp.
//! * `clock_registry` (with `clock-source`): the clock sources an application registers, which the
//!   node clock reads instead of the system clock.
//!
//! The tokio runtime re-exports both modules at the paths it has always had, and the cooperative
//! engine hosts the same ones (`docs/advanced-pubsub-on-a-neutral-core.md`).

#[cfg(feature = "clock-source")]
pub mod clock_registry;
#[cfg(feature = "event-ring")]
pub mod event_log;
pub mod node_clock;
#[cfg(feature = "time-hlc")]
pub mod standing_cell;
pub mod timestamp_source;
