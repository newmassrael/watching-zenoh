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
//! * `time_base` (with `time-base`): the time base a program supplies, which the timers of a
//!   session run on in place of the system's monotonic clock.
//!
//! The tokio runtime re-exports both modules at the paths it has always had, and the cooperative
//! engine hosts the same ones (`docs/advanced-pubsub-on-a-neutral-core.md`).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Without `std` the node's wall clock and the lock its clock's standing is under are the host's own
// (`wz-host-sync`); a build with neither has no clock to read.
#[cfg(not(any(feature = "std", feature = "host-sync")))]
compile_error!(
    "wz-node-time: a build without `std` reads the wall clock and takes its lock through the host's \
     own calls: name `host-sync`"
);

#[cfg(feature = "clock-source")]
pub mod clock_registry;
#[cfg(feature = "event-ring")]
pub mod event_log;
pub mod node_clock;
#[cfg(feature = "time-hlc")]
pub mod standing_cell;
#[cfg(feature = "time-base")]
pub mod time_base;
pub mod timestamp_source;
