// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's time (§5.18), with no runtime in it.
//!
//! * `timestamp_source` (with `std` or `host-sync`): the wall clock as an NTP64 word, its
//!   plain-milliseconds sibling, the process's
//!   [`EpochSource`](wz_session_core::epoch::EpochSource), and the fallback stamper an
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

// A test executable links `std` whatever the build, so a test may read the environment.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

// The node's HLC reads the wall clock and keeps its standing under a lock: `std`'s, or without it
// the host's own (`wz-host-sync`). A build with neither has no clock, and is the crate's core: the
// per-role switch and a node that holds no clock, which is the node of a build without `time-hlc`.
#[cfg(all(feature = "time-hlc", not(any(feature = "std", feature = "host-sync"))))]
compile_error!(
    "wz-node-time: `time-hlc` reads the wall clock and takes a lock: name `std`, or `host-sync` \
     for a build without it"
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
// The wall clock, which a build reads through `std` or the host's own calls.
#[cfg(any(feature = "std", feature = "host-sync"))]
pub mod timestamp_source;
