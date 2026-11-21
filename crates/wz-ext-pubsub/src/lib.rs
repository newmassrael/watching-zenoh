// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rules of the advanced publisher and subscriber (atom 5.25), with no runtime in them.
//!
//! zenoh-ext's advanced pub/sub is an extension protocol over zenoh's own publish, subscribe,
//! query and liveliness. What it decides (which key a publisher announces itself on, which
//! samples a cache replies to a recovery query, how a `_time` selector is read) does not depend on
//! a runtime, so it is written here once and each engine hosts it: the tokio runtime through
//! `wz-runtime-tokio`, which re-exports these modules at the paths it has always had, and the
//! cooperative engine behind the pico C ABI.
//!
//! Without `std` it is `no_std` with `alloc`, for the pico C ABI's host library without `std`: its
//! locks are the host's own (`host-sync`), and a wall-clock instant is an [`time_range::EpochTime`].
//! A build with neither `std` nor `host-sync` has no lock, and is the crate's grammars alone: the
//! `@adv` keys and the `_time` selector. The cache, the publisher and the subscriber hold their
//! state under a lock, so they need one of the two.
//!
//! The crate reads no clock, spawns nothing and holds no socket. A rule that needs "now" takes it
//! as an argument. The design, and the steps that move the rest of the mechanism here, are in
//! `docs/advanced-pubsub-on-a-neutral-core.md`.

// A test executable links `std` whatever the build, so a test may read `std`'s clock beside the
// build's own.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

// The publisher and the subscriber hold their state under a lock: `std`'s, or without it the host's
// own (`wz-host-sync`). A build with neither has none to give them.
#[cfg(all(
    not(any(feature = "std", feature = "host-sync")),
    any(feature = "advanced-publisher", feature = "advanced-subscriber")
))]
compile_error!(
    "wz-ext-pubsub: the advanced publisher and subscriber take a lock: name `std`, or `host-sync` \
     for a build without it"
);

/// What `std`'s prelude gives a module and `core`'s does not. Each module takes it whole, as it
/// takes a prelude, so an item no module of one build names is not an unused import.
#[allow(unused_imports)]
mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::format;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec;
    pub(crate) use alloc::vec::Vec;
}

#[cfg(any(feature = "std", feature = "host-sync"))]
mod sync;

#[cfg(any(feature = "std", feature = "host-sync"))]
pub mod advanced_cache;
pub mod advanced_ke;
#[cfg(feature = "advanced-publisher")]
pub mod advanced_publisher;
#[cfg(feature = "advanced-subscriber")]
pub mod advanced_subscriber;
pub mod time_range;
