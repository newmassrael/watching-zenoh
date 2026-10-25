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
//! The crate reads no clock, spawns nothing and holds no socket. A rule that needs "now" takes it
//! as an argument. The design, and the steps that move the rest of the mechanism here, are in
//! `docs/advanced-pubsub-on-a-neutral-core.md`.

pub mod advanced_cache;
pub mod advanced_ke;
pub mod advanced_publisher;
pub mod time_range;
