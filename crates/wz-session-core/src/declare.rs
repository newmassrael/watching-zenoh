// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311di-14+ — application-layer remote-declaration registries.
//!
//! Mirrors the wz-runtime-tokio `declare/` module shape but lifted
//! into wz-session-core so MCU profiles can compose the registries
//! without inheriting tokio / std. Each registry holds peer-side
//! decoded `Declare(*)` callback lists and provides
//! `dispatch_declare` / `dispatch_messages` /
//! `dispatch_iteration_event` entry points that route an inbound
//! `NetworkMessage` batch into the registered callbacks.
//!
//! The four registries (one per zenoh-pico sub-type cluster) migrate
//! across separate R311di sub-rounds in size order:
//!
//! | Round    | Registry                              | Source file LOC |
//! |----------|---------------------------------------|-----------------|
//! | R311di-14 | [`liveliness::LivelinessRegistry`]    | 281             |
//! | R311di-15 | (subscriber, planned)                | 558             |
//! | R311di-16 | (queryable, planned)                 | 489             |
//! | R311di-17 | (liveliness_subscriber, planned)     | 694             |
//!
//! R311dr-sibling — test fixture builders moved to the dedicated
//! sibling crate `wz-session-core-test-support` (R71 pattern). The
//! intermediate R311dr `#[cfg(feature = "test-helpers")] pub mod
//! test_helpers;` shape reintroduced the production-crate-feature-flag
//! anti-pattern R71 already ratified out; relocating to a sibling
//! crate restores mechanical isolation so wz-session-core production
//! builds carry zero test-only code paths.
//!
//! `cross_tests.rs` plus the wider behavioural `#[cfg(test)] mod
//! tests` blocks remain in wz-runtime-tokio because they exercise
//! AP-bound Tokio sync primitives (`crate::sync::Mutex` +
//! `std::sync::Arc`) that the no_std + alloc footing here does not
//! provide (R311dm carry preserved).

#[cfg(feature = "codec-declare")]
pub mod liveliness;

#[cfg(feature = "codec-declare")]
pub mod subscriber;

#[cfg(feature = "codec-declare")]
pub mod queryable;

#[cfg(feature = "codec-declare")]
pub mod liveliness_subscriber;
