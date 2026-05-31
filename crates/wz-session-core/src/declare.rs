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
//! R311ds — the wider behavioural `#[cfg(test)] mod tests` blocks
//! (callback fan-out value capture, mixed-message dispatch) plus
//! `cross_tests.rs` migrated here from the wz-runtime-tokio shells,
//! next to the registry code they exercise. The `Arc<Mutex<…>>`
//! capture cells use `std` under `#[cfg(test)]` (see the crate-root
//! `extern crate std`, mirroring the wz-codecs sibling-crate
//! convention); the production artifact stays strictly no_std. This
//! closes the R311dm carry that had stranded these tests in the AP
//! shell on a since-revised "no std even in cfg(test)" rationale.

#[cfg(feature = "codec-declare")]
pub mod liveliness;

#[cfg(feature = "codec-declare")]
pub mod subscriber;

#[cfg(feature = "codec-declare")]
pub mod queryable;

// R311ek — the pure-data liveliness sample types (`LivelinessSample` /
// `LivelinessSampleKind` / `LivelinessSampleCallback`) split out of the
// `codec-declare`-gated `liveliness_subscriber` module so the
// codec-agnostic callback surface composes in any subset; only the
// `DeclareOwnedVariant`-consuming `LivelinessSubscriberRegistry` stays
// `codec-declare`-gated below. Alloc-only (the callback is a `Box`).
#[cfg(feature = "alloc")]
pub mod liveliness_sample;

#[cfg(feature = "codec-declare")]
pub mod liveliness_subscriber;

// R283 — DECLARER-side registry of wz's own held LivelinessTokens + the
// inbound-Interest responder. Gated on `liveliness-token` (the declarer
// feature, which implies `codec-declare`) rather than bare
// `codec-declare`: a build that decodes peer declares but never declares
// its OWN tokens has no local-token state to reply with.
#[cfg(feature = "liveliness-token")]
pub mod local_token;

// R311ds — cross-registry composability tests (R311dr-wider-tests
// carry closure). Gated on `codec-declare` as well as `test` because
// it references all three registries, which compile only under
// `codec-declare`; the per-registry behavioural tests live inside
// each `declare/*.rs` `#[cfg(test)] mod tests` and inherit the
// module's own `codec-declare` gate.
#[cfg(all(test, feature = "codec-declare"))]
mod cross_tests;
