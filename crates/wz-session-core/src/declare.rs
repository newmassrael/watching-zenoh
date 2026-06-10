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

// R311gb (Track 2) — un-gated from `codec-declare`: each registry's
// observer-list control plane + no-heap fire (`dispatch_declared_borrowed`
// / `dispatch_undeclared`) compiles on the MCU no-heap profile; the owned
// `Declare`-consuming wire dispatch + peer-`declared` membership table
// inside gate on `all(codec-declare, alloc)` / `alloc` per-method.
pub mod liveliness;

pub mod subscriber;

pub mod queryable;

// R311ek — the pure-data liveliness sample types (`LivelinessSample` /
// `LivelinessSampleKind` / `LivelinessSampleSink`) are codec-agnostic.
// R311gb (Track 2) — un-gated from `alloc`: the sample view + sink trait
// compile on the MCU no-heap profile; only `BoxedLivelinessSampleSink`
// (the heap closure adapter) stays `alloc`-gated inside the module.
pub mod liveliness_sample;

// R311gb (Track 2) — un-gated from `codec-declare` / `alloc`: the slot
// table control plane + no-heap fire compile on the MCU no-heap profile;
// the owned `Declare`-consuming wire dispatch + the `peer_token_table`
// stay `all(codec-declare, alloc)` / `alloc`-gated per-method.
pub mod liveliness_subscriber;

// R283 — DECLARER-side registry of wz's own held LivelinessTokens + the
// inbound-Interest responder. Gated on `liveliness-token` (the declarer
// feature, which implies `codec-declare`) rather than bare
// `codec-declare`: a build that decodes peer declares but never declares
// its OWN tokens has no local-token state to reply with.
// R311hn (Track 2, Decision 2 no-heap emit) — un-gated from `alloc`: the
// bounded token table + the borrowed no-heap response staging
// (`respond_to_interest_borrowed` -> `DeclResponseItem`) compile on the
// MCU no-heap profile; only the owned `InterestOwned`-consuming inbound
// parse (`respond_to_interest` / `dispatch_*`, which resolve keyexprs
// through the peer `HashMap`) stays `alloc`-gated per-method. The owned
// `DeclareOwned` builders moved to the AP sink (wz-runtime-tokio), which
// implements the borrowed `ResponseSink` emit seam.
#[cfg(feature = "liveliness-token")]
pub mod local_token;

// liveliness-get — REQUESTER-side registry for the liveliness GET
// (snapshot query). Gated on `liveliness-get` (which implies
// `codec-declare` for the DeclToken / DeclFinal decode + the CURRENT
// Interest send path), mirror of `local_token`'s `liveliness-token`
// gate: a build that never issues a liveliness snapshot get has no
// pending-get state. The no-heap control plane (register / fire /
// sweep) compiles on the MCU no-alloc profile; the owned
// `DeclareOwned`-consuming wire dispatch gates on `alloc` per-method.
// The reply-delivery surface reuses the un-gated
// `crate::reply_sink::ReplySink` seam (the get's application surface is
// reply-shaped, matching zenoh), so there is NO query-plane dependency
// — the wire is the Interest / declaration plane.
#[cfg(feature = "liveliness-get")]
pub mod liveliness_get;

/// R311kh — the shared membership consult behind the subscriber /
/// queryable `has_matching` AND the matching-watch re-evaluation: does
/// any currently-declared peer keyexpr intersect `keyexpr` under
/// [`crate::keyexpr_match::keyexpr_intersect_patterns`]? A free fn (not
/// a registry method) so the watch-list sweep can consult the
/// membership table while the watch list itself is mutably borrowed —
/// disjoint-field borrows inside one registry.
#[cfg(feature = "alloc")]
pub(crate) fn declared_intersects(
    declared: &hashbrown::HashMap<u64, alloc::string::String>,
    keyexpr: &str,
) -> bool {
    use alloc::vec::Vec;
    let chunks: Vec<&str> = keyexpr.split('/').collect();
    declared.values().any(|peer_keyexpr| {
        let peer_chunks: Vec<&str> = peer_keyexpr.split('/').collect();
        crate::keyexpr_match::keyexpr_intersect_patterns(&peer_chunks, &chunks)
    })
}

// R311kh — matching-listener watch machinery (pico Z_FEATURE_MATCHING
// parity): the MatchingSink seam + the flip-fire MatchingWatchList the
// subscriber / queryable registries compose under `session-matching`.
// `alloc`-gated as a whole — a watch owns its keyexpr String, and the
// membership table it re-evaluates against is the registries'
// `alloc`-gated half.
#[cfg(all(feature = "session-matching", feature = "alloc"))]
pub mod matching;

// R311ds — cross-registry composability tests (R311dr-wider-tests
// carry closure). Gated on `codec-declare` as well as `test` because
// it references all three registries, which compile only under
// `codec-declare`; the per-registry behavioural tests live inside
// each `declare/*.rs` `#[cfg(test)] mod tests` and inherit the
// module's own `codec-declare` gate.
#[cfg(all(test, feature = "codec-declare"))]
mod cross_tests;
