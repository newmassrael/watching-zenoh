// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ek — pure-data liveliness sample types, split out of the
//! `codec-declare`-gated [`crate::declare::liveliness_subscriber`]
//! module.
//!
//! [`LivelinessSample`] / [`LivelinessSampleKind`] /
//! [`LivelinessSampleCallback`] carry no `wz_codecs` wire types — they
//! are the codec-agnostic callback surface the
//! `Session::declare_liveliness_subscriber{_aliased}` Result-form
//! signatures bind regardless of feature state (R311q type-ungating).
//! Housing them in the `codec-declare`-gated `liveliness_subscriber`
//! module (whose `LivelinessSubscriberRegistry` genuinely consumes
//! `DeclareOwnedVariant`) made the unconditional re-export in
//! `wz-runtime-tokio::declare` fail to resolve in a `codec-declare`-off
//! subset. Relocating just the data types here — `alloc`-only, no codec
//! gate — keeps the registry gated while the sample surface composes in
//! any subset (north-star arbitrary-composition mechanism ①).

use alloc::boxed::Box;

/// Liveliness sample dispatched into a [`LivelinessSampleCallback`].
/// Mirrors zenoh-pico's `z_sample_t` projection for the liveliness
/// path: a `DeclToken` arrival surfaces as `Put`, an `UndeclToken`
/// arrival as `Delete` (per `z_liveliness_declare_token`'s
/// doc-comment, `vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h`).
///
/// The lifetime borrow ties the keyexpr `&str` to the dispatch call
/// stack so the callback can read it without cloning. Callers that
/// want to retain the keyexpr beyond the callback body must
/// `.to_string()` it.
#[derive(Debug, Clone, Copy)]
pub struct LivelinessSample<'a> {
    /// Discriminator: `Put` for `DeclToken`, `Delete` for `UndeclToken`.
    pub kind: LivelinessSampleKind,
    /// Resolved keyexpr — either the literal carried inline on the
    /// `DeclToken` or the peer-table lookup result for an aliased
    /// declaration. For an `UndeclToken` this is the keyexpr the
    /// matching `DeclToken` resolved to (looked up from the
    /// originating registry's `peer_token_table`).
    pub keyexpr: &'a str,
    /// Peer-side token id from the originating `DeclToken`. Stable
    /// across the matching `UndeclToken` so consumers can correlate
    /// `Put` / `Delete` pairs without keyexpr comparisons.
    pub token_id: u64,
}

/// Liveliness sample kind discriminator. Mirrors the
/// `Z_SAMPLE_KIND_PUT` / `Z_SAMPLE_KIND_DELETE` pair that
/// `z_liveliness_declare_token`'s doc-comment commits to:
/// "subscribers on an intersecting key expression will receive a PUT
/// sample when connectivity is achieved, and a DELETE sample if it's
/// lost".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivelinessSampleKind {
    /// Inbound `DeclToken` — a peer just brought a liveliness token
    /// alive on a matching keyexpr.
    Put,
    /// Inbound `UndeclToken` — a peer just retracted a liveliness
    /// token whose prior `DeclToken` matched.
    Delete,
}

/// Boxed callback fired for each [`LivelinessSample`] whose keyexpr
/// matches a subscriber's pattern. `Send + 'static` so the registry
/// can be shared across tasks under `Arc<Mutex<...>>` (matching the
/// other application-layer registries' threading contract).
pub type LivelinessSampleCallback = Box<dyn FnMut(LivelinessSample<'_>) + Send + 'static>;
