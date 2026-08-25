// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ek — pure-data liveliness sample types, split out of the
//! `codec-declare`-gated [`crate::declare::liveliness_subscriber`]
//! module.
//!
//! [`LivelinessSample`] / [`LivelinessSampleKind`] /
//! [`LivelinessSampleSink`] carry no `wz_codecs` wire types — they
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

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Liveliness sample dispatched into a [`LivelinessSampleSink`].
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

/// R311gb-3d — liveliness-sample delivery seam: the Dependency-Inversion
/// sink a [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`]
/// dispatches each keyexpr-matched [`LivelinessSample`] through (model B).
/// Unlike the peer-declaration [`crate::decl_sink`] seam, no separate
/// accessor contract is needed: [`LivelinessSample`] is already a borrowed
/// `Copy` projection (kind + resolved keyexpr + token id, no owned /
/// wire-codec coupling), so it is the delivery currency itself — passed
/// by value. AP stores [`BoxedLivelinessSampleSink`] (a heap closure);
/// MCU stores a consumer-supplied closed `enum` impl with no heap.
pub trait LivelinessSampleSink {
    /// Deliver one matched liveliness sample (`Put` on `DeclToken`,
    /// `Delete` on `UndeclToken`). The borrow in [`LivelinessSample`] is
    /// valid for the duration of the call only.
    fn on_sample(&mut self, sample: LivelinessSample<'_>);
}

/// Heap closure type backing [`BoxedLivelinessSampleSink`].
#[cfg(feature = "alloc")]
type BoxedLivelinessSampleFn = Box<dyn FnMut(LivelinessSample<'_>) + Send + 'static>;

/// AP / `alloc`-profile adapter wrapping a liveliness-sample closure on
/// the heap, type-erasing it so a subscriber slot stores a homogeneous
/// sink. `Send + 'static` so the registry can be shared across tasks
/// under `Arc<Mutex<...>>` (matching the other registries' threading
/// contract). No MCU counterpart — the no-heap profile uses a consumer-
/// supplied closed `enum` instead.
#[cfg(feature = "alloc")]
pub struct BoxedLivelinessSampleSink {
    inner: BoxedLivelinessSampleFn,
}

#[cfg(feature = "alloc")]
impl BoxedLivelinessSampleSink {
    /// Wrap a capturing liveliness-sample observer as a heap-stored sink.
    pub fn new(callback: impl FnMut(LivelinessSample<'_>) + Send + 'static) -> Self {
        Self {
            inner: Box::new(callback),
        }
    }
}

#[cfg(feature = "alloc")]
impl LivelinessSampleSink for BoxedLivelinessSampleSink {
    fn on_sample(&mut self, sample: LivelinessSample<'_>) {
        (self.inner)(sample)
    }
}
