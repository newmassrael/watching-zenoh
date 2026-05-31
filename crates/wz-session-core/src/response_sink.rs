// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dz-pre — `ResponseSink`: the outbound-reply drain abstraction the
//! application-layer observer's `flush_pending` / `dispatch` depend on.
//!
//! This inverts the observer's dependency on the concrete tokio
//! `SessionLinkActions<R, T>` (defined in `wz-runtime-tokio::session_glue`,
//! a 10k-LOC tokio-bound module not yet migrated) so the observer can
//! move into this runtime-agnostic crate without dragging in the tokio
//! actions layer. `SessionLinkActions` impls `ResponseSink` in
//! wz-runtime-tokio; a future MCU runtime's equivalent actions handle
//! impls the same trait, so the observer drains identically on either
//! profile.
//!
//! The method set is feature-gated to exactly the wire emit the observer
//! performs while draining its staged `QueryReply` buffer:
//! `send_response` (`codec-response`) for each queryable reply, and
//! `send_response_final` (`codec-response-final`) to terminate each
//! reply chain. The trait itself is always-nameable so the observer's
//! `flush_pending<S: ResponseSink>` signature stays stable across feature
//! subsets (the trait is simply empty in a build with neither response
//! codec).

#[cfg(feature = "codec-response")]
use wz_codecs::response::ResponseOwned;

#[cfg(feature = "liveliness-token")]
use wz_codecs::declare::DeclareOwned;

/// Outbound sink for queryable replies + reply-chain terminals. The
/// application-layer observer drains its staged `QueryReply` records
/// through this trait so it is decoupled from any concrete runtime
/// actions type (`SessionLinkActions` in the tokio profile).
pub trait ResponseSink {
    /// Encode + enqueue one outbound `Response(Reply|Err)` frame.
    /// Mirrors `SessionLinkActions::send_response`.
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned);

    /// Encode + enqueue one outbound `ResponseFinal` frame terminating
    /// the reply chain for `request_id`. Mirrors
    /// `SessionLinkActions::send_response_final`.
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64);

    /// R283 — encode + enqueue one outbound `Declare(...)` frame. The
    /// declarer-side liveliness-token registry drains its staged
    /// interest-response declarations (an interest_id-tagged
    /// `Declare(DeclToken)` per matching held token, then a
    /// `Declare(DeclFinal)` terminating the pending query) through this
    /// method. Gated on `liveliness-token`: it is the only registry that
    /// stages outbound `Declare` frames, and that feature transitively
    /// pulls `codec-declare` (the encode path). Mirrors
    /// `SessionLinkActions::send_declare`.
    #[cfg(feature = "liveliness-token")]
    fn send_declare(&self, declare: DeclareOwned);
}

// Smart-pointer / reference transparency: an `Arc`-shared or borrowed
// sink is still a sink. Production callers hold the actions handle as
// `Arc<SessionLinkActions>` (shared across the driver + per-query tasks),
// so these blanket impls let `flush_pending<S: ResponseSink>` accept the
// Arc (or a `&SessionLinkActions`) directly without unwrapping — the same
// ergonomics the prior concrete `&SessionLinkActions<R, T>` parameter got
// for free via deref coercion. Both are empty in a build with neither
// response codec, matching the trait's gated surface.
impl<S: ResponseSink + ?Sized> ResponseSink for &S {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned) {
        (**self).send_response(response)
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        (**self).send_response_final(request_id)
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare(&self, declare: DeclareOwned) {
        (**self).send_declare(declare)
    }
}

impl<S: ResponseSink + ?Sized> ResponseSink for alloc::sync::Arc<S> {
    #[cfg(feature = "codec-response")]
    fn send_response(&self, response: ResponseOwned) {
        (**self).send_response(response)
    }
    #[cfg(feature = "codec-response-final")]
    fn send_response_final(&self, request_id: u64) {
        (**self).send_response_final(request_id)
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare(&self, declare: DeclareOwned) {
        (**self).send_declare(declare)
    }
}
