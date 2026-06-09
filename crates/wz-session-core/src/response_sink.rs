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

    /// R283 / R311hn (Track 2, Decision 2 no-heap emit) — encode + enqueue
    /// one outbound `Declare(DeclToken)` frame replying to a peer's
    /// liveliness Interest. The declarer-side liveliness-token registry
    /// drains its staged interest-response declarations (one
    /// `interest_id`-tagged `DeclToken` per matching held token, then a
    /// terminating [`send_declare_final_reply`](Self::send_declare_final_reply))
    /// through this borrowed-argument seam: the registry passes the held
    /// token's id + resolved keyexpr literal + the peer's `interest_id`,
    /// and the sink owns the encode (an AP sink encodes through a
    /// `VecSink`; an MCU sink encodes through `SliceSink` over a stack
    /// buffer with zero heap). This keeps the registry decoupled from the
    /// wire format (mirror of the `QueryResponder` split) and removes the
    /// owned `DeclareOwned` from the no-heap control plane.
    ///
    /// Gated on `liveliness-token` (NOT `all(.., alloc)`): the borrowed
    /// arguments carry no heap, so the seam composes on the MCU no-alloc
    /// profile. `liveliness-token` transitively pulls `codec-declare`
    /// (the encode path).
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64);

    /// R283 / R311hn — encode + enqueue the `Declare(DeclFinal)` that
    /// terminates the liveliness interest-response chain for
    /// `interest_id`. Emitted once after the matching
    /// [`send_declare_token_reply`](Self::send_declare_token_reply) calls (and emitted
    /// even when no token matched, so the peer's pending CURRENT query
    /// always resolves). Carries only `interest_id` — no heap — so it
    /// composes on the MCU no-alloc profile.
    #[cfg(feature = "liveliness-token")]
    fn send_declare_final_reply(&self, interest_id: u64);
}

// Smart-pointer / reference transparency: an `Arc`-shared or borrowed
// sink is still a sink. Production AP callers hold the actions handle as
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
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_token_reply(token_id, keyexpr, interest_id)
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare_final_reply(&self, interest_id: u64) {
        (**self).send_declare_final_reply(interest_id)
    }
}

// R311ja — gated on `target_has_atomic = "ptr"`: `alloc::sync::Arc` itself is
// unavailable on ARMv6-M (Cortex-M0/M0+), so naming it in an impl header would
// fail the no-alloc M0 session cross-compile. The AP profile (which has atomic
// `Arc` and is the only profile that hands an `Arc`-shared sink to
// `flush_pending`) keeps it; the single-task MCU profile reaches a shared sink
// through the unconditional `&S` impl or the bundle's own `ResponseSink` impl,
// never an `Arc`. An `Rc<S>` mirror is intentionally omitted until an MCU
// query / reply consumer actually drains through a refcounted sink (no caller
// today — the MCU drive loop does not run `flush_pending`).
#[cfg(target_has_atomic = "ptr")]
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
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        (**self).send_declare_token_reply(token_id, keyexpr, interest_id)
    }
    #[cfg(feature = "liveliness-token")]
    fn send_declare_final_reply(&self, interest_id: u64) {
        (**self).send_declare_final_reply(interest_id)
    }
}
