// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dx — `QueryableRegistry` + the query data/handle cluster
//! (`QueryReply` / `ReplyBody` / `QueryResponder` / `QueryableId`)
//! migrated to `wz-session-core::query`. This file
//! is the AP-side re-export shell: it re-exports the public surface so
//! consumers continue to write `wz_runtime_tokio::query::QueryableRegistry`
//! etc. across the reorg.
//!
//! The migration realises the textbook data/handle ↔ codec-coupled
//! split the R311dw-compose carry called for: the codec-agnostic
//! accumulator + handle types stay always-compiled (alloc-gated) in
//! wz-session-core, while the wire-dispatch entry points
//! (`dispatch_request` / `local_query` / `fire_matching_queryables`)
//! gate on `codec-request` and the wire-emit terminals
//! (`QueryReply::into_response` / [`response_final_for`]) gate on
//! `codec-response` / `codec-response-final`. The behavioural
//! `#[cfg(test)] mod tests` block moved with the registry (gated on the
//! `query-{queryable,attachment,selector-parameters,reply-err}` union in
//! wz-session-core; the C1e lane runs it).

// Codec-agnostic data / handle types — always available (alloc-bound in
// wz-session-core); these back the type-ungated
// `Session::declare_queryable` surface + the `Vec<QueryReply>` staging.
pub use wz_session_core::query::{QueryReply, QueryableId, ReplyBody};
// Codec-coupled terminals, each carrying the wz-session-core gate it was
// migrated under: `response_final_for` builds a ResponseFinal wire record
// (`codec-response-final`); `QueryResponder` + `QueryableRegistry` are the
// `Query` / `Request` codec_group dispatch surface (`codec-request`).
#[cfg(feature = "codec-response-final")]
pub use wz_session_core::query::response_final_for;
#[cfg(feature = "codec-request")]
pub use wz_session_core::query::{QueryResponder, QueryableRegistry};

/// Round 2442 (open-debt item 675) — WHAT A REQUESTER PUTS ON THE WIRE for
/// consolidation, as a free function two callers share.
///
/// # Why this is public and not a method
///
/// R311y836/y837 built the resolution and put it behind
/// `QueryOptions::wire_consolidation`, which is `pub(super)` on a type only the
/// session's own `query` / `get` paths construct. That is the right home for a
/// caller that HAS a `QueryOptions`, and it is out of reach for one that does
/// not: `wz-ap-demo`'s `--query` hand-builds a [`QueryMetadata`] and calls
/// `send_request_query_with_meta` directly, so it rode the `Option::None`
/// default and transmitted no consolidation byte at all — measured, and named
/// as a residual on this atom since R311y837.
///
/// [`QueryMetadata`]: wz_session_core::metadata::QueryMetadata
///
/// The fix is not for the demo to resolve the mode itself. Both upstreams keep
/// this rule in exactly one place (zenoh inside `get()`, pico inside
/// `_z_query_encode`'s caller), and a second copy in a demo is the shape this
/// workspace spends rounds removing. So the judgement moves HERE and
/// `QueryOptions` becomes one of its callers.
///
/// # The feature gate is INSIDE, deliberately
///
/// `query-consolidation` is the consolidation capability, and R311y317 settled
/// where its gate belongs: the last hop that knows. A caller that had to write
/// `#[cfg(feature = "query-consolidation")]` itself would be a second place the
/// OFF-arm decision is made — and `wz-ap-demo` cannot write it at all, because
/// the key is not in that crate's manifest. Callers pass their inputs and get
/// the honest answer for the build they are in.
///
/// `None` out means ELIDE the field, which both upstreams' decoders read as
/// `Auto`. On an OFF build that is the truthful statement: this binary
/// consolidates nothing, so it must not claim a mode it cannot honour.
pub fn wire_consolidation(
    requested: Option<wz_session_core::query_mode::ConsolidationMode>,
    parameters: Option<&[u8]>,
) -> Option<wz_session_core::query_mode::ConsolidationMode> {
    #[cfg(feature = "query-consolidation")]
    {
        Some(resolved_consolidation(requested, parameters))
    }
    #[cfg(not(feature = "query-consolidation"))]
    {
        let _ = (requested, parameters);
        None
    }
}

/// Round 2442 (open-debt item 675) — the same resolution, for the LOCAL sink.
///
/// The wire and the sink must be told the same thing or a query consolidates
/// one way and reports another, which is why they share this function rather
/// than each calling [`wz_session_core::query_mode::ConsolidationMode::resolve_auto`]
/// with their own idea of the inputs. zenoh does the same thing for the same
/// reason: it resolves `Auto` ONCE and feeds both.
///
/// Differs from [`wire_consolidation`] only in the OFF arm, and the difference
/// is not cosmetic: the wire ELIDES (no claim), while the sink must still be
/// handed a mode, and on a build with no consolidation capability that mode is
/// `None` — pass everything through.
pub fn resolved_consolidation(
    requested: Option<wz_session_core::query_mode::ConsolidationMode>,
    parameters: Option<&[u8]>,
) -> wz_session_core::query_mode::ConsolidationMode {
    #[cfg(feature = "query-consolidation")]
    {
        let params = parameters
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("");
        wz_session_core::query_mode::ConsolidationMode::resolve_auto(requested, params)
    }
    #[cfg(not(feature = "query-consolidation"))]
    {
        let _ = (requested, parameters);
        wz_session_core::query_mode::ConsolidationMode::None
    }
}
