// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dx — `QueryableRegistry` + the query data/handle cluster
//! (`QueryReply` / `ReplyBody` / `QueryResponder` / `QueryableId` /
//! `QueryableCallback`) migrated to `wz-session-core::query`. This file
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
pub use wz_session_core::query::{QueryReply, QueryableCallback, QueryableId, ReplyBody};
// Codec-coupled terminals, each carrying the wz-session-core gate it was
// migrated under: `response_final_for` builds a ResponseFinal wire record
// (`codec-response-final`); `QueryResponder` + `QueryableRegistry` are the
// `Query` / `Request` codec_group dispatch surface (`codec-request`).
#[cfg(feature = "codec-response-final")]
pub use wz_session_core::query::response_final_for;
#[cfg(feature = "codec-request")]
pub use wz_session_core::query::{QueryResponder, QueryableRegistry};
