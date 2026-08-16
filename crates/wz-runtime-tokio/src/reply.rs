// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dy — the application-layer reply registry (`ReplyRegistry` +
//! `InboundReply` / `InboundReplyBody` / `ReplyHandle`) migrated to
//! `wz-session-core::reply`. This file is the AP-side re-export shell: it
//! re-exports the public surface so consumers continue to write
//! `wz_runtime_tokio::reply::ReplyRegistry` etc. across the reorg.
//! R311gb-3c — the per-pending `(on_reply, on_final)` closures migrated to
//! the `ReplySink` seam (`wz-session-core::reply_sink`), so the
//! `ReplyCallback` / `FinalCallback` boxed-closure aliases were retired.
//!
//! The whole public surface is always-compiled (alloc-bound) — unlike
//! the queryable registry, `ReplyRegistry` keeps its codec-agnostic
//! loopback (`deliver_local_reply` / `deliver_local_final`) + timeout
//! sweep (`sweep_timed_out`), so the registry itself never gates out;
//! only the wire-dispatch methods (`dispatch_response` /
//! `dispatch_response_final`) carry the `codec-response` /
//! `codec-response-final` gate inside the migrated module. The
//! behavioural `#[cfg(test)] mod tests` block moved with the registry
//! (gated on the reply dispatch feature union in wz-session-core; the
//! C1f lane runs it).

//! R311y833 — the acceptance policy every registration now states lives in
//! [`crate::reply_acceptance`], re-exported at the crate root beside
//! `keyexpr_match` and its siblings: a REQUIRED parameter whose type an AP
//! consumer cannot name is not a reachable API, and wz-ap-demo reaches
//! `ReplyRegistry::register` without depending on `wz-session-core` at all.

pub use wz_session_core::reply::{InboundReply, InboundReplyBody, ReplyHandle, ReplyRegistry};
