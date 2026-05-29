// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dz — `ApplicationLayerObserver` migrated to
//! `wz-session-core::observer`. This file is the AP-side re-export shell:
//! it re-exports the public surface so consumers continue to write
//! `wz_runtime_tokio::observer::ApplicationLayerObserver` across the
//! reorg (`session.rs`, `wz-ap-demo`).
//!
//! The move was unblocked by R311dz-pre's `ResponseSink` IoC trait — the
//! observer's `flush_pending` / `dispatch` drain phase is generic over
//! `ResponseSink` rather than the concrete tokio `SessionLinkActions`, so
//! the bundle no longer depends on the tokio actions layer
//! (`session_glue`) and composes identically on the AP (tokio) and MCU
//! (lwIP) runtimes. Every per-domain registry it aggregates already lives
//! in wz-session-core (`pubsub` / `query` / `reply` / `declare` —
//! R311do..dy). The behavioural `#[cfg(test)] mod tests` block moved with
//! the struct (gated on `codec-push` next to the always-present
//! `codec-declare` module gate in wz-session-core; the C1g lane runs it).

pub use wz_session_core::observer::ApplicationLayerObserver;
