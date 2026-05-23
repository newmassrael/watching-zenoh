// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz — top-level facade for the watching-zenoh composable framework.
//
// R302a scope: feature catalog only. The 169 Cargo features defined
// in Cargo.toml (144 atomic + 19 domain-aggregate + 6 preset) are
// not yet wired to any source-level `#[cfg(feature = "...")]` gate.
// They compile to no-op labels that downstream consumers can already
// select with `cargo add wz --features preset-ap-client` etc., but
// the gates themselves land in R302b+ as the corresponding modules
// move into this facade.
//
// The intended long-term shape (R302b+ deliverables):
//   - pub use wz_runtime_tokio::* re-exports gated on `runtime-tokio`
//   - pub mod codecs gated per `codec-*` features
//   - pub mod query / pubsub / liveliness gated per domain
//
// For now: empty facade. cargo check with any feature set succeeds
// with zero compiled code.

#![cfg_attr(not(test), no_std)]
