// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311du — `SubscriberRegistry` + `SubscriptionId` migrated to
//! `wz-session-core::pubsub`. This file is the AP-side re-export shell:
//! it re-exports the public surface so consumers continue to write
//! `wz_runtime_tokio::pubsub::SubscriberRegistry` etc. across the
//! reorg. The behavioural `#[cfg(test)] mod tests` block moved with the
//! registry (gated on `codec-push` in wz-session-core, since every test
//! drives the registry with `wz_codecs::push::Push` records).

pub use wz_session_core::keyexpr_match::{keyexpr_intersects, keyexpr_matches};
pub use wz_session_core::pubsub::{SubscriberRegistry, SubscriptionId};
