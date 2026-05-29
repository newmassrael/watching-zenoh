// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ee — per-role ext-chain dispatch discriminator lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! Pure no_std + no_alloc value type (a four-variant `Copy` enum), so it
//! sits on the runtime-agnostic side alongside [`crate::qos`] /
//! [`crate::close_reason`]. R68b plumbing: the four negotiation-relevant
//! frame roles (InitSyn / InitAck / OpenSyn / OpenAck) each carry their
//! own ext chain (session-fsm §7 — QoS / QoSLink / Auth / MultiLink /
//! LowLatency), so per-deploy negotiation policy can stage distinct
//! chains per role without growing `SessionInitParams`.
//!
//! Only the discriminator moves: the per-role slot storage
//! (`SessionLinkActions::ext_chain_slot`, indexed by this enum into
//! `R::Mutex<Vec<ExtEntryOwned>>` fields) and the encoder read path
//! (`SessionLinkActions::ext_chain_for`) are runtime-bound (they hold an
//! `R::Mutex`) and stay in `session_glue.rs`. `session_glue.rs` keeps a
//! `pub use` re-export so the `crate::session_glue::ExtChainRole`
//! callsites (the slot accessors, the InitSyn/OpenSyn/InitAck/OpenAck
//! encode sites, and `wz-integration-tests::layer3_ext_chain_outbound`)
//! resolve unchanged. A DP3 leaf out of `session_glue.rs`.

/// Outbound transport-message variant for ext-chain dispatch.
///
/// R68b plumbing: 4 negotiation-relevant frame roles each carry
/// their own ext chain (session-fsm §7 — QoS / QoSLink / Auth /
/// MultiLink / LowLatency). The encoder reads the appropriate
/// slot via `SessionLinkActions::ext_chain_for` so per-deploy
/// negotiation policy can stage distinct chains per role without
/// growing the `SessionInitParams` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtChainRole {
    InitSyn,
    InitAck,
    OpenSyn,
    OpenAck,
}
