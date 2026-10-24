// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a declaration names its key on the wire, beside what it matches locally: the key an
//! entity's retraction names
//! ([`RetractionKey`](crate::declare_form::RetractionKey)), and the form and the ask of a
//! matching Interest (`InterestForm`, with `session-matching` and `declare-interest`).
//!
//! Both are wire facts a declaring C ABI chooses the way its reference library does, and both
//! were the tokio engine's (`wz-runtime-tokio`'s session module, which re-exports them). They
//! moved here when the pico C ABI over the cooperative engine (`docs/capi-pico-on-coop-engine.md`)
//! had to hand them to an engine without naming that one.

use alloc::string::String;

/// The key an entity's `Undeclare*` names beside its id, in the wire form it is held under: a
/// declared prefix's id and the rest of the key, or `0` and the whole literal. A subscriber's
/// retraction and a queryable's take the same shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetractionKey {
    /// The prefix's mapping id, or `0` for a literal.
    pub mapping_id: u64,
    /// The rest of the key after the prefix; the whole key when `mapping_id` is `0`.
    pub suffix: String,
}

/// R2962 — HOW a matching Interest names its key and what it asks of the peer, for a caller that
/// is not an engine's own declared publisher or querier.
///
/// Those ask in one fixed way: the literal keyexpr, no aggregate. A declaring C ABI asks in the
/// way its reference library does — zenoh-pico's write filter names the entity's own DECLARED key
/// (`mapping_id` plus the rest of the key as `suffix`) and, as a client, asks for aggregated
/// answers (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_create`). The session has
/// no opinion about that, so the ABI hands it in.
#[cfg(all(feature = "session-matching", feature = "declare-interest"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterestForm {
    /// The keyexpr declaration the Interest names, `0` for none.
    pub mapping_id: u64,
    /// What follows the declared prefix; the whole literal when `mapping_id` is 0.
    pub suffix: Option<String>,
    /// Ask the peer to answer aggregated (see
    /// [`build_interest_kinds_with_aggregate`](crate::interest_build::build_interest_kinds_with_aggregate)).
    pub aggregate: bool,
}
