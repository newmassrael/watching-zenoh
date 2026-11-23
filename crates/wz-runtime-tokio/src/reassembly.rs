// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared AP reassembly-pool wiring (transport-agnostic SSOT).
//!
//! R311mk — the AP reassembly Router type ([`TokioReassembly`]) + its
//! runtime config (`reassembly_config`) were hoisted out of
//! [`crate::session_glue`] (the unicast handshake driver) into this neutral
//! module so they survive the `transport-unicast` decouple. They are NOT
//! unicast machinery: both the unicast steady-state drive loop
//! (`session_glue::drive_session_until_terminal`) and the multicast drive
//! loop ([`crate::multicast_glue::drive_multicast_session`]) run their own
//! pool instance over the SAME SCE-sourced AP dims/knobs (one buffer-pool
//! policy SSOT, two transports). Keeping them in `session_glue` made a
//! `transport-multicast`-only build (no `transport-unicast`) unable to reach
//! the pool config — the facade composability gap this round closes.
//!
//! Gated on the `reassembly` feature only (the dims come from
//! [`crate::reassembly_pool_ap`], itself `reassembly`-gated); a deploy that
//! never receives a `T_MID_FRAGMENT` compiles the whole pool out.

use wz_session_core::reassembly_dispatch::ReassemblyDispatcher;
// Follows `reassembly_config`'s gate, not the module's — same G7 rule, and an
// import is where that rule is easiest to forget.
#[cfg(any(feature = "transport-unicast", feature = "transport-multicast"))]
use wz_session_core::{
    policy::SessionPolicy,
    reassembly_dispatch::{PoolOverflow, ReassemblyConfig},
};

/// Reassembly slot-pool dimensions for the AP tokio host. R311in — sourced
/// from the SCE-codegen'd AP buffer-pool constants
/// ([`crate::reassembly_pool_ap`]), whose single SSOT is
/// `sources/network/reassembly_pool_ap.scxml` (`sce:kind="buffer-pool"`).
/// These replace the prior hand-transcribed `4 / 4096` literals; the
/// values, the spec §4 table, and the deploy.yaml block no longer drift
/// because there is now one SCE-owned, build-validated source.
///
/// The slot COUNT is how many chains the Router stages at once. The slot SIZE
/// is not a bound on a chain here: see [`REASSEMBLY_CHAIN_CAP`].
const REASSEMBLY_SLOTS: usize = crate::reassembly_pool_ap::SLOT_COUNT;

/// The per-chain bound the AP Router type is built with: none of its own.
///
/// What bounds an AP chain is the session's configured
/// `transport/link/rx/max_message_size`, upstream's 1 GiB unless a deploy says
/// otherwise (`commons/zenoh-config/src/defaults.rs` @
/// `max_message_size: 2_usize.pow(30),`), which the drive loops push into the
/// Router (`ReassemblyDispatcher::set_max_message_bytes`) and which the
/// Router reads as the smaller of it and this constant. Upstream bounds a chain
/// by that value and by nothing else: its defragmentation buffer is made with
/// it as its capacity and grows as fragments arrive
/// (`io/zenoh-transport/src/manager.rs` @
/// `defrag_buff_size: *link_rx.max_message_size(),`).
///
/// Until the fan-in lane measured it, this was the AP pool's slot size,
/// 1 MiB: a configured value above it was read as 1 MiB, so every message
/// larger than that was dropped by an AP receiver and refused by an AP sender
/// (4,000,000-byte samples arrived 0% wherever wz was on either end). The slot
/// size is the reserved arena's unit, not a message size: the default arena
/// stages each chain in a heap buffer that grows with it
/// (`wz_session_core::chain_staging::HeapStaging`), and the reserved one
/// stages a chain in its slot until the chain outgrows it
/// (`crate::zero_copy::PooledStaging`). Neither has a reason to refuse a
/// chain the configuration admits.
///
/// Public, and read by the TX side, because the sender's bound is the SAME constant: the sender
/// refuses a chain this profile could not rejoin
/// (`SessionLinkActions::set_max_reassembly_bytes`, wired in
/// [`crate::session_glue::new_session_actions`], and the node's own publish,
/// `RouterForwarder::publish_with`), and that refusal is only exact while the
/// bound it tests and the bound [`TokioReassembly`] enforces are one value
/// rather than two that agree today. With no bound of the build's, neither
/// refuses, as upstream's sender does not.
///
/// The sender's bound is the BUILD's, not a session's configured
/// `transport/link/rx/max_message_size`: the configured value says what this
/// node accepts, and a sender refusing by it would refuse a message to a peer
/// configured to take more. Upstream's key is receive-only.
pub const REASSEMBLY_CHAIN_CAP: usize = usize::MAX;

/// The AP tokio host's reassembly Router type. The std `alloc` backing
/// keeps each chain's staging buffer on the heap, so an idle chain costs
/// nothing and a live one what it staged; the session's configured
/// `transport/link/rx/max_message_size` is the per-chain bound the dispatcher
/// enforces ([`REASSEMBLY_CHAIN_CAP`]). Shared by the unicast drive loop and
/// the multicast drive loop — both construct a `TokioReassembly::new(...)`.
#[cfg(not(feature = "runtime-zero-copy"))]
pub type TokioReassembly = ReassemblyDispatcher<REASSEMBLY_SLOTS, REASSEMBLY_CHAIN_CAP>;

/// R311y589 — the same Router over the RESERVED arena. `runtime-zero-copy`
/// swaps only the staging: the chain FSM, the SN arithmetic, the per-peer quota
/// and the deadline clock are the same code on both arms, which is what makes
/// `the_two_arenas_reassemble_the_same_bytes` a meaningful comparison rather
/// than two implementations that happen to agree.
///
/// The slot count is the SAME constant the arena checks itself against
/// (`crate::reassembly_pool_ap::SLOT_COUNT`), so a Router and a pool that
/// disagree cannot be built, and the assertion in `PooledStaging::new` is the
/// backstop for a deploy that writes its own dims. The chain bound is the
/// default arm's: a chain longer than a slot leaves its slot for a heap buffer
/// (`crate::zero_copy::PooledStaging`).
#[cfg(feature = "runtime-zero-copy")]
pub type TokioReassembly = ReassemblyDispatcher<
    REASSEMBLY_SLOTS,
    REASSEMBLY_CHAIN_CAP,
    crate::zero_copy::PooledStaging<REASSEMBLY_SLOTS, REASSEMBLY_CHAIN_CAP>,
>;

/// Reassembly config (`per_peer_quota` / `reassembly_timeout_ms`) sourced
/// from the same SCE-codegen'd AP buffer-pool constants. The emit types
/// them as `u32`; [`ReassemblyConfig`] takes `u16` / `u64`, so the two
/// widening casts are the only adaptation. `pub(crate)`: consumed by both
/// the unicast (`crate::session_glue`) and multicast (`crate::multicast_glue`)
/// drive loops — one buffer-pool policy SSOT, two transports.
///
/// R311y589 — gated on the UNION of its callers rather than on this module's
/// own feature, the R311y579 (G7) rule. Its two callers are
/// [`crate::session_glue`] (`transport-unicast`) and
/// [`crate::multicast_glue`] (`transport-multicast`); `reassembly` alone
/// compiles it with neither, which is dead code under `-D warnings`. The hole
/// predates this round and no lane had selected the arm that shows it — a
/// `reassembly`-without-transport build — until `runtime-tokio-uring` implied
/// `reassembly` and Layer C1bq built exactly that subset.
///
/// What a full pool does is the `reassembly-pool-overflow` value of `policy`, the snapshot of the
/// session whose loop owns the pool.
#[cfg(any(feature = "transport-unicast", feature = "transport-multicast"))]
pub(crate) fn reassembly_config(policy: &SessionPolicy) -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_ap::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_ap::REASSEMBLY_TIMEOUT_MS as u64,
    )
    .with_pool_overflow(PoolOverflow::of_policy(policy.reassembly_pool_overflow()))
}

#[cfg(all(
    test,
    any(feature = "transport-unicast", feature = "transport-multicast")
))]
mod tests {
    use super::*;
    use wz_session_core::policy::ReassemblyPoolOverflow;

    /// The AP config takes its quota from the AP buffer-pool constants and
    /// what a full pool does from the snapshot it is handed, not from the
    /// build's value nor from the constructor's default: every value the
    /// build's domain allows is selected and comes back out.
    #[test]
    fn the_ap_pool_overflow_is_the_snapshots_policy() {
        for value in [
            ReassemblyPoolOverflow::Reject,
            ReassemblyPoolOverflow::DiagnosticEvent,
            ReassemblyPoolOverflow::OldestWins,
        ] {
            let mut policy = SessionPolicy::defaults();
            if policy.select_reassembly_pool_overflow(value).is_err() {
                continue;
            }
            let cfg = reassembly_config(&policy);
            assert_eq!(
                cfg.per_peer_quota,
                crate::reassembly_pool_ap::PER_PEER_QUOTA as u16
            );
            assert_eq!(cfg.pool_overflow, PoolOverflow::of_policy(value));
        }
    }
}
