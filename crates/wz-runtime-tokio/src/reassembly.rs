// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared AP reassembly-pool wiring (transport-agnostic SSOT).
//!
//! R311mk — the AP reassembly Router type ([`TokioReassembly`]) + its
//! runtime config ([`reassembly_config`]) were hoisted out of
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
use wz_session_core::reassembly_dispatch::ReassemblyConfig;

/// Reassembly slot-pool dimensions for the AP tokio host. R311in — sourced
/// from the SCE-codegen'd AP buffer-pool constants
/// ([`crate::reassembly_pool_ap`]), whose single SSOT is
/// `sources/network/reassembly_pool_ap.scxml` (`sce:kind="buffer-pool"`).
/// These replace the prior hand-transcribed `4 / 4096` literals; the
/// values, the spec §4 table, and the deploy.yaml block no longer drift
/// because there is now one SCE-owned, build-validated source.
///
/// The emit types the slot dims as `usize`, so they bind directly as the
/// dispatcher const generics (no cast). The AP machine's dims are larger
/// than the MCU's (32 / 1 MiB vs 4 / 4096) — the tokio host IS the AP
/// node, so it correctly uses the AP machine's pool. The AP slot size is
/// the per-chain reassembly CAP, and it must exceed the link's batch
/// budget by a real margin or fragmentation is unusable end-to-end: a
/// chain only forms above the batch, so a cap equal to it leaves no
/// window (see `sources/network/reassembly_pool_ap.scxml`).
const REASSEMBLY_SLOTS: usize = crate::reassembly_pool_ap::SLOT_COUNT;
/// `pub(crate)` because the TX side reads the SAME constant: the sender
/// refuses a chain this profile could not rejoin
/// (`SessionLinkActions::set_max_reassembly_bytes`, wired in
/// [`crate::session_glue::new_session_actions`]), and that refusal is only
/// exact while the bound it tests and the bound [`TokioReassembly`] enforces
/// are one value rather than two that agree today.
pub(crate) const REASSEMBLY_SLOT_SIZE: usize = crate::reassembly_pool_ap::SLOT_SIZE;

/// The AP tokio host's reassembly Router type. The std `alloc` backing
/// keeps each chain's staging buffer on the heap; `REASSEMBLY_SLOT_SIZE`
/// is the per-chain cap the dispatcher enforces explicitly (so reassembly
/// is bounded on the AP profile too). Shared by the unicast drive loop and
/// the multicast drive loop — both construct a `TokioReassembly::new(...)`.
#[cfg(not(feature = "runtime-zero-copy"))]
pub type TokioReassembly = ReassemblyDispatcher<REASSEMBLY_SLOTS, REASSEMBLY_SLOT_SIZE>;

/// R311y589 — the same Router over the RESERVED arena. `runtime-zero-copy`
/// swaps only the staging: the chain FSM, the SN arithmetic, the per-peer quota
/// and the deadline clock are the same code on both arms, which is what makes
/// `the_two_arenas_reassemble_the_same_bytes` a meaningful comparison rather
/// than two implementations that happen to agree.
///
/// The dims are the SAME constants the arena checks itself against
/// (`crate::reassembly_pool_ap::SLOT_COUNT` / `SLOT_SIZE`), reached through the
/// Router's aliases above — so a Router and a pool that disagree cannot be
/// built, and the assertion in `PooledStaging::new` is the backstop for a
/// deploy that writes its own dims.
#[cfg(feature = "runtime-zero-copy")]
pub type TokioReassembly = ReassemblyDispatcher<
    REASSEMBLY_SLOTS,
    REASSEMBLY_SLOT_SIZE,
    crate::zero_copy::PooledStaging<REASSEMBLY_SLOTS, REASSEMBLY_SLOT_SIZE>,
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
#[cfg(any(feature = "transport-unicast", feature = "transport-multicast"))]
pub(crate) fn reassembly_config() -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_ap::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_ap::REASSEMBLY_TIMEOUT_MS as u64,
    )
}
