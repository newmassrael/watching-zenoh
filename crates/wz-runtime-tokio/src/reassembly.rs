// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};

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
/// than the MCU's (32 / 65536 vs 4 / 4096) — the tokio host IS the AP
/// node, so it correctly uses the AP machine's pool.
const REASSEMBLY_SLOTS: usize = crate::reassembly_pool_ap::SLOT_COUNT;
const REASSEMBLY_SLOT_SIZE: usize = crate::reassembly_pool_ap::SLOT_SIZE;

/// The AP tokio host's reassembly Router type. The std `alloc` backing
/// keeps each chain's staging buffer on the heap; `REASSEMBLY_SLOT_SIZE`
/// is the per-chain cap the dispatcher enforces explicitly (so reassembly
/// is bounded on the AP profile too). Shared by the unicast drive loop and
/// the multicast drive loop — both construct a `TokioReassembly::new(...)`.
pub type TokioReassembly = ReassemblyDispatcher<REASSEMBLY_SLOTS, REASSEMBLY_SLOT_SIZE>;

/// Reassembly config (`per_peer_quota` / `reassembly_timeout_ms`) sourced
/// from the same SCE-codegen'd AP buffer-pool constants. The emit types
/// them as `u32`; [`ReassemblyConfig`] takes `u16` / `u64`, so the two
/// widening casts are the only adaptation. `pub(crate)`: consumed by both
/// the unicast (`crate::session_glue`) and multicast (`crate::multicast_glue`)
/// drive loops — one buffer-pool policy SSOT, two transports.
pub(crate) fn reassembly_config() -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_ap::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_ap::REASSEMBLY_TIMEOUT_MS as u64,
    )
}
