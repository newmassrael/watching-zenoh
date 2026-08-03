// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311in carry[3] — the MCU-profile live reassembly seam.
//!
//! This is the MCU sibling of the AP host's reassembly drive (the
//! `wz-runtime-tokio::session_glue::TokioReassembly` +
//! `report_outcome_reassembling` path). It binds the engine-free
//! [`ReassemblyDispatcher`] to the MCU machine's pool policy — sourced
//! from the SCE-codegen'd buffer-pool constants whose SSOT is
//! `sources/network/reassembly_pool_mcu.scxml` (carry [0] established the
//! same pattern for the AP profile).
//!
//! ## What "drives" the dispatcher
//!
//! The dispatcher is the consumer: [`ReassemblyDispatcher::ingest`] takes
//! one decoded `T_MID_FRAGMENT` and [`ReassemblyDispatcher::sweep`]
//! reclaims deadline-elapsed chains. This module supplies the typed
//! constructor [`mcu_reassembly`] (MCU dims + config from the scxml) and
//! re-exports the driving types, so the MCU main loop owns one dispatcher
//! and drives it:
//!
//! ```ignore
//! let mut reasm = wz_runtime_coop::reassembly_rx::mcu_reassembly();
//! // on each decoded inbound fragment (zid from the established session;
//! // sn_mask = the session's negotiated SN ring, `negotiated_sn_mask()`):
//! reasm.ingest(frag, sn_mask, now_ms, |msg| { /* re-parse + dispatch */ });
//! // once per tick, with the hardware monotonic clock:
//! reasm.sweep(now_ms);
//! ```
//!
//! ## No-alloc + MCU-resident
//!
//! The dispatcher stages each chain into an inline [`BoundedVec`], so
//! this seam composes on the no-alloc MCU profile (default features, no
//! `alloc`) — the same profile Layer G.9 proves the seam cross-compiles
//! under. The no_std `ReassemblyDispatcher<4, 4096>` is ~22 KiB
//! (vendor/sce 4ec1aa642 elided the inline W3C event metadata, and
//! `fragment_chunk_schema.scxml` dropped its vestigial 1472-byte payload
//! field), so a `static` instance fits the MCU's 128 KiB SRAM region.
//!
//! `now_ms` is a caller parameter (not read from a
//! [`crate::time::ClockSource`]) so the seam needs no executor / timer:
//! the no-alloc main loop supplies the monotonic clock from its SysTick /
//! RTC read, mirroring how the dispatcher itself takes `now_ms`. The
//! `alloc`-profile auto-sweep (a timer task on the [`crate::executor`])
//! lands with the MCU session drive loop.
//!
//! [`ReassemblyDispatcher`]: wz_session_core::reassembly_dispatch::ReassemblyDispatcher
//! [`BoundedVec`]: wz_session_core::bounded::BoundedVec

use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};

// Re-export the types the MCU loop needs to drive the dispatcher, so a
// consumer reaches them through the seam without naming wz-session-core
// directly (symmetric with how the AP host re-exports its reassembly
// surface through wz-runtime-tokio).
pub use wz_session_core::reassembly_dispatch::{Fragment, IngestOutcome};

/// MCU reassembly slot count — the dispatcher const generic, from the
/// SCE-codegen'd buffer-pool SSOT ([`crate::reassembly_pool_mcu`]).
pub const MCU_REASSEMBLY_SLOTS: usize = crate::reassembly_pool_mcu::SLOT_COUNT;

/// MCU reassembly per-slot byte cap — the dispatcher const generic, from
/// the same SCE-codegen'd buffer-pool SSOT.
pub const MCU_REASSEMBLY_SLOT_SIZE: usize = crate::reassembly_pool_mcu::SLOT_SIZE;

/// The MCU profile's reassembly Router type. The no-alloc backing keeps
/// each chain's staging buffer inline (`BoundedVec<u8, SLOT_SIZE>`);
/// `MCU_REASSEMBLY_SLOT_SIZE` is the per-chain cap the dispatcher
/// enforces, so reassembly is genuinely bounded on the MCU profile.
pub type CoopReassembly = ReassemblyDispatcher<MCU_REASSEMBLY_SLOTS, MCU_REASSEMBLY_SLOT_SIZE>;

/// Reassembly config (`per_peer_quota` / `reassembly_timeout_ms`) from
/// the MCU buffer-pool SSOT. The emit types them as `u32`;
/// [`ReassemblyConfig`] takes `u16` / `u64`, so the two widening casts
/// are the only adaptation.
pub fn mcu_reassembly_config() -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_mcu::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_mcu::REASSEMBLY_TIMEOUT_MS as u64,
    )
}

/// Construct the MCU reassembly Router with the deploy-sourced MCU pool
/// dims + config. The MCU main loop owns the returned dispatcher and
/// drives it via [`ReassemblyDispatcher::ingest`] /
/// [`ReassemblyDispatcher::sweep`] (see the module docs).
pub fn mcu_reassembly() -> CoopReassembly {
    CoopReassembly::new(mcu_reassembly_config())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::qos::Priority;

    const ZID: &[u8] = &[0x11; 16];

    /// The default-resolution (0x02, 28-bit) ring the tests compare at.
    const MASK: u64 = wz_session_core::sn::mask_from_res(0x02);

    fn frag<'a>(sn: u64, more: u8, payload: &'a [u8]) -> Fragment<'a> {
        Fragment {
            peer_key: ZID,
            reliable: true,
            sn,
            more,
            payload,
            // Pre-QoS MCU unicast chain: DEFAULT collapses the §2.3 key
            // back to the (peer, reliable) form these tests assert on.
            priority: Priority::DEFAULT,
        }
    }

    /// The MCU seam constructs the dispatcher with the SCE-sourced MCU
    /// pool dims: 4 slots / 4096-byte cap / quota 2 (from
    /// `reassembly_pool_mcu.scxml`).
    #[test]
    fn mcu_dims_come_from_the_buffer_pool_ssot() {
        assert_eq!(MCU_REASSEMBLY_SLOTS, 4);
        assert_eq!(MCU_REASSEMBLY_SLOT_SIZE, 4096);
        let cfg = mcu_reassembly_config();
        assert_eq!(cfg.per_peer_quota, 2);
        assert_eq!(cfg.reassembly_timeout_ms, 500);
    }

    /// Driving the MCU seam exactly as the main loop will: a two-fragment
    /// chain reassembles its concatenated payload in SN order, no alloc.
    #[test]
    fn mcu_seam_reassembles_a_two_fragment_chain() {
        let mut reasm = mcu_reassembly();

        let r0 = reasm.ingest(frag(7, 1, b"lwip "), MASK, 0, |_| panic!("not final"));
        assert_eq!(r0, IngestOutcome::Begun);
        assert_eq!(reasm.active_chains(), 1);

        let mut delivered = false;
        let r1 = reasm.ingest(frag(8, 0, b"reassembly"), MASK, 0, |msg| {
            assert_eq!(msg, &b"lwip reassembly"[..]);
            delivered = true;
        });
        assert_eq!(r1, IngestOutcome::Reassembled);
        assert!(delivered, "completion delivered the reassembled message");
        assert_eq!(reasm.active_chains(), 0);
    }

    /// The deadline sweep — the per-tick half of the drive loop — reclaims
    /// a chain past the MCU pool's 500 ms window.
    #[test]
    fn mcu_seam_sweep_times_out_a_stale_chain() {
        let mut reasm = mcu_reassembly();
        reasm.ingest(frag(1, 1, b"partial"), MASK, 0, |_| {});
        assert_eq!(reasm.active_chains(), 1);
        // Before the deadline: nothing reclaimed.
        assert_eq!(reasm.sweep(499), 0);
        assert_eq!(reasm.active_chains(), 1);
        // At/after the 500 ms deadline: the chain is reclaimed.
        assert_eq!(reasm.sweep(500), 1);
        assert_eq!(reasm.active_chains(), 0);
    }
}
