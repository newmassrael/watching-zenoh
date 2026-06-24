// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xt — §5.18 time: the timestamp SOURCE seam for an un-timestamped
//! sample, plus the optional Hybrid Logical Clock source (`time-hlc`).
//!
//! ## What this realizes (two §5.18 atoms)
//!
//! - `time-timestamp-source` (FOUNDATIONAL): [`FallbackStamp`] is the
//!   source-selection seam. The storage capture leg stamps an
//!   un-timestamped sample through it (the only auto-stamp site in wz
//!   today — wz publishers carry a timestamp only when the caller sets one,
//!   so there is no publish auto-stamp to feed yet), which makes swapping
//!   the source a one-type change rather than a scattered edit. zenoh has
//!   no pluggable-source config knob (its source is a plain
//!   `Option<Arc<HLC>>` on the Runtime), so a general `TimestampSource`
//!   trait would be superset gold-plating until a 2nd consumer (a publish
//!   auto-stamp) lands; the seam is realized minimally as this stamper.
//! - `time-hlc` (active, the `time-hlc` feature): the [`uhlc::HLC`] variant
//!   of the stamper, the wz mirror of zenoh's `Option<Arc<HLC>>`
//!   (`zenoh/src/net/runtime/mod.rs:147`, an HLC created when `timestamping`
//!   is enabled). wz reuses the `uhlc` crate verbatim — the SSOT for the
//!   subtle logical-counter-in-low-[`uhlc::CSIZE`]-bits + drift + Timestamp
//!   `Ord` algorithm is upstream, not a wz copy — and injects wz's own
//!   [`wall_clock_ntp64`](crate::storage_service::wall_clock_ntp64) as the
//!   HLC's physical clock (`HLCBuilder::with_clock`). So the HLC WRAPS the
//!   wall-clock source (it is not an alternative to it: the system clock is
//!   the HLC's physical layer, the uhlc/zenoh model), and an HLC stamp keeps
//!   the same NTP64 magnitude the rest of the storage stack (digest /
//!   aligner) uses.
//!
//! ## What the HLC adds over the bare wall-clock fallback
//!
//! The wall-clock fallback ([`FallbackStamp`] with `time-hlc` off) is not
//! monotonic across NTP steps and collides for two stamps within one
//! `(time, zid)` (the later one Replaces under newer-wins — see the
//! [`storage_service`](crate::storage_service) module note). The HLC's
//! logical counter (the low `CSIZE` bits of the NTP64 fraction) removes
//! both: successive stamps strictly increase even within one physical
//! instant. A sample that DOES carry a publisher timestamp always uses it,
//! so a timestamped deployment is unaffected by the source choice. Only the
//! TIME word is upgraded; the stamp's `zid` stays the storage identity (so a
//! source switch never changes the tie-breaker, only the ordering word).

use wz_session_core::sample::TimestampHint;

#[cfg(feature = "time-hlc")]
use std::sync::Arc;

/// The fallback timestamp source for an un-timestamped sample: the seam that
/// selects HOW the stamp's time word is produced. Constructed once per
/// storage (over the storage's `zid`) and called on every captured
/// un-timestamped sample.
///
/// `Send + Sync` (the session may fire the capture callback from different
/// worker threads): the `time-hlc` variant holds an `Arc<uhlc::HLC>` whose
/// interior `last_time` is a `spin::Mutex`, the `time-hlc`-off variant holds
/// only the `zid`.
pub(crate) struct FallbackStamp {
    /// The storage's identity, attached to every fallback stamp as the `zid`
    /// tie-breaker — identical across both source variants, so the source
    /// choice only upgrades the TIME word, never the identity.
    zid: Vec<u8>,
    /// The Hybrid Logical Clock source. Present only with `time-hlc`; wraps
    /// wz's `wall_clock_ntp64` physical clock (injected at construction).
    #[cfg(feature = "time-hlc")]
    hlc: Arc<uhlc::HLC>,
}

impl FallbackStamp {
    /// Build the fallback source for a storage whose identity is `zid`. With
    /// `time-hlc` on this also constructs the HLC (id derived from `zid`,
    /// physical clock = wz's `wall_clock_ntp64`).
    pub(crate) fn new(zid: Vec<u8>) -> Self {
        #[cfg(feature = "time-hlc")]
        {
            let hlc = Arc::new(build_hlc(&zid));
            Self { zid, hlc }
        }
        #[cfg(not(feature = "time-hlc"))]
        {
            Self { zid }
        }
    }

    /// Produce a fallback [`TimestampHint`] for an un-timestamped sample: the
    /// source-selected NTP64 time word paired with the storage `zid`.
    pub(crate) fn stamp(&self) -> TimestampHint {
        TimestampHint {
            time: self.now_word(),
            zid: self.zid.clone(),
        }
    }

    /// HLC source: a logical-counter + monotonic NTP64 over the wall clock.
    #[cfg(feature = "time-hlc")]
    fn now_word(&self) -> u64 {
        self.hlc.new_timestamp().get_time().as_u64()
    }

    /// Bare wall-clock source: the `wall_clock_ntp64` SSOT (byte-identical to
    /// the pre-HLC behavior).
    #[cfg(not(feature = "time-hlc"))]
    fn now_word(&self) -> u64 {
        crate::storage_service::wall_clock_ntp64()
    }
}

/// Construct an HLC whose physical clock is wz's `wall_clock_ntp64` (so the
/// HLC wraps the same source the digest / aligner read) and whose id is
/// derived from the storage `zid`. The default 500ms drift bound and the
/// `CSIZE`-bit logical counter come from `uhlc`.
#[cfg(feature = "time-hlc")]
fn build_hlc(zid: &[u8]) -> uhlc::HLC {
    uhlc::HLCBuilder::new()
        .with_clock(wz_physical_clock)
        .with_id(hlc_id_from_zid(zid))
        .build()
}

/// The HLC's physical clock: wz's wall-clock NTP64 SSOT lifted into a
/// `uhlc::NTP64` (byte-identical to uhlc's own `system_time_clock`, but
/// routed through wz's single recipe). A plain `fn` so it satisfies
/// `HLCBuilder::with_clock(fn() -> NTP64)`.
#[cfg(feature = "time-hlc")]
fn wz_physical_clock() -> uhlc::NTP64 {
    uhlc::NTP64(crate::storage_service::wall_clock_ntp64())
}

/// Derive a non-zero `uhlc::ID` from the storage `zid`. `uhlc::ID` is 1..=16
/// little-endian bytes and must be non-zero; the storage `zid` is a real,
/// non-empty zid, but clamp to `MAX_SIZE` and guard the all-zero edge so HLC
/// construction never panics.
#[cfg(feature = "time-hlc")]
fn hlc_id_from_zid(zid: &[u8]) -> uhlc::ID {
    let len = zid.len().min(uhlc::ID::MAX_SIZE);
    uhlc::ID::try_from(&zid[..len])
        .unwrap_or_else(|_| uhlc::ID::try_from(&[1u8][..]).expect("constant non-zero id is valid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_stamp_carries_zid_and_real_wall_clock_magnitude() {
        let zid = vec![0xAB, 0xCD];
        let stamper = FallbackStamp::new(zid.clone());
        let ts = stamper.stamp();
        assert_eq!(ts.zid, zid, "the fallback stamp keeps the storage identity");
        // A real NTP64 wall clock has its seconds in the high 32 bits, so the
        // word is >= 2^32 (post-1970 epoch seconds). Guards against a stub
        // source returning a tiny counter value that every real timestamp
        // would dominate under newer-wins.
        assert!(
            ts.time >= (1u64 << 32),
            "the fallback NTP64 carries real wall-clock seconds in the high 32 bits"
        );
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn hlc_stamps_strictly_increase_within_one_physical_instant() {
        // The value the HLC adds over the bare wall clock: successive stamps
        // strictly increase even when called faster than the physical clock
        // ticks (the logical counter in the low CSIZE bits). Guaranteed by the
        // algorithm, so this is zero-flake regardless of host timing.
        let stamper = FallbackStamp::new(vec![0x01]);
        let mut prev = stamper.stamp().time;
        for _ in 0..1000 {
            let next = stamper.stamp().time;
            assert!(
                next > prev,
                "HLC stamp must strictly increase (logical counter): {next} !> {prev}"
            );
            prev = next;
        }
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn hlc_stamp_keeps_storage_zid_not_hlc_internal_id() {
        // The stamp's zid is the storage identity (unchanged from the
        // wall-clock path); the HLC only upgrades the TIME word.
        let zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let stamper = FallbackStamp::new(zid.clone());
        assert_eq!(stamper.stamp().zid, zid);
    }
}
