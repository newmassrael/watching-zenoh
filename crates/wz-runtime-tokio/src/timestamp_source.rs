// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xt / R311xw — §5.18 time: the AP-side wall-clock NTP64 source
//! ([`wall_clock_ntp64`]), the timestamp source-selection seam
//! ([`FallbackStamp`]), and the optional Hybrid Logical Clock source
//! (`time-hlc`).
//!
//! This is the AP/std home of the §5.18 time primitives. The runtime-agnostic
//! no_std core owns the timestamp TYPE ([`wz_session_core::sample::TimestampHint`])
//! and the source INJECTION point
//! ([`apply_sample`](wz_session_core::storage_state::StorageState::apply_sample)
//! takes the stamp as a `FnOnce`); only the concrete source IMPLEMENTATION
//! lives here, std-side, where its physical clock ([`std::time::SystemTime`])
//! and its sole consumer ([`crate::storage_service`]) live. (`wz-runtime-core`'s
//! `TimeSource` trait is the no_std MONOTONIC clock for timeouts/scheduling and
//! deliberately excludes the wall clock — a distinct axis from this NTP64
//! sample-timestamp source.)
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
//!   `Ord` algorithm is upstream, not a wz copy — and injects
//!   [`wall_clock_ntp64`] as the HLC's physical clock
//!   (`HLCBuilder::with_clock`). So the HLC WRAPS the wall-clock source (it
//!   is not an alternative to it: the system clock is the HLC's physical
//!   layer, the uhlc/zenoh model), and an HLC stamp keeps the same NTP64
//!   magnitude the rest of the storage stack (digest / aligner) uses.
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
//!
//! ## Scope: the HLC is per-storage, not yet node-wide (R311xw disclosure)
//!
//! [`FallbackStamp::new`] builds a fresh HLC per storage. zenoh keeps ONE
//! `Arc<HLC>` on the Runtime, shared by every publish / router / storage on
//! the node, so its "unique across the system" guarantee is node-wide. wz's
//! per-storage HLC delivers that guarantee WITHIN one storage (the common
//! single-storage-per-node deployment), but two storages on the SAME node
//! could stamp two simultaneous un-timestamped samples with the same
//! `(time, zid)`. This is acceptable while storage is the only auto-stamp
//! consumer; the textbook resolution is NOT to grow node-wide HLC
//! infrastructure for a single consumer (premature abstraction) but to
//! promote the HLC to a single session/runtime-scoped `Option<Arc<HLC>>`
//! (zenoh's shape) WHEN the second consumer — publish auto-stamp
//! (`zenoh api/session.rs:2129`) — lands, at which point the storage stamper
//! borrows the shared node HLC instead of building its own. Until then, a
//! single node HLC would have exactly one consumer.

use wz_session_core::sample::TimestampHint;

/// A wall-clock NTP64 timestamp word: `(unix_seconds << 32) | fraction`,
/// the same NTP64 layout uhlc / a publisher's `Timestamp` carries
/// (fraction = `subsec_nanos * 2^32 / 1e9`) — byte-identical to uhlc's
/// `system_time_clock` for any post-epoch instant. The fallback stamp for
/// an un-timestamped sample — a value of the same magnitude as a real
/// publisher timestamp, so it competes fairly under newer-wins instead of
/// being dominated by every real NTP64. By itself NOT an HLC (no logical
/// counter, not guaranteed monotonic across NTP steps); the `time-hlc`
/// source wraps it for that.
///
/// `pub` because it is the wall-clock NTP64 SSOT for the storage stack: the
/// fallback stamp ([`FallbackStamp`]), the digest publisher / subscriber
/// Hot-era upper bound ([`crate::storage_replication_service`]), and the
/// aligner answer `now` ([`crate::storage_aligner_service`]) all read it, so
/// a downstream consumer seeding a
/// [`StorageState`](wz_session_core::storage_state::StorageState) (or the
/// two-replica convergence e2e) shares the SAME recipe rather than a
/// re-derived duplicate.
pub fn wall_clock_ntp64() -> u64 {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();
    let frac = (u64::from(since_epoch.subsec_nanos()) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// The fallback timestamp source for an un-timestamped sample: the seam that
/// selects HOW the stamp's time word is produced. Constructed once per
/// storage (over the storage's `zid`) and called on every captured
/// un-timestamped sample.
///
/// `Send + Sync` (the session may fire the capture callback from different
/// worker threads): the `time-hlc` variant holds a [`uhlc::HLC`] whose
/// interior `last_time` is a `spin::Mutex` (so `&self` generation is
/// thread-safe), the `time-hlc`-off variant holds only the `zid`. Held by
/// value (single owner — the one capture closure; not shared / cloned, so no
/// `Arc`).
pub(crate) struct FallbackStamp {
    /// The storage's identity, attached to every fallback stamp as the `zid`
    /// tie-breaker — identical across both source variants, so the source
    /// choice only upgrades the TIME word, never the identity.
    zid: Vec<u8>,
    /// The Hybrid Logical Clock source. Present only with `time-hlc`; wraps
    /// the [`wall_clock_ntp64`] physical clock (injected at construction).
    #[cfg(feature = "time-hlc")]
    hlc: uhlc::HLC,
}

impl FallbackStamp {
    /// Build the fallback source for a storage whose identity is `zid`. With
    /// `time-hlc` on this also constructs the HLC (id derived from `zid`,
    /// physical clock = [`wall_clock_ntp64`]).
    pub(crate) fn new(zid: Vec<u8>) -> Self {
        #[cfg(feature = "time-hlc")]
        {
            let hlc = build_hlc(&zid);
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

    /// Bare wall-clock source: the [`wall_clock_ntp64`] SSOT (byte-identical
    /// to the pre-HLC behavior).
    #[cfg(not(feature = "time-hlc"))]
    fn now_word(&self) -> u64 {
        wall_clock_ntp64()
    }
}

/// Construct an HLC whose physical clock is [`wall_clock_ntp64`] (so the HLC
/// wraps the same source the digest / aligner read) and whose id is derived
/// from the storage `zid`. The default 500ms drift bound and the `CSIZE`-bit
/// logical counter come from `uhlc`.
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
    uhlc::NTP64(wall_clock_ntp64())
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

    #[test]
    fn wall_clock_ntp64_is_a_real_post_epoch_ntp64() {
        // The moved SSOT still produces a post-epoch NTP64 (seconds in the
        // high 32 bits), in BOTH feature configs (this test is not gated).
        assert!(wall_clock_ntp64() >= (1u64 << 32));
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn hlc_stamps_are_strictly_increasing() {
        // The observable FallbackStamp contract under `time-hlc`: successive
        // stamps strictly increase. Guaranteed by the HLC algorithm, so this
        // is zero-flake regardless of host timing. (This tests the contract,
        // not which branch provides it — see the frozen-clock test below for
        // the logical-counter isolation.)
        let stamper = FallbackStamp::new(vec![0x01]);
        let mut prev = stamper.stamp().time;
        for _ in 0..1000 {
            let next = stamper.stamp().time;
            assert!(
                next > prev,
                "HLC stamp must strictly increase: {next} !> {prev}"
            );
            prev = next;
        }
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn hlc_logical_counter_advances_when_physical_clock_is_frozen() {
        // Isolate the logical counter: with a FROZEN physical clock, the only
        // way successive timestamps can strictly increase is the low-CSIZE-bit
        // counter (the `else { last_time += 1 }` branch). This proves the
        // counter specifically, which the observable-contract test above
        // cannot (its real clock may always advance).
        fn frozen_clock() -> uhlc::NTP64 {
            uhlc::NTP64(0x0000_1234_0000_0000)
        }
        let hlc = uhlc::HLCBuilder::new()
            .with_clock(frozen_clock)
            .with_id(hlc_id_from_zid(&[0x01]))
            .build();
        let mut prev = hlc.new_timestamp().get_time().as_u64();
        for _ in 0..16 {
            let next = hlc.new_timestamp().get_time().as_u64();
            assert!(
                next > prev,
                "with the physical clock frozen, the logical counter must still advance: {next} !> {prev}"
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
