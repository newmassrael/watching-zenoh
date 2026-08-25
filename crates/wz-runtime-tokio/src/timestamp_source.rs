// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ## Scope: the HLC is node-wide (R311y450 — the R311xw disclosure, CLOSED)
//!
//! Until R311y450 [`FallbackStamp::new`] built a FRESH HLC per consumer, and the
//! disclosure that stood here recorded the resulting collision window as
//! hypothetical ("two storages on the SAME node could…") while deferring the fix
//! until a second auto-stamp consumer landed. It had already landed: R311y69 gave
//! `ext-pubsub-advanced-publisher` its own `FallbackStamp`, so a build with
//! `time-hlc,ext-pubsub-advanced-publisher` really did hold TWO independent
//! [`uhlc::HLC`]s deriving the SAME `uhlc::ID` from the same node zid with
//! SEPARATE `last_time` — the reachable form of that hazard, and uhlc's
//! "unique across the system" premise does not survive it.
//!
//! The promotion the disclosure prescribed is now done, in zenoh's shape: ONE
//! [`NodeHlc`](crate::node_clock::NodeHlc) per node (`Option<Arc<HLC>>`,
//! role-gated — `zenoh/src/net/runtime/mod.rs:147`), and this stamper BORROWS it
//! rather than constructing anything. `None` — a node whose role does not
//! timestamp, or a build without `time-hlc` — resolves to [`wall_clock_ntp64`],
//! which is precisely zenoh's own `None` arm for the same decision
//! (`Session::new_timestamp`, `zenoh/src/api/session.rs:833-843`).
//!
//! Still OUT of scope, and still for the R311xw reason: a publish auto-stamp on
//! the plain [`Session::publish`](crate::session::Session::publish) path
//! (`zenoh api/session.rs:2129`). wz publishers carry a timestamp only when the
//! caller sets one, so there is no un-timestamped publish to feed.

use wz_session_core::ntp64::Ntp64;
// `TimestampHint` is used only by the gated `FallbackStamp` stamp seam (the
// cache `_time` consumer reads only `wall_clock_ntp64`), so the import carries
// the same consumer gate to stay clean under `ext-pubsub-advanced-cache` alone.
#[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
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
    Ntp64::from_unix(since_epoch.as_secs(), since_epoch.subsec_nanos()).as_word()
}

/// The same wall clock as [`wall_clock_ntp64`], in plain milliseconds since
/// the UNIX epoch — the unit a replication INTERVAL BOUNDARY is defined in.
///
/// Its one consumer is the digest publisher's start-up alignment
/// ([`ReplicationConfig::alignment_delay_ms`](wz_session_core::storage_replication::ReplicationConfig::alignment_delay_ms),
/// zenoh `Configuration::last_elapsed_interval`, configuration.rs:113-120),
/// which needs an epoch every replica in the fleet agrees on. A monotonic
/// reading cannot serve: two replicas' monotonic epochs are their own start
/// times, so aligning against one would de-align the fleet.
///
/// Kept here, beside its NTP64 sibling, rather than derived from it: both are
/// the same `SystemTime::now()` recipe in different units, and going through
/// NTP64 would route an exact millisecond count through a fraction conversion
/// that only exists to match uhlc.
pub fn wall_clock_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
///
/// R311y98 — gated on the auto-stamp CONSUMERS (`storage-backend` /
/// `ext-pubsub-advanced-publisher`), not on the wider module gate: the advanced
/// cache's `_time` filter (`ext-pubsub-advanced-cache`) reads only the
/// [`wall_clock_ntp64`] SSOT above and never constructs the stamp seam, so this
/// stays with its real consumers. (`time-hlc` implies `storage-backend`, so the
/// HLC variant + helpers below are always live when compiled.)
#[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
pub(crate) struct FallbackStamp {
    /// The consumer's identity, attached to every fallback stamp as the `zid`
    /// tie-breaker — identical across both source variants, so the source
    /// choice only upgrades the TIME word, never the identity.
    zid: Vec<u8>,
    /// The BORROWED node clock (R311y450). Not owned and not constructed here:
    /// one clock per node, `Arc`-shared with every other consumer, so two
    /// consumers on one node cannot mint colliding `(time, zid)` pairs. `None`
    /// inside — a role that does not timestamp, or a build without `time-hlc` —
    /// falls this stamper back to [`wall_clock_ntp64`]. Zero-sized without
    /// `time-hlc`, which is why the field carries no cfg.
    node_hlc: crate::node_clock::NodeHlc,
}

#[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
impl FallbackStamp {
    /// Build the fallback source for a consumer whose identity is `zid`,
    /// borrowing this node's clock.
    ///
    /// R311y450 — `node_hlc` is a parameter rather than something this
    /// constructor derives, and that is the whole fix: the previous signature
    /// took only `zid` and built an HLC from it, so every call site silently
    /// minted another clock with the same `uhlc::ID`. Pass a clone of the ONE
    /// [`NodeHlc`](crate::node_clock::NodeHlc) the node built.
    pub(crate) fn new(zid: Vec<u8>, node_hlc: crate::node_clock::NodeHlc) -> Self {
        Self { zid, node_hlc }
    }

    /// Produce a fallback [`TimestampHint`] for an un-timestamped sample: the
    /// source-selected NTP64 time word paired with THIS consumer's `zid`.
    ///
    /// The node clock's own stamp carries the NODE zid; only its time word is
    /// taken here, so a source switch never moves the newer-wins tie-breaker
    /// (the contract stated in the module note).
    pub(crate) fn stamp(&self) -> TimestampHint {
        TimestampHint {
            time: self
                .node_hlc
                .stamp()
                .map_or_else(wall_clock_ntp64, |stamp| stamp.time),
            zid: self.zid.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
    use crate::node_clock::{NodeHlc, TimestampingEnabled};
    #[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
    use wz_codecs::whatami::WhatAmI;

    /// A node clock that DOES stamp, whatever the feature set — the fixture for
    /// the HLC-path tests. On a build without `time-hlc` this is still a
    /// non-stamping ZST, which is why every test that asserts HLC behaviour
    /// carries the feature gate.
    #[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
    fn stamping_node(zid: &[u8]) -> NodeHlc {
        NodeHlc::for_node(zid, WhatAmI::Router, TimestampingEnabled::default())
    }

    #[cfg(any(feature = "storage-backend", feature = "ext-pubsub-advanced-publisher"))]
    #[test]
    fn fallback_stamp_carries_zid_and_real_wall_clock_magnitude() {
        let zid = vec![0xAB, 0xCD];
        let stamper = FallbackStamp::new(zid.clone(), stamping_node(&zid));
        let ts = stamper.stamp();
        assert_eq!(ts.zid, zid, "the fallback stamp keeps the storage identity");
        // A real NTP64 wall clock has its seconds in the high 32 bits, so the
        // word is >= 2^32 (post-1970 epoch seconds). Guards against a stub
        // source returning a tiny counter value that every real timestamp
        // would dominate under newer-wins.
        assert!(
            ts.time >= Ntp64::FRAC_PER_SEC,
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
        // not which branch provides it — `node_clock`'s frozen-clock test
        // isolates the logical counter, which a real clock cannot.)
        let stamper = FallbackStamp::new(vec![0x01], stamping_node(&[0x01]));
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
    fn the_stamp_zid_is_the_consumers_not_the_node_clocks() {
        // R311y450 — this now DISCRIMINATES rather than restating the obvious.
        // Before the node clock the stamper derived its HLC id from the very
        // zid it stamped with, so the two could not disagree and the assertion
        // held for free. The clock's identity is now a SEPARATE input, so
        // handing it a DIFFERENT zid makes the test fail if the stamp ever
        // starts carrying the clock's id instead of the consumer's — which
        // would silently move the newer-wins tie-breaker.
        let consumer_zid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let node_zid = [0x11, 0x22];
        assert_ne!(
            consumer_zid.as_slice(),
            node_zid.as_slice(),
            "the fixture only discriminates while the two identities differ"
        );
        let stamper = FallbackStamp::new(consumer_zid.clone(), stamping_node(&node_zid));
        assert_eq!(stamper.stamp().zid, consumer_zid);
    }

    #[cfg(feature = "time-hlc")]
    #[test]
    fn a_non_stamping_node_falls_the_stamper_back_to_the_wall_clock() {
        // The role gate reaching this stamper: with `time-hlc` COMPILED but the
        // node's role not timestamping (zenoh's peer/client default), the stamp
        // must still be a real post-epoch NTP64 — zenoh's
        // `Session::new_timestamp()` `None` arm, not a zero or a bare counter
        // that every real timestamp would dominate under newer-wins.
        let zid = vec![0x0F];
        let off = NodeHlc::for_node(&zid, WhatAmI::Peer, TimestampingEnabled::default());
        assert!(!off.is_stamping(), "the zenoh default gates a peer off");
        let stamper = FallbackStamp::new(zid.clone(), off);
        let ts = stamper.stamp();
        assert_eq!(ts.zid, zid);
        assert!(ts.time >= Ntp64::FRAC_PER_SEC);
    }
}
