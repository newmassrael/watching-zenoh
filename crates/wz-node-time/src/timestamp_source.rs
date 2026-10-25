// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xt / R311xw — §5.18 time: the AP-side wall-clock NTP64 source
//! ([`wall_clock_ntp64`]), the timestamp source-selection seam
//! ([`FallbackStamp`]), and the optional Hybrid Logical Clock source
//! (`time-hlc`).
//!
//! This is the AP/std home of the §5.18 time primitives. The runtime-agnostic
//! no_std core owns the timestamp TYPE ([`wz_session_core::sample::TimestampHint`])
//! and the source INJECTION point
//! (`wz_session_core::storage_state::StorageState::apply_sample`
//! takes the stamp as a `FnOnce`); only the concrete source IMPLEMENTATION
//! lives here, std-side, where its physical clock ([`std::time::SystemTime`])
//! and its consumers (the storage service of the tokio runtime, the advanced
//! publisher) live. (`wz-runtime-core`'s
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
//! - `time-hlc` (active, the `time-hlc` feature): the `uhlc::HLC` variant
//!   of the stamper, the wz mirror of zenoh's `Option<Arc<HLC>>`
//!   (`zenoh/src/net/runtime/mod.rs:147`, an HLC created when `timestamping`
//!   is enabled). wz reuses the `uhlc` crate verbatim — the SSOT for the
//!   subtle logical-counter-in-low-`uhlc::CSIZE`-bits + drift + Timestamp
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
//! storage service's module note in the tokio runtime). The HLC's
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
//! `uhlc::HLC`s deriving the SAME `uhlc::ID` from the same node zid with
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
//! the plain `Session::publish` path of the tokio runtime
//! (`zenoh api/session.rs:2129`). wz publishers carry a timestamp only when the
//! caller sets one, so there is no un-timestamped publish to feed.

use wz_session_core::ntp64::Ntp64;
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
/// Hot-era upper bound (the replication service of the tokio runtime), and the
/// aligner answer `now` (its aligner service) all read it, so
/// a downstream consumer seeding a
/// `wz_session_core::storage_state::StorageState` (or the
/// two-replica convergence e2e) shares the SAME recipe rather than a
/// re-derived duplicate.
pub fn wall_clock_ntp64() -> u64 {
    use wz_session_core::epoch::EpochSource;
    // A clock set before 1970 reads as the epoch itself, as it always has here.
    SystemEpoch
        .try_now_ntp64()
        .unwrap_or(Ntp64::from_unix(0, 0))
        .as_word()
}

/// R2914 — this profile's [`EpochSource`](wz_session_core::epoch::EpochSource):
/// `std::time::SystemTime` since `UNIX_EPOCH`. The AP's wall clock goes through
/// the same port the MCU profiles implement (`FreertosEpoch`), so "what time is
/// it" has one shape on every profile. A system clock set before 1970 is
/// [`EpochUnavailable`](wz_session_core::epoch::EpochUnavailable).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEpoch;

impl wz_session_core::epoch::EpochSource for SystemEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| wz_session_core::epoch::EpochUnavailable)?;
        Ok(wz_session_core::epoch::SinceEpoch {
            secs: since.as_secs(),
            nanos: since.subsec_nanos(),
        })
    }
}

/// The same wall clock as [`wall_clock_ntp64`], in plain milliseconds since
/// the UNIX epoch — the unit a replication INTERVAL BOUNDARY is defined in.
///
/// Its one consumer is the digest publisher's start-up alignment
/// (`wz_session_core::storage_replication::ReplicationConfig::alignment_delay_ms`,
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
/// worker threads): the `time-hlc` variant holds a `uhlc::HLC` whose
/// interior `last_time` is a `spin::Mutex` (so `&self` generation is
/// thread-safe), the `time-hlc`-off variant holds only the `zid`. Held by
/// value (single owner — the one capture closure; not shared / cloned, so no
/// `Arc`).
///
/// Public since the seam left the tokio runtime: the runtime's storage service and the
/// advanced publisher of every engine build one, so it is no longer private to a crate.
pub struct FallbackStamp {
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

impl FallbackStamp {
    /// Build the fallback source for a consumer whose identity is `zid`,
    /// borrowing this node's clock.
    ///
    /// R311y450 — `node_hlc` is a parameter rather than something this
    /// constructor derives, and that is the whole fix: the previous signature
    /// took only `zid` and built an HLC from it, so every call site silently
    /// minted another clock with the same `uhlc::ID`. Pass a clone of the ONE
    /// [`NodeHlc`](crate::node_clock::NodeHlc) the node built.
    pub fn new(zid: Vec<u8>, node_hlc: crate::node_clock::NodeHlc) -> Self {
        Self { zid, node_hlc }
    }

    /// Produce a fallback [`TimestampHint`] for an un-timestamped sample: the
    /// source-selected NTP64 time word paired with THIS consumer's `zid`.
    ///
    /// The node clock's own stamp carries the NODE zid; only its time word is
    /// taken here, so a source switch never moves the newer-wins tie-breaker
    /// (the contract stated in the module note).
    pub fn stamp(&self) -> TimestampHint {
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
mod tests;
