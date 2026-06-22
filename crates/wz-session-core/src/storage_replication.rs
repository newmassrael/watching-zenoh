// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311vh — the storage-replication *primitives* atom (§5.11 storage
//! domain, replication 1/N): the fingerprint type, the time-bucket
//! classification, the configuration fingerprint, and the per-event
//! fingerprint a replication Digest is assembled from. Pure no_std logic —
//! no Digest assembly yet (the next atom), no Session, no async.
//!
//! ## What replication is
//!
//! Two storages active on the same key_expr are *replicas*. To converge
//! without shipping their whole contents, each periodically publishes a
//! compact **Digest** — a set of XOR-rolled [`Fingerprint`]s bucketed by
//! event time — and, on receiving a peer's Digest, computes which time
//! buckets differ. Only the differing buckets are then aligned (the aligner
//! track). This atom lands the bottom layer the Digest is built from: the
//! fingerprint, the time → bucket classification, and the two hashes
//! (configuration + event).
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0
//! `plugins/zenoh-plugin-storage-manager/src/replication/`:
//!
//! - [`Fingerprint`] = `digest::Fingerprint` (digest.rs:27-57): a 64-bit
//!   xxh3 hash composed with XOR. XOR is associative and commutative, so a
//!   bucket's fingerprint is independent of insertion order and can be
//!   maintained incrementally (insert and remove are both a single XOR).
//! - [`IntervalIdx`] / [`SubIntervalIdx`] = `classification::IntervalIdx` /
//!   `SubIntervalIdx` (classification.rs:57-84, :280-282): the two-level
//!   time-bucket coordinates.
//! - [`ReplicationConfig`] = the digest-relevant subset of
//!   `zenoh-backend-traits` `ReplicaConfig` (config.rs:73-78) wrapped by the
//!   plugin's `Configuration` (configuration.rs:38-44).
//! - [`ReplicationConfig::fingerprint`] = `Configuration::new`'s hash
//!   (configuration.rs:63-78): the config-compatibility gate. Replicas on
//!   different key_expr subsets or interval shapes get different
//!   fingerprints and never exchange Digests.
//! - [`ReplicationConfig::classify`] =
//!   `Configuration::get_time_classification` (configuration.rs:193-220):
//!   millisecond-since-epoch integer division into (interval, sub-interval).
//! - [`event_fingerprint`] = `Event::compute_fingerprint` (log.rs:232-244):
//!   xxh3 over the stored key, the timestamp's NTP64 time, and the 16-byte
//!   id.
//!
//! ## Wire fidelity (interop with a real zenoh replica)
//!
//! The hashes here are byte-exact with zenoh, so a wz replica and a zenoh
//! `zenoh-plugin-storage-manager` replica compute identical fingerprints for
//! identical data — the prerequisite for the two to ever agree their digests
//! match:
//!
//! - same hash crate and algorithm (`xxhash_rust::xxh3`, digest.rs:24);
//! - the configuration fingerprint hashes the same fields in the same order
//!   with the same little-endian widths (configuration.rs:64-72): key_expr
//!   bytes, optional prefix bytes, `interval_ms` as a `u128`, `sub_intervals`
//!   as 8 bytes, `hot` / `warm` as `u64`, `propagation_delay_ms` as a `u128`;
//! - the event fingerprint hashes the key bytes, the NTP64 `time` as 8 LE
//!   bytes (`timestamp.get_time().0.to_le_bytes()`, log.rs:240), and the zid
//!   as the **full 16-byte zero-padded LE array** uhlc's `ID::to_le_bytes`
//!   produces (id.rs:84) — the same array
//!   [`crate::storage_state::timestamp_strictly_newer`] orders on (shared via
//!   `storage_state::zid_to_le_array`), so "newer" agrees across the two
//!   subsystems;
//! - the classification reproduces uhlc's `NTP64 -> Duration -> millis`
//!   conversion bit-for-bit (see [`ntp64_to_ms`]), so an event lands in the
//!   same bucket on both replicas.
//!
//! ## Deliberate divergences (each documented)
//!
//! - **No `strip_prefix` yet.** wz carries no `strip_prefix`
//!   ([`crate::storage_backend`] divergence note), so the stored key is
//!   always the full keyexpr and is always hashed. zenoh hashes the
//!   *stripped* key and omits it entirely when the strip matched exactly
//!   (log.rs:237). The fingerprints therefore match a zenoh replica
//!   configured with no `strip_prefix` (stripped == full); `strip_prefix`
//!   parity is a later storage-config atom.
//! - **`sub_intervals` width pinned to 8 bytes.** zenoh's `sub_intervals` is
//!   a `usize`, so its hashed width is the platform pointer width (8 bytes
//!   on the 64-bit AP interop target). wz stores it as a `u64` so the hash
//!   is 8 bytes regardless of the kernel's pointer width — identical to
//!   64-bit zenoh, the interop target.
//! - **Explicit accessors instead of `Deref<Target = u64>`.** zenoh's
//!   newtypes `Deref` to `u64`; wz exposes [`Fingerprint::value`] /
//!   [`IntervalIdx::value`] / [`SubIntervalIdx::value`] instead, reserving
//!   `Deref` for smart-pointer-like types. Same data, idiomatic surface.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;

use xxhash_rust::xxh3::Xxh3;

use crate::sample::TimestampHint;
use crate::storage_state::zid_to_le_array;

/// A 64-bit fingerprint of the content it represents. zenoh
/// `digest::Fingerprint` (digest.rs:27-57).
///
/// Composition is XOR ([`BitXor`](core::ops::BitXor) /
/// [`BitXorAssign`](core::ops::BitXorAssign)): a bucket's fingerprint is the
/// XOR of the fingerprints it contains. XOR is associative and commutative,
/// so the result is independent of insertion order and a fingerprint can be
/// maintained incrementally — inserting and removing an event are both a
/// single XOR of its [`event_fingerprint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Default)]
#[repr(transparent)]
pub struct Fingerprint(pub(crate) u64);

impl Fingerprint {
    /// The raw 64-bit hash value (zenoh exposes this via `Deref<u64>`).
    pub fn value(self) -> u64 {
        self.0
    }
}

impl core::ops::BitXor for Fingerprint {
    type Output = Fingerprint;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Fingerprint(self.0 ^ rhs.0)
    }
}

impl core::ops::BitXorAssign for Fingerprint {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl From<u64> for Fingerprint {
    fn from(value: u64) -> Self {
        Fingerprint(value)
    }
}

/// The index of an `Interval` — the coarse time bucket. zenoh
/// `classification::IntervalIdx` (classification.rs:57-84).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct IntervalIdx(pub(crate) u64);

impl IntervalIdx {
    /// The raw index value.
    pub fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for IntervalIdx {
    fn from(value: u64) -> Self {
        IntervalIdx(value)
    }
}

/// The index of a `SubInterval` within its [`Interval`] — the fine time
/// bucket. zenoh `classification::SubIntervalIdx` (classification.rs:280-282).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct SubIntervalIdx(pub(crate) u64);

impl SubIntervalIdx {
    /// The raw index value.
    pub fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for SubIntervalIdx {
    fn from(value: u64) -> Self {
        SubIntervalIdx(value)
    }
}

/// The digest-relevant replication configuration plus its compatibility
/// [`Fingerprint`]. zenoh `ReplicaConfig` (config.rs:73-78) wrapped by the
/// plugin `Configuration` (configuration.rs:38-44).
///
/// The `fingerprint` is computed once at construction and gates digest
/// exchange: two replicas only ever compare digests whose
/// `configuration_fingerprint` matches, so replicas active on different
/// key_expr subsets or with different interval shapes never interact.
///
/// # Invariants
///
/// `sub_intervals >= 1` and `interval_ms >= sub_intervals` (so the
/// sub-interval width `interval_ms / sub_intervals` is at least 1ms).
/// [`classify`](ReplicationConfig::classify) divides by that width; a zero
/// width panics, exactly as zenoh's `get_time_classification`
/// (configuration.rs:212-213) would. [`defaults`](ReplicationConfig::defaults)
/// satisfies both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationConfig {
    storage_key_expr: String,
    prefix: Option<String>,
    interval_ms: u64,
    sub_intervals: u64,
    hot: u64,
    warm: u64,
    propagation_delay_ms: u64,
    fingerprint: Fingerprint,
}

impl ReplicationConfig {
    /// Builds a [`ReplicationConfig`] and computes its [`Fingerprint`].
    ///
    /// The fingerprint hashes, in this exact order and width, mirroring
    /// zenoh `Configuration::new` (configuration.rs:64-72): the
    /// `storage_key_expr` bytes, the optional `prefix` bytes, `interval_ms`
    /// as a little-endian `u128`, `sub_intervals` as a little-endian `u64`
    /// (zenoh's `usize` on the 64-bit interop target), `hot` and `warm` as
    /// little-endian `u64`, and `propagation_delay_ms` as a little-endian
    /// `u128`.
    pub fn new(
        storage_key_expr: impl Into<String>,
        prefix: Option<String>,
        interval_ms: u64,
        sub_intervals: u64,
        hot: u64,
        warm: u64,
        propagation_delay_ms: u64,
    ) -> Self {
        let storage_key_expr = storage_key_expr.into();

        let mut hasher = Xxh3::default();
        hasher.update(storage_key_expr.as_bytes());
        if let Some(prefix) = &prefix {
            hasher.update(prefix.as_bytes());
        }
        // zenoh: `interval.as_millis()` is a u128 (16 LE bytes),
        // `propagation_delay.as_millis()` likewise (configuration.rs:68,72).
        hasher.update(&(interval_ms as u128).to_le_bytes());
        hasher.update(&sub_intervals.to_le_bytes());
        hasher.update(&hot.to_le_bytes());
        hasher.update(&warm.to_le_bytes());
        hasher.update(&(propagation_delay_ms as u128).to_le_bytes());
        let fingerprint = Fingerprint::from(hasher.digest());

        Self {
            storage_key_expr,
            prefix,
            interval_ms,
            sub_intervals,
            hot,
            warm,
            propagation_delay_ms,
            fingerprint,
        }
    }

    /// A [`ReplicationConfig`] with zenoh's default replica parameters for
    /// the given `storage_key_expr`, no prefix. zenoh `ReplicaConfig`
    /// defaults (`zenoh-backend-traits/src/config.rs:92-150`): 10s interval,
    /// 5 sub-intervals, 6 hot, 30 warm, 250ms propagation delay.
    pub fn defaults(storage_key_expr: impl Into<String>) -> Self {
        Self::new(storage_key_expr, None, 10_000, 5, 6, 30, 250)
    }

    /// The configuration compatibility [`Fingerprint`] (zenoh
    /// `Configuration::fingerprint`, configuration.rs:94-96).
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The storage key_expr this replica is active on.
    pub fn storage_key_expr(&self) -> &str {
        &self.storage_key_expr
    }

    /// The `strip_prefix`, if configured (zenoh `Configuration::prefix`,
    /// configuration.rs:87-89). wz does not yet strip; this is carried for
    /// fingerprint parity.
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    /// The interval (coarse bucket) width in milliseconds.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// The number of equal sub-intervals (fine buckets) per interval.
    pub fn sub_intervals(&self) -> u64 {
        self.sub_intervals
    }

    /// The number of intervals in the Hot era.
    pub fn hot(&self) -> u64 {
        self.hot
    }

    /// The number of intervals in the Warm era.
    pub fn warm(&self) -> u64 {
        self.warm
    }

    /// The propagation delay in milliseconds.
    pub fn propagation_delay_ms(&self) -> u64 {
        self.propagation_delay_ms
    }

    /// Classifies an NTP64 `time` into its `(interval, sub-interval)` bucket.
    /// zenoh `Configuration::get_time_classification`
    /// (configuration.rs:193-220): convert to milliseconds since the epoch,
    /// then `interval = ms / interval_ms` and `sub_interval =
    /// (ms - interval_ms * interval) / (interval_ms / sub_intervals)`.
    ///
    /// # Panics
    ///
    /// Panics if `interval_ms / sub_intervals == 0` (the sub-interval width
    /// is zero) — see the [`ReplicationConfig`] invariants. zenoh's
    /// equivalent divides by the same width and would likewise panic.
    pub fn classify(&self, time: u64) -> (IntervalIdx, SubIntervalIdx) {
        let ms = ntp64_to_ms(time);
        let interval_ms = self.interval_ms as u128;

        let interval = ms / interval_ms;
        let sub_width = interval_ms / self.sub_intervals as u128;
        let sub_interval = (ms - interval_ms * interval) / sub_width;

        (
            IntervalIdx::from(interval as u64),
            SubIntervalIdx::from(sub_interval as u64),
        )
    }

    /// The lowest interval index in the Hot era, given that era's upper
    /// bound. zenoh `Configuration::hot_era_lower_bound`
    /// (configuration.rs:143-145): `hot_upper - hot + 1`.
    ///
    /// Saturating, so a small `hot_era_upper_bound` (early in the epoch, or
    /// a unit test) cannot underflow. zenoh's plain subtraction assumes
    /// epoch-scale indices and would panic below the bound; the two agree
    /// over the entire operating range.
    pub fn hot_era_lower_bound(&self, hot_era_upper_bound: IntervalIdx) -> IntervalIdx {
        IntervalIdx::from(
            hot_era_upper_bound
                .value()
                .saturating_sub(self.hot)
                .saturating_add(1),
        )
    }

    /// The lowest interval index in the Warm era, given the **Hot** era's
    /// upper bound. zenoh `Configuration::warm_era_lower_bound`
    /// (configuration.rs:166-168): `hot_upper - hot - warm + 1` (the
    /// argument is the Hot upper bound, not the Warm one). Saturating, as for
    /// [`hot_era_lower_bound`](ReplicationConfig::hot_era_lower_bound).
    pub fn warm_era_lower_bound(&self, hot_era_upper_bound: IntervalIdx) -> IntervalIdx {
        IntervalIdx::from(
            hot_era_upper_bound
                .value()
                .saturating_sub(self.hot)
                .saturating_sub(self.warm)
                .saturating_add(1),
        )
    }
}

/// Converts an NTP64 `time` to milliseconds since the UNIX epoch,
/// reproducing uhlc's `NTP64::to_duration().as_millis()` exactly.
///
/// An NTP64 packs seconds in the high 32 bits and a fraction-of-a-second (in
/// units of 1/2^32 s) in the low 32 bits (`uhlc-0.8.1/src/ntp64.rs:71`). The
/// conversion mirrors:
/// - `as_secs` = `time >> 32` (ntp64.rs:95);
/// - `subsec_nanos` = `(frac * 1e9).div_ceil(2^32)` (ntp64.rs:109-112) — the
///   `div_ceil` is what makes `NTP64::from(Duration).as_nanos()` round-trip,
///   so reproducing it (not a plain divide) is required to land in the same
///   bucket as zenoh;
/// - `Duration::new(secs, subsec_nanos).as_millis()` = `secs * 1000 +
///   subsec_nanos / 1_000_000`.
///
/// zenoh classifies on this exact value (configuration.rs:197-201), so a wz
/// replica and a zenoh replica bucket the same event identically.
fn ntp64_to_ms(time: u64) -> u128 {
    const FRAC_PER_SEC: u64 = 1u64 << 32;
    const NANO_PER_SEC: u64 = 1_000_000_000;
    const FRAC_MASK: u64 = 0xFFFF_FFFF;

    let secs = (time >> 32) as u128;
    let frac = time & FRAC_MASK;
    // frac < 2^32, so frac * 1e9 < 2^62 — no overflow in u64.
    let subsec_nanos = (frac * NANO_PER_SEC).div_ceil(FRAC_PER_SEC) as u128;

    secs * 1000 + subsec_nanos / 1_000_000
}

/// The [`Fingerprint`] of a single stored event — a `(key, timestamp)` pair.
/// zenoh `Event::compute_fingerprint` (log.rs:232-244).
///
/// Hashes the key bytes, the NTP64 `time` as 8 little-endian bytes
/// (`timestamp.get_time().0.to_le_bytes()`, log.rs:240), and the zid as the
/// 16-byte zero-padded little-endian array (via
/// `storage_state::zid_to_le_array`, matching `timestamp.get_id().to_le_bytes()`,
/// log.rs:241). The action/kind is deliberately *not* hashed — it adds no
/// distinguishing power and hashing it would cost time (log.rs:226-231). The
/// `(key, time, id)` triple is exactly what the newer-wins comparator orders
/// on, so two replicas that hold the same event compute the same fingerprint.
pub fn event_fingerprint(key: &str, timestamp: &TimestampHint) -> Fingerprint {
    let mut hasher = Xxh3::default();
    hasher.update(key.as_bytes());
    hasher.update(&timestamp.time.to_le_bytes());
    hasher.update(&zid_to_le_array(&timestamp.zid));
    Fingerprint::from(hasher.digest())
}

/// A concise, comparable summary of a replica's stored set — XOR-rolled
/// [`Fingerprint`]s bucketed by event time, grouped into three eras of
/// increasing temporal granularity. zenoh `digest::Digest` (digest.rs:77-83).
///
/// Granularity rises with recency, so the diff drill-down (the next atom)
/// localises a divergence cheaply:
/// - **Cold** (oldest): a single [`Fingerprint`] over all cold intervals;
/// - **Warm**: one [`Fingerprint`] per interval;
/// - **Hot** (newest): one [`Fingerprint`] per sub-interval, grouped by
///   interval.
///
/// `configuration_fingerprint` ([`ReplicationConfig::fingerprint`]) is
/// carried so a receiver rejects a digest from an incompatibly-configured
/// replica before comparing anything (the diff short-circuit).
///
/// The maps diverge from zenoh's `HashMap` to `BTreeMap` (the no_std kernel
/// has no std hasher, as elsewhere in wz storage). This is wire-compatible: a
/// length-prefixed map serialises and deserialises independently of entry
/// order, so a `BTreeMap` round-trips a zenoh `HashMap` digest and vice versa
/// (the R4 codec atom).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub(crate) configuration_fingerprint: Fingerprint,
    pub(crate) cold_era_fingerprint: Fingerprint,
    pub(crate) warm_era_fingerprints: BTreeMap<IntervalIdx, Fingerprint>,
    pub(crate) hot_era_fingerprints: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>>,
}

impl Digest {
    /// The configuration compatibility fingerprint (the digest-exchange gate).
    pub fn configuration_fingerprint(&self) -> Fingerprint {
        self.configuration_fingerprint
    }

    /// The single Cold-era fingerprint (XOR of all cold intervals).
    pub fn cold_era_fingerprint(&self) -> Fingerprint {
        self.cold_era_fingerprint
    }

    /// The per-interval Warm-era fingerprints.
    pub fn warm_era_fingerprints(&self) -> &BTreeMap<IntervalIdx, Fingerprint> {
        &self.warm_era_fingerprints
    }

    /// The per-sub-interval Hot-era fingerprints, grouped by interval.
    pub fn hot_era_fingerprints(
        &self,
    ) -> &BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> {
        &self.hot_era_fingerprints
    }

    /// Compares this (local) [`Digest`] against a peer's and returns a
    /// [`DigestDiff`] of what the peer has that this replica differs on or
    /// lacks — or `None` if the two are aligned. zenoh `Digest::diff`
    /// (digest.rs:109-170).
    ///
    /// The comparison is **asymmetric and from `self`'s perspective**: it
    /// surfaces only buckets where `other` differs or holds something `self`
    /// does not. Buckets that `self` has and `other` lacks are *not* reported
    /// here — the peer discovers those when it runs `remote.diff(local)`.
    /// Each replica runs `local.diff(remote)` on a received digest, so
    /// between them every divergence is found exactly once on the side that
    /// must pull (the aligner step).
    ///
    /// Returns `None` immediately if the configuration fingerprints differ
    /// (digest.rs:110-112): the replicas are active on different key_expr
    /// subsets or interval shapes and must never reconcile.
    pub fn diff(&self, mut other: Digest) -> Option<DigestDiff> {
        // Incompatible configurations never compare.
        if self.configuration_fingerprint != other.configuration_fingerprint {
            return None;
        }

        // Hot era (sub-interval granularity): drop from `other` every
        // sub-interval whose fingerprint matches `self`'s for the same
        // (interval, sub-interval). What remains in `other` is what it
        // differs on or holds alone (digest.rs:120-134).
        for (interval_idx, self_subs) in &self.hot_era_fingerprints {
            if let Some(other_subs) = other.hot_era_fingerprints.get_mut(interval_idx) {
                other_subs.retain(|other_idx, other_fp| match self_subs.get(other_idx) {
                    Some(fp) => *other_fp != *fp,
                    None => true,
                });
            }
        }
        other
            .hot_era_fingerprints
            .retain(|_, subs| !subs.is_empty());

        // Warm era (interval granularity): same retain, against `self`'s
        // warm fingerprints (digest.rs:138-145).
        other.warm_era_fingerprints.retain(|other_idx, other_fp| {
            match self.warm_era_fingerprints.get(other_idx) {
                Some(fp) => *other_fp != *fp,
                None => true,
            }
        });

        // Anything left in hot/warm => a real divergence; report it, and fold
        // in whether the cold rollups also differ (digest.rs:147-159).
        if !other.hot_era_fingerprints.is_empty() || !other.warm_era_fingerprints.is_empty() {
            return Some(DigestDiff {
                cold_eras_differ: self.cold_era_fingerprint != other.cold_era_fingerprint,
                warm_eras_differences: other.warm_era_fingerprints.into_keys().collect(),
                hot_eras_differences: other
                    .hot_era_fingerprints
                    .into_iter()
                    .map(|(interval_idx, subs)| (interval_idx, subs.into_keys().collect()))
                    .collect(),
            });
        }

        // Hot/warm aligned; only the cold rollup differs (digest.rs:161-167).
        if self.cold_era_fingerprint != other.cold_era_fingerprint {
            return Some(DigestDiff {
                cold_eras_differ: true,
                warm_eras_differences: BTreeSet::new(),
                hot_eras_differences: BTreeMap::new(),
            });
        }

        None
    }
}

/// The differences between two [`Digest`]s, as seen from the local replica
/// running [`Digest::diff`]. zenoh `digest::DigestDiff` (digest.rs:93-98).
///
/// This is the last digest-track artifact: the typed work-list the aligner
/// (the next track) consumes to pull the diverging entries. For the Cold
/// era a single `bool` (the era is one fingerprint); for the Warm era the
/// set of diverging [`IntervalIdx`]; for the Hot era the diverging
/// [`SubIntervalIdx`]s grouped by [`IntervalIdx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestDiff {
    pub(crate) cold_eras_differ: bool,
    pub(crate) warm_eras_differences: BTreeSet<IntervalIdx>,
    pub(crate) hot_eras_differences: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>>,
}

impl DigestDiff {
    /// Whether the single Cold-era fingerprints differ.
    pub fn cold_eras_differ(&self) -> bool {
        self.cold_eras_differ
    }

    /// The Warm-era intervals that diverge.
    pub fn warm_eras_differences(&self) -> &BTreeSet<IntervalIdx> {
        &self.warm_eras_differences
    }

    /// The Hot-era sub-intervals that diverge, grouped by interval.
    pub fn hot_eras_differences(&self) -> &BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> {
        &self.hot_eras_differences
    }
}

/// Builds the [`Digest`] of a replica's stored set, given the Hot era's upper
/// bound (typically the last elapsed interval). zenoh
/// `LogLatest::digest_from` (log.rs:557-590).
///
/// `events` is the distinct latest `(key, timestamp)` per key — exactly what
/// [`crate::storage_backend::StorageBackend::get_all_entries`] yields. Each
/// event is hashed ([`event_fingerprint`]) and XOR-accumulated into its
/// `(interval, sub-interval)` bucket; the bucket fingerprints then roll up by
/// era:
/// - intervals `< warm_lower` XOR into the single `cold_era_fingerprint`;
/// - intervals in `[warm_lower, hot_lower)` contribute their interval
///   fingerprint to `warm_era_fingerprints`, **only when non-zero**
///   (log.rs:576);
/// - intervals `>= hot_lower` contribute their per-sub-interval fingerprints
///   to `hot_era_fingerprints`, **dropping zero sub-intervals**
///   (`sub_intervals_fingerprints`, classification.rs:161-167).
///
/// Intervals strictly newer than `hot_era_upper_bound` are excluded
/// (log.rs:567), so two replicas comparing against the same upper bound see
/// the same era partition. The non-zero filters are required for digest
/// equality: an absent entry and a zero entry diff differently.
///
/// # Design divergence
///
/// zenoh maintains an incremental `LogLatest` (XOR-updated on every event)
/// and reads the digest off it. wz recomputes the digest from the storage
/// snapshot each publish cycle, so the buckets here are transient and no
/// parallel log is kept. The resulting [`Digest`] is identical — only the
/// computation strategy differs (recompute vs incremental). An incremental
/// log is a throughput optimisation for very large stores, a documented
/// future atom if profiling demands it.
pub fn build_digest<'a>(
    config: &ReplicationConfig,
    events: impl IntoIterator<Item = (&'a str, &'a TimestampHint)>,
    hot_era_upper_bound: IntervalIdx,
) -> Digest {
    // 1. XOR-accumulate every event into its (interval, sub-interval) bucket.
    let mut buckets: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> = BTreeMap::new();
    for (key, timestamp) in events {
        let (interval_idx, sub_interval_idx) = config.classify(timestamp.time);
        let fp = event_fingerprint(key, timestamp);
        *buckets
            .entry(interval_idx)
            .or_default()
            .entry(sub_interval_idx)
            .or_default() ^= fp;
    }

    let hot_lower = config.hot_era_lower_bound(hot_era_upper_bound);
    let warm_lower = config.warm_era_lower_bound(hot_era_upper_bound);

    let mut cold_era_fingerprint = Fingerprint::default();
    let mut warm_era_fingerprints = BTreeMap::new();
    let mut hot_era_fingerprints = BTreeMap::new();

    // 2. Roll bucket fingerprints up by era. The BTreeMap iterates ascending,
    //    so the cheapest comparison (cold — the most and oldest intervals) is
    //    tested first, mirroring zenoh's ordering note (log.rs:569-572).
    for (interval_idx, sub_map) in buckets {
        if interval_idx > hot_era_upper_bound {
            continue; // strictly newer than the hot upper bound (log.rs:567)
        }
        // An interval's fingerprint is the XOR of its sub-interval fingerprints.
        let interval_fp = sub_map
            .values()
            .copied()
            .fold(Fingerprint::default(), |acc, fp| acc ^ fp);

        if interval_idx < warm_lower {
            cold_era_fingerprint ^= interval_fp;
        } else if interval_idx < hot_lower {
            if interval_fp != Fingerprint::default() {
                warm_era_fingerprints.insert(interval_idx, interval_fp);
            }
        } else {
            let subs: BTreeMap<SubIntervalIdx, Fingerprint> = sub_map
                .into_iter()
                .filter(|(_, fp)| *fp != Fingerprint::default())
                .collect();
            hot_era_fingerprints.insert(interval_idx, subs);
        }
    }

    Digest {
        configuration_fingerprint: config.fingerprint(),
        cold_era_fingerprint,
        warm_era_fingerprints,
        hot_era_fingerprints,
    }
}

/// The storage-replication Digest **wire codec** (replication 4/N): byte-exact
/// encode/decode of a [`Digest`] to the format zenoh's replication publishes,
/// isolated here so the single place coupled to zenoh's (un-versioned)
/// serialization can be audited and changed in one spot.
///
/// zenoh serializes the Digest with `bincode` 1.3 default config
/// (core.rs:229-232, deserialize :356): little-endian, fixed-width integers,
/// and `u64` length prefixes for maps. This module reproduces that byte layout
/// by hand instead of depending on the `bincode` crate, because:
///
/// - bincode 1.x is `std::io`-based (std-only) and so cannot live in this
///   no_std kernel, while bincode 2.x's default format differs from 1.x's —
///   neither drops in;
/// - the layout is small and fully specified, so a hand-rolled codec is the
///   explicit, self-documenting SSOT (the wire format is visible here, not
///   hidden behind a dependency's default-config quirk that a version bump
///   could change silently);
/// - it stays dependency-free and unit-testable in no_std, and a future MCU
///   replication driver reuses it.
///
/// A `#[cfg(test)]` cross-check serializes a serde mirror with the actual
/// bincode 1.3 (a dev-dependency) and asserts the bytes match AND that each
/// side reads the other's bytes (both directions), so the hand-rolled format
/// is pinned to the exact library + serde structure zenoh uses.
///
/// Residual (honest scope): a fully LIVE digest exchange with a running
/// `zenoh-plugin-storage-manager` replica is not yet exercised — it needs the
/// plugin provisioned (not in the repo CI harness) and, for actual
/// convergence, the aligner (a replica that diffs wz's digest replies with an
/// alignment query, which wz answers only once the storage-aligner track
/// lands). The byte-level compatibility this module guarantees is the
/// prerequisite; the live exchange is the storage-aligner track's territory.
///
/// ## Byte layout (bincode 1.3 default: LE, fixint, `u64` lengths)
///
/// A newtype struct (`Fingerprint(u64)` etc.) serializes as its inner `u64`
/// (8 LE bytes); a map is a `u64` length then that many key/value pairs; a
/// struct is its fields concatenated in declaration order. So a [`Digest`]:
///
/// ```text
/// configuration_fingerprint : u64
/// cold_era_fingerprint      : u64
/// warm_era_fingerprints     : u64 len, then len * [ IntervalIdx:u64, Fingerprint:u64 ]
/// hot_era_fingerprints      : u64 len, then len * [ IntervalIdx:u64,
///                              (u64 len, then len * [ SubIntervalIdx:u64, Fingerprint:u64 ]) ]
/// ```
///
/// [`encode`](wire::encode) emits the maps in `BTreeMap` (sorted) order, so
/// two wz replicas produce identical bytes. [`decode`](wire::decode) reads a
/// length then that many pairs, so it accepts zenoh's arbitrary `HashMap`
/// order too — the format is order-independent on read, which is what makes
/// wz<->zenoh interop work despite the map-type divergence.
pub mod wire {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use super::{Digest, Fingerprint, IntervalIdx, SubIntervalIdx};

    /// Failure decoding a [`Digest`] from bytes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DigestDecodeError {
        /// The buffer ended before a fixed-width field could be read.
        UnexpectedEof,
        /// A length prefix exceeds the bytes that remain — a corrupt or
        /// hostile buffer. Rejected before allocating or looping.
        LengthOverflow,
        /// Bytes remained after a complete [`Digest`] was decoded.
        TrailingBytes,
    }

    fn push_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    /// Encodes a [`Digest`] to the zenoh bincode wire bytes (deterministic:
    /// maps emit in sorted order).
    pub fn encode(digest: &Digest) -> Vec<u8> {
        let mut out = Vec::new();
        push_u64(&mut out, digest.configuration_fingerprint.value());
        push_u64(&mut out, digest.cold_era_fingerprint.value());

        push_u64(&mut out, digest.warm_era_fingerprints.len() as u64);
        for (idx, fp) in &digest.warm_era_fingerprints {
            push_u64(&mut out, idx.value());
            push_u64(&mut out, fp.value());
        }

        push_u64(&mut out, digest.hot_era_fingerprints.len() as u64);
        for (idx, subs) in &digest.hot_era_fingerprints {
            push_u64(&mut out, idx.value());
            push_u64(&mut out, subs.len() as u64);
            for (sub_idx, fp) in subs {
                push_u64(&mut out, sub_idx.value());
                push_u64(&mut out, fp.value());
            }
        }
        out
    }

    /// A cursor over the input bytes that reads fixed-width little-endian
    /// `u64`s and refuses to read past the end.
    struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn read_u64(&mut self) -> Result<u64, DigestDecodeError> {
            let end = self
                .pos
                .checked_add(8)
                .ok_or(DigestDecodeError::UnexpectedEof)?;
            let slice = self
                .buf
                .get(self.pos..end)
                .ok_or(DigestDecodeError::UnexpectedEof)?;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(slice);
            self.pos = end;
            Ok(u64::from_le_bytes(bytes))
        }

        fn remaining(&self) -> usize {
            self.buf.len() - self.pos
        }
    }

    /// Rejects a map length that could not possibly fit in the bytes that
    /// remain (`len * min_entry_bytes > remaining`, or an overflow), so a
    /// hostile `u64::MAX` length fails fast instead of allocating/looping.
    fn check_len(len: u64, min_entry_bytes: usize, r: &Reader) -> Result<(), DigestDecodeError> {
        match (len as usize).checked_mul(min_entry_bytes) {
            Some(n) if n <= r.remaining() => Ok(()),
            _ => Err(DigestDecodeError::LengthOverflow),
        }
    }

    /// Decodes a [`Digest`] from the zenoh bincode wire bytes. Accepts maps in
    /// any order (zenoh emits `HashMap` order); rejects truncated, oversized,
    /// or trailing-byte buffers.
    pub fn decode(bytes: &[u8]) -> Result<Digest, DigestDecodeError> {
        let mut r = Reader::new(bytes);
        let configuration_fingerprint = Fingerprint::from(r.read_u64()?);
        let cold_era_fingerprint = Fingerprint::from(r.read_u64()?);

        let warm_len = r.read_u64()?;
        check_len(warm_len, 16, &r)?; // each warm entry: IntervalIdx + Fingerprint
        let mut warm_era_fingerprints = BTreeMap::new();
        for _ in 0..warm_len {
            let idx = IntervalIdx::from(r.read_u64()?);
            let fp = Fingerprint::from(r.read_u64()?);
            warm_era_fingerprints.insert(idx, fp);
        }

        let hot_len = r.read_u64()?;
        check_len(hot_len, 16, &r)?; // each hot entry is >= IntervalIdx + a (0) len
        let mut hot_era_fingerprints = BTreeMap::new();
        for _ in 0..hot_len {
            let idx = IntervalIdx::from(r.read_u64()?);
            let sub_len = r.read_u64()?;
            check_len(sub_len, 16, &r)?; // each sub entry: SubIntervalIdx + Fingerprint
            let mut subs = BTreeMap::new();
            for _ in 0..sub_len {
                let sub_idx = SubIntervalIdx::from(r.read_u64()?);
                let fp = Fingerprint::from(r.read_u64()?);
                subs.insert(sub_idx, fp);
            }
            hot_era_fingerprints.insert(idx, subs);
        }

        if r.remaining() != 0 {
            return Err(DigestDecodeError::TrailingBytes);
        }

        Ok(Digest {
            configuration_fingerprint,
            cold_era_fingerprint,
            warm_era_fingerprints,
            hot_era_fingerprints,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::super::{
            build_digest, Fingerprint, IntervalIdx, ReplicationConfig, TimestampHint,
        };
        use super::{decode, encode, DigestDecodeError};
        use alloc::collections::BTreeMap;
        use alloc::vec;
        use alloc::vec::Vec;
        use serde::{Deserialize, Serialize};

        // A serde mirror of zenoh's Digest, serialized with the real bincode
        // 1.3 (dev-dep) to provide byte-compat ground truth. The newtypes are
        // single-field tuple structs, exactly as in zenoh, so serde encodes
        // each as its inner u64 (a newtype_struct).
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Fp(u64);
        #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct Ii(u64);
        #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct Si(u64);
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MirrorDigest {
            configuration_fingerprint: Fp,
            cold_era_fingerprint: Fp,
            warm_era_fingerprints: BTreeMap<Ii, Fp>,
            hot_era_fingerprints: BTreeMap<Ii, BTreeMap<Si, Fp>>,
        }

        fn mirror_of(d: &Digest) -> MirrorDigest {
            MirrorDigest {
                configuration_fingerprint: Fp(d.configuration_fingerprint().value()),
                cold_era_fingerprint: Fp(d.cold_era_fingerprint().value()),
                warm_era_fingerprints: d
                    .warm_era_fingerprints()
                    .iter()
                    .map(|(i, f)| (Ii(i.value()), Fp(f.value())))
                    .collect(),
                hot_era_fingerprints: d
                    .hot_era_fingerprints()
                    .iter()
                    .map(|(i, subs)| {
                        (
                            Ii(i.value()),
                            subs.iter()
                                .map(|(s, f)| (Si(s.value()), Fp(f.value())))
                                .collect(),
                        )
                    })
                    .collect(),
            }
        }

        use super::super::Digest;

        fn ts(time: u64, zid: Vec<u8>) -> TimestampHint {
            TimestampHint { time, zid }
        }

        fn at_secs(secs: u64) -> u64 {
            secs << 32
        }

        fn sample_digest() -> Digest {
            // hot=2, warm=3, hot_upper=10 -> cold<6, warm[6,9), hot>=9.
            let cfg = ReplicationConfig::new("demo/**", None, 10_000, 5, 2, 3, 250);
            let cold = ts(at_secs(35), vec![0x01]); // interval 3 (cold)
            let warm_a = ts(at_secs(71), vec![0x01]); // interval 7 sub 0
            let warm_b = ts(at_secs(85), vec![0x01]); // interval 8 sub 2
            let hot_a = ts(at_secs(94), vec![0x01]); // interval 9 sub 2
            let hot_b = ts(at_secs(98), vec![0x01]); // interval 9 sub 4
            build_digest(
                &cfg,
                [
                    ("demo/a", &cold),
                    ("demo/b", &warm_a),
                    ("demo/c", &warm_b),
                    ("demo/d", &hot_a),
                    ("demo/e", &hot_b),
                ],
                IntervalIdx::from(10),
            )
        }

        /// THE fidelity test: the hand-rolled bytes are byte-identical to what
        /// the real bincode 1.3 (the version + default config zenoh uses)
        /// produces for the same logical Digest — across empty / cold / warm /
        /// hot / multi shapes.
        #[test]
        fn encode_is_byte_identical_to_bincode_1_3() {
            let cfg = ReplicationConfig::new("demo/**", None, 10_000, 5, 2, 3, 250);

            let empty = build_digest(&cfg, [], IntervalIdx::from(10));
            assert_eq!(
                encode(&empty),
                bincode::serialize(&mirror_of(&empty)).unwrap()
            );

            let full = sample_digest();
            assert_eq!(
                encode(&full),
                bincode::serialize(&mirror_of(&full)).unwrap()
            );
        }

        /// R9 cross-impl interop: wz's bytes are READABLE by the exact bincode
        /// 1.3 zenoh deserializes with, AND bytes bincode 1.3 produces are
        /// readable by wz — both directions, not just encode-equality. This is
        /// the strongest cross-impl proof available without provisioning a live
        /// zenoh storage-manager replica (see the module-level residual note):
        /// it pins wz<->zenoh digest wire compatibility to the real lib + the
        /// serde structure of zenoh's `Digest` (digest.rs:77-83).
        #[test]
        fn wz_and_bincode_1_3_read_each_others_digest_bytes() {
            let d = sample_digest();
            let mirror = mirror_of(&d);

            // Direction 1: wz encodes -> zenoh's deserializer reads it.
            let wz_bytes = encode(&d);
            let read_by_zenoh: MirrorDigest =
                bincode::deserialize(&wz_bytes).expect("zenoh's bincode reads wz's bytes");
            assert_eq!(read_by_zenoh, mirror);

            // Direction 2: zenoh encodes -> wz decodes it.
            let zenoh_bytes = bincode::serialize(&mirror).unwrap();
            assert_eq!(decode(&zenoh_bytes), Ok(d));
        }

        #[test]
        fn encode_decode_round_trips() {
            let d = sample_digest();
            assert_eq!(decode(&encode(&d)), Ok(d));
        }

        #[test]
        fn decode_rejects_truncated_buffer() {
            let bytes = encode(&sample_digest());
            // Truncated inside the fixed header -> a field read hits the end.
            assert_eq!(decode(&bytes[..4]), Err(DigestDecodeError::UnexpectedEof));
            // Truncated mid-body -> rejected: the length guard catches the
            // short tail (a declared length no longer fits) before any
            // over-read can happen. Either rejection variant is acceptable;
            // what matters is that a short buffer never panics or over-reads.
            assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        }

        #[test]
        fn decode_rejects_trailing_bytes() {
            let cfg = ReplicationConfig::new("demo/**", None, 10_000, 5, 2, 3, 250);
            let mut bytes = encode(&build_digest(&cfg, [], IntervalIdx::from(10)));
            bytes.push(0xFF);
            assert_eq!(decode(&bytes), Err(DigestDecodeError::TrailingBytes));
        }

        #[test]
        fn decode_rejects_hostile_length() {
            // config(8) + cold(8) + warm_len = u64::MAX -> overflow guard.
            let mut bytes = vec![0u8; 16];
            bytes.extend_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(decode(&bytes), Err(DigestDecodeError::LengthOverflow));
        }

        #[test]
        fn decode_accepts_unsorted_map_order_like_zenoh_hashmap() {
            // Two warm entries written DESCENDING by index, as a HashMap might
            // emit them; decode must still recover both (order-independent).
            let mut b = Vec::new();
            b.extend_from_slice(&0u64.to_le_bytes()); // configuration_fingerprint
            b.extend_from_slice(&0u64.to_le_bytes()); // cold_era_fingerprint
            b.extend_from_slice(&2u64.to_le_bytes()); // warm len
            b.extend_from_slice(&9u64.to_le_bytes()); // idx 9
            b.extend_from_slice(&0xAAu64.to_le_bytes()); // fp
            b.extend_from_slice(&2u64.to_le_bytes()); // idx 2 (out of order)
            b.extend_from_slice(&0xBBu64.to_le_bytes()); // fp
            b.extend_from_slice(&0u64.to_le_bytes()); // hot len 0

            let d = decode(&b).expect("unsorted map decodes");
            assert_eq!(
                d.warm_era_fingerprints().get(&IntervalIdx::from(9)),
                Some(&Fingerprint::from(0xAA))
            );
            assert_eq!(
                d.warm_era_fingerprints().get(&IntervalIdx::from(2)),
                Some(&Fingerprint::from(0xBB))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ts(time: u64, zid: alloc::vec::Vec<u8>) -> TimestampHint {
        TimestampHint { time, zid }
    }

    // -- Fingerprint algebra --------------------------------------------

    #[test]
    fn fingerprint_xor_is_order_independent_and_self_cancelling() {
        let a = Fingerprint::from(0xDEAD_BEEF);
        let b = Fingerprint::from(0x0123_4567_89AB_CDEF);

        // Commutative.
        assert_eq!(a ^ b, b ^ a);
        // Self-cancelling: x ^ x == 0 (the default).
        assert_eq!(a ^ a, Fingerprint::default());
        assert_eq!(Fingerprint::default().value(), 0);
        // Round-trip: (a ^ b) ^ b == a — insert then remove restores.
        assert_eq!((a ^ b) ^ b, a);

        // BitXorAssign matches BitXor.
        let mut acc = a;
        acc ^= b;
        assert_eq!(acc, a ^ b);
    }

    #[test]
    fn fingerprint_value_round_trips_from_u64() {
        let v = 0x1122_3344_5566_7788u64;
        assert_eq!(Fingerprint::from(v).value(), v);
    }

    /// Pins the dependency to canonical xxh3-64 (seed 0): the documented hash
    /// of the empty input. If this drifts, the wrong crate/feature is wired
    /// and every fingerprint silently diverges from zenoh.
    #[test]
    fn xxh3_dependency_is_canonical() {
        let hasher = Xxh3::default();
        assert_eq!(hasher.digest(), 0x2d06_8005_38d3_94c2);
    }

    // -- NTP64 -> ms (classification basis) -----------------------------

    #[test]
    fn ntp64_to_ms_whole_seconds() {
        assert_eq!(ntp64_to_ms(0), 0);
        // 35s, zero fraction.
        assert_eq!(ntp64_to_ms(35u64 << 32), 35_000);
    }

    #[test]
    fn ntp64_to_ms_fraction_is_uhlc_exact() {
        // Exactly half a second: frac = 2^31 -> 500ms.
        assert_eq!(ntp64_to_ms(1u64 << 31), 500);
        // A quarter second: frac = 2^30 -> 250ms.
        assert_eq!(ntp64_to_ms(1u64 << 30), 250);
    }

    // -- classification --------------------------------------------------

    #[test]
    fn classify_buckets_by_integer_division() {
        // interval 10s, 5 sub-intervals -> 2s sub-width.
        let cfg = ReplicationConfig::defaults("demo/**");
        // 35_000ms -> interval 3 (35000/10000), remainder 5000 -> sub 2
        // (5000/2000).
        let (i, s) = cfg.classify(35u64 << 32);
        assert_eq!((i.value(), s.value()), (3, 2));

        // 12_000ms -> interval 1, remainder 2000 -> sub 1.
        let (i, s) = cfg.classify(12u64 << 32);
        assert_eq!((i.value(), s.value()), (1, 1));
    }

    #[test]
    fn classify_single_sub_interval_collapses_to_zero() {
        // sub_intervals = 1 disables the fine bucket: sub is always 0.
        let cfg = ReplicationConfig::new("demo/**", None, 10_000, 1, 6, 30, 250);
        let (i, s) = cfg.classify(37u64 << 32);
        assert_eq!((i.value(), s.value()), (3, 0));
    }

    // -- configuration fingerprint --------------------------------------

    #[test]
    fn config_fingerprint_is_deterministic() {
        let a = ReplicationConfig::defaults("demo/**");
        let b = ReplicationConfig::defaults("demo/**");
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn config_fingerprint_is_sensitive_to_every_field() {
        let base = ReplicationConfig::new("demo/**", None, 10_000, 5, 6, 30, 250);
        let fp = base.fingerprint();

        // Each differing field must change the fingerprint (so incompatible
        // replicas never exchange digests).
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/a/*", None, 10_000, 5, 6, 30, 250).fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", Some("p".into()), 10_000, 5, 6, 30, 250)
                .fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", None, 5_000, 5, 6, 30, 250).fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", None, 10_000, 10, 6, 30, 250).fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", None, 10_000, 5, 12, 30, 250).fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", None, 10_000, 5, 6, 60, 250).fingerprint()
        );
        assert_ne!(
            fp,
            ReplicationConfig::new("demo/**", None, 10_000, 5, 6, 30, 500).fingerprint()
        );
    }

    /// Locks the config-fingerprint byte recipe to zenoh `Configuration::new`
    /// (configuration.rs:64-72): key_expr bytes, optional prefix bytes,
    /// interval as `u128` LE, sub_intervals as 8 LE bytes, hot / warm as
    /// `u64` LE, propagation_delay as `u128` LE — in that exact order. The
    /// config fingerprint gates digest exchange (the keyexpr segment + the
    /// `Digest::diff` short-circuit), so a field-order or width drift would
    /// silently stop wz from ever exchanging digests with a real zenoh
    /// replica. This catches such a drift (a recipe lock, not an independent
    /// oracle — the live zenoh value is the R9 residual).
    #[test]
    fn config_fingerprint_recipe_matches_zenoh_field_order() {
        let no_prefix = ReplicationConfig::new("demo/**", None, 10_000, 5, 6, 30, 250);
        let mut h = Xxh3::default();
        h.update(b"demo/**");
        h.update(&10_000u128.to_le_bytes());
        h.update(&5u64.to_le_bytes());
        h.update(&6u64.to_le_bytes());
        h.update(&30u64.to_le_bytes());
        h.update(&250u128.to_le_bytes());
        assert_eq!(no_prefix.fingerprint(), Fingerprint::from(h.digest()));

        // The prefix is hashed immediately after the key_expr, before the
        // numeric fields (configuration.rs:65-67).
        let with_prefix =
            ReplicationConfig::new("demo/**", Some("p".into()), 10_000, 5, 6, 30, 250);
        let mut hp = Xxh3::default();
        hp.update(b"demo/**");
        hp.update(b"p");
        hp.update(&10_000u128.to_le_bytes());
        hp.update(&5u64.to_le_bytes());
        hp.update(&6u64.to_le_bytes());
        hp.update(&30u64.to_le_bytes());
        hp.update(&250u128.to_le_bytes());
        assert_eq!(with_prefix.fingerprint(), Fingerprint::from(hp.digest()));
    }

    // -- event fingerprint ----------------------------------------------

    #[test]
    fn event_fingerprint_is_deterministic_and_field_sensitive() {
        let base = event_fingerprint("demo/a", &ts(100, vec![0x01]));

        assert_eq!(base, event_fingerprint("demo/a", &ts(100, vec![0x01])));
        // Different key, time, or zid all change the fingerprint.
        assert_ne!(base, event_fingerprint("demo/b", &ts(100, vec![0x01])));
        assert_ne!(base, event_fingerprint("demo/a", &ts(101, vec![0x01])));
        assert_ne!(base, event_fingerprint("demo/a", &ts(100, vec![0x02])));
    }

    /// The zid is normalised to the 16-byte LE array before hashing, so a
    /// trimmed zid and the same zid with explicit trailing zero bytes hash
    /// identically — the SSOT that keeps the fingerprint byte-compatible with
    /// uhlc's canonical 16-byte id (and with the newer-wins comparator).
    #[test]
    fn event_fingerprint_zid_is_length_normalised() {
        let trimmed = event_fingerprint("demo/a", &ts(100, vec![0x01]));
        let padded = event_fingerprint("demo/a", &ts(100, vec![0x01, 0x00, 0x00]));
        assert_eq!(trimmed, padded);
    }

    // -- Digest build (era partition + XOR rollup) ----------------------

    /// hot=2, warm=3, interval 10s, 5 sub-intervals, hot_upper=10 gives
    /// era bounds warm_lower=6, hot_lower=9: intervals <6 cold, [6,9) warm,
    /// >=9 hot.
    fn era_cfg() -> ReplicationConfig {
        ReplicationConfig::new("demo/**", None, 10_000, 5, 2, 3, 250)
    }

    /// An NTP64 `time` at exactly `secs` seconds past the epoch (zero
    /// fraction); ms = secs * 1000, so the interval is `secs / 10`.
    fn at_secs(secs: u64) -> u64 {
        secs << 32
    }

    #[test]
    fn build_digest_partitions_events_into_eras() {
        let cfg = era_cfg();
        // interval 3 (cold), interval 7 (warm), interval 9 sub 2 (hot).
        let cold = ts(at_secs(35), vec![0x01]);
        let warm = ts(at_secs(75), vec![0x01]);
        let hot = ts(at_secs(95), vec![0x01]);
        let events = [("demo/a", &cold), ("demo/b", &warm), ("demo/c", &hot)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        assert_eq!(digest.configuration_fingerprint(), cfg.fingerprint());
        // Cold: the single cold event's fingerprint.
        assert_eq!(
            digest.cold_era_fingerprint(),
            event_fingerprint("demo/a", &cold)
        );
        // Warm: exactly interval 7, fingerprint == the event's (one event,
        // one sub-interval, so the interval fingerprint is the event's).
        assert_eq!(digest.warm_era_fingerprints().len(), 1);
        assert_eq!(
            digest.warm_era_fingerprints().get(&IntervalIdx::from(7)),
            Some(&event_fingerprint("demo/b", &warm))
        );
        // Hot: interval 9, sub-interval 2 (95000ms -> rem 5000 / 2000 = 2).
        assert_eq!(digest.hot_era_fingerprints().len(), 1);
        let hot_subs = digest
            .hot_era_fingerprints()
            .get(&IntervalIdx::from(9))
            .expect("interval 9 is in the hot era");
        assert_eq!(
            hot_subs.get(&SubIntervalIdx::from(2)),
            Some(&event_fingerprint("demo/c", &hot))
        );
    }

    #[test]
    fn build_digest_xor_rolls_up_a_warm_interval() {
        let cfg = era_cfg();
        // Two events in interval 7 (warm), different sub-intervals: 71000ms
        // -> sub 0, 75000ms -> sub 2. The warm interval fingerprint is the
        // XOR of the two sub-interval (single-event) fingerprints.
        let e0 = ts(at_secs(71), vec![0x01]);
        let e2 = ts(at_secs(75), vec![0x01]);
        let events = [("demo/a", &e0), ("demo/b", &e2)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        let expected = event_fingerprint("demo/a", &e0) ^ event_fingerprint("demo/b", &e2);
        assert_eq!(
            digest.warm_era_fingerprints().get(&IntervalIdx::from(7)),
            Some(&expected)
        );
    }

    #[test]
    fn build_digest_hot_keeps_per_sub_interval_granularity() {
        let cfg = era_cfg();
        // Interval 9 (hot), two distinct sub-intervals: 94000ms -> sub 2,
        // 98000ms -> sub 4. Both must appear separately under interval 9.
        let s2 = ts(at_secs(94), vec![0x01]);
        let s4 = ts(at_secs(98), vec![0x01]);
        let events = [("demo/a", &s2), ("demo/b", &s4)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        let subs = digest
            .hot_era_fingerprints()
            .get(&IntervalIdx::from(9))
            .expect("interval 9 hot");
        assert_eq!(subs.len(), 2);
        assert_eq!(
            subs.get(&SubIntervalIdx::from(2)),
            Some(&event_fingerprint("demo/a", &s2))
        );
        assert_eq!(
            subs.get(&SubIntervalIdx::from(4)),
            Some(&event_fingerprint("demo/b", &s4))
        );
    }

    #[test]
    fn build_digest_excludes_intervals_newer_than_hot_upper() {
        let cfg = era_cfg();
        // hot_upper = 5, but the event is at interval 9 -> excluded entirely.
        let future = ts(at_secs(95), vec![0x01]);
        let events = [("demo/a", &future)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(5));

        assert_eq!(digest.cold_era_fingerprint(), Fingerprint::default());
        assert!(digest.warm_era_fingerprints().is_empty());
        assert!(digest.hot_era_fingerprints().is_empty());
    }

    #[test]
    fn build_digest_drops_self_cancelling_buckets() {
        let cfg = era_cfg();
        // The SAME event twice in a warm interval XORs to zero -> the
        // interval must NOT appear (the non-zero filter, log.rs:576). An
        // absent entry and a zero entry must diff differently, so this filter
        // is load-bearing for digest equality.
        let e = ts(at_secs(75), vec![0x01]);
        let events = [("demo/a", &e), ("demo/a", &e)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        assert!(
            digest.warm_era_fingerprints().is_empty(),
            "a net-zero interval is filtered out, not stored as zero"
        );
    }

    #[test]
    fn build_digest_empty_store_is_empty_but_carries_config_fp() {
        let cfg = era_cfg();
        let events: [(&str, &TimestampHint); 0] = [];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        assert_eq!(digest.configuration_fingerprint(), cfg.fingerprint());
        assert_eq!(digest.cold_era_fingerprint(), Fingerprint::default());
        assert!(digest.warm_era_fingerprints().is_empty());
        assert!(digest.hot_era_fingerprints().is_empty());
    }

    // -- Digest::diff ----------------------------------------------------

    #[test]
    fn diff_identical_digests_is_none() {
        let cfg = era_cfg();
        let c = ts(at_secs(35), vec![0x01]);
        let w = ts(at_secs(75), vec![0x01]);
        let h = ts(at_secs(95), vec![0x01]);
        let events = [("demo/a", &c), ("demo/b", &w), ("demo/c", &h)];

        let a = build_digest(&cfg, events, IntervalIdx::from(10));
        let b = build_digest(&cfg, events, IntervalIdx::from(10));
        assert_eq!(a.diff(b), None);
    }

    #[test]
    fn diff_incompatible_configuration_is_none() {
        let cfg = era_cfg();
        let other_cfg = ReplicationConfig::new("other/**", None, 10_000, 5, 2, 3, 250);
        let h = ts(at_secs(95), vec![0x01]);

        let local = build_digest(&cfg, [("demo/a", &h)], IntervalIdx::from(10));
        // Different key_expr -> different config fingerprint -> never compares,
        // even though the stored data plainly differs.
        let remote = build_digest(&other_cfg, [], IntervalIdx::from(10));
        assert_eq!(local.diff(remote), None);
    }

    #[test]
    fn diff_detects_a_hot_sub_interval_only_in_other() {
        let cfg = era_cfg();
        let s2 = ts(at_secs(94), vec![0x01]); // interval 9, sub 2
        let s4 = ts(at_secs(98), vec![0x01]); // interval 9, sub 4

        let local = build_digest(&cfg, [("demo/a", &s2)], IntervalIdx::from(10));
        let remote = build_digest(
            &cfg,
            [("demo/a", &s2), ("demo/b", &s4)],
            IntervalIdx::from(10),
        );

        let diff = local.diff(remote).expect("remote has an extra hot sub");
        assert!(!diff.cold_eras_differ());
        assert!(diff.warm_eras_differences().is_empty());
        let subs = diff
            .hot_eras_differences()
            .get(&IntervalIdx::from(9))
            .expect("interval 9 diverges");
        assert_eq!(subs.len(), 1);
        assert!(subs.contains(&SubIntervalIdx::from(4)));
    }

    #[test]
    fn diff_detects_a_differing_hot_sub_interval() {
        let cfg = era_cfg();
        // Same (interval 9, sub 2) bucket, different value -> different fp.
        let here = ts(at_secs(94), vec![0x01]);
        let local = build_digest(&cfg, [("demo/a", &here)], IntervalIdx::from(10));
        let remote = build_digest(&cfg, [("demo/b", &here)], IntervalIdx::from(10));

        let diff = local.diff(remote).expect("the shared bucket differs");
        let subs = diff
            .hot_eras_differences()
            .get(&IntervalIdx::from(9))
            .unwrap();
        assert!(subs.contains(&SubIntervalIdx::from(2)));
    }

    #[test]
    fn diff_detects_a_warm_interval_only_in_other() {
        let cfg = era_cfg();
        let i7 = ts(at_secs(75), vec![0x01]); // interval 7 (warm)
        let i8 = ts(at_secs(85), vec![0x01]); // interval 8 (warm)

        let local = build_digest(&cfg, [("demo/a", &i7)], IntervalIdx::from(10));
        let remote = build_digest(
            &cfg,
            [("demo/a", &i7), ("demo/b", &i8)],
            IntervalIdx::from(10),
        );

        let diff = local
            .diff(remote)
            .expect("remote has an extra warm interval");
        assert!(diff.hot_eras_differences().is_empty());
        assert_eq!(diff.warm_eras_differences().len(), 1);
        assert!(diff.warm_eras_differences().contains(&IntervalIdx::from(8)));
    }

    #[test]
    fn diff_cold_only_difference_sets_just_the_flag() {
        let cfg = era_cfg();
        // Two different cold events, no hot/warm at all.
        let c3 = ts(at_secs(35), vec![0x01]); // interval 3 (cold)
        let c4 = ts(at_secs(45), vec![0x01]); // interval 4 (cold)

        let local = build_digest(&cfg, [("demo/a", &c3)], IntervalIdx::from(10));
        let remote = build_digest(&cfg, [("demo/b", &c4)], IntervalIdx::from(10));

        let diff = local.diff(remote).expect("the cold rollups differ");
        assert!(diff.cold_eras_differ());
        assert!(diff.warm_eras_differences().is_empty());
        assert!(diff.hot_eras_differences().is_empty());
    }

    #[test]
    fn diff_is_asymmetric_extra_on_self_is_not_reported() {
        let cfg = era_cfg();
        let s2 = ts(at_secs(94), vec![0x01]);
        let s4 = ts(at_secs(98), vec![0x01]);

        // `local` is a superset of `remote` (has the extra sub 4).
        let local = build_digest(
            &cfg,
            [("demo/a", &s2), ("demo/b", &s4)],
            IntervalIdx::from(10),
        );
        let remote = build_digest(&cfg, [("demo/a", &s2)], IntervalIdx::from(10));

        // From local's perspective there is nothing to pull (it already has
        // everything remote has).
        assert_eq!(local.clone().diff(remote.clone()), None);
        // From remote's perspective, local holds an extra sub 4 -> surfaced.
        let diff = remote.diff(local).expect("local has the extra sub");
        assert!(diff
            .hot_eras_differences()
            .get(&IntervalIdx::from(9))
            .unwrap()
            .contains(&SubIntervalIdx::from(4)));
    }

    #[test]
    fn diff_folds_cold_difference_into_a_hot_diff() {
        let cfg = era_cfg();
        let s2 = ts(at_secs(94), vec![0x01]); // hot interval 9 sub 2
        let s4 = ts(at_secs(98), vec![0x01]); // hot interval 9 sub 4
        let cold = ts(at_secs(35), vec![0x01]); // cold interval 3

        let local = build_digest(&cfg, [("demo/a", &s2)], IntervalIdx::from(10));
        // remote diverges in the hot era AND has a cold event local lacks.
        let remote = build_digest(
            &cfg,
            [("demo/a", &s2), ("demo/b", &s4), ("demo/c", &cold)],
            IntervalIdx::from(10),
        );

        let diff = local.diff(remote).expect("hot + cold both differ");
        assert!(
            diff.cold_eras_differ(),
            "the cold flag rides along the hot diff"
        );
        assert!(diff
            .hot_eras_differences()
            .get(&IntervalIdx::from(9))
            .unwrap()
            .contains(&SubIntervalIdx::from(4)));
    }
}
