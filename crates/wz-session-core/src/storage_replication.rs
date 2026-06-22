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

use alloc::collections::BTreeMap;
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
}
