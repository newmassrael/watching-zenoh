// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! - `event_fingerprint` = `Event::compute_fingerprint` (log.rs:232-244):
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
//! - **`strip_prefix` and the mount-root `None` key (R311y64).** With a
//!   configured `strip_prefix` the stored key is the *stripped* key, and the
//!   exact-prefix mount-root value is stored under the backend `None` key —
//!   mirroring zenoh's `Option<OwnedKeyExpr>` stripped key. [`event_fingerprint`]
//!   takes `Option<&str>` and hashes the key bytes ONLY when `Some`, omitting
//!   them entirely for a `None` mount-root key (zenoh `compute_fingerprint`,
//!   log.rs:237: `if let Some(key_expr) = maybe_stripped_key { ... }`). So a
//!   `None` key and a `Some("")` key fingerprint identically (neither hashes
//!   any key bytes) — the zenoh-faithful equivalence. With no `strip_prefix`
//!   every stored key is `Some(full_key)` and the fingerprints match a
//!   non-strip zenoh replica.
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
use crate::zid_hex::zid_to_le_array;

/// A 64-bit fingerprint of the content it represents. zenoh
/// `digest::Fingerprint` (digest.rs:27-57).
///
/// Composition is XOR ([`BitXor`](core::ops::BitXor) /
/// [`BitXorAssign`](core::ops::BitXorAssign)): a bucket's fingerprint is the
/// XOR of the fingerprints it contains. XOR is associative and commutative,
/// so the result is independent of insertion order and a fingerprint can be
/// maintained incrementally — inserting and removing an event are both a
/// single XOR of its `event_fingerprint`.
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
/// sub-interval width `interval_ms / sub_intervals` is at least 1ms) —
/// **enforced by [`new`](ReplicationConfig::new)**, which asserts them so a
/// misconfiguration fails fast and clearly at construction rather than as a
/// cryptic divide-by-zero deep in [`classify`](ReplicationConfig::classify).
/// zenoh leaves this implicit, panicking only later in its
/// `get_time_classification` (configuration.rs:212-213).
/// [`defaults`](ReplicationConfig::defaults) satisfies both.
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
        // Make the documented invariant load-bearing: an invalid config fails
        // fast and clearly here, not as a cryptic divide-by-zero in classify().
        assert!(
            sub_intervals >= 1 && interval_ms >= sub_intervals,
            "ReplicationConfig requires sub_intervals >= 1 and \
             interval_ms >= sub_intervals (got interval_ms={interval_ms}, \
             sub_intervals={sub_intervals})"
        );

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
    /// defaults (`plugins/zenoh-backend-traits/src/config.rs:92-150`): 10s
    /// interval, 5 sub-intervals, 6 hot, 30 warm, 250ms propagation delay.
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
    /// configuration.rs:87-89), carried for config-fingerprint parity. The
    /// per-event strip is applied by [`crate::storage_state`] (R311y64); a
    /// mount-root value lands under the backend `None` key.
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

    /// The delay, from `now_unix_ms`, until the next interval boundary — what
    /// a freshly started replica sleeps before its FIRST publication so its
    /// digests land at every interval (+ δ) instead of at whatever offset the
    /// process happened to start at. zenoh `duration_until_next_interval`
    /// (core.rs:163-190), which spells it `interval - (now -
    /// last_elapsed_interval * interval)`; since `last_elapsed_interval` is
    /// `now / interval` (configuration.rs:113-120), that is `interval - (now %
    /// interval)`, computed here in the shorter form.
    ///
    /// `now_unix_ms` is milliseconds since the UNIX epoch and NOT a monotonic
    /// reading. The boundaries are shared across a fleet only because every
    /// replica derives them from the same epoch, which is the entire point of
    /// aligning; a monotonic clock would align each replica to its own start
    /// and de-align the fleet.
    ///
    /// On an exact boundary this returns the FULL `interval_ms`, not `0` —
    /// zenoh's arithmetic, kept: a replica that starts precisely on a boundary
    /// has already missed that boundary's publication window.
    pub fn alignment_delay_ms(&self, now_unix_ms: u64) -> u64 {
        // `interval_ms >= sub_intervals >= 1` is a construction invariant
        // (`new` asserts it), so the modulo cannot divide by zero.
        self.interval_ms - (now_unix_ms % self.interval_ms)
    }

    /// The exclusive upper bound of the publication jitter: `interval / 3`
    /// (zenoh `max_publication_delay`, core.rs:196).
    pub fn max_publication_delay_ms(&self) -> u64 {
        self.interval_ms / 3
    }

    /// Maps an arbitrary `draw` onto the jitter range `0..max`, i.e. zenoh's
    /// `rand::thread_rng().gen_range(0..max_publication_delay)`
    /// (core.rs:236). The jitter exists to stop a fleet publishing in
    /// lockstep, so the reduction is a plain modulo: its bias across a range
    /// this small is invisible against that purpose, and nothing here is a
    /// security claim.
    ///
    /// Taking the draw as a VALUE rather than as a source is what keeps the
    /// whole publication schedule a pure function of its inputs — see
    /// [`JitterSequence`] for where a replica's draws come from.
    ///
    /// An `interval_ms` under 3ms yields a `max` of 0 and therefore no jitter,
    /// rather than a modulo by zero.
    pub fn publication_delay_ms(&self, draw: u64) -> u64 {
        let max = self.max_publication_delay_ms();
        if max == 0 {
            0
        } else {
            draw % max
        }
    }

    /// The sleep that CLOSES a publication cycle: `interval - cycle_duration`,
    /// so the publication PERIOD stays `interval_ms` no matter how long the
    /// cycle's own work (the propagation wait, the digest build, the jitter,
    /// the put) took. zenoh core.rs:262-272.
    ///
    /// `None` means the cycle overran a whole interval; zenoh warns that the
    /// interval is configured too short and re-enters the loop immediately,
    /// so a caller that gets `None` should not sleep rather than treat it as
    /// an error. Without this subtraction the period would be `interval +
    /// work` and a replica would publish strictly less often than configured
    /// — the drift compounds over a session.
    pub fn post_publication_delay_ms(&self, cycle_duration_ms: u64) -> Option<u64> {
        self.interval_ms.checked_sub(cycle_duration_ms)
    }

    /// Classifies an NTP64 `time` into its `(interval, sub-interval)` bucket.
    /// zenoh `Configuration::get_time_classification`
    /// (configuration.rs:193-220): convert to milliseconds since the epoch,
    /// then `interval = ms / interval_ms` and `sub_interval =
    /// (ms - interval_ms * interval) / (interval_ms / sub_intervals)`.
    ///
    /// Cannot divide by zero: the sub-interval width `interval_ms /
    /// sub_intervals` is `>= 1` by the [`ReplicationConfig`] invariants, which
    /// [`new`](ReplicationConfig::new) asserts at construction — so a config
    /// that reaches here is always valid.
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

/// Where one replica's publication-jitter draws come from: a per-replica
/// sequence, seeded from the replica's own zid, that feeds
/// [`ReplicationConfig::publication_delay_ms`].
///
/// ## Why not an entropy source
///
/// zenoh draws the jitter from `rand::thread_rng()` (core.rs:236). wz seeds
/// from the zid instead, and the reason is the purpose of the draw: upstream
/// states it as "we do not want to create a coordinated update storm with all
/// replicas publishing at the same time" (core.rs:234-235). What that needs is
/// that DISTINCT replicas draw distinct sequences — and the zid is precisely
/// the value a fleet is already guaranteed to differ on. Seeding from it gets
/// the property directly, in a no_std kernel, with no entropy port and no
/// failure path to invent a fallback for.
///
/// It is therefore NOT unpredictable to an observer, and it must not be
/// borrowed for anything that needs it to be: this crate's
/// [`EntropySource`](crate::entropy::EntropySource) is the port with that
/// contract, and its own note says a source that satisfies the type while
/// defeating the purpose is the failure to avoid. De-correlation and
/// unpredictability are different requirements; only the first is claimed
/// here.
///
/// The sequence is deterministic, so a restarted replica repeats its own
/// draws. That is harmless — the anti-storm property is across replicas, not
/// across one replica's restarts — and it is what makes the schedule testable
/// end to end.
pub struct JitterSequence {
    state: u64,
}

impl JitterSequence {
    /// Seed the sequence for the replica identified by `zid`, hashed with the
    /// same `Xxh3` this module already uses for its fingerprints so no second
    /// hashing dependency enters the kernel.
    pub fn for_replica(zid: &[u8]) -> Self {
        let mut hasher = Xxh3::default();
        hasher.update(zid);
        Self {
            state: hasher.digest(),
        }
    }

    /// Advance and return the next draw (SplitMix64), which the caller hands
    /// to [`ReplicationConfig::publication_delay_ms`] to land it in the jitter
    /// range. SplitMix64 is chosen for being a few wrapping operations over a
    /// single `u64` of state — the whole requirement here is that successive
    /// cycles do not repeat one offset, not statistical quality.
    pub fn next_draw(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Converts an NTP64 `time` to milliseconds since the UNIX epoch via the
/// [`Ntp64`](crate::ntp64::Ntp64) SSOT, which reproduces uhlc's
/// `NTP64::to_duration().as_millis()` bit-for-bit (the `div_ceil` fraction
/// conversion lives there). Retained as a thin private wrapper, called at the
/// `classify` site, because zenoh classifies on this exact value
/// (configuration.rs:197-201), so a wz replica and a zenoh replica bucket the
/// same event identically.
fn ntp64_to_ms(time: u64) -> u128 {
    crate::ntp64::Ntp64::from_word(time).to_millis()
}

/// The [`Fingerprint`] of a single stored event — a `(key, timestamp)` pair.
/// zenoh `Event::compute_fingerprint` (log.rs:232-244).
///
/// The key is `Option<&str>` mirroring zenoh's `maybe_stripped_key:
/// Option<OwnedKeyExpr>`: the key bytes are hashed ONLY when `Some`
/// (`if let Some(key_expr) = maybe_stripped_key { hasher.update(...) }`,
/// log.rs:237-239), so a `None` mount-root key hashes the timestamp only.
/// Then the NTP64 `time` as 8 little-endian bytes
/// (`timestamp.get_time().0.to_le_bytes()`, log.rs:240) and the zid as the
/// 16-byte zero-padded little-endian array (via
/// `storage_state::zid_to_le_array`, matching `timestamp.get_id().to_le_bytes()`,
/// log.rs:241). The action/kind is deliberately *not* hashed — it adds no
/// distinguishing power and hashing it would cost time (log.rs:226-231). The
/// `(key, time, id)` triple is exactly what the newer-wins comparator orders
/// on, so two replicas that hold the same event compute the same fingerprint.
/// A `None` key and a `Some("")` key fingerprint identically (neither hashes
/// any key bytes) — the zenoh-faithful equivalence.
pub(crate) fn event_fingerprint(key: Option<&str>, timestamp: &TimestampHint) -> Fingerprint {
    let mut hasher = Xxh3::default();
    if let Some(k) = key {
        hasher.update(k.as_bytes());
    }
    hasher.update(&timestamp.time.to_le_bytes());
    hasher.update(&zid_to_le_array(&timestamp.zid));
    Fingerprint::from(hasher.digest())
}

/// The zid <-> zenoh `ZenohId` Display hex SSOT now lives in the foundational
/// [`crate::zid_hex`] module (the admin space `@/<zid>/<whatami>`, §5.23, needs
/// the identical recipe without the `storage-replication` gate). Re-exported
/// here so every replication keyexpr builder + cross-impl test reads unchanged:
/// the digest `@-digest/<zid-hex>/<fp>`, the aligner
/// `@zid/<zid-hex>/<fp>/aligner`, and the `AlignmentReply::Discovery` body.
pub use crate::zid_hex::{zenoh_hex_to_zid, zid_to_zenoh_hex};

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
/// `events` is the distinct latest `(Option<key>, timestamp)` per key — the
/// key being `Option` to carry a strip-configured storage's mount-root value
/// (stored under the backend `None` key), faithful to zenoh's
/// `maybe_stripped_key`. Each event is hashed (`event_fingerprint`, which
/// hashes the key bytes only when `Some`) and XOR-accumulated into its
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
    events: impl IntoIterator<Item = (Option<&'a str>, &'a TimestampHint)>,
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
/// R311y303 correction (this residual had gone stale): a fully LIVE digest
/// exchange with a running `zenoh-plugin-storage-manager` replica IS now
/// exercised — the hosted Layer Z interop test `wz_zenohd_storage_replication`
/// runs wz against a real zenohd 1.5.0 with replication enabled, and its
/// storage-manager plugin presence is asserted in CI so the lane cannot
/// SKIP-green. It proves both directions (wz decodes zenohd's digest and
/// diffs; wz's ASK pull interoperates with zenohd's aligner) with the config
/// fingerprint hard-pinned to zenohd's golden value before any I/O. The
/// remaining publisher-side residuals (propagation-delay pre-sleep, publish
/// jitter, interval-boundary alignment) are deferred tuning, not correctness —
/// see the `storage-replication` inventory atom.
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
    // The bincode-1.3 cursor + length helpers are shared with the aligner codec.
    use crate::wire_bincode::{check_len, push_u64, Reader, WireError};

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

    impl From<WireError> for DigestDecodeError {
        fn from(e: WireError) -> Self {
            match e {
                WireError::UnexpectedEof => Self::UnexpectedEof,
                WireError::LengthOverflow => Self::LengthOverflow,
            }
        }
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
                    (Some("demo/a"), &cold),
                    (Some("demo/b"), &warm_a),
                    (Some("demo/c"), &warm_b),
                    (Some("demo/d"), &hot_a),
                    (Some("demo/e"), &hot_b),
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

    // -- Publication schedule (R311y829) ---------------------------------

    /// zenoh's `duration_until_next_interval` (core.rs:163-190) as a pure
    /// function: the delay a starting replica sleeps to land on the fleet's
    /// shared boundary. The boundary case is the interesting one — a replica
    /// that starts exactly ON a boundary waits a FULL interval rather than
    /// publishing immediately, because it has already missed that boundary's
    /// window.
    #[test]
    fn alignment_delay_lands_on_the_next_interval_boundary() {
        let config = ReplicationConfig::new("demo/**", None, 1_000, 5, 6, 30, 250);

        assert_eq!(config.alignment_delay_ms(7_000), 1_000);
        assert_eq!(config.alignment_delay_ms(7_001), 999);
        assert_eq!(config.alignment_delay_ms(7_999), 1);

        // The point of the whole exercise: two replicas that start at
        // different moments inside the same interval arrive at the SAME
        // boundary.
        assert_eq!(7_001 + config.alignment_delay_ms(7_001), 8_000);
        assert_eq!(7_999 + config.alignment_delay_ms(7_999), 8_000);
    }

    /// The jitter range is `0..interval/3` (zenoh `max_publication_delay`,
    /// core.rs:196), and an interval too short to have thirds yields NO
    /// jitter rather than a modulo by zero.
    #[test]
    fn publication_delay_maps_a_draw_into_the_jitter_range() {
        let config = ReplicationConfig::new("demo/**", None, 1_000, 5, 6, 30, 250);
        assert_eq!(config.max_publication_delay_ms(), 333);

        for draw in [0, 1, 332, 333, 334, u64::MAX] {
            let delay = config.publication_delay_ms(draw);
            assert!(delay < 333, "draw {draw} produced {delay}");
        }
        // The reduction is a plain modulo, pinned so a future change to it is
        // a decision rather than a drift.
        assert_eq!(config.publication_delay_ms(0), 0);
        assert_eq!(config.publication_delay_ms(334), 1);

        // `interval / 3 == 0`: no jitter, and specifically no panic.
        let tiny = ReplicationConfig::new("demo/**", None, 2, 2, 6, 30, 0);
        assert_eq!(tiny.max_publication_delay_ms(), 0);
        assert_eq!(tiny.publication_delay_ms(u64::MAX), 0);
    }

    /// The closing sleep is `interval - cycle_work`, which is what holds the
    /// publication PERIOD at `interval` instead of letting it grow to
    /// `interval + work` (zenoh core.rs:262-272). `None` is the overrun
    /// signal, not an error: upstream warns and re-enters immediately.
    #[test]
    fn post_publication_delay_holds_the_period_at_one_interval() {
        let config = ReplicationConfig::new("demo/**", None, 1_000, 5, 6, 30, 250);

        assert_eq!(config.post_publication_delay_ms(0), Some(1_000));
        assert_eq!(config.post_publication_delay_ms(250), Some(750));
        // A cycle that exactly fills the interval sleeps zero — still Some, so
        // a caller cannot confuse "no time left" with "overran".
        assert_eq!(config.post_publication_delay_ms(1_000), Some(0));
        assert_eq!(config.post_publication_delay_ms(1_001), None);

        // The invariant the subtraction exists for: work + closing sleep is
        // one interval, whatever the work was.
        for work in [0, 1, 250, 999, 1_000] {
            assert_eq!(
                work + config.post_publication_delay_ms(work).unwrap(),
                1_000
            );
        }
    }

    /// The anti-storm property [`JitterSequence`] actually claims: DISTINCT
    /// replicas draw distinct sequences. Unpredictability is explicitly not
    /// claimed (that is what [`crate::entropy::EntropySource`] is for), so it
    /// is not asserted here either.
    #[test]
    fn jitter_sequences_differ_per_replica_and_across_cycles() {
        let draws = |zid: &[u8]| {
            let mut seq = JitterSequence::for_replica(zid);
            [seq.next_draw(), seq.next_draw(), seq.next_draw()]
        };

        let a = draws(&[0x01]);
        let b = draws(&[0x02]);
        assert_ne!(a, b, "two replicas must not publish in lockstep");

        // Successive cycles move, or the jitter would be a fixed per-replica
        // offset rather than a jitter.
        assert_ne!(a[0], a[1]);
        assert_ne!(a[1], a[2]);

        // Seeded, so the same replica reproduces its own sequence — which is
        // what lets the schedule be tested end to end.
        assert_eq!(a, draws(&[0x01]));
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
        let base = event_fingerprint(Some("demo/a"), &ts(100, vec![0x01]));

        assert_eq!(
            base,
            event_fingerprint(Some("demo/a"), &ts(100, vec![0x01]))
        );
        // Different key, time, or zid all change the fingerprint.
        assert_ne!(
            base,
            event_fingerprint(Some("demo/b"), &ts(100, vec![0x01]))
        );
        assert_ne!(
            base,
            event_fingerprint(Some("demo/a"), &ts(101, vec![0x01]))
        );
        assert_ne!(
            base,
            event_fingerprint(Some("demo/a"), &ts(100, vec![0x02]))
        );
    }

    /// The zid is normalised to the 16-byte LE array before hashing, so a
    /// trimmed zid and the same zid with explicit trailing zero bytes hash
    /// identically — the SSOT that keeps the fingerprint byte-compatible with
    /// uhlc's canonical 16-byte id (and with the newer-wins comparator).
    #[test]
    fn event_fingerprint_zid_is_length_normalised() {
        let trimmed = event_fingerprint(Some("demo/a"), &ts(100, vec![0x01]));
        let padded = event_fingerprint(Some("demo/a"), &ts(100, vec![0x01, 0x00, 0x00]));
        assert_eq!(trimmed, padded);
    }

    /// The zenoh-faithful `None`/`Some("")` equivalence: `compute_fingerprint`
    /// hashes the key bytes ONLY when `Some` (log.rs:237), so a `None`
    /// mount-root key hashes no key bytes — and `Some("")` hashes no key bytes
    /// either (an empty slice). The two are therefore EQUAL, and both differ
    /// from a non-empty key (which DOES hash bytes).
    #[test]
    fn event_fingerprint_none_key_equals_empty_key_and_differs_from_nonempty() {
        let ts = ts(100, vec![0x01]);
        assert_eq!(
            event_fingerprint(None, &ts),
            event_fingerprint(Some(""), &ts),
            "a None key and a Some(\"\") key both hash zero key bytes -> equal"
        );
        assert_ne!(
            event_fingerprint(None, &ts),
            event_fingerprint(Some("demo/a"), &ts),
            "a None key differs from a non-empty key (which hashes its bytes)"
        );
    }

    /// The zid-as-zenoh-hex SSOT: a zid renders as zenoh's `ZenohId` Display —
    /// the LE bytes read as a `u128` then big-endian hex with one leading zero
    /// stripped, i.e. the bytes appear REVERSED, NOT a per-byte hex of the wire
    /// order. This is the recipe both the digest keyexpr and the aligner's
    /// `AlignmentReply::Discovery` share, so getting it wrong would silently
    /// break keyexpr / zid interop with a real zenoh.
    #[test]
    fn zid_to_zenoh_hex_matches_zenoh_display() {
        // [0x1a,0x2b,0x3c] LE -> u128 0x3c2b1a -> "3c2b1a" (reversed, no strip).
        assert_eq!(zid_to_zenoh_hex(&[0x1a, 0x2b, 0x3c]), "3c2b1a");
        // [0x01,0xab] LE -> u128 0xab01 -> "ab01" (NOT the per-byte "01ab").
        assert_eq!(zid_to_zenoh_hex(&[0x01, 0xab]), "ab01");
        // Single low byte -> one leading zero stripped.
        assert_eq!(zid_to_zenoh_hex(&[0x0a]), "a");
        assert_eq!(zid_to_zenoh_hex(&[0x01]), "1");
    }

    #[test]
    fn zid_zenoh_hex_round_trips_and_rejects_garbage() {
        for zid in [
            alloc::vec![0x1a, 0x2b, 0x3c],
            alloc::vec![0x01],
            alloc::vec![0xff; 16],
            alloc::vec![0x01, 0x02], // a trailing-non-zero pair
        ] {
            assert_eq!(zenoh_hex_to_zid(&zid_to_zenoh_hex(&zid)), Some(zid));
        }
        // Non-hex / over-long inputs are rejected.
        assert_eq!(zenoh_hex_to_zid("zz"), None);
        assert_eq!(zenoh_hex_to_zid(&"f".repeat(33)), None); // > 16 bytes
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
        let events = [
            (Some("demo/a"), &cold),
            (Some("demo/b"), &warm),
            (Some("demo/c"), &hot),
        ];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        assert_eq!(digest.configuration_fingerprint(), cfg.fingerprint());
        // Cold: the single cold event's fingerprint.
        assert_eq!(
            digest.cold_era_fingerprint(),
            event_fingerprint(Some("demo/a"), &cold)
        );
        // Warm: exactly interval 7, fingerprint == the event's (one event,
        // one sub-interval, so the interval fingerprint is the event's).
        assert_eq!(digest.warm_era_fingerprints().len(), 1);
        assert_eq!(
            digest.warm_era_fingerprints().get(&IntervalIdx::from(7)),
            Some(&event_fingerprint(Some("demo/b"), &warm))
        );
        // Hot: interval 9, sub-interval 2 (95000ms -> rem 5000 / 2000 = 2).
        assert_eq!(digest.hot_era_fingerprints().len(), 1);
        let hot_subs = digest
            .hot_era_fingerprints()
            .get(&IntervalIdx::from(9))
            .expect("interval 9 is in the hot era");
        assert_eq!(
            hot_subs.get(&SubIntervalIdx::from(2)),
            Some(&event_fingerprint(Some("demo/c"), &hot))
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
        let events = [(Some("demo/a"), &e0), (Some("demo/b"), &e2)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        let expected =
            event_fingerprint(Some("demo/a"), &e0) ^ event_fingerprint(Some("demo/b"), &e2);
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
        let events = [(Some("demo/a"), &s2), (Some("demo/b"), &s4)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        let subs = digest
            .hot_era_fingerprints()
            .get(&IntervalIdx::from(9))
            .expect("interval 9 hot");
        assert_eq!(subs.len(), 2);
        assert_eq!(
            subs.get(&SubIntervalIdx::from(2)),
            Some(&event_fingerprint(Some("demo/a"), &s2))
        );
        assert_eq!(
            subs.get(&SubIntervalIdx::from(4)),
            Some(&event_fingerprint(Some("demo/b"), &s4))
        );
    }

    #[test]
    fn build_digest_excludes_intervals_newer_than_hot_upper() {
        let cfg = era_cfg();
        // hot_upper = 5, but the event is at interval 9 -> excluded entirely.
        let future = ts(at_secs(95), vec![0x01]);
        let events = [(Some("demo/a"), &future)];

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
        let events = [(Some("demo/a"), &e), (Some("demo/a"), &e)];

        let digest = build_digest(&cfg, events, IntervalIdx::from(10));

        assert!(
            digest.warm_era_fingerprints().is_empty(),
            "a net-zero interval is filtered out, not stored as zero"
        );
    }

    #[test]
    fn build_digest_empty_store_is_empty_but_carries_config_fp() {
        let cfg = era_cfg();
        let events: [(Option<&str>, &TimestampHint); 0] = [];

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
        let events = [
            (Some("demo/a"), &c),
            (Some("demo/b"), &w),
            (Some("demo/c"), &h),
        ];

        let a = build_digest(&cfg, events, IntervalIdx::from(10));
        let b = build_digest(&cfg, events, IntervalIdx::from(10));
        assert_eq!(a.diff(b), None);
    }

    #[test]
    fn diff_incompatible_configuration_is_none() {
        let cfg = era_cfg();
        let other_cfg = ReplicationConfig::new("other/**", None, 10_000, 5, 2, 3, 250);
        let h = ts(at_secs(95), vec![0x01]);

        let local = build_digest(&cfg, [(Some("demo/a"), &h)], IntervalIdx::from(10));
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

        let local = build_digest(&cfg, [(Some("demo/a"), &s2)], IntervalIdx::from(10));
        let remote = build_digest(
            &cfg,
            [(Some("demo/a"), &s2), (Some("demo/b"), &s4)],
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
        let local = build_digest(&cfg, [(Some("demo/a"), &here)], IntervalIdx::from(10));
        let remote = build_digest(&cfg, [(Some("demo/b"), &here)], IntervalIdx::from(10));

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

        let local = build_digest(&cfg, [(Some("demo/a"), &i7)], IntervalIdx::from(10));
        let remote = build_digest(
            &cfg,
            [(Some("demo/a"), &i7), (Some("demo/b"), &i8)],
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

        let local = build_digest(&cfg, [(Some("demo/a"), &c3)], IntervalIdx::from(10));
        let remote = build_digest(&cfg, [(Some("demo/b"), &c4)], IntervalIdx::from(10));

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
            [(Some("demo/a"), &s2), (Some("demo/b"), &s4)],
            IntervalIdx::from(10),
        );
        let remote = build_digest(&cfg, [(Some("demo/a"), &s2)], IntervalIdx::from(10));

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

        let local = build_digest(&cfg, [(Some("demo/a"), &s2)], IntervalIdx::from(10));
        // remote diverges in the hot era AND has a cold event local lacks.
        let remote = build_digest(
            &cfg,
            [
                (Some("demo/a"), &s2),
                (Some("demo/b"), &s4),
                (Some("demo/c"), &cold),
            ],
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
