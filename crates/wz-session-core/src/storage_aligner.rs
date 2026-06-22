// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311vr — the storage-aligner *event metadata* atom (§5.11 storage
//! domain, aligner 1/N): the [`Action`] + [`EventMetadata`] a replica
//! exchanges during alignment. Pure no_std logic — no AlignmentQuery /
//! AlignmentReply protocol yet (the next atoms), no Session, no async.
//!
//! ## What alignment is
//!
//! The replication Digest track ([`crate::storage_replication`]) lets a
//! replica detect *which time buckets* diverge from a peer — a
//! [`DigestDiff`](crate::storage_replication::DigestDiff). Alignment is the
//! follow-up: the diverging replica queries the peer's *Aligner* to pull the
//! exact entries it is missing. The unit exchanged is the [`EventMetadata`] —
//! the `(key, timestamp, action)` of one stored event, enough for the
//! receiver to decide whether it already holds a newer copy or must retrieve
//! the payload. This atom lands that unit; the AlignmentQuery / AlignmentReply
//! protocol and the answer / pull engines build on it.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0
//! `plugins/zenoh-plugin-storage-manager/src/replication/log.rs`:
//!
//! - [`Action`] = `log::Action` (log.rs:43-49): the kind of a logged event.
//! - [`EventMetadata`] = `log::EventMetadata` (log.rs:98-128): the metadata a
//!   replica needs to assess whether it is missing an event.
//! - [`EventMetadata::fingerprint`] = `Event::compute_fingerprint`
//!   (log.rs:232-244) — reused verbatim via the
//!   [`event_fingerprint`](crate::storage_replication::event_fingerprint) SSOT
//!   the Digest is also assembled from, so "is this the same event" agrees
//!   between the digest and the aligner.
//!
//! ## Deliberate divergences (each documented)
//!
//! - **No Wildcard actions.** zenoh's `Action` has four variants — `Put`,
//!   `Delete`, `WildcardPut(ke)`, `WildcardDelete(ke)` (log.rs:43-49) —
//!   because its storage applies wildcard updates (a `put test/** 1`
//!   overriding a whole subtree). wz storage has no wildcard updates (the
//!   [`crate::storage_state`] / storage-backend deferral), so a wz event is
//!   only ever a `Put` or a `Delete`. Modelling only the two variants wz can
//!   actually produce keeps illegal states unrepresentable; the wildcard
//!   variants land if and when wz storage gains wildcard updates. A real
//!   zenoh replica that sends a wildcard event is therefore a known
//!   non-converging case until then — an honest residual the wire-interop
//!   atom carries.
//! - **No `timestamp_last_non_wildcard_update`.** zenoh's `EventMetadata`
//!   carries this extra timestamp (log.rs:104) *solely* to order wildcard
//!   updates against the non-wildcard events they override. With no wildcard
//!   updates it always equals `timestamp` and carries no information, so wz
//!   omits the redundant field (the wire-interop atom re-supplies it as
//!   `Some(timestamp)` when emitting zenoh-compatible bytes).
//! - **`key: String`, not `Option<OwnedKeyExpr>`.** wz carries no
//!   `strip_prefix` (the [`crate::storage_replication`] divergence note), so
//!   the stored key is always the full keyexpr and always present. zenoh's
//!   `stripped_key` is an `Option` because a strip that matches the prefix
//!   exactly yields `None`; with no strip the key is always `Some(full_key)`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::sample::TimestampHint;
use crate::storage_replication::{
    event_fingerprint, Fingerprint, IntervalIdx, ReplicationConfig, SubIntervalIdx,
};

/// The kind of a logged replication event. zenoh `log::Action` (log.rs:43-49),
/// minus the two wildcard variants wz storage cannot produce (see the module
/// divergence note).
///
/// Fieldless (wz's two actions carry no key, unlike zenoh's wildcard variants
/// which embed the wildcard keyexpr), so it is [`Copy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// A value was stored at the key.
    Put,
    /// The key was deleted — a tombstone. The value is gone from the backend
    /// but the accepted timestamp survives in the newer-wins gate, so an
    /// older Put cannot resurrect the key (the [`crate::storage_state`]
    /// tombstone).
    Delete,
}

/// The metadata a replica exchanges during alignment to decide whether it is
/// missing an event: the stored key, the timestamp it was accepted at, and
/// whether it was a Put or a Delete. zenoh `log::EventMetadata`
/// (log.rs:98-128).
///
/// This is the unit an AlignmentReply carries (and, for a Put, the key by
/// which the payload is then retrieved). Two replicas that hold the same event
/// compute the same [`fingerprint`](EventMetadata::fingerprint) — the identity
/// the digest and the aligner agree on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventMetadata {
    key: String,
    timestamp: TimestampHint,
    action: Action,
}

impl EventMetadata {
    /// The metadata of a `Put` at `key` accepted at `timestamp`.
    pub fn put(key: impl Into<String>, timestamp: TimestampHint) -> Self {
        Self {
            key: key.into(),
            timestamp,
            action: Action::Put,
        }
    }

    /// The metadata of a `Delete` (tombstone) at `key` accepted at
    /// `timestamp`.
    pub fn delete(key: impl Into<String>, timestamp: TimestampHint) -> Self {
        Self {
            key: key.into(),
            timestamp,
            action: Action::Delete,
        }
    }

    /// The stored key this event is for.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The timestamp the event was accepted at — the newer-wins ordering key
    /// a receiver compares against its own copy.
    pub fn timestamp(&self) -> &TimestampHint {
        &self.timestamp
    }

    /// Whether the event was a Put or a Delete.
    pub fn action(&self) -> Action {
        self.action
    }

    /// The [`Fingerprint`] identifying this event — the xxh3 of its
    /// `(key, timestamp)`, shared with the Digest via the
    /// [`event_fingerprint`](crate::storage_replication::event_fingerprint)
    /// SSOT.
    ///
    /// The action is deliberately NOT hashed: zenoh omits it too
    /// (log.rs:226-231); it adds no distinguishing power (under the
    /// newer-wins gate a Put and a Delete on the same key never share a
    /// timestamp), and hashing it would cost time on large stores. So a
    /// replica's event and a peer's copy of it produce the same fingerprint,
    /// which is exactly what makes the digest buckets — and therefore the
    /// alignment drill-down — compare.
    pub fn fingerprint(&self) -> Fingerprint {
        event_fingerprint(&self.key, &self.timestamp)
    }
}

/// A replica's stored events bucketed by `(interval, sub-interval)` — the
/// transient structure the aligner's answers are computed from. The wz
/// counterpart of zenoh's persistent `LogLatest` intervals / sub-intervals
/// (`classification.rs`): zenoh maintains them incrementally and reads the
/// answers off them, while wz rebuilds them from the
/// [`StorageState`](crate::storage_state::StorageState) snapshot on demand —
/// the same recompute-vs-incremental-log divergence the digest carries
/// ([`crate::storage_replication::build_digest`]).
///
/// Each sub-interval holds at most one event per key (the newer-wins gate
/// keeps a single timestamp per key), so a sub-interval is a
/// `Vec<EventMetadata>` of distinct-key events.
///
/// The answer methods mirror, one-to-one, the replies a zenoh Aligner sends:
/// [`cold_era_fingerprints`](EventBuckets::cold_era_fingerprints) =
/// `reply_cold_era`, [`sub_intervals_fingerprints`](EventBuckets::sub_intervals_fingerprints)
/// = `reply_sub_intervals`, [`events_in`](EventBuckets::events_in) =
/// `reply_events_metadata`, [`all_events`](EventBuckets::all_events) = the
/// `AlignmentQuery::All` walk (`aligner_query.rs`). The
/// [`AlignmentQuery`]/[`AlignmentReply`] enums and the answer engine that
/// dispatches these are the follow-up atoms.
#[derive(Debug, Clone)]
pub struct EventBuckets {
    intervals: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Vec<EventMetadata>>>,
}

impl EventBuckets {
    /// Bucket a replica's events by the time classification
    /// ([`ReplicationConfig::classify`]). The SSOT bucketing the aligner
    /// answers share — built on the same `(classify, event_fingerprint)` the
    /// Digest is, so an aligner sub-interval fingerprint equals the digest's
    /// for the same snapshot (the property the cross-impl interop rests on).
    pub fn from_events(
        events: impl IntoIterator<Item = EventMetadata>,
        config: &ReplicationConfig,
    ) -> Self {
        let mut intervals: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Vec<EventMetadata>>> =
            BTreeMap::new();
        for event in events {
            let (interval_idx, sub_interval_idx) = config.classify(event.timestamp().time);
            intervals
                .entry(interval_idx)
                .or_default()
                .entry(sub_interval_idx)
                .or_default()
                .push(event);
        }
        Self { intervals }
    }

    /// The [`Fingerprint`] of one sub-interval = the XOR of its events'
    /// fingerprints. zenoh `SubInterval.fingerprint`, maintained as
    /// `self.fingerprint ^= event.fingerprint()` on insert (classification.rs:183,
    /// :353). XOR is order-independent, so the recomputed value matches zenoh's
    /// incrementally-maintained one.
    fn sub_fingerprint(events: &[EventMetadata]) -> Fingerprint {
        events
            .iter()
            .fold(Fingerprint::default(), |acc, e| acc ^ e.fingerprint())
    }

    /// Per-interval [`Fingerprint`]s of the **Cold era** — every interval
    /// older than the warm-era lower bound — the answer to a Cold-era
    /// divergence. zenoh `Replication::reply_cold_era` (aligner_query.rs:187-210):
    /// the asking Replica compares these against its own to find which cold
    /// intervals differ, then asks for those intervals' sub-intervals.
    ///
    /// An interval's fingerprint is the XOR of all its events' fingerprints
    /// (equivalently the XOR of its sub-interval fingerprints, zenoh
    /// `Interval.fingerprint`, classification.rs:104-108). Cold intervals are
    /// `idx < warm_era_lower_bound(hot_era_upper_bound)`; the caller passes the
    /// current interval as the upper bound, exactly as zenoh recomputes it from
    /// `last_elapsed_interval` at answer time (aligner_query.rs:190-199).
    pub fn cold_era_fingerprints(
        &self,
        config: &ReplicationConfig,
        hot_era_upper_bound: IntervalIdx,
    ) -> BTreeMap<IntervalIdx, Fingerprint> {
        let warm_lower = config.warm_era_lower_bound(hot_era_upper_bound);
        self.intervals
            .iter()
            .filter(|(&idx, _)| idx < warm_lower)
            .map(|(idx, subs)| {
                let interval_fp = subs.values().fold(Fingerprint::default(), |acc, evs| {
                    acc ^ Self::sub_fingerprint(evs)
                });
                (*idx, interval_fp)
            })
            .collect()
    }

    /// Per-sub-interval [`Fingerprint`]s of the requested `intervals` — the
    /// answer telling an asking Replica which sub-intervals to inspect. zenoh
    /// `Replication::reply_sub_intervals` (aligner_query.rs:216-235) via
    /// `Interval::sub_intervals_fingerprints` (classification.rs:161-167):
    ///
    /// - an interval absent from this replica contributes nothing (skipped);
    /// - **zero-fingerprint sub-intervals are dropped** — an absent cell and a
    ///   zero cell must diff differently, so a sub-interval whose events happen
    ///   to XOR to zero is omitted (defensive: distinct-key events make this
    ///   effectively unreachable, but the filter keeps byte-parity with zenoh).
    pub fn sub_intervals_fingerprints(
        &self,
        intervals: &BTreeSet<IntervalIdx>,
    ) -> BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> {
        let mut out = BTreeMap::new();
        for interval_idx in intervals {
            if let Some(subs) = self.intervals.get(interval_idx) {
                let fps: BTreeMap<SubIntervalIdx, Fingerprint> = subs
                    .iter()
                    .map(|(sub_idx, evs)| (*sub_idx, Self::sub_fingerprint(evs)))
                    .filter(|(_, fp)| *fp != Fingerprint::default())
                    .collect();
                out.insert(*interval_idx, fps);
            }
        }
        out
    }

    /// The [`EventMetadata`] of every event in the requested
    /// `(interval, sub-interval)` cells — the answer naming the exact events
    /// an asking Replica should consider. zenoh
    /// `Replication::reply_events_metadata` (aligner_query.rs:242-265): a cell
    /// absent from this replica contributes nothing.
    pub fn events_in(
        &self,
        sub_intervals: &BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>>,
    ) -> Vec<EventMetadata> {
        let mut out = Vec::new();
        for (interval_idx, subs) in sub_intervals {
            if let Some(interval) = self.intervals.get(interval_idx) {
                for sub_idx in subs {
                    if let Some(events) = interval.get(sub_idx) {
                        out.extend(events.iter().cloned());
                    }
                }
            }
        }
        out
    }

    /// Every event's [`EventMetadata`], the answer to an `AlignmentQuery::All`
    /// (the initial full transfer when a fresh replica joins). zenoh walks
    /// every interval / sub-interval and replies each event
    /// (aligner_query.rs:103-135).
    pub fn all_events(&self) -> Vec<EventMetadata> {
        self.intervals
            .values()
            .flat_map(|subs| subs.values())
            .flat_map(|events| events.iter().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_replication::event_fingerprint;
    use alloc::vec;

    fn ts(time: u64, zid: u8) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![zid],
        }
    }

    #[test]
    fn put_and_delete_carry_their_fields() {
        let p = EventMetadata::put("demo/a", ts(100, 1));
        assert_eq!(p.key(), "demo/a");
        assert_eq!(p.timestamp(), &ts(100, 1));
        assert_eq!(p.action(), Action::Put);

        let d = EventMetadata::delete("demo/a", ts(101, 1));
        assert_eq!(d.key(), "demo/a");
        assert_eq!(d.timestamp(), &ts(101, 1));
        assert_eq!(d.action(), Action::Delete);
    }

    #[test]
    fn fingerprint_is_the_digest_event_fingerprint_ssot() {
        // The aligner identity is byte-identical to the digest's per-event
        // fingerprint, so an event and a peer's copy of it agree.
        let meta = EventMetadata::put("demo/a", ts(100, 1));
        assert_eq!(meta.fingerprint(), event_fingerprint("demo/a", &ts(100, 1)));
    }

    #[test]
    fn fingerprint_ignores_the_action() {
        // A Put and a Delete at the same (key, timestamp) hash identically —
        // the action is not part of the fingerprint (log.rs:226-231).
        let put = EventMetadata::put("demo/a", ts(100, 1));
        let del = EventMetadata::delete("demo/a", ts(100, 1));
        assert_eq!(put.fingerprint(), del.fingerprint());
        // ...yet they are distinct events: equality keeps the action.
        assert_ne!(put, del);
    }

    #[test]
    fn fingerprint_is_field_sensitive_in_key_and_timestamp() {
        let base = EventMetadata::put("demo/a", ts(100, 1)).fingerprint();
        assert_ne!(base, EventMetadata::put("demo/b", ts(100, 1)).fingerprint());
        assert_ne!(base, EventMetadata::put("demo/a", ts(101, 1)).fingerprint());
        assert_ne!(base, EventMetadata::put("demo/a", ts(100, 2)).fingerprint());
    }

    #[test]
    fn equality_distinguishes_every_field() {
        let base = EventMetadata::put("demo/a", ts(100, 1));
        assert_eq!(base, EventMetadata::put("demo/a", ts(100, 1)));
        assert_ne!(base, EventMetadata::put("demo/b", ts(100, 1)));
        assert_ne!(base, EventMetadata::put("demo/a", ts(101, 1)));
        assert_ne!(base, EventMetadata::delete("demo/a", ts(100, 1)));
    }

    // --- EventBuckets (the snapshot answer primitives) ---

    use crate::storage_replication::build_digest;
    use alloc::string::ToString;

    // interval_ms=1000 (1 interval = 1s), sub_intervals=2 (sub_width=500ms),
    // hot=2, warm=2. So for hot_era_upper_bound H: warm_lower = H-3,
    // hot_lower = H-1; intervals < H-3 are Cold, [H-3, H-1) Warm, >= H-1 Hot.
    fn cfg2() -> ReplicationConfig {
        ReplicationConfig::new("demo/**", None, 1000, 2, 2, 2, 250)
    }

    // An NTP64 timestamp that classifies to exactly (interval, sub) under
    // cfg2: sub 0 = the interval's second on the dot, sub 1 = +500ms (frac
    // 2^31, which `ntp64_to_ms` renders as exactly 500ms).
    fn at(interval: u64, sub: u64) -> TimestampHint {
        let frac = match sub {
            0 => 0u64,
            1 => 1u64 << 31,
            _ => panic!("cfg2 has 2 sub-intervals"),
        };
        TimestampHint {
            time: (interval << 32) | frac,
            zid: vec![0x01],
        }
    }

    // A snapshot spanning all three eras at hot_upper = 10 (warm_lower=7,
    // hot_lower=9): cold {2,3}, warm {7}, hot {9,10}.
    fn spanning_snapshot() -> Vec<EventMetadata> {
        vec![
            EventMetadata::put("k/cold2", at(2, 0)),
            EventMetadata::put("k/cold3", at(3, 1)),
            EventMetadata::put("k/warm7", at(7, 0)),
            EventMetadata::put("k/hot9a", at(9, 0)),
            EventMetadata::put("k/hot9b", at(9, 1)),
            // A tombstone is a first-class aligner event too.
            EventMetadata::delete("k/hot10", at(10, 0)),
        ]
    }

    #[test]
    fn from_events_and_all_events_preserve_the_set() {
        let events = spanning_snapshot();
        let buckets = EventBuckets::from_events(events.clone(), &cfg2());
        let all = buckets.all_events();
        assert_eq!(all.len(), events.len());
        for e in &events {
            assert!(all.contains(e), "every input event survives bucketing");
        }
    }

    #[test]
    fn events_in_returns_exactly_the_requested_cells() {
        let buckets = EventBuckets::from_events(spanning_snapshot(), &cfg2());
        // Request interval 9's both sub-intervals + an absent cell.
        let mut req: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> = BTreeMap::new();
        req.insert(
            IntervalIdx::from(9),
            [SubIntervalIdx::from(0), SubIntervalIdx::from(1)]
                .into_iter()
                .collect(),
        );
        // Interval 99 is absent -> contributes nothing.
        req.insert(
            IntervalIdx::from(99),
            [SubIntervalIdx::from(0)].into_iter().collect(),
        );

        let got = buckets.events_in(&req);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&EventMetadata::put("k/hot9a", at(9, 0))));
        assert!(got.contains(&EventMetadata::put("k/hot9b", at(9, 1))));
    }

    #[test]
    fn cold_era_fingerprints_cover_only_cold_intervals() {
        let buckets = EventBuckets::from_events(spanning_snapshot(), &cfg2());
        let cold = buckets.cold_era_fingerprints(&cfg2(), IntervalIdx::from(10));
        // warm_lower = 7, so only intervals 2 and 3 are cold.
        let keys: BTreeSet<IntervalIdx> = cold.keys().copied().collect();
        assert_eq!(
            keys,
            [IntervalIdx::from(2), IntervalIdx::from(3)]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn sub_intervals_fingerprints_skips_an_absent_interval() {
        let buckets = EventBuckets::from_events(spanning_snapshot(), &cfg2());
        let req: BTreeSet<IntervalIdx> = [IntervalIdx::from(9), IntervalIdx::from(99)]
            .into_iter()
            .collect();
        let got = buckets.sub_intervals_fingerprints(&req);
        assert!(got.contains_key(&IntervalIdx::from(9)));
        assert!(
            !got.contains_key(&IntervalIdx::from(99)),
            "an interval absent from this replica contributes no entry"
        );
        // Interval 9 has events in sub 0 and sub 1.
        assert_eq!(got[&IntervalIdx::from(9)].len(), 2);
    }

    // The SSOT invariant: the aligner's per-era fingerprints, computed off the
    // EventBuckets, equal the Digest's for the same snapshot. This is what
    // makes a divergence the digest localises answerable by the aligner (and
    // what the cross-impl byte interop rests on).
    #[test]
    fn aligner_fingerprints_match_the_digest_for_the_same_snapshot() {
        let cfg = cfg2();
        let hot_upper = IntervalIdx::from(10);
        let events = spanning_snapshot();

        let kt: Vec<(alloc::string::String, TimestampHint)> = events
            .iter()
            .map(|e| (e.key().to_string(), e.timestamp().clone()))
            .collect();
        let digest = build_digest(&cfg, kt.iter().map(|(k, t)| (k.as_str(), t)), hot_upper);
        let buckets = EventBuckets::from_events(events, &cfg);

        // HOT: the per-sub map is byte-identical to the digest's hot map.
        let hot_keys: BTreeSet<IntervalIdx> =
            digest.hot_era_fingerprints().keys().copied().collect();
        assert_eq!(
            buckets.sub_intervals_fingerprints(&hot_keys),
            *digest.hot_era_fingerprints()
        );

        // COLD: the XOR of the per-interval cold fingerprints equals the
        // digest's single rolled-up cold fingerprint.
        let cold = buckets.cold_era_fingerprints(&cfg, hot_upper);
        let cold_xor = cold
            .values()
            .fold(Fingerprint::default(), |acc, fp| acc ^ *fp);
        assert_eq!(cold_xor, digest.cold_era_fingerprint());

        // WARM: each warm interval's sub fingerprints XOR to the digest's
        // per-interval warm fingerprint.
        for (idx, warm_fp) in digest.warm_era_fingerprints() {
            let set: BTreeSet<IntervalIdx> = [*idx].into_iter().collect();
            let subs = buckets.sub_intervals_fingerprints(&set);
            let interval_fp = subs[idx]
                .values()
                .fold(Fingerprint::default(), |acc, fp| acc ^ *fp);
            assert_eq!(interval_fp, *warm_fp);
        }
    }
}
