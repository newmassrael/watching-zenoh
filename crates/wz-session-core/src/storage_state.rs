// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ux — the storage *service gate* (§5.11 storage domain, atom 2/4):
//! the newer-wins decision + the query-match set, the runtime-agnostic
//! half of a storage service.
//!
//! [`crate::storage_backend`] is a dumb store — it overwrites verbatim and
//! never compares timestamps. [`StorageState`] here is the layer above it
//! that makes a store a *storage*: it applies **newer-wins** versioning
//! (an older Put/Delete is rejected as
//! [`Outdated`](crate::storage_backend::StorageInsertionResult::Outdated))
//! and resolves a (wildcard) query into the set of stored entries that
//! answer it. This is pure no_std logic — no Subscriber, no Queryable, no
//! async; the wz-runtime-tokio `StorageService` driver (atom 3) wraps a
//! [`StorageState`] in the Subscriber + complete-Queryable + select loop.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0
//! `plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs`:
//!
//! - The newer-wins gate = `guard_cache_if_latest` (service.rs:510-544):
//!   a mutation proceeds only when no *strictly newer* timestamp is
//!   already recorded for the key (`data.timestamp > new_event.timestamp`
//!   => reject, :536; the cache fast-path `new > cached` => accept, :516).
//!   So a tie (equal timestamp) is accepted — the gate is "reject iff a
//!   strictly-newer record exists", i.e. `accept ⇔ incoming >= recorded`.
//! - The latest-per-key record = `cache_latest.latest_updates`
//!   (`LatestUpdates`): the source of truth the gate compares against. It
//!   holds the latest accepted timestamp *whether the event was a Put or a
//!   Delete* — so a Delete leaves a **tombstone** timestamp behind, and a
//!   later older Put is correctly rejected instead of resurrecting the key.
//! - The query-match set = `get_matching_keys` (service.rs:628-658):
//!   iterate `get_all_entries()` and keep every stored key whose keyexpr
//!   `intersects` the query keyexpr (service.rs:646). wz reuses
//!   [`keyexpr_intersects_target`](crate::keyexpr_match::keyexpr_intersects_target)
//!   — the SAME matcher the pub/sub route and the local subscriber
//!   registry consult, so a storage's query-reply set cannot diverge from
//!   what a subscriber on the same keyexpr would have received.
//!
//! ## Timestamp ordering
//!
//! [`timestamp_strictly_newer`] mirrors uhlc's `Timestamp` `Ord`
//! (`uhlc-0.8.1/src/timestamp.rs:33-37`: derived `Ord` over
//! `(time: NTP64, id: ID)` in that field order = lexicographic time-then-id).
//! wz's [`TimestampHint`] carries the same `(time, zid)` shape, so the
//! comparison is `time` first, `zid` bytes as the tiebreak.
//!
//! ## Deliberate divergences (each layer/profile-driven)
//!
//! - **No separate cache vs storage split.** zenoh keeps `cache_latest` as
//!   an optimisation in front of the backend and falls back to
//!   `storage.get` on a cache miss (service.rs:521-541). The minimal
//!   in-memory state keeps ONE authoritative latest-per-key map
//!   ([`latest`](StorageState)) — it *is* the cache, always populated, so
//!   the storage-fallback branch never runs. A persistent backend that can
//!   outlive the process re-hydrating `latest` from `get_all_entries` is a
//!   later (durability) atom.
//! - **Tombstones are retained unbounded.** zenoh GCs stale wildcard /
//!   tombstone entries past a configured lifespan
//!   (`GarbageCollectionEvent`, service.rs:661-713). The minimal state
//!   retains every tombstone for correctness; the periodic GC is a
//!   follow-up (it rides the same timer tier as the storage-history /
//!   replication atoms).
//! - **No wildcard-update overriding.** zenoh lets a wildcard Put/Delete
//!   override later specific keys (`overriding_wild_update`,
//!   service.rs:415-494). The minimal state treats a wildcard key as an
//!   ordinary stored key; wildcard-update overriding is a dedicated
//!   follow-up atom (it needs the `KeBoxTree` wildcard registry zenoh
//!   keeps separately).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::keyexpr_match::keyexpr_intersects_target;
use crate::sample::{EncodingHint, TimestampHint};
use crate::storage_backend::{History, StorageBackend, StorageInsertionResult, StoredData};

/// Whether timestamp `a` is *strictly newer* than `b`. Lexicographic
/// `(time, zid)` — the uhlc `Timestamp` `Ord` semantic
/// (`uhlc-0.8.1/src/timestamp.rs:33-37`: derived `Ord` over `time: NTP64`
/// then `id: ID`). The single comparison the newer-wins gate keys off.
pub fn timestamp_strictly_newer(a: &TimestampHint, b: &TimestampHint) -> bool {
    a.time > b.time || (a.time == b.time && a.zid > b.zid)
}

/// The storage service gate: a [`StorageBackend`] plus the newer-wins
/// versioning + query-match logic that turns the dumb store into a storage.
/// zenoh `StorageService` minus its runtime driver (the Subscriber +
/// Queryable + select loop, which is the wz-runtime-tokio atom).
#[derive(Debug, Default)]
pub struct StorageState<B: StorageBackend> {
    backend: B,
    /// The latest accepted timestamp per key — the newer-wins comparison
    /// source (zenoh `cache_latest.latest_updates`). Populated on every
    /// accepted Put AND Delete, so a deleted key leaves a tombstone
    /// timestamp here even though its value is gone from `backend`; that is
    /// what makes an older Put after a Delete reject as Outdated instead of
    /// resurrecting the key.
    latest: BTreeMap<String, TimestampHint>,
}

impl<B: StorageBackend> StorageState<B> {
    /// Wrap a backend in the newer-wins service gate.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            latest: BTreeMap::new(),
        }
    }

    /// Whether the backend keeps only the latest value per key
    /// ([`History::Latest`]) — the mode in which the newer-wins gate runs.
    /// A [`History::All`] backend retains every version, so the gate is
    /// skipped (zenoh `storages_mgt/service.rs:319`).
    fn latest_mode(&self) -> bool {
        self.backend.history() == History::Latest
    }

    /// The newer-wins gate (zenoh `guard_cache_if_latest`,
    /// service.rs:510-544): `true` iff the mutation should proceed — i.e.
    /// no *strictly newer* timestamp is already recorded for `key`. A tie
    /// (equal timestamp) proceeds, mirroring zenoh's "reject iff
    /// `recorded > incoming`" (service.rs:536). Consulted only in
    /// [`History::Latest`] mode.
    fn accepts(&self, key: &str, incoming: &TimestampHint) -> bool {
        match self.latest.get(key) {
            Some(recorded) => !timestamp_strictly_newer(recorded, incoming),
            None => true,
        }
    }

    /// Process an inbound Put. In [`History::Latest`] mode the newer-wins
    /// gate runs: a strictly-older value returns
    /// [`Outdated`](StorageInsertionResult::Outdated) (backend untouched),
    /// otherwise the value is stored and its timestamp recorded. In
    /// [`History::All`] mode the gate is SKIPPED (zenoh
    /// service.rs:319) — every version is appended by the backend.
    pub fn process_put(
        &mut self,
        key: &str,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageInsertionResult {
        let latest_mode = self.latest_mode();
        if latest_mode && !self.accepts(key, &timestamp) {
            return StorageInsertionResult::Outdated;
        }
        let result = self.backend.put(key, payload, encoding, timestamp.clone());
        if latest_mode {
            self.latest.insert(key.to_string(), timestamp);
        }
        result
    }

    /// Process an inbound Delete. In [`History::Latest`] mode the newer-wins
    /// gate runs (a strictly-older delete returns
    /// [`Outdated`](StorageInsertionResult::Outdated)) and the accepted
    /// delete timestamp is retained as a **tombstone** (so a subsequent
    /// older Put cannot resurrect the key). In [`History::All`] mode the
    /// gate is skipped (the backend decides how a delete affects its
    /// version list).
    pub fn process_delete(
        &mut self,
        key: &str,
        timestamp: TimestampHint,
    ) -> StorageInsertionResult {
        let latest_mode = self.latest_mode();
        if latest_mode && !self.accepts(key, &timestamp) {
            return StorageInsertionResult::Outdated;
        }
        let result = self.backend.delete(key, timestamp.clone());
        if latest_mode {
            // Retain the delete timestamp as a tombstone — the value is gone
            // from the backend but the latest-accepted record survives, so
            // the newer-wins gate still rejects an older Put. zenoh keeps the
            // Delete event in `cache_latest.latest_updates` for this reason.
            self.latest.insert(key.to_string(), timestamp);
        }
        result
    }

    /// Exact-key read of the live stored value (none if absent or deleted).
    /// The direct (non-wildcard) query fast path.
    pub fn get(&self, key: &str) -> Option<&StoredData> {
        self.backend.get(key)
    }

    /// The set of live stored entries whose key answers a query on
    /// `query_keyexpr` — the queryable reply set. Mirrors zenoh
    /// `get_matching_keys` (service.rs:628-658): scan every stored key and
    /// keep those that `intersect` the query keyexpr, then pair each with
    /// its value. Deleted keys are absent (tombstones live only in the gate
    /// record, never in the backend), so a query never replies a deleted
    /// key.
    ///
    /// Wildcard awareness follows the composed keyexpr matcher: with the
    /// `keyexpr-wildcard-*` features a `demo/**` query matches `demo/a`;
    /// without them the matcher degrades to literal equality (the same
    /// graceful degradation every wz keyexpr scan shares).
    pub fn matching_entries(&self, query_keyexpr: &str) -> Vec<(String, &StoredData)> {
        let target_chunks: Vec<&str> = query_keyexpr.split('/').collect();
        let mut out = Vec::new();
        for (key, _ts) in self.backend.get_all_entries() {
            if keyexpr_intersects_target(&key, &target_chunks) {
                if let Some(data) = self.backend.get(&key) {
                    out.push((key, data));
                }
            }
        }
        out
    }

    /// The multi-version counterpart of [`matching_entries`](Self::matching_entries):
    /// every matching key paired with ALL its stored versions (newest
    /// last), the query reply set for a [`History::All`] storage. For a
    /// [`History::Latest`] backend each key yields its single value (the
    /// `get_versions` default returns 0-or-1), so the result collapses to
    /// the `matching_entries` shape with one version per key. Mirrors
    /// zenoh's `reply_query` replying every `StoredData` `get` returns
    /// (`storages_mgt/service.rs:584`).
    pub fn matching_versions(&self, query_keyexpr: &str) -> Vec<(String, Vec<&StoredData>)> {
        let target_chunks: Vec<&str> = query_keyexpr.split('/').collect();
        let mut out = Vec::new();
        for (key, _ts) in self.backend.get_all_entries() {
            if keyexpr_intersects_target(&key, &target_chunks) {
                let versions = self.backend.get_versions(&key);
                if !versions.is_empty() {
                    out.push((key, versions));
                }
            }
        }
        out
    }

    /// Borrow the underlying backend (read-only inspection / handoff).
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_backend::MemoryStorage;
    use alloc::vec;

    fn ts(time: u64, zid: u8) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![zid],
        }
    }

    fn state() -> StorageState<MemoryStorage> {
        StorageState::new(MemoryStorage::new())
    }

    #[test]
    fn newer_put_replaces_older_value() {
        let mut s = state();
        assert_eq!(
            s.process_put("demo/a", vec![1], None, ts(10, 1)),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s.process_put("demo/a", vec![2], None, ts(20, 1)),
            StorageInsertionResult::Replaced
        );
        assert_eq!(s.get("demo/a").unwrap().payload, vec![2]);
    }

    #[test]
    fn older_put_is_rejected_as_outdated_and_value_unchanged() {
        let mut s = state();
        s.process_put("demo/a", vec![9], None, ts(100, 1));
        let r = s.process_put("demo/a", vec![1], None, ts(1, 1));
        assert_eq!(r, StorageInsertionResult::Outdated);
        assert_eq!(
            s.get("demo/a").unwrap().payload,
            vec![9],
            "the outdated put must not overwrite the newer value"
        );
    }

    #[test]
    fn equal_timestamp_is_accepted_mirroring_zenoh_gate() {
        // zenoh's gate rejects iff a STRICTLY newer record exists
        // (service.rs:536 `data.timestamp > new`), so an equal timestamp
        // proceeds (Replaced).
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        let r = s.process_put("demo/a", vec![2], None, ts(10, 1));
        assert_eq!(r, StorageInsertionResult::Replaced);
        assert_eq!(s.get("demo/a").unwrap().payload, vec![2]);
    }

    #[test]
    fn zid_breaks_a_timestamp_tie_higher_zid_is_newer() {
        // Equal NTP64 time -> the zid bytes decide (uhlc Ord, time then
        // id). A put with the same time but a higher zid is strictly newer.
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        let r = s.process_put("demo/a", vec![2], None, ts(10, 2));
        assert_eq!(r, StorageInsertionResult::Replaced);
        // The reverse (lower zid at equal time) is older -> rejected.
        let r2 = s.process_put("demo/a", vec![3], None, ts(10, 1));
        assert_eq!(r2, StorageInsertionResult::Outdated);
        assert_eq!(s.get("demo/a").unwrap().payload, vec![2]);
    }

    #[test]
    fn delete_then_older_put_is_rejected_tombstone_holds() {
        // The correctness property the tombstone exists for: a Delete at
        // t=50 must block a Put at t=40 from resurrecting the key.
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        assert_eq!(
            s.process_delete("demo/a", ts(50, 1)),
            StorageInsertionResult::Deleted
        );
        assert!(s.get("demo/a").is_none(), "deleted value is gone");
        let r = s.process_put("demo/a", vec![2], None, ts(40, 1));
        assert_eq!(
            r,
            StorageInsertionResult::Outdated,
            "an older put after a delete must not resurrect the key"
        );
        assert!(s.get("demo/a").is_none());
    }

    #[test]
    fn delete_then_newer_put_resurrects_the_key() {
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        s.process_delete("demo/a", ts(50, 1));
        let r = s.process_put("demo/a", vec![2], None, ts(60, 1));
        assert_eq!(r, StorageInsertionResult::Inserted);
        assert_eq!(s.get("demo/a").unwrap().payload, vec![2]);
    }

    #[test]
    fn delete_older_than_stored_is_rejected() {
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(100, 1));
        let r = s.process_delete("demo/a", ts(50, 1));
        assert_eq!(r, StorageInsertionResult::Outdated);
        assert!(
            s.get("demo/a").is_some(),
            "an outdated delete must not remove the newer value"
        );
    }

    #[test]
    fn matching_entries_wildcard_returns_intersecting_live_keys() {
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        s.process_put("demo/b", vec![2], None, ts(10, 1));
        s.process_put("other/c", vec![3], None, ts(10, 1));
        let mut hits: Vec<String> = s
            .matching_entries("demo/*")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        hits.sort();
        assert_eq!(hits, vec![String::from("demo/a"), String::from("demo/b")]);
    }

    #[test]
    fn matching_entries_excludes_deleted_keys() {
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        s.process_put("demo/b", vec![2], None, ts(10, 1));
        s.process_delete("demo/a", ts(20, 1));
        let hits: Vec<String> = s
            .matching_entries("demo/**")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            hits,
            vec![String::from("demo/b")],
            "a deleted key must not appear in a query reply"
        );
    }

    #[test]
    fn matching_entries_exact_key_query() {
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(10, 1));
        s.process_put("demo/b", vec![2], None, ts(10, 1));
        let hits = s.matching_entries("demo/a");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "demo/a");
        assert_eq!(hits[0].1.payload, vec![1]);
    }

    #[test]
    fn matching_versions_on_latest_backend_yields_one_version_per_key() {
        // A History::Latest backend keeps one value per key, so
        // matching_versions collapses to the matching_entries shape.
        let mut s = state();
        s.process_put("demo/a", vec![1], None, ts(20, 1));
        s.process_put("demo/a", vec![2], None, ts(30, 1)); // replaces
        let hits = s.matching_versions("demo/a");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1.len(), 1, "Latest keeps one version");
        assert_eq!(hits[0].1[0].payload, vec![2]);
    }

    // The History::All path needs the storage-history backend.
    #[cfg(feature = "storage-history")]
    mod history {
        use super::*;
        use crate::storage_history::HistoryStorage;

        fn all_state() -> StorageState<HistoryStorage> {
            StorageState::new(HistoryStorage::new())
        }

        #[test]
        fn all_mode_skips_the_newer_wins_gate_and_retains_every_version() {
            let mut s = all_state();
            // Newest first, then an OLDER put: under Latest this would be
            // Outdated and dropped; under All it is retained.
            assert_eq!(
                s.process_put("demo/a", vec![3], None, ts(30, 1)),
                StorageInsertionResult::Inserted
            );
            let r = s.process_put("demo/a", vec![1], None, ts(10, 1));
            assert_ne!(
                r,
                StorageInsertionResult::Outdated,
                "History::All never drops an older value as Outdated"
            );
            let versions = s.matching_versions("demo/a");
            assert_eq!(versions.len(), 1, "one matching key");
            assert_eq!(versions[0].1.len(), 2, "both versions retained");
            // Sorted ascending by timestamp regardless of arrival.
            assert_eq!(versions[0].1[0].payload, vec![1]);
            assert_eq!(versions[0].1[1].payload, vec![3]);
        }

        #[test]
        fn matching_versions_wildcard_returns_all_versions_per_matching_key() {
            let mut s = all_state();
            s.process_put("demo/a", vec![1], None, ts(10, 1));
            s.process_put("demo/a", vec![2], None, ts(20, 1));
            s.process_put("demo/b", vec![9], None, ts(15, 1));
            let mut hits = s.matching_versions("demo/*");
            hits.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(hits.len(), 2);
            assert_eq!(hits[0].0, "demo/a");
            assert_eq!(hits[0].1.len(), 2, "demo/a has two versions");
            assert_eq!(hits[1].0, "demo/b");
            assert_eq!(hits[1].1.len(), 1);
        }
    }
}
