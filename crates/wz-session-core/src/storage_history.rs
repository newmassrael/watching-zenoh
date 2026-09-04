// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311uz — the `storage-history` atom (§5.11 storage domain, 2/4): an
//! in-memory [`History::All`](crate::storage_backend::History::All)
//! backend that keeps EVERY version per key, not just the latest.
//!
//! [`crate::storage_backend::MemoryStorage`] is `History::Latest` — one
//! value per key, an older Put dropped by the newer-wins gate above it.
//! [`HistoryStorage`] here is the `History::All` counterpart: every Put is
//! retained as a distinct version (ordered by timestamp), and a query
//! replies all of them. The service gate reads
//! [`StorageBackend::history`](crate::storage_backend::StorageBackend::history)
//! and skips the newer-wins drop for an `All` backend
//! (`crate::storage_state` — zenoh `storages_mgt/service.rs:319`).
//!
//! ## zenoh anchor
//!
//! zenoh's bundled in-memory backend is `History::Latest` only (a
//! `HashMap<Option<key>, StoredData>`, `memory_backend/mod.rs:79`).
//! `History::All` is the capability a persistent backend (influxdb /
//! rocksdb) declares; `get` then returns `Vec<StoredData>`
//! (`zenoh-backend-traits/src/lib.rs:250-254`) and the storage replies each
//! version with its own timestamp
//! (`storages_mgt/service.rs:575-577 (wildcard) / :609-611 (non-wild)` — `q.reply(key, payload).timestamp(ts)`).
//! [`HistoryStorage`] is the in-memory realisation of that `All` shape — a
//! `BTreeMap<Option<key>, Vec<StoredData>>`, the versions kept sorted by
//! timestamp. The key is `Option<String>` (R311y61, mirroring
//! [`MemoryStorage`](crate::storage_backend::MemoryStorage)): `None` is the
//! exact-prefix-match (mount-root) slot.
//!
//! ## Delete is a VERSIONED TOMBSTONE (R2350)
//!
//! A delete does NOT clear the key's versions. It appends a
//! `Version::Tombstone` at its own timestamp, and the *live* view of a
//! key is the suffix of its timeline after the newest tombstone. Two
//! properties follow, and both are the point:
//!
//! - **History survives a delete.** `History::All` is defined as "saves
//!   all the values including historical values"
//!   (`plugins/zenoh-backend-traits/src/lib.rs` @ `History::All saves all the values`).
//!   A delete that dropped the version list would keep the *latest* value
//!   semantics under an `All` capability — the one thing the capability
//!   exists not to do.
//! - **An out-of-order older Put cannot resurrect a deleted key.** With
//!   no newer-wins gate above an `All` backend
//!   (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `self.capability.history == History::Latest`,
//!   mirrored by `crate::storage_state::StorageState::latest_mode`), the ordering
//!   guarantee has to live *here*: a Put that lands at a timestamp at or
//!   below the newest tombstone is stored as history but is not live, so
//!   [`get`](crate::storage_backend::StorageBackend::get) and
//!   [`get_versions`](crate::storage_backend::StorageBackend::get_versions)
//!   do not serve it. A Put ABOVE the tombstone is live, which is how a
//!   key comes back.
//!
//! Because the timeline is kept sorted by timestamp, "after the newest
//! tombstone" is a SUFFIX, not a filter — see `HistoryStorage::live`.
//!
//! ### No upstream shape to copy — and why this is not a parity claim
//!
//! Measured against the pin (`zenoh` c479f0c, `plugins/`): `History::All`
//! occurs in the whole upstream tree exactly once, in the doc comment that
//! defines the enum. EVERY `get_capability` upstream returns
//! `History::Latest`
//! (`plugins/zenoh-plugin-storage-manager/src/memory_backend/mod.rs` @ `history: History::Latest`;
//! `plugins/zenoh-backend-example/src/lib.rs` @ `history: History::Latest`),
//! and the storage manager REFUSES to replicate a non-`Latest` storage at
//! all
//! (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/mod.rs` @ `Replication was enabled for storage`).
//! Upstream's own
//! `plugins/zenoh-backend-traits/src/lib.rs` @ `pub struct StoredData`
//! carries payload / encoding /
//! timestamp and no kind, so an upstream `All` backend could not return a
//! tombstone through `get` even if one existed. There is therefore no
//! upstream `All`-delete behaviour to be faithful TO; this shape is
//! answerable to wz's own
//! [`History::All`](crate::storage_backend::History::All) declaration, and
//! that is the ground it is justified on.
//!
//! ## Deliberate divergences (each layer/profile-driven)
//!
//! - **Exact-timestamp duplicate replaces.** Two versions with an
//!   identical `(time, zid)` are the same logical event (uhlc timestamps
//!   are unique per source-tick), so the later one replaces rather than
//!   appends — the version list never holds two entries at one timestamp.
//!   A delete and a put at one timestamp are likewise one event: the later
//!   arrival wins the slot.
//!
//! ## Retention is the capability, not a leak
//!
//! A tombstone is kept for the life of the store, and so is every version
//! it shadows. That is not a divergence from anything — it is what
//! `History::All` says. Note it is also not NEW as of R2350: this backend
//! already grew without bound on puts, since retaining every version is
//! the whole capability. What R2350 changed is that a delete no longer
//! frees the key. Bounding any of it (a retention window, a kernel GC) is
//! a policy this backend deliberately does not invent — a `History::All`
//! store that silently discarded history would be a `Latest` store with
//! extra steps.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sample::{EncodingHint, TimestampHint};
use crate::storage_backend::{
    History, StorageBackend, StorageInsertionResult, StorageWriteResult, StoredData,
};

use crate::sample::timestamp_order_key;

/// One entry in a key's timeline: a stored value, or the tombstone a
/// Delete leaves behind. Both carry the timestamp that orders them, and
/// the timeline is kept sorted on it.
///
/// A tombstone is NOT a `StoredData` with an empty payload: an empty
/// payload is a legitimate value, and the two must stay distinguishable —
/// a querier that receives an empty Put has been told the key holds
/// nothing, not that it was deleted.
#[derive(Debug)]
enum Version {
    /// A value stored at this version's timestamp.
    Put(StoredData),
    /// A Delete at this timestamp; shadows every version at or below it.
    Tombstone(TimestampHint),
}

impl Version {
    /// The timestamp that orders this entry in its key's timeline.
    fn timestamp(&self) -> &TimestampHint {
        match self {
            Version::Put(data) => &data.timestamp,
            Version::Tombstone(ts) => ts,
        }
    }
}

/// In-memory [`History::All`] [`StorageBackend`]: a `key -> timeline` map,
/// each key's `Version`s kept sorted by timestamp (newest last). The
/// multi-version counterpart of
/// [`MemoryStorage`](crate::storage_backend::MemoryStorage). Keyed on
/// `Option<String>` (`None` = the exact-prefix-match slot).
///
/// A Delete appends a tombstone rather than clearing the timeline; see the
/// module doc for why, and `Self::live` for the live/stored split that
/// follows from it.
#[derive(Debug, Default)]
pub struct HistoryStorage {
    map: BTreeMap<Option<String>, Vec<Version>>,
}

impl HistoryStorage {
    /// A fresh, empty multi-version storage.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// The LIVE suffix of one key's timeline: every version after the
    /// NEWEST tombstone, or the whole timeline when the key was never
    /// deleted. Contains only [`Version::Put`] by construction.
    ///
    /// A suffix rather than a filter because the timeline is sorted by
    /// timestamp: everything a tombstone shadows is, by definition,
    /// everything before it.
    fn live(versions: &[Version]) -> &[Version] {
        match versions
            .iter()
            .rposition(|v| matches!(v, Version::Tombstone(_)))
        {
            Some(newest_tombstone) => &versions[newest_tombstone + 1..],
            None => versions,
        }
    }

    /// Place `version` in `timeline`, keeping it sorted by `(time, zid)`.
    /// An entry already at that exact timestamp is the same logical event,
    /// so it is REPLACED (see the module doc's duplicate rule).
    fn insert_version(timeline: &mut Vec<Version>, version: Version) {
        match timeline.binary_search_by(|v| {
            // The uhlc-faithful (time, 16-byte LE zid) key — the SSOT
            // comparator the newer-wins gate also uses, so version ordering
            // and the gate agree on what "newer" means.
            timestamp_order_key(v.timestamp()).cmp(&timestamp_order_key(version.timestamp()))
        }) {
            Ok(pos) => timeline[pos] = version,
            Err(pos) => timeline.insert(pos, version),
        }
    }

    /// The number of distinct keys with a timeline (NOT the total version
    /// count, and NOT the live-key count — a key whose newest version is a
    /// tombstone still has a timeline and is still counted here).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the storage holds no timeline at all. A deleted key still
    /// has one, so this stays `false` after a delete — the history is the
    /// point of an [`History::All`] backend.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of LIVE versions under `key` (0 if absent or deleted) — the
    /// set a query replies. `key` is `None` for the exact-prefix-match
    /// slot. For the retained history behind a tombstone see
    /// [`Self::history_len`].
    pub fn version_count(&self, key: Option<&str>) -> usize {
        self.map
            .get(&key.map(String::from))
            .map_or(0, |t| Self::live(t).len())
    }

    /// Total number of entries in `key`'s timeline, tombstones and
    /// shadowed versions INCLUDED — the "all the values including
    /// historical values" count. Always `>= version_count`.
    pub fn history_len(&self, key: Option<&str>) -> usize {
        self.map.get(&key.map(String::from)).map_or(0, Vec::len)
    }

    /// Whether `key`'s newest timeline entry is a tombstone, i.e. the key
    /// is deleted even though its history is retained.
    pub fn is_deleted(&self, key: Option<&str>) -> bool {
        self.map
            .get(&key.map(String::from))
            .is_some_and(|t| matches!(t.last(), Some(Version::Tombstone(_))))
    }
}

impl StorageBackend for HistoryStorage {
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        let data = StoredData {
            payload,
            encoding,
            timestamp,
        };
        let timeline = self.map.entry(key.map(String::from)).or_default();
        // "Replaced" is about the LIVE value the caller would have read
        // back, so a Put onto a deleted key reports `Inserted` — the key
        // was absent, whatever its history holds.
        let existed = !Self::live(timeline).is_empty();
        Self::insert_version(timeline, Version::Put(data));
        // Always `Ok`: an in-memory timeline has no medium that can
        // refuse the write (the `StorageWriteError` channel exists for the
        // backends that do).
        Ok(if existed {
            StorageInsertionResult::Replaced
        } else {
            StorageInsertionResult::Inserted
        })
    }

    fn delete(&mut self, key: Option<&str>, timestamp: TimestampHint) -> StorageWriteResult {
        // Append the tombstone instead of clearing the timeline (module
        // doc). The entry is created even for a key never seen before: with
        // no newer-wins gate above an `All` backend, this tombstone is the
        // ONLY thing that can reject a Put that arrives later but is
        // stamped earlier, so it has to be recorded whether or not the
        // delete found a value.
        let timeline = self.map.entry(key.map(String::from)).or_default();
        Self::insert_version(timeline, Version::Tombstone(timestamp));
        Ok(StorageInsertionResult::Deleted)
    }

    fn get(&self, key: Option<&str>) -> Option<&StoredData> {
        // The newest LIVE version (the timeline is sorted newest-last, and
        // `live` drops everything the newest tombstone shadows).
        self.map.get(&key.map(String::from)).and_then(|timeline| {
            match Self::live(timeline).last() {
                Some(Version::Put(data)) => Some(data),
                // Unreachable by construction (`live` yields only Puts);
                // written as a match rather than an unwrap so a future
                // Version variant is a compile error, not a panic.
                Some(Version::Tombstone(_)) | None => None,
            }
        })
    }

    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
        // One row per LIVE key, carrying its newest live timestamp. A
        // deleted key is omitted, which is the contract every caller of
        // this seam already relies on ("get_all_entries drops deleted
        // keys", `crate::storage_state`): the wildcard-override scan and
        // `matching_entries` both treat a returned key as present.
        self.map
            .iter()
            .filter_map(|(k, timeline)| match Self::live(timeline).last() {
                Some(Version::Put(newest)) => Some((k.clone(), newest.timestamp.clone())),
                Some(Version::Tombstone(_)) | None => None,
            })
            .collect()
    }

    fn history(&self) -> History {
        History::All
    }

    fn get_versions(&self, key: Option<&str>) -> Vec<&StoredData> {
        // The LIVE versions — the query reply set. Shadowed history is
        // retained in the timeline but is not served: replying a version a
        // newer tombstone deleted would tell a querier the key is alive.
        self.map
            .get(&key.map(String::from))
            .map(|timeline| {
                Self::live(timeline)
                    .iter()
                    .filter_map(|v| match v {
                        Version::Put(data) => Some(data),
                        Version::Tombstone(_) => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ts(time: u64, zid: u8) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![zid],
        }
    }

    #[test]
    fn declares_history_all() {
        assert_eq!(HistoryStorage::new().history(), History::All);
    }

    #[test]
    fn put_retains_every_version_newest_last() {
        let mut s = HistoryStorage::new();
        assert_eq!(
            s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap(),
            StorageInsertionResult::Replaced
        );
        assert_eq!(s.version_count(Some("demo/a")), 2, "both versions retained");
        let versions = s.get_versions(Some("demo/a"));
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].payload, vec![1]);
        assert_eq!(versions[1].payload, vec![2]);
        // get() returns the newest.
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn out_of_order_put_is_inserted_in_timestamp_order() {
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![3], None, ts(30, 1)).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap(); // older, later
        s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap();
        let versions = s.get_versions(Some("demo/a"));
        let payloads: Vec<&Vec<u8>> = versions.iter().map(|d| &d.payload).collect();
        assert_eq!(
            payloads,
            vec![&vec![1], &vec![2], &vec![3]],
            "versions sorted ascending by timestamp regardless of arrival order"
        );
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
            vec![3],
            "newest by timestamp, not by arrival"
        );
    }

    #[test]
    fn exact_timestamp_duplicate_replaces_not_appends() {
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap();
        s.put(Some("demo/a"), vec![9], None, ts(10, 1)).unwrap(); // same (time, zid)
        assert_eq!(
            s.version_count(Some("demo/a")),
            1,
            "an identical timestamp is the same version, replaced not appended"
        );
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![9]);
    }

    #[test]
    fn delete_hides_the_versions_but_keeps_them_as_history() {
        // R2350 — the tombstone replaces the old "delete clears the version
        // list" shape. The key reads as absent; its history survives.
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap();
        s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap();
        assert_eq!(
            s.delete(Some("demo/a"), ts(30, 1)).unwrap(),
            StorageInsertionResult::Deleted
        );
        // The LIVE view: gone.
        assert_eq!(s.version_count(Some("demo/a")), 0, "no live version");
        assert!(s.get(Some("demo/a")).is_none(), "reads as deleted");
        assert!(
            s.get_versions(Some("demo/a")).is_empty(),
            "a query replies nothing for a deleted key"
        );
        assert!(
            s.get_all_entries().is_empty(),
            "the deleted key is dropped from the entry scan, the contract \
             `matching_entries` / the wildcard-override scan rely on"
        );
        // The HISTORY view: retained. This is the whole difference from the
        // pre-R2350 shape, where the version list was dropped outright.
        assert!(s.is_deleted(Some("demo/a")));
        assert_eq!(
            s.history_len(Some("demo/a")),
            3,
            "two puts and the tombstone survive as history"
        );
        assert!(!s.is_empty(), "the key still has a timeline");
    }

    #[test]
    fn a_post_delete_older_put_is_stored_but_does_not_resurrect_the_key() {
        // The ordering guarantee an `All` backend has to carry ITSELF: with
        // no newer-wins gate above it (`storage_state::latest_mode`), only
        // the tombstone can reject a Put that arrives later but is stamped
        // earlier. Pre-R2350 the delete had dropped the timeline, so this
        // put became the key's live value.
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![3], None, ts(30, 1)).unwrap();
        s.delete(Some("demo/a"), ts(40, 1)).unwrap();
        assert_eq!(
            s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap(),
            StorageInsertionResult::Inserted,
            "the key was absent, so the write is an insert, not a replace"
        );
        assert!(
            s.get(Some("demo/a")).is_none(),
            "a put stamped BELOW the tombstone must not resurrect the key"
        );
        assert!(s.get_versions(Some("demo/a")).is_empty());
        assert_eq!(
            s.history_len(Some("demo/a")),
            3,
            "it is still stored as history: put t=20, put t=30, tomb t=40"
        );
    }

    #[test]
    fn a_put_above_the_tombstone_is_live_again() {
        // The other half of the ordering rule: the tombstone shadows what is
        // at or BELOW it and nothing above, so a genuinely newer put brings
        // the key back. Without this the tombstone would be a permanent
        // grave rather than a version.
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![3], None, ts(30, 1)).unwrap();
        s.delete(Some("demo/a"), ts(40, 1)).unwrap();
        s.put(Some("demo/a"), vec![5], None, ts(50, 1)).unwrap();
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![5]);
        assert_eq!(
            s.version_count(Some("demo/a")),
            1,
            "only the post-tombstone version is live"
        );
        assert!(!s.is_deleted(Some("demo/a")));
        assert_eq!(
            s.get_all_entries(),
            vec![(Some(String::from("demo/a")), ts(50, 1))],
            "the revived key is back in the entry scan at its live timestamp"
        );
        assert_eq!(s.history_len(Some("demo/a")), 3);
    }

    #[test]
    fn an_older_delete_does_not_shadow_a_newer_put() {
        // A delete is ordered like any other version, so one that arrives
        // out of order lands BELOW the value it never applied to. Shadowing
        // by arrival order rather than by timestamp would lose the value.
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![5], None, ts(50, 1)).unwrap();
        s.delete(Some("demo/a"), ts(30, 1)).unwrap();
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
            vec![5],
            "the t=30 delete is older than the t=50 value it cannot delete"
        );
        assert!(!s.is_deleted(Some("demo/a")));
    }

    #[test]
    fn delete_of_a_never_seen_key_records_the_tombstone() {
        // The delete-before-put ordering case. `MemoryStorage` can no-op
        // here because its gate keeps the tombstone (`StorageState::latest`);
        // an `All` backend has no gate, so if the tombstone were not
        // recorded a later, older put would be served.
        let mut s = HistoryStorage::new();
        assert_eq!(
            s.delete(Some("demo/a"), ts(40, 1)).unwrap(),
            StorageInsertionResult::Deleted
        );
        s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap();
        assert!(
            s.get(Some("demo/a")).is_none(),
            "the recorded tombstone still shadows the older put"
        );
        assert_eq!(s.history_len(Some("demo/a")), 2);
    }

    #[test]
    fn a_delete_and_a_put_at_one_timestamp_are_one_event() {
        // The duplicate rule (module doc) covers tombstones too: the
        // timeline never holds two entries at one timestamp, so the later
        // arrival takes the slot. Left unhandled, a put and a delete at the
        // same uhlc stamp would both sit in the timeline and `live` would
        // depend on their insertion order.
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap();
        s.delete(Some("demo/a"), ts(10, 1)).unwrap();
        assert_eq!(s.history_len(Some("demo/a")), 1, "one slot at t=10");
        assert!(s.is_deleted(Some("demo/a")), "the delete arrived later");

        let mut s = HistoryStorage::new();
        s.delete(Some("demo/a"), ts(10, 1)).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap();
        assert_eq!(s.history_len(Some("demo/a")), 1);
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
            vec![1],
            "the put arrived later"
        );
    }

    #[test]
    fn get_all_entries_lists_each_key_once_with_its_newest_timestamp() {
        let mut s = HistoryStorage::new();
        s.put(Some("demo/a"), vec![1], None, ts(10, 1)).unwrap();
        s.put(Some("demo/a"), vec![2], None, ts(20, 1)).unwrap();
        s.put(Some("demo/b"), vec![3], None, ts(15, 1)).unwrap();
        let mut entries = s.get_all_entries();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                (Some(String::from("demo/a")), ts(20, 1)),
                (Some(String::from("demo/b")), ts(15, 1)),
            ],
            "one row per key with its newest timestamp"
        );
    }

    #[test]
    fn boxed_history_storage_keeps_all_through_the_blanket_impl() {
        // The `Box<B>` blanket impl (storage_backend.rs) forwards
        // `history` / `get_versions` EXPLICITLY rather than letting them
        // fall back to the trait defaults (which would collapse
        // `get_versions` to the single `get`). Drive a `History::All`
        // HistoryStorage entirely through a `Box<dyn StorageBackend + Send>`
        // — the boxed form a `Volume::create_storage` result is — and assert
        // the multi-version behaviour survives: the capability stays
        // `History::All` and `get_versions` returns both versions, not the
        // default-collapsed single one.
        let mut b: alloc::boxed::Box<dyn StorageBackend + Send> =
            alloc::boxed::Box::new(HistoryStorage::new());
        assert_eq!(
            b.put(Some("a"), vec![1], None, ts(10, 1)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            b.put(Some("a"), vec![2], None, ts(20, 1)).unwrap(),
            StorageInsertionResult::Replaced
        );
        assert_eq!(
            b.history(),
            History::All,
            "the boxed backend keeps its All capability (not the Latest default)"
        );
        let versions = b.get_versions(Some("a"));
        assert_eq!(
            versions.len(),
            2,
            "get_versions forwards to the All backend, not the default get-collapse"
        );
        assert_eq!(versions[0].payload, vec![1]);
        assert_eq!(versions[1].payload, vec![2]);
    }
}
