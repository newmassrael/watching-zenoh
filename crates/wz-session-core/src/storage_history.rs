// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! `HashMap<key, StoredData>`, `memory_backend/mod.rs:79`). `History::All`
//! is the capability a persistent backend (influxdb / rocksdb) declares;
//! `get` then returns `Vec<StoredData>` (`zenoh-backend-traits/src/lib.rs:250-254`)
//! and the storage replies each version with its own timestamp
//! (`storages_mgt/service.rs:575-577 (wildcard) / :609-611 (non-wild)` — `q.reply(key, payload).timestamp(ts)`).
//! [`HistoryStorage`] is the in-memory realisation of that `All` shape — a
//! `BTreeMap<key, Vec<StoredData>>`, the versions kept sorted by timestamp.
//!
//! ## Deliberate divergences (each layer/profile-driven)
//!
//! - **Delete clears the key's versions.** zenoh's `All`-capable backends
//!   may keep a delete as a tombstone version; the minimal in-memory
//!   backend removes the whole version list (the `History::Latest`
//!   `delete` shape, lifted to the version list). Versioned tombstones
//!   (a delete that survives in the history) are a refinement, alongside
//!   the kernel GC / wildcard-override follow-ups.
//! - **Exact-timestamp duplicate replaces.** Two versions with an
//!   identical `(time, zid)` are the same logical event (uhlc timestamps
//!   are unique per source-tick), so the later one replaces rather than
//!   appends — the version list never holds two entries at one timestamp.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::sample::{EncodingHint, TimestampHint};
use crate::storage_backend::{History, StorageBackend, StorageInsertionResult, StoredData};

use crate::storage_state::timestamp_order_key;

/// In-memory [`History::All`] [`StorageBackend`]: a
/// `key -> Vec<StoredData>` map, each key's versions kept sorted by
/// timestamp (newest last). The multi-version counterpart of
/// [`MemoryStorage`](crate::storage_backend::MemoryStorage).
#[derive(Debug, Default)]
pub struct HistoryStorage {
    map: BTreeMap<String, Vec<StoredData>>,
}

impl HistoryStorage {
    /// A fresh, empty multi-version storage.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// The number of distinct keys currently stored (NOT the total version
    /// count).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the storage holds no keys.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Total number of versions stored under `key` (0 if absent).
    pub fn version_count(&self, key: &str) -> usize {
        self.map.get(key).map_or(0, Vec::len)
    }
}

impl StorageBackend for HistoryStorage {
    fn put(
        &mut self,
        key: &str,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageInsertionResult {
        let data = StoredData {
            payload,
            encoding,
            timestamp,
        };
        let versions = self.map.entry(key.to_string()).or_default();
        let existed = !versions.is_empty();
        // The version list is maintained sorted by `(time, zid)`, so a
        // binary search both locates an exact-timestamp duplicate (replace)
        // and yields the insertion point that keeps the list ordered.
        match versions
            // Sorted by the uhlc-faithful (time, 16-byte LE zid) key — the
            // SSOT comparator the newer-wins gate also uses, so version
            // ordering and the gate agree on what "newer" means.
            .binary_search_by(|v| {
                timestamp_order_key(&v.timestamp).cmp(&timestamp_order_key(&data.timestamp))
            }) {
            Ok(pos) => versions[pos] = data,
            Err(pos) => versions.insert(pos, data),
        }
        if existed {
            StorageInsertionResult::Replaced
        } else {
            StorageInsertionResult::Inserted
        }
    }

    fn delete(&mut self, key: &str, _timestamp: TimestampHint) -> StorageInsertionResult {
        // Minimal in-memory shape: a delete clears the whole version list
        // (see the module-level divergence note on versioned tombstones).
        self.map.remove(key);
        StorageInsertionResult::Deleted
    }

    fn get(&self, key: &str) -> Option<&StoredData> {
        // The newest version (the list is sorted newest-last).
        self.map.get(key).and_then(|versions| versions.last())
    }

    fn get_all_entries(&self) -> Vec<(String, TimestampHint)> {
        // One row per key, carrying its NEWEST timestamp (the wildcard scan
        // only needs the key set; see the `get_all_entries` trait doc).
        self.map
            .iter()
            .filter_map(|(k, versions)| {
                versions
                    .last()
                    .map(|newest| (k.clone(), newest.timestamp.clone()))
            })
            .collect()
    }

    fn history(&self) -> History {
        History::All
    }

    fn get_versions(&self, key: &str) -> Vec<&StoredData> {
        self.map
            .get(key)
            .map(|versions| versions.iter().collect())
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
            s.put("demo/a", vec![1], None, ts(10, 1)),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s.put("demo/a", vec![2], None, ts(20, 1)),
            StorageInsertionResult::Replaced
        );
        assert_eq!(s.version_count("demo/a"), 2, "both versions retained");
        let versions = s.get_versions("demo/a");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].payload, vec![1]);
        assert_eq!(versions[1].payload, vec![2]);
        // get() returns the newest.
        assert_eq!(s.get("demo/a").unwrap().payload, vec![2]);
    }

    #[test]
    fn out_of_order_put_is_inserted_in_timestamp_order() {
        let mut s = HistoryStorage::new();
        s.put("demo/a", vec![3], None, ts(30, 1));
        s.put("demo/a", vec![1], None, ts(10, 1)); // older, arrives later
        s.put("demo/a", vec![2], None, ts(20, 1));
        let versions = s.get_versions("demo/a");
        let payloads: Vec<&Vec<u8>> = versions.iter().map(|d| &d.payload).collect();
        assert_eq!(
            payloads,
            vec![&vec![1], &vec![2], &vec![3]],
            "versions sorted ascending by timestamp regardless of arrival order"
        );
        assert_eq!(
            s.get("demo/a").unwrap().payload,
            vec![3],
            "newest by timestamp, not by arrival"
        );
    }

    #[test]
    fn exact_timestamp_duplicate_replaces_not_appends() {
        let mut s = HistoryStorage::new();
        s.put("demo/a", vec![1], None, ts(10, 1));
        s.put("demo/a", vec![9], None, ts(10, 1)); // same (time, zid)
        assert_eq!(
            s.version_count("demo/a"),
            1,
            "an identical timestamp is the same version, replaced not appended"
        );
        assert_eq!(s.get("demo/a").unwrap().payload, vec![9]);
    }

    #[test]
    fn delete_clears_the_version_list() {
        let mut s = HistoryStorage::new();
        s.put("demo/a", vec![1], None, ts(10, 1));
        s.put("demo/a", vec![2], None, ts(20, 1));
        assert_eq!(
            s.delete("demo/a", ts(30, 1)),
            StorageInsertionResult::Deleted
        );
        assert_eq!(s.version_count("demo/a"), 0);
        assert!(s.get("demo/a").is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn get_all_entries_lists_each_key_once_with_its_newest_timestamp() {
        let mut s = HistoryStorage::new();
        s.put("demo/a", vec![1], None, ts(10, 1));
        s.put("demo/a", vec![2], None, ts(20, 1));
        s.put("demo/b", vec![3], None, ts(15, 1));
        let mut entries = s.get_all_entries();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                (String::from("demo/a"), ts(20, 1)),
                (String::from("demo/b"), ts(15, 1)),
            ],
            "one row per key with its newest timestamp"
        );
    }
}
