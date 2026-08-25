// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311uw — the `storage-backend` atom (§5.11 storage domain, 1/4): the
//! pluggable storage-backend seam + an in-memory backend.
//!
//! A zenoh storage is a server-side service that captures every Put/Delete
//! on a key_expr (a Subscriber) and serves the stored data back on a query
//! (a complete Queryable). Underneath that service sits a *backend*: the
//! technology that actually holds the bytes (memory / rocksdb / filesystem
//! / influxdb). This module lands the **backend layer** — the trait every
//! backend implements and the in-memory implementation — runtime-agnostic
//! and `no_std`, so the same kernel composes on AP and (heap-permitting)
//! MCU profiles, mirroring the [`crate::routing`] data-plane kernel split.
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `zenoh-backend-traits`
//! (`plugins/zenoh-backend-traits/src/lib.rs`) and the bundled in-memory
//! backend (`plugins/zenoh-plugin-storage-manager/src/memory_backend/mod.rs`):
//!
//! - [`StorageInsertionResult`] = `StorageInsertionResult` (lib.rs:170-175):
//!   the four-way outcome of a mutation.
//! - [`StoredData`] = `StoredData` (lib.rs:177-182): a versioned value
//!   (`{ payload, encoding, timestamp }`).
//! - [`StorageBackend`] = the `Storage` trait (lib.rs:219-260): `put` /
//!   `delete` / `get` / `get_all_entries`.
//! - [`MemoryStorage`] = `MemoryStorage` (memory_backend/mod.rs:78-158): a
//!   keyexpr -> [`StoredData`] map.
//!
//! ## Deliberate divergences from zenoh (each a layer/profile decision)
//!
//! - **sync, not `async`**: zenoh's trait methods are `async` because a
//!   real backend (rocksdb, network) blocks. The no_std kernel seam stays
//!   sync — the in-memory backend never awaits, and an `async` backend is
//!   an AP-side wrapper over a sync core. The seam mirrored here is the
//!   data shape, not the await coloring.
//! - **`Option<&str>` key** (R311y61): zenoh keys are `Option<OwnedKeyExpr>`
//!   (`None` == the configured `strip_prefix` matched the storage key_expr
//!   exactly, so the value sits AT the mount point under the "none" key,
//!   lib.rs:225). wz now mirrors this exactly: a backend keys on
//!   `Option<&str>`, `None` being the exact-prefix-match slot. The
//!   strip/restore that *produces* the `None` lives one layer up in the
//!   storage service gate ([`crate::storage_state::StorageState`] +
//!   [`crate::storage_strip_prefix`]); the bare backend just stores under
//!   whatever (already-stripped) key it is handed. Before R311y61 the key
//!   was a bare `&str` (no `strip_prefix` support); the Option key is the
//!   seam change that lets a strip-configured storage hold the mount-root
//!   value.
//! - **a payload-free error, not `ZResult`**: zenoh wraps the mutation result
//!   in `ZResult` (a boxed, message-carrying error). wz keeps the error
//!   *channel* — a backend over a real medium can refuse a write, and R311y831
//!   made the seam say so — but the error is the unit
//!   [`StorageWriteError`], for the reasons on that type. Before R311y831 the
//!   seam had no channel at all, which let the durable filesystem backend
//!   serve a value it had failed to persist.
//! - **`BTreeMap`, not `HashMap`**: zenoh's memory backend is a
//!   `HashMap<Option<OwnedKeyExpr>, StoredData>` (memory_backend/mod.rs:79);
//!   the no_std kernel has no std hasher, and the exact-key lookup is
//!   semantically identical (a key->value store does not depend on iteration
//!   order — [`MemoryStorage::get_all_entries`] simply yields keys sorted,
//!   with the `None` key — if present — ordering first).
//! - **`get` returns `Option`, not `Vec`**: zenoh's `get` returns
//!   `Vec<StoredData>` because History::All (lib.rs:164-168) may hold
//!   several versions per key; the History::Latest in-memory backend holds
//!   at most one, so wz returns `Option`. The `Vec` (version-history) form
//!   arrives with the `storage-history` atom.
//! - **`StoredData.encoding` is `Option<EncodingHint>`, not a concrete
//!   `Encoding`**: zenoh's `StoredData.encoding` is a non-optional
//!   `Encoding` (it defaults to `Encoding::default()`); wz models an absent
//!   encoding as `None`, matching how a wz [`crate::sample::Sample`] carries
//!   `Option<EncodingHint>` on the receive side. The stored encoding IS
//!   served back on the query reply (the `reply_keyed_stamped` encoding
//!   leg, mirroring zenoh's `q.reply(..).encoding(entry.encoding)`), so the
//!   field round-trips — captured on Put, returned on get.
//!
//! ## NON-goals (this atom)
//!
//! The **newer-wins** decision (zenoh keeps it in the storage *service*,
//! `guard_cache_if_latest`, `storages_mgt/service.rs:510-544`, NOT in the
//! backend — the bare backend overwrites verbatim), the query-side keyexpr
//! matching (resolving a wildcard query against the stored set), and the
//! `StorageService` driver (the Subscriber + complete Queryable + select
//! loop, an AP wz-runtime-tokio binding) are the follow-up atoms. This
//! atom is the runtime-agnostic backend foundation they sit on.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sample::{EncodingHint, TimestampHint};

/// The four-way outcome of a storage mutation. zenoh
/// `StorageInsertionResult` (`zenoh-backend-traits/src/lib.rs:170-175`).
///
/// [`Outdated`](StorageInsertionResult::Outdated) is part of the contract
/// but a *bare* [`MemoryStorage`] never returns it — it overwrites
/// verbatim. Outdated is produced by the newer-wins service gate that sits
/// above a backend (zenoh `guard_cache_if_latest`, the follow-up atom).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageInsertionResult {
    /// The mutation was older than the stored value and was rejected
    /// (produced by the newer-wins gate above the backend, never by the
    /// bare backend itself).
    Outdated,
    /// A new key was created.
    Inserted,
    /// An existing key's value was overwritten.
    Replaced,
    /// A key's entry was removed.
    Deleted,
}

/// A mutation the backend could not commit to its medium. zenoh's `Storage`
/// trait returns `ZResult<StorageInsertionResult>` and its filesystem backend
/// propagates the write error with `?`
/// (`zenoh-backend-filesystem/src/lib.rs:294-353`); wz mirrors the *presence*
/// of the error channel, not its payload.
///
/// **Payload-free on purpose** (the [`EntropyUnavailable`](crate::entropy::EntropyUnavailable)
/// precedent). Two things follow from that choice. The kernel is `no_std` and
/// this type sits in the return value of every `put` / `delete`, so a
/// `String`/`Box<dyn Error>` payload would be carried on the success path of an
/// MCU profile to describe a failure only an AP-side backend can produce. And
/// there is nothing a caller can DO with the detail: every caller in this tree
/// takes the same branch — do not record the mutation — while the backend that
/// owns the medium already has the concrete `io::Error` and logs it. The
/// operator reads the cause; the caller reads the fact.
///
/// The distinction between "nothing reached the medium" and "the medium
/// changed but the change is not confirmed durable" is deliberately NOT at this
/// seam either: it decides whether a backend's own in-memory mirror moves,
/// which is that backend's bookkeeping, and both answers mean the same thing
/// here — this mutation is not committed, so nothing above may claim it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageWriteError;

impl core::fmt::Display for StorageWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the storage backend could not commit the mutation")
    }
}

/// The outcome of a backend mutation: the four-way
/// [`StorageInsertionResult`], or [`StorageWriteError`] when the backend could
/// not commit it. zenoh `ZResult<StorageInsertionResult>`
/// (`zenoh-backend-traits/src/lib.rs:219-260`).
pub type StorageWriteResult = Result<StorageInsertionResult, StorageWriteError>;

/// How many values a backend keeps per key. zenoh `History`
/// (`zenoh-backend-traits/src/lib.rs:164-168`).
///
/// The mode drives the service gate above the backend: under
/// [`Latest`](History::Latest) the newer-wins gate keeps only the newest
/// value (an outdated mutation is dropped), under [`All`](History::All)
/// the gate is skipped and every version is retained (zenoh
/// `storages_mgt/service.rs:319` — `guard_cache_if_latest` runs only for
/// `History::Latest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum History {
    /// Keep only the newest value per key (the default; the in-memory
    /// [`MemoryStorage`] mode). zenoh `History::Latest`.
    #[default]
    Latest,
    /// Keep every value per key, including historical / out-of-order ones
    /// (the `storage-history` [`crate::storage_history::HistoryStorage`]
    /// mode). zenoh `History::All`.
    All,
}

/// A single versioned value held by a backend. zenoh `StoredData`
/// (`zenoh-backend-traits/src/lib.rs:177-182`:
/// `{ payload: ZBytes, encoding: Encoding, timestamp: Timestamp }`). wz
/// projects the codec types through the application-owned [`crate::sample`]
/// mirrors ([`EncodingHint`] / [`TimestampHint`]) so a stored value carries
/// the same `Clone` / `PartialEq` surface a [`crate::sample::Sample`] does.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredData {
    /// The stored payload bytes.
    pub payload: Vec<u8>,
    /// The encoding the value was published with, if any. Captured on Put
    /// and served back on the query reply (the `reply_keyed_stamped`
    /// encoding leg), so the value renders on the querier exactly as
    /// published.
    pub encoding: Option<EncodingHint>,
    /// The timestamp that versioned this value — the key the newer-wins
    /// gate (follow-up atom) compares against.
    pub timestamp: TimestampHint,
}

/// The pluggable storage-backend seam: the contract every concrete backend
/// (memory / rocksdb / filesystem / influxdb) implements so a storage
/// service drives any of them through one interface. zenoh `Storage`
/// (`zenoh-backend-traits/src/lib.rs:219-260`).
///
/// A backend is a dumb store: it does NOT compare timestamps. Newer-wins
/// versioning is the service's job (zenoh `guard_cache_if_latest`,
/// `storages_mgt/service.rs:510-544`), so a `put` of an older value still
/// [`Replaced`](StorageInsertionResult::Replaced)s the stored one here —
/// the gate above the backend is what rejects it as
/// [`Outdated`](StorageInsertionResult::Outdated). Keeping the backend
/// comparison-free is what lets the newer-wins gate be the single,
/// testable place that decision lives.
///
/// The `key` is `Option<&str>` (zenoh `Option<OwnedKeyExpr>`): `None` is the
/// exact-prefix-match slot — the value of a strip-configured storage whose
/// incoming key equalled the `strip_prefix` exactly (it sits AT the mount
/// point). The strip transform that yields the `None` lives in the service
/// gate ([`crate::storage_state`] / [`crate::storage_strip_prefix`]); the
/// backend just stores under whatever stripped key it is handed.
pub trait StorageBackend {
    /// Store `payload` / `encoding` under `key`, versioned by `timestamp`.
    /// Returns [`Inserted`](StorageInsertionResult::Inserted) for a new
    /// key, [`Replaced`](StorageInsertionResult::Replaced) for an existing
    /// one. Does NOT compare timestamps (zenoh memory_backend `put`,
    /// `memory_backend/mod.rs:97-122`: Occupied -> Replaced, Vacant ->
    /// Inserted). `key` is `None` for the exact-prefix-match (mount-root)
    /// slot.
    ///
    /// # Contract on failure
    ///
    /// [`Err`] means **the mutation is not committed**, and the two halves of
    /// that are separate obligations. A backend that returns `Err` must not
    /// leave a caller able to read the mutation back as if it had succeeded:
    /// whatever this backend serves from [`get`](StorageBackend::get) and
    /// lists from [`get_all_entries`](StorageBackend::get_all_entries) must be
    /// what a *reopen of the same medium* would show. And the layers above —
    /// the newer-wins gate, the replication log, the aligner digest — must
    /// record nothing, which is what [`StorageState::process_put`](crate::storage_state::StorageState::process_put)
    /// enforces by propagating rather than recording.
    ///
    /// An in-memory backend is infallible and always returns [`Ok`].
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult;

    /// Remove `key`. Returns [`Deleted`](StorageInsertionResult::Deleted)
    /// unconditionally — even for an absent key (zenoh memory_backend
    /// `delete`, `memory_backend/mod.rs:126-133`: `remove_entry` then
    /// `Deleted`; the filesystem backend's `if file.exists()` is the same
    /// absent-is-success rule, `files_mgt.rs:198`). `timestamp` is accepted
    /// for contract parity (a history / replication backend records the delete
    /// version); the bare in-memory backend drops the entry.
    ///
    /// [`Err`] carries the same contract as [`put`](StorageBackend::put): the
    /// key was NOT removed as far as anything above this seam is concerned.
    fn delete(&mut self, key: Option<&str>, timestamp: TimestampHint) -> StorageWriteResult;

    /// Retrieve the value stored under an exact `key`, if any. zenoh `get`
    /// (`zenoh-backend-traits/src/lib.rs:250-254`) returns
    /// `Vec<StoredData>` for History::All; the History::Latest in-memory
    /// backend holds at most one value per key, so wz returns `Option`
    /// (the `Vec` form arrives with `storage-history`). `key` is `None` for
    /// the exact-prefix-match slot.
    fn get(&self, key: Option<&str>) -> Option<&StoredData>;

    /// List every stored `(key, timestamp)` pair — the input the query
    /// path resolves a wildcard query against. zenoh `get_all_entries`
    /// (`zenoh-backend-traits/src/lib.rs:256-259`). The key is `Option<String>`
    /// (`None` = the exact-prefix-match slot); the query path restores the
    /// configured prefix to each key before matching. For a multi-version
    /// (`History::All`) backend this lists each key once with its NEWEST
    /// timestamp (the wildcard-match scan only needs the key set).
    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)>;

    /// This backend's history capability — how many values it keeps per
    /// key. zenoh `Capability::history` (`zenoh-backend-traits/src/lib.rs:145`).
    /// Defaults to [`History::Latest`]; a multi-version backend overrides
    /// it to [`History::All`], which tells the service gate above to retain
    /// every version instead of dropping outdated ones.
    fn history(&self) -> History {
        History::Latest
    }

    /// All stored versions for an exact `key`, newest last — the
    /// multi-version form of [`get`](StorageBackend::get). zenoh `get`
    /// returns `Vec<StoredData>` for exactly this reason
    /// (`zenoh-backend-traits/src/lib.rs:250-254`). The default returns the
    /// single latest value (0 or 1), so a [`History::Latest`] backend needs
    /// no override; a [`History::All`] backend returns its full version
    /// list.
    fn get_versions(&self, key: Option<&str>) -> Vec<&StoredData> {
        self.get(key).into_iter().collect()
    }
}

/// In-memory [`StorageBackend`]: a keyexpr -> [`StoredData`] map. zenoh
/// `MemoryStorage` (`memory_backend/mod.rs:78-158`). Backed by an `alloc`
/// [`BTreeMap`] keyed on `Option<String>` (the `None` key is the
/// exact-prefix-match slot; see the module-level divergence note).
#[derive(Debug, Default)]
pub struct MemoryStorage {
    map: BTreeMap<Option<String>, StoredData>,
}

impl MemoryStorage {
    /// A fresh, empty in-memory storage.
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// The number of distinct keys currently stored.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the storage holds no keys.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl StorageBackend for MemoryStorage {
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
        // `BTreeMap::insert` returns the displaced value (Some) or None for
        // a fresh key — the exact Occupied/Vacant split zenoh's memory
        // backend keys Replaced/Inserted off of (memory_backend/mod.rs:108
        // / :121). The map key is `Option<String>`; `None` is the
        // exact-prefix-match slot. Always `Ok`: an in-memory map has no
        // medium that can refuse the write.
        Ok(match self.map.insert(key.map(String::from), data) {
            Some(_) => StorageInsertionResult::Replaced,
            None => StorageInsertionResult::Inserted,
        })
    }

    fn delete(&mut self, key: Option<&str>, _timestamp: TimestampHint) -> StorageWriteResult {
        // zenoh `remove_entry` then `Deleted` unconditionally
        // (memory_backend/mod.rs:132-133): absent-key delete is still
        // Deleted (the storage-history / tombstone semantics live above
        // the bare backend).
        self.map.remove(&key.map(String::from));
        Ok(StorageInsertionResult::Deleted)
    }

    fn get(&self, key: Option<&str>) -> Option<&StoredData> {
        self.map.get(&key.map(String::from))
    }

    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
        self.map
            .iter()
            .map(|(k, v)| (k.clone(), v.timestamp.clone()))
            .collect()
    }
}

/// Forwarding [`StorageBackend`] for a boxed backend, so a
/// [`Volume::create_storage`](crate::storage_volume::Volume::create_storage)
/// result (`Box<dyn StorageBackend + Send>`) drives a generic storage service
/// (`StorageService<.., B>`) without the caller naming the concrete backend
/// type. `?Sized` covers the `dyn` trait-object case. Every method — including
/// the defaulted [`history`](StorageBackend::history) /
/// [`get_versions`](StorageBackend::get_versions) — is forwarded explicitly,
/// so a boxed `History::All` backend keeps its version behaviour (the default
/// `get_versions` would otherwise collapse to the single `get`).
impl<B: StorageBackend + ?Sized> StorageBackend for Box<B> {
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        (**self).put(key, payload, encoding, timestamp)
    }

    fn delete(&mut self, key: Option<&str>, timestamp: TimestampHint) -> StorageWriteResult {
        (**self).delete(key, timestamp)
    }

    fn get(&self, key: Option<&str>) -> Option<&StoredData> {
        (**self).get(key)
    }

    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
        (**self).get_all_entries()
    }

    fn history(&self) -> History {
        (**self).history()
    }

    fn get_versions(&self, key: Option<&str>) -> Vec<&StoredData> {
        (**self).get_versions(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![0x01],
        }
    }

    fn enc() -> Option<EncodingHint> {
        None
    }

    #[test]
    fn put_new_key_is_inserted_and_readable() {
        let mut s = MemoryStorage::new();
        let r = s.put(Some("demo/a"), vec![1, 2, 3], enc(), ts(10)).unwrap();
        assert_eq!(r, StorageInsertionResult::Inserted);
        assert_eq!(s.len(), 1);
        let stored = s.get(Some("demo/a")).expect("key present after put");
        assert_eq!(stored.payload, vec![1, 2, 3]);
        assert_eq!(stored.timestamp, ts(10));
    }

    #[test]
    fn put_existing_key_is_replaced() {
        let mut s = MemoryStorage::new();
        assert_eq!(
            s.put(Some("demo/a"), vec![1], enc(), ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        let r = s.put(Some("demo/a"), vec![2], enc(), ts(20)).unwrap();
        assert_eq!(r, StorageInsertionResult::Replaced);
        assert_eq!(s.len(), 1, "replace does not grow the key set");
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn put_and_get_the_none_exact_prefix_key() {
        // R311y61 — the `None` key is the exact-prefix-match (mount-root) slot:
        // a strip-configured storage whose incoming key equalled the prefix
        // exactly stores under `None`. It is a distinct slot from any `Some`
        // key and round-trips on get.
        let mut s = MemoryStorage::new();
        assert_eq!(
            s.put(None, vec![7], enc(), ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s.get(None).expect("mount-root value present").payload,
            vec![7]
        );
        // The `None` slot is independent of any `Some` key.
        s.put(Some("a"), vec![1], enc(), ts(10)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.get(None).unwrap().payload, vec![7]);
        assert_eq!(s.get(Some("a")).unwrap().payload, vec![1]);
    }

    #[test]
    fn delete_removes_entry_and_returns_deleted() {
        let mut s = MemoryStorage::new();
        s.put(Some("demo/a"), vec![1], enc(), ts(10)).unwrap();
        let r = s.delete(Some("demo/a"), ts(20)).unwrap();
        assert_eq!(r, StorageInsertionResult::Deleted);
        assert!(s.get(Some("demo/a")).is_none(), "key gone after delete");
        assert!(s.is_empty());
    }

    #[test]
    fn delete_absent_key_still_returns_deleted() {
        // Faithful to zenoh memory_backend: `remove_entry` is unconditional
        // and the result is Deleted even when the key was never present
        // (memory_backend/mod.rs:132-133).
        let mut s = MemoryStorage::new();
        assert_eq!(
            s.delete(Some("demo/missing"), ts(1)).unwrap(),
            StorageInsertionResult::Deleted
        );
    }

    #[test]
    fn get_all_entries_lists_every_key_with_its_timestamp() {
        let mut s = MemoryStorage::new();
        s.put(Some("demo/a"), vec![1], enc(), ts(10)).unwrap();
        s.put(Some("demo/b"), vec![2], enc(), ts(20)).unwrap();
        let mut entries = s.get_all_entries();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                (Some(String::from("demo/a")), ts(10)),
                (Some(String::from("demo/b")), ts(20)),
            ]
        );
    }

    #[test]
    fn get_all_entries_orders_the_none_key_first() {
        // BTreeMap<Option<String>, _> orders `None` before every `Some`, so
        // the exact-prefix-match slot lists first.
        let mut s = MemoryStorage::new();
        s.put(Some("demo/a"), vec![1], enc(), ts(10)).unwrap();
        s.put(None, vec![9], enc(), ts(20)).unwrap();
        let entries = s.get_all_entries();
        assert_eq!(
            entries,
            vec![(None, ts(20)), (Some(String::from("demo/a")), ts(10)),]
        );
    }

    #[test]
    fn backend_does_not_compare_timestamps_an_older_put_still_replaces() {
        // The seam contract: a bare backend is comparison-free. A put with
        // an OLDER timestamp still Replaces (the newer-wins gate above the
        // backend is what would reject it as Outdated). This is the
        // invariant the follow-up newer-wins atom relies on.
        let mut s = MemoryStorage::new();
        s.put(Some("demo/a"), vec![9], enc(), ts(100)).unwrap();
        let r = s.put(Some("demo/a"), vec![1], enc(), ts(1)).unwrap();
        assert_eq!(r, StorageInsertionResult::Replaced);
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
            vec![1],
            "bare backend overwrites verbatim, ignoring the older timestamp"
        );
    }
}
