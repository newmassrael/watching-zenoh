// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! [`crate::sample::timestamp_strictly_newer`] mirrors uhlc's `Timestamp`
//! `Ord` (`uhlc-0.8.1/src/timestamp.rs:33-38`: derived `Ord` over
//! `(time: NTP64, id: ID)`) — `time` first, then the id. The id tiebreak
//! is uhlc-faithful: [`crate::sample::timestamp_order_key`] zero-pads the
//! trimmed `zid` to the full 16-byte LE array uhlc's `ID` (`[u8; 16]`)
//! compares, NOT a raw trimmed-`Vec` lexicographic compare (which diverges
//! for a non-canonically-encoded zid). See it for the why.
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
//! - **Wildcard-update overriding** (`storage-mgr-wildcard-updates`, R311wt
//!   slice 2). zenoh lets a wildcard Put/Delete override matching specific keys
//!   (`overriding_wild_update`, service.rs:415-494). With the feature ON,
//!   [`apply_sample`](StorageState::apply_sample) detects a wildcard keyexpr
//!   ([`crate::keyexpr_match::is_wild`]), registers it in the
//!   `wildcard_puts` / `wildcard_deletes` registries (the wz analog of zenoh's
//!   two `KeBoxTree`s — a `BTreeMap` keyed on the full keyexpr, matched via the
//!   [`keyexpr_intersects_target`] SSOT, not string equality), materializes it
//!   onto every already-stored matching key, and shadow-checks every concrete
//!   sample against the registries (the resurrection guard). With the feature
//!   OFF the minimal state treats a wildcard key as an ordinary stored key
//!   (verbatim prior behavior). One named divergence from zenoh:
//!     1. **Resurrection-ordering on the ALIGN-receive path (R311wt slice 3,
//!        divergence D-slice3-1).**
//!        [`process_alignment_reply`](StorageState::process_alignment_reply) now
//!        APPLIES a wildcard received from a peer — register + materialize via the
//!        shared [`materialize_wildcard`](StorageState::materialize_wildcard) (a
//!        WildcardDelete needs no payload and materializes in the metadata round;
//!        a WildcardPut defers to the retrieval round for its value), closing the
//!        common-case offline-replica DATA residual (a peer's wildcard now
//!        overrides wz-local keys the origin lacked). A received CONCRETE Put or
//!        Delete ALSO consults the registries
//!        ([`apply_aligned_concrete`](StorageState::apply_aligned_concrete)),
//!        mirroring zenoh's `needs_further_processing`
//!        (aligner_reply.rs:255/337/431), so a wildcard registered on this replica
//!        shadows a later concrete key aligned from a peer that never saw it (a
//!        3-party mesh convergence path). wz materializes through the newer-wins
//!        gate on `latest` (its ts-only per-key record), NOT zenoh's
//!        stored-`timestamp_last_non_wildcard_update` resurrection sweep
//!        (core.rs:628-635 / aligner_reply.rs:483-515), because wz keeps no
//!        per-key tlnwu. Divergence (only wz<->zenohd, only overlapping
//!        out-of-order wildcards): for a key whose ts a WildcardPut raised, an
//!        out-of-order event logically prior to that put but later than the key's
//!        last concrete write — a WildcardDelete OR a plain Delete — is RETAINED
//!        by wz (ts-only gate) whereas zenoh's ALIGN path deletes it. This is not
//!        a new class: zenoh is itself path-dependent here — its LIVE path also
//!        RETAINS (materialize sets tlnwu=None via `Event::new`, log.rs:208-211,
//!        so the out-of-order delete is ts-skipped), so no single faithful target
//!        exists; wz matches zenoh's live-materialize behavior and stays
//!        internally consistent (one gate, live + align). Every CONCRETE key
//!        still converges at the (key, ts) fingerprint layer. R2351 closed the
//!        wildcard's OWN log-key fingerprint too (the former AV5 residual): a
//!        registered wildcard is now derived as an event by
//!        `StorageState::wildcard_replication_entries`, so both the digest and
//!        the aligner advertise it and a retrieval for it is answerable. wz
//!        still keeps no incremental log — it recomputes — but it no longer
//!        recomputes a SMALLER population than upstream logs. wz DECODES the
//!        incoming event's tlnwu
//!        (slice 1) but does not consume it on receive (the sweep would need the
//!        STORED key's tlnwu) — it is carried for wire-fidelity, not load-bearing.
//!        Registry pruning (dropping a wildcard-put superseded by a covering
//!        wildcard-delete) is deferred to the slice-4 GC (harmless meanwhile: a
//!        stale older-ts wildcard-put can never win the put-phase). A retrieved
//!        WildcardPut whose payload the peer SKIPPED (value `None`) is a no-op
//!        (it registers nothing) — matching the plain-Put skip; a wz<->zenohd
//!        cross-impl e2e (a peer's wildcard propagating over the wire end to end)
//!        is a cross-impl-leg follow-up. R2351 removed the reason it was not
//!        unit-testable between two wz replicas: a wz peer now SERVES its
//!        wildcard events, so a two-wz `drive_alignment` can exercise wildcard
//!        reception rather than only the direct-reply unit tests. The LIVE capture
//!        path — this same wildcard reception on `apply_sample`, NOT the align
//!        path — IS now cross-impl-proven end to end by a foreign zenoh-pico
//!        `z_put -k demo/**` in the wz-integration-tests e2e
//!        `wz_storage_wildcard_update_pico_interop` (R311wt pico leg): a real
//!        pico wildcard Push crosses a live TCP link, `apply_sample` detects
//!        `is_wild`, registers it, and materializes the override onto a
//!        pre-seeded concrete key. The wz<->zenohd ALIGN-path wildcard e2e above
//!        (a wz replica pulling + applying a wildcard EVENT off a real zenohd
//!        aligner) remains the separate, open cross-impl follow-up.
//! - **`strip_prefix` and the mount-root `None` key** (R311y61/y64). With a
//!   configured `strip_prefix` (`storage-mgr-strip-prefix`), the gate keys
//!   on the STORED (stripped) key — `None` being the exact-prefix-match
//!   mount-root slot, faithful to zenoh's `Option<OwnedKeyExpr>` backend
//!   key. The replication/aligner snapshot ([`replication_digest`](StorageState::replication_digest),
//!   [`replication_events`](StorageState::replication_events)) reads the same
//!   `latest` map, and [`crate::storage_aligner::EventMetadata`] now carries an
//!   `Option<String>` key (R311y64), so the mount-root `None` value is carried
//!   through the digest, the aligner events, AND the bincode wire faithfully —
//!   mirroring zenoh's `Event.stripped_key: Option<OwnedKeyExpr>`. A mount-root
//!   value is NO LONGER skipped; the under-mount keys replicate as before, and
//!   a non-strip storage is unaffected (every stored key is `Some`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::keyexpr_match::keyexpr_intersects_target;
use crate::query_sink::{QueryView, ReplyOut};
use crate::sample::{EncodingHint, TimestampHint};
use crate::sample_kind::SampleKind;
use crate::sink::SampleView;
#[cfg(feature = "storage-aligner")]
use crate::storage_aligner::{
    Action, AlignmentFollowup, AlignmentQuery, AlignmentReply, AlignmentResponse, EventBuckets,
    EventMetadata, RetrievedValue,
};
use crate::storage_backend::{
    History, StorageBackend, StorageInsertionResult, StorageWriteError, StorageWriteResult,
    StoredData,
};
#[cfg(feature = "storage-replication")]
use crate::storage_replication::{
    build_digest, Digest, IntervalIdx, ReplicationConfig, ReplicationLog,
};

// R311y73 — the uhlc timestamp-order SSOT (`timestamp_order_key` /
// `timestamp_strictly_newer`) moved to its natural home
// [`crate::sample`], next to the [`TimestampHint`] it orders, so every
// `alloc` consumer (storage AND the ext-pubsub advanced subscriber) shares
// one ordering recipe without pulling `storage-backend` (the
// `crate::zid_hex` precedent for `zid_to_le_array`). storage_state keeps
// only the comparison it keys newer-wins on; the `zid_to_le_array`
// re-export is retired — its remaining consumers (storage_replication,
// storage_aligner) now import it from `crate::zid_hex` directly.
use crate::sample::timestamp_strictly_newer;

/// The storage service gate: a [`StorageBackend`] plus the newer-wins
/// versioning + query-match logic that turns the dumb store into a storage.
/// zenoh `StorageService` minus its runtime driver (the Subscriber +
/// Queryable + select loop, which is the wz-runtime-tokio atom).
#[derive(Debug, Default)]
pub struct StorageState<B: StorageBackend> {
    backend: B,
    /// The latest accepted timestamp per STORED key — the newer-wins
    /// comparison source (zenoh `cache_latest.latest_updates`). Keyed on the
    /// backend's `Option<String>` key space (`None` = the exact-prefix-match
    /// / mount-root slot under a configured `strip_prefix`). Populated on
    /// every accepted Put AND Delete, so a deleted key leaves a tombstone
    /// timestamp here even though its value is gone from `backend`; that is
    /// what makes an older Put after a Delete reject as Outdated instead of
    /// resurrecting the key.
    latest: BTreeMap<Option<String>, TimestampHint>,
    /// The optional keyexpr prefix STRIPPED from an incoming key before it is
    /// stored, and re-prepended (restored) on a query reply — the
    /// `storage-mgr-strip-prefix` atom (R311y61), so a storage holds keys
    /// relative to a mount point. `None` (the default + the only value when
    /// the feature is off) stores keys verbatim.
    #[cfg(feature = "storage-mgr-strip-prefix")]
    strip_prefix: Option<String>,
    /// Registered Wildcard Puts, keyed on the FULL (un-stripped) wildcard
    /// keyexpr — the wz analog of zenoh's `wildcard_puts` `KeBoxTree`
    /// (service.rs:88). A `BTreeMap` (no `KeBoxTree` in the no_std+alloc port)
    /// matched via the [`keyexpr_intersects_target`] SSOT; a re-issued wildcard
    /// upserts (zenoh `KeBoxTree.insert` semantics). Kept SEPARATE from
    /// `wildcard_deletes` because a `WildcardPut` and a `WildcardDelete` on the
    /// same keyexpr must coexist (their relative order matters across the
    /// network, zenoh log.rs:69-86). `storage-mgr-wildcard-updates` (R311wt
    /// slice 2).
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    wildcard_puts: BTreeMap<String, WildcardUpdate>,
    /// Registered Wildcard Deletes (zenoh `wildcard_deletes`, service.rs:87).
    /// See [`wildcard_puts`](StorageState).
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    wildcard_deletes: BTreeMap<String, WildcardUpdate>,
    /// The incrementally-maintained replication buckets this storage's
    /// [`Digest`] is read off (R2354). Every field above that a digest is a
    /// function of — [`latest`](StorageState) and the two wildcard registries
    /// — feeds it through the funnels
    /// [`record_latest`](StorageState::record_latest) /
    /// [`register_wildcard_update`](StorageState::register_wildcard_update) /
    /// [`collect_garbage`](StorageState::collect_garbage), which is the
    /// invariant `scripts/lib/replication_log_funnel_gate.py` derives and
    /// checks: a `&mut self` method that names a digest source must also name
    /// this log.
    #[cfg(feature = "storage-replication")]
    replication_log: ReplicationLog,
}

/// A registered wildcard update: the value + kind a wildcard Put/Delete carries,
/// stored in the [`StorageState`] wildcard registries so a later concrete
/// sample matching the wildcard can be overridden by it. zenoh `Update`
/// (`storages_mgt/service.rs:50-54` — `{ kind, data: StoredData }`).
#[cfg(feature = "storage-mgr-wildcard-updates")]
#[derive(Debug, Clone)]
struct WildcardUpdate {
    kind: SampleKind,
    data: StoredData,
}

impl<B: StorageBackend> StorageState<B> {
    /// Wrap a backend in the newer-wins service gate (no `strip_prefix`).
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            latest: BTreeMap::new(),
            #[cfg(feature = "storage-mgr-strip-prefix")]
            strip_prefix: None,
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            wildcard_puts: BTreeMap::new(),
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            wildcard_deletes: BTreeMap::new(),
            #[cfg(feature = "storage-replication")]
            replication_log: ReplicationLog::default(),
        }
    }

    /// Wrap a backend in the gate with a configured `strip_prefix`
    /// (R311y61, `storage-mgr-strip-prefix`): an incoming key `<prefix>/<rest>`
    /// is stored under `<rest>` (and `<prefix>` exactly under the `None`
    /// mount-root slot), and restored to its full keyexpr on a query reply.
    /// `None` is equivalent to [`new`](Self::new). The
    /// [`crate::storage_state`] driver / [`crate::storage_config::StorageConfig`]
    /// supply the prefix.
    #[cfg(feature = "storage-mgr-strip-prefix")]
    pub fn with_strip_prefix(backend: B, strip_prefix: Option<String>) -> Self {
        Self {
            backend,
            latest: BTreeMap::new(),
            strip_prefix,
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            wildcard_puts: BTreeMap::new(),
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            wildcard_deletes: BTreeMap::new(),
            #[cfg(feature = "storage-replication")]
            replication_log: ReplicationLog::default(),
        }
    }

    /// The STORED key for an incoming full keyexpr: applies the configured
    /// `strip_prefix` (zenoh `strip_prefix`, the capture-side transform).
    /// Returns `Some(stored)` to store — the inner `Option<String>` being the
    /// backend key (`None` = the exact-prefix-match mount-root slot) — or the
    /// outer `None` to DROP the sample (the key is not under the prefix, or the
    /// prefix is wild; zenoh logs and returns). Without the
    /// `storage-mgr-strip-prefix` feature this is the identity (every key is
    /// stored verbatim).
    #[cfg(feature = "storage-mgr-strip-prefix")]
    fn stored_key_for(&self, full_key: &str) -> Option<Option<String>> {
        // `Ok(stored)` -> store under `stored` (inner `None` = mount-root);
        // `Err` (not under prefix / wild) -> outer `None` = drop the sample.
        crate::storage_strip_prefix::strip_prefix(self.strip_prefix.as_deref(), full_key).ok()
    }
    #[cfg(not(feature = "storage-mgr-strip-prefix"))]
    fn stored_key_for(&self, full_key: &str) -> Option<Option<String>> {
        Some(Some(String::from(full_key)))
    }

    /// The full keyexpr for a STORED key: re-prepends the configured
    /// `strip_prefix` (zenoh `prefix`, the reply-side inverse). `None` when
    /// there is no full key to form (the degenerate empty-prefix + mount-root
    /// case). Without the `storage-mgr-strip-prefix` feature this is the
    /// identity (the stored key IS the full key).
    #[cfg(feature = "storage-mgr-strip-prefix")]
    fn full_key_for(&self, stored: Option<&str>) -> Option<String> {
        crate::storage_strip_prefix::restore_prefix(self.strip_prefix.as_deref(), stored)
    }
    #[cfg(not(feature = "storage-mgr-strip-prefix"))]
    fn full_key_for(&self, stored: Option<&str>) -> Option<String> {
        stored.map(String::from)
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
    fn accepts(&self, key: Option<&str>, incoming: &TimestampHint) -> bool {
        match self.latest.get(&key.map(String::from)) {
            Some(recorded) => !timestamp_strictly_newer(recorded, incoming),
            None => true,
        }
    }

    /// The SINGLE writer of [`latest`](StorageState) — the newer-wins record
    /// AND the digest's primary event source, which is why it is one method
    /// and not two `insert` call sites.
    ///
    /// R2354: the replication buckets are maintained here, at the moment the
    /// event set changes, because that is what makes them buckets rather than
    /// a cache. The previous timestamp for this key is read BEFORE the insert
    /// and handed to [`ReplicationLog::apply`] so the outgoing event leaves
    /// the bucket it was hashed into — a fingerprint is an XOR accumulator, so
    /// an overwrite that only adds is not "slightly stale", it is a
    /// permanently wrong digest for the key's OLD sub-interval as well as its
    /// new one.
    fn record_latest(&mut self, key: Option<&str>, timestamp: TimestampHint) {
        let stored_key = key.map(String::from);
        #[cfg(feature = "storage-replication")]
        {
            let previous = self.latest.get(&stored_key).cloned();
            self.replication_log
                .apply(key, previous.as_ref(), Some(&timestamp));
        }
        self.latest.insert(stored_key, timestamp);
    }

    /// Process an inbound Put over the backend's `Option<&str>` key space:
    /// `None` is the exact-prefix-match mount-root slot a strip-configured
    /// [`apply_sample`](Self::apply_sample) produces. In [`History::Latest`]
    /// mode the newer-wins gate runs: a strictly-older value returns
    /// [`Outdated`](StorageInsertionResult::Outdated) (backend untouched),
    /// otherwise the value is stored and its timestamp recorded. In
    /// [`History::All`] mode the gate is SKIPPED (zenoh
    /// service.rs:319) — every version is appended by the backend. The
    /// newer-wins gate and the `latest` record key on the same stored key.
    ///
    /// This is the RAW gated write: wildcard-update override
    /// (`storage-mgr-wildcard-updates`) is applied by
    /// [`apply_sample`](Self::apply_sample) (and, in the align path, at the
    /// alignment-reply call sites), NOT here — a direct caller of this method
    /// bypasses the wildcard registries by design (zenoh keeps the override in
    /// `process_sample` / the aligner, not in the backend write).
    /// R311y831 — a backend that could not commit the write returns
    /// [`StorageWriteError`] and the version record is NOT written. That is
    /// the load-bearing half: `latest` is what
    /// [`replication_events`](Self::replication_events) and the aligner digest
    /// are derived from, so recording an uncommitted put would make this
    /// replica advertise data it does not have — and a peer that believes you
    /// hold an event stops sending it. Upstream takes the same branch at the
    /// same point (`storages_mgt/service.rs:352-366`: on `Err` it logs and
    /// skips the `cache_guard.insert` that feeds its replication log).
    pub fn process_put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        let latest_mode = self.latest_mode();
        if latest_mode && !self.accepts(key, &timestamp) {
            return Ok(StorageInsertionResult::Outdated);
        }
        let result = self
            .backend
            .put(key, payload, encoding, timestamp.clone())?;
        if latest_mode {
            self.record_latest(key, timestamp);
        }
        Ok(result)
    }

    /// Process an inbound Delete over the backend's `Option<&str>` key space
    /// (`None` = the mount-root slot). In [`History::Latest`] mode the
    /// newer-wins gate runs (a strictly-older delete returns
    /// [`Outdated`](StorageInsertionResult::Outdated)) and the accepted
    /// delete timestamp is retained as a **tombstone** (so a subsequent
    /// older Put cannot resurrect the key). In [`History::All`] mode the
    /// gate is skipped (the backend decides how a delete affects its
    /// version list).
    ///
    /// R311y831 — as [`process_put`](Self::process_put): a backend that could
    /// not remove the record returns [`StorageWriteError`] and NO tombstone is
    /// recorded, so the replication log does not claim a deletion that did not
    /// happen.
    pub fn process_delete(
        &mut self,
        key: Option<&str>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        let latest_mode = self.latest_mode();
        if latest_mode && !self.accepts(key, &timestamp) {
            return Ok(StorageInsertionResult::Outdated);
        }
        let result = self.backend.delete(key, timestamp.clone())?;
        if latest_mode {
            // Retain the delete timestamp as a tombstone — the value is gone
            // from the backend but the latest-accepted record survives, so
            // the newer-wins gate still rejects an older Put. zenoh keeps the
            // Delete event in `cache_latest.latest_updates` for this reason.
            self.record_latest(key, timestamp);
        }
        Ok(result)
    }

    /// Exact-key read of the live stored value (none if absent or deleted).
    /// The direct (non-wildcard) query fast path. `key` is `Option<&str>`
    /// over the backend key space (`None` = the mount-root slot).
    pub fn get(&self, key: Option<&str>) -> Option<&StoredData> {
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
        for (stored_key, _ts) in self.backend.get_all_entries() {
            // Restore the configured strip_prefix so the match + reply key are
            // in the FULL keyexpr space (zenoh restores the prefix before
            // `intersects`, service.rs:639); the backend fetch uses the stored
            // key. Without strip this is the identity.
            let Some(full_key) = self.full_key_for(stored_key.as_deref()) else {
                continue;
            };
            if keyexpr_intersects_target(&full_key, &target_chunks) {
                if let Some(data) = self.backend.get(stored_key.as_deref()) {
                    out.push((full_key, data));
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
    /// (`storages_mgt/service.rs:575-577 (wildcard) / :609-611 (non-wild)`).
    pub fn matching_versions(&self, query_keyexpr: &str) -> Vec<(String, Vec<&StoredData>)> {
        let target_chunks: Vec<&str> = query_keyexpr.split('/').collect();
        let mut out = Vec::new();
        for (stored_key, _ts) in self.backend.get_all_entries() {
            let Some(full_key) = self.full_key_for(stored_key.as_deref()) else {
                continue;
            };
            if keyexpr_intersects_target(&full_key, &target_chunks) {
                let versions = self.backend.get_versions(stored_key.as_deref());
                if !versions.is_empty() {
                    out.push((full_key, versions));
                }
            }
        }
        out
    }

    /// Apply one inbound sample (the capture side of a storage): a Put is
    /// stored / a Del removes, both through the newer-wins gate
    /// ([`process_put`](Self::process_put) / [`process_delete`](Self::process_delete)).
    /// An un-timestamped sample is stamped via `fallback` (called at most
    /// once, only when the sample carries no timestamp — the §5.18 seam; a
    /// runtime driver passes a wall-clock / HLC closure). Runtime-agnostic:
    /// reads the sample through the [`SampleView`] seam, no async / no
    /// Session, so any storage driver (tokio, a future MCU one) reuses this
    /// exact capture mapping. zenoh `process_sample`
    /// (`storages_mgt/service.rs:213-369`, the `select!` sample arm).
    ///
    /// R311y831 — a backend that cannot commit the capture is LOGGED here and
    /// the capture continues, which is both upstream's answer
    /// (`storages_mgt/service.rs:361-365`: log the error, move to the next
    /// sample, never abort the loop) and the answer wz's other receive path
    /// already gives ([`note_aligned_apply`](Self::note_aligned_apply)) — one
    /// question should not have two shapes. Nothing is swallowed by that: the
    /// load-bearing consequence is that no version record is written, which is
    /// [`process_put`](Self::process_put)'s contract and is what keeps the
    /// replication digest from advertising a sample this replica never stored.
    /// A caller that needs the outcome of ONE key calls `process_put` /
    /// `process_delete` directly; `apply_sample` is the driver-loop entry, and
    /// a driver loop has nothing to do with the error but print it.
    pub fn apply_sample(
        &mut self,
        view: &dyn SampleView,
        fallback: impl FnOnce() -> TimestampHint,
    ) {
        let outcome = self.apply_sample_inner(view, fallback);
        if outcome.is_err() {
            log::error!(
                "wz storage: the backend refused the captured sample for keyexpr {:?}; it is \
                 NOT stored and NOT recorded, so a replicating peer still sees it as missing",
                view.keyexpr()
            );
        }
    }

    /// The capture body [`apply_sample`](Self::apply_sample) logs the outcome
    /// of. Split out so the propagation stays `?`-shaped internally and the
    /// log lives at exactly one place.
    fn apply_sample_inner(
        &mut self,
        view: &dyn SampleView,
        fallback: impl FnOnce() -> TimestampHint,
    ) -> Result<(), StorageWriteError> {
        // R311wt slice 2: with `storage-mgr-wildcard-updates` ON, route through
        // the wildcard-aware capture path (detect + register + materialize a
        // wildcard, shadow-check a concrete sample against the registries). OFF
        // is byte-identical to the pre-slice-2 body, so signature stability AND
        // the "wildcard stored as an ordinary key" divergence both hold trivially.
        #[cfg(feature = "storage-mgr-wildcard-updates")]
        {
            self.apply_sample_wildcard_aware(view, fallback)
        }
        #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
        {
            // Capture-side strip (zenoh `process_sample`, service.rs:308): an
            // incoming `<prefix>/<rest>` is stored under `<rest>` (and `<prefix>`
            // exactly under the `None` mount-root slot). A key not under the
            // configured prefix is DROPPED (zenoh logs + returns). Without the
            // strip feature every key is stored verbatim.
            let Some(stored_key) = self.stored_key_for(view.keyexpr()) else {
                return Ok(());
            };
            let timestamp = view.timestamp().cloned().unwrap_or_else(fallback);
            match view.kind() {
                SampleKind::Put => {
                    let encoding = view.encoding().cloned();
                    self.process_put(
                        stored_key.as_deref(),
                        view.payload().to_vec(),
                        encoding,
                        timestamp,
                    )?;
                }
                SampleKind::Del => {
                    self.process_delete(stored_key.as_deref(), timestamp)?;
                }
            }
            Ok(())
        }
    }

    /// The `storage-mgr-wildcard-updates` capture path (zenoh `process_sample`,
    /// service.rs:213-370). A WILDCARD keyexpr is registered in the
    /// `wildcard_puts` / `wildcard_deletes` registries (full, UN-stripped
    /// keyexpr) BEFORE it is materialized onto every already-stored matching
    /// key — the register-first order matters so the materialize loop's
    /// shadow-check sees the just-registered wildcard (zenoh registers at
    /// service.rs:234, materializes at :257). A CONCRETE keyexpr is stored after
    /// a shadow-check against the registries ([`apply_one_with_override`]). The
    /// `is_wild` test runs BEFORE `stored_key_for` so a wildcard is registered
    /// even under a `strip_prefix` config that would otherwise drop it.
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    fn apply_sample_wildcard_aware(
        &mut self,
        view: &dyn SampleView,
        fallback: impl FnOnce() -> TimestampHint,
    ) -> Result<(), StorageWriteError> {
        let full_key = view.keyexpr();
        let kind = view.kind();
        let timestamp = view.timestamp().cloned().unwrap_or_else(fallback);

        if crate::keyexpr_match::is_wild(full_key) {
            // Register + materialize the wildcard (shared with the align-receive
            // path, R311wt slice 3). The live path's wildcard ke is the full
            // incoming keyexpr.
            let payload = view.payload().to_vec();
            let encoding = view.encoding().cloned();
            self.materialize_wildcard(full_key, kind, timestamp, payload, encoding)
        } else {
            // Concrete sample: strip to the stored key (may DROP under strip),
            // then apply through the shadow-check. The shadow-check consults the
            // registries in the FULL keyexpr space (`full_key`), never the
            // stored key (AV8).
            let Some(stored_key) = self.stored_key_for(full_key) else {
                return Ok(());
            };
            let payload = view.payload().to_vec();
            let encoding = view.encoding().cloned();
            self.apply_one_with_override(
                stored_key.as_deref(),
                full_key,
                kind,
                timestamp,
                payload,
                encoding,
            )
        }
    }

    /// Register a wildcard update FIRST (full, un-stripped keyexpr) then
    /// MATERIALIZE it onto every already-stored key it matches — a wildcard
    /// creates no key (zenoh `get_matching_keys`, service.rs:257 + :628-658,
    /// scans live keys only). Match in FULL keyexpr space (restore the strip
    /// prefix per key, [`full_key_for`](Self::full_key_for)); WRITE in the STORED
    /// key space (AV8 invariant). The register-first order lets the materialize
    /// loop's per-key shadow-check see the just-registered wildcard.
    ///
    /// Shared by the LIVE capture path
    /// ([`apply_sample_wildcard_aware`](Self::apply_sample_wildcard_aware)) and,
    /// R311wt slice 3, the ALIGN-receive path
    /// ([`process_alignment_reply`](Self::process_alignment_reply)'s wildcard
    /// arms), which pass the wildcard keyexpr carried in the incoming
    /// `Action::WildcardPut` / `Action::WildcardDelete` (already the FULL keyexpr;
    /// the event's stripped `key()` is NOT the wildcard's match key).
    ///
    /// R311y831 — a wildcard is ONE logical mutation over N keys, and upstream
    /// leaves the failure case open ("In case of a wildcard update, multiple
    /// keys can be updated. What should be the behaviour if one or more of
    /// these updates fail?", `storages_mgt/service.rs:362-363`). wz answers it:
    /// every matching key is attempted — a full disk on one key must not
    /// silently truncate the wildcard's reach at whichever key sorted first —
    /// and the FIRST error is returned once the sweep is done. The per-key
    /// version records are independent, so the keys that did commit are
    /// correctly recorded and the ones that did not are correctly absent, which
    /// is exactly the state the aligner then repairs.
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    fn materialize_wildcard(
        &mut self,
        wildcard_ke: &str,
        kind: SampleKind,
        timestamp: TimestampHint,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
    ) -> Result<(), StorageWriteError> {
        self.register_wildcard_update(
            wildcard_ke,
            kind,
            timestamp.clone(),
            payload.clone(),
            encoding.clone(),
        );

        let target_chunks: Vec<&str> = wildcard_ke.split('/').collect();
        // Collect (stored, full) pairs so the restored full key computed for the
        // match filter is reused by the override lookup below (one
        // `full_key_for` per key). The owned Vec releases the `&self` borrow
        // before the `&mut self` apply loop.
        let matching: Vec<(Option<String>, String)> = self
            .backend
            .get_all_entries()
            .into_iter()
            .filter_map(|(stored, _ts)| {
                let full = self.full_key_for(stored.as_deref())?;
                keyexpr_intersects_target(&full, &target_chunks).then_some((stored, full))
            })
            .collect();
        let mut first_error = Ok(());
        for (stored, full) in matching {
            let outcome = self.apply_one_with_override(
                stored.as_deref(),
                &full,
                kind,
                timestamp.clone(),
                payload.clone(),
                encoding.clone(),
            );
            // Keep sweeping: the reach of the wildcard must not depend on
            // which key the backend happened to choke on.
            first_error = first_error.and(outcome);
        }
        first_error
    }

    /// Apply one sample to one stored key, first consulting the wildcard
    /// registries: if `full_key` is overridden by a registered wildcard update,
    /// the OVERRIDE's kind/value/timestamp is stored instead of the incoming
    /// one (zenoh `process_sample`'s `sample_to_store` selection,
    /// service.rs:274-291). `stored_key` is the backend key to write; `full_key`
    /// is the FULL keyexpr the override lookup keys on (they differ only under a
    /// `strip_prefix`).
    ///
    /// R2352 — the backend op is dispatched on the INCOMING kind while the
    /// VALUE and TIMESTAMP come from the override, which is exactly upstream's
    /// split: it builds `sample_to_store` from `update.kind`
    /// (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `SampleKind::Delete => SampleBuilder::delete(k.clone())`)
    /// and then dispatches on the received sample
    /// (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `let storage_result = match sample.kind()`).
    /// The only pair the two dispatches disagree on is (incoming Put, override
    /// Delete) — a Delete cannot be overridden by a Wildcard Put, because the
    /// put phase is not even entered for it — and there the shared answer is an
    /// EMPTY-PAYLOAD PUT at the wildcard-delete ts, not a tombstone. The
    /// wildcard-delete still wins; only its materialized representation is a
    /// present-but-empty value, which is what a query on a real zenohd returns.
    ///
    /// This REPLACES a divergence wz had named and justified. The justification
    /// was that a tombstone "agrees with the log action zenoh's own
    /// `determine_action` records"; measured against the pin, that is false.
    /// The overridden concrete write keeps the PLAIN action it was born with
    /// (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `let mut action: Action = kind.into()`
    /// — reassigned only inside the `is_wild` arm), the log event is built from
    /// that same `action`
    /// (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `let new_event = Event::new(stripped_key.clone()`),
    /// and `determine_action` returns a plain `Put` unchanged
    /// (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `Action::Put => return Action::Put`).
    /// So upstream logs a Put AND stores a put: it is internally consistent in
    /// the very case wz cited as its inconsistency, and it was wz that logged a
    /// Delete for a key upstream logs as a Put
    /// ([`replication_events`](Self::replication_events) derives the action from
    /// backend presence).
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    fn apply_one_with_override(
        &mut self,
        stored_key: Option<&str>,
        full_key: &str,
        kind: SampleKind,
        timestamp: TimestampHint,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
    ) -> Result<(), StorageWriteError> {
        // Phase selection mirrors zenoh `overriding_wild_update` (service.rs:426
        // delete phase ⇔ action ∈ {Put, Delete, WildcardDelete}; :471 put phase
        // ⇔ action ∈ {Put, WildcardPut}). On the live path the incoming action
        // is always a PLAIN Put/Delete (zenoh passes `kind.into()`,
        // service.rs:275), so: Put → both phases, Delete → delete phase only.
        let (run_delete_phase, run_put_phase) = match kind {
            SampleKind::Put => (true, true),
            SampleKind::Del => (true, false),
        };
        // tlnwu = None on the live write path (zenoh service.rs:275), so the
        // resurrection guard's `lowest_event_ts` collapses to the incoming ts.
        match self.overriding_wild_update(full_key, &timestamp, run_delete_phase, run_put_phase) {
            Some(update) => {
                // The override supplies the VALUE and the TIMESTAMP. A
                // wildcard-DELETE override supplies an empty value under the
                // default encoding, because that is what the sample upstream
                // builds with `SampleBuilder::delete` carries into the put.
                let (payload, encoding) = match update.kind {
                    SampleKind::Put => (update.data.payload, update.data.encoding),
                    SampleKind::Del => (Vec::new(), None),
                };
                // Override ts, NOT the incoming ts (AV3): writing at the older
                // incoming ts would open a resurrection window. Either arm
                // records `latest` = the override ts, so the newer-wins gate is
                // unchanged by which arm ran.
                match kind {
                    SampleKind::Put => {
                        self.process_put(stored_key, payload, encoding, update.data.timestamp)
                    }
                    SampleKind::Del => self.process_delete(stored_key, update.data.timestamp),
                }
            }
            None => match kind {
                SampleKind::Put => self.process_put(stored_key, payload, encoding, timestamp),
                SampleKind::Del => self.process_delete(stored_key, timestamp),
            },
        }
        .map(|_| ())
    }

    /// Register a wildcard update in the kind-selected registry, keyed on the
    /// FULL wildcard keyexpr (upsert = zenoh `KeBoxTree.insert`, service.rs:400-411).
    /// zenoh `register_wildcard_update` (service.rs:384-412).
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    fn register_wildcard_update(
        &mut self,
        wildcard_key: &str,
        kind: SampleKind,
        timestamp: TimestampHint,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
    ) {
        let update = WildcardUpdate {
            kind,
            data: StoredData {
                payload,
                encoding,
                timestamp,
            },
        };
        // R2354 — a registered wildcard update is a replication event (R2351,
        // AV5), so an upsert here is an event transition the digest buckets
        // have to hear about. The displaced registration is read out FIRST:
        // re-issuing `demo/**` at a newer timestamp moves the event to another
        // sub-interval, and only the old timestamp can XOR it out of the one
        // it was hashed into.
        #[cfg(feature = "storage-replication")]
        let displaced = match kind {
            SampleKind::Put => self.wildcard_puts.get(wildcard_key),
            SampleKind::Del => self.wildcard_deletes.get(wildcard_key),
        }
        .map(|wu| wu.data.timestamp.clone());
        #[cfg(feature = "storage-replication")]
        self.replication_log.apply(
            Some(wildcard_key),
            displaced.as_ref(),
            Some(&update.data.timestamp),
        );
        match kind {
            SampleKind::Put => {
                self.wildcard_puts
                    .insert(String::from(wildcard_key), update);
            }
            SampleKind::Del => {
                self.wildcard_deletes
                    .insert(String::from(wildcard_key), update);
            }
        }
    }

    /// The wildcard override lookup for a CONCRETE key: does a registered
    /// wildcard update override `full_key`? Returns the overriding update
    /// (owned; the caller then writes it via `&mut self`, so no `&self` borrow
    /// can be held — zenoh clones for the same reason, service.rs:463/489).
    /// Faithful port of zenoh `overriding_wild_update` (service.rs:414-494),
    /// with `Action` reduced to the two phase-selection booleans it drives (so
    /// this stays a `storage-backend`-only atom, independent of `storage-aligner`).
    ///
    /// Live-path caller: `timestamp_last_non_wildcard_update` is `None`, so
    /// `lowest_event_ts` collapses to `incoming_ts` (zenoh service.rs:275/432).
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    fn overriding_wild_update(
        &self,
        full_key: &str,
        incoming_ts: &TimestampHint,
        run_delete_phase: bool,
        run_put_phase: bool,
    ) -> Option<WildcardUpdate> {
        // Delete phase FIRST, with an early return (zenoh service.rs:426-467): a
        // Wildcard-Delete overrides a Put / Wildcard-Put; among the deletes
        // matching this key with `ts >= incoming_ts`, keep the LOWEST-ts one (a
        // Delete does not override another Delete, service.rs:442-454).
        if run_delete_phase {
            let mut lowest: Option<&WildcardUpdate> = None;
            for (wildcard_ke, wu) in &self.wildcard_deletes {
                let chunks: Vec<&str> = wildcard_ke.split('/').collect();
                // `wu.ts >= incoming_ts` ⇔ NOT (incoming_ts strictly newer).
                if keyexpr_intersects_target(full_key, &chunks)
                    && !timestamp_strictly_newer(incoming_ts, &wu.data.timestamp)
                {
                    match lowest {
                        None => lowest = Some(wu),
                        // Keep the LOWEST ts: replace only if the current pick is
                        // strictly newer than this candidate (service.rs:449).
                        Some(cur)
                            if timestamp_strictly_newer(
                                &cur.data.timestamp,
                                &wu.data.timestamp,
                            ) =>
                        {
                            lowest = Some(wu)
                        }
                        _ => {}
                    }
                }
            }
            if let Some(wu) = lowest {
                return Some(wu.clone());
            }
        }

        // Put phase (zenoh service.rs:471-491): a Wildcard-Put overrides a Put /
        // Wildcard-Put; among the puts matching this key with `ts >= incoming_ts`,
        // keep the LATEST-ts one. Seed the threshold to `incoming_ts` and update
        // it as we go (running `>=` replace, service.rs:475-483).
        if run_put_phase {
            let mut latest_ts = incoming_ts.clone();
            let mut latest: Option<&WildcardUpdate> = None;
            for (wildcard_ke, wu) in &self.wildcard_puts {
                let chunks: Vec<&str> = wildcard_ke.split('/').collect();
                // `wu.ts >= latest_ts` ⇔ NOT (latest_ts strictly newer).
                if keyexpr_intersects_target(full_key, &chunks)
                    && !timestamp_strictly_newer(&latest_ts, &wu.data.timestamp)
                {
                    latest_ts = wu.data.timestamp.clone();
                    latest = Some(wu);
                }
            }
            if let Some(wu) = latest {
                return Some(wu.clone());
            }
        }

        None
    }

    /// Apply a CONCRETE (non-wildcard) event received via alignment, first
    /// consulting the wildcard registries (R311wt slice 3). zenoh runs
    /// `needs_further_processing` → `is_overridden_by_wildcard_update`
    /// (aligner_reply.rs:255/337/431) on EVERY received event, so a concrete
    /// Put/Delete aligned from a peer that never saw a wildcard is still
    /// overridden by a registered wildcard newer than it — the SAME override the
    /// live capture path applies to a concrete sample
    /// ([`apply_one_with_override`](Self::apply_one_with_override)). Without this
    /// a wildcard registered on this replica (e.g. a wildcard-delete received
    /// from replica A, materialized onto an empty backend) would NOT shadow a
    /// later concrete key aligned from replica B — a mesh convergence gap.
    /// Matched in FULL keyexpr space (restore the strip prefix), written in the
    /// STORED key space (AV8).
    #[cfg(all(feature = "storage-aligner", feature = "storage-mgr-wildcard-updates"))]
    fn apply_aligned_concrete(
        &mut self,
        stored_key: Option<&str>,
        kind: SampleKind,
        timestamp: TimestampHint,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
    ) -> Result<(), StorageWriteError> {
        match self.full_key_for(stored_key) {
            Some(full) => {
                self.apply_one_with_override(stored_key, &full, kind, timestamp, payload, encoding)
            }
            // Degenerate empty-prefix mount-root: no full key to match a wildcard
            // against, so the raw gated write is correct.
            None => match kind {
                SampleKind::Put => self.process_put(stored_key, payload, encoding, timestamp),
                SampleKind::Del => self.process_delete(stored_key, timestamp),
            }
            .map(|_| ()),
        }
    }
    /// Raw-gated form when the wildcard engine is OFF: byte-identical to the
    /// pre-slice-3 concrete align write (no registries to consult).
    #[cfg(all(
        feature = "storage-aligner",
        not(feature = "storage-mgr-wildcard-updates")
    ))]
    fn apply_aligned_concrete(
        &mut self,
        stored_key: Option<&str>,
        kind: SampleKind,
        timestamp: TimestampHint,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
    ) -> Result<(), StorageWriteError> {
        match kind {
            SampleKind::Put => self.process_put(stored_key, payload, encoding, timestamp),
            SampleKind::Del => self.process_delete(stored_key, timestamp),
        }
        .map(|_| ())
    }

    /// Collect stale wildcard-update registry entries — the periodic GC sweep
    /// (`storage-mgr-garbage-collection`, R311wt slice 4). Removes every
    /// registered wildcard Put / Delete whose timestamp is OLDER than
    /// `now_ntp64 - lifespan`, bounding the memory the slice-2/3 registries would
    /// otherwise accumulate. zenoh `GarbageCollectionEvent`
    /// (`storages_mgt/service.rs:661-713`): `time_limit = now - lifespan`, remove
    /// each entry with `timestamp.get_time() < time_limit`.
    ///
    /// `now_ntp64` is INJECTED (the kernel has no clock — the driver passes
    /// [`crate::…wall_clock_ntp64`]), mirroring the `now: u64` seam of
    /// [`answer_alignment_query`](Self::answer_alignment_query). The comparison
    /// is on the raw NTP64 `time` WORD only (age; the zid tiebreak is irrelevant
    /// — zenoh compares `get_time()` likewise), so an entry exactly AT the limit
    /// is RETAINED (matching zenoh's strict `<` removal).
    ///
    /// # Two deliberate divergences from zenoh (both safer / faithful)
    ///
    /// - **`saturating_sub`**: zenoh's `NTP64` `Sub` is a plain u64 subtraction
    ///   (`uhlc ntp64.rs:204-210`) that debug-panics / release-wraps on
    ///   underflow — an unset-RTC boot (`now < lifespan`, e.g. an MCU before NTP
    ///   sync) would wrap the cutoff to ~u64::MAX and WIPE both registries. wz
    ///   saturates to `0`, so an un-set clock collects NOTHING (conservative).
    ///   The complementary over-long-`lifespan` overflow is guarded in
    ///   [`Ntp64::from_duration`](crate::ntp64::Ntp64::from_duration) (a span
    ///   `> 2^32 - 1` s saturates to `u64::MAX`, so the cutoff clamps to `0` —
    ///   collect nothing — rather than the `secs << 32` wrap wiping everything).
    /// - **`latest` is NEVER swept.** zenoh time-GCs its `latest_updates` cache
    ///   for a non-replicated storage (`service.rs:704-708` — via an inverted
    ///   `retain` that keeps OLD and drops NEW, a latent zenoh bug). wz's
    ///   [`latest`](StorageState) is the AUTHORITATIVE newer-wins record +
    ///   tombstone map (not a disposable cache), so sweeping it would drop
    ///   tombstones a replica needs for delete-convergence and resurrect deleted
    ///   keys. GC therefore bounds ONLY the wildcard-registry memory, NOT the
    ///   tombstone map (the documented "tombstones retained unbounded"
    ///   divergence, module doc). Faithful for a replicated storage (zenoh does
    ///   not time-GC a replicated log/cache either).
    #[cfg(feature = "storage-mgr-garbage-collection")]
    pub fn collect_garbage(&mut self, now_ntp64: u64, lifespan: core::time::Duration) {
        let time_limit =
            now_ntp64.saturating_sub(crate::ntp64::Ntp64::from_duration(lifespan).as_word());
        // R2354 — the sweep REMOVES replication events, so each collected
        // registration must leave the digest buckets it was hashed into. The
        // doomed set is read out before the retain: after it, the timestamps
        // that identify the buckets are gone. A sweep that dropped events
        // without telling the log would leave this replica advertising a
        // fingerprint for wildcard updates it no longer holds — the exact
        // shape of divergence replication exists to detect, manufactured by
        // the garbage collector.
        #[cfg(feature = "storage-replication")]
        let collected: Vec<(String, TimestampHint)> = self
            .wildcard_replication_entries()
            .filter(|(_, wu)| wu.data.timestamp.time < time_limit)
            .map(|(wildcard_ke, wu)| (String::from(wildcard_ke), wu.data.timestamp.clone()))
            .collect();
        self.wildcard_puts
            .retain(|_, wu| wu.data.timestamp.time >= time_limit);
        self.wildcard_deletes
            .retain(|_, wu| wu.data.timestamp.time >= time_limit);
        #[cfg(feature = "storage-replication")]
        for (wildcard_ke, timestamp) in &collected {
            self.replication_log
                .apply(Some(wildcard_ke.as_str()), Some(timestamp), None);
        }
    }

    /// The `(wildcard_puts, wildcard_deletes)` registry sizes — the inspection
    /// seam a GC driver / metrics surface reads to observe how much wildcard
    /// metadata is held (and that a [`collect_garbage`](Self::collect_garbage)
    /// sweep shrank it), without exposing the private registries. zenoh has no
    /// direct analog (its GC is fire-and-forget); this is the observability the
    /// [`crate::storage_state`] driver's periodic sweep test asserts against.
    #[cfg(feature = "storage-mgr-garbage-collection")]
    pub fn wildcard_registry_lens(&self) -> (usize, usize) {
        (self.wildcard_puts.len(), self.wildcard_deletes.len())
    }

    /// Every registered wildcard update, as `(full un-stripped keyexpr, entry)`
    /// — the ONE derivation the replication digest and the aligner's event
    /// snapshot both read their wildcard events off (R2351, the AV5 residual).
    ///
    /// zenoh keeps a single incremental log and both its digest and its aligner
    /// read wildcard events out of it — the insert sits next to the wildcard
    /// registration
    /// (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `if key_expr.is_wild()`).
    /// wz recomputes instead of logging, which is the
    /// declared divergence — but "recompute" must still mean ONE derivation, or
    /// the two recomputes disagree with each other. Hence this helper rather
    /// than two iterators: see
    /// [`replication_digest`](Self::replication_digest) for why a split is
    /// worse than the absence it replaces.
    ///
    /// A `WildcardPut` and a `WildcardDelete` over the same keyexpr are two
    /// distinct entries here, as they are two distinct log entries upstream —
    /// its log key is `(key, SampleKind)`
    /// (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `pub fn log_key`)
    /// — which is why the registries are two maps and this chains them rather
    /// than merging.
    #[cfg(all(
        feature = "storage-mgr-wildcard-updates",
        any(feature = "storage-replication", feature = "storage-aligner")
    ))]
    fn wildcard_replication_entries(&self) -> impl Iterator<Item = (&str, &WildcardUpdate)> + '_ {
        self.wildcard_puts
            .iter()
            .chain(self.wildcard_deletes.iter())
            .map(|(wildcard_ke, wu)| (wildcard_ke.as_str(), wu))
    }

    /// Answer one inbound query from the stored set (the serve side of a
    /// storage): reply every matching key — under `History::All` every
    /// version of it — each stamped with its OWN concrete keyexpr + value
    /// encoding + timestamp via [`ReplyOut::reply_keyed_stamped`], so a
    /// querier gets the value back exactly as stored and can order the
    /// versions. The terminating `ResponseFinal` is the queryable dispatch
    /// path's job, not this. Runtime-agnostic (reads the query through
    /// [`QueryView`], emits through the [`ReplyOut`] seam). zenoh
    /// `reply_query` (`storages_mgt/service.rs:546-622`).
    pub fn answer_into(&self, view: &dyn QueryView, out: &mut dyn ReplyOut) {
        for (key, versions) in self.matching_versions(view.keyexpr()) {
            for data in versions {
                out.reply_keyed_stamped(
                    &key,
                    &data.payload,
                    data.encoding.as_ref(),
                    &data.timestamp,
                );
            }
        }
    }

    /// Borrow the underlying backend (read-only inspection / handoff).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Builds this storage's replication [`Digest`] for the given Hot-era
    /// upper bound (the driver passes the current interval,
    /// `config.classify(now).0`). zenoh `Replication` builds the digest off
    /// its `LogLatest` (core.rs:217-227 -> log.rs:544); wz builds it off the
    /// authoritative storage state here.
    ///
    /// The digest is built from [`latest`](StorageState) — the latest
    /// accepted timestamp per key — which **includes tombstones** (an
    /// accepted Delete leaves its timestamp here even though the value is
    /// gone from the backend). Tombstones MUST be in the digest so a delete
    /// converges with a replica that still holds the key; this is why the
    /// digest is built from `latest` and not from
    /// [`StorageBackend::get_all_entries`], which drops deleted keys. zenoh
    /// records Delete events in its replication log for the same reason
    /// (log.rs:44-49 — `Action::Delete` is a first-class logged event).
    ///
    /// # History::Latest only
    ///
    /// Replication assumes a `History::Latest` backend, mirroring zenoh
    /// (replication only runs on Latest storages). The digest is built from
    /// [`latest`](StorageState), which is populated **only** in
    /// [`latest_mode`](StorageState::latest_mode) (the newer-wins gate). On a
    /// `History::All` backend `latest` stays empty, so this would return an
    /// EMPTY digest regardless of stored data — a replica would silently
    /// advertise "I have nothing". That is a misconfiguration (the
    /// `storage-replication` feature deliberately does not imply
    /// `storage-history`); the `debug_assert` below catches it loudly in
    /// debug builds instead of letting it fail silently.
    ///
    /// # Maintained, not recomputed (R2354)
    ///
    /// The digest is read off [`ReplicationLog`], which the write paths keep
    /// in step, so a publication cycle costs the era rollup and not a walk of
    /// the stored set. The `O(n)` derivation survives as
    /// [`recomputed_replication_digest`](Self::recomputed_replication_digest),
    /// and every debug build asserts the two agree on every call — the
    /// invariant is cheap to state, expensive to lose, and a write path that
    /// forgets the log has no other way of announcing itself. It is `&mut
    /// self` because the FIRST call under a configuration seeds the buckets:
    /// a storage takes writes long before anything asks it for a digest, and
    /// this tree also asks for digests under a PEER's configuration, which
    /// re-cuts the buckets.
    #[cfg(feature = "storage-replication")]
    pub fn replication_digest(
        &mut self,
        config: &ReplicationConfig,
        hot_era_upper_bound: IntervalIdx,
    ) -> Digest {
        debug_assert!(
            self.latest_mode(),
            "replication_digest assumes a History::Latest backend; a \
             History::All backend leaves `latest` empty and yields an empty \
             digest (zenoh's digest likewise assumes Latest)"
        );
        if !self.replication_log.is_bound_to(config) {
            // `mem::take` so the event stream (an immutable borrow of the
            // registries) and the log (a mutable one) are not borrowed from
            // `self` at the same time. The log is put back below; taking it is
            // sound precisely because seeding discards whatever was there.
            let mut log = core::mem::take(&mut self.replication_log);
            log.seed(config, self.replication_event_stream());
            self.replication_log = log;
        }
        let digest = self
            .replication_log
            .digest_from(config, hot_era_upper_bound);
        debug_assert_eq!(
            digest,
            self.recomputed_replication_digest(config, hot_era_upper_bound),
            "the maintained replication log disagrees with the recompute — a \
             write path changed a digest source without telling the log"
        );
        digest
    }

    /// The `O(n)` recompute of this storage's [`Digest`] straight from the
    /// event set: the SECOND derivation
    /// [`replication_digest`](Self::replication_digest) is checked against,
    /// and the one this atom published until R2354.
    ///
    /// It is public because it is an oracle, and an oracle nobody can call is
    /// not one: the differential lives in this crate's unit tests AND in the
    /// driver's, on the other side of the crate boundary. Production reads the
    /// maintained digest; this is what says the maintained digest is right.
    #[cfg(feature = "storage-replication")]
    pub fn recomputed_replication_digest(
        &self,
        config: &ReplicationConfig,
        hot_era_upper_bound: IntervalIdx,
    ) -> Digest {
        build_digest(config, self.replication_event_stream(), hot_era_upper_bound)
    }

    /// How many times this storage's replication buckets have been seeded from
    /// the full event set (R2354). A replica publishing under one
    /// configuration seeds ONCE, however many cycles it runs; the counter is
    /// the seam a test uses to say "maintained" rather than take it on trust,
    /// because a digest that silently recomputed would still be CORRECT and so
    /// could not be caught by comparing digests.
    #[cfg(feature = "storage-replication")]
    pub fn replication_log_seeds(&self) -> u64 {
        self.replication_log.seeds()
    }

    /// Every replication event of this storage as `(key, timestamp)` — the ONE
    /// derivation both the maintained log and the recompute read, so the two
    /// cannot disagree about what the population IS while disagreeing about
    /// the digest of it.
    #[cfg(feature = "storage-replication")]
    fn replication_event_stream(&self) -> impl Iterator<Item = (Option<&str>, &TimestampHint)> {
        // R2351 (AV5) — the registered wildcard updates are replication events
        // too, and they belong in the DIGEST as well as in
        // [`replication_events`](Self::replication_events). Both are the XOR of
        // the SAME per-event `event_fingerprint(key, timestamp)`
        // (`storage_replication.rs` `build_digest`, and
        // `storage_aligner.rs` `EventBuckets::sub_fingerprint`), so a wildcard
        // event carried by one and not the other would make this replica
        // advertise a sub-interval fingerprint its own digest never announced —
        // a disagreement with ITSELF, which is worse than the uniform absence
        // it replaces. zenoh cannot have that split: one log carries the
        // wildcard variants and feeds both
        // (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `WildcardPut(OwnedKeyExpr)`).
        #[cfg(feature = "storage-mgr-wildcard-updates")]
        let wildcard_events = self
            .wildcard_replication_entries()
            .map(|(wildcard_ke, wu)| (Some(wildcard_ke), &wu.data.timestamp));
        #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
        let wildcard_events = core::iter::empty();
        // Every key in `latest`, INCLUDING the mount-root (`None`) key: the
        // digest's per-event fingerprint hashes an `Option<&str>` key
        // (no key bytes when `None`), so a strip-configured storage's
        // mount-root value replicates faithfully (R311y64). zenoh hashes the
        // `Option` stripped key likewise (log.rs:237).
        self.latest
            .iter()
            .map(|(key, ts)| (key.as_deref(), ts))
            .chain(wildcard_events)
    }

    /// This storage's events as [`EventMetadata`], the snapshot the aligner
    /// answers ([`EventBuckets`](crate::storage_aligner::EventBuckets)) are
    /// computed from. One entry per key in [`latest`](StorageState),
    /// **including tombstones**: a key present in `latest` but absent from the
    /// backend was deleted, so it is a `Delete` event; a key still in the
    /// backend is a `Put`. zenoh's aligner reads the same Put/Delete events
    /// off its replication log — the `Action::Delete` tombstone is a
    /// first-class logged event there too (log.rs:44-49).
    ///
    /// Tombstones MUST be carried so a delete converges with a replica that
    /// still holds the key (the same reason
    /// [`replication_digest`](Self::replication_digest) is built from `latest`,
    /// not [`StorageBackend::get_all_entries`] which drops deleted keys).
    ///
    /// # History::Latest only
    ///
    /// Like [`replication_digest`](Self::replication_digest), the aligner
    /// assumes a `History::Latest` backend: `latest` is populated only by the
    /// newer-wins gate ([`latest_mode`](StorageState::latest_mode)), so a
    /// `History::All` backend yields no events. The `debug_assert` catches the
    /// misconfiguration loudly in debug builds.
    #[cfg(feature = "storage-aligner")]
    pub fn replication_events(&self) -> Vec<EventMetadata> {
        debug_assert!(
            self.latest_mode(),
            "replication_events assumes a History::Latest backend; a \
             History::All backend leaves `latest` empty (the aligner, like the \
             digest, assumes Latest)"
        );
        // R2351 (AV5) — a registered wildcard update is an event in its own
        // right, keyed on the FULL, un-stripped wildcard keyexpr. zenoh keys it
        // the same way and for the same reason: a wildcard cannot be stripped
        // (`put test/**` need not start with the storage's `strip_prefix`), so
        // the event carries the whole keyexpr
        // (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `cannot be stripped`),
        // and the insert sits at
        // (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `if key_expr.is_wild()`).
        //
        // `EventMetadata::wildcard` sets `timestamp_last_non_wildcard_update`
        // to `None`, which is what upstream's `Event::new` does for exactly
        // these two variants
        // (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `Action::WildcardPut(_) | Action::WildcardDelete(_) => None`)
        // — a wildcard is not a concrete write, so it cannot be its own last
        // non-wildcard one.
        //
        // Nothing else is needed for these to reach the ANSWERS: `EventBuckets`
        // classifies on the timestamp and XORs `fingerprint()`, never looking
        // at the action, so a wildcard event flows into the Diff / Intervals /
        // SubIntervals / Events drill-down like any other.
        //
        // Built as a chained iterator rather than a `push` loop so this reads
        // the same way [`replication_digest`](Self::replication_digest) does —
        // the two derivations of one population are meant to be legible as a
        // pair, and a `mut` here would exist only in one of the two feature
        // configurations anyway.
        #[cfg(feature = "storage-mgr-wildcard-updates")]
        let wildcard_events = self
            .wildcard_replication_entries()
            .map(|(wildcard_ke, wu)| {
                let action = match wu.kind {
                    SampleKind::Put => Action::WildcardPut(String::from(wildcard_ke)),
                    SampleKind::Del => Action::WildcardDelete(String::from(wildcard_ke)),
                };
                EventMetadata::wildcard(
                    Some(String::from(wildcard_ke)),
                    wu.data.timestamp.clone(),
                    action,
                )
            });
        #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
        let wildcard_events = core::iter::empty();
        self.latest
            .iter()
            // Every key in `latest`, INCLUDING the mount-root (`None`) key: an
            // [`EventMetadata`] now carries an `Option<String>` key (R311y64),
            // so a strip-configured storage's mount-root value is a first-class
            // replication event, faithful to zenoh's `Option` stripped_key.
            .map(|(key, ts)| {
                if self.backend.get(key.as_deref()).is_some() {
                    EventMetadata::put(key.clone(), ts.clone())
                } else {
                    EventMetadata::delete(key.clone(), ts.clone())
                }
            })
            .chain(wildcard_events)
            .collect()
    }

    /// Answer one [`AlignmentQuery`] from a peer that is aligning against this
    /// replica — the aligner's serve side. Returns the [`AlignmentResponse`]s
    /// to send back (a single query can yield several: a `Diff` up to three,
    /// an `All` / `Events` one per event). zenoh `Replication::aligner`
    /// (aligner_query.rs:73-172).
    ///
    /// `local_zid` answers a `Discovery`; `now` (the wall-clock NTP64) fixes
    /// the Hot-era upper bound (`config.classify(now).0`) the Cold-era reply
    /// is computed against, exactly as zenoh recomputes `last_elapsed_interval`
    /// at answer time (aligner_query.rs:190-199). Pure over the stored state +
    /// config — no Session, no async — so any aligner driver reuses it.
    ///
    /// The drill-down levels map one-to-one to [`EventBuckets`] answers; a
    /// `Retrieval` for a Put pairs its [`EventMetadata`] with the stored value
    /// via [`retrieval_response`](Self::retrieval_response).
    #[cfg(feature = "storage-aligner")]
    pub fn answer_alignment_query(
        &self,
        config: &ReplicationConfig,
        query: &AlignmentQuery,
        local_zid: &[u8],
        now: u64,
    ) -> Vec<AlignmentResponse> {
        match query {
            AlignmentQuery::Discovery => alloc::vec![AlignmentResponse {
                reply: AlignmentReply::Discovery(local_zid.to_vec()),
                value: None,
            }],
            // All: transfer every event (the initial full alignment).
            AlignmentQuery::All => self
                .replication_events()
                .into_iter()
                .filter_map(|meta| self.retrieval_response(meta))
                .collect(),
            AlignmentQuery::Diff(diff) => {
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                let hot_upper = config.classify(now).0;
                let mut out = Vec::new();
                if diff.cold_eras_differ() {
                    out.push(AlignmentResponse {
                        reply: AlignmentReply::Intervals(
                            buckets.cold_era_fingerprints(config, hot_upper),
                        ),
                        value: None,
                    });
                }
                if !diff.warm_eras_differences().is_empty() {
                    out.push(AlignmentResponse {
                        reply: AlignmentReply::SubIntervals(
                            buckets.sub_intervals_fingerprints(diff.warm_eras_differences()),
                        ),
                        value: None,
                    });
                }
                if !diff.hot_eras_differences().is_empty() {
                    out.push(AlignmentResponse {
                        reply: AlignmentReply::EventsMetadata(
                            buckets.events_in(diff.hot_eras_differences()),
                        ),
                        value: None,
                    });
                }
                out
            }
            AlignmentQuery::Intervals(intervals) => {
                if intervals.is_empty() {
                    return Vec::new();
                }
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                alloc::vec![AlignmentResponse {
                    reply: AlignmentReply::SubIntervals(
                        buckets.sub_intervals_fingerprints(intervals),
                    ),
                    value: None,
                }]
            }
            AlignmentQuery::SubIntervals(sub_intervals) => {
                if sub_intervals.is_empty() {
                    return Vec::new();
                }
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                alloc::vec![AlignmentResponse {
                    reply: AlignmentReply::EventsMetadata(buckets.events_in(sub_intervals)),
                    value: None,
                }]
            }
            AlignmentQuery::Events(events) => events
                .iter()
                .filter_map(|meta| self.retrieval_response(meta.clone()))
                .collect(),
        }
    }

    /// Build the `Retrieval` response for one event, or `None` to skip it.
    /// zenoh `reply_event_retrieval` (aligner_query.rs:271-335):
    ///
    /// - a Delete carries no value — the response is sent with `value: None`
    ///   (the peer applies the delete from the metadata alone);
    /// - a Put pairs the metadata with the stored value, **but only if the
    ///   stored value still has the requested timestamp**. If the key changed
    ///   or was removed between the metadata being sent and this retrieval, the
    ///   event is skipped (`None`) rather than replied with a stale/empty
    ///   payload (aligner_query.rs:298-316).
    #[cfg(feature = "storage-aligner")]
    fn retrieval_response(&self, meta: EventMetadata) -> Option<AlignmentResponse> {
        // Clone the action to release the `&self`-into-`meta` borrow before an
        // arm MOVES `meta` into the reply (R311wt slice-1: `action()` returns
        // `&Action` now that a wildcard variant carries a keyexpr String; the
        // clone is heap-free for the Put/Delete variants).
        match meta.action().clone() {
            Action::Delete => Some(AlignmentResponse {
                reply: AlignmentReply::Retrieval(meta),
                value: None,
            }),
            Action::Put => match self.backend.get(meta.key()) {
                Some(data) if &data.timestamp == meta.timestamp() => Some(AlignmentResponse {
                    value: Some(RetrievedValue {
                        payload: data.payload.clone(),
                        encoding: data.encoding.clone(),
                    }),
                    reply: AlignmentReply::Retrieval(meta),
                }),
                // The stored value moved on (newer ts) or is gone since the
                // metadata was sent: skip, as zenoh does.
                _ => None,
            },
            // R2351 — wz now HOSTS its wildcard events (they are derived from
            // the registry by
            // [`wildcard_replication_entries`](Self::wildcard_replication_entries)),
            // so a retrieval for one is answerable and the AV5 residual is
            // closed: a wz replica re-advertises the wildcard log entry itself,
            // not only the concrete keys it materialized onto.
            //
            // The value comes out of the REGISTRY, not the backend, and — unlike
            // the concrete `Put` arm above — there is NO timestamp comparison:
            // presence in the registry is the whole test. That asymmetry is
            // upstream's — it replies with whatever it finds
            // (`plugins/zenoh-plugin-storage-manager/src/replication/core/aligner_query.rs` @ `wildcard_puts_guard.weight_at(wildcard_ke)`)
            // — and it is not an oversight: the registry is
            // keyed on the wildcard
            // keyexpr and holds exactly one entry per key, so a re-issued
            // wildcard REPLACES rather than shadows, leaving nothing staler to
            // guard against. An absent entry is a skip — upstream logs and
            // returns without replying, which is this function's `None`.
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            Action::WildcardPut(wildcard_ke) => {
                self.wildcard_puts
                    .get(&wildcard_ke)
                    .map(|wu| AlignmentResponse {
                        value: Some(RetrievedValue {
                            payload: wu.data.payload.clone(),
                            encoding: wu.data.encoding.clone(),
                        }),
                        reply: AlignmentReply::Retrieval(meta),
                    })
            }
            // A WildcardDelete carries no value, for the same reason a concrete
            // Delete does not: the peer applies it from the metadata alone
            // (`plugins/zenoh-plugin-storage-manager/src/replication/core/aligner_query.rs` @ `Action::Delete | Action::WildcardDelete(_) => None`
            // pairs the two in one arm).
            #[cfg(feature = "storage-mgr-wildcard-updates")]
            Action::WildcardDelete(_) => Some(AlignmentResponse {
                reply: AlignmentReply::Retrieval(meta),
                value: None,
            }),
            // Without the wildcard-update engine there is no registry, so no
            // wildcard event is produced and none can be retrieved. This is the
            // slice-1 behaviour (decode-only), kept exactly where it still
            // applies rather than described as a permanent non-goal.
            #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
            Action::WildcardPut(_) | Action::WildcardDelete(_) => None,
        }
    }

    /// Process one [`AlignmentReply`] from a peer this replica is aligning
    /// *against* — the aligner's ASK half. Applies any entries this replica is
    /// missing (via the newer-wins gate) and returns the
    /// [`AlignmentFollowup`]: the next, finer query to send, or `Done`. zenoh
    /// `Replication::process_alignment_reply` (aligner_reply.rs:99-229), minus
    /// the wildcard arms wz storage has no events for.
    ///
    /// `value` is the reply body — present only for a Put
    /// [`Retrieval`](AlignmentReply::Retrieval) (the [`RetrievedValue`]); the
    /// driver pulls it off the query-reply and passes it here.
    ///
    /// The exchange is stateless and drives itself: a driver loops
    /// `query -> peer answers -> process each reply -> followup query` until
    /// every branch returns `Done`. No current-time is needed — the fingerprint
    /// comparisons are era-independent (a peer's Cold-era interval is compared
    /// against the local interval's fingerprint regardless of how this replica
    /// would classify it, mirroring zenoh, core/aligner_query.rs:179-186).
    #[cfg(feature = "storage-aligner")]
    pub fn process_alignment_reply(
        &mut self,
        config: &ReplicationConfig,
        reply: AlignmentReply,
        value: Option<RetrievedValue>,
    ) -> AlignmentFollowup {
        match reply {
            // Initial alignment: the peer told us its zid; the driver pulls all
            // of its content next.
            AlignmentReply::Discovery(zid) => AlignmentFollowup::DiscoveredReplica(zid),

            // Cold-era fingerprints: keep the intervals whose fingerprint we
            // differ on (or lack) and ask for their sub-intervals. The local
            // comparison is the era-INDEPENDENT interval fingerprint (zenoh
            // `intervals.get(idx).fingerprint()`, core/aligner_reply.rs:145),
            // NOT the cold-era-filtered map — so an interval the peer reports
            // cold but this replica would classify warm/hot under clock skew is
            // still compared on its real fingerprint, not spuriously re-requested.
            AlignmentReply::Intervals(peer_fingerprints) => {
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                let differing: alloc::collections::BTreeSet<_> = peer_fingerprints
                    .into_iter()
                    .filter(|(idx, peer_fp)| buckets.interval_fingerprint_of(idx) != Some(*peer_fp))
                    .map(|(idx, _)| idx)
                    .collect();
                if differing.is_empty() {
                    AlignmentFollowup::Done
                } else {
                    AlignmentFollowup::Query(AlignmentQuery::Intervals(differing))
                }
            }

            // Sub-interval fingerprints: keep the sub-intervals we differ on
            // (or lack) and ask for their events (aligner_reply.rs:160-200).
            // Mirrors zenoh: an interval present locally is inserted even with
            // an empty diff set; only a wholly-missing interval contributes all
            // of the peer's sub-intervals.
            AlignmentReply::SubIntervals(peer_sub_fingerprints) => {
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                let interval_keys: alloc::collections::BTreeSet<_> =
                    peer_sub_fingerprints.keys().copied().collect();
                let local = buckets.sub_intervals_fingerprints(&interval_keys);
                let mut diff: BTreeMap<_, alloc::collections::BTreeSet<_>> = BTreeMap::new();
                for (interval_idx, peer_subs) in peer_sub_fingerprints {
                    match local.get(&interval_idx) {
                        None => {
                            diff.insert(interval_idx, peer_subs.into_keys().collect());
                        }
                        Some(local_subs) => {
                            let differing = peer_subs
                                .into_iter()
                                .filter(|(sub_idx, peer_fp)| match local_subs.get(sub_idx) {
                                    Some(local_fp) => local_fp != peer_fp,
                                    None => true,
                                })
                                .map(|(sub_idx, _)| sub_idx)
                                .collect();
                            diff.insert(interval_idx, differing);
                        }
                    }
                }
                if diff.is_empty() {
                    AlignmentFollowup::Done
                } else {
                    AlignmentFollowup::Query(AlignmentQuery::SubIntervals(diff))
                }
            }

            // Event metadata: a Delete we lack applies right away (no payload
            // needed); a Put we lack is collected to fetch its payload
            // (aligner_reply.rs:201-224 -> process_event_metadata :243-306).
            AlignmentReply::EventsMetadata(events) => {
                let mut missing_puts = Vec::new();
                for meta in events {
                    if !self.is_missing(&meta) {
                        continue; // we already hold this event newer-or-equal
                    }
                    match meta.action().clone() {
                        Action::Put => missing_puts.push(meta),
                        Action::Delete => {
                            // R311wt slice 3: a received concrete Delete consults the
                            // wildcard registries (a registered wildcard-delete newer
                            // than it tombstones at the wildcard ts) — zenoh
                            // needs_further_processing, aligner_reply.rs:255/431.
                            let applied = self.apply_aligned_concrete(
                                meta.key(),
                                SampleKind::Del,
                                meta.timestamp().clone(),
                                Vec::new(),
                                None,
                            );
                            Self::note_aligned_apply(applied, meta.key());
                        }
                        // R311wt slice 3 (storage-mgr-wildcard-updates ON): apply
                        // a wildcard event received from a peer. A WildcardDelete
                        // needs no payload → materialize now; a WildcardPut needs
                        // its value → defer to the Retrieval round like a plain Put
                        // (zenoh process_event_metadata, aligner_reply.rs:265/293).
                        // The materialize key is the FULL keyexpr in the Action,
                        // NOT meta.key() (the stripped log key).
                        #[cfg(feature = "storage-mgr-wildcard-updates")]
                        Action::WildcardDelete(ke) => {
                            let applied = self.materialize_wildcard(
                                &ke,
                                SampleKind::Del,
                                meta.timestamp().clone(),
                                Vec::new(),
                                None,
                            );
                            Self::note_aligned_apply(applied, meta.key());
                        }
                        #[cfg(feature = "storage-mgr-wildcard-updates")]
                        Action::WildcardPut(_) => missing_puts.push(meta),
                        // storage-aligner WITHOUT storage-mgr-wildcard-updates: no
                        // override engine to apply into, so skip (as slice 1 did).
                        #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
                        Action::WildcardPut(_) | Action::WildcardDelete(_) => {}
                    }
                }
                if missing_puts.is_empty() {
                    AlignmentFollowup::Done
                } else {
                    AlignmentFollowup::Query(AlignmentQuery::Events(missing_puts))
                }
            }

            // A retrieved event + its payload: apply it through the newer-wins
            // gate, unless we already hold it newer-or-equal
            // (aligner_reply.rs:321-409, the wz-relevant Put / Delete arms).
            AlignmentReply::Retrieval(meta) => {
                if self.is_missing(&meta) {
                    match meta.action() {
                        Action::Put => {
                            if let Some(RetrievedValue { payload, encoding }) = value {
                                // R311wt slice 3: a received concrete Put consults the
                                // wildcard registries (a registered wildcard newer than
                                // it overrides its value/kind) — zenoh
                                // needs_further_processing, aligner_reply.rs:337/431.
                                let applied = self.apply_aligned_concrete(
                                    meta.key(),
                                    SampleKind::Put,
                                    meta.timestamp().clone(),
                                    payload,
                                    encoding,
                                );
                                Self::note_aligned_apply(applied, meta.key());
                            }
                            // A Put with no value = the peer skipped it (its
                            // data changed); nothing to apply.
                        }
                        Action::Delete => {
                            let applied = self.apply_aligned_concrete(
                                meta.key(),
                                SampleKind::Del,
                                meta.timestamp().clone(),
                                Vec::new(),
                                None,
                            );
                            Self::note_aligned_apply(applied, meta.key());
                        }
                        // R311wt slice 3: a WildcardPut retrieved WITH its payload
                        // → materialize. A WildcardDelete reaches the Retrieval arm
                        // ONLY on initial alignment (`AlignmentQuery::All` routes
                        // straight here, answer_alignment_query All arm) — zenoh
                        // register-only's there (aligner_reply.rs:355) assumes an
                        // empty backend; wz materializes (a safe idempotent superset:
                        // a no-op on an empty backend, correct if wz re-joins
                        // non-empty). Use the FULL keyexpr in the Action.
                        #[cfg(feature = "storage-mgr-wildcard-updates")]
                        Action::WildcardPut(ke) => {
                            if let Some(RetrievedValue { payload, encoding }) = value {
                                let applied = self.materialize_wildcard(
                                    ke,
                                    SampleKind::Put,
                                    meta.timestamp().clone(),
                                    payload,
                                    encoding,
                                );
                                Self::note_aligned_apply(applied, meta.key());
                            }
                            // A WildcardPut with no value = the peer skipped it;
                            // nothing to apply (mirrors the plain-Put arm).
                        }
                        #[cfg(feature = "storage-mgr-wildcard-updates")]
                        Action::WildcardDelete(ke) => {
                            let applied = self.materialize_wildcard(
                                ke,
                                SampleKind::Del,
                                meta.timestamp().clone(),
                                Vec::new(),
                                None,
                            );
                            Self::note_aligned_apply(applied, meta.key());
                        }
                        // storage-aligner WITHOUT storage-mgr-wildcard-updates: skip.
                        #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
                        Action::WildcardPut(_) | Action::WildcardDelete(_) => {}
                    }
                }
                AlignmentFollowup::Done
            }
        }
    }

    /// Record a failed ALIGN-receive apply and carry on — R311y831.
    ///
    /// There is nothing else an aligner can do mid-round, and nothing else it
    /// needs to do. The events in a reply are independent, so aborting would
    /// discard the ones that CAN be written; and the event that failed left no
    /// version record behind (that is [`process_put`](Self::process_put)'s
    /// contract), so [`is_missing`](Self::is_missing) still reports it missing
    /// and the next digest round pulls it again. Upstream's capture side lands
    /// in the same place from the other direction
    /// (`storages_mgt/service.rs:361-365`: log, continue the loop).
    #[cfg(feature = "storage-aligner")]
    fn note_aligned_apply(outcome: Result<(), StorageWriteError>, key: Option<&str>) {
        if outcome.is_err() {
            log::error!(
                "wz storage aligner: the backend refused the aligned event for key {key:?}; \
                 it stays missing on this replica and is pulled again next round"
            );
        }
    }

    /// Whether this replica is *missing* `meta` — i.e. it holds no
    /// strictly-newer-or-equal timestamp for the key, so the event should be
    /// pulled. zenoh's `latest_updates.get(key).timestamp >= replica_event` skip
    /// check (aligner_reply.rs:244-252).
    #[cfg(feature = "storage-aligner")]
    fn is_missing(&self, meta: &EventMetadata) -> bool {
        match self.latest.get(&meta.key().map(String::from)) {
            Some(recorded) => timestamp_strictly_newer(meta.timestamp(), recorded),
            None => true,
        }
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
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(
            s.process_put(Some("demo/a"), vec![2], None, ts(20, 1))
                .unwrap(),
            StorageInsertionResult::Replaced
        );
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn older_put_is_rejected_as_outdated_and_value_unchanged() {
        let mut s = state();
        s.process_put(Some("demo/a"), vec![9], None, ts(100, 1))
            .unwrap();
        let r = s
            .process_put(Some("demo/a"), vec![1], None, ts(1, 1))
            .unwrap();
        assert_eq!(r, StorageInsertionResult::Outdated);
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
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
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        let r = s
            .process_put(Some("demo/a"), vec![2], None, ts(10, 1))
            .unwrap();
        assert_eq!(r, StorageInsertionResult::Replaced);
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn zid_breaks_a_timestamp_tie_higher_zid_is_newer() {
        // Equal NTP64 time -> the zid bytes decide (uhlc Ord, time then
        // id). A put with the same time but a higher zid is strictly newer.
        let mut s = state();
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        let r = s
            .process_put(Some("demo/a"), vec![2], None, ts(10, 2))
            .unwrap();
        assert_eq!(r, StorageInsertionResult::Replaced);
        // The reverse (lower zid at equal time) is older -> rejected.
        let r2 = s
            .process_put(Some("demo/a"), vec![3], None, ts(10, 1))
            .unwrap();
        assert_eq!(r2, StorageInsertionResult::Outdated);
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn timestamp_tiebreak_matches_uhlc_zero_padded_id_not_trimmed_vec_lex() {
        // uhlc compares the FULL 16-byte zero-padded LE id array, so a
        // non-canonically-encoded zid (a trailing zero not trimmed) is the
        // SAME id as its trimmed form: [0x05] == [0x05, 0x00]. A naive
        // trimmed-Vec lexicographic compare would WRONGLY rank
        // [0x05] < [0x05, 0x00] (shorter-is-less), flipping a newer-wins
        // decision. The zero-padded comparator treats them as equal.
        let a = TimestampHint {
            time: 10,
            zid: vec![0x05],
        };
        let b = TimestampHint {
            time: 10,
            zid: vec![0x05, 0x00],
        };
        assert!(
            !timestamp_strictly_newer(&a, &b) && !timestamp_strictly_newer(&b, &a),
            "[0x05] and [0x05,0x00] are the same uhlc id — neither is newer"
        );
        // A genuinely higher 16-byte LE id IS newer at equal time.
        let c = TimestampHint {
            time: 10,
            zid: vec![0x05, 0x01],
        };
        assert!(
            timestamp_strictly_newer(&c, &a),
            "a higher high-byte (0x05,0x01 > 0x05 padded) is strictly newer"
        );
    }

    #[test]
    fn delete_then_older_put_is_rejected_tombstone_holds() {
        // The correctness property the tombstone exists for: a Delete at
        // t=50 must block a Put at t=40 from resurrecting the key.
        let mut s = state();
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        assert_eq!(
            s.process_delete(Some("demo/a"), ts(50, 1)).unwrap(),
            StorageInsertionResult::Deleted
        );
        assert!(s.get(Some("demo/a")).is_none(), "deleted value is gone");
        let r = s
            .process_put(Some("demo/a"), vec![2], None, ts(40, 1))
            .unwrap();
        assert_eq!(
            r,
            StorageInsertionResult::Outdated,
            "an older put after a delete must not resurrect the key"
        );
        assert!(s.get(Some("demo/a")).is_none());
    }

    #[test]
    fn delete_then_newer_put_resurrects_the_key() {
        let mut s = state();
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        s.process_delete(Some("demo/a"), ts(50, 1)).unwrap();
        let r = s
            .process_put(Some("demo/a"), vec![2], None, ts(60, 1))
            .unwrap();
        assert_eq!(r, StorageInsertionResult::Inserted);
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
    }

    #[test]
    fn delete_older_than_stored_is_rejected() {
        let mut s = state();
        s.process_put(Some("demo/a"), vec![1], None, ts(100, 1))
            .unwrap();
        let r = s.process_delete(Some("demo/a"), ts(50, 1)).unwrap();
        assert_eq!(r, StorageInsertionResult::Outdated);
        assert!(
            s.get(Some("demo/a")).is_some(),
            "an outdated delete must not remove the newer value"
        );
    }

    #[test]
    fn matching_entries_wildcard_returns_intersecting_live_keys() {
        let mut s = state();
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        s.process_put(Some("demo/b"), vec![2], None, ts(10, 1))
            .unwrap();
        s.process_put(Some("other/c"), vec![3], None, ts(10, 1))
            .unwrap();
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
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        s.process_put(Some("demo/b"), vec![2], None, ts(10, 1))
            .unwrap();
        s.process_delete(Some("demo/a"), ts(20, 1)).unwrap();
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
        s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
            .unwrap();
        s.process_put(Some("demo/b"), vec![2], None, ts(10, 1))
            .unwrap();
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
        s.process_put(Some("demo/a"), vec![1], None, ts(20, 1))
            .unwrap();
        s.process_put(Some("demo/a"), vec![2], None, ts(30, 1))
            .unwrap(); // replaces
        let hits = s.matching_versions("demo/a");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1.len(), 1, "Latest keeps one version");
        assert_eq!(hits[0].1[0].payload, vec![2]);
    }

    // R311y831 — what the gate may record when the BACKEND refuses the write.
    // The claim under test is not "an error is returned" (that is the seam's)
    // but "nothing above the backend remembers a mutation the backend did not
    // make": no newer-wins version record, therefore no tombstone, therefore
    // no replication event. zenoh takes the same branch by skipping its
    // `cache_guard.insert` on `Err` (`storages_mgt/service.rs:352-366`).
    mod refused_writes {
        use super::*;
        use alloc::rc::Rc;
        use core::cell::Cell;

        /// A backend over a medium that can refuse — the failure a
        /// [`MemoryStorage`] cannot model. `refuse` is a shared switch rather
        /// than a constructor flag for one reason: every claim here is about
        /// the DIFFERENCE a refusal makes, so the accepting control has to come
        /// out of the same store mid-test. Flipping it after a committed write
        /// is also the only way to reach "an older put after a REFUSED delete",
        /// which is the resurrection question.
        ///
        /// On refusal it does not touch `inner`, which is the seam's contract:
        /// what a backend serves must be what its medium holds.
        #[derive(Debug, Default)]
        struct RefusingStorage {
            inner: MemoryStorage,
            refuse: Rc<Cell<bool>>,
        }

        impl StorageBackend for RefusingStorage {
            fn put(
                &mut self,
                key: Option<&str>,
                payload: Vec<u8>,
                encoding: Option<EncodingHint>,
                timestamp: TimestampHint,
            ) -> StorageWriteResult {
                if self.refuse.get() {
                    return Err(StorageWriteError);
                }
                self.inner.put(key, payload, encoding, timestamp)
            }

            fn delete(
                &mut self,
                key: Option<&str>,
                timestamp: TimestampHint,
            ) -> StorageWriteResult {
                if self.refuse.get() {
                    return Err(StorageWriteError);
                }
                self.inner.delete(key, timestamp)
            }

            fn get(&self, key: Option<&str>) -> Option<&StoredData> {
                self.inner.get(key)
            }

            fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
                self.inner.get_all_entries()
            }
        }

        /// A state over a refusing backend, plus the switch that arms it.
        fn refusing() -> (StorageState<RefusingStorage>, Rc<Cell<bool>>) {
            let refuse = Rc::new(Cell::new(false));
            let backend = RefusingStorage {
                inner: MemoryStorage::new(),
                refuse: Rc::clone(&refuse),
            };
            (StorageState::new(backend), refuse)
        }

        #[test]
        fn a_refused_put_reports_the_refusal_and_stores_nothing() {
            let (mut s, refuse) = refusing();
            refuse.set(true);
            assert!(s
                .process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .is_err());
            assert!(s.get(Some("demo/a")).is_none());
        }

        #[test]
        fn a_refused_put_leaves_no_version_record() {
            // The discriminator: `latest` is invisible from outside, so the
            // test asks the ONE question that reads it — a strictly OLDER put
            // afterwards. If the refused write had been recorded at t=10, this
            // t=5 put would come back `Outdated`.
            let (mut s, refuse) = refusing();
            refuse.set(true);
            assert!(s
                .process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .is_err());
            refuse.set(false);
            assert_eq!(
                s.process_put(Some("demo/a"), vec![2], None, ts(5, 1))
                    .unwrap(),
                StorageInsertionResult::Inserted,
                "a write the backend refused must not gate later ones"
            );
        }

        #[test]
        fn a_committed_put_does_leave_one() {
            // The paired control for the test above, out of the SAME fixture:
            // without it, a `process_put` that recorded nothing at all would
            // pass the claim above just as well.
            let (mut s, _refuse) = refusing();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            assert_eq!(
                s.process_put(Some("demo/a"), vec![2], None, ts(5, 1))
                    .unwrap(),
                StorageInsertionResult::Outdated
            );
        }

        #[test]
        fn a_refused_delete_leaves_no_tombstone() {
            let (mut s, refuse) = refusing();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            refuse.set(true);
            assert!(s.process_delete(Some("demo/a"), ts(50, 1)).is_err());
            refuse.set(false);
            // The key is still there (the backend never removed it) AND the
            // t=50 tombstone was not recorded, so a t=20 put still lands.
            assert!(s.get(Some("demo/a")).is_some());
            assert_eq!(
                s.process_put(Some("demo/a"), vec![2], None, ts(20, 1))
                    .unwrap(),
                StorageInsertionResult::Replaced
            );
        }

        #[test]
        fn a_committed_delete_does_leave_one() {
            let (mut s, _refuse) = refusing();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_delete(Some("demo/a"), ts(50, 1)).unwrap();
            assert_eq!(
                s.process_put(Some("demo/a"), vec![2], None, ts(20, 1))
                    .unwrap(),
                StorageInsertionResult::Outdated
            );
        }

        /// The consequence that reaches other nodes: a refused write must not
        /// appear in the replication event set, or an aligning peer is told
        /// this replica holds a sample it never stored and stops sending it.
        #[cfg(feature = "storage-aligner")]
        #[test]
        fn a_refused_put_is_absent_from_the_replication_events() {
            let (mut s, refuse) = refusing();
            s.process_put(Some("demo/kept"), vec![1], None, ts(10, 1))
                .unwrap();
            refuse.set(true);
            assert!(s
                .process_put(Some("demo/lost"), vec![2], None, ts(11, 1))
                .is_err());

            let keys: Vec<Option<String>> = s
                .replication_events()
                .iter()
                .map(|e| e.key().map(String::from))
                .collect();
            assert_eq!(
                keys,
                vec![Some(String::from("demo/kept"))],
                "the digest may advertise only what this replica actually holds"
            );
        }
    }

    // R311y61 — strip_prefix composition: a strip-configured state stores keys
    // RELATIVE to the mount point (the exact-prefix key under the backend's
    // `None` slot) and restores the full keyexpr on a query.
    #[cfg(feature = "storage-mgr-strip-prefix")]
    mod strip {
        use super::*;
        use crate::sample::Sample;

        fn stripped(prefix: &str) -> StorageState<MemoryStorage> {
            StorageState::with_strip_prefix(MemoryStorage::new(), Some(prefix.into()))
        }

        #[test]
        fn under_mount_key_is_stored_relative_and_restored_on_query() {
            let mut s = stripped("home/kitchen");
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![21]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            // Stored under the RELATIVE key, not the full keyexpr.
            assert_eq!(
                s.get(Some("temp"))
                    .expect("stored under the stripped key")
                    .payload,
                vec![21]
            );
            assert!(
                s.get(Some("home/kitchen/temp")).is_none(),
                "the full keyexpr is not a stored key"
            );
            // A query is matched + replied in the FULL keyexpr space (restored).
            let hits = s.matching_entries("home/kitchen/*");
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].0, "home/kitchen/temp", "the reply key is restored");
            assert_eq!(hits[0].1.payload, vec![21]);
        }

        #[test]
        fn exact_mount_root_key_is_stored_under_the_none_slot() {
            // A put on EXACTLY the prefix sits AT the mount point: stored under
            // the backend's `None` slot (zenoh Ok(None)), restored to the prefix.
            let mut s = stripped("home/kitchen");
            s.apply_sample(
                &Sample::new_put("home/kitchen", vec![7]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            assert_eq!(
                s.backend()
                    .get(None)
                    .expect("mount-root value in the None slot")
                    .payload,
                vec![7]
            );
            let hits = s.matching_entries("home/kitchen");
            assert_eq!(hits.len(), 1);
            assert_eq!(
                hits[0].0, "home/kitchen",
                "the mount-root key restores to the prefix"
            );
            assert_eq!(hits[0].1.payload, vec![7]);
        }

        #[test]
        fn a_key_not_under_the_prefix_is_dropped() {
            let mut s = stripped("home/kitchen");
            s.apply_sample(
                &Sample::new_put("away/x", vec![1]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            assert!(
                s.backend().get_all_entries().is_empty(),
                "a key outside the mount is not captured"
            );
        }

        #[test]
        fn no_strip_configured_stores_verbatim() {
            // with_strip_prefix(None) is equivalent to new(): keys stored as-is.
            let mut s = StorageState::with_strip_prefix(MemoryStorage::new(), None);
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![5]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            assert_eq!(s.get(Some("home/kitchen/temp")).unwrap().payload, vec![5]);
        }

        #[test]
        fn delete_under_strip_leaves_a_tombstone_on_the_stripped_key() {
            // The newer-wins tombstone is keyed on the STORED (stripped) key.
            // A Put then Delete under the mount removes the relative "temp", and
            // the tombstone — recorded at the stripped key — then rejects an
            // OLDER Put on the same full keyexpr (no resurrection through strip).
            let mut s = stripped("home/kitchen");
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![21]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            s.apply_sample(
                &Sample::new_del("home/kitchen/temp").with_timestamp(ts(50, 1)),
                || unreachable!(),
            );
            assert!(
                s.get(Some("temp")).is_none(),
                "the delete removed the stripped key from the backend"
            );
            // An OLDER put on the full keyexpr is rejected — the tombstone keyed
            // on the stripped "temp" holds across the strip transform.
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![99]).with_timestamp(ts(40, 1)),
                || unreachable!(),
            );
            assert!(
                s.get(Some("temp")).is_none(),
                "an older put after the delete must not resurrect the stripped key"
            );
        }

        #[test]
        fn delete_on_the_exact_mount_root_leaves_a_tombstone_on_the_none_key() {
            // The mount-root value lives under the backend `None` key; its
            // tombstone is recorded on `None` too, so a Put then Delete then an
            // OLDER Put on EXACTLY the prefix is rejected.
            let mut s = stripped("home/kitchen");
            s.apply_sample(
                &Sample::new_put("home/kitchen", vec![7]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            s.apply_sample(
                &Sample::new_del("home/kitchen").with_timestamp(ts(50, 1)),
                || unreachable!(),
            );
            assert!(
                s.backend().get(None).is_none(),
                "the delete removed the mount-root value from the None slot"
            );
            // An OLDER put on the mount root is rejected — the tombstone keyed
            // on the `None` slot holds.
            s.apply_sample(
                &Sample::new_put("home/kitchen", vec![99]).with_timestamp(ts(40, 1)),
                || unreachable!(),
            );
            assert!(
                s.backend().get(None).is_none(),
                "an older put after the mount-root delete must not resurrect the None key"
            );
        }

        #[test]
        fn a_wild_prefix_drops_every_sample() {
            // A WILD strip_prefix (e.g. "home/*") makes strip_prefix return
            // Err(WildPrefix) -> stored_key_for yields None -> apply_sample
            // drops the sample. Nothing is ever captured (the same drop the
            // not-under-prefix case takes, for a different reason).
            let mut s = stripped("home/*");
            s.apply_sample(
                &Sample::new_put("home/x/y", vec![1]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            assert!(
                s.backend().get_all_entries().is_empty(),
                "a wild strip_prefix drops the sample (strip returns Err)"
            );
        }
    }

    // R311wt slice 2 — with `storage-mgr-wildcard-updates` OFF, a wildcard
    // keyexpr is stored VERBATIM as an ordinary key (the pre-slice-2 divergence).
    // This guards the OFF path's byte-identical behavior; the ON path is the
    // `wildcard` mod below.
    #[cfg(not(feature = "storage-mgr-wildcard-updates"))]
    #[test]
    fn wildcard_key_is_stored_literally_when_the_engine_is_off() {
        use crate::sample::Sample;
        let mut s = state();
        s.apply_sample(
            &Sample::new_put("demo/**", vec![42]).with_timestamp(ts(10, 1)),
            || unreachable!(),
        );
        assert_eq!(
            s.get(Some("demo/**"))
                .expect("wildcard stored literally")
                .payload,
            vec![42],
            "with the engine OFF a wildcard is an ordinary stored key"
        );
    }

    // R311wt slice 2 — the write-path wildcard override engine.
    #[cfg(feature = "storage-mgr-wildcard-updates")]
    mod wildcard {
        use super::*;
        use crate::sample::Sample;

        fn wput(s: &mut StorageState<MemoryStorage>, ke: &str, payload: Vec<u8>, t: u64, zid: u8) {
            s.apply_sample(
                &Sample::new_put(ke, payload).with_timestamp(ts(t, zid)),
                || unreachable!(),
            );
        }
        fn wdel(s: &mut StorageState<MemoryStorage>, ke: &str, t: u64, zid: u8) {
            s.apply_sample(
                &Sample::new_del(ke).with_timestamp(ts(t, zid)),
                || unreachable!(),
            );
        }

        #[test]
        fn wildcard_put_materializes_onto_every_matching_live_key() {
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(1, 1))
                .unwrap();
            s.process_put(Some("demo/b"), vec![1], None, ts(1, 1))
                .unwrap();
            s.process_put(Some("other/c"), vec![1], None, ts(1, 1))
                .unwrap();
            // A wildcard PUT rewrites every matching live key to its value+ts.
            wput(&mut s, "demo/**", vec![9], 5, 1);
            assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![9]);
            assert_eq!(s.get(Some("demo/b")).unwrap().payload, vec![9]);
            assert_eq!(
                s.get(Some("other/c")).unwrap().payload,
                vec![1],
                "a non-matching key is untouched"
            );
            // The wildcard itself is NOT stored as a literal key (the slice-2 fix).
            assert!(s.get(Some("demo/**")).is_none());
        }

        #[test]
        fn wildcard_delete_materializes_onto_every_matching_live_key() {
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(1, 1))
                .unwrap();
            s.process_put(Some("demo/b"), vec![1], None, ts(1, 1))
                .unwrap();
            s.process_put(Some("other/c"), vec![1], None, ts(1, 1))
                .unwrap();
            wdel(&mut s, "demo/**", 5, 1);
            assert!(s.get(Some("demo/a")).is_none(), "matched key deleted");
            assert!(s.get(Some("demo/b")).is_none(), "matched key deleted");
            assert_eq!(
                s.get(Some("other/c")).unwrap().payload,
                vec![1],
                "a non-matching key is untouched"
            );
        }

        #[test]
        fn concrete_put_survives_an_older_wildcard_delete() {
            // Timeline (a): concrete Put demo/a@t3, then wildcard-delete
            // demo/**@t2 (t2 < t3). demo/a survives. On the MATERIALIZE path the
            // override lookup is entered with the wildcard's OWN ts (t2), so it
            // finds itself and returns Delete@t2 — the protection here is the
            // DOWNSTREAM newer-wins gate: process_delete's `accepts` rejects the
            // @t2 delete because `latest[demo/a]=t3` is newer (zenoh
            // guard_cache_if_latest, service.rs:536). (The resurrection guard's
            // discriminating direction — a stale registered wildcard-delete NOT
            // suppressing a newer CONCRETE put — is the separate
            // `newer_concrete_put_survives_a_stale_registered_wildcard_delete`.)
            let mut s = state();
            s.process_put(Some("demo/a"), vec![7], None, ts(30, 1))
                .unwrap();
            wdel(&mut s, "demo/**", 20, 1);
            assert_eq!(
                s.get(Some("demo/a")).unwrap().payload,
                vec![7],
                "an older wildcard-delete must not delete a newer key"
            );
        }

        #[test]
        fn out_of_order_concrete_put_under_a_registered_wildcard_delete_is_emptied() {
            // Timeline (e)+(g), THE subtle core slice 2 finishes: wildcard-delete
            // demo/**@t5 arrives while demo/a is ABSENT (registers wd@t5,
            // materializes onto nothing), then a LATE concrete Put demo/a=Y@t3
            // (t3 < t5) arrives. The shadow-check overrides the put's VALUE with
            // the wildcard-delete's — an EMPTY value at t5 — while the backend
            // op stays the incoming put. R2352: the key is therefore PRESENT and
            // empty, which is what upstream stores and what a query on a real
            // zenohd returns.
            let mut s = state();
            wdel(&mut s, "demo/**", 50, 1);
            wput(&mut s, "demo/a", vec![9], 30, 1);
            let stored = s
                .get(Some("demo/a"))
                .expect("the overridden put is stored, not tombstoned");
            assert!(
                stored.payload.is_empty(),
                "the wildcard-delete still wins: it empties the value it overrode"
            );
            assert_eq!(
                stored.timestamp,
                ts(50, 1),
                "the stored value carries the OVERRIDE ts, not the incoming put's"
            );
            // AV3: the write sits at the wildcard-delete ts (t5=50), NOT the
            // incoming put ts (t3=30). An intermediate put@t40 is still rejected;
            // only a put NEWER than t50 resurrects.
            let r_mid = s
                .process_put(Some("demo/a"), vec![1], None, ts(40, 1))
                .unwrap();
            assert_eq!(
                r_mid,
                StorageInsertionResult::Outdated,
                "no resurrection window between the incoming ts and the wildcard ts"
            );
            let r_new = s
                .process_put(Some("demo/a"), vec![2], None, ts(60, 1))
                .unwrap();
            assert_eq!(
                r_new,
                StorageInsertionResult::Replaced,
                "R2352 — the newer put REPLACES the empty value the override left \
                 behind; it was an Insert while the override tombstoned the key"
            );
            assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![2]);
        }

        #[test]
        fn late_concrete_put_is_upgraded_to_a_registered_wildcard_put() {
            // Timeline (c): wildcard-put demo/**=X@t4 arrives while demo/a is
            // ABSENT (registers wp@t4), then concrete Put demo/a=Y@t3 (t3 < t4).
            // The shadow-check upgrades the put to the wildcard's value+ts.
            let mut s = state();
            wput(&mut s, "demo/**", vec![0xAA], 40, 1);
            assert!(
                s.get(Some("demo/a")).is_none(),
                "the wildcard-put creates no key (demo/a absent at materialize)"
            );
            wput(&mut s, "demo/a", vec![0xBB], 30, 1);
            assert_eq!(
                s.get(Some("demo/a")).unwrap().payload,
                vec![0xAA],
                "the late concrete put is upgraded to the newer wildcard-put value"
            );
        }

        #[test]
        fn wildcard_put_does_not_resurrect_a_tombstone() {
            // A wildcard-put NEWER than a tombstone does NOT re-create the key
            // (materialize scans live keys only; a tombstoned key is absent).
            // zenoh get_matching_keys, service.rs:635 (get_all_entries drops
            // deleted keys). Only a future concrete put would re-create it.
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_delete(Some("demo/a"), ts(50, 1)).unwrap(); // tombstone@50
            wput(&mut s, "demo/**", vec![9], 70, 1); // newer wildcard-put
            assert!(
                s.get(Some("demo/a")).is_none(),
                "a wildcard-put must not resurrect a tombstoned key via materialize"
            );
        }

        #[test]
        fn newer_wildcard_delete_overrides_a_wildcard_put_delete_phase_first() {
            // Timeline (d): overlapping wildcard-put@t1 and wildcard-delete@t2
            // (t2 > t1) on the same keyexpr, then concrete Put demo/a=Y@t0.
            // The delete phase runs first and returns the (newer) wildcard-delete
            // before the put phase — a WildcardDelete overrides a WildcardPut
            // (zenoh core.rs:662-669 asymmetry; service.rs:426 delete-phase-first).
            let mut s = state();
            wput(&mut s, "demo/**", vec![0xAA], 10, 1);
            wdel(&mut s, "demo/**", 20, 1);
            wput(&mut s, "demo/a", vec![0xBB], 5, 1);
            let stored = s
                .get(Some("demo/a"))
                .expect("R2352: an overridden put is stored empty, not tombstoned");
            assert!(
                stored.payload.is_empty(),
                "the newer wildcard-delete wins over the wildcard-put: the \
                 wildcard-put's 0xAA must NOT be the stored value"
            );
            assert_eq!(stored.timestamp, ts(20, 1), "at the wildcard-delete ts");
        }

        #[test]
        fn wildcard_delete_short_circuits_even_a_newer_wildcard_put_on_the_live_path() {
            // Timeline (d) reverse (wildcard-put@t2 NEWER than wildcard-delete@t1):
            // the delete phase still returns first (short-circuit, service.rs:460),
            // so a concrete Put@t0 is DELETED@t1 even though a newer wildcard-put@t2
            // exists. This is zenoh's LIVE-path limitation (convergence to the
            // wildcard-put value is the align-path's job, slice 3) — wz reproduces
            // it faithfully. Guarded so it is not later "fixed" into a divergence.
            let mut s = state();
            wdel(&mut s, "demo/**", 10, 1);
            wput(&mut s, "demo/**", vec![0xAA], 20, 1);
            wput(&mut s, "demo/a", vec![0xBB], 5, 1);
            let stored = s
                .get(Some("demo/a"))
                .expect("R2352: an overridden put is stored empty, not tombstoned");
            assert!(
                stored.payload.is_empty(),
                "the delete phase short-circuits before the newer put (zenoh live \
                 parity): neither 0xAA nor 0xBB is stored"
            );
            assert_eq!(stored.timestamp, ts(10, 1), "at the wildcard-delete ts");
        }

        #[test]
        fn newer_concrete_put_survives_a_stale_registered_wildcard_delete() {
            // The resurrection guard's DISCRIMINATING (data-loss) direction: a
            // wildcard-delete demo/**@t2 registered FIRST (materializes onto
            // nothing), then a NEWER concrete Put demo/a=X@t3 (t3 > t2). The stale
            // wildcard-delete must NOT suppress the newer put — the delete-phase
            // filter `wd.ts >= incoming` excludes wd@t2 (zenoh service.rs:441).
            // Without the filter this silently tombstones a live newer write.
            let mut s = state();
            wdel(&mut s, "demo/**", 20, 1);
            wput(&mut s, "demo/a", vec![7], 30, 1);
            assert_eq!(
                s.get(Some("demo/a")).unwrap().payload,
                vec![7],
                "a newer concrete put must survive a stale registered wildcard-delete"
            );
        }

        #[test]
        fn equal_ts_wildcard_delete_overrides_the_concrete_put() {
            // The `>=` boundary: a wildcard-delete demo/**@t and a concrete Put
            // demo/a@t at the SAME ts. zenoh's `wd.ts >= incoming` includes the
            // tie, so the wildcard-delete wins. Pins the filter as `>=`, not `>`.
            let mut s = state();
            wdel(&mut s, "demo/**", 10, 1);
            wput(&mut s, "demo/a", vec![7], 10, 1);
            let stored = s
                .get(Some("demo/a"))
                .expect("R2352: an overridden put is stored empty, not tombstoned");
            assert!(
                stored.payload.is_empty(),
                "an equal-ts wildcard-delete overrides the concrete put (>= tie), \
                 so the put's own value must not survive"
            );
        }

        #[test]
        fn latest_of_two_matching_wildcard_puts_wins() {
            // Two DIFFERENT wildcards both matching demo/x: a single-`*` put@t10
            // and a `**` put@t20. A later concrete Put demo/x@t5 is upgraded to
            // the LATEST matching wildcard-put's value (t20). Exercises the
            // put-phase multi-candidate running-latest select (dead with a single
            // registry entry) AND a single-`*` wildcard (all other tests use `**`).
            let mut s = state();
            wput(&mut s, "demo/*", vec![0xAA], 10, 1);
            wput(&mut s, "demo/**", vec![0xBB], 20, 1);
            wput(&mut s, "demo/x", vec![0xCC], 5, 1);
            assert_eq!(
                s.get(Some("demo/x")).unwrap().payload,
                vec![0xBB],
                "the latest of two matching wildcard-puts wins"
            );
        }

        #[test]
        fn concrete_delete_is_shadow_checked_against_a_registered_wildcard_delete() {
            // A concrete DELETE (not a put) also runs the shadow-check (the
            // `Del => delete-phase-only` arm). wildcard-delete demo/**@t5 first,
            // then a concrete del demo/a@t3 (t3 < t5): the tombstone sits at the
            // OVERRIDE ts (t5), not the incoming t3 (AV3), so an @t4 put is still
            // rejected.
            let mut s = state();
            wdel(&mut s, "demo/**", 50, 1);
            wdel(&mut s, "demo/a", 30, 1);
            let r_mid = s
                .process_put(Some("demo/a"), vec![1], None, ts(40, 1))
                .unwrap();
            assert_eq!(
                r_mid,
                StorageInsertionResult::Outdated,
                "the concrete delete is tombstoned at the wildcard-delete override ts (t50)"
            );
        }

        #[test]
        fn re_issued_wildcard_put_upserts_the_registry() {
            // register_wildcard_update upserts by the full wildcard keyexpr
            // (BTreeMap insert = zenoh KeBoxTree.insert): re-issuing demo/**@t20
            // after demo/**@t10 REPLACES the entry. A concrete put demo/a@t5 is
            // then upgraded to the LATEST (t20) value — a keep-older-on-reinsert
            // mutation would surface 0x10 here.
            let mut s = state();
            wput(&mut s, "demo/**", vec![0x10], 10, 1);
            wput(&mut s, "demo/**", vec![0x20], 20, 1);
            wput(&mut s, "demo/a", vec![0xCC], 5, 1);
            assert_eq!(
                s.get(Some("demo/a")).unwrap().payload,
                vec![0x20],
                "the re-issued wildcard-put replaced the older registry entry"
            );
        }

        // R2352 — which KIND the backend op is dispatched on when a wildcard
        // override applies. The population is DERIVED twice over, because the
        // residual that opened this named one function and that is who noticed,
        // not what the class is:
        //
        //   * over the TYPE — every (incoming kind, override kind) pair the
        //     phase selection can reach, so the pair the two dispatches disagree
        //     on is counted rather than asserted; and
        //   * over the SOURCE — every call site of `apply_one_with_override`, so
        //     a fourth door added later fails here instead of quietly inheriting
        //     whichever answer this module happened to pin.
        //
        // Both derivations fail on an empty population.
        mod override_dispatch {
            use super::*;

            /// Every kind, from the type rather than a hand list: a new
            /// `SampleKind` variant makes this array stop compiling, which is
            /// the only way a matrix over it can stay honest.
            const KINDS: [SampleKind; 2] = [SampleKind::Put, SampleKind::Del];

            /// The phase selection in
            /// [`apply_one_with_override`](StorageState::apply_one_with_override),
            /// restated so the matrix below can ask which overrides each
            /// incoming kind can actually meet. A Delete never enters the put
            /// phase, so it can never be overridden by a Wildcard Put.
            fn reachable_overrides(incoming: SampleKind) -> Vec<SampleKind> {
                match incoming {
                    SampleKind::Put => vec![SampleKind::Del, SampleKind::Put],
                    SampleKind::Del => vec![SampleKind::Del],
                }
            }

            /// Drive one (incoming, override) pair through the LIVE concrete
            /// door and report whether the key is present afterwards. The
            /// override is registered first so the concrete sample at the older
            /// ts is the one that gets shadowed.
            fn drive(incoming: SampleKind, override_kind: SampleKind) -> Option<Vec<u8>> {
                let mut s = state();
                match override_kind {
                    SampleKind::Put => wput(&mut s, "demo/**", vec![0xAA], 20, 1),
                    SampleKind::Del => wdel(&mut s, "demo/**", 20, 1),
                }
                match incoming {
                    SampleKind::Put => wput(&mut s, "demo/a", vec![0xBB], 10, 1),
                    SampleKind::Del => {
                        s.apply_sample(
                            &Sample::new_del("demo/a").with_timestamp(ts(10, 1)),
                            || unreachable!(),
                        );
                    }
                }
                s.get(Some("demo/a")).map(|d| d.payload.clone())
            }

            #[test]
            fn exactly_one_reachable_pair_makes_the_two_dispatches_disagree() {
                // The pairs are enumerated, not listed: dispatching on the
                // incoming kind and dispatching on the override kind differ
                // exactly where the two kinds differ, so the divergent set is
                // `{(i, o) | i != o}` intersected with what is reachable.
                let pairs: Vec<(SampleKind, SampleKind)> = KINDS
                    .into_iter()
                    .flat_map(|i| reachable_overrides(i).into_iter().map(move |o| (i, o)))
                    .collect();
                assert!(
                    !pairs.is_empty(),
                    "the phase selection reaches no (incoming, override) pair at \
                     all — this matrix would then be measuring nothing"
                );
                let divergent: Vec<(SampleKind, SampleKind)> =
                    pairs.iter().copied().filter(|(i, o)| i != o).collect();
                assert_eq!(
                    divergent,
                    vec![(SampleKind::Put, SampleKind::Del)],
                    "an incoming Put under a Wildcard-Delete override is the ONLY \
                     place the choice of dispatch kind is observable; if this set \
                     grew, the parity argument below covers only part of it"
                );
                // ...and the whole matrix agrees with upstream: the write happens
                // (the incoming kind decides the op) and the value is the
                // override's (empty for a Delete override).
                for (i, o) in pairs {
                    match (i, o) {
                        (SampleKind::Put, SampleKind::Del) => assert_eq!(
                            drive(i, o),
                            Some(Vec::new()),
                            "present and empty: the divergent pair"
                        ),
                        (SampleKind::Put, SampleKind::Put) => assert_eq!(
                            drive(i, o),
                            Some(vec![0xAA]),
                            "the wildcard-put's value is stored"
                        ),
                        (SampleKind::Del, _) => assert_eq!(
                            drive(i, o),
                            None,
                            "an incoming Delete is a delete under either dispatch"
                        ),
                    }
                }
            }

            #[test]
            fn every_call_site_of_the_override_seam_is_driven_by_this_module() {
                // The needle is ASSEMBLED at compile time so this file's own
                // source does not contain the joined form and cannot self-match
                // (the same construction `reassembly_dispatch.rs` uses).
                let needle = concat!("self.apply_one_with", "_override(");
                let src = include_str!("storage_state.rs");
                let call_sites = src.matches(needle).count();
                assert!(
                    call_sites > 0,
                    "found no call site of the override seam; the derivation is \
                     broken, so nothing below is evidence"
                );
                assert_eq!(
                    call_sites, 3,
                    "the override seam has {call_sites} doors, and this module \
                     drives three of them: the live concrete write, the wildcard \
                     materialize loop and the align-receive concrete write. A new \
                     door needs its own divergent-pair test, because the three \
                     reach the seam with DIFFERENT incoming kinds."
                );
            }

            #[test]
            fn the_materialize_door_stores_an_empty_value_over_a_live_key() {
                // The door the residual did NOT name and no test reached with the
                // divergent pair: a Wildcard PUT materializing onto an ALREADY
                // STORED key, over which a Wildcard DELETE is registered. The
                // incoming kind is the wildcard-put's, so the delete phase runs
                // first and returns the wildcard-delete; upstream still dispatches
                // the received sample's Put. Distinct from the live-concrete tests
                // above, where the incoming sample is the concrete one.
                // The delete phase keeps a wildcard-delete whose ts is >= the
                // INCOMING ts, so the wildcard-put has to sit at or below the
                // registered delete. The live key is planted with the RAW gated
                // write, which bypasses the registries by design, because a
                // wildcard-delete's own materialize would otherwise have removed
                // it and the materialize loop only visits keys the backend holds.
                let mut s = state();
                wdel(&mut s, "demo/**", 50, 1);
                s.process_put(Some("demo/a"), vec![7], None, ts(30, 1))
                    .unwrap();
                wput(&mut s, "demo/**", vec![0xAA], 20, 1);
                let stored = s
                    .get(Some("demo/a"))
                    .expect("R2352: the materialize door stores, it does not tombstone");
                assert!(
                    stored.payload.is_empty(),
                    "the registered wildcard-delete empties the value the \
                     wildcard-put tried to materialize onto this key"
                );
                assert_eq!(
                    stored.timestamp,
                    ts(50, 1),
                    "at the wildcard-delete ts, not the wildcard-put's"
                );
                // The control direction, same door: a wildcard-put NEWER than
                // every registered wildcard-delete is not overridden at all, so
                // its own value materializes. Without this the assertion above
                // would also pass on a materialize loop that always emptied.
                let mut s2 = state();
                wdel(&mut s2, "demo/**", 20, 1);
                s2.process_put(Some("demo/b"), vec![7], None, ts(30, 1))
                    .unwrap();
                wput(&mut s2, "demo/**", vec![0xAA], 40, 1);
                assert_eq!(
                    s2.get(Some("demo/b")).map(|d| d.payload.clone()),
                    Some(vec![0xAA]),
                    "an unshadowed wildcard-put materializes its own value"
                );
            }

            #[test]
            fn the_query_surface_answers_an_empty_value_not_an_absent_key() {
                // The residual's own observable: "query = absent" (wz, before)
                // vs "query = empty value" (a real zenohd). The queryable reply
                // set is `matching_entries`, so that is where it is asserted —
                // `get` alone would pin the backend without pinning the reply.
                let mut s = state();
                wdel(&mut s, "demo/**", 50, 1);
                wput(&mut s, "demo/a", vec![9], 30, 1);
                let replies = s.matching_entries("demo/**");
                assert_eq!(
                    replies.len(),
                    1,
                    "a query over the overridden key replies once, not zero times"
                );
                assert_eq!(replies[0].0, "demo/a");
                assert!(
                    replies[0].1.payload.is_empty(),
                    "the reply carries an empty value"
                );
                assert!(
                    replies[0].1.encoding.is_none(),
                    "under the default encoding, which is what the sample upstream \
                     builds with `SampleBuilder::delete` carries"
                );
            }
        }

        // R311wt slice 4 — the garbage-collection sweep over the wildcard
        // registries. NTP64-scaled timestamps (high 32 bits = seconds) so a
        // realistic lifespan cutoff selects between entries.
        #[cfg(feature = "storage-mgr-garbage-collection")]
        mod gc {
            use super::*;
            use core::time::Duration;

            // A wildcard registered at exactly `secs` seconds (NTP64 word).
            fn tsecs(secs: u64, zid: u8) -> TimestampHint {
                TimestampHint {
                    time: secs << 32,
                    zid: vec![zid],
                }
            }
            // Register a wildcard-delete at `secs` (registers, backend empty).
            fn reg_wdel(s: &mut StorageState<MemoryStorage>, ke: &str, secs: u64) {
                s.apply_sample(
                    &Sample::new_del(ke).with_timestamp(tsecs(secs, 1)),
                    || unreachable!(),
                );
            }

            #[test]
            fn sweep_removes_old_registry_entries_and_retains_recent_ones() {
                let mut s = state();
                reg_wdel(&mut s, "old/**", 10); // ts = 10s
                reg_wdel(&mut s, "new/**", 80); // ts = 80s
                assert_eq!(s.wildcard_deletes.len(), 2);
                // now = 100s, lifespan = 50s -> time_limit = 50s. old(10) < 50 ->
                // collected; new(80) >= 50 -> retained.
                s.collect_garbage(100u64 << 32, Duration::from_secs(50));
                assert_eq!(s.wildcard_deletes.len(), 1);
                assert!(
                    s.wildcard_deletes.contains_key("new/**"),
                    "the recent wildcard-delete is retained"
                );
                assert!(
                    !s.wildcard_deletes.contains_key("old/**"),
                    "the stale wildcard-delete is collected"
                );
            }

            #[test]
            fn sweep_covers_the_wildcard_puts_registry_too() {
                let mut s = state();
                wput(&mut s, "old/**", vec![1], 10, 1);
                wput(&mut s, "new/**", vec![2], 80, 1);
                // wput uses ts(t) = time=t (tiny), so use a tiny cutoff scale here.
                assert_eq!(s.wildcard_puts.len(), 2);
                // now = 100, lifespan_ntp64 for 0s = 0 -> time_limit = 100; both
                // entries (t=10,80) < 100 -> both collected. Use a fractional
                // cutoff instead: compare on the raw .time. time_limit must sit
                // between 10 and 80, so pass now=80, lifespan=0 -> limit=80.
                s.collect_garbage(80, Duration::from_secs(0));
                assert_eq!(s.wildcard_puts.len(), 1);
                assert!(
                    s.wildcard_puts.contains_key("new/**"),
                    "recent put retained"
                );
                assert!(
                    !s.wildcard_puts.contains_key("old/**"),
                    "stale put collected"
                );
            }

            #[test]
            fn entry_exactly_at_the_limit_is_retained() {
                let mut s = state();
                reg_wdel(&mut s, "edge/**", 50); // ts = 50s
                                                 // now = 100s, lifespan = 50s -> time_limit = exactly 50s. zenoh
                                                 // removes `ts < time_limit`; `ts == limit` is RETAINED.
                s.collect_garbage(100u64 << 32, Duration::from_secs(50));
                assert_eq!(
                    s.wildcard_deletes.len(),
                    1,
                    "an entry exactly at the limit is retained (>= boundary)"
                );
            }

            #[test]
            fn unset_clock_now_below_lifespan_collects_nothing() {
                let mut s = state();
                reg_wdel(&mut s, "any/**", 10);
                // now (5s) < lifespan (86400s): saturating_sub -> time_limit = 0,
                // so nothing is collected (conservative; NOT zenoh's wrap-to-max
                // wipe). An unset-RTC boot must not empty the registries.
                s.collect_garbage(5u64 << 32, Duration::from_secs(86400));
                assert_eq!(
                    s.wildcard_deletes.len(),
                    1,
                    "an un-set clock collects nothing (saturating_sub to 0)"
                );
            }

            #[test]
            fn over_long_lifespan_collects_nothing_not_everything() {
                // A lifespan whose seconds exceed the NTP64 high-word range
                // (> 2^32-1 s) is unrepresentable. from_duration SATURATES to
                // u64::MAX (not the `secs << 32` wrap that would yield a SMALL
                // word and wipe the registry), so time_limit clamps to 0 and
                // NOTHING is collected. Guards the inverted-comment defect.
                let mut s = state();
                reg_wdel(&mut s, "any/**", 10);
                // 2^32 s would wrap `secs << 32` to 0 without the guard.
                s.collect_garbage(100u64 << 32, Duration::from_secs(1u64 << 32));
                assert_eq!(
                    s.wildcard_deletes.len(),
                    1,
                    "an over-long lifespan collects nothing (from_duration saturates)"
                );
            }

            // A wildcard-PUT registered at exactly `secs` seconds (NTP64 word),
            // the put-side twin of reg_wdel — so one NTP64-scale cutoff sweeps
            // both registries.
            fn reg_wput(s: &mut StorageState<MemoryStorage>, ke: &str, secs: u64) {
                s.apply_sample(
                    &Sample::new_put(ke, vec![0xAA]).with_timestamp(tsecs(secs, 1)),
                    || unreachable!(),
                );
            }

            #[test]
            fn one_cutoff_selectively_prunes_both_registries_at_once() {
                // Both registries non-empty in a SINGLE sweep: one shared cutoff
                // removes the stale entry from EACH and retains the recent one —
                // pins the (puts, deletes) tuple order of wildcard_registry_lens
                // in the kernel too (not just the driver's delete-only pin).
                let mut s = state();
                reg_wput(&mut s, "p_old/**", 10);
                reg_wput(&mut s, "p_new/**", 80);
                reg_wdel(&mut s, "d_old/**", 10);
                reg_wdel(&mut s, "d_new/**", 80);
                assert_eq!(s.wildcard_registry_lens(), (2, 2));
                // now=100s, lifespan=50s -> limit=50s. old(10)<50 collected from
                // BOTH registries; new(80)>=50 retained in BOTH — one call.
                s.collect_garbage(100u64 << 32, Duration::from_secs(50));
                assert_eq!(
                    s.wildcard_registry_lens(),
                    (1, 1),
                    "both registries pruned to their recent entry (puts, deletes) order"
                );
                assert!(s.wildcard_puts.contains_key("p_new/**"), "recent put kept");
                assert!(
                    !s.wildcard_puts.contains_key("p_old/**"),
                    "stale put collected"
                );
                assert!(
                    s.wildcard_deletes.contains_key("d_new/**"),
                    "recent delete kept"
                );
                assert!(
                    !s.wildcard_deletes.contains_key("d_old/**"),
                    "stale delete collected"
                );
            }

            #[test]
            fn gc_of_a_wildcard_delete_lets_a_later_concrete_be_stored() {
                // Behavioral end-to-end: a wildcard-delete demo/**@t10 registered,
                // then GC'd, then a concrete put demo/a@t5 that IS older than the
                // WD (t5 < t10) — so if the WD were still registered it WOULD
                // shadow (tombstone) the put. With the WD collected, the put is
                // stored instead. This is the DISCRIMINATING form (a t > t10 put
                // would survive regardless of GC and be vacuous): demo/a present
                // proves the registry actually shrank end to end, not just a
                // len() read.
                let mut s = state();
                reg_wdel(&mut s, "demo/**", 10);
                s.collect_garbage(100u64 << 32, Duration::from_secs(50)); // WD(10s) collected
                assert!(s.wildcard_deletes.is_empty());
                // A concrete put OLDER than the (now-collected) WD is applied
                // without being shadowed — the WD is gone from the registry.
                wput(&mut s, "demo/a", vec![7], 5, 1);
                assert_eq!(
                    s.get(Some("demo/a")).map(|d| d.payload.clone()),
                    Some(vec![7]),
                    "with the wildcard-delete GC'd, the concrete put is not shadowed"
                );
            }
        }

        // Strip-prefix composition (AV8): register + match in FULL keyexpr space,
        // write in the STORED key space.
        #[cfg(feature = "storage-mgr-strip-prefix")]
        mod strip {
            use super::*;

            fn stripped(prefix: &str) -> StorageState<MemoryStorage> {
                StorageState::with_strip_prefix(MemoryStorage::new(), Some(prefix.into()))
            }

            #[test]
            fn wildcard_delete_materializes_the_under_mount_and_mount_root_keys() {
                let mut s = stripped("home/kitchen");
                // Under-mount key (stored relative as "temp") + the exact mount
                // root (stored under the None slot).
                s.apply_sample(
                    &Sample::new_put("home/kitchen/temp", vec![21]).with_timestamp(ts(10, 1)),
                    || unreachable!(),
                );
                s.apply_sample(
                    &Sample::new_put("home/kitchen", vec![7]).with_timestamp(ts(10, 1)),
                    || unreachable!(),
                );
                // A full-keyexpr wildcard-delete matches BOTH via the restored
                // full key (home/kitchen/** ⊇ home/kitchen and home/kitchen/temp).
                s.apply_sample(
                    &Sample::new_del("home/kitchen/**").with_timestamp(ts(50, 1)),
                    || unreachable!(),
                );
                assert!(
                    s.get(Some("temp")).is_none(),
                    "the under-mount stored key is deleted by the full-keyexpr wildcard"
                );
                assert!(
                    s.backend().get(None).is_none(),
                    "the mount-root None key is deleted by the full-keyexpr wildcard"
                );
            }
        }
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
                s.process_put(Some("demo/a"), vec![3], None, ts(30, 1))
                    .unwrap(),
                StorageInsertionResult::Inserted
            );
            let r = s
                .process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
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
        fn all_mode_delete_hides_every_version_and_blocks_a_post_delete_older_put() {
            // R2350 at the SEAM, not just inside the backend: the gate above
            // an `All` storage is skipped (`latest_mode` false), so the
            // ordering guarantee is the backend tombstone's alone. This is
            // the sequence the foreign witness runs — put t=30, delete t=40,
            // replay an older put t=20 — asserted here in process terms.
            let mut s = all_state();
            s.process_put(Some("demo/a"), vec![3], None, ts(30, 1))
                .unwrap();
            assert_eq!(
                s.process_delete(Some("demo/a"), ts(40, 1)).unwrap(),
                StorageInsertionResult::Deleted
            );
            // Every version is hidden from the query surfaces.
            assert!(
                s.matching_versions("demo/a").is_empty(),
                "a deleted key is replied by no version"
            );
            assert!(s.matching_entries("demo/a").is_empty());
            assert!(s.get(Some("demo/a")).is_none());

            // The gate is still skipped — the replay is ACCEPTED, exactly as
            // `all_mode_skips_the_newer_wins_gate_and_retains_every_version`
            // asserts for the no-delete case. If this came back `Outdated`
            // the tombstone would be acting as a gate, which is a different
            // (and wrong) mechanism.
            let replayed = s
                .process_put(Some("demo/a"), vec![2], None, ts(20, 1))
                .unwrap();
            assert_ne!(
                replayed,
                StorageInsertionResult::Outdated,
                "History::All has no newer-wins gate; the older put is stored"
            );
            // ...and yet it does NOT come back on a query, because it is
            // stamped below the t=40 tombstone. Pre-R2350 the delete had
            // dropped the timeline, so this put was the key's live value and
            // a querier was served a value that had been deleted.
            assert!(
                s.matching_versions("demo/a").is_empty(),
                "the post-delete older put is stored as history, not served"
            );
            assert!(s.get(Some("demo/a")).is_none());
            assert_eq!(
                s.backend().history_len(Some("demo/a")),
                3,
                "put t=30, tomb t=40 and the replayed put t=20 are all retained"
            );
        }

        #[test]
        fn matching_versions_wildcard_returns_all_versions_per_matching_key() {
            let mut s = all_state();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_put(Some("demo/a"), vec![2], None, ts(20, 1))
                .unwrap();
            s.process_put(Some("demo/b"), vec![9], None, ts(15, 1))
                .unwrap();
            let mut hits = s.matching_versions("demo/*");
            hits.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(hits.len(), 2);
            assert_eq!(hits[0].0, "demo/a");
            assert_eq!(hits[0].1.len(), 2, "demo/a has two versions");
            assert_eq!(hits[1].0, "demo/b");
            assert_eq!(hits[1].1.len(), 1);
        }
    }

    // The strip + History::All intersection: a multi-version backend under a
    // configured strip_prefix. Needs both kernels.
    #[cfg(all(feature = "storage-mgr-strip-prefix", feature = "storage-history"))]
    mod strip_history {
        use super::*;
        use crate::sample::Sample;
        use crate::storage_history::HistoryStorage;

        #[test]
        fn matching_versions_under_strip_restores_the_full_key_for_every_version() {
            // A strip-configured History::All storage: two versions captured
            // under the mount are stored RELATIVE to it, and matching_versions
            // restores the full keyexpr while still returning BOTH versions
            // (the strip restore and the version retention compose).
            let mut s =
                StorageState::with_strip_prefix(HistoryStorage::new(), Some("home/kitchen".into()));
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![1]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![2]).with_timestamp(ts(20, 1)),
                || unreachable!(),
            );
            // Stored under the RELATIVE key with both versions retained.
            assert_eq!(
                s.backend().version_count(Some("temp")),
                2,
                "both versions kept under the stripped key"
            );

            let hits = s.matching_versions("home/kitchen/*");
            assert_eq!(hits.len(), 1, "one matching key");
            assert_eq!(
                hits[0].0, "home/kitchen/temp",
                "the reply key restores the mount prefix"
            );
            assert_eq!(hits[0].1.len(), 2, "both versions returned under strip");
            assert_eq!(hits[0].1[0].payload, vec![1]);
            assert_eq!(hits[0].1[1].payload, vec![2]);
        }
    }

    // The replication digest needs the storage-replication kernel.
    #[cfg(feature = "storage-replication")]
    mod replication {
        use super::*;
        use crate::storage_replication::{build_digest, IntervalIdx, ReplicationConfig};

        fn state() -> StorageState<MemoryStorage> {
            StorageState::new(MemoryStorage::new())
        }

        #[test]
        fn replication_digest_covers_all_stored_keys() {
            let cfg = ReplicationConfig::defaults("demo/**");
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_put(Some("demo/b"), vec![2], None, ts(15, 2))
                .unwrap();

            let a = ts(10, 1);
            let b = ts(15, 2);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(
                    &cfg,
                    [(Some("demo/a"), &a), (Some("demo/b"), &b)],
                    hot_upper
                )
            );
        }

        #[test]
        fn replication_digest_includes_tombstones() {
            let cfg = ReplicationConfig::defaults("demo/**");
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_delete(Some("demo/a"), ts(20, 1)).unwrap(); // tombstone at ts 20

            // The backend dropped the deleted key, but the digest must still
            // cover it (at the delete timestamp) so the delete propagates to a
            // replica that still holds the key.
            assert!(
                s.backend().get_all_entries().is_empty(),
                "backend drops the deleted key"
            );
            let tombstone = ts(20, 1);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [(Some("demo/a"), &tombstone)], hot_upper)
            );
            // ...and it is NOT the empty digest a get_all_entries build gives.
            assert_ne!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [], hot_upper)
            );
        }

        #[test]
        fn replication_digest_reflects_newer_wins() {
            let cfg = ReplicationConfig::defaults("demo/**");
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, ts(20, 1))
                .unwrap();
            // Older put is rejected (Outdated) -> latest stays at ts 20.
            s.process_put(Some("demo/a"), vec![2], None, ts(10, 1))
                .unwrap();

            let newer = ts(20, 1);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [(Some("demo/a"), &newer)], hot_upper)
            );
        }

        // -- The maintained log, at the storage seam (R2354) -------------
        //
        // The unit differentials for the log itself live beside it in
        // `storage_replication`. What is checked HERE is the wiring: that
        // every path which changes a digest source tells the log, and that
        // the published digest is read off it rather than rebuilt.
        //
        // The population is not a list written here. `replication_digest`
        // debug-asserts maintained == recomputed on EVERY call, so every test
        // in this tree that takes a digest is a witness for the wiring; these
        // cases add the transitions no other test drives.

        /// An NTP64 `time` at `secs` seconds, so events can be placed in
        /// distinct buckets (the `ts` helper above uses raw sub-millisecond
        /// words, which all classify into interval 0).
        fn at_secs(secs: u64, zid: u8) -> TimestampHint {
            ts(secs << 32, zid)
        }

        /// A configuration whose buckets are 10s intervals of 2s
        /// sub-intervals — coarse enough to name, fine enough that the
        /// timestamps below fall in different ones.
        fn era_cfg() -> ReplicationConfig {
            ReplicationConfig::new("demo/**", None, 10_000, 5, 2, 3, 250)
        }

        /// THE claim this atom closes: a replica that publishes N digests
        /// walks its stored set ONCE, not N times. The digests are still
        /// checked against the recompute — being cheap is worthless if it is
        /// also wrong — but the load-bearing assertion is the seed count,
        /// because a digest that silently fell back to recomputing would be
        /// correct and therefore invisible to any comparison of digests.
        #[test]
        fn a_publishing_replica_seeds_once_and_maintains_thereafter() {
            let cfg = era_cfg();
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, at_secs(92, 1))
                .unwrap();

            assert_eq!(s.replication_log_seeds(), 0, "inert until first asked");
            for (n, secs) in [93u64, 95, 97, 99].into_iter().enumerate() {
                let digest = s.replication_digest(&cfg, hot_upper);
                assert_eq!(
                    digest,
                    s.recomputed_replication_digest(&cfg, hot_upper),
                    "cycle {n}"
                );
                assert_eq!(s.replication_log_seeds(), 1, "cycle {n} re-seeded");
                s.process_put(Some("demo/a"), vec![2], None, at_secs(secs, 1))
                    .unwrap();
            }
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                s.recomputed_replication_digest(&cfg, hot_upper)
            );
            assert_eq!(s.replication_log_seeds(), 1);
        }

        /// A delete is an event MOVE, not an addition: the tombstone replaces
        /// the put in the event set, and it lands in whatever bucket its own
        /// timestamp names. The two timestamps here are in different
        /// intervals, so a log that only added would carry both.
        #[test]
        fn a_tombstone_moves_the_key_out_of_its_put_bucket() {
            let cfg = era_cfg();
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, at_secs(92, 1))
                .unwrap();
            let _ = s.replication_digest(&cfg, hot_upper); // seed
            s.process_delete(Some("demo/a"), at_secs(101, 1)).unwrap();

            let tombstone = at_secs(101, 1);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [(Some("demo/a"), &tombstone)], hot_upper),
                "the put's bucket must be empty and the tombstone's occupied"
            );
            assert_eq!(s.replication_log_seeds(), 1);
        }

        /// A digest asked for under a PEER's configuration re-cuts the
        /// buckets, and asking again under the local one re-cuts them back.
        /// Both answers are right; what must not happen is one configuration's
        /// buckets answering under the other's fingerprint.
        #[test]
        fn a_peer_configuration_rebinds_and_the_local_one_rebinds_back() {
            let local = era_cfg();
            let peer = ReplicationConfig::new("demo/**", None, 1_000, 5, 2, 3, 250);
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put(Some("demo/a"), vec![1], None, at_secs(92, 1))
                .unwrap();

            let under_local = s.replication_digest(&local, hot_upper);
            let under_peer = s.replication_digest(&peer, IntervalIdx::from(100));
            assert_eq!(s.replication_log_seeds(), 2, "the peer config re-seeds");
            assert_eq!(
                under_peer,
                s.recomputed_replication_digest(&peer, IntervalIdx::from(100))
            );
            assert_eq!(
                s.replication_digest(&local, hot_upper),
                under_local,
                "the local configuration's digest is unchanged by the detour"
            );
            assert_eq!(s.replication_log_seeds(), 3);
        }

        // The wildcard registries are the digest's SECOND event source
        // (R2351, AV5), so they are the second thing the maintained log has
        // to hear from — and the garbage collector is the only path in this
        // storage that REMOVES an event outright.
        #[cfg(feature = "storage-mgr-wildcard-updates")]
        mod wildcard_events {
            use super::*;
            use crate::sample::Sample;

            fn wput(s: &mut StorageState<MemoryStorage>, ke: &str, t: TimestampHint) {
                s.apply_sample(
                    &Sample::new_put(ke, vec![9]).with_timestamp(t),
                    || unreachable!(),
                );
            }

            /// Re-issuing a wildcard update at a newer timestamp moves its
            /// event to another bucket, exactly as an overwritten key does.
            /// The registry is an upsert, so nothing else signals that the
            /// old registration left.
            #[test]
            fn a_re_registered_wildcard_update_leaves_its_old_bucket() {
                let cfg = era_cfg();
                let hot_upper = IntervalIdx::from(10);
                let mut s = state();
                wput(&mut s, "demo/**", at_secs(92, 1));
                let _ = s.replication_digest(&cfg, hot_upper); // seed
                wput(&mut s, "demo/**", at_secs(98, 1));

                let newer = at_secs(98, 1);
                assert_eq!(
                    s.replication_digest(&cfg, hot_upper),
                    build_digest(&cfg, [(Some("demo/**"), &newer)], hot_upper),
                    "only the current registration is a replication event"
                );
                assert_eq!(s.replication_log_seeds(), 1);
            }

            /// The garbage collector drops registrations, and a dropped
            /// registration is a dropped replication event. This is the one
            /// path that removes rather than replaces, and nothing else in
            /// the tree drives it with a digest in play: a sweep that did not
            /// tell the log would leave this replica advertising a
            /// fingerprint for wildcard updates it no longer holds — a
            /// divergence manufactured by the collector, which no peer could
            /// ever resolve.
            #[cfg(feature = "storage-mgr-garbage-collection")]
            #[test]
            fn a_collected_wildcard_update_leaves_the_digest() {
                let cfg = era_cfg();
                let hot_upper = IntervalIdx::from(10);
                let mut s = state();
                wput(&mut s, "old/**", at_secs(35, 1));
                wput(&mut s, "new/**", at_secs(92, 1));
                let before = s.replication_digest(&cfg, hot_upper); // seed
                assert_eq!(s.wildcard_registry_lens(), (2, 0));

                // Collect everything older than 30s at "now" = 95s: the old
                // registration goes, the new one stays.
                s.collect_garbage(at_secs(95, 1).time, core::time::Duration::from_secs(30));
                assert_eq!(s.wildcard_registry_lens(), (1, 0), "one was collected");

                let kept = at_secs(92, 1);
                let after = s.replication_digest(&cfg, hot_upper);
                assert_ne!(before, after, "the collected event left the digest");
                assert_eq!(
                    after,
                    build_digest(&cfg, [(Some("new/**"), &kept)], hot_upper)
                );
                assert_eq!(s.replication_log_seeds(), 1);
            }
        }
    }

    // The aligner event snapshot needs the storage-aligner kernel.
    #[cfg(feature = "storage-aligner")]
    mod aligner {
        use super::*;
        use crate::storage_aligner::Action;

        #[test]
        fn replication_events_distinguishes_put_from_delete_tombstone() {
            let mut s = StorageState::new(MemoryStorage::new());
            s.process_put(Some("demo/a"), vec![1], None, ts(10, 1))
                .unwrap();
            s.process_put(Some("demo/b"), vec![2], None, ts(11, 1))
                .unwrap();
            s.process_delete(Some("demo/b"), ts(20, 1)).unwrap(); // tombstone

            let events = s.replication_events();
            // One entry per key in `latest`, including the tombstone.
            assert_eq!(events.len(), 2);

            let a = events.iter().find(|e| e.key() == Some("demo/a")).unwrap();
            assert_eq!(*a.action(), Action::Put, "a live key is a Put event");
            assert_eq!(a.timestamp(), &ts(10, 1));

            let b = events.iter().find(|e| e.key() == Some("demo/b")).unwrap();
            assert_eq!(
                *b.action(),
                Action::Delete,
                "a deleted key (gone from the backend) is a Delete tombstone event"
            );
            assert_eq!(
                b.timestamp(),
                &ts(20, 1),
                "the tombstone carries the delete ts"
            );
        }

        // R311y64 — the strip + replication mount-root edge is CLOSED: a
        // strip-configured storage's exact-prefix value (stored under the
        // backend `None` key) is now carried through the replication snapshot
        // as a first-class `None`-keyed event, NO LONGER skipped (the former
        // documented edge). Needs the strip feature on top of the aligner.
        #[cfg(feature = "storage-mgr-strip-prefix")]
        #[test]
        fn replication_carries_the_mount_root_none_keyed_event() {
            use crate::sample::Sample;
            use crate::storage_replication::{IntervalIdx, ReplicationConfig};

            let mut s =
                StorageState::with_strip_prefix(MemoryStorage::new(), Some("home/kitchen".into()));
            // The mount-root value (stored under the backend `None` key) ...
            s.apply_sample(
                &Sample::new_put("home/kitchen", vec![7]).with_timestamp(ts(10, 1)),
                || unreachable!(),
            );
            // ... and an under-mount value (stored under the stripped "temp").
            s.apply_sample(
                &Sample::new_put("home/kitchen/temp", vec![21]).with_timestamp(ts(11, 1)),
                || unreachable!(),
            );

            let events = s.replication_events();
            assert_eq!(events.len(), 2, "BOTH events are carried, none skipped");
            // The mount-root event has a `None` key (no longer dropped).
            let root = events
                .iter()
                .find(|e| e.key().is_none())
                .expect("the mount-root None-keyed event is present");
            assert_eq!(*root.action(), Action::Put);
            assert_eq!(root.timestamp(), &ts(10, 1));
            // The under-mount event carries the stripped "temp" key.
            let temp = events
                .iter()
                .find(|e| e.key() == Some("temp"))
                .expect("the under-mount event is present");
            assert_eq!(*temp.action(), Action::Put);

            // The digest covers the None-keyed event's fingerprint too: a digest
            // built from BOTH keys equals the snapshot's, and dropping the None
            // key changes it -> the mount-root event is genuinely in the digest.
            let cfg = ReplicationConfig::defaults("home/kitchen/**");
            let hot_upper = IntervalIdx::from(10);
            let root_ts = ts(10, 1);
            let temp_ts = ts(11, 1);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(
                    &cfg,
                    [(None, &root_ts), (Some("temp"), &temp_ts)],
                    hot_upper
                ),
                "the digest carries the None-keyed mount-root fingerprint"
            );
            assert_ne!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [(Some("temp"), &temp_ts)], hot_upper),
                "omitting the None-keyed event changes the digest -> it is included"
            );
        }

        // ---- answer engine (answer_alignment_query) ----
        use crate::storage_aligner::{AlignmentQuery, AlignmentReply, EventMetadata};
        use crate::storage_replication::{
            DigestDiff, IntervalIdx, ReplicationConfig, SubIntervalIdx,
        };
        use alloc::collections::BTreeSet;

        // interval_ms=1000, sub_intervals=2 (sub_width 500ms), hot=2, warm=2:
        // for hot_upper=10, warm_lower=7, hot_lower=9.
        fn cfg() -> ReplicationConfig {
            ReplicationConfig::new("demo/**", None, 1000, 2, 2, 2, 250)
        }
        // An event at exactly (interval, sub): sub 0 = on the second, sub 1 =
        // +500ms (frac 2^31).
        fn at(interval: u64, sub: u64) -> TimestampHint {
            let frac = if sub == 0 { 0 } else { 1u64 << 31 };
            TimestampHint {
                time: (interval << 32) | frac,
                zid: vec![0x01],
            }
        }
        fn st_with(puts: &[(&str, TimestampHint)]) -> StorageState<MemoryStorage> {
            let mut s = StorageState::new(MemoryStorage::new());
            for (k, t) in puts {
                s.process_put(Some(k), vec![0xAB], None, t.clone()).unwrap();
            }
            s
        }
        const NOW10: u64 = 10u64 << 32; // classifies to interval 10 (hot_upper)

        #[test]
        fn answer_discovery_returns_local_zid() {
            let s = StorageState::new(MemoryStorage::new());
            let r = s.answer_alignment_query(&cfg(), &AlignmentQuery::Discovery, &[0x07, 0x08], 0);
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].reply, AlignmentReply::Discovery(vec![0x07, 0x08]));
            assert!(r[0].value.is_none());
        }

        #[test]
        fn answer_all_retrieves_puts_with_value_and_deletes_without() {
            let mut s = st_with(&[("demo/a", at(9, 0))]);
            s.process_delete(Some("demo/b"), at(9, 1)).unwrap(); // a tombstone
            let r = s.answer_alignment_query(&cfg(), &AlignmentQuery::All, &[0x01], NOW10);
            assert_eq!(r.len(), 2);
            let put = r
                .iter()
                .find(|x| matches!(&x.reply, AlignmentReply::Retrieval(m) if m.key() == Some("demo/a")))
                .unwrap();
            assert!(put.value.is_some(), "a Put retrieval carries the payload");
            let del = r
                .iter()
                .find(|x| matches!(&x.reply, AlignmentReply::Retrieval(m) if m.key() == Some("demo/b")))
                .unwrap();
            assert!(del.value.is_none(), "a Delete retrieval carries no payload");
        }

        #[test]
        fn answer_events_retrieves_matching_put_and_skips_stale() {
            let s = st_with(&[("demo/a", at(9, 0))]);
            // Matching timestamp -> retrieved with its value.
            let ok = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Events(vec![EventMetadata::put(Some("demo/a".into()), at(9, 0))]),
                &[0x01],
                NOW10,
            );
            assert_eq!(ok.len(), 1);
            assert!(ok[0].value.is_some());
            // A stale timestamp (the stored value moved on) -> skipped entirely.
            let stale = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Events(vec![EventMetadata::put(Some("demo/a".into()), at(8, 0))]),
                &[0x01],
                NOW10,
            );
            assert!(
                stale.is_empty(),
                "a changed/gone Put is skipped, not replied empty"
            );
            // A delete event -> a value-less Retrieval.
            let del = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Events(vec![EventMetadata::delete(
                    Some("demo/a".into()),
                    at(9, 0),
                )]),
                &[0x01],
                NOW10,
            );
            assert_eq!(del.len(), 1);
            assert!(del[0].value.is_none());
        }

        #[test]
        fn answer_diff_dispatches_one_response_per_differing_era() {
            let s = st_with(&[("demo/h", at(9, 0))]); // a hot-era event (interval 9)

            let hot_diff = DigestDiff {
                cold_eras_differ: false,
                warm_eras_differences: BTreeSet::new(),
                hot_eras_differences: [(
                    IntervalIdx::from(9),
                    [SubIntervalIdx::from(0)].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            };
            let r =
                s.answer_alignment_query(&cfg(), &AlignmentQuery::Diff(hot_diff), &[0x01], NOW10);
            assert_eq!(r.len(), 1);
            assert!(matches!(&r[0].reply, AlignmentReply::EventsMetadata(evs)
                    if evs.len() == 1 && evs[0].key() == Some("demo/h")));

            let cold_diff = DigestDiff {
                cold_eras_differ: true,
                warm_eras_differences: BTreeSet::new(),
                hot_eras_differences: BTreeMap::new(),
            };
            let r =
                s.answer_alignment_query(&cfg(), &AlignmentQuery::Diff(cold_diff), &[0x01], NOW10);
            assert_eq!(r.len(), 1);
            assert!(matches!(r[0].reply, AlignmentReply::Intervals(_)));

            let warm_diff = DigestDiff {
                cold_eras_differ: false,
                warm_eras_differences: [IntervalIdx::from(7)].into_iter().collect(),
                hot_eras_differences: BTreeMap::new(),
            };
            let r =
                s.answer_alignment_query(&cfg(), &AlignmentQuery::Diff(warm_diff), &[0x01], NOW10);
            assert_eq!(r.len(), 1);
            assert!(matches!(r[0].reply, AlignmentReply::SubIntervals(_)));

            let all_diff = DigestDiff {
                cold_eras_differ: true,
                warm_eras_differences: [IntervalIdx::from(7)].into_iter().collect(),
                hot_eras_differences: [(
                    IntervalIdx::from(9),
                    [SubIntervalIdx::from(0)].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            };
            let r =
                s.answer_alignment_query(&cfg(), &AlignmentQuery::Diff(all_diff), &[0x01], NOW10);
            assert_eq!(r.len(), 3, "cold + warm + hot -> three responses");
        }

        #[test]
        fn answer_intervals_subintervals_dispatch_and_empty_is_silent() {
            let s = st_with(&[("demo/h", at(9, 0))]);

            let r = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Intervals([IntervalIdx::from(9)].into_iter().collect()),
                &[0x01],
                NOW10,
            );
            assert_eq!(r.len(), 1);
            assert!(matches!(r[0].reply, AlignmentReply::SubIntervals(_)));

            let r = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Intervals(BTreeSet::new()),
                &[0x01],
                NOW10,
            );
            assert!(
                r.is_empty(),
                "an empty Intervals query produces no response"
            );

            let mut map: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> = BTreeMap::new();
            map.insert(
                IntervalIdx::from(9),
                [SubIntervalIdx::from(0)].into_iter().collect(),
            );
            let r = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::SubIntervals(map),
                &[0x01],
                NOW10,
            );
            assert_eq!(r.len(), 1);
            assert!(matches!(&r[0].reply, AlignmentReply::EventsMetadata(evs)
                    if evs.iter().any(|e| e.key() == Some("demo/h"))));

            let r = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::SubIntervals(BTreeMap::new()),
                &[0x01],
                NOW10,
            );
            assert!(
                r.is_empty(),
                "an empty SubIntervals query produces no response"
            );
        }

        // ---- pull / convergence engine (process_alignment_reply) ----
        use crate::storage_aligner::{AlignmentFollowup, EventBuckets};
        use crate::storage_replication::Fingerprint;

        #[test]
        fn process_discovery_returns_the_discovered_replica() {
            let mut s = StorageState::new(MemoryStorage::new());
            let f = s.process_alignment_reply(&cfg(), AlignmentReply::Discovery(vec![0x09]), None);
            assert_eq!(f, AlignmentFollowup::DiscoveredReplica(vec![0x09]));
        }

        #[test]
        fn process_intervals_asks_for_a_differing_interval() {
            // Local is empty; the peer reports a cold interval -> local lacks
            // it -> ask for its sub-intervals.
            let mut s = StorageState::new(MemoryStorage::new());
            let mut peer_cold: BTreeMap<IntervalIdx, Fingerprint> = BTreeMap::new();
            peer_cold.insert(IntervalIdx::from(1), Fingerprint::from(0xABCD));
            match s.process_alignment_reply(&cfg(), AlignmentReply::Intervals(peer_cold), None) {
                AlignmentFollowup::Query(AlignmentQuery::Intervals(set)) => {
                    assert!(set.contains(&IntervalIdx::from(1)));
                }
                other => panic!("expected an Intervals follow-up, got {other:?}"),
            }
        }

        #[test]
        fn process_intervals_aligned_is_done() {
            // Feed back our own per-interval fingerprints as the peer's reply
            // -> every interval matches -> nothing to ask. (cold_era_fingerprints
            // gives the same per-interval value the era-independent comparison
            // uses, for a cold interval.)
            let s = st_with(&[("demo/c", at(1, 0))]); // a cold-era key
            let local = EventBuckets::from_events(s.replication_events(), &cfg())
                .cold_era_fingerprints(&cfg(), cfg().classify(NOW10).0);
            assert!(!local.is_empty(), "the snapshot has a cold interval");
            let mut s = s;
            assert_eq!(
                s.process_alignment_reply(&cfg(), AlignmentReply::Intervals(local), None),
                AlignmentFollowup::Done
            );
        }

        #[test]
        fn process_events_metadata_applies_delete_and_collects_missing_put() {
            let mut s = StorageState::new(MemoryStorage::new());
            let reply = AlignmentReply::EventsMetadata(vec![
                EventMetadata::put(Some("demo/p".into()), at(10, 0)),
                EventMetadata::delete(Some("demo/d".into()), at(10, 1)),
            ]);
            match s.process_alignment_reply(&cfg(), reply, None) {
                AlignmentFollowup::Query(AlignmentQuery::Events(puts)) => {
                    assert_eq!(puts.len(), 1, "only the Put needs a payload fetch");
                    assert_eq!(puts[0].key(), Some("demo/p"));
                }
                other => panic!("expected an Events follow-up, got {other:?}"),
            }
            // The Delete applied as a tombstone: an older Put can't resurrect it.
            assert_eq!(
                s.process_put(Some("demo/d"), vec![1], None, at(9, 0))
                    .unwrap(),
                StorageInsertionResult::Outdated
            );
        }

        #[test]
        fn process_retrieval_applies_a_put_then_skips_when_already_held() {
            let mut s = StorageState::new(MemoryStorage::new());
            let put = EventMetadata::put(Some("demo/x".into()), at(10, 0));
            assert_eq!(
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(put.clone()),
                    Some(RetrievedValue {
                        payload: vec![0xAB],
                        encoding: None
                    }),
                ),
                AlignmentFollowup::Done
            );
            assert_eq!(
                s.get(Some("demo/x")).map(|d| d.payload.clone()),
                Some(vec![0xAB])
            );
            // Re-processing the same (already held) event does not re-apply.
            s.process_alignment_reply(
                &cfg(),
                AlignmentReply::Retrieval(put),
                Some(RetrievedValue {
                    payload: vec![0xFF],
                    encoding: None,
                }),
            );
            assert_eq!(
                s.get(Some("demo/x")).unwrap().payload,
                vec![0xAB],
                "an already-held event is not overwritten"
            );
        }

        // Drive a full alignment exchange between two in-memory replicas: the
        // local replica detects divergence (digest diff), then loops
        // query -> peer.answer -> local.process until every branch is Done.
        fn drive_alignment(
            local: &mut StorageState<MemoryStorage>,
            // `&mut` since R2354: a digest SEEDS the replication log on its
            // first call under a configuration, so even the peer's read-only
            // role in this exchange needs the mutable handle.
            peer: &mut StorageState<MemoryStorage>,
            config: &ReplicationConfig,
            now: u64,
        ) {
            let hu = config.classify(now).0;
            let diff = match local
                .replication_digest(config, hu)
                .diff(peer.replication_digest(config, hu))
            {
                Some(d) => d,
                None => return, // already aligned
            };
            let mut pending = vec![AlignmentQuery::Diff(diff)];
            let mut guard = 0;
            while let Some(query) = pending.pop() {
                guard += 1;
                assert!(guard < 100, "alignment must converge");
                for resp in peer.answer_alignment_query(config, &query, &[0xFF], now) {
                    match local.process_alignment_reply(config, resp.reply, resp.value) {
                        AlignmentFollowup::Query(q) => pending.push(q),
                        AlignmentFollowup::Done | AlignmentFollowup::DiscoveredReplica(_) => {}
                    }
                }
            }
        }

        #[test]
        fn two_replicas_converge_via_the_aligner() {
            let config = cfg();
            // hot_upper = 11: cold < 8, warm {8,9}, hot {10,11}.
            let now = 11u64 << 32;
            let mut peer = StorageState::new(MemoryStorage::new());
            peer.process_put(Some("demo/cold"), vec![1], None, at(2, 0))
                .unwrap();
            peer.process_put(Some("demo/warm"), vec![2], None, at(8, 1))
                .unwrap();
            peer.process_put(Some("demo/hot"), vec![3], None, at(10, 0))
                .unwrap();
            peer.process_delete(Some("demo/gone"), at(10, 1)).unwrap(); // hot tombstone
            let mut local = StorageState::new(MemoryStorage::new());
            local
                .process_put(Some("demo/cold"), vec![1], None, at(2, 0))
                .unwrap(); // shared cold

            drive_alignment(&mut local, &mut peer, &config, now);

            // Local pulled every entry it was missing, across all three eras.
            assert_eq!(
                local.get(Some("demo/warm")).map(|d| d.payload.clone()),
                Some(vec![2])
            );
            assert_eq!(
                local.get(Some("demo/hot")).map(|d| d.payload.clone()),
                Some(vec![3])
            );
            assert!(
                local.get(Some("demo/gone")).is_none(),
                "the tombstone removed the key locally"
            );
            // Local was a subset of the peer, so the digests now match exactly.
            let hu = config.classify(now).0;
            assert_eq!(
                local.replication_digest(&config, hu),
                peer.replication_digest(&config, hu),
                "the two replicas converged"
            );
        }

        #[test]
        fn two_replicas_converge_bidirectionally() {
            // Each replica holds entries the other lacks (across eras), so a
            // single one-directional pull is NOT enough — both sides must run
            // the aligner. After both pulls, each holds the union.
            let config = cfg();
            let now = 11u64 << 32;
            let mut a = StorageState::new(MemoryStorage::new());
            a.process_put(Some("k/shared"), vec![0], None, at(2, 0))
                .unwrap();
            a.process_put(Some("k/only_a_warm"), vec![0xA1], None, at(8, 0))
                .unwrap();
            a.process_put(Some("k/only_a_hot"), vec![0xA2], None, at(10, 0))
                .unwrap();
            let mut b = StorageState::new(MemoryStorage::new());
            b.process_put(Some("k/shared"), vec![0], None, at(2, 0))
                .unwrap();
            b.process_put(Some("k/only_b_warm"), vec![0xB1], None, at(9, 0))
                .unwrap();
            b.process_put(Some("k/only_b_hot"), vec![0xB2], None, at(11, 0))
                .unwrap();

            // a pulls from b, then b pulls from a (now the union).
            drive_alignment(&mut a, &mut b, &config, now);
            drive_alignment(&mut b, &mut a, &config, now);

            for (key, val) in [
                ("k/only_a_warm", vec![0xA1]),
                ("k/only_a_hot", vec![0xA2]),
                ("k/only_b_warm", vec![0xB1]),
                ("k/only_b_hot", vec![0xB2]),
            ] {
                assert_eq!(
                    a.get(Some(key)).map(|d| d.payload.clone()),
                    Some(val.clone())
                );
                assert_eq!(b.get(Some(key)).map(|d| d.payload.clone()), Some(val));
            }
            let hu = config.classify(now).0;
            assert_eq!(
                a.replication_digest(&config, hu),
                b.replication_digest(&config, hu),
                "both replicas converged to the union"
            );
        }

        #[test]
        fn convergence_resolves_an_equal_timestamp_conflict_by_zid() {
            // Same key + same NTP64 time but different zid on each replica:
            // newer-wins breaks the tie by the uhlc zid order, so the
            // higher-zid value wins on both sides.
            let config = cfg();
            let now = 11u64 << 32;
            let t = at(10, 0).time;
            let lo = TimestampHint {
                time: t,
                zid: vec![0x01],
            };
            let hi = TimestampHint {
                time: t,
                zid: vec![0x02],
            };
            let mut local = StorageState::new(MemoryStorage::new());
            local
                .process_put(Some("k/x"), vec![0xAA], None, lo)
                .unwrap();
            let mut peer = StorageState::new(MemoryStorage::new());
            peer.process_put(Some("k/x"), vec![0xBB], None, hi.clone())
                .unwrap();

            // The peer holds the higher-zid version -> local must adopt it.
            drive_alignment(&mut local, &mut peer, &config, now);
            assert_eq!(
                local.get(Some("k/x")).map(|d| d.payload.clone()),
                Some(vec![0xBB]),
                "the higher-zid value wins the equal-time conflict"
            );
            assert_eq!(
                local.get(Some("k/x")).map(|d| d.timestamp.clone()),
                Some(hi)
            );
        }

        // R311wt slice 3 — applying wildcard-updates received via alignment.
        // Gated on the storage-aligner (parent mod) ∩ storage-mgr-wildcard-updates
        // intersection: these need the override engine to apply into.
        #[cfg(feature = "storage-mgr-wildcard-updates")]
        mod wildcard_align {
            use super::*;
            use crate::storage_aligner::{
                AlignmentFollowup, AlignmentQuery, AlignmentReply, EventMetadata, RetrievedValue,
            };

            // A WildcardDelete / WildcardPut EventMetadata: the wildcard ke rides
            // the Action (the FULL keyexpr wz materializes on); the stripped key
            // mirrors zenoh's stored_key (ignored by wz's materialize).
            fn wdel_meta(ke: &str, t: u64, sub: u64) -> EventMetadata {
                EventMetadata::wildcard(
                    Some(ke.into()),
                    at(t, sub),
                    Action::WildcardDelete(ke.into()),
                )
            }
            fn wput_meta(ke: &str, t: u64, sub: u64) -> EventMetadata {
                EventMetadata::wildcard(Some(ke.into()), at(t, sub), Action::WildcardPut(ke.into()))
            }

            #[test]
            fn events_metadata_wildcard_delete_deletes_matching_local_keys() {
                // (a) A WildcardDelete received in the metadata round materializes
                // onto wz-local matching keys OLDER than it (keys the sender need
                // not have — this closes the common-case offline-replica residual);
                // a NEWER local key survives.
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_put(Some("demo/b"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_put(Some("demo/c"), vec![1], None, at(50, 0))
                    .unwrap();
                let reply = AlignmentReply::EventsMetadata(vec![wdel_meta("demo/**", 10, 0)]);
                let f = s.process_alignment_reply(&cfg(), reply, None);
                assert_eq!(
                    f,
                    AlignmentFollowup::Done,
                    "a WildcardDelete needs no payload fetch"
                );
                assert!(
                    s.get(Some("demo/a")).is_none(),
                    "older matching key deleted"
                );
                assert!(
                    s.get(Some("demo/b")).is_none(),
                    "older matching key deleted"
                );
                assert_eq!(
                    s.get(Some("demo/c")).unwrap().payload,
                    vec![1],
                    "a key newer than the wildcard-delete survives"
                );
            }

            #[test]
            fn events_metadata_wildcard_put_is_deferred_then_retrieval_materializes() {
                // (b) A WildcardPut is collected for a payload fetch in the metadata
                // round, then the Retrieval round materializes it onto a matching key.
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                let meta = wput_meta("demo/**", 20, 0);
                match s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::EventsMetadata(vec![meta.clone()]),
                    None,
                ) {
                    AlignmentFollowup::Query(AlignmentQuery::Events(evs)) => {
                        assert_eq!(
                            evs.len(),
                            1,
                            "the WildcardPut is collected for a payload fetch"
                        );
                    }
                    other => panic!("expected an Events follow-up, got {other:?}"),
                }
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(meta),
                    Some(RetrievedValue {
                        payload: vec![0x42],
                        encoding: None,
                    }),
                );
                assert_eq!(
                    s.get(Some("demo/a")).unwrap().payload,
                    vec![0x42],
                    "the older concrete key is upgraded to the wildcard-put value"
                );
            }

            #[test]
            fn retrieval_wildcard_delete_materializes_on_initial_alignment() {
                // (d) B1: initial alignment (AlignmentQuery::All) routes a
                // WildcardDelete straight to the Retrieval arm; wz MATERIALIZES it
                // (not zenoh's register-only, which assumes an empty backend), so a
                // non-empty backend is correctly swept.
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(wdel_meta("demo/**", 10, 0)),
                    None,
                );
                assert!(
                    s.get(Some("demo/a")).is_none(),
                    "a Retrieval-arm WildcardDelete (initial align) deletes the matching key"
                );
            }

            #[test]
            fn received_wildcard_put_does_not_resurrect_a_tombstone_but_materializes_a_live_sibling(
            ) {
                // (c+P2) A received WildcardPut does NOT resurrect a local tombstone
                // (materialize scans live keys only), AND a live sibling demo/b IS
                // upgraded — the sibling makes this non-vacuous (a no-op align arm
                // would leave demo/b=[1], failing the second assert).
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_delete(Some("demo/a"), at(10, 0)).unwrap(); // tombstone
                s.process_put(Some("demo/b"), vec![1], None, at(5, 0))
                    .unwrap(); // sibling
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(wput_meta("demo/**", 20, 0)),
                    Some(RetrievedValue {
                        payload: vec![0x42],
                        encoding: None,
                    }),
                );
                assert!(
                    s.get(Some("demo/a")).is_none(),
                    "a received wildcard-put must not resurrect a tombstoned key"
                );
                assert_eq!(
                    s.get(Some("demo/b")).unwrap().payload,
                    vec![0x42],
                    "the live sibling IS materialized (the arm actually ran)"
                );
            }

            #[test]
            fn registered_wildcard_delete_shadows_a_later_aligned_concrete_put() {
                // BLOCKER guard (IMPL-A): a wildcard-delete received from peer A
                // (materialized onto an EMPTY backend) must shadow a concrete
                // demo/a@t5 later aligned from peer B that never saw the WD — the
                // 3-party mesh path. zenoh needs_further_processing overrides the
                // concrete event (aligner_reply.rs:255/337/431); wz's concrete align
                // arm now consults the registries via apply_aligned_concrete. Before
                // the fix, demo/a would be stored raw (present) — a convergence gap.
                let mut s = StorageState::new(MemoryStorage::new());
                // (1) receive WD demo/** @t10 (registers; backend empty, no key yet)
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::EventsMetadata(vec![wdel_meta("demo/**", 10, 0)]),
                    None,
                );
                // (2) align concrete Put demo/a @t5 (t5 < t10) from a peer lacking WD
                let put = EventMetadata::put(Some("demo/a".into()), at(5, 0));
                match s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::EventsMetadata(vec![put.clone()]),
                    None,
                ) {
                    AlignmentFollowup::Query(AlignmentQuery::Events(_)) => {}
                    other => panic!("expected an Events follow-up for the put, got {other:?}"),
                }
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(put),
                    Some(RetrievedValue {
                        payload: vec![0xAA],
                        encoding: None,
                    }),
                );
                let stored = s
                    .get(Some("demo/a"))
                    .expect("R2352: the shadowed aligned put is stored empty");
                assert!(
                    stored.payload.is_empty(),
                    "the registered wildcard-delete shadows the older aligned concrete \
                     put: the retrieved 0xAA must NOT reach the backend"
                );
                assert_eq!(
                    stored.timestamp,
                    at(10, 0),
                    "at the wildcard-delete ts, so an older event still cannot resurrect"
                );
            }

            #[test]
            fn out_of_order_plain_delete_after_a_wildcard_put_retains_the_key() {
                // (P3) The plain-Delete instance of D-slice3-1: a WildcardPut@t20
                // raises demo/a's ts, then an out-of-order plain Delete demo/a@t10
                // (t5<t10<t20) is received. wz RETAINS demo/a (is_missing sees
                // latest=t20 >= t10 → skip) — matching zenoh's live-materialize
                // behavior; zenoh's align sweep would delete it via the stored tlnwu.
                // Doc-pins the divergence's plain-delete arm (module divergence #2).
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(wput_meta("demo/**", 20, 0)),
                    Some(RetrievedValue {
                        payload: vec![0x42],
                        encoding: None,
                    }),
                );
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::EventsMetadata(vec![EventMetadata::delete(
                        Some("demo/a".into()),
                        at(10, 0),
                    )]),
                    None,
                );
                assert_eq!(
                    s.get(Some("demo/a")).map(|d| d.payload.clone()),
                    Some(vec![0x42]),
                    "wz retains the key against an out-of-order plain-delete (zenoh-live); D-slice3-1"
                );
            }

            #[test]
            fn re_applying_a_received_wildcard_is_convergent() {
                // (e) is_missing is always true for a wildcard event (its ke is
                // never a concrete `latest` key), so wz re-applies it every round;
                // re-application is idempotent/convergent.
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                let reply = || AlignmentReply::EventsMetadata(vec![wdel_meta("demo/**", 10, 0)]);
                s.process_alignment_reply(&cfg(), reply(), None);
                assert!(s.get(Some("demo/a")).is_none());
                s.process_alignment_reply(&cfg(), reply(), None);
                assert!(
                    s.get(Some("demo/a")).is_none(),
                    "re-applying the same received wildcard is convergent"
                );
            }

            #[test]
            fn named_divergence_overlapping_out_of_order_wildcards_retain_the_key() {
                // (h) NAMED DIVERGENCE D-slice3-1 guard: a WildcardPut@t20 raises
                // demo/a's ts, then an OUT-OF-ORDER WildcardDelete@t10 (t5<t10<t20)
                // arrives. wz RETAINS demo/a at the put value (ts-only gate) —
                // matching zenoh's LIVE-materialize behavior. zenoh's ALIGN path
                // would delete it (stored-tlnwu sweep), but zenoh is itself
                // path-dependent here (module divergence #2). Commented so this is
                // NOT later "fixed" into a divergence.
                let mut s = StorageState::new(MemoryStorage::new());
                s.process_put(Some("demo/a"), vec![1], None, at(5, 0))
                    .unwrap();
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(wput_meta("demo/**", 20, 0)),
                    Some(RetrievedValue {
                        payload: vec![0x42],
                        encoding: None,
                    }),
                );
                assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![0x42]);
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::EventsMetadata(vec![wdel_meta("demo/**", 10, 0)]),
                    None,
                );
                assert_eq!(
                    s.get(Some("demo/a")).map(|d| d.payload.clone()),
                    Some(vec![0x42]),
                    "wz retains the key (zenoh-live behavior); named divergence D-slice3-1"
                );
            }

            // P1 (AV8 on the align path): a received wildcard matches on its
            // Action ke (FULL keyexpr), NOT meta.key() (the stripped log key).
            #[cfg(feature = "storage-mgr-strip-prefix")]
            #[test]
            fn strip_align_wildcard_delete_matches_on_the_action_ke_not_meta_key() {
                use crate::sample::Sample;
                let mut s = StorageState::with_strip_prefix(
                    MemoryStorage::new(),
                    Some("home/kitchen".into()),
                );
                // A concrete key stored RELATIVE ("temp") under the mount.
                s.apply_sample(
                    &Sample::new_put("home/kitchen/temp", vec![21]).with_timestamp(at(5, 0)),
                    || unreachable!(),
                );
                // A WildcardDelete whose Action ke is the FULL "home/kitchen/**"
                // but whose meta.key() is a SENTINEL that matches nothing: proves
                // the Action ke (not meta.key()) drives the materialize.
                let meta = EventMetadata::wildcard(
                    Some("SENTINEL/matches/nothing".into()),
                    at(10, 0),
                    Action::WildcardDelete("home/kitchen/**".into()),
                );
                s.process_alignment_reply(&cfg(), AlignmentReply::EventsMetadata(vec![meta]), None);
                assert!(
                    s.get(Some("temp")).is_none(),
                    "the full-keyexpr Action ke (not meta.key()) drove the match + delete"
                );
            }

            // R2351 — the PRODUCE half, the AV5 residual of the
            // `storage-aligner` atom. Everything above is RECEIVE: a wildcard
            // event decoded off a peer and applied here. These are the mirror:
            // a wildcard registered on THIS replica becomes an event this
            // replica advertises and can answer a retrieval for, which is what
            // upstream's log does
            // (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `if key_expr.is_wild()`).
            mod wildcard_production {
                use super::*;
                use crate::sample::Sample;

                fn wput(s: &mut StorageState<MemoryStorage>, ke: &str, payload: Vec<u8>, t: u64) {
                    s.apply_sample(
                        &Sample::new_put(ke, payload).with_timestamp(at(t, 0)),
                        || unreachable!(),
                    );
                }
                fn wdel(s: &mut StorageState<MemoryStorage>, ke: &str, t: u64) {
                    s.apply_sample(
                        &Sample::new_del(ke).with_timestamp(at(t, 0)),
                        || unreachable!(),
                    );
                }
                /// The single event whose action is a wildcard, or a panic. The
                /// tests below each assert about ONE wildcard, so anything else
                /// is a defect in the derivation rather than a case to skip.
                fn the_wildcard_event(s: &StorageState<MemoryStorage>) -> EventMetadata {
                    let mut wild: Vec<EventMetadata> = s
                        .replication_events()
                        .into_iter()
                        .filter(|e| {
                            matches!(
                                e.action(),
                                Action::WildcardPut(_) | Action::WildcardDelete(_)
                            )
                        })
                        .collect();
                    assert_eq!(wild.len(), 1, "expected exactly one wildcard event");
                    wild.remove(0)
                }

                #[test]
                fn a_registered_wildcard_put_is_advertised_as_an_event() {
                    let mut s = state();
                    s.process_put(Some("demo/a"), vec![1], None, at(1, 0))
                        .unwrap();
                    wput(&mut s, "demo/**", vec![9], 5);

                    let event = the_wildcard_event(&s);
                    assert_eq!(
                        *event.action(),
                        Action::WildcardPut("demo/**".into()),
                        "the action carries the FULL wildcard keyexpr"
                    );
                    assert_eq!(
                        event.key(),
                        Some("demo/**"),
                        "the event is keyed on the wildcard itself, not on a key it \
                         materialized onto (zenoh `Event::new(Some(key_expr), ..)`)"
                    );
                    assert_eq!(event.timestamp(), &at(5, 0));
                    assert!(
                        event.timestamp_last_non_wildcard_update().is_none(),
                        "a wildcard is not a concrete write, so it is not its own \
                         last non-wildcard update, which is what upstream's \
                         `Event::new` sets for exactly these two variants"
                    );
                }

                #[test]
                fn a_registered_wildcard_delete_is_advertised_as_an_event() {
                    let mut s = state();
                    s.process_put(Some("demo/a"), vec![1], None, at(1, 0))
                        .unwrap();
                    wdel(&mut s, "demo/**", 5);

                    let event = the_wildcard_event(&s);
                    assert_eq!(*event.action(), Action::WildcardDelete("demo/**".into()));
                    assert_eq!(event.key(), Some("demo/**"));
                }

                #[test]
                fn an_overridden_concrete_put_is_advertised_as_a_put() {
                    // R2352 — the layer wz's retired divergence appealed to. It
                    // claimed a tombstone "agrees with the log action zenoh's own
                    // `determine_action` records"; measured, upstream records a
                    // plain Put there, because the overridden concrete write keeps
                    // the action it was born with
                    // (`plugins/zenoh-plugin-storage-manager/src/storages_mgt/service.rs` @ `let mut action: Action = kind.into()`)
                    // and `determine_action` returns that unchanged
                    // (`plugins/zenoh-plugin-storage-manager/src/replication/log.rs` @ `Action::Put => return Action::Put`).
                    // wz derives the action from backend presence, so the fix moves
                    // this event from Delete to Put and the two logs now agree.
                    let mut s = state();
                    wdel(&mut s, "demo/**", 50);
                    s.apply_sample(
                        &Sample::new_put("demo/a", vec![9]).with_timestamp(at(30, 0)),
                        || unreachable!(),
                    );
                    let concrete: Vec<EventMetadata> = s
                        .replication_events()
                        .into_iter()
                        .filter(|e| e.key() == Some("demo/a"))
                        .collect();
                    assert_eq!(
                        concrete.len(),
                        1,
                        "the overridden key is one replication event"
                    );
                    assert_eq!(
                        *concrete[0].action(),
                        Action::Put,
                        "the overridden concrete put is logged as a Put, matching \
                         upstream's `determine_action`"
                    );
                    assert_eq!(
                        concrete[0].timestamp(),
                        &at(50, 0),
                        "at the wildcard-delete ts, so the fingerprint is unchanged \
                         by this fix (it hashes key + timestamp only)"
                    );
                }

                #[test]
                fn a_wildcard_put_and_delete_on_one_keyexpr_are_two_events() {
                    let mut s = state();
                    wput(&mut s, "demo/**", vec![9], 5);
                    wdel(&mut s, "demo/**", 7);
                    let wild = s
                        .replication_events()
                        .into_iter()
                        .filter(|e| {
                            matches!(
                                e.action(),
                                Action::WildcardPut(_) | Action::WildcardDelete(_)
                            )
                        })
                        .count();
                    assert_eq!(
                        wild, 2,
                        "upstream's log key is (key, SampleKind), so a Put and a \
                         Delete over the same keyexpr are two entries, not one \
                         replacing the other"
                    );
                }

                #[test]
                fn a_wildcard_put_event_retrieves_its_registered_value() {
                    let mut s = state();
                    s.process_put(Some("demo/a"), vec![1], None, at(1, 0))
                        .unwrap();
                    wput(&mut s, "demo/**", vec![9, 9, 9], 5);

                    let event = the_wildcard_event(&s);
                    let responses = s.answer_alignment_query(
                        &cfg(),
                        &AlignmentQuery::Events(vec![event]),
                        &[0x01],
                        at(9, 0).time,
                    );
                    assert_eq!(responses.len(), 1, "the wildcard event is answerable");
                    assert_eq!(
                        responses[0].value,
                        Some(RetrievedValue {
                            payload: vec![9, 9, 9],
                            encoding: None,
                        }),
                        "the value comes out of the wildcard registry, not the backend \
                         (the wildcard is not a stored key)"
                    );
                }

                #[test]
                fn a_wildcard_delete_event_retrieves_with_no_value() {
                    let mut s = state();
                    s.process_put(Some("demo/a"), vec![1], None, at(1, 0))
                        .unwrap();
                    wdel(&mut s, "demo/**", 5);

                    let event = the_wildcard_event(&s);
                    let responses = s.answer_alignment_query(
                        &cfg(),
                        &AlignmentQuery::Events(vec![event]),
                        &[0x01],
                        at(9, 0).time,
                    );
                    assert_eq!(responses.len(), 1);
                    assert!(
                        responses[0].value.is_none(),
                        "a WildcardDelete carries no value, as a concrete Delete does not"
                    );
                }

                #[test]
                fn a_retrieval_for_an_unregistered_wildcard_is_skipped() {
                    let s = state();
                    let stranger = EventMetadata::wildcard(
                        Some("never/registered/**".into()),
                        at(5, 0),
                        Action::WildcardPut("never/registered/**".into()),
                    );
                    let responses = s.answer_alignment_query(
                        &cfg(),
                        &AlignmentQuery::Events(vec![stranger]),
                        &[0x01],
                        at(9, 0).time,
                    );
                    assert!(
                        responses.is_empty(),
                        "no registry entry means no value to serve: upstream logs and \
                         returns without replying"
                    );
                }

                // The consistency claim the digest half exists for. Both
                // derivations are the XOR of the same per-event
                // `event_fingerprint(key, timestamp)`, so re-deriving the digest
                // FROM the aligner's advertised events must reproduce the digest
                // this replica publishes. If either derivation carried the
                // wildcard and the other did not, this replica would advertise a
                // sub-interval its own digest never announced — and these two
                // values would differ.
                #[cfg(feature = "storage-replication")]
                #[test]
                fn the_published_digest_is_the_digest_of_the_advertised_events() {
                    use crate::storage_replication::build_digest;
                    let mut s = state();
                    s.process_put(Some("demo/a"), vec![1], None, at(1, 0))
                        .unwrap();
                    s.process_put(Some("demo/b"), vec![2], None, at(2, 0))
                        .unwrap();
                    wput(&mut s, "demo/**", vec![9], 5);
                    wdel(&mut s, "demo/other/**", 6);
                    let hot_upper = IntervalIdx::from(9);

                    let advertised = s.replication_events();
                    assert!(
                        advertised
                            .iter()
                            .any(|e| matches!(e.action(), Action::WildcardPut(_))),
                        "precondition: the aligner really is advertising a wildcard"
                    );
                    assert_eq!(
                        s.replication_digest(&cfg(), hot_upper),
                        build_digest(
                            &cfg(),
                            advertised.iter().map(|e| (e.key(), e.timestamp())),
                            hot_upper,
                        ),
                        "the digest and the aligner must be two derivations of ONE \
                         population; zenoh cannot disagree here because one log \
                         feeds both"
                    );
                }
            }
        }
    }
}
