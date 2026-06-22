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
//! (`uhlc-0.8.1/src/timestamp.rs:33-38`: derived `Ord` over
//! `(time: NTP64, id: ID)`) — `time` first, then the id. The id tiebreak
//! is uhlc-faithful: [`timestamp_order_key`] zero-pads the trimmed `zid` to
//! the full 16-byte LE array uhlc's `ID` (`[u8; 16]`) compares, NOT a raw
//! trimmed-`Vec` lexicographic compare (which diverges for a
//! non-canonically-encoded zid). See [`timestamp_order_key`] for the why.
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
use crate::query_sink::{QueryView, ReplyOut};
use crate::sample::{EncodingHint, TimestampHint};
use crate::sample_kind::SampleKind;
use crate::sink::SampleView;
#[cfg(feature = "storage-aligner")]
use crate::storage_aligner::{
    Action, AlignmentFollowup, AlignmentQuery, AlignmentReply, AlignmentResponse, EventBuckets,
    EventMetadata,
};
use crate::storage_backend::{History, StorageBackend, StorageInsertionResult, StoredData};
#[cfg(feature = "storage-replication")]
use crate::storage_replication::{build_digest, Digest, IntervalIdx, ReplicationConfig};

/// The uhlc-faithful ordering key for a timestamp: `(time, zid-as-16-byte
/// little-endian array)`. The SSOT both the newer-wins gate
/// ([`timestamp_strictly_newer`]) and the version-list sort
/// ([`crate::storage_history`]) compare on, so one place encodes uhlc's
/// `Timestamp` `Ord` contract.
///
/// uhlc's `Timestamp` derives `Ord` over `(time: NTP64, id: ID)`
/// (`uhlc-0.8.1/src/timestamp.rs:33-38`), and `ID` is a `[u8; 16]`
/// (`#[repr(transparent)]`, `id.rs:56-59`) holding the id's FULL
/// little-endian bytes, zero-padded — so uhlc compares the whole 16-byte
/// array. wz's wire/[`TimestampHint`] `zid` is the same LE bytes but
/// length-TRIMMED (zenoh-pico `_z_id_len` drops trailing zero high bytes).
/// Comparing the trimmed `Vec`s lexicographically diverges from uhlc for a
/// non-canonically-encoded zid (a peer's, or a carelessly chosen
/// `local_zid`): the dropped high bytes are NOT guaranteed zero in general,
/// so a shorter zid is not always uhlc-less-than a longer one. Zero-padding
/// both to the full 16-byte array before comparison reproduces uhlc's
/// answer exactly (the trimmed bytes are the LE prefix; the pad supplies
/// the zero high bytes uhlc compares against). A zid longer than 16 (a
/// malformed input) is truncated to 16 — uhlc ids are exactly 16 bytes.
pub(crate) fn timestamp_order_key(ts: &TimestampHint) -> (u64, [u8; 16]) {
    (ts.time, zid_to_le_array(&ts.zid))
}

/// Normalise a (length-trimmed) `zid` to the full 16-byte little-endian
/// array uhlc's `ID` canonically holds (`[u8; 16]`,
/// `uhlc-0.8.1/src/id.rs:58-59`; `ID::to_le_bytes` returns the full
/// `[u8; 16]`, id.rs:84). wz's wire / [`TimestampHint`] `zid` is those LE
/// bytes with trailing zero high bytes dropped (zenoh-pico `_z_id_len`);
/// zero-padding back to 16 reproduces the canonical id exactly. This is the
/// SSOT zid encoding shared by the newer-wins ordering key
/// ([`timestamp_order_key`]) and, when `storage-replication` is enabled, the
/// replication event fingerprint — so "which is newer" and "is this the same
/// event" agree on the id bytes. A `zid` longer than 16 (malformed input) is
/// truncated to 16, matching uhlc's fixed id width.
pub(crate) fn zid_to_le_array(zid: &[u8]) -> [u8; 16] {
    let mut zid16 = [0u8; 16];
    let n = zid.len().min(16);
    zid16[..n].copy_from_slice(&zid[..n]);
    zid16
}

/// Whether timestamp `a` is *strictly newer* than `b`, by the uhlc
/// `Timestamp` `Ord` semantic — `(time, 16-byte LE id)` lexicographic (see
/// [`timestamp_order_key`]). The single comparison the newer-wins gate
/// keys off.
pub fn timestamp_strictly_newer(a: &TimestampHint, b: &TimestampHint) -> bool {
    timestamp_order_key(a) > timestamp_order_key(b)
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
    /// (`storages_mgt/service.rs:575-577 (wildcard) / :609-611 (non-wild)`).
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
    pub fn apply_sample(
        &mut self,
        view: &dyn SampleView,
        fallback: impl FnOnce() -> TimestampHint,
    ) {
        let timestamp = view.timestamp().cloned().unwrap_or_else(fallback);
        match view.kind() {
            SampleKind::Put => {
                let encoding = view.encoding().cloned();
                self.process_put(view.keyexpr(), view.payload().to_vec(), encoding, timestamp);
            }
            SampleKind::Del => {
                self.process_delete(view.keyexpr(), timestamp);
            }
        }
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
    #[cfg(feature = "storage-replication")]
    pub fn replication_digest(
        &self,
        config: &ReplicationConfig,
        hot_era_upper_bound: IntervalIdx,
    ) -> Digest {
        debug_assert!(
            self.latest_mode(),
            "replication_digest assumes a History::Latest backend; a \
             History::All backend leaves `latest` empty and yields an empty \
             digest (zenoh's digest likewise assumes Latest)"
        );
        build_digest(
            config,
            self.latest.iter().map(|(key, ts)| (key.as_str(), ts)),
            hot_era_upper_bound,
        )
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
        self.latest
            .iter()
            .map(|(key, ts)| {
                if self.backend.get(key).is_some() {
                    EventMetadata::put(key.clone(), ts.clone())
                } else {
                    EventMetadata::delete(key.clone(), ts.clone())
                }
            })
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
        match meta.action() {
            Action::Delete => Some(AlignmentResponse {
                reply: AlignmentReply::Retrieval(meta),
                value: None,
            }),
            Action::Put => match self.backend.get(meta.key()) {
                Some(data) if &data.timestamp == meta.timestamp() => Some(AlignmentResponse {
                    value: Some((data.payload.clone(), data.encoding.clone())),
                    reply: AlignmentReply::Retrieval(meta),
                }),
                // The stored value moved on (newer ts) or is gone since the
                // metadata was sent: skip, as zenoh does.
                _ => None,
            },
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
    /// [`Retrieval`](AlignmentReply::Retrieval) (the payload + encoding); the
    /// driver pulls it off the query-reply and passes it here. `now` fixes the
    /// Hot-era upper bound the Cold/Warm fingerprint comparisons use.
    ///
    /// The exchange is stateless and drives itself: a driver loops
    /// `query -> peer answers -> process each reply -> followup query` until
    /// every branch returns `Done`.
    #[cfg(feature = "storage-aligner")]
    pub fn process_alignment_reply(
        &mut self,
        config: &ReplicationConfig,
        reply: AlignmentReply,
        value: Option<(Vec<u8>, Option<EncodingHint>)>,
        now: u64,
    ) -> AlignmentFollowup {
        match reply {
            // Initial alignment: the peer told us its zid; the driver pulls all
            // of its content next.
            AlignmentReply::Discovery(zid) => AlignmentFollowup::DiscoveredReplica(zid),

            // Cold-era fingerprints: keep the intervals whose fingerprint we
            // differ on (or lack) and ask for their sub-intervals
            // (aligner_reply.rs:139-159).
            AlignmentReply::Intervals(peer_fingerprints) => {
                let buckets = EventBuckets::from_events(self.replication_events(), config);
                let local = buckets.cold_era_fingerprints(config, config.classify(now).0);
                let differing: alloc::collections::BTreeSet<_> = peer_fingerprints
                    .into_iter()
                    .filter(|(idx, peer_fp)| match local.get(idx) {
                        Some(local_fp) => local_fp != peer_fp,
                        None => true,
                    })
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
                    match meta.action() {
                        Action::Put => missing_puts.push(meta),
                        Action::Delete => {
                            self.process_delete(meta.key(), meta.timestamp().clone());
                        }
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
                            if let Some((payload, encoding)) = value {
                                self.process_put(
                                    meta.key(),
                                    payload,
                                    encoding,
                                    meta.timestamp().clone(),
                                );
                            }
                            // A Put with no value = the peer skipped it (its
                            // data changed); nothing to apply.
                        }
                        Action::Delete => {
                            self.process_delete(meta.key(), meta.timestamp().clone());
                        }
                    }
                }
                AlignmentFollowup::Done
            }
        }
    }

    /// Whether this replica is *missing* `meta` — i.e. it holds no
    /// strictly-newer-or-equal timestamp for the key, so the event should be
    /// pulled. zenoh's `latest_updates.get(key).timestamp >= replica_event` skip
    /// check (aligner_reply.rs:244-252).
    #[cfg(feature = "storage-aligner")]
    fn is_missing(&self, meta: &EventMetadata) -> bool {
        match self.latest.get(meta.key()) {
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
            s.process_put("demo/a", vec![1], None, ts(10, 1));
            s.process_put("demo/b", vec![2], None, ts(15, 2));

            let a = ts(10, 1);
            let b = ts(15, 2);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [("demo/a", &a), ("demo/b", &b)], hot_upper)
            );
        }

        #[test]
        fn replication_digest_includes_tombstones() {
            let cfg = ReplicationConfig::defaults("demo/**");
            let hot_upper = IntervalIdx::from(10);
            let mut s = state();
            s.process_put("demo/a", vec![1], None, ts(10, 1));
            s.process_delete("demo/a", ts(20, 1)); // tombstone at ts 20

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
                build_digest(&cfg, [("demo/a", &tombstone)], hot_upper)
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
            s.process_put("demo/a", vec![1], None, ts(20, 1));
            // Older put is rejected (Outdated) -> latest stays at ts 20.
            s.process_put("demo/a", vec![2], None, ts(10, 1));

            let newer = ts(20, 1);
            assert_eq!(
                s.replication_digest(&cfg, hot_upper),
                build_digest(&cfg, [("demo/a", &newer)], hot_upper)
            );
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
            s.process_put("demo/a", vec![1], None, ts(10, 1));
            s.process_put("demo/b", vec![2], None, ts(11, 1));
            s.process_delete("demo/b", ts(20, 1)); // tombstone

            let events = s.replication_events();
            // One entry per key in `latest`, including the tombstone.
            assert_eq!(events.len(), 2);

            let a = events.iter().find(|e| e.key() == "demo/a").unwrap();
            assert_eq!(a.action(), Action::Put, "a live key is a Put event");
            assert_eq!(a.timestamp(), &ts(10, 1));

            let b = events.iter().find(|e| e.key() == "demo/b").unwrap();
            assert_eq!(
                b.action(),
                Action::Delete,
                "a deleted key (gone from the backend) is a Delete tombstone event"
            );
            assert_eq!(
                b.timestamp(),
                &ts(20, 1),
                "the tombstone carries the delete ts"
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
                s.process_put(k, vec![0xAB], None, t.clone());
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
            s.process_delete("demo/b", at(9, 1)); // a tombstone
            let r = s.answer_alignment_query(&cfg(), &AlignmentQuery::All, &[0x01], NOW10);
            assert_eq!(r.len(), 2);
            let put = r
                .iter()
                .find(|x| matches!(&x.reply, AlignmentReply::Retrieval(m) if m.key() == "demo/a"))
                .unwrap();
            assert!(put.value.is_some(), "a Put retrieval carries the payload");
            let del = r
                .iter()
                .find(|x| matches!(&x.reply, AlignmentReply::Retrieval(m) if m.key() == "demo/b"))
                .unwrap();
            assert!(del.value.is_none(), "a Delete retrieval carries no payload");
        }

        #[test]
        fn answer_events_retrieves_matching_put_and_skips_stale() {
            let s = st_with(&[("demo/a", at(9, 0))]);
            // Matching timestamp -> retrieved with its value.
            let ok = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Events(vec![EventMetadata::put("demo/a", at(9, 0))]),
                &[0x01],
                NOW10,
            );
            assert_eq!(ok.len(), 1);
            assert!(ok[0].value.is_some());
            // A stale timestamp (the stored value moved on) -> skipped entirely.
            let stale = s.answer_alignment_query(
                &cfg(),
                &AlignmentQuery::Events(vec![EventMetadata::put("demo/a", at(8, 0))]),
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
                &AlignmentQuery::Events(vec![EventMetadata::delete("demo/a", at(9, 0))]),
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
                    if evs.len() == 1 && evs[0].key() == "demo/h"));

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
                    if evs.iter().any(|e| e.key() == "demo/h")));

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
            let f = s.process_alignment_reply(
                &cfg(),
                AlignmentReply::Discovery(vec![0x09]),
                None,
                NOW10,
            );
            assert_eq!(f, AlignmentFollowup::DiscoveredReplica(vec![0x09]));
        }

        #[test]
        fn process_intervals_asks_for_a_differing_interval() {
            // Local is empty; the peer reports a cold interval -> local lacks
            // it -> ask for its sub-intervals.
            let mut s = StorageState::new(MemoryStorage::new());
            let mut peer_cold: BTreeMap<IntervalIdx, Fingerprint> = BTreeMap::new();
            peer_cold.insert(IntervalIdx::from(1), Fingerprint::from(0xABCD));
            match s.process_alignment_reply(
                &cfg(),
                AlignmentReply::Intervals(peer_cold),
                None,
                NOW10,
            ) {
                AlignmentFollowup::Query(AlignmentQuery::Intervals(set)) => {
                    assert!(set.contains(&IntervalIdx::from(1)));
                }
                other => panic!("expected an Intervals follow-up, got {other:?}"),
            }
        }

        #[test]
        fn process_intervals_aligned_is_done() {
            // A peer fingerprint equal to ours -> nothing to ask.
            let s = st_with(&[("demo/c", at(1, 0))]); // a cold-era key
            let local = EventBuckets::from_events(s.replication_events(), &cfg())
                .cold_era_fingerprints(&cfg(), cfg().classify(NOW10).0);
            assert!(!local.is_empty(), "the snapshot has a cold interval");
            let mut s = s;
            assert_eq!(
                s.process_alignment_reply(&cfg(), AlignmentReply::Intervals(local), None, NOW10),
                AlignmentFollowup::Done
            );
        }

        #[test]
        fn process_events_metadata_applies_delete_and_collects_missing_put() {
            let mut s = StorageState::new(MemoryStorage::new());
            let reply = AlignmentReply::EventsMetadata(vec![
                EventMetadata::put("demo/p", at(10, 0)),
                EventMetadata::delete("demo/d", at(10, 1)),
            ]);
            match s.process_alignment_reply(&cfg(), reply, None, NOW10) {
                AlignmentFollowup::Query(AlignmentQuery::Events(puts)) => {
                    assert_eq!(puts.len(), 1, "only the Put needs a payload fetch");
                    assert_eq!(puts[0].key(), "demo/p");
                }
                other => panic!("expected an Events follow-up, got {other:?}"),
            }
            // The Delete applied as a tombstone: an older Put can't resurrect it.
            assert_eq!(
                s.process_put("demo/d", vec![1], None, at(9, 0)),
                StorageInsertionResult::Outdated
            );
        }

        #[test]
        fn process_retrieval_applies_a_put_then_skips_when_already_held() {
            let mut s = StorageState::new(MemoryStorage::new());
            let put = EventMetadata::put("demo/x", at(10, 0));
            assert_eq!(
                s.process_alignment_reply(
                    &cfg(),
                    AlignmentReply::Retrieval(put.clone()),
                    Some((vec![0xAB], None)),
                    NOW10,
                ),
                AlignmentFollowup::Done
            );
            assert_eq!(s.get("demo/x").map(|d| d.payload.clone()), Some(vec![0xAB]));
            // Re-processing the same (already held) event does not re-apply.
            s.process_alignment_reply(
                &cfg(),
                AlignmentReply::Retrieval(put),
                Some((vec![0xFF], None)),
                NOW10,
            );
            assert_eq!(
                s.get("demo/x").unwrap().payload,
                vec![0xAB],
                "an already-held event is not overwritten"
            );
        }

        // Drive a full alignment exchange between two in-memory replicas: the
        // local replica detects divergence (digest diff), then loops
        // query -> peer.answer -> local.process until every branch is Done.
        fn drive_alignment(
            local: &mut StorageState<MemoryStorage>,
            peer: &StorageState<MemoryStorage>,
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
                    match local.process_alignment_reply(config, resp.reply, resp.value, now) {
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
            peer.process_put("demo/cold", vec![1], None, at(2, 0));
            peer.process_put("demo/warm", vec![2], None, at(8, 1));
            peer.process_put("demo/hot", vec![3], None, at(10, 0));
            peer.process_delete("demo/gone", at(10, 1)); // a hot-era tombstone
            let mut local = StorageState::new(MemoryStorage::new());
            local.process_put("demo/cold", vec![1], None, at(2, 0)); // already shares cold

            drive_alignment(&mut local, &peer, &config, now);

            // Local pulled every entry it was missing, across all three eras.
            assert_eq!(
                local.get("demo/warm").map(|d| d.payload.clone()),
                Some(vec![2])
            );
            assert_eq!(
                local.get("demo/hot").map(|d| d.payload.clone()),
                Some(vec![3])
            );
            assert!(
                local.get("demo/gone").is_none(),
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
    }
}
