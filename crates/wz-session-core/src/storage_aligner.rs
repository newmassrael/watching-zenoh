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
//! ## Wildcard support (R311wt slice-1: aligner ext) + remaining divergences
//!
//! - **Wildcard actions — DECODED (slice-1), not yet PRODUCED/APPLIED.** zenoh's
//!   `Action` has four variants — `Put`, `Delete`, `WildcardPut(ke)`,
//!   `WildcardDelete(ke)` (log.rs:43-49) — because its storage applies wildcard
//!   updates (a `put test/** 1` overriding a whole subtree). R311wt slice-1
//!   gives wz's [`Action`] all four variants and round-trips them on the wire,
//!   RETIRING the prior `UnsupportedAction` residual that dropped a whole reply
//!   containing a wildcard event. wz does not yet PRODUCE a wildcard event (its
//!   write path treats a wildcard key as literal) nor APPLY a decoded one (it is
//!   skipped in [`crate::storage_state`]): the write-path override engine
//!   (`storage-mgr-wildcard-updates`) is slice 2 and the align-path apply is
//!   slice 3. Until then a decoded wildcard event is a known non-converging
//!   residual — but the batched NON-wildcard events in the same reply now
//!   converge (previously the whole reply was dropped).
//! - **`timestamp_last_non_wildcard_update` — now a real field (slice-1).** zenoh's
//!   `EventMetadata` carries this extra timestamp (log.rs:104) to order wildcard
//!   updates against the non-wildcard events they override. R311wt slice-1
//!   promotes it from the always-`Some(timestamp)` re-supply to a carried
//!   `Option<TimestampHint>`: `Some(timestamp)` for a `Put`/`Delete` (still
//!   byte-identical to the prior emission — a non-wildcard event's
//!   last-non-wildcard is itself), `None` for a wildcard event. Slice 2/3
//!   consume it for the override / resurrection ordering.
//! - **`key: Option<String>`, mirroring `stripped_key: Option<OwnedKeyExpr>`
//!   (R311y61/y64).** zenoh's `stripped_key` is an `Option` because a strip
//!   that matches the prefix exactly yields `None` (the mount-root slot); with
//!   a configured `strip_prefix` wz stores the stripped key, the exact-prefix
//!   value landing under the `None` mount-root slot, and an [`EventMetadata`]
//!   carries that `Option<String>` faithfully through the digest, the aligner,
//!   and the bincode wire. With no `strip_prefix` every key is `Some(full_key)`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::sample::{EncodingHint, TimestampHint};
use crate::storage_replication::{
    event_fingerprint, DigestDiff, Fingerprint, IntervalIdx, ReplicationConfig, SubIntervalIdx,
};

/// The kind of a logged replication event. zenoh `log::Action` (log.rs:43-49),
/// all four variants (R311wt slice-1 — the aligner ext for the
/// `storage-mgr-wildcard-updates` atom).
///
/// The two wildcard variants embed the (un-stripped) wildcard keyexpr they
/// apply to — a `put test/** 1` / `delete test/**` overriding a whole subtree —
/// so `Action` carries a `String` and is no longer `Copy` (zenoh
/// `WildcardPut(OwnedKeyExpr)` / `WildcardDelete(OwnedKeyExpr)`, log.rs:46-49).
/// Slice-1 DECODES + round-trips these off the wire (closing the prior
/// `UnsupportedAction` residual that dropped a whole reply); wz does not yet
/// PRODUCE or APPLY a wildcard event — the write-path override engine
/// (`storage-mgr-wildcard-updates`) + the align-path apply are slices 2/3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// A value was stored at the key.
    Put,
    /// The key was deleted — a tombstone. The value is gone from the backend
    /// but the accepted timestamp survives in the newer-wins gate, so an
    /// older Put cannot resurrect the key (the [`crate::storage_state`]
    /// tombstone).
    Delete,
    /// A wildcard Put over the embedded keyexpr (e.g. `test/**`) overriding
    /// every matching key in the subtree (zenoh `Action::WildcardPut`). Carried
    /// so the align path can round-trip a real zenoh replica's wildcard event;
    /// the write-path materialization is slice 2.
    WildcardPut(String),
    /// A wildcard Delete over the embedded keyexpr (zenoh
    /// `Action::WildcardDelete`) — deletes every matching key in the subtree.
    WildcardDelete(String),
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
    key: Option<String>,
    timestamp: TimestampHint,
    /// zenoh `EventMetadata::timestamp_last_non_wildcard_update` (log.rs:104):
    /// the timestamp of the last NON-wildcard write at this key, used to order
    /// a wildcard update against the concrete events it overrides (so a
    /// later-arriving-but-logically-earlier delete still wins over a wildcard
    /// put — the resurrection guard). `Some(timestamp)` for a `Put`/`Delete`
    /// (a non-wildcard event's last-non-wildcard IS itself); `None` for a
    /// `WildcardPut`/`WildcardDelete`. R311wt slice-1 promotes this from the
    /// always-`Some(timestamp)` re-supply to a real carried field; slice 2/3
    /// consume it for the override ordering.
    timestamp_last_non_wildcard_update: Option<TimestampHint>,
    action: Action,
}

impl EventMetadata {
    /// The metadata of a `Put` at `key` accepted at `timestamp`. `key` is
    /// `Option<String>` mirroring zenoh's `stripped_key`: `None` is the
    /// exact-prefix mount-root slot of a strip-configured storage.
    pub fn put(key: Option<String>, timestamp: TimestampHint) -> Self {
        Self {
            key,
            timestamp_last_non_wildcard_update: Some(timestamp.clone()),
            timestamp,
            action: Action::Put,
        }
    }

    /// The metadata of a `Delete` (tombstone) at `key` accepted at
    /// `timestamp`. `key` is `Option<String>` (`None` = the mount-root slot).
    pub fn delete(key: Option<String>, timestamp: TimestampHint) -> Self {
        Self {
            key,
            timestamp_last_non_wildcard_update: Some(timestamp.clone()),
            timestamp,
            action: Action::Delete,
        }
    }

    /// The metadata of a wildcard event (`WildcardPut`/`WildcardDelete`) over
    /// `wildcard_ke`, accepted at `timestamp`. `key` is the stripped key the
    /// event is logged under; `timestamp_last_non_wildcard_update` is `None`
    /// (a wildcard is not a concrete write). R311wt slice-1 constructs these
    /// only on DECODE (a peer's wildcard event round-tripped); wz does not yet
    /// materialize them (slices 2/3).
    pub fn wildcard(key: Option<String>, timestamp: TimestampHint, action: Action) -> Self {
        debug_assert!(
            matches!(action, Action::WildcardPut(_) | Action::WildcardDelete(_)),
            "EventMetadata::wildcard requires a wildcard action"
        );
        Self {
            key,
            timestamp,
            timestamp_last_non_wildcard_update: None,
            action,
        }
    }

    /// The stored key this event is for — `None` for a strip-configured
    /// storage's exact-prefix mount-root value (zenoh `stripped_key == None`).
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// The timestamp the event was accepted at — the newer-wins ordering key
    /// a receiver compares against its own copy.
    pub fn timestamp(&self) -> &TimestampHint {
        &self.timestamp
    }

    /// The timestamp of the last non-wildcard write at this key (the wildcard
    /// override-ordering key). See the field doc; `None` iff this is a wildcard
    /// event.
    pub fn timestamp_last_non_wildcard_update(&self) -> Option<&TimestampHint> {
        self.timestamp_last_non_wildcard_update.as_ref()
    }

    /// Whether the event was a Put, Delete, WildcardPut, or WildcardDelete.
    /// Returns a reference — `Action` carries the wildcard keyexpr and is no
    /// longer `Copy` (R311wt slice-1).
    pub fn action(&self) -> &Action {
        &self.action
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
        event_fingerprint(self.key.as_deref(), &self.timestamp)
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
    /// `self.fingerprint ^= event.fingerprint()` on insert (classification.rs:378
    /// SubInterval insert; :183 the Interval-level XOR). XOR is order-independent,
    /// so the recomputed value matches zenoh's incrementally-maintained one.
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
            .map(|(idx, subs)| (*idx, Self::interval_fingerprint(subs)))
            .collect()
    }

    /// The [`Fingerprint`] of one interval = the XOR of all its events'
    /// fingerprints (equivalently the XOR of its sub-interval fingerprints).
    /// zenoh `Interval.fingerprint`, classification.rs:104-108.
    fn interval_fingerprint(subs: &BTreeMap<SubIntervalIdx, Vec<EventMetadata>>) -> Fingerprint {
        subs.values().fold(Fingerprint::default(), |acc, evs| {
            acc ^ Self::sub_fingerprint(evs)
        })
    }

    /// The **era-independent** [`Fingerprint`] of an interval, or `None` if this
    /// replica holds no events in it. This is what the pull side compares a
    /// peer's Cold-era reply against — zenoh looks the interval up in its log
    /// regardless of era (`intervals.get(idx).fingerprint()`,
    /// core/aligner_reply.rs:145), explicitly NOT re-classifying it by era,
    /// because the two replicas may bucket the same interval into different eras
    /// under clock skew yet the comparison is still valid (core/aligner_query.rs:179-186).
    pub fn interval_fingerprint_of(&self, interval_idx: &IntervalIdx) -> Option<Fingerprint> {
        self.intervals
            .get(interval_idx)
            .map(Self::interval_fingerprint)
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

/// The information a Replica requests from a peer's Aligner to converge its
/// storage. zenoh `core::aligner_query::AlignmentQuery` (aligner_query.rs:51-65).
///
/// Requests drill from coarse to fine in the order
/// `Diff -> Intervals -> SubIntervals -> Events`; not all steps run — where the
/// drill starts depends on the era a divergence was detected in (a Hot-era
/// divergence skips straight to the sub-interval level). `Discovery` + `All`
/// are the initial-alignment path a fresh (empty) replica uses *instead* of a
/// Digest exchange: discover a peer, then pull everything.
///
/// wz uses `BTreeSet` / `BTreeMap` where zenoh uses `HashSet` / `HashMap` (the
/// no_std kernel has no std hasher) — wire-compatible because the codec
/// length-prefixes each collection, so the byte layout is element-order
/// independent (the same property the digest codec relies on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignmentQuery {
    /// Ask peers for their Zenoh ID, to pick one for an initial full transfer.
    Discovery,
    /// Retrieve a peer's entire contents (the initial alignment).
    All,
    /// The first alignment request after a Digest comparison localised a
    /// divergence — carries the [`DigestDiff`] that named the differing eras.
    Diff(DigestDiff),
    /// Request the per-sub-interval fingerprints of these intervals — the
    /// Cold-era follow-up, once the Replica has found which cold intervals
    /// differ.
    Intervals(BTreeSet<IntervalIdx>),
    /// Request the [`EventMetadata`] in these sub-intervals — the Warm/Hot
    /// follow-up, once the Replica has found which sub-intervals differ.
    SubIntervals(BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>>),
    /// Request the payloads for these events — the final step, once the
    /// Replica has found which exact events it is missing.
    Events(Vec<EventMetadata>),
}

/// The information a peer's Aligner sends back in response to an
/// [`AlignmentQuery`]. zenoh `core::aligner_reply::AlignmentReply`
/// (aligner_reply.rs:51-58).
///
/// Replies proceed `Intervals -> SubIntervals -> EventsMetadata -> Retrieval`,
/// each one letting the asking Replica compare against its own state and then
/// request the next, finer level. `Discovery` is the initial-alignment reply
/// (the peer's Zenoh ID). One [`Retrieval`](AlignmentReply::Retrieval) is sent
/// *per event*, and it additionally carries the event's payload on the
/// query-reply's value (this enum itself rides the reply attachment, the
/// payload rides the reply body — zenoh `reply_to_query`, aligner_query.rs:340-363).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignmentReply {
    /// The responder's Zenoh ID bytes — the same zid the digest keyexpr is
    /// formatted from — in answer to a `Discovery`. zenoh
    /// `AlignmentReply::Discovery(ZenohId)`; wz carries the raw zid bytes
    /// (the length-trimmed LE prefix [`TimestampHint::zid`] uses).
    Discovery(Vec<u8>),
    /// The per-interval fingerprints of the Cold era, in answer to a `Diff`
    /// with a Cold divergence (zenoh `reply_cold_era`). The Replica diffs
    /// these against its own to find which intervals to drill into.
    Intervals(BTreeMap<IntervalIdx, Fingerprint>),
    /// The per-sub-interval fingerprints of the requested intervals (zenoh
    /// `reply_sub_intervals`).
    SubIntervals(BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>>),
    /// The [`EventMetadata`] in the requested sub-intervals (zenoh
    /// `reply_events_metadata`). The Replica keeps those it lacks a newer copy
    /// of and requests their payloads.
    EventsMetadata(Vec<EventMetadata>),
    /// One event's [`EventMetadata`], paired (on the query-reply value) with
    /// its payload (zenoh `reply_event_retrieval`).
    Retrieval(EventMetadata),
}

/// A stored value carried back on a Put [`Retrieval`](AlignmentReply::Retrieval):
/// the payload and its optional encoding (the query-reply body in zenoh's
/// wire). Named rather than a bare `(Vec<u8>, Option<EncodingHint>)` because it
/// is a public field of [`AlignmentResponse`] and a parameter of the pull
/// engine — the pairing deserves a name, not positional `.0` / `.1`.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievedValue {
    /// The stored payload bytes.
    pub payload: Vec<u8>,
    /// The encoding the value was published with, if any.
    pub encoding: Option<EncodingHint>,
}

/// One reply the aligner emits for an [`AlignmentQuery`]: the typed
/// [`AlignmentReply`] (which rides the query-reply attachment) plus, for a
/// [`Retrieval`](AlignmentReply::Retrieval) of a Put, the [`RetrievedValue`]
/// that rides the reply body. zenoh `reply_to_query` (aligner_query.rs:340-363)
/// attaches the serialized AlignmentReply and, when present, the value.
///
/// A single [`AlignmentQuery`] can produce several responses (a `Diff` yields
/// up to three — cold / warm / hot; an `All` or `Events` yields one per event),
/// so the answer engine returns a `Vec<AlignmentResponse>`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlignmentResponse {
    /// The typed reply (serialized onto the query-reply attachment).
    pub reply: AlignmentReply,
    /// The stored value for a Put `Retrieval`; `None` for every other reply and
    /// for a Delete `Retrieval` (a delete carries no payload).
    pub value: Option<RetrievedValue>,
}

/// What the pull side does after processing one [`AlignmentReply`] — the
/// outcome of [`StorageState::process_alignment_reply`](crate::storage_state::StorageState::process_alignment_reply).
/// The aligner exchange is stateless: each reply either resolves or yields the
/// next, finer request, so a driver simply loops on the followup until
/// [`Done`](AlignmentFollowup::Done). zenoh threads this implicitly by spawning
/// the next query inside `process_alignment_reply` (aligner_reply.rs:99-229);
/// wz returns it so the engine stays pure (no Session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignmentFollowup {
    /// Nothing more to request — this branch of the alignment is converged
    /// (any missing entries were applied in place).
    Done,
    /// Send this finer [`AlignmentQuery`] to the **same** peer (the current
    /// aligner exchange) and process its replies in turn.
    Query(AlignmentQuery),
    /// Initial alignment: the peer answered a `Discovery` with its Zenoh ID.
    /// The driver sends an [`AlignmentQuery::All`] to *this* zid's aligner
    /// keyexpr to pull its entire contents (zenoh aligner_reply.rs:106-138).
    DiscoveredReplica(Vec<u8>),
}

/// The storage-aligner wire codec — byte-exact encode/decode of the aligner
/// types to the format a real zenoh `zenoh-plugin-storage-manager` replica
/// publishes, the twin of [`crate::storage_replication::wire`].
///
/// This atom lands the leaf value type — [`EventMetadata`] and the
/// [`TimestampHint`] / [`Action`] it embeds; the [`AlignmentQuery`] /
/// [`AlignmentReply`] envelopes that carry it are the next atom. As with the
/// digest codec, the layout is hand-rolled (no `bincode` dependency in the
/// no_std kernel) and pinned to the real `bincode` 1.3 by a `#[cfg(test)]`
/// cross-check.
///
/// ## Byte layout (bincode 1.3 default: LE, fixint, u64 lengths)
///
/// zenoh's `EventMetadata` (log.rs:100-106) derives serde; bincode renders it
/// field-by-field in declaration order:
///
/// ```text
/// stripped_key                       : Option -> u8 tag (1=Some), then String
/// timestamp                          : Timestamp (see below)
/// timestamp_last_non_wildcard_update : Option -> u8 tag, then Timestamp if Some
/// action                             : Action  -> u32 LE variant index
/// ```
///
/// A `Timestamp` (uhlc, derived serde, timestamp.rs:33) is its two newtype
/// fields in order: `NTP64(u64)` -> 8 LE bytes, then `ID([u8; 16])` -> 16 bytes
/// (a fixed array, no length prefix). A `String` is a u64 length then the UTF-8
/// bytes. An `Option` is a single `u8` tag (0=None, 1=Some) — NOT a u32, as
/// serde's `Option` uses `serialize_some`/`serialize_none`, distinct from an
/// enum's u32 variant index. An `Action` IS a plain enum, so its index is a
/// u32.
///
/// ## wz emission vs zenoh
///
/// wz emits `stripped_key` faithfully as an `Option` (R311y64): `Some(key)`
/// for an ordinary key, `None` for a strip-configured storage's exact-prefix
/// mount-root value — the single `0` Option tag, no key bytes. It emits
/// `timestamp_last_non_wildcard_update` as the carried field (R311wt slice-1):
/// `Some(timestamp)` for a Put/Delete (byte-identical to the prior always-Some
/// re-supply — a non-wildcard event's last-non-wildcard is itself), `None` for
/// a wildcard event. `action` is a u32 index for all four variants; the two
/// wildcard variants (2/3) are FOLLOWED by their keyexpr `String`. On decode it
/// reads the real `timestamp_last_non_wildcard_update` into the struct, accepts
/// a `None` stripped_key (round-tripping to `EventMetadata::key() == None`), and
/// round-trips a wildcard action (2/3) — retiring the prior `UnsupportedAction`
/// residual; only an index `>= 4` is a typed error. (wz DECODES a wildcard
/// event but does not yet PRODUCE or APPLY one — slices 2/3.)
pub mod wire {
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{
        Action, AlignmentQuery, AlignmentReply, DigestDiff, EventMetadata, Fingerprint,
        IntervalIdx, SubIntervalIdx,
    };
    use crate::sample::TimestampHint;
    // The zid <-> zenoh-hex SSOT lives in `crate::zid_hex` (relocated there
    // R311y34); `storage_replication` re-exports it for back-compat and this
    // import rides that re-export. The Discovery arm is one consumer.
    use crate::storage_replication::{zenoh_hex_to_zid, zid_to_zenoh_hex};
    use crate::zid_hex::zid_to_le_array;
    // The shared bincode-1.3 cursor core + length guard + the multi-consumer
    // widths (`u32` tags, `String` / `Option<String>`, the length-guarded byte
    // read) live in `wire_bincode` as the one SSOT this codec and the group
    // codec build on; the aligner-only shapes (the zenoh `Timestamp`, the
    // domain enums) layer on top here. `read_u8` / `read_u32` are reached by
    // fully-qualified delegation in the thin inherent reads below.
    use crate::wire_bincode::{
        check_len, push_option_string, push_string, push_u32, push_u64, read_len_prefixed_bytes,
        Reader, WireError,
    };

    /// Failure decoding an aligner wire structure from bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AlignmentDecodeError {
        /// The buffer ended before a fixed-width field could be read.
        UnexpectedEof,
        /// A length prefix exceeds the bytes that remain — corrupt or hostile.
        LengthOverflow,
        /// Bytes remained after a complete structure was decoded.
        TrailingBytes,
        /// A 0/1 tag byte (an `Option` discriminant or a `bool`) that was
        /// neither 0 nor 1.
        BadOptionTag(u8),
        /// An `Action` variant index the decoder does not know: `>= 4`. Indices
        /// 0-3 (Put / Delete / WildcardPut / WildcardDelete) all decode as of
        /// R311wt slice-1 — the wildcard variants are round-tripped rather than
        /// rejected (the prior residual, when they were dropped, is retired).
        UnsupportedAction(u32),
        /// A stripped_key whose bytes are not valid UTF-8.
        BadUtf8,
        /// An [`AlignmentQuery`] / [`AlignmentReply`] enum tag with no known
        /// variant.
        UnknownVariant(u32),
        /// A Discovery zid hex string that does not parse as a `<= 16`-byte id.
        BadZid,
    }

    impl From<WireError> for AlignmentDecodeError {
        fn from(e: WireError) -> Self {
            match e {
                WireError::UnexpectedEof => Self::UnexpectedEof,
                WireError::LengthOverflow => Self::LengthOverflow,
            }
        }
    }

    /// Minimum encoded size of one collection element, for the `check_len`
    /// fast-reject of a hostile length — named, not magic literals, so the
    /// byte-width arithmetic is self-documenting.
    const U64_BYTES: usize = 8; // one IntervalIdx / SubIntervalIdx / Fingerprint
    const PAIR_BYTES: usize = 16; // an (idx, value) or (idx, sub-len) pair = two u64s
    /// A conservative lower bound on a valid `EventMetadata`'s encoded size —
    /// the `check_len` fast-reject floor: `None` stripped_key tag(1) +
    /// Timestamp(24) + tlnwu tag(1) + action(4). It MUST stay `<=` the true
    /// minimum or a valid run of minimal events would be wrongly rejected.
    /// Post-R311wt slice-1 no real event is actually this small (a Put/Delete
    /// carries a `Some` tlnwu = +24; a wildcard carries `None` tlnwu but a
    /// keyexpr String = +8 min), so 30 under-approximates every variant and
    /// stays a safe conservative floor (R311y64 shrank it when the `None`-key
    /// event dropped the 8-byte key length).
    const MIN_EVENT_BYTES: usize = 1 + 24 + 1 + 4;

    /// A [`TimestampHint`] as zenoh's bincode `Timestamp`: the NTP64 time word
    /// (u64 LE), then the 16-byte zero-padded id ([`zid_to_le_array`], the SSOT
    /// shared with the newer-wins comparator and the event fingerprint).
    fn push_timestamp(out: &mut Vec<u8>, ts: &TimestampHint) {
        push_u64(out, ts.time);
        out.extend_from_slice(&zid_to_le_array(&ts.zid));
    }

    fn push_event_metadata(out: &mut Vec<u8>, e: &EventMetadata) {
        // stripped_key: Option<OwnedKeyExpr> — the shared bincode `Option<String>`
        // width: a `0`/`1` tag then the String only for Some. `None` (a
        // strip-configured mount-root value) is the single `0` byte, mirroring
        // zenoh's bincode `Option` (R311y64).
        push_option_string(out, e.key());
        push_timestamp(out, e.timestamp());
        // timestamp_last_non_wildcard_update: the real Option field (R311wt
        // slice-1). Some(ts) for a Put/Delete (byte-identical to the prior
        // always-`Some(timestamp)` re-supply, since a non-wildcard event's
        // last-non-wildcard IS itself), None for a wildcard event.
        match e.timestamp_last_non_wildcard_update() {
            Some(ts) => {
                out.push(1);
                push_timestamp(out, ts);
            }
            None => out.push(0),
        }
        // action: the u32 variant index; the wildcard variants are FOLLOWED by
        // their keyexpr String (zenoh's bincode enum-with-payload, log.rs:46-49).
        match e.action() {
            Action::Put => push_u32(out, 0),
            Action::Delete => push_u32(out, 1),
            Action::WildcardPut(ke) => {
                push_u32(out, 2);
                push_string(out, ke);
            }
            Action::WildcardDelete(ke) => {
                push_u32(out, 3);
                push_string(out, ke);
            }
        }
    }

    /// Encode one [`EventMetadata`] to the zenoh bincode wire bytes.
    pub fn encode_event_metadata(e: &EventMetadata) -> Vec<u8> {
        let mut out = Vec::new();
        push_event_metadata(&mut out, e);
        out
    }

    /// The aligner's domain decoders, layered on the shared bincode cursor
    /// ([`crate::wire_bincode::Reader`]): the cursor primitives it shares with
    /// the digest codec are `read_u64` / `read_bytes` + the `check_len` guard,
    /// and the wider widths (`read_u8` / `read_u32` / the length-prefixed
    /// `String` read) are the shared `wire_bincode` widths (with the group
    /// codec). The `read_u8` / `read_u32` inherent methods below are thin
    /// delegations to those; the rest add the aligner's typed shapes. A shared
    /// [`WireError`] lifts into [`AlignmentDecodeError`] via `?` (the `From`
    /// impl above).
    impl Reader<'_> {
        /// Read a single byte (a bincode `u8` / Option-or-bool tag) — a thin
        /// delegation to the shared width, lifting [`WireError`] into the
        /// aligner's typed error.
        fn read_u8(&mut self) -> Result<u8, AlignmentDecodeError> {
            Ok(crate::wire_bincode::read_u8(self)?)
        }

        /// Read a `u32` as 4 little-endian bytes (a bincode enum-variant index)
        /// — a thin delegation to the shared width.
        fn read_u32(&mut self) -> Result<u32, AlignmentDecodeError> {
            Ok(crate::wire_bincode::read_u32(self)?)
        }

        /// Read a bincode `String`: a u64 length then that many UTF-8 bytes. The
        /// length guard is the shared [`read_len_prefixed_bytes`] SSOT (the
        /// guard that had drifted from the group codec's copy); the aligner
        /// layers UTF-8 validation on the returned slice.
        fn read_string(&mut self) -> Result<String, AlignmentDecodeError> {
            core::str::from_utf8(read_len_prefixed_bytes(self)?)
                .map(String::from)
                .map_err(|_| AlignmentDecodeError::BadUtf8)
        }

        /// Read zenoh's bincode `Timestamp`: NTP64 (u64) + the 16-byte id. The
        /// id's trailing zero bytes are trimmed back to wz's canonical
        /// length-trimmed [`TimestampHint::zid`] form (the inverse of
        /// [`zid_to_le_array`]); re-encoding zero-pads it again, so the round
        /// trip is exact.
        fn read_timestamp(&mut self) -> Result<TimestampHint, AlignmentDecodeError> {
            let time = self.read_u64()?;
            let id = self.read_bytes(16)?;
            let trimmed_len = id.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            Ok(TimestampHint {
                time,
                zid: id[..trimmed_len].to_vec(),
            })
        }

        /// Read an `Option` / `bool` tag: 0 => false, 1 => true, else error.
        fn read_option_tag(&mut self) -> Result<bool, AlignmentDecodeError> {
            match self.read_u8()? {
                0 => Ok(false),
                1 => Ok(true),
                other => Err(AlignmentDecodeError::BadOptionTag(other)),
            }
        }

        fn read_event_metadata(&mut self) -> Result<EventMetadata, AlignmentDecodeError> {
            // stripped_key: Option<OwnedKeyExpr> — `Some(key)` for an ordinary
            // key, `None` for a strip-configured storage's exact-prefix
            // mount-root value (R311y64). Both round-trip faithfully.
            let key = if self.read_option_tag()? {
                Some(self.read_string()?)
            } else {
                None
            };
            let timestamp = self.read_timestamp()?;
            // timestamp_last_non_wildcard_update: the real Option field (R311wt
            // slice-1) — read into EventMetadata instead of discarded.
            let timestamp_last_non_wildcard_update = if self.read_option_tag()? {
                Some(self.read_timestamp()?)
            } else {
                None
            };
            // action: variants 2/3 (WildcardPut/WildcardDelete) carry the
            // wildcard keyexpr String; slice-1 decodes them, closing the prior
            // UnsupportedAction residual that dropped a whole reply. An index
            // > 3 is still an unknown-variant error.
            let action = match self.read_u32()? {
                0 => Action::Put,
                1 => Action::Delete,
                2 => Action::WildcardPut(self.read_string()?),
                3 => Action::WildcardDelete(self.read_string()?),
                other => return Err(AlignmentDecodeError::UnsupportedAction(other)),
            };
            Ok(EventMetadata {
                key,
                timestamp,
                timestamp_last_non_wildcard_update,
                action,
            })
        }
    }

    /// Decode one [`EventMetadata`] from the zenoh bincode wire bytes; rejects
    /// trailing bytes.
    pub fn decode_event_metadata(bytes: &[u8]) -> Result<EventMetadata, AlignmentDecodeError> {
        let mut r = Reader::new(bytes);
        let e = r.read_event_metadata()?;
        if r.remaining() != 0 {
            return Err(AlignmentDecodeError::TrailingBytes);
        }
        Ok(e)
    }

    // ---- AlignmentQuery / AlignmentReply envelopes (aligner 5/N) ----
    //
    // bincode renders an enum as a u32 LE variant index then the variant's
    // fields; a set / map / Vec as a u64 length then its elements / pairs; a
    // newtype index (IntervalIdx, SubIntervalIdx, Fingerprint) as its inner
    // u64. The envelopes are built on the shared bincode primitives + the
    // domain Reader methods above. `check_len` is the shared length guard.

    fn push_interval_set(out: &mut Vec<u8>, set: &BTreeSet<IntervalIdx>) {
        push_u64(out, set.len() as u64);
        for idx in set {
            push_u64(out, idx.value());
        }
    }

    fn push_subinterval_map(
        out: &mut Vec<u8>,
        map: &BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>>,
    ) {
        push_u64(out, map.len() as u64);
        for (idx, subs) in map {
            push_u64(out, idx.value());
            push_u64(out, subs.len() as u64);
            for sub in subs {
                push_u64(out, sub.value());
            }
        }
    }

    fn push_digest_diff(out: &mut Vec<u8>, diff: &DigestDiff) {
        out.push(u8::from(diff.cold_eras_differ()));
        push_interval_set(out, diff.warm_eras_differences());
        push_subinterval_map(out, diff.hot_eras_differences());
    }

    fn push_events(out: &mut Vec<u8>, events: &[EventMetadata]) {
        push_u64(out, events.len() as u64);
        for e in events {
            push_event_metadata(out, e);
        }
    }

    fn push_fingerprint_map(out: &mut Vec<u8>, map: &BTreeMap<IntervalIdx, Fingerprint>) {
        push_u64(out, map.len() as u64);
        for (idx, fp) in map {
            push_u64(out, idx.value());
            push_u64(out, fp.value());
        }
    }

    fn push_sub_fingerprint_map(
        out: &mut Vec<u8>,
        map: &BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>>,
    ) {
        push_u64(out, map.len() as u64);
        for (idx, subs) in map {
            push_u64(out, idx.value());
            push_u64(out, subs.len() as u64);
            for (sub, fp) in subs {
                push_u64(out, sub.value());
                push_u64(out, fp.value());
            }
        }
    }

    impl Reader<'_> {
        fn read_interval_set(&mut self) -> Result<BTreeSet<IntervalIdx>, AlignmentDecodeError> {
            let len = self.read_u64()?;
            check_len(len, U64_BYTES, self)?;
            let mut set = BTreeSet::new();
            for _ in 0..len {
                set.insert(IntervalIdx::from(self.read_u64()?));
            }
            Ok(set)
        }

        fn read_subinterval_map(
            &mut self,
        ) -> Result<BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>>, AlignmentDecodeError> {
            let len = self.read_u64()?;
            check_len(len, PAIR_BYTES, self)?; // idx(8) + a (>=0) sub len(8)
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let idx = IntervalIdx::from(self.read_u64()?);
                let sub_len = self.read_u64()?;
                check_len(sub_len, U64_BYTES, self)?;
                let mut subs = BTreeSet::new();
                for _ in 0..sub_len {
                    subs.insert(SubIntervalIdx::from(self.read_u64()?));
                }
                map.insert(idx, subs);
            }
            Ok(map)
        }

        fn read_digest_diff(&mut self) -> Result<DigestDiff, AlignmentDecodeError> {
            // A bincode `bool` is a 0/1 byte, same shape as an Option tag.
            let cold_eras_differ = self.read_option_tag()?;
            let warm_eras_differences = self.read_interval_set()?;
            let hot_eras_differences = self.read_subinterval_map()?;
            Ok(DigestDiff {
                cold_eras_differ,
                warm_eras_differences,
                hot_eras_differences,
            })
        }

        fn read_fingerprint_map(
            &mut self,
        ) -> Result<BTreeMap<IntervalIdx, Fingerprint>, AlignmentDecodeError> {
            let len = self.read_u64()?;
            check_len(len, PAIR_BYTES, self)?;
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let idx = IntervalIdx::from(self.read_u64()?);
                let fp = Fingerprint::from(self.read_u64()?);
                map.insert(idx, fp);
            }
            Ok(map)
        }

        fn read_sub_fingerprint_map(
            &mut self,
        ) -> Result<
            BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>>,
            AlignmentDecodeError,
        > {
            let len = self.read_u64()?;
            check_len(len, PAIR_BYTES, self)?;
            let mut map = BTreeMap::new();
            for _ in 0..len {
                let idx = IntervalIdx::from(self.read_u64()?);
                let sub_len = self.read_u64()?;
                check_len(sub_len, PAIR_BYTES, self)?;
                let mut subs = BTreeMap::new();
                for _ in 0..sub_len {
                    let sub = SubIntervalIdx::from(self.read_u64()?);
                    let fp = Fingerprint::from(self.read_u64()?);
                    subs.insert(sub, fp);
                }
                map.insert(idx, subs);
            }
            Ok(map)
        }

        fn read_events(&mut self) -> Result<Vec<EventMetadata>, AlignmentDecodeError> {
            let len = self.read_u64()?;
            // min EventMetadata: None-key-tag(1)+ts(24)+None-tlnwu-tag(1)+action(4).
            check_len(len, MIN_EVENT_BYTES, self)?;
            let mut events = Vec::new();
            for _ in 0..len {
                events.push(self.read_event_metadata()?);
            }
            Ok(events)
        }
    }

    /// Encode an [`AlignmentQuery`] to the zenoh bincode wire bytes.
    pub fn encode_alignment_query(query: &AlignmentQuery) -> Vec<u8> {
        let mut out = Vec::new();
        match query {
            AlignmentQuery::Discovery => push_u32(&mut out, 0),
            AlignmentQuery::All => push_u32(&mut out, 1),
            AlignmentQuery::Diff(diff) => {
                push_u32(&mut out, 2);
                push_digest_diff(&mut out, diff);
            }
            AlignmentQuery::Intervals(set) => {
                push_u32(&mut out, 3);
                push_interval_set(&mut out, set);
            }
            AlignmentQuery::SubIntervals(map) => {
                push_u32(&mut out, 4);
                push_subinterval_map(&mut out, map);
            }
            AlignmentQuery::Events(events) => {
                push_u32(&mut out, 5);
                push_events(&mut out, events);
            }
        }
        out
    }

    /// Decode an [`AlignmentQuery`] from the zenoh bincode wire bytes; rejects
    /// trailing bytes and an unknown variant tag.
    pub fn decode_alignment_query(bytes: &[u8]) -> Result<AlignmentQuery, AlignmentDecodeError> {
        let mut r = Reader::new(bytes);
        let q = match r.read_u32()? {
            0 => AlignmentQuery::Discovery,
            1 => AlignmentQuery::All,
            2 => AlignmentQuery::Diff(r.read_digest_diff()?),
            3 => AlignmentQuery::Intervals(r.read_interval_set()?),
            4 => AlignmentQuery::SubIntervals(r.read_subinterval_map()?),
            5 => AlignmentQuery::Events(r.read_events()?),
            other => return Err(AlignmentDecodeError::UnknownVariant(other)),
        };
        if r.remaining() != 0 {
            return Err(AlignmentDecodeError::TrailingBytes);
        }
        Ok(q)
    }

    /// Encode an [`AlignmentReply`] to the zenoh bincode wire bytes.
    pub fn encode_alignment_reply(reply: &AlignmentReply) -> Vec<u8> {
        let mut out = Vec::new();
        match reply {
            AlignmentReply::Discovery(zid) => {
                push_u32(&mut out, 0);
                push_string(&mut out, &zid_to_zenoh_hex(zid));
            }
            AlignmentReply::Intervals(map) => {
                push_u32(&mut out, 1);
                push_fingerprint_map(&mut out, map);
            }
            AlignmentReply::SubIntervals(map) => {
                push_u32(&mut out, 2);
                push_sub_fingerprint_map(&mut out, map);
            }
            AlignmentReply::EventsMetadata(events) => {
                push_u32(&mut out, 3);
                push_events(&mut out, events);
            }
            AlignmentReply::Retrieval(e) => {
                push_u32(&mut out, 4);
                push_event_metadata(&mut out, e);
            }
        }
        out
    }

    /// Decode an [`AlignmentReply`] from the zenoh bincode wire bytes; rejects
    /// trailing bytes and an unknown variant tag.
    pub fn decode_alignment_reply(bytes: &[u8]) -> Result<AlignmentReply, AlignmentDecodeError> {
        let mut r = Reader::new(bytes);
        let reply = match r.read_u32()? {
            0 => AlignmentReply::Discovery(
                zenoh_hex_to_zid(&r.read_string()?).ok_or(AlignmentDecodeError::BadZid)?,
            ),
            1 => AlignmentReply::Intervals(r.read_fingerprint_map()?),
            2 => AlignmentReply::SubIntervals(r.read_sub_fingerprint_map()?),
            3 => AlignmentReply::EventsMetadata(r.read_events()?),
            4 => AlignmentReply::Retrieval(r.read_event_metadata()?),
            other => return Err(AlignmentDecodeError::UnknownVariant(other)),
        };
        if r.remaining() != 0 {
            return Err(AlignmentDecodeError::TrailingBytes);
        }
        Ok(reply)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use alloc::string::String;
        use alloc::vec;
        use alloc::vec::Vec;
        use serde::{Deserialize, Serialize};

        // Serde mirrors of zenoh's types, serialized with the real bincode 1.3
        // (dev-dep) as byte-compat ground truth. The newtypes are single-field
        // tuple structs exactly as in uhlc / zenoh, so serde renders each as
        // its inner value (a newtype struct adds no bytes).
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MNtp64(u64);
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MId([u8; 16]);
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MTimestamp {
            time: MNtp64,
            id: MId,
        }
        // zenoh's Action: the wildcard variants carry an OwnedKeyExpr, which
        // serializes as a String. Declaration order fixes the u32 indices
        // (Put=0, Delete=1, WildcardPut=2, WildcardDelete=3).
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum MAction {
            Put,
            Delete,
            WildcardPut(String),
            WildcardDelete(String),
        }
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MEventMetadata {
            stripped_key: Option<String>,
            timestamp: MTimestamp,
            timestamp_last_non_wildcard_update: Option<MTimestamp>,
            action: MAction,
        }

        fn mts(ts: &TimestampHint) -> MTimestamp {
            let mut id = [0u8; 16];
            let n = ts.zid.len().min(16);
            id[..n].copy_from_slice(&ts.zid[..n]);
            MTimestamp {
                time: MNtp64(ts.time),
                id: MId(id),
            }
        }

        fn mirror_of(e: &EventMetadata) -> MEventMetadata {
            MEventMetadata {
                stripped_key: e.key().map(|k| k.into()),
                timestamp: mts(e.timestamp()),
                timestamp_last_non_wildcard_update: e.timestamp_last_non_wildcard_update().map(mts),
                action: match e.action() {
                    Action::Put => MAction::Put,
                    Action::Delete => MAction::Delete,
                    Action::WildcardPut(ke) => MAction::WildcardPut(ke.clone()),
                    Action::WildcardDelete(ke) => MAction::WildcardDelete(ke.clone()),
                },
            }
        }

        fn ts(time: u64, zid: Vec<u8>) -> TimestampHint {
            TimestampHint { time, zid }
        }

        /// THE fidelity test: wz's hand-rolled EventMetadata bytes are
        /// byte-identical to what the real bincode 1.3 (the version + default
        /// config zenoh uses) produces for the equivalent EventMetadata.
        #[test]
        fn encode_event_metadata_is_byte_identical_to_bincode_1_3() {
            let put = EventMetadata::put(
                Some("demo/long/key".into()),
                ts(0x1122_3344_5566_7788, vec![0x01, 0x02, 0x03]),
            );
            assert_eq!(
                encode_event_metadata(&put),
                bincode::serialize(&mirror_of(&put)).unwrap()
            );

            let del = EventMetadata::delete(Some("x".into()), ts(7, vec![0xff; 16]));
            assert_eq!(
                encode_event_metadata(&del),
                bincode::serialize(&mirror_of(&del)).unwrap()
            );

            // R311y64: a `None` stripped_key (a strip-configured mount-root
            // value) encodes byte-identically to bincode's `Option::None` — a
            // single `0` Option tag, then timestamp + tlnwu + action, no key.
            let none_key = EventMetadata::put(None, ts(9, vec![0x07]));
            assert_eq!(
                encode_event_metadata(&none_key),
                bincode::serialize(&mirror_of(&none_key)).unwrap(),
                "a None stripped_key matches bincode Option::None"
            );
            // The encoding starts with the `0` None tag (not the `1` Some tag).
            assert_eq!(encode_event_metadata(&none_key)[0], 0);
        }

        /// Cross-impl interop: wz's bytes are readable by the exact bincode 1.3
        /// zenoh deserializes with, AND bytes bincode 1.3 produces are readable
        /// by wz — both directions.
        #[test]
        fn wz_and_bincode_1_3_read_each_others_event_metadata() {
            let e = EventMetadata::put(Some("demo/a".into()), ts(42, vec![0x09, 0x08]));
            let mirror = mirror_of(&e);

            let wz = encode_event_metadata(&e);
            let read: MEventMetadata =
                bincode::deserialize(&wz).expect("zenoh's bincode reads wz's bytes");
            assert_eq!(read, mirror);

            let zen = bincode::serialize(&mirror).unwrap();
            assert_eq!(decode_event_metadata(&zen), Ok(e));
        }

        #[test]
        fn event_metadata_round_trips() {
            let e = EventMetadata::delete(Some("k".into()), ts(99, vec![0x01]));
            assert_eq!(decode_event_metadata(&encode_event_metadata(&e)), Ok(e));
        }

        #[test]
        fn wildcard_action_round_trips_and_is_byte_identical_to_bincode() {
            // R311wt slice-1: a WildcardDelete/WildcardPut event now DECODES +
            // round-trips (closing the prior UnsupportedAction residual that
            // dropped a whole reply). Its tlnwu is None (a wildcard is not a
            // concrete write), and its bytes match real bincode 1.3 (the serde
            // mirror) for the variant index (2/3) + trailing keyexpr String.
            let wd = EventMetadata::wildcard(
                Some("test/**".into()),
                ts(5, vec![0x02]),
                Action::WildcardDelete("test/**".into()),
            );
            assert_eq!(wd.timestamp_last_non_wildcard_update(), None);
            assert_eq!(
                decode_event_metadata(&encode_event_metadata(&wd)),
                Ok(wd.clone())
            );
            assert_eq!(
                encode_event_metadata(&wd),
                bincode::serialize(&mirror_of(&wd)).unwrap(),
                "a WildcardDelete matches bincode 1.3 (index 3 + keyexpr String, None tlnwu)"
            );
            // bincode -> wz direction explicitly: wz decodes the exact bytes a
            // real zenoh replica (bincode 1.3) emits for a wildcard event.
            assert_eq!(
                decode_event_metadata(&bincode::serialize(&mirror_of(&wd)).unwrap()),
                Ok(wd.clone()),
                "wz decodes real bincode 1.3 WildcardDelete bytes"
            );

            let wp = EventMetadata::wildcard(
                Some("a/**".into()),
                ts(7, vec![0xAB]),
                Action::WildcardPut("a/**".into()),
            );
            assert_eq!(
                decode_event_metadata(&encode_event_metadata(&wp)),
                Ok(wp.clone())
            );
            assert_eq!(
                encode_event_metadata(&wp),
                bincode::serialize(&mirror_of(&wp)).unwrap(),
                "a WildcardPut matches bincode 1.3 (index 2 + keyexpr String)"
            );
        }

        #[test]
        fn decode_rejects_an_unknown_action_index() {
            // An action index >= 4 is still an unknown variant (a Put has no
            // trailing keyexpr String, so patching its action u32 to 4 yields a
            // valid-length buffer with a bad action tag).
            let mut wz =
                encode_event_metadata(&EventMetadata::put(Some("k".into()), ts(1, vec![0x01])));
            let n = wz.len();
            wz[n - 4..].copy_from_slice(&4u32.to_le_bytes());
            assert_eq!(
                decode_event_metadata(&wz),
                Err(AlignmentDecodeError::UnsupportedAction(4))
            );
        }

        #[test]
        fn decode_rejects_trailing_bytes_and_truncation() {
            let mut wz =
                encode_event_metadata(&EventMetadata::put(Some("k".into()), ts(1, vec![0x01])));
            wz.push(0x00);
            assert_eq!(
                decode_event_metadata(&wz),
                Err(AlignmentDecodeError::TrailingBytes)
            );

            let wz2 =
                encode_event_metadata(&EventMetadata::put(Some("k".into()), ts(1, vec![0x01])));
            assert!(decode_event_metadata(&wz2[..3]).is_err());
        }

        #[test]
        fn decode_accepts_a_none_stripped_key() {
            // R311y64: Option tag 0 (None) for stripped_key is a strip-configured
            // mount-root value; it round-trips to an EventMetadata with no key.
            let none_key = EventMetadata::put(None, ts(9, vec![0x07]));
            let bytes = encode_event_metadata(&none_key);
            let decoded = decode_event_metadata(&bytes).expect("a None stripped_key decodes");
            assert_eq!(decoded, none_key);
            assert_eq!(decoded.key(), None, "the mount-root key decodes to None");
        }

        // ---- AlignmentQuery / AlignmentReply envelope cross-checks ----

        use crate::storage_replication::{build_digest, ReplicationConfig};

        // Serde mirrors of the envelope types + their leaf newtypes (the
        // newtypes render as their inner u64, exactly as zenoh's).
        #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct Ii(u64);
        #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
        struct Si(u64);
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Fp(u64);

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MDigestDiff {
            cold_eras_differ: bool,
            warm_eras_differences: BTreeSet<Ii>,
            hot_eras_differences: BTreeMap<Ii, BTreeSet<Si>>,
        }

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum MAlignmentQuery {
            Discovery,
            All,
            Diff(MDigestDiff),
            Intervals(BTreeSet<Ii>),
            SubIntervals(BTreeMap<Ii, BTreeSet<Si>>),
            Events(Vec<MEventMetadata>),
        }

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        enum MAlignmentReply {
            Discovery(String),
            Intervals(BTreeMap<Ii, Fp>),
            SubIntervals(BTreeMap<Ii, BTreeMap<Si, Fp>>),
            EventsMetadata(Vec<MEventMetadata>),
            Retrieval(MEventMetadata),
        }

        fn mirror_diff(d: &DigestDiff) -> MDigestDiff {
            MDigestDiff {
                cold_eras_differ: d.cold_eras_differ(),
                warm_eras_differences: d
                    .warm_eras_differences()
                    .iter()
                    .map(|i| Ii(i.value()))
                    .collect(),
                hot_eras_differences: d
                    .hot_eras_differences()
                    .iter()
                    .map(|(i, subs)| (Ii(i.value()), subs.iter().map(|s| Si(s.value())).collect()))
                    .collect(),
            }
        }

        // A DigestDiff built from two real snapshots (a peer with one extra
        // hot-era key), exercising the hot drill-down path of the diff.
        fn a_digest_diff() -> DigestDiff {
            let cfg = ReplicationConfig::new("demo/**", None, 1000, 2, 2, 2, 250);
            let a = ts(9u64 << 32, vec![0x01]);
            let b = ts((9u64 << 32) | (1u64 << 31), vec![0x01]);
            let local = build_digest(&cfg, [(Some("k/a"), &a)], IntervalIdx::from(10));
            let peer = build_digest(
                &cfg,
                [(Some("k/a"), &a), (Some("k/b"), &b)],
                IntervalIdx::from(10),
            );
            local.diff(peer).expect("the peer's extra key -> a diff")
        }

        #[test]
        fn encode_alignment_query_is_byte_identical_to_bincode_1_3() {
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::Discovery),
                bincode::serialize(&MAlignmentQuery::Discovery).unwrap()
            );
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::All),
                bincode::serialize(&MAlignmentQuery::All).unwrap()
            );

            let diff = a_digest_diff();
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::Diff(diff.clone())),
                bincode::serialize(&MAlignmentQuery::Diff(mirror_diff(&diff))).unwrap()
            );

            let set: BTreeSet<IntervalIdx> = [IntervalIdx::from(2), IntervalIdx::from(9)]
                .into_iter()
                .collect();
            let mset: BTreeSet<Ii> = set.iter().map(|i| Ii(i.value())).collect();
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::Intervals(set)),
                bincode::serialize(&MAlignmentQuery::Intervals(mset)).unwrap()
            );

            let mut sub: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> = BTreeMap::new();
            sub.insert(
                IntervalIdx::from(9),
                [SubIntervalIdx::from(0), SubIntervalIdx::from(1)]
                    .into_iter()
                    .collect(),
            );
            let msub: BTreeMap<Ii, BTreeSet<Si>> = sub
                .iter()
                .map(|(i, s)| (Ii(i.value()), s.iter().map(|x| Si(x.value())).collect()))
                .collect();
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::SubIntervals(sub)),
                bincode::serialize(&MAlignmentQuery::SubIntervals(msub)).unwrap()
            );

            let events = vec![
                EventMetadata::put(Some("k/a".into()), ts(42, vec![1, 2])),
                EventMetadata::delete(Some("k/b".into()), ts(43, vec![3])),
            ];
            let mevents: Vec<MEventMetadata> = events.iter().map(mirror_of).collect();
            assert_eq!(
                encode_alignment_query(&AlignmentQuery::Events(events)),
                bincode::serialize(&MAlignmentQuery::Events(mevents)).unwrap()
            );
        }

        #[test]
        fn encode_alignment_reply_is_byte_identical_to_bincode_1_3() {
            // Discovery: zenoh serializes the ZenohId as a hex String; the
            // expected hex is hand-computed from uhlc's Display (LE bytes read
            // as a u128, big-endian hex) so this is not circular.
            assert_eq!(
                encode_alignment_reply(&AlignmentReply::Discovery(vec![0x1a, 0x2b, 0x3c])),
                bincode::serialize(&MAlignmentReply::Discovery("3c2b1a".into())).unwrap()
            );

            let mut ivl: BTreeMap<IntervalIdx, Fingerprint> = BTreeMap::new();
            ivl.insert(IntervalIdx::from(2), Fingerprint::from(0xAA));
            ivl.insert(IntervalIdx::from(7), Fingerprint::from(0xBB));
            let mivl: BTreeMap<Ii, Fp> = ivl
                .iter()
                .map(|(i, f)| (Ii(i.value()), Fp(f.value())))
                .collect();
            assert_eq!(
                encode_alignment_reply(&AlignmentReply::Intervals(ivl)),
                bincode::serialize(&MAlignmentReply::Intervals(mivl)).unwrap()
            );

            let mut subs: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> =
                BTreeMap::new();
            let mut inner = BTreeMap::new();
            inner.insert(SubIntervalIdx::from(0), Fingerprint::from(9));
            inner.insert(SubIntervalIdx::from(1), Fingerprint::from(10));
            subs.insert(IntervalIdx::from(9), inner);
            let msubs: BTreeMap<Ii, BTreeMap<Si, Fp>> = subs
                .iter()
                .map(|(i, m)| {
                    (
                        Ii(i.value()),
                        m.iter()
                            .map(|(s, f)| (Si(s.value()), Fp(f.value())))
                            .collect(),
                    )
                })
                .collect();
            assert_eq!(
                encode_alignment_reply(&AlignmentReply::SubIntervals(subs)),
                bincode::serialize(&MAlignmentReply::SubIntervals(msubs)).unwrap()
            );

            let meta = EventMetadata::put(Some("k/r".into()), ts(7, vec![0x05]));
            assert_eq!(
                encode_alignment_reply(&AlignmentReply::Retrieval(meta.clone())),
                bincode::serialize(&MAlignmentReply::Retrieval(mirror_of(&meta))).unwrap()
            );

            let events = vec![EventMetadata::delete(Some("k/x".into()), ts(1, vec![0x01]))];
            let mevents: Vec<MEventMetadata> = events.iter().map(mirror_of).collect();
            assert_eq!(
                encode_alignment_reply(&AlignmentReply::EventsMetadata(events)),
                bincode::serialize(&MAlignmentReply::EventsMetadata(mevents)).unwrap()
            );
        }

        #[test]
        fn wz_and_bincode_1_3_read_each_others_alignment_query() {
            let diff = a_digest_diff();
            let q = AlignmentQuery::Diff(diff.clone());
            let mirror = MAlignmentQuery::Diff(mirror_diff(&diff));

            let wz = encode_alignment_query(&q);
            let read: MAlignmentQuery =
                bincode::deserialize(&wz).expect("zenoh's bincode reads wz's query bytes");
            assert_eq!(read, mirror);

            let zen = bincode::serialize(&mirror).unwrap();
            assert_eq!(decode_alignment_query(&zen), Ok(q));
        }

        #[test]
        fn wz_and_bincode_1_3_read_each_others_alignment_reply() {
            let mut subs: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> =
                BTreeMap::new();
            let mut inner = BTreeMap::new();
            inner.insert(SubIntervalIdx::from(2), Fingerprint::from(0xDEAD));
            subs.insert(IntervalIdx::from(9), inner);
            let reply = AlignmentReply::SubIntervals(subs.clone());
            let msubs: BTreeMap<Ii, BTreeMap<Si, Fp>> = subs
                .iter()
                .map(|(i, m)| {
                    (
                        Ii(i.value()),
                        m.iter()
                            .map(|(s, f)| (Si(s.value()), Fp(f.value())))
                            .collect(),
                    )
                })
                .collect();
            let mirror = MAlignmentReply::SubIntervals(msubs);

            let wz = encode_alignment_reply(&reply);
            let read: MAlignmentReply =
                bincode::deserialize(&wz).expect("zenoh's bincode reads wz's reply bytes");
            assert_eq!(read, mirror);

            let zen = bincode::serialize(&mirror).unwrap();
            assert_eq!(decode_alignment_reply(&zen), Ok(reply));
        }

        #[test]
        fn alignment_query_round_trips_every_variant() {
            let diff = a_digest_diff();
            let mut sub: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> = BTreeMap::new();
            sub.insert(
                IntervalIdx::from(9),
                [SubIntervalIdx::from(1)].into_iter().collect(),
            );
            for q in [
                AlignmentQuery::Discovery,
                AlignmentQuery::All,
                AlignmentQuery::Diff(diff),
                AlignmentQuery::Intervals([IntervalIdx::from(3)].into_iter().collect()),
                AlignmentQuery::SubIntervals(sub),
                AlignmentQuery::Events(vec![EventMetadata::put(
                    Some("k".into()),
                    ts(5, vec![0x01]),
                )]),
            ] {
                assert_eq!(decode_alignment_query(&encode_alignment_query(&q)), Ok(q));
            }
        }

        #[test]
        fn alignment_reply_round_trips_every_variant() {
            let mut ivl = BTreeMap::new();
            ivl.insert(IntervalIdx::from(2), Fingerprint::from(7));
            let mut subs = BTreeMap::new();
            let mut inner = BTreeMap::new();
            inner.insert(SubIntervalIdx::from(0), Fingerprint::from(8));
            subs.insert(IntervalIdx::from(9), inner);
            for r in [
                AlignmentReply::Discovery(vec![0x1a, 0x2b, 0x3c]),
                AlignmentReply::Intervals(ivl),
                AlignmentReply::SubIntervals(subs),
                AlignmentReply::EventsMetadata(vec![EventMetadata::delete(
                    Some("k".into()),
                    ts(5, vec![0x01]),
                )]),
                AlignmentReply::Retrieval(EventMetadata::put(Some("k".into()), ts(6, vec![0x02]))),
            ] {
                assert_eq!(decode_alignment_reply(&encode_alignment_reply(&r)), Ok(r));
            }
        }

        #[test]
        fn discovery_zid_hex_matches_uhlc_display() {
            // LE bytes read as a u128 then big-endian hex => the bytes appear
            // reversed; a single leading zero is stripped.
            assert_eq!(zid_to_zenoh_hex(&[0x1a, 0x2b, 0x3c]), "3c2b1a");
            assert_eq!(zid_to_zenoh_hex(&[0x0a]), "a");
            assert_eq!(zid_to_zenoh_hex(&[0x01]), "1");
        }

        #[test]
        fn decode_rejects_an_unknown_envelope_variant() {
            // Query tag 6 (no variant) / reply tag 5 (no variant).
            assert_eq!(
                decode_alignment_query(&6u32.to_le_bytes()),
                Err(AlignmentDecodeError::UnknownVariant(6))
            );
            assert_eq!(
                decode_alignment_reply(&5u32.to_le_bytes()),
                Err(AlignmentDecodeError::UnknownVariant(5))
            );
        }
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
        let p = EventMetadata::put(Some("demo/a".into()), ts(100, 1));
        assert_eq!(p.key(), Some("demo/a"));
        assert_eq!(p.timestamp(), &ts(100, 1));
        assert_eq!(*p.action(), Action::Put);

        let d = EventMetadata::delete(Some("demo/a".into()), ts(101, 1));
        assert_eq!(d.key(), Some("demo/a"));
        assert_eq!(d.timestamp(), &ts(101, 1));
        assert_eq!(*d.action(), Action::Delete);
    }

    #[test]
    fn fingerprint_is_the_digest_event_fingerprint_ssot() {
        // The aligner identity is byte-identical to the digest's per-event
        // fingerprint, so an event and a peer's copy of it agree.
        let meta = EventMetadata::put(Some("demo/a".into()), ts(100, 1));
        assert_eq!(
            meta.fingerprint(),
            event_fingerprint(Some("demo/a"), &ts(100, 1))
        );
    }

    #[test]
    fn fingerprint_ignores_the_action() {
        // A Put and a Delete at the same (key, timestamp) hash identically —
        // the action is not part of the fingerprint (log.rs:226-231).
        let put = EventMetadata::put(Some("demo/a".into()), ts(100, 1));
        let del = EventMetadata::delete(Some("demo/a".into()), ts(100, 1));
        assert_eq!(put.fingerprint(), del.fingerprint());
        // ...yet they are distinct events: equality keeps the action.
        assert_ne!(put, del);
    }

    #[test]
    fn fingerprint_is_field_sensitive_in_key_and_timestamp() {
        let base = EventMetadata::put(Some("demo/a".into()), ts(100, 1)).fingerprint();
        assert_ne!(
            base,
            EventMetadata::put(Some("demo/b".into()), ts(100, 1)).fingerprint()
        );
        assert_ne!(
            base,
            EventMetadata::put(Some("demo/a".into()), ts(101, 1)).fingerprint()
        );
        assert_ne!(
            base,
            EventMetadata::put(Some("demo/a".into()), ts(100, 2)).fingerprint()
        );
    }

    #[test]
    fn equality_distinguishes_every_field() {
        let base = EventMetadata::put(Some("demo/a".into()), ts(100, 1));
        assert_eq!(base, EventMetadata::put(Some("demo/a".into()), ts(100, 1)));
        assert_ne!(base, EventMetadata::put(Some("demo/b".into()), ts(100, 1)));
        assert_ne!(base, EventMetadata::put(Some("demo/a".into()), ts(101, 1)));
        assert_ne!(
            base,
            EventMetadata::delete(Some("demo/a".into()), ts(100, 1))
        );
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
            EventMetadata::put(Some("k/cold2".into()), at(2, 0)),
            EventMetadata::put(Some("k/cold3".into()), at(3, 1)),
            EventMetadata::put(Some("k/warm7".into()), at(7, 0)),
            EventMetadata::put(Some("k/hot9a".into()), at(9, 0)),
            EventMetadata::put(Some("k/hot9b".into()), at(9, 1)),
            // A tombstone is a first-class aligner event too.
            EventMetadata::delete(Some("k/hot10".into()), at(10, 0)),
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
        assert!(got.contains(&EventMetadata::put(Some("k/hot9a".into()), at(9, 0))));
        assert!(got.contains(&EventMetadata::put(Some("k/hot9b".into()), at(9, 1))));
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

        let kt: Vec<(Option<alloc::string::String>, TimestampHint)> = events
            .iter()
            .map(|e| (e.key().map(ToString::to_string), e.timestamp().clone()))
            .collect();
        let digest = build_digest(&cfg, kt.iter().map(|(k, t)| (k.as_deref(), t)), hot_upper);
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

    // --- AlignmentQuery / AlignmentReply (the protocol vocabulary) ---

    fn a_digest_diff() -> DigestDiff {
        let cfg = cfg2();
        let hot_upper = IntervalIdx::from(10);
        let local = build_digest(&cfg, [(Some("k/a"), &at(9, 0))], hot_upper);
        let peer = build_digest(
            &cfg,
            [(Some("k/a"), &at(9, 0)), (Some("k/b"), &at(9, 1))],
            hot_upper,
        );
        local
            .diff(peer)
            .expect("the peer holds an extra key -> a diff exists")
    }

    #[test]
    fn alignment_query_variants_are_distinct_and_self_equal() {
        let diff = a_digest_diff();
        let q_diff = AlignmentQuery::Diff(diff.clone());
        let q_intervals = AlignmentQuery::Intervals([IntervalIdx::from(9)].into_iter().collect());
        let mut sub_map: BTreeMap<IntervalIdx, BTreeSet<SubIntervalIdx>> = BTreeMap::new();
        sub_map.insert(
            IntervalIdx::from(9),
            [SubIntervalIdx::from(0)].into_iter().collect(),
        );
        let q_subs = AlignmentQuery::SubIntervals(sub_map);
        let q_events =
            AlignmentQuery::Events(vec![EventMetadata::put(Some("k/a".into()), at(9, 0))]);

        // self-equal (incl. through Clone)
        assert_eq!(AlignmentQuery::Discovery, AlignmentQuery::Discovery);
        assert_eq!(AlignmentQuery::All, AlignmentQuery::All);
        assert_eq!(q_diff, AlignmentQuery::Diff(diff));
        assert_eq!(q_intervals.clone(), q_intervals);

        // distinct variants
        assert_ne!(AlignmentQuery::Discovery, AlignmentQuery::All);
        assert_ne!(q_intervals, q_subs);
        assert_ne!(q_subs, q_events);
    }

    #[test]
    fn alignment_reply_variants_are_distinct_and_self_equal() {
        let r_disc = AlignmentReply::Discovery(vec![0x01, 0xab]);
        let mut ivl = BTreeMap::new();
        ivl.insert(IntervalIdx::from(2), Fingerprint::from(7u64));
        let r_ivl = AlignmentReply::Intervals(ivl.clone());
        let mut subs: BTreeMap<IntervalIdx, BTreeMap<SubIntervalIdx, Fingerprint>> =
            BTreeMap::new();
        let mut inner = BTreeMap::new();
        inner.insert(SubIntervalIdx::from(0), Fingerprint::from(9u64));
        subs.insert(IntervalIdx::from(9), inner);
        let r_subs = AlignmentReply::SubIntervals(subs);
        let r_meta = AlignmentReply::EventsMetadata(vec![EventMetadata::delete(
            Some("k/x".into()),
            at(9, 0),
        )]);
        let r_ret = AlignmentReply::Retrieval(EventMetadata::put(Some("k/y".into()), at(9, 1)));

        // self-equal
        assert_eq!(r_disc, AlignmentReply::Discovery(vec![0x01, 0xab]));
        assert_eq!(r_ivl, AlignmentReply::Intervals(ivl));

        // distinct
        assert_ne!(r_disc, AlignmentReply::Discovery(vec![0x02]));
        assert_ne!(r_subs, r_meta);
        assert_ne!(r_meta, r_ret);
    }
}
