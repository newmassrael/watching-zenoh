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
    event_fingerprint, DigestDiff, Fingerprint, IntervalIdx, ReplicationConfig, SubIntervalIdx,
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
/// wz emits `stripped_key = Some(key)` (no strip_prefix, so the key is always
/// present) and `timestamp_last_non_wildcard_update = Some(timestamp)`
/// (re-supplying the field wz's kernel type omits — with no wildcard updates it
/// always equals `timestamp`). wz emits only `action` 0/1 (Put/Delete). On
/// decode it discards `timestamp_last_non_wildcard_update` (wildcard-only) and
/// rejects an inbound wildcard action (2/3) or a `None` stripped_key with a
/// typed error — the named non-converging residual until wz storage gains
/// wildcard updates / strip_prefix.
pub mod wire {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{Action, EventMetadata};
    use crate::sample::TimestampHint;
    use crate::storage_state::zid_to_le_array;

    /// Failure decoding an aligner wire structure from bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AlignmentDecodeError {
        /// The buffer ended before a fixed-width field could be read.
        UnexpectedEof,
        /// A length prefix exceeds the bytes that remain — corrupt or hostile.
        LengthOverflow,
        /// Bytes remained after a complete structure was decoded.
        TrailingBytes,
        /// An `Option` tag byte that was neither 0 nor 1.
        BadOptionTag(u8),
        /// An `Action` variant index wz cannot represent: 2 (WildcardPut) or
        /// 3 (WildcardDelete) — wz storage has no wildcard updates — or an
        /// unknown index. The named non-converging residual for a real zenoh
        /// wildcard event.
        UnsupportedAction(u32),
        /// A `None` stripped_key (a zenoh strip-prefix-exact match); wz carries
        /// no strip_prefix, so its key is always present.
        MissingKey,
        /// A stripped_key whose bytes are not valid UTF-8.
        BadUtf8,
    }

    fn push_u32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn push_string(out: &mut Vec<u8>, s: &str) {
        push_u64(out, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
    }

    /// A [`TimestampHint`] as zenoh's bincode `Timestamp`: the NTP64 time word
    /// (u64 LE), then the 16-byte zero-padded id ([`zid_to_le_array`], the SSOT
    /// shared with the newer-wins comparator and the event fingerprint).
    fn push_timestamp(out: &mut Vec<u8>, ts: &TimestampHint) {
        push_u64(out, ts.time);
        out.extend_from_slice(&zid_to_le_array(&ts.zid));
    }

    fn push_event_metadata(out: &mut Vec<u8>, e: &EventMetadata) {
        out.push(1); // stripped_key: Some
        push_string(out, e.key());
        push_timestamp(out, e.timestamp());
        out.push(1); // timestamp_last_non_wildcard_update: Some(timestamp)
        push_timestamp(out, e.timestamp());
        push_u32(
            out,
            match e.action() {
                Action::Put => 0,
                Action::Delete => 1,
            },
        );
    }

    /// Encode one [`EventMetadata`] to the zenoh bincode wire bytes.
    pub fn encode_event_metadata(e: &EventMetadata) -> Vec<u8> {
        let mut out = Vec::new();
        push_event_metadata(&mut out, e);
        out
    }

    /// A cursor over the input bytes that reads fixed-width little-endian
    /// fields and refuses to read past the end.
    struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn remaining(&self) -> usize {
            self.buf.len() - self.pos
        }

        fn read_u8(&mut self) -> Result<u8, AlignmentDecodeError> {
            let b = *self
                .buf
                .get(self.pos)
                .ok_or(AlignmentDecodeError::UnexpectedEof)?;
            self.pos += 1;
            Ok(b)
        }

        fn read_u32(&mut self) -> Result<u32, AlignmentDecodeError> {
            let slice = self.read_bytes(4)?;
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(slice);
            Ok(u32::from_le_bytes(bytes))
        }

        fn read_u64(&mut self) -> Result<u64, AlignmentDecodeError> {
            let slice = self.read_bytes(8)?;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(slice);
            Ok(u64::from_le_bytes(bytes))
        }

        fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], AlignmentDecodeError> {
            let end = self
                .pos
                .checked_add(n)
                .ok_or(AlignmentDecodeError::UnexpectedEof)?;
            let slice = self
                .buf
                .get(self.pos..end)
                .ok_or(AlignmentDecodeError::UnexpectedEof)?;
            self.pos = end;
            Ok(slice)
        }

        /// Read a bincode `String`: a u64 length then that many UTF-8 bytes
        /// (the length is guarded against the remaining buffer before slicing,
        /// so a hostile length fails fast instead of allocating).
        fn read_string(&mut self) -> Result<String, AlignmentDecodeError> {
            let len = self.read_u64()?;
            let len: usize = len
                .try_into()
                .map_err(|_| AlignmentDecodeError::LengthOverflow)?;
            if len > self.remaining() {
                return Err(AlignmentDecodeError::LengthOverflow);
            }
            let slice = self.read_bytes(len)?;
            core::str::from_utf8(slice)
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

        /// Read an `Option` tag: 0 => None, 1 => Some, anything else => error.
        fn read_option_tag(&mut self) -> Result<bool, AlignmentDecodeError> {
            match self.read_u8()? {
                0 => Ok(false),
                1 => Ok(true),
                other => Err(AlignmentDecodeError::BadOptionTag(other)),
            }
        }

        fn read_event_metadata(&mut self) -> Result<EventMetadata, AlignmentDecodeError> {
            // stripped_key: Option<OwnedKeyExpr>. wz has no strip_prefix, so a
            // `None` key cannot be represented.
            let key = if self.read_option_tag()? {
                self.read_string()?
            } else {
                return Err(AlignmentDecodeError::MissingKey);
            };
            let timestamp = self.read_timestamp()?;
            // timestamp_last_non_wildcard_update: discarded (wildcard-only).
            if self.read_option_tag()? {
                let _ = self.read_timestamp()?;
            }
            let action = match self.read_u32()? {
                0 => Action::Put,
                1 => Action::Delete,
                other => return Err(AlignmentDecodeError::UnsupportedAction(other)),
            };
            Ok(EventMetadata {
                key,
                timestamp,
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
                stripped_key: Some(e.key().into()),
                timestamp: mts(e.timestamp()),
                timestamp_last_non_wildcard_update: Some(mts(e.timestamp())),
                action: match e.action() {
                    Action::Put => MAction::Put,
                    Action::Delete => MAction::Delete,
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
                "demo/long/key",
                ts(0x1122_3344_5566_7788, vec![0x01, 0x02, 0x03]),
            );
            assert_eq!(
                encode_event_metadata(&put),
                bincode::serialize(&mirror_of(&put)).unwrap()
            );

            let del = EventMetadata::delete("x", ts(7, vec![0xff; 16]));
            assert_eq!(
                encode_event_metadata(&del),
                bincode::serialize(&mirror_of(&del)).unwrap()
            );
        }

        /// Cross-impl interop: wz's bytes are readable by the exact bincode 1.3
        /// zenoh deserializes with, AND bytes bincode 1.3 produces are readable
        /// by wz — both directions.
        #[test]
        fn wz_and_bincode_1_3_read_each_others_event_metadata() {
            let e = EventMetadata::put("demo/a", ts(42, vec![0x09, 0x08]));
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
            let e = EventMetadata::delete("k", ts(99, vec![0x01]));
            assert_eq!(decode_event_metadata(&encode_event_metadata(&e)), Ok(e));
        }

        #[test]
        fn decode_rejects_a_wildcard_action_as_unsupported() {
            // A real zenoh WildcardPut(=2) event: wz cannot represent it.
            let mut wz = encode_event_metadata(&EventMetadata::put("k", ts(1, vec![0x01])));
            let n = wz.len();
            wz[n - 4..].copy_from_slice(&2u32.to_le_bytes());
            assert_eq!(
                decode_event_metadata(&wz),
                Err(AlignmentDecodeError::UnsupportedAction(2))
            );
        }

        #[test]
        fn decode_rejects_trailing_bytes_and_truncation() {
            let mut wz = encode_event_metadata(&EventMetadata::put("k", ts(1, vec![0x01])));
            wz.push(0x00);
            assert_eq!(
                decode_event_metadata(&wz),
                Err(AlignmentDecodeError::TrailingBytes)
            );

            let wz2 = encode_event_metadata(&EventMetadata::put("k", ts(1, vec![0x01])));
            assert!(decode_event_metadata(&wz2[..3]).is_err());
        }

        #[test]
        fn decode_rejects_a_none_stripped_key() {
            // Option tag 0 (None) for stripped_key -> wz has no strip_prefix.
            assert_eq!(
                decode_event_metadata(&[0u8]),
                Err(AlignmentDecodeError::MissingKey)
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

    // --- AlignmentQuery / AlignmentReply (the protocol vocabulary) ---

    fn a_digest_diff() -> DigestDiff {
        let cfg = cfg2();
        let hot_upper = IntervalIdx::from(10);
        let local = build_digest(&cfg, [("k/a", &at(9, 0))], hot_upper);
        let peer = build_digest(&cfg, [("k/a", &at(9, 0)), ("k/b", &at(9, 1))], hot_upper);
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
        let q_events = AlignmentQuery::Events(vec![EventMetadata::put("k/a", at(9, 0))]);

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
        let r_meta = AlignmentReply::EventsMetadata(vec![EventMetadata::delete("k/x", at(9, 0))]);
        let r_ret = AlignmentReply::Retrieval(EventMetadata::put("k/y", at(9, 1)));

        // self-equal
        assert_eq!(r_disc, AlignmentReply::Discovery(vec![0x01, 0xab]));
        assert_eq!(r_ivl, AlignmentReply::Intervals(ivl));

        // distinct
        assert_ne!(r_disc, AlignmentReply::Discovery(vec![0x02]));
        assert_ne!(r_subs, r_meta);
        assert_ne!(r_meta, r_ret);
    }
}
