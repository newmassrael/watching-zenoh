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

use alloc::string::String;

use crate::sample::TimestampHint;
use crate::storage_replication::{event_fingerprint, Fingerprint};

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
}
