// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.21 `routing-interest-pending-gc` — the PENDING-CURRENT-INTEREST table a
//! p2p_peer-shaped broker keeps for a downstream client's CURRENT interest, and
//! the GC that unwedges that client when an upstream goes silent.
//!
//! ## What the table is for
//!
//! zenoh's `p2p_peer` hat, on receiving a CURRENT interest from a **Client**
//! face, does not answer it and close it: it PROPAGATES the interest to each
//! upstream face and holds an `Arc<CurrentInterest>` shared across every
//! propagated copy (`hat/p2p_peer/interests.rs:142-206` at 49c8a53). The
//! terminating `DeclareFinal` to the client is emitted only when
//! `Arc::into_inner` succeeds — that is, when the LAST upstream has answered
//! (`dispatcher/interests.rs:106-129` `finalize_pending_interest`). Until then
//! the client's `z_liveliness_get` (or any CURRENT solicitation) stays open, so
//! a token that only an upstream holds can still reach it.
//!
//! Three events retire a pending entry, and this module models all three:
//!
//! 1. the upstream's own `Declare(DeclFinal)` carrying the propagated id
//!    (`dispatcher/interests.rs:79-94` `declare_final`) — [`resolve`];
//! 2. the upstream FACE dying before it answered
//!    (`finalize_pending_interests`, :96-104) — [`drain_face`];
//! 3. the interest TIMEOUT — `CurrentInterestCleanup` (:131-188), the GC this
//!    atom is named for — [`expired`].
//!
//! All three converge on the same act: drop this upstream's reference and, when
//! it was the last one for that downstream interest, hand the caller the
//! [`CurrentInterest`] so it can send the `DeclareFinal` DOWNSTREAM. That is the
//! one place a wz-side interest unwind puts bytes on the wire toward a REMOTE
//! face, which is what makes the atom foreign-observable at all.
//!
//! ## Why a refcount and not one entry per client interest
//!
//! One client interest fans out to N upstreams, and the client must see exactly
//! ONE `DeclareFinal` — after the last upstream, not the first. zenoh gets this
//! from `Arc` strong counts; wz has no shared ownership here (the forwarder is a
//! single-threaded actor holding everything in `RefCell`s), so the count is
//! explicit: [`outstanding`](PendingCurrentInterests::outstanding) maps the
//! DOWNSTREAM key to how many upstream entries still reference it, and only the
//! transition to zero yields a [`CurrentInterest`].
//!
//! ## Clock
//!
//! Deadlines are stamped as `Instant`s from the forwarder's injectable clock —
//! the same one the pending-QUERY sweep uses — so a unit test can advance
//! virtual time and assert an entry is reaped AT, not before, its deadline.

use std::collections::HashMap;
use std::time::Instant;

use crate::accept_loop::FaceId;

/// The DOWNSTREAM interest a set of propagated upstream interests unwinds to —
/// zenoh's `CurrentInterest` (`dispatcher/interests.rs:45-49`), minus the `Arc`
/// (see the module doc: the refcount is explicit here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CurrentInterest {
    /// The face the client's interest arrived on — zenoh's `src_face`. REMOTE,
    /// which is the whole point: the unwind crosses the wire.
    pub(crate) src_face: FaceId,
    /// The interest id the CLIENT chose. Every reply relayed downstream, and the
    /// terminating `DeclareFinal`, must carry THIS id — not the id this node
    /// minted for the upstream copy (zenoh `token.rs:214`,
    /// `interest_id: Some(interest.src_interest_id)`).
    pub(crate) src_interest_id: u64,
    /// Whether the client asked `CurrentFuture` (vs `Current` alone). zenoh
    /// registers an upstream-relayed token locally only in the CurrentFuture case
    /// (`hat/p2p_peer/token.rs:200-202`); carried here so the caller can make the
    /// same distinction without a second lookup.
    pub(crate) current_future: bool,
}

/// One propagated upstream copy of a downstream client's CURRENT interest.
struct PendingEntry {
    interest: CurrentInterest,
    /// The instant [`expired`](PendingCurrentInterests::expired) abandons this
    /// entry at — zenoh's `interests_timeout` applied per propagated copy.
    deadline: Instant,
}

/// The per-node pending-current-interest table. Keyed by
/// `(upstream face, the interest id THIS node minted for that face)`, which is
/// how an inbound `Declare` on that face is matched back to the client that is
/// waiting (zenoh keys it per-`FaceState`; one flat map is the same relation).
#[derive(Default)]
pub(crate) struct PendingCurrentInterests {
    pending: HashMap<(FaceId, u64), PendingEntry>,
    /// DOWNSTREAM key -> how many `pending` entries still reference it. The
    /// explicit stand-in for zenoh's `Arc` strong count.
    outstanding: HashMap<(FaceId, u64), usize>,
    /// The id generator for propagated copies. Monotonic per node, never reused
    /// while an entry holds it (zenoh's per-face `next_id` counter).
    next_id: u64,
    /// Count of entries abandoned by [`expired`] — the GC witness, the interest
    /// twin of the pending-QUERY sweep's `timed_out`.
    timed_out: usize,
}

impl PendingCurrentInterests {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Mint the interest id for one propagated upstream copy.
    ///
    /// Starts at 1: id 0 is what a `Declare` with no `interest_id` decodes to in
    /// several wz builders, so leaving it unused keeps "no id" and "id 0"
    /// distinguishable at every lookup site.
    pub(crate) fn allocate_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Record that `up_id` was propagated to `upstream` on behalf of the client
    /// interest `(src_face, src_interest_id)`.
    pub(crate) fn insert(
        &mut self,
        upstream: FaceId,
        up_id: u64,
        interest: CurrentInterest,
        deadline: Instant,
    ) {
        *self
            .outstanding
            .entry((interest.src_face, interest.src_interest_id))
            .or_insert(0) += 1;
        self.pending
            .insert((upstream, up_id), PendingEntry { interest, deadline });
    }

    /// The downstream interest an inbound reply on `(upstream, up_id)` belongs
    /// to, WITHOUT retiring the entry — the lookup zenoh does before rewriting a
    /// `DeclareToken`'s `interest_id` to the client's own
    /// (`hat/p2p_peer/token.rs:199-204`). A reply may arrive many times before
    /// the terminating final, so this must not consume.
    pub(crate) fn lookup(&self, upstream: FaceId, up_id: u64) -> Option<&CurrentInterest> {
        self.pending.get(&(upstream, up_id)).map(|e| &e.interest)
    }

    /// Retire the entry for `(upstream, up_id)` — the upstream answered.
    ///
    /// Returns the downstream interest ONLY when this was its last outstanding
    /// upstream, i.e. only when the caller now owes the client its single
    /// `DeclareFinal`. An unknown key is a no-op returning `None` (a duplicate or
    /// unsolicited final, which zenoh likewise ignores).
    pub(crate) fn resolve(&mut self, upstream: FaceId, up_id: u64) -> Option<CurrentInterest> {
        let entry = self.pending.remove(&(upstream, up_id))?;
        self.release(entry.interest)
    }

    /// Drop `face` from BOTH roles it can hold in this table.
    ///
    /// As an UPSTREAM: every entry propagated to it is retired, and each one that
    /// was its downstream's last yields a `CurrentInterest` the caller must
    /// finalize — zenoh's `finalize_pending_interests` on face close, which is
    /// what stops a client waiting out a full timeout for a peer that is already
    /// gone. As the DOWNSTREAM: its entries are dropped with nobody to notify
    /// (the client IS the departed face), so they are never returned.
    pub(crate) fn drain_face(&mut self, face: FaceId) -> Vec<CurrentInterest> {
        let keys: Vec<(FaceId, u64)> = self
            .pending
            .keys()
            .filter(|(up, _)| *up == face)
            .cloned()
            .collect();
        let mut finalize = Vec::new();
        for k in keys {
            if let Some(entry) = self.pending.remove(&k) {
                if let Some(i) = self.release(entry.interest) {
                    finalize.push(i);
                }
            }
        }
        // The departed face as the DOWNSTREAM: retire its entries silently. Done
        // second so an entry that is both (a face brokering to ITSELF cannot
        // occur, but the ordering is stated rather than assumed) is already gone.
        let orphaned: Vec<(FaceId, u64)> = self
            .pending
            .iter()
            .filter(|(_, e)| e.interest.src_face == face)
            .map(|(k, _)| *k)
            .collect();
        for k in orphaned {
            if let Some(entry) = self.pending.remove(&k) {
                let _ = self.release(entry.interest);
            }
        }
        finalize.retain(|i| i.src_face != face);
        finalize
    }

    /// THE GC: abandon every entry whose deadline has passed and hand back the
    /// downstream interests that are now fully unwound.
    ///
    /// zenoh's `CurrentInterestCleanup::execute` (`dispatcher/interests.rs:166`)
    /// per entry; wz sweeps them from the forwarder tick, so one call covers the
    /// whole table. An empty table is a cheap no-op — the sweep sends nothing.
    pub(crate) fn expired(&mut self, now: Instant) -> Vec<CurrentInterest> {
        let due: Vec<(FaceId, u64)> = self
            .pending
            .iter()
            .filter(|(_, e)| e.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        let mut finalize = Vec::new();
        for k in due {
            if let Some(entry) = self.pending.remove(&k) {
                self.timed_out += 1;
                if let Some(i) = self.release(entry.interest) {
                    finalize.push(i);
                }
            }
        }
        finalize
    }

    /// Decrement the downstream refcount; yield the interest on the 1 -> 0 edge.
    fn release(&mut self, interest: CurrentInterest) -> Option<CurrentInterest> {
        let key = (interest.src_face, interest.src_interest_id);
        let slot = self.outstanding.get_mut(&key)?;
        *slot -= 1;
        if *slot == 0 {
            self.outstanding.remove(&key);
            return Some(interest);
        }
        None
    }

    /// Number of propagated copies still awaiting an upstream answer.
    pub(crate) fn len(&self) -> usize {
        self.pending.len()
    }

    /// Entries the GC has abandoned since this node started.
    pub(crate) fn timed_out(&self) -> usize {
        self.timed_out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn face(n: u64) -> FaceId {
        FaceId(n)
    }

    fn interest(src: FaceId, id: u64) -> CurrentInterest {
        CurrentInterest {
            src_face: src,
            src_interest_id: id,
            current_future: false,
        }
    }

    /// The FAN invariant: a client interest propagated to TWO upstreams unwinds
    /// once, after the SECOND answers — never after the first. This is zenoh's
    /// `Arc::into_inner` gate, and getting it wrong sends the client a premature
    /// `DeclareFinal` that closes its get while an upstream is still replying.
    #[test]
    fn a_two_upstream_fan_unwinds_only_on_the_last_answer() {
        let mut t = PendingCurrentInterests::new();
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let a = t.allocate_id();
        let b = t.allocate_id();
        assert_ne!(a, b, "each propagated copy gets its own id");
        t.insert(face(10), a, interest(face(1), 7), deadline);
        t.insert(face(11), b, interest(face(1), 7), deadline);
        assert_eq!(t.len(), 2);

        assert_eq!(
            t.resolve(face(10), a),
            None,
            "the FIRST upstream's final must not terminate the client"
        );
        assert_eq!(
            t.resolve(face(11), b),
            Some(interest(face(1), 7)),
            "the LAST upstream's final unwinds to the client"
        );
        assert_eq!(t.len(), 0);
        assert_eq!(t.timed_out(), 0, "a fully answered fan times nothing out");
    }

    /// THE GC ARM: an upstream that never answers is abandoned at its deadline —
    /// not before — and the client is finalized anyway. Without this the client
    /// waits forever, because zenoh-pico's CURRENT interest carries no timeout of
    /// its own (`vendor/zenoh-pico/src/net/liveliness.c:348`).
    #[test]
    fn a_silent_upstream_is_abandoned_at_its_deadline_and_the_client_finalized() {
        let mut t = PendingCurrentInterests::new();
        let base = Instant::now();
        let id = t.allocate_id();
        t.insert(
            face(10),
            id,
            interest(face(1), 7),
            base + Duration::from_secs(5),
        );

        assert!(
            t.expired(base + Duration::from_secs(4)).is_empty(),
            "reaped BEFORE the deadline — the sweep must be deadline-driven"
        );
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.expired(base + Duration::from_secs(5)),
            vec![interest(face(1), 7)],
            "at the deadline the client is finalized by the GC"
        );
        assert_eq!(t.len(), 0);
        assert_eq!(
            t.timed_out(),
            1,
            "the GC witness counts the abandoned entry"
        );
    }

    /// A partially-answered fan: one upstream answers, the other goes silent. The
    /// client is finalized exactly once, by the GC, at the silent one's deadline.
    #[test]
    fn a_partly_answered_fan_is_finalized_once_by_the_gc() {
        let mut t = PendingCurrentInterests::new();
        let base = Instant::now();
        let a = t.allocate_id();
        let b = t.allocate_id();
        t.insert(
            face(10),
            a,
            interest(face(1), 7),
            base + Duration::from_secs(5),
        );
        t.insert(
            face(11),
            b,
            interest(face(1), 7),
            base + Duration::from_secs(5),
        );
        assert_eq!(t.resolve(face(10), a), None);
        assert_eq!(
            t.expired(base + Duration::from_secs(6)),
            vec![interest(face(1), 7)],
            "the silent branch's GC completes the unwind"
        );
        assert_eq!(t.timed_out(), 1, "only the silent branch was abandoned");
    }

    /// An upstream face dying before it answered finalizes the client at once —
    /// zenoh's `finalize_pending_interests` on close. Without it the client waits
    /// out a full interest timeout for a peer that is already gone.
    #[test]
    fn an_upstream_face_down_finalizes_the_client_without_waiting_for_the_gc() {
        let mut t = PendingCurrentInterests::new();
        let deadline = Instant::now() + Duration::from_secs(500);
        let id = t.allocate_id();
        t.insert(face(10), id, interest(face(1), 7), deadline);
        assert_eq!(t.drain_face(face(10)), vec![interest(face(1), 7)]);
        assert_eq!(t.len(), 0);
        assert_eq!(
            t.timed_out(),
            0,
            "a face-down is not a timeout — the GC witness must not move"
        );
    }

    /// The DOWNSTREAM dying yields nothing: there is nobody left to send a
    /// `DeclareFinal` to, and emitting one toward a dead face would be a send on a
    /// torn-down seam.
    #[test]
    fn a_downstream_face_down_retires_its_entries_silently() {
        let mut t = PendingCurrentInterests::new();
        let deadline = Instant::now() + Duration::from_secs(500);
        let id = t.allocate_id();
        t.insert(face(10), id, interest(face(1), 7), deadline);
        assert_eq!(
            t.drain_face(face(1)),
            vec![],
            "the client IS the departed face — no unwind is owed"
        );
        assert_eq!(t.len(), 0);
        assert_eq!(
            t.expired(Instant::now() + Duration::from_secs(600)),
            vec![],
            "and the entry is gone, so the GC has nothing left to abandon"
        );
    }

    /// `lookup` is the reply-relay path and must NOT consume: a client interest
    /// answered with several tokens looks the same entry up once per token, and
    /// the terminating final still has to find it.
    #[test]
    fn lookup_does_not_retire_the_entry() {
        let mut t = PendingCurrentInterests::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let id = t.allocate_id();
        t.insert(face(10), id, interest(face(1), 7), deadline);
        assert_eq!(t.lookup(face(10), id), Some(&interest(face(1), 7)));
        assert_eq!(t.lookup(face(10), id), Some(&interest(face(1), 7)));
        assert_eq!(t.len(), 1);
        assert_eq!(t.resolve(face(10), id), Some(interest(face(1), 7)));
        assert_eq!(t.lookup(face(10), id), None);
    }

    /// A final for an id this node never propagated is ignored — a duplicate, or
    /// an upstream answering an interest it invented. It must not unwind some
    /// other client's entry.
    #[test]
    fn an_unknown_final_is_ignored() {
        let mut t = PendingCurrentInterests::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let id = t.allocate_id();
        t.insert(face(10), id, interest(face(1), 7), deadline);
        assert_eq!(t.resolve(face(10), 9999), None);
        assert_eq!(t.resolve(face(99), id), None);
        assert_eq!(t.len(), 1, "neither miss disturbed the live entry");
        assert_eq!(t.resolve(face(10), id), Some(interest(face(1), 7)));
    }

    /// Two DIFFERENT clients on the same upstream unwind independently — the
    /// refcount is keyed by the downstream interest, not by the upstream face.
    #[test]
    fn two_clients_on_one_upstream_unwind_independently() {
        let mut t = PendingCurrentInterests::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let a = t.allocate_id();
        let b = t.allocate_id();
        t.insert(face(10), a, interest(face(1), 7), deadline);
        t.insert(face(10), b, interest(face(2), 3), deadline);
        assert_eq!(t.resolve(face(10), a), Some(interest(face(1), 7)));
        assert_eq!(t.resolve(face(10), b), Some(interest(face(2), 3)));
    }
}
