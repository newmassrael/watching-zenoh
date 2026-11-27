// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The decision record of a fixed-memory node (decision D16 of `docs/session-lifecycle-intent.md`):
//! the latest decisions of its reference monitor, each with its subject, verb, object, channel and
//! reason, kept in rows of fixed size, and the count of every decision made.
//!
//! Bounded because the node has no allocator: the oldest row is written over when the record is
//! full, and the count says how many were made in all, so a reader knows how many it did not see.

use core::cell::RefCell;
use wz_runtime_coop::cs::Mutex;
use wz_session_core::lifecycle_monitor::{Decided, Decision, DecisionRecord, Request};

/// The rows a node's record keeps: the latest decisions of its monitor.
pub const DECISION_ROWS: usize = 4;

/// The latest `N` decisions of a node's monitor, and how many it made.
///
/// A critical section guards it, as the crate's other shared state is (`PeerStore`), so a node
/// declares it in a `static` beside the node it records for.
pub struct DecisionLog<const N: usize> {
    ring: Mutex<RefCell<Ring<N>>>,
}

/// The rows, the next one to write, and the count of decisions made.
struct Ring<const N: usize> {
    rows: [Option<Decided>; N],
    next: usize,
    made: u32,
}

impl<const N: usize> DecisionLog<N> {
    /// A record of no decision. `const`, so a `static` can be one.
    pub const fn new() -> Self {
        Self {
            ring: Mutex::new(RefCell::new(Ring {
                rows: [None; N],
                next: 0,
                made: 0,
            })),
        }
    }

    /// Call `each` with every decision kept, the oldest first.
    pub fn each(&self, mut each: impl FnMut(&Decided)) {
        wz_runtime_coop::cs::with(|cs| {
            let ring = self.ring.borrow_ref(cs);
            let older = ring.rows.get(ring.next..).unwrap_or_default();
            let newer = ring.rows.get(..ring.next).unwrap_or_default();
            for row in older.iter().chain(newer).flatten() {
                each(row);
            }
        });
    }

    /// How many decisions were made, kept or written over since.
    pub fn made(&self) -> u32 {
        wz_runtime_coop::cs::with(|cs| self.ring.borrow_ref(cs).made)
    }
}

impl<const N: usize> Default for DecisionLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DecisionRecord for DecisionLog<N> {
    fn record(&self, request: &Request<'_>, decision: Decision) {
        let row = Decided::of(request, decision);
        wz_runtime_coop::cs::with(|cs| {
            let mut ring = self.ring.borrow_ref_mut(cs);
            let at = ring.next;
            if let Some(slot) = ring.rows.get_mut(at) {
                *slot = Some(row);
            }
            let after = at.wrapping_add(1);
            ring.next = if after >= N { 0 } else { after };
            ring.made = ring.made.saturating_add(1);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use wz_session_core::lifecycle_monitor::{Channel, Grounds, Object, Refusal, Subject};
    use wz_session_core::lifecycle_node::{Commander, Verb};

    fn request(verb: Verb) -> Request<'static> {
        Request {
            subject: Commander::Unproven,
            verb,
            object: Object {
                peer: "1f",
                generation: None,
                key: None,
            },
            channel: Channel::Pipe,
        }
    }

    /// Every decision is counted and the latest are kept, the oldest first; past the rows the
    /// oldest is written over. Red if `record` skipped a decision or kept the wrong end.
    #[test]
    fn the_record_keeps_the_latest_decisions_and_counts_every_one() {
        let log: DecisionLog<2> = DecisionLog::new();
        let verbs = [Verb::Open, Verb::Close, Verb::Reset];
        for verb in verbs {
            log.record(&request(verb), Decision::Deny(Refusal::Unproven));
        }
        let mut kept = Vec::new();
        log.each(|row| kept.push((row.verb, row.subject, row.decision)));
        assert_eq!(
            kept,
            [
                (
                    Verb::Close,
                    Subject::Unproven,
                    Decision::Deny(Refusal::Unproven)
                ),
                (
                    Verb::Reset,
                    Subject::Unproven,
                    Decision::Deny(Refusal::Unproven)
                ),
            ]
        );
        assert_eq!(log.made(), 3);
        log.record(&request(Verb::Status), Decision::Permit(Grounds::PipeOwner));
        let mut last = None;
        log.each(|row| last = Some(row.decision));
        assert_eq!(last, Some(Decision::Permit(Grounds::PipeOwner)));
        assert_eq!(log.made(), 4);
    }

    /// A record with no rows still counts.
    #[test]
    fn a_record_of_no_rows_counts_every_decision() {
        let log: DecisionLog<0> = DecisionLog::new();
        log.record(&request(Verb::Open), Decision::Deny(Refusal::NotBound));
        let mut rows = 0;
        log.each(|_| rows += 1);
        assert_eq!((rows, log.made()), (0, 1));
    }
}
