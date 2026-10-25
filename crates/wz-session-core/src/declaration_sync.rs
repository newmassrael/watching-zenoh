// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session still waits for from its peer before its declarations are SYNCED
//! (`docs/declaration-sync-pacing.md`, phase 3).
//!
//! # What "synced" means
//!
//! A node's declarations are in step with a peer when two things hold: the node has told the peer
//! everything it holds (no replay is running: [`crate::reconnect::DeclarationCache::replaying`]),
//! and the peer has told the node what the node asked for. The second is what this type tracks.
//!
//! What a node asks a peer for is an `Interest`: the peer answers with the declarations that match
//! and ends the answer with a `Declare(DeclFinal)` carrying the interest's id. An interest that asks
//! for what exists NOW (`current`) is therefore answered, and the node knows the answer is complete
//! when the final arrives. One that asks only for what is declared LATER has no final to wait for.
//!
//! The peer's own initial final (`extbound::INITIAL_INTEREST_ID`) is not counted: a router never
//! sends one to a client, and a client of a router is the common case, so a wait that required it
//! would never end there. The interests the node itself sent are the answers it can always expect.
//!
//! # Why a deadline per interest
//!
//! A peer may never answer: it may not implement the interest, or the answer may be lost with the
//! link. A node that waits for ever is as wrong as one that does not wait. Each interest carries the
//! time it was sent, and one that has waited the timeout is given up on: the node is synced without
//! it, as the fork's sync goes on when its retry time is spent. The deadline is per interest and not
//! per sync, so an interest sent late is not cut short by an old one.
//!
//! This type reads no clock: its callers give it the time, which keeps it testable and keeps the
//! core free of a clock it would have to be generic over.

use alloc::vec::Vec;

// A timeout of zero gives up on an interest the instant it is sent: the node would be synced
// before the peer could answer, which is a wait that waits for nothing.
const _: () = assert!(
    crate::caps::DECLARATION_SYNC_FINAL_TIMEOUT_MS >= 1,
    "DECLARATION_SYNC_FINAL_TIMEOUT_MS must be at least 1"
);

/// One interest sent whose final has not arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFinal {
    interest_id: u64,
    sent_at_ms: u64,
}

/// The interests a session has sent and has not yet had a final for.
#[derive(Debug, Default)]
pub struct DeclarationSync {
    pending: Vec<PendingFinal>,
}

impl DeclarationSync {
    /// A session that has sent no interest: it is synced.
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// An interest that asks for what exists now was sent at `now_ms`. Sending the same id again
    /// (a replay after a reconnect asks again) restarts its wait.
    pub fn interest_sent(&mut self, interest_id: u64, now_ms: u64) {
        match self
            .pending
            .iter_mut()
            .find(|held| held.interest_id == interest_id)
        {
            Some(held) => held.sent_at_ms = now_ms,
            None => self.pending.push(PendingFinal {
                interest_id,
                sent_at_ms: now_ms,
            }),
        }
    }

    /// The peer's `DeclFinal` for `interest_id` arrived. Returns whether the node was waiting for
    /// it: a final for an interest it never sent, or already had the final of, changes nothing.
    pub fn final_seen(&mut self, interest_id: u64) -> bool {
        match self
            .pending
            .iter()
            .position(|held| held.interest_id == interest_id)
        {
            Some(place) => {
                self.pending.remove(place);
                true
            }
            None => false,
        }
    }

    /// The node withdrew `interest_id` (it sent the interest's own final, or a one-shot get
    /// ended), so no answer is owed to it any more.
    pub fn forget(&mut self, interest_id: u64) {
        let _ = self.final_seen(interest_id);
    }

    /// The session ended: its next peer holds none of what was asked, and the interests are asked
    /// again by the replay, which notes each as it sends it.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// How many interests are still waited for at `now_ms`, those past `timeout_ms` not counted.
    pub fn outstanding(&self, now_ms: u64, timeout_ms: u64) -> usize {
        self.pending
            .iter()
            .filter(|held| now_ms.saturating_sub(held.sent_at_ms) < timeout_ms)
            .count()
    }

    /// How many interests were given up on at `now_ms`: waited for the whole timeout, no final.
    pub fn timed_out(&self, now_ms: u64, timeout_ms: u64) -> usize {
        self.pending.len() - self.outstanding(now_ms, timeout_ms)
    }

    /// Whether nothing is still waited for at `now_ms`.
    pub fn is_synced(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.outstanding(now_ms, timeout_ms) == 0
    }
}

/// Calls `each` with the interest id of every `Declare(DeclFinal)` that `event` delivers.
///
/// A final carries the id of the interest it ends in the envelope of the declaration. The slot
/// profile reads its records where the frame lies and has its own host, so only the owned batch of a
/// delivered frame is read here.
#[cfg(feature = "codec-declare")]
pub fn finals_in_event(event: crate::driver_loop::IterationEvent<'_>, mut each: impl FnMut(u64)) {
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::network_message::NetworkMessage;
    use wz_codecs::declare::DeclareOwnedVariant;

    let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event else {
        return;
    };
    for message in messages {
        if let NetworkMessage::Declare(declare) = message {
            if let (Some(interest_id), DeclareOwnedVariant::CodecZenohDeclFinal(_)) =
                (declare.interest_id, &declare.body)
            {
                each(interest_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: u64 = 1_000;

    #[test]
    fn a_session_that_sent_no_interest_is_synced() {
        let sync = DeclarationSync::new();
        assert!(sync.is_synced(0, TIMEOUT));
        assert_eq!(sync.outstanding(0, TIMEOUT), 0);
    }

    #[test]
    fn an_interest_sent_is_waited_for_until_its_final_arrives() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 100);
        assert!(!sync.is_synced(100, TIMEOUT));
        assert_eq!(sync.outstanding(500, TIMEOUT), 1);
        assert!(sync.final_seen(7), "it was waited for");
        assert!(sync.is_synced(500, TIMEOUT));
    }

    #[test]
    fn a_final_for_an_interest_never_sent_or_already_answered_changes_nothing() {
        let mut sync = DeclarationSync::new();
        assert!(!sync.final_seen(9), "never sent");
        sync.interest_sent(7, 0);
        assert!(sync.final_seen(7));
        assert!(!sync.final_seen(7), "already answered");
        assert!(sync.is_synced(0, TIMEOUT));
    }

    #[test]
    fn every_interest_is_waited_for_not_only_the_last() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 0);
        sync.interest_sent(3, 0);
        assert!(sync.final_seen(2));
        assert_eq!(sync.outstanding(10, TIMEOUT), 2);
        assert!(sync.final_seen(1));
        assert!(!sync.is_synced(10, TIMEOUT), "3 is still owed");
        assert!(sync.final_seen(3));
        assert!(sync.is_synced(10, TIMEOUT));
    }

    #[test]
    fn an_interest_that_waited_the_whole_timeout_is_given_up_on() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 100);
        assert!(!sync.is_synced(1_099, TIMEOUT), "one millisecond short");
        assert!(sync.is_synced(1_100, TIMEOUT), "the timeout is spent");
        assert_eq!(sync.timed_out(1_100, TIMEOUT), 1);
        assert_eq!(sync.outstanding(1_100, TIMEOUT), 0);
    }

    #[test]
    fn the_deadline_is_per_interest_so_a_late_one_is_not_cut_short_by_an_old_one() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 900);
        // At 1_000 the first has waited its timeout and the second has waited 100 ms.
        assert_eq!(sync.outstanding(1_000, TIMEOUT), 1);
        assert!(!sync.is_synced(1_000, TIMEOUT));
        assert!(sync.is_synced(1_900, TIMEOUT));
    }

    #[test]
    fn sending_an_interest_again_restarts_its_wait() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 0);
        sync.interest_sent(7, 900);
        assert_eq!(sync.outstanding(1_000, TIMEOUT), 1, "asked again at 900");
        assert!(sync.is_synced(1_900, TIMEOUT));
    }

    #[test]
    fn a_withdrawn_interest_is_no_longer_waited_for_and_a_new_session_waits_for_nothing() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 0);
        sync.forget(1);
        assert_eq!(sync.outstanding(10, TIMEOUT), 1);
        sync.clear();
        assert!(sync.is_synced(10, TIMEOUT));
    }

    #[test]
    fn a_clock_that_went_back_does_not_wrap_into_a_timeout() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 5_000);
        assert!(!sync.is_synced(1_000, TIMEOUT), "now before sent: not yet");
    }
}
