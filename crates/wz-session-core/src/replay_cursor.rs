// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A position in the sequence of declarations a node owes a peer: the shared part of paced
//! declaration sync (`docs/declaration-sync-pacing.md`).
//!
//! # What it is
//!
//! When a session comes up, the peer holds none of the node's declarations, and the node tells it
//! all of them. The hosts keep their declarations in three different shapes (an ordered cache on
//! the heap runtime, lists by kind in the cooperative engine, a static slice in the slot node), so
//! what they share is not a cache. It is a place in a sequence the host can recite in a fixed
//! order, and the rules about that place: how far the peer has been told, what to do with a
//! declaration or a retraction made while the telling is going on, and where to resume after a
//! refused send.
//!
//! This type is exactly that place and nothing else. It holds no list, reads no clock, allocates
//! nothing and does no I/O, so a host with no allocator uses it as it is. The host owns its
//! sequence and its pacing and calls the cursor at four points:
//! [`crate::replay_cursor::ReplayCursor::turn`] to learn which entries to emit now,
//! [`crate::replay_cursor::ReplayCursor::refused`] when an emit failed,
//! [`crate::replay_cursor::ReplayCursor::inserted`] when a live declaration took a place in the
//! order, and [`crate::replay_cursor::ReplayCursor::removed`] when a live undeclaration took one
//! out.
//!
//! # The rules it states once
//!
//! A host that ignores the value `inserted` or `removed` returns is the host that gets them wrong,
//! which is why they return one:
//!
//! * A declaration whose place is at or past the cursor is
//!   [`crate::replay_cursor::Insertion::Owed`]: the replay will reach it, so its caller emits
//!   nothing. One whose place is before the cursor is
//!   [`crate::replay_cursor::Insertion::EmitNow`]: everything it depends on precedes it in the
//!   order and is already at the peer, so its caller emits it at once.
//! * A retraction of an entry the cursor has not reached is
//!   [`crate::replay_cursor::Removal::Silent`]: the peer never learned of it, so nothing is sent.
//!   One of an entry before the cursor is [`crate::replay_cursor::Removal::Retract`]: the peer
//!   holds it.
//! * A refused send resumes at the entry it failed on, never at the beginning of the sequence.
//!
//! A cursor that has finished behaves as "the peer has everything": a declaration made after the
//! replay is [`crate::replay_cursor::Insertion::EmitNow`] and a retraction is
//! [`crate::replay_cursor::Removal::Retract`], so a host may keep consulting it for the life of
//! the session, and a host that stops consulting it after
//! [`crate::replay_cursor::ReplayCursor::finished`] gets the same answers.

use core::ops::Range;

/// What a host does with a live declaration, as [`ReplayCursor::inserted`] decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the caller emits the declaration when this says so, and not otherwise"]
pub enum Insertion {
    /// The replay has not reached the entry's place and will emit it: the caller stores it and
    /// emits nothing.
    Owed,
    /// The replay is past the entry's place: the caller stores it and emits it now.
    EmitNow,
}

/// What a host does with a live retraction, as [`ReplayCursor::removed`] decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the caller emits the retraction when this says so, and not otherwise"]
pub enum Removal {
    /// The peer was told of the entry: the caller emits the retraction.
    Retract,
    /// The peer was never told of the entry: the caller drops it and emits nothing.
    Silent,
}

/// How far a replay has got through a sequence of `total` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCursor {
    /// The place of the first entry the peer has not been told.
    next: usize,
    /// How many entries the sequence holds.
    total: usize,
}

impl ReplayCursor {
    /// A cursor with nothing to replay: it is finished, so every live declaration is emitted by its
    /// caller as it is made.
    pub const fn idle() -> Self {
        Self { next: 0, total: 0 }
    }

    /// Begin a replay of a sequence of `total` entries, the peer holding none of them.
    pub const fn begin(total: usize) -> Self {
        Self { next: 0, total }
    }

    /// Whether every entry has been told to the peer.
    pub const fn finished(&self) -> bool {
        self.next >= self.total
    }

    /// The place of the first entry not yet told.
    pub const fn next(&self) -> usize {
        self.next
    }

    /// How many entries the sequence holds now.
    pub const fn total(&self) -> usize {
        self.total
    }

    /// How many entries are still owed.
    pub const fn owed(&self) -> usize {
        self.total.saturating_sub(self.next)
    }

    /// The entries to emit in this turn, at most `burst` of them from the cursor, which then moves
    /// past them. An empty range means the replay is finished. A `burst` of zero emits nothing and
    /// never finishes; a host refuses it where its limit is declared.
    pub fn turn(&mut self, burst: usize) -> Range<usize> {
        let start = self.next.min(self.total);
        let end = self.total.min(start.saturating_add(burst));
        self.next = end;
        start..end
    }

    /// A send of the entry at `place` was refused: the next turn starts there, with the entries
    /// before it still told. A place at or past the cursor changes nothing, since the cursor is
    /// already before it.
    pub fn refused(&mut self, place: usize) {
        self.next = self.next.min(place);
    }

    /// A live declaration took `place` in the order, so the entries from `place` on moved one
    /// later. `place` is at most `total`, the end of the sequence; a larger one is a defect of the
    /// host and is taken as the end.
    pub fn inserted(&mut self, place: usize) -> Insertion {
        let place = place.min(self.total);
        let owed = !self.finished() && place >= self.next;
        if !owed {
            // Everything the entry depends on precedes it and has been told, so the cursor moves
            // over it with the entries that follow, and it is not owed again.
            self.next += 1;
        }
        self.total += 1;
        if owed {
            Insertion::Owed
        } else {
            Insertion::EmitNow
        }
    }

    /// A live undeclaration removed the entry at `place`, so the entries after it moved one
    /// earlier. A `place` past the end is a defect of the host and is taken as the last entry; on an
    /// empty sequence there is nothing to remove and the answer is [`Removal::Silent`].
    pub fn removed(&mut self, place: usize) -> Removal {
        if self.total == 0 {
            return Removal::Silent;
        }
        let place = place.min(self.total - 1);
        self.total -= 1;
        if place < self.next {
            self.next -= 1;
            Removal::Retract
        } else {
            Removal::Silent
        }
    }
}

impl Default for ReplayCursor {
    fn default() -> Self {
        Self::idle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_turn_emits_at_most_the_burst_from_the_cursor_and_moves_past_them() {
        let mut cursor = ReplayCursor::begin(5);
        assert_eq!(cursor.turn(2), 0..2);
        assert_eq!(cursor.next(), 2);
        assert_eq!(cursor.turn(2), 2..4);
        assert_eq!(cursor.turn(2), 4..5, "the last turn is short");
        assert!(cursor.finished());
        assert_eq!(cursor.turn(2), 5..5, "an empty range means finished");
    }

    #[test]
    fn a_burst_of_zero_emits_nothing_and_never_finishes() {
        let mut cursor = ReplayCursor::begin(3);
        assert_eq!(cursor.turn(0), 0..0);
        assert!(!cursor.finished());
        assert_eq!(cursor.owed(), 3);
    }

    #[test]
    fn an_empty_sequence_is_finished_at_once() {
        assert!(ReplayCursor::begin(0).finished());
        assert!(ReplayCursor::idle().finished());
        assert_eq!(ReplayCursor::default(), ReplayCursor::idle());
    }

    #[test]
    fn a_refused_send_resumes_at_the_entry_it_failed_on_and_never_at_zero() {
        let mut cursor = ReplayCursor::begin(6);
        assert_eq!(cursor.turn(4), 0..4);
        // Entries 0 and 1 went out; the send of entry 2 was refused.
        cursor.refused(2);
        assert_eq!(cursor.next(), 2);
        assert_eq!(
            cursor.turn(4),
            2..6,
            "the retry starts at 2, so 0 and 1 are not sent again"
        );
    }

    #[test]
    fn a_refusal_at_or_past_the_cursor_changes_nothing() {
        let mut cursor = ReplayCursor::begin(6);
        assert_eq!(cursor.turn(2), 0..2);
        cursor.refused(5);
        assert_eq!(cursor.next(), 2);
    }

    #[test]
    fn a_declaration_past_the_cursor_is_owed_and_the_replay_reaches_it() {
        let mut cursor = ReplayCursor::begin(4);
        assert_eq!(cursor.turn(2), 0..2);
        assert_eq!(cursor.inserted(3), Insertion::Owed);
        assert_eq!(cursor.total(), 5);
        assert_eq!(cursor.next(), 2, "the cursor does not move");
        assert_eq!(cursor.turn(10), 2..5, "and the turn includes the new entry");
    }

    #[test]
    fn a_declaration_at_the_cursor_is_owed_too() {
        let mut cursor = ReplayCursor::begin(4);
        assert_eq!(cursor.turn(2), 0..2);
        assert_eq!(cursor.inserted(2), Insertion::Owed);
        assert_eq!(cursor.turn(10), 2..5);
    }

    #[test]
    fn a_declaration_before_the_cursor_is_emitted_now_and_not_owed_again() {
        let mut cursor = ReplayCursor::begin(4);
        assert_eq!(cursor.turn(3), 0..3);
        // The entry takes place 1: what it depends on is before it and already told.
        assert_eq!(cursor.inserted(1), Insertion::EmitNow);
        assert_eq!(cursor.total(), 5);
        assert_eq!(
            cursor.next(),
            4,
            "the cursor moved over it with the entries after it"
        );
        assert_eq!(
            cursor.turn(10),
            4..5,
            "only the one entry that was never told remains"
        );
    }

    #[test]
    fn a_retraction_before_the_cursor_is_sent_and_the_cursor_moves_down() {
        let mut cursor = ReplayCursor::begin(5);
        assert_eq!(cursor.turn(3), 0..3);
        assert_eq!(cursor.removed(1), Removal::Retract);
        assert_eq!(cursor.total(), 4);
        assert_eq!(cursor.next(), 2);
        assert_eq!(
            cursor.turn(10),
            2..4,
            "the entries not yet told are still owed, none twice"
        );
    }

    #[test]
    fn a_retraction_of_an_entry_not_reached_is_silent_and_the_peer_never_hears_of_it() {
        let mut cursor = ReplayCursor::begin(5);
        assert_eq!(cursor.turn(2), 0..2);
        assert_eq!(cursor.removed(3), Removal::Silent);
        assert_eq!(cursor.total(), 4);
        assert_eq!(cursor.next(), 2);
        assert_eq!(
            cursor.turn(10),
            2..4,
            "the removed entry is not in the range"
        );
    }

    #[test]
    fn a_retraction_at_the_cursor_is_silent() {
        let mut cursor = ReplayCursor::begin(3);
        assert_eq!(cursor.turn(1), 0..1);
        assert_eq!(cursor.removed(1), Removal::Silent);
        assert_eq!(cursor.turn(10), 1..2);
    }

    #[test]
    fn a_finished_cursor_behaves_as_the_peer_holding_everything() {
        let mut cursor = ReplayCursor::begin(2);
        assert_eq!(cursor.turn(5), 0..2);
        assert!(cursor.finished());
        assert_eq!(
            cursor.inserted(2),
            Insertion::EmitNow,
            "appended after the replay"
        );
        assert!(cursor.finished(), "and the cursor stays finished");
        assert_eq!(cursor.inserted(0), Insertion::EmitNow);
        assert!(cursor.finished());
        assert_eq!(cursor.removed(1), Removal::Retract);
        assert!(cursor.finished());
        assert_eq!(cursor.total(), 3);
    }

    #[test]
    fn an_idle_cursor_emits_every_declaration_and_retracts_every_removal() {
        let mut cursor = ReplayCursor::idle();
        assert_eq!(cursor.inserted(0), Insertion::EmitNow);
        assert_eq!(cursor.removed(0), Removal::Retract);
        assert_eq!(cursor.removed(0), Removal::Silent, "nothing left to remove");
    }

    #[test]
    fn a_place_past_the_end_is_taken_as_the_end() {
        let mut cursor = ReplayCursor::begin(2);
        assert_eq!(cursor.inserted(99), Insertion::Owed);
        assert_eq!(cursor.total(), 3);
        assert_eq!(
            cursor.removed(99),
            Removal::Silent,
            "the last entry, not yet told"
        );
        assert_eq!(cursor.total(), 2);
    }

    /// The point of the type: whatever order a host's turns, live declarations and live
    /// retractions come in, each entry reaches the peer at most once while it is declared, and when
    /// the replay is done the peer holds exactly what the host holds. The host here is a plain array,
    /// the peer a set of ids, driven by a fixed pseudo-random sequence over many seeds.
    #[test]
    fn whatever_the_interleaving_the_peer_ends_holding_exactly_what_the_host_holds() {
        const CAP: usize = 64;
        for seed in 1u32..=200 {
            let mut state = seed.wrapping_mul(2_654_435_761).max(1);
            let mut rng = move || {
                // xorshift32: a fixed, dependency-free sequence per seed.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state
            };
            let initial = (rng() % 10) as usize;
            let mut host = [0u32; CAP];
            let mut host_len = 0usize;
            let mut next_id = 1u32;
            for _ in 0..initial {
                host[host_len] = next_id;
                host_len += 1;
                next_id += 1;
            }
            let mut cursor = ReplayCursor::begin(host_len);
            // `peer[id]` is how many times the peer was told the id and not yet retracted.
            let mut peer = [0i32; CAP * 4];
            let burst = 1 + (rng() % 3) as usize;
            for _ in 0..200 {
                match rng() % 4 {
                    0 | 1 => {
                        for place in cursor.turn(burst) {
                            peer[host[place] as usize] += 1;
                        }
                    }
                    2 if host_len < CAP => {
                        let place = (rng() as usize) % (host_len + 1);
                        for index in (place..host_len).rev() {
                            host[index + 1] = host[index];
                        }
                        host[place] = next_id;
                        host_len += 1;
                        let id = next_id;
                        next_id += 1;
                        if cursor.inserted(place) == Insertion::EmitNow {
                            peer[id as usize] += 1;
                        }
                    }
                    3 if host_len > 0 => {
                        let place = (rng() as usize) % host_len;
                        let id = host[place];
                        for index in place..host_len - 1 {
                            host[index] = host[index + 1];
                        }
                        host_len -= 1;
                        if cursor.removed(place) == Removal::Retract {
                            peer[id as usize] -= 1;
                        }
                    }
                    _ => {}
                }
                assert!(cursor.next() <= cursor.total());
                assert_eq!(
                    cursor.total(),
                    host_len,
                    "seed {seed}: the cursor counts the host"
                );
            }
            // Finish the replay.
            loop {
                let range = cursor.turn(burst);
                if range.is_empty() {
                    break;
                }
                for place in range {
                    peer[host[place] as usize] += 1;
                }
            }
            for id in 1..next_id {
                let held = host[..host_len].contains(&id);
                assert_eq!(
                    peer[id as usize],
                    i32::from(held),
                    "seed {seed}: id {id} is {} by the host and told {} time(s) net to the peer",
                    if held { "held" } else { "gone" },
                    peer[id as usize]
                );
            }
        }
    }
}
