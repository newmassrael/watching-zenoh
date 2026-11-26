// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which subscribers a peer's key reached, kept beside the key and read back while the
//! subscriptions are what they were when it was worked out.
//!
//! A peer that declared its key names every message on it by the same id, so the subscribers such
//! a message reaches are the same from one message to the next until a subscription is declared or
//! undeclared, or the key gate changes: the table's epoch
//! ([`crate::pubsub::LocalSubscribers::epoch`]) moves on each. The answer is kept as a set of the
//! places of the rows it reached ([`SubscriberSet`]) in a small direct-mapped memory of the
//! peer's side ([`PeerMatches`]), so a message whose answer is kept is handed to its subscribers
//! with no pattern matched, no key gate asked and no key text read; a key the gate refused keeps
//! the refusal as its answer, counted again for each of its messages. Zenoh keeps the same answer
//! on the resource a declared key names (`Resource::matches`), invalidated by the version of its
//! routing tables.
//!
//! Every field is a plain integer and all zero bytes are an empty memory, so a side placed in
//! zeroed memory (the region policy) holds one with nothing kept.

use crate::caps;

/// The most words a [`SubscriberSet`] holds whatever the build's `MAX_SUBSCRIPTIONS`: a build that
/// states a large table does not give every kept answer a word for each of its 64 rows, and an
/// answer that reaches a row placed past the set's width is not kept (it is matched each time).
const MAX_SET_WORDS: usize = 4;

/// The words of a [`SubscriberSet`]: one bit for every place of a table of `MAX_SUBSCRIPTIONS`
/// rows, at most [`MAX_SET_WORDS`].
const SET_WORDS: usize = {
    let words = caps::MAX_SUBSCRIPTIONS.div_ceil(64);
    if words < MAX_SET_WORDS {
        words
    } else {
        MAX_SET_WORDS
    }
};

/// How many answers a peer's side keeps at once, one for each id its low bits pick. A power of
/// two, so the pick is a mask.
pub const PEER_MATCH_ENTRIES: usize = 4;

const _: () = assert!(
    PEER_MATCH_ENTRIES.is_power_of_two(),
    "PEER_MATCH_ENTRIES is a power of two: an id picks its entry by a mask"
);

/// The mask an id's key picks its entry of a [`PeerMatches`] by.
const ENTRY_MASK: usize = PEER_MATCH_ENTRIES.wrapping_sub(1);

/// A set of places in a table of subscriptions, one bit each, read in ascending order: the order
/// the table is walked in, so the rows a kept answer is handed to are handed it in the order a
/// walk hands them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriberSet {
    words: [u64; SET_WORDS],
}

impl SubscriberSet {
    /// The set of no place.
    pub const EMPTY: Self = Self {
        words: [0; SET_WORDS],
    };

    /// One more than the last place the set holds.
    pub const WIDTH: usize = SET_WORDS.wrapping_mul(64);

    /// Add `place`: `false`, and nothing added, for a place at or past [`Self::WIDTH`].
    pub fn insert(&mut self, place: usize) -> bool {
        match self.words.get_mut(place.wrapping_shr(6)) {
            Some(word) => {
                *word |= bit_of(place);
                true
            }
            None => false,
        }
    }

    /// Whether the set holds `place`.
    pub fn contains(&self, place: usize) -> bool {
        self.words
            .get(place.wrapping_shr(6))
            .is_some_and(|word| word & bit_of(place) != 0)
    }

    /// How many places the set holds.
    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether the set holds no place.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Every place the set holds, ascending.
    pub fn places(&self) -> Places<'_> {
        Places {
            rest: self.words.iter(),
            word: 0,
            base: 0,
            next_base: 0,
        }
    }
}

/// The bit of `place` in its word.
fn bit_of(place: usize) -> u64 {
    1u64.wrapping_shl((place & 63) as u32)
}

/// The places of a [`SubscriberSet`], ascending ([`SubscriberSet::places`]).
#[derive(Clone, Debug)]
pub struct Places<'a> {
    rest: core::slice::Iter<'a, u64>,
    /// What is left of the word read last.
    word: u64,
    /// The place of that word's first bit.
    base: usize,
    /// The place of the next word's first bit.
    next_base: usize,
}

impl Iterator for Places<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            if self.word != 0 {
                let bit = self.word.trailing_zeros() as usize;
                // The lowest bit set, cleared.
                self.word &= self.word.wrapping_sub(1);
                return Some(self.base.wrapping_add(bit));
            }
            self.word = *self.rest.next()?;
            self.base = self.next_base;
            self.next_base = self.next_base.wrapping_add(64);
        }
    }
}

/// What a [`MatchEntry`] keeps, as its one state byte: nothing (zero, so an entry of all zero
/// bytes keeps none), the places of its set, or a refusal. One byte, so the answer every message
/// of a kept key is handed is told from the other two by one compare.
const KEPT_NOTHING: u8 = 0;
const KEPT_PLACES: u8 = 1;
const KEPT_REFUSAL: u8 = 2;

/// One kept answer: the subscribers a peer's key reached, the key named by the peer's id under its
/// sender ([`crate::wire_id::sender_peer_key`]), and the epoch of the table it was worked out at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatchEntry {
    /// What is kept: `KEPT_NOTHING`, `KEPT_PLACES` (the places of `set`) or `KEPT_REFUSAL`
    /// (the counter of `refused`).
    kept: u8,
    /// The key the answer is of.
    wire: u64,
    /// The table's epoch when the answer was worked out.
    epoch: u64,
    /// The places of the rows the key reached.
    set: SubscriberSet,
    /// When the answer is that the key gate refused the key: the counter it counted the refusal
    /// in ([`crate::key_gate::Refusal::counter`]), which each message on the key is counted in
    /// again with the gate not asked. Read only while `kept` is a refusal.
    refused: Option<core::num::NonZeroU8>,
}

impl MatchEntry {
    /// An entry that keeps no answer.
    pub const NONE: Self = Self {
        kept: KEPT_NOTHING,
        wire: 0,
        epoch: 0,
        set: SubscriberSet::EMPTY,
        refused: None,
    };

    /// The places the key reached, when that is the answer kept at the table's `epoch`: `None`
    /// for an answer of another epoch, and for a key the gate refused.
    #[inline]
    pub fn answer(&self, epoch: u64) -> Option<&SubscriberSet> {
        (self.kept == KEPT_PLACES && self.epoch == epoch).then_some(&self.set)
    }

    /// The counter of the key gate's refusal of the key, when that is the answer kept at the
    /// table's `epoch`.
    pub fn refusal(&self, epoch: u64) -> Option<core::num::NonZeroU8> {
        if self.kept == KEPT_REFUSAL && self.epoch == epoch {
            self.refused
        } else {
            None
        }
    }

    /// Keep `set` as the answer of this entry's key at `epoch`.
    pub fn keep(&mut self, epoch: u64, set: SubscriberSet) {
        self.kept = KEPT_PLACES;
        self.epoch = epoch;
        self.set = set;
    }

    /// Keep, as the answer of this entry's key at `epoch`, that the key gate refused it and
    /// counted the refusal in `counter`: the gate's answer changes only with the gate, which moves
    /// the epoch, or with the peer's class, which forgets the memory.
    pub fn keep_refused(&mut self, epoch: u64, counter: core::num::NonZeroU8) {
        self.kept = KEPT_REFUSAL;
        self.epoch = epoch;
        self.set = SubscriberSet::EMPTY;
        self.refused = Some(counter);
    }
}

/// A peer's side's memory of the answers to the keys it names by a declared id: direct-mapped by
/// the id, each entry an answer of one key ([`MatchEntry`]). What a key names is the peer's to
/// change (it declares an id anew, or undeclares it), so the memory also holds the count of the
/// changes to the side's names it was read under, and an entry is asked for under the count of
/// now: when they differ every entry is forgotten.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerMatches {
    entries: [MatchEntry; PEER_MATCH_ENTRIES],
    /// The count of the side's changes to its names the entries were kept under.
    names: u64,
}

impl PeerMatches {
    /// A memory that keeps nothing.
    pub const NONE: Self = Self {
        entries: [MatchEntry::NONE; PEER_MATCH_ENTRIES],
        names: 0,
    };

    /// The entry of the key `wire`, the side's names being at the count `names`: the one that keeps
    /// its answer, or the one its id picks made free for it, its answer worked out afresh.
    pub fn entry(&mut self, wire: u64, names: u64) -> Option<&mut MatchEntry> {
        if self.names != names {
            self.forget();
            self.names = names;
        }
        let entry = self.entries.get_mut((wire as usize) & ENTRY_MASK)?;
        if entry.kept == KEPT_NOTHING || entry.wire != wire {
            *entry = MatchEntry {
                wire,
                ..MatchEntry::NONE
            };
        }
        Some(entry)
    }

    /// Forget every answer: what decides one changed other than the table (the peer's class).
    pub fn forget(&mut self) {
        for entry in &mut self.entries {
            entry.kept = KEPT_NOTHING;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn a_set_reads_its_places_back_ascending_and_refuses_one_past_its_width() {
        let mut set = SubscriberSet::EMPTY;
        assert!(set.is_empty());
        let last = SubscriberSet::WIDTH - 1;
        for place in [last, 0, 3] {
            assert!(set.insert(place), "place {place}");
        }
        assert!(!set.insert(SubscriberSet::WIDTH));
        assert_eq!(set.places().collect::<Vec<_>>(), std::vec![0, 3, last]);
        assert_eq!(set.len(), 3);
        assert!(set.contains(3));
        assert!(!set.contains(1));
        assert!(!set.contains(SubscriberSet::WIDTH));
    }

    #[test]
    fn a_set_holds_every_place_of_a_table_of_the_builds_bound_up_to_its_words() {
        let width = caps::MAX_SUBSCRIPTIONS.min(MAX_SET_WORDS * 64);
        assert!(SubscriberSet::WIDTH >= width);
        let mut set = SubscriberSet::EMPTY;
        for place in 0..SubscriberSet::WIDTH {
            assert!(set.insert(place));
        }
        assert_eq!(set.places().count(), SubscriberSet::WIDTH);
    }

    #[test]
    fn an_answer_is_read_only_at_the_epoch_it_was_kept_at() {
        let mut entry = MatchEntry::NONE;
        assert_eq!(entry.answer(0), None, "all zero keeps nothing");
        let mut set = SubscriberSet::EMPTY;
        assert!(set.insert(1));
        entry.keep(7, set);
        assert_eq!(entry.answer(7), Some(&set));
        assert_eq!(entry.answer(8), None);
    }

    /// A refusal kept is read back at its epoch alone, as a refusal and not as an empty set of
    /// places, and an answer of places kept over it is read as places. Turned red by a refusal read
    /// as the set it keeps, or read past its epoch.
    #[test]
    fn a_kept_refusal_is_read_at_its_epoch_alone_and_never_as_places() {
        let counter = core::num::NonZeroU8::MIN;
        let mut entry = MatchEntry::NONE;
        assert_eq!(entry.refusal(0), None, "all zero keeps nothing");
        entry.keep_refused(4, counter);
        assert_eq!(entry.refusal(4), Some(counter));
        assert_eq!(entry.answer(4), None, "a refusal is no set of places");
        assert_eq!(entry.refusal(5), None, "another epoch");
        let mut set = SubscriberSet::EMPTY;
        assert!(set.insert(2));
        entry.keep(5, set);
        assert_eq!(entry.answer(5), Some(&set));
        assert_eq!(entry.refusal(5), None, "places kept over the refusal");
    }

    /// A refusal is forgotten as an answer of places is: by forgetting, by a change of the side's
    /// names, and by another key taking its entry; and the entry of all zero bytes keeps nothing.
    /// Turned red by a refusal that outlives `forget`, a fresh entry that keeps one, or a state
    /// of nothing that is not zero.
    #[test]
    fn a_kept_refusal_is_forgotten_as_places_are() {
        assert_eq!(
            MatchEntry::default(),
            MatchEntry::NONE,
            "all zero is nothing"
        );
        let counter = core::num::NonZeroU8::MIN;
        let wire = 3;
        let mut memory = PeerMatches::NONE;
        memory.entry(wire, 0).unwrap().keep_refused(1, counter);
        assert_eq!(memory.entry(wire, 0).unwrap().refusal(1), Some(counter));
        memory.forget();
        let entry = memory.entry(wire, 0).unwrap();
        assert_eq!(entry.refusal(1), None, "forgotten");
        assert_eq!(entry.answer(1), None, "nor read as places");
        entry.keep_refused(1, counter);
        assert_eq!(
            memory.entry(wire, 1).unwrap().refusal(1),
            None,
            "names changed"
        );
        memory.entry(wire, 1).unwrap().keep_refused(1, counter);
        let other = wire + PEER_MATCH_ENTRIES as u64;
        assert_eq!(
            memory.entry(other, 1).unwrap().refusal(1),
            None,
            "another key"
        );
        assert_eq!(memory.entry(wire, 1).unwrap().refusal(1), None);
    }

    #[test]
    fn an_entry_keeps_its_keys_answer_until_another_key_or_a_change_of_names_takes_it() {
        let mut memory = PeerMatches::NONE;
        let mut set = SubscriberSet::EMPTY;
        assert!(set.insert(2));
        let wire = 5;
        memory.entry(wire, 0).unwrap().keep(1, set);
        assert_eq!(memory.entry(wire, 0).unwrap().answer(1), Some(&set));
        // Another id picking another entry leaves this one.
        assert_eq!(memory.entry(wire + 1, 0).unwrap().answer(1), None);
        assert_eq!(memory.entry(wire, 0).unwrap().answer(1), Some(&set));
        // An id picking the same entry takes it.
        let same_entry = wire + PEER_MATCH_ENTRIES as u64;
        assert_eq!(memory.entry(same_entry, 0).unwrap().answer(1), None);
        assert_eq!(memory.entry(wire, 0).unwrap().answer(1), None);
        // A change of the side's names forgets every entry.
        memory.entry(wire, 0).unwrap().keep(1, set);
        assert_eq!(memory.entry(wire, 1).unwrap().answer(1), None);
        // As does forgetting.
        memory.entry(wire, 1).unwrap().keep(1, set);
        memory.forget();
        assert_eq!(memory.entry(wire, 1).unwrap().answer(1), None);
    }

    #[test]
    fn the_same_id_of_two_senders_is_two_keys() {
        let mut memory = PeerMatches::NONE;
        let set = SubscriberSet::EMPTY;
        let one = crate::wire_id::sender_peer_key(1, 5);
        let two = crate::wire_id::sender_peer_key(2, 5);
        memory.entry(one, 0).unwrap().keep(1, set);
        assert_eq!(memory.entry(two, 0).unwrap().answer(1), None);
    }
}
