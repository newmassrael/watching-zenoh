// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A map whose keys arrive in ascending order and leave from the front, kept as a
//! chunked log of `(key, value)`.
//!
//! Open-debt item 924, step 5 (`docs/dissect-row-index.md`, D7). A message list
//! keeps some facts for only some of its rows (what became of a fragment, which
//! chain it belonged to, a sequence gap), by the row's produced-index. They were
//! `BTreeMap`s, and a B-tree node holds about seven entries of an eleven-slot
//! capacity, so a fact cost twice its size and a node's header on top: 180 bytes
//! for an 88-byte value, which on a capture of fragments was the largest thing a
//! row cost.
//!
//! # What makes a log enough
//!
//! The keys are produced-indexes, which a list hands out in order and never
//! reuses, so every insert is past the last key; a discard takes the oldest row,
//! so a removal is nearly always at the front; and a lookup is by key. That is an
//! append-only sorted log with a bisection for the key, which [`ChunkLog`] already
//! is for the rows themselves: a position is O(1), a chunk is freed whole when its
//! last entry goes, and nothing is copied when it grows.
//!
//! The one removal that is not at the front (a row a stream is about to release
//! is kept whole, so its facts leave the map) marks its slot dead and leaves it;
//! a dead slot at the front is let go with the next removal that reaches it. The
//! number of dead slots is the number of such rows, which the list bounds.
//!
//! # What it does not do
//!
//! It does not accept a key at or below the last one other than the last itself,
//! which it replaces: that is a precondition of its holders and not something a
//! capture can make false, and it is checked in debug builds. A lookup of a key
//! that was never inserted, or that was removed, is `None`, as in a map.

use crate::chunk_log::ChunkLog;

#[derive(Debug)]
struct Slot<V> {
    key: u64,
    /// `None` once removed from the middle of the log.
    value: Option<V>,
}

/// A map from an ascending `u64` key to a value, as a chunked log.
#[derive(Debug)]
pub struct AscendingMap<V> {
    log: ChunkLog<Slot<V>>,
    /// Slots that hold a value.
    live: usize,
}

impl<V> Default for AscendingMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> AscendingMap<V> {
    /// An empty map.
    pub const fn new() -> Self {
        Self {
            log: ChunkLog::new(),
            live: 0,
        }
    }

    /// Keys that hold a value.
    pub fn len(&self) -> usize {
        self.live
    }

    /// No key holds a value.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The position of the slot for `key`, if there is one.
    fn find(&self, key: u64) -> Option<usize> {
        let at = self.log.partition_point(|slot| slot.key < key);
        self.log.get(at).filter(|slot| slot.key == key).map(|_| at)
    }

    /// The value at `key`.
    pub fn get(&self, key: u64) -> Option<&V> {
        self.log.get(self.find(key)?)?.value.as_ref()
    }

    /// Put `value` at `key`, which is past every key held, or is the last one (its
    /// value is then replaced, as a map's insert does).
    pub fn insert(&mut self, key: u64, value: V) {
        if let Some(last) = self.log.back() {
            debug_assert!(
                key >= last.key,
                "an ascending map was given {key} after {}",
                last.key
            );
            if key == last.key {
                let at = self.log.len() - 1;
                if let Some(slot) = self.log.get_mut(at) {
                    if slot.value.is_none() {
                        self.live += 1;
                    }
                    slot.value = Some(value);
                }
                return;
            }
        }
        self.log.push_back(Slot {
            key,
            value: Some(value),
        });
        self.live += 1;
    }

    /// Take the value at `key` out. A slot that is at the front once it is empty is
    /// let go, with any empty ones behind it.
    pub fn remove(&mut self, key: u64) -> Option<V> {
        let at = self.find(key)?;
        let value = self.log.get_mut(at)?.value.take()?;
        self.live -= 1;
        while self.log.front().is_some_and(|slot| slot.value.is_none()) {
            let _ = self.log.pop_front();
        }
        Some(value)
    }

    /// Every value held, in key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.log.iter_from(0).filter_map(|slot| slot.value.as_ref())
    }

    /// Bytes the map has allocated: every chunk's capacity and the list of chunks.
    pub fn allocated_bytes(&self) -> usize {
        self.log.allocated_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// A small deterministic generator, so the test needs no dependency.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    /// The map answers as the `BTreeMap` it replaces under the pattern of its
    /// holders: keys inserted in ascending order with gaps, removals mostly at the
    /// front and sometimes anywhere, lookups of held, removed and never-held keys.
    #[test]
    fn it_answers_as_the_btree_map_it_replaces() {
        let mut map: AscendingMap<u64> = AscendingMap::new();
        let mut reference: BTreeMap<u64, u64> = BTreeMap::new();
        let mut rng = Lcg(11);
        let mut next_key = 0u64;
        for step in 0..40_000u64 {
            match rng.next() % 10 {
                // Insert: ascending, with gaps (not every row has a fact).
                0..=5 => {
                    next_key += 1 + rng.next() % 3;
                    map.insert(next_key, step);
                    reference.insert(next_key, step);
                }
                // The oldest row goes, as a discard takes it.
                6..=7 => {
                    if let Some((&oldest, _)) = reference.iter().next() {
                        assert_eq!(map.remove(oldest), reference.remove(&oldest), "front");
                    }
                }
                // A row from anywhere is made whole.
                8 => {
                    if let Some((&any, _)) = reference.iter().nth((rng.next() % 50) as usize) {
                        assert_eq!(map.remove(any), reference.remove(&any), "middle");
                    }
                }
                // A key that was never held, or is gone.
                _ => {
                    let probe = rng.next() % (next_key + 5);
                    assert_eq!(map.get(probe), reference.get(&probe), "probe {probe}");
                    assert_eq!(
                        map.remove(probe),
                        reference.remove(&probe),
                        "absent {probe}"
                    );
                }
            }
            assert_eq!(map.len(), reference.len(), "step {step}");
        }
        let held: Vec<(u64, u64)> = reference.iter().map(|(k, v)| (*k, *v)).collect();
        for (key, value) in &held {
            assert_eq!(map.get(*key), Some(value));
        }
        assert!(map.values().copied().eq(reference.values().copied()));
    }

    /// An insert at the last key replaces its value, and one after a removal at
    /// the last key makes a new slot.
    #[test]
    fn an_insert_at_the_last_key_replaces_it() {
        let mut map: AscendingMap<&str> = AscendingMap::new();
        map.insert(4, "a");
        map.insert(4, "b");
        assert_eq!((map.len(), map.get(4)), (1, Some(&"b")));
        assert_eq!(map.remove(4), Some("b"));
        assert!(map.is_empty());
        map.insert(4, "c");
        assert_eq!((map.len(), map.get(4)), (1, Some(&"c")));
    }

    /// A map that has had its front taken gives the chunks back, and an entry costs
    /// its slot (the key and the value, which carries its own tag where it has no
    /// niche to hold one in) and no node around it.
    #[test]
    fn chunks_go_with_the_front_and_an_entry_costs_its_size() {
        let mut map: AscendingMap<[u8; 24]> = AscendingMap::new();
        for key in 1..=20_000u64 {
            map.insert(key, [0; 24]);
        }
        let slot = core::mem::size_of::<Slot<[u8; 24]>>() as f64;
        let per_entry = map.allocated_bytes() as f64 / 20_000.0;
        assert!(
            per_entry < slot * 1.05,
            "an entry costs {per_entry:.1} bytes against a slot of {slot}"
        );
        let full = map.allocated_bytes();
        for key in 1..=15_000u64 {
            map.remove(key);
        }
        assert!(
            map.allocated_bytes() < full / 2,
            "the front's chunks were not given back"
        );
    }
}
