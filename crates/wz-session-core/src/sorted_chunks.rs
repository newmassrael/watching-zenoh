// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An ordered map held as a list of sorted chunks, every byte of which is counted.
//!
//! Open-debt item 924, step 5 (`docs/dissect-row-index.md`, D7). The structures a
//! message list keeps for some of its rows (the rows kept whole, where a unit ends
//! on the wire, the facts few rows have) and the census's write buffers were
//! `BTreeMap`s. A B-tree is an ordered map, which is what they need, and the
//! standard library does not say how many nodes one holds. A memory report over it
//! is a MODEL of the nodes, checked against the allocator and never equal to it:
//! the model was 3% off for a map filled in an order it did not describe, and a
//! report that is a few percent off cannot tell a structure that grew from the
//! model being wrong.
//!
//! # What this is instead
//!
//! A deque of chunks, each a sorted `Vec` of at most [`CHUNK`] entries, found by
//! bisecting the chunks' first keys and then the chunk. An insert is O(chunk) in
//! the worst case and a plain append at the end, which is what a key handed out in
//! order is, is O(1) and leaves every chunk full. A removal that empties the
//! oldest chunk gives it back whole. Every allocation is a `Vec` or the deque of
//! them, so the bytes held are the capacities and are exact: [`SortedChunks::allocated_bytes`]
//! is the allocator's figure, not an estimate of it.
//!
//! # Why not a hash map
//!
//! The holders read their entries in key order (a walk of the rows in order, a
//! trim from the front), and a hash map would need a second ordered structure
//! beside it.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Entries a chunk holds at most. A chunk of 64 is a few cache lines of entries,
/// and the chunk list stays short: one entry of it per 64 of the map.
pub const CHUNK: usize = 64;

/// Where a full chunk is split: the entries from here on go to the chunk after it.
const HALF: usize = CHUNK / 2;

/// A map from an ordered key to a value, in sorted chunks.
#[derive(Debug, Clone)]
pub struct SortedChunks<K, V> {
    /// Ordered by key, and every chunk is non-empty and sorted: the first key of
    /// a chunk is above the last key of the chunk before it.
    chunks: VecDeque<Vec<(K, V)>>,
    len: usize,
}

impl<K, V> Default for SortedChunks<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> SortedChunks<K, V> {
    /// An empty map.
    pub const fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            len: 0,
        }
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// No entry is held.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Let every entry go and give back every chunk.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.len = 0;
    }

    /// Bytes the map has allocated: every chunk's capacity and the list of chunks.
    /// Exact, because every allocation is a `Vec` or the deque that holds them.
    pub fn allocated_bytes(&self) -> usize {
        // Allocated bytes are below `isize::MAX`, so no product or sum here saturates.
        self.chunks
            .iter()
            .map(|chunk| {
                chunk
                    .capacity()
                    .saturating_mul(core::mem::size_of::<(K, V)>())
            })
            .fold(
                self.chunks
                    .capacity()
                    .saturating_mul(core::mem::size_of::<Vec<(K, V)>>()),
                usize::saturating_add,
            )
    }

    /// Every entry, in key order.
    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.chunks.iter().flatten()
    }

    /// Every value, in key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    /// Keep the entries `keep` says yes to, in one pass, and give back every
    /// chunk left with none. The order of what is kept does not move, so every
    /// chunk is still sorted and above the one before it.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        for chunk in &mut self.chunks {
            chunk.retain(|(k, v)| keep(k, v));
        }
        self.chunks.retain(|chunk| !chunk.is_empty());
        self.len = self.chunks.iter().map(Vec::len).sum();
    }
}

impl<K: Ord, V> SortedChunks<K, V> {
    /// The chunk `key` belongs in, and whether it is the one before the first
    /// (a key below every key held goes at the front of the first chunk). With no
    /// chunk held it is `0`, which names none.
    fn chunk_for(&self, key: &K) -> usize {
        self.chunks
            .partition_point(|chunk| chunk.first().is_some_and(|(first, _)| first <= key))
            .saturating_sub(1)
    }

    /// Where `key` is: its chunk and its place in it.
    fn find(&self, key: &K) -> Option<(usize, usize)> {
        let at = self.chunk_for(key);
        let place = self
            .chunks
            .get(at)?
            .binary_search_by(|(k, _)| k.cmp(key))
            .ok()?;
        Some((at, place))
    }

    /// The value at `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        let (at, place) = self.find(key)?;
        self.chunks.get(at)?.get(place).map(|(_, value)| value)
    }

    /// The value at `key`, for writing.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let (at, place) = self.find(key)?;
        self.chunks
            .get_mut(at)?
            .get_mut(place)
            .map(|(_, value)| value)
    }

    /// Whether `key` holds a value.
    pub fn contains_key(&self, key: &K) -> bool {
        self.find(key).is_some()
    }

    /// Put `value` at `key`, and return the value it replaced.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let at = self.chunk_for(&key);
        // `at` names a chunk whenever one is held: past it is a chunk of its own.
        let next = at.saturating_add(1);
        let is_last = next == self.chunks.len();
        let Some(chunk) = self.chunks.get_mut(at) else {
            self.chunks.push_back(Self::new_chunk(key, value));
            self.len = self.len.saturating_add(1);
            return None;
        };
        match chunk.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(place) => chunk
                .get_mut(place)
                .map(|(_, held)| core::mem::replace(held, value)),
            Err(place) => {
                self.len = self.len.saturating_add(1);
                if chunk.len() < CHUNK {
                    chunk.insert(place, (key, value));
                } else if is_last && place == CHUNK {
                    // An append past the end of the last chunk: a chunk of its own,
                    // so a key handed out in order leaves every chunk full.
                    self.chunks.push_back(Self::new_chunk(key, value));
                } else {
                    // A full chunk is split in the middle and the entry goes to the
                    // half it belongs in.
                    let mut upper: Vec<(K, V)> = Vec::with_capacity(CHUNK);
                    upper.extend(chunk.drain(HALF..));
                    match place.checked_sub(HALF) {
                        Some(above) if above > 0 => upper.insert(above, (key, value)),
                        _ => chunk.insert(place, (key, value)),
                    }
                    self.chunks.insert(next, upper);
                }
                None
            }
        }
    }

    /// Take the value at `key` out. A chunk that is left empty is given back.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (at, place) = self.find(key)?;
        let chunk = self.chunks.get_mut(at)?;
        let (_, value) = chunk.remove(place);
        if chunk.is_empty() {
            let _ = self.chunks.remove(at);
        }
        self.len = self.len.saturating_sub(1);
        Some(value)
    }

    /// Move every entry of `other` in, which is left empty. A key held in both is
    /// `other`'s.
    pub fn append(&mut self, other: &mut Self) {
        if other.is_empty() {
            return;
        }
        let mine = self.chunks.back().and_then(|chunk| chunk.last());
        let theirs = other.chunks.front().and_then(|chunk| chunk.first());
        let past_the_end = match (mine, theirs) {
            (Some((mine, _)), Some((theirs, _))) => mine < theirs,
            _ => true,
        };
        if past_the_end {
            // Whole chunks, with no entry moved: the map a fold appends to is
            // usually older than what it takes.
            self.len = self.len.saturating_add(other.len);
            self.chunks.append(&mut other.chunks);
            other.len = 0;
            return;
        }
        let chunks = core::mem::take(&mut other.chunks);
        other.len = 0;
        for (key, value) in chunks.into_iter().flatten() {
            let _ = self.insert(key, value);
        }
    }

    fn new_chunk(key: K, value: V) -> Vec<(K, V)> {
        let mut chunk = Vec::with_capacity(CHUNK);
        chunk.push((key, value));
        chunk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

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

    /// The map answers as the `BTreeMap` it replaces, under keys in any order:
    /// inserts below, between and above what is held, replacements, removals from
    /// the front and from anywhere, and lookups of held and absent keys. Its
    /// entries read back in key order and its count is the map's.
    #[test]
    fn it_answers_as_the_btree_map_it_replaces() {
        let mut map: SortedChunks<u64, u64> = SortedChunks::new();
        let mut reference: BTreeMap<u64, u64> = BTreeMap::new();
        let mut rng = Lcg(3);
        for step in 0..60_000u64 {
            match rng.next() % 8 {
                0..=3 => {
                    // Scattered keys, so inserts land everywhere and chunks split.
                    let key = rng.next() % 9_000;
                    assert_eq!(map.insert(key, step), reference.insert(key, step));
                }
                4 => {
                    // An ascending run, which is what the list's own keys are.
                    let key = reference
                        .keys()
                        .next_back()
                        .map_or(0, |k| k + 1 + rng.next() % 3);
                    assert_eq!(map.insert(key, step), reference.insert(key, step));
                }
                5 => {
                    if let Some(&oldest) = reference.keys().next() {
                        assert_eq!(map.remove(&oldest), reference.remove(&oldest), "front");
                    }
                }
                6 => {
                    let key = rng.next() % 9_100;
                    assert_eq!(map.remove(&key), reference.remove(&key), "any {key}");
                }
                _ => {
                    let key = rng.next() % 9_100;
                    assert_eq!(map.get(&key), reference.get(&key), "get {key}");
                    if let (Some(a), Some(b)) = (map.get_mut(&key), reference.get_mut(&key)) {
                        *a += 1;
                        *b += 1;
                    }
                    assert_eq!(map.contains_key(&key), reference.contains_key(&key));
                }
            }
            assert_eq!(map.len(), reference.len(), "step {step}");
        }
        assert!(map
            .iter()
            .map(|(k, v)| (*k, *v))
            .eq(reference.iter().map(|(k, v)| (*k, *v))));
        // Every chunk is non-empty and sorted, and the chunks are in order.
        let mut last: Option<u64> = None;
        for chunk in &map.chunks {
            assert!(!chunk.is_empty() && chunk.len() <= CHUNK);
            for (key, _) in chunk {
                assert!(last.is_none_or(|l| l < *key), "{key} is out of order");
                last = Some(*key);
            }
        }
    }

    /// `retain` keeps what a `BTreeMap::retain` keeps, gives back the chunks it
    /// empties, and leaves a map later inserts and removals still answer right.
    #[test]
    fn retain_keeps_what_the_btree_map_keeps() {
        let mut map: SortedChunks<u64, u64> = SortedChunks::new();
        let mut reference: BTreeMap<u64, u64> = BTreeMap::new();
        let mut rng = Lcg(11);
        for step in 0..20_000u64 {
            let key = rng.next() % 30_000;
            map.insert(key, step);
            reference.insert(key, step);
        }
        let chunks_before = map.chunks.len();
        // A front cut and a scattered cut at once.
        let keep = |k: &u64, v: &u64| *k >= 12_000 && v % 5 != 0;
        map.retain(keep);
        reference.retain(|k, v| keep(k, v));
        assert_eq!(map.len(), reference.len());
        assert!(
            map.chunks.len() < chunks_before,
            "emptied chunks are given back"
        );
        assert!(map.chunks.iter().all(|chunk| !chunk.is_empty()));
        for step in 0..5_000u64 {
            let key = rng.next() % 31_000;
            assert_eq!(map.insert(key, step), reference.insert(key, step));
            let gone = rng.next() % 31_000;
            assert_eq!(map.remove(&gone), reference.remove(&gone));
        }
        assert!(map
            .iter()
            .map(|(k, v)| (*k, *v))
            .eq(reference.iter().map(|(k, v)| (*k, *v))));
    }

    /// `append` moves a younger map in whole, merges an overlapping one, and a key
    /// in both is the moved map's.
    #[test]
    fn append_moves_whole_chunks_or_merges() {
        let mut older: SortedChunks<u64, u64> = SortedChunks::new();
        let mut younger: SortedChunks<u64, u64> = SortedChunks::new();
        for key in 0..200u64 {
            older.insert(key, 1);
            younger.insert(key + 200, 2);
        }
        older.append(&mut younger);
        assert!(younger.is_empty() && older.len() == 400);
        assert_eq!(older.get(&150), Some(&1));
        assert_eq!(older.get(&250), Some(&2));

        let mut overlap: SortedChunks<u64, u64> = SortedChunks::new();
        for key in (100..300u64).step_by(7) {
            overlap.insert(key, 3);
        }
        let held = overlap.len();
        let new = (100..300u64).step_by(7).filter(|k| *k >= 400).count();
        older.append(&mut overlap);
        assert!(overlap.is_empty());
        assert_eq!(older.len(), 400 + new, "{held} entries all key held ones");
        assert_eq!(older.get(&107), Some(&3), "the moved map's value wins");
        assert_eq!(older.get(&108), Some(&1));
    }

    /// An ascending fill leaves every chunk full, so an entry costs its size and a
    /// chunk's share of a list; and a removal from the front gives chunks back.
    #[test]
    fn an_ascending_fill_is_dense_and_the_front_gives_chunks_back() {
        let mut map: SortedChunks<u64, [u8; 24]> = SortedChunks::new();
        for key in 0..20_000u64 {
            map.insert(key, [0; 24]);
        }
        let entry = core::mem::size_of::<(u64, [u8; 24])>() as f64;
        let per_entry = map.allocated_bytes() as f64 / 20_000.0;
        assert!(
            per_entry < entry * 1.03,
            "{per_entry:.1} bytes against {entry}"
        );
        let full = map.allocated_bytes();
        for key in 0..15_000u64 {
            map.remove(&key);
        }
        assert!(
            map.allocated_bytes() < full / 3,
            "the front's chunks are not given back"
        );
    }

    /// The count is the allocator's, exactly: every allocation is a `Vec` or the
    /// deque of them, which the capacities add up to. This holds the arithmetic to
    /// the shape: a map of a known number of chunks costs a known number of bytes.
    #[test]
    fn the_count_is_the_capacities() {
        let mut map: SortedChunks<u64, u64> = SortedChunks::new();
        for key in 0..(3 * CHUNK as u64) {
            map.insert(key, key);
        }
        let chunk_bytes = CHUNK * core::mem::size_of::<(u64, u64)>();
        let list = map.chunks.capacity() * core::mem::size_of::<Vec<(u64, u64)>>();
        assert_eq!(map.allocated_bytes(), 3 * chunk_bytes + list);
    }
}
