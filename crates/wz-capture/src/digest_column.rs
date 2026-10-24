// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The field walk's memory of the rows it has written: one 64-bit digest per row,
//! in a column indexed by the row's sequence number.
//!
//! Open-debt item 924, step 5 (`docs/dissect-row-index.md`, D7). The digests were
//! a `BTreeMap<u64, Option<u64>>`, which holds a node's share of 24 bytes of
//! payload per row and about 50 bytes in all. What the walk needs of them is
//! small and exact: for a row number, the digest of what the row read last time,
//! and nothing when it read `declined`. A row number is a small integer the
//! handle hands out in order, so the digest is one word at an index.
//!
//! # Why a column and not a hash of a block
//!
//! A block digest would say which stretch of rows changed and not which row, and
//! the document names the rows it writes again (`revised`): reporting the stretch
//! would call unchanged rows revised, which is a false statement to a consumer
//! that redraws what it is told moved. The per-row word is the least that
//! localises a change exactly, and 64 bits is what the digest already was.
//!
//! # Shape
//!
//! Chunks of [`CHUNK`] words, in a deque indexed by `seq / CHUNK`, each allocated
//! when a row in it is first written and given back when none is held: a front
//! trim that takes the oldest rows frees whole chunks, and a handle that holds
//! rows by number far apart pays for the chunks they sit in and no others. A cell
//! holds `0` for no digest, and a digest is never `0` (see [`Self::set`]), so a
//! cell needs no tag beside it. A second reserved word ([`DECLINED`]) lets one
//! document's column say that a row it wrote now reads `declined`, which, merged
//! into the memory's column, removes the digest an earlier document left: it is
//! what an `Option` inside the old map was for.

use alloc::boxed::Box;
use alloc::collections::VecDeque;

/// Words in a chunk: 8 KiB.
const CHUNK: usize = 1024;

/// A cell that holds no digest.
const NONE: u64 = 0;

/// A cell that says the row read `declined` in the document this column belongs
/// to. Never kept by a column that is a memory: [`DigestColumn::extend_from`]
/// turns it into the removal it stands for.
const DECLINED: u64 = u64::MAX;

/// A digest is never [`NONE`] or [`DECLINED`], so a cell is its own tag. The
/// digests it moves are at most 2 of 2^64, and a row whose digest moved to the
/// other one of the two is a row reported unchanged with probability 2^-64.
const fn word(digest: u64) -> u64 {
    if digest == NONE || digest == DECLINED {
        1
    } else {
        digest
    }
}

type Chunk = Box<[u64; CHUNK]>;

/// One digest per row, by sequence number.
#[derive(Debug, Clone, Default)]
pub(crate) struct DigestColumn {
    /// The number of the chunk `chunks[0]` is.
    first: u64,
    /// `None` for a chunk in which no row is held.
    chunks: VecDeque<Option<Chunk>>,
    /// Rows with a digest.
    len: usize,
}

impl DigestColumn {
    /// An empty column.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Rows that hold a digest.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// No row holds a digest.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn cell(&self, seq: u64) -> u64 {
        let chunk = seq / CHUNK as u64;
        let Some(at) = chunk.checked_sub(self.first) else {
            return NONE;
        };
        match self.chunks.get(at as usize) {
            Some(Some(words)) => words[(seq % CHUNK as u64) as usize],
            _ => NONE,
        }
    }

    /// The digest of row `seq`, if it holds one.
    pub(crate) fn get(&self, seq: u64) -> Option<u64> {
        match self.cell(seq) {
            NONE | DECLINED => None,
            digest => Some(digest),
        }
    }

    /// The chunk row `seq` is in, made when it is not there.
    fn chunk_for(&mut self, seq: u64) -> &mut Chunk {
        let chunk = seq / CHUNK as u64;
        if self.chunks.is_empty() {
            self.first = chunk;
        }
        while chunk < self.first {
            self.chunks.push_front(None);
            self.first -= 1;
        }
        let at = (chunk - self.first) as usize;
        while self.chunks.len() <= at {
            self.chunks.push_back(None);
        }
        self.chunks[at].get_or_insert_with(|| Box::new([NONE; CHUNK]))
    }

    /// Say what row `seq` reads: a digest, or nothing (`None`: it read
    /// `declined`). In a column that is a memory this is the whole of the row's
    /// state; in a column built for one document it is what the document wrote,
    /// and a row that read `declined` is kept as such until the column is merged.
    pub(crate) fn set(&mut self, seq: u64, digest: Option<u64>) {
        let cell = digest.map_or(DECLINED, word);
        let held_before = !matches!(self.cell(seq), NONE | DECLINED);
        let slot = (seq % CHUNK as u64) as usize;
        self.chunk_for(seq)[slot] = cell;
        let held_after = cell != DECLINED;
        match (held_before, held_after) {
            (false, true) => self.len += 1,
            (true, false) => self.len -= 1,
            _ => {}
        }
    }

    /// Forget row `seq`: no digest, and no tombstone either. What a column that
    /// is a memory does when a document says the row reads `declined`.
    pub(crate) fn remove(&mut self, seq: u64) {
        let chunk = seq / CHUNK as u64;
        let Some(at) = chunk.checked_sub(self.first) else {
            return;
        };
        let Some(Some(words)) = self.chunks.get_mut(at as usize) else {
            return;
        };
        let cell = &mut words[(seq % CHUNK as u64) as usize];
        if !matches!(*cell, NONE | DECLINED) {
            self.len -= 1;
        }
        *cell = NONE;
    }

    /// Every row with a digest and its digest, in ascending order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(at, chunk)| chunk.as_ref().map(|words| (at, words)))
            .flat_map(move |(at, words)| {
                let base = (self.first + at as u64) * CHUNK as u64;
                words
                    .iter()
                    .enumerate()
                    .filter(|(_, w)| !matches!(**w, NONE | DECLINED))
                    .map(move |(i, w)| (base + i as u64, *w))
            })
    }

    /// What `other` says of its rows, said of this column's: a digest replaces
    /// this column's, and a row `other` read as `declined` loses the one it had.
    pub(crate) fn extend_from(&mut self, other: &Self) {
        for (at, chunk) in other.chunks.iter().enumerate() {
            let Some(words) = chunk else { continue };
            let base = (other.first + at as u64) * CHUNK as u64;
            for (i, w) in words.iter().enumerate() {
                match *w {
                    NONE => {}
                    DECLINED => self.remove(base + i as u64),
                    digest => self.set(base + i as u64, Some(digest)),
                }
            }
        }
    }

    /// Keep the rows `keep` says to, and give back the chunks nothing is left in.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(u64) -> bool) {
        for (at, chunk) in self.chunks.iter_mut().enumerate() {
            let Some(words) = chunk else { continue };
            let base = (self.first + at as u64) * CHUNK as u64;
            let mut any = false;
            for (i, w) in words.iter_mut().enumerate() {
                if matches!(*w, NONE | DECLINED) {
                    *w = NONE;
                } else if keep(base + i as u64) {
                    any = true;
                } else {
                    *w = NONE;
                    self.len -= 1;
                }
            }
            if !any {
                *chunk = None;
            }
        }
        while matches!(self.chunks.front(), Some(None)) {
            self.chunks.pop_front();
            self.first += 1;
        }
        while matches!(self.chunks.back(), Some(None)) {
            self.chunks.pop_back();
        }
    }

    /// Bytes the column has allocated: its chunks and the deque that holds them.
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.chunks.capacity() * core::mem::size_of::<Option<Chunk>>()
            + self.chunks.iter().flatten().count() * CHUNK * core::mem::size_of::<u64>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    /// The column answers as the map it replaces did, over writes in any order,
    /// rewrites, removals and a trim.
    #[test]
    fn a_column_reads_as_the_map_it_replaces() {
        let mut column = DigestColumn::new();
        let mut map: BTreeMap<u64, u64> = BTreeMap::new();
        // Row numbers scattered over many chunks, written out of order.
        let seqs: Vec<u64> = (0..5_000u64).map(|n| (n * 7_919) % 9_973 + 1).collect();
        for (n, seq) in seqs.iter().enumerate() {
            let digest = (n as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 2;
            column.set(*seq, Some(digest));
            map.insert(*seq, digest);
        }
        // Rewrites, and rows that now read `declined`.
        for seq in seqs.iter().step_by(3) {
            column.remove(*seq);
            map.remove(seq);
        }
        assert_eq!(column.len(), map.len());
        for seq in 0..10_100u64 {
            assert_eq!(column.get(seq), map.get(&seq).copied(), "row {seq}");
        }
        assert!(column.iter().eq(map.iter().map(|(s, d)| (*s, *d))));

        column.retain(|seq| seq > 6_000);
        map.retain(|seq, _| *seq > 6_000);
        assert_eq!(column.len(), map.len());
        assert!(column.iter().eq(map.iter().map(|(s, d)| (*s, *d))));
    }

    /// A digest that would be a reserved word is kept as another, and both sides
    /// of a comparison go through the same `set`, so equal rows stay equal.
    #[test]
    fn a_digest_that_is_a_reserved_word_still_reads_back() {
        let mut column = DigestColumn::new();
        column.set(1, Some(0));
        column.set(2, Some(u64::MAX));
        assert_eq!(column.get(1), Some(1));
        assert_eq!(column.get(2), Some(1));
        assert_eq!(column.len(), 2);
    }

    /// A row a document read as `declined` removes the digest an earlier document
    /// left, when the document's column is merged into the memory's.
    #[test]
    fn a_declined_row_removes_the_digest_it_replaces() {
        let mut memory = DigestColumn::new();
        memory.set(10, Some(7));
        memory.set(11, Some(8));
        let mut document = DigestColumn::new();
        document.set(10, None);
        document.set(12, Some(9));
        assert_eq!(document.len(), 1, "a declined row holds no digest");
        memory.extend_from(&document);
        assert_eq!(memory.get(10), None);
        assert_eq!(memory.get(11), Some(8));
        assert_eq!(memory.get(12), Some(9));
        assert_eq!(memory.len(), 2);
    }

    /// A trim that takes the oldest rows gives their chunks back, and rows
    /// numbered far apart cost the chunks they sit in.
    #[test]
    fn chunks_are_given_back_when_no_row_is_left_in_them() {
        let mut column = DigestColumn::new();
        for seq in 1..=(3 * CHUNK as u64) {
            column.set(seq, Some(5));
        }
        let full = column.allocated_bytes();
        assert!(full >= 3 * CHUNK * 8);
        column.retain(|seq| seq > 2 * CHUNK as u64);
        assert!(
            column.allocated_bytes() < full - CHUNK * 8,
            "the two oldest chunks are given back"
        );
        column.retain(|_| false);
        assert!(column.is_empty());
        // The deque's own buffer is left, a few words; no chunk is.
        assert_eq!(column.chunks.iter().flatten().count(), 0);

        let mut far = DigestColumn::new();
        far.set(5, Some(1));
        far.set(5_000_000, Some(1));
        assert_eq!(far.chunks.iter().flatten().count(), 2);
    }
}
