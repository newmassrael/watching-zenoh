// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A small word per row, in a column indexed by the row's number: half a byte a
//! row.
//!
//! Open-debt item 924, step 5 (`docs/dissect-row-index.md`, D7). The selection
//! door remembers the word a selector said of each row (`yes`, `no`, `undecided`,
//! `unjudged`) so the next call can say which moved. That was a `BTreeMap` from a
//! row number to a four-valued enum: a map node's share of the row, about 40
//! bytes, to hold two bits. A row number is a small integer the handle hands out
//! in order and a word is one of a few, so the memory is what the digest column
//! is (`crate::digest_column`) with the cell narrowed to a nibble.
//!
//! A nibble holds `0` for no word and `1..=15` for a word the holder numbers, so a
//! cell needs no tag beside it. Chunks are allocated when a row in them is first
//! written and the rows are given back whole when a holder replaces the column,
//! which is what a selection memory does on every call.

use alloc::boxed::Box;
use alloc::collections::VecDeque;

/// Rows in a chunk: 2 KiB.
const CHUNK_ROWS: usize = 4096;

/// Bytes in a chunk, two rows to a byte.
const CHUNK_BYTES: usize = CHUNK_ROWS / 2;

type Chunk = Box<[u8; CHUNK_BYTES]>;

/// One word, `1..=15`, or none, for each row number.
#[derive(Debug, Clone, Default)]
pub(crate) struct WordColumn {
    /// The number of the chunk `chunks[0]` is.
    first: u64,
    chunks: VecDeque<Option<Chunk>>,
    /// Rows that hold a word.
    len: usize,
}

impl WordColumn {
    /// Rows that hold a word.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// No row holds a word.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn locate(seq: u64) -> (u64, usize, u32) {
        let chunk = seq / CHUNK_ROWS as u64;
        let row = (seq % CHUNK_ROWS as u64) as usize;
        (chunk, row / 2, (row as u32 % 2) * 4)
    }

    /// The word of row `seq`, if it holds one.
    pub(crate) fn get(&self, seq: u64) -> Option<u8> {
        let (chunk, byte, shift) = Self::locate(seq);
        let at = chunk.checked_sub(self.first)?;
        let Some(Some(bytes)) = self.chunks.get(at as usize) else {
            return None;
        };
        match (bytes[byte] >> shift) & 0xF {
            0 => None,
            word => Some(word),
        }
    }

    /// Say what row `seq` holds: a word in `1..=15`, or nothing.
    pub(crate) fn set(&mut self, seq: u64, word: Option<u8>) {
        debug_assert!(
            word.is_none_or(|w| (1..=15).contains(&w)),
            "a word is 1..=15"
        );
        let held_before = self.get(seq).is_some();
        let (chunk, byte, shift) = Self::locate(seq);
        if word.is_none() && !held_before {
            return;
        }
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
        let bytes = self.chunks[at].get_or_insert_with(|| Box::new([0; CHUNK_BYTES]));
        bytes[byte] = (bytes[byte] & !(0xF << shift)) | (word.unwrap_or(0) << shift);
        match (held_before, word.is_some()) {
            (false, true) => self.len += 1,
            (true, false) => self.len -= 1,
            _ => {}
        }
    }

    /// Bytes the column has allocated: its chunks and the deque that holds them.
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.chunks.capacity() * core::mem::size_of::<Option<Chunk>>()
            + self.chunks.iter().flatten().count() * CHUNK_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// The column answers as the map it replaces did, over writes in any order,
    /// rewrites and removals.
    #[test]
    fn a_column_reads_as_the_map_it_replaces() {
        let mut column = WordColumn::default();
        let mut map: BTreeMap<u64, u8> = BTreeMap::new();
        for n in 0..20_000u64 {
            let seq = (n * 7_919) % 30_011 + 1;
            let word = (n % 4) as u8 + 1;
            column.set(seq, Some(word));
            map.insert(seq, word);
            if n % 5 == 0 {
                column.set(seq, None);
                map.remove(&seq);
            }
        }
        assert_eq!(column.len(), map.len());
        for seq in 0..30_100u64 {
            assert_eq!(column.get(seq), map.get(&seq).copied(), "row {seq}");
        }
    }

    /// Two rows to a byte, so a column of dense rows costs half a byte a row.
    #[test]
    fn a_row_costs_half_a_byte() {
        let mut column = WordColumn::default();
        for seq in 1..=40_000u64 {
            column.set(seq, Some(3));
        }
        let per_row = column.allocated_bytes() as f64 / 40_000.0;
        assert!(per_row < 0.6, "a row costs {per_row:.2} bytes");
    }

    /// Writing nothing to a row that holds nothing allocates nothing.
    #[test]
    fn clearing_a_row_that_holds_nothing_allocates_nothing() {
        let mut column = WordColumn::default();
        column.set(1_000_000, None);
        assert_eq!(column.chunks.iter().flatten().count(), 0);
        assert!(column.is_empty());
    }
}
