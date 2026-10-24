// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the selector said of every message row, kept as a pattern a row names.
//!
//! Open-debt item 924, step 5 (`docs/dissect-row-index.md`, D7). A census plane
//! keeps, for each row it judged, the answer of every record the row carries
//! (`RowVerdict`), so a document can say WHICH rows a selector picked. That was a
//! map from a row's coordinate to its own vector of answers: about 100 bytes a
//! row, and one allocation each. The information in it is far smaller. A row
//! carries a handful of records and an answer is one of three words, so the
//! number of DISTINCT answers a capture holds is a handful; what grows with the
//! rows is which of them each row had, and that is a small number.
//!
//! # The structure, and what it keeps from the map it replaces
//!
//! * The distinct answers are kept once, in a trie ([`Patterns`]): a pattern is
//!   its parent's records with one more, so recording a row's next record is a
//!   step to a child and a row is its pattern's number.
//! * The rows are in sorted blocks, one per `(list, direction)`, as two parallel
//!   arrays: the row's coordinate and its pattern's number (12 bytes a row). A
//!   lookup is two bisections.
//! * Recent writes are in a small ordered map beside them (`delta`), folded into
//!   the blocks when they have grown past a fraction of them; the blocks and the
//!   patterns are shared (`Arc`) so a copy of the column costs a pointer and the
//!   delta. This is `crate::overlay_map::OverlayMap`'s shape, with the shared
//!   half held as arrays and not as nodes, which is where the bytes were.
//!
//! What a reader sees is unchanged: [`VerdictColumn::get`] returns the same
//! `&RowVerdict` the map did, in the same order of records, and a row never
//! written has none. `tests::the_column_reads_as_the_map_it_replaces` holds that
//! over writes in any order, copies that are written to and dropped, and folds.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use wz_session_core::sorted_chunks::SortedChunks;

use crate::filter::Truth;
use crate::payload::{RowKey, RowVerdict};

/// The pattern that has no record; no row has it.
const EMPTY: u32 = 0;

/// A child that is not made yet.
const UNSET: u32 = u32::MAX;

/// The word a [`Truth`] indexes a pattern's children by.
const fn word(truth: Truth) -> usize {
    match truth {
        Truth::Yes => 0,
        Truth::No => 1,
        Truth::Unknown => 2,
    }
}

/// One answer sequence, and the sequences that extend it by one record.
#[derive(Debug, Clone)]
struct Pattern {
    verdict: RowVerdict,
    next: [u32; 3],
}

/// Every distinct answer sequence the column holds, as a trie.
#[derive(Debug, Clone)]
struct Patterns {
    list: Vec<Pattern>,
}

impl Default for Patterns {
    fn default() -> Self {
        Self {
            list: alloc::vec![Pattern {
                verdict: RowVerdict::default(),
                next: [UNSET; 3],
            }],
        }
    }
}

impl Patterns {
    /// The pattern that is `from`'s records and one more, made when it is not
    /// there.
    fn extend(&mut self, from: u32, truth: Truth) -> u32 {
        let child = self.list[from as usize].next[word(truth)];
        if child != UNSET {
            return child;
        }
        let mut verdict = self.list[from as usize].verdict.clone();
        verdict.record(truth);
        let made = u32::try_from(self.list.len()).expect("fewer than 2^32 distinct answers");
        self.list.push(Pattern {
            verdict,
            next: [UNSET; 3],
        });
        self.list[from as usize].next[word(truth)] = made;
        made
    }

    #[cfg(any(test, feature = "dissect"))]
    fn bytes(&self) -> usize {
        self.list.capacity() * core::mem::size_of::<Pattern>()
            + self
                .list
                .iter()
                .map(|p| p.verdict.owned_bytes())
                .sum::<usize>()
    }
}

/// The rows of one `(list, direction)`, ascending by coordinate.
#[derive(Debug)]
struct Block {
    list: usize,
    direction: usize,
    at: Vec<usize>,
    pattern: Vec<u32>,
}

/// The sorted half: blocks in `(list, direction)` order.
#[derive(Debug, Default)]
struct Base {
    blocks: Vec<Block>,
    rows: usize,
}

impl Base {
    fn find(&self, key: &RowKey) -> Option<u32> {
        let (list, direction, at) = key.parts();
        let block = self
            .blocks
            .binary_search_by(|b| (b.list, b.direction).cmp(&(list, direction)))
            .ok()?;
        let block = &self.blocks[block];
        let row = block.at.binary_search(&at).ok()?;
        Some(block.pattern[row])
    }

    fn entries(&self) -> impl Iterator<Item = (RowKey, u32)> + '_ {
        self.blocks.iter().flat_map(|b| {
            b.at.iter()
                .zip(b.pattern.iter())
                .map(move |(at, pattern)| (RowKey::from_parts(b.list, b.direction, *at), *pattern))
        })
    }

    #[cfg(any(test, feature = "dissect"))]
    fn bytes(&self) -> usize {
        self.blocks.capacity() * core::mem::size_of::<Block>()
            + self
                .blocks
                .iter()
                .map(|b| {
                    b.at.capacity() * core::mem::size_of::<usize>()
                        + b.pattern.capacity() * core::mem::size_of::<u32>()
                })
                .sum::<usize>()
    }

    /// This base with `delta` written over it, in blocks of exactly the size
    /// they hold.
    fn merged(&self, delta: &SortedChunks<RowKey, u32>) -> Self {
        let mut counts: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        for b in &self.blocks {
            *counts.entry((b.list, b.direction)).or_default() += b.at.len();
        }
        for key in delta
            .iter()
            .map(|(key, _)| key)
            .filter(|key| self.find(key).is_none())
        {
            let (list, direction, _) = key.parts();
            *counts.entry((list, direction)).or_default() += 1;
        }
        let mut blocks: Vec<Block> = counts
            .iter()
            .map(|(&(list, direction), &n)| Block {
                list,
                direction,
                at: Vec::with_capacity(n),
                pattern: Vec::with_capacity(n),
            })
            .collect();
        let mut rows = 0;
        let mut old = self.entries().peekable();
        let mut new = delta.iter().map(|(k, p)| (*k, *p)).peekable();
        loop {
            let (key, pattern) = match (old.peek(), new.peek()) {
                (None, None) => break,
                (Some(_), None) => old.next().expect("peeked"),
                (None, Some(_)) => new.next().expect("peeked"),
                (Some((a, _)), Some((b, _))) => match a.cmp(b) {
                    core::cmp::Ordering::Less => old.next().expect("peeked"),
                    core::cmp::Ordering::Greater => new.next().expect("peeked"),
                    // The recent write replaces the sorted one.
                    core::cmp::Ordering::Equal => {
                        let _ = old.next();
                        new.next().expect("peeked")
                    }
                },
            };
            let (list, direction, at) = key.parts();
            // Entries arrive in key order, so a row goes to the last block that
            // is its own or the next one.
            let block = blocks
                .binary_search_by(|b| (b.list, b.direction).cmp(&(list, direction)))
                .expect("a block was counted for every row");
            blocks[block].at.push(at);
            blocks[block].pattern.push(pattern);
            rows += 1;
        }
        Self { blocks, rows }
    }
}

/// What the selector said of each row, by the row's coordinate.
#[derive(Debug, Clone, Default)]
pub(crate) struct VerdictColumn {
    patterns: Arc<Patterns>,
    base: Arc<Base>,
    delta: SortedChunks<RowKey, u32>,
}

impl VerdictColumn {
    /// What the selector said of the row at `key`, when the walk judged it.
    pub(crate) fn get(&self, key: &RowKey) -> Option<&RowVerdict> {
        let pattern = self
            .delta
            .get(key)
            .copied()
            .or_else(|| self.base.find(key))?;
        Some(&self.patterns.list[pattern as usize].verdict)
    }

    /// Add one record's answer to the row at `key`: the row's pattern becomes the
    /// pattern with one more record.
    pub(crate) fn record(&mut self, key: RowKey, truth: Truth) {
        self.fold_into_base_if_due();
        let from = self
            .delta
            .get(&key)
            .copied()
            .or_else(|| self.base.find(&key))
            .unwrap_or(EMPTY);
        let to = Arc::make_mut(&mut self.patterns).extend(from, truth);
        self.delta.insert(key, to);
    }

    /// How many rows the column holds.
    #[cfg(any(test, feature = "dissect"))]
    pub(crate) fn len(&self) -> usize {
        let fresh = self
            .delta
            .iter()
            .filter(|(key, _)| self.base.find(key).is_none())
            .count();
        self.base.rows + fresh
    }

    /// Bytes the column holds: the sorted rows, the recent writes and the
    /// patterns, each as its own allocations say.
    #[cfg(any(test, feature = "dissect"))]
    pub(crate) fn memory(&self) -> usize {
        self.base.bytes() + self.delta.allocated_bytes() + self.patterns.bytes()
    }

    /// Fold `delta` into the sorted rows when it has grown past a fraction of
    /// them and nothing else holds them, which is what keeps a copy that is alive
    /// (a reading in progress) from making the fold copy the rows.
    fn fold_into_base_if_due(&mut self) {
        if self.delta.len() <= 64 + self.base.rows / 32 {
            return;
        }
        if let Some(base) = Arc::get_mut(&mut self.base) {
            *base = base.merged(&self.delta);
            self.delta.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(list: usize, direction: usize, at: usize) -> RowKey {
        RowKey::from_parts(list, direction, at)
    }

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

    fn truth_of(n: u64) -> Truth {
        match n % 3 {
            0 => Truth::Yes,
            1 => Truth::No,
            _ => Truth::Unknown,
        }
    }

    /// The column reads as the map of vectors it replaces: over writes in any
    /// order and to rows already written, across folds into the sorted rows, and
    /// across copies that were written to and dropped.
    #[test]
    fn the_column_reads_as_the_map_it_replaces() {
        let mut column = VerdictColumn::default();
        let mut reference: BTreeMap<RowKey, Vec<Truth>> = BTreeMap::new();
        let mut rng = Lcg(7);
        for round in 0..30_000u64 {
            let k = key(
                (rng.next() % 3) as usize,
                (rng.next() % 2) as usize,
                (rng.next() % 4_000) as usize,
            );
            let t = truth_of(rng.next());
            column.record(k, t);
            reference.entry(k).or_default().push(t);
            // A reading: a copy that is written to and dropped must leave this
            // column as it was.
            if round % 997 == 0 {
                let mut reading = column.clone();
                reading.record(key(9, 9, round as usize), Truth::Yes);
                assert!(reading.get(&key(9, 9, round as usize)).is_some());
                assert!(column.get(&key(9, 9, round as usize)).is_none());
            }
        }
        assert_eq!(column.len(), reference.len());
        for (k, want) in &reference {
            assert_eq!(
                column.get(k).map(RowVerdict::records),
                Some(want.as_slice()),
                "{k:?}"
            );
        }
        // And a row never written has none.
        assert!(column.get(&key(0, 0, 4_001)).is_none());
        assert!(column.get(&key(5, 0, 0)).is_none());
        // The recent writes were folded into the sorted rows along the way.
        assert!(column.base.rows > 0, "no fold happened");
    }

    /// The distinct answers are few however many rows have them, and what a row
    /// costs is its coordinate and a pattern number.
    #[test]
    fn a_row_costs_a_coordinate_and_a_pattern_number() {
        let mut column = VerdictColumn::default();
        for at in 0..20_000usize {
            column.record(key(0, 0, at), Truth::Yes);
        }
        assert_eq!(column.patterns.list.len(), 2, "the empty pattern and [Yes]");
        let per_row = column.memory() as f64 / 20_000.0;
        // 12 bytes a folded row, and the recent writes not yet folded: at most
        // 1/32 of the rows and a few dozen, each a map entry's share.
        assert!(
            per_row < 16.0,
            "a row costs {per_row:.1} bytes, over the 12 plus what has not folded"
        );
    }
}
