// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An append-only log of rows of 64-bit columns, read by position and released
//! from the front, kept by frame of reference.
//!
//! Open-debt item 924, D10 (`docs/dissect-row-index.md`). A row of a capture's
//! index is a handful of 64-bit values (an offset, a place, a packet number, an
//! instant). Most rise from one row to the next by a little, so a row that stores
//! each whole stores mostly zeros: eight bytes for a distance that fits in four.
//! This log stores a chunk's first row once, as the chunk's BASE, and every row of
//! the chunk as the `N` columns' 32-bit distances from the base: half the bytes,
//! and the same value back out.
//!
//! # Two kinds of column
//!
//! A column that RISES SLOWLY (a stream offset, a place in a container, a packet
//! number) is a distance from the base. A column that does not (a capture
//! instant in nanoseconds, which moves four billion in four seconds, so a flow
//! that sends one segment a second would end a chunk every fourth row) is kept
//! whole, as one of the `W` raw columns. Which is which is the holder's decision
//! and is made for each column once, by what the data is, and not by a rule the
//! log applies at run time.
//!
//! # No escape code
//!
//! A row whose rebased columns do not fit (one below the base, or more than
//! `u32::MAX` above it) begins a new chunk and is that chunk's base. So there is
//! no exception table to search, no value the log cannot hold and nothing a
//! reader must test for: a chunk is shorter than [`CHUNK_ITEMS`] only where the
//! data is unlike what a capture does, and a short chunk is given back what it did
//! not use. The worst case (every row breaks) costs a chunk header a row, which is
//! what a log of unrelated values deserves to cost.
//!
//! # Position
//!
//! A chunk knows how many rows came before it over the log's life, so a position
//! is found by bisecting the chunks and then indexing one: the rows before it are
//! not read, and a chunk may be any length up to [`CHUNK_ITEMS`]. A release from
//! the front moves a counter, and a chunk whose rows are all released is dropped.
//!
//! # What it reports
//!
//! [`ColumnLog::allocated_bytes`] is a capacity times an element, as
//! [`crate::chunk_log::ChunkLog`]'s is, so a holder's memory report stays exact.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::chunk_log::CHUNK_ITEMS;

/// One row: the `N` columns kept as distances from their chunk's base, and the
/// `W` kept whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row<const N: usize, const W: usize> {
    /// The columns that rise slowly: at or above the chunk's base in the log.
    pub rebased: [u64; N],
    /// The columns kept whole.
    pub raw: [u64; W],
}

/// One chunk: a base, and the rows of it.
#[derive(Debug)]
struct Chunk<const N: usize, const W: usize> {
    /// Rows pushed before this chunk's first, over the log's life.
    start: u64,
    /// The chunk's first row's rebased columns: every row's are at or above it.
    base: [u64; N],
    /// The rows' rebased columns, as distances from [`Self::base`].
    near: Vec<[u32; N]>,
    /// The rows' raw columns.
    raw: Vec<[u64; W]>,
}

impl<const N: usize, const W: usize> Chunk<N, W> {
    /// Whether `row` is a distance a row of this chunk can hold from the base.
    fn takes(&self, rebased: &[u64; N]) -> bool {
        self.near.len() < CHUNK_ITEMS
            && rebased.iter().zip(&self.base).all(|(value, base)| {
                value
                    .checked_sub(*base)
                    .is_some_and(|d| d <= u32::MAX as u64)
            })
    }

    fn row(&self, at: usize) -> Option<Row<N, W>> {
        let near = self.near.get(at)?;
        let mut rebased = self.base;
        for (value, near) in rebased.iter_mut().zip(near) {
            *value += u64::from(*near);
        }
        Some(Row {
            rebased,
            raw: *self.raw.get(at)?,
        })
    }

    fn len(&self) -> usize {
        self.near.len()
    }

    fn shrink_to_fit(&mut self) {
        self.near.shrink_to_fit();
        self.raw.shrink_to_fit();
    }
}

/// An append-only log of rows of `N` rebased and `W` raw 64-bit columns, read by
/// position and released from the front.
#[derive(Debug)]
pub struct ColumnLog<const N: usize, const W: usize> {
    chunks: VecDeque<Chunk<N, W>>,
    /// Rows pushed over the log's life.
    pushed: u64,
    /// Rows released over the log's life.
    released: u64,
}

impl<const N: usize, const W: usize> Default for ColumnLog<N, W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const W: usize> ColumnLog<N, W> {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            pushed: 0,
            released: 0,
        }
    }

    /// Rows held.
    #[inline]
    pub fn len(&self) -> usize {
        (self.pushed - self.released) as usize
    }

    /// No row is held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pushed == self.released
    }

    /// Bytes the log has allocated: every chunk's capacity, and the list of
    /// chunks.
    pub fn allocated_bytes(&self) -> usize {
        self.chunks.capacity() * core::mem::size_of::<Chunk<N, W>>()
            + self
                .chunks
                .iter()
                .map(|chunk| {
                    chunk.near.capacity() * core::mem::size_of::<[u32; N]>()
                        + chunk.raw.capacity() * core::mem::size_of::<[u64; W]>()
                })
                .sum::<usize>()
    }

    /// Append one row.
    pub fn push_back(&mut self, row: Row<N, W>) {
        let mut after_full = false;
        if let Some(last) = self.chunks.back_mut() {
            if last.takes(&row.rebased) {
                let mut near = [0u32; N];
                for ((out, value), base) in near.iter_mut().zip(&row.rebased).zip(&last.base) {
                    *out = (*value - *base) as u32;
                }
                last.near.push(near);
                last.raw.push(row.raw);
                self.pushed += 1;
                return;
            }
            // A chunk that ends short (a row that did not fit it) gives back what
            // it reserved and did not use, and the next one grows as any buffer
            // does: it is as likely short as long. After a full chunk the next is
            // allocated whole, so no row is copied again.
            after_full = last.len() == CHUNK_ITEMS;
            if !after_full {
                last.shrink_to_fit();
            }
        }
        let (mut near, mut raw) = if after_full {
            (
                Vec::with_capacity(CHUNK_ITEMS),
                Vec::with_capacity(CHUNK_ITEMS),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        near.push([0; N]);
        raw.push(row.raw);
        self.chunks.push_back(Chunk {
            start: self.pushed,
            base: row.rebased,
            near,
            raw,
        });
        self.pushed += 1;
    }

    /// The chunk the row at absolute number `at` is in, and its place in it.
    fn locate(&self, at: u64) -> Option<(usize, usize)> {
        if at >= self.pushed || at < self.released {
            return None;
        }
        let chunk = self
            .chunks
            .partition_point(|c| c.start <= at)
            .checked_sub(1)?;
        Some((chunk, (at - self.chunks.get(chunk)?.start) as usize))
    }

    /// The row at `index`, oldest first.
    pub fn get(&self, index: usize) -> Option<Row<N, W>> {
        let (chunk, at) = self.locate(self.released + index as u64)?;
        self.chunks.get(chunk)?.row(at)
    }

    /// The oldest row.
    #[inline]
    pub fn front(&self) -> Option<Row<N, W>> {
        self.get(0)
    }

    /// The newest row.
    #[inline]
    pub fn back(&self) -> Option<Row<N, W>> {
        self.len().checked_sub(1).and_then(|last| self.get(last))
    }

    /// Release the oldest row.
    pub fn pop_front(&mut self) -> Option<Row<N, W>> {
        let first = self.chunks.front()?;
        let row = first.row((self.released - first.start) as usize)?;
        self.released += 1;
        // A chunk with nothing left in it is given back, so a log that is emptied
        // holds no chunk, and the oldest row is always in the first.
        if self.released >= first.start + first.len() as u64 {
            self.chunks.pop_front();
        }
        Some(row)
    }

    /// The position of the first row for which `pred` is `false`, the log being
    /// partitioned by it: [`slice::partition_point`] over the log, by bisection.
    pub fn partition_point(&self, mut pred: impl FnMut(&Row<N, W>) -> bool) -> usize {
        let (mut low, mut high) = (0usize, self.len());
        while low < high {
            let mid = low + (high - low) / 2;
            match self.get(mid) {
                Some(row) if pred(&row) => low = mid + 1,
                _ => high = mid,
            }
        }
        low
    }

    /// The rows from position `from`, oldest first.
    pub fn iter_from(&self, from: usize) -> Iter<'_, N, W> {
        let (chunk, at) = self
            .locate(self.released + from as u64)
            .unwrap_or((self.chunks.len(), 0));
        Iter {
            chunks: &self.chunks,
            chunk,
            at,
        }
    }
}

/// The rows of a [`ColumnLog`], oldest first.
#[derive(Debug, Clone)]
pub struct Iter<'a, const N: usize, const W: usize> {
    chunks: &'a VecDeque<Chunk<N, W>>,
    chunk: usize,
    at: usize,
}

impl<const N: usize, const W: usize> Iterator for Iter<'_, N, W> {
    type Item = Row<N, W>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let chunk = self.chunks.get(self.chunk)?;
            match chunk.row(self.at) {
                Some(row) => {
                    self.at += 1;
                    return Some(row);
                }
                None => {
                    self.chunk += 1;
                    self.at = 0;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row of three rising columns and one raw, as a capture's rows are.
    fn rising(i: u64) -> Row<3, 1> {
        Row {
            rebased: [i * 1460, 1_000_000 + i * 1500, 7 + i * 3],
            raw: [5_000_000_000 + i * 1_000_000_000],
        }
    }

    #[test]
    fn rows_come_back_as_pushed_across_many_chunks() {
        let mut log = ColumnLog::<3, 1>::new();
        let n = 5 * CHUNK_ITEMS as u64 + 17;
        for i in 0..n {
            log.push_back(rising(i));
        }
        assert_eq!(log.len(), n as usize);
        for i in 0..n {
            assert_eq!(log.get(i as usize), Some(rising(i)), "row {i}");
        }
        assert_eq!(log.get(n as usize), None);
        assert_eq!(log.front(), Some(rising(0)));
        assert_eq!(log.back(), Some(rising(n - 1)));
    }

    #[test]
    fn a_raw_column_never_ends_a_chunk() {
        // One row a second, in nanoseconds: a rebased column would end a chunk
        // every fourth row.
        let mut log = ColumnLog::<1, 1>::new();
        for i in 0..(2 * CHUNK_ITEMS as u64) {
            log.push_back(Row {
                rebased: [i],
                raw: [i * 1_000_000_000],
            });
        }
        assert_eq!(log.chunks.len(), 2);
    }

    #[test]
    fn a_row_that_does_not_fit_begins_a_chunk_and_is_still_read_back() {
        let mut log = ColumnLog::<2, 1>::new();
        let rebased: Vec<[u64; 2]> = alloc::vec![
            [10, 10],
            [11, 12],
            // Below the base.
            [3, 20],
            [4, 21],
            // More than u32::MAX above it.
            [4 + u64::from(u32::MAX) + 1, 22],
            [u64::MAX, u64::MAX],
            [u64::MAX, u64::MAX],
            [0, 0],
        ];
        let rows: Vec<Row<2, 1>> = rebased
            .iter()
            .enumerate()
            .map(|(i, rebased)| Row {
                rebased: *rebased,
                raw: [u64::MAX - i as u64],
            })
            .collect();
        for row in &rows {
            log.push_back(*row);
        }
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(log.get(i), Some(*row), "row {i}");
        }
        assert_eq!(log.iter_from(0).collect::<Vec<_>>(), rows);
        assert_eq!(log.iter_from(5).collect::<Vec<_>>(), rows[5..].to_vec());
    }

    #[test]
    fn a_distance_of_exactly_u32_max_fits_and_one_more_does_not() {
        let at = |rebased: u64| Row {
            rebased: [rebased],
            raw: [],
        };
        let mut log = ColumnLog::<1, 0>::new();
        log.push_back(at(100));
        log.push_back(at(100 + u64::from(u32::MAX)));
        assert_eq!(log.chunks.len(), 1);
        log.push_back(at(100 + u64::from(u32::MAX) + 1));
        assert_eq!(log.chunks.len(), 2);
        assert_eq!(log.get(1), Some(at(100 + u64::from(u32::MAX))));
        assert_eq!(log.get(2), Some(at(100 + u64::from(u32::MAX) + 1)));
    }

    #[test]
    fn release_from_the_front_keeps_positions_and_drops_whole_chunks() {
        let mut log = ColumnLog::<3, 1>::new();
        let n = 3 * CHUNK_ITEMS as u64 + 5;
        for i in 0..n {
            log.push_back(rising(i));
        }
        let held = log.allocated_bytes();
        for i in 0..(2 * CHUNK_ITEMS as u64 + 3) {
            assert_eq!(log.pop_front(), Some(rising(i)));
        }
        assert_eq!(log.len(), (n - 2 * CHUNK_ITEMS as u64 - 3) as usize);
        assert_eq!(log.chunks.len(), 2, "two whole chunks were given back");
        assert!(log.allocated_bytes() < held);
        for k in 0..log.len() {
            assert_eq!(
                log.get(k),
                Some(rising(2 * CHUNK_ITEMS as u64 + 3 + k as u64))
            );
        }
        while log.pop_front().is_some() {}
        assert!(log.is_empty());
        assert_eq!(log.get(0), None);
        // A log that was emptied takes rows again.
        log.push_back(rising(9));
        assert_eq!(log.get(0), Some(rising(9)));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn partition_point_bisects_on_a_column() {
        let mut log = ColumnLog::<3, 1>::new();
        for i in 0..(2 * CHUNK_ITEMS as u64 + 9) {
            log.push_back(rising(i));
        }
        for _ in 0..700 {
            assert!(log.pop_front().is_some());
        }
        for target in [0u64, 1459, 1460, 700 * 1460, 701 * 1460 + 1, u64::MAX] {
            let by_scan = (0..log.len())
                .take_while(|k| log.get(*k).is_some_and(|row| row.rebased[0] <= target))
                .count();
            assert_eq!(log.partition_point(|row| row.rebased[0] <= target), by_scan);
        }
    }

    #[test]
    fn a_full_chunk_costs_twenty_bytes_a_row_of_three_and_one() {
        let mut log = ColumnLog::<3, 1>::new();
        for i in 0..(8 * CHUNK_ITEMS as u64) {
            log.push_back(rising(i));
        }
        let per_row = log.allocated_bytes() as f64 / log.len() as f64;
        assert!((20.0..20.2).contains(&per_row), "{per_row}");
    }

    #[test]
    fn a_log_of_unrelated_rows_costs_a_chunk_a_row_and_gives_back_the_slack() {
        let mut log = ColumnLog::<1, 0>::new();
        for i in 0..100u64 {
            // Each row is below the one before.
            log.push_back(Row {
                rebased: [1_000_000 - i],
                raw: [],
            });
        }
        assert_eq!(log.chunks.len(), 100);
        for i in 0..100u64 {
            assert_eq!(
                log.get(i as usize),
                Some(Row {
                    rebased: [1_000_000 - i],
                    raw: []
                })
            );
        }
        // Every chunk but the last was shrunk to its one row.
        assert!(log
            .chunks
            .iter()
            .rev()
            .skip(1)
            .all(|c| c.near.capacity() == 1));
    }
}
