// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An append-only log of rows of 64-bit columns, read by position and released
//! from the front, kept by frame of reference with the narrowest width each
//! chunk's data allows.
//!
//! Open-debt item 924, D10 (`docs/dissect-row-index.md`). A row of a capture's
//! index is a handful of 64-bit values (an offset, a place, a packet number, an
//! instant, a length, some flags). Held whole they are mostly zeros: a length of
//! 64 in eight bytes, a flag word that never passes 2^12 in eight. This log keeps
//! a chunk of up to [`CHUNK_ITEMS`] rows as one buffer of packed rows, and
//! each column of the chunk as wide as the largest value in it needs: no bytes
//! at all for a column that is zero throughout, one, two, four or eight.
//!
//! # Two kinds of column
//!
//! A [`Kind::Rising`] column (a stream offset, a place in a container, a packet
//! number, a capture instant) is kept as its distance from the chunk's first
//! row's, so what it costs follows how far it moves within a chunk and not how
//! large it is: a nanosecond clock that has run for fifty years is four bytes a
//! row where a chunk spans four seconds. A [`Kind::Plain`] column (a length, a
//! flag word, a count) is kept as it is, as narrow as it is.
//!
//! # Widening, and no escape code
//!
//! A value that needs more than its column's width widens the column for the
//! whole chunk, which rewrites the chunk once (a column widens at most three
//! times a chunk, and mostly in its first rows). A rising value BELOW the chunk's
//! first begins a new chunk. So no value is one the log cannot hold, there is no
//! exception table to search and nothing a reader must test for. A chunk is
//! shorter than [`CHUNK_ITEMS`] only where the data is unlike what a capture does
//! (a clock that goes back), and a chunk that ended short is given back what it
//! did not use.
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
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::chunk_log::CHUNK_ITEMS;

/// Rows a chunk reserves when it is the first of a log, or follows one that
/// ended short: a log of a few rows costs a few rows.
const FIRST_ROWS: usize = 4;

/// How a column is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// As its distance from the chunk's first row's: for a value that rises.
    Rising,
    /// As it is, in as few bytes as the chunk's largest needs.
    Plain,
}

/// The bytes a distance needs: none for zero, else one, two, four or eight.
const fn width_of(distance: u64) -> u8 {
    match distance {
        0 => 0,
        1..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFFFF_FFFF => 4,
        _ => 8,
    }
}

fn put(bytes: &mut Vec<u8>, width: u8, distance: u64) {
    bytes.extend_from_slice(&distance.to_le_bytes()[..usize::from(width)]);
}

/// Zero bytes after the last row of a chunk, so that a column is read as one
/// eight-byte word and masked, whatever its width and wherever it is.
const PAD: usize = 8;

/// The bits of an eight-byte word a column of this many bytes keeps.
const MASK: [u64; 9] = [
    0,
    0xFF,
    0xFFFF,
    0xFF_FFFF,
    0xFFFF_FFFF,
    0xFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF,
    0xFF_FFFF_FFFF_FFFF,
    u64::MAX,
];

/// The column of `width` bytes at `at`. The buffer has [`PAD`] bytes past its last
/// row, so the word read always lies inside it.
#[inline]
fn take(bytes: &[u8], at: usize, width: u8) -> u64 {
    let word: [u8; 8] = bytes[at..at + 8].try_into().expect("eight bytes");
    u64::from_le_bytes(word) & MASK[usize::from(width)]
}

/// One chunk: a base, the width of each column, and the packed rows.
#[derive(Debug)]
struct Chunk<const C: usize> {
    /// Rows pushed before this chunk's first, over the log's life.
    start: u64,
    /// Rows held.
    len: usize,
    /// Rows the buffer has room for.
    cap: usize,
    /// What a [`Kind::Rising`] column's distances are from; zero for a plain one.
    base: [u64; C],
    /// Bytes a row spends on each column.
    width: [u8; C],
    /// Bytes a row spends in all: the sum of [`Self::width`], kept so a read does
    /// not add it up.
    stride: usize,
    /// Where each column begins within a row: the widths before it, kept for the
    /// same reason.
    offset: [usize; C],
    bytes: Vec<u8>,
}

/// Where each column of a row of these widths begins, and the row's length.
fn layout<const C: usize>(width: &[u8; C]) -> ([usize; C], usize) {
    let mut offset = [0usize; C];
    let mut at = 0usize;
    for j in 0..C {
        offset[j] = at;
        at += usize::from(width[j]);
    }
    (offset, at)
}

impl<const C: usize> Chunk<C> {
    /// A chunk of `rows`, with room for `cap` rows or the rows, whichever is more.
    /// A rising column's base is the lowest of its values, and a column is as wide
    /// as its largest distance needs.
    fn from_rows(start: u64, kinds: &[Kind; C], rows: &[[u64; C]], cap: usize) -> Self {
        let mut base = [0u64; C];
        for j in 0..C {
            if kinds[j] == Kind::Rising {
                base[j] = rows.iter().map(|row| row[j]).min().unwrap_or(0);
            }
        }
        let mut width = [0u8; C];
        for row in rows {
            for j in 0..C {
                width[j] = width[j].max(width_of(row[j] - base[j]));
            }
        }
        let cap = cap.max(rows.len());
        let (offset, stride) = layout(&width);
        let mut bytes = Vec::with_capacity(cap * stride + PAD);
        for row in rows {
            for j in 0..C {
                put(&mut bytes, width[j], row[j] - base[j]);
            }
        }
        bytes.extend_from_slice(&[0; PAD]);
        Self {
            start,
            len: rows.len(),
            cap,
            base,
            width,
            stride,
            offset,
            bytes,
        }
    }

    #[inline]
    fn stride(&self) -> usize {
        self.stride
    }

    /// Column `col` of the row at `at`, which is held. A plain column's base is
    /// zero, so the base is added to every column alike.
    #[inline]
    fn value(&self, col: usize, at: usize) -> u64 {
        self.base[col]
            + take(
                &self.bytes,
                at * self.stride + self.offset[col],
                self.width[col],
            )
    }

    /// Each column's distance for `row`, or `None` when a rising value is below
    /// the base.
    fn distances(&self, kinds: &[Kind; C], row: &[u64; C]) -> Option<[u64; C]> {
        let mut out = [0u64; C];
        for j in 0..C {
            out[j] = match kinds[j] {
                Kind::Rising => row[j].checked_sub(self.base[j])?,
                Kind::Plain => row[j],
            };
        }
        Some(out)
    }

    /// The columns' distances of the row at `at`.
    fn distances_at(&self, at: usize) -> [u64; C] {
        let mut out = [0u64; C];
        let row = &self.bytes[at * self.stride..];
        for (j, value) in out.iter_mut().enumerate() {
            *value = take(row, self.offset[j], self.width[j]);
        }
        out
    }

    /// The row at `at`: each column's distance and its base, which is zero for a
    /// plain column.
    #[inline]
    fn row(&self, at: usize) -> Option<[u64; C]> {
        if at >= self.len {
            return None;
        }
        let mut out = self.distances_at(at);
        for (value, base) in out.iter_mut().zip(&self.base) {
            *value += base;
        }
        Some(out)
    }

    /// The same rows in a buffer whose columns are `width` wide, with room for
    /// `cap` rows.
    fn rewrite(&mut self, width: [u8; C], cap: usize) {
        let (offset, stride) = layout(&width);
        let mut bytes = Vec::with_capacity(cap * stride + PAD);
        for at in 0..self.len {
            let distances = self.distances_at(at);
            for j in 0..C {
                put(&mut bytes, width[j], distances[j]);
            }
        }
        bytes.extend_from_slice(&[0; PAD]);
        self.width = width;
        self.stride = stride;
        self.offset = offset;
        self.cap = cap;
        self.bytes = bytes;
    }

    /// Room for one more row.
    fn make_room(&mut self) {
        if self.len < self.cap {
            return;
        }
        self.cap = (self.cap * 2).clamp(FIRST_ROWS, CHUNK_ITEMS);
        let target = self.cap * self.stride() + PAD;
        self.bytes.reserve_exact(target - self.bytes.len());
    }

    /// The columns' widths a row of these distances needs, the chunk's own or
    /// wider.
    fn widths_for(&self, distances: &[u64; C]) -> [u8; C] {
        let mut need = self.width;
        for j in 0..C {
            need[j] = need[j].max(width_of(distances[j]));
        }
        need
    }

    /// Append `row`, which this chunk takes: its rising columns are at or above
    /// the base and it has a row to spare.
    fn append(&mut self, kinds: &[Kind; C], row: &[u64; C]) {
        let distances = self
            .distances(kinds, row)
            .expect("a row appended to a chunk is at or above its base");
        let need = self.widths_for(&distances);
        if need != self.width {
            self.rewrite(need, self.cap);
        }
        self.make_room();
        // The padding gives way to the row and is put back after it.
        self.bytes.truncate(self.len * self.stride);
        for (width, distance) in self.width.iter().zip(&distances) {
            put(&mut self.bytes, *width, *distance);
        }
        self.bytes.extend_from_slice(&[0; PAD]);
        self.len += 1;
    }

    /// Whether this chunk can take `row` at its end.
    fn takes(&self, kinds: &[Kind; C], row: &[u64; C]) -> bool {
        self.len < CHUNK_ITEMS && self.distances(kinds, row).is_some()
    }

    /// Say the row at `at` is `row`.
    fn set(&mut self, kinds: &[Kind; C], at: usize, row: &[u64; C]) {
        if let Some(distances) = self.distances(kinds, row) {
            let need = self.widths_for(&distances);
            if need != self.width {
                self.rewrite(need, self.cap);
            }
            let mut offset = at * self.stride();
            for (width, distance) in self.width.iter().zip(&distances) {
                let width = usize::from(*width);
                self.bytes[offset..offset + width]
                    .copy_from_slice(&distance.to_le_bytes()[..width]);
                offset += width;
            }
            return;
        }
        // A rising value below the base: the base moves to the lowest the chunk
        // holds, which is one rewrite of the chunk and a thing no capture asks
        // for twice.
        let mut rows: Vec<[u64; C]> = (0..self.len)
            .map(|k| self.row(k).expect("a row of the chunk"))
            .collect();
        rows[at] = *row;
        *self = Self::from_rows(self.start, kinds, &rows, self.cap);
    }

    /// Give back what the chunk reserved and does not hold.
    fn shrink_to_fit(&mut self) {
        self.cap = self.len;
        self.bytes.shrink_to_fit();
    }
}

/// An append-only log of rows of `C` 64-bit columns, read by position and released
/// from the front.
#[derive(Debug)]
pub struct ColumnLog<const C: usize> {
    kinds: [Kind; C],
    chunks: VecDeque<Chunk<C>>,
    /// Rows pushed over the log's life.
    pushed: u64,
    /// Rows released over the log's life.
    released: u64,
    /// The chunk the last position asked for was in: the next is usually in it or
    /// the one after, so it is asked first. A hint and not a fact (every use checks
    /// it), and an atomic so that a log that is only read stays `Sync`.
    hint: AtomicUsize,
}

impl<const C: usize> ColumnLog<C> {
    /// An empty log whose columns are kept as `kinds` say.
    pub const fn new(kinds: [Kind; C]) -> Self {
        Self {
            kinds,
            chunks: VecDeque::new(),
            pushed: 0,
            released: 0,
            hint: AtomicUsize::new(0),
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

    /// Bytes the log has allocated: every chunk's buffer, and the list of
    /// chunks.
    pub fn allocated_bytes(&self) -> usize {
        self.chunks.capacity() * core::mem::size_of::<Chunk<C>>()
            + self
                .chunks
                .iter()
                .map(|chunk| chunk.bytes.capacity())
                .sum::<usize>()
    }

    /// Append one row.
    pub fn push_back(&mut self, row: [u64; C]) {
        let mut after_full = false;
        if let Some(last) = self.chunks.back_mut() {
            if last.takes(&self.kinds, &row) {
                last.append(&self.kinds, &row);
                self.pushed += 1;
                return;
            }
            // A chunk that ends short (a row that did not fit it) gives back what
            // it reserved and did not use, and the next one grows as any buffer
            // does: it is as likely short as long. After a full chunk the next is
            // allocated whole, so no row is copied again.
            after_full = last.len == CHUNK_ITEMS;
            if !after_full {
                last.shrink_to_fit();
            }
        }
        let cap = if after_full { CHUNK_ITEMS } else { FIRST_ROWS };
        // The list of chunks grows by doubling from one slot, not from the four a
        // deque takes: a chunk's header is a hundred bytes, and a log of a few rows
        // is the common one (a list for every flow of a capture).
        if self.chunks.len() == self.chunks.capacity() {
            self.chunks.reserve_exact(self.chunks.len().max(1));
        }
        self.chunks.push_back(Chunk::from_rows(
            self.pushed,
            &self.kinds,
            core::slice::from_ref(&row),
            cap,
        ));
        self.pushed += 1;
    }

    /// The chunk the row at absolute number `at` is in, and its place in it.
    fn locate(&self, at: u64) -> Option<(usize, usize)> {
        if at >= self.pushed || at < self.released {
            return None;
        }
        let hint = self.hint.load(Ordering::Relaxed);
        for guess in [hint, hint + 1, hint.wrapping_sub(1)] {
            if let Some(chunk) = self.chunks.get(guess) {
                if chunk.start <= at && at < chunk.start + chunk.len as u64 {
                    self.hint.store(guess, Ordering::Relaxed);
                    return Some((guess, (at - chunk.start) as usize));
                }
            }
        }
        let chunk = self
            .chunks
            .partition_point(|c| c.start <= at)
            .checked_sub(1)?;
        self.hint.store(chunk, Ordering::Relaxed);
        Some((chunk, (at - self.chunks.get(chunk)?.start) as usize))
    }

    /// Where the row at `index` (counted from the oldest held) sits; `None` for an
    /// index past the end, however far past.
    fn locate_index(&self, index: usize) -> Option<(usize, usize)> {
        self.locate(self.released.checked_add(u64::try_from(index).ok()?)?)
    }

    /// The row at `index`, oldest first.
    pub fn get(&self, index: usize) -> Option<[u64; C]> {
        let (chunk, at) = self.locate_index(index)?;
        self.chunks.get(chunk)?.row(at)
    }

    /// Column `col` of the row at `index`, without reading the others.
    pub fn column(&self, index: usize, col: usize) -> Option<u64> {
        let (chunk, at) = self.locate_index(index)?;
        let chunk = self.chunks.get(chunk)?;
        (at < chunk.len).then(|| chunk.value(col, at))
    }

    /// Say the row at `index` is `row`. `false`, and nothing changed, when there
    /// is no such row.
    ///
    /// A value that fits the chunk's widths and base is written where it stands;
    /// one that does not rewrites the chunk.
    pub fn set(&mut self, index: usize, row: [u64; C]) -> bool {
        let Some((chunk, at)) = self.locate_index(index) else {
            return false;
        };
        match self.chunks.get_mut(chunk) {
            Some(chunk) => {
                chunk.set(&self.kinds, at, &row);
                true
            }
            None => false,
        }
    }

    /// The oldest row.
    #[inline]
    pub fn front(&self) -> Option<[u64; C]> {
        self.get(0)
    }

    /// The newest row.
    #[inline]
    pub fn back(&self) -> Option<[u64; C]> {
        self.len().checked_sub(1).and_then(|last| self.get(last))
    }

    /// Release the oldest row.
    pub fn pop_front(&mut self) -> Option<[u64; C]> {
        let first = self.chunks.front()?;
        let row = first.row((self.released - first.start) as usize)?;
        self.released += 1;
        // A chunk with nothing left in it is given back, so a log that is emptied
        // holds no chunk, and the oldest row is always in the first.
        if self.released >= first.start + first.len as u64 {
            self.chunks.pop_front();
        }
        Some(row)
    }

    /// The position of the first row for which `pred` of its column `col` is
    /// `false`, the log being partitioned by it: [`slice::partition_point`] over the
    /// log, by bisection. It bisects the chunks by their last rows and then the one
    /// chunk the answer is in, and reads the one column.
    pub fn partition_point_by_column(
        &self,
        col: usize,
        mut pred: impl FnMut(u64) -> bool,
    ) -> usize {
        let (mut low, mut high) = (0usize, self.chunks.len());
        while low < high {
            let mid = low + (high - low) / 2;
            let last = &self.chunks[mid];
            if pred(last.value(col, last.len - 1)) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let Some(chunk) = self.chunks.get(low) else {
            return self.len();
        };
        // The first chunk's front may have been released.
        let floor = if low == 0 {
            (self.released - chunk.start) as usize
        } else {
            0
        };
        let (mut a, mut b) = (floor, chunk.len);
        while a < b {
            let mid = a + (b - a) / 2;
            if pred(chunk.value(col, mid)) {
                a = mid + 1;
            } else {
                b = mid;
            }
        }
        (chunk.start + a as u64 - self.released) as usize
    }

    /// The rows from position `from`, oldest first.
    pub fn iter_from(&self, from: usize) -> Iter<'_, C> {
        let (chunk, at) = self.locate_index(from).unwrap_or((self.chunks.len(), 0));
        Iter {
            chunks: &self.chunks,
            chunk,
            at,
        }
    }
}

/// The rows of a [`ColumnLog`], oldest first.
#[derive(Debug, Clone)]
pub struct Iter<'a, const C: usize> {
    chunks: &'a VecDeque<Chunk<C>>,
    chunk: usize,
    at: usize,
}

impl<const C: usize> Iterator for Iter<'_, C> {
    type Item = [u64; C];

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

    const KINDS: [Kind; 4] = [Kind::Rising, Kind::Rising, Kind::Rising, Kind::Plain];

    /// Three rising columns and a small plain one, as a capture's rows are.
    fn rising(i: u64) -> [u64; 4] {
        [
            i * 1460,
            1_000_000 + i * 1500,
            5_000_000_000_000_000 + i * 20_000,
            i % 7,
        ]
    }

    #[test]
    fn rows_come_back_as_pushed_across_many_chunks() {
        let mut log = ColumnLog::new(KINDS);
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
        assert_eq!(
            log.iter_from(3).collect::<Vec<_>>(),
            (3..n).map(rising).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_column_is_as_wide_as_the_chunks_largest_needs() {
        let mut log = ColumnLog::new([Kind::Plain, Kind::Plain, Kind::Plain]);
        // One row of zeros, then small, then 300, then 70000, then 2^40.
        for row in [
            [0, 0, 0],
            [1, 0, 0],
            [200, 0, 5],
            [300, 0, 5],
            [70_000, 0, 5],
            [1 << 40, 0, 5],
        ] {
            log.push_back(row);
        }
        let chunk = log.chunks.front().expect("a chunk");
        assert_eq!(chunk.width, [8, 0, 1]);
        assert_eq!(log.get(5), Some([1 << 40, 0, 5]));
        assert_eq!(log.get(0), Some([0, 0, 0]));
    }

    #[test]
    fn a_rising_clock_costs_what_its_chunk_spans_and_not_what_it_is() {
        // Nanoseconds since 1970 now, a row a millisecond, a chunk of 1024: a
        // second, which is four bytes, where the value is eight.
        let mut log = ColumnLog::new([Kind::Rising]);
        for i in 0..(8 * CHUNK_ITEMS as u64) {
            log.push_back([1_700_000_000_000_000_000 + i * 1_000_000]);
        }
        let per_row = log.allocated_bytes() as f64 / log.len() as f64;
        assert!((4.0..4.2).contains(&per_row), "{per_row}");
        // A row a second: a chunk spans seventeen minutes, which is too far for
        // four bytes, so the column is eight for that chunk and no chunk ends.
        let mut slow = ColumnLog::new([Kind::Rising]);
        for i in 0..(2 * CHUNK_ITEMS as u64) {
            slow.push_back([1_700_000_000_000_000_000 + i * 1_000_000_000]);
        }
        assert_eq!(slow.chunks.len(), 2, "a slow clock does not end a chunk");
        assert_eq!(
            slow.get(1500),
            Some([1_700_000_000_000_000_000 + 1500 * 1_000_000_000])
        );
    }

    #[test]
    fn a_rising_value_below_the_base_begins_a_chunk_and_is_read_back() {
        let mut log = ColumnLog::new([Kind::Rising, Kind::Plain]);
        let rows: Vec<[u64; 2]> = alloc::vec![
            [10, 10],
            [11, 12],
            // Below the base.
            [3, 20],
            [4, 21],
            [4 + u64::from(u32::MAX) + 1, 22],
            [u64::MAX, u64::MAX],
            [u64::MAX, u64::MAX],
            [0, 0],
        ];
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
    fn two_interleaved_streams_end_one_chunk_not_every_row() {
        // Request and response, each in its own offset space: the second one's
        // first row is below the first's, which begins a chunk, and the chunk then
        // takes both.
        let mut log = ColumnLog::new([Kind::Rising]);
        for i in 0..(CHUNK_ITEMS as u64 / 2) {
            log.push_back([1_000_000 + i * 70]);
            log.push_back([50_000 + i * 90]);
        }
        assert!(log.chunks.len() <= 2, "{}", log.chunks.len());
        for i in 0..(CHUNK_ITEMS as u64 / 2) {
            assert_eq!(log.get(2 * i as usize), Some([1_000_000 + i * 70]));
            assert_eq!(log.get(2 * i as usize + 1), Some([50_000 + i * 90]));
        }
    }

    #[test]
    fn set_writes_in_place_widens_or_moves_the_base() {
        let mut log = ColumnLog::new(KINDS);
        for i in 0..40 {
            log.push_back(rising(i));
        }
        // Fits where it stands.
        assert!(log.set(5, [5 * 1460 + 1, 1_007_500, 5_000_000_000_100_000, 3]));
        assert_eq!(
            log.get(5),
            Some([5 * 1460 + 1, 1_007_500, 5_000_000_000_100_000, 3])
        );
        // Wider than the column.
        assert!(log.set(6, [1 << 50, 1_009_000, 5_000_000_000_120_000, 1 << 33]));
        assert_eq!(
            log.get(6),
            Some([1 << 50, 1_009_000, 5_000_000_000_120_000, 1 << 33])
        );
        // Below the base: the base moves, every other row reads as it did.
        assert!(log.set(7, [0, 7, 7, 0]));
        assert_eq!(log.get(7), Some([0, 7, 7, 0]));
        assert!(log.set(8, [0, 6, 6, 0]));
        for i in 9..40 {
            assert_eq!(log.get(i as usize), Some(rising(i)), "row {i}");
        }
        assert_eq!(log.get(4), Some(rising(4)));
        assert_eq!(
            log.get(5),
            Some([5 * 1460 + 1, 1_007_500, 5_000_000_000_100_000, 3])
        );
        assert!(!log.set(40, [0; 4]));
    }

    #[test]
    fn release_from_the_front_keeps_positions_and_drops_whole_chunks() {
        let mut log = ColumnLog::new(KINDS);
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
        let mut log = ColumnLog::new(KINDS);
        for i in 0..(2 * CHUNK_ITEMS as u64 + 9) {
            log.push_back(rising(i));
        }
        for _ in 0..700 {
            assert!(log.pop_front().is_some());
        }
        for target in [0u64, 1459, 1460, 700 * 1460, 701 * 1460 + 1, u64::MAX] {
            let by_scan = (0..log.len())
                .take_while(|k| log.get(*k).is_some_and(|row| row[0] <= target))
                .count();
            assert_eq!(
                log.partition_point_by_column(0, |value| value <= target),
                by_scan,
                "target {target}"
            );
        }
        // A log whose chunks are full, whose front was released, and a target
        // that falls in every chunk and between them.
        let mut sorted = ColumnLog::new([Kind::Rising]);
        for i in 0..3_000u64 {
            sorted.push_back([(i / 3) * 10_000_000 + i]);
        }
        for _ in 0..1_500 {
            assert!(sorted.pop_front().is_some());
        }
        for target in (0..10_000_000u64).step_by(317_911) {
            let by_scan = (0..sorted.len())
                .take_while(|k| sorted.get(*k).is_some_and(|row| row[0] <= target))
                .count();
            assert_eq!(
                sorted.partition_point_by_column(0, |value| value <= target),
                by_scan
            );
        }
        assert_eq!(sorted.column(0, 0), sorted.get(0).map(|row| row[0]));
        assert_eq!(sorted.column(10_000, 0), None);
    }

    #[test]
    fn a_full_chunk_of_a_captures_rows_costs_the_widths_they_need() {
        // Offset to 1.5 MB in a chunk (4), place likewise (4), a clock a row at
        // 20 us (4: 20 ms a chunk), a flag word under 7 (1).
        let mut log = ColumnLog::new(KINDS);
        for i in 0..(8 * CHUNK_ITEMS as u64) {
            log.push_back(rising(i));
        }
        let per_row = log.allocated_bytes() as f64 / log.len() as f64;
        assert!((13.0..13.3).contains(&per_row), "{per_row}");
    }

    #[test]
    fn a_log_of_a_few_rows_costs_a_few_rows() {
        let mut log = ColumnLog::new(KINDS);
        for i in 0..3 {
            log.push_back(rising(i));
        }
        // One chunk slot and four rows reserved, of at most 13 bytes.
        assert!(log.allocated_bytes() < 200, "{}", log.allocated_bytes());
    }

    #[test]
    fn a_log_of_descending_rows_costs_a_chunk_a_row_and_gives_back_the_slack() {
        let mut log = ColumnLog::new([Kind::Rising]);
        for i in 0..100u64 {
            log.push_back([1_000_000 - i]);
        }
        assert_eq!(log.chunks.len(), 100);
        for i in 0..100u64 {
            assert_eq!(log.get(i as usize), Some([1_000_000 - i]));
        }
        // Every chunk but the last was shrunk to its one row.
        assert!(log
            .chunks
            .iter()
            .rev()
            .skip(1)
            .all(|c| c.bytes.capacity() == PAD));
    }
}
