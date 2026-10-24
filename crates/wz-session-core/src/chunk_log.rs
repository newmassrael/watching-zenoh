// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An append-only log read by position and released from the front, kept in
//! fixed-size chunks.
//!
//! Open-debt item 924 (`docs/dissect-row-index.md`). It was the storage of a
//! message list alone until the TCP run map, which has the same shape (appended
//! for every packet, read by position, released from the front under a
//! ceiling), needed it too; it lives here so the two hold one structure and not
//! two copies of it.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Items per chunk of a [`ChunkLog`].
///
/// Large enough that the chunk list itself is negligible (one entry per this
/// many items), small enough that the unused tail of the last chunk is
/// negligible against any log long enough to have one. A power of two, so the
/// first chunk, which grows the way any buffer does, reaches exactly this
/// capacity and stops.
pub const CHUNK_ITEMS: usize = 1024;

/// An append-only list of items, read by position and released from the front.
///
/// # Why chunks
///
/// One growable buffer doubles: each growth copies every item into a buffer
/// twice the size, and up to half of what it holds is capacity no item uses.
/// For a log of hundreds of thousands of items that is the whole log copied
/// again at every doubling and up to as much again held empty. Here items go
/// into chunks of [`CHUNK_ITEMS`]. The first chunk grows like any buffer, so a
/// short log costs what a short log costs; every later chunk is allocated
/// whole, so no item is ever copied again, and the most a long log holds unused
/// is one chunk's tail.
///
/// # Every chunk is one run
///
/// A chunk is a ring, so it could hold its items as two runs. Only a chunk that
/// is both released from and appended to can wrap, which is the one-chunk log
/// of a live tap at its ceiling, and such a chunk is straightened when it does
/// (at most [`CHUNK_ITEMS`] moves, once per [`CHUNK_ITEMS`] appends). So every
/// chunk reads as ONE slice, and [`Iter`] walks slices and skips whole chunks:
/// a skip costs the chunks it passes, as a slice's costs nothing, rather than
/// one step per item.
///
/// # The shape that makes a position O(1)
///
/// Every chunk except the first and the last holds exactly [`CHUNK_ITEMS`]
/// items. Appending fills the last chunk before starting another, and releasing
/// takes items from the first chunk only, dropping it when it is empty, so
/// neither can break that. The first chunk's length is the only variable before
/// a position, and dividing the rest by [`CHUNK_ITEMS`] finds the chunk.
///
/// No chunk is ever empty, which is what lets [`Self::len`] of zero mean "no
/// chunks" and the first chunk always be the one items are released from.
#[derive(Debug)]
pub struct ChunkLog<T> {
    /// A `Vec` and not a deque: a position is found by indexing it, and the
    /// front is dropped once per [`CHUNK_ITEMS`] releases, which moves one
    /// pointer per chunk held.
    chunks: Vec<VecDeque<T>>,
    len: usize,
}

impl<T> Default for ChunkLog<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ChunkLog<T> {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    /// Items held.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// No item is held.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append one item.
    pub fn push_back(&mut self, item: T) {
        let chunks = self.chunks.len();
        match self.chunks.last_mut() {
            Some(last) if last.len() < CHUNK_ITEMS => {
                last.push_back(item);
                // Only a chunk that is also released from can wrap, and the
                // last chunk is released from only when it is the first.
                if chunks == 1 {
                    straighten(last);
                }
            }
            _ => {
                // The first chunk grows; any later one is allocated whole.
                let mut chunk = if chunks == 0 {
                    VecDeque::new()
                } else {
                    VecDeque::with_capacity(CHUNK_ITEMS)
                };
                chunk.push_back(item);
                self.chunks.push(chunk);
            }
        }
        self.len += 1;
    }

    /// Release the oldest item.
    pub fn pop_front(&mut self) -> Option<T> {
        let first = self.chunks.first_mut()?;
        let item = first.pop_front();
        if first.is_empty() {
            self.chunks.remove(0);
        } else {
            straighten(first);
        }
        if item.is_some() {
            self.len -= 1;
        }
        item
    }

    /// Where the item at `index` sits: its chunk and its place in it.
    #[inline]
    fn locate(&self, index: usize) -> Option<(usize, usize)> {
        if index >= self.len {
            return None;
        }
        let first = self.chunks.first()?.len();
        if index < first {
            return Some((0, index));
        }
        let rest = index - first;
        Some((1 + rest / CHUNK_ITEMS, rest % CHUNK_ITEMS))
    }

    /// The item at `index`, oldest first.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        let (chunk, at) = self.locate(index)?;
        run(self.chunks.get(chunk)?).get(at)
    }

    /// [`Self::get`], mutably.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let (chunk, at) = self.locate(index)?;
        self.chunks.get_mut(chunk)?.as_mut_slices().0.get_mut(at)
    }

    /// The oldest item.
    #[inline]
    pub fn front(&self) -> Option<&T> {
        self.get(0)
    }

    /// The newest item.
    #[inline]
    pub fn back(&self) -> Option<&T> {
        self.len.checked_sub(1).and_then(|last| self.get(last))
    }

    /// The position of the first item for which `pred` is `false`, the log
    /// being partitioned by it (every item it holds for comes before every item
    /// it does not): [`slice::partition_point`] over the log, by bisection.
    pub fn partition_point(&self, mut pred: impl FnMut(&T) -> bool) -> usize {
        let (mut low, mut high) = (0usize, self.len);
        while low < high {
            let mid = low + (high - low) / 2;
            match self.get(mid) {
                Some(item) if pred(item) => low = mid + 1,
                _ => high = mid,
            }
        }
        low
    }

    /// The items from position `from` on, oldest first: what one call added to
    /// the log, read without walking what was there before it.
    pub fn iter_from(&self, from: usize) -> Iter<'_, T> {
        let chunks = self.chunks.len();
        let Some((chunk, at)) = self.locate(from) else {
            return Iter {
                front: <&[T]>::default().iter(),
                middle: self.chunks[chunks..].iter(),
                back: <&[T]>::default().iter(),
            };
        };
        let last = chunks - 1;
        let front = run(&self.chunks[chunk])[at..].iter();
        if chunk == last {
            Iter {
                front,
                middle: self.chunks[chunks..].iter(),
                back: <&[T]>::default().iter(),
            }
        } else {
            // Every chunk strictly between the first read and the last is
            // full, which is what `Iter::left` counts on.
            Iter {
                front,
                middle: self.chunks[chunk + 1..last].iter(),
                back: run(&self.chunks[last]).iter(),
            }
        }
    }

    /// The items from position `from` on, mutably.
    pub fn iter_mut_from(&mut self, from: usize) -> impl DoubleEndedIterator<Item = &mut T> {
        let (chunk, at) = self.locate(from).unwrap_or((self.chunks.len(), 0));
        self.chunks
            .iter_mut()
            .enumerate()
            .skip(chunk)
            .flat_map(move |(i, items)| items.range_mut(if i == chunk { at } else { 0 }..))
    }
}

/// The items, oldest first, moved out of the log: what a holder that keeps the
/// same items in another structure takes, which removes none of them.
impl<T> IntoIterator for ChunkLog<T> {
    type Item = T;
    type IntoIter = core::iter::Flatten<alloc::vec::IntoIter<VecDeque<T>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter().flatten()
    }
}

/// Keep a chunk one run: see [`ChunkLog`]. Free while the ring has not
/// wrapped, which is every chunk but a one-chunk log's at a live ceiling.
fn straighten<T>(chunk: &mut VecDeque<T>) {
    if !chunk.as_slices().1.is_empty() {
        chunk.make_contiguous();
    }
}

/// A chunk's items, as the one run [`straighten`] keeps them in.
fn run<T>(chunk: &VecDeque<T>) -> &[T] {
    let (items, wrapped) = chunk.as_slices();
    debug_assert!(wrapped.is_empty(), "a chunk holds its items as one run");
    items
}

/// The items of a [`ChunkLog`] from one position on, oldest first.
///
/// Walks the chunks as slices: the run being read from the front, the run being
/// read from the back, and the whole chunks between them. A skip passes whole
/// chunks by their length rather than item by item.
///
/// Every chunk between the two runs is a FULL chunk (only a log's first and
/// last chunk can be short, and those are where the runs begin), so what is
/// left is known from the three without a count kept per item, and the step
/// that reads an item is the slice's own.
#[derive(Debug)]
pub struct Iter<'a, T> {
    front: core::slice::Iter<'a, T>,
    middle: core::slice::Iter<'a, VecDeque<T>>,
    back: core::slice::Iter<'a, T>,
}

/// Not derived: a derive would ask `T: Clone`, and cloning an iterator copies
/// three positions, never an item.
impl<T> Clone for Iter<'_, T> {
    fn clone(&self) -> Self {
        Self {
            front: self.front.clone(),
            middle: self.middle.clone(),
            back: self.back.clone(),
        }
    }
}

impl<'a, T> Iter<'a, T> {
    /// Items not yet read.
    fn left(&self) -> usize {
        self.front.len() + self.middle.len() * CHUNK_ITEMS + self.back.len()
    }

    /// The iterator, spent.
    fn spend(&mut self) {
        self.front = <&[T]>::default().iter();
        self.middle.by_ref().for_each(drop);
        self.back = <&[T]>::default().iter();
    }

    /// [`Iterator::next`] once the front run is spent.
    #[cold]
    fn next_past_front(&mut self) -> Option<&'a T> {
        match self.middle.next() {
            Some(chunk) => {
                self.front = run(chunk).iter();
                self.front.next()
            }
            None => self.back.next(),
        }
    }

    /// [`DoubleEndedIterator::next_back`] once the back run is spent.
    #[cold]
    fn next_back_past_back(&mut self) -> Option<&'a T> {
        match self.middle.next_back() {
            Some(chunk) => {
                self.back = run(chunk).iter();
                self.back.next_back()
            }
            None => self.front.next_back(),
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<&'a T> {
        match self.front.next() {
            Some(item) => Some(item),
            None => self.next_past_front(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.left();
        (left, Some(left))
    }

    fn count(self) -> usize {
        self.left()
    }

    fn last(mut self) -> Option<&'a T> {
        self.next_back()
    }

    fn nth(&mut self, mut n: usize) -> Option<&'a T> {
        if n >= self.left() {
            // Past the end: the iterator is spent, as a slice's is.
            self.spend();
            return None;
        }
        loop {
            let here = self.front.len();
            if n < here {
                return self.front.nth(n);
            }
            n -= here;
            // The run is passed whole: spent here, so no later step reads it
            // again.
            self.front = <&[T]>::default().iter();
            match self.middle.next() {
                Some(chunk) => self.front = run(chunk).iter(),
                None => return self.back.nth(n),
            }
        }
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.back.next_back() {
            Some(item) => Some(item),
            None => self.next_back_past_back(),
        }
    }

    fn nth_back(&mut self, mut n: usize) -> Option<Self::Item> {
        if n >= self.left() {
            self.spend();
            return None;
        }
        loop {
            let here = self.back.len();
            if n < here {
                return self.back.nth_back(n);
            }
            n -= here;
            self.back = <&[T]>::default().iter();
            match self.middle.next_back() {
                Some(chunk) => self.back = run(chunk).iter(),
                None => return self.front.nth_back(n),
            }
        }
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}

impl<T> core::iter::FusedIterator for Iter<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bisection agrees with a slice's over every position of a log grown
    /// across chunks and trimmed into the middle of one.
    #[test]
    fn the_partition_point_is_the_slices() {
        let mut log = ChunkLog::new();
        let mut held = Vec::new();
        for n in 0..(3 * CHUNK_ITEMS + 5) {
            log.push_back(n * 2);
            held.push(n * 2);
        }
        let released = CHUNK_ITEMS + 7;
        for expected in &held[..released] {
            assert_eq!(log.pop_front().as_ref(), Some(expected));
        }
        let held = &held[released..];
        for probe in [
            0,
            1,
            2,
            held[0],
            held[0] + 1,
            held[held.len() / 2],
            usize::MAX,
        ] {
            assert_eq!(
                log.partition_point(|&v| v < probe),
                held.partition_point(|&v| v < probe),
                "probe {probe}"
            );
        }
        assert_eq!(log.front(), held.first());
        assert_eq!(log.back(), held.last());
    }
}
