// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The latest sample of a subscription, in storage the image declared: what a node that subscribes
//! keeps, and what a queryable that answers from it reads.
//!
//! A subscription of a node on the slot profile does one thing with what it receives: it keeps the
//! LAST sample (its key, its payload cut to the cell's capacity, how long it was, whether it was a
//! put or a delete) and counts it. The count is how the rest of the node learns that something
//! arrived without being called by the session: the loop's application reads it each round
//! ([`LatestSlots::sequence`]) and says it on the console, and a queryable that answers from the
//! subscription ([`Answer::Latest`](crate::slot_client::Answer)) reads the same cell.
//!
//! # Storage
//!
//! [`LatestCells`] is `K` cells of `N` bytes in ONE `static` whose initial value is all zero bytes,
//! so the linker places it in `.bss` (the rule of [`NodeStorage`](crate::slot_node::NodeStorage)).
//! Every cell has the capacity `N`, the largest any subscription of the node asks for; a
//! subscription states its own capacity (`sample_bytes`), which is at most `N`, and the sink holds
//! that number, so a payload longer than the subscription asked for is cut where the declaration
//! said and not where the largest neighbour allowed.
//!
//! The cells are written by the session's dispatch and read by the loop and by a query's answer:
//! all on the one thread that drives the node (the profile's rule), never at the same moment, and
//! no read hands out a reference that outlives its closure.
//!
//! This module does not link `alloc`.

use core::cell::{Cell, UnsafeCell};

use wz_session_core::caps::MAX_KEYEXPR_BYTES;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::{SampleSink, SampleView};

/// What a cell holds, as a reader sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Latest<'a> {
    /// The key the sample arrived under (cut to the node's key limit).
    pub key: &'a str,
    /// The payload as kept: the first `capacity` bytes.
    pub payload: &'a [u8],
    /// How long the payload was when it arrived, which is more than `payload.len()` when it was
    /// cut.
    pub received_len: usize,
    /// A put, or a delete (whose payload is empty).
    pub kind: SampleKind,
    /// How many samples this cell has taken. The first is 1; 0 is a cell nothing reached.
    pub sequence: u32,
}

/// The cells of a node's subscriptions, as the sink and the answer reach them: by index, through a
/// trait object, so they do not carry the size of the storage.
pub trait LatestSlots: Sync {
    /// Keep a sample in cell `index`, cutting the payload to `capacity` bytes (and to the cell's own).
    fn put(&self, index: usize, capacity: usize, key: &str, payload: &[u8], kind: SampleKind);

    /// Read cell `index`: `read` is called once with what it holds, or with `None` when nothing
    /// reached it yet (or `index` is outside the storage).
    fn with(&self, index: usize, read: &mut dyn FnMut(Option<Latest<'_>>));

    /// How many samples cell `index` has taken (0 for a cell nothing reached, or one that is not
    /// there).
    fn sequence(&self, index: usize) -> u32;
}

/// One cell: the last sample and the count of them.
pub struct LatestCell<const N: usize> {
    payload: UnsafeCell<[u8; N]>,
    key: UnsafeCell<[u8; MAX_KEYEXPR_BYTES]>,
    stored: Cell<usize>,
    key_len: Cell<usize>,
    received: Cell<usize>,
    deleted: Cell<bool>,
    sequence: Cell<u32>,
}

impl<const N: usize> LatestCell<N> {
    /// An empty cell; all zero bytes.
    pub const fn new() -> Self {
        Self {
            payload: UnsafeCell::new([0; N]),
            key: UnsafeCell::new([0; MAX_KEYEXPR_BYTES]),
            stored: Cell::new(0),
            key_len: Cell::new(0),
            received: Cell::new(0),
            deleted: Cell::new(false),
            sequence: Cell::new(0),
        }
    }

    fn put(&self, capacity: usize, key: &str, payload: &[u8], kind: SampleKind) {
        let keep = payload.len().min(capacity).min(N);
        // The longest prefix of the key that is still whole characters: a key cut inside one would
        // not be text.
        let mut key_len = key.len().min(MAX_KEYEXPR_BYTES);
        while !key.is_char_boundary(key_len) {
            key_len -= 1;
        }
        // SAFETY: one thread drives the node and `with` hands out nothing that outlives its call, so
        // no reference into either array exists while this writes.
        unsafe {
            let (cell_payload, cell_key) = (&mut *self.payload.get(), &mut *self.key.get());
            cell_payload[..keep].copy_from_slice(&payload[..keep]);
            cell_key[..key_len].copy_from_slice(&key.as_bytes()[..key_len]);
        }
        self.stored.set(keep);
        self.key_len.set(key_len);
        self.received.set(payload.len());
        self.deleted.set(matches!(kind, SampleKind::Del));
        self.sequence.set(self.sequence.get().wrapping_add(1));
    }

    fn with(&self, read: &mut dyn FnMut(Option<Latest<'_>>)) {
        if self.sequence.get() == 0 {
            return read(None);
        }
        // SAFETY: as in `put`: the arrays are written only by `put`, on this thread, and not while
        // this closure runs.
        let (payload, key) = unsafe { (&*self.payload.get(), &*self.key.get()) };
        read(Some(Latest {
            // `put` stored whole characters of a `&str`, so this is text; an empty key stands in
            // for the impossible case rather than panicking in the node's loop.
            key: core::str::from_utf8(&key[..self.key_len.get()]).unwrap_or(""),
            payload: &payload[..self.stored.get()],
            received_len: self.received.get(),
            kind: if self.deleted.get() {
                SampleKind::Del
            } else {
                SampleKind::Put
            },
            sequence: self.sequence.get(),
        }));
    }
}

impl<const N: usize> Default for LatestCell<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// `K` cells of `N` bytes: the storage of a node's subscriptions, in one `static`.
pub struct LatestCells<const K: usize, const N: usize> {
    cells: [LatestCell<N>; K],
}

impl<const K: usize, const N: usize> LatestCells<K, N> {
    /// Every cell empty; all zero bytes.
    pub const fn new() -> Self {
        Self {
            cells: [const { LatestCell::new() }; K],
        }
    }
}

impl<const K: usize, const N: usize> Default for LatestCells<K, N> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: the profile's rule, stated on the module: one thread drives the node and reaches the
// cells; each cell is `Sync` by the same rule.
unsafe impl<const N: usize> Sync for LatestCell<N> {}

impl<const K: usize, const N: usize> LatestSlots for LatestCells<K, N> {
    fn put(&self, index: usize, capacity: usize, key: &str, payload: &[u8], kind: SampleKind) {
        if let Some(cell) = self.cells.get(index) {
            cell.put(capacity, key, payload, kind);
        }
    }

    fn with(&self, index: usize, read: &mut dyn FnMut(Option<Latest<'_>>)) {
        match self.cells.get(index) {
            Some(cell) => cell.with(read),
            None => read(None),
        }
    }

    fn sequence(&self, index: usize) -> u32 {
        self.cells.get(index).map_or(0, |cell| cell.sequence.get())
    }
}

/// A subscription's sink: it keeps what it is delivered in its cell.
#[derive(Clone, Copy)]
pub struct LatestSink {
    slots: &'static dyn LatestSlots,
    index: usize,
    capacity: usize,
}

impl LatestSink {
    /// The sink of cell `index` of `slots`, keeping at most `capacity` bytes of a payload.
    pub const fn new(slots: &'static dyn LatestSlots, index: usize, capacity: usize) -> Self {
        Self {
            slots,
            index,
            capacity,
        }
    }
}

impl SampleSink for LatestSink {
    fn deliver(&mut self, sample: &dyn SampleView) {
        self.slots.put(
            self.index,
            self.capacity,
            sample.keyexpr(),
            sample.payload(),
            sample.kind(),
        );
    }
}

/// Where a queryable reads the latest sample: a cell of a node's subscriptions.
#[derive(Clone, Copy)]
pub struct LatestRef {
    /// The node's cells.
    pub slots: &'static dyn LatestSlots,
    /// The cell.
    pub index: usize,
}

/// What a node's loop remembers of its cells between two rounds, to say each new sample once.
///
/// A round that finds a cell's count moved calls `say` with the sample the cell holds NOW and the
/// count: a cell that took three samples between two rounds is said once, with a count three
/// higher, so what was coalesced is visible and not hidden.
pub struct LatestWatch<const K: usize> {
    seen: [u32; K],
}

impl<const K: usize> LatestWatch<K> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self { seen: [0; K] }
    }

    /// Call `say(index, sample)` for each of the first `cells` cells of `slots` that took a sample
    /// since the last call.
    pub fn poll(
        &mut self,
        slots: &dyn LatestSlots,
        cells: usize,
        say: impl FnMut(usize, Latest<'_>),
    ) {
        self.poll_range(slots, 0, cells, say);
    }

    /// [`poll`](Self::poll) for the cells from `first` to `end` (not including it): a node whose
    /// subscriptions and queriers keep their latest in one storage says each kind with its own words.
    /// The index `say` is given is the cell's in the whole storage.
    pub fn poll_range(
        &mut self,
        slots: &dyn LatestSlots,
        first: usize,
        end: usize,
        mut say: impl FnMut(usize, Latest<'_>),
    ) {
        for index in first..end.min(K) {
            let now = slots.sequence(index);
            if now == self.seen[index] {
                continue;
            }
            self.seen[index] = now;
            slots.with(index, &mut |latest| {
                if let Some(latest) = latest {
                    say(index, latest);
                }
            });
        }
    }
}

impl<const K: usize> Default for LatestWatch<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use wz_session_core::reliability::Reliability;
    use wz_session_core::sink::BorrowedSample;

    fn sample<'a>(key: &'a str, payload: &'a [u8], kind: SampleKind) -> BorrowedSample<'a> {
        BorrowedSample {
            keyexpr: key,
            payload,
            kind,
            reliability: Reliability::Reliable,
        }
    }

    fn slots() -> &'static LatestCells<2, 8> {
        Box::leak(Box::new(LatestCells::new()))
    }

    fn read(
        slots: &dyn LatestSlots,
        index: usize,
    ) -> Option<(String, Vec<u8>, usize, SampleKind, u32)> {
        let mut out = None;
        slots.with(index, &mut |latest| {
            out = latest.map(|l| {
                (
                    l.key.to_owned(),
                    l.payload.to_vec(),
                    l.received_len,
                    l.kind,
                    l.sequence,
                )
            });
        });
        out
    }

    #[test]
    fn a_cell_nothing_reached_reads_as_nothing() {
        let cells = slots();
        assert_eq!(read(cells, 0), None);
        assert_eq!(cells.sequence(0), 0);
    }

    #[test]
    fn a_sample_is_kept_and_counted_and_the_next_replaces_it() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 0, 8);
        sink.deliver(&sample("lab/in/a", b"21.0", SampleKind::Put));
        assert_eq!(
            read(cells, 0),
            Some(("lab/in/a".into(), b"21.0".to_vec(), 4, SampleKind::Put, 1))
        );
        sink.deliver(&sample("lab/in/b", b"22", SampleKind::Put));
        assert_eq!(
            read(cells, 0),
            Some(("lab/in/b".into(), b"22".to_vec(), 2, SampleKind::Put, 2))
        );
        assert_eq!(read(cells, 1), None, "the other cell is untouched");
    }

    #[test]
    fn a_payload_is_cut_at_the_subscriptions_capacity_and_says_how_long_it_was() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 0, 3);
        sink.deliver(&sample("k", b"abcdef", SampleKind::Put));
        assert_eq!(
            read(cells, 0),
            Some(("k".into(), b"abc".to_vec(), 6, SampleKind::Put, 1))
        );
    }

    #[test]
    fn a_capacity_above_the_cell_is_the_cells() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 0, 100);
        sink.deliver(&sample("k", b"0123456789", SampleKind::Put));
        let (_, payload, received, _, _) = read(cells, 0).unwrap();
        assert_eq!((payload.len(), received), (8, 10));
    }

    #[test]
    fn a_delete_is_kept_as_a_delete_with_no_payload() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 1, 8);
        sink.deliver(&sample("k", b"x", SampleKind::Put));
        sink.deliver(&sample("k", b"", SampleKind::Del));
        assert_eq!(
            read(cells, 1),
            Some(("k".into(), vec![], 0, SampleKind::Del, 2))
        );
    }

    #[test]
    fn a_key_over_the_limit_is_cut_at_a_character() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 0, 8);
        // A two-byte character straddling the limit: the cut falls before it.
        let key = format!("{}é", "k".repeat(MAX_KEYEXPR_BYTES - 1));
        sink.deliver(&sample(&key, b"x", SampleKind::Put));
        let (kept, ..) = read(cells, 0).unwrap();
        assert_eq!(kept, "k".repeat(MAX_KEYEXPR_BYTES - 1));
    }

    #[test]
    fn the_watch_says_each_new_sample_once_and_a_coalesced_run_with_its_count() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 0, 8);
        let mut watch = LatestWatch::<2>::new();
        let mut said = Vec::new();
        let poll = |watch: &mut LatestWatch<2>, said: &mut Vec<(usize, String, u32)>| {
            watch.poll(cells, 2, |index, l| {
                said.push((index, l.key.to_owned(), l.sequence))
            });
        };
        poll(&mut watch, &mut said);
        assert!(said.is_empty(), "nothing arrived");
        sink.deliver(&sample("a", b"1", SampleKind::Put));
        poll(&mut watch, &mut said);
        poll(&mut watch, &mut said);
        assert_eq!(
            said,
            vec![(0, "a".to_owned(), 1)],
            "said once, not on every round"
        );
        sink.deliver(&sample("b", b"2", SampleKind::Put));
        sink.deliver(&sample("c", b"3", SampleKind::Put));
        poll(&mut watch, &mut said);
        assert_eq!(
            said.last(),
            Some(&(0, "c".to_owned(), 3)),
            "two samples between rounds are one report with the count of both"
        );
    }

    #[test]
    fn the_watch_can_say_a_range_of_cells_by_the_cells_own_index() {
        let cells = slots();
        let mut first = LatestSink::new(cells, 0, 8);
        let mut second = LatestSink::new(cells, 1, 8);
        let mut watch = LatestWatch::<2>::new();
        first.deliver(&sample("a", b"1", SampleKind::Put));
        second.deliver(&sample("b", b"2", SampleKind::Put));
        let mut said = Vec::new();
        watch.poll_range(cells, 1, 2, |index, l| said.push((index, l.key.to_owned())));
        assert_eq!(
            said,
            [(1, "b".to_owned())],
            "only the second cell, under index 1"
        );
        watch.poll_range(cells, 0, 1, |index, l| said.push((index, l.key.to_owned())));
        assert_eq!(
            said.last(),
            Some(&(0, "a".to_owned())),
            "the first was not seen yet"
        );
    }

    #[test]
    fn a_cell_outside_the_storage_reads_as_nothing_and_takes_nothing() {
        let cells = slots();
        let mut sink = LatestSink::new(cells, 5, 8);
        sink.deliver(&sample("k", b"x", SampleKind::Put));
        assert_eq!(read(cells, 5), None);
        assert_eq!(cells.sequence(5), 0);
    }
}
