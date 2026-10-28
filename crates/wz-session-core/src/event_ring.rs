// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A ring of fixed-size event records with one producer and any number of readers
//! (`docs/observation-plane.md` M2).
//!
//! # What it is
//!
//! A node that has something to say about itself (a link came up, a session closed, a sample was
//! dropped) says it as a record: a sequence number, a level, a source, a time and a few integers.
//! Text is not stored. The format a record is read with is a constant the reader holds, so a record
//! costs a few words and nothing is formatted on the node.
//!
//! The ring holds the last `SLOTS` records. It reads no clock, allocates nothing, starts no task
//! and takes no lock, so every host uses the one set of rules, and the whole of it can sit in a
//! `static`, in a region a reset leaves alone.
//!
//! # One producer, many readers
//!
//! [`EventRing::split`] takes `&mut self` and hands out three parts: the [`Producer`], which is the
//! only writer and is neither `Clone` nor `Copy`; the [`Consumer`], the only reader that frees what
//! it has passed; and the [`Observer`], which is `Copy` and makes any number of non-consuming
//! [`Reader`]s. The single-producer rule is the borrow checker's, so the write side needs no
//! atomic read-modify-write and a Cortex-M0, which has none, runs it. The write side never waits
//! for a reader, and a reader never makes the producer wait: there is nothing for either to wait
//! on.
//!
//! # The protocol (a per-slot sequence lock)
//!
//! Every slot has a generation word `gen` beside its record, and the record is stored as plain
//! 32-bit atomic words, so a reader that sees half a record sees an atomic value of each word and
//! not a data race. For the record with sequence number `n`, in slot `n % SLOTS`, on lap
//! `n / SLOTS`:
//!
//! * the producer stores `gen = 2 * lap + 1` (odd: being written), then the record words, then
//!   `gen = 2 * lap + 2` (even: complete), and last the ring's `next` word, `n + 1`;
//! * a reader of `n` loads `gen`; if it is `2 * lap + 2` it copies the words and loads `gen` again,
//!   and the copy is the record only if `gen` has not moved.
//!
//! A `gen` behind the one the reader wants means the producer has not got there. A `gen` ahead of
//! it means the slot has been written again, so the record was overwritten: the reader reports the
//! gap, skips to the oldest record still alive and goes on.
//!
//! # Loss is a gap in the sequence
//!
//! Sequence numbers are consecutive per ring. A reader that sees `n` and then `n + 3` knows exactly
//! three records are gone, so overwritten records need no separate count, and each reader counts
//! only its own losses. A node that wants the number without the walk reads [`Observer::dropped`],
//! which counts what the `drop-newest` policy refused.
//!
//! Sequence numbers are per ring. The records of several rings are put in order by their time
//! stamp, which is a hybrid logical clock's and so never goes back on one node.
//!
//! # What a full ring does
//!
//! [`FullPolicy::OverwriteOldest`] writes over the oldest record. It keeps the latest, which is what
//! a post-mortem wants, and it needs no reader at all. [`FullPolicy::DropNewest`] refuses the new
//! record and counts it. It keeps the beginning, which is what a boot trace wants, and so it needs
//! the [`Consumer`] to say how far it has read.
//!
//! # Windows
//!
//! The words a reader compares are 32 bits wide and compared modulo 2^32, as TCP compares its own.
//! A reader must therefore read at least once in every `2^31` records, and in every `SLOTS * 2^30`
//! records; a reader that sleeps past that cannot tell that it slept. At a record a microsecond that
//! is more than half an hour for the first bound, and the second is larger for any ring of a
//! hundred slots.

use core::sync::atomic::{fence, AtomicU32, Ordering};

/// What a full ring does with the record it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullPolicy {
    /// Write over the oldest record. The ring keeps the latest `SLOTS`.
    OverwriteOldest,
    /// Refuse the new record and count it. The ring keeps what it has until the [`Consumer`] frees
    /// it.
    DropNewest,
}

/// One event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<const ARGS: usize> {
    /// The record's number in its ring: the first is 0, and each is one more than the last.
    pub sequence: u64,
    /// How serious it is, in the producer's own scale.
    pub level: u8,
    /// What said it, in the producer's own numbering.
    pub source: u16,
    /// When, as the hybrid logical clock stamped it (`0` where there was no clock).
    pub timestamp: u64,
    /// How many of [`Self::args`] are meaningful.
    pub arg_count: u8,
    /// The integers the format is filled with.
    pub args: [u64; ARGS],
}

/// What [`Producer::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// The record is in the ring, as the sequence number given.
    Stored(u64),
    /// The ring was full under [`FullPolicy::DropNewest`] and the record was refused.
    Dropped,
}

/// What a read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read<const ARGS: usize> {
    /// The next record.
    Record(Record<ARGS>),
    /// Nothing newer than what was read.
    Empty,
    /// `missed` records were overwritten before they were read, and the reader has moved to the
    /// oldest one still alive. The next read continues from there.
    Lost {
        /// How many records are gone. At least 1.
        missed: u64,
    },
}

struct Slot<const ARGS: usize> {
    gen: AtomicU32,
    seq_lo: AtomicU32,
    seq_hi: AtomicU32,
    /// `level | arg_count << 8 | source << 16`.
    meta: AtomicU32,
    ts_lo: AtomicU32,
    ts_hi: AtomicU32,
    args_lo: [AtomicU32; ARGS],
    args_hi: [AtomicU32; ARGS],
}

impl<const ARGS: usize> Slot<ARGS> {
    const fn new() -> Self {
        Self {
            gen: AtomicU32::new(0),
            seq_lo: AtomicU32::new(0),
            seq_hi: AtomicU32::new(0),
            meta: AtomicU32::new(0),
            ts_lo: AtomicU32::new(0),
            ts_hi: AtomicU32::new(0),
            args_lo: [const { AtomicU32::new(0) }; ARGS],
            args_hi: [const { AtomicU32::new(0) }; ARGS],
        }
    }
}

/// The ring: `SLOTS` records, each with up to `ARGS` integer arguments.
pub struct EventRing<const SLOTS: usize, const ARGS: usize> {
    slots: [Slot<ARGS>; SLOTS],
    /// The sequence number of the next record to be written, as two words. Written only by the
    /// producer; the low word is what a reader polls, the pair is what a new reader starts from.
    next_lo: AtomicU32,
    next_hi: AtomicU32,
    /// The sequence number of the oldest record the [`Consumer`] has not freed, as two words.
    /// Written only by the consumer; read by the producer under [`FullPolicy::DropNewest`].
    tail_lo: AtomicU32,
    tail_hi: AtomicU32,
    /// Records refused under [`FullPolicy::DropNewest`]. Written only by the producer.
    dropped: AtomicU32,
    policy: FullPolicy,
}

/// The lap a sequence number is on, as the word a `gen` is made of.
const fn lap_of<const SLOTS: usize>(sequence: u64) -> u32 {
    (sequence / SLOTS as u64) as u32
}

impl<const SLOTS: usize, const ARGS: usize> EventRing<SLOTS, ARGS> {
    /// An empty ring.
    pub const fn new(policy: FullPolicy) -> Self {
        assert!(SLOTS > 0, "a ring with no slot holds nothing");
        assert!(
            SLOTS < (1 << 30),
            "a ring this large cannot tell a lap from the lap before it"
        );
        assert!(
            ARGS <= 255,
            "the argument count is one byte of the record's meta word"
        );
        Self {
            slots: [const { Slot::new() }; SLOTS],
            next_lo: AtomicU32::new(0),
            next_hi: AtomicU32::new(0),
            tail_lo: AtomicU32::new(0),
            tail_hi: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            policy,
        }
    }

    /// How many records the ring holds at most.
    pub const fn capacity(&self) -> usize {
        SLOTS
    }

    /// What the ring does when it is full.
    pub const fn policy(&self) -> FullPolicy {
        self.policy
    }

    /// A handle that makes readers and counts, for a ring kept in a `static`, which cannot be
    /// split. Reading changes nothing, so no one can misuse it.
    pub const fn observer(&self) -> Observer<'_, SLOTS, ARGS> {
        Observer { ring: self }
    }

    /// The producer of a ring kept in a `static`, which `&mut self` cannot reach.
    ///
    /// # Safety
    ///
    /// At most one [`Producer`] of this ring may be alive at any time, and a new one must be made
    /// after the last was dropped, with whatever orders the two (a lock, a single thread). Two at
    /// once write the same slot, and a reader can then take half of one record and half of the
    /// other for a whole record.
    pub unsafe fn producer(&self) -> Producer<'_, SLOTS, ARGS> {
        Producer {
            ring: self,
            head: pair(&self.next_lo, &self.next_hi),
        }
    }

    /// The consumer of a ring kept in a `static`.
    ///
    /// # Safety
    ///
    /// At most one [`Consumer`] of this ring may be alive at any time, ordered as for
    /// [`Self::producer`]. Two at once both free what they pass, and the producer may then write
    /// over a record the slower of them has not read.
    pub unsafe fn consumer(&self) -> Consumer<'_, SLOTS, ARGS> {
        Consumer {
            reader: Reader {
                ring: self,
                cursor: Some(pair(&self.tail_lo, &self.tail_hi)),
            },
        }
    }

    /// The three parts of the ring. Taking `&mut self` is what makes the producer the only one:
    /// until all three are dropped the ring cannot be split again.
    pub fn split(
        &mut self,
    ) -> (
        Producer<'_, SLOTS, ARGS>,
        Consumer<'_, SLOTS, ARGS>,
        Observer<'_, SLOTS, ARGS>,
    ) {
        // Every field is an atomic, so the three parts share the ring; what makes the producer
        // the only one is the `&mut self` this reborrows from.
        let ring: &Self = self;
        let head = pair(&ring.next_lo, &ring.next_hi);
        let tail = pair(&ring.tail_lo, &ring.tail_hi);
        (
            Producer { ring, head },
            Consumer {
                reader: Reader {
                    ring,
                    cursor: Some(tail),
                },
            },
            Observer { ring },
        )
    }
}

/// A 64-bit value stored as two words, read when no one is changing it.
fn pair(lo: &AtomicU32, hi: &AtomicU32) -> u64 {
    loop {
        let high = hi.load(Ordering::Acquire);
        let low = lo.load(Ordering::Acquire);
        if hi.load(Ordering::Acquire) == high {
            return (u64::from(high) << 32) | u64::from(low);
        }
    }
}

fn store_pair(lo: &AtomicU32, hi: &AtomicU32, value: u64) {
    lo.store(value as u32, Ordering::Release);
    hi.store((value >> 32) as u32, Ordering::Release);
}

/// The only writer of a ring.
pub struct Producer<'a, const SLOTS: usize, const ARGS: usize> {
    ring: &'a EventRing<SLOTS, ARGS>,
    /// The next sequence number: the producer's own, so it never reads what it wrote.
    head: u64,
}

impl<const SLOTS: usize, const ARGS: usize> Producer<'_, SLOTS, ARGS> {
    /// Store a record. `args` beyond `ARGS` are ignored; fewer are stored as given and the rest
    /// read as zero.
    pub fn push(&mut self, level: u8, source: u16, timestamp: u64, args: &[u64]) -> Pushed {
        if self.ring.policy == FullPolicy::DropNewest {
            let tail = pair(&self.ring.tail_lo, &self.ring.tail_hi);
            if self.head - tail >= SLOTS as u64 {
                let dropped = self.ring.dropped.load(Ordering::Relaxed);
                self.ring
                    .dropped
                    .store(dropped.saturating_add(1), Ordering::Relaxed);
                return Pushed::Dropped;
            }
        }
        let sequence = self.head;
        let used = args.len().min(ARGS);
        self.open(sequence);
        self.fill(sequence, level, source, timestamp, &args[..used]);
        self.close(sequence);
        Pushed::Stored(sequence)
    }

    /// The first half of a write: the slot is marked as being written.
    fn open(&self, sequence: u64) {
        let slot = &self.ring.slots[(sequence % SLOTS as u64) as usize];
        slot.gen.store(
            lap_of::<SLOTS>(sequence).wrapping_mul(2).wrapping_add(1),
            Ordering::Relaxed,
        );
        // The marker is ordered before every word of the record, so a reader that sees a word of
        // this record sees the marker (or a later one) when it looks again.
        fence(Ordering::Release);
    }

    /// The record's words.
    fn fill(&self, sequence: u64, level: u8, source: u16, timestamp: u64, args: &[u64]) {
        let slot = &self.ring.slots[(sequence % SLOTS as u64) as usize];
        slot.seq_lo.store(sequence as u32, Ordering::Relaxed);
        slot.seq_hi
            .store((sequence >> 32) as u32, Ordering::Relaxed);
        slot.meta.store(
            u32::from(level) | ((args.len() as u32) << 8) | (u32::from(source) << 16),
            Ordering::Relaxed,
        );
        slot.ts_lo.store(timestamp as u32, Ordering::Relaxed);
        slot.ts_hi
            .store((timestamp >> 32) as u32, Ordering::Relaxed);
        for index in 0..ARGS {
            let value = args.get(index).copied().unwrap_or(0);
            slot.args_lo[index].store(value as u32, Ordering::Relaxed);
            slot.args_hi[index].store((value >> 32) as u32, Ordering::Relaxed);
        }
    }

    /// The second half: the slot is complete, and the ring says it has one more.
    fn close(&mut self, sequence: u64) {
        let slot = &self.ring.slots[(sequence % SLOTS as u64) as usize];
        slot.gen.store(
            lap_of::<SLOTS>(sequence).wrapping_mul(2).wrapping_add(2),
            Ordering::Release,
        );
        self.head = sequence + 1;
        store_pair(&self.ring.next_lo, &self.ring.next_hi, self.head);
    }

    /// How many records have been stored.
    pub fn stored(&self) -> u64 {
        self.head
    }
}

/// Reads records without freeing any. Any number may exist at once.
pub struct Reader<'a, const SLOTS: usize, const ARGS: usize> {
    ring: &'a EventRing<SLOTS, ARGS>,
    /// The sequence number this reader reads next; `None` until its first read, when it starts at
    /// the oldest record alive.
    cursor: Option<u64>,
}

impl<const SLOTS: usize, const ARGS: usize> Reader<'_, SLOTS, ARGS> {
    /// The next record, or why there is none.
    pub fn poll(&mut self) -> Read<ARGS> {
        let ring = self.ring;
        let cursor = match self.cursor {
            Some(cursor) => cursor,
            None => {
                let next = pair(&ring.next_lo, &ring.next_hi);
                let oldest = next.saturating_sub(SLOTS as u64);
                self.cursor = Some(oldest);
                oldest
            }
        };
        let ahead = ring
            .next_lo
            .load(Ordering::Acquire)
            .wrapping_sub(cursor as u32) as i32;
        if ahead <= 0 {
            return Read::Empty;
        }
        let slot = &ring.slots[(cursor % SLOTS as u64) as usize];
        let complete = lap_of::<SLOTS>(cursor).wrapping_mul(2).wrapping_add(2);
        let before = slot.gen.load(Ordering::Acquire);
        let distance = before.wrapping_sub(complete) as i32;
        if distance < 0 {
            // The producer published `next` after the slot was complete, so this is the slot of a
            // record not yet written: nothing to read.
            return Read::Empty;
        }
        if distance == 0 {
            let record = copy(slot);
            fence(Ordering::Acquire);
            let after = slot.gen.load(Ordering::Relaxed);
            if after == before && record.sequence == cursor {
                self.cursor = Some(cursor + 1);
                return Read::Record(record);
            }
        }
        // The slot has been written again: the record is gone. Move to the oldest one alive, which
        // is at least the one after this.
        let next_lo = ring.next_lo.load(Ordering::Acquire);
        let ahead = next_lo.wrapping_sub(cursor as u32) as i32;
        let skip = (ahead as i64 - SLOTS as i64).max(1) as u64;
        self.cursor = Some(cursor + skip);
        Read::Lost { missed: skip }
    }

    /// The sequence number this reader reads next, once it has read.
    pub fn cursor(&self) -> Option<u64> {
        self.cursor
    }
}

/// The words of a slot as a record. Not checked: the caller compares the slot's `gen` around it.
fn copy<const ARGS: usize>(slot: &Slot<ARGS>) -> Record<ARGS> {
    let meta = slot.meta.load(Ordering::Relaxed);
    let mut args = [0u64; ARGS];
    for (index, out) in args.iter_mut().enumerate() {
        *out = u64::from(slot.args_hi[index].load(Ordering::Relaxed)) << 32
            | u64::from(slot.args_lo[index].load(Ordering::Relaxed));
    }
    Record {
        sequence: u64::from(slot.seq_hi.load(Ordering::Relaxed)) << 32
            | u64::from(slot.seq_lo.load(Ordering::Relaxed)),
        level: meta as u8,
        arg_count: (meta >> 8) as u8,
        source: (meta >> 16) as u16,
        timestamp: u64::from(slot.ts_hi.load(Ordering::Relaxed)) << 32
            | u64::from(slot.ts_lo.load(Ordering::Relaxed)),
        args,
    }
}

/// The only reader that frees what it has read. Under [`FullPolicy::OverwriteOldest`] it is an
/// ordinary reader; under [`FullPolicy::DropNewest`] what it passes is what the producer may
/// overwrite.
pub struct Consumer<'a, const SLOTS: usize, const ARGS: usize> {
    reader: Reader<'a, SLOTS, ARGS>,
}

impl<const SLOTS: usize, const ARGS: usize> Consumer<'_, SLOTS, ARGS> {
    /// The next record, or why there is none; a record read, or a gap skipped, is freed.
    pub fn poll(&mut self) -> Read<ARGS> {
        let read = self.reader.poll();
        if let Some(cursor) = self.reader.cursor {
            store_pair(&self.reader.ring.tail_lo, &self.reader.ring.tail_hi, cursor);
        }
        read
    }
}

/// A handle that makes readers and counts. `Copy`: any number of threads hold one.
#[derive(Clone, Copy)]
pub struct Observer<'a, const SLOTS: usize, const ARGS: usize> {
    ring: &'a EventRing<SLOTS, ARGS>,
}

impl<'a, const SLOTS: usize, const ARGS: usize> Observer<'a, SLOTS, ARGS> {
    /// A reader that starts at the oldest record alive and frees nothing.
    pub fn reader(&self) -> Reader<'a, SLOTS, ARGS> {
        Reader {
            ring: self.ring,
            cursor: None,
        }
    }

    /// How many records the producer refused under [`FullPolicy::DropNewest`]. Saturating: a
    /// counter that wrapped would hide the overload it exists to show.
    pub fn dropped(&self) -> u32 {
        self.ring.dropped.load(Ordering::Relaxed)
    }

    /// How many records have been stored, as of the last one the producer finished.
    pub fn stored(&self) -> u64 {
        pair(&self.ring.next_lo, &self.ring.next_hi)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    type Ring = EventRing<4, 2>;

    fn read_all<const S: usize, const A: usize>(reader: &mut Reader<'_, S, A>) -> Vec<Read<A>> {
        let mut out = Vec::new();
        loop {
            match reader.poll() {
                Read::Empty => return out,
                other => out.push(other),
            }
        }
    }

    fn sequences<const A: usize>(reads: &[Read<A>]) -> Vec<i64> {
        reads
            .iter()
            .map(|read| match read {
                Read::Record(record) => record.sequence as i64,
                Read::Lost { missed } => -(*missed as i64),
                Read::Empty => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn a_record_is_read_back_as_it_was_stored() {
        let mut ring = Ring::new(FullPolicy::OverwriteOldest);
        let (mut producer, _consumer, observer) = ring.split();
        assert_eq!(
            producer.push(3, 0xBEEF, 77, &[1, u64::MAX]),
            Pushed::Stored(0)
        );
        let mut reader = observer.reader();
        let Read::Record(record) = reader.poll() else {
            panic!("a record was stored");
        };
        assert_eq!(
            record,
            Record {
                sequence: 0,
                level: 3,
                source: 0xBEEF,
                timestamp: 77,
                arg_count: 2,
                args: [1, u64::MAX],
            }
        );
        assert_eq!(reader.poll(), Read::Empty);
    }

    #[test]
    fn fewer_arguments_than_the_ring_holds_read_as_zero_and_more_are_ignored() {
        let mut ring = Ring::new(FullPolicy::OverwriteOldest);
        let (mut producer, _consumer, observer) = ring.split();
        producer.push(0, 0, 0, &[9]);
        producer.push(0, 0, 0, &[1, 2, 3, 4]);
        let reads = read_all(&mut observer.reader());
        let Read::Record(short) = reads[0] else {
            panic!()
        };
        let Read::Record(long) = reads[1] else {
            panic!()
        };
        assert_eq!((short.arg_count, short.args), (1, [9, 0]));
        assert_eq!((long.arg_count, long.args), (2, [1, 2]));
    }

    #[test]
    fn overwrite_oldest_keeps_the_latest_and_a_reader_that_fell_behind_is_told_how_many() {
        let mut ring = Ring::new(FullPolicy::OverwriteOldest);
        let (mut producer, _consumer, observer) = ring.split();
        let mut early = observer.reader();
        producer.push(0, 0, 0, &[]);
        assert_eq!(sequences(&read_all(&mut early)), [0]);
        for _ in 0..10 {
            producer.push(0, 0, 0, &[]);
        }
        // 11 stored, 4 alive (7..=10); the reader has read 0 and so missed 1..=6.
        assert_eq!(sequences(&read_all(&mut early)), [-6, 7, 8, 9, 10]);
        // A reader that starts now starts at the oldest alive.
        assert_eq!(sequences(&read_all(&mut observer.reader())), [7, 8, 9, 10]);
    }

    #[test]
    fn drop_newest_keeps_the_beginning_counts_the_refusals_and_the_consumer_frees_room() {
        let mut ring = Ring::new(FullPolicy::DropNewest);
        let (mut producer, mut consumer, observer) = ring.split();
        for _ in 0..4 {
            assert!(matches!(producer.push(0, 0, 0, &[]), Pushed::Stored(_)));
        }
        assert_eq!(producer.push(0, 0, 0, &[]), Pushed::Dropped);
        assert_eq!(producer.push(0, 0, 0, &[]), Pushed::Dropped);
        assert_eq!(observer.dropped(), 2);

        let Read::Record(first) = consumer.poll() else {
            panic!()
        };
        assert_eq!(first.sequence, 0);
        assert_eq!(
            producer.push(0, 0, 0, &[]),
            Pushed::Stored(4),
            "one slot came back"
        );
        assert_eq!(producer.push(0, 0, 0, &[]), Pushed::Dropped);

        let rest: Vec<i64> = std::iter::from_fn(|| match consumer.poll() {
            Read::Record(record) => Some(record.sequence as i64),
            _ => None,
        })
        .collect();
        assert_eq!(rest, [1, 2, 3, 4], "nothing the ring accepted was lost");
    }

    #[test]
    fn readers_are_independent_and_none_of_them_frees_anything() {
        let mut ring = Ring::new(FullPolicy::DropNewest);
        let (mut producer, _consumer, observer) = ring.split();
        for _ in 0..4 {
            producer.push(0, 0, 0, &[]);
        }
        let mut one = observer.reader();
        let mut two = observer.reader();
        assert_eq!(sequences(&read_all(&mut one)), [0, 1, 2, 3]);
        assert_eq!(sequences(&read_all(&mut two)), [0, 1, 2, 3]);
        assert_eq!(
            producer.push(0, 0, 0, &[]),
            Pushed::Dropped,
            "readers do not consume; only the consumer frees"
        );
    }

    #[test]
    fn a_ring_in_a_static_is_written_one_producer_after_another_and_read_through_its_observer() {
        let ring = Ring::new(FullPolicy::OverwriteOldest);
        // One producer at a time, as a lock would order them.
        for round in 0..3u64 {
            // SAFETY: the previous producer is dropped at the end of the previous iteration.
            let mut producer = unsafe { ring.producer() };
            assert_eq!(producer.push(0, 0, 0, &[]), Pushed::Stored(round));
        }
        assert_eq!(ring.observer().stored(), 3);
        assert_eq!(
            sequences(&read_all(&mut ring.observer().reader())),
            [0, 1, 2]
        );
    }

    #[test]
    fn a_ring_can_be_split_again_and_goes_on_from_where_it_was() {
        let mut ring = Ring::new(FullPolicy::OverwriteOldest);
        {
            let (mut producer, _consumer, _observer) = ring.split();
            producer.push(0, 0, 0, &[]);
            producer.push(0, 0, 0, &[]);
        }
        let (mut producer, _consumer, observer) = ring.split();
        assert_eq!(producer.push(0, 0, 0, &[]), Pushed::Stored(2));
        assert_eq!(sequences(&read_all(&mut observer.reader())), [0, 1, 2]);
    }

    /// A record whose every field is a function of its sequence number, so that a record put
    /// together from two writes is seen as one.
    fn payload(sequence: u64) -> (u8, u16, u64, [u64; 2]) {
        (
            sequence as u8,
            (sequence.wrapping_mul(7)) as u16,
            sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            [sequence ^ 0xAAAA_AAAA_AAAA_AAAA, !sequence],
        )
    }

    fn check(record: &Record<2>) {
        let (level, source, timestamp, args) = payload(record.sequence);
        assert_eq!(
            (record.level, record.source, record.timestamp, record.args),
            (level, source, timestamp, args),
            "record {} is not one write",
            record.sequence
        );
    }

    /// What one reader has been told, held against the cursor it keeps. A reader's cursor must
    /// move by exactly one for a record and by exactly `missed` for a gap, so a record counted
    /// twice or a gap that hides one is a cursor that disagrees.
    #[derive(Default)]
    struct Watch {
        /// Where the reader's cursor was when it started reading.
        start: Option<u64>,
        seen: u64,
        lost: u64,
    }

    impl Watch {
        fn read<const S: usize>(&mut self, reader: &mut Reader<'_, S, 2>) -> Read<2> {
            let before = reader.cursor();
            let read = reader.poll();
            let after = reader.cursor().expect("a read leaves a cursor");
            match read {
                Read::Record(record) => {
                    check(&record);
                    if let Some(before) = before {
                        assert_eq!(
                            record.sequence, before,
                            "a reader sees the sequence in order"
                        );
                    }
                    assert_eq!(after, record.sequence + 1);
                    self.start.get_or_insert(record.sequence);
                    self.seen += 1;
                }
                Read::Lost { missed } => {
                    assert!(missed >= 1);
                    if let Some(before) = before {
                        assert_eq!(after, before + missed, "a gap is exactly what was skipped");
                    }
                    self.start.get_or_insert(after - missed);
                    self.lost += missed;
                }
                Read::Empty => {
                    if let Some(before) = before {
                        assert_eq!(after, before, "nothing read, nothing moved");
                    }
                    self.start.get_or_insert(after);
                }
            }
            read
        }
    }

    /// A small deterministic generator, so a failing seed is a failing seed everywhere.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// The model: one thread plays the producer's micro-steps (open, one word at a time is one
    /// `fill`, close) and the readers' reads in a random order, so a reader looks in the middle of
    /// a write at every point the protocol has one. Whatever the order, a reader sees records in
    /// sequence, every record whole, and a gap exactly where records were overwritten.
    #[test]
    fn whatever_the_interleaving_a_reader_sees_whole_records_in_order_with_gaps_where_they_were_lost(
    ) {
        for seed in 1..=300u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
            let mut ring = EventRing::<5, 2>::new(FullPolicy::OverwriteOldest);
            let (mut producer, _consumer, observer) = ring.split();
            let mut readers: Vec<(Reader<'_, 5, 2>, Watch)> = (0..3)
                .map(|_| (observer.reader(), Watch::default()))
                .collect();
            let mut written = 0u64;
            // 0 = idle, 1 = open, 2 = filled
            let mut phase = 0u8;
            let total = 200u64;
            while written < total {
                match rng.next() % 4 {
                    0 | 1 => match phase {
                        0 => {
                            producer.open(written);
                            phase = 1;
                        }
                        1 => {
                            let (level, source, timestamp, args) = payload(written);
                            producer.fill(written, level, source, timestamp, &args);
                            phase = 2;
                        }
                        _ => {
                            producer.close(written);
                            written += 1;
                            phase = 0;
                        }
                    },
                    _ => {
                        let pick = (rng.next() % 3) as usize;
                        let (reader, watch) = &mut readers[pick];
                        watch.read(reader);
                    }
                }
            }
            // Drain: each reader ends at the last record, and every record from where it started
            // is either one it saw or one it was told it missed.
            for (reader, watch) in &mut readers {
                while watch.read(reader) != Read::Empty {}
                assert_eq!(
                    reader.cursor(),
                    Some(total),
                    "seed {seed}: the reader reached the end"
                );
                let start = watch.start.expect("the reader read at least once");
                assert_eq!(
                    watch.seen + watch.lost,
                    total - start,
                    "seed {seed}: every record from the start is seen or counted lost"
                );
            }
        }
    }

    /// Real threads: a producer writes as fast as it can while three readers read, and every
    /// record any reader returns is whole and in order.
    #[test]
    fn under_real_threads_every_record_a_reader_returns_is_whole_and_in_order() {
        use std::sync::atomic::AtomicBool;
        const TOTAL: u64 = 300_000;
        let mut ring = EventRing::<8, 2>::new(FullPolicy::OverwriteOldest);
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let (mut producer, _consumer, observer) = ring.split();
            let readers: Vec<_> = (0..3)
                .map(|_| {
                    let done = &done;
                    scope.spawn(move || {
                        let mut reader = observer.reader();
                        let (mut previous, mut seen, mut lost) = (None::<u64>, 0u64, 0u64);
                        loop {
                            // `done` is read BEFORE the poll. A reader that polled, found
                            // nothing, and only then looked at `done` could be told the producer
                            // had finished by a producer that had written a hundred thousand more
                            // records since the poll, and stop with them unread. Read first, an
                            // `Empty` after a `done` is the end: every write happened before the
                            // flag, and the poll that follows sees them all.
                            let finished = done.load(Ordering::Acquire);
                            match reader.poll() {
                                Read::Record(record) => {
                                    check(&record);
                                    if let Some(previous) = previous {
                                        assert_eq!(
                                            record.sequence,
                                            previous + 1,
                                            "a record that follows a record is the next one"
                                        );
                                    }
                                    previous = Some(record.sequence);
                                    seen += 1;
                                }
                                Read::Lost { missed } => {
                                    lost += missed;
                                    previous = None;
                                }
                                Read::Empty => {
                                    if finished {
                                        break;
                                    }
                                    std::hint::spin_loop();
                                }
                            }
                        }
                        (seen, lost, reader.cursor())
                    })
                })
                .collect();
            for sequence in 0..TOTAL {
                let (level, source, timestamp, args) = payload(sequence);
                producer.push(level, source, timestamp, &args);
            }
            done.store(true, Ordering::Release);
            for reader in readers {
                let (seen, lost, cursor) = reader.join().expect("a reader thread");
                assert!(seen > 0, "a reader read something");
                assert!(
                    seen + lost <= TOTAL,
                    "a reader never counts more than was written"
                );
                assert_eq!(
                    cursor,
                    Some(TOTAL),
                    "a reader that is told it is caught up is"
                );
            }
        });
    }
}
