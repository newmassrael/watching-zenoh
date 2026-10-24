// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An append-only log of byte runs, each read back whole by the position it was
//! logged at, and released from the front.
//!
//! Open-debt item 924 (`docs/dissect-row-index.md`, D8): the unit log a list of
//! datagrams reads its units' bytes from once it keeps them as index entries,
//! and the bytes a TCP assembler keeps for the rows that read its stream again
//! (a segment is one run, so a read of a run is one slice).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// The capacity of a [`ByteLog`]'s first chunk.
const FIRST_CHUNK: usize = 256;

/// The capacity no chunk grows past, unless one run is larger.
const MAX_CHUNK: usize = 64 * 1024;

/// Byte runs, in the order they were logged, each at a position that does not
/// change while it is held.
///
/// # Why chunks, and why a run never spans two
///
/// One growable buffer doubles, copying every byte it holds into each new
/// buffer and holding up to half of it unused, and releasing its front moves
/// every byte behind it. Here bytes go into chunks that are never reallocated:
/// a run that does not fit in the last chunk's spare capacity starts a new
/// chunk, each chunk twice the capacity of the one before it up to
/// [`MAX_CHUNK`] (or the run's own length, for a run larger than that). So no
/// byte is copied after it is logged, a log of a few runs costs a few runs'
/// bytes, the most held unused is one chunk's tail, and releasing drops whole
/// chunks. Every run lies in one chunk, so it reads as one slice and is never
/// gathered.
///
/// # Positions
///
/// A position counts bytes from the first chunk ever started, chunk capacity
/// included, so it is stable across releases. A chunk starts where the one
/// before it ends in that count, so the chunk holding a position is found by a
/// binary search over the chunks' starts.
#[derive(Debug, Default)]
pub struct ByteLog {
    chunks: VecDeque<Chunk>,
    /// Where the next chunk starts: the end of the last chunk ever started,
    /// which outlives that chunk's release.
    next_chunk_at: u64,
    /// The capacity of the last chunk ever started, which the next doubles.
    last_capacity: usize,
}

/// One chunk of a [`ByteLog`].
#[derive(Debug)]
struct Chunk {
    /// The position of the chunk's first byte.
    at: u64,
    /// The bytes logged in it. Allocated once at its capacity and never grown
    /// past it.
    bytes: Vec<u8>,
}

impl Chunk {
    /// One past the last position the chunk can hold.
    fn end(&self) -> u64 {
        self.at + self.bytes.capacity() as u64
    }
}

impl ByteLog {
    /// Log `run` and return the position it was logged at.
    pub fn append(&mut self, run: &[u8]) -> u64 {
        let fits = self
            .chunks
            .back()
            .is_some_and(|last| last.bytes.capacity() - last.bytes.len() >= run.len());
        if !fits {
            let capacity = match self.last_capacity {
                0 => FIRST_CHUNK,
                last => (last * 2).min(MAX_CHUNK),
            };
            let chunk = Chunk {
                at: self.next_chunk_at,
                bytes: Vec::with_capacity(capacity.max(run.len())),
            };
            self.next_chunk_at = chunk.end();
            self.last_capacity = capacity;
            self.chunks.push_back(chunk);
        }
        let last = self
            .chunks
            .back_mut()
            .unwrap_or_else(|| unreachable!("a chunk was started above"));
        let at = last.at + last.bytes.len() as u64;
        last.bytes.extend_from_slice(run);
        at
    }

    /// The `len` bytes logged at `at`, or `None` when they are not held (never
    /// logged, or released).
    pub fn get(&self, at: u64, len: usize) -> Option<&[u8]> {
        let k = self.chunks.partition_point(|c| c.end() <= at);
        let chunk = self.chunks.get(k)?;
        let from = usize::try_from(at.checked_sub(chunk.at)?).ok()?;
        chunk.bytes.get(from..from.checked_add(len)?)
    }

    /// Release every chunk whose logged bytes all stand before position `at`:
    /// what a holder calls once nothing reads those bytes any more. A run logged
    /// after the last chunk is released starts a chunk of its own, past every
    /// position ever handed out, so no position is handed out twice.
    pub fn release_before(&mut self, at: u64) {
        while self
            .chunks
            .front()
            .is_some_and(|c| c.at + c.bytes.len() as u64 <= at)
        {
            let _ = self.chunks.pop_front();
        }
        // A deque does not give back what it grew to as its front goes; a log
        // that held many chunks and now holds few would keep the peak's list.
        if self.chunks.len() * 4 <= self.chunks.capacity() {
            self.chunks.shrink_to_fit();
        }
    }

    /// Bytes the log holds allocated, logged or not: every chunk's buffer and the
    /// list of chunks that holds them, which doubles as the log grows and is as
    /// much the log's as the bytes are.
    pub fn allocated(&self) -> usize {
        self.chunks.capacity() * core::mem::size_of::<Chunk>()
            + self
                .chunks
                .iter()
                .map(|c| c.bytes.capacity())
                .sum::<usize>()
    }
}

/// The bit of a [`LogPlace`]'s locator that says the unit is in a container,
/// at an offset there rather than a position of the log's copy. No container
/// or log reaches 2^62 bytes.
const IN_CONTAINER: u64 = 1 << 63;

/// The bit that says the unit is in the stream its holder reassembled, at an
/// offset of it.
const IN_STREAM: u64 = 1 << 62;

/// Where a logged unit's bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogPlace {
    /// At this position of the [`UnitLog`]'s own copy.
    Kept(u64),
    /// At this offset of the capture container the log's holder lends, which
    /// the log keeps no copy of.
    Container(usize),
    /// At this offset of a direction's reassembled stream, which the log's
    /// holder keeps (or lends) and the log keeps no copy of: a unit a layer below
    /// framed (a WebSocket message that is one unmasked frame) whose bytes are
    /// the stream's own. The log cannot read it; the holder's source can
    /// ([`crate::passive_messages::UnitBytes::stream_bytes`]), and a stream that
    /// lets go of it keeps the units that stand there whole first.
    Stream(usize),
}

impl LogPlace {
    /// The place as one word, which a row keeps.
    pub fn locator(self) -> u64 {
        match self {
            LogPlace::Kept(at) => at,
            LogPlace::Container(offset) => offset as u64 | IN_CONTAINER,
            LogPlace::Stream(offset) => offset as u64 | IN_STREAM,
        }
    }

    /// The place a [`Self::locator`] word names.
    pub fn of(locator: u64) -> Self {
        if locator & IN_CONTAINER != 0 {
            LogPlace::Container((locator & !IN_CONTAINER) as usize)
        } else if locator & IN_STREAM != 0 {
            LogPlace::Stream((locator & !IN_STREAM) as usize)
        } else {
            LogPlace::Kept(locator)
        }
    }
}

/// The units a list read and reads again, each logged once: a copy of its
/// bytes, or, for a unit that sits in a capture container its holder lends,
/// its place there and no copy.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, D8): the unit log of every
/// list whose units arrive whole (a datagram, a serial frame, a WebSocket
/// message, a scouting message), read by the place it hands out and released
/// from the front as the units' last readers go.
#[derive(Debug, Default)]
pub struct UnitLog {
    copies: ByteLog,
}

impl UnitLog {
    /// Log the unit `bytes`, which sit at `in_container` in the container the
    /// log's holder lends when that is `Some`, and return its place.
    pub fn place(&mut self, bytes: &[u8], in_container: Option<usize>) -> LogPlace {
        match in_container {
            Some(offset) => LogPlace::Container(offset),
            None => LogPlace::Kept(self.copies.append(bytes)),
        }
    }

    /// The `len` bytes of the unit at `place`, read from the log's copy or
    /// from `container`; `None` when they are not held (released, or in a
    /// container the reader does not hand in), and for a [`LogPlace::Stream`]
    /// unit, whose bytes are the holder's stream's and not this log's.
    pub fn get<'a>(
        &'a self,
        place: LogPlace,
        len: usize,
        container: Option<&'a [u8]>,
    ) -> Option<&'a [u8]> {
        match place {
            LogPlace::Kept(at) => self.copies.get(at, len),
            LogPlace::Container(offset) => container?.get(offset..offset.checked_add(len)?),
            LogPlace::Stream(_) => None,
        }
    }

    /// Let go of the copy of the unit of `len` bytes at `place` and of every
    /// unit logged before it: what a holder calls when that unit's last reader
    /// goes, every earlier one having gone before it.
    pub fn release_through(&mut self, place: LogPlace, len: usize) {
        if let LogPlace::Kept(at) = place {
            self.copies.release_before(at + len as u64);
        }
    }

    /// Bytes the log holds allocated for its copies, logged or not: what its
    /// holder's memory account charges it (a unit in a lent container costs
    /// nothing here).
    pub fn allocated(&self) -> usize {
        self.copies.allocated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_reads_back_whole_at_the_position_it_was_logged() {
        let mut log = ByteLog::default();
        let runs: Vec<Vec<u8>> = (0..200u8)
            .map(|n| alloc::vec![n; usize::from(n) * 7 + 1])
            .collect();
        let at: Vec<u64> = runs.iter().map(|run| log.append(run)).collect();
        for (run, at) in runs.iter().zip(&at) {
            assert_eq!(log.get(*at, run.len()), Some(run.as_slice()));
        }
        // A run larger than any chunk gets a chunk of its own.
        let large = alloc::vec![9u8; MAX_CHUNK * 2 + 3];
        let large_at = log.append(&large);
        assert_eq!(log.get(large_at, large.len()), Some(large.as_slice()));
        // Past what was logged reads nothing.
        assert_eq!(log.get(large_at, large.len() + 1), None);
    }

    #[test]
    fn a_place_survives_its_locator_word_and_a_stream_place_is_not_the_logs() {
        for place in [
            LogPlace::Kept(0),
            LogPlace::Kept((1 << 62) - 1),
            LogPlace::Container(0),
            LogPlace::Container(123_456),
            LogPlace::Stream(0),
            LogPlace::Stream(987_654_321),
        ] {
            assert_eq!(LogPlace::of(place.locator()), place);
        }
        // The log holds a copy of nothing at a stream place, and releasing one
        // touches no copy.
        let mut log = UnitLog::default();
        let copy = log.place(b"copied", None);
        assert_eq!(log.get(LogPlace::Stream(0), 4, Some(b"container")), None);
        log.release_through(LogPlace::Stream(0), 4);
        assert_eq!(log.get(copy, 6, None), Some(b"copied".as_slice()));
    }

    #[test]
    fn releasing_drops_whole_chunks_and_keeps_what_stands_after() {
        let mut log = ByteLog::default();
        let at: Vec<u64> = (0..4000u32).map(|n| log.append(&n.to_le_bytes())).collect();
        let before = log.allocated();
        log.release_before(at[3000]);
        assert!(
            log.allocated() < before,
            "released chunks give their memory back"
        );
        for (n, at) in at.iter().enumerate().skip(3000) {
            assert_eq!(log.get(*at, 4), Some((n as u32).to_le_bytes().as_slice()));
        }
        assert_eq!(log.get(at[0], 4), None, "a released run is not read");
        log.release_before(u64::MAX);
        assert_eq!(log.allocated(), 0);
        // The log goes on from where it was.
        let next = log.append(b"again");
        assert!(next > at[3999]);
        assert_eq!(log.get(next, 5), Some(b"again".as_slice()));
    }
}
