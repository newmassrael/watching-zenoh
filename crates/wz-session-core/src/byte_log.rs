// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An append-only log of byte runs, each read back whole by the position it was
//! logged at, and released from the front.
//!
//! Open-debt item 924 (`docs/dissect-row-index.md`, D8): the unit log a list of
//! datagrams reads its units' bytes from once it keeps them as index entries.

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
pub(crate) struct ByteLog {
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
    pub(crate) fn append(&mut self, run: &[u8]) -> u64 {
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
    pub(crate) fn get(&self, at: u64, len: usize) -> Option<&[u8]> {
        let k = self.chunks.partition_point(|c| c.end() <= at);
        let chunk = self.chunks.get(k)?;
        let from = usize::try_from(at.checked_sub(chunk.at)?).ok()?;
        chunk.bytes.get(from..from.checked_add(len)?)
    }

    /// Release every chunk whose logged bytes all stand before position `at`:
    /// what a holder calls once nothing reads those bytes any more. A run logged
    /// after the last chunk is released starts a chunk of its own, past every
    /// position ever handed out, so no position is handed out twice.
    pub(crate) fn release_before(&mut self, at: u64) {
        while self
            .chunks
            .front()
            .is_some_and(|c| c.at + c.bytes.len() as u64 <= at)
        {
            let _ = self.chunks.pop_front();
        }
    }

    /// Bytes the log holds allocated, logged or not.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.chunks.iter().map(|c| c.bytes.capacity()).sum()
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
