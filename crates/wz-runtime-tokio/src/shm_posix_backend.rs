// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The built-in shared-memory backend: a POOL in one POSIX segment
//! (`transport-shm`), many chunks out of it.
//!
//! Upstream's default backend is `PosixShmProviderBackend`, which is its talc
//! backend (`commons/zenoh-shm/src/api/protocol_implementations/posix/posix_shm_provider_backend.rs` @
//! `pub type PosixShmProviderBackend = PosixShmProviderBackendTalc;`): one
//! `{id}.zenoh` segment of the size the program asked for, and an allocator that
//! carves chunks out of it. A chunk is named on the wire by the segment's id and its
//! own offset, so every chunk of a pool is a different offset into one object a
//! receiver maps once.
//!
//! # What this allocator is, and is not
//!
//! Upstream's allocator is `talc`, a general-purpose allocator that keeps its book-keeping
//! INSIDE the segment. This one keeps it outside, as a sorted list of free ranges:
//! first fit, with adjacent ranges coalesced when a chunk comes home. That changes two
//! things a program could observe and neither is a wire fact. A receiver sees only a
//! segment id, an offset and a length, which are the same. A program sees how much of a
//! pool is usable: talc spends bytes of the segment on its own headers and this does not,
//! so a pool of exactly the size of one chunk serves that chunk (upstream's own
//! `z_get_shm.c` builds its provider that way and depends on it, and the chunk must
//! therefore carry no overhead of its own).
//!
//! Two answers are upstream's and are kept rather than improved on:
//!
//! * `available` and `defragment` both answer 0. Talc does not account, and
//!   `z_shm_provider_available` through the real library reads 0 on a default provider.
//! * An allocation that cannot be served is [`AllocError::OutOfMemory`], whether the pool
//!   is full or only fragmented. Talc is configured to fail on out-of-memory and has no
//!   notion of "defragment first", so [`AllocError::NeedDefragment`] is a status only a
//!   backend a host supplies can return.
//!
//! # Lifetime
//!
//! The segment is held by an `Arc` that every chunk's [`PtrInSegment`] also holds, so a
//! chunk that outlives the backend still points at live memory, and the segment is
//! unlinked when the last of them goes. Whether a chunk is returned to the pool is
//! the PROVIDER's decision (it waits for every holder to let go), and the backend does
//! only what it is told.

use std::io;
use std::sync::{Arc, Mutex};

use crate::posix_shm::{next_candidate_id, OwnedSegment};
use crate::shm_backend::{
    AllocAlignment, AllocError, AllocatedChunk, ChunkDescriptor, LayoutError, MemoryLayout,
    ProtocolId, PtrInSegment, ShmProviderBackend,
};

/// One free range of a pool, as `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreeRange {
    start: usize,
    end: usize,
}

/// A pool's book-keeping: its free ranges.
///
/// Kept SORTED by `start` and never overlapping. Sorted is what makes coalescing a
/// linear scan instead of a search, and it is an invariant [`Self::release`] restores
/// on every free.
#[derive(Debug)]
pub(crate) struct SegmentBooks {
    free: Vec<FreeRange>,
}

impl SegmentBooks {
    /// A pool of `len` bytes, all free.
    pub(crate) fn new(len: usize) -> Self {
        Self {
            free: if len == 0 {
                Vec::new()
            } else {
                vec![FreeRange { start: 0, end: len }]
            },
        }
    }

    /// First fit. The offset of a `len`-byte range aligned to `align`, or `None`.
    ///
    /// First fit rather than best fit deliberately: a program that sizes its pool to
    /// EXACTLY the payload it will allocate needs "a request for the whole segment
    /// succeeds", which first fit gives and any strategy that reserves header bytes
    /// does not.
    pub(crate) fn claim(&mut self, len: usize, align: usize) -> Option<usize> {
        for (i, range) in self.free.iter().enumerate() {
            let start = range.start.next_multiple_of(align);
            let Some(end) = start.checked_add(len) else {
                continue;
            };
            if end > range.end {
                continue;
            }
            let (was_start, was_end) = (range.start, range.end);
            self.free.remove(i);
            // The alignment gap before the chunk and the remainder after it are both
            // still free; re-inserting them keeps the list sorted because they sit
            // where the removed range was.
            let mut insert = i;
            if start > was_start {
                self.free.insert(
                    insert,
                    FreeRange {
                        start: was_start,
                        end: start,
                    },
                );
                insert += 1;
            }
            if end < was_end {
                self.free.insert(
                    insert,
                    FreeRange {
                        start: end,
                        end: was_end,
                    },
                );
            }
            return Some(start);
        }
        None
    }

    /// Return `[start, end)` to the free list, coalescing with its neighbours.
    pub(crate) fn release(&mut self, start: usize, end: usize) {
        let at = self.free.partition_point(|r| r.start < start);
        self.free.insert(at, FreeRange { start, end });
        // Coalesce forwards from the predecessor, so a release that bridges two free
        // ranges merges all three in one pass.
        let mut i = at.saturating_sub(1);
        while i + 1 < self.free.len() {
            if self.free[i].end == self.free[i + 1].start {
                self.free[i].end = self.free[i + 1].end;
                self.free.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Total free bytes.
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.free.iter().map(|r| r.end - r.start).sum()
    }

    /// The largest single free range.
    #[cfg(test)]
    pub(crate) fn largest(&self) -> usize {
        self.free.iter().map(|r| r.end - r.start).max().unwrap_or(0)
    }
}

/// A pool's data segment, and the address it is mapped at.
///
/// The bytes are reached through the base pointer alone and never through a reference
/// to the whole mapping: chunks write disjoint ranges of it concurrently, and a
/// `&[u8]` over bytes another thread writes is a promise nothing keeps.
struct PoolSegment {
    segment: OwnedSegment,
}

/// A pool backend: one POSIX segment, a free list over it, and the alignment its layout
/// was built with.
pub struct PosixShmProviderBackend {
    segment: Arc<PoolSegment>,
    books: Mutex<SegmentBooks>,
    alignment: AllocAlignment,
}

impl PosixShmProviderBackend {
    /// A pool of `layout.size()` bytes in a new `{id}.zenoh` segment.
    ///
    /// The layout's alignment is the alignment every chunk is rounded to when it is
    /// freed, as upstream's `free` uses the backend's, and what [`Self::layout_for`] extends
    /// a request to.
    pub fn new(layout: &MemoryLayout) -> io::Result<Self> {
        let size = layout.size().get();
        let segment = OwnedSegment::create(size, || u64::from(next_candidate_id()))?;
        Ok(Self {
            segment: Arc::new(PoolSegment { segment }),
            books: Mutex::new(SegmentBooks::new(size)),
            alignment: layout.alignment(),
        })
    }

    /// The id of the segment the pool lives in: the number a chunk's header names.
    pub fn segment_id(&self) -> u64 {
        self.segment.segment.id()
    }

    /// The pool's size in bytes.
    pub fn capacity(&self) -> usize {
        self.segment.segment.len()
    }

    fn books(&self) -> std::sync::MutexGuard<'_, SegmentBooks> {
        // A panic while the books were held cannot leave the list torn: every mutation is
        // one statement sequence with no `?` in it.
        self.books.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ShmProviderBackend for PosixShmProviderBackend {
    fn id(&self) -> ProtocolId {
        crate::shm_provider::POSIX_PROTOCOL_ID
    }

    fn alloc(&self, layout: &MemoryLayout) -> Result<AllocatedChunk, AllocError> {
        let size = layout.size().get();
        let align = layout.alignment().value().get();
        let start = self
            .books()
            .claim(size, align)
            .ok_or(AllocError::OutOfMemory)?;
        // The pool is at most `u32::MAX` bytes addressable by a header's chunk field. A larger
        // pool is a pool whose far chunks a header cannot name, so they are not handed out.
        let Ok(chunk) = u32::try_from(start) else {
            self.books().release(start, start + size);
            return Err(AllocError::OutOfMemory);
        };
        let segment = u32::try_from(self.segment_id()).map_err(|_| AllocError::Other)?;
        // SAFETY: `start + size` lies inside the mapping, because `claim` only hands out a
        // range of the free list and the free list only ever holds ranges of `[0, capacity)`.
        let ptr = unsafe { self.segment.segment.base().add(start) };
        Ok(AllocatedChunk {
            descriptor: ChunkDescriptor {
                segment,
                chunk,
                len: layout.size(),
            },
            data: PtrInSegment::new(ptr, self.segment.clone()),
        })
    }

    fn free(&self, chunk: &ChunkDescriptor) {
        // The descriptor is the one `alloc` returned, so its length is the size that was
        // claimed (the provider allocates by `layout_for`'s layout, already extended).
        let start = chunk.chunk as usize;
        self.books().release(start, start + chunk.len.get());
    }

    fn defragment(&self) -> usize {
        0
    }

    fn available(&self) -> usize {
        0
    }

    fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, LayoutError> {
        layout.extend(self.alignment)
    }
}

// SAFETY: the mapping is owned by `segment` for the whole life of the value; the address
// is shared across threads only through the `Arc`, and every access to the bytes is
// through a chunk whose range the allocator handed out exactly once.
unsafe impl Send for PoolSegment {}
// SAFETY: as above.
unsafe impl Sync for PoolSegment {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::posix_shm::segment_path;

    fn layout(size: usize) -> MemoryLayout {
        MemoryLayout::of_size(size).expect("a layout")
    }

    /// Two ranges out of a pool do not overlap and the second starts where the first
    /// ends: the books hand out disjoint ranges, which is what lets two chunks be written
    /// at once.
    #[test]
    fn claims_are_disjoint_and_adjacent() {
        let mut books = SegmentBooks::new(4096);
        let a = books.claim(1024, 1).unwrap();
        let b = books.claim(1024, 1).unwrap();
        assert_eq!((a, b), (0, 1024));
        assert_eq!(books.available(), 2048);
    }

    /// A request for the whole pool is served: first fit reserves nothing for itself.
    #[test]
    fn the_whole_pool_is_one_chunk() {
        let mut books = SegmentBooks::new(37);
        assert_eq!(books.claim(37, 1), Some(0));
        assert_eq!(books.claim(1, 1), None);
    }

    /// An aligned claim lands on a multiple of the alignment and leaves the gap before
    /// it free.
    #[test]
    fn an_aligned_claim_leaves_its_gap_free() {
        let mut books = SegmentBooks::new(256);
        assert_eq!(books.claim(3, 1), Some(0));
        let at = books.claim(16, 64).unwrap();
        assert_eq!(at, 64);
        assert_eq!(books.available(), 256 - 3 - 16);
        // The gap is usable.
        assert_eq!(books.claim(61, 1), Some(3));
    }

    /// Releasing a chunk that bridges two free ranges merges all three.
    #[test]
    fn a_release_coalesces_with_both_neighbours() {
        let mut books = SegmentBooks::new(300);
        let a = books.claim(100, 1).unwrap();
        let b = books.claim(100, 1).unwrap();
        let c = books.claim(100, 1).unwrap();
        books.release(a, a + 100);
        books.release(c, c + 100);
        assert_eq!(books.largest(), 100, "two separate holes");
        books.release(b, b + 100);
        assert_eq!(books.largest(), 300, "the middle one joined them");
    }

    /// A pool is ONE segment: two chunks name the same segment id at different
    /// offsets, which is the property a receiver relies on to map it once.
    #[test]
    fn two_chunks_share_a_segment_at_different_offsets() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let a = backend.alloc(&layout(1024)).expect("first chunk");
        let b = backend.alloc(&layout(1024)).expect("second chunk");
        assert_eq!(a.descriptor.segment, b.descriptor.segment);
        assert_eq!(a.descriptor.chunk, 0);
        assert_eq!(b.descriptor.chunk, 1024);
        assert_eq!(a.descriptor.len.get(), 1024);
        // The addresses agree with the offsets.
        assert_eq!(
            b.data.ptr() as usize - a.data.ptr() as usize,
            1024,
            "the second chunk's address is the first's plus its offset"
        );
        assert!(segment_path(backend.segment_id()).exists());
        assert_eq!(
            std::fs::metadata(segment_path(backend.segment_id()))
                .unwrap()
                .len(),
            4096,
            "the segment is the size of the pool and not of a chunk"
        );
    }

    /// A pool of exactly one chunk serves that chunk, and then reports out of memory,
    /// not "defragment": upstream's backend has no such status.
    #[test]
    fn an_exhausted_pool_reports_out_of_memory_never_a_defragment() {
        let backend = PosixShmProviderBackend::new(&layout(64)).expect("a pool");
        let only = backend.alloc(&layout(64)).expect("the whole pool");
        assert_eq!(
            backend.alloc(&layout(1)).unwrap_err(),
            AllocError::OutOfMemory
        );
        backend.free(&only.descriptor);
        assert!(backend.alloc(&layout(64)).is_ok(), "freed, so served again");
    }

    /// A fragmented pool that holds enough bytes in total but no hole big enough is out of
    /// memory too: talc cannot say anything else.
    #[test]
    fn a_fragmented_pool_is_out_of_memory_not_a_defragment() {
        let backend = PosixShmProviderBackend::new(&layout(300)).expect("a pool");
        let a = backend.alloc(&layout(100)).unwrap();
        let _b = backend.alloc(&layout(100)).unwrap();
        let c = backend.alloc(&layout(100)).unwrap();
        backend.free(&a.descriptor);
        backend.free(&c.descriptor);
        assert_eq!(
            backend.alloc(&layout(150)).unwrap_err(),
            AllocError::OutOfMemory,
            "200 bytes are free but in two holes of 100"
        );
    }

    /// A pool does not account: `available` and `defragment` read 0 however full it is.
    #[test]
    fn a_pool_does_not_account() {
        let backend = PosixShmProviderBackend::new(&layout(128)).expect("a pool");
        assert_eq!(backend.available(), 0);
        assert_eq!(backend.defragment(), 0);
        let _chunk = backend.alloc(&layout(32)).unwrap();
        assert_eq!(backend.available(), 0);
    }

    /// A chunk is aligned in MEMORY and not only in its offset, because the segment is
    /// page aligned: the address a caller is handed meets the alignment it asked for.
    #[test]
    fn a_chunk_is_aligned_in_memory() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let _first = backend.alloc(&layout(3)).unwrap();
        let aligned = AllocAlignment::new(6).unwrap();
        let chunk = backend
            .alloc(&MemoryLayout::new(64, aligned).unwrap())
            .unwrap();
        assert_eq!(chunk.data.ptr() as usize % 64, 0);
        assert_eq!(chunk.descriptor.chunk % 64, 0);
    }

    /// The layout a pool serves is the request extended to the alignment the pool was
    /// built with.
    #[test]
    fn the_layout_a_pool_serves_is_extended_to_its_alignment() {
        let pool_alignment = AllocAlignment::ALIGN_8_BYTES;
        let backend = PosixShmProviderBackend::new(&MemoryLayout::new(64, pool_alignment).unwrap())
            .expect("a pool");
        let served = backend.layout_for(layout(10)).unwrap();
        assert_eq!(served.size().get(), 16);
        assert_eq!(served.alignment(), pool_alignment);
    }

    /// The segment outlives the backend for as long as a chunk's pointer does, and is
    /// unlinked when the last goes.
    #[test]
    fn a_chunk_keeps_the_segment_alive_past_its_backend() {
        let backend = PosixShmProviderBackend::new(&layout(64)).expect("a pool");
        let path = segment_path(backend.segment_id());
        let chunk = backend.alloc(&layout(8)).unwrap();
        drop(backend);
        assert!(path.exists(), "a chunk still points into the pool");
        // SAFETY: the chunk's pointer is into a live mapping of 64 bytes.
        unsafe { chunk.data.ptr().write(0xAB) };
        drop(chunk);
        assert!(!path.exists(), "the last holder unlinked it");
    }
}
