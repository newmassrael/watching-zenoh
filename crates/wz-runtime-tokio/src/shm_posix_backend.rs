// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The built-in shared-memory backend: a POOL in one POSIX segment (`transport-shm`),
//! many chunks out of it.
//!
//! Upstream's default backend is `PosixShmProviderBackend`, which is its talc backend
//! (`commons/zenoh-shm/src/api/protocol_implementations/posix/posix_shm_provider_backend.rs` @
//! `pub type PosixShmProviderBackend = PosixShmProviderBackendTalc;`): one
//! `{id}.zenoh` segment of the size the program asked for, claimed whole by a talc
//! allocator that carves chunks out of it. A chunk is named on the wire by the
//! segment's id and its own offset, so every chunk of a pool is a different offset into
//! one object a receiver maps once.
//!
//! # The allocator is upstream's, and that is a measurement
//!
//! This module first carved chunks with a free list of its own: first fit, neighbours
//! coalesced, nothing spent on headers. It was simpler and it was a different pool. A
//! program written against zenoh-c observes two facts that are the allocator's and not
//! the protocol's, and the real library was run to read them (a 4096-byte default
//! provider through the C ABI, allocating until refused):
//!
//! * **what a pool can hold.** Chunks of 1 and of 8 bytes both stop at 127, of 64 at
//!   42, of 512 at 5, of 1024 at 2 and of 2000 at 1; a chunk of 4096 never fits. Talc
//!   spends a header on every chunk and claims a part of its arena for its own bins, so
//!   about three quarters of the segment is usable.
//! * **the smallest pool that can be made.** A default provider of 1000 bytes or fewer
//!   is refused, and one of 4096 is made, because talc cannot claim an arena that small.
//!
//! A free list that held four 1024-byte chunks in 4096 bytes would have served a program
//! the real library refuses, and refused one it serves -- a pool created at 300 bytes --
//! so the difference was nameable and the atom could not be called complete with it.
//! Reusing the allocator removes the difference at its source instead of fitting a model
//! to the numbers: the same crate, claimed over the same bytes, called the same way
//! (`commons/zenoh-shm/src/api/protocol_implementations/posix/posix_shm_provider_backend_talc.rs` @
//! `talc.claim(slice::from_raw_parts_mut(ptr, real_size).into())`).
//!
//! Two answers that follow from it are kept as upstream gives them:
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

use std::alloc::Layout;
use std::io;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

use talc::{ErrOnOom, Talc};

use crate::posix_shm::{next_candidate_id, OwnedSegment};
use crate::shm_backend::{
    AllocAlignment, AllocError, AllocatedChunk, ChunkDescriptor, LayoutError, MemoryLayout,
    ProtocolId, PtrInSegment, ShmProviderBackend,
};

/// A pool's data segment, and the address it is mapped at.
///
/// The bytes are reached through the base pointer alone and never through a reference
/// to the whole mapping: chunks write disjoint ranges of it concurrently, and a
/// `&[u8]` over bytes another thread writes is a promise nothing keeps.
struct PoolSegment {
    segment: OwnedSegment,
}

// SAFETY: the mapping is owned by `segment` for the whole life of the value; the address
// is shared across threads only through the `Arc`, and every access to the bytes is
// through a chunk whose range the allocator handed out exactly once.
unsafe impl Send for PoolSegment {}
// SAFETY: as above.
unsafe impl Sync for PoolSegment {}

/// A pool backend: one POSIX segment claimed by one talc allocator, and the alignment
/// its layout was built with.
pub struct PosixShmProviderBackend {
    segment: Arc<PoolSegment>,
    talc: Mutex<Talc<ErrOnOom>>,
    alignment: AllocAlignment,
}

// SAFETY: the allocator is behind a mutex and manages only memory this value's segment
// owns; the raw pointers talc keeps internally point into that mapping, which `segment`
// keeps alive for as long as this value exists.
unsafe impl Send for PosixShmProviderBackend {}
// SAFETY: as above.
unsafe impl Sync for PosixShmProviderBackend {}

impl PosixShmProviderBackend {
    /// A pool of `layout.size()` bytes in a new `{id}.zenoh` segment, claimed whole by a
    /// talc allocator.
    ///
    /// Fails when the segment cannot be made AND when the allocator cannot claim it: a
    /// segment too small to hold talc's own bins is refused, as upstream's is.
    ///
    /// The layout's alignment is the alignment every chunk is freed at, as upstream's
    /// `free` uses the backend's, and what [`Self::layout_for`] extends a request to.
    pub fn new(layout: &MemoryLayout) -> io::Result<Self> {
        let size = layout.size().get();
        let segment = OwnedSegment::create(size, || u64::from(next_candidate_id()))?;
        let mut talc = Talc::new(ErrOnOom);
        // SAFETY: `base` is the start of a live mapping of exactly `len` bytes that this
        // function owns and nothing else has been handed a pointer into yet.
        let claimed = unsafe {
            talc.claim(std::slice::from_raw_parts_mut(segment.base(), segment.len()).into())
        };
        if claimed.is_err() {
            return Err(io::Error::other(format!(
                "a shared-memory pool of {size} bytes is too small for its allocator to claim"
            )));
        }
        Ok(Self {
            segment: Arc::new(PoolSegment { segment }),
            talc: Mutex::new(talc),
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

    fn talc(&self) -> std::sync::MutexGuard<'_, Talc<ErrOnOom>> {
        // A panic while the allocator was held can leave it mid-update; poisoning is
        // forwarded as a refusal by the callers' `OutOfMemory`, never as undefined use.
        self.talc.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ShmProviderBackend for PosixShmProviderBackend {
    fn id(&self) -> ProtocolId {
        crate::shm_provider::POSIX_PROTOCOL_ID
    }

    fn alloc(&self, layout: &MemoryLayout) -> Result<AllocatedChunk, AllocError> {
        let size = layout.size().get();
        let align = layout.alignment().value().get();
        let alloc_layout = Layout::from_size_align(size, align).map_err(|_| AllocError::Other)?;
        // SAFETY: the layout is valid, and the memory talc manages is this pool's segment.
        let buf =
            unsafe { self.talc().malloc(alloc_layout) }.map_err(|_| AllocError::OutOfMemory)?;
        let base = self.segment.segment.base() as usize;
        let offset = buf.as_ptr() as usize - base;
        // A header names a chunk by a `u32` offset; a larger pool's far chunks cannot be
        // named, so they are not handed out.
        let Ok(chunk) = u32::try_from(offset) else {
            // SAFETY: `buf` came from this allocator with this layout a line above.
            unsafe { self.talc().free(buf, alloc_layout) };
            return Err(AllocError::OutOfMemory);
        };
        let segment = u32::try_from(self.segment_id()).map_err(|_| AllocError::Other)?;
        Ok(AllocatedChunk {
            descriptor: ChunkDescriptor {
                segment,
                chunk,
                len: layout.size(),
            },
            data: PtrInSegment::new(buf.as_ptr(), self.segment.clone()),
        })
    }

    fn free(&self, chunk: &ChunkDescriptor) {
        // Freed at the BACKEND's alignment and the chunk's length, as upstream's `free`
        // does it.
        let Ok(layout) = Layout::from_size_align(chunk.len.get(), self.alignment.value().get())
        else {
            return;
        };
        // SAFETY: `chunk.chunk` is an offset `alloc` returned for a range of this segment.
        let ptr = unsafe { self.segment.segment.base().add(chunk.chunk as usize) };
        if let Some(ptr) = NonNull::new(ptr) {
            // SAFETY: the descriptor is the one `alloc` returned, so this is a live
            // allocation of this allocator with this length.
            unsafe { self.talc().free(ptr, layout) };
        }
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::posix_shm::segment_path;

    fn layout(size: usize) -> MemoryLayout {
        MemoryLayout::of_size(size).expect("a layout")
    }

    /// How many chunks of `chunk` bytes a pool of `pool` bytes serves before it refuses.
    fn how_many(pool: usize, chunk: usize) -> usize {
        let backend = PosixShmProviderBackend::new(&layout(pool)).expect("a pool");
        let mut held = Vec::new();
        while let Ok(c) = backend.alloc(&layout(chunk)) {
            held.push(c);
            assert!(held.len() < 100_000, "a pool never serves this many");
        }
        held.len()
    }

    /// WHAT A POOL CAN HOLD is upstream's, to the chunk: these are the counts the real
    /// library gave for a 4096-byte default provider, allocating until it refused. A pool
    /// that held four 1024-byte chunks here would be a different pool.
    #[test]
    fn a_pool_holds_what_the_real_library_holds() {
        for (chunk, fit) in [
            (1, 127),
            (8, 127),
            (64, 42),
            (100, 27),
            (512, 5),
            (1024, 2),
            (2000, 1),
            (2048, 1),
            (4096, 0),
        ] {
            assert_eq!(
                how_many(4096, chunk),
                fit,
                "a 4096-byte pool, chunks of {chunk} bytes"
            );
        }
    }

    /// THE SMALLEST POOL is upstream's: a default provider of 1000 bytes or fewer cannot be
    /// made, and one of 4096 and one of 5000 can.
    #[test]
    fn a_pool_too_small_for_its_allocator_is_refused() {
        for size in [1usize, 8, 64, 300, 1000] {
            assert!(
                PosixShmProviderBackend::new(&layout(size)).is_err(),
                "a pool of {size} bytes is refused by the real library"
            );
        }
        for size in [4096usize, 5000] {
            assert!(
                PosixShmProviderBackend::new(&layout(size)).is_ok(),
                "a pool of {size} bytes is made by the real library"
            );
        }
    }

    /// A refused pool leaves no segment behind: the segment it made is unlinked with the
    /// failed backend.
    #[test]
    fn a_refused_pool_unlinks_the_segment_it_made() {
        let before = std::fs::read_dir("/dev/shm")
            .map(|d| d.filter_map(Result::ok).count())
            .unwrap_or(0);
        for _ in 0..4 {
            assert!(PosixShmProviderBackend::new(&layout(300)).is_err());
        }
        let after = std::fs::read_dir("/dev/shm")
            .map(|d| d.filter_map(Result::ok).count())
            .unwrap_or(0);
        assert!(
            after <= before + 8,
            "four refused pools left {} extra objects in /dev/shm",
            after.saturating_sub(before)
        );
    }

    /// A pool is ONE segment: two chunks name the same segment id at different offsets,
    /// which is the property a receiver relies on to map it once.
    #[test]
    fn two_chunks_share_a_segment_at_different_offsets() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let a = backend.alloc(&layout(1024)).expect("first chunk");
        let b = backend.alloc(&layout(1024)).expect("second chunk");
        assert_eq!(a.descriptor.segment, b.descriptor.segment);
        assert_ne!(a.descriptor.chunk, b.descriptor.chunk);
        assert_eq!(a.descriptor.len.get(), 1024);
        // The addresses agree with the offsets.
        assert_eq!(
            b.data.ptr() as isize - a.data.ptr() as isize,
            b.descriptor.chunk as isize - a.descriptor.chunk as isize,
            "a chunk's address is the segment's base plus its offset"
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

    /// Two live chunks never overlap, and each keeps its own bytes.
    #[test]
    fn live_chunks_do_not_overlap() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let chunks: Vec<_> = (0..20u8)
            .map(|i| {
                let c = backend.alloc(&layout(64)).expect("chunk");
                // SAFETY: the chunk is 64 live bytes of this pool.
                unsafe { std::ptr::write_bytes(c.data.ptr(), i, 64) };
                c
            })
            .collect();
        for (i, c) in chunks.iter().enumerate() {
            // SAFETY: as above.
            let bytes = unsafe { std::slice::from_raw_parts(c.data.ptr(), 64) };
            assert!(
                bytes.iter().all(|&b| b == i as u8),
                "chunk {i} was overwritten by another"
            );
        }
    }

    /// A pool serves again what it took back: free a chunk and the same request is served.
    #[test]
    fn a_freed_chunk_is_served_again() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let first = backend.alloc(&layout(1024)).expect("a chunk");
        let _second = backend.alloc(&layout(1024)).expect("a second chunk");
        assert_eq!(
            backend.alloc(&layout(1024)).unwrap_err(),
            AllocError::OutOfMemory,
            "the pool is full"
        );
        backend.free(&first.descriptor);
        assert!(
            backend.alloc(&layout(1024)).is_ok(),
            "the freed room is served"
        );
    }

    /// An exhausted pool reports out of memory, never "defragment": upstream's backend has no
    /// such status. A fragmented one is the same.
    #[test]
    fn a_pool_reports_out_of_memory_never_a_defragment() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let a = backend.alloc(&layout(700)).unwrap();
        let _b = backend.alloc(&layout(700)).unwrap();
        let c = backend.alloc(&layout(700)).unwrap();
        backend.free(&a.descriptor);
        backend.free(&c.descriptor);
        assert_eq!(
            backend.alloc(&layout(2000)).unwrap_err(),
            AllocError::OutOfMemory,
            "room for it in total, in no single hole"
        );
        assert_eq!(
            backend.alloc(&layout(1_000_000)).unwrap_err(),
            AllocError::OutOfMemory
        );
    }

    /// A pool does not account: `available` and `defragment` read 0 however full it is.
    #[test]
    fn a_pool_does_not_account() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
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
        let backend =
            PosixShmProviderBackend::new(&MemoryLayout::new(4096, pool_alignment).unwrap())
                .expect("a pool");
        let served = backend.layout_for(layout(10)).unwrap();
        assert_eq!(served.size().get(), 16);
        assert_eq!(served.alignment(), pool_alignment);
    }

    /// The segment outlives the backend for as long as a chunk's pointer does, and is
    /// unlinked when the last goes.
    #[test]
    fn a_chunk_keeps_the_segment_alive_past_its_backend() {
        let backend = PosixShmProviderBackend::new(&layout(4096)).expect("a pool");
        let path = segment_path(backend.segment_id());
        let chunk = backend.alloc(&layout(8)).unwrap();
        drop(backend);
        assert!(path.exists(), "a chunk still points into the pool");
        // SAFETY: the chunk's pointer is into a live mapping of 4096 bytes.
        unsafe { chunk.data.ptr().write(0xAB) };
        drop(chunk);
        assert!(!path.exists(), "the last holder unlinked it");
    }
}
