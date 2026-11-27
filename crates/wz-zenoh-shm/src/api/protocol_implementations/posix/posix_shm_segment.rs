//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.2, file
// src/api/protocol_implementations/posix/posix_shm_segment.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{num::NonZeroUsize, ptr::NonNull, sync::Arc};

use zenoh_result::{bail, ZResult};

use crate::{
    api::{
        client::shm_segment::ShmSegment,
        common::types::{ChunkID, PtrInSegment, SegmentID},
        provider::{
            chunk::{AllocatedChunk, ChunkDescriptor},
            memory_layout::MemoryLayout,
        },
    },
    posix_shm::array::ArrayInSHM,
};

#[derive(Debug)]
pub(crate) struct PosixShmSegment {
    pub(crate) segment: ArrayInSHM<SegmentID, u8, ChunkID>,
}

impl PosixShmSegment {
    pub(crate) fn create(alloc_size: NonZeroUsize) -> ZResult<Self> {
        let segment = ArrayInSHM::create(alloc_size)?;
        Ok(Self { segment })
    }

    pub(crate) fn open(id: SegmentID) -> ZResult<Self> {
        let segment = ArrayInSHM::open(id)?;
        Ok(Self { segment })
    }

    pub(crate) fn allocated_chunk(
        self: Arc<Self>,
        buf: NonNull<u8>,
        layout: &MemoryLayout,
    ) -> AllocatedChunk {
        AllocatedChunk {
            descriptor: ChunkDescriptor::new(
                self.segment.id(),
                // SAFETY: buf is guaranteed to belong to the segment.
                unsafe { self.segment.index(buf.as_ptr()) },
                layout.size(),
            ),
            data: PtrInSegment::new(buf.as_ptr(), self),
        }
    }
}

impl PosixShmSegment {
    /// Whether `chunk` lies in this segment as its descriptor says: it names this segment, its
    /// bytes are inside it, and its address is the segment's at the offset it names.
    pub(crate) fn owns(&self, chunk: &AllocatedChunk) -> bool {
        let descriptor = &chunk.descriptor;
        let inside = usize::try_from(descriptor.chunk)
            .ok()
            .and_then(|offset| offset.checked_add(descriptor.len.get()))
            .is_some_and(|end| end <= self.segment.elem_count().get());
        if !inside || descriptor.segment != self.segment.id() {
            return false;
        }
        // SAFETY: the chunk was checked to lie inside the segment just above.
        let address = unsafe { self.segment.elem_mut(descriptor.chunk) };
        address.cast_const() == chunk.data.ptr()
    }
}

impl ShmSegment for PosixShmSegment {
    fn map(&self, chunk: ChunkID) -> ZResult<*mut u8> {
        // The chunk comes out of a descriptor that another process wrote, so it is checked against
        // the segment: the original takes the address at any chunk of 32 bits, which is past the
        // end of the mapping from the size of the segment on.
        if usize::try_from(chunk).map_or(true, |c| c >= self.segment.elem_count().get()) {
            bail!(
                "Chunk {} is out of range for the segment of {} bytes",
                chunk,
                self.segment.elem_count()
            );
        }
        // SAFETY: the chunk is within the segment, as checked above.
        Ok(unsafe { self.segment.elem_mut(chunk) })
    }
}
