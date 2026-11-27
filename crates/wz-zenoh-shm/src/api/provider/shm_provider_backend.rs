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
// src/api/provider/shm_provider_backend.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use super::{
    chunk::{AllocatedChunk, ChunkDescriptor},
    types::{ChunkAllocResult, ZLayoutError},
};
use crate::api::{common::with_id::WithProtocolID, provider::memory_layout::MemoryLayout};

/// The provider backend trait
///
/// Implement this interface to create a Zenoh-compatible shared memory provider
#[zenoh_macros::unstable_doc]
pub trait ShmProviderBackend: WithProtocolID {
    /// Allocate the chunk of desired size.
    ///
    /// If successful, the result's chunk size will be >= len
    #[zenoh_macros::unstable_doc]
    fn alloc(&self, layout: &MemoryLayout) -> ChunkAllocResult;

    /// Deallocate the chunk.
    ///
    /// It is guaranteed that chunk's descriptor will correspond to the one returned from alloc(...)
    #[zenoh_macros::unstable_doc]
    fn free(&self, chunk: &ChunkDescriptor);

    /// Defragment the memory.
    ///
    /// Should return the size of largest defragmented chunk
    #[zenoh_macros::unstable_doc]
    fn defragment(&self) -> usize;

    /// Bytes available for use
    #[zenoh_macros::unstable_doc]
    fn available(&self) -> usize;

    /// Check and calculate suitable layout for layout.
    ///
    /// Depending on the implementation, backend may relayout allocations for bigger layouts.
    /// This method is used to:
    /// - validate, if the provided layout can be used with this backend
    /// - adopt the layout for backend capabilities
    #[zenoh_macros::unstable_doc]
    fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, ZLayoutError>;

    /// Whether `chunk`, handed to [`ShmProvider::map`](crate::api::provider::shm_provider::ShmProvider::map),
    /// is one this backend could have issued, so that freeing it later is sound. A backend that
    /// owns its memory (a pool knows its own segment) refuses what it cannot own; the default
    /// accepts, for a backend whose memory is its host's and whose `free` is the host's to get
    /// right. Hidden from the documentation: the original's trait has no such method.
    #[doc(hidden)]
    fn accepts(&self, _chunk: &AllocatedChunk) -> bool {
        true
    }
}

/// A backend behind a box is the backend in it: what lets one provider type hold backends of
/// several kinds (`ShmProvider<Box<dyn ShmProviderBackend + Send + Sync>>`), as a C ABI that hands
/// out providers over the built-in pool and over a C program's callbacks does, compiling the
/// provider's allocation paths once rather than once per backend. Hidden from the documentation:
/// the original's trait has no such implementation.
#[doc(hidden)]
impl<T: ShmProviderBackend + ?Sized> ShmProviderBackend for Box<T> {
    fn alloc(&self, layout: &MemoryLayout) -> ChunkAllocResult {
        (**self).alloc(layout)
    }

    fn free(&self, chunk: &ChunkDescriptor) {
        (**self).free(chunk)
    }

    fn defragment(&self) -> usize {
        (**self).defragment()
    }

    fn available(&self) -> usize {
        (**self).available()
    }

    fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, ZLayoutError> {
        (**self).layout_for(layout)
    }

    fn accepts(&self, chunk: &AllocatedChunk) -> bool {
        (**self).accepts(chunk)
    }
}
