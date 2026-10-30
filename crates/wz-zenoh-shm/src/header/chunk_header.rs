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
// src/header/chunk_header.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use crate::api::provider::chunk::ChunkDescriptor;

// Chunk header
#[stabby::stabby]
#[derive(Debug)]
pub struct ChunkHeaderType {
    /*
    NOTE (debt-910): We don't really need 32 bits here, but access to 16-bit fields with 1 byte alignment is less performant on most of the platforms.
    We need to bench and select reasonable integer sizes here once we have an implementation to bench
    */
    pub refcount: AtomicU32,
    pub watchdog_invalidated: AtomicBool,
    pub generation: AtomicU32,

    /// Protocol identifier for particular SHM implementation
    pub protocol: AtomicU32,

    /// The data chunk descriptor
    segment: AtomicU32,
    chunk: AtomicU32,
    len: AtomicUsize,
}

// SAFETY: all fields are atomic types which are Send and Sync
// This prevents the Rust trait solver to out of recursion budget
unsafe impl Send for ChunkHeaderType {}
unsafe impl Sync for ChunkHeaderType {}

impl ChunkHeaderType {
    pub fn len(&self) -> NonZeroUsize {
        // The length is written only by `set_data_descriptor`, so a header that was never given a
        // data descriptor still holds zero, which is not a `NonZeroUsize`: the original builds one
        // out of it without a check (undefined behaviour, and a panic in a build with debug
        // assertions). A header like that can be reached from another process by a descriptor
        // naming it; it reads here as a length of one byte, and what the caller does with the
        // descriptor of such a header is then decided by the segment that descriptor names.
        NonZeroUsize::new(self.len.load(Ordering::Relaxed)).unwrap_or(NonZeroUsize::MIN)
    }

    pub fn set_data_descriptor(&self, descriptor: &ChunkDescriptor) {
        self.segment.store(descriptor.segment, Ordering::Relaxed);
        self.chunk.store(descriptor.chunk, Ordering::Relaxed);
        self.len.store(descriptor.len.into(), Ordering::Relaxed);
    }

    pub fn data_descriptor(&self) -> ChunkDescriptor {
        ChunkDescriptor::new(
            self.segment.load(Ordering::Relaxed),
            self.chunk.load(Ordering::Relaxed),
            self.len(),
        )
    }
}
