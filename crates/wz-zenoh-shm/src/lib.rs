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
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)

#[macro_export]
macro_rules! tested_module {
    ($module:ident) => {
        #[cfg(feature = "test")]
        pub mod $module;
        #[cfg(not(feature = "test"))]
        mod $module;
    };
}

#[macro_export]
macro_rules! tested_crate_module {
    ($module:ident) => {
        #[cfg(feature = "test")]
        pub mod $module;
        #[cfg(not(feature = "test"))]
        pub(crate) mod $module;
    };
}

use std::{
    any::Any,
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering},
};

use api::{
    buffer::{
        traits::BufferRelayoutError,
        zshm::{zshm, ZShm},
        zshmmut::{zshmmut, ZShmMut},
    },
    common::types::{ChunkID, ProtocolID, SegmentID},
    provider::memory_layout::MemoryLayout,
};
use metadata::{descriptor::MetadataDescriptor, subscription::GLOBAL_METADATA_SUBSCRIPTION};
use watchdog::confirmator::{ConfirmedDescriptor, GLOBAL_CONFIRMATOR};
use zenoh_buffers::ZSliceBuffer;
use zenoh_result::{bail, ZResult};

use crate::api::common::types::PtrInSegment;

pub mod api;
mod cleanup;
pub mod header;
pub mod init;
pub mod metadata;
pub mod posix_shm;
pub mod reader;
mod segment_cache;
pub mod shm;
pub mod version;
pub mod watchdog;

/// Information about a [`ShmBufInner`].
///
/// This that can be serialized and can be used to retrieve the [`ShmBufInner`] in a remote process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmBufInfo {
    /// Actual data length
    /// NOTE: data descriptor's len is >= of this len and describes the actual memory length
    /// dedicated in shared memory segment for this particular buffer.
    pub data_len: NonZeroUsize,

    /// Metadata descriptor
    pub metadata: MetadataDescriptor,
    /// Generation of the buffer
    pub generation: u32,
}

impl ShmBufInfo {
    pub fn new(
        data_len: NonZeroUsize,
        metadata: MetadataDescriptor,
        generation: u32,
    ) -> ShmBufInfo {
        ShmBufInfo {
            data_len,
            metadata,
            generation,
        }
    }
}

/// A hard shared reference to SHM buffer
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct ShmBufHardRef(ConfirmedDescriptor);

impl ShmBufHardRef {
    /// The hard reference of the buffer `info` names, for the transport of the crates of this
    /// repository, which keeps a chunk it sent confirmed until its receiver acknowledges it and
    /// knows the chunk by the descriptor it put on the wire, not by a buffer. Refused when the
    /// header is of another generation: the slot then holds another buffer, whose watchdog is not
    /// this sender's to keep up. Hidden from the documentation for the reason
    /// `ShmBufInner::release_reference` is.
    #[doc(hidden)]
    pub fn of_info(info: &ShmBufInfo) -> ZResult<Self> {
        let metadata = GLOBAL_METADATA_SUBSCRIPTION.read().link(&info.metadata)?;
        if metadata.header().generation.load(Ordering::SeqCst) != info.generation {
            bail!("Buffer is invalidated");
        }
        Ok(Self(GLOBAL_CONFIRMATOR.read().add(metadata)))
    }
}

/// What the header of a metadata slot says, read without holding the slot: how many references
/// are outstanding, which buffer the slot holds now, and whether its watchdog gave up on it.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderState {
    /// The references outstanding: the owner's and one per receiver not yet let go.
    pub refcount: u32,
    /// The generation of the buffer the slot holds now; it moves on when the slot is reclaimed.
    pub generation: u32,
    /// Whether the validator found the slot unconfirmed for a whole window.
    pub invalidated: bool,
    /// The data segment the slot's chunk lies in.
    pub segment: SegmentID,
    /// The chunk's offset in that segment.
    pub chunk: ChunkID,
}

/// The header of the slot `descriptor` names, read through the subscription of the process and
/// confirming nothing, so that reading it changes nothing the protocol counts. For the crates of
/// this repository, which keep a provider until the last receiver of its buffers has let go and
/// read another process's bookkeeping in their tests; hidden from the documentation for the
/// reason `ShmBufInner::release_reference` is.
#[doc(hidden)]
pub fn header_state(descriptor: &MetadataDescriptor) -> ZResult<HeaderState> {
    let metadata = GLOBAL_METADATA_SUBSCRIPTION.read().link(descriptor)?;
    let header = metadata.header();
    let data = header.data_descriptor();
    Ok(HeaderState {
        refcount: header.refcount.load(Ordering::SeqCst),
        generation: header.generation.load(Ordering::SeqCst),
        invalidated: header.watchdog_invalidated.load(Ordering::SeqCst),
        segment: data.segment,
        chunk: data.chunk,
    })
}

impl From<&ShmBufInner> for ShmBufHardRef {
    fn from(value: &ShmBufInner) -> Self {
        Self(value.metadata.clone())
    }
}
impl From<&ZShm> for ShmBufHardRef {
    fn from(value: &ZShm) -> Self {
        (&value.inner).into()
    }
}
impl From<&zshm> for ShmBufHardRef {
    fn from(value: &zshm) -> Self {
        (&value.inner).into()
    }
}
impl From<&ZShmMut> for ShmBufHardRef {
    fn from(value: &ZShmMut) -> Self {
        (&value.inner).into()
    }
}
impl From<&zshmmut> for ShmBufHardRef {
    fn from(value: &zshmmut) -> Self {
        (&value.inner).into()
    }
}

/// A zenoh buffer in shared memory.
pub struct ShmBufInner {
    pub(crate) metadata: ConfirmedDescriptor,
    pub(crate) buf: PtrInSegment,
    pub info: ShmBufInfo,
}

impl PartialEq for ShmBufInner {
    fn eq(&self, other: &Self) -> bool {
        // currently there is no API to resize an SHM buffer, but it is intended in the future,
        // so I add size comparison here to avoid future bugs :)
        self.buf == other.buf && self.info.data_len == other.info.data_len
    }
}
impl Eq for ShmBufInner {}

impl std::fmt::Debug for ShmBufInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShmBufInner")
            .field("metadata", &self.metadata)
            .field("buf", &self.buf)
            .field("info", &self.info)
            .finish()
    }
}

impl ShmBufInner {
    pub fn protocol(&self) -> ProtocolID {
        self.metadata
            .owned
            .header()
            .protocol
            .load(Ordering::Relaxed)
    }

    /// # Safety
    /// This operation is unsafe because we cannot guarantee that there is no upper level
    /// ZSlice that have cached the size of underlying ShmBufInner. So this function should be
    /// used only if it is guaranteed that there is no such situation
    pub unsafe fn try_resize(&mut self, new_size: NonZeroUsize) -> Option<()> {
        if self.capacity() < new_size {
            return None;
        }

        self.info.data_len = new_size;

        Some(())
    }

    /// # Safety
    /// This operation is unsafe because we cannot guarantee that there is no upper level
    /// ZSlice that have cached the size of underlying ShmBufInner. So this function should be
    /// used only if it is guaranteed that there is no such situation
    pub unsafe fn try_relayout(
        &mut self,
        new_layout: MemoryLayout,
    ) -> Result<(), BufferRelayoutError> {
        let address = self.as_ref().as_ptr() as usize;
        if address % new_layout.alignment().get_alignment_value().get() != 0 {
            return Err(BufferRelayoutError::IncompatibleAlignment);
        }

        if self.capacity() < new_layout.size() {
            return Err(BufferRelayoutError::SizeTooBig);
        }

        self.info.data_len = new_layout.size();

        Ok(())
    }

    pub fn len(&self) -> NonZeroUsize {
        self.info.data_len
    }

    pub fn capacity(&self) -> NonZeroUsize {
        self.metadata.owned.header().len()
    }

    fn is_valid(&self) -> bool {
        let header = self.metadata.owned.header();

        !header.watchdog_invalidated.load(Ordering::SeqCst)
            && header.generation.load(Ordering::SeqCst) == self.info.generation
    }

    fn is_unique(&self) -> bool {
        self.ref_count() == 1
    }

    pub fn ref_count(&self) -> u32 {
        self.metadata.owned.header().refcount.load(Ordering::SeqCst)
    }

    /// Whether a holder of this buffer may convert it to a mutable one: upstream's condition for
    /// `TryFrom<&mut zshm> for &mut zshmmut`, asked by the transport of the crates of this
    /// repository, which hands a received buffer to a C program as a chunk the program may write
    /// once it is the only holder. Hidden from the documentation for the reason
    /// `release_reference` is.
    #[doc(hidden)]
    pub fn is_writable(&self) -> bool {
        self.is_unique() && self.is_valid()
    }

    /// The address of the first byte of the buffer, through which it may be written while
    /// `is_writable` holds. Valid for as long as the buffer lives. Hidden from the documentation
    /// for the reason `release_reference` is.
    #[doc(hidden)]
    pub fn data_ptr(&self) -> *mut u8 {
        self.buf.ptr().cast_mut()
    }

    /// Increments buffer's reference count
    ///
    /// # Safety
    /// You should understand what you are doing, as overestimation
    /// of the reference counter can lead to memory being stalled until
    /// recovered by watchdog subsystem or forcibly deallocated
    pub unsafe fn inc_ref_count(&self) {
        self.metadata
            .owned
            .header()
            .refcount
            .fetch_add(1, Ordering::SeqCst);
    }

    // PRIVATE:
    /// The length a slice of this buffer may have: the length in `info`, which is a public field a
    /// caller can set to anything, held to the capacity the header of the buffer says the memory
    /// has (the original builds the slice of whatever length `info` holds).
    fn readable_len(&self) -> usize {
        self.info.data_len.min(self.capacity()).get()
    }

    fn as_slice(&self) -> &[u8] {
        tracing::trace!("ShmBufInner::as_slice() == len = {:?}", self.info.data_len);
        // SAFETY: The pointer is valid during the lifetime of `ShmBufInner`, and the length is held
        // to the capacity of the chunk.
        unsafe { std::slice::from_raw_parts(self.buf.ptr(), self.readable_len()) }
    }

    /// Decrements buffer's reference count
    ///
    /// # Safety
    /// You should understand what you are doing, as underestimation
    /// of the reference counter can lead to memory being stalled or double-freed.
    unsafe fn dec_ref_count(&self) {
        release_one_reference(&self.metadata.owned.header().refcount);
    }

    /// Gives back the reference [`Self::inc_ref_count`] took, for the transport of the crate that
    /// sends a buffer: it takes a reference for the receiver before the descriptor is built and
    /// returns it with this when the frame is not sent, which a clone of the buffer cannot do (a
    /// clone also holds the buffer's confirmation of its memory, which the receiver's reference
    /// does not).
    ///
    /// Upstream's `dec_ref_count` is private, and this crate's surface is held to upstream's, so
    /// the way in is hidden from the documentation, which is what the surface is read from: it is
    /// there for the crates of this repository and is no part of the API a user replaces.
    ///
    /// # Safety
    /// As [`Self::inc_ref_count`]: a reference given back that was never taken lets the buffer be
    /// freed under a reader.
    #[doc(hidden)]
    pub unsafe fn release_reference(&self) {
        // SAFETY: the caller's contract above is `dec_ref_count`'s.
        unsafe { self.dec_ref_count() }
    }

    /// Gets a mutable slice.
    ///
    /// # Safety
    /// This operation is marked unsafe since we cannot guarantee the single mutable reference
    /// across multiple processes. Thus if you use it, and you'll inevitable have to use it,
    /// you have to keep in mind that if you have multiple process retrieving a mutable slice
    /// you may get into concurrent writes. That said, if you have a serial pipeline and
    /// the buffer is flowing through the pipeline this will not create any issues.
    ///
    /// In short, whilst this operation is marked unsafe, you are safe if you can
    /// guarantee that your in applications only one process at the time will actually write.
    unsafe fn as_mut_slice_inner(&mut self) -> &mut [u8] {
        // SAFETY: same precondition as described in the function documentation.
        // SAFETY: the pointer is valid for the lifetime of `self`, and the length is held to the
        // capacity of the chunk.
        let len = self.readable_len();
        unsafe { std::slice::from_raw_parts_mut(self.buf.ptr_mut(), len) }
    }
}

/// Give one reference of a header back, never going below zero.
///
/// The original's release is a plain `fetch_sub`, which wraps. A header lies in a segment another
/// process made, so a stranger's mistake or a replayed descriptor would send a wrapped count to
/// four billion, a chunk its provider never takes back; stopping at zero costs nothing a correct
/// holder can see.
pub(crate) fn release_one_reference(refcount: &AtomicU32) {
    let _ = refcount.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
}

impl Drop for ShmBufInner {
    fn drop(&mut self) {
        // SAFETY: obviously, we need to decrement refcount when dropping ShmBufInner instance.
        // SAFETY: `self` is guaranteed to be valid.
        unsafe { self.dec_ref_count() };
    }
}

impl Clone for ShmBufInner {
    fn clone(&self) -> Self {
        // SAFETY: obviously, we need to increment refcount when cloning ShmBufInner instance.
        // SAFETY: `self` is guaranteed to be valid.
        unsafe { self.inc_ref_count() };
        ShmBufInner {
            metadata: self.metadata.clone(),
            buf: self.buf.clone(),
            info: self.info.clone(),
        }
    }
}

// Buffer impls
// - ShmBufInner
impl AsRef<[u8]> for ShmBufInner {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for ShmBufInner {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: we have a mutable reference to `ShmBufInner`, and we follow the precautions
        // mentioned in `as_mut_slice_inner` documentation.
        // SAFETY: `self` is guaranteed to focus on a valid buffer and the access is unique.
        unsafe { self.as_mut_slice_inner() }
    }
}

impl ZSliceBuffer for ShmBufInner {
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl ZShm {
    pub(crate) fn new(inner: ShmBufInner) -> Self {
        Self { inner }
    }
}

impl From<ShmBufInner> for ZShm {
    fn from(value: ShmBufInner) -> Self {
        Self::new(value)
    }
}

impl ZShmMut {
    /// # Safety
    ///
    /// The caller must ensure that the `ShmBufInner` is valid and can be uniquely accessed.
    pub(crate) unsafe fn new_unchecked(inner: ShmBufInner) -> Self {
        Self { inner }
    }
}

impl TryFrom<ShmBufInner> for ZShmMut {
    type Error = ShmBufInner;

    fn try_from(value: ShmBufInner) -> Result<Self, Self::Error> {
        match value.is_unique() && value.is_valid() {
            // SAFETY: we checked above that the buffer is unique and valid.
            // SAFETY: `ShmBufInner` and `ZShmMut` are layout-compatible.
            true => Ok(unsafe { Self::new_unchecked(value) }),
            false => Err(value),
        }
    }
}

impl TryFrom<&mut ShmBufInner> for &mut zshmmut {
    type Error = ();

    fn try_from(value: &mut ShmBufInner) -> Result<Self, Self::Error> {
        match value.is_unique() && value.is_valid() {
            // SAFETY: ZShm, ZShmMut, zshm and zshmmut are #[repr(transparent)]
            // to ShmBufInner type, so it is safe to transmute them in any direction.
            // We checked above that the buffer is unique and valid.
            // SAFETY: `ShmBufInner` and `zshmmut` are layout-compatible.
            true => Ok(unsafe { core::mem::transmute::<&mut ShmBufInner, &mut zshmmut>(value) }),
            false => Err(()),
        }
    }
}

impl From<&ShmBufInner> for &zshm {
    fn from(value: &ShmBufInner) -> Self {
        // SAFETY: ZShm, ZShmMut, zshm and zshmmut are #[repr(transparent)]
        // to ShmBufInner type, so it is safe to transmute them in any direction.
        // SAFETY: `ShmBufInner` and `zshm` are layout-compatible.
        unsafe { core::mem::transmute::<&ShmBufInner, &zshm>(value) }
    }
}

impl From<&mut ShmBufInner> for &mut zshm {
    fn from(value: &mut ShmBufInner) -> Self {
        // SAFETY: ZShm, ZShmMut, zshm and zshmmut are #[repr(transparent)]
        // to ShmBufInner type, so it is safe to transmute them in any direction.
        // SAFETY: `ShmBufInner` and `zshm` are layout-compatible.
        unsafe { core::mem::transmute::<&mut ShmBufInner, &mut zshm>(value) }
    }
}
