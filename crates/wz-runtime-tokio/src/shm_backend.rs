// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The seam between a shared-memory PROVIDER and the memory it hands out
//! (`transport-shm`): the value types of an allocation and the backend trait that
//! produces them.
//!
//! # Why this seam exists, and what stood where it should be
//!
//! Upstream splits a provider in two. The BACKEND owns memory: it allocates a chunk
//! of a segment, frees it, defragments, and reports what is left. The PROVIDER owns
//! the lifecycle of what the backend issued: it draws a metadata slot for each
//! chunk, watches it, keeps the chunk on a busy list until every holder has let go,
//! and only then returns the memory to the backend
//! (`commons/zenoh-shm/src/api/provider/shm_provider_backend.rs` @
//! `pub trait ShmProviderBackend: WithProtocolID {` and
//! `commons/zenoh-shm/src/api/provider/shm_provider.rs` @
//! `pub struct ShmProvider<Backend> {`).
//!
//! Until this module the runtime had the second half and not the first: a payload
//! was a data segment of its own, created for it and unlinked with it, so there was
//! no memory for a second chunk to share and no backend to ask. That was right for
//! a publisher that sends one buffer and wrong for the program upstream's own
//! examples are, which allocate a chunk out of a fixed-size pool once a second for
//! as long as they run.
//!
//! The trait is the extension point. [`crate::shm_posix_backend`] is the built-in
//! implementation, a pool in one POSIX segment, and a backend a host supplies (a
//! C program's allocator behind the zenoh-c ABI, or a protocol other than POSIX)
//! implements the same trait and is a provider's backend without the provider
//! knowing which it has.
//!
//! # The value types are upstream's, field for field
//!
//! [`AllocAlignment`], [`MemoryLayout`], [`ChunkDescriptor`], [`AllocatedChunk`],
//! [`PtrInSegment`] and the two error types are the types the trait speaks in, taken
//! from upstream's alignment (`commons/zenoh-shm/src/api/provider/types.rs` @
//! `pub struct AllocAlignment {`), layout
//! (`commons/zenoh-shm/src/api/provider/memory_layout.rs` @ `pub struct MemoryLayout {`),
//! chunk descriptor (`commons/zenoh-shm/src/api/provider/chunk.rs` @
//! `pub struct ChunkDescriptor {`) and pointer
//! (`commons/zenoh-shm/src/api/common/types.rs` @ `pub struct PtrInSegment {`),
//! because the C ABI above this crate exposes them one for one and a layer that
//! translates between two spellings of one type is a layer that can disagree with itself.

use std::any::Any;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Unique protocol identifier: which backend implementation made a chunk, and so
/// which client a receiver reads it through
/// (`commons/zenoh-shm/src/api/common/types.rs` @ `pub type ProtocolID = u32;`).
///
/// Upstream's contract, kept: it is up to the user to make sure incompatible
/// clients and backends never share an id. The POSIX one is
/// [`crate::shm_provider::POSIX_PROTOCOL_ID`].
pub type ProtocolId = u32;

/// Unique segment identifier (`pub type SegmentID = u32;`).
pub type SegmentId = u32;

/// A chunk's position within its segment (`pub type ChunkID = u32;`).
pub type ChunkId = u32;

/// The alignment of a chunk, as a power of two: 0 is one byte, 1 is two, 2 is four
/// (`commons/zenoh-shm/src/api/provider/types.rs` @ `pub struct AllocAlignment {`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllocAlignment {
    pow: u8,
}

impl Default for AllocAlignment {
    fn default() -> Self {
        Self::ALIGN_1_BYTE
    }
}

impl fmt::Display for AllocAlignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.value())
    }
}

impl AllocAlignment {
    /// One-byte alignment, the default.
    pub const ALIGN_1_BYTE: AllocAlignment = AllocAlignment { pow: 0 };
    /// Two-byte alignment.
    pub const ALIGN_2_BYTES: AllocAlignment = AllocAlignment { pow: 1 };
    /// Four-byte alignment.
    pub const ALIGN_4_BYTES: AllocAlignment = AllocAlignment { pow: 2 };
    /// Eight-byte alignment.
    pub const ALIGN_8_BYTES: AllocAlignment = AllocAlignment { pow: 3 };

    /// An alignment of `2^pow` bytes. Refused when that does not fit a `usize`, as
    /// upstream's `new` refuses it (an alignment too large to name is a layout
    /// error and not an allocation one).
    pub const fn new(pow: u8) -> Result<Self, LayoutError> {
        if pow < usize::BITS as u8 {
            Ok(Self { pow })
        } else {
            Err(LayoutError::IncorrectLayoutArgs)
        }
    }

    /// The alignment in bytes.
    pub fn value(&self) -> NonZeroUsize {
        // `new` bounds `pow` below the width of `usize`, so the shift cannot overflow
        // and a power of two is never zero.
        NonZeroUsize::new(1usize << self.pow).expect("a power of two below usize::BITS is non-zero")
    }

    /// The alignment as the power of two it was built from.
    pub fn pow(&self) -> u8 {
        self.pow
    }

    /// `size` rounded UP to a multiple of this alignment, or `None` when that does
    /// not fit a `usize`. Upstream asserts on overflow; a layer that sits under a
    /// C caller returns the refusal instead of aborting the process.
    pub fn align_size(&self, size: NonZeroUsize) -> Option<NonZeroUsize> {
        let a_minus_1 = self.value().get() - 1;
        if size.get() > usize::MAX - a_minus_1 {
            return None;
        }
        NonZeroUsize::new((size.get() + a_minus_1) & !a_minus_1)
    }
}

/// A size and the alignment it is allocated at, valid only when the size is a
/// multiple of the alignment
/// (`commons/zenoh-shm/src/api/provider/memory_layout.rs` @
/// `pub struct MemoryLayout {`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryLayout {
    size: NonZeroUsize,
    alignment: AllocAlignment,
}

impl fmt::Display for MemoryLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[size={},alignment={}]", self.size, self.alignment)
    }
}

impl MemoryLayout {
    /// A layout, or [`LayoutError::IncorrectLayoutArgs`] when `size` is zero or is
    /// not a multiple of `alignment`.
    pub fn new(size: usize, alignment: AllocAlignment) -> Result<Self, LayoutError> {
        let Some(size) = NonZeroUsize::new(size) else {
            return Err(LayoutError::IncorrectLayoutArgs);
        };
        if size.get() % alignment.value().get() != 0 {
            return Err(LayoutError::IncorrectLayoutArgs);
        }
        Ok(Self { size, alignment })
    }

    /// A layout of `size` bytes at byte alignment.
    pub fn of_size(size: usize) -> Result<Self, LayoutError> {
        Self::new(size, AllocAlignment::ALIGN_1_BYTE)
    }

    /// The size in bytes.
    pub fn size(&self) -> NonZeroUsize {
        self.size
    }

    /// The alignment.
    pub fn alignment(&self) -> AllocAlignment {
        self.alignment
    }

    /// This layout at a LARGER alignment, its size rounded up to the new multiple.
    /// A smaller alignment is refused: a chunk is never promised less than it was
    /// asked for.
    pub fn extend(&self, new_alignment: AllocAlignment) -> Result<MemoryLayout, LayoutError> {
        if new_alignment < self.alignment {
            return Err(LayoutError::IncorrectLayoutArgs);
        }
        let size = new_alignment
            .align_size(self.size)
            .ok_or(LayoutError::IncorrectLayoutArgs)?;
        MemoryLayout::new(size.get(), new_alignment)
    }
}

/// Why an allocation failed (`ZAllocError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// Enough memory in total, but no single range holds the request: defragmenting
    /// may help.
    NeedDefragment,
    /// The provider is out of memory.
    OutOfMemory,
    /// Anything else.
    Other,
}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AllocError::NeedDefragment => "need defragmentation",
            AllocError::OutOfMemory => "out of memory",
            AllocError::Other => "other",
        })
    }
}

impl std::error::Error for AllocError {}

/// Why a layout was refused (`ZLayoutError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// The arguments do not make a layout.
    IncorrectLayoutArgs,
    /// The layout is well formed and this provider cannot serve it.
    ProviderIncompatibleLayout,
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LayoutError::IncorrectLayoutArgs => "incorrect layout arguments",
            LayoutError::ProviderIncompatibleLayout => "layout is incompatible with the provider",
        })
    }
}

impl std::error::Error for LayoutError {}

/// Either failure of "make a layout, then allocate by it" (`ZLayoutAllocError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutAllocError {
    /// The allocation failed.
    Alloc(AllocError),
    /// The layout was refused.
    Layout(LayoutError),
}

impl fmt::Display for LayoutAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutAllocError::Alloc(e) => e.fmt(f),
            LayoutAllocError::Layout(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LayoutAllocError {}

impl From<AllocError> for LayoutAllocError {
    fn from(e: AllocError) -> Self {
        Self::Alloc(e)
    }
}

impl From<LayoutError> for LayoutAllocError {
    fn from(e: LayoutError) -> Self {
        Self::Layout(e)
    }
}

/// Where a chunk lies: its segment, its offset in that segment and its length
/// (`commons/zenoh-shm/src/api/provider/chunk.rs` @ `pub struct ChunkDescriptor {`).
///
/// This is what a metadata header carries to a receiver, and what the backend is
/// handed back when it is asked to free the chunk, so it names the chunk the way a
/// receiver in another process can follow and not the way this process happens to
/// address it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkDescriptor {
    /// The segment the chunk is in.
    pub segment: SegmentId,
    /// The chunk's offset in that segment.
    pub chunk: ChunkId,
    /// The chunk's length, which may exceed what was asked for.
    pub len: NonZeroUsize,
}

/// A pointer into a segment, and the segment that keeps it valid
/// (`commons/zenoh-shm/src/api/common/types.rs` @ `pub struct PtrInSegment {`).
///
/// The segment is held as an `Arc` of anything, so a backend of any kind keeps its own
/// mapping alive through a pointer it lent: a pointer held by a buffer that outlives
/// its provider still points at live memory.
#[derive(Clone)]
pub struct PtrInSegment {
    ptr: *mut u8,
    _segment: Arc<dyn Any + Send + Sync>,
}

impl PtrInSegment {
    /// A pointer, with the segment that owns it.
    pub fn new(ptr: *mut u8, segment: Arc<dyn Any + Send + Sync>) -> Self {
        Self {
            ptr,
            _segment: segment,
        }
    }

    /// The address.
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl PartialEq for PtrInSegment {
    fn eq(&self, other: &Self) -> bool {
        // Two pointers into one segment are equal when the addresses are.
        self.ptr == other.ptr
    }
}

impl Eq for PtrInSegment {}

impl fmt::Debug for PtrInSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtrInSegment")
            .field("ptr", &self.ptr)
            .finish()
    }
}

// SAFETY: the pointer is an address into a mapping the `Arc` keeps alive; sharing the
// address shares nothing mutable by itself. What may be written through it is decided
// by the chunk it is the data of, whose uniqueness the allocator guarantees.
unsafe impl Send for PtrInSegment {}
// SAFETY: as above.
unsafe impl Sync for PtrInSegment {}

/// A freshly allocated chunk: where it lies for a receiver, and where it lies for
/// this process (`pub struct AllocatedChunk {`).
#[derive(Debug)]
pub struct AllocatedChunk {
    /// The descriptor a receiver follows.
    pub descriptor: ChunkDescriptor,
    /// The address this process writes through.
    pub data: PtrInSegment,
}

/// What a provider asks of the memory it hands out
/// (`commons/zenoh-shm/src/api/provider/shm_provider_backend.rs` @
/// `pub trait ShmProviderBackend: WithProtocolID {`).
pub trait ShmProviderBackend: Send + Sync {
    /// The protocol id every chunk of this backend carries in its header.
    fn id(&self) -> ProtocolId;

    /// Allocate a chunk. The chunk's length is at least `layout.size()`.
    fn alloc(&self, layout: &MemoryLayout) -> Result<AllocatedChunk, AllocError>;

    /// Return a chunk. The descriptor is the one [`Self::alloc`] returned for it.
    fn free(&self, chunk: &ChunkDescriptor);

    /// Defragment, and report the size of the largest chunk now allocatable (0 for a
    /// backend that does not account).
    fn defragment(&self) -> usize;

    /// Bytes still available (0 for a backend that does not account).
    fn available(&self) -> usize;

    /// Validate `layout` against this backend and adapt it to what the backend can
    /// serve. The provider allocates by the layout this returns.
    fn layout_for(&self, layout: MemoryLayout) -> Result<MemoryLayout, LayoutError>;

    /// Whether `chunk`, which something else produced, is one this backend could have
    /// issued. A provider asks before it takes a mapped chunk on
    /// ([`ShmProvider::map`](crate::shm_provider::ShmProvider::map)), because it will hand
    /// the range back to this backend when it collects, and a backend given a range it never
    /// issued may corrupt itself. Upstream asks nothing; a backend that can tell (a pool knows
    /// its own segment) refuses what it cannot own, and the default accepts, for a backend
    /// whose memory is the host's and whose `free` is the host's to get right.
    fn accepts(&self, _chunk: &AllocatedChunk) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An alignment is a power of two below the width of `usize`, and one that does
    /// not fit is a LAYOUT error, which is how the C ABI above reports it.
    #[test]
    fn an_alignment_too_large_to_name_is_refused() {
        assert!(AllocAlignment::new(0).is_ok());
        assert!(AllocAlignment::new(usize::BITS as u8 - 1).is_ok());
        assert_eq!(
            AllocAlignment::new(usize::BITS as u8),
            Err(LayoutError::IncorrectLayoutArgs)
        );
    }

    /// Upstream's own worked examples for rounding a size up to an alignment: 4, 7,
    /// 8 and 9 bytes at four-byte alignment give 4, 8, 8 and 12.
    #[test]
    fn a_size_rounds_up_to_a_multiple_of_the_alignment() {
        let four = AllocAlignment::ALIGN_4_BYTES;
        let size = |n: usize| NonZeroUsize::new(n).unwrap();
        assert_eq!(four.align_size(size(4)), Some(size(4)));
        assert_eq!(four.align_size(size(7)), Some(size(8)));
        assert_eq!(four.align_size(size(8)), Some(size(8)));
        assert_eq!(four.align_size(size(9)), Some(size(12)));
        assert_eq!(
            four.align_size(size(usize::MAX)),
            None,
            "a size that cannot be rounded up is refused and does not abort"
        );
    }

    /// A layout needs a non-zero size that is a multiple of its alignment.
    #[test]
    fn a_layout_is_a_nonzero_multiple_of_its_alignment() {
        assert!(MemoryLayout::new(8, AllocAlignment::ALIGN_4_BYTES).is_ok());
        assert_eq!(
            MemoryLayout::new(0, AllocAlignment::ALIGN_1_BYTE),
            Err(LayoutError::IncorrectLayoutArgs)
        );
        assert_eq!(
            MemoryLayout::new(6, AllocAlignment::ALIGN_4_BYTES),
            Err(LayoutError::IncorrectLayoutArgs)
        );
    }

    /// Extending a layout raises its alignment and rounds its size up, and never
    /// lowers the alignment: upstream's documented example.
    #[test]
    fn extending_a_layout_only_ever_raises_the_alignment() {
        let layout = MemoryLayout::new(8, AllocAlignment::ALIGN_4_BYTES).unwrap();
        assert_eq!(
            layout.extend(AllocAlignment::ALIGN_2_BYTES),
            Err(LayoutError::IncorrectLayoutArgs)
        );
        let wider = layout.extend(AllocAlignment::ALIGN_8_BYTES).unwrap();
        assert_eq!(wider.size().get(), 8);
        assert_eq!(wider.alignment(), AllocAlignment::ALIGN_8_BYTES);
        let rounded = MemoryLayout::new(12, AllocAlignment::ALIGN_4_BYTES)
            .unwrap()
            .extend(AllocAlignment::ALIGN_8_BYTES)
            .unwrap();
        assert_eq!(
            rounded.size().get(),
            16,
            "12 rounds up to 16 at eight bytes"
        );
    }
}
