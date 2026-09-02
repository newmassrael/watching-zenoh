// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_shm_*` — the shared-memory PROVIDER and BUFFER plane at the zenoh-c ABI.
//!
//! ## What upstream's SHM API is two of, and which half this is
//!
//! zenoh's shared memory is two mechanisms wearing one name, and the corpus
//! reaches them separately:
//!
//! 1. **A buffer allocator.** A provider owns a segment; a program allocates a
//!    chunk out of it, writes into the chunk, and hands the chunk to zenoh as a
//!    payload. Six upstream examples do exactly this and nothing more:
//!    `z_pub_shm`, `z_pub_shm_thr`, `z_get_shm`, `z_ping_shm`, `z_queryable_shm`,
//!    and the allocating half of `z_sub_shm`.
//! 2. **A transport optimisation.** When two peers on the same host negotiate
//!    SHM support, a payload backed by a segment travels as a REFERENCE — the
//!    receiver maps the same pages instead of copying. When they do not, zenoh
//!    serialises the bytes and the receiver sees an ordinary payload.
//!
//! This module implements (1) completely and does not implement (2), and the
//! difference is stated here rather than left for a reader to infer from a
//! symbol list. wz's transport advertises no SHM segment, so a wz peer never
//! negotiates the optimisation — which means every wz put of an SHM buffer
//! serialises, and every payload a wz session RECEIVES is an ordinary one.
//!
//! That is not wz declining to implement a wire feature it should have; it is
//! upstream's own documented fallback for a peer that does not negotiate SHM,
//! and it is why the two arms of the drop-in test agree. `z_sub_shm.c` prints
//! the buffer type it detects, and against a publisher that did not negotiate
//! SHM the REAL `libzenohc.so` prints `RAW` for the same reason wz does. The
//! lane measures that rather than asserting it.
//!
//! The named consequence, with its re-open trigger: [`z_bytes_as_loaned_shm`]
//! and [`z_bytes_as_mut_loaned_shm`] answer "this payload is not carrying an
//! SHM buffer" for every payload wz can produce or receive. That answer is
//! TRUE today. It stops being true the day wz's transport learns SHM segment
//! negotiation, and that is the round that should revisit these two functions.
//!
//! ## The allocator is real, because the examples depend on it being real
//!
//! `z_pub_shm.c` creates a 4096-byte provider and allocates a 1024-byte chunk
//! once per second, forever. A provider that never reclaimed would fail on the
//! fifth iteration, so reclamation is not decoration: a chunk returns to the
//! segment when its owner drops, adjacent free ranges coalesce, and
//! `z_shm_provider_available` reports what is left. `z_get_shm.c` goes further
//! and creates a provider of EXACTLY the size it needs, so an allocator with any
//! per-chunk overhead taken out of the segment would fail its very first
//! allocation.
//!
//! The segment is ordinary process memory rather than a POSIX `/dev/shm`
//! mapping. A real mapping would be strictly more machinery for the same
//! observable behaviour while wz negotiates no SHM transport — nothing outside
//! this process can attach to it — and it would add a cleanup obligation
//! (`shm_unlink` on abnormal exit) that buys nothing. The type is what upstream
//! names `z_owned_shm_provider_t`; what backs it is not ABI.
//!
//! ## Gating
//!
//! Every declaration below is
//! `#if (defined(Z_FEATURE_SHARED_MEMORY) && defined(Z_FEATURE_UNSTABLE_API))`
//! upstream, so the module carries the same two-feature `cfg` — see
//! [`crate`](crate). On any other arm these symbols would name types no header
//! declares.

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

use crate::abi::{z_loaned_bytes_t, z_owned_bytes_t, Handle};
use crate::bytes::{bytes_slice, BytesState};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};

/// `z_owned_shm_t` / `z_loaned_shm_t` / `z_owned_shm_mut_t` /
/// `z_loaned_shm_mut_t` — 80 bytes at align 8, measured by upstream's own
/// opaque-type generator on the shared-memory + unstable arm.
const SHM_SIZE: usize = 80;
/// `z_owned_shm_provider_t` / `z_loaned_shm_provider_t` — 104 bytes at align 8.
const SHM_PROVIDER_SIZE: usize = 104;

// ---------------------------------------------------------------------------
// the enums
// ---------------------------------------------------------------------------

/// zenoh-c `zc_buf_layout_alloc_status_t` (`zenoh_opaque.h:94-108`) — a plain C
/// enum, so `c_int`-sized.
pub type zc_buf_layout_alloc_status_t = std::ffi::c_int;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_OK` = 0.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_OK: zc_buf_layout_alloc_status_t = 0;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR` = 1.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR: zc_buf_layout_alloc_status_t = 1;
/// `ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR` = 2.
pub const ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR: zc_buf_layout_alloc_status_t = 2;

/// zenoh-c `zc_buf_alloc_status_t` (`zenoh_opaque.h:70-82`).
pub type zc_buf_alloc_status_t = std::ffi::c_int;
/// `ZC_BUF_ALLOC_STATUS_OK` = 0.
pub const ZC_BUF_ALLOC_STATUS_OK: zc_buf_alloc_status_t = 0;
/// `ZC_BUF_ALLOC_STATUS_ALLOC_ERROR` = 1.
pub const ZC_BUF_ALLOC_STATUS_ALLOC_ERROR: zc_buf_alloc_status_t = 1;

/// zenoh-c `z_alloc_error_t` (`zenoh_opaque.h:24-43`).
pub type z_alloc_error_t = std::ffi::c_int;
/// `Z_ALLOC_ERROR_NEED_DEFRAGMENT` = 0.
pub const Z_ALLOC_ERROR_NEED_DEFRAGMENT: z_alloc_error_t = 0;
/// `Z_ALLOC_ERROR_OUT_OF_MEMORY` = 1.
pub const Z_ALLOC_ERROR_OUT_OF_MEMORY: z_alloc_error_t = 1;
/// `Z_ALLOC_ERROR_OTHER` = 2.
pub const Z_ALLOC_ERROR_OTHER: z_alloc_error_t = 2;

/// zenoh-c `z_layout_error_t` (`zenoh_opaque.h:48-63`).
pub type z_layout_error_t = std::ffi::c_int;
/// `Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS` = 0.
pub const Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS: z_layout_error_t = 0;
/// `Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT` = 1.
pub const Z_LAYOUT_ERROR_PROVIDER_INCOMPATIBLE_LAYOUT: z_layout_error_t = 1;

// ---------------------------------------------------------------------------
// the segment
// ---------------------------------------------------------------------------

/// One free range in a segment, as `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreeRange {
    start: usize,
    end: usize,
}

/// The segment's book-keeping, behind the provider's mutex.
#[derive(Debug)]
struct SegmentBooks {
    /// Free ranges, kept SORTED by `start` and never overlapping. Sorted is what
    /// makes coalescing a linear scan instead of a search, and it is an
    /// invariant [`SegmentBooks::release`] restores on every free.
    free: Vec<FreeRange>,
}

impl SegmentBooks {
    /// First-fit. Returns the offset of a `len`-byte range aligned to `align`,
    /// or `None`.
    ///
    /// First fit rather than best fit deliberately: `z_get_shm.c` sizes its
    /// provider to EXACTLY the payload it will allocate, so the property that
    /// matters is "a request for the whole segment succeeds", which first fit
    /// gives and any strategy that reserves header bytes does not.
    fn claim(&mut self, len: usize, align: usize) -> Option<usize> {
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
            // The alignment gap before the chunk and the remainder after it are
            // both still free; re-inserting them keeps the list sorted because
            // they sit where the removed range was.
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
    fn release(&mut self, start: usize, end: usize) {
        let at = self.free.partition_point(|r| r.start < start);
        self.free.insert(at, FreeRange { start, end });
        // Coalesce forwards from the predecessor, so a release that bridges two
        // free ranges merges all three in one pass.
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
    fn available(&self) -> usize {
        self.free.iter().map(|r| r.end - r.start).sum()
    }

    /// The largest single free range — what an allocation of that size could
    /// still satisfy without any further reclamation.
    fn largest(&self) -> usize {
        self.free.iter().map(|r| r.end - r.start).max().unwrap_or(0)
    }
}

/// A provider's memory and its book-keeping.
///
/// The bytes live in a boxed slice this type owns for its whole life; chunks
/// index into it. `Segment` is shared by `Arc` between the provider and every
/// live buffer, so a buffer that OUTLIVES its provider — which
/// `z_pub_shm.c` permits, since it drops the provider last but hands buffers to
/// zenoh — still points at live memory.
struct Segment {
    /// The segment's base pointer and length. A raw pointer rather than a
    /// `Box<[u8]>` field because chunks hand out `&mut` interior slices while
    /// this struct is shared behind an `Arc`; the allocator's non-overlap
    /// invariant is what makes that sound, and it is stated at each use.
    base: *mut u8,
    len: usize,
    /// The alignment `base` was allocated at, so `Drop` can name the same
    /// layout `new` did. R2289 made this a FIELD rather than reading
    /// [`SEGMENT_ALIGN`] in both places: `z_posix_shm_provider_with_layout_new`
    /// lets a caller ask for more than a page, and a `dealloc` at a different
    /// alignment than the `alloc` is undefined behaviour rather than a leak.
    align: usize,
    books: Mutex<SegmentBooks>,
    /// Signalled whenever a chunk is released — what the BLOCKING allocation
    /// waits on.
    released: Condvar,
}

// SAFETY: `base` is a heap allocation this type owns for its whole life and
// frees in `Drop`. It is shared across threads only through `Arc<Segment>`, and
// every access to the bytes goes through a `ShmChunk` whose range was handed out
// by `SegmentBooks::claim` and is not handed out again until the chunk is
// released — so no two live chunks alias, and `books` serialises the allocator
// itself.
unsafe impl Send for Segment {}
// SAFETY: as above.
unsafe impl Sync for Segment {}

/// R2264 — the alignment every segment's base carries, so an offset aligned
/// inside it is aligned in MEMORY too.
///
/// A page, because that is what upstream's `mmap`ed segments give and therefore
/// the boundary a C program written against zenoh-c may already assume. Nothing
/// here needs a page specifically; what it needs is a bound, stated once.
const SEGMENT_ALIGN: usize = 4096;

impl Segment {
    /// Allocate a segment of `len` bytes, all free.
    ///
    /// A ZERO-length segment is legal and is not an edge case to reject:
    /// `z_get_shm.c` builds its provider from `strlen(value)`, which is 0 when
    /// the example is run without a payload.
    fn new(len: usize) -> Arc<Self> {
        Self::with_alignment(len, SEGMENT_ALIGN)
    }

    /// Allocate a segment of `len` bytes whose base is aligned to at least
    /// `align`.
    ///
    /// R2289 — `z_posix_shm_provider_with_layout_new` takes a
    /// `z_loaned_memory_layout_t`, which carries an alignment the caller chose,
    /// and upstream's backend honours it when it maps the segment. A request
    /// BELOW a page is widened to [`SEGMENT_ALIGN`] rather than narrowed: the
    /// page bound is what every other constructor already promises, and giving
    /// one provider a weaker base than its siblings would make the alignment
    /// tests pass or fail depending on which constructor built the provider.
    fn with_alignment(len: usize, align: usize) -> Arc<Self> {
        let align = align.max(SEGMENT_ALIGN);
        // R2264 — the segment is allocated at PAGE alignment, and that is a
        // correctness requirement rather than a tidiness one.
        //
        // `claim` aligns an OFFSET inside the segment. A caller of
        // `z_shm_provider_alloc_aligned` is handed a POINTER and told it meets
        // the alignment it asked for, so the two agree only when the base does
        // too. This was `vec![0u8; len]` — alignment 1 — so a 64-byte request
        // returned an address that was 64-aligned within the segment and
        // arbitrary in memory. MEASURED: the first aligned spelling this round
        // added came back at `addr % 64 == 48`.
        //
        // Upstream has this for free: its segments are `mmap`ed and therefore
        // page-aligned. Matching that here makes every alignment up to a page
        // exact, and beyond a page neither implementation promises anything.
        let base = if len == 0 {
            std::ptr::null_mut()
        } else {
            let layout = std::alloc::Layout::from_size_align(len, align)
                .expect("a segment layout at page alignment");
            // SAFETY: `len` is non-zero, so the layout is non-zero-sized.
            let p = unsafe { std::alloc::alloc_zeroed(layout) };
            if p.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            p
        };
        Arc::new(Self {
            base,
            len,
            align,
            books: Mutex::new(SegmentBooks {
                free: if len == 0 {
                    Vec::new()
                } else {
                    vec![FreeRange { start: 0, end: len }]
                },
            }),
            released: Condvar::new(),
        })
    }

    /// Lock the books, ignoring poisoning — a panic while holding them cannot
    /// leave the free list torn, because every mutation is a single statement
    /// sequence with no `?` inside.
    fn books(&self) -> std::sync::MutexGuard<'_, SegmentBooks> {
        self.books.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        if self.len == 0 || self.base.is_null() {
            return;
        }
        // SAFETY: `base` came from `alloc_zeroed` in `new` with exactly this
        // layout, and no chunk can outlive the `Arc` that owns this. R2264 — the
        // matching `dealloc`; it was `Box::from_raw` while `new` used `vec!`,
        // and both had to move together when the segment gained an alignment.
        let layout = std::alloc::Layout::from_size_align(self.len, self.align)
            .expect("the layout `new` allocated with");
        unsafe { std::alloc::dealloc(self.base, layout) };
    }
}

/// Where one allocated chunk's bytes live, and what returning them means.
///
/// R2289 — TWO arms, because a provider now has two backends (see [`Provider`])
/// and a chunk must be released to the one that issued it: wz's own allocator
/// takes the range back into its free list, a C-supplied backend is told through
/// its `free_fn`. Nothing above [`ShmChunk`] branches on which — the buffer
/// plane asks for a pointer and a length and gets the same answers either way.
enum ChunkBacking {
    /// A range of a segment wz allocated.
    Native {
        segment: Arc<Segment>,
        /// The chunk's offset into `segment`.
        start: usize,
    },
    /// A chunk a C backend allocated and is the only one able to free.
    Foreign {
        backend: Arc<ForeignBackend>,
        /// What `free_fn` is handed back. Upstream's `free` takes the
        /// DESCRIPTOR rather than the pointer, so the descriptor is the part
        /// that has to survive.
        descriptor: z_chunk_descriptor_t,
        /// The pointer the backend handed over, and the segment context it
        /// keeps alive. Held for its `Drop` as much as for its address: the
        /// context's `delete_fn` must not run while a chunk still points into
        /// the memory that context owns.
        ptr: PtrInSegment,
    },
}

/// One allocated chunk. Dropping it returns the memory to whichever backend
/// issued it.
struct ShmChunk {
    backing: ChunkBacking,
    len: usize,
    /// `false` once the chunk has been frozen into an immutable `z_owned_shm_t`.
    /// The flag is what [`z_shm_try_reloan_mut`] answers with, so it has to
    /// travel with the chunk rather than with the handle that names it.
    mutable: bool,
}

impl ShmChunk {
    /// The chunk's bytes.
    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: a native range was handed out by `claim` and is not handed
        // out again until this chunk drops; a foreign one is the backend's
        // promise for the life of the descriptor. No other live chunk aliases
        // either.
        unsafe { std::slice::from_raw_parts(self.as_mut_ptr(), self.len) }
    }

    /// The chunk's bytes, mutably.
    fn as_mut_ptr(&self) -> *mut u8 {
        match &self.backing {
            // SAFETY: as `as_slice` — exclusive by the allocator's invariant.
            ChunkBacking::Native { segment, start } => unsafe { segment.base.add(*start) },
            ChunkBacking::Foreign { ptr, .. } => ptr.ptr,
        }
    }

    /// The provider this chunk came out of, so a copy can be taken from the
    /// same place ([`z_shm_clone`]).
    fn provider(&self) -> Provider {
        match &self.backing {
            ChunkBacking::Native { segment, .. } => Provider::Native(segment.clone()),
            ChunkBacking::Foreign { backend, .. } => Provider::Foreign(backend.clone()),
        }
    }
}

impl Drop for ShmChunk {
    fn drop(&mut self) {
        match &self.backing {
            ChunkBacking::Native { segment, start } => {
                if self.len > 0 {
                    segment.books().release(*start, *start + self.len);
                }
                // Woken even for a zero-length chunk: a waiter blocked on a
                // request this release cannot satisfy re-checks and blocks
                // again, which is cheaper than reasoning about which releases
                // are worth a notify.
                segment.released.notify_all();
            }
            ChunkBacking::Foreign {
                backend,
                descriptor,
                ..
            } => backend.free(descriptor),
        }
    }
}

// ---------------------------------------------------------------------------
// the opaque handles
// ---------------------------------------------------------------------------

/// Declare one `{owned, loaned, moved}` SHM family at `$size` bytes / align 8,
/// with the handle in slot 0 — the same shape [`crate::abi`]'s `define_opaque!`
/// produces, repeated here because these families are `cfg`-gated and that
/// macro's invocations are not.
macro_rules! define_shm_opaque {
    // R2289 — the OWNED + MOVED half on its own, for a family upstream gives no
    // `_loan`: `z_chunk_alloc_result_t` has no `z_loaned_` spelling in any
    // header and no function that would take one, and declaring the type anyway
    // would put a name in wz's surface that the reference does not have.
    ($Owned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Moved wrapper — upstream's `z_moved_X_t` is `struct { z_owned_X_t; }`.
        #[repr(C)]
        pub struct $Moved {
            pub(crate) _this: $Owned,
        }

        impl $Owned {
            /// The gravestone value: a null handle and zeroed padding.
            #[inline]
            pub(crate) fn null_value() -> Self {
                Self {
                    handle: std::ptr::null_mut(),
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }

            /// Wrap a `Box::into_raw` pointer.
            #[inline]
            pub(crate) fn from_handle(handle: Handle) -> Self {
                Self {
                    handle,
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }
        }

        const _: () = {
            assert!(std::mem::size_of::<$Owned>() == $size);
            assert!(std::mem::align_of::<$Owned>() == 8);
            assert!(std::mem::size_of::<$Moved>() == $size);
        };
    };
    ($Owned:ident, $Loaned:ident, $Moved:ident, $size:expr) => {
        /// Owned value: our handle in slot 0, zero padding to the C size.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Loaned view — the same layout, so `loan` is a pointer cast.
        #[repr(C)]
        pub struct $Loaned {
            pub(crate) handle: Handle,
            pub(crate) _pad: [u8; $size - std::mem::size_of::<Handle>()],
        }

        /// Moved wrapper — upstream's `z_moved_X_t` is `struct { z_owned_X_t; }`.
        #[repr(C)]
        pub struct $Moved {
            pub(crate) _this: $Owned,
        }

        impl $Owned {
            /// The gravestone value: a null handle and zeroed padding.
            #[inline]
            pub(crate) fn null_value() -> Self {
                Self {
                    handle: std::ptr::null_mut(),
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }

            /// Wrap a `Box::into_raw` pointer.
            #[inline]
            pub(crate) fn from_handle(handle: Handle) -> Self {
                Self {
                    handle,
                    _pad: [0u8; $size - std::mem::size_of::<Handle>()],
                }
            }
        }

        const _: () = {
            assert!(std::mem::size_of::<$Owned>() == $size);
            assert!(std::mem::align_of::<$Owned>() == 8);
            assert!(std::mem::size_of::<$Loaned>() == $size);
            assert!(std::mem::size_of::<$Moved>() == $size);
        };
    };
}

/// zenoh-c `z_owned_memory_layout_t` (`zenoh_opaque.h`: `ALIGN(8) uint8_t
/// _0[16]`) — MEASURED off the shm-arm header, which is the only arm that
/// declares it.
const MEMORY_LAYOUT_SIZE: usize = 16;

define_shm_opaque!(
    z_owned_memory_layout_t,
    z_loaned_memory_layout_t,
    z_moved_memory_layout_t,
    MEMORY_LAYOUT_SIZE
);

/// zenoh-c `z_owned_precomputed_layout_t` (`zenoh_opaque.h`: `ALIGN(8) uint8_t
/// _0[40]`) — MEASURED off the shm-arm header.
const PRECOMPUTED_LAYOUT_SIZE: usize = 40;

define_shm_opaque!(
    z_owned_precomputed_layout_t,
    z_loaned_precomputed_layout_t,
    z_moved_precomputed_layout_t,
    PRECOMPUTED_LAYOUT_SIZE
);

/// zenoh-c makes `z_owned_alloc_layout_t` a TYPEDEF of
/// `z_owned_precomputed_layout_t`, so wz does the same rather than declaring a
/// second type that would have to be kept identical by hand.
pub type z_owned_alloc_layout_t = z_owned_precomputed_layout_t;
/// See [`z_owned_alloc_layout_t`].
pub type z_loaned_alloc_layout_t = z_loaned_precomputed_layout_t;
/// See [`z_owned_alloc_layout_t`].
pub type z_moved_alloc_layout_t = z_moved_precomputed_layout_t;

define_shm_opaque!(z_owned_shm_t, z_loaned_shm_t, z_moved_shm_t, SHM_SIZE);
define_shm_opaque!(
    z_owned_shm_mut_t,
    z_loaned_shm_mut_t,
    z_moved_shm_mut_t,
    SHM_SIZE
);
define_shm_opaque!(
    z_owned_shm_provider_t,
    z_loaned_shm_provider_t,
    z_moved_shm_provider_t,
    SHM_PROVIDER_SIZE
);

/// zenoh-c `z_alloc_alignment_t` (`zenoh_opaque.h:181-183`): a power-of-two
/// exponent in ONE byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_alloc_alignment_t {
    /// `1 << pow` is the required alignment.
    pub pow: u8,
}

/// zenoh-c `z_buf_layout_alloc_result_t` (`zenoh_opaque.h:837-842`) —
/// TRANSPARENT, so it is mirrored field for field and Rust computes the layout.
#[repr(C)]
pub struct z_buf_layout_alloc_result_t {
    /// Which of the three outcomes this is.
    pub status: zc_buf_layout_alloc_status_t,
    /// The buffer, valid when `status` is OK and a gravestone otherwise.
    pub buf: z_owned_shm_mut_t,
    /// Meaningful when `status` is `ALLOC_ERROR`.
    pub alloc_error: z_alloc_error_t,
    /// Meaningful when `status` is `LAYOUT_ERROR`.
    pub layout_error: z_layout_error_t,
}

/// zenoh-c `z_buf_alloc_result_t` (`zenoh_opaque.h:123-127`).
#[repr(C)]
pub struct z_buf_alloc_result_t {
    /// Which of the two outcomes this is.
    pub status: zc_buf_alloc_status_t,
    /// The buffer, valid when `status` is OK.
    pub buf: z_owned_shm_mut_t,
    /// Meaningful when `status` is `ALLOC_ERROR`.
    pub error: z_alloc_error_t,
}

// ---------------------------------------------------------------------------
// handle plumbing
// ---------------------------------------------------------------------------

/// Read the backend behind a loaned provider.
///
/// # Safety
/// `this_` must be null, or a valid loaned provider whose handle slot holds a
/// live [`Provider`] pointer.
unsafe fn provider_of<'a>(this_: *const z_loaned_shm_provider_t) -> Option<&'a Provider> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<Provider>` this crate leaked.
    Some(unsafe { &*(handle as *const Provider) })
}

/// Mint an owned provider handle from a backend.
fn provider_handle(provider: Provider) -> Handle {
    Box::into_raw(Box::new(provider)) as Handle
}

/// Where a provider's memory comes from.
///
/// R2289 (open-debt item 607) — until this round there was one answer and the
/// type did not exist: every provider owned a [`Segment`] wz allocated. Upstream
/// has FOUR arms (`CSHMProvider::{Posix, SharedPosix, Dynamic,
/// DynamicThreadsafe}`) and the two that matter here are the split between
/// memory wz manages and memory a C program manages, because
/// `z_shm_provider_new` hands the whole allocator to the caller.
///
/// The `threadsafe` flag lives inside [`ForeignBackend`] rather than being a
/// third arm: it changes what the callbacks are allowed to do, not where the
/// memory is.
#[derive(Clone)]
enum Provider {
    /// wz's own segment allocator — `z_shm_provider_default_new`,
    /// `z_posix_shm_provider_new`, `z_posix_shm_provider_with_layout_new`.
    Native(Arc<Segment>),
    /// A backend the C caller supplied — `z_shm_provider_new`,
    /// `z_shm_provider_threadsafe_new`.
    Foreign(Arc<ForeignBackend>),
}

impl Provider {
    /// Allocate `size` bytes at `align`, blocking for a release if asked.
    fn alloc(
        &self,
        size: usize,
        align: usize,
        blocking: bool,
    ) -> Result<Box<ShmChunk>, z_alloc_error_t> {
        match self {
            Provider::Native(segment) => native_alloc(segment, size, align, blocking),
            Provider::Foreign(backend) => backend.alloc(size, align, blocking),
        }
    }

    /// Bytes still allocatable.
    fn available(&self) -> usize {
        match self {
            Provider::Native(segment) => segment.books().available(),
            Provider::Foreign(backend) => backend.available(),
        }
    }

    /// Defragment, reporting what that leaves reachable.
    fn defragment(&self) -> usize {
        match self {
            Provider::Native(segment) => segment.books().largest(),
            Provider::Foreign(backend) => backend.defragment(),
        }
    }

    /// Whether the caller promised this provider's callbacks may run
    /// concurrently — what the `_async` spellings refuse on.
    ///
    /// TRUE for the native arm: wz's own allocator is behind a mutex and has
    /// always been callable from any thread, and upstream agrees (its `Posix`
    /// and `SharedPosix` arms both accept an async allocation).
    fn is_threadsafe(&self) -> bool {
        match self {
            Provider::Native(_) => true,
            Provider::Foreign(backend) => backend.threadsafe,
        }
    }
}

/// Read the chunk behind a loaned SHM buffer, in either mutability spelling.
///
/// The two loaned types are separate C types with the SAME layout and the same
/// handle contents, which is what lets [`z_shm_try_reloan_mut`] hand one back as
/// the other with a cast rather than a conversion.
///
/// # Safety
/// `handle` must be null or a live `Box::into_raw::<ShmChunk>` pointer.
unsafe fn chunk<'a>(handle: Handle) -> Option<&'a ShmChunk> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(handle as *const ShmChunk) })
}

// ---------------------------------------------------------------------------
// the provider
// ---------------------------------------------------------------------------

/// Create a provider owning a `size`-byte segment (zenoh-c
/// `z_shm_provider_default_new`, `zenoh_commons.h:4789-4790`).
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_default_new(
    this_: *mut z_owned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract, written before any fallible work.
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
        let handle = provider_handle(Provider::Native(Segment::new(size)));
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_provider_t::from_handle(handle) };
        Z_OK
    })
}

/// The shared body of every `z_shm_provider_alloc*` spelling.
///
/// `blocking` selects upstream's `BlockOn` policy: wait for another thread to
/// release a chunk rather than reporting failure. That is a faithful
/// reproduction and it has upstream's consequence — a SINGLE-threaded program
/// which exhausts its segment and then asks for more waits forever, because the
/// only thread that could free anything is the one now waiting. The
/// non-blocking spellings report `ALLOC_ERROR` instead, which is what a program
/// that cannot tolerate that should call.
///
/// # Safety
/// `out` must be valid and writable; `provider` must be null or a valid loaned
/// provider.
unsafe fn provider_alloc(
    out: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    blocking: bool,
) {
    if out.is_null() {
        return;
    }
    // Write the failure shape FIRST, so every early return below leaves the
    // caller a well-formed result rather than the uninitialised stack struct
    // `z_pub_shm.c` hands in.
    // SAFETY: the caller's contract.
    unsafe {
        (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
        (*out).buf = z_owned_shm_mut_t::null_value();
        (*out).alloc_error = Z_ALLOC_ERROR_OTHER;
        (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
    }
    // SAFETY: the caller's contract.
    let Some(backend) = (unsafe { provider_of(provider) }) else {
        return;
    };
    if alignment.pow >= usize::BITS as u8 {
        // An alignment that does not fit in a `usize` is a LAYOUT error, not an
        // allocation one — upstream splits the two statuses for exactly this.
        // SAFETY: `out` was checked non-null above.
        unsafe {
            (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR;
            (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
        }
        return;
    }
    let align = 1usize << alignment.pow;

    match backend.alloc(size, align, blocking) {
        Ok(chunk) => {
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_OK;
                (*out).buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                (*out).alloc_error = Z_ALLOC_ERROR_OTHER;
                (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
            }
        }
        Err(reason) => {
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
                (*out).alloc_error = reason;
            }
        }
    }
}

/// Claim `size` bytes at `align` out of wz's own segment.
///
/// Split out of [`provider_alloc`] by R2289 so the two backends are two
/// functions rather than two arms inside one — the entry point now decides
/// WHICH allocator runs and nothing else.
fn native_alloc(
    segment: &Arc<Segment>,
    size: usize,
    align: usize,
    blocking: bool,
) -> Result<Box<ShmChunk>, z_alloc_error_t> {
    let mut books = segment.books();
    let start = loop {
        if let Some(start) = books.claim(size, align) {
            break start;
        }
        // A request LARGER than the whole segment can never be satisfied, no
        // matter who releases what, so blocking on it would be the deadlock
        // rather than the wait. Reported as out-of-memory on both policies.
        if size > segment.len || !blocking {
            return Err(if size > segment.len || books.available() < size {
                Z_ALLOC_ERROR_OUT_OF_MEMORY
            } else {
                // Enough total room, but no single range holds it.
                Z_ALLOC_ERROR_NEED_DEFRAGMENT
            });
        }
        books = segment
            .released
            .wait(books)
            .unwrap_or_else(|e| e.into_inner());
    };
    drop(books);
    Ok(Box::new(ShmChunk {
        backing: ChunkBacking::Native {
            segment: segment.clone(),
            start,
        },
        len: size,
        mutable: true,
    }))
}

/// The default alignment upstream's unaligned spellings imply: byte alignment.
const ALIGN_BYTE: z_alloc_alignment_t = z_alloc_alignment_t { pow: 0 };

/// Allocate a buffer (zenoh-c `z_shm_provider_alloc`,
/// `zenoh_commons.h:4647-4649`).
///
/// # Safety
/// `out_result` must be valid and writable; `provider` must be null or a valid
/// loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, false) };
    });
}

/// Allocate an ALIGNED buffer (zenoh-c `z_shm_provider_alloc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, false) };
    });
}

/// Allocate, reclaiming released chunks first (zenoh-c
/// `z_shm_provider_alloc_gc`).
///
/// Identical to [`z_shm_provider_alloc`] here, and that is a property of the
/// allocator rather than a shortcut: a chunk returns to the free list in its
/// own `Drop`, so there is never a released-but-unreclaimed chunk for a garbage
/// collection pass to find. [`z_shm_provider_garbage_collect`] reports 0 for the
/// same reason.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, false) };
    });
}

/// Allocate, reclaiming and defragmenting first (zenoh-c
/// `z_shm_provider_alloc_gc_defrag`).
///
/// Also identical, and for the second half of the same reason: adjacent free
/// ranges coalesce in `Drop`, so the free list is always as defragmented as it
/// can be without moving live chunks — which no allocator may do behind a
/// pointer the C side is holding.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, false) };
    });
}

/// Allocate, reclaiming and defragmenting, and BLOCK rather than fail (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_blocking`, `zenoh_commons.h:4739-4741`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_blocking(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, true) };
    });
}

// ---------------------------------------------------------------------------
// the PRECOMPUTED LAYOUT — R2265 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// A layout BOUND TO A PROVIDER: `(provider, size, alignment)` decided once and
// allocated from many times. `z_memory_layout_t` (R2263) is the unbound half —
// a `(size, alignment)` pair with no provider — and this is what upstream hands
// a program that wants to skip re-deriving the layout on every allocation.
//
// ⛔ `z_owned_alloc_layout_t` IS `z_owned_precomputed_layout_t`. Upstream makes
// the first a `typedef` of the second (`zenoh_opaque.h`), so the twenty-two
// functions the census lists under two family names are ONE type under two
// spellings, and every `z_alloc_layout_*` below delegates to its
// `z_precomputed_layout_*` twin rather than reimplementing it. A reader who
// took the census grouping for two planes would build the same thing twice.
//
// ⚠ The result type is `z_buf_alloc_result_t`, NOT the
// `z_buf_layout_alloc_result_t` the provider entry points fill. That is
// upstream's own distinction and it is load-bearing: a precomputed layout was
// already validated when it was built, so an allocation through it can fail to
// ALLOCATE but can no longer fail to LAYOUT — which is exactly the arm the
// narrower result type drops.

/// What an owned precomputed layout's handle points at.
struct PrecomputedLayoutState {
    /// The BACKEND, not the provider handle: a layout outlives the
    /// `z_owned_shm_provider_t` it was built from (`z_pub_shm.c` relies on it),
    /// so it holds its own reference to the allocator rather than a pointer to
    /// the caller's box.
    provider: Provider,
    size: usize,
    alignment: z_alloc_alignment_t,
}

/// Borrow the state behind a loaned precomputed layout.
///
/// # Safety
/// `this_` must be null or a live loaned layout whose handle this crate minted.
#[inline]
unsafe fn precomputed_state<'a>(
    this_: *const z_loaned_precomputed_layout_t,
) -> Option<&'a PrecomputedLayoutState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<PrecomputedLayoutState>` this module leaked.
    Some(unsafe { &*(handle as *const PrecomputedLayoutState) })
}

/// Build a layout bound to `provider`, shared by all four constructor names.
///
/// # Safety
/// `this_` must be null or writable; `provider` null or a live loaned provider.
unsafe fn precomputed_new(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    if this_.is_null() {
        return Z_ENULL;
    }
    // Gravestone first, so a refusal never leaves the caller's stack value.
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_precomputed_layout_t::null_value() };
    // SAFETY: the caller's contract, delegated.
    let Some(backend) = (unsafe { provider_of(provider) }) else {
        return Z_ENULL;
    };
    // The SAME two refusals `z_memory_layout_new` makes, and for the same
    // reason: a layout is a precondition, so a nonsense one must not become an
    // allocation failure later that cannot say what was wrong.
    if size == 0 || usize::from(alignment.pow) >= usize::BITS as usize {
        return Z_EINVAL;
    }
    let state = PrecomputedLayoutState {
        provider: backend.clone(),
        size,
        alignment,
    };
    let handle = Box::into_raw(Box::new(state)) as Handle;
    // SAFETY: the caller's contract.
    unsafe { *this_ = z_owned_precomputed_layout_t::from_handle(handle) };
    Z_OK
}

/// Allocate through a precomputed layout, shared by all ten alloc spellings.
///
/// # Safety
/// `out_result` must be null or writable; `layout` null or a live loaned layout.
unsafe fn precomputed_alloc(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_precomputed_layout_t,
    blocking: bool,
) {
    if out_result.is_null() {
        return;
    }
    // The failure shape first, as `provider_alloc` does and for the same
    // reason — the C side hands in an uninitialised stack struct.
    // SAFETY: the caller's contract.
    unsafe {
        (*out_result).status = ZC_BUF_ALLOC_STATUS_ALLOC_ERROR;
        (*out_result).buf = z_owned_shm_mut_t::null_value();
        (*out_result).error = Z_ALLOC_ERROR_OTHER;
    }
    // SAFETY: the caller's contract, delegated.
    let Some(state) = (unsafe { precomputed_state(layout) }) else {
        return;
    };
    // Allocate through the PROVIDER path, so there is one allocator and one
    // blocking policy rather than a second copy that could drift from it. The
    // wider result is then narrowed: a layout-error arm cannot be reached from
    // here, because `precomputed_new` refused those inputs when the layout was
    // built.
    let mut wide = z_buf_layout_alloc_result_t {
        status: ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR,
        buf: z_owned_shm_mut_t::null_value(),
        alloc_error: Z_ALLOC_ERROR_OTHER,
        layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
    };
    let provider = z_owned_shm_provider_t::from_handle(provider_handle(state.provider.clone()));
    // SAFETY: `wide` is a live local and `provider` a live owned provider.
    unsafe {
        provider_alloc(
            &mut wide,
            z_shm_provider_loan(&provider),
            state.size,
            state.alignment,
            blocking,
        )
    };
    let mut moved = z_moved_shm_provider_t { _this: provider };
    // SAFETY: dropped exactly once; the segment itself is kept alive by the
    // layout's own `Arc`.
    unsafe { z_shm_provider_drop(&mut moved) };

    if wide.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
        // SAFETY: `out_result` was checked non-null above.
        unsafe {
            (*out_result).status = ZC_BUF_ALLOC_STATUS_OK;
            (*out_result).buf = wide.buf;
        }
    } else {
        // SAFETY: as above.
        unsafe { (*out_result).error = wide.alloc_error };
    }
}

/// Emit one alloc spelling for each of the two family names.
macro_rules! precomputed_alloc_spelling {
    ($precomputed:ident, $alloc_layout:ident, $blocking:expr, $what:literal) => {
        #[doc = concat!("Allocate through a precomputed layout, ", $what, " (zenoh-c `")]
        #[doc = stringify!($precomputed)]
        /// `).
        ///
        /// # Safety
        /// `out_result` must be null or writable; `layout` null or live.
        #[no_mangle]
        pub unsafe extern "C" fn $precomputed(
            out_result: *mut z_buf_alloc_result_t,
            layout: *const z_loaned_precomputed_layout_t,
        ) {
            guard_val((), || {
                // SAFETY: the caller's contract, delegated.
                unsafe { precomputed_alloc(out_result, layout, $blocking) };
            });
        }

        #[doc = concat!("The `alloc_layout` spelling of [`", stringify!($precomputed), "`] (zenoh-c `")]
        #[doc = stringify!($alloc_layout)]
        /// `).
        ///
        /// Upstream typedefs the two layout types together, so this is the same
        /// function under the name the older API used.
        ///
        /// # Safety
        /// As its twin.
        #[no_mangle]
        pub unsafe extern "C" fn $alloc_layout(
            out_result: *mut z_buf_alloc_result_t,
            layout: *const z_loaned_alloc_layout_t,
        ) {
            guard_val((), || {
                // SAFETY: the caller's contract, delegated.
                unsafe { precomputed_alloc(out_result, layout, $blocking) };
            });
        }
    };
}

precomputed_alloc_spelling!(
    z_precomputed_layout_alloc,
    z_alloc_layout_alloc,
    false,
    "failing rather than waiting"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc,
    z_alloc_layout_alloc_gc,
    false,
    "reclaiming first"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag,
    z_alloc_layout_alloc_gc_defrag,
    false,
    "reclaiming and defragmenting"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag_blocking,
    z_alloc_layout_alloc_gc_defrag_blocking,
    true,
    "blocking rather than failing"
);
precomputed_alloc_spelling!(
    z_precomputed_layout_alloc_gc_defrag_dealloc,
    z_alloc_layout_alloc_gc_defrag_dealloc,
    false,
    "with the third reclaim step wz has nothing to take"
);

/// Build a precomputed layout at the provider's default alignment (zenoh-c
/// `z_alloc_layout_new`).
///
/// # Safety
/// `this_` must be null or writable; `provider` null or live.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_new(
    this_: *mut z_owned_alloc_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, ALIGN_BYTE) }
    })
}

/// Build a precomputed layout at the caller's alignment (zenoh-c
/// `z_alloc_layout_with_alignment_new`).
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_with_alignment_new(
    this_: *mut z_owned_alloc_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, alignment) }
    })
}

/// Build a precomputed layout from a provider (zenoh-c
/// `z_shm_provider_alloc_layout`) — the provider-side spelling of
/// [`z_alloc_layout_new`].
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_layout(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, ALIGN_BYTE) }
    })
}

/// The aligned twin of [`z_shm_provider_alloc_layout`] (zenoh-c
/// `z_shm_provider_alloc_layout_aligned`).
///
/// # Safety
/// As [`z_alloc_layout_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_layout_aligned(
    this_: *mut z_owned_precomputed_layout_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_new(this_, provider, size, alignment) }
    })
}

/// Borrow an owned precomputed layout (zenoh-c `z_precomputed_layout_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_loan(
    this_: *const z_owned_precomputed_layout_t,
) -> *const z_loaned_precomputed_layout_t {
    this_.cast()
}

/// The `alloc_layout` spelling of [`z_precomputed_layout_loan`] (zenoh-c
/// `z_alloc_layout_loan`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_loan(
    this_: *const z_owned_alloc_layout_t,
) -> *const z_loaned_alloc_layout_t {
    this_.cast()
}

/// Free a precomputed layout, shared by both drop names.
///
/// # Safety
/// `this_` must be null or a valid moved layout whose handle is live.
#[inline]
unsafe fn precomputed_drop(this_: *mut z_moved_precomputed_layout_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let taken = unsafe {
        std::mem::replace(
            &mut (*this_)._this,
            z_owned_precomputed_layout_t::null_value(),
        )
    };
    if !taken.handle.is_null() {
        // SAFETY: a `Box<PrecomputedLayoutState>` this module leaked, dropped
        // once because the source was gravestoned above.
        drop(unsafe { Box::from_raw(taken.handle as *mut PrecomputedLayoutState) });
    }
}

/// Free a precomputed layout (zenoh-c `z_precomputed_layout_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_drop(this_: *mut z_moved_precomputed_layout_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_drop(this_) };
    });
}

/// The `alloc_layout` spelling of [`z_precomputed_layout_drop`] (zenoh-c
/// `z_alloc_layout_drop`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_drop(this_: *mut z_moved_alloc_layout_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { precomputed_drop(this_) };
    });
}

/// `true` iff the owned layout holds a live handle (zenoh-c
/// `z_internal_precomputed_layout_check`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_internal_precomputed_layout_check(
    this_: *const z_owned_precomputed_layout_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// The `alloc_layout` spelling (zenoh-c `z_internal_alloc_layout_check`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_internal_alloc_layout_check(
    this_: *const z_owned_alloc_layout_t,
) -> bool {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_internal_precomputed_layout_check(this_) }
}

/// Gravestone an owned layout (zenoh-c `z_internal_precomputed_layout_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_precomputed_layout_null(
    this_: *mut z_owned_precomputed_layout_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_precomputed_layout_t::null_value() };
    }
}

/// The `alloc_layout` spelling (zenoh-c `z_internal_alloc_layout_null`).
///
/// # Safety
/// As its twin.
#[no_mangle]
pub unsafe extern "C" fn z_internal_alloc_layout_null(this_: *mut z_owned_alloc_layout_t) {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_internal_precomputed_layout_null(this_) };
}

// --- R2264 (open-debt item 607): the ALIGNED and DEALLOC spellings ----------
//
// Upstream's provider surface is one allocation with three independent axes —
// the reclaim policy (gc / gc+defrag / gc+defrag+dealloc), whether it BLOCKS,
// and whether the caller names an alignment — and it spells every reachable
// combination as its own symbol. wz already had the unaligned column; these
// five are the rest of the grid that needs no machinery wz does not have.
//
// ⛔ THE ALIGNMENT IS NOT DECORATION HERE, and that is why these are not
// aliases of the five above: `provider_alloc` already takes an alignment and
// the existing entry points all pass `ALIGN_BYTE`. Each function below passes
// the CALLER'S, so a program that asks for 64-byte alignment gets it — which
// `z_shm_provider_alloc_aligned` already proved reachable on the non-gc path.
//
// ⚠ `dealloc` is upstream's THIRD reclaim step: when gc and defrag both fail,
// forcibly release the least recently used segment. wz's allocator has nothing
// to force — a chunk returns to the free list in its own `Drop` and adjacent
// ranges coalesce there, so by the time an allocation fails there is nothing
// held that releasing could recover. That makes these two identical to their
// defrag twins HERE, for the same measured reason `alloc_gc` is identical to
// `alloc`, and the doc says so rather than leaving a reader to infer a
// shortcut.

/// Allocate at the caller's alignment, reclaiming first (zenoh-c
/// `z_shm_provider_alloc_gc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, false) };
    });
}

/// Allocate at the caller's alignment, reclaiming and defragmenting (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, false) };
    });
}

/// Allocate at the caller's alignment and BLOCK rather than fail (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_blocking_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_blocking_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, true) };
    });
}

/// Allocate, reclaiming, defragmenting and force-releasing (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_dealloc`).
///
/// Identical to its defrag twin here — see the block comment above for why wz
/// has no third reclaim step to take.
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_dealloc(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, ALIGN_BYTE, false) };
    });
}

/// The aligned twin of [`z_shm_provider_alloc_gc_defrag_dealloc`] (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_dealloc_aligned`).
///
/// # Safety
/// As [`z_shm_provider_alloc`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_dealloc_aligned(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        unsafe { provider_alloc(out_result, provider, size, alignment, false) };
    });
}

/// Bytes still allocatable from this provider (zenoh-c
/// `z_shm_provider_available`).
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_available(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        match unsafe { provider_of(provider) } {
            Some(backend) => backend.available(),
            None => 0,
        }
    })
}

/// Reclaim released chunks (zenoh-c `z_shm_provider_garbage_collect`), reporting
/// how many bytes that freed.
///
/// Always 0 here, and the reason is stated on [`z_shm_provider_alloc_gc`]: this
/// allocator has no deferred-release state to collect.
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_garbage_collect(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // Still dereferenced, so a bad handle is caught here rather than at the
        // next call: a function that ignores its argument would report success
        // for a gravestone provider.
        // SAFETY: the caller's contract.
        let _ = unsafe { provider_of(provider) };
        0
    })
}

/// Defragment the free list (zenoh-c `z_shm_provider_defragment`), reporting the
/// largest range now available.
///
/// # Safety
/// `provider` must be null or a valid loaned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_defragment(
    provider: *const z_loaned_shm_provider_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        match unsafe { provider_of(provider) } {
            Some(backend) => backend.defragment(),
            None => 0,
        }
    })
}

/// Borrow a provider (zenoh-c `z_shm_provider_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_loan(
    this_: *const z_owned_shm_provider_t,
) -> *const z_loaned_shm_provider_t {
    this_ as *const z_loaned_shm_provider_t
}

// R311y568 — REMOVED: z_shm_provider_loan_mut.
//
// Upstream declares no such function on EITHER arm (0 hits across every header
// in both oracles), so wz was exporting a `z_`-prefixed symbol that is not part
// of the zenoh-c ABI. Nothing in the tree called it and no C program compiled
// against upstream's header could name it; what it did was make wz's exported
// surface a superset of the reference's, which is a different library wearing
// the same names. Found by the census's REVERSE direction, added the same round
// — the forward ratchet had been green over it since the plane landed.

/// Drop a provider (zenoh-c `z_shm_provider_drop`).
///
/// Buffers still outstanding keep the segment alive — they hold their own `Arc`
/// — which is what makes `z_pub_shm.c`'s teardown order safe.
///
/// # Safety
/// `this_` must be null or a valid moved provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_drop(this_: *mut z_moved_shm_provider_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Provider>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut Provider) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_provider_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned provider (zenoh-c `z_internal_shm_provider_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_provider_null(this_: *mut z_owned_shm_provider_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
    }
}

/// `true` iff the owned provider holds a live handle (zenoh-c
/// `z_internal_shm_provider_check`).
///
/// # Safety
/// `this_` must be null or a valid owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_provider_check(
    this_: *const z_owned_shm_provider_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the MEMORY LAYOUT — R2263 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// A `(size, alignment)` pair, and nothing else. It is the most self-contained
// of the eighty-four symbols item 607 covers: no provider, no segment, no
// allocation — which is why this round takes it whole and leaves the layout
// family that DOES allocate (`z_alloc_layout_*` / `z_precomputed_layout_*`,
// which upstream makes ALIASES of one type) to a round that can witness an
// allocation end to end.
//
// ⚠ The C type is 16 bytes at align 8 and holds a `usize` plus a byte, so wz
// stores its state behind the same handle every sibling here uses rather than
// packing the two inline. The alternative would make this the one type in the
// module whose loan is not a pointer cast.

/// What an owned memory layout's handle points at.
struct MemoryLayoutState {
    size: usize,
    alignment: z_alloc_alignment_t,
}

/// Borrow the state behind a loaned memory layout.
///
/// # Safety
/// `this_` must be null or a live loaned layout whose handle this crate minted.
#[inline]
unsafe fn memory_layout_state<'a>(
    this_: *const z_loaned_memory_layout_t,
) -> Option<&'a MemoryLayoutState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<MemoryLayoutState>` this module leaked.
    Some(unsafe { &*(handle as *const MemoryLayoutState) })
}

/// Construct a memory layout (zenoh-c `z_memory_layout_new`).
///
/// ⛔ REFUSES a zero size and a non-power-of-two alignment, which upstream also
/// refuses — its `AllocLayout::new` returns a `LayoutError` for both. A layout
/// is a PRECONDITION for an allocation, so accepting a nonsense one here would
/// move the failure to a later call that cannot explain it.
///
/// `z_alloc_alignment_t` carries a power-of-two EXPONENT rather than the
/// alignment itself, so every representable value is already a power of two;
/// what is refused is an exponent so large that `1 << pow` does not fit a
/// `usize`, which is the same boundary upstream's `AllocAlignment` checks.
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_new(
    this_: *mut z_owned_memory_layout_t,
    size: usize,
    alignment: z_alloc_alignment_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // Written before the checks so a refused layout leaves a gravestone
        // rather than the caller's uninitialised stack value.
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::null_value() };
        if size == 0 {
            return Z_EINVAL;
        }
        if usize::from(alignment.pow) >= usize::BITS as usize {
            return Z_EINVAL;
        }
        let state = MemoryLayoutState { size, alignment };
        let handle = Box::into_raw(Box::new(state)) as Handle;
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::from_handle(handle) };
        Z_OK
    })
}

/// Read a layout's `(size, alignment)` back (zenoh-c `z_memory_layout_get_data`).
///
/// Both outputs are written independently, so a caller that wants one passes
/// NULL for the other — upstream's signature takes two pointers and says
/// nothing about them being required together.
///
/// # Safety
/// `this_` must be null or a live loaned layout; each output must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_get_data(
    this_: *const z_loaned_memory_layout_t,
    out_size: *mut usize,
    out_alignment: *mut z_alloc_alignment_t,
) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        let Some(state) = (unsafe { memory_layout_state(this_) }) else {
            return;
        };
        if !out_size.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_size = state.size };
        }
        if !out_alignment.is_null() {
            // SAFETY: as above.
            unsafe { *out_alignment = state.alignment };
        }
    });
}

/// Borrow an owned memory layout (zenoh-c `z_memory_layout_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_loan(
    this_: *const z_owned_memory_layout_t,
) -> *const z_loaned_memory_layout_t {
    this_.cast()
}

/// Free a memory layout (zenoh-c `z_memory_layout_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved layout whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_memory_layout_drop(this_: *mut z_moved_memory_layout_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(&mut (*this_)._this, z_owned_memory_layout_t::null_value())
        };
        if !taken.handle.is_null() {
            // SAFETY: a `Box<MemoryLayoutState>` this module leaked, dropped
            // once because the source was gravestoned above.
            drop(unsafe { Box::from_raw(taken.handle as *mut MemoryLayoutState) });
        }
    });
}

/// Gravestone an owned memory layout (zenoh-c `z_internal_memory_layout_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_memory_layout_null(this_: *mut z_owned_memory_layout_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_memory_layout_t::null_value() };
    }
}

/// `true` iff the owned layout holds a live handle (zenoh-c
/// `z_internal_memory_layout_check`).
///
/// # Safety
/// `this_` must be null or a valid owned layout.
#[no_mangle]
pub unsafe extern "C" fn z_internal_memory_layout_check(
    this_: *const z_owned_memory_layout_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the MUTABLE buffer
// ---------------------------------------------------------------------------

/// A mutable buffer's bytes (zenoh-c `z_shm_mut_data_mut`,
/// `zenoh_commons.h:4591`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutable buffer. The returned pointer
/// is valid for `z_shm_mut_len` bytes and for as long as the buffer is.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_data_mut(this_: *mut z_loaned_shm_mut_t) -> *mut u8 {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_mut_ptr(),
            None => std::ptr::null_mut(),
        }
    })
}

/// A mutable buffer's bytes, read-only (zenoh-c `z_shm_mut_data`).
///
/// # Safety
/// As [`z_shm_mut_data_mut`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_data(this_: *const z_loaned_shm_mut_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_slice().as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// A mutable buffer's length (zenoh-c `z_shm_mut_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_len(this_: *const z_loaned_shm_mut_t) -> usize {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { chunk((*this_).handle) }.map_or(0, |c| c.len)
    })
}

/// Borrow a mutable buffer (zenoh-c `z_shm_mut_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_loan(
    this_: *const z_owned_shm_mut_t,
) -> *const z_loaned_shm_mut_t {
    this_ as *const z_loaned_shm_mut_t
}

/// Mutably borrow a mutable buffer (zenoh-c `z_shm_mut_loan_mut`,
/// `zenoh_commons.h:4623`).
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_loan_mut(
    this_: *mut z_owned_shm_mut_t,
) -> *mut z_loaned_shm_mut_t {
    this_ as *mut z_loaned_shm_mut_t
}

/// Drop a mutable buffer (zenoh-c `z_shm_mut_drop`), returning its range to the
/// segment.
///
/// # Safety
/// `this_` must be null or a valid moved mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_mut_drop(this_: *mut z_moved_shm_mut_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ShmChunk>` this crate leaked; its `Drop`
            // releases the range and wakes any blocked allocation.
            drop(unsafe { Box::from_raw(handle as *mut ShmChunk) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_mut_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned mutable buffer (zenoh-c `z_internal_shm_mut_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_mut_null(this_: *mut z_owned_shm_mut_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_mut_t::null_value() };
    }
}

/// `true` iff the owned mutable buffer holds a live handle.
///
/// # Safety
/// `this_` must be null or a valid owned mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_mut_check(this_: *const z_owned_shm_mut_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

// ---------------------------------------------------------------------------
// the IMMUTABLE buffer
// ---------------------------------------------------------------------------

/// Freeze a mutable buffer into an immutable one (zenoh-c `z_shm_from_mut`,
/// `zenoh_commons.h:4550-4551`). The source is consumed.
///
/// The chunk itself does not move; only its `mutable` flag is cleared, which is
/// what makes [`z_shm_try_reloan_mut`] answer "no" afterwards. Upstream's
/// freeze is the same shape — the point of it is to permit reference copies,
/// not to relocate bytes.
///
/// # Safety
/// `this_` must be valid and writable; `that` must be null or a valid moved
/// mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_from_mut(this_: *mut z_owned_shm_t, that: *mut z_moved_shm_mut_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_t::null_value() };
        if that.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*that)._this.handle };
        // SAFETY: the caller's contract — consumed on every path, so the source
        // is nulled whether or not it carried a live chunk.
        unsafe { (*that)._this = z_owned_shm_mut_t::null_value() };
        if handle.is_null() {
            return;
        }
        // SAFETY: a live `Box<ShmChunk>` this crate leaked; taken and re-leaked
        // rather than dropped, so the range is not released here.
        let mut boxed = unsafe { Box::from_raw(handle as *mut ShmChunk) };
        boxed.mutable = false;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_shm_t::from_handle(Box::into_raw(boxed) as Handle) };
    });
}

/// An immutable buffer's bytes (zenoh-c `z_shm_data`).
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_data(this_: *const z_loaned_shm_t) -> *const u8 {
    guard_val(std::ptr::null(), || {
        if this_.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            Some(c) => c.as_slice().as_ptr(),
            None => std::ptr::null(),
        }
    })
}

/// An immutable buffer's length (zenoh-c `z_shm_len`).
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_len(this_: *const z_loaned_shm_t) -> usize {
    guard_val(0, || {
        if this_.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        unsafe { chunk((*this_).handle) }.map_or(0, |c| c.len)
    })
}

/// Borrow an immutable buffer (zenoh-c `z_shm_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_loan(this_: *const z_owned_shm_t) -> *const z_loaned_shm_t {
    this_ as *const z_loaned_shm_t
}

/// Mutably borrow an immutable buffer (zenoh-c `z_shm_loan_mut`) — the borrow is
/// mutable, the buffer's frozen status is not.
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_loan_mut(this_: *mut z_owned_shm_t) -> *mut z_loaned_shm_t {
    this_ as *mut z_loaned_shm_t
}

/// Try to recover MUTABLE access to a borrowed buffer (zenoh-c
/// `z_shm_try_reloan_mut`, `zenoh_commons.h:4871`).
///
/// NULL when the buffer has been frozen by [`z_shm_from_mut`] or when it came
/// off the wire, which is what `z_sub_shm.c` distinguishes `SHM (MUT)` from
/// `SHM (IMMUT)` by.
///
/// # Safety
/// `this_` must be null or a valid loaned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_try_reloan_mut(
    this_: *mut z_loaned_shm_t,
) -> *mut z_loaned_shm_mut_t {
    guard_val(std::ptr::null_mut(), || {
        if this_.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: the caller's contract.
        match unsafe { chunk((*this_).handle) } {
            // The two loaned types have identical layout and identical handle
            // contents, so the recovery is a cast — see `chunk`.
            Some(c) if c.mutable => this_ as *mut z_loaned_shm_mut_t,
            _ => std::ptr::null_mut(),
        }
    })
}

/// Try to recover MUTABLE access to an OWNED buffer (zenoh-c `z_shm_try_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_try_mut(this_: *mut z_owned_shm_t) -> *mut z_loaned_shm_mut_t {
    // SAFETY: the caller's contract, delegated — the owned and loaned forms have
    // the same layout, which is what `z_shm_loan_mut` already relies on.
    unsafe { z_shm_try_reloan_mut(this_ as *mut z_loaned_shm_t) }
}

/// Drop an immutable buffer (zenoh-c `z_shm_drop`, `zenoh_commons.h:4542`).
///
/// # Safety
/// `this_` must be null or a valid moved buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_drop(this_: *mut z_moved_shm_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ShmChunk>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut ShmChunk) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_shm_t::null_value() };
        }
        Z_OK
    });
}

/// Zero an owned buffer (zenoh-c `z_internal_shm_null`).
///
/// # Safety
/// `this_` must be null or a valid, writable owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_null(this_: *mut z_owned_shm_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_t::null_value() };
    }
}

/// `true` iff the owned buffer holds a live handle (zenoh-c
/// `z_internal_shm_check`).
///
/// # Safety
/// `this_` must be null or a valid owned buffer.
#[no_mangle]
pub unsafe extern "C" fn z_internal_shm_check(this_: *const z_owned_shm_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Copy an immutable buffer into a NEW chunk of the same segment (zenoh-c
/// `z_shm_clone`).
///
/// Upstream's clone is a reference copy, which it can afford because its buffers
/// are reference-counted inside the segment. Here a clone allocates and copies,
/// so the two agree on what the result CONTAINS and differ on how much of the
/// segment it costs — a difference `z_shm_provider_available` reports honestly.
/// The out value is a gravestone when the segment cannot satisfy the
/// allocation, which upstream's cannot produce; no example in the corpus calls
/// this.
///
/// # Safety
/// `out` must be valid and writable; `this_` must be null or a valid loaned
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn z_shm_clone(out: *mut z_owned_shm_t, this_: *const z_loaned_shm_t) {
    guard_val((), || {
        if out.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = z_owned_shm_t::null_value() };
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let Some(source) = (unsafe { chunk((*this_).handle) }) else {
            return;
        };
        // Through the SAME allocator the source came out of, so a foreign
        // backend's copy is its own memory rather than a range of a segment wz
        // would then try to free through the wrong route.
        let Ok(mut copy) = source.provider().alloc(source.len, 1, false) else {
            return;
        };
        copy.mutable = false;
        // SAFETY: both ranges are live and, being distinct allocator ranges, do
        // not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(source.as_slice().as_ptr(), copy.as_mut_ptr(), copy.len)
        };
        // SAFETY: `out` was checked non-null above.
        unsafe { *out = z_owned_shm_t::from_handle(Box::into_raw(copy) as Handle) };
    });
}

// ---------------------------------------------------------------------------
// the bytes bridge
// ---------------------------------------------------------------------------

/// Build a payload from an immutable SHM buffer (zenoh-c `z_bytes_from_shm`,
/// `zenoh_commons.h:1531-1532`). The buffer is consumed.
///
/// The bytes are COPIED into an ordinary payload and the chunk returns to its
/// segment. That is what makes `z_pub_shm.c`'s forever-loop work on a
/// 4096-byte provider, and it costs nothing observable while wz negotiates no
/// SHM transport: the put would serialise the same bytes anyway. See the module
/// note for the named consequence.
///
/// # Safety
/// `this_` must be valid and writable; `shm` must be null or a valid moved
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_shm(
    this_: *mut z_owned_bytes_t,
    shm: *mut z_moved_shm_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_bytes_t::null_value() };
        if shm.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*shm)._this.handle };
        // SAFETY: consumed on every path.
        unsafe { (*shm)._this = z_owned_shm_t::null_value() };
        if handle.is_null() {
            return Z_ENULL;
        }
        // SAFETY: a live `Box<ShmChunk>`; dropped at the end of this scope,
        // which releases the range.
        let boxed = unsafe { Box::from_raw(handle as *mut ShmChunk) };
        let payload = boxed.as_slice().to_vec();
        drop(boxed);
        let state = Box::into_raw(Box::new(BytesState::whole(payload))) as Handle;
        // SAFETY: `this_` was checked non-null above.
        unsafe { *this_ = z_owned_bytes_t::from_handle(state) };
        Z_OK
    })
}

/// Build a payload from a MUTABLE SHM buffer (zenoh-c `z_bytes_from_shm_mut`,
/// `zenoh_commons.h:1540-1541`). The buffer is consumed.
///
/// # Safety
/// `this_` must be valid and writable; `shm` must be null or a valid moved
/// mutable buffer.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_shm_mut(
    this_: *mut z_owned_bytes_t,
    shm: *mut z_moved_shm_mut_t,
) -> ZResult {
    // The two moved types have identical layout and identical handle contents,
    // so the mutable spelling is the immutable one with a cast rather than a
    // second copy of the body.
    // SAFETY: the caller's contract, delegated.
    unsafe { z_bytes_from_shm(this_, shm as *mut z_moved_shm_t) }
}

/// Try to view a payload as an immutable SHM buffer (zenoh-c
/// `z_bytes_as_loaned_shm`, `zenoh_commons.h:1452-1453`).
///
/// Always `Z_EINVAL` with `*dst` left NULL, and that is the TRUE answer rather
/// than an unimplemented one: wz's transport negotiates no SHM segment, so no
/// payload a wz session produces or receives is backed by one. The module note
/// states the re-open trigger.
///
/// # Safety
/// `this_` must be null or a valid loaned payload; `dst` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_as_loaned_shm(
    this_: *const z_loaned_bytes_t,
    dst: *mut *const z_loaned_shm_t,
) -> ZResult {
    guarded(|| {
        if !dst.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = std::ptr::null() };
        }
        // Dereferenced so a gravestone payload is distinguished from a live one
        // that merely carries no SHM: a function that ignored its argument would
        // give the same answer for a null pointer.
        // SAFETY: the caller's contract.
        if unsafe { bytes_slice(this_) }.is_none() {
            return Z_ENULL;
        }
        Z_EINVAL
    })
}

/// Try to view a payload as a MUTABLE SHM buffer (zenoh-c
/// `z_bytes_as_mut_loaned_shm`, `zenoh_commons.h:1464-1465`).
///
/// # Safety
/// As [`z_bytes_as_loaned_shm`].
#[no_mangle]
pub unsafe extern "C" fn z_bytes_as_mut_loaned_shm(
    this_: *mut z_loaned_bytes_t,
    dst: *mut *mut z_loaned_shm_t,
) -> ZResult {
    guarded(|| {
        if !dst.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *dst = std::ptr::null_mut() };
        }
        // SAFETY: the caller's contract.
        if unsafe { bytes_slice(this_ as *const z_loaned_bytes_t) }.is_none() {
            return Z_ENULL;
        }
        Z_EINVAL
    })
}

// ---------------------------------------------------------------------------
// the C-SUPPLIED BACKEND — R2289 (open-debt item 607)
// ---------------------------------------------------------------------------
//
// Everything above answers "wz owns a segment and hands pieces of it out". This
// section answers the other half of upstream's provider surface: a C program
// supplies the allocator, and zenoh-c calls INTO it. The plane is taken whole
// rather than a verb at a time, for R2259's reason — the value types
// (`z_ptr_in_segment_t`, `z_chunk_alloc_result_t`) exist ONLY to cross the
// callback boundary, so shipping them without `z_shm_provider_new` would leave
// a header promising a link that goes nowhere.
//
// What the plane is, and why these twenty symbols are one thing:
//
//   * `zc_context_t` / `zc_threadsafe_context_t` — the C-owned state every
//     callback is handed back, with the destructor wz owes it. NOT symbols;
//     they are the reason the rest could not be built before.
//   * `z_ptr_in_segment_*` (6) — a pointer plus the segment context that keeps
//     it valid. Upstream's is `(*mut u8, Arc<dyn Segment>)`, so a clone SHARES
//     the segment and the destructor fires once; wz's is the same shape.
//   * `z_chunk_alloc_result_*` (5) — what `alloc_fn` writes: an allocated chunk
//     or an alloc error. The one type the callback returns.
//   * `z_shm_provider_new` / `_threadsafe_new` / `_map` (3) — install a backend,
//     and hand a chunk it allocated back as a buffer.
//   * `z_posix_shm_provider_new` / `_with_layout_new` (2) — upstream's named
//     spellings of the BUILT-IN backend, the second sized by a memory layout.
//   * the four `_async` spellings — the only place the threadsafe / not
//     distinction is OBSERVABLE, which is why they are in this round and not a
//     later one. Without them `z_shm_provider_new` and
//     `z_shm_provider_threadsafe_new` would differ only in a flag nothing reads,
//     and a stored-but-unread flag is a dead arm.
//
// ⚠ THREE named divergences from upstream, each of them a deliberate strictening
// rather than a shortcut, and each witnessed by a test in `foreign_backend_tests`:
//
//   1. wz gravestones the `z_owned_chunk_alloc_result_t` BEFORE calling
//      `alloc_fn`. Upstream passes `MaybeUninit` and calls `assume_init()`, so a
//      callback that writes nothing has it reading uninitialised memory; here it
//      reads a gravestone and the allocation fails cleanly.
//   2. A BLOCKING allocation against a foreign backend that has NOTHING
//      outstanding fails instead of waiting. Upstream's `BlockOn` waits for a
//      buffer release that, with no live buffer, can never come — a deadlock
//      rather than a wait. wz keeps the count that makes the difference sayable.
//   3. The `_async` spellings CLONE the provider (an `Arc` bump) rather than
//      requiring the `&'static` upstream's signature demands, so a caller that
//      drops the provider handle while the allocation is in flight is not a
//      use-after-free.

/// zenoh-c `z_segment_id_t` (`zenoh_opaque.h:290`).
pub type z_segment_id_t = u32;
/// zenoh-c `z_chunk_id_t` (`zenoh_opaque.h:297`).
pub type z_chunk_id_t = u32;
/// zenoh-c `z_protocol_id_t` (`zenoh_opaque.h:910`).
pub type z_protocol_id_t = u32;

/// zenoh-c `zc_context_t` (`zenoh_opaque.h:975-978`) — a C-owned pointer and the
/// destructor wz must run for it.
///
/// The NON-thread-safe spelling: upstream's own header promises that callbacks
/// sharing one instance are never executed concurrently, which is why
/// [`ForeignBackend`] serialises them.
#[repr(C)]
pub struct zc_context_t {
    /// The caller's state, handed back to every callback.
    pub context: *mut c_void,
    /// Run once, when the last holder of this context drops.
    pub delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// zenoh-c `zc_threadsafe_context_data_t` (`zenoh_opaque.h:157-159`).
///
/// A one-field struct rather than a bare pointer because upstream nests it, and
/// the nesting is what makes `zc_threadsafe_context_t` a different C type from
/// `zc_context_t` at the same size.
#[repr(C)]
pub struct zc_threadsafe_context_data_t {
    /// The caller's state.
    pub ptr: *mut c_void,
}

/// zenoh-c `zc_threadsafe_context_t` (`zenoh_opaque.h:177-180`).
///
/// The caller PROMISES the associated callbacks are thread-safe, and that
/// promise is the only difference between [`z_shm_provider_new`] and
/// [`z_shm_provider_threadsafe_new`] — see [`Provider::is_threadsafe`] for what
/// reads it.
#[repr(C)]
pub struct zc_threadsafe_context_t {
    /// The caller's state.
    pub context: zc_threadsafe_context_data_t,
    /// Run once, when the last holder of this context drops.
    pub delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// zenoh-c `z_chunk_descriptor_t` (`zenoh_opaque.h`) — how a backend NAMES one
/// of its chunks.
///
/// `free_fn` is handed this rather than the pointer, so it is the part a chunk
/// must carry for its whole life.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_chunk_descriptor_t {
    /// Which of the backend's segments.
    pub segment: z_segment_id_t,
    /// Which chunk within it.
    pub chunk: z_chunk_id_t,
    /// The chunk's capacity in bytes.
    pub len: usize,
}

/// zenoh-c `z_allocated_chunk_t` (`zenoh_opaque.h:322-325`).
///
/// ⚠ `descriptpr` is upstream's spelling, typo and all. It is kept because a
/// reader diffing this file against `zenoh_opaque.h` must see the same field
/// name; the name crosses no ABI boundary, so correcting it here would buy
/// nothing and cost that.
#[repr(C)]
pub struct z_allocated_chunk_t {
    /// How the backend names this chunk.
    pub descriptpr: z_chunk_descriptor_t,
    /// The pointer, MOVED: taking a chunk gravestones the caller's value.
    pub ptr: *mut z_moved_ptr_in_segment_t,
}

/// zenoh-c `zc_shm_provider_backend_callbacks_t` — the whole allocator, as six
/// function pointers.
///
/// Mirrored field for field and in upstream's order: this struct is passed BY
/// VALUE across the ABI, so a reordering here is a wild call rather than a
/// compile error. `wz_capi_c_layout` carries its footprint for that reason.
#[repr(C)]
pub struct zc_shm_provider_backend_callbacks_t {
    /// Allocate for `layout`, writing an owned result.
    pub alloc_fn: Option<
        unsafe extern "C" fn(
            *mut z_owned_chunk_alloc_result_t,
            *const z_loaned_memory_layout_t,
            *mut c_void,
        ),
    >,
    /// Release a chunk this backend allocated.
    pub free_fn: Option<unsafe extern "C" fn(*const z_chunk_descriptor_t, *mut c_void)>,
    /// Defragment, reporting what that made reachable.
    pub defragment_fn: Option<unsafe extern "C" fn(*mut c_void) -> usize>,
    /// Bytes still allocatable.
    pub available_fn: Option<unsafe extern "C" fn(*mut c_void) -> usize>,
    /// Adjust a layout in place to one this backend can serve.
    pub layout_for_fn: Option<unsafe extern "C" fn(*mut z_owned_memory_layout_t, *mut c_void)>,
    /// This backend's SHM protocol id.
    pub id_fn: Option<unsafe extern "C" fn(*mut c_void) -> z_protocol_id_t>,
}

/// zenoh-c `z_owned_ptr_in_segment_t` (`zenoh_opaque.h:314-316`): 24 bytes at
/// align 8 — upstream stores a pointer plus a fat `Arc<dyn Segment>`.
const PTR_IN_SEGMENT_SIZE: usize = 24;

define_shm_opaque!(
    z_owned_ptr_in_segment_t,
    z_loaned_ptr_in_segment_t,
    z_moved_ptr_in_segment_t,
    PTR_IN_SEGMENT_SIZE
);

/// zenoh-c `z_owned_chunk_alloc_result_t` (`zenoh_opaque.h`): 48 bytes at
/// align 8.
const CHUNK_ALLOC_RESULT_SIZE: usize = 48;

define_shm_opaque!(
    z_owned_chunk_alloc_result_t,
    z_moved_chunk_alloc_result_t,
    CHUNK_ALLOC_RESULT_SIZE
);

/// A C-owned context and the destructor wz owes it.
///
/// One type for both spellings: `zc_context_t` and `zc_threadsafe_context_t`
/// differ in what the CALLER promises, not in what wz has to store, and the
/// promise is recorded separately (see [`ForeignBackend::threadsafe`]) so this
/// stays one destructor and one place that runs it.
struct DroppableContext {
    ptr: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}

impl Drop for DroppableContext {
    fn drop(&mut self) {
        if let Some(delete_fn) = self.delete_fn {
            // SAFETY: the caller handed this pair over together and upstream's
            // header states the contract — `delete_fn` runs once, after the last
            // associated callback returns. Holding the context behind an `Arc`
            // is what makes "the last" well defined here.
            unsafe { delete_fn(self.ptr) };
        }
    }
}

// SAFETY: the pointer is opaque to wz; it is only ever handed back to the
// caller's own callbacks. Whether those may run on another thread is the
// caller's promise, recorded in `ForeignBackend::threadsafe` and enforced there
// by serialising when the promise was not made.
unsafe impl Send for DroppableContext {}
// SAFETY: as above.
unsafe impl Sync for DroppableContext {}

/// What an owned `z_owned_ptr_in_segment_t`'s handle points at.
///
/// The context is `Arc`-shared, which is the whole content of
/// [`z_ptr_in_segment_clone`] being a SHALLOW copy: two pointers into one
/// segment, and the segment released once when the second of them goes.
struct PtrInSegment {
    ptr: *mut u8,
    /// Kept for its `Drop`, not for reading.
    _segment: Arc<DroppableContext>,
}

impl PtrInSegment {
    /// A shallow copy: the same address, one more owner of the segment.
    fn shallow_clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            _segment: self._segment.clone(),
        }
    }
}

/// What an owned `z_owned_chunk_alloc_result_t`'s handle points at: upstream's
/// `Result<AllocatedChunk, ZAllocError>`.
enum ChunkAllocResult {
    /// The backend allocated a chunk.
    Ok {
        descriptor: z_chunk_descriptor_t,
        ptr: PtrInSegment,
    },
    /// The backend could not, and said why.
    Err(z_alloc_error_t),
}

/// A backend the C caller supplied, and the book-keeping wz keeps around it.
struct ForeignBackend {
    context: Arc<DroppableContext>,
    callbacks: zc_shm_provider_backend_callbacks_t,
    /// `true` when the caller used [`z_shm_provider_threadsafe_new`].
    threadsafe: bool,
    /// Held across every callback when `threadsafe` is false.
    ///
    /// Upstream keeps the same promise a different way — its non-threadsafe
    /// provider is `!Sync`, so RUST cannot share it — which does not reach a C
    /// caller with two threads and one `z_loaned_shm_provider_t`. wz's callbacks
    /// are reachable from C on any thread, so the promise the header prints is
    /// kept here by holding this.
    serialise: Mutex<()>,
    /// Chunks this backend has issued and not yet had freed.
    ///
    /// Read for ONE decision: whether a blocking allocation has anything to wait
    /// for. See divergence 2 in this section's banner.
    live: Mutex<usize>,
    /// Signalled by [`ForeignBackend::free`].
    released: Condvar,
}

impl ForeignBackend {
    /// Run `f` with the caller's context pointer, serialised when the caller did
    /// not promise thread safety.
    fn with_context<T>(&self, f: impl FnOnce(*mut c_void) -> T) -> T {
        if self.threadsafe {
            f(self.context.ptr)
        } else {
            let _guard = self.serialise.lock().unwrap_or_else(|e| e.into_inner());
            f(self.context.ptr)
        }
    }

    /// One call into `alloc_fn`, with the result decoded.
    fn try_alloc(
        self: &Arc<Self>,
        size: usize,
        align: usize,
    ) -> Result<Box<ShmChunk>, z_alloc_error_t> {
        let Some(alloc_fn) = self.callbacks.alloc_fn else {
            return Err(Z_ALLOC_ERROR_OTHER);
        };
        let layout =
            z_owned_memory_layout_t::from_handle(Box::into_raw(Box::new(MemoryLayoutState {
                size,
                alignment: z_alloc_alignment_t {
                    pow: align.trailing_zeros() as u8,
                },
            })) as Handle);
        // Divergence 1: a GRAVESTONE, not `MaybeUninit`. A callback that writes
        // nothing then leaves a readable "no result" rather than whatever was on
        // the stack.
        let mut out = z_owned_chunk_alloc_result_t::null_value();
        self.with_context(|ctx| {
            // SAFETY: `out` and `layout` are live locals this frame owns, and
            // `ctx` is the caller's own pointer.
            unsafe {
                alloc_fn(
                    &mut out,
                    &layout as *const z_owned_memory_layout_t as *const z_loaned_memory_layout_t,
                    ctx,
                )
            }
        });
        let mut moved_layout = z_moved_memory_layout_t { _this: layout };
        // SAFETY: dropped exactly once; the callback borrowed it and does not
        // own it, which is what `_loaned_` says.
        unsafe { z_memory_layout_drop(&mut moved_layout) };

        let handle = out.handle;
        out = z_owned_chunk_alloc_result_t::null_value();
        let _ = out;
        if handle.is_null() {
            return Err(Z_ALLOC_ERROR_OTHER);
        }
        // SAFETY: a live `Box<ChunkAllocResult>` minted by this module's own
        // constructors, which are the only way a callback can fill this out.
        let result = unsafe { Box::from_raw(handle as *mut ChunkAllocResult) };
        let (descriptor, ptr) = match *result {
            ChunkAllocResult::Ok { descriptor, ptr } => (descriptor, ptr),
            ChunkAllocResult::Err(reason) => return Err(reason),
        };
        if descriptor.len < size || ptr.ptr.is_null() {
            // The backend said OK and delivered less than was asked for, or
            // nothing. Reported rather than trusted: the buffer plane hands this
            // pointer and length straight to the caller.
            self.free(&descriptor);
            return Err(Z_ALLOC_ERROR_OTHER);
        }
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        Ok(Box::new(ShmChunk {
            backing: ChunkBacking::Foreign {
                backend: self.clone(),
                descriptor,
                ptr,
            },
            len: size,
            mutable: true,
        }))
    }

    /// Allocate, retrying while a blocking caller still has something
    /// outstanding that could be released.
    fn alloc(
        self: &Arc<Self>,
        size: usize,
        align: usize,
        blocking: bool,
    ) -> Result<Box<ShmChunk>, z_alloc_error_t> {
        loop {
            let reason = match self.try_alloc(size, align) {
                Ok(chunk) => return Ok(chunk),
                Err(reason) => reason,
            };
            if !blocking {
                return Err(reason);
            }
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            // Divergence 2: with nothing outstanding, no release can ever come,
            // so waiting would be a deadlock rather than a wait.
            if *live == 0 {
                return Err(reason);
            }
            drop(self.released.wait(live).unwrap_or_else(|e| e.into_inner()));
        }
    }

    /// Hand a chunk back to the backend that issued it.
    fn free(&self, descriptor: &z_chunk_descriptor_t) {
        if let Some(free_fn) = self.callbacks.free_fn {
            // SAFETY: the descriptor is a live local and `ctx` the caller's own
            // pointer.
            self.with_context(|ctx| unsafe { free_fn(descriptor, ctx) });
        }
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        *live = live.saturating_sub(1);
        drop(live);
        self.released.notify_all();
    }

    /// `available_fn`, or 0 when the caller supplied none.
    fn available(&self) -> usize {
        match self.callbacks.available_fn {
            // SAFETY: `ctx` is the caller's own pointer.
            Some(f) => self.with_context(|ctx| unsafe { f(ctx) }),
            None => 0,
        }
    }

    /// `defragment_fn`, or 0 when the caller supplied none.
    fn defragment(&self) -> usize {
        match self.callbacks.defragment_fn {
            // SAFETY: `ctx` is the caller's own pointer.
            Some(f) => self.with_context(|ctx| unsafe { f(ctx) }),
            None => 0,
        }
    }
}

/// Borrow the state behind a loaned pointer-in-segment.
///
/// # Safety
/// `this_` must be null or a live loaned value whose handle this crate minted.
#[inline]
unsafe fn ptr_in_segment<'a>(this_: *const z_loaned_ptr_in_segment_t) -> Option<&'a PtrInSegment> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<PtrInSegment>` this module leaked.
    Some(unsafe { &*(handle as *const PtrInSegment) })
}

/// Construct a pointer in an SHM segment (zenoh-c `z_ptr_in_segment_new`,
/// `zenoh_commons.h:4911-4915`). The context is CONSUMED.
///
/// # Safety
/// `this_` must be null or writable. `ptr` is the caller's, and `segment` names
/// state whose `delete_fn` wz runs once the last copy of this value is gone.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_new(
    this_: *mut z_owned_ptr_in_segment_t,
    ptr: *mut u8,
    segment: zc_threadsafe_context_t,
) {
    let context = Arc::new(DroppableContext {
        ptr: segment.context.ptr,
        delete_fn: segment.delete_fn,
    });
    guard_val((), || {
        if this_.is_null() {
            // The context is still consumed — it was passed by value, so
            // returning without dropping it would leak the caller's state with
            // no way to reach it again.
            return;
        }
        let state = PtrInSegment {
            ptr,
            _segment: context,
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ = z_owned_ptr_in_segment_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
    });
}

/// Zero an owned pointer-in-segment (zenoh-c
/// `z_internal_ptr_in_segment_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_ptr_in_segment_null(this_: *mut z_owned_ptr_in_segment_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_ptr_in_segment_t::null_value() };
    }
}

/// `true` iff the value holds a live pointer (zenoh-c
/// `z_internal_ptr_in_segment_check`).
///
/// # Safety
/// `this_` must be null or a valid owned value.
#[no_mangle]
pub unsafe extern "C" fn z_internal_ptr_in_segment_check(
    this_: *const z_owned_ptr_in_segment_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Borrow a pointer-in-segment (zenoh-c `z_ptr_in_segment_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_loan(
    this_: *const z_owned_ptr_in_segment_t,
) -> *const z_loaned_ptr_in_segment_t {
    this_ as *const z_loaned_ptr_in_segment_t
}

/// SHALLOW-copy a pointer-in-segment (zenoh-c `z_ptr_in_segment_clone`).
///
/// The copy is the SAME address with one more owner of the segment, which is
/// what upstream's `Arc<dyn Segment>` gives and what makes the destructor fire
/// exactly once however many copies were taken.
///
/// # Safety
/// `out` must be null or writable; `this_` null or a valid loaned value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_clone(
    out: *mut z_owned_ptr_in_segment_t,
    this_: *const z_loaned_ptr_in_segment_t,
) {
    guard_val((), || {
        if out.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = z_owned_ptr_in_segment_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(source) = (unsafe { ptr_in_segment(this_) }) else {
            return;
        };
        let copy = source.shallow_clone();
        // SAFETY: `out` was checked non-null above.
        unsafe {
            *out = z_owned_ptr_in_segment_t::from_handle(Box::into_raw(Box::new(copy)) as Handle)
        };
    });
}

/// Drop a pointer-in-segment (zenoh-c `z_ptr_in_segment_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved value.
#[no_mangle]
pub unsafe extern "C" fn z_ptr_in_segment_drop(this_: *mut z_moved_ptr_in_segment_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<PtrInSegment>` this module leaked.
            drop(unsafe { Box::from_raw(handle as *mut PtrInSegment) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_ptr_in_segment_t::null_value() };
        }
        Z_OK
    });
}

/// Take the pointer out of a moved value, leaving a gravestone.
///
/// Shared by [`z_chunk_alloc_result_new_ok`] and [`z_shm_provider_map`], which
/// are the two places upstream's `z_allocated_chunk_t` is consumed.
///
/// # Safety
/// `this_` must be null or a valid moved value.
unsafe fn take_ptr_in_segment(this_: *mut z_moved_ptr_in_segment_t) -> Option<PtrInSegment> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    unsafe { (*this_)._this = z_owned_ptr_in_segment_t::null_value() };
    // SAFETY: a live `Box<PtrInSegment>` this module leaked.
    Some(*unsafe { Box::from_raw(handle as *mut PtrInSegment) })
}

/// Report a successful backend allocation (zenoh-c
/// `z_chunk_alloc_result_new_ok`). The chunk's pointer is CONSUMED.
///
/// # Safety
/// `this_` must be null or writable, and `allocated_chunk.ptr` null or a valid
/// moved pointer-in-segment.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_new_ok(
    this_: *mut z_owned_chunk_alloc_result_t,
    allocated_chunk: z_allocated_chunk_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let Some(ptr) = (unsafe { take_ptr_in_segment(allocated_chunk.ptr) }) else {
            // A chunk with no pointer is not a chunk. Refused HERE rather than
            // at the allocation that would use it, which could not say what was
            // wrong.
            if !this_.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *this_ = z_owned_chunk_alloc_result_t::null_value() };
            }
            return Z_EINVAL;
        };
        if this_.is_null() {
            return Z_ENULL;
        }
        let state = ChunkAllocResult::Ok {
            descriptor: allocated_chunk.descriptpr,
            ptr,
        };
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ =
                z_owned_chunk_alloc_result_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
        Z_OK
    })
}

/// Report a failed backend allocation (zenoh-c
/// `z_chunk_alloc_result_new_error`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_new_error(
    this_: *mut z_owned_chunk_alloc_result_t,
    alloc_error: z_alloc_error_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        let state = ChunkAllocResult::Err(alloc_error);
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ =
                z_owned_chunk_alloc_result_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
        };
    });
}

/// Zero an owned chunk-alloc result (zenoh-c
/// `z_internal_chunk_alloc_result_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_chunk_alloc_result_null(
    this_: *mut z_owned_chunk_alloc_result_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_chunk_alloc_result_t::null_value() };
    }
}

/// `true` iff the result holds an outcome (zenoh-c
/// `z_internal_chunk_alloc_result_check`).
///
/// # Safety
/// `this_` must be null or a valid owned result.
#[no_mangle]
pub unsafe extern "C" fn z_internal_chunk_alloc_result_check(
    this_: *const z_owned_chunk_alloc_result_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Drop a chunk-alloc result (zenoh-c `z_chunk_alloc_result_drop`).
///
/// ⚠ Dropping an `Ok` result drops the pointer-in-segment it holds, which
/// releases that segment's context if this was the last copy. It does NOT call
/// the backend's `free_fn`: the chunk was never handed to a provider, so nothing
/// took ownership of it.
///
/// # Safety
/// `this_` must be null or a valid moved result.
#[no_mangle]
pub unsafe extern "C" fn z_chunk_alloc_result_drop(this_: *mut z_moved_chunk_alloc_result_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<ChunkAllocResult>` this module leaked.
            drop(unsafe { Box::from_raw(handle as *mut ChunkAllocResult) });
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_chunk_alloc_result_t::null_value() };
        }
        Z_OK
    });
}

/// Install a C-supplied backend (zenoh-c `z_shm_provider_new`,
/// `zenoh_commons.h:6134-6137`). The context is CONSUMED.
///
/// The callbacks are SERIALISED — see [`ForeignBackend::serialise`] for why that
/// is what upstream's header promises rather than a wz addition.
///
/// # Safety
/// `this_` must be null or writable; the callbacks must be valid for as long as
/// any buffer from this provider is alive.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_new(
    this_: *mut z_owned_shm_provider_t,
    context: zc_context_t,
    callbacks: zc_shm_provider_backend_callbacks_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { foreign_provider_new(this_, context.context, context.delete_fn, callbacks, false) };
}

/// Install a C-supplied backend whose callbacks the caller promises are
/// thread-safe (zenoh-c `z_shm_provider_threadsafe_new`). The context is
/// CONSUMED.
///
/// The promise is what the `_async` spellings require: a provider built here
/// accepts [`z_shm_provider_alloc_gc_defrag_async`], one built by
/// [`z_shm_provider_new`] refuses it with `Z_EINVAL`.
///
/// # Safety
/// As [`z_shm_provider_new`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_threadsafe_new(
    this_: *mut z_owned_shm_provider_t,
    context: zc_threadsafe_context_t,
    callbacks: zc_shm_provider_backend_callbacks_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        foreign_provider_new(
            this_,
            context.context.ptr,
            context.delete_fn,
            callbacks,
            true,
        )
    };
}

/// The shared body of the two foreign-backend constructors.
///
/// # Safety
/// As [`z_shm_provider_new`].
unsafe fn foreign_provider_new(
    this_: *mut z_owned_shm_provider_t,
    context: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
    callbacks: zc_shm_provider_backend_callbacks_t,
    threadsafe: bool,
) {
    let backend = Arc::new(ForeignBackend {
        context: Arc::new(DroppableContext {
            ptr: context,
            delete_fn,
        }),
        callbacks,
        threadsafe,
        serialise: Mutex::new(()),
        live: Mutex::new(0),
        released: Condvar::new(),
    });
    guard_val((), || {
        if this_.is_null() {
            // The context is consumed either way — `backend` drops here and its
            // `delete_fn` runs, rather than leaking state the caller can no
            // longer reach.
            return;
        }
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ =
                z_owned_shm_provider_t::from_handle(provider_handle(Provider::Foreign(backend)))
        };
    });
}

/// Create a provider on the built-in POSIX backend (zenoh-c
/// `z_posix_shm_provider_new`, `zenoh_commons.h:4792-4793`).
///
/// Identical to [`z_shm_provider_default_new`] here, and upstream agrees: its
/// `default_backend` IS the POSIX one, and both constructors produce the same
/// `CSHMProvider::Posix` arm. The two names exist because upstream's default may
/// one day not be POSIX, and a program that needs the POSIX one specifically can
/// say so.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_posix_shm_provider_new(
    this_: *mut z_owned_shm_provider_t,
    size: usize,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe { z_shm_provider_default_new(this_, size) }
}

/// Create a POSIX-backend provider sized and ALIGNED by a memory layout
/// (zenoh-c `z_posix_shm_provider_with_layout_new`).
///
/// The layout's alignment reaches the segment's BASE, not just the offsets
/// inside it — the R2264 finding, applied to the one constructor that lets a
/// caller ask for more than a page.
///
/// # Safety
/// `this_` must be valid and writable; `layout` null or a valid loaned layout.
#[no_mangle]
pub unsafe extern "C" fn z_posix_shm_provider_with_layout_new(
    this_: *mut z_owned_shm_provider_t,
    layout: *const z_loaned_memory_layout_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_shm_provider_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { memory_layout_state(layout) }) else {
            return Z_ENULL;
        };
        if usize::from(state.alignment.pow) >= usize::BITS as usize {
            return Z_EINVAL;
        }
        let segment = Segment::with_alignment(state.size, 1usize << state.alignment.pow);
        // SAFETY: `this_` was checked non-null above.
        unsafe {
            *this_ = z_owned_shm_provider_t::from_handle(provider_handle(Provider::Native(segment)))
        };
        Z_OK
    })
}

/// Hand a chunk the BACKEND allocated back as a buffer (zenoh-c
/// `z_shm_provider_map`). The chunk's pointer is CONSUMED.
///
/// ⛔ REFUSES on a native provider, and that is not a gap: nothing in wz issues a
/// `z_allocated_chunk_t` for a segment wz owns, so a descriptor handed in here
/// names a chunk this allocator never made. Upstream refuses the same call for
/// the same reason — its POSIX backend cannot resolve a descriptor it did not
/// issue either.
///
/// # Safety
/// `out_result` must be null or writable; `provider` null or a valid loaned
/// provider; `allocated_chunk.ptr` null or a valid moved pointer-in-segment.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_map(
    out_result: *mut z_owned_shm_mut_t,
    provider: *const z_loaned_shm_provider_t,
    allocated_chunk: z_allocated_chunk_t,
    len: usize,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract. Taken FIRST and unconditionally: the
        // chunk was passed by value, so every exit below owns it.
        let ptr = unsafe { take_ptr_in_segment(allocated_chunk.ptr) };
        if !out_result.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_result = z_owned_shm_mut_t::null_value() };
        }
        let Some(ptr) = ptr else {
            return Z_EINVAL;
        };
        if out_result.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(Provider::Foreign(backend)) = (unsafe { provider_of(provider) }) else {
            return Z_EINVAL;
        };
        let descriptor = allocated_chunk.descriptpr;
        if ptr.ptr.is_null() || len > descriptor.len {
            return Z_EINVAL;
        }
        *backend.live.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let chunk = Box::new(ShmChunk {
            backing: ChunkBacking::Foreign {
                backend: backend.clone(),
                descriptor,
                ptr,
            },
            len,
            mutable: true,
        });
        // SAFETY: `out_result` was checked non-null above.
        unsafe { *out_result = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle) };
        Z_OK
    })
}

/// A raw pointer an allocation thread carries.
///
/// The C caller owns the storage and upstream's signature says so with
/// `&'static mut`; wz cannot express that through a raw pointer, so the promise
/// is restated here and the wrapper is what lets the pointer cross the spawn.
struct AsyncOut<T>(*mut T);
// SAFETY: the C caller promised the storage outlives the callback, which is the
// same contract upstream's `&'static mut` states. wz adds nothing to it and
// takes nothing away.
unsafe impl<T> Send for AsyncOut<T> {}

/// The caller's result context, carried to the allocation thread.
struct AsyncContext {
    ptr: *mut c_void,
    delete_fn: Option<unsafe extern "C" fn(*mut c_void)>,
}
// SAFETY: the caller used the THREADSAFE context spelling, which is exactly the
// promise that its state may be touched from another thread.
unsafe impl Send for AsyncContext {}

impl Drop for AsyncContext {
    fn drop(&mut self) {
        if let Some(delete_fn) = self.delete_fn {
            // SAFETY: run once, after the result callback has returned.
            unsafe { delete_fn(self.ptr) };
        }
    }
}

/// The shared body of the two provider `_async` spellings.
///
/// # Safety
/// `out_result` must outlive the callback; `provider` null or a valid loaned
/// provider.
unsafe fn provider_alloc_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    result_context: AsyncContext,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    guarded(|| {
        if out_result.is_null() || result_callback.is_none() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(backend) = (unsafe { provider_of(provider) }) else {
            return Z_ENULL;
        };
        if !backend.is_threadsafe() {
            // Upstream's own answer for a non-threadsafe provider, and the only
            // place the two constructors differ observably.
            return Z_EINVAL;
        }
        // Divergence 3: the BACKEND is cloned, so the caller may drop the
        // provider handle while this is in flight.
        let backend = backend.clone();
        let out = AsyncOut(out_result);
        let callback = result_callback;
        std::thread::spawn(move || {
            let out = out;
            let context = result_context;
            let mut wide = z_buf_layout_alloc_result_t {
                status: ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR,
                buf: z_owned_shm_mut_t::null_value(),
                alloc_error: Z_ALLOC_ERROR_OTHER,
                layout_error: Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS,
            };
            if usize::from(alignment.pow) >= usize::BITS as usize {
                wide.status = ZC_BUF_LAYOUT_ALLOC_STATUS_LAYOUT_ERROR;
            } else {
                match backend.alloc(size, 1usize << alignment.pow, true) {
                    Ok(chunk) => {
                        wide.status = ZC_BUF_LAYOUT_ALLOC_STATUS_OK;
                        wide.buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                    }
                    Err(reason) => wide.alloc_error = reason,
                }
            }
            // SAFETY: the caller's storage, which outlives this callback by the
            // contract restated on `AsyncOut`.
            unsafe { *out.0 = wide };
            if let Some(callback) = callback {
                // SAFETY: as above; the context is the caller's own.
                unsafe { callback(context.ptr, out.0) };
            }
        });
        Z_OK
    })
}

/// Allocate on another thread, calling back with the result (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_async`). The context is CONSUMED.
///
/// # Safety
/// As [`provider_alloc_async`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    // SAFETY: the caller's contract, delegated.
    unsafe {
        provider_alloc_async(
            out_result,
            provider,
            size,
            ALIGN_BYTE,
            context,
            result_callback,
        )
    }
}

/// The aligned twin of [`z_shm_provider_alloc_gc_defrag_async`] (zenoh-c
/// `z_shm_provider_alloc_gc_defrag_aligned_async`). The context is CONSUMED.
///
/// # Safety
/// As [`provider_alloc_async`].
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_alloc_gc_defrag_aligned_async(
    out_result: *mut z_buf_layout_alloc_result_t,
    provider: *const z_loaned_shm_provider_t,
    size: usize,
    alignment: z_alloc_alignment_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_layout_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    // SAFETY: the caller's contract, delegated.
    unsafe {
        provider_alloc_async(
            out_result,
            provider,
            size,
            alignment,
            context,
            result_callback,
        )
    }
}

/// Allocate through a precomputed layout on another thread (zenoh-c
/// `z_precomputed_layout_threadsafe_alloc_gc_defrag_async`). The context is
/// CONSUMED.
///
/// `Z_EINVAL` when the layout's provider is not threadsafe, which is the same
/// refusal [`z_shm_provider_alloc_gc_defrag_async`] makes and for the same
/// reason: the layout carries the backend, so it carries the promise too.
///
/// # Safety
/// `out_result` must outlive the callback; `layout` null or a valid loaned
/// layout.
#[no_mangle]
pub unsafe extern "C" fn z_precomputed_layout_threadsafe_alloc_gc_defrag_async(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_precomputed_layout_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_alloc_result_t)>,
) -> ZResult {
    let context = AsyncContext {
        ptr: result_context.context.ptr,
        delete_fn: result_context.delete_fn,
    };
    guarded(|| {
        if out_result.is_null() || result_callback.is_none() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { precomputed_state(layout) }) else {
            return Z_ENULL;
        };
        if !state.provider.is_threadsafe() {
            return Z_EINVAL;
        }
        let backend = state.provider.clone();
        let (size, align) = (state.size, 1usize << state.alignment.pow);
        let out = AsyncOut(out_result);
        let callback = result_callback;
        std::thread::spawn(move || {
            let out = out;
            let context = context;
            let mut narrow = z_buf_alloc_result_t {
                status: ZC_BUF_ALLOC_STATUS_ALLOC_ERROR,
                buf: z_owned_shm_mut_t::null_value(),
                error: Z_ALLOC_ERROR_OTHER,
            };
            match backend.alloc(size, align, true) {
                Ok(chunk) => {
                    narrow.status = ZC_BUF_ALLOC_STATUS_OK;
                    narrow.buf = z_owned_shm_mut_t::from_handle(Box::into_raw(chunk) as Handle);
                }
                Err(reason) => narrow.error = reason,
            }
            // SAFETY: the caller's storage, per `AsyncOut`.
            unsafe { *out.0 = narrow };
            if let Some(callback) = callback {
                // SAFETY: as above.
                unsafe { callback(context.ptr, out.0) };
            }
        });
        Z_OK
    })
}

/// The `alloc_layout` spelling of
/// [`z_precomputed_layout_threadsafe_alloc_gc_defrag_async`] (zenoh-c
/// `z_alloc_layout_threadsafe_alloc_gc_defrag_async`).
///
/// ⛔ Upstream makes `z_owned_alloc_layout_t` a TYPEDEF of
/// `z_owned_precomputed_layout_t`, so this is one implementation under two
/// names — see the layout section for the whole family.
///
/// # Safety
/// As [`z_precomputed_layout_threadsafe_alloc_gc_defrag_async`].
#[no_mangle]
pub unsafe extern "C" fn z_alloc_layout_threadsafe_alloc_gc_defrag_async(
    out_result: *mut z_buf_alloc_result_t,
    layout: *const z_loaned_alloc_layout_t,
    result_context: zc_threadsafe_context_t,
    result_callback: Option<unsafe extern "C" fn(*mut c_void, *mut z_buf_alloc_result_t)>,
) -> ZResult {
    // SAFETY: the caller's contract, delegated.
    unsafe {
        z_precomputed_layout_threadsafe_alloc_gc_defrag_async(
            out_result,
            layout,
            result_context,
            result_callback,
        )
    }
}

const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<z_alloc_alignment_t>() == 1);
    assert!(size_of::<z_buf_layout_alloc_result_t>() == 96);
    assert!(align_of::<z_buf_layout_alloc_result_t>() == 8);
    assert!(size_of::<z_buf_alloc_result_t>() == 96);
    // R2289 — the by-VALUE structs of the backend plane. These cross the ABI as
    // arguments rather than behind a handle, so a field this file added or
    // reordered is a wild call at run time and nothing else would catch it.
    assert!(size_of::<zc_context_t>() == 16);
    assert!(size_of::<zc_threadsafe_context_t>() == 16);
    assert!(size_of::<z_chunk_descriptor_t>() == 16);
    assert!(size_of::<z_allocated_chunk_t>() == 24);
    assert!(size_of::<zc_shm_provider_backend_callbacks_t>() == 48);
};

#[cfg(test)]
mod precomputed_layout_tests {
    use super::*;

    /// # Safety
    /// The returned provider is the caller's to drop.
    unsafe fn provider(total: usize) -> z_owned_shm_provider_t {
        let mut p = z_owned_shm_provider_t::null_value();
        assert_eq!(z_shm_provider_default_new(&mut p, total), Z_OK);
        p
    }

    /// ⛔⛔ SKEW THE SEGMENT FIRST, or the alignment assertion is VACUOUS.
    ///
    /// Since R2264 a segment's base is page-aligned, so the FIRST allocation
    /// sits at offset 0 and satisfies every alignment by accident. MEASURED: a
    /// mutation that made `precomputed_new` store `ALIGN_BYTE` instead of the
    /// caller's alignment PASSED the first draft of these tests. Claiming one
    /// odd byte first moves the free list off the boundary, so the next
    /// allocation is aligned only if the code aligns it.
    ///
    /// The returned buffer must be held for the duration — dropping it returns
    /// the byte and re-coalesces the free list.
    ///
    /// # Safety
    /// `p` must be a live owned provider.
    pub(super) unsafe fn skew(p: &z_owned_shm_provider_t) -> z_owned_shm_mut_t {
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and `p` is live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(p), 1) };
        assert_eq!(
            out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
            "the skew allocation must succeed or the fixture proves nothing"
        );
        out.buf
    }

    /// R2265 — a layout allocates at the size AND alignment it was built with,
    /// through every one of the ten alloc spellings.
    ///
    /// ⛔ The assertion is on the ADDRESS and the LENGTH, not on the status.
    /// R2264 measured what a status-only test misses: five aligned entry points
    /// were green while returning `addr % 64 == 48`. A layout that forgot its
    /// alignment, or that allocated its provider's default size instead of its
    /// own, would pass `status == OK` on all ten of these.
    #[test]
    fn a_layout_allocates_at_its_own_size_and_alignment() {
        const POW: u8 = 6;
        const SIZE: usize = 300;
        type Alloc =
            unsafe extern "C" fn(*mut z_buf_alloc_result_t, *const z_loaned_precomputed_layout_t);
        let spellings: [(&str, Alloc); 10] = [
            ("precomputed_alloc", z_precomputed_layout_alloc),
            ("precomputed_alloc_gc", z_precomputed_layout_alloc_gc),
            (
                "precomputed_alloc_gc_defrag",
                z_precomputed_layout_alloc_gc_defrag,
            ),
            (
                "precomputed_alloc_gc_defrag_blocking",
                z_precomputed_layout_alloc_gc_defrag_blocking,
            ),
            (
                "precomputed_alloc_gc_defrag_dealloc",
                z_precomputed_layout_alloc_gc_defrag_dealloc,
            ),
            ("alloc_layout_alloc", z_alloc_layout_alloc),
            ("alloc_layout_alloc_gc", z_alloc_layout_alloc_gc),
            (
                "alloc_layout_alloc_gc_defrag",
                z_alloc_layout_alloc_gc_defrag,
            ),
            (
                "alloc_layout_alloc_gc_defrag_blocking",
                z_alloc_layout_alloc_gc_defrag_blocking,
            ),
            (
                "alloc_layout_alloc_gc_defrag_dealloc",
                z_alloc_layout_alloc_gc_defrag_dealloc,
            ),
        ];
        for (name, f) in spellings {
            // SAFETY: a live provider this frame owns.
            let mut p = unsafe { provider(64 * 1024) };
            // SAFETY: `p` is live; the buffer is held until the end of the
            // iteration so the free list stays skewed.
            let skewed = unsafe { skew(&p) };
            let mut layout = z_owned_precomputed_layout_t::null_value();
            // SAFETY: `layout` is writable and `p` is live.
            assert_eq!(
                unsafe {
                    z_alloc_layout_with_alignment_new(
                        &mut layout,
                        z_shm_provider_loan(&p),
                        SIZE,
                        z_alloc_alignment_t { pow: POW },
                    )
                },
                Z_OK,
                "{name}: the layout must build"
            );
            assert!(unsafe { z_internal_precomputed_layout_check(&layout) });

            let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` is writable and `layout` is live.
            unsafe { f(&mut out, z_precomputed_layout_loan(&layout)) };
            assert_eq!(out.status, ZC_BUF_ALLOC_STATUS_OK, "{name}: must allocate");
            // SAFETY: the status says the buffer is live.
            let loaned = unsafe { z_shm_mut_loan(&out.buf) };
            let data = unsafe { z_shm_mut_data(loaned) };
            assert!(!data.is_null(), "{name}: OK with no data");
            assert_eq!(
                unsafe { z_shm_mut_len(loaned) },
                SIZE,
                "{name}: allocated a length that is not the layout's"
            );
            assert_eq!(
                data as usize % (1usize << POW),
                0,
                "{name}: the layout's alignment did not reach the allocation"
            );

            let mut moved = z_moved_shm_mut_t { _this: out.buf };
            // SAFETY: dropped once.
            unsafe { z_shm_mut_drop(&mut moved) };
            let mut moved_skew = z_moved_shm_mut_t { _this: skewed };
            // SAFETY: dropped once, after the assertions it was holding open.
            unsafe { z_shm_mut_drop(&mut moved_skew) };
            let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
            // SAFETY: as above.
            unsafe { z_precomputed_layout_drop(&mut moved_l) };
            assert!(!unsafe { z_internal_precomputed_layout_check(&moved_l._this) });
            let mut moved_p = z_moved_shm_provider_t { _this: p };
            // SAFETY: as above.
            unsafe { z_shm_provider_drop(&mut moved_p) };
            p = z_owned_shm_provider_t::null_value();
            let _ = p;
        }
    }

    /// A layout OUTLIVES the provider handle it was built from, and still
    /// allocates.
    ///
    /// The layout holds an `Arc<Segment>`, not the provider's box, and this is
    /// the only assertion that can tell those apart: a layout that kept a raw
    /// pointer into the provider would allocate fine until the provider was
    /// dropped and then read freed memory.
    #[test]
    fn a_layout_outlives_the_provider_handle() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(8192) };
        let mut layout = z_owned_precomputed_layout_t::null_value();
        // SAFETY: both are live.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 128) },
            Z_OK
        );
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: dropped once; the layout keeps the segment alive.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;

        let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `layout` is still live.
        unsafe { z_precomputed_layout_alloc(&mut out, z_precomputed_layout_loan(&layout)) };
        assert_eq!(
            out.status, ZC_BUF_ALLOC_STATUS_OK,
            "the layout must still allocate after its provider handle is gone"
        );
        let mut moved = z_moved_shm_mut_t { _this: out.buf };
        // SAFETY: dropped once.
        unsafe { z_shm_mut_drop(&mut moved) };
        let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
        // SAFETY: as above.
        unsafe { z_precomputed_layout_drop(&mut moved_l) };
    }

    /// A nonsense layout is refused at construction, and NULL is tolerated
    /// everywhere.
    #[test]
    fn a_nonsense_layout_is_refused_and_null_is_tolerated() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(4096) };
        let mut layout = z_owned_precomputed_layout_t::null_value();
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 0) },
            Z_EINVAL,
            "a zero-size layout is not a layout"
        );
        assert!(!unsafe { z_internal_alloc_layout_check(&layout) });
        assert_eq!(
            unsafe {
                z_alloc_layout_with_alignment_new(
                    &mut layout,
                    z_shm_provider_loan(&p),
                    64,
                    z_alloc_alignment_t {
                        pow: usize::BITS as u8,
                    },
                )
            },
            Z_EINVAL
        );
        // A layout with no provider is refused too.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, std::ptr::null(), 64) },
            Z_ENULL
        );
        // CONTROL: the same size against the same provider is accepted.
        assert_eq!(
            unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&p), 64) },
            Z_OK
        );

        // NULL everywhere else.
        assert!(!unsafe { z_internal_precomputed_layout_check(std::ptr::null()) });
        let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
        unsafe { z_precomputed_layout_alloc(&mut out, std::ptr::null()) };
        assert_eq!(
            out.status, ZC_BUF_ALLOC_STATUS_ALLOC_ERROR,
            "a null layout must leave a well-formed failure, not the caller's stack"
        );
        unsafe { z_precomputed_layout_drop(std::ptr::null_mut()) };
        unsafe { z_alloc_layout_drop(std::ptr::null_mut()) };

        let mut moved_l = z_moved_precomputed_layout_t { _this: layout };
        // SAFETY: dropped once.
        unsafe { z_precomputed_layout_drop(&mut moved_l) };
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: as above.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;
    }
}

#[cfg(test)]
mod aligned_alloc_tests {
    use super::*;

    /// # Safety
    /// The returned provider is the caller's to drop.
    unsafe fn provider(total: usize) -> z_owned_shm_provider_t {
        let mut p = z_owned_shm_provider_t::null_value();
        assert_eq!(z_shm_provider_default_new(&mut p, total), Z_OK);
        p
    }

    /// R2264 — the CALLER's alignment reaches the allocator on every one of the
    /// new aligned spellings.
    ///
    /// This is the assertion that separates them from aliases of the unaligned
    /// five: those pass `ALIGN_BYTE`, so a new entry point that forgot to
    /// forward its argument would still allocate, still return OK, and still
    /// pass any test that only checked the status. The address is what tells.
    #[test]
    fn every_aligned_spelling_honours_the_callers_alignment() {
        const POW: u8 = 6; // 64 bytes
        let align = z_alloc_alignment_t { pow: POW };
        type Aligned = unsafe extern "C" fn(
            *mut z_buf_layout_alloc_result_t,
            *const z_loaned_shm_provider_t,
            usize,
            z_alloc_alignment_t,
        );
        let spellings: [(&str, Aligned); 4] = [
            ("alloc_gc_aligned", z_shm_provider_alloc_gc_aligned),
            (
                "alloc_gc_defrag_aligned",
                z_shm_provider_alloc_gc_defrag_aligned,
            ),
            (
                "alloc_gc_defrag_blocking_aligned",
                z_shm_provider_alloc_gc_defrag_blocking_aligned,
            ),
            (
                "alloc_gc_defrag_dealloc_aligned",
                z_shm_provider_alloc_gc_defrag_dealloc_aligned,
            ),
        ];
        for (name, f) in spellings {
            // SAFETY: a live provider this frame owns.
            let mut p = unsafe { provider(64 * 1024) };
            // ⛔ R2265 — SKEW FIRST. R2264 wrote this test when segments were
            // alignment-1, so a wrong answer showed up as `addr % 64 == 48`.
            // Page-aligning the segment (the repair R2264 itself made) turned
            // the FIRST allocation into one that satisfies any alignment by
            // accident, which would have made this assertion vacuous from the
            // next round on. Claiming one odd byte first is what keeps it real.
            let skewed = unsafe { super::precomputed_layout_tests::skew(&p) };
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` is writable and `p` is live.
            unsafe { f(&mut out, z_shm_provider_loan(&p), 128, align) };
            assert_eq!(
                out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK,
                "{name} must allocate from a fresh 64K provider"
            );
            // SAFETY: the status says the buffer is live.
            let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
            assert!(!data.is_null(), "{name} returned OK with no data");
            assert_eq!(
                data as usize % (1usize << POW),
                0,
                "{name} did not honour the caller's alignment — it is forwarding \
                 ALIGN_BYTE like its unaligned twin"
            );
            let mut moved = z_moved_shm_mut_t { _this: out.buf };
            // SAFETY: dropped once.
            unsafe { z_shm_mut_drop(&mut moved) };
            let mut moved_skew = z_moved_shm_mut_t { _this: skewed };
            // SAFETY: as above.
            unsafe { z_shm_mut_drop(&mut moved_skew) };
            let mut moved_p = z_moved_shm_provider_t { _this: p };
            // SAFETY: as above.
            unsafe { z_shm_provider_drop(&mut moved_p) };
            p = z_owned_shm_provider_t::null_value();
            let _ = p;
        }
    }

    /// The two DEALLOC spellings allocate, which is the claim their name makes
    /// about wz: there is no third reclaim step, but the entry point works.
    #[test]
    fn the_dealloc_spellings_allocate() {
        // SAFETY: a live provider this frame owns.
        let mut p = unsafe { provider(64 * 1024) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and `p` is live.
        unsafe { z_shm_provider_alloc_gc_defrag_dealloc(&mut out, z_shm_provider_loan(&p), 256) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        let mut moved = z_moved_shm_mut_t { _this: out.buf };
        // SAFETY: dropped once.
        unsafe { z_shm_mut_drop(&mut moved) };
        let mut moved_p = z_moved_shm_provider_t { _this: p };
        // SAFETY: as above.
        unsafe { z_shm_provider_drop(&mut moved_p) };
        p = z_owned_shm_provider_t::null_value();
        let _ = p;
    }
}

#[cfg(test)]
mod memory_layout_tests {
    use super::*;

    /// A layout round-trips its `(size, alignment)` through the C accessors.
    ///
    /// Both fields are asserted with DISTINCT values, and the alignment is a
    /// non-zero exponent: a layout that stored only the size, or that dropped
    /// the exponent, would pass a test that checked one of them or that used
    /// `pow = 0`.
    #[test]
    fn a_layout_round_trips_its_size_and_alignment() {
        let mut owned = z_owned_memory_layout_t::null_value();
        assert!(!unsafe { z_internal_memory_layout_check(&owned) });
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 4096, z_alloc_alignment_t { pow: 6 }) },
            Z_OK
        );
        assert!(unsafe { z_internal_memory_layout_check(&owned) });

        let loaned = unsafe { z_memory_layout_loan(&owned) };
        let mut size = 0usize;
        let mut alignment = z_alloc_alignment_t { pow: 0 };
        unsafe { z_memory_layout_get_data(loaned, &mut size, &mut alignment) };
        assert_eq!(size, 4096);
        assert_eq!(alignment.pow, 6);

        // Each output is independently optional — upstream's signature says
        // nothing about them being required together.
        let mut only_size = 0usize;
        unsafe { z_memory_layout_get_data(loaned, &mut only_size, std::ptr::null_mut()) };
        assert_eq!(only_size, 4096);

        let mut moved = z_moved_memory_layout_t { _this: owned };
        unsafe { z_memory_layout_drop(&mut moved) };
        assert!(!unsafe { z_internal_memory_layout_check(&moved._this) });
    }

    /// A nonsense layout is REFUSED at construction, with a gravestone left
    /// behind rather than the caller's stack value.
    ///
    /// This is the half a stub gets wrong: returning `Z_OK` for a zero size
    /// moves the failure to the allocation that uses the layout, which cannot
    /// say what was wrong with it.
    #[test]
    fn a_nonsense_layout_is_refused_at_construction() {
        let mut owned = z_owned_memory_layout_t::null_value();
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 0, z_alloc_alignment_t { pow: 3 }) },
            Z_EINVAL,
            "a zero-size layout is not a layout"
        );
        assert!(
            !unsafe { z_internal_memory_layout_check(&owned) },
            "and the refusal must leave a gravestone"
        );

        // An exponent at or past the pointer width cannot name an alignment.
        assert_eq!(
            unsafe {
                z_memory_layout_new(
                    &mut owned,
                    64,
                    z_alloc_alignment_t {
                        pow: usize::BITS as u8,
                    },
                )
            },
            Z_EINVAL
        );
        assert!(!unsafe { z_internal_memory_layout_check(&owned) });

        // CONTROL: the same size with a representable exponent is accepted, so
        // the refusals above are about the values and not about the function.
        assert_eq!(
            unsafe { z_memory_layout_new(&mut owned, 64, z_alloc_alignment_t { pow: 3 }) },
            Z_OK
        );
        let mut moved = z_moved_memory_layout_t { _this: owned };
        unsafe { z_memory_layout_drop(&mut moved) };
    }

    /// Every accessor tolerates NULL, and a gravestone reads as absent.
    #[test]
    fn the_accessors_answer_without_dereferencing_null() {
        assert!(!unsafe { z_internal_memory_layout_check(std::ptr::null()) });
        assert_eq!(
            unsafe { z_memory_layout_new(std::ptr::null_mut(), 8, z_alloc_alignment_t { pow: 0 }) },
            Z_ENULL
        );
        let mut size = 7usize;
        unsafe { z_memory_layout_get_data(std::ptr::null(), &mut size, std::ptr::null_mut()) };
        assert_eq!(size, 7, "a null layout must not write the outputs");
        unsafe { z_memory_layout_drop(std::ptr::null_mut()) };

        let mut grave = z_owned_memory_layout_t::null_value();
        let loaned = unsafe { z_memory_layout_loan(&grave) };
        unsafe { z_memory_layout_get_data(loaned, &mut size, std::ptr::null_mut()) };
        assert_eq!(size, 7, "a gravestone carries no data to read");
        unsafe { z_internal_memory_layout_null(&mut grave) };
        assert!(!unsafe { z_internal_memory_layout_check(&grave) });
    }
}

#[cfg(test)]
mod segment_tests {
    use super::*;

    /// The property `z_pub_shm.c` depends on and nothing else in the corpus
    /// states: a provider whose chunks are released can serve the SAME request
    /// forever. A allocator that leaked would fail on the fifth iteration of
    /// that example's loop and on no earlier one, which is exactly the shape of
    /// bug a single-shot test does not see.
    #[test]
    fn a_released_chunk_is_reusable_indefinitely() {
        let segment = Segment::new(4096);
        for _ in 0..64 {
            let start = segment
                .books()
                .claim(1024, 1)
                .expect("a 1024-byte chunk fits in a 4096-byte segment");
            let chunk = ShmChunk {
                backing: ChunkBacking::Native {
                    segment: segment.clone(),
                    start,
                },
                len: 1024,
                mutable: true,
            };
            drop(chunk);
        }
        assert_eq!(segment.books().available(), 4096);
    }

    /// Adjacent releases COALESCE, so a segment cut into four and freed can
    /// serve a request for the whole of it again. Without coalescing this is
    /// the first request that fails while `available()` still reports 4096 —
    /// the failure mode `Z_ALLOC_ERROR_NEED_DEFRAGMENT` exists to name.
    #[test]
    fn adjacent_frees_coalesce_back_into_one_range() {
        let segment = Segment::new(4096);
        let chunks: Vec<ShmChunk> = (0..4)
            .map(|_| {
                let start = segment.books().claim(1024, 1).expect("quarter fits");
                ShmChunk {
                    backing: ChunkBacking::Native {
                        segment: segment.clone(),
                        start,
                    },
                    len: 1024,
                    mutable: true,
                }
            })
            .collect();
        assert_eq!(segment.books().available(), 0);
        drop(chunks);
        assert_eq!(segment.books().largest(), 4096);
        assert!(segment.books().claim(4096, 1).is_some());
    }

    /// `z_get_shm.c` sizes its provider to EXACTLY the payload it allocates, so
    /// an allocator taking any per-chunk overhead out of the segment fails that
    /// example's FIRST call. Pinned here because the example only shows it when
    /// the oracle is present.
    #[test]
    fn a_request_for_the_whole_segment_succeeds() {
        let segment = Segment::new(11);
        assert_eq!(segment.books().claim(11, 1), Some(0));
        assert_eq!(segment.books().available(), 0);
    }

    /// A zero-length segment is legal — `z_get_shm.c` builds one when run with
    /// no payload — and a zero-length request out of it succeeds rather than
    /// reporting out-of-memory.
    #[test]
    fn a_zero_length_segment_serves_a_zero_length_request() {
        let segment = Segment::new(0);
        assert_eq!(segment.books().available(), 0);
        // `claim` finds no range to cut from, so the caller gets None and the
        // ALLOC path reports out-of-memory. The example only allocates when it
        // has a payload, so this documents the boundary rather than asserting a
        // success the C side would then write zero bytes into.
        assert_eq!(segment.books().claim(0, 1), None);
    }

    /// Alignment is honoured out of the middle of a range, and the skipped
    /// bytes stay FREE rather than being lost — a leak here would show only as
    /// a provider that slowly stops serving.
    #[test]
    fn an_aligned_claim_leaves_the_alignment_gap_free() {
        let segment = Segment::new(4096);
        // Take one byte so the next range starts at an odd offset.
        let head = segment.books().claim(1, 1).expect("one byte fits");
        assert_eq!(head, 0);
        let aligned = segment.books().claim(16, 64).expect("64-aligned fits");
        assert_eq!(aligned % 64, 0);
        assert_eq!(aligned, 64);
        // 4096 - 1 (head) - 16 (chunk) = 4079, so the 63-byte gap is still free.
        assert_eq!(segment.books().available(), 4079);
    }

    /// Freezing clears the mutable flag and does NOT move the bytes — the
    /// property `z_shm_try_reloan_mut` reports and `z_sub_shm.c` prints.
    #[test]
    fn freezing_keeps_the_range_and_clears_mutability() {
        let segment = Segment::new(64);
        let start = segment.books().claim(8, 1).expect("fits");
        let mut chunk = ShmChunk {
            backing: ChunkBacking::Native {
                segment: segment.clone(),
                start,
            },
            len: 8,
            mutable: true,
        };
        assert!(chunk.mutable);
        chunk.mutable = false;
        assert!(matches!(
            chunk.backing,
            ChunkBacking::Native { start: at, .. } if at == start
        ));
        assert_eq!(segment.books().available(), 56);
    }
}

#[cfg(test)]
mod foreign_backend_tests {
    //! R2289 (open-debt item 607) — the C-SUPPLIED backend, driven the way a C
    //! program drives it.
    //!
    //! Every test here goes through the exported entry points and a backend
    //! written as six `extern "C"` callbacks over one opaque context, because
    //! that is the only shape in which the plane's claim is testable: wz calls
    //! OUT, and a test that called wz's internals instead would be asserting
    //! about a function nobody reaches.
    //!
    //! The harness records what it was asked and what it was told, so each test
    //! can assert the two directions separately — that the request reached the
    //! backend intact, and that the backend's answer reached the caller intact.
    //! Status codes alone would pass for a wz that allocated out of its OWN
    //! segment and never called the callbacks at all, which is why every
    //! allocation test also asserts the returned pointer lies inside the
    //! BACKEND's arena.

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// The segment id this backend stamps into every descriptor, so a test can
    /// tell its own descriptors from a zeroed struct.
    const SEGMENT_ID: z_segment_id_t = 7;
    /// How long the concurrency probe waits for a second caller before deciding
    /// there is not going to be one.
    const PEER_WAIT: Duration = Duration::from_millis(400);
    /// What `defragment_fn` returns: a number no wz book-keeping path could
    /// produce, so an answer that did not come from the backend is visible.
    const DEFRAGMENT_ANSWER: usize = 0xDEF7A6;

    /// The book-keeping the callbacks share.
    struct HarnessState {
        /// Which slots of the arena are handed out.
        used: Vec<bool>,
        alloc_calls: usize,
        free_calls: usize,
        defragment_calls: usize,
        available_calls: usize,
        /// The `(size, alignment exponent)` of every layout `alloc_fn` saw.
        layouts_seen: Vec<(usize, u8)>,
        /// Every descriptor `free_fn` was handed.
        freed: Vec<(z_segment_id_t, z_chunk_id_t, usize)>,
        in_flight: usize,
        concurrent_max: usize,
    }

    /// A backend a C program could have written, with the counters a test needs.
    struct Harness {
        /// The memory this backend hands out. The `Box` is what owns it; the raw
        /// pointer is what the callbacks compute chunk addresses from while the
        /// book-keeping is locked.
        _arena: Box<[u8]>,
        arena: *mut u8,
        slot_len: usize,
        state: Mutex<HarnessState>,
        peer: Condvar,
        /// Bumped by this backend's own `delete_fn`.
        deleted: Arc<AtomicUsize>,
        /// Bumped when a chunk's segment context is released.
        segment_drops: Arc<AtomicUsize>,
        /// When set, `alloc_fn` waits for a second caller so a test can see
        /// whether wz let one in.
        probe_concurrency: bool,
        /// When set, every allocation fails — for the blocking-path tests.
        always_fail: bool,
        /// When set, `alloc_fn` hands out a slot even when it is SMALLER than
        /// the request — a misbehaving backend, which is the only way to reach
        /// wz's check that the chunk covers what was asked for.
        ///
        /// ⚠ Added after the first draft of `a_backend_that_under_delivers…`
        /// PASSED with wz's check deleted: the harness refused the oversized
        /// request itself, so the branch under test was never entered and the
        /// test was measuring nothing.
        under_deliver: bool,
    }

    // SAFETY: the arena is owned for the harness's whole life and every chunk
    // handed out of it is a distinct range; `state` serialises the book-keeping.
    unsafe impl Send for Harness {}
    // SAFETY: as above.
    unsafe impl Sync for Harness {}

    impl Harness {
        fn new(slots: usize, slot_len: usize) -> Box<Self> {
            let mut arena = vec![0u8; slots * slot_len].into_boxed_slice();
            let ptr = arena.as_mut_ptr();
            Box::new(Self {
                _arena: arena,
                arena: ptr,
                slot_len,
                state: Mutex::new(HarnessState {
                    used: vec![false; slots],
                    alloc_calls: 0,
                    free_calls: 0,
                    defragment_calls: 0,
                    available_calls: 0,
                    layouts_seen: Vec::new(),
                    freed: Vec::new(),
                    in_flight: 0,
                    concurrent_max: 0,
                }),
                peer: Condvar::new(),
                deleted: Arc::new(AtomicUsize::new(0)),
                segment_drops: Arc::new(AtomicUsize::new(0)),
                probe_concurrency: false,
                always_fail: false,
                under_deliver: false,
            })
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HarnessState> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// The address of slot `n`.
        fn slot_ptr(&self, n: usize) -> *mut u8 {
            // SAFETY: `n` is a slot index this harness handed out.
            unsafe { self.arena.add(n * self.slot_len) }
        }

        /// Whether `p` points inside this backend's arena — the assertion that
        /// separates "wz called the backend" from "wz allocated its own memory
        /// and returned a plausible status".
        fn owns(&self, p: *const u8, len: usize) -> bool {
            let base = self.arena as usize;
            let end = base + self._arena.len();
            let p = p as usize;
            p >= base && p + len <= end
        }
    }

    /// What a chunk's segment context points at: nothing but a counter to bump
    /// when wz releases it.
    struct SegmentTag(Arc<AtomicUsize>);

    unsafe extern "C" fn segment_delete(ctx: *mut c_void) {
        // SAFETY: the pointer this module handed to `z_ptr_in_segment_new`.
        let tag = unsafe { Box::from_raw(ctx as *mut SegmentTag) };
        tag.0.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn backend_delete(ctx: *mut c_void) {
        // SAFETY: the pointer this module handed to the provider constructor.
        let harness = unsafe { Box::from_raw(ctx as *mut Harness) };
        harness.deleted.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn backend_alloc(
        out: *mut z_owned_chunk_alloc_result_t,
        layout: *const z_loaned_memory_layout_t,
        ctx: *mut c_void,
    ) {
        // SAFETY: the harness pointer, alive for the provider's whole life.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut size = 0usize;
        let mut alignment = z_alloc_alignment_t { pow: 0 };
        // SAFETY: `layout` is the loaned layout wz built for this call.
        unsafe { z_memory_layout_get_data(layout, &mut size, &mut alignment) };

        let mut state = harness.lock();
        state.alloc_calls += 1;
        state.layouts_seen.push((size, alignment.pow));
        state.in_flight += 1;
        state.concurrent_max = state.concurrent_max.max(state.in_flight);
        harness.peer.notify_all();
        if harness.probe_concurrency {
            // Wait, briefly, for a second caller. Two threads that wz let in
            // together both see `in_flight == 2`; two that wz serialised each
            // time out alone.
            while state.in_flight < 2 {
                let (guard, timeout) = harness
                    .peer
                    .wait_timeout(state, PEER_WAIT)
                    .unwrap_or_else(|e| e.into_inner());
                state = guard;
                if timeout.timed_out() {
                    break;
                }
            }
        }
        state.in_flight -= 1;

        let slot = if harness.always_fail {
            None
        } else {
            state
                .used
                .iter()
                .position(|used| !used)
                .filter(|_| harness.under_deliver || size <= harness.slot_len)
        };
        let Some(slot) = slot else {
            drop(state);
            // SAFETY: `out` is wz's own gravestoned local.
            unsafe { z_chunk_alloc_result_new_error(out, Z_ALLOC_ERROR_OUT_OF_MEMORY) };
            return;
        };
        state.used[slot] = true;
        drop(state);

        let tag = Box::into_raw(Box::new(SegmentTag(harness.segment_drops.clone())));
        let mut ptr = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: `ptr` is a live local and the context pair is well formed.
        unsafe {
            z_ptr_in_segment_new(
                &mut ptr,
                harness.slot_ptr(slot),
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        let mut moved = z_moved_ptr_in_segment_t { _this: ptr };
        // SAFETY: `out` is wz's gravestoned local and `moved` a live local whose
        // pointer this call consumes.
        unsafe {
            z_chunk_alloc_result_new_ok(
                out,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: slot as z_chunk_id_t,
                        len: harness.slot_len,
                    },
                    ptr: &mut moved,
                },
            )
        };
    }

    unsafe extern "C" fn backend_free(chunk: *const z_chunk_descriptor_t, ctx: *mut c_void) {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        // SAFETY: wz hands back a live descriptor.
        let desc = unsafe { *chunk };
        let mut state = harness.lock();
        state.free_calls += 1;
        state.freed.push((desc.segment, desc.chunk, desc.len));
        if let Some(used) = state.used.get_mut(desc.chunk as usize) {
            *used = false;
        }
    }

    unsafe extern "C" fn backend_defragment(ctx: *mut c_void) -> usize {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut state = harness.lock();
        state.defragment_calls += 1;
        // A number nothing else in the harness produces, so a wz that answered
        // from its own book-keeping instead of calling here is visible.
        DEFRAGMENT_ANSWER
    }

    unsafe extern "C" fn backend_available(ctx: *mut c_void) -> usize {
        // SAFETY: the harness pointer.
        let harness = unsafe { &*(ctx as *const Harness) };
        let mut state = harness.lock();
        state.available_calls += 1;
        state.used.iter().filter(|used| !**used).count() * harness.slot_len
    }

    unsafe extern "C" fn backend_layout_for(
        _layout: *mut z_owned_memory_layout_t,
        _ctx: *mut c_void,
    ) {
        // This backend serves any layout it is given unchanged.
    }

    unsafe extern "C" fn backend_id(_ctx: *mut c_void) -> z_protocol_id_t {
        0x77
    }

    fn callbacks() -> zc_shm_provider_backend_callbacks_t {
        zc_shm_provider_backend_callbacks_t {
            alloc_fn: Some(backend_alloc),
            free_fn: Some(backend_free),
            defragment_fn: Some(backend_defragment),
            available_fn: Some(backend_available),
            layout_for_fn: Some(backend_layout_for),
            id_fn: Some(backend_id),
        }
    }

    /// Install `harness` as a provider, returning the provider and a borrow of
    /// the harness that stays valid until the provider is dropped.
    ///
    /// # Safety
    /// The caller must drop the returned provider before reading the harness's
    /// `deleted` counter through anything but the `Arc` it was cloned from.
    unsafe fn install(
        harness: Box<Harness>,
        threadsafe: bool,
    ) -> (z_owned_shm_provider_t, &'static Harness) {
        let deleted = harness.deleted.clone();
        let _ = deleted;
        let raw = Box::into_raw(harness);
        // SAFETY: the box outlives the provider, which is what `delete_fn`
        // enforces — it is the only thing that frees it.
        let borrow = unsafe { &*raw };
        let mut provider = z_owned_shm_provider_t::null_value();
        if threadsafe {
            // SAFETY: `provider` is a live local.
            unsafe {
                z_shm_provider_threadsafe_new(
                    &mut provider,
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: raw as *mut c_void,
                        },
                        delete_fn: Some(backend_delete),
                    },
                    callbacks(),
                )
            };
        } else {
            // SAFETY: as above.
            unsafe {
                z_shm_provider_new(
                    &mut provider,
                    zc_context_t {
                        context: raw as *mut c_void,
                        delete_fn: Some(backend_delete),
                    },
                    callbacks(),
                )
            };
        }
        assert!(unsafe { z_internal_shm_provider_check(&provider) });
        (provider, borrow)
    }

    /// Drop a provider once.
    ///
    /// # Safety
    /// `provider` must be live.
    unsafe fn drop_provider(provider: z_owned_shm_provider_t) {
        let mut moved = z_moved_shm_provider_t { _this: provider };
        // SAFETY: dropped exactly once.
        unsafe { z_shm_provider_drop(&mut moved) };
    }

    /// Drop a mutable buffer once.
    ///
    /// # Safety
    /// `buf` must be live.
    unsafe fn drop_buf(buf: z_owned_shm_mut_t) {
        let mut moved = z_moved_shm_mut_t { _this: buf };
        // SAFETY: dropped exactly once.
        unsafe { z_shm_mut_drop(&mut moved) };
    }

    /// The whole round trip: the request reaches the backend as a layout, the
    /// backend's memory reaches the caller, and the release reaches the backend
    /// as the descriptor it issued.
    ///
    /// Each of the four assertions fails on a different wrong implementation: a
    /// wz that never called `alloc_fn`, one that called it and returned its own
    /// memory, one that lost the descriptor, and one that never called
    /// `free_fn`.
    #[test]
    fn a_foreign_backend_serves_the_allocation_and_the_release() {
        // SAFETY: the provider owns the harness until it is dropped.
        let (provider, harness) = unsafe { install(Harness::new(4, 256), false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);

        // SAFETY: the status says the buffer is live.
        let loaned = unsafe { z_shm_mut_loan_mut(&mut out.buf) };
        // SAFETY: as above.
        let data = unsafe { z_shm_mut_data_mut(loaned) };
        assert!(
            harness.owns(data, 64),
            "the buffer must be the BACKEND's memory — a pointer outside its \
             arena means wz allocated its own and never asked"
        );
        // SAFETY: 64 bytes of the backend's own arena, exclusively ours.
        unsafe { std::ptr::write_bytes(data, 0xA5, 64) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_mut_len(loaned) }, 64);
        // SAFETY: as above.
        let read = unsafe { std::slice::from_raw_parts(z_shm_mut_data(loaned), 64) };
        assert!(read.iter().all(|b| *b == 0xA5), "the bytes must flow back");

        {
            let state = harness.lock();
            assert_eq!(state.alloc_calls, 1);
            assert_eq!(
                state.layouts_seen,
                vec![(64usize, 0u8)],
                "the caller's size must reach the backend as a layout"
            );
            assert_eq!(state.free_calls, 0, "nothing is released while it is held");
        }

        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        {
            let state = harness.lock();
            assert_eq!(state.free_calls, 1);
            assert_eq!(
                state.freed,
                vec![(SEGMENT_ID, 0, 256)],
                "the backend must get back the descriptor it issued, not a \
                 reconstruction"
            );
        }
        assert_eq!(
            harness.segment_drops.load(Ordering::SeqCst),
            1,
            "the chunk's segment context is released with the chunk"
        );

        let deleted = harness.deleted.clone();
        // SAFETY: dropped once; `harness` must not be read after this.
        unsafe { drop_provider(provider) };
        assert_eq!(
            deleted.load(Ordering::SeqCst),
            1,
            "the provider owes the context exactly one delete_fn"
        );
    }

    /// `available` and `defragment` are the BACKEND's answers, not wz's.
    ///
    /// Both return values a wz book-keeping path could not produce, so an
    /// implementation that answered from its own free list rather than calling
    /// out fails here rather than looking plausible.
    #[test]
    fn available_and_defragment_are_answered_by_the_backend() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(4, 256), false) };
        // SAFETY: the provider is live.
        let loan = unsafe { z_shm_provider_loan(&provider) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_provider_available(loan) }, 4 * 256);
        // SAFETY: as above.
        assert_eq!(
            unsafe { z_shm_provider_defragment(loan) },
            DEFRAGMENT_ANSWER
        );
        {
            let state = harness.lock();
            assert_eq!(state.available_calls, 1);
            assert_eq!(state.defragment_calls, 1);
        }

        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, loan, 16) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: the provider is live.
        assert_eq!(
            unsafe { z_shm_provider_available(loan) },
            3 * 256,
            "the backend's own accounting must be what is reported"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The caller's ALIGNMENT reaches the backend, and it reaches it as an
    /// exponent rather than being flattened to the default.
    #[test]
    fn the_callers_alignment_reaches_the_backend() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 512), false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe {
            z_shm_provider_alloc_aligned(
                &mut out,
                z_shm_provider_loan(&provider),
                128,
                z_alloc_alignment_t { pow: 6 },
            )
        };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        assert_eq!(
            harness.lock().layouts_seen,
            vec![(128usize, 6u8)],
            "an entry point that forwarded ALIGN_BYTE would show pow = 0 here"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The BACKEND's error code is what the caller sees.
    ///
    /// wz's own exhaustion answer is `Z_ALLOC_ERROR_OUT_OF_MEMORY` too, so the
    /// discriminating half is the second request: this backend refuses an
    /// oversized request with the same code while `available` still reports room,
    /// which wz's native allocator would call a defragmentation problem.
    #[test]
    fn the_backends_refusal_is_the_callers_refusal() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(1, 128), false) };
        // SAFETY: the provider is live.
        let loan = unsafe { z_shm_provider_loan(&provider) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, loan, 4096) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        assert_eq!(out.alloc_error, Z_ALLOC_ERROR_OUT_OF_MEMORY);
        assert_eq!(
            harness.lock().alloc_calls,
            1,
            "the refusal must come from the backend, not from a size check wz \
             made on its behalf"
        );
        // SAFETY: the provider is live.
        assert_eq!(unsafe { z_shm_provider_available(loan) }, 128);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A backend that says OK and delivers a chunk SMALLER than was asked for is
    /// refused, and the chunk is handed back rather than leaked.
    ///
    /// The buffer plane passes this pointer and length straight to the caller,
    /// so trusting the backend here would hand a C program a 64-byte window on
    /// a 16-byte chunk.
    #[test]
    fn a_backend_that_under_delivers_is_refused_and_the_chunk_returned() {
        let mut harness = Harness::new(1, 16);
        // The backend hands out a 16-byte slot for a 64-byte request. Without
        // this the harness refuses the request ITSELF and wz's check is never
        // reached — which is how the first draft of this test passed with that
        // check deleted.
        harness.under_deliver = true;
        // SAFETY: the provider owns the harness.
        let (provider, borrow) = unsafe { install(harness, false) };
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(
            borrow.lock().alloc_calls,
            1,
            "the backend must have been ASKED — a refusal wz made on its own \
             would leave this at zero and the rest of the test vacuous"
        );
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR);
        assert!(
            !unsafe { z_internal_shm_mut_check(&out.buf) },
            "a refused allocation must leave a gravestone"
        );
        assert_eq!(
            borrow.lock().freed,
            vec![(SEGMENT_ID, 0, 16)],
            "the chunk wz refused must go back to the backend, not be dropped"
        );
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A blocking allocation with NOTHING outstanding fails instead of waiting
    /// — divergence 2 — and the CONTROL shows the waiting path is live.
    ///
    /// Without the control this test would pass on a wz that never blocked at
    /// all, which is the failure it is meant to be about.
    #[test]
    fn a_blocking_request_waits_only_when_a_release_can_come() {
        // Nothing outstanding: the call must return rather than wait forever.
        let mut harness = Harness::new(1, 64);
        harness.always_fail = true;
        // SAFETY: the provider owns the harness.
        let (provider, _borrow) = unsafe { install(harness, false) };
        let (tx, rx) = mpsc::channel();
        let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
        std::thread::spawn(move || {
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: the provider outlives this thread — the test joins on the
            // channel before dropping it.
            unsafe {
                z_shm_provider_alloc_gc_defrag_blocking(
                    &mut out,
                    loan as *const z_loaned_shm_provider_t,
                    32,
                )
            };
            let status = out.status;
            if status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                // SAFETY: dropped once, on the thread that made it.
                unsafe { drop_buf(out.buf) };
            }
            let _ = tx.send(status);
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR),
            "a blocking allocation with no live chunk has nothing to wait for"
        );
        // SAFETY: dropped once, after the thread signalled.
        unsafe { drop_provider(provider) };

        // CONTROL: with a chunk outstanding, the same call WAITS and then
        // succeeds when that chunk is released.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(1, 64), false) };
        let mut held: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `held` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut held, z_shm_provider_loan(&provider), 32) };
        assert_eq!(held.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);

        let (tx, rx) = mpsc::channel();
        let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
        let waiter = std::thread::spawn(move || {
            let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            unsafe {
                z_shm_provider_alloc_gc_defrag_blocking(
                    &mut out,
                    loan as *const z_loaned_shm_provider_t,
                    32,
                )
            };
            let status = out.status;
            if status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                // SAFETY: dropped once, on the thread that made it.
                unsafe { drop_buf(out.buf) };
            }
            let _ = tx.send(status);
        });
        // The waiter cannot succeed while the only slot is held.
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "the blocking call must WAIT while a release is still possible"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(held.buf) };
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_OK),
            "the release must wake the waiter"
        );
        waiter.join().expect("the waiting thread finished");
        assert!(harness.lock().alloc_calls >= 2);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// A pointer-in-segment CLONE shares the segment: the destructor runs once,
    /// after the last copy.
    ///
    /// A deep copy would run it twice and a copy that dropped the context would
    /// run it early — the intermediate assertion is what tells those apart.
    #[test]
    fn a_pointer_in_segment_clone_shares_its_segment() {
        let drops = Arc::new(AtomicUsize::new(0));
        let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
        let mut byte = 0u8;
        let mut owned = z_owned_ptr_in_segment_t::null_value();
        assert!(!unsafe { z_internal_ptr_in_segment_check(&owned) });
        // SAFETY: `owned` is a live local and the context pair well formed.
        unsafe {
            z_ptr_in_segment_new(
                &mut owned,
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        assert!(unsafe { z_internal_ptr_in_segment_check(&owned) });

        let mut copy = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: both are live locals.
        unsafe { z_ptr_in_segment_clone(&mut copy, z_ptr_in_segment_loan(&owned)) };
        assert!(unsafe { z_internal_ptr_in_segment_check(&copy) });

        let mut moved = z_moved_ptr_in_segment_t { _this: owned };
        // SAFETY: dropped once.
        unsafe { z_ptr_in_segment_drop(&mut moved) };
        assert!(!unsafe { z_internal_ptr_in_segment_check(&moved._this) });
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "the segment is still held by the clone"
        );

        let mut moved_copy = z_moved_ptr_in_segment_t { _this: copy };
        // SAFETY: dropped once.
        unsafe { z_ptr_in_segment_drop(&mut moved_copy) };
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "and released exactly once when the last copy goes"
        );

        // NULL is tolerated everywhere.
        assert!(!unsafe { z_internal_ptr_in_segment_check(std::ptr::null()) });
        unsafe { z_ptr_in_segment_drop(std::ptr::null_mut()) };
        let mut grave = z_owned_ptr_in_segment_t::null_value();
        unsafe { z_ptr_in_segment_clone(&mut grave, std::ptr::null()) };
        assert!(!unsafe { z_internal_ptr_in_segment_check(&grave) });
        unsafe { z_internal_ptr_in_segment_null(&mut grave) };
    }

    /// A chunk-alloc result carries EITHER outcome, and taking the chunk
    /// gravestones the caller's pointer.
    #[test]
    fn a_chunk_alloc_result_carries_either_outcome() {
        let drops = Arc::new(AtomicUsize::new(0));
        let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
        let mut byte = 0u8;
        let mut ptr = z_owned_ptr_in_segment_t::null_value();
        // SAFETY: `ptr` is a live local.
        unsafe {
            z_ptr_in_segment_new(
                &mut ptr,
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(segment_delete),
                },
            )
        };
        let mut moved = z_moved_ptr_in_segment_t { _this: ptr };

        let mut ok = z_owned_chunk_alloc_result_t::null_value();
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&ok) });
        // SAFETY: both are live locals; the pointer is consumed.
        let rc = unsafe {
            z_chunk_alloc_result_new_ok(
                &mut ok,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 3,
                        len: 32,
                    },
                    ptr: &mut moved,
                },
            )
        };
        assert_eq!(rc, Z_OK);
        assert!(unsafe { z_internal_chunk_alloc_result_check(&ok) });
        assert!(
            !unsafe { z_internal_ptr_in_segment_check(&moved._this) },
            "taking the chunk must gravestone the caller's pointer, or it will \
             be dropped twice"
        );

        // A second take of the SAME (now empty) pointer is refused.
        let mut again = z_owned_chunk_alloc_result_t::null_value();
        // SAFETY: `moved` is a live gravestone.
        let rc = unsafe {
            z_chunk_alloc_result_new_ok(
                &mut again,
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 3,
                        len: 32,
                    },
                    ptr: &mut moved,
                },
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&again) });

        let mut moved_ok = z_moved_chunk_alloc_result_t { _this: ok };
        // SAFETY: dropped once.
        unsafe { z_chunk_alloc_result_drop(&mut moved_ok) };
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&moved_ok._this) });
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "dropping the result releases the pointer it took"
        );

        let mut err = z_owned_chunk_alloc_result_t::null_value();
        // SAFETY: a live local.
        unsafe { z_chunk_alloc_result_new_error(&mut err, Z_ALLOC_ERROR_NEED_DEFRAGMENT) };
        assert!(unsafe { z_internal_chunk_alloc_result_check(&err) });
        let mut moved_err = z_moved_chunk_alloc_result_t { _this: err };
        // SAFETY: dropped once.
        unsafe { z_chunk_alloc_result_drop(&mut moved_err) };

        // NULL is tolerated.
        assert!(!unsafe { z_internal_chunk_alloc_result_check(std::ptr::null()) });
        unsafe { z_chunk_alloc_result_drop(std::ptr::null_mut()) };
        unsafe { z_chunk_alloc_result_new_error(std::ptr::null_mut(), Z_ALLOC_ERROR_OTHER) };
        let mut grave = z_owned_chunk_alloc_result_t::null_value();
        unsafe { z_internal_chunk_alloc_result_null(&mut grave) };
        assert!(!unsafe { z_internal_chunk_alloc_result_check(&grave) });
    }

    /// `z_shm_provider_map` adopts a chunk the BACKEND allocated, and refuses
    /// one aimed at a provider that could not have issued it.
    #[test]
    fn map_adopts_a_backend_chunk_and_refuses_a_native_provider() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 128), false) };
        let drops = Arc::new(AtomicUsize::new(0));

        let make_chunk = |slot: usize| {
            let tag = Box::into_raw(Box::new(SegmentTag(drops.clone())));
            let mut ptr = z_owned_ptr_in_segment_t::null_value();
            // SAFETY: `ptr` is a live local.
            unsafe {
                z_ptr_in_segment_new(
                    &mut ptr,
                    harness.slot_ptr(slot),
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: tag as *mut c_void,
                        },
                        delete_fn: Some(segment_delete),
                    },
                )
            };
            z_moved_ptr_in_segment_t { _this: ptr }
        };

        let mut moved = make_chunk(0);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: all three are live locals.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&provider),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 0,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                96,
            )
        };
        assert_eq!(rc, Z_OK);
        // SAFETY: the result says the buffer is live.
        let loaned = unsafe { z_shm_mut_loan(&buf) };
        // SAFETY: as above.
        assert_eq!(unsafe { z_shm_mut_len(loaned) }, 96);
        // SAFETY: as above.
        assert_eq!(
            unsafe { z_shm_mut_data(loaned) },
            harness.slot_ptr(0) as *const u8,
            "the mapped buffer must be the chunk's own memory"
        );
        // SAFETY: dropped once.
        unsafe { drop_buf(buf) };
        assert_eq!(
            harness.lock().freed,
            vec![(SEGMENT_ID, 0, 128)],
            "a mapped chunk is released to the backend like an allocated one"
        );

        // A length beyond the chunk is refused.
        let mut moved = make_chunk(1);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: as above.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&provider),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 1,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                129,
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(!unsafe { z_internal_shm_mut_check(&buf) });

        // A NATIVE provider cannot have issued this descriptor, and says so.
        let mut native = z_owned_shm_provider_t::null_value();
        assert_eq!(
            unsafe { z_shm_provider_default_new(&mut native, 4096) },
            Z_OK
        );
        let mut moved = make_chunk(1);
        let mut buf = z_owned_shm_mut_t::null_value();
        // SAFETY: as above.
        let rc = unsafe {
            z_shm_provider_map(
                &mut buf,
                z_shm_provider_loan(&native),
                z_allocated_chunk_t {
                    descriptpr: z_chunk_descriptor_t {
                        segment: SEGMENT_ID,
                        chunk: 1,
                        len: 128,
                    },
                    ptr: &mut moved,
                },
                96,
            )
        };
        assert_eq!(rc, Z_EINVAL);
        assert!(
            !unsafe { z_internal_ptr_in_segment_check(&moved._this) },
            "the pointer was passed by value, so a refusal must still consume it"
        );
        // SAFETY: dropped once each.
        unsafe { drop_provider(native) };
        unsafe { drop_provider(provider) };
    }

    /// The `_async` spellings are the only place the two constructors differ,
    /// and they differ in BOTH directions: refused on a non-threadsafe provider,
    /// served on a threadsafe one.
    #[test]
    fn the_async_spellings_split_on_the_threadsafe_promise() {
        struct Signals {
            called: mpsc::Sender<isize>,
            deleted: mpsc::Sender<()>,
        }
        unsafe extern "C" fn on_result(ctx: *mut c_void, result: *mut z_buf_layout_alloc_result_t) {
            // SAFETY: the context this test handed to the async call.
            let signals = unsafe { &*(ctx as *const Signals) };
            // SAFETY: wz wrote the caller's own storage before calling back.
            let status = unsafe { (*result).status };
            let _ = signals.called.send(status as isize);
        }
        unsafe extern "C" fn on_delete(ctx: *mut c_void) {
            // SAFETY: as above; this is the last use of the context.
            let signals = unsafe { Box::from_raw(ctx as *mut Signals) };
            let _ = signals.deleted.send(());
        }

        // The NON-threadsafe provider refuses, and still consumes the context.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 256), false) };
        let (called_tx, called_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let signals = Box::into_raw(Box::new(Signals {
            called: called_tx,
            deleted: deleted_tx,
        }));
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        let rc = unsafe {
            z_shm_provider_alloc_gc_defrag_async(
                &mut out,
                z_shm_provider_loan(&provider),
                64,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: signals as *mut c_void,
                    },
                    delete_fn: Some(on_delete),
                },
                Some(on_result),
            )
        };
        assert_eq!(
            rc, Z_EINVAL,
            "a provider built by z_shm_provider_new made no thread-safety promise"
        );
        assert_eq!(
            deleted_rx.recv_timeout(Duration::from_secs(5)),
            Ok(()),
            "the context is passed by value, so a refusal must still delete it"
        );
        assert_eq!(
            called_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected),
            "a refused async call must not run the result callback"
        );
        assert_eq!(harness.lock().alloc_calls, 0);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };

        // The THREADSAFE provider serves it, and the alignment travels.
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 256), true) };
        let (called_tx, called_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let signals = Box::into_raw(Box::new(Signals {
            called: called_tx,
            deleted: deleted_tx,
        }));
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` outlives the callback — the test waits for both signals
        // before this frame ends.
        let rc = unsafe {
            z_shm_provider_alloc_gc_defrag_aligned_async(
                &mut out,
                z_shm_provider_loan(&provider),
                64,
                z_alloc_alignment_t { pow: 5 },
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: signals as *mut c_void,
                    },
                    delete_fn: Some(on_delete),
                },
                Some(on_result),
            )
        };
        assert_eq!(rc, Z_OK);
        assert_eq!(
            called_rx.recv_timeout(Duration::from_secs(5)),
            Ok(ZC_BUF_LAYOUT_ALLOC_STATUS_OK as isize)
        );
        assert_eq!(deleted_rx.recv_timeout(Duration::from_secs(5)), Ok(()));
        assert_eq!(
            harness.lock().layouts_seen,
            vec![(64usize, 5u8)],
            "the async spelling must forward the caller's alignment too"
        );
        // SAFETY: the status said the buffer is live, and nothing touches `out`
        // after both signals.
        unsafe { drop_buf(out.buf) };
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
    }

    /// The LAYOUT `_async` spellings split the same way, and the two names are
    /// one implementation.
    #[test]
    fn the_layout_async_spellings_split_on_the_same_promise() {
        struct Signals {
            called: mpsc::Sender<isize>,
            deleted: mpsc::Sender<()>,
        }
        unsafe extern "C" fn on_result(ctx: *mut c_void, result: *mut z_buf_alloc_result_t) {
            // SAFETY: the context this test handed to the async call.
            let signals = unsafe { &*(ctx as *const Signals) };
            // SAFETY: wz wrote the caller's own storage before calling back.
            let status = unsafe { (*result).status };
            let _ = signals.called.send(status as isize);
        }
        unsafe extern "C" fn on_delete(ctx: *mut c_void) {
            // SAFETY: as above; the last use of the context.
            let signals = unsafe { Box::from_raw(ctx as *mut Signals) };
            let _ = signals.deleted.send(());
        }

        for (threadsafe, expected) in [(false, Z_EINVAL), (true, Z_OK)] {
            // SAFETY: the provider owns the harness.
            let (provider, _harness) = unsafe { install(Harness::new(2, 256), threadsafe) };
            let mut layout = z_owned_precomputed_layout_t::null_value();
            // SAFETY: both are live locals.
            assert_eq!(
                unsafe { z_alloc_layout_new(&mut layout, z_shm_provider_loan(&provider), 48) },
                Z_OK
            );
            let (called_tx, called_rx) = mpsc::channel();
            let (deleted_tx, deleted_rx) = mpsc::channel();
            let signals = Box::into_raw(Box::new(Signals {
                called: called_tx,
                deleted: deleted_tx,
            }));
            let mut out: z_buf_alloc_result_t = unsafe { std::mem::zeroed() };
            // SAFETY: `out` outlives the callback — both signals are awaited
            // before this iteration ends.
            let rc = unsafe {
                z_alloc_layout_threadsafe_alloc_gc_defrag_async(
                    &mut out,
                    z_alloc_layout_loan(&layout),
                    zc_threadsafe_context_t {
                        context: zc_threadsafe_context_data_t {
                            ptr: signals as *mut c_void,
                        },
                        delete_fn: Some(on_delete),
                    },
                    Some(on_result),
                )
            };
            assert_eq!(rc, expected, "threadsafe = {threadsafe}");
            assert_eq!(deleted_rx.recv_timeout(Duration::from_secs(5)), Ok(()));
            if expected == Z_OK {
                assert_eq!(
                    called_rx.recv_timeout(Duration::from_secs(5)),
                    Ok(ZC_BUF_ALLOC_STATUS_OK as isize)
                );
                // SAFETY: the status said the buffer is live.
                unsafe { drop_buf(out.buf) };
            } else {
                assert_eq!(called_rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
            }
            let mut moved = z_moved_precomputed_layout_t { _this: layout };
            // SAFETY: dropped once.
            unsafe { z_precomputed_layout_drop(&mut moved) };
            // SAFETY: dropped once.
            unsafe { drop_provider(provider) };
        }
    }

    /// A NON-threadsafe backend's callbacks are serialised; a threadsafe one's
    /// are not.
    ///
    /// The second half is the CONTROL and it is what makes the first half mean
    /// anything: `concurrent_max == 1` is also what a wz that ran both calls on
    /// one thread would report, and a probe that could never observe 2 would
    /// pass on any implementation at all.
    #[test]
    fn a_non_threadsafe_backend_sees_one_callback_at_a_time() {
        for (threadsafe, expected_max) in [(false, 1usize), (true, 2usize)] {
            let mut harness = Harness::new(4, 128);
            harness.probe_concurrency = true;
            // SAFETY: the provider owns the harness.
            let (provider, borrow) = unsafe { install(harness, threadsafe) };
            let loan = unsafe { z_shm_provider_loan(&provider) } as usize;
            let threads: Vec<_> = (0..2)
                .map(|_| {
                    std::thread::spawn(move || {
                        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
                        // SAFETY: the provider outlives every thread — they are
                        // joined below.
                        unsafe {
                            z_shm_provider_alloc(
                                &mut out,
                                loan as *const z_loaned_shm_provider_t,
                                32,
                            )
                        };
                        if out.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK {
                            // SAFETY: dropped once, on the thread that made it.
                            unsafe { drop_buf(out.buf) };
                        }
                    })
                })
                .collect();
            for thread in threads {
                thread.join().expect("an allocating thread finished");
            }
            assert_eq!(
                borrow.lock().concurrent_max,
                expected_max,
                "threadsafe = {threadsafe}"
            );
            // SAFETY: dropped once, after every thread joined.
            unsafe { drop_provider(provider) };
        }
    }

    /// The two POSIX constructors: `_new` is the default backend under its other
    /// name, and `_with_layout_new` carries the layout's ALIGNMENT into the
    /// segment's base.
    ///
    /// ⚠ The address assertion alone would be probabilistic — a 4096-aligned
    /// allocation is sometimes 8192-aligned by luck — so the segment's own
    /// alignment is asserted as well. That one is deterministic, and it is the
    /// half a constructor that ignored the layout fails.
    #[test]
    fn the_posix_constructors_size_and_align_their_segment() {
        let mut plain = z_owned_shm_provider_t::null_value();
        assert_eq!(unsafe { z_posix_shm_provider_new(&mut plain, 4096) }, Z_OK);
        // SAFETY: the provider is live.
        assert_eq!(
            unsafe { z_shm_provider_available(z_shm_provider_loan(&plain)) },
            4096
        );
        // SAFETY: dropped once.
        unsafe { drop_provider(plain) };

        const POW: u8 = 13; // 8192, deliberately wider than SEGMENT_ALIGN
        let mut layout = z_owned_memory_layout_t::null_value();
        assert_eq!(
            unsafe {
                z_memory_layout_new(&mut layout, 64 * 1024, z_alloc_alignment_t { pow: POW })
            },
            Z_OK
        );
        let mut provider = z_owned_shm_provider_t::null_value();
        // SAFETY: both are live locals.
        assert_eq!(
            unsafe {
                z_posix_shm_provider_with_layout_new(&mut provider, z_memory_layout_loan(&layout))
            },
            Z_OK
        );
        // SAFETY: the provider is live and this crate minted its handle.
        let backend =
            unsafe { provider_of(z_shm_provider_loan(&provider)) }.expect("a live provider");
        match backend {
            Provider::Native(segment) => {
                assert_eq!(segment.len, 64 * 1024);
                assert_eq!(
                    segment.align,
                    1usize << POW,
                    "a constructor that ignored the layout would leave SEGMENT_ALIGN"
                );
                assert_eq!(segment.base as usize % (1usize << POW), 0);
            }
            Provider::Foreign(_) => panic!("the POSIX constructor builds a native provider"),
        }

        // And an allocation at that alignment reaches an aligned ADDRESS, with a
        // skew first so the answer is not the base's by accident.
        let mut skew: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `skew` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut skew, z_shm_provider_loan(&provider), 1) };
        assert_eq!(skew.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe {
            z_shm_provider_alloc_aligned(
                &mut out,
                z_shm_provider_loan(&provider),
                128,
                z_alloc_alignment_t { pow: POW },
            )
        };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: the status says the buffer is live.
        let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
        assert_eq!(data as usize % (1usize << POW), 0);
        // SAFETY: dropped once each.
        unsafe { drop_buf(out.buf) };
        unsafe { drop_buf(skew.buf) };
        unsafe { drop_provider(provider) };
        let mut moved = z_moved_memory_layout_t { _this: layout };
        // SAFETY: dropped once.
        unsafe { z_memory_layout_drop(&mut moved) };

        // NULL and a nonsense layout are refused.
        let mut grave = z_owned_shm_provider_t::null_value();
        assert_eq!(
            unsafe { z_posix_shm_provider_with_layout_new(&mut grave, std::ptr::null()) },
            Z_ENULL
        );
        assert!(!unsafe { z_internal_shm_provider_check(&grave) });
        assert_eq!(
            unsafe { z_posix_shm_provider_new(std::ptr::null_mut(), 8) },
            Z_ENULL
        );
    }

    /// A foreign provider's BUFFER outlives the provider handle, and the
    /// backend is not released until the last buffer is gone.
    ///
    /// `z_pub_shm.c`'s teardown order relies on this for the native provider;
    /// the foreign one has the sharper version of it, because releasing the
    /// context early would run a C destructor over memory a live buffer still
    /// points into.
    #[test]
    fn a_foreign_buffer_outlives_its_provider_handle() {
        // SAFETY: the provider owns the harness.
        let (provider, harness) = unsafe { install(Harness::new(2, 128), false) };
        let deleted = harness.deleted.clone();
        let mut out: z_buf_layout_alloc_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: `out` is writable and the provider live.
        unsafe { z_shm_provider_alloc(&mut out, z_shm_provider_loan(&provider), 64) };
        assert_eq!(out.status, ZC_BUF_LAYOUT_ALLOC_STATUS_OK);
        // SAFETY: dropped once.
        unsafe { drop_provider(provider) };
        assert_eq!(
            deleted.load(Ordering::SeqCst),
            0,
            "a live buffer still holds the backend"
        );
        // SAFETY: the buffer is still live, and so is the memory behind it.
        let data = unsafe { z_shm_mut_data(z_shm_mut_loan(&out.buf)) };
        // SAFETY: 64 bytes of the backend's arena, still ours.
        assert_eq!(unsafe { std::slice::from_raw_parts(data, 64) }.len(), 64);
        // SAFETY: dropped once.
        unsafe { drop_buf(out.buf) };
        assert_eq!(deleted.load(Ordering::SeqCst), 1);
    }

    /// A NULL `this_` still consumes the context both constructors take by
    /// value, so a caller that passed a bad output does not leak its own state.
    #[test]
    fn a_refused_constructor_still_deletes_the_context() {
        let deleted = Arc::new(AtomicUsize::new(0));
        struct Tag(Arc<AtomicUsize>);
        unsafe extern "C" fn tag_delete(ctx: *mut c_void) {
            // SAFETY: the pointer this test handed over.
            let tag = unsafe { Box::from_raw(ctx as *mut Tag) };
            tag.0.fetch_add(1, Ordering::SeqCst);
        }
        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        // SAFETY: a deliberate null output.
        unsafe {
            z_shm_provider_new(
                std::ptr::null_mut(),
                zc_context_t {
                    context: tag as *mut c_void,
                    delete_fn: Some(tag_delete),
                },
                callbacks(),
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 1);

        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        // SAFETY: as above.
        unsafe {
            z_shm_provider_threadsafe_new(
                std::ptr::null_mut(),
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(tag_delete),
                },
                callbacks(),
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 2);

        let tag = Box::into_raw(Box::new(Tag(deleted.clone())));
        let mut byte = 0u8;
        // SAFETY: as above.
        unsafe {
            z_ptr_in_segment_new(
                std::ptr::null_mut(),
                &mut byte,
                zc_threadsafe_context_t {
                    context: zc_threadsafe_context_data_t {
                        ptr: tag as *mut c_void,
                    },
                    delete_fn: Some(tag_delete),
                },
            )
        };
        assert_eq!(deleted.load(Ordering::SeqCst), 3);
    }
}
