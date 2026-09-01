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
            let layout = std::alloc::Layout::from_size_align(len, SEGMENT_ALIGN)
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
        let layout = std::alloc::Layout::from_size_align(self.len, SEGMENT_ALIGN)
            .expect("the layout `new` allocated with");
        unsafe { std::alloc::dealloc(self.base, layout) };
    }
}

/// One allocated chunk. Dropping it returns the range to the segment.
struct ShmChunk {
    segment: Arc<Segment>,
    start: usize,
    len: usize,
    /// `false` once the chunk has been frozen into an immutable `z_owned_shm_t`.
    /// The flag is what [`z_shm_try_reloan_mut`] answers with, so it has to
    /// travel with the chunk rather than with the handle that names it.
    mutable: bool,
}

impl ShmChunk {
    /// The chunk's bytes.
    fn as_slice(&self) -> &[u8] {
        // SAFETY: the range was handed out by `claim` and is not handed out
        // again until this chunk drops, so no other live chunk aliases it.
        unsafe { std::slice::from_raw_parts(self.segment.base.add(self.start), self.len) }
    }

    /// The chunk's bytes, mutably.
    fn as_mut_ptr(&self) -> *mut u8 {
        // SAFETY: as `as_slice` — exclusive by the allocator's invariant.
        unsafe { self.segment.base.add(self.start) }
    }
}

impl Drop for ShmChunk {
    fn drop(&mut self) {
        if self.len > 0 {
            self.segment
                .books()
                .release(self.start, self.start + self.len);
        }
        // Woken even for a zero-length chunk: a waiter blocked on a request this
        // release cannot satisfy re-checks and blocks again, which is cheaper
        // than reasoning about which releases are worth a notify.
        self.segment.released.notify_all();
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

/// Read the segment behind a loaned provider.
///
/// # Safety
/// `this_` must be null, or a valid loaned provider whose handle slot holds a
/// live `Arc<Segment>` pointer.
unsafe fn provider_segment<'a>(this_: *const z_loaned_shm_provider_t) -> Option<&'a Arc<Segment>> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<Arc<Segment>>` this crate leaked.
    Some(unsafe { &*(handle as *const Arc<Segment>) })
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
        let segment = Segment::new(size);
        let handle = Box::into_raw(Box::new(segment)) as Handle;
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
    let Some(segment) = (unsafe { provider_segment(provider) }) else {
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

    let mut books = segment.books();
    let start = loop {
        if let Some(start) = books.claim(size, align) {
            break start;
        }
        // A request LARGER than the whole segment can never be satisfied, no
        // matter who releases what, so blocking on it would be the deadlock
        // rather than the wait. Reported as out-of-memory on both policies.
        if size > segment.len || !blocking {
            let reason = if size > segment.len || books.available() < size {
                Z_ALLOC_ERROR_OUT_OF_MEMORY
            } else {
                // Enough total room, but no single range holds it.
                Z_ALLOC_ERROR_NEED_DEFRAGMENT
            };
            // SAFETY: `out` was checked non-null above.
            unsafe {
                (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_ALLOC_ERROR;
                (*out).alloc_error = reason;
            }
            return;
        }
        books = segment
            .released
            .wait(books)
            .unwrap_or_else(|e| e.into_inner());
    };
    drop(books);

    let boxed = Box::new(ShmChunk {
        segment: segment.clone(),
        start,
        len: size,
        mutable: true,
    });
    // SAFETY: `out` was checked non-null above.
    unsafe {
        (*out).status = ZC_BUF_LAYOUT_ALLOC_STATUS_OK;
        (*out).buf = z_owned_shm_mut_t::from_handle(Box::into_raw(boxed) as Handle);
        (*out).alloc_error = Z_ALLOC_ERROR_OTHER;
        (*out).layout_error = Z_LAYOUT_ERROR_INCORRECT_LAYOUT_ARGS;
    }
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
    segment: Arc<Segment>,
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
    let Some(segment) = (unsafe { provider_segment(provider) }) else {
        return Z_ENULL;
    };
    // The SAME two refusals `z_memory_layout_new` makes, and for the same
    // reason: a layout is a precondition, so a nonsense one must not become an
    // allocation failure later that cannot say what was wrong.
    if size == 0 || usize::from(alignment.pow) >= usize::BITS as usize {
        return Z_EINVAL;
    }
    let state = PrecomputedLayoutState {
        segment: segment.clone(),
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
    let provider = z_owned_shm_provider_t::from_handle(Box::into_raw(Box::new(
        state.segment.clone(),
    )) as Handle);
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
        match unsafe { provider_segment(provider) } {
            Some(segment) => segment.books().available(),
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
        let _ = unsafe { provider_segment(provider) };
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
        match unsafe { provider_segment(provider) } {
            Some(segment) => segment.books().largest(),
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
            // SAFETY: a live `Box<Arc<Segment>>` this crate leaked.
            drop(unsafe { Box::from_raw(handle as *mut Arc<Segment>) });
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
        let segment = source.segment.clone();
        let Some(start) = segment.books().claim(source.len, 1) else {
            return;
        };
        let copy = ShmChunk {
            segment,
            start,
            len: source.len,
            mutable: false,
        };
        // SAFETY: both ranges are live and, being distinct allocator ranges, do
        // not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(source.as_slice().as_ptr(), copy.as_mut_ptr(), copy.len)
        };
        // SAFETY: `out` was checked non-null above.
        unsafe { *out = z_owned_shm_t::from_handle(Box::into_raw(Box::new(copy)) as Handle) };
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

const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<z_alloc_alignment_t>() == 1);
    assert!(size_of::<z_buf_layout_alloc_result_t>() == 96);
    assert!(align_of::<z_buf_layout_alloc_result_t>() == 8);
    assert!(size_of::<z_buf_alloc_result_t>() == 96);
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
                segment: segment.clone(),
                start,
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
                    segment: segment.clone(),
                    start,
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
            segment: segment.clone(),
            start,
            len: 8,
            mutable: true,
        };
        assert!(chunk.mutable);
        chunk.mutable = false;
        assert_eq!(chunk.start, start);
        assert_eq!(segment.books().available(), 56);
    }
}
