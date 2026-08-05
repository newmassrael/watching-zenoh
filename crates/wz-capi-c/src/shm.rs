// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

impl Segment {
    /// Allocate a segment of `len` bytes, all free.
    ///
    /// A ZERO-length segment is legal and is not an edge case to reject:
    /// `z_get_shm.c` builds its provider from `strlen(value)`, which is 0 when
    /// the example is run without a payload.
    fn new(len: usize) -> Arc<Self> {
        let mut bytes = vec![0u8; len].into_boxed_slice();
        let base = bytes.as_mut_ptr();
        std::mem::forget(bytes);
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
        if self.len == 0 && self.base.is_null() {
            return;
        }
        // SAFETY: `base` / `len` came from `Box<[u8]>::into` in `new` and no
        // chunk can outlive the `Arc` that owns this.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(self.base, self.len)) });
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

/// Mutably borrow a provider (zenoh-c `z_shm_provider_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned provider.
#[no_mangle]
pub unsafe extern "C" fn z_shm_provider_loan_mut(
    this_: *mut z_owned_shm_provider_t,
) -> *mut z_loaned_shm_provider_t {
    this_ as *mut z_loaned_shm_provider_t
}

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
