// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_bytes_*`, `z_slice_*`, `z_string_*` — the payload value types.
//!
//! `z_bytes_t` is the wire payload (`z_put` / `z_publisher_put` consume it and
//! the subscriber callback reads it back). A subscriber reads a delivered
//! payload the pico way: `z_sample_payload` → `z_bytes_to_slice` →
//! `z_slice_data` / `z_slice_len` (or `z_bytes_to_string` → `z_string_data` /
//! `z_string_len`).
//!
//! bytes and slice use the handle model (owned == loaned layout, `loan` is a
//! cast; the accessor reads the payload's block). string uses the borrowed-view
//! model: an owned string holds a `StringState` and hands out a cached
//! `{ start, len }` self-view on `loan`, so `z_loaned_string_t` is the same
//! borrowed shape a view string (from `z_keyexpr_as_view_string`) produces.
//!
//! The bytes a payload, a string or a slice holds lie in a block (`Block`): in a library with
//! the process pools, one of their payloads' area (`HELD_PAYLOAD_BYTES`), so making or copying one
//! allocates nothing once the pools are reserved and is refused with
//! `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when the area has no block for it; in one without, the heap's.

use core::ffi::{c_char, c_void, CStr};
use core::ptr::NonNull;
use core::sync::atomic::{fence, AtomicUsize, Ordering};

use crate::prelude::*;

use crate::abi::{
    handle_ref, impl_value_ownership, z_loaned_bytes_t, z_loaned_slice_t, z_loaned_string_t,
    z_moved_bytes_t, z_moved_slice_t, z_moved_string_t, z_owned_bytes_t, z_owned_slice_t,
    z_owned_string_t, z_view_slice_t, z_view_string_t,
};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};

// --- payloads -------------------------------------------------------------

/// The caller's deleter and the buffer it releases: `deleter(value, context)`
/// runs ONCE, when the last holder of the bytes it releases goes (pico's
/// `_z_delete_context_t`, run by `_z_slice_clear`).
///
/// A `None` deleter is pico's "static": the caller keeps the buffer and nothing
/// is released.
pub(crate) struct Release {
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    value: *mut c_void,
    context: *mut c_void,
}

impl Release {
    /// Release `value` through `deleter` when this drops.
    pub(crate) fn new(
        deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
        value: *mut c_void,
        context: *mut c_void,
    ) -> Self {
        Self {
            deleter,
            value,
            context,
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(deleter) = self.deleter.take() {
            // SAFETY: the deleter is the caller's, handed over with the buffer
            // it releases and with the promise pico's contract makes — that it
            // may be called once, with exactly these two arguments.
            unsafe { deleter(self.value, self.context) };
        }
    }
}

/// No room for an owned value's bytes, or for its place: what a constructor or a copy of a payload,
/// a string or a slice meets when the payloads' area of the process pools, or the pool of its
/// kind, has none free; the call answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` and leaves its output null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoRoom;

impl NoRoom {
    /// The code a door answers for it.
    pub(crate) const fn code(self) -> ZResult {
        crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY
    }
}

/// The head of a block of payload storage, which its contents follow.
///
/// wz's payload model was an owning `Vec<u8>` with a deep-copying `Clone`, and
/// that is not what zenoh-pico's is: its constructors that take a caller's
/// buffer ALIAS it, its moves take over the allocation they are given, its
/// payload clone SHARES the storage, and the caller's deleter runs when the
/// last holder is dropped. All four are observable from C (pointer identity,
/// mutation through the alias, the deleter's timing), and
/// `pico_bytes_alias_twice_and_diff` measures each against the real library.
/// A block therefore holds one of two things, bytes of its own or the record of
/// the caller's ([`Alias`]), and its holders share it by the count in its head,
/// as zenoh-pico's arc-slices share theirs.
#[repr(C, align(16))]
struct BlockHead {
    /// The holders of the block.
    refs: AtomicUsize,
    /// The bytes after the head, with [`ALIAS`] set when they hold an [`Alias`].
    room: usize,
}

/// The bytes of a block's head, after which its contents lie aligned to 16.
const HEAD: usize = core::mem::size_of::<BlockHead>();

/// Set in [`BlockHead::room`] when the block holds the record of the caller's bytes.
const ALIAS: usize = 1 << (usize::BITS - 1);

/// The CALLER'S bytes, described and not copied, with the caller's promise to
/// release them (or not to, for a static buffer) through `_release`.
struct Alias {
    start: *const u8,
    len: usize,
    _release: Release,
}

/// A block of at least `bytes` bytes aligned to 16 from the payloads' area of the process pools,
/// and the bytes it has; `None` when the area has no free block that large.
#[cfg(wz_process_pools)]
fn take_block(bytes: usize) -> Option<(NonNull<u8>, usize)> {
    crate::process_pool::take_block(bytes)
}

/// Give back a block [`take_block`] handed out.
///
/// # Safety
/// `at` and `bytes` are a block [`take_block`] handed out, given back once.
#[cfg(wz_process_pools)]
unsafe fn give_back_block(at: NonNull<u8>, bytes: usize) {
    crate::process_pool::give_back_block(at, bytes);
}

/// A block of `bytes` bytes aligned to 16 from the heap: a library without the process pools keeps
/// its payloads where its engine keeps its sessions.
#[cfg(not(wz_process_pools))]
fn take_block(bytes: usize) -> Option<(NonNull<u8>, usize)> {
    let layout =
        core::alloc::Layout::from_size_align(bytes, core::mem::align_of::<BlockHead>()).ok()?;
    // SAFETY: a block is never of zero bytes: it has its head.
    NonNull::new(unsafe { alloc::alloc::alloc(layout) }).map(|at| (at, bytes))
}

/// Give back a block [`take_block`] handed out.
///
/// # Safety
/// `at` and `bytes` are a block [`take_block`] handed out, given back once.
#[cfg(not(wz_process_pools))]
unsafe fn give_back_block(at: NonNull<u8>, bytes: usize) {
    alloc::alloc::dealloc(
        at.as_ptr(),
        core::alloc::Layout::from_size_align_unchecked(bytes, core::mem::align_of::<BlockHead>()),
    );
}

/// One holder's share of a block: a payload's storage, or a string's or a slice's that payloads
/// made over it share. The last share let go runs the caller's release, for the record of an
/// alias, and gives the block back.
pub(crate) struct Block {
    head: NonNull<BlockHead>,
}

// SAFETY: a block's own bytes are written only while it has one holder ([`Block::write`]), an
// alias's are the caller's, which pico's contract keeps valid and unchanged until the release
// runs, and the count of its holders is atomic.
unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    /// A block with room for `room` bytes of its own after its head, this its one holder; `None`
    /// when there is no such block.
    fn with_room(room: usize) -> Option<Self> {
        let (at, bytes) = take_block(HEAD.checked_add(room)?)?;
        let head = at.cast::<BlockHead>();
        // SAFETY: the block is `bytes` bytes aligned to 16, which nothing else holds.
        unsafe {
            head.as_ptr().write(BlockHead {
                refs: AtomicUsize::new(1),
                room: bytes - HEAD,
            })
        };
        Some(Self { head })
    }

    /// A block holding a copy of `bytes`; `None` when there is no room for one.
    fn copy_of(bytes: &[u8]) -> Option<Self> {
        let mut block = Self::with_room(bytes.len())?;
        // SAFETY: a new block, of one holder, with room for the bytes.
        unsafe { block.write(0, bytes) };
        Some(block)
    }

    /// A block holding the record of the caller's `len` bytes at `start`, which `release` lets
    /// go when the last holder goes; with no room for one, the release is handed back.
    ///
    /// # Safety
    /// As [`ByteBuf::aliased`].
    unsafe fn alias(start: *const u8, len: usize, release: Release) -> Result<Self, Release> {
        let Some(block) = Self::with_room(core::mem::size_of::<Alias>()) else {
            return Err(release);
        };
        (*block.head.as_ptr()).room |= ALIAS;
        block.contents().cast::<Alias>().write(Alias {
            start,
            len,
            _release: release,
        });
        Ok(block)
    }

    fn head(&self) -> &BlockHead {
        // SAFETY: the head lives as long as a holder does.
        unsafe { self.head.as_ref() }
    }

    fn is_alias(&self) -> bool {
        self.head().room & ALIAS != 0
    }

    /// The bytes of the block after its head.
    fn room(&self) -> usize {
        self.head().room & !ALIAS
    }

    /// Where the contents start.
    fn contents(&self) -> *mut u8 {
        // SAFETY: the contents follow the head inside the block.
        unsafe { self.head.as_ptr().cast::<u8>().add(HEAD) }
    }

    /// Where the bytes the block holds start, and at most how many there are: its own room, or the
    /// caller's bytes its record describes. Which of them are written is its holders' to know.
    fn span(&self) -> (*const u8, usize) {
        if self.is_alias() {
            // SAFETY: an alias block holds its record from its making to its last holder.
            let alias = unsafe { &*self.contents().cast::<Alias>() };
            (alias.start, alias.len)
        } else {
            (self.contents().cast_const(), self.room())
        }
    }

    /// Write `bytes` at `at` of the block's own room.
    ///
    /// # Safety
    /// This is the block's one holder, the block holds bytes of its own, and `at + bytes.len()` is
    /// within its room.
    unsafe fn write(&mut self, at: usize, bytes: &[u8]) {
        debug_assert!(!self.is_alias() && at + bytes.len() <= self.room());
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.contents().add(at), bytes.len());
    }

    /// Another holder of the block.
    fn share(&self) -> Self {
        let before = self.head().refs.fetch_add(1, Ordering::Relaxed);
        // As `Arc` does: a count past half the address space is a share leaked in a loop.
        assert!(
            before <= isize::MAX as usize,
            "a payload's block is shared past any count"
        );
        Self { head: self.head }
    }

    /// Whether this is the block's one holder.
    fn is_unique(&self) -> bool {
        self.head().refs.load(Ordering::Acquire) == 1
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        if self.head().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        let bytes = HEAD + self.room();
        if self.is_alias() {
            // SAFETY: the last holder lets the record go once, which runs the caller's release.
            unsafe { core::ptr::drop_in_place(self.contents().cast::<Alias>()) };
        }
        // SAFETY: the block was taken with `bytes` bytes and no holder is left.
        unsafe { give_back_block(self.head.cast::<u8>(), bytes) };
    }
}

/// Where a payload's bytes are held.
enum Store {
    /// Nowhere: an empty payload holds no block.
    Empty,
    /// A block its holders share.
    Shared(Block),
    /// The start of bytes the payload only reads, for as long as their owner keeps them: a
    /// sample's, reply's or query's payload handed to a callback ([`ByteBuf::lent`]). Never shared,
    /// so a holder that may outlive them is given a copy.
    Lent(*const u8),
}

// SAFETY: a lent payload's bytes are its lender's, valid and unchanged for as long as the payload
// lives (`ByteBuf::lent`); nothing writes through the pointer, so it is shared between threads
// exactly as the lender's own reference would be. A block is `Send` and `Sync` on its own.
unsafe impl Send for Store {}
unsafe impl Sync for Store {}

/// The `len` bytes at `start`, none when `len` is zero.
///
/// # Safety
/// `start` is null only with `len` zero, and the `len` bytes there are written and live while
/// they are read.
unsafe fn lent_bytes<'a>(start: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(start, len)
    }
}

/// Behind a `z_owned_bytes_t` / `z_owned_slice_t` handle: the raw bytes, plus
/// the SEGMENT boundaries a `z_bytes_writer_append` left in them.
///
/// The bytes alone would be enough for every wire path and every reader — and
/// they were, until upstream's own `z_bytes.c` walked a payload with
/// `z_bytes_get_slice_iterator` and printed one 9-byte slice on wz where the
/// real zenoh-pico printed three of 3. pico's `_z_bytes_t` is a VECTOR of
/// arc-slices and `z_bytes_writer_append` moves a whole payload in as its own
/// slice, so appending three payloads leaves three slices a program can walk.
/// wz's contiguous buffer lost that structure, and only a foreign oracle could
/// show it: every other observable (length, content, `z_bytes_to_string`, the
/// reader) is identical either way.
///
/// So the buffer stays CONTIGUOUS — every consumer that wants bytes still gets
/// one `&[u8]` with no gather — and the boundaries ride alongside it as end
/// offsets. `bounds` empty means "one implicit segment covering all the data"
/// (or none, when the data is empty), which is the state every inbound sample
/// and every single-shot constructor is in; only the writer ever populates it.
///
/// A clone SHARES the block ([`ByteBuf::try_clone`]), as pico's `z_bytes_clone`
/// does; a copy is asked for by name ([`ByteBuf::copied`]), and a writer that
/// needs to change shared or aliased bytes copies them first. A LENT payload
/// ([`ByteBuf::lent`]) has no block to share, so its clone is a copy. Every
/// one that takes a block can be refused one ([`NoRoom`]).
pub(crate) struct ByteBuf {
    backing: Store,
    /// How much of the block this payload is: shorter than the block's room for a payload made
    /// over a string, whose terminator it does not carry, and for a writer's, which grows into it.
    len: usize,
    /// END offset of each segment. Either empty (the implicit single segment)
    /// or ending at `len`.
    bounds: Vec<usize>,
}

impl core::fmt::Debug for ByteBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ByteBuf")
            .field("len", &self.len)
            .field("bounds", &self.bounds)
            .finish()
    }
}

impl Default for ByteBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteBuf {
    /// An empty payload with no segments, which holds no block.
    pub(crate) fn new() -> Self {
        Self {
            backing: Store::Empty,
            len: 0,
            bounds: Vec::new(),
        }
    }

    /// A payload holding a copy of `bytes` in a block of its own.
    pub(crate) fn copy_of(bytes: &[u8]) -> Result<Self, NoRoom> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        let block = Block::copy_of(bytes).ok_or(NoRoom)?;
        Ok(Self {
            backing: Store::Shared(block),
            len: bytes.len(),
            bounds: Vec::new(),
        })
    }

    /// A payload that DESCRIBES the caller's `len` bytes at `start` and lets
    /// `release` return them when the last holder is dropped. Refused, the release runs at once,
    /// as pico's transfer of the caller's buffer is unconditional once the call is made.
    ///
    /// # Safety
    /// `start` must be null with `len == 0`, or point at `len` readable bytes
    /// that stay valid and unchanged until `release` has run.
    pub(crate) unsafe fn aliased(
        start: *const u8,
        len: usize,
        release: Release,
    ) -> Result<Self, NoRoom> {
        let block = Block::alias(start, len, release).map_err(|release| {
            drop(release);
            NoRoom
        })?;
        Ok(Self {
            backing: Store::Shared(block),
            len,
            bounds: Vec::new(),
        })
    }

    /// A payload that READS `bytes` where they lie and allocates nothing: a sample's payload
    /// handed to a callback, read where the session delivered it. What may outlive the bytes is
    /// given a copy: a clone, and the storage a slice or a string takes over.
    ///
    /// # Safety
    /// `bytes` stay valid and unchanged until this payload is dropped.
    pub(crate) unsafe fn lent(bytes: &[u8]) -> Self {
        Self {
            backing: Store::Lent(bytes.as_ptr()),
            len: bytes.len(),
            bounds: Vec::new(),
        }
    }

    /// The payload's bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        match &self.backing {
            Store::Empty => &[],
            // SAFETY: the first `len` bytes of the block's span are this payload's, written when
            // it was made, and the block lives as long as this holder.
            Store::Shared(block) => unsafe { lent_bytes(block.span().0, self.len) },
            // SAFETY: a lent payload's bytes outlive it (`Self::lent`).
            Store::Lent(start) => unsafe { lent_bytes(*start, self.len) },
        }
    }

    /// Another holder of the payload: one that SHARES its block, as pico's `z_bytes_clone` shares
    /// the storage, or for a lent payload, whose lender's bytes a clone may outlive, a copy.
    pub(crate) fn try_clone(&self) -> Result<Self, NoRoom> {
        let backing = match &self.backing {
            Store::Empty => Store::Empty,
            Store::Shared(block) => Store::Shared(block.share()),
            Store::Lent(_) => Self::copy_of(self.as_slice())?.backing,
        };
        Ok(Self {
            backing,
            len: self.len,
            bounds: self.bounds.clone(),
        })
    }

    /// The block, for a holder that keeps it: a lent payload's bytes are copied into one of their
    /// own first; an empty payload has none.
    fn into_block(self) -> Result<Option<Block>, NoRoom> {
        match self.backing {
            Store::Empty => Ok(None),
            Store::Shared(block) => Ok(Some(block)),
            Store::Lent(_) if self.len == 0 => Ok(None),
            // SAFETY: a lent payload's bytes outlive it (`Self::lent`), and it lives here.
            Store::Lent(start) => Block::copy_of(unsafe { lent_bytes(start, self.len) })
                .map(Some)
                .ok_or(NoRoom),
        }
    }

    /// A payload with the same bytes in a block of its own: the copy an
    /// extraction (`z_bytes_to_slice`) makes and a clone does not.
    pub(crate) fn copied(&self) -> Result<Self, NoRoom> {
        Self::copy_of(self.as_slice())
    }

    /// Make the payload's bytes a block of its own, of this one holder, with room for `extra` more
    /// bytes after them: the block it has when that is so, else a new one the bytes are copied
    /// into, twice as large as they are where there is such a block, so a writer's appends copy
    /// the bytes a bounded number of times.
    fn reserve(&mut self, extra: usize) -> Result<(), NoRoom> {
        let need = self.len.checked_add(extra).ok_or(NoRoom)?;
        if let Store::Shared(block) = &self.backing {
            if block.is_unique() && !block.is_alias() && block.room() >= need {
                return Ok(());
            }
        }
        let grown = need.max(self.len.saturating_mul(2));
        let mut block = Block::with_room(grown)
            .or_else(|| Block::with_room(need))
            .ok_or(NoRoom)?;
        // SAFETY: a new block, of one holder, with room for the payload's bytes.
        unsafe { block.write(0, self.as_slice()) };
        self.backing = Store::Shared(block);
        Ok(())
    }

    /// Write `bytes` after the payload's bytes, into the room [`Self::reserve`] made for them.
    fn put_after(&mut self, bytes: &[u8]) {
        if let Store::Shared(block) = &mut self.backing {
            // SAFETY: `reserve` left a block of the payload's own, of one holder, with room for
            // these bytes after its own.
            unsafe { block.write(self.len, bytes) };
        }
        self.len += bytes.len();
    }

    /// Whether the payload is ONE slice, which is what
    /// `z_bytes_get_contiguous_view` requires.
    ///
    /// wz's storage is always one block, so a naive answer would be "always" —
    /// and that would be WRONG against a real pico, whose `_z_bytes_t` is a
    /// vector of arc-slices and whose `z_bytes_get_contiguous_view` fails once
    /// there is more than one. The question the export asks is about the
    /// payload's SEGMENT structure, not about wz's allocator, so it is answered
    /// from `bounds` — the same field the slice iterator walks, and the same
    /// field the R311y532 foreign oracle showed wz had been discarding. The export
    /// is the unstable API's, and so is this.
    #[cfg(feature = "unstable-api")]
    pub(crate) fn is_contiguous(&self) -> bool {
        self.bounds.len() <= 1
    }

    /// The `idx`-th segment, or `None` past the end — what
    /// `z_bytes_slice_iterator_next` yields.
    pub(crate) fn segment(&self, idx: usize) -> Option<&[u8]> {
        let data = self.as_slice();
        if self.bounds.is_empty() {
            return (idx == 0 && !data.is_empty()).then_some(data);
        }
        let start = if idx == 0 {
            0
        } else {
            *self.bounds.get(idx - 1)?
        };
        let end = *self.bounds.get(idx)?;
        data.get(start..end)
    }

    /// Append another payload AS ITS OWN SEGMENTS (pico
    /// `z_bytes_writer_append`, which moves the source's slice list in). Refused, the payload is
    /// as it was.
    ///
    /// The first append on a buffer that already holds unsegmented bytes has to
    /// close that implicit segment first, or the existing content would silently
    /// merge into the newly appended one.
    pub(crate) fn append_segments(&mut self, other: &ByteBuf) -> Result<(), NoRoom> {
        if other.len != 0 {
            self.reserve(other.len)?;
        }
        if self.bounds.is_empty() && self.len != 0 {
            self.bounds.push(self.len);
        }
        let mut idx = 0usize;
        while let Some(segment) = other.segment(idx) {
            self.put_after(segment);
            self.bounds.push(self.len);
            idx += 1;
        }
        Ok(())
    }

    /// Append raw bytes to the CURRENT segment (pico
    /// `z_bytes_writer_write_all`, which writes into the buffer rather than
    /// adding a slice). Refused, the payload is as it was.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<(), NoRoom> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.reserve(bytes.len())?;
        self.put_after(bytes);
        if let Some(last) = self.bounds.last_mut() {
            *last = self.len;
        }
        Ok(())
    }
}

impl core::ops::Deref for ByteBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A payload over the block a slice or string state holds, SHARING it, so the
/// payload has the state's own address and the caller's deleter waits for both
/// (pico's `z_bytes_from_slice` / `z_bytes_from_string` take over the
/// allocation they are given).
///
/// A state whose view no longer describes its block — a caller emptied it, or
/// moved it out through `take_from_loaned` — has nothing to share and reads as
/// a copy of the bytes it now shows.
///
/// # Safety
/// `start` / `len` must be a view a state made over `block`, of whose bytes `filled` are
/// written, as the states' own `backing` documents.
unsafe fn payload_over(
    block: Option<&Block>,
    filled: usize,
    start: *const u8,
    len: usize,
) -> Result<ByteBuf, NoRoom> {
    if let Some(block) = block {
        if start == block.span().0 && len <= filled {
            return Ok(ByteBuf {
                backing: Store::Shared(block.share()),
                len,
                bounds: Vec::new(),
            });
        }
    }
    ByteBuf::copy_of(crate::abi::view_bytes(start, len).unwrap_or(&[]))
}

/// The terminator an empty owned string's view points at, so its data is a C string with no block.
static EMPTY_C_STRING: u8 = 0;

/// Behind a `z_owned_string_t` handle. An OWNED string's `backing` is
/// NUL-terminated so a C caller treating `z_string_data` as a C string is safe;
/// an ALIASED one (`z_string_from_str`) is the caller's own C string, whose
/// terminator is the caller's. `self_view` is the cached borrowed
/// `{ start, len }` that `z_string_loan` returns, with `len` the logical length
/// (excluding the terminator) — stable, because it points at `backing`'s bytes,
/// which do not move when the box does.
pub(crate) struct StringState {
    /// The block `self_view` borrows, shared with any payload it was moved
    /// into; released when the last of them goes. None for an empty string.
    backing: Option<Block>,
    /// The bytes of `backing` written: the string's and its terminator, or the caller's.
    filled: usize,
    self_view: z_loaned_string_t,
}

/// Behind a `z_owned_slice_t` handle. Mirrors [`StringState`]: `backing` holds
/// the bytes and `self_view` is the cached borrowed `{ start, len }` that
/// `z_slice_loan` returns (stable — it points at `backing`'s bytes, which do not
/// move when the box does).
///
/// No NUL terminator, unlike the string: a slice is binary and pico's
/// `z_slice_data` is not a C-string contract.
pub(crate) struct SliceState {
    /// The block `self_view` borrows, shared with any payload it was moved
    /// into; released when the last of them goes. None for an empty slice.
    backing: Option<Block>,
    /// The bytes of `backing` written.
    filled: usize,
    self_view: z_loaned_slice_t,
}

impl SliceState {
    /// A slice over `buf`'s block, which it keeps.
    fn boxed(buf: ByteBuf) -> Result<Box<SliceState>, NoRoom> {
        let len = buf.len;
        let backing = buf.into_block()?;
        // An empty slice's data is a pointer all the same, as a slice of no bytes has.
        let start = match backing.as_ref().map(|block| block.span().0) {
            Some(start) if !start.is_null() => start,
            _ => NonNull::<u8>::dangling().as_ptr().cast_const(),
        };
        Ok(Box::new(SliceState {
            backing,
            filled: len,
            self_view: z_loaned_slice_t {
                _start: start,
                _len: len,
            },
        }))
    }

    /// This slice as a payload that SHARES its block.
    fn shared_payload(&self) -> Result<ByteBuf, NoRoom> {
        // SAFETY: `self_view` is this state's own view.
        unsafe {
            payload_over(
                self.backing.as_ref(),
                self.filled,
                self.self_view._start,
                self.self_view._len,
            )
        }
    }
}

impl StringState {
    /// A string in a block of its own: the bytes, then the NUL a C caller
    /// treating `z_string_data` as a C string relies on. An empty one points at a terminator of
    /// the library's and holds no block.
    fn boxed(bytes: &[u8]) -> Result<Box<StringState>, NoRoom> {
        if bytes.is_empty() {
            return Ok(Box::new(StringState {
                backing: None,
                filled: 0,
                self_view: z_loaned_string_t {
                    _start: &EMPTY_C_STRING,
                    _len: 0,
                },
            }));
        }
        let filled = bytes.len().checked_add(1).ok_or(NoRoom)?;
        let mut block = Block::with_room(filled).ok_or(NoRoom)?;
        // SAFETY: a new block, of one holder, with room for the bytes and their terminator.
        unsafe {
            block.write(0, bytes);
            block.write(bytes.len(), &[0]);
        }
        let start = block.span().0;
        Ok(Box::new(StringState {
            backing: Some(block),
            filled,
            self_view: z_loaned_string_t {
                _start: start,
                _len: bytes.len(),
            },
        }))
    }

    /// A string that DESCRIBES the caller's `len` bytes at `start` (pico
    /// `z_string_from_str`): `z_string_data` answers `start` itself.
    ///
    /// # Safety
    /// As [`ByteBuf::aliased`].
    unsafe fn aliased(
        start: *const u8,
        len: usize,
        release: Release,
    ) -> Result<Box<StringState>, NoRoom> {
        let block = Block::alias(start, len, release).map_err(|release| {
            drop(release);
            NoRoom
        })?;
        let view_start = block.span().0;
        Ok(Box::new(StringState {
            backing: Some(block),
            filled: len,
            self_view: z_loaned_string_t {
                _start: view_start,
                _len: len,
            },
        }))
    }

    /// This string as a payload that SHARES its block, minus the terminator.
    fn shared_payload(&self) -> Result<ByteBuf, NoRoom> {
        // SAFETY: `self_view` is this state's own view.
        unsafe {
            payload_over(
                self.backing.as_ref(),
                self.filled,
                self.self_view._start,
                self.self_view._len,
            )
        }
    }
}

/// How many empty boxes a thread keeps for the next payload it makes.
#[cfg(all(feature = "std", not(wz_process_pools)))]
const BOX_CACHE: usize = 32;

// Without `std` there is no thread-local storage to keep them in, and each payload is a box of
// its own, as zenoh-pico's are. With the process pools the pool of payloads is what keeps them.
#[cfg(all(feature = "std", not(wz_process_pools)))]
std::thread_local! {
    /// The allocations that held a payload this thread made and then consumed, kept empty. A
    /// publisher's loop clones a payload and puts it, over and over: the box the clone allocates
    /// is the box the put frees, on the same thread, so keeping it for the next clone replaces a
    /// `malloc` and a `free` per message with two thread-local accesses.
    ///
    /// The boxes ARE the thing kept (an allocation that a `*mut ByteBuf` already points into
    /// is handed out again), so a `Vec` of the values themselves is not the same cache.
    #[allow(clippy::vec_box)]
    static EMPTY_BOXES: core::cell::RefCell<Vec<Box<core::mem::MaybeUninit<ByteBuf>>>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// An empty box this thread kept, if it has one.
#[cfg(all(feature = "std", not(wz_process_pools)))]
fn kept_box() -> Option<Box<core::mem::MaybeUninit<ByteBuf>>> {
    EMPTY_BOXES
        .try_with(|boxes| boxes.try_borrow_mut().ok().and_then(|mut b| b.pop()))
        .ok()
        .flatten()
}

/// None is kept without `std`.
#[cfg(all(not(feature = "std"), not(wz_process_pools)))]
fn kept_box() -> Option<Box<core::mem::MaybeUninit<ByteBuf>>> {
    None
}

/// Box `buf`, in a kept allocation when this thread has one; `None` never.
#[cfg(not(wz_process_pools))]
fn box_bytes(buf: ByteBuf) -> Option<*mut ByteBuf> {
    // `Box::new_uninit` is newer than this crate's minimum Rust; an uninitialised value boxed
    // is the same allocation, and the optimiser writes nothing into it.
    let mut slot = kept_box().unwrap_or_else(|| Box::new(core::mem::MaybeUninit::uninit()));
    slot.write(buf);
    Some(Box::into_raw(slot).cast::<ByteBuf>())
}

/// Place `buf` in a slot of its own; `None` when the pool of payloads is full.
#[cfg(wz_process_pools)]
fn box_bytes(buf: ByteBuf) -> Option<*mut ByteBuf> {
    crate::object_slot::Slot::take(crate::object_slot::Kind::Bytes).map(|slot| slot.fill(buf))
}

/// Take the payload out of a place made by [`box_bytes`] (or by `Box::new`: the two have the same
/// layout) and give the place back.
///
/// # Safety
/// `h` must be a live `ByteBuf` handle, not used again.
#[cfg(wz_process_pools)]
pub(crate) unsafe fn unbox_bytes(h: *mut ByteBuf) -> ByteBuf {
    crate::object_slot::reclaim(h)
}

/// Take the payload out of a box made by [`box_bytes`] (or by `Box::new`: the two have the same
/// layout) and keep the allocation, empty, for the next one; past `BOX_CACHE` it is freed.
///
/// # Safety
/// `h` must be a live `Box::into_raw::<ByteBuf>` pointer, not used again.
#[cfg(not(wz_process_pools))]
pub(crate) unsafe fn unbox_bytes(h: *mut ByteBuf) -> ByteBuf {
    let slot = Box::from_raw(h.cast::<core::mem::MaybeUninit<ByteBuf>>());
    let buf = slot.assume_init_read();
    #[cfg(feature = "std")]
    let _ = EMPTY_BOXES.try_with(|boxes| {
        if let Ok(mut boxes) = boxes.try_borrow_mut() {
            if boxes.len() < BOX_CACHE {
                boxes.push(slot);
            }
        }
    });
    buf
}

/// # Safety
/// `h` must be a live `Box::into_raw::<ByteBuf>` pointer.
unsafe fn free_bytes(h: *mut c_void) {
    drop(unbox_bytes(h as *mut ByteBuf));
}
/// # Safety
/// `h` must be a live `Box::into_raw::<SliceState>` pointer.
unsafe fn free_slice(h: *mut c_void) {
    drop(Box::from_raw(h as *mut SliceState));
}

impl_value_ownership!(
    z_owned_bytes_t,
    z_loaned_bytes_t,
    z_moved_bytes_t,
    free_bytes,
    z_internal_bytes_null,
    z_internal_bytes_check,
    z_bytes_loan,
    z_bytes_loan_mut,
    z_bytes_move,
    z_bytes_take,
    z_bytes_drop,
    z_bytes_take_from_loaned
);

// The slice ownership family is HAND-WRITTEN rather than emitted by
// `impl_value_ownership!`, because that macro's `loan` is a pointer
// reinterpretation of the owned struct — correct only while owned and loaned
// share a layout. slice's loaned form is a `{ start, len }` borrow pair (see
// [`crate::abi`]), so `loan` must hand back the state's cached self-view, and
// `take_from_loaned` must COPY the borrowed bytes (a borrow carries no
// transferable handle). This is the same family string writes out for the same
// reason.

/// Zero an owned slice (pico `z_internal_slice_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_null(obj: *mut z_owned_slice_t) {
    if !obj.is_null() {
        *obj = z_owned_slice_t::null_value();
    }
}

/// `true` iff the owned slice holds a live handle (pico
/// `z_internal_slice_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_slice_check(obj: *const z_owned_slice_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow an owned slice immutably (pico `z_slice_loan`). Returns the state's
/// cached `{ start, len }` self-view.
#[no_mangle]
pub unsafe extern "C" fn z_slice_loan(obj: *const z_owned_slice_t) -> *const z_loaned_slice_t {
    guard_val(core::ptr::null(), || {
        match handle_ref::<z_owned_slice_t, SliceState>(obj) {
            Some(state) => &state.self_view as *const z_loaned_slice_t,
            None => core::ptr::null(),
        }
    })
}

/// Borrow an owned slice mutably (pico `z_slice_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_loan_mut(obj: *mut z_owned_slice_t) -> *mut z_loaned_slice_t {
    if obj.is_null() || (*obj).handle.is_null() {
        return core::ptr::null_mut();
    }
    let state = &mut *((*obj).handle as *mut SliceState);
    &mut state.self_view as *mut z_loaned_slice_t
}

/// Move-cast an owned slice (pico `z_slice_move`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_move(obj: *mut z_owned_slice_t) -> *mut z_moved_slice_t {
    obj as *mut z_moved_slice_t
}

/// Take an owned slice out of `src` into `dst` (pico `z_slice_take`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_take(dst: *mut z_owned_slice_t, src: *mut z_moved_slice_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_slice_t::null_value();
}

/// Drop an owned slice (pico `z_slice_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_drop(obj: *mut z_moved_slice_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let h = (*obj)._this.handle;
        if !h.is_null() {
            free_slice(h);
            (*obj)._this = z_owned_slice_t::null_value();
        }
        Z_OK
    });
}

/// Adopt a loaned slice into an owned one, emptying the source view (pico
/// `z_slice_take_from_loaned`). Same copy-and-clear contract as
/// [`z_string_take_from_loaned`], including its caveat about being applied to
/// an owned slice's own self-view.
#[no_mangle]
pub unsafe extern "C" fn z_slice_take_from_loaned(
    dst: *mut z_owned_slice_t,
    src: *mut z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let rc = store_slice(
            dst,
            ByteBuf::copy_of(core::slice::from_raw_parts(start, len)),
        );
        if rc != Z_OK {
            return rc;
        }
        (*src)._start = core::ptr::null();
        (*src)._len = 0;
        Z_OK
    })
}

// --- helpers to box a payload into an owned value -------------------------

/// Put the payload `made` in `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst` null and the
/// payload dropped, when there was no room for its bytes or the pool of payloads is full.
unsafe fn store_bytes(dst: *mut z_owned_bytes_t, made: Result<ByteBuf, NoRoom>) -> ZResult {
    match made.and_then(|buf| box_bytes(buf).ok_or(NoRoom)) {
        Ok(handle) => {
            *dst = z_owned_bytes_t {
                handle: handle as *mut c_void,
                _pad: [core::ptr::null_mut(); 3],
            };
            Z_OK
        }
        Err(no_room) => {
            *dst = z_owned_bytes_t::null_value();
            no_room.code()
        }
    }
}

/// Put a slice over the payload `made` in `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst`
/// null, when there was no room for its bytes.
unsafe fn store_slice(dst: *mut z_owned_slice_t, made: Result<ByteBuf, NoRoom>) -> ZResult {
    match made.and_then(SliceState::boxed) {
        Ok(state) => {
            *dst = z_owned_slice_t {
                handle: Box::into_raw(state) as *mut c_void,
                _pad: [core::ptr::null_mut(); 3],
            };
            Z_OK
        }
        Err(no_room) => {
            *dst = z_owned_slice_t::null_value();
            no_room.code()
        }
    }
}
/// Build an empty payload (pico `z_bytes_empty`).
///
/// Distinct from a NULL one: a program that builds an empty payload and attaches
/// it gets a present-but-zero-length attachment, which `z_sample_attachment`
/// reports as non-NULL. See that accessor for why the two must not collapse.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_empty(bytes: *mut z_owned_bytes_t) {
    if bytes.is_null() {
        return;
    }
    // A full pool leaves `bytes` null, the one answer a call with no result has.
    let _ = store_bytes(bytes, Ok(ByteBuf::new()));
}

/// Adopt a caller-allocated C string into an owned string (pico
/// `z_string_from_str`).
///
/// pico TAKES OWNERSHIP and calls `deleter(value, context)` when the string is
/// dropped, and the string DESCRIBES the caller's buffer rather than copying it:
/// `z_string_data` answers `value` itself. So does wz, since R2964 — until then
/// this copied and ran the deleter at construction, on the recorded ground that
/// the divergence was "one observable consequence". It was three (the address,
/// a change made through the caller's own pointer, the deleter's timing), and
/// `pico_bytes_alias_twice_and_diff` measures all of them against the real
/// library.
#[no_mangle]
pub unsafe extern "C" fn z_string_from_str(
    str_out: *mut z_owned_string_t,
    value: *mut core::ffi::c_char,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_owned_string_t::null_value();
        if value.is_null() {
            return Z_ERR_NULL;
        }
        let len = core::ffi::CStr::from_ptr(value).to_bytes().len();
        let release = Release::new(deleter, value as *mut c_void, context);
        store_string(
            str_out,
            StringState::aliased(value as *const u8, len, release),
        )
    })
}

/// Put the payload `made` in `dst` (see [`store_bytes`]).
pub(crate) unsafe fn store_owned_bytes(
    dst: *mut z_owned_bytes_t,
    made: Result<ByteBuf, NoRoom>,
) -> ZResult {
    store_bytes(dst, made)
}

/// Put a slice over the payload `made` in `dst` (see [`store_slice`]).
pub(crate) unsafe fn store_owned_slice(
    dst: *mut z_owned_slice_t,
    made: Result<ByteBuf, NoRoom>,
) -> ZResult {
    store_slice(dst, made)
}

/// Put a string holding a copy of `bytes` in `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst`
/// null, when there was no room for its bytes.
pub(crate) unsafe fn store_owned_string(dst: *mut z_owned_string_t, bytes: &[u8]) -> ZResult {
    store_string(dst, StringState::boxed(bytes))
}

/// Put the string `made` in `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst` null, when
/// there was no room for its bytes.
unsafe fn store_string(
    dst: *mut z_owned_string_t,
    made: Result<Box<StringState>, NoRoom>,
) -> ZResult {
    match made {
        Ok(state) => {
            *dst = z_owned_string_t {
                handle: Box::into_raw(state) as *mut c_void,
                _pad: [core::ptr::null_mut(); 3],
            };
            Z_OK
        }
        Err(no_room) => {
            *dst = z_owned_string_t::null_value();
            no_room.code()
        }
    }
}

/// Read the raw bytes behind a loaned bytes/slice value (both wrap `ByteBuf`).
pub(crate) unsafe fn bytes_ref<'a>(ptr: *const z_loaned_bytes_t) -> Option<&'a ByteBuf> {
    handle_ref::<z_loaned_bytes_t, ByteBuf>(ptr)
}

// --- bytes constructors ---------------------------------------------------

/// Copy a buffer into an owned payload (pico `z_bytes_copy_from_buf`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_buf(
    bytes: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        let buf: &[u8] = if data.is_null() || len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(data, len)
        };
        store_bytes(bytes, ByteBuf::copy_of(buf))
    })
}

/// Copy a C string's bytes into an owned payload (pico `z_bytes_copy_from_str`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_str(
    bytes: *mut z_owned_bytes_t,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        store_bytes(bytes, ByteBuf::copy_of(CStr::from_ptr(value).to_bytes()))
    })
}

/// Fill `bytes` with a payload that DESCRIBES the caller's `len` bytes at
/// `data` and hands `release` to the last holder (pico's
/// `_z_slice_from_buf_custom_deleter` behind every `z_bytes_from_*` that takes a
/// buffer).
///
/// A null `data` is an empty payload, as the copying constructors treat it. With no room for the
/// payload, `release` runs at once and `bytes` is left null.
///
/// # Safety
/// `bytes` must be null or valid and writable; `data` must be null or point at
/// `len` readable bytes that stay valid and unchanged until `release` has run.
pub(crate) unsafe fn store_aliased_payload(
    bytes: *mut z_owned_bytes_t,
    data: *const u8,
    len: usize,
    release: Release,
) -> ZResult {
    if bytes.is_null() {
        return Z_ERR_NULL;
    }
    let (data, len) = if data.is_null() {
        (core::ptr::null(), 0)
    } else {
        (data, len)
    };
    store_bytes(bytes, ByteBuf::aliased(data, len, release))
}

/// Build a payload from a statically allocated C string (pico
/// `z_bytes_from_static_str`).
///
/// The payload DESCRIBES the caller's storage and never frees it, which is why
/// the name says `static` and why there is no failure mode for allocation:
/// `z_bytes_get_contiguous_view` answers `value` itself, and a change made
/// through the caller's own pointer shows in the payload. wz copied here until
/// R2964, recording that as "confined to cost, not to observable behaviour" —
/// a sentence read off the source that `pico_bytes_alias_twice_and_diff`
/// falsified against the real library on the first run.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_str(
    bytes: *mut z_owned_bytes_t,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() || value.is_null() {
            return Z_ERR_NULL;
        }
        let len = CStr::from_ptr(value).to_bytes().len();
        store_aliased_payload(
            bytes,
            value as *const u8,
            len,
            Release::new(None, core::ptr::null_mut(), core::ptr::null_mut()),
        )
    })
}

// --- conversions ----------------------------------------------------------

/// Copy a payload into an owned slice (pico `z_bytes_to_slice`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_slice(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            // A COPY, as pico's is: the slice this hands back owns storage
            // of its own and outlives the payload it was read from.
            Some(buf) => store_slice(dst, buf.copied()),
            None => Z_ERR_NULL,
        }
    })
}

/// Copy a payload into an owned string (pico `z_bytes_to_string`).
#[no_mangle]
pub unsafe extern "C" fn z_bytes_to_string(
    bytes: *const z_loaned_bytes_t,
    dst: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(bytes) {
            Some(buf) => store_string(dst, StringState::boxed(buf)),
            None => Z_ERR_NULL,
        }
    })
}

// --- slice accessors ------------------------------------------------------

/// Pointer to a slice's bytes (pico `z_slice_data`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_data(slice: *const z_loaned_slice_t) -> *const u8 {
    guard_val(core::ptr::null(), || {
        if slice.is_null() {
            return core::ptr::null();
        }
        (*slice)._start
    })
}

/// Length of a slice (pico `z_slice_len`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_len(slice: *const z_loaned_slice_t) -> usize {
    guard_val(0, || {
        if slice.is_null() {
            return 0;
        }
        (*slice)._len
    })
}

// --- string ownership + accessors -----------------------------------------

/// Zero an owned string (pico `z_internal_string_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_null(obj: *mut z_owned_string_t) {
    if !obj.is_null() {
        *obj = z_owned_string_t::null_value();
    }
}

/// `true` iff the owned string holds a live handle (pico
/// `z_internal_string_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_string_check(obj: *const z_owned_string_t) -> bool {
    guard_val(false, || !obj.is_null() && !(*obj).handle.is_null())
}

/// Borrow an owned string immutably (pico `z_string_loan`). Returns the
/// state's cached `{ start, len }` self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_loan(obj: *const z_owned_string_t) -> *const z_loaned_string_t {
    guard_val(core::ptr::null(), || {
        match handle_ref::<z_owned_string_t, StringState>(obj) {
            Some(state) => &state.self_view as *const z_loaned_string_t,
            None => core::ptr::null(),
        }
    })
}

/// Borrow an owned string mutably (pico `z_string_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_string_loan_mut(obj: *mut z_owned_string_t) -> *mut z_loaned_string_t {
    if obj.is_null() || (*obj).handle.is_null() {
        return core::ptr::null_mut();
    }
    let state = &mut *((*obj).handle as *mut StringState);
    &mut state.self_view as *mut z_loaned_string_t
}

/// Move-cast an owned string (pico `z_string_move`).
#[no_mangle]
pub unsafe extern "C" fn z_string_move(obj: *mut z_owned_string_t) -> *mut z_moved_string_t {
    obj as *mut z_moved_string_t
}

/// Take an owned string out of `src` into `dst` (pico `z_string_take`).
#[no_mangle]
pub unsafe extern "C" fn z_string_take(dst: *mut z_owned_string_t, src: *mut z_moved_string_t) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).handle = (*src)._this.handle;
    (*dst)._pad = (*src)._this._pad;
    (*src)._this = z_owned_string_t::null_value();
}

/// Drop an owned string (pico `z_string_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_string_drop(obj: *mut z_moved_string_t) {
    let _ = guarded(|| {
        if obj.is_null() {
            return Z_OK;
        }
        let h = (*obj)._this.handle;
        if !h.is_null() {
            drop(Box::from_raw(h as *mut StringState));
            (*obj)._this = z_owned_string_t::null_value();
        }
        Z_OK
    });
}

/// Pointer to a string's (NUL-terminated) bytes (pico `z_string_data`).
#[no_mangle]
pub unsafe extern "C" fn z_string_data(string: *const z_loaned_string_t) -> *const c_char {
    guard_val(core::ptr::null(), || {
        if string.is_null() {
            core::ptr::null()
        } else {
            (*string)._start as *const c_char
        }
    })
}

/// Logical length of a string, excluding the NUL terminator (pico
/// `z_string_len`).
#[no_mangle]
pub unsafe extern "C" fn z_string_len(string: *const z_loaned_string_t) -> usize {
    guard_val(0, || if string.is_null() { 0 } else { (*string)._len })
}

/// Adopt a loaned string into an owned one, emptying the source view (pico
/// `z_string_take_from_loaned`). The string loaned form is a borrowed
/// `{ start, len }`, so "take" copies the borrowed bytes into a fresh owned
/// `StringState` (there is no transferable handle in a borrow) and clears the
/// source view.
///
/// Caveat: if `src` was obtained via `z_string_loan[_mut]` on an owned string,
/// it points at that owned string's cached self-view; clearing it here leaves
/// that owned string's subsequent `z_string_loan` returning an empty
/// `{ null, 0 }` view (the owned `StringState` box is untouched and still
/// freed on drop — no leak, no double-free). Idiomatic pico "take from loaned"
/// is applied to a fresh loaned handle, not an owned string's self-view.
#[no_mangle]
pub unsafe extern "C" fn z_string_take_from_loaned(
    dst: *mut z_owned_string_t,
    src: *mut z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = core::slice::from_raw_parts(start, len);
        let rc = store_string(dst, StringState::boxed(bytes));
        if rc != Z_OK {
            return rc;
        }
        (*src)._start = core::ptr::null();
        (*src)._len = 0;
        Z_OK
    })
}

// --- clone ------------------------------------------------------------------

/// Clone a payload (pico `z_bytes_clone`): the clone SHARES the original's
/// storage, and the caller's deleter, if the payload came with one, waits for
/// both. Only the slice and string clones below copy, as pico's do.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_clone(
    dst: *mut z_owned_bytes_t,
    src: *const z_loaned_bytes_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        match bytes_ref(src) {
            Some(buf) => store_bytes(dst, buf.try_clone()),
            None => Z_ERR_NULL,
        }
    })
}

// --- the view-slice family + the slice iterator ----------------------------

/// Build a view slice borrowing the caller's buffer (pico
/// `z_view_slice_from_buf`). No copy and no ownership: the caller keeps `data`
/// alive for the view's lifetime.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_from_buf(
    slice: *mut z_view_slice_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if slice.is_null() || data.is_null() {
            return Z_ERR_NULL;
        }
        *slice = z_view_slice_t {
            _start: data,
            _len: len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Empty a view slice (pico `z_view_slice_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_empty(slice: *mut z_view_slice_t) {
    if slice.is_null() {
        return;
    }
    *slice = z_view_slice_t {
        _start: core::ptr::null(),
        _len: 0,
        _pad: [0usize; 2],
    };
}

/// `true` iff the view slice is empty (pico `z_view_slice_is_empty`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_is_empty(slice: *const z_view_slice_t) -> bool {
    guard_val(true, || slice.is_null() || (*slice)._len == 0)
}

/// Borrow a view slice immutably (pico `z_view_slice_loan`). A pointer
/// reinterpretation: slots 0/1 of a view ARE the loaned `{ start, len }`.
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_loan(
    slice: *const z_view_slice_t,
) -> *const z_loaned_slice_t {
    slice as *const z_loaned_slice_t
}

/// Borrow a view slice mutably (pico `z_view_slice_loan_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_view_slice_loan_mut(
    slice: *mut z_view_slice_t,
) -> *mut z_loaned_slice_t {
    slice as *mut z_loaned_slice_t
}

/// pico `z_bytes_slice_iterator_t` (`api/types.h:84-87`), 16 B measured:
/// `{ const _z_bytes_t *_bytes; size_t _slice_idx; }`.
///
/// Crosses the boundary BY VALUE out of [`z_bytes_get_slice_iterator`] and is
/// stack-allocated by the C caller, so the field order and size are ABI.
#[repr(C)]
pub struct z_bytes_slice_iterator_t {
    pub(crate) _bytes: *const z_loaned_bytes_t,
    pub(crate) _slice_idx: usize,
}

/// Start iterating a payload's underlying slices (pico
/// `z_bytes_get_slice_iterator`).
///
/// The slices are the SEGMENTS a `z_bytes_writer_append` left behind (see
/// `ByteBuf`), so upstream's own `z_bytes.c` walks the same three slices on
/// wz that it walks on the real zenoh-pico.
///
/// An earlier cut of this function yielded ONE slice covering the whole payload
/// and argued it was faithful, on the grounds that upstream documents "no
/// guarantee is provided on the internal slices arrangement... the only provided
/// guarantee is on the bytes order" (`api/primitives.h:774-777`). That is what
/// the header says and it was still the wrong call: the two implementations
/// printed different output for the same program, and a drop-in is judged by
/// what the program prints, not by what the header permits.
///
/// An EMPTY payload yields nothing, matching pico's empty svec.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_slice_iterator(
    bytes: *const z_loaned_bytes_t,
) -> z_bytes_slice_iterator_t {
    z_bytes_slice_iterator_t {
        _bytes: bytes,
        _slice_idx: 0,
    }
}

/// Advance a slice iterator, filling `out` with a view of the next slice (pico
/// `z_bytes_slice_iterator_next`). `false` at the end.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_slice_iterator_next(
    iter: *mut z_bytes_slice_iterator_t,
    out: *mut z_view_slice_t,
) -> bool {
    guard_val(false, || {
        if iter.is_null() || out.is_null() {
            return false;
        }
        let Some(buf) = bytes_ref((*iter)._bytes) else {
            return false;
        };
        let Some(segment) = buf.segment((*iter)._slice_idx) else {
            return false;
        };
        (*iter)._slice_idx += 1;
        *out = z_view_slice_t {
            _start: segment.as_ptr(),
            _len: segment.len(),
            _pad: [0usize; 2],
        };
        true
    })
}

/// Deep-copy a slice (pico `z_slice_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_slice_clone(
    dst: *mut z_owned_slice_t,
    src: *const z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        if src.is_null() || (*src)._start.is_null() {
            return Z_ERR_NULL;
        }
        store_slice(
            dst,
            ByteBuf::copy_of(core::slice::from_raw_parts((*src)._start, (*src)._len)),
        )
    })
}

/// Deep-copy a string (pico `z_string_clone`).
#[no_mangle]
pub unsafe extern "C" fn z_string_clone(
    dst: *mut z_owned_string_t,
    src: *const z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() || src.is_null() {
            return Z_ERR_NULL;
        }
        let start = (*src)._start;
        let len = (*src)._len;
        if start.is_null() {
            return Z_ERR_NULL;
        }
        let bytes = core::slice::from_raw_parts(start, len);
        store_string(dst, StringState::boxed(bytes))
    })
}

// --- R311y559: the rest of the container surface ----------------------------
//
// Everything below is a symbol the REAL `libzenohpico.so` defines and this
// cdylib did not, found by `wz-integration-tests/tests/pico_abi_symbol_census.rs`.
// A drop-in is a claim about the linker before it is a claim about behaviour: a
// program naming any of these did not fail a comparison, it failed to LINK, and
// no behavioural leg in this tree could reach it. They are ordinary members of
// the families already above and reuse the same state types.

/// Total payload length in bytes (pico `z_bytes_len`).
///
/// Across ALL segments, not the first one: a `ByteBuf` may be a multi-segment
/// gather (a fragmented receive, an `append_segments`), and upstream's
/// `_z_bytes_len` sums the arc-slice vector. Reading only segment 0 would agree
/// on every single-segment payload — which is every payload a wz-authored test
/// builds — and under-report exactly the case the field exists for.
///
/// # Safety
/// `bytes` must be null or a live loaned payload.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_len(bytes: *const z_loaned_bytes_t) -> usize {
    guard_val(0, || bytes_ref(bytes).map_or(0, |buf| buf.len()))
}

/// Whether a payload carries no bytes (pico `z_bytes_is_empty`).
///
/// # Safety
/// As [`z_bytes_len`].
#[no_mangle]
pub unsafe extern "C" fn z_bytes_is_empty(bytes: *const z_loaned_bytes_t) -> bool {
    guard_val(true, || z_bytes_len(bytes) == 0)
}

/// Copy a loaned slice's bytes into an owned payload (pico
/// `z_bytes_copy_from_slice`).
///
/// # Safety
/// `bytes` must be valid and writable; `slice` must be null or a live loaned
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_slice(
    bytes: *mut z_owned_bytes_t,
    slice: *const z_loaned_slice_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        z_bytes_copy_from_buf(bytes, (*slice)._start, (*slice)._len)
    })
}

/// Move an owned slice into an owned payload (pico `z_bytes_from_slice`),
/// consuming the slice.
///
/// The slice is CONSUMED on every path, success or not — upstream's ownership
/// transfer is unconditional once the call is made, so an early return that
/// skipped the drop would leak the caller's value.
///
/// # Safety
/// `bytes` must be valid and writable; `slice` must be null or a valid moved
/// slice.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_slice(
    bytes: *mut z_owned_bytes_t,
    slice: *mut z_moved_slice_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            // Still consume, per the paragraph above.
            z_slice_drop(slice);
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        let rc = if slice.is_null() {
            Z_ERR_NULL
        } else {
            match handle_ref::<z_owned_slice_t, SliceState>(&(*slice)._this) {
                Some(state) => {
                    // The payload takes over the slice's storage rather than
                    // copying it (pico moves the allocation), so its address is
                    // the slice's and an aliased slice's deleter waits for it.
                    store_bytes(bytes, state.shared_payload())
                }
                None => Z_ERR_NULL,
            }
        };
        z_slice_drop(slice);
        rc
    })
}

/// Copy a loaned string's bytes into an owned payload (pico
/// `z_bytes_copy_from_string`). The NUL terminator is NOT copied — a payload's
/// length is the string's logical length.
///
/// # Safety
/// `bytes` must be valid and writable; `s` must be null or a live loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_copy_from_string(
    bytes: *mut z_owned_bytes_t,
    s: *const z_loaned_string_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        if s.is_null() {
            return Z_ERR_NULL;
        }
        z_bytes_copy_from_buf(bytes, (*s)._start, (*s)._len)
    })
}

/// Move an owned string into an owned payload (pico `z_bytes_from_string`),
/// consuming the string.
///
/// # Safety
/// `bytes` must be valid and writable; `s` must be null or a valid moved string.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_string(
    bytes: *mut z_owned_bytes_t,
    s: *mut z_moved_string_t,
) -> ZResult {
    guarded(|| {
        if bytes.is_null() {
            z_string_drop(s);
            return Z_ERR_NULL;
        }
        *bytes = z_owned_bytes_t::null_value();
        let rc = if s.is_null() {
            Z_ERR_NULL
        } else {
            match handle_ref::<z_owned_string_t, StringState>(&(*s)._this) {
                Some(state) => {
                    // As `z_bytes_from_slice`: the string's own storage, minus
                    // its terminator.
                    store_bytes(bytes, state.shared_payload())
                }
                None => Z_ERR_NULL,
            }
        };
        z_string_drop(s);
        rc
    })
}

/// Adopt a caller-allocated C string into an owned payload (pico
/// `z_bytes_from_str`).
///
/// The payload DESCRIBES the caller's string, and the deleter runs when the last
/// holder of it is dropped — after a clone, once both are; see
/// [`z_string_from_str`].
///
/// The deleter is owed on EVERY path once the call is made, a failed one
/// included: pico's ownership transfer is unconditional, so it is held in a
/// `Release` before anything can return early.
///
/// # Safety
/// `bytes` must be valid and writable; `value` must be null or a live
/// NUL-terminated string the deleter can release.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_str(
    bytes: *mut z_owned_bytes_t,
    value: *mut c_char,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let release = Release::new(deleter, value as *mut c_void, context);
        if value.is_null() {
            return Z_ERR_NULL;
        }
        let len = CStr::from_ptr(value).to_bytes().len();
        store_aliased_payload(bytes, value as *const u8, len, release)
    })
}

/// Point a view slice at the payload's bytes WITHOUT copying (pico
/// `z_bytes_get_contiguous_view`, unstable).
///
/// Fails with `Z_ERR_INVALID` on a payload that is not contiguous, which is
/// upstream's contract and not a limitation of this implementation: the export
/// exists precisely so a caller can distinguish "I can read this in place" from
/// "I must gather it", and returning a view over a copy would answer the
/// question wrongly while looking like it worked.
///
/// # Safety
/// `bytes` must be null or a live loaned payload; `view` must be valid and
/// writable, and must not outlive `bytes`.
#[cfg(feature = "unstable-api")]
#[no_mangle]
pub unsafe extern "C" fn z_bytes_get_contiguous_view(
    bytes: *const z_loaned_bytes_t,
    view: *mut z_view_slice_t,
) -> ZResult {
    guarded(|| {
        if view.is_null() {
            return Z_ERR_NULL;
        }
        z_view_slice_empty(view);
        let Some(buf) = bytes_ref(bytes) else {
            return Z_ERR_NULL;
        };
        if !buf.is_contiguous() {
            return crate::result::Z_ERR_INVALID;
        }
        z_view_slice_from_buf(view, buf.as_slice().as_ptr(), buf.len())
    })
}

// --- slice constructors ------------------------------------------------------

/// Copy a buffer into an owned slice (pico `z_slice_copy_from_buf`).
///
/// # Safety
/// `slice` must be valid and writable; `data` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_slice_copy_from_buf(
    slice: *mut z_owned_slice_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    guarded(|| {
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        *slice = z_owned_slice_t::null_value();
        if data.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(data, len)
        };
        store_slice(slice, ByteBuf::copy_of(bytes))
    })
}

/// Adopt a caller-owned buffer into an owned slice (pico `z_slice_from_buf`).
///
/// The slice DESCRIBES the caller's buffer — `z_slice_data` answers `data`
/// itself — and the deleter runs when the last holder of it is dropped, which is
/// after the payload the slice was moved into, if any. Held in a `Release`
/// before anything can return early, so a failed call still runs it, as pico's
/// unconditional ownership transfer requires.
///
/// # Safety
/// `slice` must be valid and writable; `data` must be null or point at `len`
/// readable bytes the deleter can release.
#[no_mangle]
pub unsafe extern "C" fn z_slice_from_buf(
    slice: *mut z_owned_slice_t,
    data: *mut u8,
    len: usize,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let release = Release::new(deleter, data as *mut c_void, context);
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        *slice = z_owned_slice_t::null_value();
        if data.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        store_slice(slice, ByteBuf::aliased(data, len, release))
    })
}

/// Build an EMPTY owned slice (pico `z_slice_empty`).
///
/// Present-but-zero-length, not null — the same distinction
/// [`z_bytes_empty`] documents, and for the same reason.
///
/// # Safety
/// `slice` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_slice_empty(slice: *mut z_owned_slice_t) {
    let _ = guarded(|| {
        if slice.is_null() {
            return Z_ERR_NULL;
        }
        store_slice(slice, Ok(ByteBuf::new()))
    });
}

/// Whether a loaned slice carries no bytes (pico `z_slice_is_empty`).
///
/// # Safety
/// `slice` must be null or a live loaned slice.
#[no_mangle]
pub unsafe extern "C" fn z_slice_is_empty(slice: *const z_loaned_slice_t) -> bool {
    guard_val(true, || z_slice_len(slice) == 0)
}

// --- string constructors + accessors -----------------------------------------

/// Build an EMPTY owned string (pico `z_string_empty`).
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_string_empty(str_out: *mut z_owned_string_t) {
    let _ = guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        store_string(str_out, StringState::boxed(&[]))
    });
}

/// Whether a loaned string is zero-length (pico `z_string_is_empty`).
///
/// # Safety
/// `str_in` must be null or a live loaned string.
#[no_mangle]
pub unsafe extern "C" fn z_string_is_empty(str_in: *const z_loaned_string_t) -> bool {
    guard_val(true, || z_string_len(str_in) == 0)
}

/// Copy a NUL-terminated C string into an owned string (pico
/// `z_string_copy_from_str`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_str(
    str_out: *mut z_owned_string_t,
    value: *const c_char,
) -> ZResult {
    let len = if value.is_null() {
        0
    } else {
        CStr::from_ptr(value).to_bytes().len()
    };
    z_string_copy_from_substr(str_out, value, len)
}

/// Copy an explicitly-sized substring into an owned string (pico
/// `z_string_copy_from_substr`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_string_copy_from_substr(
    str_out: *mut z_owned_string_t,
    value: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_owned_string_t::null_value();
        if value.is_null() && len != 0 {
            return Z_ERR_NULL;
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(value as *const u8, len)
        };
        store_string(str_out, StringState::boxed(bytes))
    })
}

/// Reinterpret a loaned string as a loaned slice (pico `z_string_as_slice`).
///
/// A pointer reinterpretation, not a copy: both loaned forms are the SAME
/// `{ start, len }` borrow pair (see [`crate::abi`]), which is exactly why
/// upstream can hand back a `const z_loaned_slice_t *` into the string's own
/// storage. The NUL terminator is excluded, because `_len` is the logical
/// length.
///
/// # Safety
/// `str_in` must be null or a live loaned string; the result must not outlive
/// it.
#[no_mangle]
pub unsafe extern "C" fn z_string_as_slice(
    str_in: *const z_loaned_string_t,
) -> *const z_loaned_slice_t {
    str_in as *const z_loaned_slice_t
}

// --- the view-string family ---------------------------------------------------

/// Point a view string at a NUL-terminated C string (pico
/// `z_view_string_from_str`). No copy: the caller keeps `value` alive.
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or a valid
/// NUL-terminated string that outlives the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_str(
    str_out: *mut z_view_string_t,
    value: *const c_char,
) -> ZResult {
    let len = if value.is_null() {
        0
    } else {
        CStr::from_ptr(value).to_bytes().len()
    };
    z_view_string_from_substr(str_out, value, len)
}

/// Point a view string at an explicitly-sized substring (pico
/// `z_view_string_from_substr`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or point at `len`
/// readable bytes that outlive the view.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_from_substr(
    str_out: *mut z_view_string_t,
    value: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if str_out.is_null() {
            return Z_ERR_NULL;
        }
        z_view_string_empty(str_out);
        if value.is_null() {
            return Z_ERR_NULL;
        }
        *str_out = z_view_string_t {
            _start: value as *const u8,
            _len: len,
            _pad: [0usize; 2],
        };
        Z_OK
    })
}

/// Zero a view string (pico `z_view_string_empty`).
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_empty(str_out: *mut z_view_string_t) {
    if str_out.is_null() {
        return;
    }
    *str_out = z_view_string_t {
        _start: core::ptr::null(),
        _len: 0,
        _pad: [0usize; 2],
    };
}

/// Whether a view string points at nothing (pico `z_view_string_is_empty`).
///
/// # Safety
/// `str_in` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_is_empty(str_in: *const z_view_string_t) -> bool {
    guard_val(true, || {
        str_in.is_null() || (*str_in)._start.is_null() || (*str_in)._len == 0
    })
}

/// Mutably borrow a view string (pico `z_view_string_loan_mut`) — the offset-0
/// reinterpretation its immutable sibling already uses.
///
/// # Safety
/// `str_in` must be null or a valid view string.
#[no_mangle]
pub unsafe extern "C" fn z_view_string_loan_mut(
    str_in: *mut z_view_string_t,
) -> *mut z_loaned_string_t {
    str_in as *mut z_loaned_string_t
}

#[cfg(all(test, not(wz_process_pools)))]
mod box_cache_tests {
    use super::*;

    fn kept() -> usize {
        EMPTY_BOXES.with(|boxes| boxes.borrow().len())
    }

    /// A box kept for the next payload is reused for it, the payload read back out of a reused box
    /// is the one stored in it and never the one before, and the list stops at its bound.
    #[test]
    fn a_reused_box_holds_exactly_the_payload_put_in_it() {
        // SAFETY: every pointer below comes from `box_bytes` and is unboxed once.
        unsafe {
            let first =
                box_bytes(ByteBuf::copy_of(b"first").expect("the heap's")).expect("the heap's");
            let first_at = first as usize;
            let got = unbox_bytes(first);
            assert_eq!(got.to_vec(), b"first");
            let after_first = kept();
            assert!(after_first >= 1, "the emptied box is kept");

            let second = box_bytes(ByteBuf::copy_of(b"second payload").expect("the heap's"))
                .expect("the heap's");
            assert_eq!(
                second as usize, first_at,
                "the kept allocation is the next one used"
            );
            assert_eq!(
                kept(),
                after_first - 1,
                "and leaves the list while it holds a payload"
            );
            assert_eq!((*second).to_vec(), b"second payload");
            assert_eq!(unbox_bytes(second).to_vec(), b"second payload");

            // Many at once: the list holds at most BOX_CACHE and the rest are freed.
            let many: Vec<*mut ByteBuf> = (0..BOX_CACHE * 3)
                .map(|i| {
                    let buf = ByteBuf::copy_of(&vec![i as u8; i % 7]).expect("the heap's");
                    box_bytes(buf).expect("the heap's")
                })
                .collect();
            for (i, ptr) in many.into_iter().enumerate() {
                assert_eq!(
                    unbox_bytes(ptr).to_vec(),
                    vec![i as u8; i % 7],
                    "payload {i}"
                );
            }
            assert!(kept() <= BOX_CACHE, "bounded: {}", kept());
        }
    }

    /// A payload boxed on one thread and consumed on another (a publisher thread cloning, an
    /// application thread putting) is intact, and the other thread's list is its own.
    #[test]
    fn a_box_unboxed_on_another_thread_is_intact() {
        // SAFETY: the pointer is handed to the other thread whole and unboxed once.
        unsafe {
            let ptr = box_bytes(ByteBuf::copy_of(b"across").expect("the heap's"))
                .expect("the heap's") as usize;
            let seen = std::thread::spawn(move || {
                let before = kept();
                let buf = unbox_bytes(ptr as *mut ByteBuf);
                (buf.to_vec(), before, kept())
            })
            .join()
            .unwrap();
            assert_eq!(seen.0, b"across");
            assert_eq!(seen.1, 0, "a thread starts with no kept boxes");
            assert_eq!(seen.2, 1, "and keeps the one it emptied");
        }
    }

    /// Dropping an owned payload through the C ABI frees through the same path.
    #[test]
    fn dropping_an_owned_payload_keeps_its_box() {
        // SAFETY: `owned` is built and dropped by the ABI's own functions.
        unsafe {
            let mut owned: z_owned_bytes_t = core::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut owned, c"dropped".as_ptr()), Z_OK);
            let before = kept();
            free_bytes(owned.handle);
            assert_eq!(kept(), (before + 1).min(BOX_CACHE));
        }
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;

    /// Counts the releases of a caller's buffer.
    unsafe extern "C" fn count_release(_value: *mut c_void, context: *mut c_void) {
        (*context.cast::<AtomicUsize>()).fetch_add(1, Ordering::SeqCst);
    }

    /// Where a payload's bytes start.
    fn start_of(buf: &ByteBuf) -> *const u8 {
        buf.as_slice().as_ptr()
    }

    /// An empty payload holds no block, and neither does its clone.
    #[test]
    fn an_empty_payload_holds_no_block() {
        let empty = ByteBuf::copy_of(&[]).expect("no room is asked for");
        assert!(matches!(empty.backing, Store::Empty));
        let clone = empty.try_clone().expect("no room is asked for");
        assert!(matches!(clone.backing, Store::Empty));
        assert!(clone.as_slice().is_empty());
    }

    /// A clone shares the block of the payload it was made from, which holds its bytes once, and
    /// a copy has a block of its own.
    #[test]
    fn a_clone_shares_the_block_and_a_copy_has_its_own() {
        let first = ByteBuf::copy_of(b"shared bytes").expect("room for a payload");
        let clone = first.try_clone().expect("a share takes no room");
        assert_eq!(start_of(&clone), start_of(&first), "the same block");
        let copy = first.copied().expect("room for a copy");
        assert_ne!(start_of(&copy), start_of(&first), "a block of its own");
        assert_eq!(copy.as_slice(), b"shared bytes");
        drop(first);
        assert_eq!(
            clone.as_slice(),
            b"shared bytes",
            "the block lives with its last holder"
        );
    }

    /// A lent payload's clone is a copy, which outlives the lender's bytes.
    #[test]
    fn a_lent_payloads_clone_is_a_copy() {
        let lender = b"lent".to_vec();
        // SAFETY: `lender` outlives the lent payload, dropped first.
        let lent = unsafe { ByteBuf::lent(&lender) };
        let clone = lent.try_clone().expect("room for a copy");
        assert_ne!(start_of(&clone), lender.as_ptr());
        drop(lent);
        drop(lender);
        assert_eq!(clone.as_slice(), b"lent");
    }

    /// The caller's release runs once, when the last holder of its alias goes, and an alias reads
    /// the caller's bytes where they lie.
    #[test]
    fn an_alias_is_released_once_by_its_last_holder() {
        let released = AtomicUsize::new(0);
        let bytes = *b"caller's";
        let release = Release::new(
            Some(count_release),
            bytes.as_ptr().cast_mut().cast::<c_void>(),
            (&released as *const AtomicUsize)
                .cast_mut()
                .cast::<c_void>(),
        );
        // SAFETY: `bytes` outlive the payload and its clone, both dropped below.
        let alias = unsafe { ByteBuf::aliased(bytes.as_ptr(), bytes.len(), release) }
            .expect("room for the record");
        assert_eq!(start_of(&alias), bytes.as_ptr(), "the caller's own bytes");
        let clone = alias.try_clone().expect("a share takes no room");
        drop(alias);
        assert_eq!(released.load(Ordering::SeqCst), 0, "a holder is left");
        drop(clone);
        assert_eq!(
            released.load(Ordering::SeqCst),
            1,
            "released once, by the last"
        );
    }

    /// A write to a payload whose block is shared copies it first, so the other holder reads what
    /// it held; a payload with a block of its own writes into it, growing it when it must.
    #[test]
    fn a_write_copies_a_shared_block_and_grows_its_own() {
        let mut writer = ByteBuf::new();
        writer.write_all(b"ab").expect("room");
        let held = writer.try_clone().expect("a share takes no room");
        writer.write_all(b"cd").expect("room");
        assert_eq!(held.as_slice(), b"ab", "the shared block is not written");
        assert_eq!(writer.as_slice(), b"abcd");
        let long = [7u8; 300];
        writer.write_all(&long).expect("room to grow");
        assert_eq!(writer.len, 304);
        assert_eq!(&writer.as_slice()[..4], b"abcd");
        assert!(writer.as_slice()[4..].iter().all(|&byte| byte == 7));
    }

    /// Segments appended to a writer keep their bounds, and the appended payload is left whole.
    #[test]
    fn appended_payloads_are_segments_of_their_own() {
        let mut writer = ByteBuf::copy_of(b"head").expect("room");
        let tail = ByteBuf::copy_of(b"tail").expect("room");
        writer.append_segments(&tail).expect("room");
        writer.append_segments(&tail).expect("room");
        assert_eq!(writer.as_slice(), b"headtailtail");
        assert_eq!(writer.segment(0), Some(&b"head"[..]));
        assert_eq!(writer.segment(1), Some(&b"tail"[..]));
        assert_eq!(writer.segment(2), Some(&b"tail"[..]));
        assert_eq!(writer.segment(3), None);
        assert_eq!(tail.as_slice(), b"tail");
    }

    /// A string moved into a payload shares its block without its terminator; an empty string is
    /// a C string with no block.
    #[test]
    fn a_string_shares_its_block_with_a_payload_without_its_terminator() {
        let state = StringState::boxed(b"text").expect("room");
        // SAFETY: the view is the state's own, over its block's written bytes.
        let terminated = unsafe { lent_bytes(state.self_view._start, 5) };
        assert_eq!(terminated, b"text\0");
        let payload = state.shared_payload().expect("a share takes no room");
        assert_eq!(start_of(&payload), state.self_view._start);
        assert_eq!(payload.as_slice(), b"text");
        let empty = StringState::boxed(&[]).expect("no room is asked for");
        assert!(empty.backing.is_none());
        // SAFETY: an empty string's view points at a terminator.
        assert_eq!(unsafe { *empty.self_view._start }, 0);
    }

    /// With the process pools, a payload's bytes lie in their payloads' area, not on the heap.
    #[cfg(wz_process_pools)]
    #[test]
    fn a_payloads_bytes_lie_in_the_process_pools() {
        let payload = ByteBuf::copy_of(b"pooled bytes").expect("room in the area");
        let Store::Shared(block) = &payload.backing else {
            panic!("a payload of bytes holds a block");
        };
        assert!(crate::process_pool::lies_in_area(block.head.cast::<u8>()));
    }
}
