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
//! bytes holds its payload in the owned value's own words (owned == loaned layout, `loan`
//! is a cast); slice uses the handle model, its handle the slice's state. string uses the
//! borrowed-view model: an owned string holds a `StringState` and hands out a cached
//! `{ start, len }` self-view on `loan`, so `z_loaned_string_t` is the same
//! borrowed shape a view string (from `z_keyexpr_as_view_string`) produces.
//!
//! The bytes a payload, a string or a slice holds lie in a block (`Block`): in a library with
//! the process pools, one of their pools of payload blocks (`HELD_SMALL_PAYLOAD_BLOCKS` and the
//! two larger), so making or copying one allocates nothing once the pools are reserved and is
//! refused with `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when no pool has a free block that holds it; in one
//! without, the heap's.

use core::ffi::{c_char, c_void, CStr};
use core::ptr::NonNull;
use core::sync::atomic::{fence, AtomicUsize, Ordering};

use crate::prelude::*;

use crate::abi::{
    handle_ref, impl_handle_ownership6, z_loaned_bytes_t, z_loaned_slice_t, z_loaned_string_t,
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
/// a string or a slice meets when the process pools' payload blocks, or the pool of its
/// kind, has none free; the call answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY` and leaves its output null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoRoom;

impl NoRoom {
    /// The code a door answers for it.
    pub(crate) const fn code(self) -> ZResult {
        crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY
    }
}

/// `value` in a box of its own, or [`NoRoom`] with `value` let go of when the heap refuses the
/// box: what every door that boxes an object it hands the program asks, so a full heap is answered
/// as zenoh-pico answers its failed `malloc` and never ends the program. Laid out as
/// `Box::new(value)` lays it out, so the box is dropped and freed as any other is.
pub(crate) fn try_box<T>(value: T) -> Result<Box<T>, NoRoom> {
    let layout = core::alloc::Layout::new::<T>();
    let at = if layout.size() == 0 {
        NonNull::<T>::dangling()
    } else {
        // SAFETY: the layout has bytes.
        NonNull::new(unsafe { alloc::alloc::alloc(layout) }.cast::<T>()).ok_or(NoRoom)?
    };
    // SAFETY: `at` is a block of `T`'s layout from the global allocator (or the aligned place of
    // a value of no bytes), this call's alone; it is written whole before the box owns it.
    unsafe {
        at.as_ptr().write(value);
        Ok(Box::from_raw(at.as_ptr()))
    }
}

/// A copy of `bytes` of its own, or [`NoRoom`] when the heap refuses it: laid out as
/// `Box::<[u8]>::from(bytes)` lays it out, so it is dropped and freed as that is.
pub(crate) fn try_boxed_bytes(bytes: &[u8]) -> Result<Box<[u8]>, NoRoom> {
    let len = bytes.len();
    let at = if len == 0 {
        NonNull::<u8>::dangling()
    } else {
        let layout = core::alloc::Layout::array::<u8>(len).map_err(|_| NoRoom)?;
        // SAFETY: the layout has bytes, `len` of them.
        let at = NonNull::new(unsafe { alloc::alloc::alloc(layout) }).ok_or(NoRoom)?;
        // SAFETY: a new block of `len` bytes, this call's alone, apart from `bytes`.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), at.as_ptr(), len) };
        at
    };
    // SAFETY: `len` bytes written whole, laid out as a boxed slice of them (none for no bytes).
    Ok(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(at.as_ptr(), len)) })
}

/// `value` put after the last of `items`, or [`NoRoom`] with `items` as they were and `value`
/// let go of when the heap refuses the room: a push with no path that ends the program.
pub(crate) fn try_push<T>(items: &mut Vec<T>, value: T) -> Result<(), NoRoom> {
    items.try_reserve(1).map_err(|_| NoRoom)?;
    push_within(items, value)
}

/// `value` put after the last of `items` in the room already reserved, or [`NoRoom`] with `items`
/// as they were and `value` let go of when none is left: for a caller that reserved the room of
/// every item it puts, whose pushes then carry no growth of their own.
pub(crate) fn push_within<T>(items: &mut Vec<T>, value: T) -> Result<(), NoRoom> {
    let len = items.len();
    items
        .spare_capacity_mut()
        .first_mut()
        .ok_or(NoRoom)?
        .write(value);
    // SAFETY: the place after the last item was written above, within the room reserved.
    unsafe { items.set_len(len.saturating_add(1)) };
    Ok(())
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
pub(crate) const HEAD: usize = core::mem::size_of::<BlockHead>();

/// Set in [`BlockHead::room`] when the block holds the record of the caller's bytes.
const ALIAS: usize = 1 << (usize::BITS - 1);

/// The CALLER'S bytes, described and not copied, with the caller's promise to
/// release them (or not to, for a static buffer) through `_release`.
struct Alias {
    start: *const u8,
    len: usize,
    _release: Release,
}

/// A block of at least `bytes` bytes aligned to 16 from the pools of payload blocks,
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
    // A pool's block is found by its address; its bytes are the heap's to know.
    let _ = bytes;
    let given = crate::process_pool::give_back(at);
    debug_assert!(given, "a payload block goes back to the pool it lies in");
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
/// made over it share, or an encoding's kept schema. The last share let go runs the caller's
/// release, for the record of an alias, and gives the block back.
#[repr(transparent)]
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
                // A block taken is at least the bytes asked for, which hold the head.
                room: bytes.saturating_sub(HEAD),
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

    /// A block holding a copy of `bytes` and where the copy starts in it, for a holder that only
    /// reads them by start and length and needs none of a payload's segment ends: an encoding's
    /// kept schema. `None` when there is no room for one.
    pub(crate) fn kept_copy(bytes: &[u8]) -> Option<(Self, NonNull<u8>)> {
        let block = Self::copy_of(bytes)?;
        let start = block_start(&block);
        Some((block, start))
    }

    /// One block holding each of `parts` copied one after another, the start of each written to
    /// the entry of `starts` at its index: the one copy a value kept past its callback makes of
    /// what was lent to it, whose parts then each hold a share of the block. `None` when there
    /// is no room for all of them.
    pub(crate) fn kept_parts(parts: &[&[u8]], starts: &mut [*const u8]) -> Option<Self> {
        let room = parts
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(part.len()))?;
        let mut block = Self::with_room(room)?;
        let mut at = 0usize;
        for (part, start) in parts.iter().zip(starts.iter_mut()) {
            // SAFETY: a new block, of one holder, with room for every part after the ones before.
            unsafe { block.write(at, part) };
            *start = block.contents().wrapping_add(at).cast_const();
            at = at.saturating_add(part.len());
        }
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

    /// How many whole words the block's own room holds: a payload's segment ends lie in them from
    /// the top down ([`SEGMENTED`]).
    fn words(&self) -> usize {
        self.room().wrapping_div(WORD)
    }

    /// The top word of the block's own room, where a payload's count of segment ends lies; the
    /// word `k` below it is `.sub(k)` of it. Read once by a caller that writes words below it, so
    /// the head is not read again after each write.
    ///
    /// # Safety
    /// The block holds bytes of its own, at least one whole word of them.
    unsafe fn top(&self) -> *mut usize {
        self.contents()
            .cast::<usize>()
            .add(self.words().wrapping_sub(1))
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
        debug_assert!(
            !self.is_alias()
                && at
                    .checked_add(bytes.len())
                    .is_some_and(|end| end <= self.room())
        );
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.contents().add(at), bytes.len());
    }

    /// Another holder of the block; `None` when its holders are past half the address space, a
    /// share leaked in a loop, which `Arc` aborts the process for and a payload is refused for.
    pub(crate) fn share(&self) -> Option<Self> {
        let before = self.head().refs.fetch_add(1, Ordering::Relaxed);
        if before > isize::MAX as usize {
            self.head().refs.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Self { head: self.head })
    }

    /// Whether this is the block's one holder.
    fn is_unique(&self) -> bool {
        self.head().refs.load(Ordering::Acquire) == 1
    }
}

impl Drop for Block {
    // Out of line: every holder's drop and every refused copy's unwinding lets a block go, and the
    // body inlined at each of them is several times the call.
    #[inline(never)]
    fn drop(&mut self) {
        if self.head().refs.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        // The room is what the block took past its head, so the sum is the bytes it took.
        let bytes = HEAD.saturating_add(self.room());
        if self.is_alias() {
            // SAFETY: the last holder lets the record go once, which runs the caller's release.
            unsafe { core::ptr::drop_in_place(self.contents().cast::<Alias>()) };
        }
        // SAFETY: the block was taken with `bytes` bytes and no holder is left.
        unsafe { give_back_block(self.head.cast::<u8>(), bytes) };
    }
}

/// The `len` bytes at `start`, none when `len` is zero.
///
/// # Safety
/// `start` is null only with `len` zero, and the `len` bytes there are written and live while
/// they are read.
#[cfg(test)]
unsafe fn lent_bytes<'a>(start: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(start, len)
    }
}

/// Behind a `z_owned_bytes_t`, in the value's own words: the raw bytes, and the SEGMENT
/// boundaries a `z_bytes_writer_append` left in them.
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
/// one `&[u8]` with no gather — and the boundaries are kept as end offsets at the
/// top of the payload's own block ([`SEGMENTED`]). A payload that keeps none is
/// "one implicit segment covering all the data" (or none, when the data is
/// empty), which is the state every inbound sample and every single-shot
/// constructor is in; only the writer ever keeps ends.
///
/// The payload is three words, so the owned bytes value holds it in its own words
/// ([`store_bytes`]) and needs no place of its own: making, moving and letting one go
/// takes no lock. The ends lie in the block rather than beside the bytes because three
/// words is all the value has room for beside its borrow tag.
///
/// A clone SHARES the block ([`ByteBuf::try_clone`]), as pico's `z_bytes_clone`
/// does, and with it the ends; a copy is asked for by name ([`ByteBuf::copied`]), and a
/// writer that needs to change shared or aliased bytes copies them first. A LENT payload
/// ([`ByteBuf::lent`]) has no block to share, so its clone is a copy. Every
/// one that takes a block can be refused one ([`NoRoom`]).
#[repr(C)]
pub(crate) struct ByteBuf {
    /// Where the payload's bytes start: in the block it holds a share of, in its lender's bytes
    /// ([`ByteBuf::lent`]), or dangling for none. Read with the size and nothing else, so reading
    /// a payload has no branch on where it is held.
    start: NonNull<u8>,
    /// How many bytes of the block this payload is, with [`SEGMENTED`] set when it keeps segment
    /// ends: shorter than the block's room for a payload made over a string, whose terminator it
    /// does not carry, and for a writer's, which grows into it.
    extent: usize,
    /// The block the payload holds a share of, let go with it; none for an empty payload and for
    /// a lent one, whose bytes are its lender's.
    block: Option<Block>,
}

/// Set in [`ByteBuf::extent`] when the payload keeps segment ends. They lie at the top of its
/// block's own room, apart from its bytes, which start the block: the top word is their count and
/// each end lies one word below the one before it. Only a writer keeps them
/// ([`ByteBuf::append_segments`]), so they lie in a block of the payload's own, which a share of
/// it reads unchanged: a write to a shared block copies the block first ([`ByteBuf::reserve`]).
const SEGMENTED: usize = 1 << (usize::BITS - 1);

/// The bytes of one word of a payload's segment ends.
const WORD: usize = core::mem::size_of::<usize>();

/// The bytes the segment ends of a payload that keeps `ends` of them take at the top of its
/// block: a word for their count and one for each, none for a payload that keeps none.
fn table_bytes(ends: usize) -> Option<usize> {
    if ends == 0 {
        Some(0)
    } else {
        ends.checked_add(1)?.checked_mul(WORD)
    }
}

/// The room of a block for `bytes` bytes of a payload and, above them in whole words, `table`
/// bytes of its segment ends.
fn room_for(bytes: usize, table: usize) -> Option<usize> {
    if table == 0 {
        Some(bytes)
    } else {
        bytes.div_ceil(WORD).checked_mul(WORD)?.checked_add(table)
    }
}

/// Whether `block` holds `bytes` bytes of a payload and, above them, `table` bytes of its
/// segment ends.
fn holds(block: &Block, bytes: usize, table: usize) -> bool {
    if table == 0 {
        block.room() >= bytes
    } else {
        block
            .words()
            .checked_mul(WORD)
            .and_then(|top| top.checked_sub(table))
            .is_some_and(|below| below >= bytes)
    }
}

// SAFETY: a lent payload's bytes are its lender's, valid and unchanged for as long as the payload
// lives (`ByteBuf::lent`); nothing writes through `start` but the one holder of an own block
// ([`Block::write`]), so the pointer is shared between threads exactly as the lender's reference
// or the block would be. A block is `Send` and `Sync` on its own.
unsafe impl Send for ByteBuf {}
unsafe impl Sync for ByteBuf {}

impl core::fmt::Debug for ByteBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ByteBuf")
            .field("len", &self.size())
            .field("segments", &self.segments())
            .finish()
    }
}

impl Default for ByteBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Where the bytes of `block` start, dangling for an alias of none.
fn block_start(block: &Block) -> NonNull<u8> {
    NonNull::new(block.span().0.cast_mut()).unwrap_or(NonNull::dangling())
}

impl ByteBuf {
    /// An empty payload with no segments, which holds no block.
    pub(crate) fn new() -> Self {
        Self {
            start: NonNull::dangling(),
            extent: 0,
            block: None,
        }
    }

    /// The first `len` bytes of `block`, which this payload holds a share of.
    fn over(block: Block, len: usize) -> Self {
        Self {
            start: block_start(&block),
            extent: len,
            block: Some(block),
        }
    }

    /// A payload holding a copy of `bytes` in a block of its own. Never inlined: every door that
    /// copies the caller's bytes into a payload, a slice or a string calls this one body.
    #[inline(never)]
    pub(crate) fn copy_of(bytes: &[u8]) -> Result<Self, NoRoom> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        let block = Block::copy_of(bytes).ok_or(NoRoom)?;
        Ok(Self::over(block, bytes.len()))
    }

    /// A payload that DESCRIBES the caller's `len` bytes at `start` and lets
    /// `release` return them when the last holder is dropped. Refused, the release runs at once,
    /// as pico's transfer of the caller's buffer is unconditional once the call is made.
    ///
    /// Never inlined, as [`Self::copy_of`]: every door that takes over the caller's buffer calls
    /// this one body.
    ///
    /// # Safety
    /// `start` must be null with `len == 0`, or point at `len` readable bytes
    /// that stay valid and unchanged until `release` has run.
    #[inline(never)]
    pub(crate) unsafe fn aliased(
        start: *const u8,
        len: usize,
        release: Release,
    ) -> Result<Self, NoRoom> {
        let block = Block::alias(start, len, release).map_err(|release| {
            drop(release);
            NoRoom
        })?;
        Ok(Self::over(block, len))
    }

    /// A payload that READS `bytes` where they lie and allocates nothing: a sample's payload
    /// handed to a callback, read where the session delivered it. What may outlive the bytes is
    /// given a copy: a clone, and the storage a slice or a string takes over.
    ///
    /// # Safety
    /// `bytes` stay valid and unchanged until this payload is dropped.
    pub(crate) unsafe fn lent(bytes: &[u8]) -> Self {
        Self {
            start: NonNull::from(bytes).cast::<u8>(),
            extent: bytes.len(),
            block: None,
        }
    }

    /// A payload of the `like` size of bytes at `start` of `block`, holding a share of it: a part
    /// of a block that holds more than one ([`Block::kept_parts`]), made for a `like` that holds no
    /// block and so keeps no segment ends. An empty one holds no block, as an empty payload does,
    /// and needs none made for it.
    ///
    /// # Safety
    /// For a `like` that is not empty, `block` is one and the bytes at `start` lie in its own room
    /// and are written.
    unsafe fn part_of(
        block: Option<&Block>,
        start: *const u8,
        like: &ByteBuf,
    ) -> Result<Self, NoRoom> {
        Ok(match NonNull::new(start.cast_mut()) {
            Some(start) if like.size() != 0 => Self {
                start,
                extent: like.size(),
                block: Some(block.and_then(Block::share).ok_or(NoRoom)?),
            },
            _ => Self::new(),
        })
    }

    /// Whether the payload holds a share of a block, which a holder that keeps it may share
    /// rather than copy: not a lent one, whose bytes are its lender's, nor an empty one.
    pub(crate) fn holds_block(&self) -> bool {
        self.block.is_some()
    }

    /// This payload as a value kept past its callback holds it: a share of the block it holds, or
    /// for a lent one the part of `block` at `start` that the one copy of what was lent wrote its
    /// bytes to ([`Self::part_of`]). Out of line: a kept sample keeps its payload and its
    /// attachment through it.
    ///
    /// # Safety
    /// For a payload that holds no block, as [`Self::part_of`] with this payload as `like`.
    #[inline(never)]
    pub(crate) unsafe fn kept_in(
        &self,
        block: Option<&Block>,
        start: *const u8,
    ) -> Result<Self, NoRoom> {
        if self.holds_block() {
            self.try_clone()
        } else {
            Self::part_of(block, start, self)
        }
    }

    /// How many bytes the payload is.
    fn size(&self) -> usize {
        self.extent & !SEGMENTED
    }

    /// Whether the payload keeps segment ends in its block ([`SEGMENTED`]).
    fn is_segmented(&self) -> bool {
        self.extent & SEGMENTED != 0
    }

    /// The payload's bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: `start` is never null, and the bytes there are the payload's, written when it
        // was made: in its block, which lives as long as this holder, or in its lender's bytes,
        // which outlive it (`Self::lent`). For none it is dangling and the size is zero.
        unsafe { core::slice::from_raw_parts(self.start.as_ptr(), self.size()) }
    }

    /// How many segment ends the payload keeps: none for one that keeps none.
    fn ends(&self) -> usize {
        match &self.block {
            // SAFETY: a payload that keeps ends keeps their count in the top word of a block of
            // its own ([`SEGMENTED`]).
            Some(block) if self.is_segmented() => unsafe { block.top().read() },
            _ => 0,
        }
    }

    /// How many segments the payload has: one for each end it keeps, else one of all its bytes,
    /// or none when it has none.
    fn segments(&self) -> usize {
        if self.is_segmented() {
            self.ends()
        } else {
            usize::from(self.size() != 0)
        }
    }

    /// Where the payload's segment `idx` ends; `None` past its last.
    fn segment_end(&self, idx: usize) -> Option<usize> {
        match &self.block {
            // SAFETY: a payload that keeps ends keeps their count in the top word of a block of its
            // own, and end `idx`, below their count, `idx + 1` words below it ([`SEGMENTED`]).
            Some(block) if self.is_segmented() => unsafe {
                let top = block.top();
                if idx < top.read() {
                    Some(top.sub(idx.saturating_add(1)).read())
                } else {
                    None
                }
            },
            // One segment of all the bytes, or none when there are none.
            _ => (idx == 0 && self.size() != 0).then_some(self.size()),
        }
    }

    /// Another holder of the payload: one that SHARES its block, and the segment ends it keeps
    /// there, as pico's `z_bytes_clone` shares the storage, or for a lent payload, whose lender's
    /// bytes a clone may outlive, a copy.
    pub(crate) fn try_clone(&self) -> Result<Self, NoRoom> {
        match &self.block {
            Some(block) => Ok(Self {
                start: self.start,
                extent: self.extent,
                block: Some(block.share().ok_or(NoRoom)?),
            }),
            None => Self::copy_of(self.as_slice()),
        }
    }

    /// The block, for a holder that keeps it: a lent payload's bytes, and those of a part of a
    /// block that holds more ([`Self::part_of`]), whose holder reads the block from its start, are
    /// copied into one of their own first; an empty payload has none.
    fn into_block(mut self) -> Result<Option<Block>, NoRoom> {
        if self
            .block
            .as_ref()
            .is_some_and(|block| block_start(block) == self.start)
        {
            return Ok(self.block.take());
        }
        if self.size() == 0 {
            return Ok(None);
        }
        Block::copy_of(self.as_slice()).map(Some).ok_or(NoRoom)
    }

    /// A payload with the same bytes in a block of its own: the copy an
    /// extraction (`z_bytes_to_slice`) makes and a clone does not.
    pub(crate) fn copied(&self) -> Result<Self, NoRoom> {
        Self::copy_of(self.as_slice())
    }

    /// Make the payload's bytes a block of its own, of this one holder, with room for `extra`
    /// more bytes after them and for `more_ends` more segment ends above them: the block it has
    /// when that is so, else a new one its bytes and ends are copied into, twice as large as they
    /// are where there is such a block, so a writer's appends copy them a bounded number of times.
    fn reserve(&mut self, extra: usize, more_ends: usize) -> Result<(), NoRoom> {
        let need = self.size().checked_add(extra).ok_or(NoRoom)?;
        let ends = self.ends();
        let table = ends
            .checked_add(more_ends)
            .and_then(table_bytes)
            .ok_or(NoRoom)?;
        if let Some(block) = &self.block {
            // Written after its bytes only where they start the block, as a part of a block that
            // holds more does not ([`Self::part_of`]).
            if block.is_unique()
                && !block.is_alias()
                && block_start(block) == self.start
                && holds(block, need, table)
            {
                return Ok(());
            }
        }
        let grown = room_for(
            need.max(self.size().saturating_mul(2)),
            table.saturating_mul(2),
        );
        let mut block = grown
            .and_then(Block::with_room)
            .or_else(|| room_for(need, table).and_then(Block::with_room))
            .ok_or(NoRoom)?;
        // SAFETY: a new block, of one holder, with room for the payload's bytes below the words of
        // its ends.
        unsafe { block.write(0, self.as_slice()) };
        if let Some(old) = self.block.as_ref().filter(|_| self.is_segmented()) {
            // SAFETY: the old block holds the count of the payload's ends and each of them in the
            // `ends + 1` words at its top, and the new one, apart from it, has room for as many at
            // its top, above the bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    old.top().sub(ends),
                    block.top().sub(ends),
                    ends.saturating_add(1),
                );
            }
        }
        self.start = block_start(&block);
        self.block = Some(block);
        Ok(())
    }

    /// Write `bytes` after the payload's bytes, into the room [`Self::reserve`] made for them.
    fn put_after(&mut self, bytes: &[u8]) {
        let at = self.size();
        if let Some(block) = &mut self.block {
            // SAFETY: `reserve` left a block of the payload's own, of one holder, with room for
            // these bytes after its own, below its segment ends.
            unsafe { block.write(at, bytes) };
        }
        // `reserve` counted these bytes after the payload's with checked arithmetic.
        self.extent = self.extent.saturating_add(bytes.len());
    }

    /// End a segment at `end`, in the word [`Self::reserve`] made for one more end.
    fn push_end(&mut self, end: usize) {
        let ends = self.ends().saturating_add(1);
        let Some(block) = &self.block else {
            return;
        };
        // SAFETY: `reserve` left a block of the payload's own, of one holder, with the word of the
        // ends' count and of one more end free at its top, above the payload's bytes.
        unsafe {
            let top = block.top();
            top.sub(ends).write(end);
            top.write(ends);
        }
        self.extent |= SEGMENTED;
    }

    /// Whether the payload is ONE slice, which is what
    /// `z_bytes_get_contiguous_view` requires.
    ///
    /// wz's storage is always one block, so a naive answer would be "always" —
    /// and that would be WRONG against a real pico, whose `_z_bytes_t` is a
    /// vector of arc-slices and whose `z_bytes_get_contiguous_view` fails once
    /// there is more than one. The question the export asks is about the
    /// payload's SEGMENT structure, not about wz's allocator, so it is answered
    /// from the segment ends — the same ones the slice iterator walks, and the same
    /// ones the R311y532 foreign oracle showed wz had been discarding. The export
    /// is the unstable API's, and so is this.
    #[cfg(feature = "unstable-api")]
    pub(crate) fn is_contiguous(&self) -> bool {
        self.segments() <= 1
    }

    /// The `idx`-th segment, or `None` past the end — what
    /// `z_bytes_slice_iterator_next` yields.
    pub(crate) fn segment(&self, idx: usize) -> Option<&[u8]> {
        let start = match idx.checked_sub(1) {
            None => 0,
            Some(before) => self.segment_end(before)?,
        };
        let end = self.segment_end(idx)?;
        self.as_slice().get(start..end)
    }

    /// Append another payload AS ITS OWN SEGMENTS (pico
    /// `z_bytes_writer_append`, which moves the source's slice list in). Refused, the payload is
    /// as it was.
    ///
    /// The first append on a buffer that already holds unsegmented bytes has to
    /// close that implicit segment first, or the existing content would silently
    /// merge into the newly appended one. An empty payload brings no segment, and
    /// closing the buffer's bytes alone would change no segment a reader sees, so it
    /// writes nothing.
    pub(crate) fn append_segments(&mut self, other: &ByteBuf) -> Result<(), NoRoom> {
        let brought = other.segments();
        if brought == 0 {
            return Ok(());
        }
        let close = !self.is_segmented() && self.size() != 0;
        // The room of every byte and end this append writes, taken before anything is written:
        // one end for each of the other's segments and one to close this payload's own.
        self.reserve(other.size(), brought.saturating_add(usize::from(close)))?;
        if close {
            self.push_end(self.size());
        }
        // The other's segments follow one another and its last ends at its last byte (a write
        // grows the last), so its bytes are written in one copy and each of its ends is moved up
        // by the bytes before them.
        let before = self.size();
        self.put_after(other.as_slice());
        for idx in 0..brought {
            let Some(end) = other.segment_end(idx) else {
                break;
            };
            self.push_end(before.saturating_add(end));
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
        self.reserve(bytes.len(), 0)?;
        self.put_after(bytes);
        let ends = self.ends();
        if let Some(block) = self.block.as_ref().filter(|_| ends != 0) {
            // SAFETY: the last of the payload's ends lies `ends` words down from the top of the
            // block of its own that `reserve` left it, of one holder.
            unsafe { block.top().sub(ends).write(self.size()) };
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
            return Ok(ByteBuf::over(block.share().ok_or(NoRoom)?, len));
        }
    }
    ByteBuf::copy_of(crate::abi::view_bytes(start, len).unwrap_or(&[]))
}

/// Put in `bytes` the payload [`payload_over`] makes of a moved slice's or string's state: one
/// body, out of line, for `z_bytes_from_slice` and `z_bytes_from_string`, which differ only in
/// the type of the state they read and the drop they owe it.
///
/// # Safety
/// `bytes` is valid and writable, and the rest is as [`payload_over`] asks.
#[inline(never)]
unsafe fn store_payload_over(
    bytes: *mut z_owned_bytes_t,
    block: Option<&Block>,
    filled: usize,
    start: *const u8,
    len: usize,
) -> ZResult {
    store_bytes(bytes, payload_over(block, filled, start, len))
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
        let len = buf.size();
        let backing = buf.into_block()?;
        // An empty slice's data is a pointer all the same, as a slice of no bytes has.
        let start = match backing.as_ref().map(|block| block.span().0) {
            Some(start) if !start.is_null() => start,
            _ => NonNull::<u8>::dangling().as_ptr().cast_const(),
        };
        try_box(SliceState {
            backing,
            filled: len,
            self_view: z_loaned_slice_t {
                _start: start,
                _len: len,
            },
        })
    }

    /// Put in `bytes` this slice as a payload that SHARES its block.
    ///
    /// # Safety
    /// `bytes` is valid and writable.
    unsafe fn store_shared(&self, bytes: *mut z_owned_bytes_t) -> ZResult {
        // `self_view` is this state's own view.
        store_payload_over(
            bytes,
            self.backing.as_ref(),
            self.filled,
            self.self_view._start,
            self.self_view._len,
        )
    }
}

impl StringState {
    /// A string in a block of its own: the bytes, then the NUL a C caller
    /// treating `z_string_data` as a C string relies on. An empty one points at a terminator of
    /// the library's and holds no block.
    fn boxed(bytes: &[u8]) -> Result<Box<StringState>, NoRoom> {
        if bytes.is_empty() {
            return try_box(StringState {
                backing: None,
                filled: 0,
                self_view: z_loaned_string_t {
                    _start: &EMPTY_C_STRING,
                    _len: 0,
                },
            });
        }
        let filled = bytes.len().checked_add(1).ok_or(NoRoom)?;
        let mut block = Block::with_room(filled).ok_or(NoRoom)?;
        // SAFETY: a new block, of one holder, with room for the bytes and their terminator.
        unsafe {
            block.write(0, bytes);
            block.write(bytes.len(), &[0]);
        }
        let start = block.span().0;
        try_box(StringState {
            backing: Some(block),
            filled,
            self_view: z_loaned_string_t {
                _start: start,
                _len: bytes.len(),
            },
        })
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
        try_box(StringState {
            backing: Some(block),
            filled: len,
            self_view: z_loaned_string_t {
                _start: view_start,
                _len: len,
            },
        })
    }

    /// Put in `bytes` this string as a payload that SHARES its block, minus the terminator.
    ///
    /// # Safety
    /// `bytes` is valid and writable.
    unsafe fn store_shared(&self, bytes: *mut z_owned_bytes_t) -> ZResult {
        // `self_view` is this state's own view.
        store_payload_over(
            bytes,
            self.backing.as_ref(),
            self.filled,
            self.self_view._start,
            self.self_view._len,
        )
    }
}

// An owned payload is its payload's three words and a fourth, the borrow tag
// (`crate::abi::HandleOwnership`), so a payload is placed, moved and let go of in the value itself.
const _: () = {
    assert!(core::mem::size_of::<ByteBuf>() == core::mem::size_of::<[usize; 3]>());
    assert!(core::mem::size_of::<z_owned_bytes_t>() == core::mem::size_of::<[usize; 4]>());
    assert!(core::mem::align_of::<ByteBuf>() <= core::mem::align_of::<z_owned_bytes_t>());
};

/// The payload the owned value at `obj` holds in its words, taken out of it and the value left
/// null. A borrow's (`crate::abi::HandleOwnership`) is a copy of its marshal's, which the caller
/// does not let go of.
///
/// # Safety
/// `obj` is valid and writable and holds a payload: its first word is not null.
pub(crate) unsafe fn take_payload(obj: *mut z_owned_bytes_t) -> ByteBuf {
    let buf = obj.cast::<ByteBuf>().read();
    *obj = z_owned_bytes_t::null_value();
    buf
}

/// # Safety
/// `h` must be a live `Box::into_raw::<SliceState>` pointer.
unsafe fn free_slice(h: *mut c_void) {
    drop(Box::from_raw(h as *mut SliceState));
}

impl_handle_ownership6!(
    z_owned_bytes_t,
    z_loaned_bytes_t,
    z_moved_bytes_t,
    z_internal_bytes_null,
    z_internal_bytes_check,
    z_bytes_loan,
    z_bytes_loan_mut,
    z_bytes_move,
    z_bytes_take
);

/// Drop an owned payload (pico `z_bytes_drop`): its share of its block is let go, unless the value
/// is a borrow of a delivered sample's payload, whose sample lets it go, and the value is left
/// null. Idempotent on a null pointer or a null value.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_drop(obj: *mut z_moved_bytes_t) {
    let _ = guarded(|| {
        drop(crate::pubsub::read_moved_bytes(obj));
        Z_OK
    });
}

/// Adopt a loaned payload into an owned one, leaving the loaned value null (pico
/// `z_bytes_take_from_loaned`). The payload's words move, and a borrow's tag with them.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_take_from_loaned(
    dst: *mut z_owned_bytes_t,
    src: *mut z_loaned_bytes_t,
) -> ZResult {
    if dst.is_null() || src.is_null() {
        return Z_ERR_NULL;
    }
    crate::abi::take_block(
        dst.cast(),
        src.cast(),
        core::mem::size_of::<z_owned_bytes_t>(),
    );
    Z_OK
}

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

/// Put the payload `made` in the words of `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst` null,
/// when there was no room for its bytes.
///
/// One body out of line: every door that hands a payload back stores it this way, and each copy
/// inlined held its own placing of the payload and its own refusal.
#[inline(never)]
unsafe fn store_bytes(dst: *mut z_owned_bytes_t, made: Result<ByteBuf, NoRoom>) -> ZResult {
    match made {
        Ok(buf) => {
            // The tag word cleared, as an owned payload's is, and the payload in the words before.
            *dst = z_owned_bytes_t::null_value();
            dst.cast::<ByteBuf>().write(buf);
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
///
/// Out of line: a door that renders a string of a fixed length into a buffer of its own would
/// otherwise inline a copy of the string's construction specialised to that length, and hold its
/// rendering in registers only to copy it into the block byte by byte.
#[inline(never)]
pub(crate) unsafe fn store_owned_string(dst: *mut z_owned_string_t, bytes: &[u8]) -> ZResult {
    store_string(dst, StringState::boxed(bytes))
}

/// Put the string `made` in `dst`. `Z_OK`; `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, `dst` null, when
/// there was no room for its bytes. Out of line for the reason `store_bytes` is: every door
/// that hands a string back stores it this way.
#[inline(never)]
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

/// Read the payload a loaned bytes value holds in its own words; `None` for a null pointer or a
/// null value.
pub(crate) unsafe fn bytes_ref<'a>(ptr: *const z_loaned_bytes_t) -> Option<&'a ByteBuf> {
    if ptr.is_null() || (*ptr).handle.is_null() {
        return None;
    }
    Some(&*ptr.cast::<ByteBuf>())
}

// --- bytes constructors ---------------------------------------------------

/// Copy a buffer into an owned payload (pico `z_bytes_copy_from_buf`).
///
/// Out of line: the slice, string and one-octet doors end in this one, and each held a copy of
/// its own.
#[no_mangle]
#[inline(never)]
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
            value.cast::<u8>(),
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
            (*string)._start.cast::<c_char>()
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
        (*iter)._slice_idx = (*iter)._slice_idx.saturating_add(1);
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
                // The payload takes over the slice's storage rather than
                // copying it (pico moves the allocation), so its address is
                // the slice's and an aliased slice's deleter waits for it.
                Some(state) => state.store_shared(bytes),
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
                // As `z_bytes_from_slice`: the string's own storage, minus
                // its terminator.
                Some(state) => state.store_shared(bytes),
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
    let len = crate::abi::c_str_len(value);
    z_string_copy_from_substr(str_out, value, len)
}

/// Copy an explicitly-sized substring into an owned string (pico
/// `z_string_copy_from_substr`).
///
/// # Safety
/// `str_out` must be valid and writable; `value` must be null or point at `len`
/// readable bytes.
///
/// Out of line: the `_from_str` door ends in this one, and held a copy of its own.
#[no_mangle]
#[inline(never)]
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
            core::slice::from_raw_parts(value.cast::<u8>(), len)
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
    let len = crate::abi::c_str_len(value);
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
            _start: value.cast::<u8>(),
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

#[cfg(test)]
impl ByteBuf {
    /// How many hold the block this payload holds a share of; none for a payload with no block.
    pub(crate) fn holders(&self) -> usize {
        self.block
            .as_ref()
            .map_or(0, |block| block.head().refs.load(Ordering::Relaxed))
    }

    /// Set how many hold this payload's block, for a test that has a share of it refused.
    pub(crate) fn set_holders(&self, holders: usize) {
        if let Some(block) = &self.block {
            block.head().refs.store(holders, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;

    /// A payload that is a part of a block holding more is copied before it is written after, as
    /// its bytes do not start the block, and kept as the block of a slice the same way: the bytes
    /// before it are never read or written as its own. Turned red by dropping the start test in
    /// `ByteBuf::reserve` or in `ByteBuf::into_block`.
    #[test]
    fn a_part_of_a_block_is_copied_before_it_is_written_or_kept() {
        let like = ByteBuf::copy_of(b"cd").expect("room");
        let parts: [&[u8]; 2] = [b"ab", b"cd"];
        let mut starts = [core::ptr::null::<u8>(); 2];
        let block = Block::kept_parts(&parts, &mut starts).expect("room");
        // SAFETY: `kept_parts` wrote "cd" at `starts[1]` of `block`.
        let mut part =
            unsafe { ByteBuf::part_of(Some(&block), starts[1], &like) }.expect("a share");
        assert_eq!(part.holders(), 2);
        drop(block);
        assert_eq!(part.as_slice(), b"cd");
        part.write_all(b"ef").expect("room");
        assert_eq!(part.as_slice(), b"cdef");

        let block = Block::kept_parts(&parts, &mut starts).expect("room");
        // SAFETY: as above.
        let kept = unsafe { ByteBuf::part_of(Some(&block), starts[1], &like) }.expect("a share");
        drop(block);
        let slice = SliceState::boxed(kept).expect("room");
        // SAFETY: the slice's own view of its block.
        let read =
            unsafe { core::slice::from_raw_parts(slice.self_view._start, slice.self_view._len) };
        assert_eq!(read, b"cd");
    }

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
        assert!(empty.block.is_none());
        let clone = empty.try_clone().expect("no room is asked for");
        assert!(clone.block.is_none());
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
        assert_eq!(writer.size(), 304);
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

    /// A payload appended to an empty writer is its first segment, with no empty one before it.
    /// Turned red by an append that closes a segment the writer never had.
    #[test]
    fn an_append_to_an_empty_writer_starts_at_its_first_segment() {
        let mut writer = ByteBuf::new();
        writer
            .append_segments(&ByteBuf::copy_of(b"ab").expect("room"))
            .expect("room");
        assert_eq!(writer.as_slice(), b"ab");
        assert_eq!(writer.segment(0), Some(&b"ab"[..]));
        assert_eq!(writer.segment(1), None);
    }

    /// A payload of several segments appended to a writer brings each of them, in order, and no
    /// index past the last names one.
    #[test]
    fn a_segmented_payload_appends_each_of_its_segments() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        let mut parts = ByteBuf::copy_of(b"p").expect("room");
        parts
            .append_segments(&ByteBuf::copy_of(b"q").expect("room"))
            .expect("room");
        writer.append_segments(&parts).expect("room");
        assert_eq!(writer.as_slice(), b"xpq");
        assert_eq!(writer.segment(0), Some(&b"x"[..]));
        assert_eq!(writer.segment(1), Some(&b"p"[..]));
        assert_eq!(writer.segment(2), Some(&b"q"[..]));
        assert_eq!(writer.segment(3), None);
        assert_eq!(writer.segment(usize::MAX), None);
    }

    /// A payload of segments whose last a write grew, appended to a writer that keeps ends of its
    /// own, brings all its bytes in order and each end moved up by the writer's bytes before it.
    /// Turned red by an append that leaves an end where it lay in the payload, or that copies the
    /// bytes of the last segment short of the write that grew it.
    #[test]
    fn a_segmented_payload_appended_to_a_segmented_writer_keeps_each_bound() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        writer
            .append_segments(&ByteBuf::copy_of(b"ab").expect("room"))
            .expect("room");
        let mut parts = ByteBuf::copy_of(b"p").expect("room");
        parts
            .append_segments(&ByteBuf::copy_of(b"q").expect("room"))
            .expect("room");
        parts.write_all(b"rs").expect("room");
        writer.append_segments(&parts).expect("room");
        assert_eq!(writer.as_slice(), b"xabpqrs");
        assert_eq!(writer.segments(), 4);
        assert_eq!(writer.segment(0), Some(&b"x"[..]));
        assert_eq!(writer.segment(1), Some(&b"ab"[..]));
        assert_eq!(writer.segment(2), Some(&b"p"[..]));
        assert_eq!(writer.segment(3), Some(&b"qrs"[..]));
        assert_eq!(writer.segment(4), None);
        assert_eq!(
            parts.segment(1),
            Some(&b"qrs"[..]),
            "the appended payload is left whole"
        );
    }

    /// An empty payload appended brings no segment, not an empty one, and the writer's own bytes
    /// stay its one segment. Turned red by an append that walks one end for every payload that
    /// keeps none, whatever its length.
    #[test]
    fn an_empty_payload_appended_brings_no_segment() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        writer.append_segments(&ByteBuf::new()).expect("room");
        assert_eq!(writer.as_slice(), b"x");
        assert_eq!(writer.segments(), 1);
        assert_eq!(writer.segment(0), Some(&b"x"[..]));
        assert_eq!(writer.segment(1), None);
    }

    /// A push within the room reserved puts the value while there is room and refuses it, the items
    /// as they were, once there is none, where a growing push would have taken more. Turned red by a
    /// `push_within` that grows the items.
    #[test]
    fn a_push_within_the_room_reserved_never_grows() {
        let mut items: Vec<u8> = Vec::new();
        assert_eq!(push_within(&mut items, 1), Err(NoRoom));
        assert!(items.is_empty());
        items.try_reserve_exact(2).expect("the test's heap");
        let room = items.capacity();
        for value in 0..room {
            assert_eq!(push_within(&mut items, value as u8), Ok(()));
        }
        assert_eq!(push_within(&mut items, 0), Err(NoRoom));
        assert_eq!(items.len(), room);
        assert_eq!(items.capacity(), room);
        assert_eq!(items.first(), Some(&0));
    }

    /// A clone of a payload that keeps segment ends shares them with its block and asks the heap
    /// for nothing. Turned red by a clone that copies the ends apart from the block, or drops them.
    #[test]
    fn a_clone_of_a_segmented_payload_shares_its_ends_and_asks_the_heap_for_nothing() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        writer
            .append_segments(&ByteBuf::copy_of(b"ab").expect("room"))
            .expect("room");
        assert_eq!(writer.segments(), 2);
        let clone =
            crate::test_heap::refused(|| writer.try_clone()).expect("a share takes no room");
        assert_eq!(writer.holders(), 2);
        assert_eq!(clone.segments(), 2);
        assert_eq!(clone.segment(0), Some(&b"x"[..]));
        assert_eq!(clone.segment(1), Some(&b"ab"[..]));
        assert_eq!(clone.segment(2), None);
    }

    /// A write to a writer whose block a clone shares copies the bytes and the segment ends into
    /// a block of its own, and the clone reads what it held. Turned red by a `reserve` that leaves
    /// the ends behind when it grows, or writes the shared block.
    #[test]
    fn a_write_after_a_clone_carries_the_ends_into_a_block_of_its_own() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        writer
            .append_segments(&ByteBuf::copy_of(b"ab").expect("room"))
            .expect("room");
        let held = writer.try_clone().expect("a share takes no room");
        writer.write_all(b"cd").expect("room");
        assert_eq!(writer.holders(), 1, "a block of its own");
        assert_eq!(writer.segment(0), Some(&b"x"[..]));
        assert_eq!(
            writer.segment(1),
            Some(&b"abcd"[..]),
            "the last segment grows"
        );
        assert_eq!(writer.segment(2), None);
        assert_eq!(held.segment(0), Some(&b"x"[..]));
        assert_eq!(held.segment(1), Some(&b"ab"[..]));
        assert_eq!(held.as_slice(), b"xab");
    }

    /// Many appends keep every segment while the block grows under them: the bytes never reach
    /// the ends above them, and each growth carries both. Turned red by a table the bytes write
    /// over, or one a growth loses.
    #[test]
    fn many_appends_keep_every_segment_as_the_block_grows() {
        let mut writer = ByteBuf::new();
        let mut whole = Vec::new();
        for i in 0..40u8 {
            let part = vec![i; usize::from(i % 5) + 1];
            writer
                .append_segments(&ByteBuf::copy_of(&part).expect("room"))
                .expect("room");
            whole.extend_from_slice(&part);
        }
        assert_eq!(writer.segments(), 40);
        assert_eq!(writer.as_slice(), &whole[..]);
        for i in 0..40u8 {
            let part = vec![i; usize::from(i % 5) + 1];
            assert_eq!(
                writer.segment(usize::from(i)),
                Some(&part[..]),
                "segment {i}"
            );
        }
        assert_eq!(writer.segment(40), None);
    }

    /// A slice over a writer's block, and a payload made over that slice, read the bytes as one
    /// segment: the ends at the top of the block are the writer's, not the block's. Turned red by a
    /// payload that reads ends from any block that holds some.
    #[test]
    fn a_payload_over_a_writers_block_keeps_none_of_its_ends() {
        let mut writer = ByteBuf::copy_of(b"x").expect("room");
        writer
            .append_segments(&ByteBuf::copy_of(b"ab").expect("room"))
            .expect("room");
        let slice = SliceState::boxed(writer).expect("room");
        // SAFETY: the view is the slice's own, over its block's written bytes.
        let payload = unsafe {
            payload_over(
                slice.backing.as_ref(),
                slice.filled,
                slice.self_view._start,
                slice.self_view._len,
            )
        }
        .expect("a share takes no room");
        assert_eq!(payload.as_slice(), b"xab");
        assert_eq!(payload.segments(), 1);
        assert_eq!(payload.segment(0), Some(&b"xab"[..]));
    }

    /// An owned payload lies in the words of its value: a clone shares the block with no place of
    /// its own, a take and a take from a loan move the words and leave the source null, and each
    /// drop lets go of one share. Turned red by a payload placed apart from its value.
    #[test]
    fn an_owned_payload_lies_in_the_words_of_its_value() {
        // SAFETY: each pointer handed over points at a live value of its type, which outlives the
        // call, and each owned value is dropped once.
        unsafe {
            let mut owned = z_owned_bytes_t::null_value();
            assert_eq!(z_bytes_copy_from_buf(&mut owned, b"abc".as_ptr(), 3), Z_OK);
            let payload = bytes_ref(z_bytes_loan(&owned)).expect("a payload");
            assert_eq!(
                core::ptr::from_ref(payload) as usize,
                core::ptr::from_ref(&owned) as usize,
                "the payload is the value's own words"
            );
            assert!(owned._pad[2].is_null(), "an owned payload is no borrow");
            let start = start_of(payload);

            let mut clone = z_owned_bytes_t::null_value();
            let cloned =
                crate::test_heap::refused(|| z_bytes_clone(&mut clone, z_bytes_loan(&owned)));
            assert_eq!(cloned, Z_OK, "a clone takes no place");
            let shared = bytes_ref(z_bytes_loan(&clone)).expect("a clone");
            assert_eq!(start_of(shared), start);
            assert_eq!(shared.holders(), 2);

            let mut taken = z_owned_bytes_t::null_value();
            z_bytes_take(&mut taken, z_bytes_move(&mut clone));
            assert!(!z_internal_bytes_check(&clone), "the source is spent");
            let mut adopted = z_owned_bytes_t::null_value();
            assert_eq!(
                z_bytes_take_from_loaned(&mut adopted, z_bytes_loan_mut(&mut taken)),
                Z_OK
            );
            assert!(
                !z_internal_bytes_check(&taken),
                "the loaned source is spent"
            );
            let adopted_payload = bytes_ref(z_bytes_loan(&adopted)).expect("adopted");
            assert_eq!(start_of(adopted_payload), start);
            assert_eq!(adopted_payload.as_slice(), b"abc");

            z_bytes_drop(z_bytes_move(&mut adopted));
            assert!(!z_internal_bytes_check(&adopted));
            assert_eq!(
                bytes_ref(z_bytes_loan(&owned))
                    .expect("a payload")
                    .holders(),
                1,
                "the clone's share let go of"
            );
            z_bytes_drop(z_bytes_move(&mut taken));
            z_bytes_drop(z_bytes_move(&mut owned));
            assert!(!z_internal_bytes_check(&owned));
        }
    }

    /// A block whose holders are past half the address space is not shared again: the share is
    /// refused and the count left as it was, where `Arc` would abort the process.
    #[test]
    fn a_block_shared_past_any_count_is_refused() {
        let block = Block::copy_of(b"held").expect("room");
        let past = isize::MAX as usize + 1;
        block.head().refs.store(past, Ordering::Relaxed);
        assert!(block.share().is_none());
        assert_eq!(block.head().refs.load(Ordering::Relaxed), past);
        block.head().refs.store(1, Ordering::Relaxed);
        let shared = block.share().expect("a second holder");
        assert_eq!(block.head().refs.load(Ordering::Relaxed), 2);
        drop(shared);
        assert_eq!(block.head().refs.load(Ordering::Relaxed), 1);
    }

    /// A slice and a string moved into a payload through their doors share their block: the
    /// payload's bytes are where the state held them, a string's terminator left out.
    #[test]
    fn a_moved_slice_and_string_share_their_block_with_the_payload() {
        // SAFETY: each pointer handed over points at a live value of its type, which outlives
        // the call, and each owned value is dropped once.
        unsafe {
            let mut slice = z_owned_slice_t::null_value();
            assert_eq!(
                z_slice_copy_from_buf(&mut slice, b"slice".as_ptr(), 5),
                Z_OK
            );
            let start = (*z_slice_loan(&slice))._start;
            let mut bytes = z_owned_bytes_t::null_value();
            assert_eq!(
                z_bytes_from_slice(&mut bytes, z_slice_move(&mut slice)),
                Z_OK
            );
            assert!(slice.handle.is_null(), "the slice is spent");
            let payload = bytes_ref(z_bytes_loan(&bytes)).expect("a payload");
            assert_eq!(payload.as_slice(), b"slice");
            assert_eq!(start_of(payload), start);
            z_bytes_drop(z_bytes_move(&mut bytes));

            let mut string = z_owned_string_t::null_value();
            assert_eq!(z_string_copy_from_str(&mut string, c"text".as_ptr()), Z_OK);
            let start = (*z_string_loan(&string))._start;
            assert_eq!(
                z_bytes_from_string(&mut bytes, z_string_move(&mut string)),
                Z_OK
            );
            assert!(string.handle.is_null(), "the string is spent");
            let payload = bytes_ref(z_bytes_loan(&bytes)).expect("a payload");
            assert_eq!(payload.as_slice(), b"text");
            assert_eq!(start_of(payload), start);
            z_bytes_drop(z_bytes_move(&mut bytes));
        }
    }

    /// A string moved into a payload shares its block without its terminator; an empty string is
    /// a C string with no block.
    #[test]
    fn a_string_shares_its_block_with_a_payload_without_its_terminator() {
        let state = StringState::boxed(b"text").expect("room");
        // SAFETY: the view is the state's own, over its block's written bytes.
        let terminated = unsafe { lent_bytes(state.self_view._start, 5) };
        assert_eq!(terminated, b"text\0");
        // SAFETY: the view is the state's own, over its block's written bytes.
        let payload = unsafe {
            payload_over(
                state.backing.as_ref(),
                state.filled,
                state.self_view._start,
                state.self_view._len,
            )
        }
        .expect("a share takes no room");
        assert_eq!(start_of(&payload), state.self_view._start);
        assert_eq!(payload.as_slice(), b"text");
        let empty = StringState::boxed(&[]).expect("no room is asked for");
        assert!(empty.backing.is_none());
        // SAFETY: an empty string's view points at a terminator.
        assert_eq!(unsafe { *empty.self_view._start }, 0);
    }

    /// With the process pools, a payload's bytes lie in their pools of payload blocks, not on the
    /// heap.
    #[cfg(wz_process_pools)]
    #[test]
    fn a_payloads_bytes_lie_in_the_process_pools() {
        let payload = ByteBuf::copy_of(b"pooled bytes").expect("room in the pools");
        let Some(block) = &payload.block else {
            panic!("a payload of bytes holds a block");
        };
        assert!(crate::process_pool::lies_in_payloads(
            block.head.cast::<u8>()
        ));
    }
}
