// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Byte storage an image declares and a link borrows: a table of `N` buffers of `SIZE` bytes in
//! a `static`, each lent out by a claim and given back when the claim is dropped.
//!
//! ## Why a link does not own its buffers
//!
//! A link's receive buffer and the buffer its frames are encoded into are each about a batch
//! long. Held by value inside the link's driver they make the driver a few KB, and a driver is a
//! value that is made, moved into a session's slot and moved again on the way: every move is a
//! copy on the stack the node is running on, so the stack the node needs grows with the buffers
//! it moves rather than with anything it computes. Here the buffers stay where the image put
//! them, in `.bss`, and the driver holds a [`ByteBuf`](crate::byte_cells::ByteBuf): a pointer, a length and a flag to clear,
//! a few words however large the batch is.
//!
//! A table need not be a `static`: one a session lays out in the memory it reserves when it opens
//! ([`LentByteCells`], lent by an [`Arena`](crate::bounded::Arena)) lends its buffers by the same
//! claim, so a link holds the same `ByteBuf` whichever table it took its buffers from.
//!
//! It is also where the size of a buffer is a decision of the image and not of the code that
//! uses it: the same driver serves a 512-byte batch and a 1400-byte one, because the length is a
//! property of the cell it was lent, not a parameter of its type.
//!
//! ## The contract
//!
//! As the session table's ([`crate::session_slot`]): the table is `Sync` by the profile's rule,
//! stated on the impl, that one cooperative task on one core drives everything that claims from
//! it; a claim and a release are plain loads and stores, not critical sections. A buffer's bytes
//! are NOT cleared when it is lent or returned: a user writes what it reads back, and a link
//! tracks the length of what it has put in.
//!
//! A table in memory a session reserved names the form of its flags ([`CellFlag`]): a cell
//! where one task claims and releases, as above, or an atomic where the last holder of what lies
//! in a cell may let it go on another thread than the one that claims, which a runtime of several
//! threads asks of the cells its shared handles are placed in.
//!
//! [`LentByteCells`]: crate::byte_cells::LentByteCells
//! [`CellFlag`]: crate::byte_cells::CellFlag

use core::cell::{Cell, UnsafeCell};
use core::ptr::NonNull;
#[cfg(target_has_atomic = "8")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use crate::bounded::ZeroEmpty;
use crate::runtime_cell::FlagCell;

/// The flag that says a cell of a [`LentByteCells`] table is lent, in the form the table's
/// holders need: `Cell<bool>` where one task claims and releases, `AtomicBool` where a release
/// may come from any thread while a claim is made, so a claim takes the flag in one step and a
/// release is ordered after every use of the bytes it gives back. Its all-zero byte is `false`
/// ([`ZeroEmpty`]), so a table lent from zeroed memory is free as the memory lies.
pub trait CellFlag: FlagCell + ZeroEmpty + 'static {
    /// Take the flag when it is free: `true` when this call took it, `false` when it was taken.
    fn take(&self) -> bool;
}

impl CellFlag for Cell<bool> {
    #[inline]
    fn take(&self) -> bool {
        if self.get() {
            return false;
        }
        self.set(true);
        true
    }
}

#[cfg(target_has_atomic = "8")]
impl CellFlag for AtomicBool {
    #[inline]
    fn take(&self) -> bool {
        self.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }
}

// An arena lays a table's flags out as bytes with no alignment of their own
// (`LentByteCells::FLAG_BYTES`), whichever form they take.
#[cfg(target_has_atomic = "8")]
const _: () = assert!(
    core::mem::size_of::<AtomicBool>() == core::mem::size_of::<Cell<bool>>()
        && core::mem::align_of::<AtomicBool>() == core::mem::align_of::<Cell<bool>>()
);

/// One cell of a table.
struct ByteCell<const SIZE: usize> {
    taken: Cell<bool>,
    bytes: UnsafeCell<[u8; SIZE]>,
}

/// A table of `N` buffers of `SIZE` bytes, to be a `static`:
///
/// ```text
/// static RX: ByteCells<1600, 2> = ByteCells::new();
/// let buf = RX.claim().expect("a free buffer");
/// ```
pub struct ByteCells<const SIZE: usize, const N: usize> {
    cells: [ByteCell<SIZE>; N],
}

// SAFETY: the profile's rule, stated in the module documentation: one cooperative task on one
// core claims and releases, and a lent buffer is reached only through the claim that holds it.
unsafe impl<const SIZE: usize, const N: usize> Sync for ByteCells<SIZE, N> {}

impl<const SIZE: usize, const N: usize> ByteCells<SIZE, N> {
    /// A table of free cells, for a `static`. Its bytes are zero, so it is placed in `.bss`.
    pub const fn new() -> Self {
        Self {
            cells: [const {
                ByteCell {
                    taken: Cell::new(false),
                    bytes: UnsafeCell::new([0; SIZE]),
                }
            }; N],
        }
    }

    /// How many buffers the table holds.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many buffers are lent.
    pub fn in_use(&self) -> usize {
        self.cells.iter().filter(|cell| cell.taken.get()).count()
    }
}

impl<const SIZE: usize, const N: usize> Default for ByteCells<SIZE, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A table of buffers of some length, whatever it is: what a link takes its buffers from without
/// naming how big they are or how many there are.
pub trait ByteSource {
    /// Lend a free buffer, or `None` when every one is out.
    fn claim(&'static self) -> Option<ByteBuf>;
}

impl<const SIZE: usize, const N: usize> ByteSource for ByteCells<SIZE, N> {
    fn claim(&'static self) -> Option<ByteBuf> {
        let cell = self.cells.iter().find(|cell| !cell.taken.get())?;
        cell.taken.set(true);
        Some(ByteBuf {
            taken: NonNull::from(&cell.taken),
            base: cell.bytes.get().cast::<u8>(),
            len: SIZE,
        })
    }
}

/// A table of `count` buffers of `size` bytes in memory a session reserved when it opened, each
/// lent by a claim as a [`ByteCells`] cell is: its flags and its bytes are two spans of the
/// session's arena ([`Arena::lend_byte_cells`](crate::bounded::Arena::lend_byte_cells)), so its
/// size is the session's limits' and not a constant of the image.
///
/// A handle: a copy names the same table, which is how the stack that opens a session's links
/// holds it while the arena that owns the memory stays with the session. The memory outlives every
/// claim and every copy (the contract of `LentByteCells::over`), and the table keeps the
/// profile's rule of [`ByteCells`] by its flags' form `F` ([`CellFlag`]): with cells, one task
/// claims and releases, so a claim is a plain load and store; with atomics, a buffer may be given
/// back on any thread.
#[derive(Debug)]
pub struct LentByteCells<F: CellFlag = Cell<bool>> {
    taken: NonNull<F>,
    bytes: NonNull<u8>,
    size: usize,
    count: usize,
}

impl<F: CellFlag> Clone for LentByteCells<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: CellFlag> Copy for LentByteCells<F> {}

// SAFETY: a table of atomic flags is claimed by a read-modify-write of a flag and given back by an
// ordered store of it, so threads that claim and release through copies of the handle keep one
// account of which cell is lent; a cell's bytes are reached only through the one claim that took
// it, and the memory outlives every copy and every claim (`Self::over`).
#[cfg(target_has_atomic = "8")]
unsafe impl Send for LentByteCells<AtomicBool> {}
// SAFETY: as `Send` above; a shared handle claims and reads flags only.
#[cfg(target_has_atomic = "8")]
unsafe impl Sync for LentByteCells<AtomicBool> {}

impl LentByteCells {
    /// The bytes of the flag that says a cell is lent: an arena lays `count` of them out in front
    /// of the cells' bytes. The same for every form of the flag (asserted beside [`CellFlag`]).
    pub const FLAG_BYTES: usize = core::mem::size_of::<Cell<bool>>();
}

impl<F: CellFlag> LentByteCells<F> {
    /// The table whose `count` flags are at `taken` and whose `count` cells of `size` bytes each
    /// are at `bytes`, one after the other.
    ///
    /// # Safety
    /// `taken` points at `count` flags, each `false`, and `bytes` at `count * size` initialised
    /// bytes; both are valid for reads and writes, used by nothing but this table, and stay so for
    /// as long as any copy of the table or any buffer it lends lives.
    pub(crate) const unsafe fn over(
        taken: NonNull<F>,
        bytes: NonNull<u8>,
        size: usize,
        count: usize,
    ) -> Self {
        Self {
            taken,
            bytes,
            size,
            count,
        }
    }

    /// The flag of cell `at`, below the table's count.
    fn flag(&self, at: usize) -> &F {
        // SAFETY: `at` is below `count`, so the flag is one of the table's, alive for as long as
        // the table is (`Self::over`).
        unsafe { &*self.taken.as_ptr().add(at) }
    }

    /// Lend a free buffer, or `None` when every one is out.
    pub fn claim(&self) -> Option<ByteBuf<F>> {
        let at = (0..self.count).find(|&at| self.flag(at).take())?;
        // SAFETY: `at` is below `count`, so the flag and the cell's bytes are inside the table's
        // spans (`Self::over`).
        let (taken, base) = unsafe {
            (
                NonNull::new_unchecked(self.taken.as_ptr().add(at)),
                // `at` is below the count, so the cell's offset is inside the table.
                self.bytes.as_ptr().add(at.wrapping_mul(self.size)),
            )
        };
        Some(ByteBuf {
            taken,
            base,
            len: self.size,
        })
    }

    /// The length of every buffer.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// How many buffers the table holds.
    pub const fn capacity(&self) -> usize {
        self.count
    }

    /// How many buffers are lent.
    pub fn in_use(&self) -> usize {
        (0..self.count)
            .filter(|&at| self.flag(at).load(Ordering::Relaxed))
            .count()
    }

    /// Take back the buffer that starts at `base`, whose claim its holder kept past the claim's
    /// own life (`core::mem::forget`) and now lets go, as dropping the claim would have: `false`,
    /// changing nothing, when no cell of the table starts at `base` or that cell is not lent.
    ///
    /// # Safety
    /// Nothing uses the buffer's bytes from here: its holder gave them up with this call.
    pub unsafe fn release_at(&self, base: NonNull<u8>) -> bool {
        let Some(offset) = (base.as_ptr() as usize).checked_sub(self.bytes.as_ptr() as usize)
        else {
            return false;
        };
        let Some(at) = offset.checked_div(self.size) else {
            return false;
        };
        if at >= self.count
            || at.checked_mul(self.size) != Some(offset)
            || !self.flag(at).load(Ordering::Acquire)
        {
            return false;
        }
        self.flag(at).store(false, Ordering::Release);
        true
    }
}

/// The count of a [`HeapByteCells`] table: its buffers lent and the holders of the count, in an
/// allocation of its own.
#[cfg(feature = "alloc")]
struct HeapCells {
    /// The handles of the table and the buffers it lent: the last of them gives the allocation
    /// back.
    holders: Cell<usize>,
    /// How many buffers are lent.
    lent: Cell<usize>,
    /// The length of every buffer.
    size: usize,
    /// The most buffers lent at once.
    count: usize,
}

/// A table of `count` buffers of `size` bytes whose memory the allocator gives: each buffer taken
/// when it is claimed and given back when its claim drops, as a [`LentByteCells`] cell is lent and
/// given back, so a claim is refused where a lent table of the same count refuses it, with every
/// buffer out, whatever memory the buffers lie in; and where the allocator refuses the buffer. A
/// table that lends nothing holds no buffer.
///
/// A handle: a clone names the same table. The count lies in an allocation of its own, taken when
/// the table is made, which every handle and every buffer the table lent holds, so a buffer may
/// outlive the handle it was claimed through and the count stands until the last of them lets go.
/// Neither `Send` nor `Sync`: as a lent table of cells, one task claims and releases.
#[cfg(feature = "alloc")]
pub struct HeapByteCells {
    at: NonNull<HeapCells>,
}

#[cfg(feature = "alloc")]
impl HeapByteCells {
    /// The bytes the table's count takes of the allocator when the table is made.
    pub const COUNT_BYTES: usize = core::mem::size_of::<HeapCells>();

    /// A table of `count` buffers of `size` bytes, none lent; `None` where the allocator refuses
    /// the table's count.
    pub fn try_new(size: usize, count: usize) -> Option<Self> {
        let layout = core::alloc::Layout::new::<HeapCells>();
        // SAFETY: the layout's size is not zero: the count holds two cells and two words.
        let at = NonNull::new(unsafe { alloc::alloc::alloc(layout) }.cast::<HeapCells>())?;
        // SAFETY: `at` was allocated for one `HeapCells`, written once here before any handle
        // reads it.
        unsafe {
            at.as_ptr().write(HeapCells {
                holders: Cell::new(1),
                lent: Cell::new(0),
                size,
                count,
            });
        }
        Some(Self { at })
    }

    /// The table's count.
    fn cells(&self) -> &HeapCells {
        // SAFETY: this handle holds the count, so its allocation stands.
        unsafe { self.at.as_ref() }
    }

    /// Lend a buffer of room for the table's length, none of it written; `None` when every buffer
    /// is out or the allocator refuses the room.
    pub fn claim(&self) -> Option<OwnBuf> {
        let cells = self.cells();
        if cells.lent.get() >= cells.count {
            return None;
        }
        let mut bytes = alloc::vec::Vec::new();
        bytes.try_reserve_exact(cells.size).ok()?;
        // Below the count.
        cells.lent.set(cells.lent.get().saturating_add(1));
        Some(OwnBuf {
            bytes,
            table: self.clone(),
        })
    }

    /// The length of every buffer.
    pub fn size(&self) -> usize {
        self.cells().size
    }

    /// How many buffers the table lends at once.
    pub fn capacity(&self) -> usize {
        self.cells().count
    }

    /// How many buffers are lent.
    pub fn in_use(&self) -> usize {
        self.cells().lent.get()
    }
}

#[cfg(feature = "alloc")]
impl Clone for HeapByteCells {
    fn clone(&self) -> Self {
        let holders = &self.cells().holders;
        holders.set(holders.get().saturating_add(1));
        Self { at: self.at }
    }
}

#[cfg(feature = "alloc")]
impl Drop for HeapByteCells {
    fn drop(&mut self) {
        let holders = &self.cells().holders;
        let left = holders.get().saturating_sub(1);
        holders.set(left);
        if left == 0 {
            // SAFETY: no holder is left, so nothing reads the count again: it was allocated by
            // `Self::try_new` for its layout and is given back once, here.
            unsafe {
                core::ptr::drop_in_place(self.at.as_ptr());
                alloc::alloc::dealloc(
                    self.at.as_ptr().cast::<u8>(),
                    core::alloc::Layout::new::<HeapCells>(),
                );
            }
        }
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for HeapByteCells {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeapByteCells")
            .field("size", &self.size())
            .field("count", &self.capacity())
            .field("lent", &self.in_use())
            .finish()
    }
}

/// A buffer a [`HeapByteCells`] table lent, until it is dropped: what was written in it, in room
/// for the table's length taken when it was claimed, and the count of its table it is out of,
/// given back when it drops, its memory to the allocator with it. Not `Send`, as its table is not.
#[cfg(feature = "alloc")]
pub struct OwnBuf {
    bytes: alloc::vec::Vec<u8>,
    table: HeapByteCells,
}

#[cfg(feature = "alloc")]
impl OwnBuf {
    /// What was written in the buffer.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// What was written in the buffer, to write more in the room it was claimed with: a chain's
    /// staging writes its fragments through it.
    #[cfg(any(test, feature = "reassembly"))]
    pub(crate) fn written(&mut self) -> &mut alloc::vec::Vec<u8> {
        &mut self.bytes
    }
}

#[cfg(feature = "alloc")]
impl Drop for OwnBuf {
    fn drop(&mut self) {
        let lent = &self.table.cells().lent;
        lent.set(lent.get().saturating_sub(1));
    }
}

/// A buffer lent by a [`ByteCells`] table or a [`LentByteCells`] one, until it is dropped. Of a
/// table of cells it is not `Send`: it belongs to the task that claimed it. Of a table of atomic
/// flags it may be given back on another thread.
pub struct ByteBuf<F: CellFlag = Cell<bool>> {
    /// The flag of the cell it was lent, which the table's memory holds for longer than the claim.
    taken: NonNull<F>,
    base: *mut u8,
    len: usize,
}

// SAFETY: the bytes are reached only through this claim, which moves with them, and the flag is
// given back by an ordered store that the table's claims read atomically, so the thread that drops
// the claim need not be the one that took it.
#[cfg(target_has_atomic = "8")]
unsafe impl Send for ByteBuf<AtomicBool> {}

impl<F: CellFlag> ByteBuf<F> {
    /// The buffer's bytes, mutably. The claim is the only way to them, so there is no other
    /// reference to alias.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `base` and `len` are a cell of a table whose memory outlives the claim, lent to
        // this claim alone until it drops, and `&mut self` makes this the only borrow of them.
        unsafe { core::slice::from_raw_parts_mut(self.base, self.len) }
    }

    /// The buffer's bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: as `as_mut_slice`; `&self` lets the caller hold only shared borrows of them.
        unsafe { core::slice::from_raw_parts(self.base, self.len) }
    }

    /// The buffer's first byte and its length, for a user that hands the memory on (a frame
    /// encoded in place). Valid for as long as the claim is.
    pub fn raw(&self) -> (*mut u8, usize) {
        (self.base, self.len)
    }
}

impl<F: CellFlag> AsMut<[u8]> for ByteBuf<F> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<F: CellFlag> Drop for ByteBuf<F> {
    fn drop(&mut self) {
        // SAFETY: the flag is the claimed cell's, in a table whose memory outlives every claim (a
        // `'static` table, or a lent one by the contract of `LentByteCells::over`).
        unsafe { self.taken.as_ref() }.store(false, Ordering::Release);
    }
}

/// Bytes kept past the call that wrote them, where they were written: the first bytes of a buffer
/// a table lent, whose cell is lent to no other claim until this drops, or a buffer a table of the
/// allocator's buffers lent, out of its table's count until this drops and given back to the
/// allocator then. What reads
/// those bytes where they lie may do so for as long as it holds this. A completed reassembly chain
/// is handed up as one when its staging can give its buffer away (`ChainStaging::keep`). Not
/// `Send`, as the claim it may hold is not.
pub struct KeptBytes {
    held: Held,
}

/// What keeps the bytes of a [`KeptBytes`] where they lie.
enum Held {
    /// The first `len` bytes of a table's cell.
    Cell { buf: ByteBuf, len: usize },
    /// A buffer of the allocator a table lent, as long as what it keeps.
    #[cfg(feature = "alloc")]
    Own(OwnBuf),
}

impl KeptBytes {
    /// The first `len` bytes of `buf`, at most the whole buffer.
    pub fn of(buf: ByteBuf, len: usize) -> Self {
        let len = len.min(buf.len);
        Self {
            held: Held::Cell { buf, len },
        }
    }

    /// The bytes of `bytes`, kept where they lie: the buffer moves in, not its bytes, and stays
    /// out of its table until this drops.
    #[cfg(feature = "alloc")]
    pub fn own(bytes: OwnBuf) -> Self {
        Self {
            held: Held::Own(bytes),
        }
    }

    /// The bytes kept.
    pub fn as_slice(&self) -> &[u8] {
        match &self.held {
            Held::Cell { buf, len } => buf.as_slice().get(..*len).unwrap_or_default(),
            #[cfg(feature = "alloc")]
            Held::Own(bytes) => bytes.as_slice(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_is_lent_until_it_drops_and_the_table_refuses_past_its_cells() {
        static CELLS: ByteCells<8, 2> = ByteCells::new();
        let mut a = CELLS.claim().expect("first");
        let b = CELLS.claim().expect("second");
        assert_eq!(CELLS.in_use(), 2);
        assert!(CELLS.claim().is_none(), "a third claim is refused");
        a.as_mut_slice()[0] = 7;
        assert_eq!(a.raw().1, 8);
        drop(b);
        assert_eq!(CELLS.in_use(), 1);
        let mut again = CELLS.claim().expect("the freed cell");
        assert_eq!(again.as_mut_slice().len(), 8);
        drop(a);
        drop(again);
        assert_eq!(CELLS.in_use(), 0);
    }

    /// A table in memory a session reserved lends its cells as a `static` one does: each to one
    /// claim until the claim drops, none past its count, through any copy of the handle, and the
    /// bytes of one claim are never another's.
    #[test]
    fn a_lent_table_lends_each_cell_to_one_claim_until_it_drops() {
        let flags = [Cell::new(false), Cell::new(false)];
        let mut bytes = [0u8; 8];
        // SAFETY: two flags, each false, and two cells of four bytes, all in this frame, which
        // outlives the table and every claim of it.
        let table = unsafe {
            LentByteCells::over(
                NonNull::from(&flags).cast::<Cell<bool>>(),
                NonNull::from(&mut bytes).cast::<u8>(),
                4,
                2,
            )
        };
        assert_eq!((table.size(), table.capacity(), table.in_use()), (4, 2, 0));
        let mut a = table.claim().expect("first");
        let mut b = table.claim().expect("second");
        assert_eq!(table.in_use(), 2);
        assert!(table.claim().is_none(), "a third claim is refused");
        a.as_mut_slice().fill(1);
        b.as_mut_slice().fill(2);
        assert_eq!(a.raw().1, 4);
        assert!(a.as_mut_slice().iter().all(|&x| x == 1));
        drop(b);
        assert_eq!(table.in_use(), 1);
        let copy = table;
        let again = copy
            .claim()
            .expect("the freed cell, through a copy of the handle");
        assert_eq!(table.in_use(), 2, "the copy names the same table");
        drop(again);
        drop(a);
        assert_eq!(table.in_use(), 0);
    }

    /// Kept bytes are the first bytes of their claim, read where the claim lies, at most the whole
    /// buffer, and the cell is lent to no other claim until they drop. Turned red by a keep that
    /// copies the bytes out or lets the cell go while they are held.
    #[test]
    fn kept_bytes_hold_their_cell_until_they_drop() {
        static CELLS: ByteCells<4, 1> = ByteCells::new();
        let mut buf = CELLS.claim().expect("the cell");
        buf.as_mut_slice().copy_from_slice(&[1, 2, 3, 4]);
        let base = buf.raw().0.cast_const();
        let kept = KeptBytes::of(buf, 3);
        assert_eq!(kept.as_slice(), &[1, 2, 3]);
        assert_eq!(kept.as_slice().as_ptr(), base, "read where the claim lies");
        assert!(
            CELLS.claim().is_none(),
            "the cell is lent to no other claim"
        );
        drop(kept);
        let whole = KeptBytes::of(CELLS.claim().expect("the cell, given back"), 9);
        assert_eq!(whole.as_slice(), &[1, 2, 3, 4], "at most the whole buffer");
    }

    /// Kept bytes of a buffer of the allocator are what was written in it, read where the buffer
    /// lies, and the buffer stays out of its table until they drop. Turned red by a keep that
    /// copies them, or one that gives the buffer back to its table while they are held.
    #[cfg(feature = "alloc")]
    #[test]
    fn kept_bytes_of_an_own_buffer_are_read_where_it_lies() {
        let table = HeapByteCells::try_new(8, 1).expect("the allocator has the count");
        let mut buf = table.claim().expect("the table's one buffer");
        buf.written().extend_from_slice(&[5, 6, 7]);
        let base = buf.as_slice().as_ptr();
        let kept = KeptBytes::own(buf);
        assert_eq!(kept.as_slice(), &[5, 6, 7]);
        assert_eq!(kept.as_slice().as_ptr(), base, "read where the buffer lies");
        assert_eq!(table.in_use(), 1, "kept, the buffer is out of its table");
        drop(kept);
        assert_eq!(table.in_use(), 0, "let go of, it is the table's again");
    }

    /// A table of the allocator's buffers lends as a lent table does: a buffer of room for its
    /// length to each claim, none past its count while its buffers are out, a buffer given back by
    /// its claim's drop, through any clone of the handle; and a buffer outlives the handle it was
    /// claimed through. The CONTROL is the lent table of the same count, which refuses the same
    /// claim. Turned red by a claim past the count (`HeapByteCells::claim`), a buffer whose drop
    /// gives nothing back (`OwnBuf`'s drop), or a count let go of while a buffer holds it.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_heap_table_lends_as_many_buffers_as_a_lent_table_of_its_count() {
        let flags = [Cell::new(false), Cell::new(false)];
        let mut bytes = [0u8; 8];
        // SAFETY: two flags, each false, and two cells of four bytes, all in this frame, which
        // outlives the table and every claim of it.
        let lent = unsafe {
            LentByteCells::over(
                NonNull::from(&flags).cast::<Cell<bool>>(),
                NonNull::from(&mut bytes).cast::<u8>(),
                4,
                2,
            )
        };
        let table = HeapByteCells::try_new(4, 2).expect("the allocator has the count");
        assert_eq!((table.size(), table.capacity(), table.in_use()), (4, 2, 0));
        let (_lent_a, _lent_b) = (lent.claim().expect("first"), lent.claim().expect("second"));
        assert!(
            lent.claim().is_none(),
            "CONTROL: the lent table refuses a third"
        );
        let a = table.claim().expect("first");
        assert!(a.as_slice().is_empty(), "nothing written yet");
        let copy = table.clone();
        let b = copy.claim().expect("second, through a clone of the handle");
        assert_eq!(table.in_use(), 2, "the clone names the same table");
        assert!(table.claim().is_none(), "a third claim is refused");
        drop(a);
        assert_eq!(table.in_use(), 1, "a dropped claim is the table's again");
        drop(copy);
        drop(table);
        assert!(b.as_slice().is_empty(), "the buffer outlives every handle");
        drop(b);
    }

    /// A claim kept past its own life is taken back by the address it starts at, once, and an
    /// address no cell starts at, or a cell not lent, is refused and changes nothing. Turned red
    /// by a release that frees the cell an address merely falls inside.
    #[test]
    fn a_kept_claim_is_taken_back_by_where_it_starts() {
        let flags = [Cell::new(false), Cell::new(false)];
        let mut bytes = [0u8; 8];
        // SAFETY: as in the test above.
        let table = unsafe {
            LentByteCells::over(
                NonNull::from(&flags).cast::<Cell<bool>>(),
                NonNull::from(&mut bytes).cast::<u8>(),
                4,
                2,
            )
        };
        let first = table.claim().expect("first");
        let second = table.claim().expect("second");
        let (base, _) = second.raw();
        core::mem::forget(second);
        let base = NonNull::new(base).expect("a cell's address");
        // SAFETY: the kept claim is given up here and nothing uses its bytes after.
        unsafe {
            let inside = NonNull::new(base.as_ptr().add(1)).expect("an address");
            assert!(!table.release_at(inside), "no cell starts there");
            assert_eq!(table.in_use(), 2);
            assert!(table.release_at(base));
            assert_eq!(table.in_use(), 1);
            assert!(!table.release_at(base), "a cell not lent is refused");
        }
        drop(first);
        assert_eq!(table.in_use(), 0);
    }

    /// A table of atomic flags lends each cell to one claim, and a claim dropped on another thread
    /// gives its cell back to the table's next claim. Turned red by a claim that does not take
    /// the flag (a second claim of the same cell) or a drop that does not clear it.
    #[cfg(target_has_atomic = "8")]
    #[test]
    fn an_atomic_table_takes_back_a_cell_given_back_on_another_thread() {
        let flags = [AtomicBool::new(false), AtomicBool::new(false)];
        let mut bytes = [0u8; 8];
        // SAFETY: two flags, each false, and two cells of four bytes, all in this frame, which
        // outlives the table, every claim of it and the scope's threads.
        let table = unsafe {
            LentByteCells::over(
                NonNull::from(&flags).cast::<AtomicBool>(),
                NonNull::from(&mut bytes).cast::<u8>(),
                4,
                2,
            )
        };
        let a = table.claim().expect("first");
        let b = table.claim().expect("second");
        assert_ne!(a.raw().0, b.raw().0, "two claims, two cells");
        assert!(table.claim().is_none(), "a third claim is refused");
        std::thread::scope(|scope| {
            scope.spawn(move || drop(b));
        });
        assert_eq!(table.in_use(), 1);
        let again = table
            .claim()
            .expect("the cell given back on the other thread");
        assert_eq!(table.in_use(), 2);
        drop(again);
        drop(a);
        assert_eq!(table.in_use(), 0);
    }

    #[test]
    fn two_claims_never_share_bytes() {
        static CELLS: ByteCells<4, 2> = ByteCells::new();
        let mut a = CELLS.claim().unwrap();
        let mut b = CELLS.claim().unwrap();
        a.as_mut_slice().fill(1);
        b.as_mut_slice().fill(2);
        assert!(a.as_mut_slice().iter().all(|&x| x == 1));
        assert!(b.as_mut_slice().iter().all(|&x| x == 2));
    }
}
