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

use core::cell::{Cell, UnsafeCell};
use core::ptr::NonNull;

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
/// profile's rule of [`ByteCells`]: one task claims and releases, so a claim is a plain load and
/// store.
#[derive(Clone, Copy, Debug)]
pub struct LentByteCells {
    taken: NonNull<Cell<bool>>,
    bytes: NonNull<u8>,
    size: usize,
    count: usize,
}

impl LentByteCells {
    /// The bytes of the flag that says a cell is lent: an arena lays `count` of them out in front
    /// of the cells' bytes.
    pub const FLAG_BYTES: usize = core::mem::size_of::<Cell<bool>>();

    /// The table whose `count` flags are at `taken` and whose `count` cells of `size` bytes each
    /// are at `bytes`, one after the other.
    ///
    /// # Safety
    /// `taken` points at `count` flags, each `false`, and `bytes` at `count * size` initialised
    /// bytes; both are valid for reads and writes, used by nothing but this table, and stay so for
    /// as long as any copy of the table or any buffer it lends lives.
    pub(crate) const unsafe fn over(
        taken: NonNull<Cell<bool>>,
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
    fn flag(&self, at: usize) -> &Cell<bool> {
        // SAFETY: `at` is below `count`, so the flag is one of the table's, alive for as long as
        // the table is (`Self::over`).
        unsafe { &*self.taken.as_ptr().add(at) }
    }

    /// Lend a free buffer, or `None` when every one is out.
    pub fn claim(&self) -> Option<ByteBuf> {
        let at = (0..self.count).find(|&at| !self.flag(at).get())?;
        self.flag(at).set(true);
        // SAFETY: `at` is below `count`, so the flag and the cell's bytes are inside the table's
        // spans (`Self::over`).
        let (taken, base) = unsafe {
            (
                NonNull::new_unchecked(self.taken.as_ptr().add(at)),
                // `at` is below the count, so the cell's offset is inside the table.
                self.bytes.as_ptr().add(at.saturating_mul(self.size)),
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
        (0..self.count).filter(|&at| self.flag(at).get()).count()
    }
}

/// A buffer lent by a [`ByteCells`] table or a [`LentByteCells`] one, until it is dropped. Not
/// `Send`: it belongs to the task that claimed it.
pub struct ByteBuf {
    /// The flag of the cell it was lent, which the table's memory holds for longer than the claim.
    taken: NonNull<Cell<bool>>,
    base: *mut u8,
    len: usize,
}

impl ByteBuf {
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

impl AsMut<[u8]> for ByteBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for ByteBuf {
    fn drop(&mut self) {
        // SAFETY: the flag is the claimed cell's, in a table whose memory outlives every claim (a
        // `'static` table, or a lent one by the contract of `LentByteCells::over`).
        unsafe { self.taken.as_ref() }.set(false);
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
