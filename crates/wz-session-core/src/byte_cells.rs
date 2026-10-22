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
            taken: &cell.taken,
            base: cell.bytes.get().cast::<u8>(),
            len: SIZE,
        })
    }
}

/// A buffer lent by a [`ByteCells`] table, until it is dropped. Not `Send`: it belongs to the
/// task that claimed it.
pub struct ByteBuf {
    taken: &'static Cell<bool>,
    base: *mut u8,
    len: usize,
}

impl ByteBuf {
    /// The buffer's bytes, mutably. The claim is the only way to them, so there is no other
    /// reference to alias.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `base` and `len` are a cell of a `'static` table, lent to this claim alone
        // until it drops, and `&mut self` makes this the only borrow of them.
        unsafe { core::slice::from_raw_parts_mut(self.base, self.len) }
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
        self.taken.set(false);
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
