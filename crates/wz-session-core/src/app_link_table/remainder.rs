// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A link's remainder: the bytes a writer that cannot wait handed over and the program has not
//! taken, in a ring over storage taken with the link's row, whose front run is lent to the one
//! writer that offers it to the program.
//!
//! The program is called with no lock of the transport held, so the bytes it is offered are read
//! outside the table's lock, in place: the run is lent ([`Remainder::lend`]) and, until it is
//! given back ([`Remainder::give_back`]), no byte of it is written, its storage is not freed and
//! no other writer is lent it. Appends go on around it, into the ring's free part, which never
//! overlaps the bytes held. A remainder of no bound that must grow while its front is lent moves
//! to new storage and keeps the old until the run comes back, so the lent run stays where it was.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ptr::NonNull;

/// Storage of bytes that may be read outside the table's lock while the table writes other bytes
/// of it: each byte a cell of its own, the allocation owned through a pointer rather than a `Box`
/// so that a write through the table never asserts it is the only one reaching the storage.
struct Cells {
    base: NonNull<UnsafeCell<u8>>,
    len: usize,
}

// SAFETY: `Cells` owns its allocation as a `Box<[UnsafeCell<u8>]>` does. It is reached only
// through the table, under the table's lock, except for a lent run, which no one writes while it
// is lent (the module's contract), so moving it to another thread with the table is sound.
unsafe impl Send for Cells {}

impl Cells {
    fn new(len: usize) -> Self {
        let cells: Box<[UnsafeCell<u8>]> = (0..len).map(|_| UnsafeCell::new(0)).collect();
        let len = cells.len();
        let base = NonNull::new(Box::into_raw(cells).cast::<UnsafeCell<u8>>())
            .unwrap_or(NonNull::dangling());
        Self { base, len }
    }

    /// The cell at `at`, inside the storage.
    fn cell(&self, at: usize) -> Option<&UnsafeCell<u8>> {
        if at >= self.len {
            return None;
        }
        // SAFETY: `at` is below the length, so the cell is inside the allocation, which lives as
        // long as `self`.
        Some(unsafe { &*self.base.as_ptr().add(at) })
    }

    fn write(&self, at: usize, byte: u8) {
        if let Some(cell) = self.cell(at) {
            // SAFETY: the table writes a cell only under its lock and never a cell of a lent run,
            // so nothing reads or writes this one at the same time.
            unsafe { *cell.get() = byte };
        }
    }

    fn read(&self, at: usize) -> u8 {
        let Some(cell) = self.cell(at) else {
            return 0;
        };
        // SAFETY: as for `Self::write`: a cell the table reads is not being written.
        unsafe { *cell.get() }
    }

    /// The address of the run of `len` bytes from `at`, inside the storage.
    fn run(&self, at: usize, len: usize) -> Option<NonNull<u8>> {
        if at.checked_add(len)? > self.len {
            return None;
        }
        // `UnsafeCell<u8>` has the layout of `u8`.
        self.cell(at).map(|cell| NonNull::from(cell).cast::<u8>())
    }
}

impl Drop for Cells {
    fn drop(&mut self) {
        // SAFETY: `base` and `len` are the parts of the `Box` `Self::new` let go of, and only
        // this drop gives them back.
        drop(unsafe {
            Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                self.base.as_ptr(),
                self.len,
            ))
        });
    }
}

/// The bytes held for the program, oldest first, from `head`, `len` of them, wrapping at the
/// storage's end.
pub(super) struct Remainder {
    cells: Cells,
    head: usize,
    len: usize,
    /// The length of the front run lent to a writer, while one is.
    lent: Option<usize>,
    /// The storage a remainder of no bound left while its front was lent, kept until the run
    /// comes back. A fixed build (`bounded-heapless`) never grows a remainder.
    #[cfg(not(feature = "bounded-heapless"))]
    retired: Option<Cells>,
}

impl Remainder {
    /// A remainder of `capacity` bytes of storage, empty.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            cells: Cells::new(capacity),
            head: 0,
            len: 0,
            lent: None,
            #[cfg(not(feature = "bounded-heapless"))]
            retired: None,
        }
    }

    pub(super) fn capacity(&self) -> usize {
        self.cells.len
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether a front run is lent: the row is not to be freed or reused until it comes back.
    pub(super) fn is_lent(&self) -> bool {
        self.lent.is_some()
    }

    /// Hold nothing, for a new link of the row. A row is reused only when its run is not lent.
    pub(super) fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Where the byte `offset` bytes past the head is.
    fn at(&self, offset: usize) -> usize {
        self.head
            .checked_add(offset)
            .and_then(|at| at.checked_rem(self.cells.len))
            .unwrap_or(0)
    }

    /// Hold `bytes` behind what is held: `false`, with nothing held, when the storage has no room
    /// for them and `grow` is not set. A remainder that may grow moves to storage that holds them,
    /// except on a fixed build (`bounded-heapless`), whose storage is what the row took when the
    /// session opened, and which allocates nothing after.
    pub(super) fn push(&mut self, bytes: &[u8], grow: bool) -> bool {
        let Some(need) = self.len.checked_add(bytes.len()) else {
            return false;
        };
        if need > self.cells.len {
            #[cfg(not(feature = "bounded-heapless"))]
            if grow {
                self.grow_to(need.max(self.cells.len.saturating_mul(2)));
            } else {
                return false;
            }
            #[cfg(feature = "bounded-heapless")]
            {
                let _ = grow;
                return false;
            }
        }
        for (offset, &byte) in bytes.iter().enumerate() {
            self.cells
                .write(self.at(self.len.saturating_add(offset)), byte);
        }
        self.len = need;
        true
    }

    /// Move what is held to new storage of `capacity` bytes, from its start. The old storage is
    /// kept while a run of it is lent.
    #[cfg(not(feature = "bounded-heapless"))]
    fn grow_to(&mut self, capacity: usize) {
        let cells = Cells::new(capacity);
        for offset in 0..self.len {
            cells.write(offset, self.cells.read(self.at(offset)));
        }
        let old = core::mem::replace(&mut self.cells, cells);
        self.head = 0;
        if self.lent.is_some() && self.retired.is_none() {
            self.retired = Some(old);
        }
    }

    /// Lend the front run of what is held, as far as the storage's end: its address and length.
    /// `None` when nothing is held or a run is lent already: one writer offers the remainder at a
    /// time.
    pub(super) fn lend(&mut self) -> Option<(NonNull<u8>, usize)> {
        if self.lent.is_some() || self.len == 0 {
            return None;
        }
        let run = self.len.min(self.cells.len.saturating_sub(self.head));
        let base = self.cells.run(self.head, run)?;
        self.lent = Some(run);
        Some((base, run))
    }

    /// The lent run comes back, `taken` bytes of it taken by the program: they leave the front.
    /// How many left it; 0 when no run was lent.
    pub(super) fn give_back(&mut self, taken: usize) -> usize {
        let Some(run) = self.lent.take() else {
            return 0;
        };
        #[cfg(not(feature = "bounded-heapless"))]
        {
            self.retired = None;
        }
        let taken = taken.min(run).min(self.len);
        self.head = self.at(taken);
        self.len = self.len.saturating_sub(taken);
        if self.len == 0 {
            self.head = 0;
        }
        taken
    }

    /// The bytes held, in order: what a test reads.
    #[cfg(test)]
    pub(super) fn to_vec(&self) -> alloc::vec::Vec<u8> {
        (0..self.len)
            .map(|offset| self.cells.read(self.at(offset)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lent_bytes(remainder: &mut Remainder) -> alloc::vec::Vec<u8> {
        let (base, len) = remainder.lend().expect("a run");
        // SAFETY: the run is lent and nothing writes it before it is given back below.
        unsafe { core::slice::from_raw_parts(base.as_ptr(), len) }.to_vec()
    }

    /// A remainder holds what is pushed in order, lends its front run up to the storage's end,
    /// lends it to one writer at a time, and drops what the program took when it comes back. Turned
    /// red by a ring that lends past its end, or lends twice.
    #[test]
    fn a_remainder_lends_its_front_run_to_one_writer_at_a_time() {
        let mut remainder = Remainder::with_capacity(8);
        assert!(remainder.lend().is_none(), "nothing held, nothing lent");
        assert!(remainder.push(b"abcdef", false));
        assert_eq!(lent_bytes(&mut remainder), b"abcdef");
        assert!(remainder.lend().is_none(), "one writer at a time");
        assert_eq!(remainder.give_back(4), 4);
        assert_eq!(remainder.to_vec(), b"ef");
        // Wraps: two at the end, then four at the front.
        assert!(remainder.push(b"ghijkl", false));
        assert_eq!(remainder.to_vec(), b"efghijkl");
        assert!(
            !remainder.push(b"m", false),
            "full, and no bound to grow by"
        );
        assert_eq!(
            lent_bytes(&mut remainder),
            b"efgh",
            "the run ends at the storage's end"
        );
        assert_eq!(remainder.give_back(4), 4);
        assert_eq!(lent_bytes(&mut remainder), b"ijkl");
        assert_eq!(remainder.give_back(9), 4, "no more than the run is taken");
        assert!(remainder.is_empty());
    }

    /// Pushes while the front is lent fill the ring's free part exactly, around the lent run, and
    /// leave it as it was; one past the free part is refused with nothing held. Turned red by a
    /// push that writes into the lent run, or counts it as free.
    #[test]
    fn pushes_while_the_front_is_lent_fill_only_the_free_part() {
        let mut remainder = Remainder::with_capacity(8);
        assert!(remainder.push(b"xxab", false));
        assert_eq!(remainder.give_back(3), 0, "nothing lent, nothing taken");
        assert_eq!(remainder.to_vec(), b"xxab");
        let (base, len) = remainder.lend().expect("a run");
        assert_eq!(len, 4);
        assert!(remainder.push(b"cdef", false), "the free part");
        assert!(!remainder.push(b"g", false), "no free byte left");
        // SAFETY: the run is lent; nothing writes it before it is given back below.
        let read = unsafe { core::slice::from_raw_parts(base.as_ptr(), len) };
        assert_eq!(read, b"xxab");
        assert_eq!(remainder.give_back(2), 2);
        assert_eq!(remainder.to_vec(), b"abcdef");
        assert!(remainder.push(b"gh", false), "what was taken is free again");
        assert_eq!(remainder.to_vec(), b"abcdefgh");
    }

    /// Bytes pushed while the front is lent go around the lent run and leave it as it was; a
    /// remainder of no bound that grows while its front is lent, twice, keeps the lent run readable
    /// where it was. Turned red by a push that writes over a lent run, or a grow that frees it.
    #[cfg(not(feature = "bounded-heapless"))]
    #[test]
    fn a_push_while_the_front_is_lent_leaves_the_lent_run_as_it_was() {
        let mut remainder = Remainder::with_capacity(4);
        assert!(remainder.push(b"ab", true));
        let (base, len) = remainder.lend().expect("a run");
        assert!(remainder.push(b"cd", true), "room in the ring");
        assert!(remainder.push(b"efgh", true), "grows, the old storage kept");
        assert!(
            remainder.push(&[b'i'; 64], true),
            "grows again, the first storage still kept"
        );
        // SAFETY: the run is lent, and the storage it lies in is kept until it comes back.
        let read = unsafe { core::slice::from_raw_parts(base.as_ptr(), len) };
        assert_eq!(read, b"ab");
        assert_eq!(remainder.give_back(2), 2);
        assert!(
            remainder.retired.is_none(),
            "the old storage goes with the run"
        );
        assert_eq!(remainder.len(), 70);
        assert_eq!(remainder.to_vec().get(..6), Some(&b"cdefgh"[..]));
        assert!(remainder.capacity() >= 70);
    }
}
