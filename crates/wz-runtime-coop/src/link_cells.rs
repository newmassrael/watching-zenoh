// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cells a session's links live in: one for each link its open admits, reserved with the
//! session's arena, each holding one link's driver for as long as a handle to it lives
//! ([`Shared`]) and given back when the last handle goes. A handle is what the session's actions
//! send through and what its drive loop pumps, the one value behind both, as an `Rc` is, with no
//! allocation: a link the session takes after its open takes a cell and no memory of the heap
//! (`docs/c-abi-architecture.md`, P3).
//!
//! A cell is a claim of a [`LentByteCells`] table, its value laid out with a head that counts the
//! handles and knows how to drop what the cell holds. A program whose links were lent no table (a
//! host's links outside a session's arena) holds the same handle over a cell of its own on the
//! heap, so a link is one type whichever memory it lives in.

use alloc::boxed::Box;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{align_of, size_of, MaybeUninit};
use core::ops::Deref;
use core::ptr::NonNull;

use wz_session_core::bounded::ARENA_ALIGN;
use wz_session_core::byte_cells::{ByteBuf, LentByteCells};

/// What a cell keeps before its value: how many handles name it, and what drops the value and
/// gives the cell's memory back once none does.
struct CellHead {
    handles: Cell<usize>,
    release: unsafe fn(NonNull<CellHead>),
}

/// Where a cell's memory came from, which is where it goes back.
enum Owner {
    /// A claim of a session's table: dropping it gives the cell back.
    Table(ByteBuf),
    /// A cell of its own on the heap.
    Heap,
}

/// A cell as it is laid out: the head first, so a pointer to the head is one to the cell.
#[repr(C)]
struct Slot<K> {
    head: CellHead,
    owner: Owner,
    value: K,
}

/// Drop the value of the cell `head` heads, which holds a `K`, and give its memory back.
///
/// # Safety
/// `head` heads a `Slot<K>` whose value was written and not dropped, which no handle names any
/// more.
unsafe fn release<K>(head: NonNull<CellHead>) {
    let slot = head.cast::<Slot<K>>().as_ptr();
    // SAFETY: the caller's contract: the slot is whole, and nothing reaches it after this call.
    // The owner is moved out before the value is dropped and the memory given back, so neither
    // is read again.
    unsafe {
        let owner = core::ptr::addr_of!((*slot).owner).read();
        core::ptr::addr_of_mut!((*slot).value).drop_in_place();
        match owner {
            Owner::Table(claim) => drop(claim),
            Owner::Heap => drop(Box::from_raw(slot.cast::<MaybeUninit<Slot<K>>>())),
        }
    }
}

/// A handle on the value a cell holds, counted as an `Rc` is: a clone names the same value, and
/// the last handle to go drops it and gives the cell back. `T` is the value's type or a trait
/// object of it ([`Self::unsize`]). Not `Send`: the cells belong to the session's one task.
pub struct Shared<T: ?Sized> {
    head: NonNull<CellHead>,
    value: NonNull<T>,
    _owns: PhantomData<T>,
}

impl<K> Shared<K> {
    /// `value` in a cell of `cells`, or `value` back when every cell is taken or a cell is too
    /// small for it, or not aligned for it.
    pub fn place(cells: &LentByteCells, value: K) -> Result<Self, K> {
        if !Self::fits(cells.size()) {
            return Err(value);
        }
        let Some(claim) = cells.claim() else {
            return Err(value);
        };
        let (base, _) = claim.raw();
        let slot = base.cast::<Slot<K>>();
        // A table's cells start on its span's alignment, and each is a whole number of
        // alignments long ([`Self::fits`]), so this holds; a table laid out otherwise is refused.
        if (slot as usize).checked_rem(align_of::<Slot<K>>()) != Some(0) {
            return Err(value);
        }
        // SAFETY: the claim lends this cell to this call alone, the slot fits in it and is aligned
        // for it (checked above), and the claim moves into the slot, which keeps the cell until
        // the last handle releases it.
        unsafe {
            slot.write(Slot {
                head: CellHead {
                    handles: Cell::new(1),
                    release: release::<K>,
                },
                owner: Owner::Table(claim),
                value,
            });
            Ok(Self::over(slot))
        }
    }

    /// `value` in a cell of its own on the heap: the handle of a link lent no table.
    pub fn boxed(value: K) -> Self {
        let slot = Box::into_raw(Box::new(Slot {
            head: CellHead {
                handles: Cell::new(1),
                release: release::<K>,
            },
            owner: Owner::Heap,
            value,
        }));
        // SAFETY: the slot was just written whole and is the heap's until its release.
        unsafe { Self::over(slot) }
    }

    /// Whether a value of `K` fits a cell of `size` bytes of a table, whose cells start on an
    /// arena's alignment: the whole slot fits, it asks for no more alignment than that, and the
    /// cells are a whole number of alignments long, so each starts on it too.
    pub const fn fits(size: usize) -> bool {
        size_of::<Slot<K>>() <= size
            && align_of::<Slot<K>>() <= ARENA_ALIGN
            && matches!(size.checked_rem(ARENA_ALIGN), Some(0))
    }

    /// The bytes of a cell that holds a `K`, a whole number of an arena's alignments: what a
    /// table is laid out with for its links' largest driver.
    pub const fn cell_bytes() -> usize {
        match size_of::<Slot<K>>().checked_next_multiple_of(ARENA_ALIGN) {
            Some(bytes) => bytes,
            None => usize::MAX,
        }
    }

    /// The handle of the slot at `slot`, its count already one.
    ///
    /// # Safety
    /// `slot` is a whole `Slot<K>` whose count is one and that no handle names yet.
    unsafe fn over(slot: *mut Slot<K>) -> Self {
        // SAFETY: the caller's contract: `slot` is a live slot, so neither pointer is null.
        unsafe {
            Self {
                head: NonNull::new_unchecked(slot).cast::<CellHead>(),
                value: NonNull::new_unchecked(core::ptr::addr_of_mut!((*slot).value)),
                _owns: PhantomData,
            }
        }
    }
}

impl<T: ?Sized> Shared<T> {
    /// This handle as one on `U`, the value seen through `as_u`: a trait object of it.
    ///
    /// # Safety
    /// `as_u` answers a pointer to the same value it is handed (an unsizing coercion), so the
    /// cell's release, which drops the value as what it was placed as, drops what the handle
    /// names.
    pub unsafe fn unsize<U: ?Sized>(
        self,
        as_u: impl FnOnce(NonNull<T>) -> NonNull<U>,
    ) -> Shared<U> {
        let this = core::mem::ManuallyDrop::new(self);
        Shared {
            head: this.head,
            value: as_u(this.value),
            _owns: PhantomData,
        }
    }

    /// The cell's head.
    fn head(&self) -> &CellHead {
        // SAFETY: a handle keeps its cell, so the head is live for as long as the handle is.
        unsafe { self.head.as_ref() }
    }
}

impl<T: ?Sized> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a handle keeps its cell, and the cell its value, for as long as the handle is;
        // the value is only ever read through shared references.
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> Clone for Shared<T> {
    fn clone(&self) -> Self {
        let handles = &self.head().handles;
        handles.set(handles.get().saturating_add(1));
        Self {
            head: self.head,
            value: self.value,
            _owns: PhantomData,
        }
    }
}

impl<T: ?Sized> Drop for Shared<T> {
    fn drop(&mut self) {
        let head = self.head();
        let left = head.handles.get().saturating_sub(1);
        head.handles.set(left);
        if left == 0 {
            let release = head.release;
            // SAFETY: this was the last handle, so nothing names the cell after this call, and its
            // value was placed and not dropped.
            unsafe { release(self.head) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;

    /// A value that counts its drops.
    struct Counted(Rc<Cell<u32>>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.set(self.0.get().saturating_add(1));
        }
    }

    trait Named {
        fn name(&self) -> u32;
    }

    impl Named for Counted {
        fn name(&self) -> u32 {
            7
        }
    }

    /// A table of two cells of `size` bytes, in memory of the test's own, lent as a session's
    /// arena lends its tables.
    fn table(size: usize) -> LentByteCells {
        use wz_session_core::bounded::Arena;

        const BYTES: usize = 1024;
        #[repr(C, align(16))]
        struct Memory([u8; BYTES]);

        let memory: &'static mut Memory = Box::leak(Box::new(Memory([0; BYTES])));
        // SAFETY: the memory is leaked, so it outlives the arena, the table and every claim of
        // it; it is aligned as an arena's spans start, BYTES long, and used by nothing else.
        let mut arena = unsafe { Arena::over(NonNull::from(memory).cast::<u8>(), BYTES) };
        arena
            .lend_byte_cells(size, 2)
            .expect("the memory holds two cells")
    }

    /// A value placed in a cell is named by every clone of its handle, dropped once when the last
    /// goes, and its cell is given back then and not before; a cell past the table's is refused
    /// with the value handed back.
    #[test]
    fn a_placed_value_lives_while_a_handle_does_and_gives_its_cell_back() {
        let cells = table(Shared::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let first = Shared::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let second = Shared::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        assert_eq!(cells.in_use(), 2);
        let refused = Shared::place(&cells, Counted(drops.clone()));
        assert!(refused.is_err(), "past the table's cells");
        drop(refused);
        assert_eq!(
            drops.get(),
            1,
            "the refused value was handed back and dropped by the caller"
        );
        let copy = first.clone();
        drop(first);
        assert_eq!(
            (drops.get(), cells.in_use()),
            (1, 2),
            "a clone keeps the value and its cell"
        );
        drop(copy);
        assert_eq!(
            (drops.get(), cells.in_use()),
            (2, 1),
            "the last handle drops it and frees it"
        );
        drop(second);
        assert_eq!((drops.get(), cells.in_use()), (3, 0));
    }

    /// A value larger than a cell is refused, with the value handed back, and takes no cell.
    #[test]
    fn a_value_larger_than_a_cell_is_refused() {
        let cells = table(ARENA_ALIGN);
        assert!(!Shared::<[u64; 4]>::fits(ARENA_ALIGN));
        assert!(Shared::place(&cells, [7u64; 4]).is_err());
        assert_eq!(cells.in_use(), 0);
    }

    /// A handle seen as a trait object names the same value, and its last handle drops the value
    /// as what it was placed as, from a table's cell or from the heap.
    #[test]
    fn a_handle_seen_as_a_trait_object_drops_its_value_once() {
        let cells = table(Shared::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let placed = Shared::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let boxed = Shared::boxed(Counted(drops.clone()));
        for handle in [placed, boxed] {
            // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
            let named: Shared<dyn Named> =
                unsafe { handle.unsize(|value| -> NonNull<dyn Named> { value }) };
            let again = named.clone();
            assert_eq!(again.name(), 7);
            drop(named);
            drop(again);
        }
        assert_eq!(drops.get(), 2, "each value dropped once");
        assert_eq!(cells.in_use(), 0, "and the table's cell given back");
    }
}
