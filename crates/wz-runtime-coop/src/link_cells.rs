// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cells a session's links live in: one for each link its open admits, reserved with the
//! session's arena, each holding one link's driver for as long as a handle to it lives
//! ([`CellRc`]) and given back when the last handle goes. A handle is what the session's actions
//! send through and what its drive loop pumps, the one value behind both, as an `Rc` is, with no
//! allocation: a link the session takes after its open takes a cell and no memory of the heap
//! (`docs/c-abi-architecture.md`, P3).
//!
//! A cell is a claim of a [`LentByteCells`] table, its value laid out with a head that counts the
//! handles and knows how to drop what the cell holds. A program whose links were lent no table (a
//! host's links outside a session's arena) holds the same handle over a cell of its own on the
//! heap, so a link is one type whichever memory it lives in.

use alloc::boxed::Box;
use core::alloc::Layout;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};
use core::ops::Deref;
use core::ptr::NonNull;

use wz_session_core::bounded::ARENA_ALIGN;
use wz_session_core::byte_cells::{ByteBuf, LentByteCells};
use wz_session_core::link::BoxedLinkDriver;

use crate::session_drive::SessionDatagramLink;

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
pub struct CellRc<T: ?Sized> {
    head: NonNull<CellHead>,
    value: NonNull<T>,
    _owns: PhantomData<T>,
}

/// A claimed cell of `cells` for a slot of `layout`: its place and the claim, which gives the
/// cell back when it goes. `None` when every cell is taken, a cell is too small for the slot, or
/// the cell is not aligned for it. Out of line and generic over nothing: the one body of every
/// kind of value a table's cell holds, which tells them apart by the slot's layout alone.
#[inline(never)]
fn table_cell(cells: &LentByteCells, layout: Layout) -> Option<(NonNull<u8>, ByteBuf)> {
    if !fits_layout(cells.size(), layout) {
        return None;
    }
    let claim = cells.claim()?;
    let (base, _) = claim.raw();
    // A table's cells start on its span's alignment, and each is a whole number of alignments
    // long (`fits_layout`), so this holds; a table laid out otherwise is refused, the claim
    // given back as it goes.
    if (base as usize).checked_rem(layout.align()) != Some(0) {
        return None;
    }
    Some((NonNull::new(base)?, claim))
}

/// A block of the heap for a slot of `layout`, which the slot's release gives back as the box
/// of the slot it is. Out of line and generic over nothing, as [`table_cell`] is.
#[inline(never)]
fn heap_cell(layout: Layout) -> NonNull<u8> {
    // SAFETY: a slot's layout is never of no bytes: it holds a head.
    let base = unsafe { alloc::alloc::alloc(layout) };
    match NonNull::new(base) {
        Some(base) => base,
        None => alloc::alloc::handle_alloc_error(layout),
    }
}

/// Whether a slot of `layout` fits a cell of `size` bytes of a table, whose cells start on an
/// arena's alignment: the whole slot fits, it asks for no more alignment than that, and the cells
/// are a whole number of alignments long, so each starts on it too.
const fn fits_layout(size: usize, layout: Layout) -> bool {
    layout.size() <= size
        && layout.align() <= ARENA_ALIGN
        && matches!(size.checked_rem(ARENA_ALIGN), Some(0))
}

impl<K> CellRc<K> {
    /// `value` in a cell of `cells`, or `value` back when every cell is taken or a cell is too
    /// small for it, or not aligned for it. Out of line: inlined, each of its callers holds a copy
    /// of the slot's writing for every kind of value it places.
    #[inline(never)]
    pub fn place(cells: &LentByteCells, value: K) -> Result<Self, K> {
        match table_cell(cells, Layout::new::<Slot<K>>()) {
            // SAFETY: the claim lends this cell to this call alone, of the slot's layout, and
            // moves into the slot, which keeps the cell until the last handle releases it.
            Some((base, claim)) => Ok(unsafe { Self::fill(base, Owner::Table(claim), value) }),
            None => Err(value),
        }
    }

    /// `value` in a cell of `cells` when a table is lent, or `value` back when none of its cells
    /// takes it ([`Self::place`]); in a cell of its own on the heap when no table is
    /// ([`Self::boxed`]). What every maker of a link's part asks, whichever memory the session
    /// lends. Out of line, as [`Self::place`] is.
    #[inline(never)]
    pub fn in_cells(cells: Option<&LentByteCells>, value: K) -> Result<Self, K> {
        match cells {
            Some(cells) => Self::place(cells, value),
            None => Ok(Self::boxed(value)),
        }
    }

    /// `value` in a cell of its own on the heap: the handle of a link lent no table.
    pub fn boxed(value: K) -> Self {
        let base = heap_cell(Layout::new::<Slot<K>>());
        // SAFETY: the block is the heap's, of the slot's layout, until the slot's release gives it
        // back as the box of a slot of `K`.
        unsafe { Self::fill(base, Owner::Heap, value) }
    }

    /// The handle of the slot written at `base`, from `owner` and `value`, its count one.
    ///
    /// # Safety
    /// `base` is memory of `Slot<K>`'s layout that nothing else reaches, and `owner` is where it
    /// came from.
    unsafe fn fill(base: NonNull<u8>, owner: Owner, value: K) -> Self {
        let slot = base.cast::<Slot<K>>().as_ptr();
        // SAFETY: the caller's contract: the memory is the slot's alone and laid out for it.
        unsafe {
            slot.write(Slot {
                head: CellHead {
                    handles: Cell::new(1),
                    release: release::<K>,
                },
                owner,
                value,
            });
            Self::over(slot)
        }
    }

    /// Whether a value of `K` fits a cell of `size` bytes of a table, whose cells start on an
    /// arena's alignment: the whole slot fits, it asks for no more alignment than that, and the
    /// cells are a whole number of alignments long, so each starts on it too.
    pub const fn fits(size: usize) -> bool {
        fits_layout(size, Layout::new::<Slot<K>>())
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

impl<T: ?Sized> CellRc<T> {
    /// This handle as one on `U`, the value seen through `as_u`: a trait object of it.
    ///
    /// # Safety
    /// `as_u` answers a pointer to the same value it is handed (an unsizing coercion), so the
    /// cell's release, which drops the value as what it was placed as, drops what the handle
    /// names.
    pub unsafe fn unsize<U: ?Sized>(
        self,
        as_u: impl FnOnce(NonNull<T>) -> NonNull<U>,
    ) -> CellRc<U> {
        let this = core::mem::ManuallyDrop::new(self);
        CellRc {
            head: this.head,
            value: as_u(this.value),
            _owns: PhantomData,
        }
    }

    /// How many handles name the value `this` names, `this` among them.
    pub fn handles(this: &Self) -> usize {
        this.head().handles.get()
    }

    /// The value `this` names, as an address: two live handles name one value exactly when
    /// theirs are equal. A released cell's address can name the next value placed in it.
    pub fn as_ptr(this: &Self) -> *const T {
        this.value.as_ptr()
    }

    /// The cell's head.
    fn head(&self) -> &CellHead {
        // SAFETY: a handle keeps its cell, so the head is live for as long as the handle is.
        unsafe { self.head.as_ref() }
    }
}

impl<K: BoxedLinkDriver + 'static> CellRc<K> {
    /// This handle as the one the session's actions send through.
    pub fn into_sink(self) -> CellRc<dyn BoxedLinkDriver> {
        // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
        unsafe { self.unsize(|value| -> NonNull<dyn BoxedLinkDriver> { value }) }
    }
}

impl<K: SessionDatagramLink + 'static> CellRc<K> {
    /// This handle as the link the session's drive loop pumps.
    pub fn into_link(self) -> CellRc<dyn SessionDatagramLink> {
        // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
        unsafe { self.unsize(|value| -> NonNull<dyn SessionDatagramLink> { value }) }
    }
}

/// `driver` in a cell of its own on the heap, as the session's actions send through it: the sink
/// of a link no table lends a cell.
pub fn heap_sink<K: BoxedLinkDriver + 'static>(driver: K) -> CellRc<dyn BoxedLinkDriver> {
    CellRc::boxed(driver).into_sink()
}

impl<T: ?Sized> Deref for CellRc<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a handle keeps its cell, and the cell its value, for as long as the handle is;
        // the value is only ever read through shared references.
        unsafe { self.value.as_ref() }
    }
}

impl<T: ?Sized> Clone for CellRc<T> {
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

impl<T: ?Sized> Drop for CellRc<T> {
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
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let first = CellRc::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let second = CellRc::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        assert_eq!(cells.in_use(), 2);
        let refused = CellRc::place(&cells, Counted(drops.clone()));
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

    /// A value is placed in a cell of a table when one is lent, refused with the value handed back
    /// when the table has no cell left, and placed on the heap when no table is lent. Turned red by
    /// a lent table that is passed over for the heap, or a full one that is.
    #[test]
    fn a_value_goes_in_the_lent_table_or_on_the_heap_when_none_is_lent() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let first = CellRc::in_cells(Some(&cells), Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let second = CellRc::in_cells(Some(&cells), Counted(drops.clone()))
            .ok()
            .expect("a cell");
        assert_eq!(cells.in_use(), 2, "both in the table");
        assert!(
            CellRc::in_cells(Some(&cells), Counted(drops.clone())).is_err(),
            "a full table refuses, and the heap is not asked"
        );
        let boxed = CellRc::in_cells(None, Counted(drops.clone()))
            .ok()
            .expect("the heap when no table is lent");
        assert_eq!(cells.in_use(), 2, "the heap's takes no cell");
        drop((first, second, boxed));
        assert_eq!((drops.get(), cells.in_use()), (4, 0));
    }

    /// A value larger than a cell is refused, with the value handed back, and takes no cell.
    #[test]
    fn a_value_larger_than_a_cell_is_refused() {
        let cells = table(ARENA_ALIGN);
        assert!(!CellRc::<[u64; 4]>::fits(ARENA_ALIGN));
        assert!(CellRc::place(&cells, [7u64; 4]).is_err());
        assert_eq!(cells.in_use(), 0);
    }

    /// A handle seen as a trait object names the same value, and its last handle drops the value
    /// as what it was placed as, from a table's cell or from the heap.
    #[test]
    fn a_handle_seen_as_a_trait_object_drops_its_value_once() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let placed = CellRc::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let boxed = CellRc::boxed(Counted(drops.clone()));
        for handle in [placed, boxed] {
            // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
            let named: CellRc<dyn Named> =
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
