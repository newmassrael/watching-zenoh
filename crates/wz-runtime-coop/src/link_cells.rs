// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cells a session's links live in: one for each link its open admits, reserved with the
//! session's arena, each holding one link's driver for as long as a handle to it lives
//! ([`CellRc`]) and given back when the last handle goes. A handle is what the session's actions
//! send through and what its drive loop pumps, the one value behind both, as an `Rc` is, with no
//! allocation: a link the session takes after its open takes a cell and no memory of the heap
//! (`docs/c-abi-architecture.md`, P3).
//!
//! A cell is a claim of a [`LentByteCells`] table, its value laid out after a head that counts the
//! handles and knows where the cell's memory goes back. A program whose links were lent no table
//! (a host's links outside a session's arena) holds the same handle over a cell of its own on the
//! heap, so a link is one type whichever memory it lives in.
//!
//! Making a cell and giving it back are one body each, generic over nothing: what is left for each
//! kind of value is writing it into its cell, and the last handle drops it through the view of it
//! that handle is (the value's own type or a trait object of it), so a kind of link adds no body of
//! its own here.

use alloc::alloc::{alloc, dealloc, handle_alloc_error};
use core::alloc::Layout;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::Deref;
use core::ptr::NonNull;

use wz_session_core::bounded::ARENA_ALIGN;
use wz_session_core::byte_cells::{ByteBuf, LentByteCells};
use wz_session_core::link::BoxedLinkDriver;

use crate::session_drive::SessionDatagramLink;

/// What a cell keeps before its value: how many handles name it, where its memory came from,
/// which is where it goes back once none does, and, for a cell whose handles name parts of its
/// value ([`CellRc::halves`]), what drops the whole value. A cell whose handles each name the
/// whole value has none: its last handle drops the value through the view of it that handle is.
struct CellHead {
    handles: Cell<usize>,
    owner: Owner,
    whole: Cell<Option<DropWhole>>,
}

/// What drops the whole value of a cell whose handles name parts of it, given the cell's head.
type DropWhole = unsafe fn(NonNull<CellHead>);

/// Where a cell's memory came from, which is where it goes back.
enum Owner {
    /// A claim of a session's table: dropping it gives the cell back.
    Table(ByteBuf),
    /// A block of its own on the heap, of this layout.
    Heap(Layout),
}

/// A cell as it is laid out: the head first, so a pointer to the head is one to the cell.
#[repr(C)]
struct Slot<K> {
    head: CellHead,
    value: K,
}

/// A handle on the value a cell holds, counted as an `Rc` is: a clone names the same value, and
/// the last handle to go drops it and gives the cell back. `T` is the value's type or a trait
/// object of it ([`Self::unsize`]). Not `Send`: the cells belong to the session's one task.
pub struct CellRc<T: ?Sized> {
    head: NonNull<CellHead>,
    value: NonNull<T>,
    _owns: PhantomData<T>,
}

/// A cell for a slot of `layout`, its head written with one handle and its value not yet: a
/// claimed cell of `cells` when a table is lent, `None` when every cell is taken or a cell is too
/// small or not aligned for the slot; a block of the heap when no table is. Out of line: the one
/// body of every kind of value a cell holds, which tells them apart by the slot's layout alone.
#[inline(never)]
fn head_in(cells: Option<&LentByteCells>, layout: Layout) -> Option<NonNull<CellHead>> {
    match cells {
        Some(cells) => table_head(cells, layout),
        None => Some(heap_head(layout)),
    }
}

/// A claimed cell of `cells` for a slot of `layout`, its head written; `None` when every cell is
/// taken, a cell is too small for the slot, or the cell is not aligned for it.
fn table_head(cells: &LentByteCells, layout: Layout) -> Option<NonNull<CellHead>> {
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
    let base = NonNull::new(base)?;
    // SAFETY: the claim lends this cell to this call alone, of the slot's layout and aligned for
    // it, and moves into the head, which keeps the cell until the last handle gives it back.
    Some(unsafe { write_head(base, Owner::Table(claim)) })
}

/// A block of the heap for a slot of `layout`, its head written: the cell of a value no table is
/// lent for, given back to the heap with the same layout.
#[inline(never)]
fn heap_head(layout: Layout) -> NonNull<CellHead> {
    // SAFETY: a slot's layout is never of no bytes: it holds a head.
    let base = unsafe { alloc(layout) };
    let Some(base) = NonNull::new(base) else {
        handle_alloc_error(layout)
    };
    // SAFETY: the block is the heap's, of the slot's layout, and this call's alone.
    unsafe { write_head(base, Owner::Heap(layout)) }
}

/// The head of a cell at `base`, written with one handle and `owner`.
///
/// # Safety
/// `base` is memory of a slot's layout that nothing else reaches, and `owner` is where it came
/// from.
unsafe fn write_head(base: NonNull<u8>, owner: Owner) -> NonNull<CellHead> {
    let head = base.cast::<CellHead>();
    // SAFETY: the caller's contract: the memory is the slot's alone, and a slot starts with its
    // head, aligned for it.
    unsafe {
        head.as_ptr().write(CellHead {
            handles: Cell::new(1),
            owner,
            whole: Cell::new(None),
        });
    }
    head
}

/// Give the cell `head` heads back to where it came from: its table, or the heap.
///
/// # Safety
/// `head` heads a cell whose value was dropped and which no handle names any more.
#[inline(never)]
unsafe fn give_back(head: NonNull<CellHead>) {
    // SAFETY: the caller's contract: the head is whole and read for the last time. The owner is
    // moved out before the memory it lies in is given back, so it is not read again.
    let owner = unsafe { core::ptr::addr_of!((*head.as_ptr()).owner).read() };
    match owner {
        Owner::Table(claim) => drop(claim),
        // SAFETY: the block is the heap's, taken with this layout by `heap_head`, and nothing
        // reaches it after this call.
        Owner::Heap(layout) => unsafe { dealloc(head.as_ptr().cast::<u8>(), layout) },
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
    /// small for it, or not aligned for it.
    pub fn place(cells: &LentByteCells, value: K) -> Result<Self, K> {
        Self::in_cells(Some(cells), value)
    }

    /// `value` in a cell of `cells` when a table is lent, or `value` back when none of its cells
    /// takes it ([`Self::place`]); in a cell of its own on the heap when no table is
    /// ([`Self::boxed`]). What every maker of a link's part asks, whichever memory the session
    /// lends. The cell is made by `head_in`, out of line; what is left here, for each kind of
    /// value, is moving the value into it.
    pub fn in_cells(cells: Option<&LentByteCells>, value: K) -> Result<Self, K> {
        match head_in(cells, Layout::new::<Slot<K>>()) {
            // SAFETY: the head heads a cell of `Slot<K>`'s layout, written with one handle, whose
            // value this writes.
            Some(head) => Ok(unsafe { Self::fill(head, value) }),
            None => Err(value),
        }
    }

    /// `value` in a cell of its own on the heap: the handle of a link lent no table.
    pub fn boxed(value: K) -> Self {
        let head = heap_head(Layout::new::<Slot<K>>());
        // SAFETY: as in `Self::in_cells`.
        unsafe { Self::fill(head, value) }
    }

    /// The handle of the cell `head` heads, its value written from `value`.
    ///
    /// # Safety
    /// `head` heads a cell laid out for `Slot<K>`, its head written with one handle, its value not
    /// written, and no handle names it yet.
    unsafe fn fill(head: NonNull<CellHead>, value: K) -> Self {
        let slot = head.cast::<Slot<K>>().as_ptr();
        // SAFETY: the caller's contract: the cell is a slot of `K` that only this call reaches, so
        // its value's place is aligned for `K`, written once here, and never null.
        unsafe {
            let at = core::ptr::addr_of_mut!((*slot).value);
            at.write(value);
            Self {
                head,
                value: NonNull::new_unchecked(at),
                _owns: PhantomData,
            }
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
}

/// Drop the value of the cell `head` heads, which holds a `K`: the whole of a value whose handles
/// name its parts.
///
/// # Safety
/// `head` heads a `Slot<K>` whose value was written and not dropped, which no handle names any
/// more.
unsafe fn drop_whole<K>(head: NonNull<CellHead>) {
    let slot = head.cast::<Slot<K>>().as_ptr();
    // SAFETY: the caller's contract: the value is whole and nothing reaches it after this call.
    unsafe { core::ptr::addr_of_mut!((*slot).value).drop_in_place() };
}

impl<A, B> CellRc<(A, B)> {
    /// `first` and `second` together in one cell of `cells` ([`Self::in_cells`], or one of the
    /// heap when no table is lent), and a handle on each: two values that are made together and
    /// shared apart, the cell given back with the last handle on either, which drops both. Both
    /// back when no cell takes them.
    pub fn halves(
        cells: Option<&LentByteCells>,
        first: A,
        second: B,
    ) -> Result<(CellRc<A>, CellRc<B>), (A, B)> {
        let pair = Self::in_cells(cells, (first, second))?;
        Ok(pair.into_halves())
    }

    /// Two values `write` writes together in one cell of `cells` ([`Self::in_cells`], or one of
    /// the heap when no table is lent), where they stay, and a handle on each, as [`Self::halves`]
    /// answers: neither value is made in a frame and moved into the cell. `None` when no cell
    /// takes them, `write` not called and let go of with what it holds.
    ///
    /// # Safety
    /// `write` leaves a whole `A` at the first place it is handed and a whole `B` at the second
    /// when it returns. One that unwinds keeps the cell, which is then never given back.
    pub unsafe fn halves_in(
        cells: Option<&LentByteCells>,
        write: impl FnOnce(*mut A, *mut B),
    ) -> Option<(CellRc<A>, CellRc<B>)> {
        let head = head_in(cells, Layout::new::<Slot<(A, B)>>())?;
        let slot = head.cast::<Slot<(A, B)>>().as_ptr();
        // SAFETY: the head heads a cell of `Slot<(A, B)>`'s layout, written with one handle and
        // named by none, whose value is not written: its two fields are places of `A` and `B`,
        // aligned, apart and this call's alone, which `write` leaves whole (the caller's
        // contract), so the pair is whole when the handle names it.
        let pair = unsafe {
            let at = core::ptr::addr_of_mut!((*slot).value);
            write(
                core::ptr::addr_of_mut!((*at).0),
                core::ptr::addr_of_mut!((*at).1),
            );
            Self {
                head,
                value: NonNull::new_unchecked(at),
                _owns: PhantomData,
            }
        };
        Some(pair.into_halves())
    }

    /// This handle on a pair as one handle on each of its halves, the cell given back with the
    /// last of them, which drops the pair whole.
    fn into_halves(self) -> (CellRc<A>, CellRc<B>) {
        // The last handle names one half, so it drops the pair through this, not through its view.
        self.head().whole.set(Some(drop_whole::<(A, B)>));
        let other = self.clone();
        // SAFETY: each closure answers a pointer to a field of the pair the handle names, which
        // lives as long as the cell does; the cell's `whole` drops the pair it was placed as.
        unsafe {
            (
                self.part(|pair| {
                    NonNull::new_unchecked(core::ptr::addr_of_mut!((*pair.as_ptr()).0))
                }),
                other.part(|pair| {
                    NonNull::new_unchecked(core::ptr::addr_of_mut!((*pair.as_ptr()).1))
                }),
            )
        }
    }
}

impl<T: ?Sized> CellRc<T> {
    /// This handle as one on a part of its value, `as_part` answering where the part lies.
    ///
    /// # Safety
    /// `as_part` answers a pointer to a value that lives as long as the value it is handed, and
    /// the cell's `whole` is set: its last handle drops the whole value placed, never the part.
    unsafe fn part<U>(self, as_part: impl FnOnce(NonNull<T>) -> NonNull<U>) -> CellRc<U> {
        let this = core::mem::ManuallyDrop::new(self);
        CellRc {
            head: this.head,
            value: as_part(this.value),
            _owns: PhantomData,
        }
    }

    /// This handle as one on `U`, the value seen through `as_u`: a trait object of it.
    ///
    /// # Safety
    /// `as_u` answers a pointer to the same value it is handed (an unsizing coercion), so the last
    /// handle, which drops the value through the view it is, drops the value that was placed.
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
            let whole = head.whole.get();
            // SAFETY: this was the last handle, so nothing names the value or the cell after this,
            // and the value was placed and not dropped. A cell whose handles name parts drops the
            // whole value through `whole` (`Self::part`); any other handle names the value as what
            // it was placed as or as a trait object of it (`Self::unsize`), so this drops the
            // value placed.
            unsafe {
                match whole {
                    Some(drop_whole) => drop_whole(self.head),
                    None => self.value.as_ptr().drop_in_place(),
                }
                give_back(self.head);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
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

    trait Numbered {
        fn number(&self) -> u32;
    }

    impl Numbered for Counted {
        fn number(&self) -> u32 {
            9
        }
    }

    /// A value that asks for more alignment than a cell's head does.
    #[repr(align(16))]
    struct Wide(Counted);

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

    /// One cell seen through two trait objects, as a link is by the session's actions and by its
    /// loop: the value lives while either view does and is dropped once, by whichever view goes
    /// last, and the cell is given back then, to its table or to the heap. Turned red by a last
    /// handle that does not drop the value through its view, or that keeps the cell.
    #[test]
    fn the_last_of_two_views_drops_the_value_once_and_gives_the_cell_back() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        for named_goes_first in [true, false] {
            for lent in [Some(&cells), None] {
                let handle = CellRc::in_cells(lent, Counted(drops.clone()))
                    .ok()
                    .expect("a cell, or the heap");
                let before = drops.get();
                // SAFETY: each closure is the unsizing coercion of the pointer it is handed.
                let named: CellRc<dyn Named> = unsafe {
                    handle
                        .clone()
                        .unsize(|value| -> NonNull<dyn Named> { value })
                };
                // SAFETY: as above.
                let numbered: CellRc<dyn Numbered> =
                    unsafe { handle.unsize(|value| -> NonNull<dyn Numbered> { value }) };
                assert_eq!((named.name(), numbered.number()), (7, 9));
                assert_eq!(CellRc::handles(&named), 2, "two views, one count");
                if named_goes_first {
                    drop(named);
                    assert_eq!(drops.get(), before, "the other view keeps the value");
                    drop(numbered);
                } else {
                    drop(numbered);
                    assert_eq!(drops.get(), before, "the other view keeps the value");
                    drop(named);
                }
                assert_eq!(drops.get(), before + 1, "dropped once, by the last view");
                assert_eq!(cells.in_use(), 0, "the table's cell given back");
            }
        }
    }

    /// A value that asks for more alignment than a cell's head is placed on its alignment, in a
    /// table's cell and on the heap, and both are given back when its last handle goes.
    #[test]
    fn a_value_aligned_past_the_head_is_placed_on_its_alignment() {
        let cells = table(CellRc::<Wide>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let placed = CellRc::place(&cells, Wide(Counted(drops.clone())))
            .ok()
            .expect("a cell");
        let boxed = CellRc::boxed(Wide(Counted(drops.clone())));
        for handle in [&placed, &boxed] {
            assert_eq!((CellRc::as_ptr(handle) as usize).checked_rem(16), Some(0));
            assert_eq!(handle.0.name(), 7);
        }
        assert_eq!(cells.in_use(), 1);
        drop((placed, boxed));
        assert_eq!((drops.get(), cells.in_use()), (2, 0));
    }

    /// Two values placed as halves share one cell: each handle names its own value, the cell
    /// keeps both until the last handle on either goes, and halves placed in a lent table take
    /// no memory of the heap. Turned red by halves boxed while a table is lent, or by a cell
    /// given back while a handle on one half lives.
    #[cfg(feature = "alloc")]
    #[test]
    fn halves_share_one_cell_until_the_last_handle_on_either() {
        let cells = table(CellRc::<(Counted, u32)>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let (placed, made) = crate::table_tests::allocations(|| {
            CellRc::halves(Some(&cells), Counted(drops.clone()), 7u32)
        });
        let (first, second) = placed.ok().expect("a cell");
        assert_eq!(made, 0, "halves in a lent table take no memory of the heap");
        assert_eq!((cells.in_use(), *second), (1, 7), "one cell holds both");
        drop(first);
        assert_eq!(
            (drops.get(), cells.in_use()),
            (0, 1),
            "the other half keeps the cell and both values"
        );
        drop(second);
        assert_eq!(
            (drops.get(), cells.in_use()),
            (1, 0),
            "the last handle drops both and gives the cell back"
        );
        let (_, boxed) = CellRc::halves(None, Counted(drops.clone()), 8u32)
            .ok()
            .expect("the heap when no table is lent");
        assert_eq!((*boxed, cells.in_use()), (8, 0), "the heap's takes no cell");
    }

    /// Halves written in place lie where their writer wrote them: the places it is handed are the
    /// ones the handles name, in the table's cell, and no memory of the heap is taken. With every
    /// cell taken the writer is not called and what it holds is let go of, once. Turned red by
    /// halves made in a frame and moved into the cell, or by a writer called with no cell to
    /// write in.
    #[cfg(feature = "alloc")]
    #[test]
    fn halves_written_in_place_lie_where_they_were_written() {
        let cells = table(CellRc::<(Counted, u32)>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let mut written = (
            core::ptr::null_mut::<Counted>(),
            core::ptr::null_mut::<u32>(),
        );
        let counted = Counted(drops.clone());
        let (placed, made) = crate::table_tests::allocations(|| {
            // SAFETY: the writer writes a whole value at each place it is handed.
            unsafe {
                CellRc::halves_in(Some(&cells), |first: *mut Counted, second: *mut u32| {
                    first.write(counted);
                    second.write(7);
                    written = (first, second);
                })
            }
        });
        let (first, second) = placed.expect("a cell");
        assert_eq!(
            made, 0,
            "halves written in a lent table take no memory of the heap"
        );
        assert_eq!(
            (CellRc::as_ptr(&first), CellRc::as_ptr(&second)),
            (written.0.cast_const(), written.1.cast_const()),
            "the handles name the places the writer wrote"
        );
        assert_eq!((first.name(), *second, cells.in_use()), (7, 7, 1));
        // SAFETY: as above.
        let other = unsafe {
            CellRc::halves_in(Some(&cells), |first: *mut Counted, second: *mut u32| {
                first.write(Counted(drops.clone()));
                second.write(8);
            })
        }
        .expect("the table's second cell");
        let refused_drops = Rc::new(Cell::new(0));
        let held = Counted(refused_drops.clone());
        let mut called = false;
        // SAFETY: as above.
        let refused = unsafe {
            CellRc::halves_in(Some(&cells), |first: *mut Counted, second: *mut u32| {
                called = true;
                first.write(held);
                second.write(9);
            })
        };
        assert!(refused.is_none(), "every cell is taken");
        assert_eq!(
            (called, refused_drops.get(), cells.in_use()),
            (false, 1, 2),
            "the writer is let go of uncalled, what it held dropped once"
        );
        drop((first, other));
        assert_eq!(
            (drops.get(), cells.in_use()),
            (1, 1),
            "a pair goes whole with its last handle, the other stays"
        );
        drop(second);
        assert_eq!((drops.get(), cells.in_use()), (2, 0));
    }
}
