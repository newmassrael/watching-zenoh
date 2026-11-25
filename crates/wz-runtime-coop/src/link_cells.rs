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
//! Making a cell, letting go of a handle and giving the cell back are one body each for each form
//! of a table's flag a build uses ([`CountKind::Flag`]), and generic over nothing else: what is
//! left for each kind of value is writing it into its cell with what drops it, and the last handle
//! drops it through that, whatever view of it the handle is (the value's own type, a trait object
//! of it or a part of it), so a kind of link adds no body of its own here.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};
use core::ops::Deref;
use core::ptr::NonNull;
#[cfg(target_has_atomic = "8")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicUsize, Ordering};

use portable_atomic::AtomicUsize as CountWord;

use wz_session_core::bounded::ARENA_ALIGN;
use wz_session_core::byte_cells::{ByteBuf, CellFlag, LentByteCells};
use wz_session_core::link::BoxedLinkDriver;

use crate::session_drive::SessionDatagramLink;

/// What a cell keeps before its value: how many handles name it and where the value lies, where its
/// memory came from, which is where it goes back once none does, and what drops the whole value
/// placed in it, which its last handle calls whatever view of the value it is
/// ([`CellRc::unsize`], [`CellRc::halves`]). `F` is the form of the flag of the table a cell
/// is claimed from, which its handles' kind names ([`CountKind::Flag`]).
struct CellHead<F: CellFlag = Cell<bool>> {
    /// The handles that name the value, counted in [`ONE_HANDLE`]s, above the place of the value
    /// ([`Slot::PLACE`]): one word, as the count alone was, so a cell is no larger for the place.
    /// A clone may name a value of no cell, so nothing bounds the count but the word: one held at
    /// its most keeps its value for good, and the clone past it is counted
    /// ([`held_past_count`]).
    word: CountWord,
    owner: Owner<F>,
    whole: DropWhole,
}

// A cell's value lies past its head by the head's size alone (`value_at`), whichever form the
// flag of its table takes.
#[cfg(target_has_atomic = "8")]
const _: () = assert!(size_of::<CellHead<AtomicBool>>() == size_of::<CellHead>());

/// How the handles of a cell are counted. A cell's word is written by one kind's handles alone, so
/// a kind is a type argument of the handle ([`CellRc`]) and never a choice made at run time, and
/// sized as that argument is, so a kind's own items may name a handle of their kind.
pub trait CountKind: Sized + 'static {
    /// The flag of a table's cell that a handle of this kind may be placed in: a handle's last let
    /// go gives the cell back by it, on whichever thread a handle of this kind may be let go of.
    type Flag: CellFlag;

    /// How the handles on a value that several links of this kind share (a port their peers
    /// read from, the session's entropy) are counted: such a value outlives any one link's
    /// holder, so its handles are counted for every thread a link's handles may be on.
    type Shared: CountKind<Flag = Self::Flag>;

    /// The word as it stands.
    fn read(word: &CountWord) -> usize;

    /// Write `f`'s answer over the word it is handed, when it answers one, and answer the word
    /// `f` was handed.
    fn update(word: &CountWord, f: impl FnMut(usize) -> Option<usize>) -> usize;

    /// A value that handles of this kind share and reach one holder at a time: a `RefCell` where
    /// one task holds them, the profile's lock ([`crate::sync::Mutex`]) where threads do.
    type Local<T>;

    /// `value`, in a new [`Self::Local`].
    fn new_local<T>(value: T) -> Self::Local<T>;

    /// Run `f` on the value of `local`. A hold inside another hold of the same value is the
    /// caller's fault, as a `RefCell`'s second borrow is.
    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U;

    /// [`Self::with_local`] unless a holder has the value now (this task, inside a hold, or
    /// another thread): `None` then, and `f` has not run.
    fn try_with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> Option<U>;
}

/// Counted as an `Rc` is: the handles of a cell are held by one task at a time, so the word is
/// read and written with plain loads and stores, no read-modify-write. What a session of one
/// thread, or one confined to its engine's lock, holds its links by.
pub enum OneTask {}

impl CountKind for OneTask {
    type Flag = Cell<bool>;
    type Shared = OneTask;

    #[inline]
    fn read(word: &CountWord) -> usize {
        word.load(Ordering::Relaxed)
    }

    #[inline]
    fn update(word: &CountWord, mut f: impl FnMut(usize) -> Option<usize>) -> usize {
        let was = word.load(Ordering::Relaxed);
        if let Some(now) = f(was) {
            word.store(now, Ordering::Relaxed);
        }
        was
    }

    type Local<T> = core::cell::RefCell<T>;

    #[inline]
    fn new_local<T>(value: T) -> Self::Local<T> {
        core::cell::RefCell::new(value)
    }

    #[inline]
    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U {
        f(&mut local.borrow_mut())
    }

    #[inline]
    fn try_with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> Option<U> {
        local.try_borrow_mut().ok().map(|mut value| f(&mut value))
    }
}

/// Counted as an `Arc` is: handles of one cell may be cloned and let go of on several threads at
/// once, so each change of the word is one read-modify-write, and the last handle's let go is
/// ordered after every other handle's. Its cell is a block of the heap, which any thread may give
/// back, or a cell of a table of atomic flags, which the last handle gives back by an ordered store
/// that the table's claims read atomically.
#[cfg(target_has_atomic = "8")]
pub enum Atomic {}

#[cfg(target_has_atomic = "8")]
impl CountKind for Atomic {
    type Flag = AtomicBool;
    type Shared = Atomic;

    #[inline]
    fn read(word: &CountWord) -> usize {
        word.load(Ordering::Acquire)
    }

    #[inline]
    fn update(word: &CountWord, f: impl FnMut(usize) -> Option<usize>) -> usize {
        match word.fetch_update(Ordering::AcqRel, Ordering::Acquire, f) {
            Ok(was) | Err(was) => was,
        }
    }

    type Local<T> = crate::sync::Mutex<T>;

    #[inline]
    fn new_local<T>(value: T) -> Self::Local<T> {
        #[cfg(feature = "host-lock")]
        {
            crate::cs::HostMutex::new(value)
        }
        #[cfg(not(feature = "host-lock"))]
        {
            critical_section::Mutex::new(core::cell::RefCell::new(value))
        }
    }

    #[inline]
    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U {
        #[cfg(feature = "host-lock")]
        {
            local.with(f)
        }
        #[cfg(not(feature = "host-lock"))]
        {
            crate::cs::with(|cs| f(&mut local.borrow(cs).borrow_mut()))
        }
    }

    #[inline]
    fn try_with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> Option<U> {
        #[cfg(feature = "host-lock")]
        {
            local.try_with(f)
        }
        #[cfg(not(feature = "host-lock"))]
        {
            crate::cs::with(|cs| {
                local
                    .borrow(cs)
                    .try_borrow_mut()
                    .ok()
                    .map(|mut value| f(&mut value))
            })
        }
    }
}

/// Counted as [`OneTask`] counts, for the handles of one face's link held together: every handle
/// on such a cell lies in the one value a face keeps its link's parts in, which moves between
/// threads whole and is reached by one thread at a time ([`FaceHeld`]), so the word is
/// written by plain loads and stores as one task's is. The cell goes back to a table that the
/// faces held on other threads claim cells of at the same time, so its flag is an atomic, given
/// back by an ordered store, and what the links share is counted as an `Arc`'s is
/// ([`Atomic`]). Its handles are not `Send`: only the face's value, as a whole, crosses threads.
#[cfg(target_has_atomic = "8")]
pub enum OneFace {}

#[cfg(target_has_atomic = "8")]
impl CountKind for OneFace {
    type Flag = AtomicBool;
    type Shared = Atomic;

    #[inline]
    fn read(word: &CountWord) -> usize {
        OneTask::read(word)
    }

    #[inline]
    fn update(word: &CountWord, f: impl FnMut(usize) -> Option<usize>) -> usize {
        OneTask::update(word, f)
    }

    type Local<T> = core::cell::RefCell<T>;

    #[inline]
    fn new_local<T>(value: T) -> Self::Local<T> {
        OneTask::new_local(value)
    }

    #[inline]
    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U {
        OneTask::with_local(local, f)
    }

    #[inline]
    fn try_with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> Option<U> {
        OneTask::try_with_local(local, f)
    }
}

/// The bits of a head's word below its count: the base-2 logarithm of the alignment of the value
/// placed ([`Slot::PLACE`]), which says where after the head the value lies.
const PLACE_BITS: u32 = 4;

/// One handle, as a head's word counts it.
const ONE_HANDLE: usize = 1usize.wrapping_shl(PLACE_BITS);

/// The place bits of a head's word.
const PLACE_MASK: usize = ONE_HANDLE.wrapping_sub(1);

/// How often a cell was held by a clone past the most its count holds, in this process. Read and
/// written apart, not as one step: handles are not `Send`, and the count only says that it
/// happened.
static HELD_PAST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Where after the start of its cell a value lies whose alignment is `1 << place`: the head's
/// size, rounded up to that alignment, as `repr(C)` lays a slot out.
const fn value_at(place: usize) -> usize {
    let align_less_one = 1usize.wrapping_shl(place as u32).wrapping_sub(1);
    size_of::<CellHead>().wrapping_add(align_less_one) & !align_less_one
}

/// What drops the whole value of a cell, handed the place it lies at: the drop of the type placed
/// ([`Slot::WHOLE`]).
type DropWhole = unsafe fn(*mut u8);

/// Where a cell's memory came from, which is where it goes back.
enum Owner<F: CellFlag = Cell<bool>> {
    /// A claim of a session's table: dropping it gives the cell back.
    Table(ByteBuf<F>),
    /// A block of its own on the heap, of this layout.
    Heap(Layout),
}

/// A cell as it is laid out: the head first, so a pointer to the head is one to the cell.
#[repr(C)]
struct Slot<K, F: CellFlag = Cell<bool>> {
    head: CellHead<F>,
    value: K,
}

impl<K, F: CellFlag> Slot<K, F> {
    /// The drop of a `K` as a cell's head keeps it: `K`'s own drop, the body a trait object of a
    /// `K` drops through too, and not a body of the cell's for each kind of value placed.
    // SAFETY: `K` is `Sized` (a slot's value is), so `*mut K` and `*mut u8` are pointers with no
    // metadata, which the Rust reference's rules of function pointer ABI compatibility pass alike:
    // a call through the `unsafe fn(*mut u8)` is a call of `drop_in_place::<K>` with the same
    // address. The head hands it a `K`'s place only (`let_go`).
    const WHOLE: DropWhole = unsafe {
        core::mem::transmute::<unsafe fn(*mut K), DropWhole>(core::ptr::drop_in_place::<K>)
    };

    /// Where the value lies, as a head's word keeps it ([`value_at`]): the base-2 logarithm of
    /// `K`'s alignment, which its place bits hold.
    const PLACE: usize = {
        let place = core::mem::align_of::<K>().trailing_zeros() as usize;
        assert!(
            place <= PLACE_MASK,
            "a cell's value is aligned to 32 KiB at most"
        );
        place
    };
}

/// A handle on the value a cell holds, counted as an `Rc` is: a clone names the same value, and
/// the last handle to go drops it and gives the cell back. `T` is the value's type or a trait
/// object of it ([`Self::unsize`]). `N` is how its handles are counted ([`CountKind`]): one
/// task's ([`OneTask`], not `Send`) or several threads' ([`Atomic`]).
pub struct CellRc<T: ?Sized, N: CountKind = OneTask> {
    head: NonNull<CellHead<N::Flag>>,
    value: NonNull<T>,
    _owns: PhantomData<T>,
    _count: PhantomData<fn() -> N>,
}

// SAFETY: a handle of the atomic kind counts its cell with read-modify-writes ordered as an
// `Arc`'s are, so clones and let gos on several threads keep one count, and the last handle drops
// the value after every other handle let go. Its cell is the heap's, which any thread gives back,
// or one of a table of atomic flags (`Atomic::Flag`), given back by an ordered store. The value
// is reached through shared references only, so sending a handle or sharing one needs the value
// to be `Send` and `Sync`, as `Arc` asks.
#[cfg(target_has_atomic = "8")]
unsafe impl<T: ?Sized + Send + Sync> Send for CellRc<T, Atomic> {}
// SAFETY: as for `Send` above.
#[cfg(target_has_atomic = "8")]
unsafe impl<T: ?Sized + Send + Sync> Sync for CellRc<T, Atomic> {}

/// A cell for a slot of `layout`, its head written with one handle, `whole` and `place`, its
/// value not yet: a claimed cell of `cells` when a table is lent, `None` when every cell is taken
/// or a cell is too small or not aligned for the slot; a block of the heap when no table is, `None`
/// when the heap refuses it. Out of line: the one body of every kind of value a cell holds, which
/// tells them apart by the slot's layout, the drop of its value and where the value lies alone.
#[inline(never)]
fn head_in<F: CellFlag>(
    cells: Option<&LentByteCells<F>>,
    layout: Layout,
    whole: DropWhole,
    place: usize,
) -> Option<NonNull<CellHead<F>>> {
    match cells {
        Some(cells) => table_head(cells, layout, whole, place),
        None => heap_head(layout, whole, place),
    }
}

/// A claimed cell of `cells` for a slot of `layout`, its head written with `whole` and
/// `place`; `None` when every cell is taken, a cell is too small for the slot, or the cell is
/// not aligned for it.
fn table_head<F: CellFlag>(
    cells: &LentByteCells<F>,
    layout: Layout,
    whole: DropWhole,
    place: usize,
) -> Option<NonNull<CellHead<F>>> {
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
    Some(unsafe { write_head(base, Owner::Table(claim), whole, place) })
}

/// A block of the heap for a slot of `layout`, its head written with `whole` and `place`: the
/// cell of a value no table is lent for, given back to the heap with the same layout. `None` when
/// the heap refuses the block: a link made then is refused as one past a table's cells is, and the
/// program goes on.
#[inline(never)]
fn heap_head<F: CellFlag>(
    layout: Layout,
    whole: DropWhole,
    place: usize,
) -> Option<NonNull<CellHead<F>>> {
    // SAFETY: a slot's layout is never of no bytes: it holds a head.
    let base = NonNull::new(unsafe { alloc(layout) })?;
    // SAFETY: the block is the heap's, of the slot's layout, and this call's alone.
    Some(unsafe { write_head(base, Owner::Heap(layout), whole, place) })
}

/// The head of a cell at `base`, written with one handle, `owner`, `whole` and `place`.
///
/// # Safety
/// `base` is memory of a slot's layout that nothing else reaches, and `owner` is where it came
/// from.
unsafe fn write_head<F: CellFlag>(
    base: NonNull<u8>,
    owner: Owner<F>,
    whole: DropWhole,
    place: usize,
) -> NonNull<CellHead<F>> {
    let head = base.cast::<CellHead<F>>();
    // SAFETY: the caller's contract: the memory is the slot's alone, and a slot starts with its
    // head, aligned for it.
    unsafe {
        head.as_ptr().write(CellHead {
            word: CountWord::new(ONE_HANDLE | place),
            owner,
            whole,
        });
    }
    head
}

/// Give the cell `head` heads back to where it came from: its table, or the heap.
///
/// # Safety
/// `head` heads a cell whose value was dropped and which no handle names any more.
#[inline(never)]
unsafe fn give_back<F: CellFlag>(head: NonNull<CellHead<F>>) {
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

/// Let go of one handle on the cell `head` heads: the last drops the value placed through the
/// cell's `whole` and gives the cell back. Out of line: the one body of every handle's drop,
/// which each kind of handle only calls.
///
/// # Safety
/// `head` heads a cell whose value was placed and not dropped, named by a handle that is let go
/// of here and not used after.
#[inline(never)]
unsafe fn let_go<N: CountKind>(head: NonNull<CellHead<N::Flag>>) {
    // SAFETY: the caller's contract: a handle names the cell, so its head is live.
    let cell = unsafe { head.as_ref() };
    // A count held at its most was passed by a clone it did not count, so it no longer says when
    // the last handle goes: the value is kept for good. Otherwise the handle let go of is
    // counted, so the count is one at least.
    let word = N::update(&cell.word, |word| {
        word.checked_add(ONE_HANDLE)
            .map(|_| word.wrapping_sub(ONE_HANDLE))
    });
    if word.checked_add(ONE_HANDLE).is_none() {
        return;
    }
    let left = word.wrapping_sub(ONE_HANDLE);
    if left < ONE_HANDLE {
        let (whole, at) = (cell.whole, value_at(left & PLACE_MASK));
        // SAFETY: this was the last handle, so nothing names the value or the cell after this,
        // and the value was placed at `at` and not dropped: `whole` drops it as the type it was
        // placed as, whatever view of it the handle was, before the cell goes back.
        unsafe {
            whole(head.as_ptr().cast::<u8>().add(at));
            give_back(head);
        }
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

impl<K, N: CountKind> CellRc<K, N> {
    /// `value` in a cell of its own on the heap, its handles counted by `N`. `None`, with
    /// `value` let go of, when the heap refuses the cell: the program goes on.
    pub fn try_on_heap(value: K) -> Option<Self> {
        Self::in_cells_of(None, value).ok()
    }

    /// The handle of the cell `head` heads, its value written from `value`.
    ///
    /// # Safety
    /// `head` heads a cell laid out for `Slot<K, N::Flag>`, its head written with one handle, its
    /// value not written, and no handle names it yet.
    unsafe fn fill(head: NonNull<CellHead<N::Flag>>, value: K) -> Self {
        let slot = head.cast::<Slot<K, N::Flag>>().as_ptr();
        // SAFETY: the caller's contract: the cell is a slot of `K` that only this call reaches, so
        // its value's place is aligned for `K`, written once here, and never null.
        unsafe {
            let at = core::ptr::addr_of_mut!((*slot).value);
            at.write(value);
            Self {
                head,
                value: NonNull::new_unchecked(at),
                _owns: PhantomData,
                _count: PhantomData,
            }
        }
    }

    /// [`CellRc::in_cells`] for handles counted by `N`, of a table whose flags are the form
    /// `N` gives a cell back by.
    pub fn in_cells_of(cells: Option<&LentByteCells<N::Flag>>, value: K) -> Result<Self, K> {
        match head_in(
            cells,
            Layout::new::<Slot<K, N::Flag>>(),
            Slot::<K, N::Flag>::WHOLE,
            Slot::<K, N::Flag>::PLACE,
        ) {
            // SAFETY: the head heads a cell of `Slot<K, N::Flag>`'s layout, written with one
            // handle, whose value this writes.
            Some(head) => Ok(unsafe { Self::fill(head, value) }),
            None => Err(value),
        }
    }

    /// The bytes of a cell that holds a `K` counted by `N`, a whole number of an arena's
    /// alignments: what a cell `Self::in_cells_of` made on the heap asked of it.
    pub const fn cell_bytes_of() -> usize {
        match size_of::<Slot<K, N::Flag>>().checked_next_multiple_of(ARENA_ALIGN) {
            Some(bytes) => bytes,
            None => usize::MAX,
        }
    }

    /// [`CellRc::claim`] for handles counted by `N`, of a table whose flags are the form `N`
    /// gives a cell back by.
    pub fn claim_of(cells: Option<&LentByteCells<N::Flag>>) -> Option<CellClaim<K, N>> {
        let head = head_in(
            cells,
            Layout::new::<Slot<K, N::Flag>>(),
            Slot::<K, N::Flag>::WHOLE,
            Slot::<K, N::Flag>::PLACE,
        )?;
        Some(CellClaim {
            head,
            _owns: PhantomData,
        })
    }
}

impl<K> CellRc<K> {
    /// `value` in a cell of `cells`, or `value` back when every cell is taken or a cell is too
    /// small for it, or not aligned for it.
    pub fn place(cells: &LentByteCells, value: K) -> Result<Self, K> {
        Self::in_cells_of(Some(cells), value)
    }

    /// `value` in a cell of `cells` when a table is lent, or `value` back when none of its cells
    /// takes it ([`Self::place`]); in a cell of its own on the heap when no table is
    /// ([`Self::try_boxed`]), or `value` back when the heap refuses the cell. What every maker of a link's part asks, whichever memory the session
    /// lends. The cell is made by `head_in`, out of line; what is left here, for each kind of
    /// value, is moving the value into it.
    pub fn in_cells(cells: Option<&LentByteCells>, value: K) -> Result<Self, K> {
        Self::in_cells_of(cells, value)
    }

    /// A cell for a value of `K`, claimed and not yet written: one of `cells` when a table is
    /// lent, `None` when every cell is taken or a cell is too small or not aligned for it, and one
    /// of its own on the heap when none is ([`Self::in_cells`]). Its value is written in it where
    /// it stays ([`CellClaim::made`]); one let go of unwritten goes back. `None` too when the
    /// heap refuses the cell.
    pub fn claim(cells: Option<&LentByteCells>) -> Option<CellClaim<K>> {
        Self::claim_of(cells)
    }

    /// `value` in a cell of its own on the heap: the handle of a link lent no table. `None`, with
    /// `value` let go of, when the heap refuses the cell.
    pub fn try_boxed(value: K) -> Option<Self> {
        Self::try_on_heap(value)
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

/// A cell claimed for a value of `K` and not yet written ([`CellRc::claim`]). The cell is had
/// before its value's maker is formed, so what the value is made of goes into the cell from where
/// it lies, and a refused cell lets go of it there, never gathered into a maker first. Let go of
/// unwritten, the cell goes back where it came from.
pub struct CellClaim<K, N: CountKind = OneTask> {
    head: NonNull<CellHead<N::Flag>>,
    _owns: PhantomData<(K, fn() -> N)>,
}

impl<K, N: CountKind> CellClaim<K, N> {
    pub fn made(self, make: impl FnOnce(&mut MaybeUninit<K>) -> &mut K) -> Option<CellRc<K, N>> {
        let slot = self.head.cast::<Slot<K, N::Flag>>().as_ptr();
        // SAFETY: the claim heads a cell of `Slot<K>`'s layout that only it reaches.
        let at = unsafe { core::ptr::addr_of_mut!((*slot).value) };
        // SAFETY: the value's place is aligned for `K`, not yet written and reached by nothing
        // else, and `MaybeUninit<K>` lays out as a `K`.
        let made: *mut K = make(unsafe { &mut *at.cast::<MaybeUninit<K>>() });
        if !core::ptr::eq(made, at) {
            // Whatever the maker wrote elsewhere stays the maker's: the claim, let go of here,
            // gives the cell back without reading its value.
            return None;
        }
        let head = self.head;
        core::mem::forget(self);
        Some(CellRc {
            head,
            // SAFETY: the place of a cell's value, which is never null.
            value: unsafe { NonNull::new_unchecked(at) },
            _owns: PhantomData,
            _count: PhantomData,
        })
    }
}

impl<K, N: CountKind> Drop for CellClaim<K, N> {
    fn drop(&mut self) {
        // SAFETY: a claim still held is of a cell no handle names, whose value is not written
        // whole and is not dropped: it is not read before the cell goes back.
        unsafe { give_back(self.head) }
    }
}

impl<A, B> CellRc<(A, B)> {
    /// `first` and `second` together in one cell of `cells` ([`Self::in_cells`], or one of the
    /// heap when no table is lent), and a handle on each: two values that are made together and
    /// shared apart, the cell given back with the last handle on either, which drops both. Both
    /// back when no cell takes them or the heap refuses one.
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
    /// takes them or the heap refuses one, `write` not called and let go of with what it holds.
    ///
    /// # Safety
    /// `write` leaves a whole `A` at the first place it is handed and a whole `B` at the second
    /// when it returns. One that unwinds keeps the cell, which is then never given back.
    pub unsafe fn halves_in(
        cells: Option<&LentByteCells>,
        write: impl FnOnce(*mut A, *mut B),
    ) -> Option<(CellRc<A>, CellRc<B>)> {
        // SAFETY: the caller's contract, which is this call's.
        unsafe { Self::halves_in_of(cells, write) }
    }
}

impl<A, B, N: CountKind> CellRc<(A, B), N> {
    /// [`CellRc::halves_in`] for handles counted by `N`, of a table whose flags are the form
    /// `N` gives a cell back by.
    ///
    /// # Safety
    /// As [`CellRc::halves_in`].
    pub unsafe fn halves_in_of(
        cells: Option<&LentByteCells<N::Flag>>,
        write: impl FnOnce(*mut A, *mut B),
    ) -> Option<(CellRc<A, N>, CellRc<B, N>)> {
        let head = head_in(
            cells,
            Layout::new::<Slot<(A, B), N::Flag>>(),
            Slot::<(A, B), N::Flag>::WHOLE,
            Slot::<(A, B), N::Flag>::PLACE,
        )?;
        let slot = head.cast::<Slot<(A, B), N::Flag>>().as_ptr();
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
                _count: PhantomData,
            }
        };
        Some(pair.into_halves())
    }

    /// This handle on a pair as one handle on each of its halves, the cell given back with the
    /// last of them, which drops the pair whole.
    fn into_halves(self) -> (CellRc<A, N>, CellRc<B, N>) {
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

impl<T: ?Sized, N: CountKind> CellRc<T, N> {
    /// This handle as one on a part of its value, `as_part` answering where the part lies.
    ///
    /// # Safety
    /// `as_part` answers a pointer to a value that lives as long as the value it is handed: the
    /// last handle drops the whole value placed, through the cell's `whole`, never the part.
    unsafe fn part<U>(self, as_part: impl FnOnce(NonNull<T>) -> NonNull<U>) -> CellRc<U, N> {
        let this = core::mem::ManuallyDrop::new(self);
        CellRc {
            head: this.head,
            value: as_part(this.value),
            _owns: PhantomData,
            _count: PhantomData,
        }
    }

    /// This handle as one on `U`, the value seen through `as_u`: a trait object of it.
    ///
    /// # Safety
    /// `as_u` answers a pointer to the same value it is handed (an unsizing coercion), so the
    /// handle reads the value that was placed, which the last handle drops through the cell's
    /// `whole`.
    pub unsafe fn unsize<U: ?Sized>(
        self,
        as_u: impl FnOnce(NonNull<T>) -> NonNull<U>,
    ) -> CellRc<U, N> {
        let this = core::mem::ManuallyDrop::new(self);
        CellRc {
            head: this.head,
            value: as_u(this.value),
            _owns: PhantomData,
            _count: PhantomData,
        }
    }

    /// How many handles name the value `this` names, `this` among them.
    pub fn handles(this: &Self) -> usize {
        N::read(&this.head().word).wrapping_shr(PLACE_BITS)
    }

    /// The value `this` names, as an address: two live handles name one value exactly when
    /// theirs are equal. A released cell's address can name the next value placed in it.
    pub fn as_ptr(this: &Self) -> *const T {
        this.value.as_ptr()
    }

    /// The cell's head.
    fn head(&self) -> &CellHead<N::Flag> {
        // SAFETY: a handle keeps its cell, so the head is live for as long as the handle is.
        unsafe { self.head.as_ref() }
    }
}

impl<K: BoxedLinkDriver + 'static, N: CountKind> CellRc<K, N> {
    /// This handle as the one the session's actions send through.
    pub fn into_sink(self) -> CellRc<dyn BoxedLinkDriver, N> {
        // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
        unsafe { self.unsize(|value| -> NonNull<dyn BoxedLinkDriver> { value }) }
    }
}

impl<K: SessionDatagramLink + 'static, N: CountKind> CellRc<K, N> {
    /// This handle as the link the session's drive loop pumps.
    pub fn into_link(self) -> CellRc<dyn SessionDatagramLink, N> {
        // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
        unsafe { self.unsize(|value| -> NonNull<dyn SessionDatagramLink> { value }) }
    }
}

/// `driver` in a cell of its own on the heap, as the session's actions send through it: the sink
/// of a link no table lends a cell. `None`, with `driver` let go of, when the heap refuses the
/// cell.
pub fn heap_sink<K: BoxedLinkDriver + 'static>(driver: K) -> Option<CellRc<dyn BoxedLinkDriver>> {
    CellRc::try_boxed(driver).map(CellRc::into_sink)
}

impl<T: ?Sized, N: CountKind> Deref for CellRc<T, N> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a handle keeps its cell, and the cell its value, for as long as the handle is;
        // the value is only ever read through shared references.
        unsafe { self.value.as_ref() }
    }
}

/// How often, in this process, a cell was held by a clone past the most its count holds, which
/// keeps that cell's value for good. Never, but for a program that holds more handles than its
/// address space has room for; a test build stops at the first.
pub fn held_past_count() -> usize {
    HELD_PAST_COUNT.load(Ordering::Relaxed)
}

/// Count one more handle on the cell `head` heads; past the most its count holds, keep the count
/// there, which keeps the value for good ([`let_go`]), and count the clone
/// ([`held_past_count`]). Out of line: the one body of every handle's clone.
#[inline(never)]
fn hold<N: CountKind>(head: &CellHead<N::Flag>) {
    let was = N::update(&head.word, |word| word.checked_add(ONE_HANDLE));
    let past = was.checked_add(ONE_HANDLE).is_none();
    debug_assert!(
        !past,
        "a cell was held by more handles than its count holds"
    );
    if past {
        HELD_PAST_COUNT.store(
            HELD_PAST_COUNT.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
    }
}

impl<T: ?Sized, N: CountKind> Clone for CellRc<T, N> {
    fn clone(&self) -> Self {
        hold::<N>(self.head());
        Self {
            head: self.head,
            value: self.value,
            _owns: PhantomData,
            _count: PhantomData,
        }
    }
}

impl<T: ?Sized, N: CountKind> Drop for CellRc<T, N> {
    fn drop(&mut self) {
        // SAFETY: the handle names its cell, whose value was placed and not dropped, and is let
        // go of here once.
        unsafe { let_go::<N>(self.head) }
    }
}

/// A kind of value one face keeps its link's parts in (its pump, its actions, its sink), whose
/// handles are counted for one task ([`OneFace`]) and so are not `Send` one by one: what
/// [`FaceHeld`] moves between threads whole.
///
/// # Safety
///
/// A value of the type is not `Send` only because of handles, cells and counts whose every other
/// holder is a part of the same value: it holds nothing bound to the thread it was made on (a
/// guard of a lock, a value a thread-local names), and the drop of any of its parts may run on
/// any thread once the whole value has moved there.
pub unsafe trait FaceParts: 'static {}

/// The parts of one face's link, held together: every handle on a cell of the link that any code
/// holds is a part of [`Self`], so the whole moves to another thread with nothing left behind
/// that names what it moved. Its parts are reached only while it is lent ([`Self::lend`]), and a
/// lend neither takes a value that is not `Send` in nor answers one out, so a clone of a handle
/// made in a lend stays in the parts, and no handle made outside them comes in. What a face's lock
/// holds (`crate::sync::FacePlace`) where several threads drive a session's faces.
pub struct FaceHeld<X: FaceParts> {
    parts: X,
}

// SAFETY: every handle on the cells of the parts is a part of `parts` (`gather` takes the parts
// from a `Send` closure, which captures no handle made elsewhere, and `lend` takes and answers
// only `Send` values, which no handle counted for one task is), and nothing of them is bound to a
// thread (`FaceParts`' contract). So the counts and cells that are not atomic are reached by the
// thread that holds the whole value alone, as one task's are, wherever it moved.
unsafe impl<X: FaceParts> Send for FaceHeld<X> {}

impl<X: FaceParts> FaceHeld<X> {
    /// The parts `make` makes, held together. `make` is `Send`, so it captures no handle of a
    /// link made outside it, and what it keeps of the handles it makes is what it answers.
    pub fn gather(make: impl FnOnce() -> X + Send) -> Self {
        Self { parts: make() }
    }

    /// `parts` made outside a [`Self::gather`], held together.
    ///
    /// # Safety
    ///
    /// No handle on a cell of `parts` lives outside `parts`: the caller let go of every clone it
    /// made of one while it built them.
    pub unsafe fn gathered(parts: X) -> Self {
        Self { parts }
    }

    /// Lend the parts to `f`, and answer what it answers. `f` and its answer are `Send`, so no
    /// handle on a cell of the parts leaves them and none comes into them.
    #[inline]
    pub fn lend<U: Send>(&mut self, f: impl FnOnce(&mut X) -> U + Send) -> U {
        f(&mut self.parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use core::cell::Cell;

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

    impl Named for Wide {
        fn name(&self) -> u32 {
            self.0.name()
        }
    }

    /// A table of two cells of `size` bytes, in memory of the test's own, lent as a session's
    /// arena lends its tables.
    fn table(size: usize) -> LentByteCells {
        table_of::<Cell<bool>>(size)
    }

    /// [`table`] with flags of the form `F`.
    fn table_of<F: CellFlag>(size: usize) -> LentByteCells<F> {
        use wz_session_core::bounded::Arena;

        const BYTES: usize = 1024;
        #[repr(C, align(16))]
        struct Memory([u8; BYTES]);

        let memory: &'static mut Memory = Box::leak(Box::new(Memory([0; BYTES])));
        // SAFETY: the memory is leaked, so it outlives the arena, the table and every claim of
        // it; it is aligned as an arena's spans start, BYTES long, and used by nothing else.
        let mut arena = unsafe { Arena::over(NonNull::from(memory).cast::<u8>(), BYTES) };
        arena
            .lend_byte_cells_of::<F>(size, 2)
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

    /// A value made in a cell is made only once a cell is had for it: past the table's cells it is
    /// not made and what its maker holds is let go of, and with no table it is made on the heap.
    /// Turned red by a claim that calls a maker before its cell is had, or one kept past a refusal.
    #[test]
    fn a_value_is_made_in_its_cell_and_not_made_when_no_cell_takes_it() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        fn make(
            made: &Cell<u32>,
            held: Counted,
        ) -> impl FnOnce(&mut MaybeUninit<Counted>) -> &mut Counted + '_ {
            move |place| {
                made.set(made.get().saturating_add(1));
                place.write(held)
            }
        }
        let made = Cell::new(0u32);
        let made_in = |cells: Option<&LentByteCells>, maker| {
            CellRc::<Counted>::claim(cells).and_then(|cell| cell.made(maker))
        };
        let first = made_in(Some(&cells), make(&made, Counted(drops.clone()))).expect("a cell");
        let second = made_in(Some(&cells), make(&made, Counted(drops.clone()))).expect("a cell");
        assert_eq!((made.get(), cells.in_use()), (2, 2));
        let refused = made_in(Some(&cells), make(&made, Counted(drops.clone())));
        assert!(refused.is_none(), "past the table's cells");
        assert_eq!(
            (made.get(), drops.get()),
            (2, 1),
            "the refused value was never made, and what its maker held is dropped"
        );
        let boxed = made_in(None, make(&made, Counted(drops.clone()))).expect("the heap");
        assert_eq!(
            (made.get(), cells.in_use()),
            (3, 2),
            "the heap's takes no cell"
        );
        assert_eq!(first.name(), 7);
        drop((first, second, boxed));
        assert_eq!((drops.get(), cells.in_use()), (4, 0));
    }

    /// A value is made in the place its handle names: the place its maker is handed, and lends
    /// back, is the value's. Turned red by a cell that hands its maker a place of a frame and
    /// moves what was written there into the cell.
    #[test]
    fn a_value_is_made_where_its_handle_names_it() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let mut handed: *const Counted = core::ptr::null();
        let made = CellRc::claim(Some(&cells))
            .expect("a cell")
            .made(|place| {
                handed = place.as_ptr();
                place.write(Counted(drops.clone()))
            })
            .expect("made in its cell");
        assert!(
            core::ptr::eq(handed, &*made),
            "made where its handle names it"
        );
        drop(made);
        assert_eq!((drops.get(), cells.in_use()), (1, 0));
    }

    /// A maker that lends back a place other than the one it was handed has not written its cell:
    /// it is refused, its cell given back, and nothing in the cell is dropped. Turned red by a cell
    /// that takes the maker's word for it.
    #[test]
    fn a_maker_that_lends_back_another_place_is_refused_and_its_cell_given_back() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let elsewhere: *mut Counted = Box::into_raw(Box::new(Counted(drops.clone())));
        // SAFETY: the box is this test's alone until it is taken back below, and nothing else
        // reaches it while the maker lends it.
        let refused = CellRc::claim(Some(&cells))
            .expect("a cell")
            .made(|_place| unsafe { &mut *elsewhere });
        assert!(refused.is_none(), "a value not written in its cell");
        assert_eq!(
            (drops.get(), cells.in_use()),
            (0, 0),
            "the cell is given back and nothing is dropped"
        );
        // SAFETY: the box came from `Box::into_raw` above, and nothing holds it now.
        drop(unsafe { Box::from_raw(elsewhere) });
        assert_eq!(drops.get(), 1);
    }

    /// A cell claimed and let go of before anything is made in it goes back to its table, and a
    /// table claimed full refuses one more. Turned red by a claim that keeps its cell when it is
    /// let go of unwritten.
    #[test]
    fn a_claim_let_go_of_unwritten_gives_its_cell_back() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let first = CellRc::<Counted>::claim(Some(&cells)).expect("a cell");
        let second = CellRc::<Counted>::claim(Some(&cells)).expect("a cell");
        assert_eq!(cells.in_use(), 2);
        assert!(
            CellRc::<Counted>::claim(Some(&cells)).is_none(),
            "past the table's cells"
        );
        drop(first);
        assert_eq!(cells.in_use(), 1, "the unwritten claim went back");
        drop(second);
        assert_eq!(cells.in_use(), 0);
    }

    /// A value larger than a cell is refused, with the value handed back, and takes no cell.
    #[test]
    fn a_value_larger_than_a_cell_is_refused() {
        let cells = table(ARENA_ALIGN);
        assert!(!CellRc::<[u64; 4]>::fits(ARENA_ALIGN));
        assert!(CellRc::place(&cells, [7u64; 4]).is_err());
        assert_eq!(cells.in_use(), 0);
    }

    /// A value lent no table whose cell the heap refuses is handed back, a claim of such a cell
    /// is none and halves are both handed back: the refusal is the caller's to answer, and the
    /// program goes on. Turned red by a heap cell that ends the program when the heap refuses it.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_cell_the_heap_refuses_hands_its_value_back() {
        let drops = Rc::new(Cell::new(0));
        let (one, claimed, pair) = crate::table_tests::refused(|| {
            (
                CellRc::in_cells(None, Counted(drops.clone())),
                CellRc::<Counted>::claim(None).is_some(),
                CellRc::halves(None, Counted(drops.clone()), 7u32),
            )
        });
        let one = one.err().expect("the value handed back");
        let (first, second) = pair.err().expect("both halves handed back");
        assert_eq!((claimed, second, drops.get()), (false, 7, 0));
        drop((one, first));
        assert_eq!(
            drops.get(),
            2,
            "each value is the caller's again, dropped once"
        );
        let placed = CellRc::in_cells(None, Counted(drops.clone()))
            .ok()
            .expect("a cell of the heap once it gives one");
        assert_eq!(placed.name(), 7);
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
        let boxed = CellRc::try_boxed(Counted(drops.clone())).expect("the heap has room");
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

    /// A heap that refuses a cell of its own answers `None` and lets the value go, and the
    /// program goes on; a sink and a pump share the answer. Turned red by `try_boxed` making its
    /// cell with a maker that ends the program on a refused heap, or keeping the value past the
    /// refusal.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_cell_the_heap_refuses_is_none_and_lets_its_value_go() {
        let drops = Rc::new(Cell::new(0));
        let refused =
            crate::table_tests::refused(|| CellRc::try_boxed(Counted(drops.clone())).is_none());
        assert!(refused, "a refused heap makes no cell");
        assert_eq!(drops.get(), 1, "the value is let go of");
        let kept = CellRc::try_boxed(Counted(drops.clone())).expect("the heap has room");
        drop(kept);
        assert_eq!(
            drops.get(),
            2,
            "a heap with room holds the value until its last handle"
        );
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
        let boxed = CellRc::try_boxed(Wide(Counted(drops.clone()))).expect("the heap has room");
        for handle in [&placed, &boxed] {
            assert_eq!((CellRc::as_ptr(handle) as usize).checked_rem(16), Some(0));
            assert_eq!(handle.0.name(), 7);
        }
        assert_eq!(cells.in_use(), 1);
        drop((placed, boxed));
        assert_eq!((drops.get(), cells.in_use()), (2, 0));
    }

    /// A value aligned past the head, seen as a trait object, is dropped once by its last handle,
    /// from the place it lies at, in a table's cell and on the heap. Turned red by a head that
    /// hands its drop the place just past itself, where such a value does not lie.
    #[test]
    fn a_wide_value_seen_as_a_trait_object_is_dropped_where_it_lies() {
        let cells = table(CellRc::<Wide>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        for lent in [Some(&cells), None] {
            let handle = CellRc::in_cells(lent, Wide(Counted(drops.clone())))
                .ok()
                .expect("a cell, or the heap");
            // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
            let named: CellRc<dyn Named> =
                unsafe { handle.unsize(|value| -> NonNull<dyn Named> { value }) };
            assert_eq!(named.name(), 7);
            drop(named);
        }
        assert_eq!((drops.get(), cells.in_use()), (2, 0));
    }

    /// The place a head keeps for its value is the one `repr(C)` lays the slot out with, for a
    /// value aligned as the head is and for one aligned past it, and the head with it is no larger
    /// than one with a count of a word. Turned red by a place counted otherwise, or by a head
    /// that grows every cell.
    #[test]
    fn a_heads_place_of_its_value_is_the_slots_and_costs_no_room() {
        assert_eq!(
            value_at(Slot::<Counted>::PLACE),
            core::mem::offset_of!(Slot<Counted>, value)
        );
        assert_eq!(
            value_at(Slot::<Wide>::PLACE),
            core::mem::offset_of!(Slot<Wide>, value)
        );
        assert!(value_at(Slot::<Wide>::PLACE) > size_of::<CellHead>());
        assert_eq!(
            size_of::<CellHead>(),
            size_of::<(CountWord, Owner, DropWhole)>()
        );
    }

    /// A value of several threads that counts its drops.
    struct DropsOnce(alloc::sync::Arc<AtomicUsize>);

    impl Drop for DropsOnce {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A value either kind of count shares is reached by one holder at a time: a try inside a
    /// hold finds it held and does not run, and runs once the hold is let go. Turned red by a try
    /// that runs inside a hold, a second `&mut` of the value.
    #[test]
    fn a_shared_value_is_reached_by_one_holder_at_a_time() {
        fn one_at_a_time<N: CountKind>() {
            let local = N::new_local(0u32);
            N::with_local::<u32, ()>(&local, |value| {
                *value += 1;
                assert_eq!(
                    N::try_with_local::<u32, ()>(&local, |_| ()),
                    None,
                    "the value is held"
                );
            });
            assert_eq!(
                N::try_with_local::<u32, u32>(&local, |value| *value),
                Some(1)
            );
        }
        one_at_a_time::<OneTask>();
        #[cfg(target_has_atomic = "8")]
        one_at_a_time::<Atomic>();
    }

    /// Handles counted as an `Arc`'s are may cross threads, as handles counted for one task may
    /// not. Turned red by an atomic handle that is not `Send` or not `Sync`.
    #[test]
    fn an_atomic_handle_crosses_threads() {
        fn crosses<T: Send + Sync>() {}
        crosses::<CellRc<u32, Atomic>>();
        crosses::<CellRc<dyn Fn() + Send + Sync, Atomic>>();
    }

    /// Clones of one atomic handle made and let go of on several threads at once keep one count:
    /// the value is dropped once, by the last handle, and not before. Turned red by a count
    /// changed with a load and a store, which loses a clone or a let go when two threads race.
    #[test]
    fn atomic_handles_let_go_on_several_threads_drop_the_value_once() {
        extern crate std;
        let drops = alloc::sync::Arc::new(AtomicUsize::new(0));
        let handle =
            CellRc::<_, Atomic>::try_on_heap(DropsOnce(drops.clone())).expect("the heap has room");
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let mine = handle.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        drop(mine.clone());
                    }
                    drop(mine);
                });
            }
        });
        assert_eq!(drops.load(Ordering::SeqCst), 0, "one handle is left");
        assert_eq!(CellRc::handles(&handle), 1);
        drop(handle);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the last handle dropped it once"
        );
    }

    /// A handle counted as an `Arc`'s is, placed in a table of atomic flags, keeps its cell while
    /// a clone does, and the last handle, let go of on another thread than the one that placed it,
    /// drops the value once and gives the cell back to the table. Turned red by an atomic handle
    /// refused a table's cell, or a last let go that does not clear the cell's flag.
    #[cfg(target_has_atomic = "8")]
    #[test]
    fn an_atomic_handle_in_a_table_gives_its_cell_back_on_another_thread() {
        extern crate std;
        let cells = table_of::<AtomicBool>(CellRc::<DropsOnce>::cell_bytes());
        let drops = alloc::sync::Arc::new(AtomicUsize::new(0));
        let Ok(handle) =
            CellRc::<DropsOnce, Atomic>::in_cells_of(Some(&cells), DropsOnce(drops.clone()))
        else {
            panic!("a free cell of the table");
        };
        assert_eq!(cells.in_use(), 1);
        let theirs = handle.clone();
        std::thread::scope(|scope| {
            scope.spawn(move || drop(theirs));
        });
        assert_eq!(cells.in_use(), 1, "a handle is left");
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        std::thread::scope(|scope| {
            scope.spawn(move || drop(handle));
        });
        assert_eq!(drops.load(Ordering::SeqCst), 1, "dropped once");
        assert_eq!(cells.in_use(), 0, "the cell is back in the table");
    }

    /// The count of `handle`'s cell set to the most its word holds, its place kept.
    fn count_at_its_most<T: ?Sized>(handle: &CellRc<T>) {
        let word = &handle.head().word;
        word.store(
            !PLACE_MASK | (word.load(Ordering::Relaxed) & PLACE_MASK),
            Ordering::Relaxed,
        );
    }

    /// A count held at its most keeps its value for good: a handle let go of then does not count
    /// down, so no later handle drops the value under one the count missed. Turned red by a let go
    /// that counts down from the most.
    #[test]
    fn a_count_held_at_its_most_keeps_its_value() {
        let cells = table(CellRc::<Counted>::cell_bytes());
        let drops = Rc::new(Cell::new(0));
        let handle = CellRc::place(&cells, Counted(drops.clone()))
            .ok()
            .expect("a cell");
        let other = handle.clone();
        count_at_its_most(&handle);
        let most = CellRc::handles(&handle);
        assert_eq!(most, usize::MAX.wrapping_shr(PLACE_BITS));
        drop(handle);
        assert_eq!(
            (CellRc::handles(&other), drops.get(), other.name()),
            (most, 0, 7),
            "the count stays at its most and the value lives"
        );
        drop(other);
        assert_eq!((drops.get(), cells.in_use()), (0, 1), "kept for good");
    }

    /// A clone past the most a count holds is named in a test build. Turned red by a clone that
    /// passes the count in silence.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a cell was held by more handles than its count holds")]
    fn a_clone_past_the_count_is_named_in_a_test_build() {
        let handle = CellRc::try_boxed(7u32).expect("the heap has room");
        count_at_its_most(&handle);
        let _ = handle.clone();
    }

    /// A clone past the most a count holds is counted, and the count stays at its most. Turned
    /// red by a clone that passes the count uncounted, or one that wraps it.
    #[cfg(not(debug_assertions))]
    #[test]
    fn a_clone_past_the_count_is_counted_and_keeps_the_count() {
        let handle = CellRc::try_boxed(7u32).expect("the heap has room");
        count_at_its_most(&handle);
        let before = held_past_count();
        let clone = handle.clone();
        assert_eq!(
            (held_past_count(), CellRc::handles(&clone)),
            (
                before.saturating_add(1),
                usize::MAX.wrapping_shr(PLACE_BITS)
            )
        );
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

    /// The parts of a face in the tests below: two handles on one value.
    #[cfg(target_has_atomic = "8")]
    struct Parts {
        first: CellRc<DropsOnce, OneFace>,
        second: CellRc<DropsOnce, OneFace>,
    }

    // SAFETY: the parts are two handles on one cell, which no other value holds, and nothing
    // bound to a thread.
    #[cfg(target_has_atomic = "8")]
    unsafe impl FaceParts for Parts {}

    /// A handle counted for one face does not cross threads alone, so a lend, whose closure and
    /// answer do, neither takes one in nor answers one out; the parts held together do cross.
    /// Turned red, at build, by a `Send` handle of one face (the call below is then ambiguous),
    /// or by held parts that are not `Send`.
    #[cfg(target_has_atomic = "8")]
    #[test]
    fn a_faces_handle_crosses_threads_only_with_the_parts_it_is_held_in() {
        trait AmbiguousIfSend<A> {
            fn some_item() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
        <CellRc<u32, OneFace> as AmbiguousIfSend<_>>::some_item();
        fn crosses<T: Send>() {}
        crosses::<FaceHeld<Parts>>();
    }

    /// Parts placed in a table of atomic flags move to another thread whole: a clone made in a
    /// lend counts with the parts' handles and goes with the lend, and the last handle, let go of
    /// on that thread, drops the value once and gives the cell back to the table. Turned red by a
    /// handle of the parts that outlives them, or a last let go that does not clear the cell's flag.
    #[cfg(target_has_atomic = "8")]
    #[test]
    fn a_faces_parts_move_whole_and_their_handles_stay_in_them() {
        extern crate std;
        let cells = table_of::<AtomicBool>(CellRc::<DropsOnce>::cell_bytes());
        let drops = alloc::sync::Arc::new(AtomicUsize::new(0));
        let mut held = FaceHeld::gather(|| {
            let Ok(first) =
                CellRc::<DropsOnce, OneFace>::in_cells_of(Some(&cells), DropsOnce(drops.clone()))
            else {
                panic!("a free cell of the table");
            };
            let second = first.clone();
            Parts { first, second }
        });
        assert_eq!(held.lend(|parts| CellRc::handles(&parts.first)), 2);
        assert_eq!(cells.in_use(), 1);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let counted = held.lend(|parts| {
                    let third = parts.first.clone();
                    CellRc::handles(&third)
                });
                assert_eq!(
                    counted, 3,
                    "a clone made in a lend counts with the parts' handles"
                );
                assert_eq!(
                    held.lend(|parts| CellRc::handles(&parts.second)),
                    2,
                    "and went with the lend"
                );
                drop(held);
            });
        });
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "dropped once, on the other thread"
        );
        assert_eq!(cells.in_use(), 0, "the cell is back in the table");
    }
}
