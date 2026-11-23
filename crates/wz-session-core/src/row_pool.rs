// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rows the faces of a session keep what their peers write in: for a session of many faces one
//! pool of each kind of row that they share, and for a session of one face a span of that face's
//! own for each table (`docs/c-abi-no-heap-pools.md`, section 4.5).
//!
//! # Why
//!
//! A table a peer writes is bounded for each peer (`MAX_REMOTE_DECLS` and its kin), and a session
//! that holds many peers reserving that bound for each of them reserves its faces times the worst
//! one. zenoh-pico takes each such row from its heap as it comes, with no bound. A pool sized by
//! what the whole session may hold keeps the bound of each peer, reserves the session's sum once,
//! and a peer that declares little leaves its share to the others. A session of one face has no
//! one to share with: its tables take the rows of their bound in spans of their own, laid out as
//! an inline table lays them out, and carry no link and no pool state.
//!
//! # Two layouts of one kind of row
//!
//! A kind of row ([`RowKind`]) is laid out twice. In a table's own span a row is the item itself,
//! [`Seq`]'s value or [`Keyed`]'s `(id, value)`, packed as an inline table packs it. In a shared
//! pool a row is a slot that also carries its [`Link`]: the next row of the table that holds it and
//! a generation, two `u16`s, declared beside the item's own fields so they take what the item's
//! alignment would leave as padding where there is any (`KeyedSlot`).
//!
//! # Rows and handles of a shared pool
//!
//! A row is taken from the free list, or else from the rows no table has touched yet, and given
//! back to the free list. Its generation moves when it is taken and when it is given back, odd
//! while it is held: a [`RowHandle`] names a row and the generation it was taken at, so a handle
//! kept past the row's return names nothing rather than the row's next holder. A pool names its
//! rows by `u16`, so it holds at most [`MAX_POOL_ROWS`], which a session's open holds its limits
//! to.
//!
//! A [`PooledRows`] is one table: in a shared pool the rows it holds, in the order they were pushed,
//! linked through the rows; in a span of its own the rows from the span's start. Either way it is a
//! few words wherever it lies. A lookup walks the table's own rows, as a scan of an inline table
//! does; clearing or dropping the table gives back exactly its rows, one step each.
//!
//! # Refusal
//!
//! A push past the table's own bound `N`, past its span's rows, or that its pool has no row for,
//! is refused as a full inline table refuses it, the value handed back and counted by the table
//! ([`PooledRows::refusals`]); a shared pool counts what it refused too ([`RowCounts::refused`]).
//!
//! # One thread, and the lifetime
//!
//! As the key arena's ([`crate::key_arena`]): a pool's state is kept in cells, so a [`RowSpace`]
//! and every table that holds one are neither `Send` nor `Sync`, and every table that holds rows
//! of a space is dropped before the memory the arena was reserved from is given back.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, addr_of, addr_of_mut, NonNull};

use crate::bounded::{Arena, BoundedVec, CapacityFull, Storage};

/// No row: the end of a list and of the free list, and the first row of an empty shared table.
const NIL: u16 = u16::MAX;

/// The mark of a table whose rows are a span of its own: its `first` is this and its rows.
const DENSE: u16 = 0x8000;

/// The most rows a pool, or a table's own span, holds: a row is named by a `u16` below
/// [`DENSE`]'s bit, and the largest of those is no row.
pub const MAX_POOL_ROWS: usize = 0x7FFE;

/// What a row of a shared pool carries besides its item: the next row of the table, or of the free
/// list, that holds it, and its generation.
#[derive(Clone, Copy, Debug)]
pub struct Link {
    next: u16,
    generation: u16,
}

/// A kind of row, in its two layouts: the item a table's own span holds, and the slot of a shared
/// pool, which carries the item and a [`Link`].
///
/// # Safety
///
/// [`Self::link`] points at a [`Link`] inside the slot that no other method reads or writes, so
/// the pool may keep the link of a row whose item is not there, and the item's methods touch only
/// the item's fields.
pub unsafe trait RowKind {
    /// What a table puts in and takes out, and what its own span holds.
    type Item;
    /// A row of a shared pool.
    type Slot;
    /// What reading a row hands out.
    type Ref<'a>
    where
        Self: 'a;
    /// What writing a row hands out.
    type Mut<'a>
    where
        Self: 'a;

    /// The link of the slot at `slot`.
    ///
    /// # Safety
    /// `slot` points into a slot of a pool's rows, which need not hold an item.
    unsafe fn link(slot: *mut Self::Slot) -> *mut Link;

    /// Write `item` into the slot at `slot`, its link untouched.
    ///
    /// # Safety
    /// `slot` points at a slot that holds no item.
    unsafe fn put(slot: *mut Self::Slot, item: Self::Item);

    /// Read the item out of the slot at `slot`, which holds none after.
    ///
    /// # Safety
    /// `slot` points at a slot that holds an item.
    unsafe fn take(slot: *mut Self::Slot) -> Self::Item;

    /// The item of the slot at `slot`, to read.
    ///
    /// # Safety
    /// `slot` points at a slot that holds an item, which nothing writes for `'a`.
    unsafe fn slot_ref<'a>(slot: *const Self::Slot) -> Self::Ref<'a>
    where
        Self: 'a;

    /// The item of the slot at `slot`, to write.
    ///
    /// # Safety
    /// `slot` points at a slot that holds an item, which nothing else reaches for `'a`.
    unsafe fn slot_mut<'a>(slot: *mut Self::Slot) -> Self::Mut<'a>
    where
        Self: 'a;

    /// An item of a table's own span, to read.
    fn item_ref<'a>(item: &'a Self::Item) -> Self::Ref<'a>
    where
        Self: 'a;

    /// An item of a table's own span, to write.
    fn item_mut<'a>(item: &'a mut Self::Item) -> Self::Mut<'a>
    where
        Self: 'a;
}

/// The kind of row of a sequence of `T` (an interest, a repeat): the item is the value.
pub struct Seq<T> {
    _item: PhantomData<T>,
}

/// A row of a shared pool of [`Seq`]: the value and its link.
pub struct SeqSlot<T> {
    item: T,
    link: Link,
}

// SAFETY: the link is a field of its own, which no method of the item reaches.
unsafe impl<T> RowKind for Seq<T> {
    type Item = T;
    type Slot = SeqSlot<T>;
    type Ref<'a>
        = &'a T
    where
        Self: 'a;
    type Mut<'a>
        = &'a mut T
    where
        Self: 'a;

    unsafe fn link(slot: *mut SeqSlot<T>) -> *mut Link {
        // SAFETY: the caller's contract: `slot` points into a slot.
        unsafe { addr_of_mut!((*slot).link) }
    }

    unsafe fn put(slot: *mut SeqSlot<T>, item: T) {
        // SAFETY: the caller's contract: the slot holds no item.
        unsafe { addr_of_mut!((*slot).item).write(item) }
    }

    unsafe fn take(slot: *mut SeqSlot<T>) -> T {
        // SAFETY: the caller's contract: the slot holds an item, read out once.
        unsafe { addr_of_mut!((*slot).item).read() }
    }

    unsafe fn slot_ref<'a>(slot: *const SeqSlot<T>) -> &'a T
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the item is there and not written for `'a`.
        unsafe { &*addr_of!((*slot).item) }
    }

    unsafe fn slot_mut<'a>(slot: *mut SeqSlot<T>) -> &'a mut T
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the item is there and reached by nothing else.
        unsafe { &mut *addr_of_mut!((*slot).item) }
    }

    fn item_ref<'a>(item: &'a T) -> &'a T
    where
        Self: 'a,
    {
        item
    }

    fn item_mut<'a>(item: &'a mut T) -> &'a mut T
    where
        Self: 'a,
    {
        item
    }
}

/// The kind of row of a table keyed by a peer's ids: the item is `(id, value)`.
pub struct Keyed<V> {
    _value: PhantomData<V>,
}

/// A row of a shared pool of [`Keyed`]: the id, the link and the value as fields of one row, so
/// the link takes the room the id and the value leave where they leave any (a value of four-byte
/// alignment after an eight-byte id, on a 32-bit core).
pub struct KeyedSlot<V> {
    id: u64,
    link: Link,
    value: V,
}

// SAFETY: the link is a field of its own, which no method of the item reaches.
unsafe impl<V> RowKind for Keyed<V> {
    type Item = (u64, V);
    type Slot = KeyedSlot<V>;
    type Ref<'a>
        = (u64, &'a V)
    where
        Self: 'a;
    type Mut<'a>
        = (u64, &'a mut V)
    where
        Self: 'a;

    unsafe fn link(slot: *mut KeyedSlot<V>) -> *mut Link {
        // SAFETY: the caller's contract: `slot` points into a slot.
        unsafe { addr_of_mut!((*slot).link) }
    }

    unsafe fn put(slot: *mut KeyedSlot<V>, (id, value): (u64, V)) {
        // SAFETY: the caller's contract: the slot holds no item.
        unsafe {
            addr_of_mut!((*slot).id).write(id);
            addr_of_mut!((*slot).value).write(value);
        }
    }

    unsafe fn take(slot: *mut KeyedSlot<V>) -> (u64, V) {
        // SAFETY: the caller's contract: the slot holds an item, read out once.
        unsafe {
            (
                addr_of!((*slot).id).read(),
                addr_of_mut!((*slot).value).read(),
            )
        }
    }

    unsafe fn slot_ref<'a>(slot: *const KeyedSlot<V>) -> (u64, &'a V)
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the item is there and not written for `'a`.
        unsafe { (addr_of!((*slot).id).read(), &*addr_of!((*slot).value)) }
    }

    unsafe fn slot_mut<'a>(slot: *mut KeyedSlot<V>) -> (u64, &'a mut V)
    where
        Self: 'a,
    {
        // SAFETY: the caller's contract: the item is there and reached by nothing else.
        unsafe {
            (
                addr_of!((*slot).id).read(),
                &mut *addr_of_mut!((*slot).value),
            )
        }
    }

    fn item_ref<'a>(item: &'a (u64, V)) -> (u64, &'a V)
    where
        Self: 'a,
    {
        (item.0, &item.1)
    }

    fn item_mut<'a>(item: &'a mut (u64, V)) -> (u64, &'a mut V)
    where
        Self: 'a,
    {
        (item.0, &mut item.1)
    }
}

/// The state of a shared pool, kept at the start of the span it was lent, its counters `u16`s as
/// its rows are.
struct Pool<K: RowKind> {
    /// The first slot, aligned for it.
    slots: NonNull<K::Slot>,
    /// How many slots there are.
    rows: u16,
    /// The slots below this have been written; none at or past it has.
    top: Cell<u16>,
    /// The first free slot below `top`, or [`NIL`].
    free: Cell<u16>,
    /// The slots held.
    used: Cell<u16>,
    /// The most `used` has been.
    peak: Cell<u16>,
    /// The rows refused for want of one, saturating.
    refused: Cell<u16>,
}

impl<K: RowKind> Pool<K> {
    /// The slot at `at`, one that has been written.
    fn slot(&self, at: u16) -> *mut K::Slot {
        debug_assert!(at < self.top.get(), "a slot past those written");
        // SAFETY: `at` is below `top`, at most `rows`, so the slot lies inside the slots the pool
        // was lent.
        unsafe { self.slots.as_ptr().add(usize::from(at)) }
    }

    /// The link of the slot at `at`.
    fn link(&self, at: u16) -> Link {
        // SAFETY: the slot was written, its link first, when it was first taken, and only the pool
        // writes links, through no reference.
        unsafe { K::link(self.slot(at)).read() }
    }

    /// Write the link of the slot at `at`.
    fn set_link(&self, at: u16, link: Link) {
        // SAFETY: as `link`; the slot lies inside the slots, its link apart from its item.
        unsafe { K::link(self.slot(at)).write(link) }
    }

    /// The row after the one at `at`, in the list or the free list that holds it.
    fn next(&self, at: u16) -> u16 {
        self.link(at).next
    }

    /// Make `next` follow the row at `at`.
    fn set_next(&self, at: u16, next: u16) {
        let mut link = self.link(at);
        link.next = next;
        self.set_link(at, link);
    }

    /// A slot holding `item`, or the item back, counted, when every slot is held.
    fn take(&self, item: K::Item) -> Result<RowHandle, CapacityFull<K::Item>> {
        let at = match self.free.get() {
            NIL => {
                let top = self.top.get();
                if top == self.rows {
                    self.refused.set(self.refused.get().saturating_add(1));
                    return Err(CapacityFull(item));
                }
                self.top.set(top + 1);
                self.set_link(
                    top,
                    Link {
                        next: NIL,
                        generation: 0,
                    },
                );
                top
            }
            at => {
                self.free.set(self.next(at));
                at
            }
        };
        let mut link = self.link(at);
        // From even to odd: the row is held. `u16::MAX` is odd, so the parity holds as it wraps.
        link.generation = link.generation.wrapping_add(1);
        link.next = NIL;
        self.set_link(at, link);
        // SAFETY: the slot was free, so it holds no item, and nothing reads it until this write.
        unsafe { K::put(self.slot(at), item) };
        let used = self.used.get() + 1;
        self.used.set(used);
        self.peak.set(self.peak.get().max(used));
        Ok(RowHandle {
            at,
            generation: link.generation,
        })
    }

    /// Take the item out of the held slot at `at` and put the slot on the free list.
    ///
    /// # Safety
    /// The slot at `at` is held, and no table links to it any more.
    unsafe fn release(&self, at: u16) -> K::Item {
        let mut link = self.link(at);
        debug_assert_eq!(link.generation & 1, 1, "a row given back twice");
        // SAFETY: the caller's contract: the slot holds an item, read out once here.
        let item = unsafe { K::take(self.slot(at)) };
        link.generation = link.generation.wrapping_add(1);
        link.next = self.free.get();
        self.set_link(at, link);
        self.free.set(at);
        self.used.set(self.used.get() - 1);
        item
    }

    /// Whether `handle` names a slot held since it was taken.
    fn holds(&self, handle: RowHandle) -> bool {
        handle.at < self.top.get() && self.link(handle.at).generation == handle.generation
    }
}

/// A row a shared pool handed out ([`RowSpace::take`]): where it lies and the generation it was
/// taken at. Once the row is given back the handle names nothing, though another holder takes the
/// row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowHandle {
    at: u16,
    generation: u16,
}

/// What a shared pool holds, as [`RowSpace::counts`] reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowCounts {
    /// The rows the pool was lent.
    pub rows: usize,
    /// The rows held now.
    pub used: usize,
    /// The most rows held at once.
    pub peak: usize,
    /// The rows no table has touched since the pool was lent.
    pub untouched: usize,
    /// The rows refused for want of one: the pool was full. Saturates at `u16::MAX`.
    pub refused: u32,
}

/// Where the tables of one kind of row keep their rows: a pool the faces of a session share, or a
/// span of one table's own. A handle: copies name the same rows. Made by [`Arena::lend_pool`] and
/// [`Arena::lend_own`].
pub struct RowSpace<K: RowKind> {
    /// The pool's state, or the first row of a table's own span.
    at: NonNull<u8>,
    /// [`NIL`] for a shared pool; [`DENSE`] and the rows for a span of one table's own.
    shape: u16,
    _kind: PhantomData<*const K>,
}

impl<K: RowKind> Clone for RowSpace<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: RowKind> Copy for RowSpace<K> {}

impl<K: RowKind> PartialEq for RowSpace<K> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.shape == other.shape
    }
}

impl<K: RowKind> Eq for RowSpace<K> {}

impl<K: RowKind> RowSpace<K> {
    /// The bytes a shared pool's own state takes at the start of its span, a whole span of an arena.
    const STATE_BYTES: usize = match Arena::span(core::mem::size_of::<Pool<K>>()) {
        Some(bytes) => bytes,
        None => panic!("a pool's state fits the address space"),
    };

    /// The bytes one row of a shared pool takes: its item and its link, where the item leaves the
    /// link no room.
    pub const fn slot_bytes() -> usize {
        core::mem::size_of::<K::Slot>()
    }

    /// The bytes one row of a table's own span takes: its item alone.
    pub const fn item_bytes() -> usize {
        core::mem::size_of::<K::Item>()
    }

    /// The alignment a table's own span starts on: its item's.
    pub const fn item_align() -> usize {
        core::mem::align_of::<K::Item>()
    }

    /// The bytes a shared pool of `rows` rows takes in an [`Arena`]: its state and its slots.
    /// `None` past [`MAX_POOL_ROWS`] or the address space.
    pub const fn pool_bytes(rows: usize) -> Option<usize> {
        if rows > MAX_POOL_ROWS {
            return None;
        }
        match Arena::table_bytes::<K::Slot>(rows) {
            Some(slots) => slots.checked_add(Self::STATE_BYTES),
            None => None,
        }
    }

    /// The bytes a table's own span of `rows` rows takes, not rounded to an arena's spans. `None`
    /// past [`MAX_POOL_ROWS`] or the address space.
    pub const fn own_bytes(rows: usize) -> Option<usize> {
        if rows > MAX_POOL_ROWS {
            return None;
        }
        rows.checked_mul(Self::item_bytes())
    }

    /// A shared pool of `rows` rows over the span at `span`, none of them held.
    ///
    /// # Safety
    /// `span` is aligned to [`ARENA_ALIGN`](crate::bounded::ARENA_ALIGN), the
    /// [`Self::pool_bytes`] of `rows` bytes from it are valid for reads and writes and used by
    /// nothing else for as long as any copy of the space or any table holding its rows lives, and
    /// `rows` is at most [`MAX_POOL_ROWS`].
    pub(crate) unsafe fn pool_over(span: NonNull<u8>, rows: usize) -> Self {
        const {
            assert!(
                core::mem::align_of::<Pool<K>>() <= crate::bounded::ARENA_ALIGN
                    && core::mem::align_of::<K::Slot>() <= crate::bounded::ARENA_ALIGN,
                "a pool's state or row asks for more alignment than an arena's spans start on"
            )
        };
        let store = span.cast::<Pool<K>>();
        // SAFETY: the caller's contract: the span is aligned for the state, which it starts with,
        // and the slots follow it at a multiple of the arena's alignment, inside the span.
        unsafe {
            store.as_ptr().write(Pool {
                slots: NonNull::new_unchecked(span.as_ptr().add(Self::STATE_BYTES))
                    .cast::<K::Slot>(),
                rows: rows as u16,
                top: Cell::new(0),
                free: Cell::new(NIL),
                used: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
            });
        }
        Self {
            at: span,
            shape: NIL,
            _kind: PhantomData,
        }
    }

    /// A span of one table's own of `rows` rows at `at`, none of them holding an item.
    ///
    /// # Safety
    /// `at` is aligned to [`Self::item_align`], the [`Self::own_bytes`] of `rows` bytes from it
    /// are valid for reads and writes and used by nothing else for as long as the one table it is
    /// handed to lives, it is handed to one table, and `rows` is at most [`MAX_POOL_ROWS`].
    pub(crate) unsafe fn own_over(at: NonNull<u8>, rows: usize) -> Self {
        Self {
            at,
            shape: DENSE | rows as u16,
            _kind: PhantomData,
        }
    }

    /// The pool's state, if this is a shared pool.
    fn pool(&self) -> Option<&Pool<K>> {
        // SAFETY: `pool_over`'s contract: the state lives for as long as this handle does.
        (self.shape == NIL).then(|| unsafe { self.at.cast::<Pool<K>>().as_ref() })
    }

    /// Whether the faces share these rows: a pool, and not a span of one table's own.
    pub fn is_shared(&self) -> bool {
        self.shape == NIL
    }

    /// How many rows there are.
    pub fn rows(&self) -> usize {
        match self.pool() {
            Some(pool) => usize::from(pool.rows),
            None => usize::from(self.shape & !DENSE),
        }
    }

    /// A row of a shared pool holding `item`, or the item back when every row is held, which the
    /// pool counts. A span of one table's own hands out no row this way.
    pub fn take(&self, item: K::Item) -> Result<RowHandle, CapacityFull<K::Item>> {
        match self.pool() {
            Some(pool) => pool.take(item),
            None => Err(CapacityFull(item)),
        }
    }

    /// The item of the row `handle` names, the row back on the free list; `None`, and nothing
    /// done, when the handle names no row held since it was taken (it was given back already).
    pub fn give_back(&self, handle: RowHandle) -> Option<K::Item> {
        let pool = self.pool()?;
        if !pool.holds(handle) {
            return None;
        }
        // SAFETY: the row is held at the handle's generation, which only `take` handed out, and
        // a row a table holds is never handed out as a handle, so no table links to it.
        Some(unsafe { pool.release(handle.at) })
    }

    /// Whether `handle` names a row held since it was taken.
    pub fn holds(&self, handle: RowHandle) -> bool {
        self.pool().is_some_and(|pool| pool.holds(handle))
    }

    /// What a shared pool holds now; `None` for a span of one table's own, whose table says what it
    /// holds.
    pub fn counts(&self) -> Option<RowCounts> {
        self.pool().map(|pool| RowCounts {
            rows: usize::from(pool.rows),
            used: usize::from(pool.used.get()),
            peak: usize::from(pool.peak.get()),
            untouched: usize::from(pool.rows - pool.top.get()),
            refused: u32::from(pool.refused.get()),
        })
    }
}

impl<K: RowKind> fmt::Debug for RowSpace<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RowSpace")
            .field("shared", &self.is_shared())
            .field("rows", &self.rows())
            .field("counts", &self.counts())
            .finish()
    }
}

/// Where a walk over a table stands: the row, and in a shared pool the one before it.
#[derive(Clone, Copy)]
struct Place {
    at: u16,
    prev: u16,
}

/// One table of a kind of row: at most `N` rows, in the order they were pushed, in a pool the
/// session's faces share or in a span of its own ([`Self::keep_rows_in`]). Made with neither
/// ([`Self::new`], `Default`), it refuses every item as a full table does until it is handed one.
/// Dropped or cleared, it gives back exactly the rows it holds. It is a pointer and three counters
/// wherever it lies, the refusals among them.
pub struct PooledRows<K: RowKind, const N: usize> {
    /// The pool's state, or the first row of the table's span.
    at: Option<NonNull<u8>>,
    /// In a shared pool the first row, or [`NIL`]; in a span of its own [`DENSE`] and its rows.
    first: u16,
    len: u16,
    refused: u32,
    _items: PhantomData<(K, K::Item)>,
}

impl<K: RowKind, const N: usize> PooledRows<K, N> {
    /// A table of no rows and no space. `const`, as an inline table's constructor is.
    pub const fn new() -> Self {
        Self {
            at: None,
            first: NIL,
            len: 0,
            refused: 0,
            _items: PhantomData,
        }
    }

    /// Take the rows pushed from here on from `space`. A table keeps the space it holds rows of: one
    /// that holds rows of another is emptied first, as its rows belong to the space it held before.
    pub fn keep_rows_in(&mut self, space: RowSpace<K>) {
        if self.at == Some(space.at) {
            return;
        }
        self.clear();
        self.at = Some(space.at);
        self.first = space.shape;
    }

    /// Where the table takes its rows, if it was handed a space.
    pub fn space(&self) -> Option<RowSpace<K>> {
        let at = self.at?;
        let shape = match self.own() {
            Some((_, rows)) => DENSE | rows,
            None => NIL,
        };
        Some(RowSpace {
            at,
            shape,
            _kind: PhantomData,
        })
    }

    /// The first row of the table's own span and how many rows it has, if it has one.
    fn own(&self) -> Option<(NonNull<K::Item>, u16)> {
        match self.at {
            Some(at) if self.first != NIL && self.first & DENSE != 0 => {
                Some((at.cast::<K::Item>(), self.first & !DENSE))
            }
            _ => None,
        }
    }

    /// The shared pool the table takes its rows from, if it does. The state is the pool's, which
    /// outlives every table holding its rows (`RowSpace::pool_over`), so the reference is not the
    /// table's to bound.
    fn pool<'p>(&self) -> Option<&'p Pool<K>> {
        match self.at {
            // SAFETY: `pool_over`'s contract: the state lives as long as a table that holds it.
            Some(at) if self.own().is_none() => Some(unsafe { at.cast::<Pool<K>>().as_ref() }),
            _ => None,
        }
    }

    /// The most rows the table holds: the bound of one table, whatever its space has left.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many rows the table holds.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether the table holds no row.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many items the table refused since it was made: past its bound, past its span, for want
    /// of a pool's row or of any space, or as its owner counted ([`Self::count_refused`]).
    pub fn refusals(&self) -> u32 {
        self.refused
    }

    /// Count an item refused before it reached the table, as one it had no room for is.
    pub fn count_refused(&mut self) {
        self.refused = self.refused.saturating_add(1);
    }

    /// `item` back, counted as refused.
    fn refuse(&mut self, item: K::Item) -> CapacityFull<K::Item> {
        self.count_refused();
        CapacityFull(item)
    }

    /// Append `item`, or hand it back, counted: the table holds `N` rows, its span has no row
    /// left, it was handed no space, or its pool has no row left, which the pool counts too.
    pub fn push(&mut self, item: K::Item) -> Result<(), CapacityFull<K::Item>> {
        if self.len() >= N {
            return Err(self.refuse(item));
        }
        if let Some((base, rows)) = self.own() {
            if self.len >= rows {
                return Err(self.refuse(item));
            }
            // SAFETY: the row lies inside the span, past the rows held, so it holds no item.
            unsafe { base.as_ptr().add(self.len()).write(item) };
            self.len += 1;
            return Ok(());
        }
        let Some(pool) = self.pool() else {
            return Err(self.refuse(item));
        };
        let at = match pool.take(item) {
            Ok(handle) => handle.at,
            Err(CapacityFull(item)) => return Err(self.refuse(item)),
        };
        if self.first == NIL {
            self.first = at;
        } else {
            // No tail is kept: the walk to the last row is over the table's own rows, at most
            // its bound, as a lookup is.
            let mut last = self.first;
            loop {
                let next = pool.next(last);
                if next == NIL {
                    break;
                }
                last = next;
            }
            pool.set_next(last, at);
        }
        self.len += 1;
        Ok(())
    }

    /// Where a walk over the rows starts.
    fn start(&self) -> Option<Place> {
        if self.len == 0 {
            return None;
        }
        Some(Place {
            at: if self.own().is_some() { 0 } else { self.first },
            prev: NIL,
        })
    }

    /// Where a walk goes after `place`.
    fn advance(&self, place: Place) -> Option<Place> {
        let next = if self.own().is_some() {
            place.at + 1
        } else {
            self.pool()?.next(place.at)
        };
        let past = if self.own().is_some() {
            next >= self.len
        } else {
            next == NIL
        };
        (!past).then_some(Place {
            at: next,
            prev: place.at,
        })
    }

    /// The row at `place`, to read.
    fn get(&self, place: Place) -> K::Ref<'_> {
        match (self.own(), self.pool()) {
            (Some((base, _)), _) => {
                // SAFETY: a walk's place is a row the table holds, below its length.
                K::item_ref(unsafe { &*base.as_ptr().add(usize::from(place.at)) })
            }
            // SAFETY: a walk's place is a row the table holds, and the table is borrowed for as
            // long as the reference lives, so the row is not given back or written meanwhile.
            (None, Some(pool)) => unsafe { K::slot_ref(pool.slot(place.at)) },
            (None, None) => unreachable!("a walk over a table of no space"),
        }
    }

    /// The row at `place`, to write, for as long as `'a`.
    ///
    /// # Safety
    /// The table is borrowed mutably for `'a`, and no other reference to the row is handed out
    /// meanwhile.
    unsafe fn get_mut<'a>(&self, place: Place) -> K::Mut<'a>
    where
        K: 'a,
    {
        match (self.own(), self.pool()) {
            (Some((base, _)), _) => {
                // SAFETY: the caller's contract, and the place is a row below the table's length.
                K::item_mut(unsafe { &mut *base.as_ptr().add(usize::from(place.at)) })
            }
            // SAFETY: the caller's contract, and the place is a row the table holds.
            (None, Some(pool)) => unsafe { K::slot_mut(pool.slot(place.at)) },
            (None, None) => unreachable!("a walk over a table of no space"),
        }
    }

    /// Take the row at `place` out of the table, its order kept, and where the walk goes next.
    fn remove(&mut self, place: Place) -> (K::Item, Option<Place>) {
        if let Some((base, _)) = self.own() {
            let at = usize::from(place.at);
            // SAFETY: the row is held, below the length; the ones after it move down by one,
            // inside the span, and the length is shortened with them.
            let item = unsafe {
                let item = base.as_ptr().add(at).read();
                ptr::copy(
                    base.as_ptr().add(at + 1),
                    base.as_ptr().add(at),
                    self.len() - at - 1,
                );
                item
            };
            self.len -= 1;
            return (item, (place.at < self.len).then_some(place));
        }
        let pool = self
            .pool()
            .unwrap_or_else(|| unreachable!("a walk over a table of no space"));
        let next = pool.next(place.at);
        if place.prev == NIL {
            self.first = next;
        } else {
            pool.set_next(place.prev, next);
        }
        self.len -= 1;
        // SAFETY: the table held the row and no longer links to it.
        let item = unsafe { pool.release(place.at) };
        (
            item,
            (next != NIL).then_some(Place {
                at: next,
                prev: place.prev,
            }),
        )
    }

    /// The rows, in the order they were pushed.
    pub fn iter(&self) -> Rows<'_, K, N> {
        Rows {
            list: self,
            at: self.start(),
            left: self.len,
        }
    }

    /// The rows, to write, in the order they were pushed.
    pub fn iter_mut(&mut self) -> RowsMut<'_, K, N> {
        RowsMut {
            at: self.start(),
            left: self.len,
            list: NonNull::from(&*self),
            _list: PhantomData,
        }
    }

    /// Give every row back, each item dropped: one step for each row the table holds.
    pub fn clear(&mut self) {
        if let Some((base, _)) = self.own() {
            let len = self.len();
            self.len = 0;
            // SAFETY: the rows below the old length held items, dropped once here; the length was
            // set first, so a drop that panics leaks the rest rather than dropping them twice.
            unsafe { ptr::drop_in_place(ptr::slice_from_raw_parts_mut(base.as_ptr(), len)) };
            return;
        }
        let Some(pool) = self.pool() else {
            return;
        };
        let mut at = self.first;
        self.first = NIL;
        self.len = 0;
        while at != NIL {
            let next = pool.next(at);
            // SAFETY: the table held the row, and the list it was linked in is gone.
            drop(unsafe { pool.release(at) });
            at = next;
        }
    }
}

impl<T, const N: usize> PooledRows<Seq<T>, N> {
    /// Keep only the values `keep` accepts, in order; each other row is given back.
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        let mut at = self.start();
        while let Some(place) = at {
            at = if keep(self.get(place)) {
                self.advance(place)
            } else {
                self.remove(place).1
            };
        }
    }

    /// Take the first value `which` accepts out of the table, its row given back.
    pub fn remove_first<F: FnMut(&T) -> bool>(&mut self, mut which: F) -> Option<T> {
        let mut at = self.start();
        while let Some(place) = at {
            if which(self.get(place)) {
                return Some(self.remove(place).0);
            }
            at = self.advance(place);
        }
        None
    }
}

impl<V, const N: usize> PooledRows<Keyed<V>, N> {
    /// Take the row of `id` out of the table, its row given back, and hand back its value.
    pub fn remove_id(&mut self, id: u64) -> Option<V> {
        let mut at = self.start();
        while let Some(place) = at {
            if self.get(place).0 == id {
                return Some(self.remove(place).0 .1);
            }
            at = self.advance(place);
        }
        None
    }
}

impl<K: RowKind, const N: usize> Default for PooledRows<K, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: RowKind, const N: usize> Drop for PooledRows<K, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<K: RowKind, const N: usize> fmt::Debug for PooledRows<K, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledRows")
            .field("len", &self.len)
            .field("own", &self.own().map(|(_, rows)| rows))
            .field("refused", &self.refused)
            .finish()
    }
}

/// The rows of a [`PooledRows`], in the order they were pushed.
pub struct Rows<'a, K: RowKind, const N: usize> {
    list: &'a PooledRows<K, N>,
    at: Option<Place>,
    left: u16,
}

impl<'a, K: RowKind, const N: usize> Iterator for Rows<'a, K, N> {
    type Item = K::Ref<'a>;

    fn next(&mut self) -> Option<K::Ref<'a>> {
        let place = self.at?;
        self.at = self.list.advance(place);
        self.left -= 1;
        Some(self.list.get(place))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl<K: RowKind, const N: usize> ExactSizeIterator for Rows<'_, K, N> {}

/// The rows of a [`PooledRows`], to write, in the order they were pushed.
pub struct RowsMut<'a, K: RowKind, const N: usize> {
    list: NonNull<PooledRows<K, N>>,
    at: Option<Place>,
    left: u16,
    _list: PhantomData<&'a mut PooledRows<K, N>>,
}

impl<'a, K: RowKind, const N: usize> Iterator for RowsMut<'a, K, N> {
    type Item = K::Mut<'a>;

    fn next(&mut self) -> Option<K::Mut<'a>> {
        let place = self.at?;
        // SAFETY: the table is borrowed mutably for `'a` by this walk alone, which reads its
        // counters and links through a shared reference and hands out each row once: the rows lie
        // in the space, not in the table, so no reference handed out overlaps the table.
        let list = unsafe { self.list.as_ref() };
        self.at = list.advance(place);
        self.left -= 1;
        // SAFETY: as above; each place is reached once.
        Some(unsafe { list.get_mut(place) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl<K: RowKind, const N: usize> ExactSizeIterator for RowsMut<'_, K, N> {}

/// A table of rows a peer writes, as a storage policy keeps it ([`Storage::Pooled`]): an inline or
/// growable sequence on the policies that keep their own rows, and on the lent one a
/// [`PooledRows`] of [`Seq`]. The operations the tables above it need, written once for every
/// policy.
pub trait RowList<T>: Default {
    /// How many values the table holds.
    fn len(&self) -> usize;

    /// Whether the table holds no value.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append `value`, or hand it back when the table or its space has no room.
    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>>;

    /// The values, in order.
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a;

    /// The values, mutably, in order.
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a;

    /// Keep only the values `keep` accepts, in order.
    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F);

    /// Take the first value `which` accepts out of the table.
    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T>;

    /// Drop every value.
    fn clear(&mut self);
}

impl<T, const N: usize, P: Storage> RowList<T> for BoundedVec<T, N, P> {
    fn len(&self) -> usize {
        <[T]>::len(self)
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        BoundedVec::push(self, value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        <[T]>::iter(self)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        <[T]>::iter_mut(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        BoundedVec::retain(self, keep);
    }

    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T> {
        let at = <[T]>::iter(self).position(which)?;
        Some(BoundedVec::remove(self, at))
    }

    fn clear(&mut self) {
        BoundedVec::clear(self);
    }
}

impl<T, const N: usize> RowList<T> for PooledRows<Seq<T>, N> {
    fn len(&self) -> usize {
        PooledRows::len(self)
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        PooledRows::push(self, value)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
    where
        T: 'a,
    {
        PooledRows::iter(self)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut T>
    where
        T: 'a,
    {
        PooledRows::iter_mut(self)
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, keep: F) {
        PooledRows::retain(self, keep);
    }

    fn remove_first<F: FnMut(&T) -> bool>(&mut self, which: F) -> Option<T> {
        PooledRows::remove_first(self, which)
    }

    fn clear(&mut self) {
        PooledRows::clear(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{LendRefused, Static, ARENA_ALIGN};
    use std::rc::Rc;
    use std::vec::Vec;

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// An arena over `bytes` bytes of memory the test process leaks, so it outlives every row.
    fn arena_of(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every row.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// A shared pool of `rows` rows, lent from an arena of exactly its span.
    fn pool_of<K: RowKind>(rows: usize) -> RowSpace<K> {
        let span = RowSpace::<K>::pool_bytes(rows).expect("a test pool fits");
        let mut arena = arena_of(span);
        let pool = arena.lend_pool(rows).expect("the arena is the pool's span");
        assert_eq!(arena.high_water(), span, "the span is what the pool takes");
        pool
    }

    /// A span of one table's own of `rows` rows.
    fn own_of<K: RowKind>(rows: usize) -> RowSpace<K> {
        let bytes = Arena::span(RowSpace::<K>::own_bytes(rows).expect("fits")).expect("fits");
        arena_of(bytes)
            .lend_own(rows)
            .expect("the arena is the span")
    }

    fn values<const N: usize>(table: &PooledRows<Seq<u32>, N>) -> Vec<u32> {
        table.iter().copied().collect()
    }

    /// A row of a pool carries two `u16`s besides its item, and where the item's fields leave room
    /// the row is no longer than the item: an id and a value of four-byte alignment (a key's place
    /// on a 32-bit core) take the link into the padding the pair leaves. A pool's state is a
    /// pointer and six `u16`s.
    #[test]
    fn a_rows_link_is_two_u16s_and_packs_into_room_the_item_leaves() {
        assert_eq!(core::mem::size_of::<Link>(), 4);
        assert_eq!(
            core::mem::size_of::<KeyedSlot<[u32; 3]>>(),
            core::mem::size_of::<(u64, [u32; 3])>(),
            "the link takes the padding of an id and a three-word value"
        );
        assert_eq!(
            core::mem::size_of::<SeqSlot<u32>>(),
            8,
            "a four-byte value and its link"
        );
        assert!(
            core::mem::size_of::<Pool<Seq<u64>>>()
                <= core::mem::size_of::<usize>() + 6 * core::mem::size_of::<u16>() + 4,
            "the state is a pointer and six counters"
        );
        assert!(RowSpace::<Seq<u8>>::pool_bytes(MAX_POOL_ROWS).is_some());
        assert_eq!(RowSpace::<Seq<u8>>::pool_bytes(MAX_POOL_ROWS + 1), None);
        assert_eq!(RowSpace::<Seq<u8>>::own_bytes(MAX_POOL_ROWS + 1), None);
    }

    /// A shared pool lends its rows until every one is held, refuses the next and counts it, and a
    /// row given back is taken again. A handle names its row only until the row goes back.
    #[test]
    fn a_handle_names_its_row_until_the_row_goes_back() {
        let pool = pool_of::<Seq<u32>>(2);
        let first = pool.take(10).expect("a row is free");
        let second = pool.take(20).expect("the last row is free");
        assert_eq!(pool.take(30).err().map(|full| full.0), Some(30));
        let counts = pool.counts().expect("a shared pool");
        assert_eq!((counts.used, counts.refused), (2, 1));
        assert_eq!(pool.give_back(first), Some(10));
        assert_eq!(
            pool.give_back(first),
            None,
            "a handle given back names nothing"
        );
        let again = pool.take(40).expect("the row given back is free");
        assert!(
            !pool.holds(first),
            "the old handle does not name the row's new holder"
        );
        assert!(pool.holds(again) && pool.holds(second));
        assert_eq!(pool.give_back(again), Some(40));
        assert_eq!(pool.counts().expect("a shared pool").peak, 2);
    }

    /// Many tables, each bounded at sixteen rows, each holding three, fit a pool of the rows they
    /// hold together; the next push of any of them is refused and counted by the pool and by the
    /// table, and every table keeps what it held.
    #[test]
    fn many_tables_holding_a_few_rows_fit_a_pool_far_smaller_than_their_bounds() {
        const TABLES: usize = 8;
        let pool = pool_of::<Seq<u32>>(TABLES * 3);
        let mut tables: Vec<PooledRows<Seq<u32>, 16>> =
            (0..TABLES).map(|_| PooledRows::new()).collect();
        for (n, table) in tables.iter_mut().enumerate() {
            table.keep_rows_in(pool);
            for k in 0..3 {
                assert!(table.push((n * 10 + k) as u32).is_ok(), "table {n} row {k}");
            }
        }
        assert_eq!(pool.counts().expect("shared").used, TABLES * 3);
        assert_eq!(tables[5].push(99).err().map(|full| full.0), Some(99));
        assert_eq!(
            (
                tables[5].len(),
                tables[5].refusals(),
                pool.counts().expect("shared").refused
            ),
            (3, 1, 1),
            "the refusal takes nothing and is counted by the table and the pool"
        );
        for (n, table) in tables.iter().enumerate() {
            let n = n as u32;
            assert_eq!(values(table), [n * 10, n * 10 + 1, n * 10 + 2]);
        }
    }

    /// Clearing a table gives back exactly its rows: the pool holds the other tables' rows still,
    /// their values intact, and the rows given back hold the next table's values.
    #[test]
    fn clearing_a_table_gives_back_exactly_its_rows() {
        let pool = pool_of::<Seq<u32>>(5);
        let (mut a, mut b) = (
            PooledRows::<Seq<u32>, 4>::new(),
            PooledRows::<Seq<u32>, 4>::new(),
        );
        a.keep_rows_in(pool);
        b.keep_rows_in(pool);
        for v in [1, 2, 3] {
            a.push(v).expect("room");
        }
        for v in [7, 8] {
            b.push(v).expect("room");
        }
        a.clear();
        assert_eq!(
            pool.counts().expect("shared").used,
            2,
            "a's three rows went back"
        );
        assert_eq!(values(&b), [7, 8], "b's rows are untouched");
        let mut c = PooledRows::<Seq<u32>, 4>::new();
        c.keep_rows_in(pool);
        for v in [4, 5, 6] {
            c.push(v).expect("the rows a gave back");
        }
        assert_eq!(pool.counts().expect("shared").untouched, 0);
        assert!(c.push(9).is_err(), "the pool is full again");
        assert_eq!(
            (values(&b), values(&c)),
            (std::vec![7, 8], std::vec![4, 5, 6])
        );
    }

    /// A table keeps the order of its pushes through removals in either layout: in a shared pool
    /// and in a span of its own, the head, the middle and the last row each removed, a push after
    /// them landing last.
    #[test]
    fn a_table_keeps_its_push_order_through_removals_in_either_layout() {
        for space in [pool_of::<Seq<u32>>(8), own_of::<Seq<u32>>(8)] {
            let mut table = PooledRows::<Seq<u32>, 8>::new();
            table.keep_rows_in(space);
            for v in 1..=5 {
                table.push(v).expect("room");
            }
            assert_eq!(table.remove_first(|v| *v == 3), Some(3));
            table.retain(|v| *v != 2);
            assert_eq!(values(&table), [1, 4, 5]);
            assert_eq!(table.remove_first(|v| *v == 5), Some(5), "the last");
            table.push(6).expect("room");
            assert_eq!(values(&table), [1, 4, 6]);
            assert_eq!(table.remove_first(|v| *v == 1), Some(1), "the head");
            for v in table.iter_mut() {
                *v += 10;
            }
            assert_eq!(values(&table), [14, 16]);
            table.retain(|_| false);
            assert!(table.is_empty());
        }
    }

    /// A table of its own span holds as many rows as the span and no pool state: its rows lie from
    /// the span's start as an inline table's do, a push past them is refused and counted, a row
    /// taken out makes room, and the span hands out no row by handle.
    #[test]
    fn a_table_of_its_own_span_holds_its_rows_in_place_and_refuses_past_them() {
        let own = own_of::<Seq<u64>>(2);
        assert!(!own.is_shared());
        assert_eq!((own.rows(), own.counts()), (2, None));
        assert!(
            own.take(1).is_err(),
            "no handle is handed out of a table's own span"
        );
        let mut table = PooledRows::<Seq<u64>, 4>::new();
        table.keep_rows_in(own);
        table.push(1).expect("room");
        table.push(2).expect("room");
        let first = table.iter().next().expect("a row") as *const u64;
        assert_eq!(
            first as usize,
            own.at.as_ptr() as usize,
            "the first row lies at the span's start"
        );
        assert_eq!(table.push(3).err().map(|full| full.0), Some(3));
        assert_eq!(table.refusals(), 1);
        assert_eq!(table.remove_first(|v| *v == 1), Some(1));
        table.push(3).expect("the row taken out");
        assert_eq!(table.iter().copied().collect::<Vec<_>>(), [2, 3]);
    }

    /// A table refuses past its own bound though its space has rows left, as an inline table of
    /// that bound refuses, and the pool counts no refusal of its own for it.
    #[test]
    fn a_table_refuses_past_its_own_bound_with_rows_left_in_the_space() {
        let pool = pool_of::<Seq<u32>>(8);
        let mut table = PooledRows::<Seq<u32>, 2>::new();
        table.keep_rows_in(pool);
        table.push(1).expect("room");
        table.push(2).expect("room");
        assert_eq!(table.push(3).err().map(|full| full.0), Some(3));
        let counts = pool.counts().expect("shared");
        assert_eq!((counts.used, counts.refused, table.refusals()), (2, 0, 1));
    }

    /// A table handed no space refuses every item, and so does one whose pool lends no row.
    #[test]
    fn a_table_with_no_space_or_an_empty_one_refuses() {
        let mut table = PooledRows::<Seq<u32>, 4>::default();
        assert_eq!(table.push(1).err().map(|full| full.0), Some(1));
        let empty = pool_of::<Seq<u32>>(0);
        table.keep_rows_in(empty);
        assert!(table.push(1).is_err());
        assert_eq!(empty.counts().expect("shared").refused, 1);
        assert_eq!(table.refusals(), 2);
    }

    /// A dropped table gives its rows back and drops each item once, in either layout; so does one
    /// handed another space, whose rows belong to the first.
    #[test]
    fn a_dropped_table_drops_its_items_and_gives_its_rows_back() {
        let value = Rc::new(());
        for space in [pool_of::<Seq<Rc<()>>>(4), own_of::<Seq<Rc<()>>>(4)] {
            let mut table = PooledRows::<Seq<Rc<()>>, 4>::new();
            table.keep_rows_in(space);
            for _ in 0..3 {
                table.push(Rc::clone(&value)).expect("room");
            }
            assert_eq!(Rc::strong_count(&value), 4);
            drop(table);
            assert_eq!(Rc::strong_count(&value), 1, "each item dropped once");
        }
        let (pool, other) = (pool_of::<Seq<Rc<()>>>(4), pool_of::<Seq<Rc<()>>>(4));
        let mut moved = PooledRows::<Seq<Rc<()>>, 4>::new();
        moved.keep_rows_in(pool);
        moved.push(Rc::clone(&value)).expect("room");
        moved.keep_rows_in(other);
        assert_eq!(
            (
                pool.counts().expect("shared").used,
                Rc::strong_count(&value)
            ),
            (0, 1)
        );
        moved.push(Rc::clone(&value)).expect("the other pool's row");
        assert_eq!(other.counts().expect("shared").used, 1);
    }

    /// A keyed table finds, rewrites and takes out a row by its id in either layout, the value of
    /// the rest untouched.
    #[test]
    fn a_keyed_table_finds_and_takes_out_a_row_by_its_id_in_either_layout() {
        for space in [pool_of::<Keyed<u32>>(4), own_of::<Keyed<u32>>(4)] {
            let mut table = PooledRows::<Keyed<u32>, 4>::new();
            table.keep_rows_in(space);
            for id in 1..=3u64 {
                table.push((id, id as u32 * 10)).expect("room");
            }
            if let Some((_, value)) = table.iter_mut().find(|(id, _)| *id == 2) {
                *value = 21;
            }
            assert_eq!(table.remove_id(1), Some(10));
            assert_eq!(table.remove_id(1), None);
            assert_eq!(
                table.iter().map(|(id, v)| (id, *v)).collect::<Vec<_>>(),
                [(2, 21), (3, 30)]
            );
        }
    }

    /// An arena one byte short of a pool's span refuses it, taking nothing.
    #[test]
    fn an_arena_refuses_a_pool_past_what_is_left() {
        let span = RowSpace::<Seq<u64>>::pool_bytes(4).expect("fits");
        let mut arena = arena_of(span - 1);
        assert!(matches!(
            arena.lend_pool::<Seq<u64>>(4),
            Err(LendRefused::Exhausted { .. })
        ));
        assert_eq!(arena.high_water(), 0);
    }

    /// The tables of every policy answer the same: an inline sequence is a `RowList` as a pooled one
    /// and one of its own span are, in push order.
    #[test]
    fn an_inline_sequence_and_a_pooled_one_answer_alike() {
        fn exercise<L: RowList<u32>>(table: &mut L) -> Vec<u32> {
            for v in 1..=4 {
                table.push(v).expect("room");
            }
            assert_eq!(table.remove_first(|v| *v == 2), Some(2));
            table.retain(|v| *v != 4);
            for v in table.iter_mut() {
                *v *= 10;
            }
            table.iter().copied().collect()
        }
        let mut inline = BoundedVec::<u32, 8, Static>::new_static();
        let mut pooled = PooledRows::<Seq<u32>, 8>::new();
        pooled.keep_rows_in(pool_of(8));
        let mut own = PooledRows::<Seq<u32>, 8>::new();
        own.keep_rows_in(own_of(8));
        let expected = exercise(&mut inline);
        assert_eq!(expected, [10, 30]);
        assert_eq!(exercise(&mut pooled), expected);
        assert_eq!(exercise(&mut own), expected);
    }
}
