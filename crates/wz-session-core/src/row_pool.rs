// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A pool of rows the faces of one session share: a slab of rows of one kind lent from the
//! session's [`Arena`] once, the rows no table holds on a free list, and each table a list of the
//! rows it holds (`docs/c-abi-no-heap-pools.md`, section 4.5).
//!
//! # Why
//!
//! A table a peer writes is bounded for each peer (`MAX_REMOTE_DECLS` and its kin), and a session
//! that holds many peers reserving that bound for each of them reserves its faces times the worst
//! one. zenoh-pico takes each such row from its heap as it comes, with no bound. A pool sized by
//! what the whole session may hold keeps the bound of each peer, reserves the session's sum once,
//! and a peer that declares little leaves its share to the others.
//!
//! # Rows and handles
//!
//! A row is taken from the free list, or else from the rows no table has touched yet, and given
//! back to the free list. Each row carries a generation that moves when it is taken and when it is
//! given back, odd while it is held: a [`RowHandle`] names a row and the generation it was taken
//! at, so a handle kept past the row's return names nothing rather than the row's next holder.
//!
//! A [`PooledRows`] is one table: the rows it holds, in the order they were pushed, linked through
//! the rows themselves, so a table is a few words wherever it lies and its rows lie in the pool. A
//! lookup walks the table's own rows, as a scan of an inline table does; clearing or dropping the
//! table gives back exactly its rows, one step each.
//!
//! # Refusal
//!
//! A push past the table's own bound `N` is refused as a full inline table refuses it, the value
//! handed back. A push the pool has no row for is refused the same way and counted by the pool
//! ([`RowCounts::refused`]), so a caller that drops and counts a declaration at the table's bound
//! drops and counts it here too, and nothing else changes.
//!
//! # One thread, and the lifetime
//!
//! As the key arena's ([`crate::key_arena`]): the pool's state is kept in cells, so a
//! [`RowSpace`] and every table that holds one are neither `Send` nor `Sync`, and every table
//! that holds rows of a pool is dropped before the memory the arena was reserved from is given back.

use core::cell::{Cell, UnsafeCell};
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::bounded::{Arena, BoundedVec, CapacityFull, Storage};

/// No row: the end of a list and of the free list.
const NIL: u32 = u32::MAX;

/// The most rows a pool holds: every row is named by a `u32`, and the largest names none.
pub const MAX_POOL_ROWS: usize = (u32::MAX - 1) as usize;

/// One row of a pool.
struct Slot<T> {
    /// Moves when the row is taken and when it is given back: odd while a table holds the row.
    generation: Cell<u32>,
    /// The next row of the table that holds this one, or of the free list; [`NIL`] at the end.
    next: Cell<u32>,
    /// The value, while the row is held.
    value: UnsafeCell<MaybeUninit<T>>,
}

/// The state of a pool, kept at the start of the span it was lent.
struct RowStore<T> {
    /// The first row, aligned for it.
    slots: NonNull<Slot<T>>,
    /// How many rows there are.
    rows: u32,
    /// The rows below this have been written; none at or past it has.
    top: Cell<u32>,
    /// The first free row below `top`, or [`NIL`].
    free: Cell<u32>,
    /// The rows held.
    used: Cell<u32>,
    /// The most `used` has been.
    peak: Cell<u32>,
    /// The rows refused for want of one.
    refused: Cell<u32>,
}

impl<T> RowStore<T> {
    /// The row at `at`.
    fn slot(&self, at: u32) -> &Slot<T> {
        debug_assert!(at < self.top.get(), "a row past those written");
        // SAFETY: every row below `top` was written when it was first taken and lies inside the
        // rows the pool was lent; its fields are cells, so a shared reference to it is all that is
        // ever made.
        unsafe { &*self.slots.as_ptr().add(at as usize) }
    }

    /// A row for `value`, or the value back, counted, when every row is held.
    fn take(&self, value: T) -> Result<RowHandle, CapacityFull<T>> {
        let at = match self.free.get() {
            NIL => {
                let top = self.top.get();
                if top == self.rows {
                    self.refused.set(self.refused.get().saturating_add(1));
                    return Err(CapacityFull(value));
                }
                // SAFETY: `top` is below `rows`, so the row lies inside the rows the pool was
                // lent, and no row at or past `top` was ever written or referenced.
                unsafe {
                    self.slots.as_ptr().add(top as usize).write(Slot {
                        generation: Cell::new(0),
                        next: Cell::new(NIL),
                        value: UnsafeCell::new(MaybeUninit::uninit()),
                    });
                }
                self.top.set(top + 1);
                top
            }
            at => {
                self.free.set(self.slot(at).next.get());
                at
            }
        };
        let slot = self.slot(at);
        // From even to odd: the row is held. `u32::MAX` is odd, so the parity holds as it wraps.
        let generation = slot.generation.get().wrapping_add(1);
        slot.generation.set(generation);
        slot.next.set(NIL);
        // SAFETY: the row was free, so it holds no value and nothing reads it until this write.
        unsafe { (*slot.value.get()).write(value) };
        let used = self.used.get() + 1;
        self.used.set(used);
        self.peak.set(self.peak.get().max(used));
        Ok(RowHandle { at, generation })
    }

    /// Take the value out of the held row at `at` and put the row on the free list.
    ///
    /// # Safety
    /// The row at `at` is held, and no table links to it any more.
    unsafe fn release(&self, at: u32) -> T {
        let slot = self.slot(at);
        debug_assert_eq!(slot.generation.get() & 1, 1, "a row given back twice");
        // SAFETY: the caller's contract: the row is held, so it holds a value, read out once here.
        let value = unsafe { (*slot.value.get()).assume_init_read() };
        slot.generation.set(slot.generation.get().wrapping_add(1));
        slot.next.set(self.free.get());
        self.free.set(at);
        self.used.set(self.used.get() - 1);
        value
    }

    /// Whether `handle` names a row held since it was taken.
    fn holds(&self, handle: RowHandle) -> bool {
        handle.at < self.top.get() && self.slot(handle.at).generation.get() == handle.generation
    }
}

/// A row a pool handed out ([`RowSpace::take`]): where it lies and the generation it was taken at.
/// Once the row is given back the handle names nothing, though another holder takes the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowHandle {
    at: u32,
    generation: u32,
}

/// What a pool holds, as [`RowSpace::counts`] reads it.
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
    /// The rows refused for want of one: the pool was full.
    pub refused: u32,
}

/// A pool of rows of `T` that the tables of a session's faces share. A handle: copies name the same
/// pool. Made by [`Arena::lend_pool`].
pub struct RowSpace<T> {
    store: NonNull<RowStore<T>>,
}

impl<T> Clone for RowSpace<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RowSpace<T> {}

impl<T> PartialEq for RowSpace<T> {
    fn eq(&self, other: &Self) -> bool {
        self.store == other.store
    }
}

impl<T> Eq for RowSpace<T> {}

impl<T> RowSpace<T> {
    /// The bytes the pool's own state takes at the start of its span, a whole span of an arena.
    const STATE_BYTES: usize = match Arena::span(core::mem::size_of::<RowStore<T>>()) {
        Some(bytes) => bytes,
        None => panic!("a pool's state fits the address space"),
    };

    /// The bytes one row takes: its value and the two words that link and age it.
    pub const fn row_bytes() -> usize {
        core::mem::size_of::<Slot<T>>()
    }

    /// The bytes a pool of `rows` rows takes in an [`Arena`]: its state and its rows. `None` past
    /// [`MAX_POOL_ROWS`] or the address space.
    pub const fn span_bytes(rows: usize) -> Option<usize> {
        if rows > MAX_POOL_ROWS {
            return None;
        }
        match Arena::table_bytes::<Slot<T>>(rows) {
            Some(slots) => slots.checked_add(Self::STATE_BYTES),
            None => None,
        }
    }

    /// A pool of `rows` rows over the span at `span`, none of them held.
    ///
    /// # Safety
    /// `span` is aligned to [`ARENA_ALIGN`](crate::bounded::ARENA_ALIGN), the
    /// [`Self::span_bytes`] of `rows` bytes from it are valid for reads and writes and used by
    /// nothing else for as long as any copy of the pool or any table holding its rows lives, and
    /// `rows` is at most [`MAX_POOL_ROWS`].
    pub(crate) unsafe fn over(span: NonNull<u8>, rows: usize) -> Self {
        const {
            assert!(
                core::mem::align_of::<RowStore<T>>() <= crate::bounded::ARENA_ALIGN
                    && core::mem::align_of::<Slot<T>>() <= crate::bounded::ARENA_ALIGN,
                "a pool's state or row asks for more alignment than an arena's spans start on"
            )
        };
        let store = span.cast::<RowStore<T>>();
        // SAFETY: the caller's contract: the span is aligned for the state, which it starts with,
        // and the rows follow it at a multiple of the arena's alignment, inside the span.
        unsafe {
            store.as_ptr().write(RowStore {
                slots: NonNull::new_unchecked(span.as_ptr().add(Self::STATE_BYTES))
                    .cast::<Slot<T>>(),
                rows: rows as u32,
                top: Cell::new(0),
                free: Cell::new(NIL),
                used: Cell::new(0),
                peak: Cell::new(0),
                refused: Cell::new(0),
            });
        }
        Self { store }
    }

    /// The pool's state.
    fn store(&self) -> &RowStore<T> {
        // SAFETY: `over`'s contract: the state lives for as long as any copy of the handle does.
        unsafe { self.store.as_ref() }
    }

    /// A row holding `value`, or the value back when every row is held, which the pool counts.
    pub fn take(&self, value: T) -> Result<RowHandle, CapacityFull<T>> {
        self.store().take(value)
    }

    /// The value of the row `handle` names, the row back on the free list; `None`, and nothing
    /// done, when the handle names no row held since it was taken (it was given back already).
    pub fn give_back(&self, handle: RowHandle) -> Option<T> {
        let store = self.store();
        if !store.holds(handle) {
            return None;
        }
        // SAFETY: the row is held at the handle's generation, which only `take` handed out, and
        // a row a table holds is never handed out as a handle, so no table links to it.
        Some(unsafe { store.release(handle.at) })
    }

    /// Whether `handle` names a row held since it was taken.
    pub fn holds(&self, handle: RowHandle) -> bool {
        self.store().holds(handle)
    }

    /// What the pool holds now.
    pub fn counts(&self) -> RowCounts {
        let store = self.store();
        RowCounts {
            rows: store.rows as usize,
            used: store.used.get() as usize,
            peak: store.peak.get() as usize,
            untouched: (store.rows - store.top.get()) as usize,
            refused: store.refused.get(),
        }
    }
}

impl<T> fmt::Debug for RowSpace<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RowSpace").field(&self.counts()).finish()
    }
}

/// One table whose rows lie in a pool the session's faces share: at most `N` rows, in the order
/// they were pushed, linked through the rows. Made with no pool ([`Self::new`], `Default`), it
/// refuses every value as a full table does until it is handed one ([`Self::keep_rows_in`]).
/// Dropped or cleared, it gives back exactly the rows it holds.
pub struct PooledRows<T, const N: usize> {
    pool: Option<RowSpace<T>>,
    head: u32,
    tail: u32,
    len: u32,
}

impl<T, const N: usize> PooledRows<T, N> {
    /// A table of no rows and no pool. `const`, as an inline table's constructor is.
    pub const fn new() -> Self {
        Self {
            pool: None,
            head: NIL,
            tail: NIL,
            len: 0,
        }
    }

    /// Take the rows pushed from here on from `pool`. A table keeps the pool it holds rows of: one
    /// that holds rows is emptied first, as its rows belong to the pool it was handed before.
    pub fn keep_rows_in(&mut self, pool: RowSpace<T>) {
        if self.pool != Some(pool) {
            self.clear();
            self.pool = Some(pool);
        }
    }

    /// The pool the table takes its rows from, if it was handed one.
    pub fn pool(&self) -> Option<RowSpace<T>> {
        self.pool
    }

    /// The most rows the table holds: the bound of one table, whatever the pool has left.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many rows the table holds.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the table holds no row.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append `value` in a row of the pool, or hand it back: the table holds `N` rows, it was
    /// handed no pool, or the pool has no row left, which the pool counts.
    pub fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        if self.len() >= N {
            return Err(CapacityFull(value));
        }
        let Some(pool) = self.pool else {
            return Err(CapacityFull(value));
        };
        let at = pool.take(value)?.at;
        let store = pool.store();
        if self.tail == NIL {
            self.head = at;
        } else {
            store.slot(self.tail).next.set(at);
        }
        self.tail = at;
        self.len += 1;
        Ok(())
    }

    /// The values, in the order they were pushed.
    pub fn iter(&self) -> Rows<'_, T> {
        Rows {
            store: self.pool.map(|pool| {
                // SAFETY: as `RowSpace::store`; the reference lives no longer than this table,
                // which holds the pool.
                unsafe { &*pool.store.as_ptr() }
            }),
            at: self.head,
            left: self.len,
        }
    }

    /// The values, mutably, in the order they were pushed.
    pub fn iter_mut(&mut self) -> RowsMut<'_, T> {
        RowsMut {
            store: self.pool.map(|pool| {
                // SAFETY: as in `iter`.
                unsafe { &*pool.store.as_ptr() }
            }),
            at: self.head,
            left: self.len,
            _values: PhantomData,
        }
    }

    /// Unlink the row at `at`, which follows `prev` ([`NIL`] at the head) and precedes `next`.
    fn unlink(&mut self, store: &RowStore<T>, prev: u32, at: u32, next: u32) {
        if prev == NIL {
            self.head = next;
        } else {
            store.slot(prev).next.set(next);
        }
        if self.tail == at {
            self.tail = prev;
        }
        self.len -= 1;
    }

    /// Keep only the values `keep` accepts, in order; each other row goes back to the pool.
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        let Some(pool) = self.pool else {
            return;
        };
        let store = pool.store();
        let (mut prev, mut at) = (NIL, self.head);
        while at != NIL {
            let slot = store.slot(at);
            let next = slot.next.get();
            // SAFETY: the table holds the row, so it holds a value.
            if keep(unsafe { (*slot.value.get()).assume_init_ref() }) {
                prev = at;
            } else {
                self.unlink(store, prev, at, next);
                // SAFETY: the table held the row and no longer links to it.
                drop(unsafe { store.release(at) });
            }
            at = next;
        }
    }

    /// Take the first value `which` accepts out of the table, its row back to the pool.
    pub fn remove_first<F: FnMut(&T) -> bool>(&mut self, mut which: F) -> Option<T> {
        let pool = self.pool?;
        let store = pool.store();
        let (mut prev, mut at) = (NIL, self.head);
        while at != NIL {
            let slot = store.slot(at);
            let next = slot.next.get();
            // SAFETY: the table holds the row, so it holds a value.
            if which(unsafe { (*slot.value.get()).assume_init_ref() }) {
                self.unlink(store, prev, at, next);
                // SAFETY: the table held the row and no longer links to it.
                return Some(unsafe { store.release(at) });
            }
            prev = at;
            at = next;
        }
        None
    }

    /// Give every row back to the pool, each value dropped: one step for each row the table holds.
    pub fn clear(&mut self) {
        let Some(pool) = self.pool else {
            return;
        };
        let store = pool.store();
        let mut at = self.head;
        self.head = NIL;
        self.tail = NIL;
        self.len = 0;
        while at != NIL {
            let next = store.slot(at).next.get();
            // SAFETY: the table held the row, and the list it was linked in is gone.
            drop(unsafe { store.release(at) });
            at = next;
        }
    }
}

impl<T, const N: usize> Default for PooledRows<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for PooledRows<T, N> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for PooledRows<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// The values of a [`PooledRows`], in the order they were pushed.
pub struct Rows<'a, T> {
    store: Option<&'a RowStore<T>>,
    at: u32,
    left: u32,
}

impl<'a, T> Iterator for Rows<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        let store = self.store?;
        if self.at == NIL {
            return None;
        }
        let slot = store.slot(self.at);
        self.at = slot.next.get();
        self.left -= 1;
        // SAFETY: the table this walks holds the row, so it holds a value, and the table is
        // borrowed for as long as the reference lives, so the row is not given back meanwhile.
        Some(unsafe { (*slot.value.get()).assume_init_ref() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}

impl<T> ExactSizeIterator for Rows<'_, T> {}

/// The values of a [`PooledRows`], mutably, in the order they were pushed.
pub struct RowsMut<'a, T> {
    store: Option<&'a RowStore<T>>,
    at: u32,
    left: u32,
    _values: PhantomData<&'a mut T>,
}

impl<'a, T> Iterator for RowsMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<&'a mut T> {
        let store = self.store?;
        if self.at == NIL {
            return None;
        }
        let slot = store.slot(self.at);
        self.at = slot.next.get();
        self.left -= 1;
        // SAFETY: as in `Rows::next`; the table is borrowed mutably for as long as the reference
        // lives, each row is linked once, so no two references this hands out name one value,
        // and no table but this one reaches the row.
        Some(unsafe { (*slot.value.get()).assume_init_mut() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left as usize, Some(self.left as usize))
    }
}

impl<T> ExactSizeIterator for RowsMut<'_, T> {}

/// A table of rows a peer writes, as a storage policy keeps it ([`Storage::Pooled`]): an inline or
/// growable sequence on the policies that keep their own rows, and on the lent one a
/// [`PooledRows`] whose rows the session's faces share. The operations the tables above it need,
/// written once for every policy.
pub trait RowList<T>: Default {
    /// How many values the table holds.
    fn len(&self) -> usize;

    /// Whether the table holds no value.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append `value`, or hand it back when the table or its pool has no room.
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

impl<T, const N: usize> RowList<T> for PooledRows<T, N> {
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
    use crate::bounded::{LendRefused, ARENA_ALIGN};
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

    /// A pool of `rows` rows, lent from an arena of exactly its span.
    fn pool_of<T>(rows: usize) -> RowSpace<T> {
        let span = RowSpace::<T>::span_bytes(rows).expect("a test pool fits");
        let mut arena = arena_of(span);
        let pool = arena.lend_pool(rows).expect("the arena is the pool's span");
        assert_eq!(arena.high_water(), span, "the span is what the pool takes");
        pool
    }

    fn values<const N: usize>(table: &PooledRows<u32, N>) -> Vec<u32> {
        table.iter().copied().collect()
    }

    /// A pool lends its rows until every one is held, refuses the next and counts it, and a row
    /// given back is taken again. A handle names its row only until the row goes back: given back
    /// twice, or read after another holder took the row, it names nothing.
    #[test]
    fn a_handle_names_its_row_until_the_row_goes_back() {
        let pool = pool_of::<u32>(2);
        let first = pool.take(10).expect("a row is free");
        let second = pool.take(20).expect("the last row is free");
        assert_eq!(pool.take(30).err().map(|full| full.0), Some(30));
        assert_eq!(
            (pool.counts().used, pool.counts().refused),
            (2, 1),
            "(rows held, rows refused)"
        );
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
        assert_eq!(pool.give_back(first), None);
        assert_eq!(pool.give_back(again), Some(40));
        assert_eq!(pool.counts().peak, 2);
    }

    /// Many tables, each bounded at sixteen rows, each holding three, fit a pool of the rows they
    /// hold together, far fewer than their bounds add up to; the next value any of them pushes is
    /// refused and counted by the pool, and every table keeps what it held.
    #[test]
    fn many_tables_holding_a_few_rows_fit_a_pool_far_smaller_than_their_bounds() {
        const TABLES: usize = 8;
        let pool = pool_of::<u32>(TABLES * 3);
        let mut tables: Vec<PooledRows<u32, 16>> = (0..TABLES).map(|_| PooledRows::new()).collect();
        for (n, table) in tables.iter_mut().enumerate() {
            table.keep_rows_in(pool);
            for k in 0..3 {
                assert!(table.push((n * 10 + k) as u32).is_ok(), "table {n} row {k}");
            }
        }
        assert_eq!(pool.counts().used, TABLES * 3);
        assert_eq!(tables[5].push(99).err().map(|full| full.0), Some(99));
        assert_eq!(
            (tables[5].len(), pool.counts().refused),
            (3, 1),
            "the refusal takes nothing and is counted once"
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
        let pool = pool_of::<u32>(5);
        let (mut a, mut b) = (PooledRows::<u32, 4>::new(), PooledRows::<u32, 4>::new());
        a.keep_rows_in(pool);
        b.keep_rows_in(pool);
        for v in [1, 2, 3] {
            a.push(v).expect("room");
        }
        for v in [7, 8] {
            b.push(v).expect("room");
        }
        assert_eq!(pool.counts().used, 5);
        a.clear();
        assert_eq!(
            (a.len(), pool.counts().used),
            (0, 2),
            "a's three rows went back"
        );
        assert_eq!(values(&b), [7, 8], "b's rows are untouched");
        let mut c = PooledRows::<u32, 4>::new();
        c.keep_rows_in(pool);
        for v in [4, 5, 6] {
            c.push(v).expect("the rows a gave back");
        }
        assert_eq!(
            pool.counts().untouched,
            0,
            "no row past those written was needed"
        );
        assert!(c.push(9).is_err(), "the pool is full again");
        assert_eq!(values(&b), [7, 8]);
        assert_eq!(values(&c), [4, 5, 6]);
    }

    /// A table keeps the order of its pushes through removals, and its tail follows the last row
    /// it holds: a push after the last row was removed lands last.
    #[test]
    fn a_table_keeps_its_push_order_through_removals() {
        let pool = pool_of::<u32>(8);
        let mut table = PooledRows::<u32, 8>::new();
        table.keep_rows_in(pool);
        for v in 1..=5 {
            table.push(v).expect("room");
        }
        assert_eq!(table.remove_first(|v| *v == 3), Some(3));
        table.retain(|v| *v != 2);
        assert_eq!(values(&table), [1, 4, 5]);
        assert_eq!(table.remove_first(|v| *v == 5), Some(5), "the tail");
        table.push(6).expect("room");
        assert_eq!(values(&table), [1, 4, 6]);
        assert_eq!(table.remove_first(|v| *v == 1), Some(1), "the head");
        table.retain(|_| false);
        assert!(table.is_empty());
        table.push(7).expect("room");
        assert_eq!(values(&table), [7]);
        for v in table.iter_mut() {
            *v += 1;
        }
        assert_eq!(values(&table), [8]);
        assert_eq!(
            pool.counts().used,
            1,
            "only the row held is out of the pool"
        );
    }

    /// A table refuses past its own bound though its pool has rows left, as an inline table of
    /// that bound refuses, and the pool counts no refusal of its own for it.
    #[test]
    fn a_table_refuses_past_its_own_bound_with_rows_left_in_the_pool() {
        let pool = pool_of::<u32>(8);
        let mut table = PooledRows::<u32, 2>::new();
        table.keep_rows_in(pool);
        table.push(1).expect("room");
        table.push(2).expect("room");
        assert_eq!(table.push(3).err().map(|full| full.0), Some(3));
        assert_eq!((pool.counts().used, pool.counts().refused), (2, 0));
    }

    /// A table handed no pool refuses every value, and so does one whose pool lends no row.
    #[test]
    fn a_table_with_no_pool_or_an_empty_one_refuses() {
        let mut table = PooledRows::<u32, 4>::default();
        assert_eq!(table.push(1).err().map(|full| full.0), Some(1));
        let empty = pool_of::<u32>(0);
        table.keep_rows_in(empty);
        assert!(table.push(1).is_err());
        assert_eq!(empty.counts().refused, 1);
    }

    /// A dropped table gives its rows back and drops each value once; so does one handed another
    /// pool, whose rows belong to the first.
    #[test]
    fn a_dropped_table_drops_its_values_and_gives_its_rows_back() {
        let pool = pool_of::<Rc<()>>(4);
        let value = Rc::new(());
        let mut table = PooledRows::<Rc<()>, 4>::new();
        table.keep_rows_in(pool);
        for _ in 0..3 {
            table.push(Rc::clone(&value)).expect("room");
        }
        assert_eq!(Rc::strong_count(&value), 4);
        drop(table);
        assert_eq!(Rc::strong_count(&value), 1, "each value dropped once");
        assert_eq!(pool.counts().used, 0);

        let other = pool_of::<Rc<()>>(4);
        let mut moved = PooledRows::<Rc<()>, 4>::new();
        moved.keep_rows_in(pool);
        moved.push(Rc::clone(&value)).expect("room");
        moved.keep_rows_in(other);
        assert_eq!((pool.counts().used, Rc::strong_count(&value)), (0, 1));
        moved.push(Rc::clone(&value)).expect("the other pool's row");
        assert_eq!(other.counts().used, 1);
    }

    /// An arena one byte short of a pool's span refuses it, taking nothing.
    #[test]
    fn an_arena_refuses_a_pool_past_what_is_left() {
        let span = RowSpace::<u64>::span_bytes(4).expect("fits");
        let mut arena = arena_of(span - 1);
        assert!(matches!(
            arena.lend_pool::<u64>(4),
            Err(LendRefused::Exhausted { .. })
        ));
        assert_eq!(arena.high_water(), 0);
        assert_eq!(
            span,
            Arena::span(core::mem::size_of::<RowStore<u64>>()).expect("fits")
                + Arena::table_bytes::<Slot<u64>>(4).expect("fits"),
            "a pool's span is its state and its rows"
        );
    }

    /// The tables of every policy answer the same: an inline sequence is a `RowList` as a pooled
    /// one is, in push order.
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
        let mut inline = BoundedVec::<u32, 8, crate::bounded::Static>::new_static();
        let pool = pool_of::<u32>(8);
        let mut pooled = PooledRows::<u32, 8>::new();
        pooled.keep_rows_in(pool);
        assert_eq!(exercise(&mut inline), exercise(&mut pooled));
        assert_eq!(
            exercise(&mut BoundedVec::<u32, 8, crate::bounded::Static>::new_static()),
            [10, 30]
        );
    }
}
