// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The column and the keys of the on-use policy ([`OnUse`](crate::bounded::OnUse)): memory a
//! table takes from the allocator at its first value, all of it at once, and never moves after.
//!
//! # The column
//!
//! A [`FirstUse`] is made with its count and no memory. Its first value takes all its count's rows
//! in one allocation, made and given back by one body for every row type (`take_rows`,
//! `give_rows`); it never grows, so a row stays where it was put while it stands, and a value past
//! the count, or one the allocator refuses, is handed back as a value past a fixed table's capacity
//! is. A column never pushed to takes nothing, and a read, a removal or a clear takes nothing either.
//!
//! # The keys
//!
//! A [`HeapKey`] is one allocation of its own: a header (how many keys hold it, its length and the
//! budget it is counted against) and its bytes. A clone is one holder more and takes nothing; the
//! last holder's drop gives the allocation back, and its bytes to the budget. A key is counted
//! against the session's [`KeyBudget`] as the block the session's key arena would give it
//! ([`block_bytes`]), so a budget of `KEY_ARENA_BYTES` refuses a key where an arena of those bytes
//! whose keys left no free block between them would refuse it, and a key past the session's
//! `MAX_KEYEXPR_BYTES` is too long on both.
//!
//! # One thread
//!
//! As the key arena's, the counts are cells: a [`HeapKey`] and the [`BudgetKeys`] a table holds are
//! neither `Send` nor `Sync`, and are reached by the one thread that holds the session's state. A
//! budget its owner keeps behind a lock is checked as the arena is, in a build with debug
//! assertions: a key counted against it made, shared or let go of with that lock not held fails at
//! once ([`KeyBudget::guard_by_owner_lock`]).
//!
//! # Lifetime
//!
//! Every key points at the budget it is counted against, which neither moves nor is let go of while
//! a key of it lives ([`KeyBudget::keys`]), as a key of the arena points at the arena.

use core::alloc::Layout;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::NonNull;
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::bounded::{
    drop_row, drop_rows, CapacityFull, KeyBacking, KeyMaker, KeyUnkept, SeqBacking,
};
#[cfg(debug_assertions)]
use crate::key_arena::OwnerLock;
use crate::key_arena::{block_bytes, KeyCounts};
use crate::limits::MaxKeyexprBytesHeld;

/// The allocation of `rows` rows of `size` bytes each, aligned to `align`; `None` past the address
/// space.
fn rows_layout(size: usize, align: usize, rows: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_mul(rows)?, align).ok()
}

/// The memory of `rows` rows of `size` bytes each, aligned to `align`: one allocation, or `None`
/// where the allocator refuses it, where it is past the address space, or where it is of no bytes
/// (a column of no rows, or of rows of no bytes, takes no memory). One body for every row type.
#[inline(never)]
fn take_rows(size: usize, align: usize, rows: usize) -> Option<NonNull<u8>> {
    let layout = rows_layout(size, align, rows)?;
    if layout.size() == 0 {
        return None;
    }
    // SAFETY: the layout's size is not zero.
    NonNull::new(unsafe { alloc::alloc::alloc(layout) })
}

/// Give back the memory [`take_rows`] took for the same `size`, `align` and `rows`. One body for
/// every row type.
///
/// # Safety
/// `at` is what `take_rows` answered for these three, given back once and read by nothing after.
#[inline(never)]
unsafe fn give_rows(at: NonNull<u8>, size: usize, align: usize, rows: usize) {
    if let Some(layout) = rows_layout(size, align, rows) {
        // SAFETY: the caller's contract: `take_rows` allocated `at` with this layout.
        unsafe { alloc::alloc::dealloc(at.as_ptr(), layout) };
    }
}

/// The sequence of the on-use policy: at most `count` values, at most `N`, in rows taken from the
/// allocator at the first value, all at once (see the module).
pub struct FirstUse<T, const N: usize> {
    /// The rows, once the first value took them: `None` before, and a dangling place for rows of
    /// no bytes, which take none.
    rows: Option<NonNull<T>>,
    /// The rows that hold values: never more than `count`.
    len: u32,
    /// The rows the first value takes, and the most values the column holds.
    count: u32,
    _owns: PhantomData<T>,
}

// SAFETY: the column owns its values and the rows it took, which nothing else reaches, as a `Vec`
// owns its buffer: it may move to another thread when its values may, and be shared when they may be.
unsafe impl<T: Send, const N: usize> Send for FirstUse<T, N> {}
// SAFETY: as `Send`: a shared column hands out shared references to its values only.
unsafe impl<T: Sync, const N: usize> Sync for FirstUse<T, N> {}

impl<T, const N: usize> FirstUse<T, N> {
    /// A column of at most `rows` values, held to the build's `N`, that has taken no memory.
    pub const fn counted(rows: usize) -> Self {
        let most = if rows < N { rows } else { N };
        let count = if most > u32::MAX as usize {
            u32::MAX
        } else {
            most as u32
        };
        Self {
            rows: None,
            len: 0,
            count,
            _owns: PhantomData,
        }
    }

    /// Whether the column took its rows.
    pub fn holds_rows(&self) -> bool {
        self.rows.is_some()
    }

    /// The most values the column holds.
    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// The rows that hold values.
    #[inline(always)]
    fn len(&self) -> usize {
        self.len as usize
    }

    /// The first row: aligned and not null before the rows are taken too, when no value lies there.
    #[inline(always)]
    fn base(&self) -> NonNull<T> {
        match self.rows {
            Some(rows) => rows,
            None => NonNull::dangling(),
        }
    }

    /// Room for `more` values after the last: the column's rows, taken now where none were, and as
    /// many of them free. `false`, nothing taken, past the count or where the allocator refuses.
    #[inline]
    fn room_for(&mut self, more: usize) -> bool {
        // `len` never passes `count`.
        if more > self.count().wrapping_sub(self.len()) {
            return false;
        }
        if more == 0 || self.rows.is_some() {
            return true;
        }
        self.take_memory()
    }

    /// Take the column's rows, all of its count at once. Out of line, so a push inlines one compare
    /// and reaches this by a call only at its column's first value.
    #[inline(never)]
    fn take_memory(&mut self) -> bool {
        let size = core::mem::size_of::<T>();
        if size == 0 {
            self.rows = Some(NonNull::dangling());
            return true;
        }
        match take_rows(size, core::mem::align_of::<T>(), self.count()) {
            Some(rows) => {
                self.rows = Some(rows.cast::<T>());
                true
            }
            None => false,
        }
    }

    /// The next row, for `write` to build a value in where the column keeps it, counted as held
    /// once `write` returns, and the value built: the column's rows taken now where none were, as a
    /// push takes them. `None`, `write` not called, past the count or where the allocator refuses
    /// the rows. For a value too large to be one of its own in a frame.
    ///
    /// # Safety
    /// `write` leaves a whole `T` in the row it is handed, and does not unwind.
    pub unsafe fn push_in_place(
        &mut self,
        write: impl FnOnce(&mut MaybeUninit<T>),
    ) -> Option<&mut T> {
        if !self.room_for(1) {
            return None;
        }
        // SAFETY: `len < count` and the rows are taken (`room_for`), so the row at `len` is the
        // column's and holds no value; a `MaybeUninit<T>` has the layout of `T`.
        let row = unsafe {
            &mut *self
                .base()
                .as_ptr()
                .add(self.len())
                .cast::<MaybeUninit<T>>()
        };
        write(&mut *row);
        self.len = self.len.wrapping_add(1);
        // SAFETY: the caller's contract: `write` left a whole value in the row.
        Some(unsafe { row.assume_init_mut() })
    }

    /// Drop the values from `len` on. The length is shortened first, so a value whose drop panics
    /// leaks the ones after it rather than letting them be dropped twice.
    fn drop_from(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }
        // `len < self.len`, checked above.
        let tail = self.len().wrapping_sub(len);
        // Below the length, which is a `u32`.
        self.len = len as u32;
        if !core::mem::needs_drop::<T>() {
            return;
        }
        // SAFETY: the `tail` rows from `len` held values of `T`, `size_of::<T>()` bytes apart, which
        // the length no longer covers, so each is dropped here once, by `drop_row::<T>`.
        unsafe {
            drop_rows(
                self.base().as_ptr().add(len).cast::<u8>(),
                tail,
                core::mem::size_of::<T>(),
                drop_row::<T>,
            );
        }
    }
}

impl<T, const N: usize> Drop for FirstUse<T, N> {
    fn drop(&mut self) {
        self.drop_from(0);
        if let Some(rows) = self.rows {
            // SAFETY: `take_memory` took these rows for the column's count, which never changes, by
            // `take_rows` of the same three, or took none (rows of no bytes), for which the layout is
            // of no bytes and nothing is given back.
            unsafe { give_rows_of::<T>(rows, self.count()) };
        }
    }
}

/// Give back the rows of a column of `count` rows of `T` whose first is `rows`: nothing where the
/// rows are of no bytes, which took none.
///
/// # Safety
/// `rows` is a column's first row, taken for `count` rows of `T`, given back once.
unsafe fn give_rows_of<T>(rows: NonNull<T>, count: usize) {
    let size = core::mem::size_of::<T>();
    if size == 0 || count == 0 {
        return;
    }
    // SAFETY: the caller's contract: `take_rows` answered `rows` for these three.
    unsafe { give_rows(rows.cast::<u8>(), size, core::mem::align_of::<T>(), count) };
}

impl<T, const N: usize> SeqBacking<T> for FirstUse<T, N> {
    #[inline(always)]
    fn empty() -> Self {
        Self::counted(N)
    }

    fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` rows hold values, and the base is aligned and not null even
        // before the rows are taken, when `len` is zero.
        unsafe { core::slice::from_raw_parts(self.base().as_ptr(), self.len()) }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as `as_slice`, and `&mut self` makes this the only borrow of them.
        unsafe { core::slice::from_raw_parts_mut(self.base().as_ptr(), self.len()) }
    }

    fn free_slots(&self) -> usize {
        self.count().wrapping_sub(self.len())
    }

    fn make_room(&mut self) -> bool {
        self.room_for(1)
    }

    fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        if !self.room_for(1) {
            return Err(CapacityFull(value));
        }
        // SAFETY: `len < count` and the rows are taken, so the row at `len` is the column's and holds
        // no value.
        unsafe { self.base().as_ptr().add(self.len()).write(value) };
        self.len = self.len.wrapping_add(1);
        Ok(())
    }

    fn push_with<F: FnOnce() -> T>(&mut self, make: F) -> bool {
        if !self.room_for(1) {
            return false;
        }
        // SAFETY: as `push`; `make` panicking leaves the row and the length as they were.
        unsafe { self.base().as_ptr().add(self.len()).write(make()) };
        self.len = self.len.wrapping_add(1);
        true
    }

    fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len = self.len.wrapping_sub(1);
        // SAFETY: the row at the old last index held a value, which the length no longer covers,
        // so it is read out once.
        Some(unsafe { self.base().as_ptr().add(self.len()).read() })
    }

    fn remove(&mut self, index: usize) -> T {
        assert!(
            index < self.len(),
            "removal index {index} is past a column of {} values",
            self.len
        );
        // SAFETY: `index < len`: the value at `index` is read out once, and the rows after it, which
        // hold values, move down over it before the length drops by one.
        unsafe {
            let at = self.base().as_ptr().add(index);
            let value = at.read();
            core::ptr::copy(
                at.add(1),
                at,
                self.len().wrapping_sub(index).wrapping_sub(1),
            );
            self.len = self.len.wrapping_sub(1);
            value
        }
    }

    fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        // Each value is asked once, in order: one taken out moves the next to where it stood.
        let mut index = 0usize;
        while let Some(value) = self.as_slice().get(index) {
            if keep(value) {
                index = index.wrapping_add(1);
            } else {
                self.remove(index);
            }
        }
    }

    fn clear(&mut self) {
        self.drop_from(0);
    }

    fn truncate(&mut self, len: usize) {
        self.drop_from(len);
    }

    fn resize(&mut self, len: usize, fill: T) -> Result<(), CapacityFull<()>>
    where
        T: Clone,
    {
        if len > self.len() && !self.room_for(len.wrapping_sub(self.len())) {
            return Err(CapacityFull(()));
        }
        self.drop_from(len);
        while self.len() < len {
            // Within the room made above, so every push is taken.
            if self.push(fill.clone()).is_err() {
                break;
            }
        }
        Ok(())
    }

    fn extend_from_slice(&mut self, src: &[T]) -> Result<(), CapacityFull<()>>
    where
        T: Copy,
    {
        if !self.room_for(src.len()) {
            return Err(CapacityFull(()));
        }
        if src.is_empty() {
            return Ok(());
        }
        // SAFETY: the `src.len()` rows from `len` are the column's, taken and free (checked above),
        // and hold no value; `T: Copy` is copied bitwise. The new length is within `count`, a `u32`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.base().as_ptr().add(self.len()),
                src.len(),
            );
        }
        self.len = self.len().wrapping_add(src.len()) as u32;
        Ok(())
    }
}

impl<T, const N: usize> IntoIterator for FirstUse<T, N> {
    type Item = T;
    type IntoIter = FirstUseIntoIter<T>;

    fn into_iter(self) -> FirstUseIntoIter<T> {
        // The values and the rows move to the iterator, which drops what it is not asked for and
        // gives the rows back.
        let column = core::mem::ManuallyDrop::new(self);
        FirstUseIntoIter {
            rows: column.rows,
            next: 0,
            end: column.len(),
            count: column.count(),
            _owns: PhantomData,
        }
    }
}

/// The values of a [`FirstUse`] column, taken out of it in order.
pub struct FirstUseIntoIter<T> {
    rows: Option<NonNull<T>>,
    next: usize,
    end: usize,
    /// The column's count, which its rows were taken for.
    count: usize,
    _owns: PhantomData<T>,
}

// SAFETY: as `FirstUse`'s: the iterator owns the values it has not handed out yet, and the rows.
unsafe impl<T: Send> Send for FirstUseIntoIter<T> {}
// SAFETY: as `Send`; a shared iterator hands out nothing.
unsafe impl<T: Sync> Sync for FirstUseIntoIter<T> {}

impl<T> Iterator for FirstUseIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.next == self.end {
            return None;
        }
        let rows = self.rows?;
        let index = self.next;
        // Below `end`, checked above.
        self.next = self.next.wrapping_add(1);
        // SAFETY: the rows `next..end` hold values this iterator owns; this one is read out once and
        // the cursor has passed it.
        Some(unsafe { rows.as_ptr().add(index).read() })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end.wrapping_sub(self.next);
        (left, Some(left))
    }
}

impl<T> ExactSizeIterator for FirstUseIntoIter<T> {}

impl<T> Drop for FirstUseIntoIter<T> {
    fn drop(&mut self) {
        let Some(rows) = self.rows else {
            return;
        };
        let (from, left) = (self.next, self.end.wrapping_sub(self.next));
        self.next = self.end;
        // SAFETY: the rows `from..end` hold values no call handed out; each is dropped here once.
        unsafe {
            core::ptr::drop_in_place(core::ptr::slice_from_raw_parts_mut(
                rows.as_ptr().add(from),
                left,
            ));
        }
        // SAFETY: the column's rows, taken for its count, moved here from it and given back once.
        unsafe { give_rows_of::<T>(rows, self.count) };
    }
}

/// The bytes a session's keys may take together and the longest key it keeps: what every
/// [`HeapKey`] made through its [`BudgetKeys`] is counted against (see the module).
pub struct KeyBudget {
    /// The bytes the keys may take together: the session's `KEY_ARENA_BYTES`.
    bytes: usize,
    /// The bytes the keys held now are counted for.
    used: Cell<usize>,
    /// The most `used` has been.
    peak: Cell<usize>,
    /// The keys refused for want of room.
    refused: Cell<u32>,
    /// The longest key kept: the session's `MAX_KEYEXPR_BYTES`.
    longest: MaxKeyexprBytesHeld,
    /// The lock the budget's owner keeps it behind ([`Self::guard_by_owner_lock`]), `None` for a
    /// budget no lock guards. Written before a second thread reaches the budget, or by its owner
    /// alone.
    #[cfg(debug_assertions)]
    guard: Cell<Option<OwnerLock>>,
    /// Whether that lock is held now, by any thread.
    #[cfg(debug_assertions)]
    held: AtomicBool,
}

impl KeyBudget {
    /// A budget of `bytes` that keeps keys of at most `longest` bytes, none counted yet.
    pub fn new(bytes: usize, longest: MaxKeyexprBytesHeld) -> Self {
        Self {
            bytes,
            used: Cell::new(0),
            peak: Cell::new(0),
            refused: Cell::new(0),
            longest,
            #[cfg(debug_assertions)]
            guard: Cell::new(None),
            #[cfg(debug_assertions)]
            held: AtomicBool::new(false),
        }
    }

    /// Whether the budget keeps a key of `len` bytes: at most the session's `MAX_KEYEXPR_BYTES`.
    pub fn holds_key(&self, len: usize) -> bool {
        self.longest.get().admits(len)
    }

    /// The handle a table makes its keys through, counted against this budget.
    ///
    /// # Safety
    /// The budget neither moves nor is let go of while the handle, a copy of it, or a key made
    /// through one lives.
    pub unsafe fn keys(&self) -> BudgetKeys {
        BudgetKeys(Some(NonNull::from(self)))
    }

    /// What the keys counted against the budget take now, in the terms of a key arena's counts:
    /// `untouched` is the bytes the keys have never reached together.
    pub fn counts(&self) -> KeyCounts {
        KeyCounts {
            bytes: self.bytes,
            used: self.used.get(),
            peak: self.peak.get(),
            untouched: self.bytes.saturating_sub(self.peak.get()),
            refused: self.refused.get(),
        }
    }

    /// Keep the budget behind its owner's one lock from now on, the lock that lies at `at`, as the
    /// key arena is kept ([`KeySpace::guard_by_owner_lock`](crate::key_arena::KeySpace::guard_by_owner_lock)):
    /// in a build with debug assertions a key counted against it made, shared or let go of while
    /// the owner has not marked the lock held ([`Self::owner_lock_taken`]), or on a thread for
    /// which `held_here` answers that it does not hold the lock at `at`, fails at once. Nothing is
    /// kept or checked in a build without debug assertions.
    pub fn guard_by_owner_lock(&self, at: *const (), held_here: fn(*const ()) -> bool) {
        #[cfg(debug_assertions)]
        self.guard.set(Some(OwnerLock { at, held_here }));
        #[cfg(not(debug_assertions))]
        let _ = (at, held_here);
    }

    /// The owner holds the budget alone from here on, with no lock (its state is being let go of,
    /// through an exclusive borrow): no other thread reaches it, so nothing is checked.
    pub fn owner_alone(&self) {
        #[cfg(debug_assertions)]
        self.guard.set(None);
    }

    /// The owner took the lock that guards the budget.
    #[inline]
    pub fn owner_lock_taken(&self) {
        #[cfg(debug_assertions)]
        self.held.store(true, Ordering::Relaxed);
    }

    /// The owner is letting go of the lock that guards the budget.
    #[inline]
    pub fn owner_lock_released(&self) {
        #[cfg(debug_assertions)]
        self.held.store(false, Ordering::Relaxed);
    }

    /// Fail at once, in a build with debug assertions, when a key counted against a budget its
    /// owner's lock guards is made, shared or let go of by a thread that does not hold that lock:
    /// the counts are cells, and a thread that touches them outside the lock races the one that
    /// holds it.
    #[inline]
    fn assert_owner_lock(&self) {
        #[cfg(debug_assertions)]
        if let Some(lock) = self.guard.get() {
            assert!(
                self.held.load(Ordering::Relaxed) && (lock.held_here)(lock.at),
                "a key of a budget its owner's lock guards was touched with that lock not held"
            );
        }
    }

    /// Count `cost` bytes more, or `false`, counting nothing, past the budget.
    fn charge(&self, cost: usize) -> bool {
        self.assert_owner_lock();
        let Some(used) = self
            .used
            .get()
            .checked_add(cost)
            .filter(|used| *used <= self.bytes)
        else {
            return false;
        };
        self.used.set(used);
        self.peak.set(self.peak.get().max(used));
        true
    }

    /// Count `cost` bytes fewer: a key counted for them was let go of, or not made.
    fn refund(&self, cost: usize) {
        self.assert_owner_lock();
        self.used.set(self.used.get().saturating_sub(cost));
    }

    /// Count a key refused for want of room, and say so.
    fn refuse(&self) -> KeyUnkept {
        self.assert_owner_lock();
        self.refused.set(self.refused.get().wrapping_add(1));
        KeyUnkept::NoRoom
    }
}

impl fmt::Debug for KeyBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyBudget").field(&self.counts()).finish()
    }
}

/// The header a key's allocation starts with, its bytes right after it.
#[repr(C)]
struct KeyHead {
    /// How many keys hold the allocation: a count at its largest keeps it for good rather than wrap.
    holders: Cell<u32>,
    /// The key's length.
    len: u32,
    /// The budget the key is counted against.
    budget: NonNull<KeyBudget>,
}

/// The allocation of a key of `len` bytes: its header, then its bytes, which start at the header's
/// size, a byte array asking for no more alignment.
fn key_layout(len: usize) -> Option<Layout> {
    let bytes = core::mem::size_of::<KeyHead>().checked_add(len)?;
    Layout::from_size_align(bytes, core::mem::align_of::<KeyHead>()).ok()
}

/// A key a row of the on-use policy keeps: an allocation of its own, shared by its clones and given
/// back with its last (see the module). It reads as the key's text ([`Deref`] to `str`).
pub struct HeapKey {
    /// The allocation, or `None` for the empty key, which takes none.
    head: Option<NonNull<KeyHead>>,
}

impl HeapKey {
    /// `text` as a key of its own, counted against `budget`: refused as too long past the budget's
    /// longest key, before anything is counted, and as no room, counted, where the budget or the
    /// allocator has none. The empty key takes nothing.
    fn make(budget: &KeyBudget, text: &str) -> Result<Self, KeyUnkept> {
        if !budget.holds_key(text.len()) {
            return Err(KeyUnkept::TooLong);
        }
        if text.is_empty() {
            return Ok(Self { head: None });
        }
        let (Some(cost), Ok(len), Some(layout)) = (
            block_bytes(text.len()),
            u32::try_from(text.len()),
            key_layout(text.len()),
        ) else {
            return Err(budget.refuse());
        };
        if !budget.charge(cost) {
            return Err(budget.refuse());
        }
        // SAFETY: the layout holds the header, so its size is not zero.
        let Some(head) = NonNull::new(unsafe { alloc::alloc::alloc(layout) }) else {
            budget.refund(cost);
            return Err(budget.refuse());
        };
        let head = head.cast::<KeyHead>();
        // SAFETY: the allocation is aligned for the header and holds it and `text.len()` bytes after
        // it, none of them read before this write.
        unsafe {
            head.as_ptr().write(KeyHead {
                holders: Cell::new(1),
                len,
                budget: NonNull::from(budget),
            });
            core::ptr::copy_nonoverlapping(
                text.as_ptr(),
                head.as_ptr()
                    .cast::<u8>()
                    .add(core::mem::size_of::<KeyHead>()),
                text.len(),
            );
        }
        Ok(Self { head: Some(head) })
    }

    /// The header, while this key holds it.
    fn head(&self) -> Option<&KeyHead> {
        // SAFETY: the allocation lives while any of its holders does, this one among them.
        self.head.map(|head| unsafe { &*head.as_ptr() })
    }

    /// The key's text.
    pub fn as_str(&self) -> &str {
        let Some(head) = self.head else {
            return "";
        };
        // SAFETY: the allocation holds the header and, after it, the `len` bytes of the `str` the key
        // was made from, which nothing writes while a holder lives.
        unsafe {
            let len = (*head.as_ptr()).len as usize;
            let text = head
                .as_ptr()
                .cast::<u8>()
                .add(core::mem::size_of::<KeyHead>());
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(text, len))
        }
    }

    /// The bytes the key is counted for against its budget, the block the key arena would give it;
    /// none for the empty key.
    pub fn block_bytes(&self) -> usize {
        self.head()
            .and_then(|head| block_bytes(head.len as usize))
            .unwrap_or(0)
    }
}

impl Clone for HeapKey {
    fn clone(&self) -> Self {
        if let Some(head) = self.head() {
            // SAFETY: the budget outlives every key counted against it (`KeyBudget::keys`).
            unsafe { head.budget.as_ref() }.assert_owner_lock();
            head.holders.set(head.holders.get().saturating_add(1));
        }
        Self { head: self.head }
    }
}

impl Drop for HeapKey {
    fn drop(&mut self) {
        let Some(head) = self.head else {
            return;
        };
        let at = head.as_ptr();
        // SAFETY: this key is one of the allocation's holders, so the header is there.
        let (holders, len, budget) = unsafe { ((*at).holders.get(), (*at).len, (*at).budget) };
        // SAFETY: the budget outlives every key counted against it (`KeyBudget::keys`).
        let budget = unsafe { budget.as_ref() };
        budget.assert_owner_lock();
        // A count held at its largest keeps the allocation for good.
        if holders == u32::MAX {
            return;
        }
        if holders > 1 {
            // SAFETY: as above.
            unsafe { (*at).holders.set(holders.wrapping_sub(1)) };
            return;
        }
        let len = len as usize;
        budget.refund(block_bytes(len).unwrap_or(0));
        if let Some(layout) = key_layout(len) {
            // SAFETY: the last holder gives back the allocation `make` took with this layout, once.
            unsafe { alloc::alloc::dealloc(at.cast::<u8>(), layout) };
        }
    }
}

impl Deref for HeapKey {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl KeyBacking for HeapKey {
    fn as_str(&self) -> &str {
        HeapKey::as_str(self)
    }
}

impl AsRef<str> for HeapKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HeapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for HeapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl PartialEq for HeapKey {
    fn eq(&self, other: &HeapKey) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for HeapKey {}

impl PartialEq<str> for HeapKey {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for HeapKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Where a table of the on-use policy makes the keys its rows keep
/// ([`Storage::Keys`](crate::bounded::Storage::Keys)): the session's [`KeyBudget`], which the table
/// is handed with its count, or none for a table made by `Default`, which keeps no key.
#[derive(Clone, Copy, Debug, Default)]
pub struct BudgetKeys(Option<NonNull<KeyBudget>>);

impl BudgetKeys {
    /// The budget the table's keys are counted against, if it was handed one.
    pub fn budget(&self) -> Option<&KeyBudget> {
        // SAFETY: `KeyBudget::keys`'s contract: the budget lives, unmoved, while this handle does.
        self.0.map(|budget| unsafe { &*budget.as_ptr() })
    }

    /// What the keys counted against the budget take now ([`KeyBudget::counts`]), as the key
    /// arena's handle answers for its arena: nothing for a handle of no budget.
    pub fn counts(&self) -> KeyCounts {
        self.budget().map(KeyBudget::counts).unwrap_or_default()
    }

    /// Keep the budget behind its owner's one lock ([`KeyBudget::guard_by_owner_lock`]); a handle
    /// of no budget has nothing to keep.
    pub fn guard_by_owner_lock(&self, at: *const (), held_here: fn(*const ()) -> bool) {
        if let Some(budget) = self.budget() {
            budget.guard_by_owner_lock(at, held_here);
        }
    }

    /// The owner holds the budget alone from here on ([`KeyBudget::owner_alone`]).
    pub fn owner_alone(&self) {
        if let Some(budget) = self.budget() {
            budget.owner_alone();
        }
    }

    /// The owner took the lock that guards the budget ([`KeyBudget::owner_lock_taken`]).
    #[inline]
    pub fn owner_lock_taken(&self) {
        if let Some(budget) = self.budget() {
            budget.owner_lock_taken();
        }
    }

    /// The owner is letting go of the lock that guards the budget
    /// ([`KeyBudget::owner_lock_released`]).
    #[inline]
    pub fn owner_lock_released(&self) {
        if let Some(budget) = self.budget() {
            budget.owner_lock_released();
        }
    }
}

impl KeyMaker<HeapKey> for BudgetKeys {
    /// A key past the session's `MAX_KEYEXPR_BYTES` is refused before anything is counted, as a
    /// row of the static policy refuses one past its buffer; a key the budget or the allocator has
    /// no room for is refused and counted ([`KeyCounts::refused`]). A table handed no budget keeps
    /// no key.
    fn key(&self, text: &str) -> Result<HeapKey, KeyUnkept> {
        let Some(budget) = self.budget() else {
            return Err(KeyUnkept::NoRoom);
        };
        HeapKey::make(budget, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit_binding::{LimitSpec, Quota};
    use crate::limits::SessionLimits;

    /// A value that counts its drops in a cell.
    struct Counted<'a>(&'a Cell<u32>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get().saturating_add(1));
        }
    }

    /// A budget of `bytes` that keeps keys as long as a session that states nothing does.
    fn budget_of(bytes: usize) -> KeyBudget {
        KeyBudget::new(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
    }

    /// A column takes no memory until its first value, then all of its count's rows at once, which
    /// never move, and refuses a value past its count though the build's `N` is larger; reading,
    /// popping and clearing an empty column take nothing. Turned red by a column that takes its rows
    /// before a value asks for them, takes one row at a time (the first row moves), or holds to `N`
    /// rather than its count.
    #[test]
    fn a_column_takes_its_rows_at_its_first_value_and_never_moves_them() {
        let mut column = FirstUse::<u64, 8>::counted(3);
        assert_eq!(column.count(), 3);
        assert_eq!(column.free_slots(), 3);
        assert!(column.as_slice().is_empty());
        assert_eq!(column.pop(), None);
        column.clear();
        column.truncate(0);
        assert!(
            !column.holds_rows(),
            "a read, a pop and a clear take nothing"
        );
        assert!(column.push(1).is_ok());
        assert!(column.holds_rows());
        let first: *const u64 = &column.as_slice()[0];
        assert!(column.push(2).is_ok());
        assert!(column.push(3).is_ok());
        assert!(
            core::ptr::eq(&column.as_slice()[0], first),
            "the rows never move"
        );
        match column.push(4) {
            Err(CapacityFull(back)) => assert_eq!(back, 4),
            Ok(()) => panic!("a value went in past the count"),
        }
        assert_eq!(column.as_slice(), &[1, 2, 3]);
        assert_eq!(column.free_slots(), 0);
    }

    /// A column counted past the build's `N` holds `N`, and a column of no rows refuses every value
    /// and takes nothing, an empty slice put in among them. Turned red by a count not held to `N`, or
    /// by a column that takes memory it has no row for.
    #[test]
    fn a_column_holds_its_count_to_the_build_and_one_of_no_rows_takes_nothing() {
        assert_eq!(FirstUse::<u8, 4>::counted(100).count(), 4);
        let mut none = FirstUse::<u8, 4>::counted(0);
        assert!(none.push(1).is_err());
        assert!(!none.make_room());
        assert!(none.extend_from_slice(&[]).is_ok());
        assert!(none.extend_from_slice(&[1]).is_err());
        assert!(none.resize(1, 0).is_err());
        assert!(!none.holds_rows());
    }

    /// Order, removal and the bulk forms keep the shape every policy's sequence keeps, and the
    /// bulk forms refuse whole: a slice or a resize past the count takes nothing and changes
    /// nothing. Turned red by a refused bulk form that wrote part of itself.
    #[test]
    fn a_column_keeps_order_and_refuses_a_bulk_form_whole() {
        let mut column = FirstUse::<u8, 8>::counted(5);
        assert!(column.extend_from_slice(b"abc").is_ok());
        assert!(
            column.extend_from_slice(b"def").is_err(),
            "six bytes in a column of five"
        );
        assert_eq!(column.as_slice(), b"abc");
        assert!(column.resize(6, b'z').is_err());
        assert_eq!(column.as_slice(), b"abc");
        assert!(column.resize(5, b'z').is_ok());
        assert_eq!(column.as_slice(), b"abczz");
        assert_eq!(column.remove(1), b'b');
        column.retain(|b| *b != b'z');
        assert_eq!(column.as_slice(), b"ac");
        assert!(column.resize(1, b'q').is_ok());
        assert_eq!(column.as_slice(), b"a");
    }

    /// Every value put in a column is dropped once: by a truncation, by the column's drop, and by its
    /// iterator, whether the iterator handed it out or was dropped with it left. Turned red by a drop
    /// that skips a value, drops one twice, or drops a row no value was written to.
    #[test]
    fn every_value_of_a_column_is_dropped_once() {
        let drops = Cell::new(0);
        let mut column = FirstUse::<Counted<'_>, 4>::counted(4);
        for _ in 0..3 {
            assert!(column.push(Counted(&drops)).is_ok());
        }
        column.truncate(1);
        assert_eq!(drops.get(), 2);
        drop(column);
        assert_eq!(drops.get(), 3);

        let mut column = FirstUse::<Counted<'_>, 4>::counted(4);
        for _ in 0..3 {
            assert!(column.push(Counted(&drops)).is_ok());
        }
        let mut values = column.into_iter();
        drop(values.next());
        assert_eq!(drops.get(), 4);
        drop(values);
        assert_eq!(drops.get(), 6);

        let never = FirstUse::<Counted<'_>, 4>::counted(4);
        drop(never.into_iter());
        assert_eq!(drops.get(), 6, "a column that took nothing drops nothing");
    }

    /// The one body that takes rows refuses an allocation past the address space, and one of no
    /// bytes, without asking the allocator. Turned red by an overflow of the rows' bytes that wraps
    /// to a smaller allocation.
    #[test]
    fn rows_past_the_address_space_or_of_no_bytes_are_not_taken() {
        assert!(take_rows(usize::MAX, 8, 2).is_none());
        assert!(take_rows(1, 1, usize::MAX).is_none());
        assert!(take_rows(8, 8, 0).is_none());
    }

    /// A key reads back whole and is counted as the block the key arena would give it, until it is
    /// let go of. Turned red by a key that copies part of its text, or that is counted for other
    /// bytes than the arena's block.
    #[test]
    fn a_key_reads_back_whole_and_is_counted_as_its_block() {
        let budget = budget_of(256);
        // SAFETY: the budget outlives the handle and every key, all of this test's.
        let keys = unsafe { budget.keys() };
        let key = keys.key("demo/key/one").expect("room for the key");
        assert_eq!(key.as_str(), "demo/key/one");
        assert_eq!(&*key, "demo/key/one");
        let block = block_bytes(12).expect("a short key's block");
        assert_eq!(key.block_bytes(), block);
        assert_eq!(budget.counts().used, block);
        drop(key);
        assert_eq!(budget.counts().used, 0);
        assert_eq!(budget.counts().peak, block);
    }

    /// A key past the session's `MAX_KEYEXPR_BYTES` is too long, and a key past what the budget has
    /// left is no room, counted; neither takes anything, and the bytes a key gave back are taken
    /// again. Turned red by a refusal that counts bytes, or by a budget that does not get back the
    /// bytes of a key let go of.
    #[test]
    fn a_key_past_the_bound_or_the_budget_is_refused_and_takes_nothing() {
        let one = block_bytes(5).expect("a short key's block");
        let budget = budget_of(one * 2);
        // SAFETY: as in the test above.
        let keys = unsafe { budget.keys() };
        let long = "k".repeat(crate::caps::MAX_KEYEXPR_BYTES + 1);
        assert_eq!(keys.key(&long).err(), Some(KeyUnkept::TooLong));
        assert_eq!(budget.counts().refused, 0, "a key too long asks no room");
        let first = keys.key("aaaaa").expect("room for one");
        let second = keys.key("bbbbb").expect("room for two");
        assert_eq!(keys.key("ccccc").err(), Some(KeyUnkept::NoRoom));
        assert_eq!(budget.counts().used, one * 2);
        assert_eq!(budget.counts().refused, 1);
        drop(first);
        let third = keys
            .key("ccccc")
            .expect("the bytes the first key gave back");
        assert_eq!((second.as_str(), third.as_str()), ("bbbbb", "ccccc"));
    }

    /// A budget keeps keys up to the `MAX_KEYEXPR_BYTES` it was made with, lowered under the build's,
    /// and refuses one byte more as too long; a build whose domain is its own value alone has no
    /// lower bound to state.
    #[test]
    fn a_budget_holds_keys_to_the_bound_it_was_made_with() {
        let mut limits = SessionLimits::defaults();
        if limits.select_max_keyexpr_bytes(Quota::at_most(8)).is_err() {
            assert!(
                <crate::limits::MaxKeyexprBytes as LimitSpec>::DOMAIN.is_singleton(),
                "only a domain of one value refuses a lower bound"
            );
            return;
        }
        let budget = KeyBudget::new(256, limits.max_keyexpr_bytes_held());
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        assert_eq!(keys.key(&"k".repeat(9)).err(), Some(KeyUnkept::TooLong));
        let at = keys.key(&"k".repeat(8)).expect("a key of the bound itself");
        assert_eq!(at.as_str().len(), 8);
    }

    /// A clone is one more holder and takes nothing; the key lives until its last holder is let go
    /// of, and its bytes go back to the budget then. Turned red by a clone that copies the key, or a
    /// drop that gives the allocation back while a holder remains.
    #[test]
    fn a_shared_key_lives_until_its_last_holder() {
        let budget = budget_of(256);
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        let first = keys.key("shared/key").expect("room for the key");
        let used = budget.counts().used;
        let second = first.clone();
        assert_eq!(budget.counts().used, used, "a clone takes nothing");
        assert_eq!(first, second);
        drop(first);
        assert_eq!(second.as_str(), "shared/key");
        assert_eq!(budget.counts().used, used);
        drop(second);
        assert_eq!(budget.counts().used, 0);
    }

    /// The empty key takes nothing and reads as empty; a table handed no budget keeps no key, the
    /// empty one among them. Turned red by an empty key that is counted, or by a table with no
    /// budget that keeps a key.
    #[test]
    fn the_empty_key_takes_nothing_and_no_budget_keeps_nothing() {
        let budget = budget_of(0);
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        let empty = keys.key("").expect("the empty key takes no room");
        assert_eq!(empty.as_str(), "");
        assert_eq!(empty.block_bytes(), 0);
        assert_eq!(keys.key("a").err(), Some(KeyUnkept::NoRoom));
        let none = BudgetKeys::default();
        assert!(none.budget().is_none());
        assert_eq!(none.key("a").err(), Some(KeyUnkept::NoRoom));
        assert_eq!(none.key("").err(), Some(KeyUnkept::NoRoom));
    }

    /// A value written where the column keeps it takes the column's rows at the first, as a push
    /// does, and one past the count is refused with its write not called. Turned red by a write in
    /// place that does not make the column's room first (`room_for`), which writes a row before the
    /// rows are taken or past the count.
    #[test]
    fn a_value_written_in_place_takes_the_rows_and_holds_the_count() {
        let mut column = FirstUse::<u64, 4>::counted(2);
        // SAFETY: the write leaves a whole value in its row and cannot unwind.
        let first = unsafe {
            column.push_in_place(|row| {
                row.write(7);
            })
        };
        assert_eq!(first.copied(), Some(7));
        assert!(column.holds_rows());
        let mut called = false;
        // SAFETY: as above, for each write.
        unsafe {
            assert!(column
                .push_in_place(|row| {
                    row.write(8);
                })
                .is_some());
            assert!(
                column
                    .push_in_place(|row| {
                        called = true;
                        row.write(9);
                    })
                    .is_none(),
                "one past the count"
            );
        }
        assert!(!called, "a refused write is not called");
        assert_eq!(column.as_slice(), &[7, 8]);
    }

    /// An owner whose answer is that every thread holds its lock, which leaves its mark to say
    /// whether the lock is held.
    fn held_by_every_thread(_: *const ()) -> bool {
        true
    }

    /// An owner whose answer is that the calling thread does not hold its lock: the thread runs
    /// beside the one that holds it.
    fn held_by_another_thread(_: *const ()) -> bool {
        false
    }

    /// A budget its owner's lock guards makes, shares and lets go of keys while the owner marks the
    /// lock held; a key let go of after the lock is let go of fails a debug build at once. Turned red
    /// by a key's drop that does not ask its budget's guard (`assert_owner_lock` in `HeapKey`'s
    /// drop).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "that lock not held")]
    fn a_key_let_go_of_outside_its_budgets_lock_fails() {
        let budget = budget_of(256);
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        keys.guard_by_owner_lock(core::ptr::null(), held_by_every_thread);
        keys.owner_lock_taken();
        let key = keys.key("demo/guarded").expect("room");
        drop(key.clone());
        keys.owner_lock_released();
        drop(key);
    }

    /// A key let go of by a thread that does not hold its budget's lock fails a debug build at
    /// once, though the mark says another thread holds the lock: the race the mark alone misses.
    /// Turned red by a guard that reads the owner's mark and not its answer for the calling thread.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "that lock not held")]
    fn a_key_let_go_of_beside_the_thread_that_holds_its_budgets_lock_fails() {
        let budget = budget_of(256);
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        let key = keys.key("demo/beside").expect("room");
        keys.guard_by_owner_lock(core::ptr::null(), held_by_another_thread);
        keys.owner_lock_taken();
        drop(key);
    }

    /// The CONTROL: keys made, shared and let go of while the lock is marked held, and one let go of
    /// once the owner holds the budget alone, pass, and every byte goes back; the handle reads its
    /// budget's counts, and one of no budget counts nothing. Turned red by a guard that fails a key
    /// touched under the lock, or by an owner alone still checked.
    #[test]
    fn keys_under_their_budgets_lock_or_with_the_owner_alone_pass() {
        let budget = budget_of(256);
        // SAFETY: as in the tests above.
        let keys = unsafe { budget.keys() };
        keys.guard_by_owner_lock(core::ptr::null(), held_by_every_thread);
        keys.owner_lock_taken();
        let key = keys.key("demo/guarded").expect("room");
        let alone = keys.key("demo/alone").expect("room");
        drop(key.clone());
        drop(key);
        keys.owner_lock_released();
        keys.guard_by_owner_lock(core::ptr::null(), held_by_another_thread);
        keys.owner_alone();
        drop(alone);
        assert_eq!(keys.counts().used, 0);
        assert_eq!(
            keys.counts(),
            budget.counts(),
            "the handle reads its budget"
        );
        assert_eq!(BudgetKeys::default().counts(), KeyCounts::default());
    }
}
