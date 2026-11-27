// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A counted table of rows, each a value made in an allocation of its own at the row's first use
//! and kept where it lies until the table is dropped ([`OnceRows`]): what the read slots of the
//! faces past the dial role's and the places of the faces' rooms lie in where the session's tables
//! take their memory on use. A row is read through a shared reference by every read, with no lock:
//! its value is published whole, once, and never moved or let go of while the table stands, so a
//! reader that sees the row made reads a value that stays. A table held under a lock of its own
//! (the rooms') makes and changes its values with the table held alone instead.

use core::alloc::Layout;
use core::marker::PhantomData;
use core::ptr::NonNull;
use core::sync::atomic::AtomicPtr;
#[cfg(any(feature = "listen", test))]
use core::sync::atomic::Ordering;

use wz_session_core::bounded::{BoundedVec, OnUse};

use crate::arena::{ArenaRefused, MAX_FACE_SETS};

/// One row of a [`OnceRows`]: null until its value is made, then the allocation the value lies in,
/// which the row owns.
struct OnceRow<T> {
    at: AtomicPtr<T>,
    /// The row owns the value it points at, as a `Box` does.
    _owns: PhantomData<T>,
}

impl<T> OnceRow<T> {
    /// A row that holds no value yet.
    const fn empty() -> Self {
        Self {
            at: AtomicPtr::new(core::ptr::null_mut()),
            _owns: PhantomData,
        }
    }

    /// The row's value, once it was made.
    #[cfg(any(feature = "listen", test))]
    fn get(&self) -> Option<&T> {
        // SAFETY: a pointer is stored once, after the whole value was written in its allocation
        // (`OnceRows::made`, whose release this acquire reads), and the value is dropped only by
        // the row's own drop, which no shared reference outlives.
        NonNull::new(self.at.load(Ordering::Acquire)).map(|at| unsafe { at.as_ref() })
    }

    /// The row's value, once it was made, with the row held alone.
    fn get_mut(&mut self) -> Option<&mut T> {
        // SAFETY: as `Self::get`, and the row is borrowed alone, so the value is.
        NonNull::new(*self.at.get_mut()).map(|mut at| unsafe { at.as_mut() })
    }
}

impl<T> Drop for OnceRow<T> {
    fn drop(&mut self) {
        let Some(at) = NonNull::new(*self.at.get_mut()) else {
            return;
        };
        // SAFETY: the row owns the value its pointer names, written whole in an allocation of
        // `T`'s layout (`OnceRows::made`); it is dropped once, here, in place, and its allocation
        // given back after it.
        unsafe { let_go(at) };
    }
}

/// Drop the value at `at` where it lies and give its allocation back.
///
/// # Safety
/// `at` holds a whole `T` in an allocation of `T`'s layout the global allocator gave, which
/// nothing reaches after this.
unsafe fn let_go<T>(at: NonNull<T>) {
    // SAFETY: the caller's contract.
    unsafe {
        core::ptr::drop_in_place(at.as_ptr());
        alloc::alloc::dealloc(at.as_ptr().cast::<u8>(), Layout::new::<T>());
    }
}

/// A table of rows counted when it is made, at most [`MAX_FACE_SETS`], whose values are made one
/// at a time, each at its row's first use, in an allocation of its own (`Self::made`, or
/// `Self::made_mut` with the table held alone), and kept where they lie until the table is
/// dropped: a value made once serves every later use of its row. The rows themselves are taken
/// whole when the table is made, so a row never moves while another is made, and a reader walks
/// them while a value is made with no lock between them.
pub(crate) struct OnceRows<T> {
    rows: BoundedVec<OnceRow<T>, MAX_FACE_SETS, OnUse>,
}

// SAFETY: the table owns each value made in it, as a `Box` owns its value, so it is sent with
// the table.
unsafe impl<T: Send> Send for OnceRows<T> {}
// SAFETY: a shared table hands `&T` to every holder and makes a value on whichever thread asks,
// which the table's owner drops: the value is shared and sent, as `OnceLock`'s is.
unsafe impl<T: Send + Sync> Sync for OnceRows<T> {}

impl<T> OnceRows<T> {
    /// A table of `rows` rows, none holding a value. Refused, having taken nothing, when the
    /// allocator has no room for the rows; a table of no row takes nothing.
    pub(crate) fn counted(rows: usize) -> Result<Self, ArenaRefused> {
        const {
            assert!(
                core::mem::size_of::<T>() != 0,
                "a value of its own holds some bytes"
            )
        };
        let mut table = BoundedVec::counted(rows);
        for _ in 0..rows {
            // The first push takes every row of the count at once; a refused one takes none.
            if table.push(OnceRow::empty()).is_err() {
                return Err(ArenaRefused::NoMemory {
                    bytes: rows.saturating_mul(core::mem::size_of::<OnceRow<T>>()),
                });
            }
        }
        Ok(Self { rows: table })
    }

    /// The value of row `row`, once it was made; `None` past the rows or before.
    #[cfg(feature = "listen")]
    pub(in crate::engine) fn get(&self, row: usize) -> Option<&T> {
        self.rows.get(row).and_then(OnceRow::get)
    }

    /// Every row in order, each its value once it was made.
    #[cfg(any(feature = "listen", test))]
    pub(in crate::engine) fn rows(
        &self,
    ) -> impl DoubleEndedIterator<Item = Option<&T>> + ExactSizeIterator {
        self.rows.iter().map(OnceRow::get)
    }

    /// The values made, in the order of their rows.
    #[cfg(any(feature = "listen", test))]
    pub(in crate::engine) fn iter(&self) -> impl Iterator<Item = &T> {
        self.rows().flatten()
    }

    /// The values made, in the order of their rows, with the table held alone.
    pub(in crate::engine) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.rows.iter_mut().filter_map(OnceRow::get_mut)
    }

    /// Row `row` with the table held alone: its value once it was made, `Some(None)` before;
    /// `None` past the rows.
    pub(in crate::engine) fn row_mut(&mut self, row: usize) -> Option<Option<&mut T>> {
        self.rows.get_mut(row).map(OnceRow::get_mut)
    }

    /// The value of row `row` with the table held alone, made by `make` in an allocation of its
    /// own where the row holds none yet: what a table under a lock of its own asks, where no other
    /// make of the row runs beside it. `None` past the rows, `make` not called, or when the
    /// allocator has no room for the value, which is dropped.
    pub(in crate::engine) fn made_mut(
        &mut self,
        row: usize,
        make: impl FnOnce() -> T,
    ) -> Option<&mut T> {
        let slot = self.rows.get_mut(row)?;
        if slot.at.get_mut().is_null() {
            let value = make();
            let layout = Layout::new::<T>();
            // SAFETY: the layout's size is not zero (`Self::counted`).
            let at = NonNull::new(unsafe { alloc::alloc::alloc(layout) }.cast::<T>())?;
            // SAFETY: the allocation is of `T`'s layout, aligned and valid for a write of one;
            // the row, held alone, owns the value from here and drops it only in its own drop.
            unsafe { at.as_ptr().write(value) };
            *slot.at.get_mut() = at.as_ptr();
        }
        slot.get_mut()
    }

    /// The value of row `row`, made by `write` in an allocation of its own where the row holds
    /// none yet. `None`, `write` not called, past the rows or when the allocator has no room for
    /// the value. Where another value was made in the row while `write` ran, that one is the
    /// row's, and the one `write` made is dropped unseen.
    ///
    /// # Safety
    /// `write` leaves a whole `T` at the pointer it is handed, which is aligned for `T` and valid
    /// for writes of one, and does not unwind; the value is not moved from there.
    #[cfg(feature = "listen")]
    pub(in crate::engine) unsafe fn made(
        &self,
        row: usize,
        write: impl FnOnce(NonNull<T>),
    ) -> Option<&T> {
        let slot = self.rows.get(row)?;
        if let Some(made) = slot.get() {
            return Some(made);
        }
        let layout = Layout::new::<T>();
        // SAFETY: the layout's size is not zero (`Self::counted`).
        let at = NonNull::new(unsafe { alloc::alloc::alloc(layout) }.cast::<T>())?;
        write(at);
        match slot.at.compare_exchange(
            core::ptr::null_mut(),
            at.as_ptr(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // SAFETY: the value is whole (the caller's contract) and the row owns it from here,
            // dropping it only in its own drop.
            Ok(_) => Some(unsafe { at.as_ref() }),
            Err(other) => {
                // SAFETY: the value `write` made was never published: dropped once, here; the
                // row's value is whole, published by the store this exchange read.
                unsafe {
                    let_go(at);
                    Some(&*other)
                }
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// A value that counts its drops.
    struct Counted<'d> {
        drops: &'d Cell<usize>,
        id: usize,
    }

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    /// Write `Counted { drops, id }` at `at`.
    #[cfg(feature = "listen")]
    fn write_at<'d>(at: NonNull<Counted<'d>>, drops: &'d Cell<usize>, id: usize) {
        // SAFETY: the pointer the table hands is aligned and valid for writes of one value.
        unsafe { at.as_ptr().write(Counted { drops, id }) };
    }

    /// A table made holds no value in any row: each is made at its row's first use, where it then
    /// lies for every use after, the rows around it still empty; a row past the count is refused
    /// with nothing made, and every value made is dropped once, with the table. Turned red by a
    /// `counted` that makes its rows' values (a made value in place of `OnceRow::empty`), by a
    /// `made` that makes a second value for a row that holds one, or by `OnceRow`'s drop skipping
    /// a made value or dropping an empty row's.
    #[cfg(feature = "listen")]
    #[test]
    fn an_on_use_rows_value_is_made_at_its_first_use_and_kept_there() {
        let drops = Cell::new(0);
        let table = OnceRows::<Counted<'_>>::counted(3).expect("the test allocator answers");
        assert_eq!(
            table.rows().len(),
            3,
            "CONTROL: the table holds its count of rows"
        );
        assert!(
            table.rows().all(|row| row.is_none()),
            "no row holds a value yet"
        );
        // SAFETY: `write_at` writes a whole value.
        let first = unsafe { table.made(1, |at| write_at(at, &drops, 7)) }.expect("row 1 is made");
        let first = core::ptr::from_ref(first);
        // SAFETY: as above; the row holds a value, so `write` is not called.
        let again = unsafe { table.made(1, |_| unreachable!("the row holds its value")) };
        assert!(
            again.is_some_and(|again| core::ptr::eq(again, first)),
            "a made row is read where its value lies"
        );
        assert_eq!(table.get(1).map(|made| made.id), Some(7));
        assert!(
            table.get(0).is_none() && table.get(2).is_none(),
            "the other rows hold none"
        );
        assert_eq!(table.iter().count(), 1, "the values made are the one row's");
        // SAFETY: as above; past the rows `write` is not called.
        assert!(unsafe { table.made(3, |_| unreachable!("past the rows")) }.is_none());
        assert_eq!(drops.get(), 0, "nothing is dropped while the table stands");
        drop(table);
        assert_eq!(
            drops.get(),
            1,
            "the one value made is dropped once, with the table"
        );
    }

    /// A value made in a row while another make of the same row ran is the row's, and the one the
    /// other make wrote is dropped unseen: here the inner make is reached from the outer one's
    /// write, the one order in which two makes of a row meet on one thread. Turned red by `made`
    /// storing its value over one another make published (a plain store in place of the exchange),
    /// or by the losing value kept or dropped twice.
    #[cfg(feature = "listen")]
    #[test]
    fn an_on_use_row_made_twice_at_once_keeps_the_first_value_published() {
        let drops = Cell::new(0);
        let table = OnceRows::<Counted<'_>>::counted(1).expect("the test allocator answers");
        // SAFETY: each write writes a whole value; the inner make finds the row empty and makes
        // it, the outer one then finds it made when it publishes.
        let kept = unsafe {
            table.made(0, |outer| {
                table.made(0, |inner| write_at(inner, &drops, 2));
                write_at(outer, &drops, 1);
            })
        }
        .map(|kept| kept.id);
        assert_eq!(kept, Some(2), "the value published first is the row's");
        assert_eq!(drops.get(), 1, "the losing value is dropped unseen, once");
        assert_eq!(table.get(0).map(|made| made.id), Some(2));
        drop(table);
        assert_eq!(drops.get(), 2, "the row's value is dropped with the table");
    }

    /// A table of no row takes nothing and holds none: every row is past its count. Turned red by
    /// `counted` pushing a row past `rows`.
    #[test]
    fn an_on_use_table_of_no_row_holds_none() {
        let mut table =
            OnceRows::<Counted<'_>>::counted(0).expect("a table of no row takes nothing");
        assert_eq!(table.rows().len(), 0);
        assert!(table.row_mut(0).is_none());
        assert!(table
            .made_mut(0, || unreachable!("past the rows"))
            .is_none());
    }

    /// A table held alone makes a row's value at the row's first make and changes it where it
    /// lies after: a second make finds it and calls nothing, a row not made reads as one before
    /// its value, and the value made is dropped once, with the table. Turned red by a `made_mut`
    /// that makes a second value for a row that holds one, or that makes none (`row_mut` then
    /// reads the row empty), or by a `row_mut` that reads a row not made as past the rows.
    #[test]
    fn an_on_use_row_held_alone_is_made_at_its_first_make_and_changed_in_place() {
        let drops = Cell::new(0);
        let mut table = OnceRows::<Counted<'_>>::counted(2).expect("the test allocator answers");
        assert!(
            matches!(table.row_mut(1), Some(None)),
            "CONTROL: a row not made is a row, holding no value"
        );
        let made = table
            .made_mut(1, || Counted {
                drops: &drops,
                id: 3,
            })
            .expect("row 1 is made");
        made.id = 4;
        let first = core::ptr::from_mut(made).cast_const();
        let again = table
            .made_mut(1, || unreachable!("the row holds its value"))
            .map(|again| core::ptr::from_mut(again).cast_const());
        assert_eq!(again, Some(first), "a made row is changed where it lies");
        assert!(
            matches!(table.row_mut(1), Some(Some(made)) if made.id == 4),
            "the change is the row's"
        );
        assert!(
            matches!(table.row_mut(0), Some(None)),
            "the other row holds none"
        );
        assert!(table.row_mut(2).is_none(), "past the rows");
        assert_eq!(table.iter_mut().count(), 1, "one value made");
        assert_eq!(drops.get(), 0, "nothing is dropped while the table stands");
        drop(table);
        assert_eq!(
            drops.get(),
            1,
            "the value made is dropped once, with the table"
        );
    }
}
