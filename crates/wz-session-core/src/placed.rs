// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One value placed in a span of a session's arena, owned by one [`Placed`] and reached by
//! [`PlacedRef`] handles that count nothing (docs/c-abi-architecture.md, P3: one owner, no
//! reference counting inside a session).
//!
//! The value lies where the arena lent it for as long as its owner lives, so moving the owner
//! moves no byte of it and a handle taken once stays good. The owner drops the value where it lies;
//! the arena's memory goes back after it, with the arena.

use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::NonNull;

use crate::bounded::{Arena, LendRefused, ARENA_ALIGN};

/// One value of `T` in a span of an [`Arena`], owned here: dropped where it lies when this is.
pub struct Placed<T> {
    at: NonNull<T>,
    _owns: PhantomData<T>,
}

// SAFETY: `Placed` owns its `T` as a `Box` does; only the place differs.
unsafe impl<T: Send> Send for Placed<T> {}
// SAFETY: as `Send`: a shared `Placed` hands out only `&T`.
unsafe impl<T: Sync> Sync for Placed<T> {}

impl<T> Placed<T> {
    /// The value, to change before any handle of it is shared ([`Self::share`]).
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: `at` holds a whole `T` this owner owns, and `&mut self` is the one way to it
        // but the handles, which `share`'s caller keeps from being used meanwhile.
        unsafe { self.at.as_mut() }
    }

    /// A handle of the value that counts nothing.
    ///
    /// # Safety
    /// The caller uses no handle after this owner is dropped, nor while a reference
    /// [`Self::get_mut`] gave is in use.
    pub unsafe fn share(&self) -> PlacedRef<T> {
        PlacedRef { at: self.at }
    }
}

impl<T> Deref for Placed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: `at` holds a whole `T` for as long as this owner lives.
        unsafe { self.at.as_ref() }
    }
}

impl<T> Drop for Placed<T> {
    fn drop(&mut self) {
        // SAFETY: `at` holds a whole `T` this owner owns, dropped here once; no handle is used
        // after this (`Self::share`).
        unsafe { core::ptr::drop_in_place(self.at.as_ptr()) };
    }
}

/// A handle of a [`Placed`] value: a shared borrow whose lifetime is its owner's, which the
/// maker of the handle answers for ([`Placed::share`]).
pub struct PlacedRef<T> {
    at: NonNull<T>,
}

// SAFETY: a handle hands out only `&T`, as a `&T` sent or shared would.
unsafe impl<T: Sync> Send for PlacedRef<T> {}
// SAFETY: as `Send`.
unsafe impl<T: Sync> Sync for PlacedRef<T> {}

impl<T> Clone for PlacedRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for PlacedRef<T> {}

impl<T> Deref for PlacedRef<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the owner outlives every use of its handles (`Placed::share`).
        unsafe { self.at.as_ref() }
    }
}

impl Arena {
    /// Place `value` in the next span of the arena, owned by what is handed back. Refused, taking
    /// nothing and dropping `value`, past what is left.
    pub fn place<T>(&mut self, value: T) -> Result<Placed<T>, LendRefused> {
        // SAFETY: the closure writes a whole `T`.
        unsafe { self.place_with(|at: *mut T| at.write(value)) }
    }

    /// Place a value `write` writes where it is to lie, in the next span of the arena: a value of
    /// kilobytes is built there, never in a frame. Refused, taking nothing and calling nothing,
    /// past what is left.
    ///
    /// # Safety
    /// `write` writes a whole valid `T` at the pointer it is given, which is aligned for `T` and
    /// valid for writes of one.
    pub unsafe fn place_with<T>(
        &mut self,
        write: impl FnOnce(*mut T),
    ) -> Result<Placed<T>, LendRefused> {
        const {
            assert!(
                core::mem::align_of::<T>() <= ARENA_ALIGN,
                "a placed value asks for more alignment than an arena's spans start on"
            )
        };
        let (start, _) = self.lend_rows(1, 1, Self::table_bytes::<T>(1))?;
        let at = start.cast::<T>();
        write(at.as_ptr());
        Ok(Placed {
            at,
            _owns: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// Counts its drops in the cell it names.
    struct Counted<'a>(&'a Cell<usize>, u32);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// One block of an arena's memory, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// A value placed is read through its owner and every handle at one place, changed before it
    /// is shared, and dropped once, by its owner; a place past what is left is refused and its
    /// value dropped then. Turned red by an owner that does not drop its value, or drops it twice.
    #[test]
    fn a_placed_value_is_read_where_it_lies_and_dropped_once_by_its_owner() {
        let mut memory = [Block {
            _bytes: [0; ARENA_ALIGN],
        }; 2];
        let drops = Cell::new(0);
        let bytes = core::mem::size_of_val(&memory);
        // SAFETY: the blocks are aligned to `ARENA_ALIGN`, hold `bytes` bytes and outlive the
        // arena and the value placed in it, which nothing else uses.
        let mut arena = unsafe { Arena::over(NonNull::from(&mut memory).cast::<u8>(), bytes) };
        let mut placed = arena.place(Counted(&drops, 1)).unwrap();
        placed.get_mut().1 = 2;
        // SAFETY: the handles are used only while `placed` lives, and nothing changes it then.
        let (one, two) = unsafe { (placed.share(), placed.share()) };
        assert_eq!((one.1, two.1, placed.1), (2, 2, 2));
        assert!(
            core::ptr::eq(&*one, &*placed),
            "the handle reads where the value lies"
        );
        let moved = placed;
        assert_eq!(one.1, 2, "moving the owner moves no byte of the value");
        drop(moved);
        assert_eq!(drops.get(), 1, "dropped once, by its owner");
        let refused = arena.place([0_u8; 64]);
        assert!(matches!(refused, Err(LendRefused::Exhausted { .. })));
    }
}
