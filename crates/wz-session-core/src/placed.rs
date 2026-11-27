// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One value placed in a span of a session's arena, owned by one `Placed` and reached by
//! `PlacedRef` handles that count nothing (docs/c-abi-architecture.md, P3: one owner, no
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

    /// A handle of the value that counts nothing: a shared borrow of it whose lifetime the caller
    /// answers for, where the compiler cannot.
    ///
    /// # Safety
    /// For this handle and every copy of it, on whichever thread:
    /// - none is dereferenced once this owner is dropped: a value that holds one may be dropped
    ///   later only if its drop does not dereference it;
    /// - none is dereferenced while a reference [`Self::get_mut`] gave is in use, and no such
    ///   reference is taken while one dereferenced is.
    pub unsafe fn share(&self) -> PlacedRef<T> {
        PlacedRef { at: self.at }
    }

    /// The owner of the value `write` writes at `at`, a place in memory another owner holds (a
    /// field of a session's region) rather than a span an arena lends: a value of kilobytes is
    /// built where it is to lie, and dropped there when this is, the memory staying its holder's.
    ///
    /// # Safety
    /// `at` is aligned and valid for writes of one `T`, which `write` writes whole; nothing else
    /// drops the value or reaches it but through this owner and its handles; and the memory stays,
    /// unmoved, until after this owner is dropped.
    pub unsafe fn written_at(at: NonNull<T>, write: impl FnOnce(*mut T)) -> Self {
        write(at.as_ptr());
        Self {
            at,
            _owns: PhantomData,
        }
    }
}

/// A span of an [`Arena`] lent for one `T`, nothing written in it yet ([`Arena::vacant`]): what a
/// maker reserves while what it would write the value from is still its own, and fills once nothing
/// after it can refuse ([`Self::fill`]). It owns nothing: a span left vacant stays lent, unwritten,
/// until the arena goes.
pub struct Vacant<T> {
    at: NonNull<T>,
}

impl<T> Vacant<T> {
    /// The owner of the value `write` writes in the span, dropped there when the owner is.
    ///
    /// # Safety
    /// `write` writes a whole valid `T` at the pointer it is given, which is aligned for `T` and
    /// valid for writes of one.
    pub unsafe fn fill(self, write: impl FnOnce(*mut T)) -> Placed<T> {
        write(self.at.as_ptr());
        Placed {
            at: self.at,
            _owns: PhantomData,
        }
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
/// maker of the handle answers for ([`Placed::share`]). Of a part of the value, or of the value
/// as a trait it implements, too ([`Self::map`]).
pub struct PlacedRef<T: ?Sized> {
    at: NonNull<T>,
}

// SAFETY: a handle hands out only `&T`, as a `&T` sent or shared would.
unsafe impl<T: Sync + ?Sized> Send for PlacedRef<T> {}
// SAFETY: as `Send`.
unsafe impl<T: Sync + ?Sized> Sync for PlacedRef<T> {}

impl<T: ?Sized> PlacedRef<T> {
    /// A handle of a value that stands for the rest of the program, which no owner drops.
    pub fn of_static(value: &'static T) -> Self {
        Self {
            at: NonNull::from(value),
        }
    }

    /// A handle of the value at `at`, which its holder keeps there in place of a [`Placed`]
    /// owner: a field of a value that lies where it was written for as long as it lives, reached
    /// by another part of that value.
    ///
    /// # Safety
    /// For this handle and every copy of it, on whichever thread: none is dereferenced before a
    /// whole `T` lies at `at`, nor once the value there is moved or dropped; and none is
    /// dereferenced while a `&mut` of the value is in use, nor such a reference taken while one
    /// dereferenced is.
    pub unsafe fn of_place(at: NonNull<T>) -> Self {
        Self { at }
    }

    /// A handle of what `part` borrows of the value: a field of it, or the value as a trait it
    /// implements. What `part` answers lies in the value or lives longer, as its signature binds
    /// it, so the handle is good for as long as this one is.
    pub fn map<U: ?Sized>(self, part: impl FnOnce(&T) -> &U) -> PlacedRef<U> {
        PlacedRef {
            at: NonNull::from(part(&*self)),
        }
    }
}

impl<T: ?Sized> Clone for PlacedRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for PlacedRef<T> {}

impl<T: ?Sized> Deref for PlacedRef<T> {
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
        let vacant = self.vacant::<T>()?;
        // SAFETY: the caller's contract, handed on.
        Ok(unsafe { vacant.fill(write) })
    }

    /// The next span of the arena, lent for one `T` and left unwritten ([`Vacant`]). Refused,
    /// taking nothing, past what is left.
    pub fn vacant<T>(&mut self) -> Result<Vacant<T>, LendRefused> {
        const {
            assert!(
                core::mem::align_of::<T>() <= ARENA_ALIGN,
                "a placed value asks for more alignment than an arena's spans start on"
            )
        };
        let (start, _) = self.lend_rows(1, 1, Self::table_bytes::<T>(1))?;
        Ok(Vacant {
            at: start.cast::<T>(),
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

    /// A handle of a value that stands for the rest of the program reads it where it lies.
    /// Turned red by a handle that reads a copy.
    #[test]
    fn a_handle_of_a_static_value_reads_it_where_it_lies() {
        static VALUE: u32 = 7;
        let handle = PlacedRef::of_static(&VALUE);
        assert_eq!(*handle, 7);
        assert!(core::ptr::eq(&*handle, &VALUE));
    }

    /// A handle of a value its holder keeps in place reads it where it lies, every copy of the
    /// handle alike, and a write through a cell of it is the holder's. Turned red by a handle that
    /// reads a copy of the value it was made of.
    #[test]
    fn a_handle_of_a_value_held_in_place_reads_it_where_it_lies() {
        let held = Cell::new(1_u32);
        // SAFETY: `held` lies in this frame, unmoved, for every use of the handles below, and no
        // `&mut` of it is taken.
        let handle = unsafe { PlacedRef::of_place(NonNull::from(&held)) };
        let copy = handle;
        copy.set(2);
        assert_eq!((held.get(), handle.get()), (2, 2));
        assert!(
            core::ptr::eq(&*handle, &held),
            "the handle reads where the value lies"
        );
    }

    /// A value written at a place its owner does not lend is read there, through the owner and a
    /// handle, and dropped once, by the owner, the place left to its holder. Turned red by an owner
    /// that reads anywhere but the place it was given, or drops its value twice or not at all.
    #[test]
    fn a_value_written_at_a_held_place_is_read_there_and_dropped_once_by_its_owner() {
        let drops = Cell::new(0);
        let mut place = core::mem::MaybeUninit::<Counted<'_>>::uninit();
        let at = NonNull::from(&mut place).cast::<Counted<'_>>();
        // SAFETY: the place is a local's, aligned for the value and written whole by the closure;
        // the owner and its handle are its only way in, and the local outlives them.
        let mut owner = unsafe { Placed::written_at(at, |at| at.write(Counted(&drops, 1))) };
        owner.get_mut().1 = 3;
        // SAFETY: the handle is used only while `owner` lives, and nothing changes it then.
        let handle = unsafe { owner.share() };
        assert!(
            core::ptr::eq(&*handle, at.as_ptr()),
            "read where it was written"
        );
        assert_eq!((handle.1, owner.1), (3, 3));
        drop(owner);
        assert_eq!(drops.get(), 1, "dropped once, by its owner");
    }

    /// A vacant span is lent from the arena and holds nothing until it is filled: what is written
    /// in it then is read where the span lies and dropped once, by the owner the fill hands back,
    /// and a span past what is left is refused, taking nothing. Turned red by a vacant span that
    /// writes or drops a value before it is filled, or a fill that writes anywhere but the span.
    #[test]
    fn a_vacant_span_holds_nothing_until_it_is_filled() {
        let mut memory = [Block {
            _bytes: [0; ARENA_ALIGN],
        }; 2];
        let drops = Cell::new(0);
        let bytes = core::mem::size_of_val(&memory);
        // SAFETY: the blocks are aligned to `ARENA_ALIGN`, hold `bytes` bytes and outlive the
        // arena and the value placed in it, which nothing else uses.
        let mut arena = unsafe { Arena::over(NonNull::from(&mut memory).cast::<u8>(), bytes) };
        let vacant = arena.vacant::<Counted<'_>>().unwrap();
        let at = vacant.at;
        assert_eq!(
            drops.get(),
            0,
            "nothing is written or dropped while the span is vacant"
        );
        // SAFETY: the closure writes a whole value.
        let placed = unsafe { vacant.fill(|at| at.write(Counted(&drops, 4))) };
        assert!(
            core::ptr::eq(&*placed, at.as_ptr()),
            "the value lies where the span was lent"
        );
        assert_eq!(placed.1, 4);
        drop(placed);
        assert_eq!(drops.get(), 1, "dropped once, by its owner");
        let refused = arena.vacant::<[u8; 64]>();
        assert!(matches!(refused, Err(LendRefused::Exhausted { .. })));
    }

    /// Says a number, as the trait a handle is mapped to reads it.
    trait Numbered {
        fn number(&self) -> u32;
    }

    /// Two numbers, the second of which the trait says.
    struct Numbers {
        first: u32,
        second: u32,
    }

    impl Numbered for Numbers {
        fn number(&self) -> u32 {
            self.second
        }
    }

    fn as_numbered(value: &Numbers) -> &(dyn Numbered + 'static) {
        value
    }

    /// A handle mapped to a part of the value, or to the value as a trait it implements, reads the
    /// value where its owner holds it. Turned red by a map that reads a copy of the part, or
    /// answers a handle of anything but the part.
    #[test]
    fn a_mapped_handle_reads_the_part_where_the_owner_holds_it() {
        let mut memory = [Block {
            _bytes: [0; ARENA_ALIGN],
        }; 2];
        let bytes = core::mem::size_of_val(&memory);
        // SAFETY: the blocks are aligned to `ARENA_ALIGN`, hold `bytes` bytes and outlive the
        // arena and the value placed in it, which nothing else uses.
        let mut arena = unsafe { Arena::over(NonNull::from(&mut memory).cast::<u8>(), bytes) };
        let placed = arena
            .place(Numbers {
                first: 3,
                second: 9,
            })
            .unwrap();
        // SAFETY: the handles are used only while `placed` lives, and nothing changes it then.
        let handle = unsafe { placed.share() };
        let first = handle.map(|value| &value.first);
        let numbered: PlacedRef<dyn Numbered> = handle.map(as_numbered);
        assert_eq!((*first, numbered.number()), (3, 9));
        assert!(
            core::ptr::eq(&*first, &placed.first),
            "the part is read where the owner holds it"
        );
        assert!(
            core::ptr::eq(
                core::ptr::from_ref::<dyn Numbered>(&*numbered).cast::<u8>(),
                core::ptr::from_ref::<Numbers>(&*placed).cast::<u8>()
            ),
            "the value as a trait is the value where it lies"
        );
    }
}
