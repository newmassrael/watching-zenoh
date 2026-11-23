// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The place of the object behind an owned handle of this ABI: a session, a publisher, a
//! subscriber, a queryable, a liveliness token, an owned sample, reply or query, and a payload.
//!
//! Each such object is placed with [`Slot::take`] and [`Slot::fill`], and let go with [`release`];
//! a session of the cooperative engine is placed in its own arena instead (`crate::session_place`).
//! Without the `object-pool` capability a slot is the heap's: the same allocation the `Box` it
//! replaces made, so a build without the capability is the build it was. With it, a slot comes from
//! the fixed pool of the object's kind (`crate::object_pool`), the program's or, when it reserved
//! none, the build's, which the first object reserves; a pool with no room refuses the object, and
//! nothing falls back to the heap. The call that wanted it answers `_Z_ERR_SYSTEM_OUT_OF_MEMORY`
//! and has declared or opened nothing, because each caller takes its slot before it does either.
//!
//! An object let go is given back to where it lies: its pool, or the heap for one a constructor
//! still boxes. What decides is where the object lies, never which build placed it.

use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::prelude::*;

/// Which object a place is for. With the pools reserved each kind has a pool of its own, so the
/// count the program stated for one kind is never spent by another of the same size; a kind a
/// build places nowhere is not a variant of it, and each keeps its number in every build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    // The cooperative engine's session lies in its own arena (`crate::session_place`); its pool
    // is the program's to reserve where the doors are.
    #[cfg(any(feature = "engine-tokio", feature = "object-pool"))]
    Session = 0,
    Publisher = 1,
    Subscriber = 2,
    #[cfg(feature = "queryable")]
    Queryable = 3,
    #[cfg(feature = "liveliness")]
    LivelinessToken = 4,
    #[cfg(feature = "liveliness")]
    LivelinessSubscriber = 5,
    Sample = 6,
    #[cfg(feature = "query")]
    Reply = 7,
    #[cfg(feature = "queryable")]
    Query = 8,
    // A payload takes a slot only where there are pools to take it from; without them it is
    // boxed in the allocation its thread kept for it (`crate::bytes`).
    #[cfg(feature = "object-pool")]
    Bytes = 9,
}

/// The place of one `T`, taken and not yet filled. Dropped unfilled, it is given back.
pub(crate) struct Slot<T> {
    place: NonNull<MaybeUninit<T>>,
}

impl<T> Slot<T> {
    /// A place for one `T` of `kind`, or `None` when the pool of that kind is full.
    #[cfg(feature = "object-pool")]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        crate::object_pool::take::<T>(kind).map(|place| Self {
            place: place.cast(),
        })
    }

    /// A place for one `T`: without the pools every place is the heap's, whatever its kind.
    #[cfg(not(feature = "object-pool"))]
    pub(crate) fn take(kind: Kind) -> Option<Self> {
        let _ = kind;
        Some(Self {
            place: NonNull::from(Box::leak(Box::new(MaybeUninit::<T>::uninit()))),
        })
    }

    /// Put `value` in the place and hand back where it lies: the handle an owned struct holds,
    /// which [`release`] lets go.
    pub(crate) fn fill(self, value: T) -> *mut T {
        let place = self.place;
        core::mem::forget(self);
        // SAFETY: the place is a live allocation sized and aligned for `T`, which nothing else
        // holds, and it is not filled yet.
        unsafe { place.as_ptr().write(MaybeUninit::new(value)) };
        place.as_ptr().cast::<T>()
    }
}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        // SAFETY: an unfilled place this slot took, given back once.
        unsafe { give_back(self.place) }
    }
}

/// Drop the object at `object` and give its place back.
///
/// # Safety
/// `object` is a live handle [`Slot::fill`] or `Box::into_raw` made for a `T`, and is not used
/// again.
pub(crate) unsafe fn release<T>(object: *mut T) {
    core::ptr::drop_in_place(object);
    give_back(NonNull::new_unchecked(object.cast::<MaybeUninit<T>>()));
}

/// Move the object at `object` out and give its place back.
///
/// # Safety
/// As [`release`].
#[cfg(feature = "object-pool")]
pub(crate) unsafe fn reclaim<T>(object: *mut T) -> T {
    let value = object.read();
    give_back(NonNull::new_unchecked(object.cast::<MaybeUninit<T>>()));
    value
}

/// Give back a place whose value is gone: to its pool when it lies in one, else to the heap.
///
/// # Safety
/// `place` was taken for a `T` (by a [`Slot`] or a `Box`), holds no live value, and is given
/// back once.
unsafe fn give_back<T>(place: NonNull<MaybeUninit<T>>) {
    #[cfg(feature = "object-pool")]
    if crate::object_pool::give_back(place.cast::<u8>()) {
        return;
    }
    drop(Box::from_raw(place.as_ptr()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts its drops, to tell a value dropped once from one dropped twice or never.
    struct Counted<'a>(&'a core::cell::Cell<usize>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// A slot is there for a sample (the heap's, or one of the build's pools the first object
    /// reserves), a filled one holds its value, and a release drops the value once.
    #[test]
    fn a_filled_slot_holds_its_value_and_a_release_drops_it_once() {
        let drops = core::cell::Cell::new(0);
        let object = Slot::take(Kind::Sample)
            .expect("a sample has a place")
            .fill(Counted(&drops));
        assert_eq!(drops.get(), 0, "filling drops nothing");
        // SAFETY: `object` was filled just above and is released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1);
    }

    /// With the pools, a slot lies in the pool of its kind, and a release gives it back to it:
    /// nothing is the heap's.
    #[cfg(feature = "object-pool")]
    #[test]
    fn a_slot_lies_in_the_pools_and_goes_back_to_them() {
        let drops = core::cell::Cell::new(0);
        let object = Slot::take(Kind::Sample)
            .expect("the build's pools hold samples")
            .fill(Counted(&drops));
        let place = NonNull::new(object.cast::<u8>()).expect("a place");
        assert!(
            crate::object_pool::lies_in_pools(place),
            "the place is a pool's, not the heap's"
        );
        // SAFETY: `object` was filled just above and is released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1, "the value is dropped once");
    }

    /// An object a `Box` made is released as one a slot made: where it lies decides.
    #[test]
    fn an_object_a_box_made_is_released_like_one_a_slot_made() {
        let drops = core::cell::Cell::new(0);
        let object = Box::into_raw(Box::new(Counted(&drops)));
        // SAFETY: a live `Box::into_raw` handle, released once.
        unsafe { release(object) };
        assert_eq!(drops.get(), 1);
    }
}
