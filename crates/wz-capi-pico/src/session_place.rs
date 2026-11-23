// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The place a session's handle lies in on the cooperative engine: a span of the session's own
//! arena, which the open reserves with the rest of the session (`wz_capi_coop::arena::HandlePlace`),
//! so the handle takes no memory of its own and an open whose arena cannot hold it opens nothing.
//!
//! A word beside the handle says whether the place still holds it. `z_session_drop` clears the
//! word and moves the handle out before letting it go, so a copy of the owned session kept past the
//! drop finds the place vacant and is refused rather than read. The place stands as long as the
//! session's memory does, which an entity declared on the session keeps standing; a copy kept past
//! the session's last holder names memory the program has let go, as a copy of zenoh-pico's own
//! owned session does.

use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

/// A value of `T` in a place it does not own, and whether the place still holds it.
#[repr(C)]
pub(crate) struct HeldPlace<T> {
    held: AtomicBool,
    value: MaybeUninit<T>,
}

impl<T> HeldPlace<T> {
    /// The layout the place is asked for.
    pub(crate) const LAYOUT: Layout = Layout::new::<Self>();

    /// Write `value` into the place at `at`, which holds it from then on, and answer the place.
    ///
    /// # Safety
    /// `at` is valid for writes of [`Self::LAYOUT`], aligned to it, and holds no live value.
    pub(crate) unsafe fn fill(at: NonNull<u8>, value: T) -> *mut Self {
        let place = at.cast::<Self>().as_ptr();
        // SAFETY: the caller's contract.
        unsafe {
            place.write(Self {
                held: AtomicBool::new(true),
                value: MaybeUninit::new(value),
            })
        };
        place
    }

    /// The value, while the place holds it.
    pub(crate) fn held(&self) -> Option<&T> {
        if self.held.load(Ordering::Acquire) {
            // SAFETY: a place that says it holds its value was filled and its value not taken.
            Some(unsafe { self.value.assume_init_ref() })
        } else {
            None
        }
    }

    /// Take the value out and leave the place vacant; `None` when it is vacant already, so a
    /// second take through a copy of the handle takes nothing. Two takes at once are the program's
    /// error, as two drops of one owned value are.
    ///
    /// # Safety
    /// `place` is a place [`Self::fill`] made whose memory still stands, and no reference to its
    /// value is held across this call.
    pub(crate) unsafe fn take(place: *mut Self) -> Option<T> {
        // SAFETY: the caller's contract: the place's memory stands.
        let place = unsafe { &*place };
        if !place.held.load(Ordering::Acquire) {
            return None;
        }
        place.held.store(false, Ordering::Release);
        // SAFETY: the place held its value, and the flag cleared above lets nothing read it again.
        Some(unsafe { place.value.assume_init_read() })
    }
}

#[cfg(test)]
mod tests {
    use super::HeldPlace;
    use core::cell::Cell;
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    /// Counts its drops, to tell a value dropped once from one dropped twice or never.
    struct Counted<'a>(&'a Cell<usize>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// A filled place holds its value; taken, it is vacant, so a copy of the handle kept past the
    /// take reads nothing and a second take takes nothing, and the value is dropped once.
    #[test]
    fn a_place_taken_once_is_vacant_to_every_copy_of_its_handle() {
        let drops = Cell::new(0);
        let mut memory = MaybeUninit::<HeldPlace<Counted<'_>>>::uninit();
        let at = NonNull::from(&mut memory).cast::<u8>();
        // SAFETY: `memory` is a place of the layout, aligned, holding nothing.
        let place = unsafe { HeldPlace::fill(at, Counted(&drops)) };
        let copy = place;
        // SAFETY: the place's memory is `memory`, which stands for the whole test.
        unsafe {
            assert!((*copy).held().is_some(), "a filled place holds its value");
            let taken = HeldPlace::take(place).expect("the first take takes the value");
            assert!((*copy).held().is_none(), "the copy finds the place vacant");
            assert!(
                HeldPlace::take(copy).is_none(),
                "a second take through the copy takes nothing"
            );
            drop(taken);
        }
        assert_eq!(drops.get(), 1, "the value is dropped once");
    }

    /// The place's layout holds the value and the word beside it.
    #[test]
    fn a_places_layout_holds_its_value() {
        let layout = HeldPlace::<[u64; 3]>::LAYOUT;
        assert!(layout.size() > core::mem::size_of::<[u64; 3]>());
        assert!(layout.align() >= core::mem::align_of::<[u64; 3]>());
    }
}
