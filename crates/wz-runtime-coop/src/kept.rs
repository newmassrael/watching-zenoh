// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A value kept by a count of its holders (`Shared`), in memory of the heap or in a span of
//! memory that is itself kept by a count ([`Kept`]): a session's arena, which the runtime's state
//! and its task table are placed in. The last holder drops the value; a value placed in counted
//! memory then gives back its count of that memory, and the last count of the memory gives the
//! memory back. A waker or a join handle kept past the runtime is such a holder, so what it points
//! at stands until it lets go, wherever the memory came from.

use alloc::boxed::Box;
use core::alloc::Layout;
use core::ops::Deref;
use core::ptr::{self, NonNull};

use crate::atomic::{AtomicUsize, Ordering};

/// A count past which a count taken is given straight back: no program holds that many at once, so
/// a count this high is one of holders that were forgotten, and what it keeps is kept for ever
/// rather than wrapped to no holder while one is still held.
const MOST_HOLDERS: usize = isize::MAX as usize;

/// A count of the holders of something, and what the last of them does when it lets go.
pub struct Kept {
    count: AtomicUsize,
    last: unsafe fn(NonNull<Kept>),
}

impl Kept {
    /// A count of one holder, whose last release runs `last` on the count's own place.
    pub const fn new(last: unsafe fn(NonNull<Kept>)) -> Self {
        Self {
            count: AtomicUsize::new(1),
            last,
        }
    }

    /// Take a count for another holder.
    pub fn retain(&self) {
        let before = self.count.fetch_add(1, Ordering::Relaxed);
        if before > MOST_HOLDERS {
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Take a count for another holder while one is left, and say whether it was taken: a count
    /// that reached no holder stays there, so what its last holder dropped is not held again.
    pub fn retain_live(&self) -> bool {
        self.count
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |held| match held {
                0 => None,
                held if held > MOST_HOLDERS => Some(held),
                held => Some(held + 1),
            })
            .is_ok()
    }

    /// Give back a count; the last one runs what the count was made with.
    ///
    /// # Safety
    /// `this` is a live count the caller holds one of, given back here once; the caller reads
    /// nothing through it after.
    pub unsafe fn release(this: NonNull<Self>) {
        // SAFETY: the caller holds a count, so the place is live.
        let kept = unsafe { this.as_ref() };
        // Acquire on the last release orders every holder's use before what `last` drops.
        if kept.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            let last = kept.last;
            // SAFETY: no holder is left, so `last` is the one user of the place.
            unsafe { last(this) }
        }
    }
}

/// A value and the count of its holders, the count first, so a pointer to the count is a pointer
/// to the whole.
#[repr(C)]
struct Held<T> {
    kept: Kept,
    /// The memory the value is placed in, a count of which it holds: `None` on the heap.
    memory: Option<NonNull<Kept>>,
    value: T,
}

/// A value shared by a count of its holders: one of them. Cloning takes a count, dropping gives it
/// back, and the last drops the value and gives its memory back ([`Self::boxed`],
/// [`Self::placed`]).
pub struct Shared<T> {
    at: NonNull<Held<T>>,
}

// SAFETY: a holder hands out only `&T` and may drop the value on whichever thread lets go last,
// as an `Arc<T>` does.
unsafe impl<T: Send + Sync> Send for Shared<T> {}
// SAFETY: as `Send`.
unsafe impl<T: Send + Sync> Sync for Shared<T> {}

impl<T> Shared<T> {
    /// `value` in memory of the heap, freed with it.
    pub fn boxed(value: T) -> Self {
        let held = Box::new(Held {
            kept: Kept::new(Self::last_boxed),
            memory: None,
            value,
        });
        Self {
            at: NonNull::from(Box::leak(held)),
        }
    }

    /// The bytes and alignment [`Self::placed`] writes.
    pub const fn layout() -> Layout {
        Layout::new::<Held<T>>()
    }

    /// `value` written at `at`, in memory `memory` keeps, a count of which it takes until its
    /// last holder lets go.
    ///
    /// # Safety
    /// `at` is aligned and valid for a write of [`Self::layout`], and nothing else uses those
    /// bytes while a count of `memory` is held; `memory` is live and its memory holds `at`.
    pub unsafe fn placed(at: NonNull<u8>, value: T, memory: NonNull<Kept>) -> Self {
        // SAFETY: the caller's: the count is live.
        unsafe { memory.as_ref() }.retain();
        let at = at.cast::<Held<T>>();
        // SAFETY: the caller's: the place is aligned and free for a `Held<T>`.
        unsafe {
            at.as_ptr().write(Held {
                kept: Kept::new(Self::last_placed),
                memory: Some(memory),
                value,
            })
        };
        Self { at }
    }

    /// The count this value is held by: what a holder that keeps only a pointer to it retains and
    /// releases ([`Kept::retain`], [`Kept::release`]).
    pub fn kept(this: &Self) -> NonNull<Kept> {
        this.at.cast()
    }

    /// The value, where it lies: what a holder that keeps no count names it by, and what
    /// [`Self::retain_live`] and [`Self::from_counted`] are handed back.
    pub fn as_ptr(this: &Self) -> NonNull<T> {
        // SAFETY: `at` is a live `Held<T>`, so the place of its value is not null.
        unsafe { NonNull::new_unchecked(ptr::addr_of_mut!((*this.at.as_ptr()).value)) }
    }

    /// Whether the two hold the same value.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        this.at == other.at
    }

    /// The count of the value at `value`, which lies in a `Held<T>` after it.
    ///
    /// # Safety
    /// `value` is what [`Self::as_ptr`] answered of a holder of this type.
    unsafe fn held_of(value: NonNull<T>) -> NonNull<Held<T>> {
        let at = value
            .as_ptr()
            .cast::<u8>()
            .wrapping_sub(core::mem::offset_of!(Held<T>, value));
        // SAFETY: the caller's: the value lies at that offset of its `Held<T>`, which is not null.
        unsafe { NonNull::new_unchecked(at.cast::<Held<T>>()) }
    }

    /// A holder of the value at `value`, taken while one of its holders is left; `None` once
    /// its last holder let go, though its place still stands.
    ///
    /// # Safety
    /// `value` is what [`Self::as_ptr`] answered of a holder of this type, and the place of its
    /// `Held<T>` stands: the memory it lies in was not given back.
    pub unsafe fn retain_live(value: NonNull<T>) -> Option<Self> {
        // SAFETY: the caller's.
        let at = unsafe { Self::held_of(value) };
        // SAFETY: the caller's: the count's place stands, whatever it counts.
        unsafe { at.as_ref() }
            .kept
            .retain_live()
            .then_some(Self { at })
    }

    /// A holder of the value at `value` that takes over a count already taken of it (by
    /// [`Kept::retain_live`] on [`Self::kept`], say), and gives it back when dropped.
    ///
    /// # Safety
    /// `value` is what [`Self::as_ptr`] answered of a holder of this type, and the caller hands
    /// over one count it holds of it, used by nothing else after.
    pub unsafe fn from_counted(value: NonNull<T>) -> Self {
        Self {
            // SAFETY: the caller's.
            at: unsafe { Self::held_of(value) },
        }
    }

    /// The last holder of a value of the heap let go: the value and its memory go.
    ///
    /// # Safety
    /// `kept` is the count of a `Held<T>` [`Self::boxed`] made, which no holder is left of.
    unsafe fn last_boxed(kept: NonNull<Kept>) {
        // SAFETY: the caller's: the box was leaked by `boxed` and is taken back once.
        drop(unsafe { Box::from_raw(kept.cast::<Held<T>>().as_ptr()) });
    }

    /// The last holder of a placed value let go: the value is dropped where it lies, and the count
    /// of the memory it held is given back.
    ///
    /// # Safety
    /// `kept` is the count of a `Held<T>` [`Self::placed`] wrote, which no holder is left of.
    unsafe fn last_placed(kept: NonNull<Kept>) {
        let held = kept.cast::<Held<T>>().as_ptr();
        // SAFETY: the caller's: the value is live and dropped once, here; the memory's count is
        // read before, as the memory may go with it.
        unsafe {
            let memory = (*held).memory;
            ptr::drop_in_place(ptr::addr_of_mut!((*held).value));
            if let Some(memory) = memory {
                Kept::release(memory);
            }
        }
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        // SAFETY: this holder keeps the value alive.
        unsafe { self.at.as_ref() }.kept.retain();
        Self { at: self.at }
    }
}

impl<T> Drop for Shared<T> {
    fn drop(&mut self) {
        // SAFETY: this holder's count, given back once; nothing is read through it after.
        unsafe { Kept::release(self.at.cast()) }
    }
}

impl<T> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this holder keeps the value alive.
        unsafe { &self.at.as_ref().value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use core::mem::MaybeUninit;

    /// Counts its drops in the cell it names.
    struct Counted<'a>(&'a Cell<usize>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    // SAFETY: the tests share a `Counted` on one thread only.
    unsafe impl Send for Counted<'_> {}
    // SAFETY: as `Send`.
    unsafe impl Sync for Counted<'_> {}

    /// What the memory's last count does in these tests: it records that it ran.
    static GIVEN_BACK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    unsafe fn record_given_back(_kept: NonNull<Kept>) {
        GIVEN_BACK.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }

    /// A value of the heap is dropped once, by the last of its holders, whichever goes last. Turned
    /// red by a clone that takes no count, or a drop that gives none back.
    #[test]
    fn a_boxed_value_is_dropped_by_its_last_holder() {
        let drops = Cell::new(0);
        let first = Shared::boxed(Counted(&drops));
        let second = first.clone();
        drop(first);
        assert_eq!(drops.get(), 0, "a holder is left");
        assert!(core::ptr::eq(second.0, &drops));
        drop(second);
        assert_eq!(drops.get(), 1, "dropped once, by the last");
    }

    /// A placed value holds a count of its memory: the memory is given back only once the value's
    /// last holder and the memory's own holder have both let go, in either order, and the value is
    /// dropped once, where it lies. Turned red by a placed value that takes no count of its memory,
    /// or by one that gives it back before its own last holder.
    #[test]
    fn a_placed_value_keeps_its_memory_until_its_last_holder() {
        let drops = Cell::new(0);
        let mut room = MaybeUninit::<[u64; 16]>::uninit();
        assert!(Shared::<Counted<'_>>::layout().size() <= core::mem::size_of_val(&room));
        let memory = Box::leak(Box::new(Kept::new(record_given_back)));
        let memory = NonNull::from(memory);
        let before = GIVEN_BACK.load(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: the room is aligned for a `u64`, which is at least the `Held`'s alignment, holds
        // its bytes, and is used by nothing else while the value lives.
        let value =
            unsafe { Shared::placed(NonNull::from(&mut room).cast(), Counted(&drops), memory) };
        let held = value.clone();
        // SAFETY: the memory's own holder lets go first.
        unsafe { Kept::release(memory) };
        assert_eq!(
            GIVEN_BACK.load(core::sync::atomic::Ordering::SeqCst),
            before,
            "the placed value keeps the memory"
        );
        drop(value);
        assert_eq!(drops.get(), 0);
        drop(held);
        assert_eq!(drops.get(), 1, "dropped once, where it lies");
        assert_eq!(
            GIVEN_BACK.load(core::sync::atomic::Ordering::SeqCst),
            before + 1,
            "the last holder gives the memory back"
        );
        // SAFETY: the count gave its place up; the box is taken back once, here.
        drop(unsafe { Box::from_raw(memory.as_ptr()) });
    }

    /// A holder reached by the value's place alone takes a count while a holder is left, and the
    /// value is dropped by the last of them; once it was, its place, which still stands, is not
    /// held again. Turned red by a `retain_live` that takes a count from no holder, or by a
    /// value found at another offset than the one `placed` wrote it at.
    #[test]
    fn a_value_reached_by_its_place_is_held_only_while_a_holder_is_left() {
        let drops = Cell::new(0);
        let mut room = MaybeUninit::<[u64; 16]>::uninit();
        let memory = NonNull::from(Box::leak(Box::new(Kept::new(given_back_unseen))));
        // SAFETY: as in `a_placed_value_keeps_its_memory_until_its_last_holder`.
        let first =
            unsafe { Shared::placed(NonNull::from(&mut room).cast(), Counted(&drops), memory) };
        let at = Shared::as_ptr(&first);
        // SAFETY: `at` is the value's place, whose room stands for the whole test.
        let reached = unsafe { Shared::<Counted<'_>>::retain_live(at) }.expect("a holder is left");
        assert!(Shared::ptr_eq(&first, &reached));
        assert!(
            core::ptr::eq(reached.0, &drops),
            "the value read where it lies"
        );
        // SAFETY: a holder is left, so the count's place is live.
        assert!(unsafe { Shared::kept(&first).as_ref() }.retain_live());
        // SAFETY: the count taken just above is handed over, once.
        let counted = unsafe { Shared::<Counted<'_>>::from_counted(at) };
        drop(first);
        drop(reached);
        assert_eq!(drops.get(), 0, "the counted holder is left");
        drop(counted);
        assert_eq!(drops.get(), 1, "dropped once, by the last");
        // SAFETY: the room still stands, though no holder is left.
        assert!(unsafe { Shared::<Counted<'_>>::retain_live(at) }.is_none());
        // SAFETY: the memory's own holder lets go, its last.
        unsafe { Kept::release(memory) };
        // SAFETY: the count gave its place up; the box is taken back once, here.
        drop(unsafe { Box::from_raw(memory.as_ptr()) });
    }

    /// What the memory's last count does where another test reads `GIVEN_BACK`: nothing.
    unsafe fn given_back_unseen(_kept: NonNull<Kept>) {}
}
