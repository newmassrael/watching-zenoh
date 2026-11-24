// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A value shared by counts as an `Arc` shares one, lying where its maker put it: in a box of its
//! own, or in a place a holder lent ([`Strong::lodge`]), so an ABI that keeps its objects in places
//! of its session's takes no memory for what its objects share.
//!
//! Two counts, as `Arc`'s: of the value, which is dropped with the last, and of the place, which
//! every count of the value holds once together and each weak count once more; the place is given
//! back with the last of them, by the function its maker named. A weak count reads the value only
//! by upgrading, which fails once the value is gone.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{fence, AtomicUsize, Ordering};

use alloc::boxed::Box;

/// Where a value lies and its two counts. Written once, when the value is lodged, and read through
/// the counts until the place is given back.
pub struct Lodging<T> {
    /// The counts of the value.
    strong: AtomicUsize,
    /// The counts of the place: each weak count, and one for every count of the value together.
    weak: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
    /// What gives the place back, and what it is called with.
    give_back: unsafe fn(*mut c_void),
    context: *mut c_void,
}

impl<T> Lodging<T> {
    /// A place for one value, holding none.
    pub const fn vacant() -> MaybeUninit<Self> {
        MaybeUninit::uninit()
    }
}

/// A count of a lodged value; dropped, it lets go of it.
pub struct Strong<T> {
    at: NonNull<Lodging<T>>,
}

/// A count of a lodged value's place, which reads the value only by upgrading ([`Self::upgrade`]).
pub struct WeakRef<T> {
    at: NonNull<Lodging<T>>,
}

// SAFETY: as `Arc<T>`'s: the counts are atomic, and the value is shared and sent with them.
unsafe impl<T: Send + Sync> Send for Strong<T> {}
// SAFETY: as `Send`.
unsafe impl<T: Send + Sync> Sync for Strong<T> {}
// SAFETY: as `Strong`'s.
unsafe impl<T: Send + Sync> Send for WeakRef<T> {}
// SAFETY: as `Send`.
unsafe impl<T: Send + Sync> Sync for WeakRef<T> {}

impl<T> Strong<T> {
    /// `value` in a box of its own, given back to the heap with the last count of it.
    pub fn boxed(value: T) -> Self {
        let place = NonNull::from(Box::leak(Box::new(Lodging::<T>::vacant())));
        // SAFETY: the box is this value's alone and is given back by `free_box`, once.
        unsafe { Self::lodge(place, value, free_box::<T>, place.as_ptr().cast::<c_void>()) }
    }

    /// `value` in the place at `place`, which `give_back(context)` gives back once, after the
    /// last count of the value and of its place is let go of.
    ///
    /// # Safety
    /// `place` is valid for writes of a `Lodging<T>`, holds none, and stands until
    /// `give_back(context)` runs; `give_back` may be called from any thread that lets go of the
    /// last count.
    pub unsafe fn lodge(
        place: NonNull<MaybeUninit<Lodging<T>>>,
        value: T,
        give_back: unsafe fn(*mut c_void),
        context: *mut c_void,
    ) -> Self {
        let at = place.cast::<Lodging<T>>();
        // SAFETY: the caller's: the place is free and valid for the write.
        unsafe {
            at.as_ptr().write(Lodging {
                strong: AtomicUsize::new(1),
                weak: AtomicUsize::new(1),
                value: UnsafeCell::new(MaybeUninit::new(value)),
                give_back,
                context,
            });
        }
        Self { at }
    }

    fn lodging(&self) -> &Lodging<T> {
        // SAFETY: a count of the value holds its place.
        unsafe { self.at.as_ref() }
    }

    /// A weak count of the place.
    pub fn downgrade(this: &Self) -> WeakRef<T> {
        this.lodging().weak.fetch_add(1, Ordering::Relaxed);
        WeakRef { at: this.at }
    }

    /// Give this count up as a pointer, let go of later by [`Self::from_raw`].
    pub fn into_raw(this: Self) -> *mut c_void {
        let at = this.at;
        core::mem::forget(this);
        at.as_ptr().cast::<c_void>()
    }

    /// Where this count's value is lodged, as [`Self::into_raw`] names it, with no count given up:
    /// what [`Self::value_of`] reads while another count is held.
    pub fn as_raw(this: &Self) -> *const c_void {
        this.at.as_ptr().cast_const().cast::<c_void>()
    }

    /// The count [`Self::into_raw`] gave up.
    ///
    /// # Safety
    /// `raw` is a count given up by [`Self::into_raw`] for a `T`, taken back once.
    pub unsafe fn from_raw(raw: *mut c_void) -> Self {
        // SAFETY: the caller's: the pointer is a lodging's, never null.
        Self {
            at: unsafe { NonNull::new_unchecked(raw.cast::<Lodging<T>>()) },
        }
    }

    /// The value a count given up by [`Self::into_raw`] holds, the count left held.
    ///
    /// # Safety
    /// `raw` is such a count, not yet taken back, held for `'a`.
    pub unsafe fn value_of<'a>(raw: *const c_void) -> &'a T {
        // SAFETY: the caller's: the count holds the value.
        unsafe { (*(*raw.cast::<Lodging<T>>()).value.get()).assume_init_ref() }
    }

    /// How many counts of the value are held.
    pub fn strong_count(this: &Self) -> usize {
        this.lodging().strong.load(Ordering::Acquire)
    }
}

impl<T> Clone for Strong<T> {
    fn clone(&self) -> Self {
        // Relaxed, as `Arc`'s: a new count is made from one held, which keeps the value.
        self.lodging().strong.fetch_add(1, Ordering::Relaxed);
        Self { at: self.at }
    }
}

impl<T> core::ops::Deref for Strong<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a count of the value keeps it.
        unsafe { (*self.lodging().value.get()).assume_init_ref() }
    }
}

impl<T> Drop for Strong<T> {
    fn drop(&mut self) {
        if self.lodging().strong.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        // SAFETY: the last count of the value drops it, once; the place stands on the weak count
        // every count of the value held together, let go of after.
        unsafe {
            (*self.lodging().value.get()).assume_init_drop();
            release_place(self.at);
        }
    }
}

impl<T> WeakRef<T> {
    /// A count of the value, while one is still held.
    pub fn upgrade(&self) -> Option<Strong<T>> {
        // SAFETY: a weak count holds the place, so its counts stand.
        let strong = unsafe { &self.at.as_ref().strong };
        let mut seen = strong.load(Ordering::Relaxed);
        loop {
            if seen == 0 {
                return None;
            }
            match strong.compare_exchange_weak(seen, seen + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(Strong { at: self.at }),
                Err(now) => seen = now,
            }
        }
    }

    /// Give this count up as a pointer, let go of later by [`Self::from_raw`].
    pub fn into_raw(this: Self) -> *mut c_void {
        let at = this.at;
        core::mem::forget(this);
        at.as_ptr().cast::<c_void>()
    }

    /// The count [`Self::into_raw`] gave up.
    ///
    /// # Safety
    /// `raw` is a count given up by [`Self::into_raw`] for a `T`, taken back once.
    pub unsafe fn from_raw(raw: *mut c_void) -> Self {
        // SAFETY: the caller's: the pointer is a lodging's, never null.
        Self {
            at: unsafe { NonNull::new_unchecked(raw.cast::<Lodging<T>>()) },
        }
    }
}

impl<T> Drop for WeakRef<T> {
    fn drop(&mut self) {
        // SAFETY: this count holds the place and is let go of once, here.
        unsafe { release_place(self.at) };
    }
}

/// Let go of one count of the place at `at`; the last gives it back.
///
/// # Safety
/// The caller holds a count of the place and lets go of it once, here.
unsafe fn release_place<T>(at: NonNull<Lodging<T>>) {
    // SAFETY: the caller's count holds the place.
    let lodging = unsafe { at.as_ref() };
    if lodging.weak.fetch_sub(1, Ordering::Release) != 1 {
        return;
    }
    fence(Ordering::Acquire);
    let (give_back, context) = (lodging.give_back, lodging.context);
    // SAFETY: no count is left, so nothing reads the place; its maker named how it goes back.
    unsafe { give_back(context) };
}

/// Give back a box [`Strong::boxed`] made.
///
/// # Safety
/// `context` is that box, whose value was dropped, given back once.
unsafe fn free_box<T>(context: *mut c_void) {
    // SAFETY: the caller's; a vacant lodging drops nothing of the value.
    drop(unsafe { Box::from_raw(context.cast::<MaybeUninit<Lodging<T>>>()) });
}
