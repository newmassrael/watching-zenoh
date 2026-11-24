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
use alloc::sync::Arc;

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
    /// A count of the value, while one is still held and the counts have room for one more: none
    /// when the value is gone, or when its counts are as many as a count can say.
    pub fn upgrade(&self) -> Option<Strong<T>> {
        // SAFETY: a weak count holds the place, so its counts stand.
        let strong = unsafe { &self.at.as_ref().strong };
        let mut seen = strong.load(Ordering::Relaxed);
        loop {
            if seen == 0 {
                return None;
            }
            // A count past the most would wrap to none held, and the next let go of would drop the
            // value under the counts still held: refused, as a value gone is.
            let next = seen.checked_add(1)?;
            match strong.compare_exchange_weak(seen, next, Ordering::Acquire, Ordering::Relaxed) {
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

/// A count of a value its holder neither names nor reads, held for what the value keeps alive: a
/// value in a box of its own (`Arc`), or one lodged where its maker put it ([`Strong`]), so a
/// holder that keeps another's value takes no memory for it when the value is lodged. A copy is one
/// more count; a drop lets one go, and the last lets the value go as its own count says.
#[derive(Clone)]
pub struct Kept(KeptForm);

/// The count a [`Kept`] holds. Copying one is all it is read for: the copy is one more count of
/// the same value, and dropping a form lets its count go.
enum KeptForm {
    Shared(Arc<dyn Send + Sync>),
    Lodged(LodgedCount),
}

impl Clone for KeptForm {
    fn clone(&self) -> Self {
        match self {
            Self::Shared(held) => Self::Shared(Arc::clone(held)),
            Self::Lodged(count) => Self::Lodged(count.clone()),
        }
    }
}

/// A count of a lodged value whose type is named only by the two functions that take and let go
/// of a count of it.
struct LodgedCount {
    raw: NonNull<c_void>,
    retain: unsafe fn(*const c_void),
    release: unsafe fn(*mut c_void),
}

// SAFETY: made only from a `Strong<T>` with `T: Send + Sync` ([`Kept::lodged`]), which is both.
unsafe impl Send for LodgedCount {}
// SAFETY: as `Send`.
unsafe impl Sync for LodgedCount {}

impl Kept {
    /// One count of `value`, in a box of its own.
    pub fn shared(value: Arc<dyn Send + Sync>) -> Self {
        Self(KeptForm::Shared(value))
    }

    /// The count `count` is, of a value lodged where its maker put it.
    pub fn lodged<T: Send + Sync>(count: Strong<T>) -> Self {
        Self(KeptForm::Lodged(LodgedCount {
            // SAFETY: `into_raw` gives up a count of a lodging, which is never null.
            raw: unsafe { NonNull::new_unchecked(Strong::into_raw(count)) },
            retain: retain_raw::<T>,
            release: release_raw::<T>,
        }))
    }
}

impl core::fmt::Debug for Kept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self.0 {
            KeptForm::Shared(_) => "Kept::Shared",
            KeptForm::Lodged(_) => "Kept::Lodged",
        })
    }
}

impl Clone for LodgedCount {
    fn clone(&self) -> Self {
        // SAFETY: this count holds the value, so another may be taken from it.
        unsafe { (self.retain)(self.raw.as_ptr().cast_const()) };
        Self {
            raw: self.raw,
            retain: self.retain,
            release: self.release,
        }
    }
}

impl Drop for LodgedCount {
    fn drop(&mut self) {
        // SAFETY: this count was given up by `Strong::into_raw` (or taken by `retain_raw`) and is
        // let go of once, here.
        unsafe { (self.release)(self.raw.as_ptr()) };
    }
}

/// Take one more count of the value lodged at `raw`.
///
/// # Safety
/// `raw` names a lodging of a `T` of which the caller holds a count.
unsafe fn retain_raw<T>(raw: *const c_void) {
    // SAFETY: the caller's count holds the lodging; Relaxed, as `Strong::clone`'s.
    unsafe { &*raw.cast::<Lodging<T>>() }
        .strong
        .fetch_add(1, Ordering::Relaxed);
}

/// Let go of one count of the value lodged at `raw`.
///
/// # Safety
/// `raw` is a count of a `T`'s lodging that the caller gives up, once.
unsafe fn release_raw<T>(raw: *mut c_void) {
    // SAFETY: the caller's.
    drop(unsafe { Strong::<T>::from_raw(raw) });
}

/// Give back a box [`Strong::boxed`] made.
///
/// # Safety
/// `context` is that box, whose value was dropped, given back once.
unsafe fn free_box<T>(context: *mut c_void) {
    // SAFETY: the caller's; a vacant lodging drops nothing of the value.
    drop(unsafe { Box::from_raw(context.cast::<MaybeUninit<Lodging<T>>>()) });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Count one giving back of a place, in the counter `context` names.
    ///
    /// # Safety
    /// `context` is an `AtomicUsize` that outlives the call.
    unsafe fn count_back(context: *mut c_void) {
        // SAFETY: the caller's.
        unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::Relaxed);
    }

    /// A lodged value held by a key's keep is a count like any other: a copy of the keep is one
    /// more, a drop one less, and the place goes back once, after the last of them.
    ///
    /// # Control
    ///
    /// A keep whose copy takes no count gives the place back while a copy still holds it, which
    /// reds the second and third assertions.
    #[test]
    fn a_lodged_keep_counts_its_copies_and_the_place_goes_back_once() {
        let mut place = Lodging::<u32>::vacant();
        let given = AtomicUsize::new(0);
        // SAFETY: the place is vacant and stands, as the counter does, past every count here.
        let count = unsafe {
            Strong::lodge(
                NonNull::from(&mut place),
                7,
                count_back,
                core::ptr::from_ref(&given).cast_mut().cast::<c_void>(),
            )
        };
        let kept = Kept::lodged(count.clone());
        let copy = kept.clone();
        assert_eq!(
            Strong::strong_count(&count),
            3,
            "the keep and its copy are counts"
        );
        drop(kept);
        assert_eq!(
            Strong::strong_count(&count),
            2,
            "a dropped keep is one less"
        );
        drop(count);
        assert_eq!(
            given.load(Ordering::Relaxed),
            0,
            "the copy still holds the place"
        );
        drop(copy);
        assert_eq!(
            given.load(Ordering::Relaxed),
            1,
            "the last count gave the place back"
        );
    }

    /// A keep of a value in a box of its own is a count of the box: its copy is one more, and
    /// the box goes with the last of them.
    ///
    /// # Control
    ///
    /// A copy that makes a new box, or takes no count, leaves the box's count at two after the
    /// copy, which reds the first assertion.
    #[test]
    fn a_shared_keep_counts_its_copies() {
        let value: Arc<u32> = Arc::new(7);
        let kept = Kept::shared(value.clone());
        let copy = kept.clone();
        assert_eq!(
            Arc::strong_count(&value),
            3,
            "the keep and its copy are counts"
        );
        drop(kept);
        drop(copy);
        assert_eq!(Arc::strong_count(&value), 1, "both counts were let go of");
    }

    /// A weak count upgrades to a count while the value is held, and is refused, the counts left
    /// as they were, when the value has as many counts as a count can say.
    ///
    /// # Control
    ///
    /// The first upgrade, of a value with room for a count, is the control. An upgrade that adds
    /// to the count unchecked overflows it, which reds the refusal and the count after it.
    #[test]
    fn an_upgrade_past_the_most_counts_is_refused() {
        let count = Strong::boxed(7u32);
        let weak = Strong::downgrade(&count);
        let upgraded = weak.upgrade().expect("CONTROL: the value is held");
        assert_eq!(Strong::strong_count(&count), 2, "the upgrade is a count");
        drop(upgraded);
        count.lodging().strong.store(usize::MAX, Ordering::Relaxed);
        assert!(weak.upgrade().is_none(), "no room for one more count");
        assert_eq!(
            Strong::strong_count(&count),
            usize::MAX,
            "a refused upgrade leaves the counts as they were"
        );
        // Back to the one count held, so the drops below give the box back as it was made.
        count.lodging().strong.store(1, Ordering::Relaxed);
        drop(weak);
        drop(count);
    }
}
