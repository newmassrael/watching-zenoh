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
use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};

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

/// No place for a value: the heap refused its box, or every place of a table is held. What a
/// maker answers in place of ending the program, as a C ABI answers its failed `malloc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoPlace;

/// A place a holder lent for one lodged value, with what gives it back: what a session's region,
/// a table of slots or a static table ([`StaticPlaces`]) hands a maker, which lodges its value
/// there ([`Strong::lodge_at`]). Dropped unused, the place goes back at once.
pub struct Lent<T> {
    place: NonNull<MaybeUninit<Lodging<T>>>,
    give_back: unsafe fn(*mut c_void),
    context: *mut c_void,
}

impl<T> Lent<T> {
    /// A place in a box of its own, given back to the heap with the last count of what is lodged
    /// there, or at once when dropped unused; [`NoPlace`] when the heap refuses the box. What a
    /// holder with no place of its own to lend hands a maker.
    pub fn try_boxed() -> Result<Self, NoPlace> {
        // Laid out as `Box::new(Lodging::vacant())` lays it out, so `free_box` gives it back.
        let layout = core::alloc::Layout::new::<MaybeUninit<Lodging<T>>>();
        // SAFETY: a lodging has bytes: its counts.
        let place = NonNull::new(unsafe { alloc::alloc::alloc(layout) })
            .ok_or(NoPlace)?
            .cast::<MaybeUninit<Lodging<T>>>();
        // SAFETY: the block is this place's alone, of a lodging's layout from the global
        // allocator, valid for writes of one and holding none; `free_box` gives it back once,
        // with a value lodged there or none.
        Ok(unsafe { Self::new(place, free_box::<T>, place.as_ptr().cast::<c_void>()) })
    }

    /// The place at `place`, which `give_back(context)` gives back once.
    ///
    /// # Safety
    /// As [`Strong::lodge`]'s `place`, `give_back` and `context`; and `give_back(context)` may
    /// also run with no value lodged, when the lent place is dropped unused.
    pub unsafe fn new(
        place: NonNull<MaybeUninit<Lodging<T>>>,
        give_back: unsafe fn(*mut c_void),
        context: *mut c_void,
    ) -> Self {
        Self {
            place,
            give_back,
            context,
        }
    }
}

impl<T> Drop for Lent<T> {
    fn drop(&mut self) {
        // SAFETY: `new`'s: nothing was lodged, so the place goes back now, once.
        unsafe { (self.give_back)(self.context) };
    }
}

/// Places for lodged values in a `static`, each lent to one value at a time and taken back with
/// the last count of it: a value the whole process shares lies in one of them, so it asks nothing
/// of a pool or a heap, and a table with every place held refuses the next value, never ending
/// the program. A `static` never moves, so a lock made in a place stays where it was made.
pub struct StaticPlaces<T, const N: usize> {
    places: [UnsafeCell<MaybeUninit<Lodging<T>>>; N],
    /// Whether each place is lent.
    held: [AtomicBool; N],
}

// SAFETY: a place is written only by the one lend that took its mark, and read after through the
// counts of the value lodged there, which are shared and sent as `Strong<T>` is.
unsafe impl<T: Send + Sync, const N: usize> Sync for StaticPlaces<T, N> {}

impl<T, const N: usize> StaticPlaces<T, N> {
    /// A table with no place lent.
    pub const fn new() -> Self {
        Self {
            places: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            held: [const { AtomicBool::new(false) }; N],
        }
    }

    /// A place no value holds, lent until the last count of what is lodged there lets it go;
    /// `None` when every place is held.
    pub fn lend(&'static self) -> Option<Lent<T>> {
        for (place, held) in self.places.iter().zip(&self.held) {
            // Acquire, to see the drop of the value the place held last before it is written again.
            if held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: the place is this table's, which never moves, and holds no value now that
                // its mark is this call's; `free_mark` clears the mark once, after the last count.
                return Some(unsafe {
                    Lent::new(
                        NonNull::new_unchecked(place.get()),
                        free_mark,
                        core::ptr::from_ref(held).cast_mut().cast::<c_void>(),
                    )
                });
            }
        }
        None
    }

    /// How many places are lent. For tests and diagnostics.
    pub fn lent(&self) -> usize {
        self.held
            .iter()
            .filter(|held| held.load(Ordering::Relaxed))
            .count()
    }
}

impl<T, const N: usize> Default for StaticPlaces<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Clear the mark of a static place: the place is free for the next value.
///
/// # Safety
/// `context` is the mark of a place [`StaticPlaces::lend`] lent, cleared once.
unsafe fn free_mark(context: *mut c_void) {
    // SAFETY: the caller's: the mark is a static table's, which outlives every call.
    unsafe { &*context.cast::<AtomicBool>() }.store(false, Ordering::Release);
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
    /// The value `make` writes in a box of its own ([`Lent::try_boxed`]), where it stays: what a
    /// value holding a lock is made in, its locks made there ([`crate::os::mutex_in`]). [`NoPlace`]
    /// when the heap refuses the box, with `make` not called.
    ///
    /// # Safety
    /// `make` leaves a valid `T` in the place it is handed, which is valid for writes of one,
    /// aligned for it and holds none.
    pub unsafe fn try_boxed_in(make: impl FnOnce(NonNull<T>)) -> Result<Self, NoPlace> {
        let lent = Lent::try_boxed()?;
        // SAFETY: the caller's.
        Ok(unsafe { Self::lodge_at(lent, make) })
    }

    /// `value` in the place `lent` names, given back with the last count of the value and of
    /// its place. Safe where [`Self::lodge_at`] is not: the whole value is written at once.
    pub fn new_at(lent: Lent<T>, value: T) -> Self {
        let write = |at: NonNull<T>| {
            // SAFETY: the place `lodge_at` hands is valid for writes of a `T` and holds none.
            unsafe { at.as_ptr().write(value) }
        };
        // SAFETY: `write` leaves `value` whole in the place it is handed.
        unsafe { Self::lodge_at(lent, write) }
    }

    /// The value `make` writes in the place `lent` names, where it stays: the place a session's
    /// region, a table of slots or a static table ([`StaticPlaces::lend`]) lent, given back with
    /// the last count of the value and of its place.
    ///
    /// # Safety
    /// `make` leaves a valid `T` in the place it is handed, which is valid for writes of one,
    /// aligned for it and holds none.
    pub unsafe fn lodge_at(lent: Lent<T>, make: impl FnOnce(NonNull<T>)) -> Self {
        let lent = core::mem::ManuallyDrop::new(lent);
        // SAFETY: `Lent::new`'s for the place, now the value's, given back by the counts and not
        // by the lent place's drop; `make` is the caller's.
        unsafe { Self::lodge_in(lent.place, make, lent.give_back, lent.context) }
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
        let write = |at: NonNull<T>| {
            // SAFETY: the place `lodge_in` hands is valid for writes of a `T` and holds none.
            unsafe { at.as_ptr().write(value) }
        };
        // SAFETY: the caller's, and `write` leaves `value` in the place it is handed.
        unsafe { Self::lodge_in(place, write, give_back, context) }
    }

    /// The value `make` writes in the place at `place`, where it stays, as [`Self::lodge`] lodges
    /// one: what a value holding a lock is made in, its locks made there
    /// ([`crate::os::mutex_in`]).
    ///
    /// # Safety
    /// As [`Self::lodge`]; and `make` leaves a valid `T` in the place it is handed, which is valid
    /// for writes of one, aligned for it and holds none.
    pub unsafe fn lodge_in(
        place: NonNull<MaybeUninit<Lodging<T>>>,
        make: impl FnOnce(NonNull<T>),
        give_back: unsafe fn(*mut c_void),
        context: *mut c_void,
    ) -> Self {
        let at = place.cast::<Lodging<T>>().as_ptr();
        // SAFETY: the caller's: the place is free and valid for writes of a `Lodging<T>`, and each
        // field is written once through a pointer to it, the value by `make` in its cell
        // (`UnsafeCell<MaybeUninit<T>>` has the layout of `T`), not null as it is inside the place.
        unsafe {
            addr_of_mut!((*at).strong).write(AtomicUsize::new(1));
            addr_of_mut!((*at).weak).write(AtomicUsize::new(1));
            addr_of_mut!((*at).give_back).write(give_back);
            addr_of_mut!((*at).context).write(context);
            make(NonNull::new_unchecked(
                addr_of_mut!((*at).value).cast::<T>(),
            ));
        }
        Self {
            at: place.cast::<Lodging<T>>(),
        }
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
pub(crate) unsafe fn retain_raw<T>(raw: *const c_void) {
    // SAFETY: the caller's count holds the lodging; Relaxed, as `Strong::clone`'s.
    unsafe { &*raw.cast::<Lodging<T>>() }
        .strong
        .fetch_add(1, Ordering::Relaxed);
}

/// Let go of one count of the value lodged at `raw`.
///
/// # Safety
/// `raw` is a count of a `T`'s lodging that the caller gives up, once.
pub(crate) unsafe fn release_raw<T>(raw: *mut c_void) {
    // SAFETY: the caller's.
    drop(unsafe { Strong::<T>::from_raw(raw) });
}

/// Give back a box [`Lent::try_boxed`] made.
///
/// # Safety
/// `context` is that box, whose value was dropped or never written, given back once.
unsafe fn free_box<T>(context: *mut c_void) {
    // SAFETY: the caller's; a vacant lodging drops nothing of the value.
    drop(unsafe { Box::from_raw(context.cast::<MaybeUninit<Lodging<T>>>()) });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value holding a lock, made in its lodging's place with its lock made there, is read and
    /// locked through every count, and the place goes back once, after the last. Turned red by a
    /// `lodge_in` that writes the counts or the value anywhere but the place it was handed.
    #[test]
    fn a_value_made_in_its_place_is_shared_by_its_counts() {
        struct Held {
            count: crate::os::Mutex<u32>,
        }
        let mut place = Lodging::<Held>::vacant();
        let given = AtomicUsize::new(0);
        let make = |at: NonNull<Held>| {
            // SAFETY: the place is the lodging's, valid for one `Held`, never moved while counted.
            unsafe {
                crate::os::mutex_in(
                    NonNull::new_unchecked(addr_of_mut!((*at.as_ptr()).count)),
                    |value| value.write(1),
                );
            }
        };
        // SAFETY: the place is vacant and stands, as the counter does, past every count here;
        // `make` makes the whole `Held`.
        let first = unsafe {
            Strong::lodge_in(
                NonNull::from(&mut place),
                make,
                count_back,
                core::ptr::from_ref(&given).cast_mut().cast::<c_void>(),
            )
        };
        let second = first.clone();
        *second.count.lock() += 1;
        assert_eq!(*first.count.lock(), 2);
        assert_eq!(Strong::strong_count(&first), 2);
        drop(first);
        assert_eq!(
            given.load(Ordering::Relaxed),
            0,
            "a count still holds the place"
        );
        drop(second);
        assert_eq!(given.load(Ordering::Relaxed), 1);
    }

    /// A static table lends each place to one value at a time: a full table refuses the next
    /// value, and a place goes back with the last count of its value, or at once when the place
    /// lent is dropped unused. Turned red by a lend that hands a held place again, or by a give
    /// back that leaves the place marked lent.
    #[test]
    fn a_static_table_lends_each_place_once_and_takes_it_back() {
        static TABLE: StaticPlaces<u32, 2> = StaticPlaces::new();
        let first_place = TABLE.lend().expect("CONTROL: a fresh table lends");
        let write = |at: NonNull<u32>| {
            // SAFETY: the place a lent place hands is valid for one `u32` and holds none.
            unsafe { at.as_ptr().write(1) }
        };
        // SAFETY: `write` makes the whole value.
        let first = unsafe { Strong::lodge_at(first_place, write) };
        let unused = TABLE.lend().expect("the second place is free");
        assert!(TABLE.lend().is_none(), "every place is held");
        drop(unused);
        assert_eq!(TABLE.lent(), 1, "a place dropped unused goes back at once");
        let copy = first.clone();
        drop(first);
        assert_eq!(*copy, 1);
        assert_eq!(TABLE.lent(), 1, "a count still holds the place");
        drop(copy);
        assert_eq!(TABLE.lent(), 0, "the last count gave the place back");
        assert!(TABLE.lend().is_some(), "a place given back is lent again");
    }

    /// A value made in a box of its own is read through its counts and dropped once, with the
    /// last of them. Turned red by a `try_boxed_in` that drops the value with the first count, or
    /// never.
    #[test]
    fn a_value_made_in_its_own_box_is_dropped_with_its_last_count() {
        struct Dropped<'a>(&'a AtomicUsize);
        impl Drop for Dropped<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let drops = AtomicUsize::new(0);
        let make = |at: NonNull<Dropped<'_>>| {
            // SAFETY: the place `try_boxed_in` hands is valid for one value and holds none.
            unsafe { at.as_ptr().write(Dropped(&drops)) }
        };
        // SAFETY: `make` makes the whole value.
        let first = unsafe { Strong::try_boxed_in(make) }.expect("the heap has room");
        let second = first.clone();
        drop(first);
        assert_eq!(drops.load(Ordering::Relaxed), 0, "a count still holds it");
        drop(second);
        assert_eq!(
            drops.load(Ordering::Relaxed),
            1,
            "dropped once, with the last"
        );
    }

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
        let count = Strong::new_at(Lent::try_boxed().expect("the test's heap"), 7u32);
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
