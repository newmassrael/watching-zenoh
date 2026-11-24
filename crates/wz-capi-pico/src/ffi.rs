// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! FFI-boundary safety helpers shared across the exported symbols.
//!
//! Two invariants every `#[no_mangle] extern "C"` export upholds:
//!
//! 1. **No unwinding across the boundary.** A Rust panic crossing an
//!    `extern "C"` frame is undefined behaviour. [`guarded`] wraps the body in
//!    `std::panic::catch_unwind` and converts a panic into a
//!    [`crate::result::Z_ERR_GENERIC`] return (or the caller-chosen fallback).
//!    Without `std` nothing unwinds: an image's panic handler stops the program
//!    (its staticlib is built `panic = "abort"`), so the body runs as it is.
//!
//! 2. **Raw C pointers can be moved across threads.** The wz drive loop runs
//!    on a worker thread; a subscriber's C `context` pointer must travel with
//!    it. [`SendPtr`] is the explicit, auditable assertion that the C side
//!    owns that pointer's thread-safety (the pico closure contract: the
//!    callback fires from the read task, the `drop` from teardown — never
//!    concurrently).

use alloc::sync::Arc;

use wz_capi_port::os::{Condvar, Mutex};

use crate::prelude::*;

// The guard and the thread-crossing pointer are compiled by every library of the ABI for itself.
mod boundary;
pub(crate) use boundary::{catch, guard_val, guarded, SendPtr};

/// A pico closure `{ context, call, drop }` adopted from the C side, generic
/// over the plane's `call` signature.
///
/// pico's closure families (`sample`, `query`, and the `reply` a later round
/// adds) are the SAME struct modulo the callback type, and share one lifecycle
/// rule: `drop(context)` runs exactly once, at teardown, never concurrently
/// with `call`. That rule is the whole mechanism, so it lives here once — a
/// second hand-written copy is a second place for the drop-once discipline to
/// drift.
///
/// **`Sync` is deliberately NOT implemented here.** Each plane must write its
/// own `unsafe impl Sync for CClosure<ItsCallbackType>`, because the safety
/// argument is per-plane and genuinely different: the subscriber plane's rests
/// on where a publish may go and the queryable plane's on where a queryable
/// admits a query from, in each arm of pico's local switches. A blanket
/// `unsafe impl<C> Sync for CClosure<C>` would silently hand that guarantee to
/// the next plane before anyone had made its argument — which is exactly the
/// class of bug R311y288 fixed on the publish plane. Rust allows `unsafe impl`
/// on a concrete instantiation, so per-plane proofs cost nothing.
///
/// `C` is the plane's pico callback typedef, which is itself already an
/// `Option<unsafe extern "C" fn(..)>` (a nullable C function pointer), so it is
/// held directly rather than re-wrapped.
pub(crate) struct CClosure<C> {
    pub(crate) context: SendPtr,
    pub(crate) call: C,
    pub(crate) drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    released: Released,
}

/// What a closure tells when its `drop(context)` has run: a latch of its own, which an owner keeps
/// to wait on, or the count of open closures of the owner it was adopted under
/// ([`OpenClosures`]), which takes no memory of its own.
enum Released {
    /// A latch of the closure's own ([`CClosure::new`]).
    Latch(Arc<ReleaseLatch>),
    /// The owner it is counted in, none while it is counted in none
    /// ([`CClosure::uncounted`], [`CClosure::count_in`]).
    Counted(Option<HeldIn>),
}

/// The owner a closure is counted in: the count of the closures it answers for, which lies in the
/// owner's place, and how that place is given back. The place goes back once its owner has let go
/// of it ([`OpenClosures::retire`]) and no closure counted in it is held, by whichever of the two
/// comes last, so a closure let go of after its owner (an undeclare or a close made from inside the
/// closure's own callback, which cannot wait for it) still finds its count, and nothing is
/// allocated for any closure.
#[derive(Clone, Copy)]
pub(crate) struct CountIn {
    open: core::ptr::NonNull<OpenClosures>,
    place: core::ptr::NonNull<core::ffi::c_void>,
    give_back: unsafe fn(core::ptr::NonNull<core::ffi::c_void>),
}

// SAFETY: the count it names is a lock, and the place is given back once, by the one thread the
// count tells it is last (`CountIn::new`); a closure is dropped on whatever thread lets go of it.
unsafe impl Send for CountIn {}
// SAFETY: as `Send`: a shared `CountIn` reads nothing but through the count's lock.
unsafe impl Sync for CountIn {}

impl CountIn {
    /// The owner whose closures `open` counts, its place `place`, given back by
    /// `give_back(place)`.
    ///
    /// # Safety
    /// `open` lies in `place` and stands until `give_back(place)` runs. The owner calls
    /// [`OpenClosures::retire`] once and, when it answers `true`, gives the place back itself;
    /// otherwise the place is the last closure's to give back, and nothing else gives it back.
    pub(crate) unsafe fn new(
        open: &OpenClosures,
        place: core::ptr::NonNull<core::ffi::c_void>,
        give_back: unsafe fn(core::ptr::NonNull<core::ffi::c_void>),
    ) -> Self {
        Self {
            open: core::ptr::NonNull::from(open),
            place,
            give_back,
        }
    }

    /// The count, which stands while a closure counted in it is held (`Self::new`).
    fn open(&self) -> &OpenClosures {
        // SAFETY: the count stands until the place is given back, which waits for this closure.
        unsafe { self.open.as_ref() }
    }

    /// Hold one open in this owner until the hold is dropped: a closure's, or a background
    /// entity's place, which the owner's close waits for as it waits for a closure.
    pub(crate) fn hold(self) -> HeldIn {
        self.open().open_one();
        HeldIn(self)
    }
}

/// One held open in an owner's count ([`CountIn::hold`]): dropped, it tells the count, and the
/// last one let go of after the owner let go of its place gives the place back.
pub(crate) struct HeldIn(CountIn);

impl Drop for HeldIn {
    fn drop(&mut self) {
        if self.0.open().close_one() {
            // SAFETY: the owner let go of its place and this was the last hold counted in it, so
            // the place is this drop's to give back, once (`CountIn::new`).
            unsafe { (self.0.give_back)(self.0.place) };
        }
    }
}

impl<C> CClosure<C> {
    /// Adopt a moved C closure's fields. The caller nulls the source (pico's
    /// consume-on-all-paths contract): from here this value owns the
    /// responsibility to run `drop(context)`.
    pub(crate) fn new(
        context: *mut core::ffi::c_void,
        call: C,
        drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
            released: Released::Latch(Arc::new(ReleaseLatch::default())),
        }
    }

    /// Adopt a moved C closure's fields, as [`Self::new`] does, with no latch: counted in no owner
    /// until [`Self::count_in`], so a closure dropped before it (a call refused before its session
    /// is read) runs its `drop(context)` and tells nobody.
    pub(crate) fn uncounted(
        context: *mut core::ffi::c_void,
        call: C,
        drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
            released: Released::Counted(None),
        }
    }

    /// Count this closure in `owner` until its `drop(context)` has run, so the owner waits for it
    /// ([`OpenClosures::wait_none`]) and its place stands until then. A closure made with a latch
    /// of its own, or counted already, is left as it is.
    pub(crate) fn count_in(&mut self, owner: CountIn) {
        if let Released::Counted(counted @ None) = &mut self.released {
            *counted = Some(owner.hold());
        }
    }

    /// The latch that opens once this closure's `drop(context)` has run. An entity that owns the
    /// closure takes it before the closure moves into the engine, and waits on it after the
    /// engine let go, which is how an undeclare returns only when the callback is finished. A
    /// closure an owner counts ([`Self::count_in`]) is waited on through the count, and its latch
    /// is open from the start.
    pub(crate) fn release_latch(&self) -> Arc<ReleaseLatch> {
        match &self.released {
            Released::Latch(latch) => latch.clone(),
            Released::Counted(_) => {
                let latch = Arc::new(ReleaseLatch::default());
                latch.open();
                latch
            }
        }
    }
}

impl<C> Drop for CClosure<C> {
    fn drop(&mut self) {
        if let Some(dropfn) = self.drop.take() {
            // SAFETY: pico contract — drop runs once, never concurrently with
            // call. A panic across the C boundary is UB, so guard it.
            let ctx = self.context.0;
            let _ = catch(|| unsafe {
                dropfn(ctx);
            });
        }
        match &mut self.released {
            Released::Latch(latch) => latch.open(),
            // The hold is let go of after the drop above has run, and may give back the place the
            // count lies in.
            Released::Counted(held) => drop(held.take()),
        }
    }
}

/// How many closures an owner answers for are still held: counted up as each is adopted under the
/// owner ([`CClosure::count_in`]) and down as each runs its `drop(context)`, so the owner waits
/// until none is open, as zenoh-pico's close waits for the callbacks in flight
/// (`_z_sync_group_wait`), with no latch and no allocation for each closure. It lies inline in
/// the owner's place, which stands until the owner has let go of it and no closure is held
/// (`CountIn`), so a closure let go of after its owner stopped waiting (a close made from
/// inside a callback) still has its count to tell.
#[derive(Default)]
pub(crate) struct OpenClosures {
    state: Mutex<Open>,
    none_open: Condvar,
}

/// The closures an owner's count holds, and whether the owner has let go of its place.
#[derive(Default)]
struct Open {
    held: usize,
    retired: bool,
}

impl OpenClosures {
    /// One more held open here: a closure counted in the owner, or a leg of a get, which lets it
    /// go with [`Self::close_one`].
    pub(crate) fn open_one(&self) {
        let mut state = self.state.lock();
        debug_assert!(
            !state.retired,
            "a closure is counted in an owner still held"
        );
        state.held = state.held.saturating_add(1);
    }

    /// One closure let go of: `true` when it was the last one held and the owner has let go of
    /// its place, which this closure then gives back.
    pub(crate) fn close_one(&self) -> bool {
        let mut state = self.state.lock();
        state.held = state.held.saturating_sub(1);
        // Every close is told, as a waiter may wait for fewer held rather than none
        // ([`Self::wait_at_most`]).
        self.none_open.notify_all();
        state.held == 0 && state.retired
    }

    /// The owner lets go of its place: `true` when no closure counted here is held, so the owner
    /// gives the place back now; otherwise the last closure let go of gives it back.
    pub(crate) fn retire(&self) -> bool {
        let mut state = self.state.lock();
        debug_assert!(!state.retired, "an owner lets go of its place once");
        state.retired = true;
        state.held == 0
    }

    /// Block until no closure counted here is held, unless this thread is inside one of the
    /// program's callbacks: that callback holds a closure, so waiting would wait for itself, as
    /// [`ReleaseLatch::wait`] says.
    pub(crate) fn wait_none(&self) {
        self.wait_at_most(0);
    }

    /// Block until at most `kept` are held here: the holds the caller has itself and lets go of
    /// after, so it waits for every other one, closures among them, and not for its own. Returns
    /// at once inside one of the program's callbacks, as [`Self::wait_none`] does.
    pub(crate) fn wait_at_most(&self, kept: usize) {
        if InCallback::here() {
            return;
        }
        let mut state = self.state.lock();
        while state.held > kept {
            state = self.none_open.wait(state);
        }
    }
}

/// Opens once, when the last holder of a closure has let go of it and its `drop(context)` has
/// run. Zenoh-pico's undeclare waits for the callbacks in flight and then runs the closure's
/// drop before it returns (`_z_sync_group_wait`), so a program may free what the callback reads
/// the moment an undeclare returns; this is what gives a call here the same word.
#[derive(Default)]
pub(crate) struct ReleaseLatch {
    open: Mutex<bool>,
    opened: Condvar,
}

impl ReleaseLatch {
    fn open(&self) {
        *self.open.lock() = true;
        self.opened.notify_all();
    }

    /// Block until the closure is released, unless this thread is inside one of the program's
    /// callbacks: that callback holds the closure, so waiting would wait for itself. The
    /// closure is then released when the callback returns, as it was before there was a wait.
    pub(crate) fn wait(&self) {
        if InCallback::here() {
            return;
        }
        let mut open = self.open.lock();
        while !*open {
            open = self.opened.wait(open);
        }
    }
}

impl ReleaseLatch {
    fn is_open(&self) -> bool {
        *self.open.lock()
    }
}

/// Waits for a closure's release when it is dropped. A struct that holds what the closure's
/// callbacks run through declares this LAST: fields drop in declaration order, so the wait comes
/// after everything before it has let go, which a `Drop::drop` body cannot say. The default waits
/// for nothing, which is what an owner whose callbacks are not the program's holds.
///
/// Its holders are the advanced publisher's and subscriber's states, so it exists where they do;
/// a build without `advanced` (the client-only and reduced builds) would carry it unused.
#[cfg(feature = "advanced")]
#[derive(Default)]
pub(crate) struct AwaitRelease(LatchList);

#[cfg(feature = "advanced")]
impl AwaitRelease {
    pub(crate) fn new(latch: Arc<ReleaseLatch>) -> Self {
        let list = LatchList::default();
        list.keep(latch);
        Self(list)
    }

    /// Wait for one more closure as well, one the owner came to hold after it was made.
    pub(crate) fn add(&self, latch: Arc<ReleaseLatch>) {
        self.0.keep(latch);
    }

    /// Take the latches, so that dropping this waits for nothing: the owner hands them to
    /// whoever will wait (a session's close) because the state outlives the handle.
    pub(crate) fn disarm(&mut self) -> Vec<Arc<ReleaseLatch>> {
        self.0.take_all()
    }
}

#[cfg(feature = "advanced")]
impl Drop for AwaitRelease {
    fn drop(&mut self) {
        self.0.wait_all();
    }
}

/// The latches of the closures an owner is answerable for, to wait on together. An owner that
/// hands out many (a querier's gets, a session's background declarations) keeps only the ones
/// still closed, so the list is as long as what is still running and not as what ever ran.
#[derive(Default)]
pub(crate) struct LatchList(Mutex<Vec<Arc<ReleaseLatch>>>);

impl LatchList {
    pub(crate) fn keep(&self, latch: Arc<ReleaseLatch>) {
        let mut list = self.0.lock();
        list.retain(|kept| !kept.is_open());
        list.push(latch);
    }

    /// Block until every kept closure has run its `drop(context)`. The list is emptied first, so
    /// a waiter holds nothing a callback running meanwhile could need.
    pub(crate) fn wait_all(&self) {
        for latch in self.take_all() {
            latch.wait();
        }
    }

    pub(crate) fn take_all(&self) -> Vec<Arc<ReleaseLatch>> {
        core::mem::take(&mut *self.0.lock())
    }
}

/// Marks the thread as running one of the program's callbacks until it is dropped; held across
/// the C call at every site that makes one.
pub(crate) struct InCallback {
    // Held for its drop, which leaves the callback; never read.
    _entered: callback_depth::Entered,
}

impl InCallback {
    pub(crate) fn enter() -> Self {
        Self {
            _entered: callback_depth::enter(),
        }
    }

    /// Whether the calling thread is inside one of the program's callbacks.
    pub(crate) fn here() -> bool {
        callback_depth::here()
    }
}

/// How many of the program's callbacks each thread is running: a thread-local count on a host,
/// whose callbacks are on the hot path of every delivery.
#[cfg(feature = "std")]
mod callback_depth {
    use core::cell::Cell;

    std::thread_local! {
        static IN_CALLBACK: Cell<usize> = const { Cell::new(0) };
    }

    /// One callback of the calling thread, from [`enter`] to drop.
    pub(super) struct Entered;

    pub(super) fn enter() -> Entered {
        IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_add(1)));
        Entered
    }

    pub(super) fn here() -> bool {
        IN_CALLBACK.with(|depth| depth.get()) > 0
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            // This callback entered, so the count is one or more.
            IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
}

/// How many of the program's callbacks each thread is running, without `std`: one entry for each
/// callback in the process's table, keyed by the thread's identity, because an MCU kernel gives a
/// Rust image no thread-local storage. Compiled for the host's tests too, so the table is run
/// where the tests run.
#[cfg(any(not(feature = "std"), test))]
mod callback_table {
    use alloc::vec::Vec;

    use wz_capi_port::os::{self, ThreadId};
    use wz_capi_port::sync::Lock;

    static IN_CALLBACK: Lock<Vec<ThreadId>> = Lock::new(Vec::new());

    /// One callback of the calling thread, from [`enter`] to drop.
    pub(super) struct Entered {
        thread: ThreadId,
    }

    pub(super) fn enter() -> Entered {
        let thread = os::current();
        IN_CALLBACK.with(|threads| threads.push(thread));
        Entered { thread }
    }

    pub(super) fn here() -> bool {
        let thread = os::current();
        IN_CALLBACK.with(|threads| threads.contains(&thread))
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            let thread = self.thread;
            IN_CALLBACK.with(|threads| {
                if let Some(at) = threads.iter().rposition(|t| *t == thread) {
                    threads.swap_remove(at);
                }
            });
        }
    }
}

#[cfg(not(feature = "std"))]
use callback_table as callback_depth;

#[cfg(test)]
mod tests {
    use super::callback_table;

    #[test]
    fn the_callback_table_counts_each_thread_on_its_own() {
        assert!(!callback_table::here());
        let outer = callback_table::enter();
        let inner = callback_table::enter();
        assert!(callback_table::here());
        let elsewhere = std::thread::spawn(callback_table::here)
            .join()
            .expect("the probe thread ends");
        assert!(!elsewhere, "another thread is in no callback");
        drop(inner);
        assert!(callback_table::here(), "the outer callback still runs");
        drop(outer);
        assert!(!callback_table::here());
    }
}

#[cfg(test)]
mod closure_tests {
    //! A closure counted in an owner is open there from its count to its drop, and the owner's
    //! place goes back with the last of the owner and its closures.
    use super::*;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// The C drop the closures of these tests run: counts how often it ran.
    unsafe extern "C" fn counted_drop(context: *mut core::ffi::c_void) {
        // SAFETY: each test hands the address of its own counter, which outlives the closure.
        unsafe { (*context.cast::<AtomicUsize>()).fetch_add(1, Ordering::SeqCst) };
    }

    type Closure = CClosure<Option<unsafe extern "C" fn()>>;

    fn closure(dropped: &AtomicUsize) -> Closure {
        Closure::uncounted(
            core::ptr::from_ref(dropped).cast_mut().cast(),
            None,
            Some(counted_drop),
        )
    }

    /// An owner's place: its count, and how often the place was given back.
    #[derive(Default)]
    struct Owner {
        open: OpenClosures,
        given_back: AtomicUsize,
    }

    /// Give an [`Owner`]'s place back: count it.
    unsafe fn give_back_owner(place: NonNull<core::ffi::c_void>) {
        // SAFETY: every place of these tests is an `Owner` that outlives its closures.
        unsafe { place.cast::<Owner>().as_ref() }
            .given_back
            .fetch_add(1, Ordering::SeqCst);
    }

    fn owner_of(owner: &Owner) -> CountIn {
        // SAFETY: the owner outlives every closure of the test, and no test gives its place back
        // other than as the count tells.
        unsafe { CountIn::new(&owner.open, NonNull::from(owner).cast(), give_back_owner) }
    }

    fn held(owner: &Owner) -> usize {
        owner.open.state.lock().held
    }

    /// An owner's count is open while a closure counted in it is held and none once its drop ran;
    /// a closure counted twice counts once, and one counted in no owner tells none.
    #[test]
    fn a_counted_closure_is_open_until_its_drop_ran() {
        let dropped = AtomicUsize::new(0);
        let owner = Owner::default();
        let mut first = closure(&dropped);
        first.count_in(owner_of(&owner));
        first.count_in(owner_of(&owner));
        let mut second = closure(&dropped);
        second.count_in(owner_of(&owner));
        assert_eq!(held(&owner), 2, "each closure counts once");
        drop(closure(&dropped));
        assert_eq!(held(&owner), 2, "a closure counted nowhere tells no owner");
        drop(first);
        drop(second);
        assert_eq!(held(&owner), 0);
        owner.open.wait_none();
        assert_eq!(dropped.load(Ordering::SeqCst), 3, "every drop ran");
        assert_eq!(
            owner.given_back.load(Ordering::SeqCst),
            0,
            "an owner still held keeps its place"
        );
    }

    /// An owner that lets go of its place while closures are held leaves the place to the last of
    /// them, which gives it back once.
    #[test]
    fn the_last_closure_gives_back_the_place_its_owner_let_go_of() {
        let dropped = AtomicUsize::new(0);
        let owner = Owner::default();
        let mut first = closure(&dropped);
        first.count_in(owner_of(&owner));
        let mut second = closure(&dropped);
        second.count_in(owner_of(&owner));
        assert!(!owner.open.retire(), "two closures are held");
        drop(first);
        assert_eq!(owner.given_back.load(Ordering::SeqCst), 0, "one still held");
        drop(second);
        assert_eq!(
            owner.given_back.load(Ordering::SeqCst),
            1,
            "the last closure gave the place back"
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
    }

    /// An owner that lets go of its place with no closure held gives it back itself: no closure
    /// let go of before does.
    #[test]
    fn an_owner_with_no_closure_held_gives_its_place_back_itself() {
        let dropped = AtomicUsize::new(0);
        let owner = Owner::default();
        let mut only = closure(&dropped);
        only.count_in(owner_of(&owner));
        drop(only);
        assert!(owner.open.retire(), "none is held");
        assert_eq!(
            owner.given_back.load(Ordering::SeqCst),
            0,
            "the closure, let go of before its owner, gave nothing back"
        );
    }

    /// A wait returns once the last closure counted is let go of on another thread.
    #[test]
    fn a_wait_returns_when_the_last_closure_goes() {
        static DROPPED: AtomicUsize = AtomicUsize::new(0);
        let owner = std::sync::Arc::new(Owner::default());
        let mut held_closure = closure(&DROPPED);
        held_closure.count_in(owner_of(&owner));
        let kept = std::sync::Arc::clone(&owner);
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(held_closure);
            drop(kept);
        });
        owner.open.wait_none();
        assert_eq!(
            DROPPED.load(Ordering::SeqCst),
            1,
            "the wait outlasted the drop"
        );
        release.join().expect("the releasing thread ends");
    }

    /// A wait for all but the waiter's own hold returns once the other closure is let go of on
    /// another thread, and leaves that hold counted. Turned red by a close that tells a waiter
    /// only when none is held, which leaves this wait waiting on its own hold.
    #[test]
    fn a_wait_for_all_but_its_own_hold_returns_when_the_others_go() {
        static DROPPED: AtomicUsize = AtomicUsize::new(0);
        let owner = std::sync::Arc::new(Owner::default());
        let own = owner_of(&owner).hold();
        let mut other = closure(&DROPPED);
        other.count_in(owner_of(&owner));
        assert_eq!(held(&owner), 2);
        let kept = std::sync::Arc::clone(&owner);
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(other);
            drop(kept);
        });
        owner.open.wait_at_most(1);
        assert_eq!(
            DROPPED.load(Ordering::SeqCst),
            1,
            "the wait outlasted the other closure's drop"
        );
        assert_eq!(held(&owner), 1, "the waiter's own hold is still counted");
        release.join().expect("the releasing thread ends");
        drop(own);
        assert_eq!(held(&owner), 0);
        assert_eq!(
            owner.given_back.load(Ordering::SeqCst),
            0,
            "an owner still held keeps its place"
        );
    }
}
