// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! FFI-boundary safety helpers shared across the exported symbols.
//!
//! Two invariants every `#[no_mangle] extern "C"` export upholds:
//!
//! 1. **No unwinding across the boundary.** A panic aborts at the C boundary in
//!    every build: without `std` the panic handler stops the program, and with it
//!    a panic reaching an `extern "C"` frame aborts there. [`guarded`] is a plain
//!    call of the body, so no export carries a landing pad.
//!
//! 2. **Raw C pointers can be moved across threads.** The wz drive loop runs
//!    on a worker thread; a subscriber's C `context` pointer must travel with
//!    it. [`SendPtr`] is the explicit, auditable assertion that the C side
//!    owns that pointer's thread-safety (the pico closure contract: the
//!    callback fires from the read task, the `drop` from teardown — never
//!    concurrently).

use wz_capi_port::os::{Condvar, Mutex};

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
    /// The owner it is counted in, none while it is counted in none ([`CClosure::uncounted`],
    /// [`CClosure::count_in`]): told when its `drop(context)` has run, which takes no memory of
    /// its own.
    released: Option<HeldIn>,
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
        self.open().count_one(false);
        HeldIn(self)
    }

    /// Keep the owner's place until the hold is dropped, for what lies in it and is reached apart
    /// from the owner after it let go: the place stands, and the owner's close does not wait for
    /// it, as it is no closure.
    #[cfg(any(
        feature = "advanced",
        all(
            test,
            not(feature = "engine-tokio"),
            feature = "peer",
            feature = "query"
        )
    ))]
    pub(crate) fn keep(self) -> KeptIn {
        self.open().count_one(true);
        KeptIn(self)
    }

    /// One hold, or one keep (`kept`), let go of: the last of them let go of after the owner let
    /// go of its place gives the place back. One body for both, out of line, as every drop of a
    /// hold or a keep reaches it.
    #[inline(never)]
    fn let_go(&self, kept: bool) {
        if self.open().uncount_one(kept) {
            // SAFETY: the owner let go of its place and this was the last hold or keep counted in
            // it, so the place is this call's to give back, once (`CountIn::new`).
            unsafe { (self.give_back)(self.place) };
        }
    }
}

/// One keep of an owner's place ([`CountIn::keep`]): dropped, it tells the count, and the last of
/// the holds and keeps let go of after the owner let go of its place gives the place back.
#[cfg(any(
    feature = "advanced",
    all(
        test,
        not(feature = "engine-tokio"),
        feature = "peer",
        feature = "query"
    )
))]
pub(crate) struct KeptIn(CountIn);

#[cfg(any(
    feature = "advanced",
    all(
        test,
        not(feature = "engine-tokio"),
        feature = "peer",
        feature = "query"
    )
))]
impl Drop for KeptIn {
    fn drop(&mut self) {
        self.0.let_go(true);
    }
}

#[cfg(feature = "advanced")]
impl KeptIn {
    /// The count this keep is held in, from which more keeps of the same place may be taken while
    /// this one holds it.
    pub(crate) fn count(&self) -> CountIn {
        self.0
    }
}

/// One held open in an owner's count ([`CountIn::hold`]): dropped, it tells the count, and the
/// last one let go of after the owner let go of its place gives the place back.
pub(crate) struct HeldIn(CountIn);

impl HeldIn {
    /// The place this hold is counted in, the hold left counted: what lets it go is kept apart
    /// from this value, by one pointer ([`Self::adopt`] takes it back).
    pub(crate) fn into_place(self) -> core::ptr::NonNull<core::ffi::c_void> {
        let place = self.0.place;
        core::mem::forget(self);
        place
    }

    /// A hold of `count` parted from its value by [`Self::into_place`], taken back to be let go
    /// of.
    ///
    /// # Safety
    /// `count` is the count a hold parted by [`Self::into_place`] was counted in, and that hold
    /// is taken back once, here.
    pub(crate) unsafe fn adopt(count: CountIn) -> Self {
        Self(count)
    }
}

impl Drop for HeldIn {
    fn drop(&mut self) {
        self.0.let_go(false);
    }
}

impl<C> CClosure<C> {
    /// Adopt a moved C closure's fields. The caller nulls the source (pico's
    /// consume-on-all-paths contract): from here this value owns the
    /// responsibility to run `drop(context)`. Counted in no owner until [`Self::count_in`], so a
    /// closure dropped before it (a call refused before its session is read) runs its
    /// `drop(context)` and tells nobody.
    pub(crate) fn uncounted(
        context: *mut core::ffi::c_void,
        call: C,
        drop: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    ) -> Self {
        Self {
            context: SendPtr(context),
            call,
            drop,
            released: None,
        }
    }

    /// The closure's context, C function and C drop, for a holder that runs the drop itself (an
    /// engine's row, `wz_capi_port::SubscriberSink::c`): this value no longer drops it. Taken
    /// from a closure counted in no owner, as that holder tells none.
    pub(crate) fn into_c_parts(
        self,
    ) -> (
        *mut core::ffi::c_void,
        C,
        Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    )
    where
        C: Copy,
    {
        let mut this = core::mem::ManuallyDrop::new(self);
        debug_assert!(
            this.released.is_none(),
            "a closure handed to a row is counted in no owner"
        );
        (this.context.0, this.call, this.drop.take())
    }

    /// Count this closure in `owner` until its `drop(context)` has run, so the owner waits for it
    /// ([`OpenClosures::wait_none`]) and its place stands until then. A closure counted already
    /// is left as it is.
    pub(crate) fn count_in(&mut self, owner: CountIn) {
        if self.released.is_none() {
            self.released = Some(owner.hold());
        }
    }
}

impl<C> Drop for CClosure<C> {
    fn drop(&mut self) {
        if let Some(dropfn) = self.drop.take() {
            // SAFETY: pico contract — drop runs once, never concurrently with
            // call.
            let ctx = self.context.0;
            let _ = catch(|| unsafe {
                dropfn(ctx);
            });
        }
        // The hold is let go of after the drop above has run, and may give back the place the
        // count lies in.
        drop(self.released.take());
    }
}

/// How many closures an owner answers for are still held: counted up as each is adopted under the
/// owner ([`CClosure::count_in`]) and down as each runs its `drop(context)`, so the owner waits
/// until none is open, as zenoh-pico's close waits for the callbacks in flight
/// (`_z_sync_group_wait`), with no latch and no allocation for each closure. It lies inline in
/// the owner's place, which stands until the owner has let go of it and no closure is held
/// (`CountIn`), so a closure let go of after its owner stopped waiting (a close made from
/// inside a callback) still has its count to tell.
///
/// Its lock and condition variable are a kernel's in a Zephyr image, which are made where they
/// stay and never moved (`Self::init_at`); only a build whose lock is the host's makes one by
/// value.
#[cfg_attr(any(test, feature = "engine-tokio"), derive(Default))]
pub(crate) struct OpenClosures {
    state: Mutex<Open>,
    none_open: Condvar,
}

/// The closures an owner's count holds, the keeps of its place ([`KeptIn`]), and whether the
/// owner has let go of its place.
#[derive(Default)]
struct Open {
    held: usize,
    kept: usize,
    retired: bool,
}

impl Open {
    /// Nothing holds or keeps the place.
    fn unheld(&self) -> bool {
        self.held == 0 && self.kept == 0
    }
}

impl OpenClosures {
    /// A count with no closure held, made in `at` with its lock and condition variable made where
    /// they stay.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The count is not moved from `at` until it is dropped there.
    pub(crate) unsafe fn init_at(at: core::ptr::NonNull<Self>) {
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            wz_capi_port::os::mutex_in(
                core::ptr::NonNull::new_unchecked(core::ptr::addr_of_mut!((*at).state)),
                |open| open.write(Open::default()),
            );
            wz_capi_port::os::condvar_in(core::ptr::NonNull::new_unchecked(
                core::ptr::addr_of_mut!((*at).none_open),
            ));
        }
    }

    /// One more held open here: a closure counted in the owner, or a leg of a get, which lets it
    /// go with [`Self::close_one`].
    #[cfg(feature = "query")]
    pub(crate) fn open_one(&self) {
        self.count_one(false);
    }

    /// One closure let go of: `true` when it was the last one held and the owner has let go of
    /// its place, which this closure then gives back.
    #[cfg(feature = "query")]
    pub(crate) fn close_one(&self) -> bool {
        self.uncount_one(false)
    }

    /// One more held open here, or one more keep of the owner's place (`kept`), which no wait
    /// waits for. The place must stand: its owner holds it, or, once the owner let go of it, a hold
    /// or a keep counted before does (a background listener's place, which the session's table of
    /// listeners holds and its fan holds again for each call).
    fn count_one(&self, kept: bool) {
        let mut state = self.state.lock();
        debug_assert!(
            !(state.retired && state.unheld()),
            "a closure or a keep is counted in a place already given back"
        );
        if kept {
            state.kept = state.kept.saturating_add(1);
        } else {
            state.held = state.held.saturating_add(1);
        }
    }

    /// One held, or one keep (`kept`), let go of: `true` when nothing else holds or keeps the
    /// place and the owner has let go of it, which the caller then gives back.
    fn uncount_one(&self, kept: bool) -> bool {
        let mut state = self.state.lock();
        if kept {
            state.kept = state.kept.saturating_sub(1);
        } else {
            state.held = state.held.saturating_sub(1);
            // Every close is told, as a waiter may wait for fewer held rather than none
            // ([`Self::wait_at_most`]).
            self.none_open.notify_all();
        }
        state.unheld() && state.retired
    }

    /// The owner lets go of its place: `true` when no closure counted here is held and no keep
    /// ([`KeptIn`]) is, so the owner gives the place back now; otherwise the last of them gives it
    /// back.
    pub(crate) fn retire(&self) -> bool {
        let mut state = self.state.lock();
        debug_assert!(!state.retired, "an owner lets go of its place once");
        state.retired = true;
        state.unheld()
    }

    /// Block until no closure counted here is held, unless this thread is inside one of the
    /// program's callbacks: that callback holds a closure, so waiting would wait for itself; the
    /// closure is then released when the callback returns.
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

/// Marks the thread as running one of the program's callbacks until it is dropped; held across
/// the C call at every site that makes one.
pub(crate) struct InCallback {
    // Held for its drop, which leaves the callback; never read.
    _entered: callback_depth::Entered,
}

impl InCallback {
    /// Mark the calling thread, or `None` when the build counts its callbacks in a table and
    /// [`wz_session_core::caps::CALLBACK_THREADS`] other threads already run one: the caller then
    /// does not call the program, since a callback run unmarked would wait for itself at a door
    /// that waits for the program's callbacks.
    pub(crate) fn enter() -> Option<Self> {
        Some(Self {
            _entered: callback_depth::enter()?,
        })
    }

    /// Whether the calling thread is inside one of the program's callbacks.
    pub(crate) fn here() -> bool {
        callback_depth::here()
    }
}

/// How many of the program's callbacks the library did not run because the table that marks the
/// threads inside one was full (`InCallback::enter` answered `None`); 0 in the tokio engine's
/// build, which marks every thread and so runs every callback.
#[no_mangle]
pub extern "C" fn zext_callbacks_refused() -> usize {
    callback_depth::refused()
}

/// How many of the program's callbacks each thread is running: a thread-local count in the tokio
/// engine's build, which links `std` and whose callbacks are on the hot path of every delivery.
#[cfg(feature = "engine-tokio")]
mod callback_depth {
    use core::cell::Cell;

    std::thread_local! {
        static IN_CALLBACK: Cell<usize> = const { Cell::new(0) };
    }

    /// One callback of the calling thread, from [`enter`] to drop.
    pub(super) struct Entered;

    pub(super) fn enter() -> Option<Entered> {
        IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_add(1)));
        Some(Entered)
    }

    pub(super) fn here() -> bool {
        IN_CALLBACK.with(|depth| depth.get()) > 0
    }

    pub(super) fn refused() -> usize {
        0
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            // This callback entered, so the count is one or more.
            IN_CALLBACK.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
}

/// How many of the program's callbacks each thread is running in a library without `std`: one entry for each
/// thread in a callback, keyed by the thread's word, in a table of the process whose room is fixed
/// by the build, because an MCU kernel gives a Rust image no thread-local storage and a session
/// takes no heap after it opens. It is asked on every delivery, so it takes no lock: a thread
/// claims a free entry with one compare-and-swap and is then the only one to write it until it
/// frees it, and a thread looks for nothing but its own word, which only its own writes put in the
/// table. Compiled for the host's tests too, so the table is run where the tests run.
#[cfg(any(not(feature = "engine-tokio"), test))]
mod callback_table {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use wz_capi_port::os;
    #[cfg(feature = "multi-thread")]
    use wz_session_core::caps;

    /// The threads that may be inside callbacks at once: in the multi-threaded arm the read tasks
    /// and the program's threads, as many as the build states.
    #[cfg(feature = "multi-thread")]
    const ROOM: usize = caps::CALLBACK_THREADS;
    /// In the single-threaded arm the program calls the library from one thread at a time, as
    /// zenoh-pico's arm without threads asks, and no task of the library's runs a callback, so one
    /// thread at most is inside callbacks, however deep they nest.
    #[cfg(not(feature = "multi-thread"))]
    const ROOM: usize = 1;

    static IN_CALLBACK: Threads<ROOM> = Threads::new();

    /// What a free entry holds: no thread's word is 0.
    const NO_THREAD: usize = 0;

    /// The threads running one of the program's callbacks, and how many callbacks a thread past
    /// the room did not run. Entries are claimed from the front, so a search ends at `used`, the
    /// most entries ever claimed, rather than at the room.
    pub(super) struct Threads<const N: usize> {
        entries: [Entry; N],
        used: AtomicUsize,
        refused: AtomicUsize,
    }

    /// One thread inside callbacks: its word ([`os::current_word`]), [`NO_THREAD`] while the
    /// entry is free, and how many callbacks it runs, nested, which only that thread touches.
    struct Entry {
        thread: AtomicUsize,
        depth: AtomicUsize,
    }

    impl Entry {
        const fn free() -> Self {
            Self {
                thread: AtomicUsize::new(NO_THREAD),
                depth: AtomicUsize::new(0),
            }
        }

        /// Take the entry for `thread`, one callback counted, if it is free.
        fn claim(&self, thread: usize) -> bool {
            // The load first, so an entry another thread holds is passed by without a locked
            // operation. Acquire: the thread that freed the entry wrote its depth before it let go.
            if self.thread.load(Ordering::Relaxed) != NO_THREAD
                || self
                    .thread
                    .compare_exchange(NO_THREAD, thread, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
            {
                return false;
            }
            self.depth.store(1, Ordering::Relaxed);
            true
        }
    }

    impl<const N: usize> Threads<N> {
        pub(super) const fn new() -> Self {
            Self {
                entries: [const { Entry::free() }; N],
                used: AtomicUsize::new(0),
                refused: AtomicUsize::new(0),
            }
        }

        /// Count one more callback of `thread`: the entry that counts it, or `None`, counting
        /// nothing but the refusal, when `thread` runs none yet and `N` others do.
        pub(super) fn enter(&self, thread: usize) -> Option<usize> {
            if let Some((at, entry)) = self.held_by(thread) {
                let depth = entry.depth.load(Ordering::Relaxed);
                entry
                    .depth
                    .store(depth.saturating_add(1), Ordering::Relaxed);
                return Some(at);
            }
            let claimed = self.claim(thread);
            if claimed.is_none() {
                // Saturating, so the program never reads fewer than were refused.
                let _ =
                    self.refused
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |refused| {
                            refused.checked_add(1)
                        });
            }
            claimed
        }

        /// A free entry claimed for `thread`: the first free one among those claimed before, or
        /// else the next one past them, none past the room.
        fn claim(&self, thread: usize) -> Option<usize> {
            if N == 1 {
                // A table of one entry has no entries past those claimed to count: its one entry
                // is free or another thread's.
                return self.entries.first()?.claim(thread).then_some(0);
            }
            loop {
                let used = self.used.load(Ordering::Relaxed);
                if let Some(at) = self
                    .entries
                    .iter()
                    .take(used)
                    .position(|entry| entry.claim(thread))
                {
                    return Some(at);
                }
                let at = self
                    .used
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                        used.checked_add(1).filter(|&next| next <= N)
                    })
                    .ok()?;
                if self.entries.get(at)?.claim(thread) {
                    return Some(at);
                }
                // The entry is searched from the moment `used` passes it, so another thread
                // claimed it first: look again.
            }
        }

        pub(super) fn refused(&self) -> usize {
            self.refused.load(Ordering::Relaxed)
        }

        pub(super) fn here(&self, thread: usize) -> bool {
            self.held_by(thread).is_some()
        }

        /// The entry `thread` holds. Relaxed: a thread looks for its own word, which it wrote
        /// itself, below a `used` it reads no lower than when it claimed the entry.
        fn held_by(&self, thread: usize) -> Option<(usize, &Entry)> {
            // A table of one entry is read whether claimed or not: a free entry holds no thread's
            // word.
            let used = if N == 1 {
                1
            } else {
                self.used.load(Ordering::Relaxed)
            };
            self.entries
                .iter()
                .take(used)
                .enumerate()
                .find(|(_, entry)| entry.thread.load(Ordering::Relaxed) == thread)
        }

        /// Count one callback less in the entry at `at`, which [`Self::enter`] gave the calling
        /// thread; the entry is freed with its last.
        pub(super) fn leave(&self, at: usize) {
            let Some(entry) = self.entries.get(at) else {
                return;
            };
            match entry.depth.load(Ordering::Relaxed).checked_sub(1) {
                Some(rest) if rest > 0 => entry.depth.store(rest, Ordering::Relaxed),
                // Release: the thread that claims the entry next writes its depth after this one.
                _ => entry.thread.store(NO_THREAD, Ordering::Release),
            }
        }
    }

    /// One callback of the calling thread, from [`enter`] to drop: the entry that counts it.
    pub(super) struct Entered {
        at: usize,
    }

    // Out of line, as `here` and the drop are: every door that calls into C or waits for a
    // callback would otherwise hold its own copy of the search.
    #[inline(never)]
    pub(super) fn enter() -> Option<Entered> {
        // Built only once counted: an `Entered` dropped leaves the table.
        let at = IN_CALLBACK.enter(os::current_word())?;
        Some(Entered { at })
    }

    #[inline(never)]
    pub(super) fn here() -> bool {
        IN_CALLBACK.here(os::current_word())
    }

    pub(super) fn refused() -> usize {
        IN_CALLBACK.refused()
    }

    impl Drop for Entered {
        #[inline(never)]
        fn drop(&mut self) {
            IN_CALLBACK.leave(self.at);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Ordering, Threads};

        #[test]
        fn the_refused_count_stops_at_its_largest() {
            let threads = Threads::<0>::new();
            threads.refused.store(usize::MAX - 1, Ordering::Relaxed);
            assert!(threads.enter(1).is_none(), "a table of no room refuses");
            assert_eq!(threads.refused(), usize::MAX);
            assert!(threads.enter(1).is_none());
            assert_eq!(
                threads.refused(),
                usize::MAX,
                "the count stays at its largest rather than going back to 0"
            );
        }
    }
}

#[cfg(not(feature = "engine-tokio"))]
use callback_table as callback_depth;

#[cfg(test)]
mod tests {
    use super::callback_table;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn the_callback_table_counts_each_thread_on_its_own() {
        assert!(!callback_table::here());
        let outer = callback_table::enter().expect("the table has room for this thread");
        let inner = callback_table::enter().expect("a nested callback takes no more room");
        assert!(callback_table::here());
        let elsewhere = std::thread::spawn(callback_table::here)
            .join()
            .expect("the probe thread ends");
        assert!(!elsewhere, "another thread is in no callback");
        drop(inner);
        assert!(callback_table::here(), "the outer callback still runs");
        drop(outer);
        assert!(!callback_table::here());
        assert_eq!(callback_table::refused(), 0, "no callback was refused");
    }

    /// The door answers the count of the build's own marking of threads in callbacks: a build
    /// with std (the tokio engine's, which keeps the count in thread-local storage) marks every
    /// thread, so it refuses none, however many callbacks run at once.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn the_refused_callbacks_door_answers_none_in_a_build_with_std() {
        let entered: std::vec::Vec<_> = (0..4).map(|_| super::callback_depth::enter()).collect();
        assert!(
            entered.iter().all(Option::is_some),
            "every callback entered"
        );
        assert_eq!(super::zext_callbacks_refused(), 0);
        drop(entered);
        assert_eq!(super::zext_callbacks_refused(), 0);
    }

    #[test]
    fn a_full_callback_table_refuses_a_new_thread_and_takes_a_nested_callback() {
        let threads = callback_table::Threads::<2>::new();
        let one = threads
            .enter(1)
            .expect("the first thread takes the first entry");
        let two = threads
            .enter(2)
            .expect("the second thread takes the second");
        assert_eq!((one, two), (0, 1), "entries are claimed from the front");
        assert!(
            threads.enter(3).is_none(),
            "a third thread is refused while two run callbacks"
        );
        assert!(!threads.here(3), "the refused thread is not counted");
        assert_eq!(threads.refused(), 1, "the callback not run is counted");
        let nested = threads
            .enter(1)
            .expect("a nested callback takes no entry of its own");
        assert_eq!(
            nested, one,
            "a nested callback counts in its thread's entry"
        );
        threads.leave(nested);
        assert!(threads.here(1), "the outer callback still runs");
        threads.leave(one);
        assert!(!threads.here(1));
        assert!(threads.here(2), "the other thread keeps its entry");
        let three = threads
            .enter(3)
            .expect("the entry let go of takes the refused thread");
        assert_eq!(three, one, "the freed entry is claimed before any past it");
        assert!(threads.here(3));
        assert_eq!(threads.refused(), 1, "nothing more was refused");
    }

    /// A table of one entry, the single-threaded build's: the thread that claims it counts its
    /// nested callbacks there, another thread is refused and counted until it is let go of, and
    /// then claims it. Turned red by a one-entry claim that takes an entry another thread holds,
    /// or a lookup that finds a thread in an entry it does not hold.
    #[test]
    fn a_table_of_one_entry_takes_one_thread_at_a_time() {
        let threads = callback_table::Threads::<1>::new();
        assert!(!threads.here(1), "no thread is in the free entry");
        let one = threads
            .enter(1)
            .expect("the first thread takes the one entry");
        assert_eq!(one, 0);
        assert!(
            threads.enter(2).is_none(),
            "a second thread is refused while the first runs a callback"
        );
        assert!(!threads.here(2), "the refused thread is not counted");
        assert_eq!(threads.refused(), 1);
        let nested = threads
            .enter(1)
            .expect("a nested callback takes no entry of its own");
        assert_eq!(nested, one);
        threads.leave(nested);
        assert!(threads.here(1), "the outer callback still runs");
        threads.leave(one);
        assert!(!threads.here(1));
        assert_eq!(
            threads.enter(2),
            Some(0),
            "the entry let go of takes the next thread"
        );
        assert!(threads.here(2) && !threads.here(1));
        assert_eq!(threads.refused(), 1, "nothing more was refused");
    }

    /// Threads entering and leaving at once, more of them than the table has room for: each finds
    /// its own entry and no other's, a nested callback is never refused, and every callback either
    /// ran or is counted refused.
    #[test]
    fn threads_entering_at_once_each_keep_an_entry_of_their_own() {
        const THREADS: usize = 6;
        const ROUNDS: usize = 2_000;
        let table = callback_table::Threads::<4>::new();
        let ran = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for word in 1..=THREADS {
                let (table, ran) = (&table, &ran);
                scope.spawn(move || {
                    for _ in 0..ROUNDS {
                        let Some(outer) = table.enter(word) else {
                            assert!(!table.here(word), "a refused thread is not counted");
                            continue;
                        };
                        ran.fetch_add(1, Ordering::Relaxed);
                        assert!(table.here(word), "the thread finds its entry");
                        let inner = table
                            .enter(word)
                            .expect("a nested callback is never refused");
                        assert_eq!(inner, outer, "a nested callback counts in the same entry");
                        table.leave(inner);
                        assert!(table.here(word), "the outer callback still runs");
                        table.leave(outer);
                        assert!(!table.here(word), "the thread left its last callback");
                    }
                });
            }
        });
        assert_eq!(
            ran.load(Ordering::Relaxed) + table.refused(),
            THREADS * ROUNDS,
            "every callback ran or was counted refused"
        );
        assert!((1..=THREADS).all(|word| !table.here(word)));
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

    /// A count made where it stays (`OpenClosures::init_at`), as a kernel's lock must be, starts
    /// with nothing held, kept or retired, and counts as one made by value does: a closure counted
    /// holds it, its release lets it go with the owner still holding the place, and the owner's
    /// retire then gives the place back at once. Turned red by an `init_at` that leaves the count
    /// anything but empty.
    #[test]
    fn a_count_made_in_its_place_starts_empty_and_counts() {
        let mut place = core::mem::MaybeUninit::<OpenClosures>::uninit();
        // SAFETY: `place` is valid for one count, aligned and holding none, and it is not moved
        // until the count is dropped in it below.
        let open = unsafe {
            OpenClosures::init_at(NonNull::from(&mut place).cast());
            place.assume_init_ref()
        };
        assert_eq!(open.state.lock().held, 0, "nothing is held at first");
        assert_eq!(open.state.lock().kept, 0, "nothing is kept at first");
        open.count_one(false);
        assert_eq!(open.state.lock().held, 1);
        assert!(
            !open.uncount_one(false),
            "CONTROL: the owner still holds its place"
        );
        open.wait_none();
        assert!(open.retire(), "an empty count's owner gives its place back");
        // SAFETY: the count was made in `place` and nothing borrows it past here.
        unsafe { place.assume_init_drop() };
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
