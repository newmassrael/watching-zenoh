// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The threads that hand out a session's deliveries now, and the callbacks each of them runs.
//!
//! A callback that steps its session again hands out nothing itself: the delivery it is inside of
//! goes on to hand out what the inner step queued, in order ([`Deliveries::within`]). A put or a
//! get of the session's own calls each subscriber or queryable it reaches at once, from inside that
//! entity's own callback too, as zenoh-pico does: a callback is called through a shared borrow and
//! is not marked here.
//!
//! It is asked on every delivery, so the case of one thread delivering, which is a read task's or a
//! program's that steps its session itself, is answered with atomics: the first thread to deliver
//! holds the owner's word ([`os::current_word`]). A thread that delivers while another holds the
//! word is linked into a list under a lock, its link lying in its own frame for as long as it
//! delivers, so any number of threads deliver at once with nothing reserved for them and nothing
//! taken of the heap; the count of that list says, without its lock, whether there is anything in
//! it to look for. A set held per engine and keyed by thread is what a thread-local set keyed by
//! engine would be, without a thread-local, which an MCU kernel does not give a Rust image.
//!
//! A build of one thread (no `threads`) has one thread to know of: whether it delivers now is one
//! flag ([`OneThreadDeliveries`]), read and written with no read-modify-write and no lock.

#[cfg(feature = "threads")]
use core::cell::Cell;
use core::sync::atomic::Ordering;

#[cfg(feature = "threads")]
use portable_atomic::AtomicUsize;
#[cfg(feature = "threads")]
use wz_capi_port::os;
#[cfg(feature = "threads")]
use wz_capi_port::sync::Lock;
use wz_capi_port::EngineDeliveries;

#[allow(unused_imports)]
use crate::prelude::*;

/// What the owner's word holds while no thread holds it: no thread's word is 0.
#[cfg(feature = "threads")]
const NO_THREAD: usize = 0;

/// The delivery of a build whose every call runs on the thread that steps the session.
#[cfg(not(feature = "threads"))]
pub(super) type Deliveries = OneThreadDeliveries;

/// Whether the one thread of the engine delivers now: what [`Deliveries`] is in a build of one
/// thread. An atomic flag read and written in two steps, so the engine stays `Sync` as the type
/// of threads leaves it, with no read-modify-write and no lock.
#[cfg(any(not(feature = "threads"), all(test, feature = "std")))]
pub(super) struct OneThreadDeliveries {
    delivering: core::sync::atomic::AtomicBool,
}

#[cfg(any(not(feature = "threads"), all(test, feature = "std")))]
impl OneThreadDeliveries {
    pub(super) fn new() -> Self {
        Self {
            delivering: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Run `f` as a delivery, told whether it is one: `false` inside the delivery already made,
    /// which a callback that steps its session again is.
    pub(super) fn within<R>(&self, f: impl FnOnce(bool) -> R) -> R {
        if self.delivering.load(Ordering::Relaxed) {
            return f(false);
        }
        self.delivering.store(true, Ordering::Relaxed);
        let _delivering = Delivering(self);
        f(true)
    }

    /// No list of other threads is kept, so none is ever taken.
    #[cfg(all(test, feature = "std", not(feature = "threads")))]
    pub(super) fn others_taken(&self) -> usize {
        0
    }
}

/// Whether the one thread delivers now: a callback of the session may run below on its stack.
#[cfg(any(not(feature = "threads"), all(test, feature = "std")))]
impl EngineDeliveries for OneThreadDeliveries {
    fn delivers_here(&self) -> bool {
        self.delivering.load(Ordering::Relaxed)
    }
}

/// The delivery of the one thread, ended as it drops, so a callback that unwinds ends it too.
#[cfg(any(not(feature = "threads"), all(test, feature = "std")))]
struct Delivering<'a>(&'a OneThreadDeliveries);

#[cfg(any(not(feature = "threads"), all(test, feature = "std")))]
impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        self.0.delivering.store(false, Ordering::Relaxed);
    }
}

/// The threads delivering for one engine.
#[cfg(feature = "threads")]
pub(super) struct Deliveries {
    /// The word of the thread that delivers with the owner's place, or [`NO_THREAD`].
    owner: AtomicUsize,
    /// How many threads `others` holds: each thread counts itself in after it is linked and out
    /// before it is taken out, so a thread in the list always reads its own count in it.
    beside: AtomicUsize,
    /// The threads delivering beside the owner.
    others: Lock<Others>,
    /// How often `others` was taken, which the tests of the cost of one sample count.
    #[cfg(all(test, feature = "std"))]
    others_taken: core::sync::atomic::AtomicUsize,
}

/// A thread delivering beside the owner: its link in [`Deliveries::others`], which lies in the
/// thread's frame of [`Deliveries::within`] and is taken out of the list before that frame ends.
#[cfg(feature = "threads")]
struct Beside {
    word: usize,
    /// The next thread of the list, null for none; written only under the list's lock.
    next: Cell<*const Beside>,
}

/// The first thread of the list of those delivering beside the owner, null for none.
#[cfg(feature = "threads")]
struct Others(*const Beside);

// SAFETY: the links are reached only under the lock that holds this head, and each stands in its
// thread's frame for as long as it is linked (`Beside`), so whichever thread holds the lock reads
// and writes links that stand, one thread at a time.
#[cfg(feature = "threads")]
unsafe impl Send for Others {}

#[cfg(feature = "threads")]
impl Deliveries {
    pub(super) fn new() -> Self {
        Self {
            owner: AtomicUsize::new(NO_THREAD),
            beside: AtomicUsize::new(0),
            others: Lock::new(Others(core::ptr::null())),
            #[cfg(all(test, feature = "std"))]
            others_taken: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Run `f` as a delivery of this thread's, told whether it is one: `false` when this thread
    /// delivers for the engine already, which leaves what it would hand out to the delivery it is
    /// inside of. A thread that delivers beside the owner is linked into the list for as long as
    /// `f` runs, by a link in this frame.
    pub(super) fn within<R>(&self, f: impl FnOnce(bool) -> R) -> R {
        let word = os::current_word();
        if self.delivers(word) {
            return f(false);
        }
        if self
            .owner
            .compare_exchange(NO_THREAD, word, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let _owner = Owning(self);
            return f(true);
        }
        let link = Beside {
            word,
            next: Cell::new(core::ptr::null()),
        };
        let _linked = Linked::link(self, &link);
        f(true)
    }

    /// Whether the thread of `word` delivers for the engine now.
    fn delivers(&self, word: usize) -> bool {
        self.owner.load(Ordering::Acquire) == word
            || (self.beside.load(Ordering::Acquire) > 0
                && self.with_others(|others| {
                    let mut at = others.0;
                    while !at.is_null() {
                        // SAFETY: a link in the list stands until its own thread takes it out,
                        // under this lock (`Others`).
                        let link = unsafe { &*at };
                        if link.word == word {
                            return true;
                        }
                        at = link.next.get();
                    }
                    false
                }))
    }

    /// The threads beside the owner, held for `f`.
    fn with_others<R>(&self, f: impl FnOnce(&mut Others) -> R) -> R {
        #[cfg(all(test, feature = "std"))]
        self.others_taken.fetch_add(1, Ordering::Relaxed);
        self.others.with(f)
    }

    /// How often the list of the threads beside the owner was taken since the engine was made.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn others_taken(&self) -> usize {
        self.others_taken.load(Ordering::Relaxed)
    }
}

/// Whether this thread delivers for the engine now: a callback of the session may run below on its
/// stack, so nothing here waits for a call to end.
#[cfg(feature = "threads")]
impl EngineDeliveries for Deliveries {
    fn delivers_here(&self) -> bool {
        self.delivers(os::current_word())
    }
}

/// The owner's place held by this thread, let go of as it drops.
#[cfg(feature = "threads")]
struct Owning<'a>(&'a Deliveries);

#[cfg(feature = "threads")]
impl Drop for Owning<'_> {
    fn drop(&mut self) {
        self.0.owner.store(NO_THREAD, Ordering::Release);
    }
}

/// A thread's link in the list of those beside the owner, taken out as it drops, before the
/// frame the link lies in ends.
#[cfg(feature = "threads")]
struct Linked<'a> {
    set: &'a Deliveries,
    link: &'a Beside,
}

#[cfg(feature = "threads")]
impl<'a> Linked<'a> {
    /// Put `link` first in `set`'s list, and count it in.
    fn link(set: &'a Deliveries, link: &'a Beside) -> Self {
        set.with_others(|others| {
            link.next.set(others.0);
            others.0 = core::ptr::from_ref(link);
        });
        set.beside.fetch_add(1, Ordering::AcqRel);
        Self { set, link }
    }
}

#[cfg(feature = "threads")]
impl Drop for Linked<'_> {
    fn drop(&mut self) {
        self.set.beside.fetch_sub(1, Ordering::AcqRel);
        let gone = core::ptr::from_ref(self.link);
        self.set.with_others(|others| {
            // Read under the lock: a thread taken out after this one in the list rewrites this
            // link's `next` under it, so a `next` read before would relink a link already gone.
            let after = self.link.next.get();
            if others.0 == gone {
                others.0 = after;
                return;
            }
            let mut at = others.0;
            while !at.is_null() {
                // SAFETY: a link in the list stands until its own thread takes it out, under this
                // lock (`Others`).
                let link = unsafe { &*at };
                if link.next.get() == gone {
                    link.next.set(after);
                    return;
                }
                at = link.next.get();
            }
        });
    }
}

/// The scenario both forms of the deliveries answer alike.
#[cfg(all(test, feature = "std"))]
mod both_forms {
    use super::*;

    /// What a test asks of either form.
    trait Delivers {
        fn enter(&self, f: &mut dyn FnMut(bool));
        fn here(&self) -> bool;
    }

    impl Delivers for OneThreadDeliveries {
        fn enter(&self, f: &mut dyn FnMut(bool)) {
            self.within(f);
        }

        fn here(&self) -> bool {
            self.delivers_here()
        }
    }

    #[cfg(feature = "threads")]
    impl Delivers for Deliveries {
        fn enter(&self, f: &mut dyn FnMut(bool)) {
            self.within(f);
        }

        fn here(&self) -> bool {
            self.delivers_here()
        }
    }

    /// A delivery is entered once on the thread: one made inside it (a callback that steps its
    /// session again) is told it is none, the thread is known to deliver only while it does, and
    /// one ended by a callback that unwinds is ended all the same.
    fn one_delivery_at_a_time_on_the_thread(set: &dyn Delivers) {
        assert!(!set.here(), "no delivery before the first");
        set.enter(&mut |outer| {
            assert!(outer, "the first delivery is entered");
            assert!(set.here(), "and the thread is known to deliver");
            set.enter(&mut |inner| assert!(!inner, "the same thread enters no second"));
            assert!(
                set.here(),
                "the inner call left the outer delivery standing"
            );
        });
        assert!(!set.here(), "ended with its frame");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            set.enter(&mut |_| panic!("a callback that unwinds"));
        }));
        assert!(unwound.is_err(), "CONTROL: the callback unwound");
        assert!(!set.here(), "an unwound delivery is ended too");
        set.enter(&mut |again| assert!(again, "once it ended, the thread delivers again"));
    }

    #[test]
    fn the_one_thread_form_enters_one_delivery_at_a_time() {
        one_delivery_at_a_time_on_the_thread(&OneThreadDeliveries::new());
    }

    #[cfg(feature = "threads")]
    #[test]
    fn the_threads_form_enters_one_delivery_at_a_time() {
        one_delivery_at_a_time_on_the_thread(&Deliveries::new());
    }
}

#[cfg(all(test, feature = "std", feature = "threads"))]
mod tests {
    use super::*;
    use std::sync::Barrier;

    /// A thread that delivers already enters no second delivery, which is how a callback that
    /// steps its session again leaves what it queued to the delivery it is inside of; the one
    /// thread delivering is answered with atomics alone, the list of the others never taken.
    #[test]
    fn a_thread_that_delivers_already_enters_no_second_delivery() {
        let set = Deliveries::new();
        set.within(|outer| {
            assert!(outer, "the first delivery is entered");
            set.within(|inner| assert!(!inner, "the same thread enters no second"));
        });
        set.within(|again| assert!(again, "once it ended, the thread delivers again"));
        assert_eq!(set.others_taken(), 0, "one thread asked no lock");
    }

    /// A thread that delivers while another holds the owner's place delivers beside it, kept in
    /// the list, and it too enters no second delivery; once it is done the list is empty again
    /// and the owner's thread asks no lock.
    #[test]
    fn a_second_thread_delivers_beside_the_first() {
        let set = Deliveries::new();
        let taken = set.within(|owner| {
            assert!(owner, "the owner's delivery");
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        set.within(|beside| {
                            assert!(beside, "a second thread delivers beside the first");
                            assert!(set.delivers_here(), "and is known to deliver");
                            set.within(|inner| assert!(!inner, "and enters no second delivery"));
                        });
                        assert!(!set.delivers_here(), "and is let go of once it is done");
                    })
                    .join()
                    .expect("the second thread");
            });
            assert!(
                set.others_taken() > 0,
                "CONTROL: the second thread was kept in the list"
            );
            assert_eq!(set.beside.load(Ordering::Acquire), 0, "and taken out of it");
            set.others_taken()
        });
        set.within(|again| assert!(again));
        assert_eq!(set.others_taken(), taken, "the owner alone asked no lock");
    }

    /// A thread that delivers beside the owner takes nothing of the heap to be kept in the list:
    /// its link lies in its own frame.
    #[test]
    fn a_thread_delivering_beside_the_owner_allocates_nothing() {
        use crate::tests::redial_heap::counted;
        let set = Deliveries::new();
        let allocated = set.within(|owner| {
            assert!(owner, "the owner's delivery");
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut entered = false;
                        let allocated = counted(|| {
                            entered = set.within(|beside| beside);
                        });
                        assert!(entered, "CONTROL: the thread delivered beside the owner");
                        allocated
                    })
                    .join()
                    .expect("the second thread")
            })
        });
        assert_eq!(allocated, 0, "a thread beside the owner took the heap");
    }

    /// Threads beside the owner come and go in any order: each that stands is known to deliver,
    /// one taken out of the middle of the list leaves the others linked, and once every one is
    /// gone the list is empty.
    #[test]
    fn threads_beside_the_owner_leave_in_any_order() {
        const THREADS: usize = 3;
        let set = Deliveries::new();
        // Each thread links in its turn, so the list is the threads in the reverse of their turns
        // and the thread of the middle turn lies in the middle of it.
        let turn = AtomicUsize::new(0);
        let linked = Barrier::new(THREADS + 1);
        let middle_gone = Barrier::new(THREADS + 1);
        set.within(|owner| {
            assert!(owner, "the owner's delivery");
            std::thread::scope(|scope| {
                for at in 0..THREADS {
                    let (set, turn, linked, middle_gone) = (&set, &turn, &linked, &middle_gone);
                    scope.spawn(move || {
                        while turn.load(Ordering::Acquire) != at {
                            std::thread::yield_now();
                        }
                        if at == THREADS / 2 {
                            set.within(|beside| {
                                assert!(beside);
                                turn.store(at + 1, Ordering::Release);
                                linked.wait();
                            });
                            assert!(!set.delivers_here(), "a thread gone is not known");
                            middle_gone.wait();
                        } else {
                            set.within(|beside| {
                                assert!(beside);
                                turn.store(at + 1, Ordering::Release);
                                linked.wait();
                                middle_gone.wait();
                                assert!(set.delivers_here(), "a thread that stands is known");
                            });
                        }
                    });
                }
                linked.wait();
                middle_gone.wait();
            });
            assert_eq!(
                set.beside.load(Ordering::Acquire),
                0,
                "every thread was counted out"
            );
            assert!(
                set.with_others(|others| others.0.is_null()),
                "and taken out of the list"
            );
        });
    }
}
