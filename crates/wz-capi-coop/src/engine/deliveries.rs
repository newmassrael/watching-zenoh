// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The threads that hand out a session's deliveries now, and the callbacks each of them runs.
//!
//! A callback that steps its session again hands out nothing itself: the delivery it is inside of
//! goes on to hand out what the inner step queued, in order ([`Deliveries::enter`]). A put of the
//! session's own calls each subscriber it reaches at once, from inside that subscriber's own
//! callback too, as zenoh-pico does: a subscriber's callback is called through a shared borrow and
//! is not marked here. A get of the session's own hands its query to each queryable at once,
//! except to one that runs on the asking thread now, which would wait on itself: that one is
//! handed it once it returns ([`Deliveries::runs_here`]).
//!
//! Both are asked on every delivery and around every callback, so the case of one thread
//! delivering, which is a read task's or a program's that steps its session itself, is answered
//! with atomics: the first thread to deliver holds the owner's word ([`os::current_word`]) and
//! keeps the callbacks it runs where no other thread reads them. A thread that delivers while
//! another holds the word, or runs a callback outside a delivery of its own, is kept in a list
//! under a lock, as every thread was before; the count of that list says, without its lock,
//! whether there is anything in it to look for. A set held per engine and keyed by thread is what
//! a thread-local set keyed by engine would be, without a thread-local, which an MCU kernel does
//! not give a Rust image.

#[cfg(feature = "local-queryable")]
use core::cell::UnsafeCell;
use core::sync::atomic::Ordering;

use portable_atomic::AtomicUsize;
use wz_capi_port::os;
use wz_capi_port::sync::Lock;

#[cfg(feature = "local-queryable")]
use super::TargetKey;
#[allow(unused_imports)]
use crate::prelude::*;

/// What the owner's word holds while no thread holds it: no thread's word is 0.
const NO_THREAD: usize = 0;

/// The threads delivering for one engine and the callbacks each runs.
pub(super) struct Deliveries {
    /// The word of the thread that delivers with the owner's place, or [`NO_THREAD`].
    owner: AtomicUsize,
    /// The callbacks running on the owner's thread now, the innermost last. Read and written by
    /// that thread alone, from the exchange that gave it the word to the store that gives it
    /// back, which leaves it empty.
    #[cfg(feature = "local-queryable")]
    owner_running: UnsafeCell<Vec<TargetKey>>,
    /// How many threads `others` holds: each thread counts itself in after it is put in and out
    /// before it is taken out, so a thread in the list always reads its own count in it.
    beside: AtomicUsize,
    /// The threads delivering beside the owner, and those running a callback outside a delivery.
    others: Lock<Vec<Beside>>,
    /// How often `others` was taken, which the tests of the cost of one sample count.
    #[cfg(all(test, feature = "std"))]
    others_taken: core::sync::atomic::AtomicUsize,
}

// SAFETY: `owner_running` is reached only by the thread whose word `owner` holds, between the
// compare-exchange that gave it the word (acquire) and the store that gives it back (release), so
// no two threads reach it at once and each holder sees what the one before it left; every other
// field is an atomic or behind its lock.
#[cfg(feature = "local-queryable")]
unsafe impl Sync for Deliveries {}

/// A thread of [`Deliveries::others`].
struct Beside {
    word: usize,
    /// Whether it delivers now; one that only runs a callback does not.
    delivering: bool,
    /// The callbacks running on it now, the innermost last.
    #[cfg(feature = "local-queryable")]
    running: Vec<TargetKey>,
}

impl Beside {
    /// Whether nothing of the thread is kept: it delivers nothing and runs no callback.
    fn is_spent(&self) -> bool {
        #[cfg(feature = "local-queryable")]
        let idle = self.running.is_empty();
        #[cfg(not(feature = "local-queryable"))]
        let idle = true;
        !self.delivering && idle
    }
}

impl Deliveries {
    pub(super) fn new() -> Self {
        Self {
            owner: AtomicUsize::new(NO_THREAD),
            #[cfg(feature = "local-queryable")]
            owner_running: UnsafeCell::new(Vec::new()),
            beside: AtomicUsize::new(0),
            others: Lock::new(Vec::new()),
            #[cfg(all(test, feature = "std"))]
            others_taken: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A delivery on this thread, until the guard drops; `None` when this thread delivers for the
    /// engine already, which leaves what it would hand out to the delivery it is inside of.
    pub(super) fn enter(&self) -> Option<Delivering<'_>> {
        let word = os::current_word();
        if self.owner.load(Ordering::Acquire) == word {
            return None;
        }
        if self.beside.load(Ordering::Acquire) > 0
            && self.with_others(|others| others.iter().any(|t| t.word == word && t.delivering))
        {
            return None;
        }
        if self
            .owner
            .compare_exchange(NO_THREAD, word, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return Some(Delivering {
                set: self,
                word,
                owner: true,
            });
        }
        let added = self.with_others(|others| match others.iter_mut().find(|t| t.word == word) {
            Some(thread) => {
                thread.delivering = true;
                false
            }
            None => {
                others.push(Beside {
                    word,
                    delivering: true,
                    #[cfg(feature = "local-queryable")]
                    running: Vec::new(),
                });
                true
            }
        });
        if added {
            self.beside.fetch_add(1, Ordering::AcqRel);
        }
        Some(Delivering {
            set: self,
            word,
            owner: false,
        })
    }

    /// Whether this thread delivers for the engine now: a callback of the session may run below
    /// on its stack, so nothing here waits for a call to end.
    pub(super) fn delivers_here(&self) -> bool {
        let word = os::current_word();
        self.owner.load(Ordering::Acquire) == word
            || (self.beside.load(Ordering::Acquire) > 0
                && self.with_others(|others| others.iter().any(|t| t.word == word && t.delivering)))
    }

    /// The callback of `key` runs on this thread until the guard drops, or unwinds.
    #[cfg(feature = "local-queryable")]
    pub(super) fn run(&self, key: TargetKey) -> Running<'_> {
        let word = os::current_word();
        if self.owner.load(Ordering::Acquire) == word {
            // SAFETY: this thread holds the owner's word (`owner_running`).
            unsafe { (*self.owner_running.get()).push(key) };
            return Running {
                set: self,
                word,
                key,
                owner: true,
            };
        }
        let added = self.with_others(|others| match others.iter_mut().find(|t| t.word == word) {
            Some(thread) => {
                thread.running.push(key);
                false
            }
            None => {
                others.push(Beside {
                    word,
                    delivering: false,
                    running: vec![key],
                });
                true
            }
        });
        if added {
            self.beside.fetch_add(1, Ordering::AcqRel);
        }
        Running {
            set: self,
            word,
            key,
            owner: false,
        }
    }

    /// Whether the callback of `key` runs on this thread now: a call into it from here would wait
    /// on itself.
    #[cfg(feature = "local-queryable")]
    pub(super) fn runs_here(&self, key: TargetKey) -> bool {
        let word = os::current_word();
        // SAFETY: read only when this thread holds the owner's word (`owner_running`).
        if self.owner.load(Ordering::Acquire) == word
            && unsafe { (*self.owner_running.get()).contains(&key) }
        {
            return true;
        }
        self.beside.load(Ordering::Acquire) > 0
            && self.with_others(|others| {
                others
                    .iter()
                    .any(|t| t.word == word && t.running.contains(&key))
            })
    }

    /// The threads beside the owner, held for `f`.
    fn with_others<R>(&self, f: impl FnOnce(&mut Vec<Beside>) -> R) -> R {
        #[cfg(all(test, feature = "std"))]
        self.others_taken.fetch_add(1, Ordering::Relaxed);
        self.others.with(f)
    }

    /// Take `word`'s thread out of `others` when nothing of it is kept any more.
    fn let_go_of(&self, word: usize, change: impl FnOnce(&mut Beside)) {
        let removed = self.with_others(|others| {
            let Some(at) = others.iter().position(|t| t.word == word) else {
                return false;
            };
            change(&mut others[at]);
            if others[at].is_spent() {
                others.swap_remove(at);
                true
            } else {
                false
            }
        });
        if removed {
            self.beside.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// How often the list of the threads beside the owner was taken since the engine was made.
    #[cfg(all(test, feature = "std"))]
    pub(super) fn others_taken(&self) -> usize {
        self.others_taken.load(Ordering::Relaxed)
    }
}

/// One thread's delivery for one engine, from [`Deliveries::enter`] to drop.
pub(super) struct Delivering<'a> {
    set: &'a Deliveries,
    word: usize,
    owner: bool,
}

impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        if self.owner {
            // Every callback this thread ran inside the delivery has returned, its guard dropped
            // before this one; what is left is cleared so the next owner starts from nothing.
            #[cfg(feature = "local-queryable")]
            // SAFETY: this thread holds the owner's word until the store below.
            unsafe {
                (*self.set.owner_running.get()).clear()
            };
            self.set.owner.store(NO_THREAD, Ordering::Release);
        } else {
            self.set
                .let_go_of(self.word, |thread| thread.delivering = false);
        }
    }
}

/// A callback running on this thread, from [`Deliveries::run`] to its return, or its unwinding.
#[cfg(feature = "local-queryable")]
pub(super) struct Running<'a> {
    set: &'a Deliveries,
    word: usize,
    key: TargetKey,
    /// Whether it was noted with the owner's callbacks: the thread held the owner's word, and holds
    /// it still, the delivery that gave it the word being outside this callback.
    owner: bool,
}

#[cfg(feature = "local-queryable")]
impl Drop for Running<'_> {
    fn drop(&mut self) {
        let key = self.key;
        if self.owner {
            // SAFETY: this thread holds the owner's word (`Running::owner`).
            let running = unsafe { &mut *self.set.owner_running.get() };
            if let Some(at) = running.iter().rposition(|held| *held == key) {
                running.remove(at);
            }
        } else {
            self.set.let_go_of(self.word, |thread| {
                if let Some(at) = thread.running.iter().rposition(|held| *held == key) {
                    thread.running.remove(at);
                }
            });
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// A thread that delivers already enters no second delivery, which is how a callback that
    /// steps its session again leaves what it queued to the delivery it is inside of; the one
    /// thread delivering is answered with atomics alone, the list of the others never taken.
    #[test]
    fn a_thread_that_delivers_already_enters_no_second_delivery() {
        let set = Deliveries::new();
        let outer = set.enter();
        assert!(outer.is_some(), "the first delivery is entered");
        assert!(set.enter().is_none(), "the same thread enters no second");
        drop(outer);
        assert!(
            set.enter().is_some(),
            "once it ended, the thread delivers again"
        );
        assert_eq!(set.others_taken(), 0, "one thread asked no lock");
    }

    /// A thread that delivers while another holds the owner's place delivers beside it, kept in
    /// the list, and it too enters no second delivery; once it is done the list is empty again
    /// and the owner's thread asks no lock.
    #[test]
    fn a_second_thread_delivers_beside_the_first() {
        let set = Deliveries::new();
        let owner = set.enter().expect("the owner's delivery");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let beside = set.enter();
                    assert!(
                        beside.is_some(),
                        "a second thread delivers beside the first"
                    );
                    assert!(set.enter().is_none(), "and enters no second delivery");
                    drop(beside);
                })
                .join()
                .expect("the second thread");
        });
        assert!(
            set.others_taken() > 0,
            "CONTROL: the second thread was kept in the list"
        );
        assert_eq!(set.beside.load(Ordering::Acquire), 0, "and taken out of it");
        let taken = set.others_taken();
        drop(owner);
        let again = set.enter();
        assert!(again.is_some());
        assert_eq!(set.others_taken(), taken, "the owner alone asked no lock");
    }

    /// A callback runs here only on the thread that runs it: the owner's own, a thread delivering
    /// beside it, and a thread running a callback outside any delivery each see their own and no
    /// other's, and each is forgotten when its guard drops.
    #[cfg(feature = "local-queryable")]
    #[test]
    fn a_callback_runs_here_only_on_its_own_thread() {
        let set = Deliveries::new();
        let owner = set.enter().expect("the owner's delivery");
        let first = set.run(TargetKey::Queryable(1));
        assert!(set.runs_here(TargetKey::Queryable(1)));
        assert!(!set.runs_here(TargetKey::Queryable(2)));
        assert_eq!(set.others_taken(), 0, "the owner's callbacks ask no lock");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(
                        !set.runs_here(TargetKey::Queryable(1)),
                        "the owner's callback does not run on this thread"
                    );
                    let beside = set.enter().expect("a delivery beside the owner's");
                    let second = set.run(TargetKey::Queryable(2));
                    assert!(set.runs_here(TargetKey::Queryable(2)));
                    drop(second);
                    assert!(!set.runs_here(TargetKey::Queryable(2)));
                    drop(beside);
                })
                .join()
                .expect("the thread beside");
            scope
                .spawn(|| {
                    let outside = set.run(TargetKey::Queryable(3));
                    assert!(
                        set.runs_here(TargetKey::Queryable(3)),
                        "run outside a delivery"
                    );
                    drop(outside);
                    assert!(!set.runs_here(TargetKey::Queryable(3)));
                })
                .join()
                .expect("the thread outside a delivery");
        });
        assert_eq!(
            set.beside.load(Ordering::Acquire),
            0,
            "nothing is left in the list"
        );
        assert!(
            !set.runs_here(TargetKey::Queryable(2)),
            "another thread's callback"
        );
        drop(first);
        assert!(
            !set.runs_here(TargetKey::Queryable(1)),
            "the callback returned"
        );
        drop(owner);
    }
}
