// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The threads that hand out a session's deliveries now, and the callbacks each of them runs.
//!
//! A callback that steps its session again hands out nothing itself: the delivery it is inside of
//! goes on to hand out what the inner step queued, in order ([`Deliveries::enter`]). A put or a
//! get of the session's own calls each subscriber or queryable it reaches at once, from inside that
//! entity's own callback too, as zenoh-pico does: a callback is called through a shared borrow and
//! is not marked here.
//!
//! It is asked on every delivery, so the case of one thread delivering, which is a read task's or a
//! program's that steps its session itself, is answered with atomics: the first thread to deliver
//! holds the owner's word ([`os::current_word`]). A thread that delivers while another holds the
//! word is kept in a list under a lock, as every thread was before; the count of that list says,
//! without its lock, whether there is anything in it to look for. A set held per engine and keyed by thread is what
//! a thread-local set keyed by engine would be, without a thread-local, which an MCU kernel does
//! not give a Rust image.

use core::sync::atomic::Ordering;

use portable_atomic::AtomicUsize;
use wz_capi_port::os;
use wz_capi_port::sync::Lock;

#[allow(unused_imports)]
use crate::prelude::*;

/// What the owner's word holds while no thread holds it: no thread's word is 0.
const NO_THREAD: usize = 0;

/// The threads delivering for one engine.
pub(super) struct Deliveries {
    /// The word of the thread that delivers with the owner's place, or [`NO_THREAD`].
    owner: AtomicUsize,
    /// How many threads `others` holds: each thread counts itself in after it is put in and out
    /// before it is taken out, so a thread in the list always reads its own count in it.
    beside: AtomicUsize,
    /// The threads delivering beside the owner.
    others: Lock<Vec<Beside>>,
    /// How often `others` was taken, which the tests of the cost of one sample count.
    #[cfg(all(test, feature = "std"))]
    others_taken: core::sync::atomic::AtomicUsize,
}

/// A thread of [`Deliveries::others`].
struct Beside {
    word: usize,
    /// Whether it delivers now.
    delivering: bool,
}

impl Beside {
    /// Whether nothing of the thread is kept: it delivers nothing.
    fn is_spent(&self) -> bool {
        !self.delivering
    }
}

impl Deliveries {
    pub(super) fn new() -> Self {
        Self {
            owner: AtomicUsize::new(NO_THREAD),
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

    /// The threads beside the owner, held for `f`.
    fn with_others<R>(&self, f: impl FnOnce(&mut Vec<Beside>) -> R) -> R {
        #[cfg(all(test, feature = "std"))]
        self.others_taken.fetch_add(1, Ordering::Relaxed);
        self.others.with(f)
    }

    /// Take `word`'s thread out of `others` when nothing of it is kept any more.
    fn let_go_of(&self, word: usize, change: impl FnOnce(&mut Beside)) {
        let removed = self.with_others(|others| {
            let Some((at, thread)) = others.iter_mut().enumerate().find(|(_, t)| t.word == word)
            else {
                return false;
            };
            change(thread);
            let spent = thread.is_spent();
            if spent {
                others.swap_remove(at);
            }
            spent
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
            self.set.owner.store(NO_THREAD, Ordering::Release);
        } else {
            self.set
                .let_go_of(self.word, |thread| thread.delivering = false);
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
}
