// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A queue the deliveries drain, behind its lock, with whether it holds anything read without the
//! lock. Every delivery looks at each queue (the matching changes, the queries, the ends of the
//! gets) and almost always finds it empty: the word answers that with no lock taken, and the lock
//! is taken only for what is there.

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::os::{Mutex, MutexGuard};
use wz_capi_port::MatchId;
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps;

/// What a queue tells its word: whether it holds anything.
pub(super) trait Pending {
    fn is_pending(&self) -> bool;
}

/// A queue behind its lock, and its word ([`Self::is_pending`]).
pub(super) struct Queued<T: Pending> {
    queue: Mutex<T>,
    /// Whether the queue holds anything, as its last holder left it.
    pending: AtomicBool,
}

impl<T: Pending> Queued<T> {
    pub(super) fn new(queue: T) -> Self {
        let pending = queue.is_pending();
        Self {
            queue: Mutex::new(queue),
            pending: AtomicBool::new(pending),
        }
    }

    /// The queue, held until the guard drops, which leaves its word as the queue is then.
    pub(super) fn lock(&self) -> QueuedGuard<'_, T> {
        QueuedGuard {
            queue: self.queue.lock(),
            pending: &self.pending,
        }
    }

    /// Whether the queue holds anything, read without its lock: what its last holder left. A
    /// reader that finds it clear just before another thread queues something misses it as one
    /// that took the lock just before would have; what a thread queues is read by that thread's
    /// own delivery after it.
    pub(super) fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

/// A [`Queued`] held.
pub(super) struct QueuedGuard<'a, T: Pending> {
    queue: MutexGuard<'a, T>,
    pending: &'a AtomicBool,
}

impl<T: Pending> Deref for QueuedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.queue
    }
}

impl<T: Pending> DerefMut for QueuedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.queue
    }
}

impl<T: Pending> Drop for QueuedGuard<'_, T> {
    fn drop(&mut self) {
        // The lock is let go after this body, when the fields are dropped.
        self.pending
            .store(self.queue.is_pending(), Ordering::Release);
    }
}

impl<T> Pending for alloc::collections::VecDeque<T> {
    fn is_pending(&self) -> bool {
        !self.is_empty()
    }
}

/// The changes of the session's matching statuses its lock found, handed to their listeners after
/// it, in the order they were found. A listener holds one row at most: a change and the change
/// back before the first was handed leave the listener where it stood, so the second takes the
/// first's row away rather than a row of its own, and the table needs a row for each listener the
/// build admits and no more.
pub(crate) struct MatchFlips {
    flips: BoundedVec<(MatchId, bool), { caps::MAX_MATCHING_LISTENERS }, Static>,
}

impl MatchFlips {
    pub(crate) fn new() -> Self {
        Self {
            flips: BoundedVec::new_static(),
        }
    }

    /// The status of `listener` changed to `matching`. A change back takes the waiting row away;
    /// the same change again finds it already waiting and is that change, not a second one.
    pub(crate) fn flip(&mut self, listener: MatchId, matching: bool) {
        if let Some(at) = self.flips.iter().position(|(id, _)| *id == listener) {
            if self
                .flips
                .get(at)
                .is_some_and(|&(_, waiting)| waiting != matching)
            {
                self.flips.remove(at);
            }
            return;
        }
        let held = self.flips.push((listener, matching));
        debug_assert!(held.is_ok(), "a row for each listener the build admits");
    }

    /// The change found first, to hand to its listener.
    pub(crate) fn next(&mut self) -> Option<(MatchId, bool)> {
        if self.flips.is_empty() {
            None
        } else {
            Some(self.flips.remove(0))
        }
    }

    /// `listener` is gone: nothing it was owed is handed.
    pub(crate) fn forget(&mut self, listener: MatchId) {
        self.flips.retain(|(id, _)| *id != listener);
    }

    /// Whether no change is owed.
    pub(crate) fn is_empty(&self) -> bool {
        self.flips.is_empty()
    }
}

impl Pending for MatchFlips {
    fn is_pending(&self) -> bool {
        !self.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;

    /// The word follows the queue as each holder leaves it: set by what is queued, cleared once the
    /// last of it is taken, and read with no lock.
    #[test]
    fn the_word_says_what_the_last_holder_left() {
        let queue = Queued::new(VecDeque::<u8>::new());
        assert!(!queue.is_pending(), "a new queue holds nothing");
        queue.lock().push_back(1);
        queue.lock().push_back(2);
        assert!(queue.is_pending());
        assert_eq!(queue.lock().pop_front(), Some(1));
        assert!(queue.is_pending(), "one is left");
        assert_eq!(queue.lock().pop_front(), Some(2));
        assert!(!queue.is_pending(), "the last was taken");
        assert_eq!(queue.lock().pop_front(), None);
        assert!(!queue.is_pending());
    }

    /// The changes of matching statuses are handed in the order they were found; a change and the
    /// change back before the first was handed leave the listener where it stood and are handed as
    /// nothing.
    #[test]
    fn a_change_and_its_change_back_are_handed_as_nothing() {
        let mut flips = MatchFlips::new();
        flips.flip(1, true);
        flips.flip(2, true);
        flips.flip(1, false);
        assert_eq!(flips.next(), Some((2, true)));
        assert_eq!(flips.next(), None, "listener 1 stands where it stood");
        flips.flip(1, true);
        assert_eq!(flips.next(), Some((1, true)));
    }

    /// The same change found twice before it was handed is that one change, handed once: a second
    /// report of a status already owed neither cancels it nor queues it again.
    #[test]
    fn the_same_change_found_twice_is_handed_once() {
        let mut flips = MatchFlips::new();
        flips.flip(1, true);
        flips.flip(1, true);
        assert_eq!(flips.next(), Some((1, true)));
        assert_eq!(flips.next(), None);
    }

    /// A listener that is gone is handed nothing it was owed, and the others keep their order.
    #[test]
    fn a_listener_that_is_gone_is_handed_nothing() {
        let mut flips = MatchFlips::new();
        flips.flip(1, true);
        flips.flip(2, true);
        flips.flip(3, false);
        flips.forget(2);
        assert_eq!(flips.next(), Some((1, true)));
        assert_eq!(flips.next(), Some((3, false)));
        assert_eq!(flips.next(), None);
    }

    /// Every listener the build admits has a row: as many listeners as the build's value each owe a
    /// change, and each is handed.
    #[test]
    fn every_listener_the_build_admits_has_a_row() {
        let mut flips = MatchFlips::new();
        let listeners = caps::MAX_MATCHING_LISTENERS as u64;
        for id in 0..listeners {
            flips.flip(id, true);
        }
        for id in 0..listeners {
            assert_eq!(flips.next(), Some((id, true)));
        }
        assert_eq!(flips.next(), None);
    }
}
