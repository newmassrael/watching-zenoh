// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A queue the deliveries drain, behind its lock, with whether it holds anything read without the
//! lock. Every delivery looks at each queue (the matching changes, the queries, the ends of the
//! gets) and almost always finds it empty: the word answers that with no lock taken, and the lock
//! is taken only for what is there.

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::os::{Mutex, MutexGuard};

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

impl Pending for crate::lane::MatchFlips {
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
}
