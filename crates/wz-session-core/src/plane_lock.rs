// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock a plane of the session keeps its state under. A plane is reached from under the
//! session's lock and from the deliveries that run with no lock held, so it holds its state under a
//! lock of its own; which lock that is (an OS mutex on a host, a critical section on a target) is
//! the engine's port's, which this crate does not name, so the engine names it as a
//! [`LockFamily`]. A queue the deliveries look at on every pass sits behind such a lock with a
//! word of its own that says, without the lock, whether it holds anything ([`Queued`]).
//!
//! [`LockFamily`]: crate::plane_lock::LockFamily
//! [`Queued`]: crate::plane_lock::Queued

use core::sync::atomic::{AtomicBool, Ordering};

/// The locks an engine keeps a plane's state under.
pub trait LockFamily {
    /// A lock over a value of `T`.
    type Lock<T>;

    /// `value`, under a lock.
    fn new<T>(value: T) -> Self::Lock<T>;

    /// `f` on the value under `lock`, which is held for the length of the call.
    fn with<T, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R;
}

/// What a queue tells its word: whether it holds anything.
pub trait Pending {
    /// Whether the queue holds anything.
    fn is_pending(&self) -> bool;
}

/// A queue the deliveries drain, behind a lock of the family `L`, with whether it holds anything
/// read without the lock ([`Self::is_pending`]). Every delivery looks at each queue and almost
/// always finds it empty: the word answers that with no lock taken, and the lock is taken only for
/// what is there.
pub struct Queued<L: LockFamily, T> {
    queue: L::Lock<T>,
    /// Whether the queue holds anything, as its last holder left it.
    pending: AtomicBool,
}

impl<L: LockFamily, T: Pending> Queued<L, T> {
    /// `queue`, behind its lock.
    pub fn new(queue: T) -> Self {
        let pending = queue.is_pending();
        Self {
            queue: L::new(queue),
            pending: AtomicBool::new(pending),
        }
    }

    /// `f` on the queue, with its lock held; the word is left as the queue is when `f` returns,
    /// before the lock is let go.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        L::with(&self.queue, |queue| {
            let out = f(queue);
            self.pending.store(queue.is_pending(), Ordering::Release);
            out
        })
    }

    /// Whether the queue holds anything, read without its lock: what its last holder left. A
    /// reader that finds it clear just before another thread queues something misses it as one
    /// that took the lock just before would have; what a thread queues is read by that thread's
    /// own delivery after it.
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

#[cfg(feature = "alloc")]
impl<T> Pending for alloc::collections::VecDeque<T> {
    fn is_pending(&self) -> bool {
        !self.is_empty()
    }
}

/// The host's mutex as a family of locks, for the tests of the planes that keep their state under
/// one.
#[cfg(all(test, feature = "alloc"))]
pub(crate) enum StdLocks {}

#[cfg(all(test, feature = "alloc"))]
impl LockFamily for StdLocks {
    type Lock<T> = std::sync::Mutex<T>;

    fn new<T>(value: T) -> std::sync::Mutex<T> {
        std::sync::Mutex::new(value)
    }

    fn with<T, R>(lock: &std::sync::Mutex<T>, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut lock.lock().unwrap())
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;

    /// The word follows the queue as each holder leaves it: set by what is queued, cleared once the
    /// last of it is taken, and read with no lock.
    #[test]
    fn the_word_says_what_the_last_holder_left() {
        let queue = Queued::<StdLocks, _>::new(VecDeque::<u8>::new());
        assert!(!queue.is_pending(), "a new queue holds nothing");
        queue.with(|queue| queue.push_back(1));
        queue.with(|queue| queue.push_back(2));
        assert!(queue.is_pending());
        assert_eq!(queue.with(VecDeque::pop_front), Some(1));
        assert!(queue.is_pending(), "one is left");
        assert_eq!(queue.with(VecDeque::pop_front), Some(2));
        assert!(!queue.is_pending(), "the last was taken");
        assert_eq!(queue.with(VecDeque::pop_front), None);
        assert!(!queue.is_pending());
    }

    /// A queue made with something in it says so before any holder took its lock.
    #[test]
    fn a_queue_made_full_says_so_at_once() {
        let queue = Queued::<StdLocks, _>::new(VecDeque::from([7u8]));
        assert!(queue.is_pending());
    }
}
