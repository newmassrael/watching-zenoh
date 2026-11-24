// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The changes of the session's matching statuses, queued for the deliveries behind the session
//! core's queue ([`Queued`]): whether it holds anything is read without its lock, so a delivery
//! that finds nothing, which almost every one does, takes no lock for it.

use wz_capi_port::MatchId;
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps;
use wz_session_core::plane_lock::{Pending, Queued};

use super::CoopLocks;

/// The matching changes behind their lock ([`MatchFlips`]).
pub(super) type MatchQueue = Queued<CoopLocks, MatchFlips>;

/// The changes of the session's matching statuses its lock found, handed to their listeners after
/// it, in the order they were found. A listener holds one row at most: a change and the change
/// back before the first was handed leave the listener where it stood, so the second takes the
/// first's row away rather than a row of its own, and the table needs a row for each listener the
/// build admits and no more.
///
/// One thread hands them out at a time ([`Self::begin`]): a listener's callback is taken out of its
/// row for its call, and only the thread that took it puts it back, so two calls of one callback
/// never overlap and a change is never handed to a row whose callback is out.
pub(crate) struct MatchFlips {
    flips: BoundedVec<(MatchId, bool), { caps::MAX_MATCHING_LISTENERS }, Static>,
    /// Whether a thread is handing the changes out.
    handing: bool,
}

impl MatchFlips {
    pub(crate) fn new() -> Self {
        Self {
            flips: BoundedVec::new_static(),
            handing: false,
        }
    }

    /// Whether this caller hands the changes out: `false` when another thread is, which hands
    /// out what this one queued too ([`Self::next_or_end`]).
    pub(crate) fn begin(&mut self) -> bool {
        !core::mem::replace(&mut self.handing, true)
    }

    /// The change found first, for the thread that began ([`Self::begin`]); when none is owed,
    /// that thread's turn ends here, under the same lock a change is queued under, so no change
    /// queued meanwhile is left with no thread to hand it.
    pub(crate) fn next_or_end(&mut self) -> Option<(MatchId, bool)> {
        let next = self.next();
        if next.is_none() {
            self.handing = false;
        }
        next
    }

    /// The turn that began is over before its changes are all handed (its thread unwound).
    fn end(&mut self) {
        self.handing = false;
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

/// This thread's turn to hand the matching changes in `queue` out, or `None` when none is owed or
/// another thread's turn is running, which hands out what this one queued too.
pub(super) fn begin_handing(queue: &MatchQueue) -> Option<HandingTurn<'_>> {
    (queue.is_pending() && queue.with(MatchFlips::begin))
        .then_some(HandingTurn { queue, over: false })
}

/// One thread's turn of handing the matching changes out ([`begin_handing`]): it ends
/// when no change is left, or, should the thread unwind out of a callback, when it is dropped, so
/// the next thread that queues a change hands it.
pub(super) struct HandingTurn<'a> {
    queue: &'a MatchQueue,
    /// Whether the turn ended with no change left ([`MatchFlips::next_or_end`]).
    over: bool,
}

impl HandingTurn<'_> {
    /// The change to hand next, taken under the queue's lock alone and released before the
    /// caller hands it; `None` ends the turn.
    pub(super) fn next(&mut self) -> Option<(MatchId, bool)> {
        let next = self.queue.with(MatchFlips::next_or_end);
        self.over = next.is_none();
        next
    }
}

impl Drop for HandingTurn<'_> {
    fn drop(&mut self) {
        // A turn that ended itself is another thread's to begin again, and is not ended twice.
        if !self.over {
            self.queue.with(MatchFlips::end);
        }
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
