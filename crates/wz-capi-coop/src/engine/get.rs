// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query on the cooperative engine.
//!
//! A get is asked of the one peer the session's link reaches, so it has one leg and owes one
//! Final; the session asks no queryable of its own, as zenoh-pico's default build asks none
//! (`Z_FEATURE_LOCAL_QUERYABLE` 0). Its pending entry is session-core's, registered with the
//! observer under the request id the link's actions allocate, with the deadline, the accepted
//! reply keys and the consolidation `QueryOptions` reads, as the tokio engine registers its own.
//!
//! What the observer hands the entry's sink happens under the session's lock, and a C callback
//! never runs there (decision D8), so the sink only queues: each reply in the session's delivery
//! lane, one event of the lane for it and its bytes where the lane lies, and the leg's END when the
//! entry is dropped (its Final, its deadline, its cancellation, the loss of its link), said by a
//! guard the sink owns. The deliveries hand both out with no lock held, the end once the lane has
//! handed every reply queued before it, as the drop of the leg's callback, which is how a C
//! program learns its get is over.
//!
//! The ends wait in a table the session's arena lent ([`EndedLegs`]), a row for each get the
//! session's tables of pending gets can hold. A leg ends when its row in those tables goes, and the
//! deliveries that follow every step take every end out, so the ends waiting never outnumber the
//! rows; a leg the session ends itself (cancelled, or never sent) drops its callback where it ends
//! it and leaves no end waiting.

use alloc::sync::Arc;

use wz_session_core::bounded::{BoundedVec, Lent};

use wz_session_core::reply_sink::{BoxedReplySink, ReplyView};

use crate::lane::SharedLane;

use super::queued::{Pending, Queued};
use super::registry::{FaceId, Registry};

/// The legs whose entries went and whose callbacks are still to be dropped, a row for each get the
/// session's tables of pending gets hold (see the module).
pub(super) struct EndedLegs {
    legs: BoundedVec<u64, { usize::MAX }, Lent>,
}

impl EndedLegs {
    /// A table over the rows `legs` an arena lent.
    pub(super) fn over(legs: BoundedVec<u64, { usize::MAX }, Lent>) -> Self {
        Self { legs }
    }

    /// Leg `leg` ended: its callback is to be dropped.
    fn note(&mut self, leg: u64) {
        let kept = self.legs.push(leg);
        debug_assert!(
            kept.is_ok(),
            "the ends waiting outnumber the rows of the tables of pending gets"
        );
    }

    /// A leg whose callback is still to be dropped, if any.
    pub(super) fn take(&mut self) -> Option<u64> {
        self.legs.pop()
    }

    /// Leg `leg`'s callback was dropped where its end was decided: nothing is left to do for it.
    pub(super) fn forget(&mut self, leg: u64) {
        self.legs.retain(|ended| *ended != leg);
    }

    /// Drop every end still waiting: the session is closed, and its legs' callbacks with it.
    pub(super) fn clear(&mut self) {
        self.legs.clear();
    }
}

impl Pending for EndedLegs {
    fn is_pending(&self) -> bool {
        !self.legs.is_empty()
    }
}

/// What the get plane shares between the session's state, the observer's reply sinks and the
/// deliveries.
pub(super) struct GetPlane {
    /// The legs that ended, handed out after the replies queued before them.
    pub(super) ended: Queued<EndedLegs>,
}

impl GetPlane {
    /// A plane with nothing ended, its ends waiting in `ended`.
    pub(super) fn new(ended: EndedLegs) -> Self {
        Self {
            ended: Queued::new(ended),
        }
    }
}

/// Which of the observer's registries a pending leg's entry is in, and the id it is registered
/// under there: each kind's id is its own type, so one cannot be looked up as the other.
#[derive(Clone, Copy)]
pub(super) enum GetKind {
    /// A query: its entry is under its request id, and its peer owes a Final.
    Query(wz_session_core::wire_id::RequestId),
    /// A liveliness snapshot: its entry is under its Interest id, and its peer owes a DeclFinal.
    #[cfg(feature = "liveliness-get")]
    Liveliness(u64),
}

/// A leg the session has pending: the face it was asked of, the id its callback is held under,
/// and its entry ([`GetKind`]).
pub(super) struct PendingGet {
    pub(super) face: FaceId,
    pub(super) leg: u64,
    pub(super) kind: GetKind,
}

impl PendingGet {
    /// Drop this leg's entry from its face's pending gets, which ends the leg (its sink's guard
    /// says so). A face the session no longer holds took its entries with it.
    pub(super) fn unregister(&self, registry: &mut Registry) {
        let Some(gets) = registry.gets_mut(self.face) else {
            return;
        };
        match self.kind {
            GetKind::Query(rid) => {
                gets.replies.unregister(rid);
            }
            #[cfg(feature = "liveliness-get")]
            GetKind::Liveliness(interest_id) => {
                gets.liveliness_gets.unregister(interest_id);
            }
        }
    }
}

/// The end of a leg, said once: when the pending entry that owns it is dropped.
struct LegEnd {
    leg: u64,
    plane: Arc<GetPlane>,
}

impl Drop for LegEnd {
    fn drop(&mut self) {
        self.plane.ended.lock().note(self.leg);
    }
}

/// The sink of leg `leg`'s pending entry: each reply is queued in the session's delivery
/// `lane`, and the entry's drop queues the leg's end. The Final itself says nothing more: the
/// registry drops the entry once its Finals are in, which is the end.
pub(super) fn reply_sink(
    leg: u64,
    plane: &Arc<GetPlane>,
    lane: &Arc<SharedLane>,
) -> BoxedReplySink {
    let lane = Arc::clone(lane);
    let end = LegEnd {
        leg,
        plane: Arc::clone(plane),
    };
    BoxedReplySink::new(
        move |view: &dyn ReplyView| {
            lane.lock().offer_reply(leg, view);
        },
        move |_rid| {
            // Owned by this closure so it is dropped with the sink.
            let _ = &end;
        },
    )
}

#[cfg(test)]
mod tests {
    //! The ends of the legs wait in rows an arena lent, each handed out once.
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};

    /// A table of ends and the arena it was lent from, the table first so it goes before the memory
    /// it lies in.
    struct Held {
        ends: EndedLegs,
        _arena: SessionArena,
    }

    /// A table of `rows` ends over an arena of its own.
    fn ended(rows: usize) -> Held {
        let mut arena =
            SessionArena::of_bytes(1 << 12, &AllocatorMemory).expect("the host has the memory");
        let legs = arena.lend(rows).expect("the arena has the rows");
        Held {
            ends: EndedLegs::over(legs),
            _arena: arena,
        }
    }

    /// Each end noted is taken once, an end its leg's maker handled itself is not taken, and a
    /// closed session's ends are all let go.
    #[test]
    fn each_end_is_taken_once_and_a_forgotten_one_never() {
        let mut held = ended(3);
        let ends = &mut held.ends;
        ends.note(1);
        ends.note(2);
        ends.note(3);
        ends.forget(2);
        let mut taken = [ends.take(), ends.take(), ends.take()];
        taken.sort();
        assert_eq!(taken, [None, Some(1), Some(3)]);
        ends.note(4);
        ends.clear();
        assert_eq!(ends.take(), None, "a closed session hands out no end");
    }

    /// A table lent no rows is the defect the plan rules out: the end is not kept, and a debug
    /// build stops there.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the ends waiting outnumber")
    )]
    fn an_end_past_the_rows_is_a_defect() {
        let mut held = ended(0);
        let ends = &mut held.ends;
        ends.note(1);
        assert_eq!(ends.take(), None);
    }
}
