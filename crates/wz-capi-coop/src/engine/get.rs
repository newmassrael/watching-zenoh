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
//! never runs there (decision D8), so the sink ([`LegSink`]) hands each reply on to be called
//! after the lock: to the thread that made it, for an answer of the session's own queryables; to
//! the lane's pending table, for a reply that lies in a datagram a link lends; to the session's
//! delivery lane otherwise. What the entry's consolidation held to its end, and a timeout, wait in
//! the plane's held table, given up whole, and the leg's END is said when the entry is dropped (its
//! Final, its deadline, its cancellation, the loss of its link) by a guard the sink owns. The
//! deliveries hand them out with no lock held, the end once the lane has handed every reply queued
//! before it and the held table every reply held, as the drop of the leg's callback, which is how
//! a C program learns its get is over.
//!
//! The ends wait in a table the session's arena lent ([`EndedLegs`]), a row for each get the
//! session's tables of pending gets can hold. A leg ends when its row in those tables goes, and the
//! deliveries that follow every step take every end out, so the ends waiting never outnumber the
//! rows; a leg the session ends itself (cancelled, or never sent) drops its callback where it ends
//! it and leaves no end waiting.

use alloc::sync::Arc;

use wz_session_core::bounded::{BoundedVec, Lent};

use alloc::collections::VecDeque;

#[cfg(feature = "local-queryable")]
use wz_capi_port::sync::Lock;
use wz_capi_port::ReplyCallback;
use wz_session_core::reply::InboundReply;
use wz_session_core::reply_sink::{timeout_reply, ReplySink, ReplyView};

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
    /// What the entries of legs held to their ends, each with its leg, in the order they gave it
    /// up: handed to the leg's callback before its end.
    held: Queued<VecDeque<(u64, Held)>>,
    /// Whether a thread that holds the session's lock takes the callback the answer it makes
    /// reaches ([`Self::capture`]).
    #[cfg(feature = "local-queryable")]
    capture: Lock<Capture>,
}

impl GetPlane {
    /// A plane with nothing ended, its ends waiting in `ended`.
    pub(super) fn new(ended: EndedLegs) -> Self {
        Self {
            ended: Queued::new(ended),
            held: Queued::new(VecDeque::new()),
            #[cfg(feature = "local-queryable")]
            capture: Lock::new(Capture::Off),
        }
    }

    /// Take out, instead of queueing, the callback of the leg the replies handed to the sinks from
    /// here on reach, until [`Self::captured`]: how the thread that makes an answer of the
    /// session's own queryables, holding the session's lock, learns what to call to hand it the
    /// answer itself once it lets go.
    #[cfg(feature = "local-queryable")]
    pub(super) fn capture(&self) {
        self.capture.with(|capture| *capture = Capture::On(None));
    }

    /// The callback the replies since [`Self::capture`] reached; what is handed after this is
    /// queued again.
    #[cfg(feature = "local-queryable")]
    pub(super) fn captured(&self) -> Option<Arc<ReplyCallback>> {
        self.capture
            .with(|capture| match core::mem::replace(capture, Capture::Off) {
                Capture::On(found) => found,
                Capture::Off => None,
            })
    }

    /// Whether `callback` was taken out for the thread that captures: one leg's, the first a reply
    /// reached. A second leg reached under the same capture is queued, so nothing is lost.
    #[cfg(feature = "local-queryable")]
    fn captures(&self, callback: &Arc<ReplyCallback>) -> bool {
        self.capture.with(|capture| match capture {
            Capture::On(slot) if slot.is_none() => {
                *slot = Some(Arc::clone(callback));
                true
            }
            _ => false,
        })
    }

    /// Hold `held` for leg `leg`, after what it holds already.
    fn hold(&self, leg: u64, held: Held) {
        self.held.lock().push_back((leg, held));
    }

    /// What leg `leg`'s entry held to its end, the first of it, taken out; `None` once there is
    /// nothing. Read without the lock while nothing is held.
    pub(super) fn take_held(&self, leg: u64) -> Option<Held> {
        if !self.held.is_pending() {
            return None;
        }
        let mut held = self.held.lock();
        let at = held.iter().position(|(of, _)| *of == leg)?;
        held.remove(at).map(|(_, held)| held)
    }

    /// Everything held for every leg, taken out: the session is closed.
    pub(super) fn take_all_held(&self) -> VecDeque<(u64, Held)> {
        core::mem::take(&mut *self.held.lock())
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

/// What a leg's entry held to its end and the deliveries hand its callback before they let it go:
/// a reply its consolidation kept until the end, given up whole by the entry, or the timeout that
/// ended it.
pub(super) enum Held {
    Reply(InboundReply),
    Timeout(wz_session_core::wire_id::RequestId),
}

impl Held {
    /// Hand this to `callback`, with no lock of the session held.
    pub(super) fn hand(&self, callback: &ReplyCallback) {
        match self {
            Self::Reply(reply) => callback.call(reply),
            Self::Timeout(rid) => callback.call(&timeout_reply(*rid)),
        }
    }
}

/// Whether the session's own queryables answer a get of the session now, on the thread that holds
/// the session's lock: the callback of the leg the answer reaches is taken out, for that thread
/// to hand it the answer once it lets go of the lock ([`GetPlane::capture`]).
#[cfg(feature = "local-queryable")]
enum Capture {
    Off,
    On(Option<Arc<ReplyCallback>>),
}

/// The sink of leg `leg`'s pending entry, holding the leg's `callback`. A reply the session's own
/// queryables made while the plane captures is the thread's that made it, which hands it to the
/// callback once it lets go of the session ([`GetPlane::capture`]); a reply of a datagram a link
/// lends is held for the callback in the lane's pending table, and any other is queued in the
/// session's delivery `lane` (`SharedLane::offer_reply_to`). What the entry's consolidation held
/// to its end, and the timeout of a leg that timed out, wait in the plane's held table
/// ([`GetPlane::take_held`]). The sink's drop is the leg's end: the Final says nothing more, as
/// the registry drops the entry once its Finals are in. The table of callbacks holds the callback
/// past the entry, so the entry's drop, under the session's lock, is never its last.
pub(crate) struct LegSink {
    leg: u64,
    callback: Arc<ReplyCallback>,
    lane: Arc<SharedLane>,
    end: LegEnd,
}

impl LegSink {
    /// The sink of leg `leg`, handing what it is handed to `callback`.
    pub(super) fn new(
        leg: u64,
        callback: &Arc<ReplyCallback>,
        plane: &Arc<GetPlane>,
        lane: &Arc<SharedLane>,
    ) -> Self {
        Self {
            leg,
            callback: Arc::clone(callback),
            lane: Arc::clone(lane),
            end: LegEnd {
                leg,
                plane: Arc::clone(plane),
            },
        }
    }
}

impl ReplySink for LegSink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        #[cfg(feature = "local-queryable")]
        if self.end.plane.captures(&self.callback) {
            return;
        }
        // SAFETY: the registry hands its sinks a reply under the session's lock.
        unsafe { self.lane.offer_reply_to(self.leg, &self.callback, reply) };
    }

    fn on_final(&mut self, _rid: wz_session_core::wire_id::RequestId) {}

    fn on_timeout(&mut self, rid: wz_session_core::wire_id::RequestId) {
        self.end.plane.hold(self.leg, Held::Timeout(rid));
    }

    fn on_reply_owned(&mut self, reply: InboundReply) {
        self.end.plane.hold(self.leg, Held::Reply(reply));
    }
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
