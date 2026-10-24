// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Credit-based egress of the router hat: what a face with a full queue costs the faces that do
//! not feed it.
//!
//! ## What it replaces
//!
//! The router drives every face from one loop task and calls [`RouterForwarder::forward`] inline
//! from it. A forward to a destination whose queue was full used to wait for room inside the
//! send (`wait_for_room`), up to `wait_before_close` (5 s) for a message that may not be dropped,
//! and for that time the loop took no frame from any other face. One subscriber that stopped
//! reading therefore silenced every publisher in the router. Upstream parks the receive task of
//! the one link that publishes to it, because each link has a task of its own; here the unit of
//! isolation was the whole router (measured: a live pair 15 s without a message beside one
//! stopped subscriber, `docs/router-data-plane-scaling.md` 7.5).
//!
//! ## The rule
//!
//! A message that may not be dropped (a reliable `Push` with a blocking congestion control) is
//! sent with a probe ([`SessionLinkActions::try_send_network_message_qos`]), which asks once and
//! does not wait. What finds room leaves, and what does not is HELD, whole, in a queue of the
//! destination face, in the order it arrived:
//!
//! - a destination with held messages takes every later credited message behind them, so one
//!   source's messages to one destination keep their order;
//! - a destination that holds [`EGRESS_CREDIT`] messages GATES the face whose message filled it:
//!   [`RouterForwarder::read_gate`] answers that face's drive, which stops reading that face and
//!   nothing else, until the destination holds no more than half of the credit. The face's peer
//!   meanwhile finds its own link full and waits as upstream's sender waits for a parked receive
//!   task, with the same deadline;
//! - a destination whose oldest held message is older than its `wait_before_close` is closed as
//!   unresponsive, which is what a send that waited that long would have done, and its held
//!   messages go with it. The gates it held are released.
//!
//! A droppable message (best effort, or congestion control `Drop`) is not held: it keeps the send
//! it had, which waits `wait_before_drop` (1 ms) once and is then dropped at once while the
//! lane's congested mark stands, and was not what stalled the loop.
//!
//! ## What is bounded, and by what
//!
//! A destination holds [`EGRESS_CREDIT`] messages, and the faces that fed it are gated at that
//! point, so what it can hold past the credit is what the gated faces had already read: at most
//! one inbound frame each. A message that comes from no face (a multicast ingress, a local
//! publish) cannot be gated, and is sent as it was, waiting inside the send.
//!
//! ## Not covered
//!
//! A message whose payload is in shared memory is sent through the relay, whose mapping of the
//! payload for the destination cannot be undone and retried, and keeps the waiting send. A
//! declaration, a query and a reply are rare and are not held here.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use wz_session_core::network_message::NetworkMessage;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::session_actions::Unsent;

use super::{RouterFaceState, RouterForwarder};
use crate::accept_loop::FaceId;

/// How many messages a destination face holds before the faces that feed it are gated.
///
/// A message here is one network message of a data stream, at most a batch; a face that holds
/// this many has a link that has stopped taking frames for as long as they take to be written,
/// which is the case the stage exists for. Sixty-four is far from a healthy queue (a face that
/// takes what it is sent holds none) and far from a memory problem: it is the number of messages
/// a gated destination may keep, not of bytes the router is willing to buffer for it, and a
/// destination that holds them for `wait_before_close` is closed.
pub const EGRESS_CREDIT: usize = 64;

/// A gated face is released when every destination it fed holds no more than this: half the
/// credit, so that a destination hovering at the credit does not gate and release a face with
/// every message.
const RELEASE_AT_OR_BELOW: usize = EGRESS_CREDIT / 2;

/// One message waiting for room, with what the send needs to be asked again.
pub(super) struct Held {
    msg: NetworkMessage,
    reliable: bool,
    express: bool,
    priority: Priority,
    /// When it was held: a destination is closed when its oldest message has waited its
    /// `wait_before_close`.
    since: Instant,
}

/// The messages a destination face holds, oldest first.
#[derive(Default)]
pub(super) struct EgressQueue {
    items: VecDeque<Held>,
}

impl EgressQueue {
    pub(super) fn len(&self) -> usize {
        self.items.len()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The forwarder's flow-control state: which face is being routed from, which faces are gated
/// on which destinations, and what is held.
pub(super) struct Credit {
    /// The face whose inbound frame is being routed now, so that a destination that fills up
    /// knows whom to gate. `None` outside a `forward`, and for a message with no face behind it.
    source: Cell<Option<FaceId>>,
    /// For each gated face, the destinations it fed that are over their credit.
    gated: RefCell<HashMap<FaceId, HashSet<FaceId>>>,
    /// The faces that hold at least one message, so that a pass over them does not visit the
    /// faces that hold none (a router holds thousands).
    holding: RefCell<HashSet<FaceId>>,
    /// Messages held now, over every destination.
    held: Cell<usize>,
    /// Messages that were held and then sent.
    released: Cell<usize>,
    /// Messages held at a destination that was closed for not taking them in time, or that went
    /// away.
    abandoned: Cell<usize>,
    /// Destinations closed for not taking a held message within `wait_before_close`.
    closed: Cell<usize>,
    /// Told when a destination took messages, so that a gated face asks again at once.
    wake: Arc<tokio::sync::Notify>,
    /// Told, with a stored permit, when a link the router holds messages for has room, so that
    /// the loop sends them then and not at its next tick ([`FaceForwarder::wake_signal`]).
    loop_wake: Arc<tokio::sync::Notify>,
    /// What a link calls when it makes room, set on a destination while it holds messages and
    /// cleared when it holds none: it wakes the loop, and every face gated on a destination.
    /// Runs on the link's writer thread, so it does no more than wake tasks.
    room_waker: Arc<dyn Fn() + Send + Sync>,
}

impl Default for Credit {
    fn default() -> Self {
        let wake = Arc::new(tokio::sync::Notify::new());
        let loop_wake = Arc::new(tokio::sync::Notify::new());
        let room_waker: Arc<dyn Fn() + Send + Sync> = {
            let (wake, loop_wake) = (Arc::clone(&wake), Arc::clone(&loop_wake));
            Arc::new(move || {
                loop_wake.notify_one();
                wake.notify_waiters();
            })
        };
        Self {
            source: Cell::default(),
            gated: RefCell::default(),
            holding: RefCell::default(),
            held: Cell::default(),
            released: Cell::default(),
            abandoned: Cell::default(),
            closed: Cell::default(),
            wake,
            loop_wake,
            room_waker,
        }
    }
}

/// Ends the routing of a source face's frame when it drops, on every way out of `forward`.
pub(super) struct Routing<'a>(&'a Credit);

impl Drop for Routing<'_> {
    fn drop(&mut self) {
        self.0.source.set(None);
    }
}

impl Credit {
    /// The frame of face `id` is being routed until the guard drops.
    pub(super) fn routing_from(&self, id: FaceId) -> Routing<'_> {
        self.source.set(Some(id));
        Routing(self)
    }
}

/// What the credited send of one message did.
pub(super) enum Credited {
    /// It left now.
    Sent,
    /// It is held, in order, and will leave when the destination has room.
    Held,
    /// It will not leave: the send failed for a reason sending again does not change.
    Refused,
}

impl RouterForwarder {
    /// Whether a message goes through the credit stage: a reliable `Push` whose congestion control
    /// may not drop it, sent on behalf of a face that can be gated, and not carrying shared
    /// memory.
    pub(super) fn is_credited(&self, msg: &NetworkMessage, reliable: bool) -> bool {
        if !reliable || self.credit.source.get().is_none() {
            return false;
        }
        let NetworkMessage::Push(push) = msg else {
            return false;
        };
        #[cfg(feature = "transport-shm")]
        if let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body {
            if !wz_session_core::put_payload::shm_descriptors(put).is_empty() {
                return false;
            }
        }
        wz_session_core::declare_ext_qos::read_push_qos(push).congestion()
            != CongestionControl::Drop
    }

    /// Send `msg` to destination `dest` without waiting, or hold it for when there is room.
    pub(super) fn credited_send(
        &self,
        dest: FaceId,
        state: &RouterFaceState,
        msg: NetworkMessage,
        reliable: bool,
        express: bool,
        priority: Priority,
    ) -> Credited {
        // Behind what the destination already holds, whatever room it has now: a message that
        // went past its predecessors would put one source's messages out of order.
        if !state.held.borrow().is_empty() {
            self.hold(dest, state, msg, reliable, express, priority);
            return Credited::Held;
        }
        match state
            .actions
            .try_send_network_message_qos(msg, reliable, express, priority)
        {
            Ok(()) => Credited::Sent,
            Err(Unsent::NoRoom(msg)) => {
                self.hold(dest, state, msg, reliable, express, priority);
                Credited::Held
            }
            Err(Unsent::Failed(_)) => Credited::Refused,
        }
    }

    fn hold(
        &self,
        dest: FaceId,
        state: &RouterFaceState,
        msg: NetworkMessage,
        reliable: bool,
        express: bool,
        priority: Priority,
    ) {
        let mut queue = state.held.borrow_mut();
        let first = queue.is_empty();
        queue.items.push_back(Held {
            msg,
            reliable,
            express,
            priority,
            since: (self.clock)(),
        });
        self.credit.held.set(self.credit.held.get() + 1);
        if first {
            // The link tells the router when it has room, for as long as it holds something.
            // Room may have been made between the probe that found none and this call, which
            // the link cannot have told it of, so the loop is woken once to look.
            state
                .actions
                .watch_link_room(Some(Arc::clone(&self.credit.room_waker)));
            self.credit.loop_wake.notify_one();
        }
        self.credit.holding.borrow_mut().insert(dest);
        if queue.len() >= EGRESS_CREDIT {
            if let Some(source) = self.credit.source.get().filter(|source| *source != dest) {
                self.credit
                    .gated
                    .borrow_mut()
                    .entry(source)
                    .or_default()
                    .insert(dest);
            }
        }
    }

    /// Offer every destination that holds messages the room it may have now, in order, and
    /// release the faces whose destinations have drained.
    pub(super) fn drain_egress(&self) {
        if self.credit.held.get() == 0 {
            return;
        }
        let holding: Vec<FaceId> = self.credit.holding.borrow().iter().copied().collect();
        let faces = self.faces.borrow();
        let mut took = false;
        for id in holding {
            let Some(state) = faces.get(&id) else {
                self.credit.holding.borrow_mut().remove(&id);
                continue;
            };
            let mut queue = state.held.borrow_mut();
            while let Some(held) = queue.items.pop_front() {
                let Held {
                    msg,
                    reliable,
                    express,
                    priority,
                    since,
                } = held;
                match state
                    .actions
                    .try_send_network_message_qos(msg, reliable, express, priority)
                {
                    Ok(()) => {
                        self.credit.held.set(self.credit.held.get() - 1);
                        self.credit.released.set(self.credit.released.get() + 1);
                        self.note_sent(true);
                        took = true;
                    }
                    Err(Unsent::NoRoom(msg)) => {
                        queue.items.push_front(Held {
                            msg,
                            reliable,
                            express,
                            priority,
                            since,
                        });
                        break;
                    }
                    Err(Unsent::Failed(_)) => {
                        self.credit.held.set(self.credit.held.get() - 1);
                        self.credit.abandoned.set(self.credit.abandoned.get() + 1);
                    }
                }
            }
            if queue.is_empty() {
                self.credit.holding.borrow_mut().remove(&id);
                // Nothing held, so nothing to be told: the writer stops paying for the call.
                state.actions.watch_link_room(None);
            }
        }
        drop(faces);
        self.release_gates();
        if took {
            self.credit.wake.notify_waiters();
        }
    }

    /// Close every destination whose oldest held message has waited its `wait_before_close`, as
    /// a send that waited that long would have, and drop what it held.
    pub(super) fn sweep_egress(&self) {
        if self.credit.held.get() == 0 {
            return;
        }
        let now = (self.clock)();
        let holding: Vec<FaceId> = self.credit.holding.borrow().iter().copied().collect();
        let faces = self.faces.borrow();
        let mut closed_any = false;
        for id in holding {
            let Some(state) = faces.get(&id) else {
                continue;
            };
            let mut queue = state.held.borrow_mut();
            let Some(oldest) = queue.items.front().map(|held| held.since) else {
                continue;
            };
            if now.saturating_duration_since(oldest) < state.actions.wait_before_close() {
                continue;
            }
            let dropped = queue.items.len();
            queue.items.clear();
            self.credit.held.set(self.credit.held.get() - dropped);
            self.credit
                .abandoned
                .set(self.credit.abandoned.get() + dropped);
            self.credit.closed.set(self.credit.closed.get() + 1);
            self.credit.holding.borrow_mut().remove(&id);
            state.actions.watch_link_room(None);
            state.actions.request_congestion_close();
            closed_any = true;
        }
        drop(faces);
        if closed_any {
            self.release_gates();
            self.credit.wake.notify_waiters();
        }
    }

    /// Release every gated face whose destinations are no longer over the credit, or are gone.
    fn release_gates(&self) {
        let faces = self.faces.borrow();
        self.credit.gated.borrow_mut().retain(|_, dests| {
            dests.retain(|dest| {
                faces
                    .get(dest)
                    .is_some_and(|state| state.held.borrow().len() > RELEASE_AT_OR_BELOW)
            });
            !dests.is_empty()
        });
    }

    /// The answer to [`FaceForwarder::read_gate`](crate::accept_loop::FaceForwarder::read_gate):
    /// whether face `id` must wait, after the destinations it waits on were offered room.
    pub(super) fn gate_of(&self, id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        if !self.credit.gated.borrow().contains_key(&id) {
            return None;
        }
        self.drain_egress();
        self.sweep_egress();
        if self.credit.gated.borrow().contains_key(&id) {
            Some(Arc::clone(&self.credit.wake))
        } else {
            None
        }
    }

    /// The signal a link's room raises on the loop ([`FaceForwarder::wake_signal`]).
    pub(super) fn wake_signal_of(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.credit.loop_wake)
    }

    /// A face left: what it held is gone with it, and no face waits on it or for it.
    pub(super) fn forget_egress_of(&self, id: FaceId, state: &RouterFaceState) {
        let dropped = state.held.borrow().len();
        if dropped > 0 {
            self.credit.held.set(self.credit.held.get() - dropped);
            self.credit
                .abandoned
                .set(self.credit.abandoned.get() + dropped);
        }
        self.credit.holding.borrow_mut().remove(&id);
        {
            let mut gated = self.credit.gated.borrow_mut();
            gated.remove(&id);
            gated.retain(|_, dests| {
                dests.remove(&id);
                !dests.is_empty()
            });
        }
        self.credit.wake.notify_waiters();
    }

    /// Messages held for destinations that have no room, over every destination.
    pub fn egress_held(&self) -> usize {
        self.credit.held.get()
    }

    /// Messages that were held, and were sent when their destination had room.
    pub fn egress_released(&self) -> usize {
        self.credit.released.get()
    }

    /// Messages that were held and did not leave: their destination was closed for not taking
    /// them in time, or went away.
    pub fn egress_abandoned(&self) -> usize {
        self.credit.abandoned.get()
    }

    /// Destinations closed for not taking a held message within `wait_before_close`.
    pub fn egress_destinations_closed(&self) -> usize {
        self.credit.closed.get()
    }

    /// The faces that are gated now: not read until a destination they fed has room.
    pub fn egress_gated_faces(&self) -> usize {
        self.credit.gated.borrow().len()
    }
}
