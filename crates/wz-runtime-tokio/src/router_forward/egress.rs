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
//! - a destination that holds [`EgressBudget::per_destination_bytes`] GATES the face whose
//!   message filled it: [`RouterForwarder::read_gate`] answers that face's drive, which stops
//!   reading that face and nothing else, until the destination holds no more than half of its
//!   budget. The face's peer meanwhile finds its own link full and waits as upstream's sender
//!   waits for a parked receive task, with the same deadline;
//! - the router as a whole holds at most [`EgressBudget::pool_bytes`]: past it, every face whose
//!   message is held is gated, whatever its destination holds, until the pool is down to half;
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
//! Credit is counted in BYTES, the memory a held message really occupies: the size of the held
//! entry, which carries the message itself, and its payload. A count of messages would let a
//! destination keep sixty-four messages of a megabyte each, and every destination of a router
//! do the same. Two budgets, as a transport's connection and stream credit are two
//! (HTTP/2, QUIC): one per destination, so that a stopped reader costs the router a bounded
//! amount, and one for the router, so that many stopped readers together do too.
//!
//! A destination is gated at its budget, so what it can hold past it is what the gated faces had
//! already read: at most one inbound frame each. A message larger than the whole budget is still
//! held, as the only one its destination holds (a queue that refused it could never send it, and
//! the face that sent it would wait for nothing). A message that comes from no face (a multicast
//! ingress, a local publish) cannot be gated, and is sent as it was, waiting inside the send.
//!
//! ## Not covered
//!
//! A message whose payload is in shared memory is sent through the relay, whose mapping of the
//! payload for the destination cannot be undone and retried, and keeps the waiting send. A
//! declaration, a query and a reply are rare and are not held here.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use wz_session_core::network_message::NetworkMessage;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::session_actions::Unsent;

use super::{RouterFaceState, RouterForwarder};
use crate::accept_loop::FaceId;

/// How many bytes the router lets a face's messages wait for, and where the faces that fed them
/// are gated.
///
/// A face that holds [`per_destination_bytes`](Self::per_destination_bytes) has a link that has
/// stopped taking frames for as long as they take to be written, which is the case the stage
/// exists for; a router that holds [`pool_bytes`](Self::pool_bytes) has many such faces, or one
/// whose messages are very large. Either gates the face whose message filled it. A face is
/// released when what it waits on is down to half, so that a budget hovering at its limit does
/// not gate and release a face with every message.
///
/// The defaults are four batches for a face (the link's own queue is two) and sixty-four
/// mebibytes for the router, which is two hundred and fifty-six faces each at its own budget.
/// They bound memory and are not tuned to a measured load; a host sized for more or less sets
/// its own ([`RouterForwarder::with_egress_budget`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressBudget {
    /// The bytes one destination face may hold.
    pub per_destination_bytes: usize,
    /// The bytes every destination of the router may hold together.
    pub pool_bytes: usize,
}

impl EgressBudget {
    /// Four 64 KiB batches for a face.
    pub const DEFAULT_PER_DESTINATION_BYTES: usize = 4 * 64 * 1024;
    /// Sixty-four mebibytes for the router.
    pub const DEFAULT_POOL_BYTES: usize = 64 * 1024 * 1024;
}

impl Default for EgressBudget {
    fn default() -> Self {
        Self {
            per_destination_bytes: Self::DEFAULT_PER_DESTINATION_BYTES,
            pool_bytes: Self::DEFAULT_POOL_BYTES,
        }
    }
}

/// What a face is gated on: a destination that holds its budget, or the router's pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum GateOn {
    Destination(FaceId),
    Pool,
}

/// One message waiting for room, with what the send needs to be asked again.
pub(super) struct Held {
    msg: NetworkMessage,
    reliable: bool,
    express: bool,
    priority: Priority,
    /// When it was held: a destination is closed when its oldest message has waited its
    /// `wait_before_close`.
    since: Instant,
    /// What it costs the budgets, fixed when it is held so that what is taken back is what was
    /// put in whatever happens to the message between.
    cost: usize,
}

/// The bytes a held message occupies: the entry that carries it and the payload it points at.
/// Another part of the message (the extension chain, the key suffix) is not counted; a Put that
/// carries a large one of those is not what a budget is for.
pub(super) fn message_cost(msg: &NetworkMessage) -> usize {
    let payload = match msg {
        NetworkMessage::Push(push) => match &push.body {
            wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
                wz_session_core::put_payload::payload_len(put)
            }
            _ => 0,
        },
        _ => 0,
    };
    std::mem::size_of::<Held>().saturating_add(payload)
}

/// The messages a destination face holds, oldest first, and what they cost together.
///
/// The bytes are kept here and nowhere else, beside the entries they are the sum of, so that
/// no caller can change the one and forget the other.
#[derive(Default)]
pub(super) struct EgressQueue {
    items: VecDeque<Held>,
    bytes: usize,
}

impl EgressQueue {
    /// What the queue holds, in bytes.
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    fn push_back(&mut self, held: Held) {
        self.bytes += held.cost;
        self.items.push_back(held);
    }

    /// Put back at the front what [`Self::pop_front`] took and could not send.
    fn push_front(&mut self, held: Held) {
        self.bytes += held.cost;
        self.items.push_front(held);
    }

    fn pop_front(&mut self) -> Option<Held> {
        let held = self.items.pop_front()?;
        self.bytes -= held.cost;
        Some(held)
    }

    /// When the oldest message was held.
    fn oldest(&self) -> Option<Instant> {
        self.items.front().map(|held| held.since)
    }

    /// Drop everything, answering how many messages and bytes that was.
    fn clear(&mut self) -> (usize, usize) {
        let taken = (self.items.len(), self.bytes);
        self.items.clear();
        self.bytes = 0;
        taken
    }
}

/// The forwarder's flow-control state: which face is being routed from, which faces are gated
/// on which destinations, and what is held.
pub(super) struct Credit {
    /// The face whose inbound frame is being routed now, so that a destination that fills up
    /// knows whom to gate. `None` outside a `forward`, and for a message with no face behind it.
    source: Cell<Option<FaceId>>,
    /// For each gated face, what it is gated on: the destinations it fed that are at their
    /// budget, and the pool when the router is at its.
    gated: RefCell<HashMap<FaceId, HashSet<GateOn>>>,
    /// The faces that hold at least one message, so that a pass over them does not visit the
    /// faces that hold none (a router holds thousands).
    holding: RefCell<HashSet<FaceId>>,
    /// Messages held now, over every destination.
    held: Cell<usize>,
    /// What they cost together, in bytes: the pool the router's budget is spent from.
    held_bytes: Cell<usize>,
    /// Where faces are gated.
    budget: EgressBudget,
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
            held_bytes: Cell::default(),
            budget: EgressBudget::default(),
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

/// A read-only handle on what the router holds back (see [`RouterForwarder::egress_view`]).
#[derive(Clone)]
pub struct EgressView(Rc<Credit>);

impl EgressView {
    /// What the router holds back now, as the capacity report carries it.
    pub fn counts(&self) -> wz_session_core::capacity::EgressCounts {
        let credit = &*self.0;
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        wz_session_core::capacity::EgressCounts {
            held: credit.held.get(),
            held_bytes: credit.held_bytes.get(),
            pool_bytes: credit.budget.pool_bytes,
            released: count(credit.released.get()),
            abandoned: count(credit.abandoned.get()),
            destinations_closed: count(credit.closed.get()),
            gated_faces: credit.gated.borrow().len(),
        }
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
            // A chain of fragments cannot be sent without waiting for room between its
            // fragments, so it is sent as it was before anything was held back: waiting inside
            // the send. This is the one message the stage does not isolate a stopped reader from.
            Err(Unsent::Chain(msg)) => {
                if self.send_to_face_actions(&state.actions, msg, reliable, express, priority) {
                    Credited::Sent
                } else {
                    Credited::Refused
                }
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
        let cost = message_cost(&msg);
        queue.push_back(Held {
            msg,
            reliable,
            express,
            priority,
            since: (self.clock)(),
            cost,
        });
        self.credit.held.set(self.credit.held.get() + 1);
        self.credit
            .held_bytes
            .set(self.credit.held_bytes.get() + cost);
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
        // The face whose message this is waits on what is full, so that what it had already read
        // is all the router holds past a budget for it. A face is not gated on itself.
        let Some(source) = self.credit.source.get() else {
            return;
        };
        let budget = self.credit.budget;
        let mut gated = self.credit.gated.borrow_mut();
        if source != dest && queue.bytes() >= budget.per_destination_bytes {
            gated
                .entry(source)
                .or_default()
                .insert(GateOn::Destination(dest));
        }
        if self.credit.held_bytes.get() >= budget.pool_bytes {
            gated.entry(source).or_default().insert(GateOn::Pool);
        }
    }

    /// Offer every destination that holds messages the room it may have now, in order, and
    /// release the faces whose destinations have drained.
    pub(super) fn drain_egress(&self) {
        if self.credit.held.get() == 0 {
            return;
        }
        let holding: Vec<FaceId> = self.credit.holding.borrow().iter().copied().collect();
        let faces = self.tables.faces.borrow();
        let mut took = false;
        for id in holding {
            let Some(state) = faces.get(&id) else {
                self.credit.holding.borrow_mut().remove(&id);
                continue;
            };
            let mut queue = state.held.borrow_mut();
            while let Some(held) = queue.pop_front() {
                let Held {
                    msg,
                    reliable,
                    express,
                    priority,
                    since,
                    cost,
                } = held;
                match state
                    .actions
                    .try_send_network_message_qos(msg, reliable, express, priority)
                {
                    Ok(()) => {
                        self.credit.held.set(self.credit.held.get() - 1);
                        self.credit
                            .held_bytes
                            .set(self.credit.held_bytes.get() - cost);
                        self.credit.released.set(self.credit.released.get() + 1);
                        self.note_sent(true);
                        took = true;
                    }
                    Err(Unsent::NoRoom(msg)) => {
                        queue.push_front(Held {
                            msg,
                            reliable,
                            express,
                            priority,
                            since,
                            cost,
                        });
                        break;
                    }
                    // A message held behind others, and so not probed when it came, turns out to
                    // be a chain. It is the head of its destination's queue, so sending it now,
                    // waiting inside the send, keeps the order; what it costs the loop is what it
                    // cost before anything was held back.
                    Err(Unsent::Chain(msg)) => {
                        self.credit.held.set(self.credit.held.get() - 1);
                        self.credit
                            .held_bytes
                            .set(self.credit.held_bytes.get() - cost);
                        if self.send_to_face_actions(
                            &state.actions,
                            msg,
                            reliable,
                            express,
                            priority,
                        ) {
                            self.credit.released.set(self.credit.released.get() + 1);
                            self.note_sent(true);
                            took = true;
                        } else {
                            self.credit.abandoned.set(self.credit.abandoned.get() + 1);
                        }
                    }
                    Err(Unsent::Failed(_)) => {
                        self.credit.held.set(self.credit.held.get() - 1);
                        self.credit
                            .held_bytes
                            .set(self.credit.held_bytes.get() - cost);
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
        let faces = self.tables.faces.borrow();
        let mut closed_any = false;
        for id in holding {
            let Some(state) = faces.get(&id) else {
                continue;
            };
            let mut queue = state.held.borrow_mut();
            let Some(oldest) = queue.oldest() else {
                continue;
            };
            if now.saturating_duration_since(oldest) < state.actions.wait_before_close() {
                continue;
            }
            let (dropped, bytes) = queue.clear();
            self.credit.held.set(self.credit.held.get() - dropped);
            self.credit
                .held_bytes
                .set(self.credit.held_bytes.get() - bytes);
            self.credit
                .abandoned
                .set(self.credit.abandoned.get() + dropped);
            self.credit.closed.set(self.credit.closed.get() + 1);
            self.credit.holding.borrow_mut().remove(&id);
            state.actions.watch_link_room(None);
            let _ = state.actions.settle_blocking_expiry();
            closed_any = true;
        }
        drop(faces);
        if closed_any {
            self.release_gates();
            self.credit.wake.notify_waiters();
        }
    }

    /// Release every gated face whose destinations are down to half their budget or gone, and,
    /// when the pool is down to half, the faces gated on it.
    fn release_gates(&self) {
        let faces = self.tables.faces.borrow();
        let budget = self.credit.budget;
        let pool_full = self.credit.held_bytes.get() > budget.pool_bytes / 2;
        self.credit.gated.borrow_mut().retain(|_, on| {
            on.retain(|on| match on {
                GateOn::Destination(dest) => faces.get(dest).is_some_and(|state| {
                    state.held.borrow().bytes() > budget.per_destination_bytes / 2
                }),
                GateOn::Pool => pool_full,
            });
            !on.is_empty()
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
        let (dropped, bytes) = state.held.borrow_mut().clear();
        if dropped > 0 {
            self.credit.held.set(self.credit.held.get() - dropped);
            self.credit
                .held_bytes
                .set(self.credit.held_bytes.get() - bytes);
            self.credit
                .abandoned
                .set(self.credit.abandoned.get() + dropped);
        }
        self.credit.holding.borrow_mut().remove(&id);
        {
            let mut gated = self.credit.gated.borrow_mut();
            gated.remove(&id);
            gated.retain(|_, on| {
                on.remove(&GateOn::Destination(id));
                !on.is_empty()
            });
        }
        self.credit.wake.notify_waiters();
    }

    /// Where this router's faces are gated, in bytes held for a destination and in all
    /// ([`EgressBudget`]). Set before the router serves, as its other builders are.
    pub fn with_egress_budget(mut self, budget: EgressBudget) -> Self {
        // Before the router serves and so before any view of the credit was handed out.
        match Rc::get_mut(&mut self.credit) {
            Some(credit) => credit.budget = budget,
            None => log::warn!(
                "wz-runtime-tokio: the egress budget was set after a view of it was taken; \
                 it is kept as it was"
            ),
        }
        self
    }

    /// A handle that reads what the router holds back, for the capacity report: the handler of
    /// that report is stored inside this forwarder, so it cannot hold the forwarder itself.
    pub fn egress_view(&self) -> EgressView {
        EgressView(Rc::clone(&self.credit))
    }

    /// What the held messages cost together, in bytes: the pool [`EgressBudget::pool_bytes`]
    /// bounds.
    pub fn egress_held_bytes(&self) -> usize {
        self.credit.held_bytes.get()
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
