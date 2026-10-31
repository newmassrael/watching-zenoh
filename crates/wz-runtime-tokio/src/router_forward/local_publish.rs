// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A put from the node's own session waits for room outside the tables.
//!
//! ## The problem
//!
//! A put that may not be dropped (congestion control `Block`) waits for room in the destination's
//! queue, up to `wait_before_close` (5 s), and closes the session as unresponsive when none comes.
//! The node routes the put with its tables held for reading, and the send was made inside the
//! route, so the wait was made inside the lock. Everything that changes the node needs the
//! tables for writing: a face that comes up, a topology list, the tick, the answer of a dial or an
//! accept. A writer waits for the readers that are in, so while a publisher waited for room the
//! node could neither take a link up nor answer a handshake, and with a publisher that puts
//! without pause the queue is full again as soon as it has room, so the wait followed the wait.
//! Measured on 960 recipes of upstream's routing test, with the publisher a peer: the node's own
//! write waits ended at 5.0 s each (85 of them in one run), peers that had both dialled each other
//! never linked, and 14 recipes lost every message. The same recipes with a publisher that
//! paused a millisecond between puts lost none.
//!
//! Upstream's routing core takes its tables, computes the route and lets them go before it sends
//! (`full_reentrant_route_data`: `drop(tables)` before the faces are written to), so that a sender
//! that waits stalls itself and nobody else. The credit stage ([`super::egress`]) does the same
//! for what a face feeds the router; a message that comes from no face could not be gated and
//! kept the waiting send. This is its other half.
//!
//! ## The rule
//!
//! The entry points of a local publish open a [`Scope`]. Inside it a push that may not be dropped
//! is sent with a probe, which asks once and does not wait. What finds room leaves. What does not
//! is owed: the scope keeps it, whole, and the entry point sends it with the waiting send once the
//! tables are released, in the order the route produced it. The publisher still waits for the
//! room, for the time it waited before and with the same close on a deadline; it waits without
//! the lock.
//!
//! A droppable push keeps the send it had: it waits `wait_before_drop` (1 ms) once and is then
//! dropped, which is not what stalled the node. A push whose payload is in shared memory keeps
//! it too, as the relay's mapping of the payload for the destination cannot be undone and retried.

use std::cell::RefCell;
use std::sync::Arc;

use wz_session_core::network_message::NetworkMessage;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::session_actions::Unsent;

use crate::session_glue::SessionLinkActions;

/// A send the publisher still owes: the destination, and the message that found no room.
pub(super) struct Owed {
    actions: Arc<SessionLinkActions>,
    msg: NetworkMessage,
    reliable: bool,
    express: bool,
    priority: Priority,
}

impl Owed {
    /// Make the send, waiting for room as long as the message's congestion control allows.
    pub(super) fn send(self) {
        let began = std::time::Instant::now();
        let sent = self.actions.send_network_message_qos(
            self.msg,
            self.reliable,
            self.express,
            self.priority,
        );
        // What it answers is not reported to the publisher: a put does not report a destination
        // that closed. The wait is what backpressure on a publisher costs it, which is worth a
        // line when it was long, and a refusal is worth one at any length.
        let took = began.elapsed();
        if took >= super::SLOW_TABLES_WAIT || sent.is_err() {
            log::debug!(
                "router: a local put waited {took:?} for room on a destination's link and was {}",
                if sent.is_ok() { "sent" } else { "refused" }
            );
        }
    }
}

thread_local! {
    /// The sends the publish running on this thread owes, or `None` outside a [`Scope`].
    static OWED: RefCell<Option<Vec<Owed>>> = const { RefCell::new(None) };
}

/// The span of one local publish in which a send that would have to wait is owed instead.
pub(super) struct Scope {
    /// Whether this scope opened the span: a publish made from inside another (a hosted
    /// subscriber that publishes in its callback) joins the outer one, which sends what is owed.
    outermost: bool,
}

impl Scope {
    /// Open the span on this thread, or join the one that is open.
    pub(super) fn enter() -> Self {
        OWED.with(|owed| {
            let mut owed = owed.borrow_mut();
            let outermost = owed.is_none();
            if outermost {
                *owed = Some(Vec::new());
            }
            Self { outermost }
        })
    }

    /// Close the span and hand over what it owes, to be sent with the tables released. A scope
    /// that joined another owes nothing: the outer one holds it.
    pub(super) fn finish(self) -> Vec<Owed> {
        if !self.outermost {
            return Vec::new();
        }
        OWED.with(|owed| owed.borrow_mut().take().unwrap_or_default())
    }
}

impl Drop for Scope {
    /// A publish that unwinds leaves no span open on the thread.
    fn drop(&mut self) {
        if self.outermost {
            OWED.with(|owed| *owed.borrow_mut() = None);
        }
    }
}

/// Send `msg` to `actions` without waiting when it is a local publish that would wait, owing the
/// rest. `Ok` with whether it was sent (or is owed), or `Err` with the message when this send is
/// none that is deferred and the caller makes it as it always did.
pub(super) fn send_or_owe(
    actions: &Arc<SessionLinkActions>,
    msg: NetworkMessage,
    reliable: bool,
    express: bool,
    priority: Priority,
) -> Result<bool, NetworkMessage> {
    if OWED.with(|owed| owed.borrow().is_none()) {
        return Err(msg);
    }
    let NetworkMessage::Push(push) = &msg else {
        return Err(msg);
    };
    if wz_session_core::declare_ext_qos::read_push_qos(push).congestion() == CongestionControl::Drop
    {
        return Err(msg);
    }
    #[cfg(feature = "transport-shm")]
    if let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body {
        if !wz_session_core::put_payload::shm_descriptors(put).is_empty() {
            return Err(msg);
        }
    }
    match actions.try_send_network_message_qos(msg, reliable, express, priority) {
        Ok(()) => Ok(true),
        // No room now, or a chain of fragments, which cannot be sent without waiting between
        // them: both are sent by the publisher once the tables are free.
        Err(Unsent::NoRoom(msg) | Unsent::Chain(msg)) => {
            OWED.with(|owed| {
                if let Some(owed) = owed.borrow_mut().as_mut() {
                    owed.push(Owed {
                        actions: Arc::clone(actions),
                        msg,
                        reliable,
                        express,
                        priority,
                    });
                }
            });
            Ok(true)
        }
        Err(Unsent::Failed(_)) => Ok(false),
    }
}
