// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qc — the tokio side of the `routing-routes` atom: the
//! [`RoutingForwarder`] that backs the [`accept_loop`](crate::accept_loop)'s
//! [`FaceForwarder`](crate::accept_loop::FaceForwarder) seam with the
//! [`wz_session_core::routing::RouteTable`] forwarding kernel.
//!
//! The accept loop holds N peer faces on one `!Send` task (its
//! [`FuturesUnordered`](futures_util::stream::FuturesUnordered) drive set), so
//! the routing table is shared across the per-face observers with a plain
//! `Rc<RefCell<…>>` — no `Mutex`, no `Send` bound. Each table operation
//! (`add_face` / `remove_face` / `observe`) is synchronous and holds the
//! `RefCell` borrow only for its own duration, never across an `.await`, so the
//! borrows from `register` / `deregister` (called by the loop) and `forward`
//! (called from a face's drive observer) are strictly sequential on the one
//! task — never overlapping.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use wz_session_core::routing::RouteTable;

use crate::accept_loop::{FaceForwarder, FaceId};
use crate::runtime_impl::{TokioRuntime, TokioTime};
use crate::session_glue::{IterationEvent, SessionLinkActions};

/// A [`FaceForwarder`] that routes: it owns the [`RouteTable`] keyed by
/// [`FaceId`], registering each held face's send seam so a Put received on one
/// face is forwarded to every other face with a matching subscription. The
/// `routing-routes` counterpart to [`NoOpForwarder`](crate::accept_loop::NoOpForwarder).
pub struct RoutingForwarder {
    /// Shared single-task routing table — `Rc<RefCell>`, not `Mutex`, because
    /// the whole accept loop is one `!Send` task.
    table: Rc<RefCell<RouteTable<TokioRuntime, TokioTime>>>,
    /// Running total of forwards emitted, for the router's shutdown summary /
    /// log witness. `Cell` (single-task interior mutability through the
    /// `&self` trait method).
    forwarded: Cell<usize>,
}

impl RoutingForwarder {
    /// A new forwarder over an empty routing table.
    pub fn new() -> Self {
        Self {
            table: Rc::new(RefCell::new(RouteTable::new())),
            forwarded: Cell::new(0),
        }
    }

    /// Total forwards emitted so far — the router's data-plane work witness
    /// (logged in the shutdown summary; asserted by tests alongside the
    /// consumer-side receipt).
    pub fn forwarded(&self) -> usize {
        self.forwarded.get()
    }

    /// Total subscriptions currently recorded across all held faces — the
    /// routing-state witness ([`RouteTable::subscription_count`]) a test asserts
    /// directly (e.g. that an aliased declare was NOT recorded), distinct from
    /// the observable [`forwarded`](Self::forwarded) count.
    pub fn subscription_count(&self) -> usize {
        self.table.borrow().subscription_count()
    }
}

impl Default for RoutingForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl FaceForwarder for RoutingForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        self.table.borrow_mut().add_face(id.0, actions.clone());
    }

    fn deregister(&self, id: FaceId) {
        self.table.borrow_mut().remove_face(id.0);
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        let n = self.table.borrow_mut().observe(id.0, event);
        if n > 0 {
            self.forwarded.set(self.forwarded.get() + n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::recording_actions;
    use crate::Reliability;
    use wz_codecs::push::PushOwned;
    use wz_session_core::driver_loop::DriverLoopOutcome;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::push_build::{build_push_del_literal, build_push_literal};
    use wz_session_core_test_support::{
        decl_subscriber, declare_envelope_decl_subscriber, declare_envelope_undecl_subscriber,
        undecl_subscriber,
    };

    // Wrap a Push as the inbound FramePayload iteration event the forwarder
    // observes, on the given reliability channel. The Pushes come from the
    // PRODUCTION builders (`build_push_*_literal`) — exactly what a publishing
    // peer emits on the wire (literal id=0 keyexpr + real payload) — so the
    // tests forward the same bytes the e2e does, with no test-only Push shape.
    fn push_frame(push: PushOwned, reliable: bool) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            reliable,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    fn declare_frame(declare: wz_codecs::declare::DeclareOwned) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Declare(Box::new(declare))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// Feed `forwarder` a literal-keyexpr DeclareSubscriber for `(sub_id,
    /// keyexpr)` on face `face`.
    fn declare_sub(forwarder: &RoutingForwarder, face: u64, sub_id: u64, keyexpr: &str) {
        let outcome = declare_frame(declare_envelope_decl_subscriber(decl_subscriber(
            sub_id,
            0,
            Some(keyexpr),
        )));
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a reliable Put (production literal builder, real
    /// payload) on `keyexpr` published by face `face`.
    fn publish(forwarder: &RoutingForwarder, face: u64, keyexpr: &str) {
        let push = build_push_literal(keyexpr, b"payload").expect("literal Put push");
        let outcome = push_frame(push, true);
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    #[test]
    fn forwards_a_put_to_a_matching_subscriber_on_another_face() {
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 1, "home/temp");

        assert_eq!(fwd.forwarded(), 1, "one forward emitted");
        assert_eq!(
            consumer_sink.frame_count(),
            1,
            "the subscriber's face received the forwarded Put"
        );
        assert_eq!(
            producer_sink.frame_count(),
            0,
            "the publisher's face received nothing back"
        );
    }

    #[test]
    fn does_not_forward_when_no_subscription_matches() {
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 1, "home/humidity"); // different keyexpr

        assert_eq!(fwd.forwarded(), 0, "no matching subscription, no forward");
        assert_eq!(consumer_sink.frame_count(), 0);
    }

    #[test]
    fn fans_out_to_every_matching_face() {
        let fwd = RoutingForwarder::new();
        let (sub_a, sink_a) = recording_actions();
        let (sub_b, sink_b) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &sub_a);
        fwd.register(FaceId(1), &sub_b);
        fwd.register(FaceId(2), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        declare_sub(&fwd, 1, 1, "home/temp");
        publish(&fwd, 2, "home/temp");

        assert_eq!(fwd.forwarded(), 2, "forwarded to both subscribers");
        assert_eq!(sink_a.frame_count(), 1);
        assert_eq!(sink_b.frame_count(), 1);
    }

    #[test]
    fn never_forwards_a_put_back_to_its_source_face() {
        // A face that subscribes its OWN keyexpr and then publishes it must not
        // receive its own Put — the `src != dst` skip is the loop guard.
        let fwd = RoutingForwarder::new();
        let (peer, peer_sink) = recording_actions();
        fwd.register(FaceId(0), &peer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 0, "home/temp");

        assert_eq!(
            fwd.forwarded(),
            0,
            "source is the only subscriber, no forward"
        );
        assert_eq!(
            peer_sink.frame_count(),
            0,
            "a face never echoes its own Put"
        );
    }

    #[test]
    fn stops_forwarding_after_the_subscription_is_undeclared() {
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 7, "home/temp");
        publish(&fwd, 1, "home/temp");
        assert_eq!(consumer_sink.frame_count(), 1, "forwarded while subscribed");

        // Undeclare the SAME subscriber id, then publish again.
        let undecl = declare_frame(declare_envelope_undecl_subscriber(undecl_subscriber(7)));
        fwd.forward(FaceId(0), IterationEvent::Poll(&undecl));
        publish(&fwd, 1, "home/temp");

        assert_eq!(
            consumer_sink.frame_count(),
            1,
            "no further forward after undeclare"
        );
        assert_eq!(
            fwd.forwarded(),
            1,
            "total forwards unchanged by the second Put"
        );
    }

    #[test]
    fn stops_forwarding_after_the_subscriber_face_leaves() {
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        fwd.deregister(FaceId(0)); // the subscriber face leaves (peer close)
        publish(&fwd, 1, "home/temp");

        assert_eq!(fwd.forwarded(), 0, "a departed face is not a destination");
        assert_eq!(consumer_sink.frame_count(), 0);
    }

    #[test]
    fn a_wildcard_subscription_matches_a_concrete_put() {
        // Routing reuses the keyexpr matcher SSOT, so chunk wildcards work.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/**");
        publish(&fwd, 1, "home/livingroom/temp");

        assert_eq!(fwd.forwarded(), 1, "wildcard subscription matched");
        assert_eq!(consumer_sink.frame_count(), 1);
    }

    #[test]
    fn forwards_only_to_the_face_whose_subscription_matches() {
        // The heart of a router: a Put reaches ONLY the face whose subscription
        // matches, not every held face. Two subscribers on DIFFERENT keyexprs +
        // a producer; a Put on one keyexpr must hit one and skip the other.
        let fwd = RoutingForwarder::new();
        let (sub_temp, sink_temp) = recording_actions();
        let (sub_humidity, sink_humidity) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &sub_temp);
        fwd.register(FaceId(1), &sub_humidity);
        fwd.register(FaceId(2), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        declare_sub(&fwd, 1, 1, "home/humidity");
        publish(&fwd, 2, "home/temp");

        assert_eq!(fwd.forwarded(), 1, "exactly one face matched");
        assert_eq!(
            sink_temp.frame_count(),
            1,
            "the temp subscriber received it"
        );
        assert_eq!(
            sink_humidity.frame_count(),
            0,
            "the humidity subscriber must NOT receive a temp Put"
        );
    }

    #[test]
    fn an_aliased_subscription_is_not_recorded_yet() {
        // A DeclareSubscriber whose keyexpr references an expr-id (id != 0) the
        // router has no mapping for cannot be resolved (alias resolution is a
        // later increment), so it must NOT be recorded — proven directly via the
        // subscription count, not just an absent forward.
        let fwd = RoutingForwarder::new();
        let (consumer, _consumer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);

        // mapping_id = 7 (non-zero) => WireexprLocal { id: 7, .. }, unresolvable
        // against the empty per-face alias table.
        let outcome = declare_frame(declare_envelope_decl_subscriber(decl_subscriber(
            1,
            7,
            Some("/leaf"),
        )));
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        assert_eq!(
            fwd.subscription_count(),
            0,
            "an aliased (id != 0) subscription is not recorded in this atom"
        );
    }

    #[test]
    fn forwards_on_the_published_reliability_channel() {
        // The forward must carry the Put's reliability through to the
        // destination's send seam — a best-effort Put forwards best-effort.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        let push = build_push_literal("home/temp", b"payload").expect("literal Put push");
        let outcome = push_frame(push, false); // best-effort
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(
            consumer_sink.frame_count(),
            1,
            "forwarded the best-effort Put"
        );
        assert_eq!(
            consumer_sink.frame_reliability(0),
            Reliability::BestEffort,
            "the forward preserved the published best-effort channel"
        );
    }

    #[test]
    fn forwards_a_del_to_a_matching_subscriber() {
        // Forwarding is body-agnostic: a Del (MsgDel) routes by keyexpr exactly
        // like a Put, since `observe` matches `NetworkMessage::Push` regardless
        // of the inner Put/Del variant.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        let del = build_push_del_literal("home/temp").expect("literal Del push");
        let outcome = push_frame(del, true);
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(fwd.forwarded(), 1, "a Del routes like a Put");
        assert_eq!(consumer_sink.frame_count(), 1);
    }
}
