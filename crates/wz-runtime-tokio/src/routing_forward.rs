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

    /// Number of currently-valid cached routes
    /// ([`RouteTable::cached_route_count`]) — a route-cache state witness: a
    /// route appears after a Put on a fresh keyexpr, and the count drops to 0
    /// when a declaration / face change invalidates the cache.
    pub fn cached_route_count(&self) -> usize {
        self.table.borrow().cached_route_count()
    }

    /// Total route computations (cache misses) so far
    /// ([`RouteTable::route_computations`]) — the cache-effectiveness witness: a
    /// repeated Put on a cached keyexpr does not increment it, a Put after an
    /// invalidation does.
    pub fn route_computations(&self) -> u64 {
        self.table.borrow().route_computations()
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
    use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
    use crate::Reliability;
    use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
    use wz_codecs::push::PushOwned;
    use wz_session_core::driver_loop::DriverLoopOutcome;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::push_build::{
        build_push_aliased, build_push_del_literal, build_push_literal,
    };
    use wz_session_core_test_support::{
        decl_kexpr, decl_subscriber, declare_envelope_decl_kexpr, declare_envelope_decl_subscriber,
        declare_envelope_undecl_kexpr, declare_envelope_undecl_subscriber, interest_subscriber,
        undecl_kexpr, undecl_subscriber,
    };

    // Wrap a Push as the inbound FramePayload iteration event the forwarder
    // observes, on the given reliability channel. The Pushes come from the
    // PRODUCTION builders (`build_push_*_literal`) — exactly what a publishing
    // peer emits on the wire (literal id=0 keyexpr + real payload) — so the
    // tests forward the same bytes the e2e does, with no test-only Push shape.
    fn push_frame(push: PushOwned, reliable: bool) -> DriverLoopOutcome {
        push_frame_priority(push, reliable, wz_session_core::qos::Priority::DEFAULT)
    }

    /// [`push_frame`] with an explicit priority BAND — so a transport-qos test can
    /// drive a banded Put and assert the switchboard PRESERVES it on transit
    /// (R311y224). `push_frame` delegates here with `Priority::DEFAULT`, so this
    /// helper always has a non-gated caller (no dead-code under the plain
    /// `routing-routes` clippy arm).
    fn push_frame_priority(
        push: PushOwned,
        reliable: bool,
        priority: wz_session_core::qos::Priority,
    ) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority,
            reliable,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    fn declare_frame(declare: wz_codecs::declare::DeclareOwned) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
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

    /// Feed `forwarder` a DeclareKeyexpr mapping `id -> keyexpr` on face `face`
    /// (R311qd — the peer's bandwidth-optimisation alias).
    fn declare_kexpr(forwarder: &RoutingForwarder, face: u64, id: u64, keyexpr: &str) {
        let outcome = declare_frame(declare_envelope_decl_kexpr(decl_kexpr(id, keyexpr)));
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a subscriber `Interest` on `keyexpr` from face `face` —
    /// the pico-publisher write-filter shape (R311y373). `current` / `future` are
    /// the envelope C / F bits, `aggregate` the body AG bit (a pico client
    /// publisher sends C+F+AG).
    fn send_interest(
        forwarder: &RoutingForwarder,
        face: u64,
        interest_id: u64,
        keyexpr: &str,
        current: bool,
        future: bool,
        aggregate: bool,
    ) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Interest(interest_subscriber(
                interest_id,
                keyexpr,
                current,
                future,
                aggregate,
            ))],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Every `Declare` a face's recording sink captured, flattened across frames
    /// in emit order — robust to whether the express sends batched or not, so a
    /// test asserts the DECODED reply sequence (subscriber decl + Final) rather
    /// than a frame count. Decodes through the production RX path
    /// (`parse_inbound` + `parse_frame_payload`), so a malformed reply would fail
    /// to decode here (not silently pass).
    fn captured_declares(sink: &RecordingLinkDriver) -> Vec<DeclareOwned> {
        use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
        let mut out = Vec::new();
        for i in 0..sink.frame_count() {
            let bytes = sink.frame_bytes(i);
            let InboundFrame::Frame { payload, .. } =
                parse_inbound(&bytes).expect("parse emitted frame")
            else {
                panic!("emitted bytes are not a T_MID_FRAME");
            };
            for m in parse_frame_payload(&payload).expect("parse frame payload") {
                if let NetworkMessage::Declare(d) = m {
                    out.push(*d);
                }
            }
        }
        out
    }

    fn is_decl_subscriber(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohDeclSubscriber(_))
    }

    fn is_decl_final(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohDeclFinal(_))
    }

    /// The subscriber id of a `Declare(DeclSubscriber)` — 0 for a CURRENT dump,
    /// non-zero for a FUTURE push (`build_declare_subscriber_reply{,_with_id}`).
    fn decl_subscriber_id(d: &DeclareOwned) -> u64 {
        match &d.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(s) => s.id,
            other => panic!("expected a DeclSubscriber, got {other:?}"),
        }
    }

    #[test]
    fn answers_a_current_subscriber_interest_with_the_matching_declare_and_final() {
        // R311y373 — the sub-before-pub half: a pico publisher's CURRENT interest
        // (net/filtering.c write filter) is answered with the DeclareSubscriber a
        // matching subscription on ANOTHER face implies, so the publisher's filter
        // releases. Without this reply the filter stays ACTIVE and every put is
        // dropped locally (the cross-impl RED: forwarded 0 / computed 0).
        let fwd = RoutingForwarder::new();
        let (subscriber, sub_sink) = recording_actions();
        let (publisher, pub_sink) = recording_actions();
        fwd.register(FaceId(0), &subscriber);
        fwd.register(FaceId(1), &publisher);

        declare_sub(&fwd, 0, 1, "demo/route");
        // The publisher's write-filter interest (C+F+AG, the pico client shape).
        send_interest(&fwd, 1, 42, "demo/route", true, true, true);

        let replies = captured_declares(&pub_sink);
        assert_eq!(
            replies.len(),
            2,
            "the interest is answered with a DeclareSubscriber then a Final"
        );
        assert!(
            is_decl_subscriber(&replies[0]) && replies[0].interest_id == Some(42),
            "first reply is a DeclareSubscriber stamped with the soliciting interest_id"
        );
        assert_eq!(
            decl_subscriber_id(&replies[0]),
            0,
            "a CURRENT dump carries subscriber id 0 (zenoh make_sub_id = 0 for non-future)"
        );
        assert!(
            is_decl_final(&replies[1]) && replies[1].interest_id == Some(42),
            "the dump is terminated by a Final stamped with the interest_id"
        );
        assert_eq!(
            captured_declares(&sub_sink).len(),
            0,
            "the subscriber's own face receives no interest reply"
        );
    }

    #[test]
    fn a_current_interest_with_no_matching_subscription_sends_only_a_final() {
        // The discriminator for the reply: with NO matching subscription the
        // router advertises NO subscriber, so a pico publisher's write filter
        // correctly stays ACTIVE (it must not put into a void). Only the Final is
        // sent (closing the CURRENT interest); no DeclareSubscriber.
        let fwd = RoutingForwarder::new();
        let (publisher, pub_sink) = recording_actions();
        let (_bystander, _bystander_sink) = recording_actions();
        fwd.register(FaceId(1), &publisher);
        // face 0 is a bystander with no subscription.
        fwd.register(FaceId(0), &_bystander);

        send_interest(&fwd, 1, 7, "demo/route", true, true, true);

        let replies = captured_declares(&pub_sink);
        assert_eq!(
            replies.len(),
            1,
            "only a Final is sent when nothing matches"
        );
        assert!(
            is_decl_final(&replies[0]) && replies[0].interest_id == Some(7),
            "the sole reply is the Final that closes the CURRENT interest"
        );
        assert!(
            !replies.iter().any(is_decl_subscriber),
            "NO subscriber is advertised — the filter must stay ACTIVE"
        );
    }

    #[test]
    fn a_future_interest_pushes_a_later_declared_subscription() {
        // R311y373 — the pub-before-sub half: a publisher whose C+F interest found
        // no current subscriber (Final only) is later PUSHED the subscription that
        // arrives on another face, releasing its write filter on the pub-first
        // ordering. The FUTURE push carries a NON-ZERO subscriber id (id 0 is the
        // CURRENT dump) so a value-aware re-push updates the same target in place.
        let fwd = RoutingForwarder::new();
        let (subscriber, _sub_sink) = recording_actions();
        let (publisher, pub_sink) = recording_actions();
        fwd.register(FaceId(0), &subscriber);
        fwd.register(FaceId(1), &publisher);

        // Publisher interest arrives FIRST — no subscription yet, so only a Final.
        send_interest(&fwd, 1, 9, "demo/route", true, true, true);
        assert_eq!(
            captured_declares(&pub_sink).len(),
            1,
            "CURRENT dump finds nothing yet -> only the Final"
        );

        // The subscription arrives LATER on the other face -> unsolicited push.
        declare_sub(&fwd, 0, 5, "demo/route");
        let replies = captured_declares(&pub_sink);
        assert_eq!(
            replies.len(),
            2,
            "the later subscription is pushed to the waiting publisher face"
        );
        assert!(
            is_decl_subscriber(&replies[1]) && replies[1].interest_id == Some(9),
            "the FUTURE push is a DeclareSubscriber stamped with the interest_id"
        );
        assert_ne!(
            decl_subscriber_id(&replies[1]),
            0,
            "a FUTURE push carries a non-zero subscriber id (id 0 is the CURRENT dump)"
        );
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

    #[cfg(feature = "transport-qos")]
    #[test]
    fn forward_push_preserves_the_received_band_on_transit() {
        // R311y224 — the switchboard twin of the linkstate/router transit band
        // preservation: a RealTime Put published by the producer must reach the
        // subscribing consumer still banded RealTime, driven through the full
        // `observe` dispatch (so the FramePayload destructure -> forward_push band
        // threading is proven). The consumer must be QoS-negotiated, else the
        // per-face send clamps every Frame to DEFAULT (`dispatch_push`) and the band
        // cannot be observed.
        use crate::session_glue::{parse_inbound, InboundFrame};
        fn egress_band(frame: &[u8]) -> wz_session_core::qos::Priority {
            let InboundFrame::Frame { priority, .. } =
                parse_inbound(frame).expect("parse forwarded frame")
            else {
                panic!("forwarded bytes are not a Frame");
            };
            priority
        }

        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        consumer.set_qos_offer(true);
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);
        declare_sub(&fwd, 0, 1, "home/temp");
        // register + declare emit nothing on the consumer's own sink (the switchboard
        // sends only forwarded Puts), so frame index 0 is the first forward — no
        // `RecordingLinkDriver::reset` (which is `routing-peer`-gated, absent here).

        // A RealTime Put from the producer must reach the consumer still RealTime.
        let push = build_push_literal("home/temp", b"payload").expect("literal Put push");
        let outcome = push_frame_priority(push, true, wz_session_core::qos::Priority::RealTime);
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));
        assert_eq!(
            consumer_sink.frame_count(),
            1,
            "forwarded to the subscriber"
        );
        assert_eq!(
            egress_band(&consumer_sink.frame_bytes(0)),
            wz_session_core::qos::Priority::RealTime,
            "switchboard transit PRESERVES the received band — not re-clamped to DEFAULT"
        );

        // Negative control: a DEFAULT transit stays DEFAULT (byte-identical to the
        // pre-y224 `send_network_message` path) — the 2nd forward, frame index 1.
        let push = build_push_literal("home/temp", b"payload").expect("literal Put push");
        let outcome = push_frame_priority(push, true, wz_session_core::qos::Priority::DEFAULT);
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));
        assert_eq!(
            consumer_sink.frame_count(),
            2,
            "the DEFAULT Put also forwards"
        );
        assert_eq!(
            egress_band(&consumer_sink.frame_bytes(1)),
            wz_session_core::qos::Priority::DEFAULT,
            "a DEFAULT transit stays DEFAULT"
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
    fn drops_a_put_on_a_trailing_slash_keyexpr() {
        // zenoh `compute_data_route` guard (linkstate_peer/pubsub.rs:948): a
        // keyexpr ending in '/' is malformed (a trailing empty chunk) and must
        // reach NO face — not even a `**` subscriber, whose backtrack would
        // otherwise absorb the trailing "" chunk and spuriously match. The
        // control half confirms the SAME subscriber receives the well-formed key
        // (so the drop is the trailing slash, not a non-matching subscription).
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/**");

        // Malformed: trailing slash -> empty route, nothing forwarded.
        publish(&fwd, 1, "home/temp/");
        assert_eq!(
            fwd.forwarded(),
            0,
            "a trailing-slash keyexpr resolves to an empty route"
        );
        assert_eq!(
            consumer_sink.frame_count(),
            0,
            "the `**` subscriber received nothing for the malformed key"
        );

        // Control: the well-formed key matches the same `**` subscriber.
        publish(&fwd, 1, "home/temp");
        assert_eq!(fwd.forwarded(), 1, "the well-formed key forwards once");
        assert_eq!(consumer_sink.frame_count(), 1);
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
    fn an_aliased_subscription_without_a_mapping_is_dropped() {
        // A DeclareSubscriber whose keyexpr references an expr-id (id != 0) with
        // NO prior DeclareKeyexpr cannot be resolved, so it must NOT be recorded
        // — proven directly via the subscription count, not just an absent
        // forward. (With a prior mapping it IS recorded — the next test.)
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
            "an aliased subscription with no prior DeclareKeyexpr is not recorded"
        );
    }

    #[test]
    fn an_aliased_subscription_resolves_after_its_keyexpr_is_declared() {
        // R311qd: a peer that DeclareKeyexpr(id=7 -> "home/temp") then declares a
        // subscriber on the ALIASED keyexpr (WireexprLocal{id:7}) must have its
        // subscription recorded against the resolved literal — and a literal Put
        // on "home/temp" then forwards to it.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_kexpr(&fwd, 0, 7, "home/temp");
        // aliased DeclareSubscriber: keyexpr WireexprLocal{ id: 7, suffix: None }
        let sub = declare_frame(declare_envelope_decl_subscriber(decl_subscriber(
            1, 7, None,
        )));
        fwd.forward(FaceId(0), IterationEvent::Poll(&sub));

        assert_eq!(
            fwd.subscription_count(),
            1,
            "the aliased subscription resolved through the declared mapping"
        );
        publish(&fwd, 1, "home/temp");
        assert_eq!(fwd.forwarded(), 1, "a literal Put matched the resolved sub");
        assert_eq!(consumer_sink.frame_count(), 1);
    }

    #[test]
    fn re_literalizes_an_aliased_put_for_the_destination() {
        // R311qd: a producer that DeclareKeyexpr(id=9 -> "home/temp") then emits
        // an ALIASED Put (WireexprLocal{id:9, suffix:None}) must be forwarded to
        // a LITERAL subscriber re-literalized — the destination never saw the
        // mapping, so the forwarded frame must carry the literal "home/temp".
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp"); // literal subscriber
        declare_kexpr(&fwd, 1, 9, "home/temp"); // producer's alias
        let aliased = build_push_aliased(9, None, b"payload").expect("aliased Put push");
        let outcome = push_frame(aliased, true);
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(fwd.forwarded(), 1, "the aliased Put resolved + forwarded");
        assert_eq!(consumer_sink.frame_count(), 1);
        // The re-literalized forward must carry the literal keyexpr bytes (an
        // id-only aliased frame would NOT contain them) so the destination,
        // which never saw the mapping, can decode it.
        let frame = consumer_sink.frame_bytes(0);
        assert!(
            frame.windows(b"home/temp".len()).any(|w| w == b"home/temp"),
            "the forwarded frame must carry the re-literalized keyexpr bytes"
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

    #[test]
    fn re_literalizes_an_aliased_put_with_a_per_push_suffix() {
        // The aliased keyexpr resolution is prefix + per-push suffix concat
        // (resolve_wireexpr: table[id] + suffix, no separator inserted). A
        // producer maps id=9 -> "home" then publishes an aliased Put carrying a
        // per-push suffix "/temp" (resolved keyexpr "home/temp"), which must
        // forward to a literal subscriber on "home/temp", re-literalized.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        declare_kexpr(&fwd, 1, 9, "home"); // prefix-only mapping
        let aliased = build_push_aliased(9, Some("/temp"), b"payload").expect("aliased Put push");
        let outcome = push_frame(aliased, true);
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        assert_eq!(
            fwd.forwarded(),
            1,
            "prefix+suffix concat resolved to the matching keyexpr"
        );
        assert_eq!(consumer_sink.frame_count(), 1);
        let frame = consumer_sink.frame_bytes(0);
        assert!(
            frame.windows(b"home/temp".len()).any(|w| w == b"home/temp"),
            "the concatenated keyexpr 'home/temp' must be re-literalized on the wire"
        );
    }

    #[test]
    fn an_undeclared_keyexpr_alias_stops_resolving_but_existing_subs_keep_routing() {
        // UndeclareKeyexpr removes the alias: a SUBSEQUENT aliased record on that
        // id no longer resolves, but a subscription already recorded against the
        // resolved LITERAL keeps routing (subs store the literal, not the id).
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_kexpr(&fwd, 1, 9, "home/temp");
        declare_sub(&fwd, 0, 1, "home/temp"); // literal sub (stores the literal)

        // Undeclare the producer's alias id=9.
        let undecl = declare_frame(declare_envelope_undecl_kexpr(undecl_kexpr(9)));
        fwd.forward(FaceId(1), IterationEvent::Poll(&undecl));

        // An aliased Put on the now-removed id is dropped...
        let aliased = build_push_aliased(9, None, b"payload").expect("aliased Put push");
        let dropped = push_frame(aliased, true);
        fwd.forward(FaceId(1), IterationEvent::Poll(&dropped));
        assert_eq!(fwd.forwarded(), 0, "aliased Put on a removed id is dropped");
        assert_eq!(consumer_sink.frame_count(), 0);

        // ...but the already-recorded literal subscription still routes a literal
        // Put (alias removal must not break a resolved route).
        publish(&fwd, 1, "home/temp");
        assert_eq!(fwd.forwarded(), 1, "the existing literal sub still routes");
        assert_eq!(consumer_sink.frame_count(), 1);
    }

    #[test]
    fn repeated_puts_on_one_keyexpr_are_served_from_the_route_cache() {
        // R311qf: the first Put on a keyexpr computes the destination set (one
        // declared_intersects scan) and caches it; a second Put on the SAME
        // keyexpr is served from the cache — no second computation — and still
        // forwards correctly. The cache hit path: same result, computed once.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 1, "home/temp");
        publish(&fwd, 1, "home/temp");

        assert_eq!(fwd.forwarded(), 2, "both Puts forwarded");
        assert_eq!(consumer_sink.frame_count(), 2, "subscriber received both");
        assert_eq!(
            fwd.route_computations(),
            1,
            "the second Put was served from cache — only one route computation"
        );
        assert_eq!(fwd.cached_route_count(), 1, "one keyexpr route cached");
    }

    #[test]
    fn a_new_subscription_invalidates_the_route_cache() {
        // R311qf: a Put caches a route; a subsequent DeclareSubscriber on the
        // same keyexpr from another face must invalidate that cache, so the next
        // Put recomputes (a fresh scan) and fans out to BOTH subscribers —
        // proving the cache cannot serve a stale destination set across a
        // subscription change.
        let fwd = RoutingForwarder::new();
        let (sub_a, sink_a) = recording_actions();
        let (sub_b, sink_b) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &sub_a);
        fwd.register(FaceId(1), &sub_b);
        fwd.register(FaceId(2), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 2, "home/temp"); // caches {face 0}
        assert_eq!(fwd.route_computations(), 1, "first Put computed the route");
        assert_eq!(sink_a.frame_count(), 1);
        assert_eq!(sink_b.frame_count(), 0);

        // A new subscriber on the SAME keyexpr — invalidates the cache.
        declare_sub(&fwd, 1, 1, "home/temp");
        publish(&fwd, 2, "home/temp");

        assert_eq!(
            fwd.route_computations(),
            2,
            "the new subscription forced a recomputation"
        );
        assert_eq!(sink_a.frame_count(), 2, "first subscriber still routed");
        assert_eq!(
            sink_b.frame_count(),
            1,
            "the recomputed route picked up the new subscriber"
        );
    }

    #[test]
    fn a_departed_face_invalidates_the_route_cache() {
        // R311qf: a Put caches a route to a subscriber; when that subscriber's
        // face leaves, the cache must invalidate so the next Put recomputes (and
        // forwards to nobody) rather than serving the departed face from a stale
        // entry.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 1, "home/temp"); // caches {face 0}
        assert_eq!(consumer_sink.frame_count(), 1);
        assert_eq!(fwd.route_computations(), 1);

        fwd.deregister(FaceId(0)); // the subscriber leaves
        publish(&fwd, 1, "home/temp");

        assert_eq!(
            fwd.route_computations(),
            2,
            "the departed face invalidated the cache, forcing a recomputation"
        );
        assert_eq!(
            consumer_sink.frame_count(),
            1,
            "no forward after the subscriber left (recomputed empty route)"
        );
        assert_eq!(
            fwd.forwarded(),
            1,
            "total forwards unchanged by the second Put"
        );
    }

    #[test]
    fn an_alias_declaration_does_not_invalidate_the_route_cache() {
        // R311qf: a DeclareKeyexpr only records an expr-id alias; it changes no
        // subscription, so it must NOT invalidate the route cache. A Put after
        // an unrelated alias declaration is still served from cache (no
        // recomputation) — locking in that alias churn does not thrash the
        // data-plane cache.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_sub(&fwd, 0, 1, "home/temp");
        publish(&fwd, 1, "home/temp"); // caches the route (one computation)
        assert_eq!(fwd.route_computations(), 1);

        // The producer declares an expr-id alias — no subscription delta.
        declare_kexpr(&fwd, 1, 9, "home/other");
        publish(&fwd, 1, "home/temp");

        assert_eq!(
            fwd.route_computations(),
            1,
            "an alias declaration left the route cache intact — the second Put hit it"
        );
        assert_eq!(consumer_sink.frame_count(), 2, "both Puts forwarded");
    }

    #[test]
    fn a_subscription_after_an_unmatched_put_still_routes() {
        // R311qf: a Put published before any matching subscriber caches an EMPTY
        // route (a negative cache entry). A subsequent DeclareSubscriber must
        // invalidate that empty entry so the next Put recomputes and forwards —
        // a stale negative cache must not swallow a now-matching Put.
        // Publisher-before-subscriber is a normal startup ordering.
        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        publish(&fwd, 1, "home/temp"); // no subscriber yet -> caches empty
        assert_eq!(fwd.forwarded(), 0, "nothing to route yet");
        assert_eq!(
            fwd.route_computations(),
            1,
            "computed the (empty) route once"
        );

        declare_sub(&fwd, 0, 1, "home/temp"); // invalidates the empty entry
        publish(&fwd, 1, "home/temp");

        assert_eq!(
            fwd.route_computations(),
            2,
            "the subscription invalidated the negative cache, forcing a recompute"
        );
        assert_eq!(fwd.forwarded(), 1, "the now-matching Put routed");
        assert_eq!(consumer_sink.frame_count(), 1);
    }
}
