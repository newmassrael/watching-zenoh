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

    /// Total liveliness tokens currently recorded across all held faces
    /// ([`RouteTable::token_count`]) — the token twin of
    /// [`subscription_count`](Self::subscription_count), so a test can assert
    /// the table's own state (recorded, retracted, gone with a departed face)
    /// independently of the declarations it emitted onto other faces.
    pub fn token_count(&self) -> usize {
        self.table.borrow().token_count()
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

    /// Total queryables currently recorded across all held faces
    /// ([`RouteTable::queryable_count`]) — the query-plane twin of
    /// [`subscription_count`](Self::subscription_count).
    pub fn queryable_count(&self) -> usize {
        self.table.borrow().queryable_count()
    }

    /// Queries currently in flight ([`RouteTable::pending_query_count`]) — the
    /// LEAK witness: every path that ends a query must drive this back to zero,
    /// and a router whose count only grows exhausts memory on query traffic.
    pub fn pending_query_count(&self) -> usize {
        self.table.borrow().pending_query_count()
    }

    /// Total queries routed to at least one queryable
    /// ([`RouteTable::queries_routed`]). Deliberately separate from
    /// [`forwarded`](Self::forwarded), which counts Push DESTINATIONS.
    pub fn queries_routed(&self) -> u64 {
        self.table.borrow().queries_routed()
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

    /// Feed `forwarder` an already-built `Interest` from face `face` — the
    /// kind-agnostic twin of [`send_interest`], so a test can drive the table
    /// with a QUERYABLE or TOKEN interest the subscriber-only helper cannot
    /// express.
    fn send_built_interest(
        forwarder: &RoutingForwarder,
        face: u64,
        interest: wz_codecs::interest::InterestOwned,
    ) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Interest(interest)],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// R311y773 THE DISCRIMINATOR. A CURRENT interest for a kind this table
    /// cannot dump is TERMINATED, not ignored.
    ///
    /// Before this round `record_interest` returned on `!body.su()` before any
    /// Final, and the requester is entitled to one: pico holds the pending
    /// interest until a Final arrives, so silence is a HANG to its own timeout
    /// rather than "no matches". zenoh sends the Final for a `mode.current()`
    /// interest whatever option bits are set (`hat/client/interests.rs`).
    ///
    /// Driven with the round-R311y771 builder rather than a hand-rolled body:
    /// that is the same message `Querier::declare_matching_listener` now puts on
    /// the wire, so this test also pins that wz's own emit and wz's own router
    /// meet.
    #[test]
    fn a_current_queryable_interest_is_terminated_rather_than_left_hanging() {
        use wz_session_core::interest_build::build_interest_queryables;

        let fwd = RoutingForwarder::new();
        let (querier, querier_sink) = recording_actions();
        let (bystander, _bystander_sink) = recording_actions();
        fwd.register(FaceId(1), &querier);
        fwd.register(FaceId(0), &bystander);

        send_built_interest(
            &fwd,
            1,
            build_interest_queryables(
                /*interest_id=*/ 9,
                /*current=*/ true,
                /*future=*/ true,
                /*mapping_id=*/ 0,
                Some("demo/route"),
            )
            .expect("builder accepts a literal keyexpr"),
        );

        let replies = captured_declares(&querier_sink);
        assert_eq!(
            replies.len(),
            1,
            "a CURRENT queryable interest must be answered -- exactly the Final",
        );
        assert!(
            is_decl_final(&replies[0]) && replies[0].interest_id == Some(9),
            "the reply is a Final stamped with the soliciting interest_id",
        );
        assert!(
            !replies.iter().any(is_decl_subscriber),
            "this table holds no queryable registry, so the dump is EMPTY -- \
             answering with a subscriber would be a lie about the plane",
        );
    }

    /// ANTI-VACUITY. A FUTURE-only interest of the same kind is correctly
    /// SILENT. Without this the test above is satisfied by a fix that Finals
    /// every interest, which would terminate streams the peer means to keep
    /// open — zenoh Finals only on `mode.current()`.
    #[test]
    fn a_future_only_queryable_interest_is_correctly_silent() {
        use wz_session_core::interest_build::build_interest_queryables;

        let fwd = RoutingForwarder::new();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(1), &querier);

        send_built_interest(
            &fwd,
            1,
            build_interest_queryables(
                9,
                /*current=*/ false,
                /*future=*/ true,
                0,
                Some("demo/route"),
            )
            .expect("builder accepts a literal keyexpr"),
        );

        assert_eq!(
            captured_declares(&querier_sink).len(),
            0,
            "a FUTURE-only interest has nothing to terminate; a Final here would \
             close a stream the peer means to keep open",
        );
    }

    /// The TOKEN plane too, so the fix reads as "any kind" rather than "the
    /// queryable kind as well as the subscriber one". `build_interest_liveliness_get`
    /// is CURRENT-only (C=1, F=0), which additionally covers the mode that has
    /// no future half at all.
    #[test]
    fn a_current_token_interest_is_terminated_on_the_same_rule() {
        use wz_session_core::interest_build::build_interest_liveliness_get;

        let fwd = RoutingForwarder::new();
        let (peer, peer_sink) = recording_actions();
        fwd.register(FaceId(1), &peer);

        send_built_interest(
            &fwd,
            1,
            build_interest_liveliness_get(4, 0, Some("demo/**"))
                .expect("builder accepts a literal"),
        );

        let replies = captured_declares(&peer_sink);
        assert_eq!(replies.len(), 1);
        assert!(is_decl_final(&replies[0]) && replies[0].interest_id == Some(4));
    }

    // ─── R311y803: the liveliness plane ──────────────────────────────────
    //
    // A `RouteTable` dispatches `Declare`, `Push` and `Interest` and no other
    // message kind, and the whole token plane is expressed in the first and the
    // third: the `DeclareToken` IS the delivery, the `UndeclareToken` IS the
    // retraction, the TOKENS `Interest` is the ask. So unlike the queryable
    // plane above, routing tokens advertises nothing unreachable.

    /// Feed `forwarder` a literal-keyexpr `DeclareToken` for `(token_id,
    /// keyexpr)` on face `face` — the shape a peer holding a liveliness token
    /// puts on the wire.
    fn declare_token(forwarder: &RoutingForwarder, face: u64, token_id: u64, keyexpr: &str) {
        let outcome = declare_frame(wz_session_core_test_support::declare_envelope_decl_token(
            wz_session_core_test_support::decl_token(token_id, 0, Some(keyexpr)),
        ));
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` an id-only `UndeclareToken` on face `face` — the
    /// ordinary retraction a holder sends for a token it declared by id.
    fn undeclare_token(forwarder: &RoutingForwarder, face: u64, token_id: u64) {
        let outcome = declare_frame(wz_session_core_test_support::declare_envelope_undecl_token(
            wz_session_core_test_support::undecl_token(token_id),
        ));
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a TOKENS `Interest` from the PRODUCTION builder — the
    /// exact message a liveliness subscriber emits. `history` is the CURRENT
    /// bit: a pico `z_liveliness_declare_subscriber` sends `CURRENT|FUTURE`
    /// with history and `FUTURE` alone without it
    /// (`vendor/zenoh-pico/src/net/liveliness.c:202`).
    fn send_token_interest(
        forwarder: &RoutingForwarder,
        face: u64,
        interest_id: u64,
        keyexpr: &str,
        history: bool,
    ) {
        use wz_session_core::interest_build::build_interest_liveliness_subscriber;
        send_built_interest(
            forwarder,
            face,
            build_interest_liveliness_subscriber(interest_id, history, 0, Some(keyexpr))
                .expect("builder accepts a literal keyexpr"),
        );
    }

    fn is_decl_token(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohDeclToken(_))
    }

    fn is_undecl_token(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohUndeclToken(_))
    }

    fn decl_token_id(d: &DeclareOwned) -> u64 {
        match &d.body {
            DeclareOwnedVariant::CodecZenohDeclToken(t) => t.id,
            other => panic!("expected a DeclToken, got {other:?}"),
        }
    }

    fn undecl_token_id(d: &DeclareOwned) -> u64 {
        match &d.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(u) => u.id,
            other => panic!("expected an UndeclToken, got {other:?}"),
        }
    }

    /// The literal keyexpr a `DeclToken` carries.
    fn decl_token_keyexpr(d: &DeclareOwned) -> String {
        match &d.body {
            DeclareOwnedVariant::CodecZenohDeclToken(t) => match &t.keyexpr.body {
                wz_codecs::wireexpr::WireexprOwnedVariant::WireexprLocal(w) => {
                    String::from(w.suffix.as_deref().unwrap_or_default())
                }
                other => panic!("expected a literal wireexpr, got {other:?}"),
            },
            other => panic!("expected a DeclToken, got {other:?}"),
        }
    }

    /// The keyexpr a SOURCED `UndeclToken` carries in its `ext_wire_expr`
    /// (`None` for the ordinary id-only form).
    fn undecl_token_ext_keyexpr(d: &DeclareOwned) -> Option<String> {
        match &d.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(u) => {
                wz_session_core::declare_ext_keyexpr::read_ext_keyexpr(u.extensions.as_ref())
                    .map(String::from)
            }
            other => panic!("expected an UndeclToken, got {other:?}"),
        }
    }

    /// THE HEADLINE. A liveliness token declared on one face reaches a face
    /// that asked for tokens — which before this round it did not, at all:
    /// `record_declare` matched only the keyexpr and subscriber arms and a
    /// `DeclToken` fell through to `_ => false`, so a liveliness subscriber
    /// behind a wz `--router` read an empty world however many holders were
    /// connected to the same router.
    ///
    /// The advertised id is NON-ZERO and that is load-bearing rather than
    /// cosmetic: the receiver keys its token table by the declared id
    /// (`liveliness_subscriber.rs`'s `peer_token_table`), so an advertisement
    /// carrying 0 could never be retracted by the ordinary id-only
    /// `UndeclareToken` — which is exactly what the retraction tests below
    /// require. zenoh allocates the same way (`make_token_id`'s future branch).
    #[test]
    fn a_token_declared_on_one_face_reaches_a_face_that_asked_for_tokens() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &observer);

        // The observer subscribes FIRST, with no history: nothing to dump.
        send_token_interest(&fwd, 1, 4, "group/**", /*history=*/ false);
        assert_eq!(
            captured_declares(&observer_sink).len(),
            0,
            "a FUTURE-only interest has nothing to terminate and nothing to dump",
        );

        declare_token(&fwd, 0, 77, "group/member/a");

        assert_eq!(fwd.token_count(), 1, "the table recorded the held token");
        let seen = captured_declares(&observer_sink);
        assert_eq!(
            seen.len(),
            1,
            "the token declared on the holder's face must reach the observer -- \
             a DeclareToken IS the delivery on this plane, so a table that \
             records it without advertising it carries liveliness nowhere",
        );
        assert!(is_decl_token(&seen[0]), "the advertisement is a DeclToken");
        assert_eq!(decl_token_keyexpr(&seen[0]), "group/member/a");
        assert_ne!(
            decl_token_id(&seen[0]),
            0,
            "the advertisement must carry a NON-ZERO id: the receiver keys its \
             token table by it and the retraction names it back",
        );
        assert_eq!(
            seen[0].interest_id, None,
            "an unsolicited advertisement carries no interest id -- upstream's \
             shape (propagate_simple_token_to leaves it None), and the one every \
             receiver accepts",
        );
    }

    /// ANTI-VACUITY for the interest GATE. A face that never asked for tokens
    /// is told nothing. Without this, the test above is satisfied by a table
    /// that broadcasts every token to every face — which is zenoh's CLIENT hat
    /// rule, not its router one (`hat/router/token.rs` collects
    /// `remote_interests` filtered by `options.tokens() && i.matches(res)`), and
    /// would put a message on a face with no liveliness subscriber to read it.
    #[test]
    fn a_face_that_never_asked_for_tokens_is_told_nothing() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (bystander, bystander_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &bystander);
        fwd.register(FaceId(2), &observer);

        // The bystander asks for SUBSCRIBERS on the same keyexpr -- a matching
        // keyexpr but the wrong KIND, so the gate is on the kind bit and not
        // merely on having registered something.
        send_interest(&fwd, 1, 8, "group/**", true, true, false);
        send_token_interest(&fwd, 2, 4, "group/**", false);
        declare_token(&fwd, 0, 77, "group/member/a");

        assert!(
            !captured_declares(&bystander_sink).iter().any(is_decl_token),
            "a face whose interest names SUBSCRIBERS must not be told about a \
             token: it has no liveliness subscriber to fire",
        );
        assert!(
            captured_declares(&observer_sink).iter().any(is_decl_token),
            "the face that DID ask for tokens still hears it, so the assertion \
             above is not grading a table that advertises to nobody",
        );
    }

    /// The CURRENT half: a token already held is DUMPED to an interest that
    /// asks for history, ahead of the Final. The sibling
    /// `a_current_token_interest_is_terminated_on_the_same_rule` pins the empty
    /// case (Final alone), so together they separate "this table has none" from
    /// "this table does not look".
    #[test]
    fn a_current_token_interest_dumps_the_tokens_already_held() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &observer);

        // The token exists BEFORE anyone asks -- the ordering the FUTURE half
        // cannot cover.
        declare_token(&fwd, 0, 77, "group/member/a");
        assert_eq!(
            captured_declares(&observer_sink).len(),
            0,
            "nobody has asked yet, so nothing is advertised",
        );

        send_token_interest(&fwd, 1, 4, "group/**", /*history=*/ true);

        let replies = captured_declares(&observer_sink);
        assert_eq!(replies.len(), 2, "the dump, then the Final");
        assert!(is_decl_token(&replies[0]));
        assert_eq!(decl_token_keyexpr(&replies[0]), "group/member/a");
        assert_eq!(
            replies[0].interest_id,
            Some(4),
            "a CURRENT-dump reply is stamped with the soliciting interest_id",
        );
        assert_ne!(
            decl_token_id(&replies[0]),
            0,
            "this interest is CURRENT+FUTURE, so the dump allocates a real id \
             (zenoh's make_token_id returns 0 only when !mode.future()) -- \
             without it the token could never be retracted by id",
        );
        assert!(
            is_decl_final(&replies[1]) && replies[1].interest_id == Some(4),
            "ONE Final closes the interest, after the dump",
        );
    }

    /// The retraction the HOLDER sends, carried to the observer under the id the
    /// advertisement used. A retraction under any other id would name a token
    /// the receiver's table does not hold, and its liveliness subscriber would
    /// fall through to the sourced-keyexpr path or drop it.
    #[test]
    fn an_undeclared_token_is_retracted_by_the_id_it_was_advertised_under() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &observer);

        send_token_interest(&fwd, 1, 4, "group/**", false);
        declare_token(&fwd, 0, 77, "group/member/a");
        let advertised = captured_declares(&observer_sink);
        assert_eq!(advertised.len(), 1);
        let advertised_id = decl_token_id(&advertised[0]);

        // The holder's OWN id is 77; the advertised id is the table's. They must
        // not be conflated, and the retraction must use the second.
        undeclare_token(&fwd, 0, 77);

        assert_eq!(
            fwd.token_count(),
            0,
            "the table dropped the retracted token"
        );
        let after = captured_declares(&observer_sink);
        assert_eq!(after.len(), 2, "the retraction reached the observer");
        assert!(is_undecl_token(&after[1]));
        assert_eq!(
            undecl_token_id(&after[1]),
            advertised_id,
            "the retraction names the id the ADVERTISEMENT carried, which is \
             what `local_tokens` remembers it for",
        );
        assert_eq!(
            undecl_token_ext_keyexpr(&after[1]),
            None,
            "an advertised token retracts by id alone -- the sourced form is for \
             a face that was never told",
        );
    }

    /// THE ROUTER-GENERATED RETRACTION. A holder that LEAVES takes its tokens
    /// with it, and the observer is told — the arm R311y802 closed on the
    /// subscriber and queryable planes and recorded as absent on this one.
    ///
    /// It is a different arm from the test above and not a duplicate of it: no
    /// peer sends anything here. A liveliness token's whole meaning is that its
    /// holder is alive, so a face that vanishes without a retraction leaves
    /// every observer believing a dead peer is still there and NO later message
    /// corrects it. zenoh synthesises it in `close_face`, draining
    /// `remote_tokens` into `undeclare_simple_token`
    /// (`hat/router/mod.rs:541-544`).
    #[test]
    fn a_departing_face_takes_its_tokens_with_it() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &observer);

        send_token_interest(&fwd, 1, 4, "group/**", false);
        declare_token(&fwd, 0, 77, "group/member/a");
        let advertised_id = decl_token_id(&captured_declares(&observer_sink)[0]);

        // The holder's link drops: the accept loop deregisters the face. Nothing
        // arrives on the wire from it -- this retraction has no sender but the
        // router.
        fwd.deregister(FaceId(0));

        assert_eq!(
            fwd.token_count(),
            0,
            "a departed face's tokens leave the table with it",
        );
        let after = captured_declares(&observer_sink);
        assert_eq!(
            after.len(),
            2,
            "the observer must be told the holder is gone -- silence here is a \
             liveliness token that stays alive forever",
        );
        assert!(is_undecl_token(&after[1]));
        assert_eq!(
            undecl_token_id(&after[1]),
            advertised_id,
            "the synthesised retraction names the advertised id, exactly as the \
             holder's own would have",
        );
    }

    /// A SECOND HOLDER KEEPS IT ALIVE. Two peers holding the same liveliness
    /// keyexpr are ONE fact to an observer, so one of them leaving retracts
    /// nothing. Upstream guards the same condition — `undeclare_simple_token`
    /// propagates the forget only when `simple_tokens(res)` is empty.
    ///
    /// This is the discriminator for the dedup half as well: the observer is
    /// told ONCE for two holders, because a second advertisement under a second
    /// id would leave it still believing after only one retraction.
    #[test]
    fn a_second_holder_keeps_the_token_alive_when_the_first_leaves() {
        let fwd = RoutingForwarder::new();
        let (first, _first_sink) = recording_actions();
        let (second, _second_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &first);
        fwd.register(FaceId(1), &second);
        fwd.register(FaceId(2), &observer);

        send_token_interest(&fwd, 2, 4, "group/**", false);
        declare_token(&fwd, 0, 77, "group/member/a");
        declare_token(&fwd, 1, 88, "group/member/a");

        assert_eq!(fwd.token_count(), 2, "both holders are recorded");
        assert_eq!(
            captured_declares(&observer_sink).len(),
            1,
            "the observer is told ONCE: the same keyexpr held twice is one \
             liveliness fact, and a second id would survive the first retraction",
        );

        fwd.deregister(FaceId(0));

        assert_eq!(fwd.token_count(), 1, "the survivor's token is still held");
        assert_eq!(
            captured_declares(&observer_sink).len(),
            1,
            "nothing is retracted while a holder remains -- the peer IS still \
             alive and a Delete here would be a lie",
        );

        fwd.deregister(FaceId(1));

        let after = captured_declares(&observer_sink);
        assert_eq!(after.len(), 2, "the LAST holder leaving does retract it");
        assert!(is_undecl_token(&after[1]));
    }

    /// The SOURCED retraction, and the shape that reaches it. A FUTURE-only
    /// (no-history) liveliness subscriber registers its interest and is never
    /// sent a declaration for a token that predates it, so when that token dies
    /// there is no advertised id to name — upstream sends a one-shot
    /// `UndeclareToken` carrying the keyexpr in `ext_wire_expr` instead
    /// (`hat/router/token.rs:438-457`), and so does this.
    ///
    /// The driver is a real shape rather than a constructed one: pico's
    /// `z_liveliness_declare_subscriber` sends exactly `FUTURE` alone when
    /// history is off (`net/liveliness.c:202`).
    #[test]
    fn a_token_older_than_a_future_only_interest_retracts_by_its_keyexpr() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &observer);

        // The token exists BEFORE the interest, and the interest asks for no
        // history -- so nothing is ever advertised to this face.
        declare_token(&fwd, 0, 77, "group/member/a");
        send_token_interest(&fwd, 1, 4, "group/**", /*history=*/ false);
        assert_eq!(
            captured_declares(&observer_sink).len(),
            0,
            "no history was asked for, so the pre-existing token is not dumped",
        );

        undeclare_token(&fwd, 0, 77);

        let after = captured_declares(&observer_sink);
        assert_eq!(after.len(), 1, "the retraction still reaches the observer");
        assert!(is_undecl_token(&after[0]));
        assert_eq!(
            undecl_token_id(&after[0]),
            0,
            "a sourced retraction uses no id -- the keyexpr is the identity",
        );
        assert_eq!(
            undecl_token_ext_keyexpr(&after[0]).as_deref(),
            Some("group/member/a"),
            "so the keyexpr must ride in the ext, or the receiver has nothing to \
             resolve the Delete against",
        );
    }

    /// The INBOUND sourced form — the RECEIVE side of the very shape this table
    /// EMITS two tests above. A sourced retraction names its token by KEYEXPR
    /// with `id == 0` (`build_undeclare_token_with_keyexpr`), so a table that
    /// only ever looked the id up would discard every one of them: that is the
    /// defect R311y769 paid off on the endpoint registry, and `record_declare`
    /// has the same seam. Same two-step in the same order — id first, then the
    /// `ext_wire_expr` — through the shared `resolve_ext_keyexpr` SSOT.
    ///
    /// The token is deliberately NOT declared to this table first. That is what
    /// makes the ext the only thing that can name it, and it is also the honest
    /// shape: upstream declines to act on a sourced retraction while the face
    /// still holds the same resource under an id of its own
    /// (`undeclare_simple_token`'s `!remote_tokens.values().any(..)` guard),
    /// which this table's own "still held by someone" guard reproduces.
    #[test]
    fn a_sourced_undeclare_is_resolved_through_its_ext_keyexpr() {
        use wz_session_core::declare_build::build_undeclare_token_with_keyexpr;

        let fwd = RoutingForwarder::new();
        let (upstream, _upstream_sink) = recording_actions();
        let (observer, observer_sink) = recording_actions();
        fwd.register(FaceId(0), &upstream);
        fwd.register(FaceId(1), &observer);

        send_token_interest(&fwd, 1, 4, "group/**", /*history=*/ false);

        // The PRODUCTION builder, so this drives the same bytes this file's own
        // forget path puts on the wire rather than a hand-rolled fixture.
        let sourced = build_undeclare_token_with_keyexpr("group/member/a")
            .expect("the literal keyexpr fits the owned carrier");
        let outcome = declare_frame(sourced);
        fwd.forward(FaceId(0), IterationEvent::Poll(&outcome));

        let after = captured_declares(&observer_sink);
        assert_eq!(
            after.len(),
            1,
            "the retraction must be carried on -- id 0 names nothing, so \
             dropping on the table miss would discard every sourced retraction \
             there is",
        );
        assert!(is_undecl_token(&after[0]));
        assert_eq!(
            undecl_token_ext_keyexpr(&after[0]).as_deref(),
            Some("group/member/a"),
            "and it names the keyexpr the inbound ext resolved to, which is the \
             only place that string could have come from",
        );
    }

    /// A CURRENT SUBSCRIBER interest whose keyexpr cannot be resolved is
    /// terminated as well. The alias names a mapping the face never declared, so
    /// there is nothing to match against — but the requester is owed the same
    /// Final, and this arm used to drop it silently for exactly the reason the
    /// `!su()` arm did.
    #[test]
    fn a_current_interest_on_an_unresolvable_alias_is_still_terminated() {
        let fwd = RoutingForwarder::new();
        let (publisher, pub_sink) = recording_actions();
        fwd.register(FaceId(1), &publisher);

        // Alias id 77 was never declared by this face.
        let mut interest = wz_session_core_test_support::interest_subscriber(
            5, "ignored", /*current=*/ true, /*future=*/ false, /*aggregate=*/ false,
        );
        if let Some(body) = interest.body.as_mut() {
            body.keyexpr = Some(wz_codecs::wireexpr::WireexprOwned {
                body: wz_codecs::wireexpr::WireexprOwnedVariant::WireexprLocal(
                    wz_codecs::wireexpr_local::WireexprLocalOwned {
                        id: 77,
                        suffix_len: None,
                        suffix: None,
                    },
                ),
            });
        }
        send_built_interest(&fwd, 1, interest);

        let replies = captured_declares(&pub_sink);
        assert_eq!(
            replies.len(),
            1,
            "an unresolvable CURRENT interest is terminated, not dropped",
        );
        assert!(is_decl_final(&replies[0]) && replies[0].interest_id == Some(5));
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

    /// The mapping id of the keyexpr an emitted record names, or `None` for a
    /// record that carries no keyexpr.
    ///
    /// EXHAUSTIVE, and the catch-all arms PANIC rather than returning `None`.
    /// A record kind this forwarder has never emitted before is a NEW emit
    /// path, and a new emit path is precisely where an alias of the relay's own
    /// could first appear — so the guard below must fail on it rather than
    /// quietly skip it. Silence on an unrecognised shape is how a guard passes
    /// over the thing it was written to catch.
    fn emitted_keyexpr_id(record: &NetworkMessage) -> Option<u64> {
        fn id_of(w: &wz_codecs::wireexpr::WireexprOwned) -> u64 {
            match &w.body {
                wz_codecs::wireexpr::WireexprOwnedVariant::WireexprLocal(a) => a.id,
                wz_codecs::wireexpr::WireexprOwnedVariant::WireexprNonlocal(a) => a.id,
            }
        }
        match record {
            NetworkMessage::Push(p) => Some(id_of(&p.keyexpr)),
            NetworkMessage::Declare(d) => match &d.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(s) => Some(id_of(&s.keyexpr)),
                // R311y803 — the liveliness emits, answering this guard's own
                // instruction rather than being waved past it. A `DeclToken`
                // carries a body wireexpr and so is graded exactly like the
                // subscriber arm; an `UndeclToken` carries none (the sourced
                // form puts its keyexpr in an `ext_wire_expr`, built by the
                // `declare_ext_keyexpr` SSOT from an already-resolved literal),
                // so there is no id to grade and `None` skips it.
                DeclareOwnedVariant::CodecZenohDeclToken(t) => Some(id_of(&t.keyexpr)),
                DeclareOwnedVariant::CodecZenohUndeclToken(_) => None,
                other => panic!(
                    "the routing forwarder emitted a Declare arm this guard has \
                     never seen ({other:?}). It is a NEW emit path -- check \
                     whether it can carry an alias the relay declared, and see \
                     `routing.rs`'s peer-only resolve if it can"
                ),
            },
            other => panic!(
                "the routing forwarder emitted a record kind this guard has \
                 never seen ({other:?}); see the note on this function"
            ),
        }
    }

    /// R311y766 (carry N39) — THE PREMISE THE RELAY'S REFUSAL RESTS ON.
    ///
    /// `RouteTable` resolves every inbound keyexpr against the SOURCE FACE's
    /// `peer_aliases` and nothing else (`routing.rs:670`); there is no own-id
    /// space on the other side of the `M` bit, so an `M=0` alias — one naming
    /// an id the RELAY declared — resolves against nothing and the message is
    /// dropped. That is correct exactly while the relay declares no alias of
    /// its own, and the day it does it becomes a silent drop of legitimate
    /// traffic that looks identical to a peer naming an id it never declared.
    /// N39 recorded that latency; this is what stops it being latent.
    ///
    /// THE CLAIM IS ABOUT EMITTED BYTES, not about the absence of a call site.
    /// The frames the destination face actually received are decoded and every
    /// keyexpr in them is required to be a literal (`id == 0`). A grep for
    /// `send_declare_keyexpr` would keep passing on the day a forward path
    /// started aliasing inline; this does not.
    ///
    /// THE DISCRIMINATOR IS THAT BOTH INBOUND HALVES ARE ALIASED, on DIFFERENT
    /// ids: the consumer subscribed through its id 7, the producer published
    /// through its id 9. A forwarder that passed its input through verbatim
    /// would hand the consumer an id 9 it never declared, and would red here.
    #[test]
    fn the_relay_emits_no_alias_of_its_own() {
        use wz_session_core::inbound::{parse_inbound, InboundFrame};
        use wz_session_core::network_message::parse_frame_payload;

        let fwd = RoutingForwarder::new();
        let (consumer, consumer_sink) = recording_actions();
        let (producer, _producer_sink) = recording_actions();
        fwd.register(FaceId(0), &consumer);
        fwd.register(FaceId(1), &producer);

        declare_kexpr(&fwd, 0, 7, "home/temp");
        let sub = declare_frame(declare_envelope_decl_subscriber(decl_subscriber(
            1, 7, None,
        )));
        fwd.forward(FaceId(0), IterationEvent::Poll(&sub));

        declare_kexpr(&fwd, 1, 9, "home/temp");
        let push = build_push_aliased(9, None, b"payload").expect("aliased Put push");
        fwd.forward(FaceId(1), IterationEvent::Poll(&push_frame(push, true)));

        // ANTI-VACUITY: nothing forwarded means every assertion below holds
        // over an empty set, which is the same green a relay that emitted only
        // literals would produce.
        assert_eq!(
            fwd.forwarded(),
            1,
            "the aliased Put did not reach the aliased subscription, so this \
             guard would be grading an empty emit set"
        );
        assert!(
            consumer_sink.frame_count() > 0,
            "the consumer face received no frame"
        );

        let mut inspected = 0usize;
        for idx in 0..consumer_sink.frame_count() {
            let bytes = consumer_sink.frame_bytes(idx);
            let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(&bytes) else {
                continue;
            };
            for record in parse_frame_payload(&payload).expect("the relay's own frame parses") {
                let Some(id) = emitted_keyexpr_id(&record) else {
                    continue;
                };
                inspected += 1;
                assert_eq!(
                    id, 0,
                    "the relay emitted an ALIASED keyexpr (id {id}). Every \
                     resolve site in routing.rs consults only the source face's \
                     peer table, so a peer answering this alias with M=0 would \
                     be dropped -- that is carry N39, and this is the day it \
                     stopped being latent. Give the face an own-id space and \
                     resolve through MappingSpaces, as every other plane has \
                     since R311y739"
                );
            }
        }
        assert!(
            inspected > 0,
            "no keyexpr-carrying record was inspected, so the id assertion \
             graded nothing"
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

    // ─── R311y840 — the QUERY plane ──────────────────────────────────────
    //
    // zenoh routes a `z_get` through the SAME dispatcher that routes a Put:
    // `route_query` (`dispatcher/queries.rs`) picks the faces whose declared
    // queryable matches, sends each one a Request under a face-local request
    // id, and maps the Responses back to the querier's own id; the querier is
    // closed by exactly one ResponseFinal however many queryables answered
    // (`Drop for Query`). Everything below asserts that behaviour.

    /// Every non-Declare `NetworkMessage` a face's recording sink captured,
    /// flattened across frames in emit order — the query-plane twin of
    /// [`captured_declares`], decoded through the same production RX path so a
    /// malformed emit fails here rather than passing silently.
    fn captured_messages(sink: &RecordingLinkDriver) -> Vec<NetworkMessage> {
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
                out.push(m);
            }
        }
        out
    }

    /// The `(request_id, keyexpr)` of every `Request` a face received.
    fn captured_requests(sink: &RecordingLinkDriver) -> Vec<(u64, String)> {
        captured_messages(sink)
            .into_iter()
            .filter_map(|m| match m {
                NetworkMessage::Request(r) => {
                    Some((r.rid, wireexpr_literal(&r.keyexpr, "Request")))
                }
                _ => None,
            })
            .collect()
    }

    /// The `(request_id, keyexpr)` of every `Response` a face received.
    fn captured_responses(sink: &RecordingLinkDriver) -> Vec<(u64, String)> {
        captured_messages(sink)
            .into_iter()
            .filter_map(|m| match m {
                NetworkMessage::Response(r) => {
                    Some((r.request_id, wireexpr_literal(&r.keyexpr, "Response")))
                }
                _ => None,
            })
            .collect()
    }

    /// The request id of every `ResponseFinal` a face received.
    fn captured_finals(sink: &RecordingLinkDriver) -> Vec<u64> {
        captured_messages(sink)
            .into_iter()
            .filter_map(|m| match m {
                NetworkMessage::ResponseFinal(rf) => Some(rf.request_id),
                _ => None,
            })
            .collect()
    }

    fn wireexpr_literal(keyexpr: &wz_codecs::wireexpr::WireexprOwned, what: &str) -> String {
        match &keyexpr.body {
            wz_codecs::wireexpr::WireexprOwnedVariant::WireexprLocal(w) => {
                String::from(w.suffix.as_deref().unwrap_or_default())
            }
            other => panic!("expected a literal wireexpr on the {what}, got {other:?}"),
        }
    }

    /// Feed `forwarder` a literal-keyexpr DeclareQueryable for `(qabl_id,
    /// keyexpr)` on face `face`.
    fn declare_qabl(forwarder: &RoutingForwarder, face: u64, qabl_id: u64, keyexpr: &str) {
        let outcome = declare_frame(
            wz_session_core_test_support::declare_envelope_decl_queryable(
                wz_session_core_test_support::decl_queryable(qabl_id, 0, Some(keyexpr)),
            ),
        );
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    fn undeclare_qabl(forwarder: &RoutingForwarder, face: u64, qabl_id: u64) {
        let outcome = declare_frame(
            wz_session_core_test_support::declare_envelope_undecl_queryable(
                wz_session_core_test_support::undecl_queryable(qabl_id),
            ),
        );
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a `Request(Query)` on `keyexpr` from face `face`, built
    /// by the PRODUCTION builder a querying peer uses.
    fn send_query(forwarder: &RoutingForwarder, face: u64, rid: u64, keyexpr: &str) {
        let request = wz_session_core::request_build::build_request_query(rid, 0, Some(keyexpr))
            .expect("literal query request");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(request))],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a `Response(Reply)` from face `face` answering `rid`.
    fn send_reply(forwarder: &RoutingForwarder, face: u64, rid: u64, keyexpr: &str, body: &[u8]) {
        let response =
            wz_session_core::response_build::build_response_reply_literal(rid, keyexpr, body)
                .expect("literal reply");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Response(Box::new(response))],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// Feed `forwarder` a `ResponseFinal` from face `face` closing `rid`.
    fn send_final(forwarder: &RoutingForwarder, face: u64, rid: u64) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::ResponseFinal(
                wz_session_core::response_final_build::build_response_final(rid),
            )],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// THE HEADLINE. A `z_get` traversing a wz router must reach the face that
    /// declared a matching queryable. Before this round `record_declare` had no
    /// DeclareQueryable arm and `observe` had no Request arm at all, so a
    /// queryable behind a wz `--router` was unreachable — the router silently
    /// dropped every query, and the querier waited out its own timeout.
    #[test]
    fn routes_a_query_to_a_face_that_declared_a_matching_queryable() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_query(&fwd, 1, 42, "demo/example");

        let seen = captured_requests(&qabl_sink);
        assert_eq!(
            seen.len(),
            1,
            "the queryable's face received exactly one Request, got {seen:?}"
        );
        assert_eq!(
            seen[0].1, "demo/example",
            "the routed Request carries the QUERIED keyexpr, not the queryable's pattern"
        );
        assert!(
            captured_requests(&querier_sink).is_empty(),
            "the querier is never sent its own query back"
        );
    }

    /// zenoh does NOT leave a querier hanging when nothing matches: an empty
    /// route sends the ResponseFinal straight back (`route_query`'s
    /// `if route.is_empty()` arm), so `z_get` completes immediately instead of
    /// waiting out its timeout. The same shape R311y773 fixed for `declare-final`.
    #[test]
    fn a_query_with_no_matching_queryable_is_finalized_immediately() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "other/**");
        send_query(&fwd, 1, 42, "demo/example");

        assert!(
            captured_requests(&qabl_sink).is_empty(),
            "a non-matching queryable is not queried"
        );
        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "the querier is closed at once under its OWN request id"
        );
        assert_eq!(
            fwd.pending_query_count(),
            0,
            "an unrouted query is never entered as pending"
        );
        assert_eq!(
            fwd.queries_routed(),
            0,
            "and it is not counted as a routed query"
        );
    }

    /// A reply must come back to the querier under the id the QUERIER minted,
    /// not the face-local id the router used downstream — the router owns the
    /// mapping both ways (zenoh's `face.pending_queries` -> `query.src_qid`).
    #[test]
    fn routes_a_reply_back_to_the_querier_under_its_own_request_id() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_query(&fwd, 1, 42, "demo/example");

        let downstream_rid = captured_requests(&qabl_sink)[0].0;
        send_reply(&fwd, 0, downstream_rid, "demo/example", b"answer");
        send_final(&fwd, 0, downstream_rid);

        assert_eq!(
            captured_responses(&querier_sink),
            vec![(42, String::from("demo/example"))],
            "the reply reached the querier re-stamped with its own request id"
        );
        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "and the stream was closed under that same id"
        );
        assert_eq!(
            fwd.pending_query_count(),
            0,
            "the closed query left no state behind"
        );
        assert_eq!(fwd.queries_routed(), 1);
    }

    /// Two queryables, ONE final. zenoh closes the querier when the last
    /// outstanding downstream query drops (`Drop for Query`), so a querier that
    /// counts finals (both zenoh and pico do) is not closed early by the first
    /// answerer.
    #[test]
    fn closes_the_querier_with_one_final_however_many_queryables_answered() {
        let fwd = RoutingForwarder::new();
        let (qabl_a, sink_a) = recording_actions();
        let (qabl_b, sink_b) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl_a);
        fwd.register(FaceId(1), &qabl_b);
        fwd.register(FaceId(2), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        declare_qabl(&fwd, 1, 9, "demo/example");
        send_query(&fwd, 2, 42, "demo/example");

        let rid_a = captured_requests(&sink_a)[0].0;
        let rid_b = captured_requests(&sink_b)[0].0;
        send_reply(&fwd, 0, rid_a, "demo/example", b"a");
        send_final(&fwd, 0, rid_a);
        assert!(
            captured_finals(&querier_sink).is_empty(),
            "the FIRST answerer's final must not close the querier — one is still outstanding"
        );

        send_reply(&fwd, 1, rid_b, "demo/example", b"b");
        send_final(&fwd, 1, rid_b);

        assert_eq!(
            captured_responses(&querier_sink).len(),
            2,
            "both replies reached the querier"
        );
        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "exactly one final closed the querier, after the last answerer"
        );
        assert_eq!(
            fwd.pending_query_count(),
            0,
            "and the fan-out left no state behind"
        );
    }

    /// The undeclare counterpart — the query route must go away with the
    /// queryable, and the querier must then be finalized immediately.
    #[test]
    fn stops_routing_queries_after_the_queryable_is_undeclared() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        undeclare_qabl(&fwd, 0, 7);
        send_query(&fwd, 1, 42, "demo/example");

        assert!(
            captured_requests(&qabl_sink).is_empty(),
            "an undeclared queryable is no longer a query destination"
        );
        assert_eq!(captured_finals(&querier_sink), vec![42]);
    }

    /// A face that leaves takes its queryables with it (zenoh `close_face`
    /// drains the departing face's `qabls`), and any query still outstanding on
    /// it must not strand the querier — the router closes it on the departure.
    #[test]
    fn a_departing_queryable_face_frees_the_querier_it_was_answering() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_query(&fwd, 1, 42, "demo/example");
        assert_eq!(captured_requests(&qabl_sink).len(), 1, "the query went out");
        assert!(
            captured_finals(&querier_sink).is_empty(),
            "still outstanding before the departure"
        );

        fwd.deregister(FaceId(0));

        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "the departure closed the query the departed face was answering"
        );
        assert_eq!(
            fwd.pending_query_count(),
            0,
            "and dropped the pending entry with it"
        );
    }

    /// The loop guard, the query twin of
    /// `never_forwards_a_put_back_to_its_source_face`: a face that declares its
    /// own queryable and then queries it is answered locally, never through the
    /// router.
    #[test]
    fn never_routes_a_query_back_to_its_source_face() {
        let fwd = RoutingForwarder::new();
        let (peer, peer_sink) = recording_actions();
        fwd.register(FaceId(0), &peer);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_query(&fwd, 0, 42, "demo/example");

        assert!(
            captured_requests(&peer_sink).is_empty(),
            "a face never receives its own query"
        );
        assert_eq!(
            captured_finals(&peer_sink),
            vec![42],
            "and it is finalized rather than left hanging"
        );
    }

    /// The control-plane half. R311y802 terminated a CURRENT queryable interest
    /// with a bare Final, and its own argument was that advertising a queryable
    /// "would invite a Request no arm answers". That premise is what this round
    /// removes, so the interest now DUMPS the matching queryables ahead of the
    /// Final — the same shape the subscriber and token planes already have.
    #[test]
    fn a_current_queryable_interest_dumps_the_queryables_already_held() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (asker, asker_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &asker);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_built_interest(
            &fwd,
            1,
            wz_session_core::interest_build::build_interest_queryables(
                5,
                true,
                false,
                0,
                Some("demo/**"),
            )
            .expect("queryable interest"),
        );

        let declares = captured_declares(&asker_sink);
        assert_eq!(
            declares.len(),
            2,
            "a queryable declaration then the Final, got {declares:?}"
        );
        assert!(
            matches!(
                declares[0].body,
                DeclareOwnedVariant::CodecZenohDeclQueryable(_)
            ),
            "the held queryable is dumped first, got {:?}",
            declares[0]
        );
        assert!(
            is_decl_final(&declares[1]),
            "and the interest is still terminated"
        );
    }

    /// WHY THE ROUTER MINTS ITS OWN REQUEST ID. A querier's id is unique only
    /// within its own face — two faces routinely both use 0 — so a router that
    /// forwarded the id verbatim could not attribute the replies. This is the
    /// test that makes that claim falsifiable at all: with one querier the
    /// verbatim id works by accident.
    #[test]
    fn mints_its_own_request_id_so_two_queriers_can_share_one() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier_a, sink_a) = recording_actions();
        let (querier_b, sink_b) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier_a);
        fwd.register(FaceId(2), &querier_b);

        declare_qabl(&fwd, 0, 7, "demo/**");
        // BOTH queriers use request id 7 — legal, and indistinguishable to a
        // router that does not re-stamp.
        send_query(&fwd, 1, 7, "demo/a");
        send_query(&fwd, 2, 7, "demo/b");

        let out = captured_requests(&qabl_sink);
        assert_eq!(out.len(), 2, "both queries reached the queryable");
        assert_ne!(
            out[0].0, out[1].0,
            "the router minted DISTINCT ids for two queries that shared one, got {out:?}"
        );

        // Answer the SECOND one only. If the ids had collided, this reply would
        // be attributable to either querier.
        let rid_b = out
            .iter()
            .find(|(_, ke)| ke == "demo/b")
            .expect("the second query went out")
            .0;
        send_reply(&fwd, 0, rid_b, "demo/b", b"b");
        send_final(&fwd, 0, rid_b);

        assert!(
            captured_responses(&sink_a).is_empty(),
            "querier A, which asked for demo/a, received nothing"
        );
        assert_eq!(
            captured_responses(&sink_b),
            vec![(7, String::from("demo/b"))],
            "querier B received its own reply under its own id"
        );
        assert_eq!(
            fwd.pending_query_count(),
            1,
            "querier A's query is still outstanding"
        );
    }

    /// The routed Request must be self-contained. A destination face never saw
    /// the querier's `DeclareKeyexpr`, so an aliased query forwarded verbatim
    /// names an expr-id that face cannot resolve — the query twin of the
    /// `the_relay_emits_no_alias_of_its_own` premise on the Push plane.
    #[test]
    fn re_literalizes_an_aliased_query_for_a_face_that_never_saw_the_alias() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        declare_kexpr(&fwd, 1, 9, "demo/example");
        let request = wz_session_core::request_build::build_request_query(42, 9, None)
            .expect("aliased query request");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(request))],
            has_ext: false,
            extensions: Vec::new(),
        };
        fwd.forward(FaceId(1), IterationEvent::Poll(&outcome));

        let out = captured_requests(&qabl_sink);
        assert_eq!(out.len(), 1, "the aliased query still routed");
        assert_eq!(
            out[0].1, "demo/example",
            "and reached the queryable as a LITERAL keyexpr it can resolve"
        );
    }

    /// A `Response` is honoured only on the face the matching `Request` went to.
    /// The per-face pending map is what makes that true; a table-wide one would
    /// let any peer answer — or poison — another peer's query by guessing an id.
    #[test]
    fn drops_a_reply_from_a_face_that_was_never_sent_the_query() {
        let fwd = RoutingForwarder::new();
        let (qabl, qabl_sink) = recording_actions();
        let (bystander, _bystander_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &qabl);
        fwd.register(FaceId(1), &bystander);
        fwd.register(FaceId(2), &querier);

        declare_qabl(&fwd, 0, 7, "demo/**");
        send_query(&fwd, 2, 42, "demo/example");
        let routed_rid = captured_requests(&qabl_sink)[0].0;

        // The bystander guesses the router-minted id correctly and answers.
        send_reply(&fwd, 1, routed_rid, "demo/example", b"forged");
        send_final(&fwd, 1, routed_rid);

        assert!(
            captured_responses(&querier_sink).is_empty(),
            "a face that was never sent the query cannot answer it"
        );
        assert!(
            captured_finals(&querier_sink).is_empty(),
            "nor close it — the real answerer is still outstanding"
        );
        assert_eq!(fwd.pending_query_count(), 1, "the query is untouched");
    }

    /// The FUTURE half of the advertisement plane: a queryable declared AFTER a
    /// face registered a QUERYABLES interest is pushed to it unsolicited, so its
    /// `Querier` has a remote queryable to match against. A zenoh router
    /// propagates on exactly this gate (`hat/router/queries.rs:255-259`).
    #[test]
    fn a_queryable_declared_later_reaches_a_face_that_asked_for_queryables() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (asker, asker_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &asker);

        send_built_interest(
            &fwd,
            1,
            wz_session_core::interest_build::build_interest_queryables(
                5,
                false,
                true,
                0,
                Some("demo/**"),
            )
            .expect("future queryable interest"),
        );
        declare_qabl(&fwd, 0, 7, "demo/example");

        let declares = captured_declares(&asker_sink);
        assert_eq!(
            declares.len(),
            1,
            "one unsolicited queryable declaration, got {declares:?}"
        );
        assert!(
            matches!(
                declares[0].body,
                DeclareOwnedVariant::CodecZenohDeclQueryable(_)
            ),
            "and it is a DeclQueryable, got {:?}",
            declares[0]
        );
        assert_ne!(
            decl_queryable_id(&declares[0]),
            0,
            "carrying a NON-ZERO id, so the later retraction can name it"
        );
    }

    /// The gate's negative. A face that asked for nothing is told nothing —
    /// otherwise every peer learns every queryable, which is the CLIENT rule,
    /// not the router rule this table follows.
    #[test]
    fn a_face_that_never_asked_for_queryables_is_told_nothing() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (quiet, quiet_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &quiet);

        declare_qabl(&fwd, 0, 7, "demo/example");

        assert!(
            captured_declares(&quiet_sink).is_empty(),
            "an uninterested face heard nothing"
        );
        assert_eq!(fwd.queryable_count(), 1, "but the table recorded it");
    }

    /// The retraction must name the id the advertisement carried — the receiver
    /// keys its remote-queryable table by that id, so a retraction under any
    /// other id leaves a dead queryable in it forever.
    #[test]
    fn an_undeclared_queryable_is_retracted_by_the_id_it_was_advertised_under() {
        let fwd = RoutingForwarder::new();
        let (holder, _holder_sink) = recording_actions();
        let (asker, asker_sink) = recording_actions();
        fwd.register(FaceId(0), &holder);
        fwd.register(FaceId(1), &asker);

        send_built_interest(
            &fwd,
            1,
            wz_session_core::interest_build::build_interest_queryables(
                5,
                false,
                true,
                0,
                Some("demo/**"),
            )
            .expect("future queryable interest"),
        );
        declare_qabl(&fwd, 0, 7, "demo/example");
        let advertised_id = decl_queryable_id(&captured_declares(&asker_sink)[0]);

        undeclare_qabl(&fwd, 0, 7);

        let declares = captured_declares(&asker_sink);
        assert_eq!(declares.len(), 2, "declaration then retraction");
        assert_eq!(
            undecl_queryable_id(&declares[1]),
            advertised_id,
            "the retraction names the advertised id"
        );
        assert_eq!(fwd.queryable_count(), 0, "and the table forgot it");
    }

    // ---------------------------------------------------------------------
    // R311y841 — QueryTarget honoured ROUTE-SIDE.
    //
    // R311y840 shipped the query plane fanning every Query out to EVERY
    // matching queryable, and recorded the target as relayed-verbatim. That is
    // not what a zenoh router does: `compute_final_route`
    // (`zenoh/src/net/routing/dispatcher/queries.rs:205-266`) branches on the
    // target THREE ways, and the branch a stock `z_get` takes by DEFAULT is the
    // one that fans out least.
    // ---------------------------------------------------------------------

    /// Declare a queryable carrying a [`QueryableInfo`] — the `complete` /
    /// `distance` pair a `BestMatching` route selects on. Built through the
    /// PRODUCTION stamp (`set_declare_queryable_info`), so the ext the table
    /// reads is the ext a real peer writes, not a test-only shape.
    fn declare_qabl_info(
        forwarder: &RoutingForwarder,
        face: u64,
        qabl_id: u64,
        keyexpr: &str,
        info: wz_session_core::queryable_info::QueryableInfo,
    ) {
        let mut declare = wz_session_core_test_support::declare_envelope_decl_queryable(
            wz_session_core_test_support::decl_queryable(qabl_id, 0, Some(keyexpr)),
        );
        wz_session_core::declare_build::set_declare_queryable_info(&mut declare, info);
        let outcome = declare_frame(declare);
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// `{ complete: true, distance }` — the shape a queryable that can serve the
    /// whole keyexpr by itself advertises.
    fn complete_at(distance: u16) -> wz_session_core::queryable_info::QueryableInfo {
        wz_session_core::queryable_info::QueryableInfo {
            complete: true,
            distance,
        }
    }

    /// `{ complete: false, distance }` — zenoh's DEFAULT completeness with an
    /// explicit hop count.
    fn partial_at(distance: u16) -> wz_session_core::queryable_info::QueryableInfo {
        wz_session_core::queryable_info::QueryableInfo {
            complete: false,
            distance,
        }
    }

    /// Feed `forwarder` a `Request(Query)` carrying an explicit `ext_target`,
    /// built by the production builder. Note there is deliberately no
    /// `BestMatching` value to pass: pico CLEARS the ext for that case
    /// (`network.c:27`), so the wire default is the plain [`send_query`] above.
    fn send_query_with_target(
        forwarder: &RoutingForwarder,
        face: u64,
        rid: u64,
        keyexpr: &str,
        target: wz_session_core::query_mode::QueryTarget,
    ) {
        let request = wz_session_core::request_build::build_request_query_with_target(
            rid,
            0,
            Some(keyexpr),
            target,
        )
        .expect("literal query request with a target ext");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(request))],
            has_ext: false,
            extensions: Vec::new(),
        };
        forwarder.forward(FaceId(face), IterationEvent::Poll(&outcome));
    }

    /// THE HEADLINE. `BestMatching` is what a `z_get` sends when it asks for
    /// nothing in particular — pico omits the target ext for it entirely — and
    /// zenoh answers it from ONE queryable: `qabls.iter().find(|q| .. info.complete)`
    /// (`dispatcher/queries.rs:243-250`). Fanning it to every match is not a
    /// slower answer, it is a DIFFERENT one: the querier gets N replies where
    /// stock zenoh delivers 1, and every incomplete answerer is woken for a
    /// question the complete one already covers.
    #[test]
    fn a_default_target_query_goes_to_the_one_complete_queryable_not_to_every_match() {
        let fwd = RoutingForwarder::new();
        let (whole, whole_sink) = recording_actions();
        let (partial, partial_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &whole);
        fwd.register(FaceId(1), &partial);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 2, 42, "demo/example");

        assert_eq!(
            captured_requests(&whole_sink).len(),
            1,
            "the COMPLETE queryable is the one BestMatching selects"
        );
        assert!(
            captured_requests(&partial_sink).is_empty(),
            "and the incomplete one is not queried at all, got {:?}",
            captured_requests(&partial_sink)
        );
    }

    /// The other half of zenoh's BestMatching arm, and the half that keeps the
    /// optimisation from becoming a REGRESSION: when nothing is complete there
    /// is no single queryable that can answer, so the route falls back to
    /// `QueryTarget::All` (`dispatcher/queries.rs:252-262`). A router that
    /// picked "the first one" regardless would silently drop answers.
    #[test]
    fn a_default_target_query_falls_back_to_every_match_when_none_is_complete() {
        let fwd = RoutingForwarder::new();
        let (a, a_sink) = recording_actions();
        let (b, b_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", partial_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 2, 42, "demo/example");

        assert_eq!(
            captured_requests(&a_sink).len(),
            1,
            "no complete queryable exists, so BestMatching degrades to All"
        );
        assert_eq!(captured_requests(&b_sink).len(), 1, "for BOTH of them");
    }

    /// zenoh's BestMatching takes the FIRST complete entry out of a set the
    /// router sorted by distance (`hat/router/queries.rs:1520`), so "best" means
    /// NEAREST-complete, not merely any-complete. The witness needs the nearer
    /// queryable declared SECOND, otherwise a first-wins implementation passes.
    #[test]
    fn a_default_target_query_prefers_the_nearest_complete_queryable() {
        let fwd = RoutingForwarder::new();
        let (far, far_sink) = recording_actions();
        let (near, near_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &far);
        fwd.register(FaceId(1), &near);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(5));
        declare_qabl_info(&fwd, 1, 8, "demo/**", complete_at(2));
        send_query(&fwd, 2, 42, "demo/example");

        assert_eq!(
            captured_requests(&near_sink).len(),
            1,
            "the nearer complete queryable wins even though it declared later"
        );
        assert!(
            captured_requests(&far_sink).is_empty(),
            "and the farther one is left alone, got {:?}",
            captured_requests(&far_sink)
        );
    }

    /// `Z_QUERY_TARGET_ALL_COMPLETE` asks every AUTHORITATIVE answerer and no
    /// one else — zenoh filters on `info.complete` and keeps the rest of the
    /// fan-out (`dispatcher/queries.rs:228-241`). Distinct from BestMatching in
    /// exactly one way, which this test pins: TWO complete queryables both get
    /// the query.
    #[test]
    fn an_all_complete_query_reaches_every_complete_queryable_and_no_other() {
        let fwd = RoutingForwarder::new();
        let (whole_a, whole_a_sink) = recording_actions();
        let (whole_b, whole_b_sink) = recording_actions();
        let (partial, partial_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &whole_a);
        fwd.register(FaceId(1), &whole_b);
        fwd.register(FaceId(2), &partial);
        fwd.register(FaceId(3), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 2, 9, "demo/**", partial_at(1));
        send_query_with_target(
            &fwd,
            3,
            42,
            "demo/example",
            wz_session_core::query_mode::QueryTarget::AllComplete,
        );

        assert_eq!(
            captured_requests(&whole_a_sink).len(),
            1,
            "AllComplete is a FILTER, not a selection — both complete ones are asked"
        );
        assert_eq!(captured_requests(&whole_b_sink).len(), 1);
        assert!(
            captured_requests(&partial_sink).is_empty(),
            "the incomplete queryable is filtered out, got {:?}",
            captured_requests(&partial_sink)
        );
    }

    /// The CONTROL for the two filtering tests above: `Z_QUERY_TARGET_ALL`
    /// explicitly asks for everyone, so an implementation that filtered on
    /// completeness unconditionally would red here while passing the rest.
    #[test]
    fn an_all_target_query_reaches_incomplete_queryables_too() {
        let fwd = RoutingForwarder::new();
        let (whole, whole_sink) = recording_actions();
        let (partial, partial_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &whole);
        fwd.register(FaceId(1), &partial);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query_with_target(
            &fwd,
            2,
            42,
            "demo/example",
            wz_session_core::query_mode::QueryTarget::All,
        );

        assert_eq!(captured_requests(&whole_sink).len(), 1);
        assert_eq!(
            captured_requests(&partial_sink).len(),
            1,
            "an explicit All target still fans out to everyone"
        );
    }

    /// COMPLETENESS IS PER-QUERY, NOT PER-QUERYABLE. zenoh computes
    /// `complete && qabl_info.complete` where the left operand is
    /// `DEFAULT_INCLUDER.includes(queryable_ke, queried_ke)`
    /// (`hat/router/queries.rs:1464`): a queryable that only INTERSECTS the
    /// query cannot answer the whole of it however complete it declared itself.
    /// The discriminator is that both halves of this test use the SAME
    /// declaration and differ only in what was asked.
    #[test]
    fn a_complete_queryable_that_only_intersects_the_query_is_not_complete_for_it() {
        // Asked for `demo/*` — `demo/a` intersects it but does not cover it, so
        // the complete flag does not apply and the route degrades to All.
        let fwd = RoutingForwarder::new();
        let (narrow, narrow_sink) = recording_actions();
        let (wide, wide_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &narrow);
        fwd.register(FaceId(1), &wide);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/a", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 2, 42, "demo/*");

        assert_eq!(
            captured_requests(&narrow_sink).len(),
            1,
            "`demo/a` does not COVER `demo/*`, so its complete flag does not select it alone"
        );
        assert_eq!(
            captured_requests(&wide_sink).len(),
            1,
            "and the fan-out therefore degrades to All"
        );

        // The CONTROL, same declarations: asked for `demo/a`, which `demo/a`
        // does cover, the complete flag applies and selects it alone.
        let fwd = RoutingForwarder::new();
        let (narrow, narrow_sink) = recording_actions();
        let (wide, wide_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &narrow);
        fwd.register(FaceId(1), &wide);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/a", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 2, 42, "demo/a");

        assert_eq!(
            captured_requests(&narrow_sink).len(),
            1,
            "`demo/a` covers `demo/a`, so it is complete FOR THIS QUERY"
        );
        assert!(
            captured_requests(&wide_sink).is_empty(),
            "and it answers alone, got {:?}",
            captured_requests(&wide_sink)
        );
    }

    /// A narrowed route must still TERMINATE the querier. The selection changes
    /// how many faces are asked; it must not change the one-final contract or
    /// leak the pending entry.
    #[test]
    fn a_best_matching_query_is_closed_by_the_single_answerer_it_selected() {
        let fwd = RoutingForwarder::new();
        let (whole, whole_sink) = recording_actions();
        let (partial, _partial_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &whole);
        fwd.register(FaceId(1), &partial);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 2, 42, "demo/example");

        let downstream_rid = captured_requests(&whole_sink)[0].0;
        send_reply(&fwd, 0, downstream_rid, "demo/example", b"answer");
        send_final(&fwd, 0, downstream_rid);

        assert_eq!(
            captured_responses(&querier_sink),
            vec![(42, String::from("demo/example"))],
            "the selected queryable's reply reached the querier"
        );
        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "and closed it under its own id"
        );
        assert_eq!(
            fwd.pending_query_count(),
            0,
            "a narrowed route leaves no pending state behind"
        );
        assert_eq!(fwd.queries_routed(), 1);
    }

    /// An `AllComplete` query whose filter empties the route is an EMPTY route,
    /// and R311y840's rule for those is unchanged: answer it now rather than let
    /// the querier wait out its own timeout. The failure this refuses is the
    /// exact one the target filter could newly introduce.
    #[test]
    fn an_all_complete_query_with_no_complete_queryable_is_finalized_immediately() {
        let fwd = RoutingForwarder::new();
        let (a, a_sink) = recording_actions();
        let (b, b_sink) = recording_actions();
        let (querier, querier_sink) = recording_actions();
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", partial_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query_with_target(
            &fwd,
            2,
            42,
            "demo/example",
            wz_session_core::query_mode::QueryTarget::AllComplete,
        );

        assert!(
            captured_requests(&a_sink).is_empty(),
            "no complete queryable, so nobody is asked"
        );
        assert!(captured_requests(&b_sink).is_empty());
        assert_eq!(
            captured_finals(&querier_sink),
            vec![42],
            "and the querier is closed at once rather than hung"
        );
        assert_eq!(fwd.pending_query_count(), 0);
        assert_eq!(fwd.queries_routed(), 0);
    }

    /// The source face is excluded BEFORE completeness is considered — zenoh's
    /// find carries `qabl.direction.0.id != src_face.id` inside the predicate
    /// (`dispatcher/queries.rs:244`). A BestMatching scan written over the whole
    /// face map would select the querier's own queryable and route the query
    /// back to its asker.
    #[test]
    fn a_best_matching_query_never_selects_the_queriers_own_queryable() {
        let fwd = RoutingForwarder::new();
        let (querier, querier_sink) = recording_actions();
        let (other, other_sink) = recording_actions();
        fwd.register(FaceId(0), &querier);
        fwd.register(FaceId(1), &other);

        // The QUERIER holds the only complete queryable.
        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(1));
        declare_qabl_info(&fwd, 1, 8, "demo/**", partial_at(1));
        send_query(&fwd, 0, 42, "demo/example");

        assert!(
            captured_requests(&querier_sink).is_empty(),
            "a query is never routed back to its source, complete or not, got {:?}",
            captured_requests(&querier_sink)
        );
        assert_eq!(
            captured_requests(&other_sink).len(),
            1,
            "so the only candidate is the other face, and All is the fallback"
        );
    }

    /// zenoh's tie-break is its route Vec's insertion order under a STABLE sort;
    /// wz scans a `HashMap` of faces, whose iteration order is randomised per
    /// process, so the selection needs a total order of its own or it is a coin
    /// flip. Twenty queries make a nondeterministic implementation fail with
    /// probability `1 - 2^-19` rather than flake once in a while.
    #[test]
    fn a_tie_between_equally_near_complete_queryables_resolves_deterministically() {
        let fwd = RoutingForwarder::new();
        let (a, a_sink) = recording_actions();
        let (b, b_sink) = recording_actions();
        let (querier, _querier_sink) = recording_actions();
        fwd.register(FaceId(0), &a);
        fwd.register(FaceId(1), &b);
        fwd.register(FaceId(2), &querier);

        declare_qabl_info(&fwd, 0, 7, "demo/**", complete_at(3));
        declare_qabl_info(&fwd, 1, 8, "demo/**", complete_at(3));
        for rid in 0..20u64 {
            send_query(&fwd, 2, rid, "demo/example");
        }

        assert_eq!(
            captured_requests(&a_sink).len(),
            20,
            "every one of the twenty queries picked the SAME tied queryable"
        );
        assert!(
            captured_requests(&b_sink).is_empty(),
            "the tie is broken by face id, not by hash order, got {:?}",
            captured_requests(&b_sink)
        );
    }

    fn decl_queryable_id(d: &DeclareOwned) -> u64 {
        match &d.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(q) => q.id,
            other => panic!("expected a DeclQueryable, got {other:?}"),
        }
    }

    fn undecl_queryable_id(d: &DeclareOwned) -> u64 {
        match &d.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(q) => q.id,
            other => panic!("expected an UndeclQueryable, got {other:?}"),
        }
    }
}
