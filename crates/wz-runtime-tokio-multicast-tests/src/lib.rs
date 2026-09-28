// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mo (Level B) — isolated multicast-only runtime tests for the tokio
//! profile's `Session` API.
//!
//! `wz-runtime-tokio`'s own `cargo test` cannot reach the multicast-only
//! `Session` API (`Session::new_multicast`, gated `not(transport-unicast)`;
//! and the now-unified transport-agnostic `Session::publish` exercised against
//! a multicast transport): its `wz-runtime-tokio-test-support` dev-dependency
//! depends on `wz-runtime-tokio` with `transport-unicast`, so `cargo test`'s
//! feature unification forces `transport-unicast` ON and the multicast-only
//! constructor is `cfg`'d out. This
//! crate pulls `wz-runtime-tokio` with ONLY `transport-multicast,codec-push`
//! (no test-support, no unicast) as a dev-dependency, so — built ISOLATED via
//! `cargo test -p` (Layer C1s; excluded from the C1/C2 `--workspace`
//! unification, the same feature-leak hazard the wz-mcu-* crates carry) — the
//! multicast `Session` surface is reachable and runtime-testable.
//!
//! The library is intentionally empty; the proof lives in the test module.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wz_runtime_tokio::multicast_glue::MulticastTxTap;
    use wz_runtime_tokio::observer::ApplicationLayerObserver;
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session::{PublishOptions, TokioMulticastSession};
    use wz_session_core::network_message::NetworkMessage;

    /// R2937 — a multicast `Session` over a group whose pipeline the test
    /// reads: the session pushes onto it on the caller's thread, and what it
    /// pushed is read back as the group datagrams a transmit task would write.
    fn tapped_session() -> (TokioMulticastSession, MulticastTxTap) {
        let params = wz_session_core::multicast_params::MulticastParams {
            version: 0x09,
            whatami: wz_session_core::WhatAmI::Peer,
            zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
            lease_ms: 5_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        };
        let (producer, tap) = MulticastTxTap::attach(&params);
        let session = TokioMulticastSession::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            producer,
        );
        (session, tap)
    }

    /// The network messages in the next group datagram, if one was pushed.
    fn next_pushed(tap: &mut MulticastTxTap) -> Option<Vec<NetworkMessage>> {
        use wz_session_core::inbound::{parse_inbound, InboundFrame};
        let datagram = tap.try_next()?;
        let Ok(InboundFrame::Frame { payload, .. }) = parse_inbound(&datagram) else {
            panic!("a pushed datagram that is not a Frame");
        };
        Some(
            wz_session_core::network_message::parse_frame_payload(&payload)
                .expect("the pushed frame's payload parses"),
        )
    }

    /// A multicast `Session::publish` builds a Put Push and pushes exactly one
    /// onto the group — the multicast analogue of the unicast publish wire leg,
    /// proving the unified `Session` API reaches the multicast transport (the
    /// Level B north star). The drive loop's side of that pipeline is covered
    /// separately by `wz_runtime_tokio::multicast_glue`'s
    /// `drive_loop_frames_queued_push` test; this asserts the B3 wiring —
    /// `publish` builds the right message and pushes it through the session's
    /// transport producer (R2937).
    #[test]
    fn multicast_session_publish_enqueues_one_put_push() {
        let (session, mut tap) = tapped_session();

        session
            .publish("demo/mc", b"hello-multicast", PublishOptions::put())
            .expect("multicast Put builds within codec capacity");

        let messages = next_pushed(&mut tap).expect("publish pushed one datagram");
        assert!(
            matches!(messages.as_slice(), [NetworkMessage::Push(_)]),
            "the pushed multicast message is a Put Push"
        );
        assert!(
            next_pushed(&mut tap).is_none(),
            "publish pushed exactly one datagram (no duplicate)"
        );
    }

    /// R311mp (B4) — a multicast `Session` declares a subscriber through the
    /// now-transport-agnostic `Session::declare_subscriber`, and a
    /// `Session::publish` delivers the Put to that local subscriber via the
    /// loopback leg (`pubsub-allow-loop`) — exactly the unicast publish
    /// loopback contract, proving the multicast `Session` gained the subscriber
    /// surface (the B4 north star) while the remote leg still pushes onto the
    /// group. The callback fires on the caller thread (deferred-fire drain
    /// inside `publish`), so the count is observable synchronously.
    #[test]
    fn multicast_session_publish_loops_back_to_declared_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wz_runtime_tokio::session::SubscribeOptions;

        let (session, mut tap) = tapped_session();

        let fired = Arc::new(AtomicUsize::new(0));
        let sub = {
            let fired = fired.clone();
            session.declare_subscriber("demo/mc", SubscribeOptions::new(), move |sample| {
                assert_eq!(sample.keyexpr(), "demo/mc");
                assert_eq!(sample.payload(), b"loop-me");
                fired.fetch_add(1, Ordering::SeqCst);
            })
        };

        let delivered = session
            .publish("demo/mc", b"loop-me", PublishOptions::put())
            .expect("multicast Put builds within codec capacity");

        // Loopback leg: exactly one local subscriber callback fired.
        assert_eq!(delivered, 1, "one local subscriber fired via loopback");
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "the deferred callback ran synchronously inside publish"
        );

        // Remote leg still pushed the Put onto the group (both legs run).
        let messages = next_pushed(&mut tap).expect("remote leg pushed the Put");
        assert!(
            matches!(messages.as_slice(), [NetworkMessage::Push(_)]),
            "the pushed multicast message is a Put Push"
        );

        // A non-matching keyexpr fires no local subscriber.
        let none = session
            .publish("other/key", b"nope", PublishOptions::put())
            .expect("Put builds");
        assert_eq!(none, 0, "no subscriber matches other/key");

        drop(sub);
    }

    /// R311mq (B5a) — wiring the multicast drive loop's dispatch into a
    /// Session's observer + fires connects a `Session::declare_subscriber`'d
    /// deferred subscriber to wire-arrived multicast Frames. Feeding the B5a
    /// dispatch SSOT (`dispatch_multicast_iteration_event`) the IterationEvent
    /// a Push Frame produces fires the subscriber exactly once: the deferred
    /// staging sink stages onto the session's fires, and the SSOT drains it
    /// after the observer lock drops. B4 left this wire-RX leg unconnected
    /// (the standalone drive loop dispatched into a free-standing observer and
    /// never drained the session's queue), so a Session-declared deferred
    /// subscriber saw loopback Puts but not wire ones until B5a.
    #[test]
    fn multicast_dispatch_event_fires_declared_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wz_runtime_tokio::session::SubscribeOptions;
        use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
        use wz_session_core::push_build::build_push_literal;

        // No TX side exercised here (a producer no loop ever attaches); the
        // proof is the RX dispatch path into the Session's subscriber registry.
        let session: TokioMulticastSession = TokioMulticastSession::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            wz_runtime_tokio::multicast_glue::MulticastTxProducer::new(),
        );

        let fired = Arc::new(AtomicUsize::new(0));
        let sub = {
            let fired = fired.clone();
            session.declare_subscriber("demo/mc", SubscribeOptions::new(), move |sample| {
                assert_eq!(sample.keyexpr(), "demo/mc");
                assert_eq!(sample.payload(), b"wire-rx");
                fired.fetch_add(1, Ordering::SeqCst);
            })
        };

        // The IterationEvent a wire Push Frame produces: a FramePayload batch
        // carrying one NetworkMessage::Push built through the production
        // builder so the fixture cannot drift from the wire shape.
        let push = build_push_literal("demo/mc", b"wire-rx").expect("push fixture");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: std::vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        };
        session.dispatch_multicast_iteration_event(IterationEvent::Poll(&outcome));

        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "the wire Push reached the Session-declared subscriber exactly once"
        );
        drop(sub);
    }

    /// R311mr (B5b-1) — the transport-dispatch send seam
    /// (`Session::send_network_message`, the `_z_send_n_msg` analogue) routes a
    /// built `NetworkMessage::Push` to the multicast group directly. This is
    /// the path `Session::publish` now sends through; testing the seam in
    /// isolation pins the public send entry point independent of `publish`.
    #[test]
    fn multicast_send_network_message_routes_push_to_channel() {
        use wz_session_core::push_build::build_push_literal;

        let (session, mut tap) = tapped_session();

        let push = build_push_literal("demo/mc", b"via-seam").expect("push fixture");
        session
            .send_network_message(NetworkMessage::Push(Box::new(push)), true, false)
            .expect("the seam routes a Push to the multicast group");

        let messages = next_pushed(&mut tap).expect("the seam pushed the Push");
        assert!(
            matches!(messages.as_slice(), [NetworkMessage::Push(_)]),
            "the pushed message is a Put Push"
        );
        assert!(
            next_pushed(&mut tap).is_none(),
            "exactly one datagram pushed"
        );
    }
}
