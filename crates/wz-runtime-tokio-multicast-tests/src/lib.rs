// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mo (Level B) — isolated multicast-only runtime tests for the tokio
//! profile's `Session` API.
//!
//! `wz-runtime-tokio`'s own `cargo test` cannot reach the multicast-only
//! `Session` API ([`Session::new_multicast`] / the multicast
//! `Session::publish`, both gated `not(transport-unicast)`): its
//! `wz-runtime-tokio-test-support` dev-dependency depends on `wz-runtime-tokio`
//! with `transport-unicast`, so `cargo test`'s feature unification forces
//! `transport-unicast` ON and the multicast-only items are `cfg`'d out. This
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

    use wz_runtime_tokio::multicast_glue::MulticastTxItem;
    use wz_runtime_tokio::observer::ApplicationLayerObserver;
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session::Session;

    /// A multicast `Session::publish` builds a `MulticastTxItem::Push` (Put)
    /// and enqueues exactly one onto the TX seam the drive loop drains — the
    /// multicast analogue of the unicast publish wire leg, proving the unified
    /// `Session` API reaches the multicast transport (the Level B north star).
    /// The drive-loop framing of that queued item is covered separately by
    /// `wz_runtime_tokio::multicast_glue`'s
    /// `drive_loop_frames_queued_push` test; this asserts the new B3 wiring —
    /// `publish` builds the right item and enqueues it onto the session's
    /// transport sender.
    #[test]
    fn multicast_session_publish_enqueues_one_put_push() {
        // The Session owns the sender; the drive loop would drain the receiver.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
        let session: Session = Session::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            tx,
        );

        session
            .publish("demo/mc", b"hello-multicast")
            .expect("multicast Put builds within codec capacity");

        let item = rx.try_recv().expect("publish enqueued one tx item");
        assert!(
            matches!(item, MulticastTxItem::Push { .. }),
            "the enqueued multicast item is a Put Push"
        );
        assert!(
            rx.try_recv().is_err(),
            "publish enqueued exactly one item (no duplicate)"
        );
    }

    /// R311mp (B4) — a multicast `Session` declares a subscriber through the
    /// now-transport-agnostic `Session::declare_subscriber`, and a
    /// `Session::publish` delivers the Put to that local subscriber via the
    /// loopback leg (`pubsub-allow-loop`) — exactly the unicast publish
    /// loopback contract, proving the multicast `Session` gained the subscriber
    /// surface (the B4 north star) while the remote leg still enqueues onto the
    /// TX seam. The callback fires on the caller thread (deferred-fire drain
    /// inside `publish`), so the count is observable synchronously.
    #[test]
    fn multicast_session_publish_loops_back_to_declared_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wz_runtime_tokio::session::SubscribeOptions;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
        let session: Session = Session::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            tx,
        );

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
            .publish("demo/mc", b"loop-me")
            .expect("multicast Put builds within codec capacity");

        // Loopback leg: exactly one local subscriber callback fired.
        assert_eq!(delivered, 1, "one local subscriber fired via loopback");
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "the deferred callback ran synchronously inside publish"
        );

        // Remote leg still enqueued the Put onto the TX seam (both legs run).
        let item = rx.try_recv().expect("remote leg enqueued the Put");
        assert!(
            matches!(item, MulticastTxItem::Push { .. }),
            "the enqueued multicast item is a Put Push"
        );

        // A non-matching keyexpr fires no local subscriber.
        let none = session.publish("other/key", b"nope").expect("Put builds");
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
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::push_build::build_push_literal;

        // No TX seam exercised here (the receiver is dropped); the proof is the
        // RX dispatch path into the Session's subscriber registry.
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
        let session: Session = Session::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            tx,
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
}
