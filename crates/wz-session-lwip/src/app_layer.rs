// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2827 — the MCU session with its application layer attached.
//!
//! [`crate::session_drive`] decodes every inbound frame and hands the batch to
//! its caller's `on_event`, and stops there. Until this module nothing in the
//! MCU stack took it further in production: the only caller counted frames,
//! and the application-layer dispatch (`ApplicationLayerObserver`, the one the
//! AP runs) was reached on the MCU only from tests. A Push therefore had no
//! subscriber to land on and a query no queryable to answer it, however the
//! firmware was written.
//!
//! [`dispatch_to`] is that missing step, as an `on_event` value both session
//! drivers take ([`crate::session_drive::run_session`] and
//! [`crate::session_drive::spawn_session`]): every iteration's event goes to
//! the observer, and whatever the observer staged — replies and their finals,
//! declare replies — goes out through the SAME session's action bundle, which
//! is what the AP's `observer.dispatch(event, &actions)` does.
//!
//! The observer is shared (`Rc<RefCell<..>>`), because the firmware registers
//! its subscribers and queryables on it while the session runs, and a spawned
//! session must own its share. `!Send` is fine: the MCU session runs on a
//! local set, which is the reason the bundle is `Rc` in the first place.

use alloc::rc::Rc;
use core::cell::RefCell;

use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::session_actions::SessionLinkActions;

/// The `on_event` that dispatches each iteration to `observer` and drains its
/// staged output through `actions`, the session's own send path.
///
/// Pass the same `actions` the session is driven with: a reply drained
/// through a different bundle would go out on a different session.
pub fn dispatch_to<C>(
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
) -> impl FnMut(IterationEvent<'_>) + 'static
where
    C: ClockSource + 'static,
{
    move |event| observer.borrow_mut().dispatch(event, &*actions)
}

#[cfg(all(
    test,
    feature = "query-queryable",
    feature = "codec-response",
    feature = "pubsub-put"
))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use wz_codecs::push::{Push, PushVariant};
    use wz_codecs::query::Query;
    use wz_codecs::request::{Request, RequestVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_link_lwip::ipv4_addr_loopback;
    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_session_core::driver_loop::DriverLoopOutcome;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;
    use wz_session_core::WhatAmI;

    use crate::driver::{LwipUdpDriver, SharedSessionSocket};

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    fn params() -> SessionInitParams {
        SessionInitParams {
            version: 0x05,
            whatami: WhatAmI::Peer,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    fn wire(suffix: &str) -> Wireexpr<'_> {
        Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        }
    }

    fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// The whole seam on a real lwIP link: a Push reaches the subscriber the
    /// firmware registered, and a query's reply leaves on the session's own
    /// link. The CONTROL is the same event with no registration: nothing
    /// fires, and the reply's payload is not on the wire. Something IS sent
    /// then — an unanswered query is still terminated with a ResponseFinal,
    /// which is zenoh's behaviour — so the witness is the reply's own bytes,
    /// not the number of datagrams.
    #[test]
    fn a_push_reaches_its_subscriber_and_a_reply_leaves_on_the_session() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let (node_port, peer_port): (u16, u16) = (7471, 7472);
        let node_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, node_port).expect("bind node socket"),
        ));
        let peer_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, peer_port).expect("bind peer socket"),
        ));
        let driver = Rc::new(LwipUdpDriver::new(
            node_socket,
            ipv4_addr_loopback(),
            peer_port,
        ));
        let peer = LwipUdpDriver::new(peer_socket, ipv4_addr_loopback(), node_port);

        let runtime = CoopRuntime::new(FrozenClock);
        let clock = CoopTime::new(&runtime);
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions =
            SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                sink,
                params(),
                clock,
            );

        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let mut on_event = dispatch_to(observer.clone(), actions.clone());
        static PUSHES: AtomicUsize = AtomicUsize::new(0);

        let push = || {
            let mut push = Push {
                keyexpr: wire("home/temp"),
                ..Push::default()
            };
            if let PushVariant::CodecZenohMsgPut(ref mut put) = push.body {
                put.payload_len = 4;
                put.payload = b"21.0";
            }
            NetworkMessage::Push(Box::new(push.try_into_owned().unwrap()))
        };
        let query = || {
            let request = Request {
                rid: 42,
                keyexpr: wire("svc/a"),
                body: RequestVariant::CodecZenohQuery(Query::default()),
                ..Request::default()
            };
            NetworkMessage::Request(Box::new(request.try_into_owned().unwrap()))
        };
        // Whether any datagram the peer received carries the reply payload.
        let peer_saw_pong = || {
            link.poll_loopback();
            link.check_timeouts();
            let mut seen = false;
            while let Some(dg) = peer.try_recv() {
                seen |= dg.data.windows(4).any(|w| w == b"pong");
            }
            seen
        };

        // CONTROL: nothing registered, so nothing fires and no reply leaves.
        on_event(IterationEvent::Poll(&frame(vec![push(), query()])));
        std::assert!(!peer_saw_pong(), "no queryable, no reply payload");
        std::assert_eq!(PUSHES.load(Ordering::SeqCst), 0);

        observer
            .borrow_mut()
            .subscribers
            .register("home/temp", |_| {
                PUSHES.fetch_add(1, Ordering::SeqCst);
            });
        observer
            .borrow_mut()
            .queryables
            .register("svc/a", |_query, responder| {
                responder.reply(b"pong");
            });

        on_event(IterationEvent::Poll(&frame(vec![push(), query()])));
        std::assert_eq!(
            PUSHES.load(Ordering::SeqCst),
            1,
            "the Push reached its subscriber"
        );
        std::assert_eq!(
            observer.borrow().pending_reply_count(),
            0,
            "the staged reply was drained, not left behind"
        );
        std::assert!(peer_saw_pong(), "the reply left on the session's link");
    }
}
