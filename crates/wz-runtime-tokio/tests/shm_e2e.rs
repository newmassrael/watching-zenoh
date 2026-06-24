// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "session-extshm",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz scoped shared-memory transport end to end — the negotiated zero-copy
//! data path (R3b finale).
//!
//! The wz mirror of zenoh's SHM payload transfer: both peers OFFER the 0x2 SHM
//! capability on Init, the `&=` merge agrees (`is_shm`), and an SHM-backed Put
//! then carries only the segment DESCRIPTOR (+ the 0x2 ext_shm body marker) over
//! the wire while the bytes stay in /dev/shm — the subscriber mmaps the segment
//! and reads them zero-copy off the shared page. SCOPED: a UNIT capability
//! AND-merge (NOT zenoh's challenge-response), one segment per payload, same-host;
//! cross-impl deferred.
//!
//!   1. `shm_negotiates_and_delivers_put_zero_copy_over_real_tcp` — the
//!      end-to-end proof. Both sides reach Established with `is_shm()` true; the
//!      publisher writes a payload into a /dev/shm segment and `publish_shm`s it;
//!      the descriptor rides the TCP link; the acceptor's `PosixShmResolver` maps
//!      the segment and the subscriber receives the bytes BYTE-EXACT. The wire
//!      carried a descriptor (proven deterministically by the push_build unit
//!      test `build_push_shm_literal_carries_descriptor_and_marker`); here the
//!      byte-exact delivery proves the resolve closes the loop. The publisher
//!      holds the `ShmBackedPayload` alive until delivery (the scoped lifecycle).
//!   2. `shm_negotiation_and_merge` — the deterministic `&=`: both offer -> both
//!      `is_shm()` true; a one-sided offer -> BOTH false (the peer never
//!      reflects), so the data path stays inert.
//!
//! ## Non-flakiness
//! Test 1 is a handful of in-order loopback TCP datagrams + a same-process
//! /dev/shm mmap; the publisher holds the segment until the subscriber's counter
//! increments, bounded by a ~3s probe budget. Test 2 touches no socket.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, new_session_actions, new_session_engine, poll_and_dispatch_one,
    BoxedLinkDriver, SessionLinkActions,
};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_shm, connect_and_open_session_with_shm, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::shm_provider::{PosixShmResolver, ShmBackedPayload};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::{LinkEvent, RxFrame};
use wz_runtime_tokio_test_support::{
    fixture_session_init_params, LifecycleRecordingDriver, QueueDriver,
};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/shm";

fn params(zid_byte: u8) -> wz_session_core::session_init_params::SessionInitParams {
    let mut p = fixture_session_init_params();
    p.zid = vec![zid_byte; 4];
    p
}

/// Test 1 — two wz nodes handshake over loopback TCP, BOTH offering SHM, reach
/// Established with the capability negotiated on, and a Put published from a
/// /dev/shm segment is delivered byte-exact to a subscriber on the acceptor that
/// mmaps the segment off the descriptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shm_negotiates_and_delivers_put_zero_copy_over_real_tcp() {
    let data = b"payload-living-in-dev-shm".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_shm(
            DialedLink::Tcp(stream),
            params(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with SHM offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_shm(
            locator,
            params(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with SHM offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(opened_init.actions.is_shm(), "initiator negotiated SHM on");
    assert!(opened_acc.actions.is_shm(), "acceptor negotiated SHM on");

    // Subscriber on the acceptor + the SHM resolver installed on the SAME registry
    // the drive dispatches through.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    observer
        .subscribers
        .set_shm_resolver(Box::new(PosixShmResolver));
    {
        let fired = fired.clone();
        let expect = data.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the subscriber reads the publisher's bytes off the shared segment"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // The publisher writes the payload into a /dev/shm segment; it MUST outlive
    // the round-trip (the scoped lifecycle — Drop unlinks).
    let mut shm_payload = ShmBackedPayload::alloc(data.len()).expect("alloc /dev/shm segment");
    shm_payload.write(&data);

    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let fired_probe = fired.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let delivered = publisher
            .publish_shm(KEYEXPR, &shm_payload, PublishOptions::put())
            .expect("publish_shm builds the descriptor + routes through the send seam");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
        // shm_payload stays in scope here -> the segment lives across the probe.
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one zero-copy delivery from the SHM Put"
    );
}

/// Drive a complete wz<->wz handshake over recording drivers to Established, with
/// `init_offer` / `resp_offer` controlling each side's SHM offer. Returns the
/// initiator + responder actions. No socket — a deterministic feed.
async fn establish_pair(
    init_offer: bool,
    resp_offer: bool,
) -> (Arc<SessionLinkActions>, Arc<SessionLinkActions>) {
    let init_driver = Arc::new(LifecycleRecordingDriver::default());
    let resp_driver = Arc::new(LifecycleRecordingDriver::default());

    let init_actions = {
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = init_driver.clone();
        let a = new_session_actions(outbound, params(0x01), TokioTime::new());
        if init_offer {
            a.set_shm_offer(true);
        }
        a
    };
    let resp_actions = {
        let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = resp_driver.clone();
        let a = new_session_actions(outbound, params(0x02), TokioTime::new());
        if resp_offer {
            a.set_shm_offer(true);
        }
        a
    };

    let mut init_engine = new_session_engine(&init_actions);
    init_engine.initialize();
    let mut resp_engine = new_session_engine(&resp_actions);
    resp_engine.initialize();

    let last_send =
        |d: &LifecycleRecordingDriver| d.snapshot().sends.last().expect("a send").0.clone();

    resp_engine.process_event(E::InboundStart);
    init_engine.process_event(E::OutboundStart);
    init_engine.process_event(E::LinkOpened);
    let init_syn = last_send(&init_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_syn))]);
    poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;
    let init_ack = last_send(&resp_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(init_ack))]);
    poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;
    let open_syn = last_send(&init_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_syn))]);
    poll_and_dispatch_one(&mut d, &resp_actions, &mut resp_engine).await;
    let open_ack = last_send(&resp_driver);

    let mut d = QueueDriver::with(vec![LinkEvent::Rx(RxFrame::new(open_ack))]);
    poll_and_dispatch_one(&mut d, &init_actions, &mut init_engine).await;

    (init_actions, resp_actions)
}

/// Test 2 — the deterministic negotiation `&=`: both offer -> both on; a
/// one-sided offer leaves BOTH sides off (the peer never reflects), so the data
/// path stays inert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shm_negotiation_and_merge() {
    let (init, resp) = establish_pair(true, true).await;
    assert!(init.is_shm(), "initiator negotiated SHM on");
    assert!(resp.is_shm(), "acceptor negotiated SHM on");

    let (init_one, resp_one) = establish_pair(true, false).await;
    assert!(
        !init_one.is_shm(),
        "a one-sided offer leaves the initiator off (peer did not reflect)"
    );
    assert!(
        !resp_one.is_shm(),
        "the responder never offered, so it stays off"
    );
}
