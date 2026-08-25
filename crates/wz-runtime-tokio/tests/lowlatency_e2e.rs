// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-lowlatency",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz lowlatency transport end to end — the negotiated lean data path.
//!
//! The wz mirror of zenoh's lowlatency unicast transport
//! (`init.rs:162 zextunit!(0x5,false)`): both peers OFFER the Z_EXT_LOWLATENCY
//! unit ext on InitSyn / InitAck, the `&=` merge agrees, and the established
//! session drops the Frame(sn) wrapper + fragmentation, serializing the bare
//! NetworkMessage directly (zenoh `TransportMessageLowLatencyRef::Network`).
//!
//! Two complementary proofs:
//!
//!   1. `lowlatency_negotiates_and_delivers_put_over_real_tcp` — the end-to-end
//!      proof over a real TCP loopback. Both sides reach Established with
//!      `is_lowlatency()` true, and a `Put` is delivered byte-exact. Since the
//!      tx seam is `if is_lowlatency() { lean; return }`, a true flag FORCES the
//!      lean wire; and a lean Put (leading id 0x1D, not a Frame) would tear the
//!      peer down on the universal path — so a successful delivery with the flag
//!      asserted proves BOTH the lean tx AND the lean rx engaged.
//!   2. `lowlatency_put_rides_a_bare_network_message_not_a_frame` — the
//!      deterministic, socket-free distinguishing proof: drive the handshake
//!      over recording drivers, publish, and inspect the captured wire. With
//!      lowlatency the Put's leading id is `N_MID_PUSH` (0x1D, a bare network
//!      message); the no-offer CONTROL wraps it in `T_MID_FRAME` (0x05). Plus
//!      the negotiation `&=`: a one-sided offer leaves BOTH sides universal.
//!
//! ## Non-flakiness
//!
//! Test 1 is a handful of in-order, loss-free datagrams on 127.0.0.1 (TCP
//! retransmits); both sides drive continuously until the delivery is observed,
//! bounded by a ~3s probe budget. Test 2 touches no socket and no clock — it is
//! a deterministic feed of each side's captured bytes into the other.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_codecs::wire_const;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_lowlatency, connect_and_open_session_with_lowlatency, DialConfig,
    DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{
    establish_capability_pair, fixture_params_with_zid, LifecycleRecordingDriver,
};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/lowlatency";

/// The most recent outbound frame the recording driver captured.
fn last_send(driver: &LifecycleRecordingDriver) -> Vec<u8> {
    driver
        .snapshot()
        .sends
        .last()
        .expect("a send was recorded")
        .0
        .clone()
}

/// Test 1 — two wz nodes handshake over a loopback TCP link, BOTH offering
/// lowlatency, reach Established with the capability negotiated on, and a `Put`
/// published on the initiator is delivered byte-exact to a subscriber on the
/// acceptor — over the lean (no-Frame) wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_negotiates_and_delivers_put_over_real_tcp() {
    let payload = b"lean-no-frame-hello".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently, each offering lowlatency.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_lowlatency(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with lowlatency offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_lowlatency(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with lowlatency offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // The negotiation succeeded on BOTH sides (the `&=` of two true offers).
    assert!(
        opened_init.actions.is_lowlatency(),
        "initiator negotiated lowlatency on"
    );
    assert!(
        opened_acc.actions.is_lowlatency(),
        "acceptor negotiated lowlatency on"
    );

    // ── Subscriber on the acceptor; asserts the delivered payload byte-exact.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the payload delivered over the lean wire matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

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
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("lowlatency publish builds and routes through the lean send seam");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one delivery from the Put over the lean lowlatency wire"
    );
}

/// Publish a Put on `actions` and return its captured outbound wire bytes.
fn publish_and_capture(
    actions: &Arc<SessionLinkActions>,
    driver: &LifecycleRecordingDriver,
) -> Vec<u8> {
    let session = TokioSession::new(
        actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish(KEYEXPR, b"payload", PublishOptions::put())
        .expect("publish on an established session");
    last_send(driver)
}

/// Test 2 — the distinguishing wire-form proof. With lowlatency negotiated, the
/// Put's leading message id is a BARE NetworkMessage (`N_MID_PUSH`); without the
/// offer, the same Put is wrapped in a `T_MID_FRAME`. Plus the negotiation `&=`:
/// a one-sided offer leaves BOTH sides universal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowlatency_put_rides_a_bare_network_message_not_a_frame() {
    let offer = |a: &Arc<SessionLinkActions>| {
        a.set_lowlatency_offer(true);
    };

    // Both offer -> negotiated on -> lean Put (leading id N_MID_PUSH, no Frame).
    let both = establish_capability_pair(true, true, offer).await;
    assert!(
        both.init_actions.is_lowlatency(),
        "initiator negotiated lowlatency on"
    );
    assert!(
        both.resp_actions.is_lowlatency(),
        "acceptor negotiated lowlatency on"
    );
    let lean = publish_and_capture(&both.init_actions, &both.init_driver);
    assert_eq!(
        lean[0] & 0x1F,
        wire_const::N_MID_PUSH,
        "the lowlatency Put rides a bare NetworkMessage (N_MID_PUSH), NO Frame wrapper"
    );

    // CONTROL: neither offers -> universal -> the Put is Frame-wrapped.
    let none = establish_capability_pair(false, false, offer).await;
    assert!(
        !none.init_actions.is_lowlatency(),
        "initiator stays universal"
    );
    assert!(
        !none.resp_actions.is_lowlatency(),
        "acceptor stays universal"
    );
    let framed = publish_and_capture(&none.init_actions, &none.init_driver);
    assert_eq!(
        framed[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "without lowlatency the Put is wrapped in a T_MID_FRAME (the universal path)"
    );

    // NEGOTIATION `&=`: only the initiator offers -> the responder never
    // reflects, so BOTH finalize universal (zenoh `is_lowlatency &= other`).
    let one = establish_capability_pair(true, false, offer).await;
    assert!(
        !one.init_actions.is_lowlatency(),
        "a one-sided offer leaves the initiator universal (peer did not reflect)"
    );
    assert!(
        !one.resp_actions.is_lowlatency(),
        "the responder never offered, so it stays universal"
    );
}
