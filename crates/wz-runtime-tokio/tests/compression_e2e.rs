// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "session-extcompression",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz transport compression end to end — the negotiated lz4 batch wrap.
//!
//! The wz mirror of zenoh's per-batch compression (`init.rs:168
//! zextunit!(0x6,false)` + `batch.rs`): both peers OFFER the Z_EXT_COMPRESSION
//! unit ext on InitSyn / InitAck, the `&=` merge agrees, and every
//! post-establishment batch is lz4-wrapped as `[BatchHeader][payload]` (the
//! compressed form kept only when smaller). Handshake messages stay
//! uncompressed (zenoh sets the link's is_compression only after establishment).
//!
//! Two complementary proofs:
//!
//!   1. `compression_negotiates_and_delivers_put_over_real_tcp` — the end-to-end
//!      proof over real TCP. Both sides reach Established with `is_compression()`
//!      true, and a (compressible) `Put` is delivered byte-exact. Since the tx
//!      seam compresses iff `is_compression() && is_established()`, and the rx
//!      seam decompresses under the same gate, a successful byte-exact delivery
//!      proves the lz4 round-trip end to end.
//!   2. `compression_put_rides_a_batch_header_not_a_bare_frame` — the
//!      deterministic, socket-free distinguishing proof: drive the handshake over
//!      recording drivers, publish a COMPRESSIBLE Put, and inspect the captured
//!      wire. With compression the batch's leading byte is the BatchHeader with
//!      the COMPRESSION bit set (0x01); the no-offer CONTROL ships a bare
//!      T_MID_FRAME (0x05). Plus the negotiation `&=`: a one-sided offer leaves
//!      BOTH sides uncompressed.

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
    accept_and_open_session_with_compression, connect_and_open_session_with_compression,
    DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::{
    establish_capability_pair, fixture_params_with_zid, LifecycleRecordingDriver,
};
use wz_session_core::compression::{decompress_batch, BATCH_HEADER_COMPRESSION};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/compression";

/// A highly compressible payload (repeated bytes) so the batch shrinks and the
/// COMPRESSION bit is set.
fn compressible_payload() -> Vec<u8> {
    vec![0xABu8; 4096]
}

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
/// compression, reach Established with the capability negotiated on, and a
/// compressible `Put` is delivered byte-exact to a subscriber on the acceptor —
/// proving the lz4 wrap + un-wrap round-trips end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compression_negotiates_and_delivers_put_over_real_tcp() {
    let payload = compressible_payload();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_compression(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with compression offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_compression(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with compression offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.is_compression(),
        "initiator negotiated compression on"
    );
    assert!(
        opened_acc.actions.is_compression(),
        "acceptor negotiated compression on"
    );

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
                "the payload delivered through the lz4 wrap matches the Put byte-for-byte"
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
            .expect("compression publish builds and routes through the lz4 send seam");
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
        "exactly one delivery from the Put over the compressed wire"
    );
}

/// Publish a Put on `actions` and return its captured outbound wire bytes.
fn publish_and_capture(
    actions: &Arc<SessionLinkActions>,
    driver: &LifecycleRecordingDriver,
    payload: &[u8],
) -> Vec<u8> {
    let session = TokioSession::new(
        actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );
    session
        .publish(KEYEXPR, payload, PublishOptions::put())
        .expect("publish on an established session");
    last_send(driver)
}

/// Test 2 — the distinguishing wire-form proof. With compression negotiated, the
/// Put's batch leads with the BatchHeader (COMPRESSION bit set) and the payload
/// after it decompresses back to a valid frame; without the offer, the same Put
/// ships as a bare T_MID_FRAME. Plus the negotiation `&=`: a one-sided offer
/// leaves BOTH sides uncompressed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compression_put_rides_a_batch_header_not_a_bare_frame() {
    let payload = compressible_payload();

    let offer = |a: &Arc<SessionLinkActions>| {
        a.set_compression_offer(true);
    };

    // Both offer -> negotiated on -> the Put batch leads with the COMPRESSION
    // BatchHeader, and the lz4 payload decompresses back to a T_MID_FRAME.
    let both = establish_capability_pair(true, true, offer).await;
    assert!(
        both.init_actions.is_compression(),
        "initiator negotiated compression on"
    );
    assert!(
        both.resp_actions.is_compression(),
        "acceptor negotiated compression on"
    );
    let wire = publish_and_capture(&both.init_actions, &both.init_driver, &payload);
    assert_eq!(
        wire[0], BATCH_HEADER_COMPRESSION,
        "the compressible Put batch leads with the COMPRESSION BatchHeader (0x01)"
    );
    let decompressed = decompress_batch(&wire, 65536).expect("the batch decompresses");
    assert_eq!(
        decompressed[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "the decompressed batch is a universal T_MID_FRAME carrying the Put"
    );

    // CONTROL: neither offers -> the Put ships as a bare uncompressed T_MID_FRAME
    // (no BatchHeader prefix at all).
    let none = establish_capability_pair(false, false, offer).await;
    assert!(
        !none.init_actions.is_compression(),
        "initiator stays uncompressed"
    );
    assert!(
        !none.resp_actions.is_compression(),
        "acceptor stays uncompressed"
    );
    let raw = publish_and_capture(&none.init_actions, &none.init_driver, &payload);
    assert_eq!(
        raw[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "without compression the Put is a bare T_MID_FRAME (no BatchHeader)"
    );

    // NEGOTIATION `&=`: only the initiator offers -> the responder never reflects,
    // so BOTH finalize uncompressed (zenoh `is_compression &= other`).
    let one = establish_capability_pair(true, false, offer).await;
    assert!(
        !one.init_actions.is_compression(),
        "a one-sided offer leaves the initiator uncompressed (peer did not reflect)"
    );
    assert!(
        !one.resp_actions.is_compression(),
        "the responder never offered, so it stays uncompressed"
    );
}
