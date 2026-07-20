// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-udp", feature = "transport-unicast"))]

//! R311y381 — wz ACCEPTS a session over UDP through the SCHEME-KEYED accept seam
//! (`bind_endpoint("udp/..")` -> `BoundListener::accept_raw` ->
//! `AcceptedLink::handshake`), the acceptor twin of the already-wired dial seam
//! and the FIRST datagram arm of accept-symmetry Stage 4.
//!
//! ## What makes UDP the structurally-hardest arm
//!
//! UDP has no `accept()` yielding a per-peer socket: there is ONE bound socket
//! serving N peers. So the accept seam (R311y382 demux, superseding R311y381's
//! single-shot model):
//! - `bind_udp_demux` binds the socket into a `BoundListener::Udp` and spawns a
//!   pump task that is the sole `recv_from` owner, routing each datagram to its
//!   SOURCE's per-face channel;
//! - `accept_raw` awaits a NEW src on the demux's new-face channel and hands back
//!   an accepted face whose RX is that src's channel (its first datagram — the
//!   InitSyn — pre-queued) and whose TX is the shared listener socket;
//! - the peer is a REAL IP (`AcceptedPeer::Ip`, the datagram source), unlike the
//!   unix/vsock/unixpipe families' anonymous accept.
//!
//! ## Discriminator vs the raw-primitive siblings
//!
//! `udp_frag_e2e` / `udp_chaos_e2e` already drive the RAW peer-learning accept
//! (`UdpSocket::bind` + `peek_from` + a hand-wrapped `DialedLink::Udp`), so they
//! stay GREEN even while the scheme-keyed `bind_locator` returns `Unsupported`
//! for a `udp/..` listen. THIS test binds through `bind_endpoint` — the seam a
//! `--listen udp/..` router uses — so before the Stage 4 arm lands it FAILS at
//! `bind_endpoint`, and after it reaches Established + delivers a `Put`.
//!
//! ## Non-flakiness
//!
//! Loopback UDP does not drop (a single small Put is a handful of in-order,
//! loss-free bytes over the kernel loopback), so the handshake + one Put are
//! deterministic — the same clean-path assumption `udp_frag_e2e` relies on. Both
//! sides drive continuously until the delivery is observed, bounded by a ~3s
//! probe budget. ([[feedback-no-flaky-ever]])

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, bind_endpoint, connect_and_open_session, AcceptedPeer, DialConfig,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/udp-seam";

/// R311y381 — wz ACCEPTS a session over UDP through the scheme-keyed accept seam
/// (`bind_endpoint("udp/..")` -> `BoundListener::accept_raw` ->
/// `AcceptedLink::handshake`). Before the Stage 4 arm lands, `bind_endpoint`
/// returns `Unsupported` for a `udp/..` listen; after, two nodes reach
/// Established over the datagram link and a `Put` is delivered byte-exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_accepts_a_session_over_udp_via_the_bind_endpoint_seam() {
    let payload = b"udp-seam-hello".to_vec();

    // ── The Stage 4 gap: the scheme-keyed listen seam. Before the arm lands
    //    this is `Unsupported` (bind_locator wired only for tcp/ws/tls); after,
    //    it binds the datagram socket into a `BoundListener::Udp`. Bind on an
    //    ephemeral loopback port; UDP's `local_addr` returns the assigned port
    //    (unlike the non-IP families) so the initiator can target it.
    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind_endpoint accepts a udp/ listen (Stage 4 accept seam)");
    assert_eq!(
        bound.transport_name(),
        "udp",
        "the scheme-keyed bind yields a udp listener"
    );
    let addr = bound
        .local_addr()
        .expect("a udp listener HAS a bound IP addr (unlike the non-IP families)");

    let acc_open = async {
        // The pub accept seam: accept one peer (peek the first datagram to learn
        // the source WITHOUT consuming the InitSyn), then run the (no-op for udp)
        // post-accept handshake into the SAME DialedLink the dial side produces.
        let (accepted, peer) = bound
            .accept_raw()
            .await
            .expect("accept_raw peeks the udp peer");
        assert!(
            matches!(peer, AcceptedPeer::Ip(_)),
            "a udp accept yields a REAL IP peer (the datagram source), not NonIp"
        );
        let link = accepted
            .handshake()
            .await
            .expect("udp post-accept handshake (a direct wrap)");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            link,
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over the udp seam")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("udp/{addr}")).expect("parse udp locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over udp")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the udp seam"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over the udp seam"
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
                "the payload delivered over the udp seam matches the Put byte-for-byte"
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
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("udp seam publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the udp seam"
    );
}

/// R311y382 — the DEMUX discriminator (supersedes R311y381's single-shot test).
/// `BoundListener::Udp` is now a multi-peer demux: two senders to one udp listen
/// yield TWO distinct IP faces (`accept_raw` awaits each new src), and the
/// listener's `local_addr` stays available (the pump owns the socket — there is
/// no "consumed" state). The superseded single-shot model held EXACTLY ONE face
/// (a second `accept_raw` `Err`ed — the F2 throttle) and reported `local_addr`
/// as consumed after the first accept; these assertions INVERT that contract,
/// discriminating that the demux (not the single-shot `Option<UdpSocket>`) is
/// wired. If the single-shot model were still in place the second `accept_raw`
/// would `Err` (this test would fail on the `expect`) and `local_addr` would be
/// `Err` after the first accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_listener_demuxes_a_second_peer() {
    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind a udp listener");
    let addr = bound.local_addr().expect("udp listener addr");

    // Two independent senders to the same listen addr.
    let s1 = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender s1");
    let s2 = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender s2");
    let s1_addr = s1.local_addr().expect("s1 addr");
    let s2_addr = s2.local_addr().expect("s2 addr");
    assert_ne!(s1_addr, s2_addr, "two distinct source ports");

    // First src -> first face.
    s1.send_to(b"peer-1", addr).await.expect("s1 send");
    let (accepted1, peer1) = bound.accept_raw().await.expect("first accept");
    assert!(
        matches!(peer1, AcceptedPeer::Ip(_)),
        "a udp accept yields a real IP peer"
    );
    assert_eq!(
        peer1.to_string(),
        s1_addr.to_string(),
        "first face keyed on s1's source"
    );

    // Second src -> a REAL SECOND face (NOT an `Err` — the single-shot F2
    // throttle is retired; the demux keys a fresh face on s2's source).
    s2.send_to(b"peer-2", addr).await.expect("s2 send");
    let (accepted2, peer2) = bound
        .accept_raw()
        .await
        .expect("second accept succeeds (demux, not single-shot Err)");
    assert_eq!(
        peer2.to_string(),
        s2_addr.to_string(),
        "second face keyed on s2's source"
    );
    assert_ne!(
        peer1.to_string(),
        peer2.to_string(),
        "two distinct demuxed peers"
    );

    // The listener keeps its bound addr across accepts (the pump owns the
    // socket; no "consumed" state, unlike the superseded single-shot model).
    assert!(
        bound.local_addr().is_ok(),
        "a demux listener keeps its bound addr across accepts"
    );

    drop(accepted1);
    drop(accepted2);
}

/// R311y382 — `accept_raw` stays CANCEL-SAFE under the demux: a UDP accept
/// dropped while it awaits the next new src (a `select!` in the mesh loop
/// choosing another arm) must NOT lose a subsequently-arriving face, so a later
/// accept still works. Under the demux `accept_raw` is a bare
/// `mpsc::Receiver::recv` (the demux's new-face channel), which tokio documents
/// cancel-safe — a cancelled recv leaves any buffered `NewUdpFace` in the
/// channel. (The superseded single-shot model earned cancel-safety by peeking on
/// a BORROWED socket and taking it only after the peek resolved; the demux earns
/// it for free from the channel.) The pump keeps running across the cancelled
/// accept, so the datagram sent afterwards is learned and delivered as the next
/// face.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_accept_is_cancel_safe_when_dropped_mid_peek() {
    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind a udp listener");
    let addr = bound.local_addr().expect("udp listener addr");

    // No datagram yet, so `accept_raw`'s peek pends. Race it against a short
    // timer that wins, dropping the accept future mid-peek.
    tokio::select! {
        _ = bound.accept_raw() => panic!("no datagram sent; the accept must not complete"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    // The listener MUST have survived the cancelled accept (the socket was not
    // taken). Send a datagram and accept again: success proves the socket is
    // intact. Under take-before-peek the socket would be gone and this errors.
    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a throwaway sender");
    sender
        .send_to(b"after-cancel", addr)
        .await
        .expect("send a datagram after the cancelled accept");
    let (accepted, peer) = bound
        .accept_raw()
        .await
        .expect("the listener survived the cancelled accept (cancel-safe: socket not taken)");
    assert!(
        matches!(peer, AcceptedPeer::Ip(_)),
        "the surviving listener still accepts a real IP peer"
    );
    drop(accepted);
}

/// R311y382 (reviewer-C headline fix) — the one-shot accept path drops the
/// `BoundListener` while an accepted face lives on via the shared pump guard. A
/// THIRD-PARTY datagram from a NEW source arriving at the listen port must NOT
/// tear down the established session. Before the fix the demux pump did `return`
/// on the failed new-face handoff (the listener's `new_face_rx` is gone),
/// dropping its `faces` map and CLOSING the live face's channel -> the acceptor
/// session went `Lost` and the Put never arrived (a 1-packet, spoofable-src DoS).
/// The fix drops the un-acceptable new src and keeps serving the accepted face.
/// This is the discriminator: RED under the pre-fix `return`, GREEN after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_stray_new_src_does_not_tear_down_a_one_shot_session() {
    let payload = b"survives-the-stray".to_vec();

    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind a udp listener");
    let addr = bound.local_addr().expect("udp listener addr");

    // Establish one acceptor<->initiator session over the demux.
    let acc_open = async {
        let (accepted, peer) = bound.accept_raw().await.expect("accept the initiator");
        assert!(matches!(peer, AcceptedPeer::Ip(_)));
        let link = accepted
            .handshake()
            .await
            .expect("udp post-accept handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            link,
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("udp/{addr}")).expect("parse udp locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // The one-shot consume-and-drop: the listener (and its `new_face_rx`) is gone;
    // the pump lives on ONLY via the accepted face's Arc<UdpDemuxPump> clone.
    drop(bound);

    // A stray datagram from a NEW source arrives at the listen port. Under the
    // pre-fix pump this failed the new-face handoff and RETURNED, closing the live
    // face's channel and killing the established session.
    let stray = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a stray sender");
    stray
        .send_to(b"stray-new-src", addr)
        .await
        .expect("send the stray new-src datagram");

    // The established session must survive: a Put from the initiator still reaches
    // the acceptor's subscriber.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.payload(), &expect[..]);
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
        // Give the pump time to process the stray datagram (which pre-fix would
        // have torn the session down) before the Put flows.
        tokio::time::sleep(Duration::from_millis(300)).await;
        publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("publish builds and routes");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("the Put was not delivered within ~3s (session torn down by the stray?)");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive ended (session torn down by the stray datagram)"),
        _ = drive_init => panic!("initiator drive ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "the established one-shot session survived the stray new-src datagram"
    );
}
