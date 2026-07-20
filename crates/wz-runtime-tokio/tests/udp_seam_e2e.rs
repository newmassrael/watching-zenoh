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
//! UDP has no `accept()` yielding a per-peer socket: there is ONE bound socket,
//! and a unicast link IS that socket addressed to the peer it learns from the
//! first datagram. So the accept seam:
//! - `bind_udp`s the socket into a single-shot `BoundListener::Udp(Some(..))`;
//! - `accept_raw` `take`s the socket out (leaving `None`) and `peek`s the first
//!   datagram's SOURCE to learn the peer WITHOUT consuming the InitSyn — the
//!   datagram stays queued for the read driver's first `recv_from`;
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

/// R311y381 — the SINGLE-SHOT mesh-safety mechanism. `BoundListener::Udp` wraps
/// its socket in an `Option` so `accept_raw` `take`s it: a UDP listener yields
/// EXACTLY ONE link (there is one socket), and a second `accept_raw` finds
/// `None` and errors. This is what keeps a `--listen udp/..` in the mesh loop
/// safe — the first accept is a real IP face, and the second onward is the
/// existing `Step::Accepted(Err)` throttle rather than a spin creating duplicate
/// faces off one shared socket. A shared-socket design (no `Option`) would let
/// the second accept succeed, so this assertion discriminates the single-shot
/// mechanism.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_bound_listener_is_single_shot() {
    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind a udp listener");
    let addr = bound.local_addr().expect("udp listener addr");

    // Send a datagram so the first accept's peek has a source to learn (peek
    // blocks until a datagram arrives).
    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind a throwaway sender");
    sender
        .send_to(b"init-datagram", addr)
        .await
        .expect("send the first datagram");

    // First accept: takes the socket, peeks the sender's source -> an IP peer.
    let (accepted, peer) = bound
        .accept_raw()
        .await
        .expect("the first accept peeks the peer");
    assert!(
        matches!(peer, AcceptedPeer::Ip(_)),
        "a udp accept yields a real IP peer"
    );

    // Second accept: the socket was taken (single-shot) -> Err, NOT a second
    // link off the same socket.
    let second = bound.accept_raw().await;
    assert!(
        second.is_err(),
        "a udp listener yields exactly one link; the second accept errors (single-shot)"
    );

    // The consumed listener's local_addr / display now report the taken state.
    assert!(
        bound.local_addr().is_err(),
        "a consumed udp listener has no addr"
    );

    drop(accepted);
}

/// R311y381 — `accept_raw` is CANCEL-SAFE: a UDP accept that is dropped while its
/// `peek` is still pending (a `select!` in the mesh loop choosing another arm)
/// must NOT consume the listener's socket, so a subsequent accept still works.
/// The fix peeks on the BORROWED socket and `take`s it only after the peek
/// resolves; a `take` BEFORE the await would lose the socket on cancellation and
/// permanently kill the listener — so this test is the discriminator for that
/// ordering (it goes RED under take-before-peek).
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
