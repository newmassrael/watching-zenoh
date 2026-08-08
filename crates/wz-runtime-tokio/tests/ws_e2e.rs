// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-ws", feature = "transport-unicast"))]

//! R311ob — wz<->wz session end to end over a real loopback WebSocket link.
//!
//! The WS sibling of `tls_e2e`, but simpler in two ways that reflect WS's
//! nature:
//! - **No cert.** WS needs no TLS material, so there is no config to build.
//! - **Dialed from a LOCATOR.** Unlike TLS (whose `dial_locator` arm is
//!   `Unsupported`), a `ws/...` locator dials directly, so the initiator here
//!   goes through `connect_and_open_session(parse_any_locator("ws/{addr}"))` —
//!   exercising the dial_locator Ws arm end to end (the udp-like dialable
//!   path), not just an explicit `dial_ws`.
//!
//! Two nodes complete the RFC6455 handshake, bring a zenoh session up to
//! Established over the WebSocket, and a `Put` published on the initiator is
//! delivered byte-exact to a subscriber on the acceptor — proving the data
//! plane rides WS BINARY messages (datagram flow: each batch is one WS
//! message, no StreamEnvelope length prefix, the message boundary IS the
//! frame).
//!
//! ## Non-flakiness
//!
//! Loopback TCP under WS: the HTTP-Upgrade handshake + a single small Put are
//! a handful of in-order, loss-free segments on 127.0.0.1. Both sides drive
//! continuously (`None`) until the delivery is observed; the `select!` tears
//! the drives down once it fires, bounded by a ~3s probe budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, bind_locator, connect_and_open_session, dial_locator, AcceptConfig,
    DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::ws_pipeline::accept_ws;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/ws";

/// Two wz nodes handshake over WebSocket (the initiator via a `ws/...`
/// locator), reach Established, and a `Put` published on the initiator is
/// delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_ws_reaches_established_and_delivers_put() {
    let payload = b"ws-framed-hello".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently (the handshake needs both sides
    //    progressing): the acceptor runs the WS server handshake over the
    //    accepted TcpStream; the initiator dials the `ws/...` locator (TCP
    //    connect + WS client handshake) through the generic dial path.
    let acc_open = async {
        let (tcp, _peer) = listener.accept().await.expect("accept tcp");
        let ws = accept_ws(tcp).await.expect("server ws handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Ws(Box::new(ws)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over ws")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("ws/{addr}")).expect("parse ws locator");
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
        .expect("initiator reaches Established over ws")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // Both ends reached Established over the WebSocket.
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over ws"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over ws"
    );

    // ── Subscriber on the acceptor's observer; asserts the delivered payload
    //    byte-for-byte (proving data rides the WS BINARY messages).
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
                "the payload delivered over ws matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote delivery over the WS link).
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
            .expect("ws publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the ws link"
    );
}

/// R311y601 — a `ws/NAME:port` locator resolves on BOTH halves: the acceptor
/// binds `ws/localhost:0` and the dialer reaches it at `ws/localhost:<port>`,
/// completing the RFC6455 upgrade. Before this round the dial half answered
/// `Unsupported` for every non-tcp name ("DNS-name dial is wired only for tcp
/// and udp") and the bind half had no `Proto::Ws` NAME arm reachable without
/// tcp, so neither end of this test could be built.
///
/// Both ends deliberately use the NAME rather than `127.0.0.1`: `localhost`
/// resolves to two addresses on a dual-stack host, the acceptor binds exactly
/// one of them, and the dialer must therefore WALK its candidates to find the
/// one that answers. That walk is the divergence from zenoh (which takes
/// `lookup_host(..).next()` only) and this is the test that exercises it —
/// asserting only "connected" would pass on a first-candidate-only
/// implementation whenever resolution happened to order them agreeably.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_ws_locator_resolves_on_both_the_dial_and_the_bind_half() {
    let mut listener = bind_locator(
        parse_any_locator("ws/localhost:0").expect("parse ws listen locator"),
        &AcceptConfig::default(),
    )
    .await
    .expect("bind ws/localhost:0 — the NAME acceptor arm");
    let port = listener.local_addr().expect("local_addr").port();

    let acc = async move {
        let (accepted, _peer) = listener.accept_raw().await.expect("accept a ws peer");
        accepted
            .handshake()
            .await
            .expect("RFC6455 server upgrade over the named-bound listener")
    };
    let dial = async move {
        let locator =
            parse_any_locator(&format!("ws/localhost:{port}")).expect("parse ws name locator");
        dial_locator(locator, &DialConfig::default())
            .await
            .expect("ws/localhost dial resolves and upgrades")
    };
    let (accepted, dialed) = tokio::join!(acc, dial);

    // `DialedLink` is not `Debug`, so assert by shape rather than equality.
    assert!(
        matches!(dialed, DialedLink::Ws(_)),
        "the named dial produced a WebSocket link, not some other transport"
    );
    assert!(
        matches!(accepted, DialedLink::Ws(_)),
        "the named bind accepted a WebSocket link, not a bare TCP one"
    );
}

/// R311y601 (the discriminator) — a `ws/NAME` that cannot be reached must fail
/// through the RESOLVER or the network, never with `Unsupported`.
///
/// This is the assertion that separates "wired" from "refused", and it is the
/// one that fails on the pre-R311y601 tree: that code answered `Unsupported`
/// for every non-tcp name regardless of whether the name existed, so a test
/// asserting only `is_err()` would have passed unchanged and proved nothing.
/// `.invalid` is the RFC6761 reserved TLD, so a conforming resolver returns
/// NXDOMAIN; a resolver that hijacks NXDOMAIN instead yields an address nothing
/// listens on, and the dial then fails with `ConnectionRefused`. Both are
/// non-`Unsupported`, which is why the assertion is stated that way rather than
/// pinning one kind.
#[tokio::test]
async fn an_unreachable_ws_name_fails_as_a_dial_not_as_an_unsupported_scheme() {
    let locator = parse_any_locator("ws/wz-r311y601-nonexistent.invalid:7447")
        .expect("parse ws name locator");
    let Err(err) = dial_locator(locator, &DialConfig::default()).await else {
        panic!("dialing an unroutable ws name must error, got Ok");
    };
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "a `ws/NAME` dial is WIRED: the failure must come from the resolver or the \
         network, not from the seam refusing the scheme (got {err:?})"
    );
}
