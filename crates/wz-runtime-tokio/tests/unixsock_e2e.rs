// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-unixsock", feature = "transport-unicast"))]

//! R311xi — wz<->wz session end to end over a real loopback unix-domain socket.
//!
//! The unixsock sibling of `ws_e2e` / `tls_e2e`, and the SIMPLEST of the three
//! because a unix socket needs neither a cert (unlike TLS) nor a protocol
//! handshake at accept time (unlike WS's RFC6455 upgrade): an accepted
//! `UnixStream` is wrapped DIRECTLY as `DialedLink::Unixsock`, and the
//! initiator dials a `unixsock-stream/...` locator straight through
//! `connect_and_open_session` (no `DialConfig`, like ws/udp). This exercises:
//! - the locator leaf end to end (`parse_any_locator("unixsock-stream/{path}")`
//!   -> `AnyLocator::Unixsock` -> the `dial_locator` Unixsock arm), and
//! - the `unixsock_pipeline` dial/bind/accept + `wire_unixsock_stream`
//!   StreamEnvelope split (the same `stream_link` SSOT as TCP/TLS).
//!
//! Two nodes bring a zenoh session up to Established over the unix socket, and
//! a `Put` published on the initiator is delivered byte-exact to a subscriber
//! on the acceptor — proving the data plane rides the StreamEnvelope-framed
//! unix byte stream exactly as it does over TCP.
//!
//! ## Non-flakiness
//!
//! Loopback unix domain socket: a single small Put is a handful of in-order,
//! loss-free bytes over kernel IPC (more reliable than even loopback TCP — no
//! network stack). Both sides drive continuously (`None`) until the delivery is
//! observed; the `select!` tears the drives down once it fires, bounded by a
//! ~3s probe budget. The socket path is unique per process and the bind unlinks
//! any stale file, so concurrent test runs do not collide.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, bind_endpoint, connect_and_open_session, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::unixsock_pipeline::{accept_unixsock_on, bind_unixsock};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/unixsock";

/// A unique unix-socket path under the system temp dir (kept short for the
/// ~108-byte path limit; the pid makes it unique across concurrent runs).
fn unique_sock_path() -> String {
    std::env::temp_dir()
        .join(format!("wz-unixsock-e2e-{}.sock", std::process::id()))
        .to_str()
        .expect("utf-8 temp path")
        .to_string()
}

/// Two wz nodes handshake over a unix domain socket (the initiator via a
/// `unixsock-stream/...` locator), reach Established, and a `Put` published on
/// the initiator is delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_unixsock_reaches_established_and_delivers_put() {
    let payload = b"unixsock-framed-hello".to_vec();

    let path = unique_sock_path();
    // Bind BEFORE the initiator dials so the socket file exists race-free (the
    // unixsock mirror of ws_e2e binding its TcpListener before the join).
    let listener = bind_unixsock(&path).await.expect("bind unixsock listener");

    // ── Open BOTH sessions concurrently (the handshake needs both sides
    //    progressing): the acceptor accepts the inbound `UnixStream` and wraps
    //    it directly (no accept-time handshake); the initiator dials the
    //    `unixsock-stream/...` locator through the generic dial path.
    let acc_open = async {
        let stream = accept_unixsock_on(&listener)
            .await
            .expect("accept unixsock peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Unixsock(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over unixsock")
    };
    let init_open = async {
        let locator =
            parse_any_locator(&format!("unixsock-stream/{path}")).expect("parse unixsock locator");
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
        .expect("initiator reaches Established over unixsock")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // Both ends reached Established over the unix socket.
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over unixsock"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over unixsock"
    );

    // ── Subscriber on the acceptor's observer; asserts the delivered payload
    //    byte-for-byte (proving data rides the StreamEnvelope-framed unix stream).
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
                "the payload delivered over unixsock matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote delivery over the unix link).
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
            .expect("unixsock publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the unixsock link"
    );

    // Hygiene: unlink the socket file (a unix listener does not auto-unlink on
    // drop). `listener` is still owned here; it drops at function end.
    drop(listener);
    let _ = std::fs::remove_file(&path);
}

/// A unique unix-socket path for the accept-seam test (a distinct suffix from
/// [`unique_sock_path`] so the two tests never share a socket file within one
/// process).
fn unique_seam_sock_path() -> String {
    std::env::temp_dir()
        .join(format!("wz-unixsock-seam-{}.sock", std::process::id()))
        .to_str()
        .expect("utf-8 temp path")
        .to_string()
}

/// R311y378 (accept-symmetry Stage 4) — wz ACCEPTS a session over unixsock
/// through the SCHEME-KEYED accept seam (`bind_endpoint("unixsock-stream/..")`
/// -> `BoundListener::accept_raw` -> `AcceptedLink::handshake`), the acceptor
/// twin of the already-wired dial seam `dial_endpoint("unixsock-stream/..")`.
///
/// This is the DISCRIMINATOR the sibling
/// [`wz_to_wz_over_unixsock_reaches_established_and_delivers_put`] cannot be:
/// that test drives the RAW primitives (`bind_unixsock` / `accept_unixsock_on`
/// + a hand-wrapped `DialedLink::Unixsock`), so it stays GREEN even while the
/// scheme-keyed `bind_locator` returns `Unsupported` for `AnyLocator::Unixsock`.
/// THIS test binds through `bind_endpoint` — the seam a `--listen
/// unixsock-stream/..` router/acceptor uses — so before the Stage 4 arm lands it
/// FAILS at `bind_endpoint` (the seam is tcp/ws/tls-only), and after it reaches
/// Established + delivers a `Put`, exactly like the tcp/ws/tls acceptors.
///
/// Bind happens BEFORE the initiator dials (the socket file must exist
/// race-free), so `bind_endpoint` is split from the accept, then accept + dial
/// run concurrently — the unixsock mirror of the stream-family seam tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_accepts_a_session_over_unixsock_via_the_bind_endpoint_seam() {
    let payload = b"unixsock-seam-hello".to_vec();
    let path = unique_seam_sock_path();

    // ── The Stage 4 gap: the scheme-keyed listen seam. Before the arm lands
    //    this is `Unsupported` (bind_locator wired only for tcp/ws/tls); after,
    //    it yields a `BoundListener::Unixsock`.
    let mut bound = bind_endpoint(&format!("unixsock-stream/{path}"))
        .await
        .expect("bind_endpoint accepts a unixsock-stream/ listen (Stage 4 accept seam)");
    assert_eq!(
        bound.transport_name(),
        "unixsock",
        "the scheme-keyed bind yields a unixsock listener"
    );

    let acc_open = async {
        // The pub accept seam: accept one raw peer, then run the (no-op for
        // unixsock) post-accept handshake into the SAME DialedLink the dial side
        // produces — exactly what the one-shot `accept_bound` drives internally.
        let (accepted, _peer) = bound
            .accept_raw()
            .await
            .expect("accept_raw yields a unixsock peer");
        let link = accepted
            .handshake()
            .await
            .expect("unixsock post-accept handshake (a direct wrap)");
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
        .expect("acceptor reaches Established over the unixsock seam")
    };
    let init_open = async {
        let locator =
            parse_any_locator(&format!("unixsock-stream/{path}")).expect("parse unixsock locator");
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
        .expect("initiator reaches Established over unixsock")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the unixsock seam"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over the unixsock seam"
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
                "the payload delivered over the unixsock seam matches the Put byte-for-byte"
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
            .expect("unixsock seam publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the unixsock seam"
    );

    let _ = std::fs::remove_file(&path);
}
