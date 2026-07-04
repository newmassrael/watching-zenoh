// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "rest-sse-subscribe")]

//! End-to-end WIRE proof of the SSE half: an HTTP client opens a
//! `GET … Accept: text/event-stream` against a `wz_rest::serve_on` bridge on
//! one session; a SEPARATE session over a real loopback TCP link publishes; the
//! bridge's SSE subscriber receives the push over the wire and streams it to the
//! client as `event: PUT\ndata: {…}\n\n`.
//!
//! Routes the whole path across two DISTINCT sessions (not loopback), so a
//! streamed event PROVES the subscriber declaration propagated over the wire AND
//! the remote push routed back through the SSE subscriber — the streaming twin
//! of the request/response wire test.
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! The publisher routes to the bridge's subscriber only once the bridge's
//! `Declare(DeclSubscriber)` (emitted when the SSE GET is accepted) has
//! propagated to the publishing session. The publish is RE-ISSUED on a poll
//! cadence until the client reads the event; over loopback that is the first or
//! second attempt, and the retry only absorbs propagation latency (the assertion
//! still requires the real streamed event within the budget).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 64;
const SSE_KEY: &str = "demo/rest/sse";
const PAYLOAD: &[u8] = b"sse-hello";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_sse_streams_a_remote_publish_as_an_event() {
    let link = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz link");
    let link_addr = link.local_addr().expect("wz link addr");
    let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let http_addr = http_listener.local_addr().expect("http addr");

    // ── The PUBLISHER session (acceptor).
    let acc_open = async {
        let (stream, _peer) = link.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("publisher Established")
    };
    // ── The BRIDGE session (initiator) — declares the SSE subscriber on GET.
    let bridge_open = async {
        let locator = parse_any_locator(&format!("tcp/{link_addr}")).expect("parse locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        let cfg = DialConfig::default();
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("bridge Established")
    };
    let (mut opened_acc, mut opened_bridge) = tokio::join!(acc_open, bridge_open);

    let timeouts = SessionTimeouts::spec_defaults();

    let observer_acc = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_acc = TokioSession::new(
        opened_acc.actions.clone(),
        observer_acc,
        Arc::new(opened_acc.clock),
    );
    let session_acc_drive = session_acc.clone();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        move |event| session_acc_drive.dispatch_iteration_event(event),
    );

    let observer_bridge = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_bridge = TokioSession::new(
        opened_bridge.actions.clone(),
        observer_bridge,
        Arc::new(opened_bridge.clock),
    );
    let serve = tokio::spawn(wz_rest::serve_on(
        http_listener,
        session_bridge.clone(),
        vec![0x01; 4],
    ));
    let session_bridge_drive = session_bridge.clone();
    let drive_bridge = drive_session_until_terminal(
        &mut opened_bridge.inbound,
        &opened_bridge.actions,
        &mut opened_bridge.engine,
        None,
        &opened_bridge.clock,
        &timeouts,
        move |event| session_bridge_drive.dispatch_iteration_event(event),
    );

    let publisher = session_acc.clone();
    let scenario = async move {
        // Open the SSE stream.
        let mut stream = TcpStream::connect(http_addr).await.expect("connect http");
        let get =
            format!("GET /{SSE_KEY} HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n");
        stream.write_all(get.as_bytes()).await.expect("write GET");
        stream.flush().await.expect("flush GET");

        // Re-publish on a poll cadence until the client reads a PUT event
        // carrying the payload (absorbs DeclSubscriber propagation).
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut found = false;
        let payload_str = std::str::from_utf8(PAYLOAD).unwrap();
        'outer: for _ in 0..200 {
            let _ = publisher.publish(SSE_KEY, PAYLOAD, PublishOptions::put());
            for _ in 0..4 {
                match tokio::time::timeout(Duration::from_millis(50), stream.read(&mut tmp)).await {
                    Ok(Ok(0)) => break 'outer, // server closed
                    Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                    Ok(Err(_)) => break 'outer, // socket error
                    Err(_) => {}                // no data yet
                }
                let text = String::from_utf8_lossy(&buf);
                if text.contains("event: PUT") && text.contains(payload_str) {
                    found = true;
                    break 'outer;
                }
            }
        }

        let text = String::from_utf8_lossy(&buf).into_owned();
        assert!(
            found,
            "the SSE stream delivered a PUT event with the payload: {text}"
        );
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "the SSE response is 200 OK: {text}"
        );
        assert!(
            text.contains("text/event-stream"),
            "the SSE response is text/event-stream: {text}"
        );
        assert!(
            text.contains(SSE_KEY),
            "the SSE data carries the sample keyexpr: {text}"
        );
    };

    tokio::select! {
        _ = drive_acc => panic!("publisher drive loop ended unexpectedly"),
        _ = drive_bridge => panic!("bridge drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    serve.abort();
}
