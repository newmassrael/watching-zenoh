// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! End-to-end WIRE proof of the REST bridge: an HTTP client drives `PUT` / `GET`
//! / `DELETE` against a `wz_rest::serve_on` bridge running on one session, and a
//! SEPARATE session connected over a real loopback TCP link answers — a
//! subscriber receives the `PUT`/`DELETE` and a queryable answers the `GET`.
//!
//! ## Why the WIRE path (not loopback)
//!
//! A single-session loopback test would pass even if the bridge's feature set
//! omitted `codec-push` (a co-located `PUT` delivers via the allow-loop leg) or
//! `codec-response-final` (a co-located `GET` synthesises its own final). This
//! test routes every op across two DISTINCT sessions over TCP, so:
//!   - a `PUT` reaching the remote subscriber PROVES the `codec-push` emit path;
//!   - a `GET` returning the remote queryable's reply as JSON PROVES `query` +
//!     the wire `codec-response-final` completion (the bridge's `on_final`).
//!
//! Strip either feature and this test fails — it is the diagnose-first guard for
//! the design panel's wire-broken-feature-set blocker.
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! A publish/query routes to the peer only once that peer's
//! `Declare(DeclSubscriber)` / `Declare(DeclQueryable)` has propagated to the
//! bridge session. Rather than a fixed settle sleep, each op is RE-ISSUED on a
//! poll cadence until its effect is observed; over loopback that is the first or
//! second attempt, and the retry only absorbs propagation latency (the assertion
//! still requires the real remote effect within the budget).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{QueryableOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 64;
const DATA_KEY: &str = "demo/rest/data";
const QUERY_KEY: &str = "demo/rest/query";
const PUT_BODY: &[u8] = b"hello-from-rest";
const REPLY_PAYLOAD: &[u8] = b"rest-bridge-reply";

/// A sample the answerer's subscriber received, copied out of the callback.
#[derive(Clone)]
struct Received {
    kind: SampleKind,
    payload: Vec<u8>,
}

/// Send one raw HTTP request to `addr` and read the whole response (the server
/// replies `Connection: close`, so read to EOF). Returns `(status, body)`.
async fn http(addr: std::net::SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("connect http");
    stream.write_all(request).await.expect("write request");
    stream.flush().await.expect("flush request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a header terminator");
    let head = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let status_line = std::str::from_utf8(head)
        .expect("ascii head")
        .lines()
        .next()
        .expect("status line");
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_bridge_put_get_delete_traverse_the_wire() {
    // ── The wz link between the two sessions.
    let link = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz link");
    let link_addr = link.local_addr().expect("wz link addr");

    // ── The HTTP listener the bridge serves on (bound here so the test knows
    //    the port; handed to serve_on).
    let http_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let http_addr = http_listener.local_addr().expect("http addr");

    // ── Open both sessions to Established (engines are !Send -> join, not spawn).
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
        .expect("acceptor Established")
    };
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

    // ── ANSWERER session: a subscriber on DATA_KEY (records Put/Del) + a
    //    queryable on QUERY_KEY (replies REPLY_PAYLOAD). Handles held for the
    //    whole test (dropping would undeclare).
    let received: Arc<StdMutex<Vec<Received>>> = Arc::new(StdMutex::new(Vec::new()));
    let observer_acc = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_acc = TokioSession::new(
        opened_acc.actions.clone(),
        observer_acc,
        Arc::new(opened_acc.clock),
    );
    let received_cb = Arc::clone(&received);
    let _subscriber = session_acc
        .declare_subscriber(DATA_KEY, SubscribeOptions::default(), move |sample| {
            received_cb.lock().unwrap().push(Received {
                kind: sample.kind(),
                payload: sample.payload().to_vec(),
            });
        })
        .expect("acceptor declares the subscriber");
    let _queryable = session_acc
        .declare_queryable(
            QUERY_KEY,
            QueryableOptions::default(),
            |_view: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply(REPLY_PAYLOAD);
            },
        )
        .expect("acceptor declares the queryable");
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

    // ── BRIDGE session: drives HTTP-originated query/publish. serve_on runs the
    //    HTTP accept loop on a spawned task (its per-connection handlers use
    //    Send session clones); the drive loop runs on this task.
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

    let received_scn = Arc::clone(&received);
    let scenario = async move {
        // 1. PUT until the remote subscriber records the Put (proves codec-push
        //    over the wire). Re-PUT absorbs DeclSubscriber propagation latency.
        let put_req = format!(
            "PUT /{DATA_KEY} HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            PUT_BODY.len()
        );
        let mut put_bytes = put_req.into_bytes();
        put_bytes.extend_from_slice(PUT_BODY);
        let mut put_ok = false;
        'put: for _ in 0..120 {
            let (status, _) = http(http_addr, &put_bytes).await;
            assert_eq!(status, 200, "PUT returns 200");
            for _ in 0..4 {
                if received_scn
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| matches!(r.kind, SampleKind::Put) && r.payload == PUT_BODY)
                {
                    put_ok = true;
                    break 'put;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        assert!(
            put_ok,
            "the PUT payload reached the remote subscriber over the wire"
        );

        // 2. GET until the JSON body carries the remote queryable's reply (proves
        //    query + wire ResponseFinal completion).
        let get_req = format!("GET /{QUERY_KEY} HTTP/1.1\r\nHost: x\r\n\r\n");
        let reply_str = std::str::from_utf8(REPLY_PAYLOAD).unwrap();
        let mut got = None;
        for _ in 0..120 {
            let (status, body) = http(http_addr, get_req.as_bytes()).await;
            assert_eq!(status, 200, "GET returns 200");
            let text = String::from_utf8_lossy(&body).into_owned();
            if text.contains(reply_str) {
                got = Some(text);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let body = got.expect("the GET returned the remote queryable's reply as JSON");
        assert!(
            body.trim_start().starts_with('['),
            "GET body is a JSON array: {body}"
        );
        assert!(
            body.contains(QUERY_KEY),
            "the reply JSON carries the reply keyexpr: {body}"
        );

        // 3. DELETE, then poll for the remote subscriber's Del.
        let del_req = format!("DELETE /{DATA_KEY} HTTP/1.1\r\nHost: x\r\n\r\n");
        let (status, _) = http(http_addr, del_req.as_bytes()).await;
        assert_eq!(status, 200, "DELETE returns 200");
        let mut del_ok = false;
        for _ in 0..80 {
            if received_scn
                .lock()
                .unwrap()
                .iter()
                .any(|r| matches!(r.kind, SampleKind::Del))
            {
                del_ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            del_ok,
            "the DELETE reached the remote subscriber as a Del over the wire"
        );
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_bridge => panic!("bridge drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    serve.abort();
}
