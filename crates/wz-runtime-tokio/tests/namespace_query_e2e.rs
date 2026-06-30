// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-reply",
    feature = "transport-link-tcp",
    feature = "transport-unicast"
))]

//! §5.21 routing-namespace — the QUERY/REPLY plane end to end under a shared
//! namespace (R311y106 active flip).
//!
//! This is the proof for the reply EGRESS seam (`SessionLinkActions::send_response`):
//! query replies flush through a dedicated `dispatch_response` path that bypasses
//! BOTH the `send_network_message` floor and the unicast `Tp` send arm, so the
//! `Namespace` decorator has to hook the reply there separately. If it did NOT,
//! a namespaced query's REQUEST would ship as `myns/demo/q` (so the remote
//! queryable matches) but the REPLY would ship bare `demo/q`, and the asker's
//! ingress strip would drop it — the query would hang. A returned reply
//! therefore proves the full round-trip: Request egress + ingress strip on the
//! answerer, Response egress + ingress strip on the asker.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, QueryableOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_namespace, connect_and_open_session_with_namespace, DialConfig,
    DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 256;
/// The BARE (application-level) keyexpr; `myns` is applied by the decorator.
const KEYEXPR: &str = "demo/q";
const REPLY_PAYLOAD: &[u8] = b"namespaced-reply";

fn ns(s: &str) -> OwnedNonWildKeyExpr {
    OwnedNonWildKeyExpr::new(s).expect("valid non-wild namespace")
}

/// Both peers on `myns`: an initiator `query("demo/q")` reaches the acceptor's
/// queryable on `demo/q` (Request `myns/demo/q` -> ingress strip), and the
/// reply travels back (Response `myns/demo/q` via the `send_response` seam ->
/// ingress strip). A delivered reply proves the reply egress seam is wired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_reply_round_trips_under_shared_namespace() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Both participants share ONE namespace, installed via the production
    // `*_with_namespace` open seam (the `*_with_compression` sibling); every
    // keyexpr below is relative to it.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        accept_and_open_session_with_namespace(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            ns("myns"),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_namespace(
            locator,
            fixture_params_with_zid(0x01),
            ns("myns"),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    let timeouts = SessionTimeouts::spec_defaults();

    // ── ANSWERER: a queryable on the BARE keyexpr replies with REPLY_PAYLOAD.
    let observer_acc = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_acc = TokioSession::new(
        opened_acc.actions.clone(),
        observer_acc,
        Arc::new(opened_acc.clock),
    );
    let _queryable = session_acc
        .declare_queryable(
            KEYEXPR,
            QueryableOptions::default(),
            |_view: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply(REPLY_PAYLOAD);
            },
        )
        .expect("acceptor declares the answering queryable");
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

    // ── ASKER.
    let observer_init = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_init = TokioSession::new(
        opened_init.actions.clone(),
        observer_init,
        Arc::new(opened_init.clock),
    );
    let session_init_drive = session_init.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        move |event| session_init_drive.dispatch_iteration_event(event),
    );

    let replies: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
    let finals = Arc::new(AtomicUsize::new(0));

    let scenario = {
        let session = session_init.clone();
        let replies = replies.clone();
        let finals = finals.clone();
        async move {
            // Re-issue on a poll cadence until a reply is observed (absorbs the
            // DeclQueryable propagation latency without a racy fixed sleep);
            // hold every handle so the pending query is not torn down.
            let mut handles = Vec::new();
            for _ in 0..120 {
                let replies_cb = replies.clone();
                let finals_cb = finals.clone();
                if let Ok(handle) = session.query(
                    KEYEXPR,
                    QueryOptions::get(),
                    move |view: &dyn ReplyView| {
                        replies_cb.lock().unwrap().push(view.payload().to_vec());
                    },
                    move |_rid: u64| {
                        finals_cb.fetch_add(1, Ordering::SeqCst);
                    },
                ) {
                    handles.push(handle);
                }
                for _ in 0..4 {
                    if !replies.lock().unwrap().is_empty() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            panic!("the namespaced query received no reply within the ~12s budget");
        }
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    let got = replies.lock().unwrap().clone();
    assert!(
        !got.is_empty(),
        "the namespaced reply returned over the wire (proves the send_response egress seam)"
    );
    assert!(
        got.iter().all(|p| p.as_slice() == REPLY_PAYLOAD),
        "every reply carries the queryable's payload"
    );
    assert!(
        finals.load(Ordering::SeqCst) >= 1,
        "the terminal ResponseFinal fired on the asker"
    );
}
