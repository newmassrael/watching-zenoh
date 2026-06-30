// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "declare-subscriber",
    feature = "transport-link-tcp",
    feature = "transport-unicast"
))]

//! §5.21 routing-namespace — the REMOTE-DECLARE → matching_status composed path
//! (R311y106 implementation-panel finding).
//!
//! This pins the design DECISION to NOT namespace-qualify
//! `Publisher::get_matching_status`: the stateful ingress strips an inbound
//! `DeclareSubscriber` to its RELATIVE keyexpr BEFORE the observer fan-out, so
//! `remote_subscribers` is populated in relative form and a publisher's relative
//! keyexpr matches WITHOUT any prepend (a prepend would double-namespace and
//! break matching). The four pub/sub e2e prove only the LOCAL subscriber path;
//! this drives a remote `DeclareSubscriber` over the wire and asserts the
//! publisher's `get_matching_status` reflects it — the load-bearing surface the
//! DROP decision governs.

use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_namespace, connect_and_open_session_with_namespace, DialConfig,
    DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

use std::sync::Arc;

const ITER_CAP: usize = 512;
/// The BARE (application) keyexpr both participants name.
const KEYEXPR: &str = "zenoh/data";

fn ns(s: &str) -> OwnedNonWildKeyExpr {
    OwnedNonWildKeyExpr::new(s).expect("valid non-wild namespace")
}

/// The initiator A (namespace `a_ns`) declares a PUBLISHER on `KEYEXPR`; the
/// acceptor B (namespace `b_ns`) declares a SUBSCRIBER on `KEYEXPR`, whose
/// `DeclareSubscriber` ships namespaced and reaches A's remote-subscriber table
/// (stripped). Returns whether A's `get_matching_status` ever flips `true`.
async fn remote_subscriber_matches(a_ns: &str, b_ns: &str) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        accept_and_open_session_with_namespace(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            ns(b_ns),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        connect_and_open_session_with_namespace(
            locator,
            fixture_params_with_zid(0x01),
            ns(a_ns),
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    let timeouts = SessionTimeouts::spec_defaults();

    // ── A (initiator): a publisher whose matching_status reads its remote
    //    subscriber table; its drive loop fans inbound declares into the same
    //    observer the publisher reads.
    let session_a = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );
    let publisher = session_a.declare_publisher(KEYEXPR, PublishOptions::put());
    let session_a_drive = session_a.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        move |event| session_a_drive.dispatch_iteration_event(event),
    );

    // ── B (acceptor): a subscriber whose declare propagates to A.
    let session_b = TokioSession::new(
        opened_acc.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_acc.clock),
    );
    let _subscriber = session_b
        .declare_subscriber(KEYEXPR, SubscribeOptions::default(), |_sample| {})
        .expect("acceptor declares the subscriber");
    let session_b_drive = session_b.clone();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        move |event| session_b_drive.dispatch_iteration_event(event),
    );

    let scenario = async move {
        // Poll for the DeclareSubscriber to propagate and flip matching true;
        // a cross-namespace declare is dropped at A's ingress and never flips, so
        // the full window elapses and the helper reports the steady `false`.
        for _ in 0..200 {
            if publisher.get_matching_status().matching {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        publisher.get_matching_status().matching
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        matched = scenario => matched,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_status_sees_same_namespace_remote_subscriber() {
    assert!(
        remote_subscriber_matches("myns", "myns").await,
        "a same-namespace remote DeclareSubscriber is stripped to the relative \
         keyexpr and matches the publisher's relative keyexpr (the matching_status \
         DROP decision: no namespace-qualify)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_status_isolates_cross_namespace_remote_subscriber() {
    assert!(
        !remote_subscriber_matches("myns", "other").await,
        "a cross-namespace remote DeclareSubscriber is dropped at ingress, so it \
         never enters the remote-subscriber table and never matches"
    );
}
