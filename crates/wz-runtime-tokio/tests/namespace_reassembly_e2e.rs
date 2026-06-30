// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "transport-fragmentation",
    feature = "transport-link-tcp",
    feature = "transport-unicast",
    feature = "codec-push"
))]

//! §5.21 routing-namespace — the REASSEMBLED ingress path under a shared
//! namespace (R311y106 active flip).
//!
//! This is the proof for the SECOND ingress strip mint-point
//! (`report_outcome_reassembling`, `drive.rs:649`). A whole-frame `FramePayload`
//! is stripped by `drive_session_until_terminal`; a fragment chain instead
//! completes INSIDE `report_outcome_reassembling`, which synthesizes its own
//! `FramePayload` and dispatches it separately — so that reassembled outcome
//! needs its own strip, or an oversize namespaced Put would reach the app
//! un-stripped. Forcing a tiny 64-byte negotiated MTU fragments a 200-byte Put;
//! a delivery carrying the RELATIVE keyexpr proves the reassembled-path strip.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
/// The BARE (application-level) keyexpr; `myns` is applied by the decorator.
const KEYEXPR: &str = "demo/frag";
/// 64-byte negotiated MTU; a 200-byte payload's namespaced Put frame far
/// exceeds it and fragments into a multi-chunk T_MID_FRAGMENT chain.
const BATCH_SIZE: u16 = 64;

fn ns(s: &str) -> OwnedNonWildKeyExpr {
    OwnedNonWildKeyExpr::new(s).expect("valid non-wild namespace")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_namespaced_put_fragments_and_reassembled_path_strips() {
    let payload: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        params.batch_size = BATCH_SIZE;
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        params.batch_size = BATCH_SIZE;
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

    // Both participants share ONE namespace.
    opened_acc.actions.set_namespace(ns("myns"));
    opened_init.actions.set_namespace(ns("myns"));

    // Fragmentation precondition, asserted by construction: with MTU == 64 a
    // 200-byte Put is FORCED through the fragment branch (without this the test
    // could false-pass on a single un-fragmented frame, never exercising the
    // reassembled-path strip). Read before the bundles are borrowed by the loops.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "publisher negotiated MTU must be the tiny budget so the namespaced Put fragments"
    );

    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(
                sample.keyexpr(),
                KEYEXPR,
                "reassembled delivery carries the RELATIVE (stripped) keyexpr"
            );
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the reassembled payload matches the oversize Put byte-for-byte"
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
        tokio::time::sleep(Duration::from_millis(150)).await;
        let local = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("oversize publish builds + fragments through the egress seam");
        assert_eq!(local, 0, "no local subscriber on the publisher side");
        for _ in 0..150 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("the reassembled namespaced Sample did not arrive within the budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one reassembled delivery, namespace-stripped on the reassembled path"
    );
}
