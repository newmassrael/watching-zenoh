// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "transport-unicast",
    feature = "transport-link-tcp",
    feature = "codec-push"
))]

//! §5.21 routing-namespace — the per-participant keyexpr namespace decorator,
//! end to end over a real loopback TCP wz<->wz link (R311y106 active flip).
//!
//! The y105 kernel (`apply_egress` / stateful `NamespaceIngress`) is unit-tested
//! in isolation; these tests drive it through the ACTUAL wiring seams — the
//! egress at the unicast `Tp::send_network_message` arm and the ingress strip in
//! `drive_session_until_terminal` — so the COMPOSED path is proven, not just the
//! atom (the project's composition-over-isolated-atoms rule).
//!
//! The application always names BARE keyexprs (`zenoh/pub`); a session with a
//! namespace publishes/subscribes RELATIVE to it. The proofs:
//!
//!   1. `pubsub_same_namespace_delivers` — both peers on `myns`: a Put on `foo`
//!      ships as `myns/foo` on the wire and is delivered back as `foo` to a
//!      subscriber registered on `foo`. Egress prepend + ingress strip round-trip.
//!   2. `pubsub_cross_namespace_is_isolated` — peers on DIFFERENT namespaces:
//!      the Put never reaches the subscriber (ingress drops the out-of-namespace
//!      keyexpr). The core isolation guarantee.
//!   3. `pubsub_unnamespaced_peer_cannot_reach_namespaced_subscriber` — a peer
//!      with NO namespace ships a bare `foo`, which the namespaced acceptor drops.
//!   4. `pubsub_no_namespace_delivers_unchanged` — neither peer namespaced: the
//!      decorator is a transparent no-op (the off-path regression guard).

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
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

fn ns(s: &str) -> OwnedNonWildKeyExpr {
    OwnedNonWildKeyExpr::new(s).expect("valid non-wild namespace")
}

/// Open a real loopback-TCP wz<->wz pair, install the optional namespaces, then
/// register a subscriber on `sub_ke` (the acceptor) and publish a Put on `pub_ke`
/// (the initiator). Returns the number of subscriber deliveries observed.
///
/// `expect_deliver` shapes only the WAIT, never the assertion (the caller
/// asserts): a delivery is polled-until-seen (no fixed-window flake); a NON
/// delivery waits a generous settle window — comfortably longer than the
/// ~150 ms a real delivery takes — then reports the (expected-zero) count.
async fn run_pubsub(
    acc_ns: Option<&str>,
    init_ns: Option<&str>,
    sub_ke: &'static str,
    pub_ke: &'static str,
    expect_deliver: bool,
) -> usize {
    let payload = vec![0x5Au8; 48];

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
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
        connect_and_open_session(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // R311y106 active-flip seam — install the per-participant namespace on each
    // bundle BEFORE the drive loop spins (the `set_lowlatency_offer` discipline).
    if let Some(n) = acc_ns {
        opened_acc.actions.set_namespace(ns(n));
    }
    if let Some(n) = init_ns {
        opened_init.actions.set_namespace(ns(n));
    }

    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(sub_ke, move |sample| {
            assert_eq!(
                sample.keyexpr(),
                sub_ke,
                "delivery carries the RELATIVE (namespace-stripped) keyexpr"
            );
            assert_eq!(
                sample.payload(),
                &expect[..],
                "payload survives the round-trip"
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
            .publish(pub_ke, &payload, PublishOptions::put())
            .expect("publish builds + routes through the egress seam");
        assert_eq!(local, 0, "no local subscriber on the publisher side");
        if expect_deliver {
            // ~12s budget (matched to the query e2e) so full-CI shared load
            // cannot starve a true delivery into a spurious FAIL; the early-out
            // keeps the happy path fast.
            for _ in 0..400 {
                if fired_probe.load(Ordering::SeqCst) > 0 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        } else {
            // No early-out: confirm the drop holds across a window comfortably
            // longer than a real delivery would take.
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    fired.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pubsub_same_namespace_delivers() {
    let delivered = run_pubsub(Some("myns"), Some("myns"), "zenoh/pub", "zenoh/pub", true).await;
    assert_eq!(
        delivered, 1,
        "a Put under a shared namespace round-trips (egress myns/zenoh/pub -> ingress strip -> zenoh/pub)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pubsub_cross_namespace_is_isolated() {
    let delivered = run_pubsub(Some("myns"), Some("other"), "zenoh/pub", "zenoh/pub", false).await;
    assert_eq!(
        delivered, 0,
        "a Put from a DIFFERENT namespace (other/zenoh/pub) is dropped at the myns ingress"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pubsub_unnamespaced_peer_cannot_reach_namespaced_subscriber() {
    let delivered = run_pubsub(Some("myns"), None, "zenoh/pub", "zenoh/pub", false).await;
    assert_eq!(
        delivered, 0,
        "a bare (un-namespaced) Put is not under myns, so the namespaced acceptor drops it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pubsub_no_namespace_delivers_unchanged() {
    let delivered = run_pubsub(None, None, "zenoh/pub", "zenoh/pub", true).await;
    assert_eq!(
        delivered, 1,
        "with no namespace installed the decorator is a transparent no-op (off-path guard)"
    );
}
