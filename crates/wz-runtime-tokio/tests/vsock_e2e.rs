// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-link-vsock",
    target_os = "linux",
    feature = "transport-unicast"
))]

//! R311xj — wz<->wz session end to end over a real loopback AF_VSOCK link.
//!
//! The vsock sibling of `unixsock_e2e` / `ws_e2e`: the acceptor wraps an
//! accepted `VsockStream` directly (no accept-time handshake), and the
//! initiator dials a `vsock/<CID>:<PORT>` locator straight through
//! `connect_and_open_session` (no `DialConfig`, like unixsock/ws/udp). Two
//! nodes bring a session up over `VMADDR_CID_LOCAL`, reach Established, and a
//! `Put` published on the initiator is delivered byte-exact to a subscriber on
//! the acceptor — proving the data plane rides the StreamEnvelope-framed vsock
//! byte stream exactly as it does over TCP / unixsock.
//!
//! ## `#[ignore]` — needs AF_VSOCK loopback
//!
//! AF_VSOCK loopback (`VMADDR_CID_LOCAL`) needs the `vsock_loopback` kernel
//! module, which is ABSENT in the default dev / CI sandbox (no `/dev/vsock`; a
//! bind to `VMADDR_CID_LOCAL` returns `EPERM`). So this test is `#[ignore]` and
//! runs only on a vsock-capable host via
//! `cargo test -p wz-runtime-tokio --features transport-link-vsock -- --ignored`
//! — the same environment-gated shape the Layer Z cross-impl tests use. The
//! data path it exercises (StreamEnvelope over the split stream) is already
//! proven green by the TCP / TLS / unixsock e2e lanes; the vsock-specific
//! bit it adds is the `(cid, port)` dial/accept over a real `VsockStream`.
//!
//! ## Non-flakiness (when it runs)
//!
//! Loopback vsock is kernel-local IPC: a single small Put is a handful of
//! in-order, loss-free bytes. Both sides drive continuously (`None`) until the
//! delivery is observed; the `select!` tears the drives down once it fires,
//! bounded by a ~3s probe budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, bind_endpoint, connect_and_open_session, BoundListener, DialConfig,
    DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::vsock_pipeline::{accept_vsock_on, bind_vsock};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::{parse_any_locator, VMADDR_CID_LOCAL, VMADDR_PORT_ANY};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/vsock";

/// Two wz nodes handshake over a loopback AF_VSOCK link (the initiator via a
/// `vsock/<CID>:<PORT>` locator), reach Established, and a `Put` published on
/// the initiator is delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
async fn wz_to_wz_over_vsock_reaches_established_and_delivers_put() {
    let payload = b"vsock-framed-hello".to_vec();

    // Bind on VMADDR_CID_LOCAL with an ephemeral port; learn the assigned port
    // BEFORE the initiator dials (race-free, the bind/accept split pattern).
    let mut listener =
        bind_vsock(VMADDR_CID_LOCAL, VMADDR_PORT_ANY).expect("bind vsock loopback listener");
    let port = listener.local_addr().expect("bound local addr").port();

    // ── Open BOTH sessions concurrently: the acceptor accepts the inbound
    //    `VsockStream` and wraps it directly (no accept-time handshake); the
    //    initiator dials the `vsock/<CID>:<PORT>` locator through dial_locator.
    let acc_open = async {
        let stream = accept_vsock_on(&mut listener)
            .await
            .expect("accept vsock peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Vsock(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over vsock")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("vsock/VMADDR_CID_LOCAL:{port}"))
            .expect("parse vsock locator");
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
        .expect("initiator reaches Established over vsock")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over vsock"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over vsock"
    );

    // ── Subscriber on the acceptor; asserts the delivered payload byte-exact.
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
                "the payload delivered over vsock matches the Put byte-for-byte"
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
            .expect("vsock publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the vsock link"
    );
}

/// R311y379 (accept-symmetry Stage 4, second arm) — wz ACCEPTS a session over
/// AF_VSOCK through the SCHEME-KEYED accept seam (`bind_endpoint("vsock/..") ->
/// BoundListener::accept_raw -> AcceptedLink::handshake`), the acceptor twin of
/// the already-wired dial seam `dial_endpoint("vsock/..")`.
///
/// The DISCRIMINATOR the sibling
/// [`wz_to_wz_over_vsock_reaches_established_and_delivers_put`] cannot be: that
/// test drives the RAW primitives (`bind_vsock` / `accept_vsock_on` + a
/// hand-wrapped `DialedLink::Vsock`), so it stays GREEN even while the
/// scheme-keyed `bind_locator` returns `Unsupported` for `AnyLocator::Vsock`.
/// THIS test binds through `bind_endpoint` — so before the Stage 4 vsock arm
/// lands it FAILS at `bind_endpoint`, and after it reaches Established +
/// delivers a `Put`, exactly like the unixsock seam. `bind_endpoint` also
/// exercises the `accept_raw(&mut self)` generalization the vsock arm forced
/// (`tokio_vsock::VsockListener::accept` is `&mut self`).
///
/// `#[ignore]` for the same reason as the sibling: AF_VSOCK loopback needs the
/// `vsock_loopback` kernel module (absent in the default CI sandbox). Run with
/// `cargo test -p wz-runtime-tokio --features transport-link-vsock -- --ignored`
/// on a vsock-capable host (`sudo modprobe vsock_loopback`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
async fn wz_accepts_a_session_over_vsock_via_the_bind_endpoint_seam() {
    let payload = b"vsock-seam-hello".to_vec();

    // ── The Stage 4 gap: the scheme-keyed listen seam. Before the arm this is
    //    `Unsupported`; after, it yields a `BoundListener::Vsock` bound on
    //    VMADDR_CID_LOCAL with an ephemeral port (learned BEFORE the dial).
    let mut bound = bind_endpoint("vsock/VMADDR_CID_LOCAL:VMADDR_PORT_ANY")
        .await
        .expect("bind_endpoint accepts a vsock/ listen (Stage 4 accept seam)");
    assert_eq!(
        bound.transport_name(),
        "vsock",
        "the scheme-keyed bind yields a vsock listener"
    );
    let port = match &bound {
        BoundListener::Vsock(l) => l.local_addr().expect("bound vsock addr").port(),
        _ => panic!("bind_endpoint(vsock/..) must yield BoundListener::Vsock"),
    };

    let acc_open = async {
        let (accepted, _peer) = bound
            .accept_raw()
            .await
            .expect("accept_raw yields a vsock peer");
        let link = accepted
            .handshake()
            .await
            .expect("vsock post-accept handshake (a direct wrap)");
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
        .expect("acceptor reaches Established over the vsock seam")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("vsock/VMADDR_CID_LOCAL:{port}"))
            .expect("parse vsock locator");
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
        .expect("initiator reaches Established over vsock")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over the vsock seam"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over the vsock seam"
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
                "the payload delivered over the vsock seam matches the Put byte-for-byte"
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
            .expect("vsock seam publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the vsock seam"
    );
}
