// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-quic", feature = "transport-unicast"))]

//! R311xk — wz<->wz session end to end over a real loopback QUIC link.
//!
//! The QUIC sibling of `tls_e2e`: a self-signed `localhost` cert (`rcgen`) is
//! loaded through the PRODUCTION `quic_config` builders (TLS-1.3 + ALPN
//! `hq-29`), the acceptor binds a QUIC server `Endpoint` and accepts the single
//! bidirectional stream, and the initiator dials a `quic/...` LOCATOR through
//! the R311oc config-threaded seam (`connect_and_open_session` -> `dial_locator`
//! -> `dial_quic`) with `DialConfig.quic`. Both nodes reach Established and a
//! `Put` published on the initiator is delivered byte-exact to a subscriber on
//! the acceptor — proving the data plane rides the StreamEnvelope-framed QUIC
//! bidirectional stream exactly as it does over TCP/TLS.
//!
//! ## Fully runnable (NO `#[ignore]`)
//!
//! Unlike `vsock_e2e`, QUIC loopback needs no special kernel support — it rides
//! ordinary UDP on 127.0.0.1, and the self-signed cert is generated in-process.
//! So this is the fully-verified link round: the live (cid-free) QUIC dial /
//! accept / handshake / data path all execute here.
//!
//! ## Non-flakiness
//!
//! Loopback UDP under QUIC: the TLS-1.3 handshake + a single small Put are a
//! handful of in-order, loss-free datagrams on 127.0.0.1 (QUIC retransmits any
//! that are not). Both sides drive continuously (`None`) until the delivery is
//! observed; the `select!` tears the drives down once it fires, bounded by a
//! ~3s probe budget.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
use wz_runtime_tokio::quic_pipeline::{accept_quic_on, bind_quic};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, QuicDialConfig,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/quic";

/// Two wz nodes handshake over a loopback QUIC link (the initiator via a
/// `quic/<host>:<port>` locator + `DialConfig.quic`), reach Established, and a
/// `Put` published on the initiator is delivered byte-exact to a subscriber on
/// the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_quic_reaches_established_and_delivers_put() {
    let payload = b"quic-framed-hello".to_vec();

    // Self-signed `localhost` cert via rcgen, loaded through the production
    // quic_config builders. The self-signed leaf is its own trust anchor (the
    // loopback_tls_configs pattern): the client roots = the same cert.
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config =
        quic_client_config_from_pem(cert_pem.as_bytes(), None).expect("build quic client config");

    // Bind the QUIC server endpoint BEFORE the initiator dials (learn the
    // OS-chosen port race-free, the bind/accept split pattern). The test owns
    // the endpoint so it outlives both sessions.
    let endpoint = bind_quic("127.0.0.1:0".parse().expect("loopback addr"), server_config)
        .expect("bind quic server endpoint");
    let addr = endpoint.local_addr().expect("endpoint local addr");

    // ── Open BOTH sessions concurrently: the acceptor accepts the inbound QUIC
    //    connection + its single bidi stream; the initiator dials the
    //    `quic/...` locator through the cert-threaded dial seam.
    let acc_open = async {
        let link = accept_quic_on(&endpoint).await.expect("accept quic peer");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Quic(Box::new(link)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over quic")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("quic/{addr}")).expect("parse quic locator");
        // R311y253 — builder form, not a struct literal. Both `DialConfig`
        // fields are `#[cfg]`-gated, so an exhaustive literal only compiles for
        // the feature combo it was written against: this one omitted `tls` and
        // so failed E0063 the moment `transport-link-tls` was also on (which
        // `--all-features` does). `DialConfig` is now `#[non_exhaustive]`, so
        // the literal form is unrepresentable here and the builder is the only
        // way in — which also sidesteps the `needless_update` lint that the old
        // comment cited as the reason for omitting `..Default::default()`.
        let cfg = DialConfig::default().with_quic(QuicDialConfig {
            client_config,
            // SNI must match the cert SAN (`localhost`), independent of the
            // numeric dial address — exactly the tls model.
            server_name: "localhost".to_string(),
        });
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over quic via locator")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over quic"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over quic"
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
                "the payload delivered over quic matches the Put byte-for-byte"
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
            .expect("quic publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the quic link"
    );
}
