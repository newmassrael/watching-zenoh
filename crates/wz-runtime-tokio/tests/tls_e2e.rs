// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-tls", feature = "transport-unicast"))]

//! R311oa — wz<->wz session end to end over a real loopback TLS link.
//!
//! The TLS analogue of `serial_pty_e2e` and the secured-stream sibling of the
//! TCP session tests: two nodes complete the rustls handshake, bring a zenoh
//! session up to Established over the encrypted byte stream, and a `Put`
//! published on one node is delivered byte-exact to a subscriber on the other
//! — proving the data plane rides the TLS stream through the SAME
//! StreamEnvelope framing TCP uses (`tls_pipeline` reuses `link_pipeline`'s
//! `writer_task` + `poll_framed`, differing only in the stream type).
//!
//! ## Cert plumbing
//!
//! A self-signed cert for `localhost` is generated at test time (`rcgen`).
//! The acceptor's rustls `ServerConfig` presents it; the dialer's
//! `ClientConfig` trusts exactly it (added to a fresh root store) and verifies
//! the server name `localhost`. Both configs pin the `ring` crypto provider
//! explicitly (`builder_with_provider`) so the test does not depend on a
//! process-default provider being installed. This mirrors how a production
//! caller supplies its own configs to `dial_tls`/`accept_tls` — the cert
//! POLICY lives at the call site, not in the `tls/...` locator.
//!
//! ## Non-flakiness
//!
//! Loopback TCP under TLS: the handshake + a single small Put are a handful of
//! in-order, loss-free segments on 127.0.0.1. Both sides drive continuously
//! (`None`) until the delivery is observed; the `select!` tears the drives
//! down once it fires, bounded by a ~3s probe budget so a regression fails
//! fast instead of hanging.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::tls_pipeline::{accept_tls, dial_tls};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/tls";

/// Build the (ServerConfig, ClientConfig) pair sharing one self-signed
/// `localhost` cert: the server presents it, the client trusts exactly it.
/// Both pin the `ring` provider so no process-default install is needed.
fn loopback_tls_configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_der: CertificateDer<'static> = issued.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key_pair.serialize_der()));

    let provider = Arc::new(ring::default_provider());

    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("server default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server single cert");

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("trust the self-signed cert");
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

/// Two wz nodes handshake over TLS, reach Established, and a `Put` published on
/// the initiator is delivered byte-exact to a subscriber on the acceptor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_tls_reaches_established_and_delivers_put() {
    let payload = b"tls-secured-hello".to_vec();
    let (server_config, client_config) = loopback_tls_configs();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently (the handshake needs both sides
    //    progressing): the acceptor runs the rustls server handshake over the
    //    accepted TcpStream, the initiator the client handshake.
    let acc_open = async {
        let (tcp, _peer) = listener.accept().await.expect("accept tcp");
        let tls = accept_tls(tcp, server_config)
            .await
            .expect("server tls handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        accept_and_open_session(
            DialedLink::Tls(Box::new(tls)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over tls")
    };
    let init_open = async {
        let server_name = ServerName::try_from("localhost").expect("server name");
        let tls = dial_tls(addr, client_config, server_name)
            .await
            .expect("client tls handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        initiate_and_open_session(
            DialedLink::Tls(Box::new(tls)),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over tls")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // Both ends reached Established over the encrypted stream.
    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over tls"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over tls"
    );

    // ── Subscriber on the acceptor's observer; asserts the delivered payload
    //    byte-for-byte (proving data rides the TLS stream, not just handshake).
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
                "the payload delivered over tls matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote delivery over the TLS link).
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
            .expect("tls publish builds and routes through the send seam");
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
        "exactly one delivery from the Put over the tls link"
    );
}
