// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-tls", feature = "transport-unicast"))]

//! R311og — mutual-TLS (mTLS) + cert-PEM-loading end to end.
//!
//! Two follow-ups to the R311oa plain-TLS e2e (`tls_e2e`), proven together
//! because they compose: the production [`wz_runtime_tokio::tls_config`] PEM
//! loaders build the rustls configs, and the mTLS knob (client presents a cert
//! / server requires one) is just their optional argument.
//!
//! ## What each test proves
//!
//! - `mtls_mutual_auth_reaches_established`: configs built FROM PEM via the
//!   production loaders, BOTH sides authenticating (server presents its leaf +
//!   verifies the client's; client presents its leaf + verifies the server's),
//!   reach a zenoh session Established over the mutually-authenticated stream.
//!   This is the positive proof for BOTH features at once.
//! - `mtls_server_rejects_anonymous_client`: an mTLS server REJECTS a client
//!   that presents no cert — the handshake fails. This proves the
//!   `with_client_cert_verifier` policy is actually enforced, not decorative
//!   (the data plane never even comes up).
//! - `plain_tls_from_pem_reaches_established`: one-way TLS configs built from
//!   PEM (no client auth either side) reach Established — proving the cert-PEM
//!   loader's non-mTLS path standalone, distinct from the self-signed-DER
//!   `loopback_tls_configs` fixture the other TLS tests use.
//!
//! ## Cert material
//!
//! A single self-signed CA (from the `loopback_mtls_pems` fixture) issues a
//! server leaf (SAN `localhost`) and a client leaf; the CA is the trust anchor
//! both directions chain to. The fixture returns PEM strings, so these tests
//! drive the SAME `tls_config::{server_config_from_pem, client_config_from_pem}`
//! path a production deployment uses to load on-disk certs.
//!
//! ## Non-flakiness
//!
//! Loopback TCP under TLS: the handshake is a handful of in-order, loss-free
//! segments on 127.0.0.1. The reach-Established tests drive both sides via
//! `connect_and_open_session` / `accept_and_open_session`, which run the open
//! handshake to terminal under a bounded iteration cap; the negative test only
//! drives the rustls handshake, which resolves (success or fatal alert) in one
//! round trip.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, OpenedSession,
    TlsDialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::tls_config::{client_config_from_pem, server_config_from_pem, ClientAuthPem};
use wz_runtime_tokio::tls_pipeline::{accept_tls, dial_tls};
use wz_runtime_tokio_test_support::{fixture_session_init_params, loopback_mtls_pems};
use wz_session_core::locator::parse_any_locator;

const ITER_CAP: usize = 4096;

/// Bring up both ends of a wz<->wz TLS session over the given rustls configs and
/// drive each to Established. The acceptor runs the rustls server handshake over
/// the accepted `TcpStream`; the initiator dials a `tls/...` locator through the
/// R311oc config-threaded seam. Shared by the two reach-Established tests, which
/// differ ONLY in the configs (mTLS vs one-way) handed in.
async fn open_both_to_established(
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
) -> (OpenedSession, OpenedSession) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (tcp, _peer) = listener.accept().await.expect("accept tcp");
        let tls = accept_tls(tcp, server_config)
            .await
            .expect("server tls handshake");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
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
        let locator = parse_any_locator(&format!("tls/{addr}")).expect("parse tls locator");
        let server_name = ServerName::try_from("localhost").expect("server name");
        let cfg = DialConfig {
            tls: Some(TlsDialConfig {
                client_config,
                server_name,
            }),
        };
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
        .expect("initiator reaches Established over tls via locator")
    };

    tokio::join!(acc_open, init_open)
}

/// mTLS positive: server + client configs built from PEM via the production
/// loaders, BOTH authenticating, reach Established over the mutually-verified
/// stream. Proves cert-PEM loading AND mutual auth in one path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_mutual_auth_reaches_established() {
    let pems = loopback_mtls_pems();

    // Server presents its leaf AND requires a client cert chaining to the CA.
    let server_config = server_config_from_pem(
        pems.server_cert_pem.as_bytes(),
        pems.server_key_pem.as_bytes(),
        Some(pems.ca_pem.as_bytes()),
    )
    .expect("build mTLS server config from PEM");

    // Client trusts the CA (to verify the server) AND presents its own leaf.
    let client_config = client_config_from_pem(
        pems.ca_pem.as_bytes(),
        Some(ClientAuthPem {
            cert_chain_pem: pems.client_cert_pem.as_bytes(),
            private_key_pem: pems.client_key_pem.as_bytes(),
        }),
    )
    .expect("build mTLS client config from PEM");

    let (opened_acc, opened_init) = open_both_to_established(server_config, client_config).await;

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over mTLS"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over mTLS"
    );
}

/// mTLS enforcement (negative): a server that requires a client cert REJECTS a
/// client that presents none — the SERVER's `accept_tls` handshake errors, so
/// the session never comes up. Driven at the handshake level (`accept_tls` /
/// `dial_tls`) because the proof is the verifier's rejection, not the data
/// plane.
///
/// Why the assertion is on the SERVER side only: under TLS 1.3 (rustls's
/// default) client authentication happens AFTER the client finishes its half of
/// the handshake — the client sends an empty `Certificate` + `Finished` and
/// `dial_tls` returns `Ok`, then the SERVER evaluates the empty cert, rejects
/// it, and sends a fatal alert the client only observes on a subsequent read.
/// So the server's rejection is the authoritative enforcement signal; the
/// client's local handshake completing is expected, not a leak.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_server_rejects_anonymous_client() {
    let pems = loopback_mtls_pems();

    // Server REQUIRES a client cert (client-CA supplied).
    let server_config = server_config_from_pem(
        pems.server_cert_pem.as_bytes(),
        pems.server_key_pem.as_bytes(),
        Some(pems.ca_pem.as_bytes()),
    )
    .expect("build mTLS server config from PEM");

    // Client presents NO cert (one-way client config) — the anonymous case the
    // mTLS server must reject.
    let client_config = client_config_from_pem(pems.ca_pem.as_bytes(), None)
        .expect("build anonymous client config from PEM");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server_name = ServerName::try_from("localhost").expect("server name");

    let acc = async {
        let (tcp, _peer) = listener.accept().await.expect("accept tcp");
        accept_tls(tcp, server_config).await
    };
    // The dial must run concurrently so the server handshake can progress; its
    // result is intentionally not asserted (see the doc comment — TLS 1.3 lets
    // the client's half complete before the server validates the cert).
    let dial = async { dial_tls(addr, client_config, server_name).await };

    let (acc_res, _dial_res) = tokio::join!(acc, dial);

    assert!(
        acc_res.is_err(),
        "mTLS server must reject a client presenting no cert (got Ok handshake)"
    );
}

/// cert-PEM loading, one-way TLS (no mTLS): server + client configs built from
/// PEM with no client auth either side reach Established. Proves the loader's
/// `None` (no-client-auth) path produces working configs — the cert-PEM feature
/// independent of mutual auth.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_tls_from_pem_reaches_established() {
    let pems = loopback_mtls_pems();

    // Server presents its leaf, requires NO client cert.
    let server_config = server_config_from_pem(
        pems.server_cert_pem.as_bytes(),
        pems.server_key_pem.as_bytes(),
        None,
    )
    .expect("build one-way server config from PEM");

    // Client trusts the CA, presents NO cert.
    let client_config = client_config_from_pem(pems.ca_pem.as_bytes(), None)
        .expect("build one-way client config from PEM");

    let (opened_acc, opened_init) = open_both_to_established(server_config, client_config).await;

    assert!(
        opened_init.actions.trace_snapshot().record_established_at >= 1,
        "initiator established over one-way TLS built from PEM"
    );
    assert!(
        opened_acc.actions.trace_snapshot().record_established_at >= 1,
        "acceptor established over one-way TLS built from PEM"
    );
}
