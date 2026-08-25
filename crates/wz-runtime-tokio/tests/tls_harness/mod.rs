// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-tls", feature = "transport-unicast"))]

//! R311oi — shared wz<->wz TLS-session test harness.
//!
//! The SSOT for "bring up both ends of a wz session over a TLS config pair and
//! drive each to Established", which `tls_e2e` (then a Put delivery) and
//! `tls_pem_mtls_e2e` (then an Established assertion) previously spelled out
//! byte-for-byte. It lives in a `tests/<dir>/mod.rs` SUBDIRECTORY module — NOT
//! a `tests/*.rs` file — so cargo compiles it INTO each including test binary
//! (via `mod tls_harness;`) rather than as its own test target. That is the
//! canonical Cargo idiom for sharing integration-test code, and it is the right
//! home here precisely BECAUSE the alternative (hoisting to the
//! `wz-runtime-tokio-test-support` sibling crate) cannot be done without
//! breaching the R311fr `default-features = false` isolation contract: this
//! helper needs `transport-link-tls` + `session-unicast-open`, and forcing
//! those into test-support would leak them into the 6 non-TLS consumers that
//! dev-dep it. The pure-data cert fixtures (`loopback_tls_configs` /
//! `loopback_mtls_pems`) ARE in test-support because they leak no wz feature;
//! this behavioural drive correctly is not.
//!
//! `session_reconnect_e2e` deliberately does NOT use this helper — its open
//! path is `open_session_with_reconnect` (reconnect-supervised) plus a
//! declare-collection drive, a genuinely different operation; unifying it here
//! would be over-abstraction.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, OpenedSession,
    TlsDialConfig, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::tls_pipeline::accept_tls;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;

/// Bounded open-handshake drive cap for the loopback TLS e2e tests — the
/// handshake is a handful of in-order segments on 127.0.0.1, so this only
/// bounds a regression to fail fast instead of hanging.
pub const ITER_CAP: usize = 4096;

/// Bring up both ends of a wz<->wz TLS session over the given rustls configs and
/// drive each to Established. The acceptor runs the rustls server handshake over
/// the accepted `TcpStream`; the initiator dials a `tls/...` locator through the
/// R311oc config-threaded seam (`connect_and_open_session` -> `dial_locator` ->
/// `dial_tls`), proving the SEAM rather than a bespoke explicit dial. Returns
/// both `OpenedSession`s so the caller can assert on the trace or continue with
/// a data-plane scenario. Distinct zids (0x02 acceptor / 0x01 initiator) match
/// the per-file convention the two TLS tests already used.
pub async fn open_both_to_established(
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
        // R311y253 — builder form (`DialConfig` is `#[non_exhaustive]`; both its
        // fields are cfg-gated, so an exhaustive literal broke under any feature
        // combo it was not written against — this one omitted `quic`).
        let cfg = DialConfig::default().with_tls(TlsDialConfig {
            client_config,
            server_name,
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
        .expect("initiator reaches Established over tls via locator")
    };

    tokio::join!(acc_open, init_open)
}
