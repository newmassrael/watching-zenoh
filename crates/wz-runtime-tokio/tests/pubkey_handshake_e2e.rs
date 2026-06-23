// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R4b — wz<->wz pubkey handshake e2e over a real TCP loopback, through the
//! PRODUCTION open seams. The responder runs `accept_and_open_session_with_auth`
//! (which draws a fresh per-handshake challenge nonce IN-SEAM from OS entropy and
//! feeds it to the pubkey method via `set_challenge_nonce` — the R4a accept-seam
//! payoff, now driving pubkey's RSA challenge) and the initiator runs
//! `connect_and_open_session_with_auth`, both with a `PubKeyMethod` dispatch.
//!
//! This is the transport-level counterpart of the `extauth_pubkey` kernel unit
//! tests (which drive the four-stage exchange through `AuthDispatch` in
//! isolation): it proves the mutual RSA challenge-response authenticates over the
//! same method-agnostic wiring + open seams as usrpwd, end-to-end on a socket.
//! The wire is non-deterministic (PKCS#1 v1.5 blinding), so the assertion is
//! behavioral (both sides reach Established), not byte-pinned.

#![cfg(feature = "access-extauth-pubkey")]

use tokio::net::TcpListener;

use wz_runtime_tokio::extauth_pubkey::{generate_keypair, PubKeyMethod};
use wz_runtime_tokio::rsa::RsaPublicKey;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_auth, connect_and_open_session_with_auth, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::locator::parse_any_locator;

const ITER_CAP: usize = 64;
/// 512-bit RSA for test speed — the wire is key-size-agnostic.
const KEY_BITS: usize = 512;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pubkey_production_open_seams_authenticate_over_real_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // The initiator's keypair; its public half goes in the responder's lookup so
    // the responder admits exactly this initiator (the authorized-key path).
    let init_priv = generate_keypair(KEY_BITS).expect("initiator keypair");
    let init_pub = RsaPublicKey::from(&init_priv);

    // Responder: accept -> accept_and_open_session_with_auth. The seam injects the
    // live challenge nonce into the PubKeyMethod (set_challenge_nonce).
    let acceptor_fut = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        // Some(vec![init_pub]) = admit exactly this initiator key (membership).
        let responder = AuthDispatch::new(vec![Box::new(PubKeyMethod::responder(
            generate_keypair(KEY_BITS).expect("responder keypair"),
            Some(vec![init_pub]),
        )) as _]);
        accept_and_open_session_with_auth(
            DialedLink::Tcp(stream),
            params,
            responder,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    };

    // Initiator: connect_and_open_session_with_auth proving possession of its key.
    let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let cfg = DialConfig::default();
    let initiator = AuthDispatch::new(vec![Box::new(PubKeyMethod::initiator(init_priv)) as _]);
    let initiator_fut = connect_and_open_session_with_auth(
        locator,
        params,
        initiator,
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let (accepted, opened) = tokio::join!(acceptor_fut, initiator_fut);
    let accepted = accepted
        .expect("pubkey responder reaches Established via accept_and_open_session_with_auth");
    let opened = opened
        .expect("pubkey initiator reaches Established via connect_and_open_session_with_auth");
    assert!(
        accepted.actions.trace_snapshot().record_established_at >= 1,
        "responder Established after the mutual RSA challenge-response"
    );
    assert!(
        opened.actions.trace_snapshot().record_established_at >= 1,
        "initiator Established after proving key possession over real TCP"
    );
}
