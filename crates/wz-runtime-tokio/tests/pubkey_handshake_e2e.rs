// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// An initiator-side method that keeps the InitAck sub-ext its inner method
/// was handed, so a test can read what the responder actually SENT rather
/// than what it believes it sent.
#[cfg(feature = "access-extauth-usrpwd")]
struct RecordsInitAck<M> {
    inner: M,
    seen: std::sync::Arc<std::sync::Mutex<Option<wz_session_core::auth_dispatch::AuthSubExt>>>,
}

#[cfg(feature = "access-extauth-usrpwd")]
impl<M: wz_session_core::auth_dispatch::AuthMethod> wz_session_core::auth_dispatch::AuthMethod
    for RecordsInitAck<M>
{
    fn id(&self) -> u8 {
        self.inner.id()
    }
    fn open_init_syn(
        &mut self,
    ) -> Result<
        Option<wz_session_core::auth_dispatch::AuthSubExt>,
        wz_session_core::auth_dispatch::AuthError,
    > {
        self.inner.open_init_syn()
    }
    fn open_recv_init_ack(
        &mut self,
        sub: Option<wz_session_core::auth_dispatch::AuthSubExt>,
    ) -> Result<(), wz_session_core::auth_dispatch::AuthError> {
        *self.seen.lock().unwrap() = sub.clone();
        self.inner.open_recv_init_ack(sub)
    }
    fn open_open_syn(
        &mut self,
    ) -> Result<
        Option<wz_session_core::auth_dispatch::AuthSubExt>,
        wz_session_core::auth_dispatch::AuthError,
    > {
        self.inner.open_open_syn()
    }
    fn open_recv_open_ack(
        &mut self,
        sub: Option<wz_session_core::auth_dispatch::AuthSubExt>,
    ) -> Result<(), wz_session_core::auth_dispatch::AuthError> {
        self.inner.open_recv_open_ack(sub)
    }
}

/// R2779 (open-debt item 803) — a responder running usrpwd AND pubkey
/// challenges the initiator with two DIFFERENT values.
///
/// usrpwd sends its challenge in the clear (a `Z64` on InitAck), and pubkey
/// sends its own encrypted to the initiator's key and accepts, at OpenSyn,
/// whoever returns it re-encrypted to the responder's key. If the two are
/// one value, a peer that knows ONE trusted public key and holds valid usrpwd
/// credentials can answer the pubkey challenge without the private key: it
/// reads the plaintext and encrypts it itself. Upstream draws them apart --
/// `io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs` @ `impl StateAccept {`
/// and `io/zenoh-transport/src/unicast/establishment/ext/auth/pubkey.rs` @ `state.challenge = prng.gen();`.
///
/// Driven through the PRODUCTION seams on both ends over loopback TCP, and
/// read off the artifact: the initiator records both InitAck sub-exts, and
/// the test decrypts the pubkey challenge with the initiator's own key.
#[cfg(feature = "access-extauth-usrpwd")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usrpwd_and_pubkey_challenge_the_initiator_with_different_values() {
    use std::sync::{Arc, Mutex};
    use wz_runtime_tokio::rsa::Pkcs1v15Encrypt;
    use wz_session_core::auth_dispatch::AuthSubExt;
    use wz_session_core::extauth_usrpwd::UsrPwdMethod;
    use wz_session_core::vle::read_zbuf;

    const USER: &[u8] = b"alice";
    const PASSWORD: &[u8] = b"secret";

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let init_priv = generate_keypair(KEY_BITS).expect("initiator keypair");
    let init_pub = RsaPublicKey::from(&init_priv);

    let acceptor_fut = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        let responder = AuthDispatch::new(vec![
            Box::new(UsrPwdMethod::responder(
                vec![(USER.to_vec(), PASSWORD.to_vec())],
                0,
            )) as _,
            Box::new(PubKeyMethod::responder(
                generate_keypair(KEY_BITS).expect("responder keypair"),
                Some(vec![init_pub]),
            )) as _,
        ]);
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

    let usrpwd_seen = Arc::new(Mutex::new(None));
    let pubkey_seen = Arc::new(Mutex::new(None));
    let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let cfg = DialConfig::default();
    let initiator = AuthDispatch::new(vec![
        Box::new(RecordsInitAck {
            inner: UsrPwdMethod::initiator(USER.to_vec(), PASSWORD.to_vec()),
            seen: usrpwd_seen.clone(),
        }) as _,
        Box::new(RecordsInitAck {
            inner: PubKeyMethod::initiator(init_priv.clone()),
            seen: pubkey_seen.clone(),
        }) as _,
    ]);
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
    accepted.expect("the responder establishes with both methods");
    opened.expect("the initiator establishes with both methods");

    let usrpwd_nonce = match usrpwd_seen.lock().unwrap().clone() {
        Some(AuthSubExt::Z64(n)) => n,
        other => panic!("usrpwd's InitAck challenge is a Z64, got {other:?}"),
    };
    let body = match pubkey_seen.lock().unwrap().clone() {
        Some(AuthSubExt::Zbuf(b)) => b,
        other => panic!("pubkey's InitAck is a Zbuf, got {other:?}"),
    };
    // `{ responder pubkey (n, e), challenge ciphertext }`, three ZBufs.
    let mut cursor = sce_forge_runtime::codec::SceCursor::new(&body);
    read_zbuf(&mut cursor).expect("the responder key's modulus");
    read_zbuf(&mut cursor).expect("the responder key's exponent");
    let ciphertext = read_zbuf(&mut cursor).expect("the challenge ciphertext");
    let challenge = init_priv
        .decrypt(Pkcs1v15Encrypt, &ciphertext)
        .expect("the challenge was encrypted to the initiator's key");
    assert_eq!(challenge.len(), 8, "the pubkey challenge is one u64");
    assert_ne!(
        challenge,
        usrpwd_nonce.to_le_bytes(),
        "the pubkey challenge is the usrpwd nonce the same InitAck sent in the \
         clear -- one value serves both methods (open-debt item 803)"
    );
}
