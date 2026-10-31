// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel as the stream link's dial and listener, under both policies, against rustls 0.23
//! on the other side of the socket (step T2 of L6 in `docs/capi-pico-on-coop-engine.md`).
//!
//! The library keeps one arena with no lock, so two ends of the channel cannot run on two
//! threads of one process: each role is proved against a rustls peer, which runs on a thread of
//! its own, and the two ends of the channel meeting on one thread is the engine's test (T3).
//!
//! What is held here: a chain dial verifies the server and offers no credential zid, with the
//! name checked only when asked and a client chain only under mutual TLS; a chain listener
//! presents its chain and requires a client chain only under mutual TLS; a pinned listener names
//! the client by the zid of its key; the listener's accept never blocks on the network, drops a
//! peer that stalls, sends junk, or is not trusted, and is not wedged by any of them.
#![cfg(feature = "vendored")]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use common::{library, now_unix, rustls_client, serve, server_config, Authority, End};
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_session_core::credential_identity::zid_from_spki_der;
use wz_tls_mbedtls::channel::{Identity, Trust};
use wz_tls_mbedtls::stream::{AcceptBudget, ChainTrust, HandshakeBudget, TlsDial};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn clock_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

const ACCEPT: AcceptBudget = AcceptBudget {
    clock: clock_ms,
    timeout_ms: 5_000,
};

fn budget() -> HandshakeBudget {
    HandshakeBudget {
        wait_ms: 100,
        waits: 50,
    }
}

fn identity(end: &End) -> &'static Identity {
    Box::leak(Box::new(end.identity()))
}

fn roots(authority: &Authority) -> &'static Trust {
    Box::leak(Box::new(
        Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots"),
    ))
}

/// The dial of a client that verifies the server by chain, as pico's `tls/` does by default.
fn chain_dial(
    authority: &Authority,
    verify_name: bool,
    mutual_as: Option<&End>,
) -> TlsDial<PosixTcpDial> {
    TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: mutual_as.map(identity),
            roots: Some(roots(authority)),
            mutual: mutual_as.is_some(),
            verify_name,
        },
    )
    .with_budget(budget())
}

/// The listener's dial: presents `server`, and under mutual TLS requires a chain `authority`
/// vouches for.
fn chain_listener(server: &End, mutual_roots: Option<&Authority>) -> TlsDial<PosixTcpDial> {
    TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: Some(identity(server)),
            roots: mutual_roots.map(roots),
            mutual: mutual_roots.is_some(),
            verify_name: false,
        },
    )
    .with_accept(ACCEPT)
}

/// Send a batch as the stream link writes one and read its echo back.
fn echo_through<S: StreamSocket>(stream: &S) {
    stream
        .send_parts(&[&4u16.to_le_bytes(), b"ping"])
        .expect("the batch leaves");
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    for _ in 0..100 {
        if got.len() == 6 {
            break;
        }
        stream.wait_readable(100);
        if let Some(n) = stream.try_read(&mut buf).expect("a read") {
            assert_ne!(n, 0, "the peer ended the session early");
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(got, [4, 0, b'p', b'i', b'n', b'g']);
}

/// Poll the listener the way the node's loop does until it yields a stream, or `within` passes.
fn accept_within<L: StreamListen>(listener: &L, within: Duration) -> Option<L::Stream> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Some(stream) = listener.accept().expect("the listener is sound") {
            return Some(stream);
        }
        thread::sleep(Duration::from_millis(1));
    }
    None
}

/// What the rustls client of `rustls_client` does, from the listener's side: read four bytes,
/// echo them, and read to the end of the session.
fn serve_echo<S: StreamSocket>(stream: &S) {
    let mut buf = [0u8; 16];
    let mut seen = 0;
    for _ in 0..200 {
        stream.wait_readable(50);
        match stream.try_read(&mut buf[seen..]).expect("a read") {
            Some(0) => return,
            Some(n) => {
                seen += n;
                if seen == 4 {
                    stream.send_parts(&[&buf[..4]]).expect("the echo leaves");
                    seen = 0;
                }
            }
            None => {}
        }
    }
    panic!("the client never ended the session");
}

#[test]
fn a_chain_dial_verifies_the_server_and_offers_no_credential_zid() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let stream = chain_dial(&authority, true, None)
        .dial(LOOPBACK, port)
        .expect("the chain verifies, and the address is in the certificate");
    assert_eq!(stream.peer_zid(), Some(server.zid()));
    assert_eq!(
        stream.peer_credential_zid(),
        None,
        "a router's zid is its own, not its key's: the chain was the proof"
    );
    echo_through(&stream);
    stream.shutdown();
    assert_eq!(
        served.join().expect("thread").expect("served"),
        None,
        "no client certificate was asked for"
    );
}

#[test]
fn a_chain_dial_checks_the_name_only_when_asked() {
    let _library = library();
    let authority = Authority::new();
    let named_otherwise = authority.issue_for(
        ExtendedKeyUsagePurpose::ServerAuth,
        &["router.invalid"],
        false,
        None,
    );

    let (port, served) = serve(server_config(&named_otherwise, None));
    let refused = chain_dial(&authority, true, None).dial(LOOPBACK, port);
    assert!(
        matches!(refused, Err(LinkOpenError::Refused)),
        "a certificate that does not cover the address"
    );
    let _ = served.join();

    let (port, served) = serve(server_config(&named_otherwise, None));
    let stream = chain_dial(&authority, false, None)
        .dial(LOOPBACK, port)
        .expect("no name check, as pico's default");
    echo_through(&stream);
    stream.shutdown();
    served.join().expect("thread").expect("served");
}

#[test]
fn a_chain_dial_to_a_server_the_roots_do_not_vouch_for_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = stranger.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let refused = chain_dial(&authority, false, None).dial(LOOPBACK, port);
    assert!(matches!(refused, Err(LinkOpenError::Refused)));
    let _ = served.join();
}

#[test]
fn a_mutual_dial_presents_its_chain_and_a_policy_missing_a_half_is_unsupported() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let client = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);

    let (port, served) = serve(server_config(&server, Some(&authority)));
    let stream = chain_dial(&authority, true, Some(&client))
        .dial(LOOPBACK, port)
        .expect("a router that requires a client chain takes one");
    echo_through(&stream);
    stream.shutdown();
    assert_eq!(
        served.join().expect("thread").expect("served").as_deref(),
        Some(client.cert.der().as_ref())
    );

    // Mutual TLS with no chain of the end's own is a configuration error, not a plain dial: it
    // never connects (the port has no listener to take the connection, and none is asked).
    let half = TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: None,
            roots: Some(roots(&authority)),
            mutual: true,
            verify_name: false,
        },
    );
    assert!(matches!(
        half.dial(LOOPBACK, 1),
        Err(LinkOpenError::Unsupported)
    ));
}

#[test]
fn a_chain_listener_presents_its_chain_and_a_rustls_client_verifies_it() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let listener = chain_listener(&server, None)
        .listen(LOOPBACK, 0)
        .expect("the port opens");
    let (_, port) = listener.local();
    let client = rustls_client(port, &authority, None);

    let stream = accept_within(&listener, Duration::from_secs(10)).expect("a verified client");
    assert_eq!(
        stream.peer_zid(),
        None,
        "no client certificate was asked for"
    );
    assert_eq!(stream.peer_credential_zid(), None);
    serve_echo(&stream);
    client.join().expect("thread").expect("the client verified");
}

#[test]
fn a_mutual_listener_requires_the_clients_chain_and_is_not_wedged_by_a_refused_one() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let client = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let strange = stranger.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let listener = chain_listener(&server, Some(&authority))
        .listen(LOOPBACK, 0)
        .expect("the port opens");
    let (_, port) = listener.local();

    // A client with no certificate and one the roots do not vouch for come first, and are not
    // handed on.
    for presented in [None, Some(&strange)] {
        let refused = rustls_client(port, &authority, presented);
        assert!(
            accept_within(&listener, Duration::from_millis(1_500)).is_none(),
            "a client the roots do not vouch for was accepted"
        );
        assert!(refused.join().expect("thread").is_err());
    }

    let good = rustls_client(port, &authority, Some(&client));
    let stream = accept_within(&listener, Duration::from_secs(10)).expect("the vouched client");
    assert_eq!(stream.peer_zid(), Some(client.zid()));
    serve_echo(&stream);
    good.join().expect("thread").expect("the client served");
}

#[test]
fn a_peer_that_stalls_or_speaks_junk_is_dropped_and_the_next_is_served() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let quick = AcceptBudget {
        clock: clock_ms,
        timeout_ms: 300,
    };
    let listener = chain_listener(&server, None)
        .with_accept(quick)
        .listen(LOOPBACK, 0)
        .expect("the port opens");
    let (_, port) = listener.local();

    // A connection that sends nothing: dropped when its handshake outlasts the budget, which the
    // peer sees as the end of the stream.
    let mut stalled = TcpStream::connect((Ipv4Addr::from(LOOPBACK), port)).expect("connects");
    stalled
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a timeout");
    assert!(accept_within(&listener, Duration::from_millis(1_000)).is_none());
    let mut byte = [0u8; 1];
    assert!(
        matches!(stalled.read(&mut byte), Ok(0) | Err(_)),
        "the stalled connection was left open"
    );

    // A client that is not speaking TLS: dropped as soon as the handshake fails.
    let mut junk = TcpStream::connect((Ipv4Addr::from(LOOPBACK), port)).expect("connects");
    junk.write_all(&[b'G'; 200]).expect("junk leaves");
    assert!(accept_within(&listener, Duration::from_millis(1_000)).is_none());

    // Neither wedged it.
    let client = rustls_client(port, &authority, None);
    let stream = accept_within(&listener, Duration::from_secs(10)).expect("a real client");
    serve_echo(&stream);
    client.join().expect("thread").expect("the client verified");
}

/// A rustls client that accepts any server certificate and still checks the handshake signature
/// (what a pinned peer does: the key is the identity, and the zid is the verdict).
#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[test]
fn a_pinned_listener_names_the_client_by_the_zid_of_its_key() {
    let _library = library();
    let device = Box::leak(Box::new(
        Identity::generate(c"CN=wz-listener").expect("the listener's identity"),
    ));
    let listener = TlsDial::new(PosixTcpDial, device)
        .with_accept(ACCEPT)
        .listen(LOOPBACK, 0)
        .expect("the port opens");
    let (_, port) = listener.local();

    // The client: a self-signed key of its own, and no verdict on the listener's certificate.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    let cert = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("parameters")
        .self_signed(&key)
        .expect("a self-signed certificate");
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("the client's configuration");
    let client = thread::spawn(move || -> Result<(), std::io::Error> {
        let tcp = TcpStream::connect((Ipv4Addr::from(LOOPBACK), port))?;
        let name = ServerName::try_from("wz.invalid").expect("a name");
        let conn = ClientConnection::new(Arc::new(config), name).expect("a client session");
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"ping")?;
        tls.flush()?;
        let mut got = [0u8; 4];
        tls.read_exact(&mut got)?;
        tls.conn.send_close_notify();
        tls.flush()?;
        Ok(())
    });

    let stream = accept_within(&listener, Duration::from_secs(10)).expect("a pinned client");
    let named = zid_from_spki_der(&key.public_key_der());
    assert_eq!(stream.peer_zid(), Some(named));
    assert_eq!(
        stream.peer_credential_zid(),
        Some(named),
        "a pinned stream's key is the peer's credential"
    );
    serve_echo(&stream);
    client.join().expect("thread").expect("the client served");
}

#[test]
fn a_dial_that_cannot_accept_does_not_take_the_port() {
    let _library = library();
    let device = Box::leak(Box::new(
        Identity::generate(c"CN=wz-dial-only").expect("an identity"),
    ));
    let dial_only = TlsDial::new(PosixTcpDial, device);
    assert!(matches!(
        dial_only.listen(LOOPBACK, 0),
        Err(LinkOpenError::Unsupported)
    ));
}
