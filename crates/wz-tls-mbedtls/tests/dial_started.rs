// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel's dial begun without waiting (`StreamDial::dial_started`), which is how the
//! cooperative engine dials a `tls/` endpoint while it holds the session: the stream comes back
//! before the connection under it is made, and runs one step of its handshake for each ask of
//! `StreamSocket::connected`, so no ask waits for the peer. Against rustls 0.23 on the other side
//! of the socket, as `stream_policy.rs` is.
//!
//! What is held: a peer that never answers the handshake leaves every ask prompt, with the
//! client's first handshake record sent; a peer that answers completes the handshake over several
//! asks and the stream then names the peer and carries bytes; a port nobody listens on is
//! refused, when the dial begins or at a later ask; and a server the dial does not trust fails
//! the handshake as the channel's error.
#![cfg(feature = "vendored")]

mod common;

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;

use common::{library, now_unix, serve, server_config, Authority};
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_tls_mbedtls::channel::Trust;
use wz_tls_mbedtls::stream::{ChainTrust, TlsDial, TlsStreamError};

/// `port` on the IPv4 loopback.
fn at(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// The dial of a client that verifies the server against `authority`'s root.
fn chain_dial(authority: &Authority) -> TlsDial<PosixTcpDial> {
    let roots: &'static Trust = Box::leak(Box::new(
        Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots"),
    ));
    TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: None,
            roots: Some(roots),
            mutual: false,
            verify_name: false,
        },
    )
}

/// Ask `stream` until it is made or refused, a millisecond apart as an engine's steps are, for
/// at most `within`.
fn ask_until_answered<S: StreamSocket>(
    stream: &mut S,
    within: Duration,
) -> (Result<(), S::Error>, usize) {
    let until = Instant::now() + within;
    let mut asks = 0;
    loop {
        asks += 1;
        match stream.connected() {
            Ok(true) => return (Ok(()), asks),
            Ok(false) => {}
            Err(e) => return (Err(e), asks),
        }
        assert!(Instant::now() < until, "the dial was never answered");
        thread::sleep(Duration::from_millis(1));
    }
}

/// A peer that takes the connection and never answers the handshake: twenty asks together take
/// far less than one wait of the waiting dial's budget (100 ms), each answering that the stream
/// is not made, and the peer has the client's first handshake record.
#[test]
fn a_begun_dial_answers_every_ask_at_once_while_the_peer_says_nothing() {
    let _library = library();
    let authority = Authority::new();
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener");
    let port = silent.local_addr().expect("its port").port();

    let mut stream = chain_dial(&authority)
        .dial_started(at(port))
        .expect("the dial begins");
    let (mut peer, _) = silent.accept().expect("the connection arrives");
    let mut spent = Duration::ZERO;
    for _ in 0..20 {
        let asked = Instant::now();
        let answer = stream.connected();
        spent += asked.elapsed();
        assert!(
            matches!(answer, Ok(false)),
            "a peer that says nothing makes no stream"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        spent < Duration::from_millis(1_000),
        "twenty asks waited {spent:?} for a peer that says nothing"
    );

    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a read timeout");
    let mut first = [0u8; 1];
    peer.read_exact(&mut first)
        .expect("the client's first record arrived");
    assert_eq!(first[0], 0x16, "a handshake record");
}

/// A peer that answers: the handshake completes over more than one ask, as the peer's records
/// arrive, and the stream once made names the server by its key, offers no credential zid (a
/// chain peer), stays made, and carries bytes both ways.
#[test]
fn a_begun_dial_completes_its_handshake_one_step_for_each_ask() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let mut stream = chain_dial(&authority)
        .dial_started(at(port))
        .expect("the dial begins");
    let (answer, asks) = ask_until_answered(&mut stream, Duration::from_secs(10));
    assert!(answer.is_ok(), "the server's chain verifies: {answer:?}");
    assert!(
        asks > 1,
        "the peer's records came after the first ask, which did not wait for them"
    );
    assert_eq!(stream.peer_zid(), Some(server.zid()));
    assert_eq!(stream.peer_credential_zid(), None);
    assert!(
        matches!(stream.connected(), Ok(true)),
        "a made stream stays made"
    );

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
    stream.shutdown();
    assert_eq!(served.join().expect("thread").expect("served"), None);
}

/// A loopback port that refuses every connect for as long as the value lives. Its number is the
/// near end of a connection the value holds open, so no other socket is bound to it, and nothing
/// listens on it, so a connect to it is answered with a reset. The tree's guard
/// (`wz_runtime_tokio_test_support::refusing_port`, a socket bound and never listening) needs a
/// call the standard library does not make, and its crate would bring the tokio runtime into
/// these tests.
struct RefusingPort {
    _listener: TcpListener,
    held: TcpStream,
}

impl RefusingPort {
    fn hold() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener");
        let held = TcpStream::connect(listener.local_addr().expect("its address"))
            .expect("a connection to hold");
        Self {
            _listener: listener,
            held,
        }
    }

    fn port(&self) -> u16 {
        self.held.local_addr().expect("the held number").port()
    }
}

/// A port nobody listens on: the dial is refused, by the stack when it begins or as the answer
/// of a later ask, and is never made.
#[test]
fn a_begun_dial_to_a_closed_port_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let closed = RefusingPort::hold();

    match chain_dial(&authority).dial_started(at(closed.port())) {
        Err(refused) => assert_eq!(refused, LinkOpenError::Refused),
        Ok(mut stream) => {
            let (answer, _) = ask_until_answered(&mut stream, Duration::from_secs(10));
            assert!(
                matches!(answer, Err(TlsStreamError::Transport(_))),
                "the connection under the channel was refused: {answer:?}"
            );
        }
    }
}

/// A server whose chain the dial's roots do not vouch for: the handshake fails at an ask, as the
/// channel's own error and not the connection's.
#[test]
fn a_begun_dial_to_a_server_it_does_not_trust_fails_its_handshake() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new().issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&stranger, None));

    let mut stream = chain_dial(&authority)
        .dial_started(at(port))
        .expect("the dial begins");
    let (answer, _) = ask_until_answered(&mut stream, Duration::from_secs(10));
    assert!(
        matches!(answer, Err(TlsStreamError::Tls(_))),
        "the chain does not verify: {answer:?}"
    );
    drop(stream);
    assert!(
        served.join().expect("thread").is_err(),
        "the server saw the handshake end"
    );
}
