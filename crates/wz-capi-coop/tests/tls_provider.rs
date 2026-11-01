// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `tls/` provider of the cooperative engine on a host (`wz_capi_coop::tls::HostTls`, step T4
//! of L6 in `docs/capi-pico-on-coop-engine.md`): the dial and the listen a stack is given, made
//! from the PEM material a C ABI's config resolved. Each end is a provider, the server on this
//! thread and the client on one of its own, so what is held is that the PEM a config states makes
//! a working channel in both roles and that a config that cannot make one says so.
//!
//! What is held: a chain-verified dial reaches a listener that presents its chain, and both
//! carry bytes; under mutual TLS the listener takes a client whose chain its roots vouch for and
//! none else, and a dial that should present a chain and has none does not connect; a dial that
//! does not trust the listener's root is refused; a config with no material carries no `tls/`
//! link, and a half listener or a mutual listener without roots is a typed error; the time of
//! each dial is stated to the roots, so a certificate that lapsed since they were made is refused;
//! and one set of roots is made for each distinct PEM. (That an identity is made once for each
//! distinct chain and key is the same rule, and is not observable from outside the module.)
#![cfg(feature = "tls-mbedtls")]

#[path = "../../wz-tls-mbedtls/tests/common/mod.rs"]
mod common;

use std::thread;
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;

use common::{library, Authority, End};
use wz_capi_coop::tls::{HostTls, HostTlsError};
use wz_capi_port::tls_material::CapiTlsConfig;
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_posix::stream::PosixTcpDial;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const ACCEPT_MS: u64 = 5_000;
/// September 2020, inside the year the lapsed certificate below was valid for.
const WITHIN_2020: i64 = 1_600_000_000;

type Provider = HostTls<PosixTcpDial>;
type Stream = <Provider as StreamDial>::Stream;
type Listener = Box<dyn StreamListen<Stream = Stream>>;

fn bytes(pem: std::ffi::CString) -> Vec<u8> {
    pem.as_bytes().to_vec()
}

/// What a dialing config states: the roots it verifies the server against, and under mutual TLS
/// the chain it presents.
fn dial_config(roots: &Authority, client: Option<&End>, mutual: bool) -> CapiTlsConfig {
    CapiTlsConfig {
        root_ca_pem: Some(bytes(roots.root_pem())),
        connect_cert_pem: client.map(|c| bytes(c.chain_pem())),
        connect_key_pem: client.map(|c| bytes(c.key_pem())),
        require_client_auth: mutual,
        ..CapiTlsConfig::default()
    }
}

/// What a listening config states: the chain it presents and, under mutual TLS, the roots that
/// vouch for a client.
fn listen_config(server: &End, client_roots: Option<&Authority>) -> CapiTlsConfig {
    CapiTlsConfig {
        listen_cert_pem: Some(bytes(server.chain_pem())),
        listen_key_pem: Some(bytes(server.key_pem())),
        root_ca_pem: client_roots.map(|a| bytes(a.root_pem())),
        require_client_auth: client_roots.is_some(),
        ..CapiTlsConfig::default()
    }
}

fn provider(config: &CapiTlsConfig) -> Provider {
    Provider::from_config(PosixTcpDial, config, ACCEPT_MS)
        .unwrap_or_else(|e| panic!("the config makes a provider: {e}"))
}

/// Bind a listener on a port the stack picks, and the port.
fn bind(config: &CapiTlsConfig) -> (Provider, Listener, u16) {
    let server = provider(config);
    let listener = server
        .listen(LOOPBACK, 0)
        .unwrap_or_else(|e| panic!("the listener binds: {e:?}"));
    let port = listener.local().1;
    (server, listener, port)
}

/// The connection the listener yields within `within`, if it yields one; the accept advances the
/// handshake and never blocks, so it is asked again.
fn accept_within(listener: &Listener, within: Duration) -> Option<Stream> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok(Some(stream)) => return Some(stream),
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("the listener broke: {e:?}"),
        }
    }
    None
}

fn read_within(stream: &Stream, len: usize, within: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < len && Instant::now() < deadline {
        match stream.try_read(&mut buf) {
            Ok(Some(0)) | Err(_) => return None,
            Ok(Some(n)) => got.extend_from_slice(&buf[..n]),
            Ok(None) => stream.wait_readable(10),
        }
    }
    (got.len() == len).then_some(got)
}

/// A client on a thread of its own: dial `port` under `config`, say ping, and report whether pong
/// came back, or why the dial was refused.
fn ping(config: CapiTlsConfig, port: u16) -> thread::JoinHandle<Result<Vec<u8>, LinkOpenError>> {
    thread::spawn(move || {
        let client = provider(&config);
        let stream = client.dial(LOOPBACK, port)?;
        stream
            .send_parts(&[b"ping".as_slice()])
            .expect("the stream takes bytes");
        Ok(read_within(&stream, 4, Duration::from_secs(5)).unwrap_or_default())
    })
}

/// The server's half of [`ping`]: take the connection and answer. `None` when none was taken.
fn pong(listener: &Listener) -> Option<Vec<u8>> {
    let stream = accept_within(listener, Duration::from_secs(10))?;
    let got = read_within(&stream, 4, Duration::from_secs(5))?;
    stream
        .send_parts(&[b"pong".as_slice()])
        .expect("the stream takes bytes");
    Some(got)
}

#[test]
fn a_dial_verifies_the_listeners_chain_and_both_carry_bytes() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (_server, listener, port) = bind(&listen_config(&server, None));

    let client = ping(dial_config(&authority, None, false), port);
    assert_eq!(
        pong(&listener),
        Some(b"ping".to_vec()),
        "the listener took it"
    );
    assert_eq!(
        client.join().expect("thread").expect("the dial connects"),
        b"pong".to_vec()
    );
}

#[test]
fn under_mutual_tls_the_listener_takes_a_vouched_client_and_none_else() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let vouched = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let unvouched = stranger.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let (_server, listener, port) = bind(&listen_config(&server, Some(&authority)));

    // A client whose chain the listener's roots vouch for.
    let client = ping(dial_config(&authority, Some(&vouched), true), port);
    assert_eq!(
        pong(&listener),
        Some(b"ping".to_vec()),
        "the vouched client is taken"
    );
    assert_eq!(
        client.join().expect("thread").expect("the dial connects"),
        b"pong".to_vec()
    );

    // A client whose chain they do not: the listener holds no connection for it.
    let client = ping(dial_config(&authority, Some(&unvouched), true), port);
    assert!(
        accept_within(&listener, Duration::from_millis(1_500)).is_none(),
        "a client the roots do not vouch for is not taken"
    );
    let _ = client.join();
}

#[test]
fn a_dial_that_should_present_a_chain_and_has_none_does_not_connect() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (_server, listener, port) = bind(&listen_config(&server, Some(&authority)));

    // Mutual TLS is on and no pair was given: the channel never connects, rather than
    // degrading to one-way TLS.
    let client = ping(dial_config(&authority, None, true), port);
    let refused = client.join().expect("thread");
    assert!(
        matches!(refused, Err(LinkOpenError::Unsupported)),
        "a mutual dial with no chain: {refused:?}"
    );
    assert!(accept_within(&listener, Duration::from_millis(300)).is_none());
}

#[test]
fn a_dial_that_does_not_trust_the_listeners_root_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (_server, listener, port) = bind(&listen_config(&server, None));

    let client = ping(dial_config(&stranger, None, false), port);
    assert!(
        accept_within(&listener, Duration::from_millis(1_500)).is_none(),
        "no session is made with a dial that refused the chain"
    );
    let refused = client.join().expect("thread");
    assert!(refused.is_err(), "a stranger's root: {refused:?}");
}

#[test]
fn a_config_with_no_material_carries_no_tls_link() {
    let _library = library();
    let none = provider(&CapiTlsConfig::default());
    assert!(!none.carries_any());
    assert!(matches!(
        none.dial(LOOPBACK, 1),
        Err(LinkOpenError::Unsupported)
    ));
    assert!(matches!(
        none.listen(LOOPBACK, 0),
        Err(LinkOpenError::Unsupported)
    ));

    // Roots alone dial and do not listen; a chain and key alone listen and do not dial.
    let authority = Authority::new();
    let dial_only = provider(&dial_config(&authority, None, false));
    assert!(dial_only.carries_any());
    assert!(matches!(
        dial_only.listen(LOOPBACK, 0),
        Err(LinkOpenError::Unsupported)
    ));
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let listen_only = provider(&listen_config(&server, None));
    assert!(matches!(
        listen_only.dial(LOOPBACK, 1),
        Err(LinkOpenError::Unsupported)
    ));
}

#[test]
fn a_config_that_cannot_make_a_channel_is_a_typed_error() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);

    // A chain without its key.
    let half = CapiTlsConfig {
        listen_cert_pem: Some(bytes(server.chain_pem())),
        ..CapiTlsConfig::default()
    };
    let refused = Provider::from_config(PosixTcpDial, &half, ACCEPT_MS).err();
    assert!(
        matches!(refused, Some(HostTlsError::Config(_))),
        "half a listener: {refused:?}"
    );

    // Mutual TLS on a listener with nothing to vouch for a client by.
    let no_roots = CapiTlsConfig {
        require_client_auth: true,
        ..listen_config(&server, None)
    };
    let refused = Provider::from_config(PosixTcpDial, &no_roots, ACCEPT_MS).err();
    assert!(
        matches!(refused, Some(HostTlsError::Config(_))),
        "a mutual listener without roots: {refused:?}"
    );

    // A key that is not the chain's own is the library's refusal, where it is read.
    let other = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let crossed = CapiTlsConfig {
        listen_key_pem: Some(bytes(other.key_pem())),
        ..listen_config(&server, None)
    };
    let refused = Provider::from_config(PosixTcpDial, &crossed, ACCEPT_MS).err();
    assert!(
        matches!(refused, Some(HostTlsError::Tls(_))),
        "a key that is not the chain's: {refused:?}"
    );

    // A PEM is a C string to the library, so a NUL in one is refused and not truncated.
    let nul = CapiTlsConfig {
        root_ca_pem: Some(b"-----BEGIN CERTIFICATE-----\0".to_vec()),
        ..CapiTlsConfig::default()
    };
    let refused = Provider::from_config(PosixTcpDial, &nul, ACCEPT_MS).err();
    assert!(
        matches!(refused, Some(HostTlsError::Config(_))),
        "a PEM with a NUL: {refused:?}"
    );
}

#[test]
fn the_time_of_each_dial_is_stated_to_the_roots() {
    let _library = library();
    let authority = Authority::new();
    let lapsed = authority.issue_valid(ExtendedKeyUsagePurpose::ServerAuth, Some((2020, 2021)));
    let (_server, listener, port) = bind(&listen_config(&lapsed, None));

    // The roots were made in 2020 as far as the library is told. Were the dial not to state the
    // time before it connects, this certificate would be taken for as long as the program lives.
    let config = dial_config(&authority, None, false);
    let client = thread::spawn(move || {
        let client = provider(&config);
        client
            .dial_roots()
            .expect("a dial has roots")
            .set_now(Some(WITHIN_2020));
        client.dial(LOOPBACK, port).map(|_| ())
    });
    assert!(
        accept_within(&listener, Duration::from_millis(1_500)).is_none(),
        "no session is made over a certificate that lapsed"
    );
    let refused = client.join().expect("thread");
    assert!(refused.is_err(), "a certificate that lapsed: {refused:?}");
}

#[test]
fn one_set_of_roots_is_made_for_each_distinct_pem() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let first = provider(&dial_config(&authority, None, false));
    let second = provider(&dial_config(&authority, None, false));
    assert!(
        std::ptr::eq(first.dial_roots().unwrap(), second.dial_roots().unwrap()),
        "the same bundle lends the same roots"
    );
    let other = Authority::new();
    let third = provider(&dial_config(&other, None, false));
    assert!(
        !std::ptr::eq(first.dial_roots().unwrap(), third.dial_roots().unwrap()),
        "another bundle makes its own"
    );

    // The roots a listener checks a client against are the same kind of value, and the same rule.
    let config = listen_config(&server, Some(&authority));
    let a = provider(&config);
    let b = provider(&config);
    assert!(std::ptr::eq(
        a.listen_roots().unwrap(),
        b.listen_roots().unwrap()
    ));
}
