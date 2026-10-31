// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the chain tests share: the library started once for the binary, a certificate authority
//! and the end certificates it issues (rcgen), and rustls 0.23 as the peer on either side. Each
//! test binary uses a part of it.
#![allow(dead_code)]

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};

use wz_session_core::credential_identity::zid_from_spki_der;
use wz_tls_mbedtls::channel::{arena_peak_reset, start, Identity, Zid};

/// The arena a binary starts the library on: room for every test, which share the process.
pub const ARENA: usize = 256 << 10;

/// The library keeps process-wide state with no lock (its profile has one thread), and the test
/// harness runs tests on several: a test holds this while it uses the library.
static LIBRARY: Mutex<()> = Mutex::new(());
static STARTED: Once = Once::new();

/// The library, started once, held for the test that calls this; the arena's peak restarts.
pub fn library() -> MutexGuard<'static, ()> {
    let guard = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    STARTED.call_once(|| {
        let arena: &'static mut [u8] = vec![0u8; ARENA].leak();
        start(arena).expect("the library starts");
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
    arena_peak_reset();
    guard
}

pub fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs(),
    )
    .expect("a time that fits")
}

/// A certificate authority: a P-256 key and the self-signed certificate that is the root.
pub struct Authority {
    key: KeyPair,
    pub cert: rcgen::Certificate,
}

/// An end certificate the authority issued, with its key.
pub struct End {
    pub key: KeyPair,
    pub cert: rcgen::Certificate,
}

impl Authority {
    pub fn new() -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).expect("a root");
        Self { key, cert }
    }

    pub fn root_pem(&self) -> CString {
        CString::new(self.cert.pem()).expect("PEM has no NUL")
    }

    /// An end certificate for `usage`, covering `localhost` and the loopback address.
    pub fn issue(&self, usage: ExtendedKeyUsagePurpose) -> End {
        self.issue_valid(usage, None)
    }

    /// As [`Authority::issue`], valid only within `window` (years, from and to) when given.
    pub fn issue_valid(&self, usage: ExtendedKeyUsagePurpose, window: Option<(i32, i32)>) -> End {
        self.issue_for(usage, &["localhost"], true, window)
    }

    /// An end certificate covering the DNS names `dns` and, when `loopback`, the loopback
    /// address as an IP address, valid only within `window` (years, from and to) when given.
    pub fn issue_for(
        &self,
        usage: ExtendedKeyUsagePurpose,
        dns: &[&str],
        loopback: bool,
        window: Option<(i32, i32)>,
    ) -> End {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let mut params =
            CertificateParams::new(dns.iter().map(ToString::to_string).collect::<Vec<_>>())
                .expect("parameters");
        if loopback {
            params
                .subject_alt_names
                .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        }
        params.extended_key_usages = vec![usage];
        if let Some((from, to)) = window {
            params.not_before = rcgen::date_time_ymd(from, 1, 1);
            params.not_after = rcgen::date_time_ymd(to, 1, 1);
        }
        let cert = params
            .signed_by(&key, &self.cert, &self.key)
            .expect("an end certificate");
        End { key, cert }
    }
}

impl End {
    pub fn chain_pem(&self) -> CString {
        CString::new(self.cert.pem()).expect("PEM has no NUL")
    }

    pub fn key_pem(&self) -> CString {
        CString::new(self.key.serialize_pem()).expect("PEM has no NUL")
    }

    pub fn identity(&self) -> Identity {
        Identity::from_pem(&self.chain_pem(), &self.key_pem()).expect("the end's identity")
    }

    pub fn zid(&self) -> Zid {
        zid_from_spki_der(&self.key.public_key_der())
    }
}

/// A rustls server on loopback serving one connection in its own thread: echo until the client
/// ends the session. The certificate the client presented, if any, or why the server refused.
pub type Served = thread::JoinHandle<Result<Option<Vec<u8>>, std::io::Error>>;

pub fn serve(config: Arc<ServerConfig>) -> (u16, Served) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().expect("its port").port();
    let served = thread::spawn(move || {
        let (tcp, _) = listener.accept()?;
        let conn = ServerConnection::new(config).expect("a server session");
        let mut tls = StreamOwned::new(conn, tcp);
        let mut buf = [0u8; 256];
        loop {
            match tls.read(&mut buf)? {
                0 => break,
                n => {
                    tls.write_all(&buf[..n])?;
                    tls.flush()?;
                }
            }
        }
        Ok(tls.conn.peer_certificates().map(|chain| chain[0].to_vec()))
    });
    (port, served)
}

/// rustls as zenohd configures it: TLS 1.3, `own` as the server's chain, and a client verifier
/// over `client_roots` when mutual TLS is on.
pub fn server_config(own: &End, client_roots: Option<&Authority>) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = match client_roots {
        None => builder.with_no_client_auth(),
        Some(authority) => {
            let mut roots = RootCertStore::empty();
            roots
                .add(authority.cert.der().clone())
                .expect("a root the server can hold");
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder(roots.into())
                    .build()
                    .expect("a client verifier"),
            )
        }
    };
    Arc::new(
        builder
            .with_single_cert(
                vec![own.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(own.key.serialize_der())),
            )
            .expect("the server's configuration"),
    )
}

/// A rustls client on its own thread: connect to `port`, echo a few bytes, end the session.
pub fn rustls_client(
    port: u16,
    roots: &Authority,
    own: Option<&End>,
) -> thread::JoinHandle<Result<(), std::io::Error>> {
    let mut store = RootCertStore::empty();
    store.add(roots.cert.der().clone()).expect("a root");
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(store);
    let config = match own {
        None => builder.with_no_client_auth(),
        Some(end) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(end.cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(end.key.serialize_der())),
            )
            .expect("the client's configuration"),
    };
    thread::spawn(move || {
        let tcp = TcpStream::connect(("127.0.0.1", port))?;
        let name = ServerName::try_from("localhost").expect("a name");
        let conn = ClientConnection::new(Arc::new(config), name).expect("a client session");
        let mut tls = StreamOwned::new(conn, tcp);
        tls.write_all(b"ping")?;
        tls.flush()?;
        let mut got = [0u8; 4];
        tls.read_exact(&mut got)?;
        assert_eq!(&got, b"ping");
        tls.conn.send_close_notify();
        tls.flush()?;
        Ok(())
    })
}
