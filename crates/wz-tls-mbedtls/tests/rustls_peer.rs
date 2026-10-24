// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel's dial against the peer a zenoh router is: rustls 0.23 configured the way zenohd
//! 1.10.1's TLS link configures it with mutual TLS on (TLS 1.3 only, the ring provider, webpki's
//! client verifier over the `root_ca_certificate` it is given;
//! `io/zenoh-links/zenoh-link-tls/src/utils.rs` @
//! `let client_auth = WebPkiClientVerifier::builder(root_cert_store.into()).build()?;`).
//!
//! The router's certificate is self-signed over a P-256 key, as an operator makes one, and its
//! root store holds the dialling device's own self-signed certificate: that is how a router pins
//! a device by certificate. The dial must complete, each end must name the other's key, and
//! bytes must cross both ways through the stream the link would run over; a router that pins
//! another certificate must refuse the device.
//!
//! The channel runs here, so this links the library `vendored` builds.
#![cfg(feature = "vendored")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use wz_runtime_coop::ip_stack::{IpDriver, IpLinks};
use wz_runtime_coop::session_drive::{IpEndpoint, LinkOpenError, Locator, SessionLinks};
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_session_core::credential_identity::zid_from_spki_der;
use wz_session_core::link::BoxedLinkDriver;
use wz_tls_mbedtls::channel::{start, Identity, Zid};
use wz_tls_mbedtls::stream::{HandshakeBudget, TlsDial};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// The library keeps process-wide state with no lock (its profile has one thread), and the test
/// harness runs tests on several: a test holds this while it uses the library.
static LIBRARY: Mutex<()> = Mutex::new(());
static STARTED: Once = Once::new();

/// The library, started once, and a device identity for the test that holds the lock.
fn device() -> (MutexGuard<'static, ()>, &'static Identity) {
    let guard = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    STARTED.call_once(|| {
        let arena: &'static mut [u8] = vec![0u8; 256 << 10].leak();
        start(arena).expect("the library starts");
    });
    let id = Identity::generate(c"CN=wz-device").expect("the device's identity");
    (guard, Box::leak(Box::new(id)))
}

/// A router's identity, as an operator makes it: a P-256 key and a self-signed certificate, and
/// the zid the key names.
struct RouterIdentity {
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

impl RouterIdentity {
    fn generate() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
        let cert = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("certificate parameters")
            .self_signed(&key)
            .expect("a self-signed certificate");
        Self { key, cert }
    }

    fn zid(&self) -> Zid {
        zid_from_spki_der(&self.key.public_key_der())
    }
}

/// zenohd's server configuration with mutual TLS on, pinning `root` (a certificate, DER).
fn router_config(own: &RouterIdentity, root: &[u8]) -> Arc<ServerConfig> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root.to_vec()))
        .expect("a self-signed certificate is a root the router can hold");
    let client_auth = WebPkiClientVerifier::builder(roots.into())
        .build()
        .expect("a client verifier");
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_auth)
        .with_single_cert(
            vec![own.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(own.key.serialize_der())),
        )
        .expect("the router's configuration");
    Arc::new(config)
}

/// The router's side of one connection: the handshake, then an echo of what the device sends
/// until it ends the session. The certificate the router verified, or why it refused.
fn serve(listener: TcpListener, config: Arc<ServerConfig>) -> Result<Vec<u8>, std::io::Error> {
    let (tcp, _) = listener.accept()?;
    let conn = ServerConnection::new(config).expect("a server session");
    let mut tls = StreamOwned::new(conn, tcp);
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf)? {
            0 => break,
            n => {
                tls.write_all(&buf[..n])?;
                tls.flush()?;
            }
        }
    }
    let presented = tls
        .conn
        .peer_certificates()
        .expect("a verified device certificate");
    Ok(presented[0].to_vec())
}

/// A router listening on loopback, serving one connection in its own thread.
fn listen(config: Arc<ServerConfig>) -> (u16, thread::JoinHandle<Result<Vec<u8>, std::io::Error>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().expect("its port").port();
    (port, thread::spawn(move || serve(listener, config)))
}

fn dial(device: &'static Identity) -> TlsDial<PosixTcpDial> {
    TlsDial::new(PosixTcpDial, device).with_budget(HandshakeBudget {
        wait_ms: 100,
        waits: 50,
    })
}

#[test]
fn a_device_dials_a_router_that_pins_its_certificate_and_each_names_the_others_key() {
    let (_library, device) = device();
    let router = RouterIdentity::generate();
    let (port, served) = listen(router_config(&router, device.certificate_der()));

    let stream = dial(device)
        .dial(LOOPBACK, port)
        .expect("the channel opens");
    assert_eq!(
        stream.peer_zid(),
        router.zid(),
        "the device names the router by the key the router proved"
    );
    assert_eq!(stream.suite(), Some("TLS1-3-AES-128-GCM-SHA256"));

    // A length and a batch, as the stream link writes them, and their echo.
    let batch = [0xa5u8; 1024];
    stream
        .send_parts(&[&1024u16.to_le_bytes(), &batch])
        .expect("the batch leaves");
    let mut echoed = Vec::new();
    let mut buf = [0u8; 512];
    for _ in 0..100 {
        if echoed.len() == 2 + batch.len() {
            break;
        }
        stream.wait_readable(100);
        if let Some(n) = stream.try_read(&mut buf).expect("a read") {
            assert_ne!(n, 0, "the router ended the session early");
            echoed.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(&echoed[..2], &1024u16.to_le_bytes());
    assert_eq!(&echoed[2..], &batch[..]);

    stream.shutdown();
    let presented = served
        .join()
        .expect("the router's thread")
        .expect("the router served");
    assert_eq!(
        presented,
        device.certificate_der(),
        "the router verified the device's own certificate"
    );
}

#[test]
fn a_router_that_pins_another_certificate_refuses_the_device() {
    let (_library, device) = device();
    let router = RouterIdentity::generate();
    let stranger = RouterIdentity::generate();
    let (port, served) = listen(router_config(&router, stranger.cert.der()));

    assert!(matches!(
        dial(device).dial(LOOPBACK, port),
        Err(LinkOpenError::Refused)
    ));
    assert!(
        served.join().expect("the router's thread").is_err(),
        "the router refused the handshake"
    );
}

#[test]
fn a_tls_locator_opens_the_stream_link_over_the_channel_on_the_hosts_links() {
    let (_library, device) = device();
    let router = RouterIdentity::generate();
    let (port, served) = listen(router_config(&router, device.certificate_der()));

    // The heap profile's links over the host's sockets, given the channel for `tls/`.
    let links =
        IpLinks::<PosixUdpSocket, PosixTcpDial>::new(LOOPBACK, PosixTcpDial).with_tls(dial(device));
    let at = IpEndpoint {
        addr: LOOPBACK,
        port,
    };
    let link = links
        .open_initiator(Locator::tls(at))
        .expect("the secure stream link opens")
        .pump;
    let IpDriver::Tls(_) = &*link else {
        panic!("a `tls/` dial opened another kind of link");
    };
    assert_eq!(
        link.link_endpoints().map(|ends| ends.dst.as_str()),
        Some(format!("tls/127.0.0.1:{port}").as_str())
    );
    assert_eq!(
        link.peer_credential_zid(),
        Some(router.zid()),
        "the link hands the session the key the router proved"
    );

    link.close_blocking();
    let presented = served
        .join()
        .expect("the router's thread")
        .expect("the router served until the device ended the session");
    assert_eq!(presented, device.certificate_der());
}
