// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel's chain trust policy against rustls 0.23, the TLS stack zenohd 1.10.2 links: a
//! certificate authority issues the end certificates, and each end answers "who is the peer" by
//! verifying the chain against the authority's root instead of pinning the key's zid.
//!
//! What a pico `tls/` link does is what a client does here (`root_ca_certificate`, a name check
//! only when it is asked for, a client certificate only under mutual TLS), so the tests state
//! each of those: the chain verifies, the root must be the right one, the name must be covered
//! when one is given, the dates are held to the time the caller supplies, mutual TLS refuses a
//! client without a certificate of the authority's, and the server role presents a chain a rustls
//! client verifies.
//!
//! These drive the session itself, over a blocking socket; the stream, dial and listener built on
//! it are `stream_policy.rs`. The channel runs here, so this links the library `vendored` builds.
#![cfg(feature = "vendored")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use rcgen::ExtendedKeyUsagePurpose;

use common::{library, now_unix, rustls_client, serve, server_config, Authority};
use wz_tls_mbedtls::channel::{
    arena_peak, Identity, Io, Role, Session, Step, TlsError, Transport, Trust, Zid,
};

/// What a client that verifies a two-link chain (root, end) with a name check may take from the
/// arena, in bytes. Measured at 26,656 on the pinned Mbed TLS; a verification that grows past
/// this is a failing test, not a late surprise on a device whose arena is its whole budget.
const CHAIN_CLIENT_ARENA: usize = 32 << 10;

/// A blocking TCP stream as the channel's transport: no call ever reports "would block".
struct Tcp(TcpStream);

impl Transport for Tcp {
    fn send(&self, buf: &[u8]) -> Io {
        match (&self.0).write(buf) {
            Ok(n) => Io::Done(n),
            Err(_) => Io::Failed,
        }
    }

    fn recv(&self, buf: &mut [u8]) -> Io {
        match (&self.0).read(buf) {
            Ok(n) => Io::Done(n),
            Err(_) => Io::Failed,
        }
    }
}

fn handshake(session: &mut Session<'_, Tcp>, io: &Tcp) -> Result<(), TlsError> {
    loop {
        if let Step::Done(()) = session.handshake(io)? {
            return Ok(());
        }
    }
}

/// Send `data`, then read the same number of bytes back. A peer that ended the session, or never
/// answered, is [`TlsError::Transport`].
fn echo(session: &mut Session<'_, Tcp>, io: &Tcp, data: &[u8]) -> Result<(), TlsError> {
    let mut sent = 0;
    while sent < data.len() {
        if let Step::Done(n) = session.write(io, &data[sent..])? {
            sent += n;
        }
    }
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < data.len() {
        match session.read(io, &mut buf)? {
            Step::Done(0) => return Err(TlsError::Transport),
            Step::Done(n) => got.extend_from_slice(&buf[..n]),
            Step::Wait(_) => {}
        }
    }
    assert_eq!(got, data);
    Ok(())
}

/// A wz client: connect to `port`, handshake, and echo a few bytes. The zid of the key the server
/// proved, or why the session failed.
fn wz_client(
    port: u16,
    own: Option<&Identity>,
    trust: &Trust,
    server_name: Option<&std::ffi::CStr>,
) -> Result<Zid, TlsError> {
    let io = Tcp(TcpStream::connect(("127.0.0.1", port)).expect("the server listens"));
    let mut session = Session::open_chain(Role::Client, own, Some(trust), server_name)?;
    handshake(&mut session, &io)?;
    let zid = session.peer_zid()?;
    echo(&mut session, &io, b"ping")?;
    session.close_notify(&io);
    Ok(zid)
}

#[test]
fn a_client_verifies_the_servers_chain_and_names_the_key_it_proved() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let trust = Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots");
    let zid = wz_client(port, None, &trust, Some(c"localhost")).expect("the chain verifies");

    assert_eq!(
        zid,
        server.zid(),
        "the session names the key the chain ends in"
    );
    let presented = served.join().expect("thread").expect("the server served");
    assert_eq!(presented, None, "no client certificate was asked for");
    let (peak, _) = arena_peak().expect("the build measures the arena");
    assert!(
        peak <= CHAIN_CLIENT_ARENA,
        "a client that verifies a chain used {peak} bytes of the arena, over its {CHAIN_CLIENT_ARENA}"
    );
}

#[test]
fn an_address_literal_is_matched_against_the_certificates_ip_address() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let trust = Trust::roots(&authority.root_pem(), None).expect("the roots");
    wz_client(port, None, &trust, Some(c"127.0.0.1")).expect("the IP SAN covers the address");
    served.join().expect("thread").expect("the server served");
}

#[test]
fn a_client_that_states_no_name_checks_none() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let trust = Trust::roots(&authority.root_pem(), None).expect("the roots");
    wz_client(port, None, &trust, None).expect("no name, no name check");
    served.join().expect("thread").expect("the server served");
}

#[test]
fn a_name_the_certificate_does_not_cover_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let trust = Trust::roots(&authority.root_pem(), None).expect("the roots");
    let refused = wz_client(port, None, &trust, Some(c"router.invalid"));
    assert!(matches!(refused, Err(TlsError::Code(_))), "{refused:?}");
    let _ = served.join();
}

#[test]
fn a_chain_that_does_not_end_in_the_given_root_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let stranger = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let (port, served) = serve(server_config(&server, None));

    let trust = Trust::roots(&stranger.root_pem(), None).expect("the roots");
    let refused = wz_client(port, None, &trust, Some(c"localhost"));
    assert!(matches!(refused, Err(TlsError::Code(_))), "{refused:?}");
    let _ = served.join();
}

#[test]
fn dates_are_held_to_the_time_the_caller_supplies_and_to_none_without_one() {
    let _library = library();
    let authority = Authority::new();
    let expired = authority.issue_valid(ExtendedKeyUsagePurpose::ServerAuth, Some((2020, 2021)));

    let (port, served) = serve(server_config(&expired, None));
    let trust = Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots");
    let refused = wz_client(port, None, &trust, Some(c"localhost"));
    assert!(
        matches!(refused, Err(TlsError::Code(_))),
        "an expired certificate at a supplied time: {refused:?}"
    );
    let _ = served.join();

    let (port, served) = serve(server_config(&expired, None));
    let clockless = Trust::roots(&authority.root_pem(), None).expect("the roots");
    wz_client(port, None, &clockless, Some(c"localhost"))
        .expect("a device with no clock holds no certificate to its dates");
    served.join().expect("thread").expect("the server served");

    // Before the certificate's first day, the same time is a refusal too.
    let future = authority.issue_valid(ExtendedKeyUsagePurpose::ServerAuth, Some((2090, 2091)));
    let (port, served) = serve(server_config(&future, None));
    let refused = wz_client(port, None, &trust, Some(c"localhost"));
    assert!(
        matches!(refused, Err(TlsError::Code(_))),
        "a certificate not yet valid: {refused:?}"
    );
    let _ = served.join();
}

#[test]
fn mutual_tls_presents_the_clients_chain_and_a_client_without_one_is_refused() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let client = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let identity = client.identity();
    let trust = Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots");

    let (port, served) = serve(server_config(&server, Some(&authority)));
    wz_client(port, Some(&identity), &trust, Some(c"localhost")).expect("the client is verified");
    let presented = served.join().expect("thread").expect("the server served");
    assert_eq!(
        presented.as_deref(),
        Some(client.cert.der().as_ref()),
        "the server verified the client's own certificate"
    );

    // TLS 1.3 finishes the client's handshake before the server's verdict on the client's
    // certificate reaches it, so the refusal comes at the handshake or at the first read; either
    // way the client is never left with a session that carries data.
    let (port, served) = serve(server_config(&server, Some(&authority)));
    let refused = wz_client(port, None, &trust, Some(c"localhost"));
    assert!(
        refused.is_err(),
        "a client with no certificate: {refused:?}"
    );
    assert!(
        served.join().expect("thread").is_err(),
        "the server refused the handshake"
    );
}

/// A wz server: accept one connection, handshake, and echo until the client ends the session.
/// The zid of the key the client proved, when it presented one.
fn wz_server(
    listener: &TcpListener,
    own: &Identity,
    trust: Option<&Trust>,
) -> Result<Option<Zid>, TlsError> {
    let (tcp, _) = listener.accept().expect("a client");
    let io = Tcp(tcp);
    let mut session = Session::open_chain(Role::Server, Some(own), trust, None)?;
    handshake(&mut session, &io)?;
    let zid = session.peer_zid().ok();
    let mut buf = [0u8; 64];
    loop {
        match session.read(&io, &mut buf)? {
            Step::Done(0) => return Ok(zid),
            Step::Done(n) => {
                let mut sent = 0;
                while sent < n {
                    if let Step::Done(m) = session.write(&io, &buf[sent..n])? {
                        sent += m;
                    }
                }
            }
            Step::Wait(_) => {}
        }
    }
}

#[test]
fn a_server_presents_its_chain_and_a_rustls_client_verifies_it() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let identity = server.identity();
    assert_eq!(identity.zid(), server.zid());

    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().expect("its port").port();
    let client = rustls_client(port, &authority, None);
    let peer = wz_server(&listener, &identity, None).expect("the server served");
    client.join().expect("thread").expect("the client verified");
    assert_eq!(peer, None, "a server with no roots asks for no certificate");
}

#[test]
fn a_server_with_roots_requires_a_client_chain_that_verifies() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let client = authority.issue(ExtendedKeyUsagePurpose::ClientAuth);
    let identity = server.identity();
    let trust = Trust::roots(&authority.root_pem(), Some(now_unix())).expect("the roots");

    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let port = listener.local_addr().expect("its port").port();
    let peer = rustls_client(port, &authority, Some(&client));
    let named = wz_server(&listener, &identity, Some(&trust)).expect("the server served");
    peer.join().expect("thread").expect("the client served");
    assert_eq!(
        named,
        Some(client.zid()),
        "the server names the client's key"
    );

    // A client with no certificate, and one the roots do not vouch for, are both refused.
    let stranger = Authority::new();
    let strange_client = stranger.issue(ExtendedKeyUsagePurpose::ClientAuth);
    for presented in [None, Some(&strange_client)] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("its port").port();
        let peer = rustls_client(port, &authority, presented);
        let refused = wz_server(&listener, &identity, Some(&trust));
        assert!(refused.is_err(), "{refused:?}");
        assert!(peer.join().expect("thread").is_err());
    }
}

#[test]
fn a_chain_session_needs_what_its_role_needs() {
    let _library = library();
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let identity = server.identity();
    let trust = Trust::roots(&authority.root_pem(), None).expect("the roots");

    let no_roots = Session::<Tcp>::open_chain(Role::Client, None, None, None);
    assert!(matches!(no_roots, Err(TlsError::NoTrust)));
    let no_identity = Session::<Tcp>::open_chain(Role::Server, None, Some(&trust), None);
    assert!(matches!(no_identity, Err(TlsError::NoTrust)));
    let client = Session::<Tcp>::open_chain(Role::Client, Some(&identity), Some(&trust), None);
    assert!(client.is_ok(), "a client may present a chain of its own");
}

#[test]
fn a_key_that_is_not_the_chains_own_is_refused_where_it_is_read() {
    let _library = library();
    let authority = Authority::new();
    let one = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let other = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);

    assert!(Identity::from_pem(&one.chain_pem(), &other.key_pem()).is_err());
    assert!(Identity::from_pem(c"not a certificate", &one.key_pem()).is_err());
    assert!(Identity::from_pem(&one.chain_pem(), c"not a key").is_err());
    assert!(Trust::roots(c"not a certificate", None).is_err());
}
