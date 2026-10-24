// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two sessions of this crate against each other over an in-memory pipe: the handshake, the pin,
//! the data both ways, and what the arena held.

use core::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, Once};
use std::vec::Vec;

use wz_session_core::credential_identity::zid_from_spki_der;

use crate::channel::{
    arena_peak, arena_peak_reset, start, Identity, Io, Role, Session, Step, Transport, Want,
};

/// The library keeps process-wide state with no lock (the profile has one thread), and the test
/// harness runs tests on several: each test holds this for as long as it uses the library.
static LIBRARY: Mutex<()> = Mutex::new(());
static STARTED: Once = Once::new();

fn library() -> MutexGuard<'static, ()> {
    let guard = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    STARTED.call_once(|| {
        let arena: &'static mut [u8] = std::vec![0u8; 512 << 10].leak();
        start(arena).expect("the library starts on its arena");
    });
    guard
}

/// One direction of the pipe, and the largest single write that crossed it: the session writes a
/// record at a time, so that is the largest record.
#[derive(Default)]
struct Ring {
    bytes: RefCell<VecDeque<u8>>,
    max_write: RefCell<usize>,
}

/// One end of the pipe.
struct End<'a> {
    out: &'a Ring,
    inn: &'a Ring,
}

impl Transport for End<'_> {
    fn send(&self, buf: &[u8]) -> Io {
        self.out.bytes.borrow_mut().extend(buf);
        let mut max = self.out.max_write.borrow_mut();
        *max = (*max).max(buf.len());
        Io::Done(buf.len())
    }

    fn recv(&self, buf: &mut [u8]) -> Io {
        let mut bytes = self.inn.bytes.borrow_mut();
        if bytes.is_empty() {
            return Io::WouldBlock;
        }
        let n = buf.len().min(bytes.len());
        for (slot, byte) in buf.iter_mut().zip(bytes.drain(..n)) {
            *slot = byte;
        }
        Io::Done(n)
    }
}

/// Drive both handshakes until both are done.
fn handshake<'a>(
    client: &mut Session<'_, End<'a>>,
    client_end: &End<'a>,
    server: &mut Session<'_, End<'a>>,
    server_end: &End<'a>,
) {
    let (mut client_done, mut server_done) = (false, false);
    for _ in 0..64 {
        if !client_done {
            client_done = client
                .handshake(client_end)
                .expect("the client's handshake")
                == Step::Done(());
        }
        if !server_done {
            server_done = server
                .handshake(server_end)
                .expect("the server's handshake")
                == Step::Done(());
        }
        if client_done && server_done {
            return;
        }
    }
    panic!("the handshake did not finish: client {client_done}, server {server_done}");
}

/// The `SubjectPublicKeyInfo` of a self-signed certificate this crate wrote, found by walking
/// its DER: Certificate -> TBSCertificate -> the seventh element (version, serial, signature,
/// issuer, validity, subject, subjectPublicKeyInfo).
fn spki_of(cert: &[u8]) -> &[u8] {
    /// The (header length, content length) of the DER element at the front of `der`.
    fn element(der: &[u8]) -> (usize, usize) {
        let first = der[1] as usize;
        if first < 0x80 {
            return (2, first);
        }
        let n = first & 0x7f;
        let len = der[2..2 + n]
            .iter()
            .fold(0usize, |len, b| (len << 8) | *b as usize);
        (2 + n, len)
    }
    let (head, _) = element(cert);
    let tbs = &cert[head..];
    let (head, _) = element(tbs);
    let mut at = &tbs[head..];
    for _ in 0..6 {
        let (head, len) = element(at);
        at = &at[head + len..];
    }
    let (head, len) = element(at);
    &at[..head + len]
}

#[test]
fn an_identity_names_the_zid_of_its_certificates_key() {
    let _library = library();
    let id = Identity::generate(c"CN=wz-test").expect("an identity");
    assert_eq!(
        id.zid(),
        zid_from_spki_der(spki_of(id.certificate_der())),
        "the session core's derivation, over the key the certificate carries"
    );
    assert!(
        id.certificate_der().len() < 400,
        "a self-signed P-256 certificate"
    );
}

#[test]
fn both_ends_prove_their_keys_and_each_names_the_others_zid() {
    let _library = library();
    let client_id = Identity::generate(c"CN=wz-client").expect("the client's identity");
    let server_id = Identity::generate(c"CN=wz-server").expect("the server's identity");
    let (to_server, to_client) = (Ring::default(), Ring::default());
    let client_end = End {
        out: &to_server,
        inn: &to_client,
    };
    let server_end = End {
        out: &to_client,
        inn: &to_server,
    };

    arena_peak_reset();
    let mut client = Session::open(Role::Client, &client_id).expect("a client session");
    let mut server = Session::open(Role::Server, &server_id).expect("a server session");
    handshake(&mut client, &client_end, &mut server, &server_end);

    assert_eq!(client.peer_zid(), Ok(server_id.zid()));
    assert_eq!(server.peer_zid(), Ok(client_id.zid()));
    assert_eq!(
        client.suite().and_then(|s| s.to_str().ok()),
        Some("TLS1-3-AES-128-GCM-SHA256")
    );

    let hello = [0x5au8; 1024];
    assert_eq!(client.write(&client_end, &hello), Ok(Step::Done(1024)));
    let mut got = Vec::new();
    let mut buf = [0u8; 300];
    while got.len() < hello.len() {
        match server.read(&server_end, &mut buf).expect("a read") {
            Step::Done(n) => got.extend_from_slice(&buf[..n]),
            Step::Wait(want) => panic!("the record is all there, yet the read waits: {want:?}"),
        }
    }
    assert_eq!(got, hello);
    assert_eq!(
        server.read(&server_end, &mut buf),
        Ok(Step::Wait(Want::Read))
    );

    client.close_notify(&client_end);
    assert_eq!(
        server.read(&server_end, &mut buf),
        Ok(Step::Done(0)),
        "the end of the session"
    );

    let (peak, blocks) = arena_peak().expect("this build measures the arena");
    std::println!(
        "two sessions: arena peak {peak} B in {blocks} blocks; largest record {} B to the \
         server, {} B to the client",
        to_server.max_write.borrow(),
        to_client.max_write.borrow()
    );
    // A TLS 1.3 record: 5 bytes of header, the content (at most the send buffer's 1,500), its
    // 1-byte inner content type, and the 16-byte AEAD tag.
    let record_max = 5 + 1500 + 1 + 16;
    for (direction, ring) in [("to the client", &to_client), ("to the server", &to_server)] {
        assert!(
            *ring.max_write.borrow() <= record_max,
            "every record {direction} fits the 1,500-byte send buffer"
        );
    }
}
