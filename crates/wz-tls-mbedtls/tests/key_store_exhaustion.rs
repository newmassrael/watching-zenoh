// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A handshake the key store has no slot for is dropped and counted, with the channel's own code.
//! The host build keeps 1024 keys (`MBEDTLS_PSA_KEY_SLOT_COUNT`, `WZ_TLS_HOST`) and a held
//! session takes four, so about 255 sessions fill the store. This binary starts an arena far
//! larger than that many sessions need, so the store runs out first: the arena's own peak stays
//! a fraction of it, which tells the two exhaustions apart (`arena_exhaustion.rs` is the other).

#[path = "common/mod.rs"]
mod common;

use std::io::Read;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use common::{library_sized, Authority};
use wz_runtime_coop::stream_link::StreamListen;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_tls_mbedtls::channel::{arena_peak, Identity, TlsError};
use wz_tls_mbedtls::stream::{AcceptBudget, ChainTrust, TlsDial};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// Room for several times the sessions the key store can hold (about 20 KB each with RSA).
const ARENA_BYTES: usize = 64 << 20;

/// The most sessions the store of 1024 keys can hold at four each, the listener's own identity
/// taking at least one slot.
const STORE_SESSIONS: usize = 256;

fn clock_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).expect("fits")
}

#[test]
fn a_handshake_the_key_store_has_no_slot_for_is_dropped_counted_and_names_a_code() {
    let _library = library_sized(ARENA_BYTES);
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let identity: &'static Identity = Box::leak(Box::new(server.identity()));

    let dial = TlsDial::chain(
        PosixTcpDial,
        ChainTrust {
            identity: Some(identity),
            roots: None,
            mutual: false,
            verify_name: false,
        },
    )
    .with_accept(AcceptBudget {
        clock: clock_ms,
        timeout_ms: 2_000,
    });
    let listener = dial.listen_counted(LOOPBACK, 0).expect("the port opens");
    let (_, port) = listener.local();

    let mut store = RootCertStore::empty();
    store.add(authority.cert.der().clone()).expect("a root");
    let config = Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(store)
            .with_no_client_auth(),
    );

    // Clients that finish the handshake and then hold the connection open until told to go.
    let (release, held) = mpsc::channel::<()>();
    let held = Arc::new(std::sync::Mutex::new(held));
    let mut clients = Vec::new();
    let mut accepted = Vec::new();
    for _ in 0..(STORE_SESSIONS + 64) {
        let config = Arc::clone(&config);
        let held = Arc::clone(&held);
        clients.push(thread::spawn(move || {
            let Ok(tcp) = TcpStream::connect((Ipv4Addr::from(LOOPBACK), port)) else {
                return;
            };
            let name = ServerName::try_from("localhost").expect("a name");
            let conn = ClientConnection::new(config, name).expect("a client session");
            let mut tls = StreamOwned::new(conn, tcp);
            let mut byte = [0u8; 1];
            // Reading drives the handshake; it ends when the listener closes or on release.
            let _ = tls.read(&mut byte);
            let _ = held
                .lock()
                .map(|rx| rx.recv_timeout(Duration::from_secs(60)));
        }));
        let deadline = Instant::now() + Duration::from_millis(1_500);
        let before = listener.dropped();
        while Instant::now() < deadline {
            match listener.accept() {
                Ok(Some(stream)) => {
                    accepted.push(stream);
                    break;
                }
                Err(_) => break,
                Ok(None) if listener.dropped() > before => break,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
            }
        }
        if listener.dropped() > 0 {
            break;
        }
    }

    let (peak, _) = arena_peak().expect("the build measures the arena");
    eprintln!(
        "KEYSTORE accepted={} dropped={} last_drop={:?} arena_peak={} of {}",
        accepted.len(),
        listener.dropped(),
        listener.last_drop(),
        peak,
        ARENA_BYTES
    );
    assert!(
        listener.dropped() > 0,
        "the key store did not run out within {} sessions",
        accepted.len()
    );
    assert!(
        peak < ARENA_BYTES / 2,
        "the arena ran out, not the key store: peak {peak} of {ARENA_BYTES}"
    );
    // Measured: 255 held, the store's 1024 keys at four a session less the identity's slot.
    assert!(
        (STORE_SESSIONS - 16..STORE_SESSIONS).contains(&accepted.len()),
        "{} sessions held, not what a store of 1024 keys at four each gives",
        accepted.len()
    );
    // Measured: Mbed TLS itself reports a full store from inside the handshake as its generic
    // handshake failure (`MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE`, -0x6E00), not as PSA's
    // insufficient-memory code. The channel asks the store (`mbedtls_psa_get_stats`) when a
    // handshake fails that way and names a store with no empty slot `OutOfMemory`; the count and
    // the arena's peak above say it was the store and not the arena.
    assert_eq!(
        listener.last_drop(),
        Some(TlsError::OutOfMemory),
        "a store with no free slot is the channel's out-of-memory"
    );

    drop(accepted);
    for _ in 0..clients.len() {
        let _ = release.send(());
    }
    for client in clients {
        let _ = client.join();
    }
}
