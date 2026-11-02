// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How many secure sessions a host program holds at once (`wz_capi_coop::tls::HostTls`, step T4
//! of L6 in `docs/capi-pico-on-coop-engine.md`).
//!
//! An established TLS 1.3 session holds four of the keys PSA Crypto keeps in a store of a fixed
//! size, and the library's default store holds 32: a listener took 7 sessions and dropped the
//! eighth connection's handshake without a word, with 4 MiB of arena unused. The host build sizes
//! the store to the arena instead (`wz_tls_crypto_config.h`, `WZ_TLS_HOST`), and this holds that a
//! program keeps more sessions than the default store could, both ends of each in this process.
//!
//! This binary does not use the shared library helper that starts a small arena for the other
//! tests: the arena under test is the one the provider starts for itself.

#![cfg(feature = "tls-mbedtls")]

#[path = "../../wz-tls-mbedtls/tests/common/mod.rs"]
mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::ExtendedKeyUsagePurpose;

use common::{Authority, End};
use wz_capi_coop::tls::{HostTls, HOST_ARENA};
use wz_capi_port::tls_material::CapiTlsConfig;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_tls_mbedtls::channel::arena_peak;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const ACCEPT_MS: u64 = 5_000;

/// More connections than the default store of 32 keys could hold (each is two sessions of four
/// keys in this process, so 24 of them are 192 keys), and well within the arena.
const HELD: usize = 24;

type Provider = HostTls<PosixTcpDial>;

fn bytes(pem: std::ffi::CString) -> Vec<u8> {
    pem.as_bytes().to_vec()
}

fn listen_config(server: &End) -> CapiTlsConfig {
    CapiTlsConfig {
        listen_cert_pem: Some(bytes(server.chain_pem())),
        listen_key_pem: Some(bytes(server.key_pem())),
        ..CapiTlsConfig::default()
    }
}

fn dial_config(roots: &Authority) -> CapiTlsConfig {
    CapiTlsConfig {
        root_ca_pem: Some(bytes(roots.root_pem())),
        ..CapiTlsConfig::default()
    }
}

fn provider(config: &CapiTlsConfig) -> Provider {
    Provider::from_config(PosixTcpDial, config, ACCEPT_MS)
        .unwrap_or_else(|e| panic!("the config makes a provider: {e}"))
}

#[test]
fn a_host_holds_more_sessions_than_the_librarys_default_key_store_could() {
    let authority = Authority::new();
    let server = authority.issue(ExtendedKeyUsagePurpose::ServerAuth);
    let listening = provider(&listen_config(&server));
    let listener = listening
        .listen(LOOPBACK, 0)
        .unwrap_or_else(|e| panic!("the listener binds: {e:?}"));
    let port = listener.local().1;

    // Every client keeps its session until the server has answered all of them, so the sessions
    // are live together: the barrier is passed once, by every client and by this thread.
    let all_live = Arc::new(Barrier::new(HELD + 1));
    let config = dial_config(&authority);
    let clients: Vec<_> = (0..HELD)
        .map(|_| {
            let (all_live, config) = (all_live.clone(), config.clone());
            thread::spawn(move || {
                let stream = provider(&config).dial(LOOPBACK, port)?;
                stream
                    .send_parts(&[b"ping".as_slice()])
                    .expect("the stream takes bytes");
                let mut buf = [0u8; 4];
                let deadline = Instant::now() + Duration::from_secs(20);
                let mut got = 0;
                while got < buf.len() && Instant::now() < deadline {
                    match stream.try_read(&mut buf[got..]) {
                        Ok(Some(0)) | Err(_) => break,
                        Ok(Some(n)) => got += n,
                        Ok(None) => stream.wait_readable(10),
                    }
                }
                all_live.wait();
                Ok::<_, wz_runtime_coop::session_drive::LinkOpenError>(buf[..got].to_vec())
            })
        })
        .collect();

    let mut held = Vec::new();
    let started = Instant::now();
    while held.len() < HELD && started.elapsed() < Duration::from_secs(60) {
        match listener.accept() {
            Ok(Some(stream)) => {
                let mut buf = [0u8; 4];
                let mut got = 0;
                let deadline = Instant::now() + Duration::from_secs(20);
                while got < buf.len() && Instant::now() < deadline {
                    match stream.try_read(&mut buf[got..]) {
                        Ok(Some(0)) | Err(_) => break,
                        Ok(Some(n)) => got += n,
                        Ok(None) => stream.wait_readable(10),
                    }
                }
                assert_eq!(&buf[..got], b"ping");
                stream
                    .send_parts(&[b"pong".as_slice()])
                    .expect("the stream takes bytes");
                held.push(stream);
            }
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => panic!("the listener broke after {} sessions: {e:?}", held.len()),
        }
    }
    assert_eq!(
        held.len(),
        HELD,
        "the listener took {} of {HELD} connections: a handshake past the key store's room is \
         dropped, and the peer sees only a close",
        held.len()
    );

    all_live.wait();
    for (n, client) in clients.into_iter().enumerate() {
        let answered = client
            .join()
            .expect("client thread")
            .unwrap_or_else(|e| panic!("client {n} was refused: {e:?}"));
        assert_eq!(answered, b"pong".to_vec(), "client {n} was answered");
    }

    let (peak, blocks) = arena_peak().expect("this build measures the arena");
    std::println!(
        "{HELD} connections, both ends in this process: arena peak {peak} B in {blocks} blocks \
         of {HOST_ARENA} B"
    );
    assert!(peak < HOST_ARENA, "the sessions fit the host's arena");
}
