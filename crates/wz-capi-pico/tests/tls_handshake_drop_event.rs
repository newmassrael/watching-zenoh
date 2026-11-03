// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "tls-mbedtls", feature = "event-ring"))]

//! A `tls/` listener on the cooperative engine tells the node's event log when it ends a
//! connection without a stream (`docs/capi-pico-on-coop-engine.md`, the L6 record): to the peer a
//! handshake the arena or the key store had no room for is a closed connection, and without this
//! the program sees nothing. Reached through the exported `z_*` and `wz_ext_event_*` symbols as a
//! C program would reach them.
//!
//! What is held: a client that is not speaking TLS is taken off the port, and one event of the
//! library's source `WZ_EXT_EVENT_SOURCE_TLS_HANDSHAKE_DROPPED` and level
//! `WZ_EXT_EVENT_LEVEL_LIBRARY` follows, whose first integer is `WZ_EXT_EVENT_TLS_DROP_OTHER` and
//! whose second is the channel's own code (not 0: a failed handshake has one).
//!
//! The arena running out is held below the provider, where the arena can be made small
//! (`wz-tls-mbedtls`'s `arena_exhaustion`): here it is the one the provider starts, 4 MiB.
//!
//! RED reproduction: with `Timed::tell_the_log` left out of `accept`, the junk connection is
//! dropped as before and the log never receives the event.

use std::ffi::{CStr, CString};
use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine};
use wz_capi_pico::event_log::{
    wz_ext_event_read, wz_ext_event_t, WZ_EXT_EVENT_LEVEL_LIBRARY, WZ_EXT_EVENT_RECORD,
    WZ_EXT_EVENT_SOURCE_TLS_HANDSHAKE_DROPPED, WZ_EXT_EVENT_TLS_DROP_OTHER,
};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::{free_port, localhost_cert_key_pem};

fn base64_of(pem: &str) -> CString {
    CString::new(general_purpose::STANDARD.encode(pem)).unwrap()
}

unsafe fn insert(cfg: &mut z_owned_config_t, key: u8, value: &CStr) {
    assert_eq!(
        zp_config_insert(z_config_loan_mut(cfg), key, value.as_ptr()),
        Z_OK
    );
}

/// A session that listens on `tls/127.0.0.1:port`, presenting the certificate `cert` and its key.
unsafe fn listen(port: u16, cert: &str, key: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    let endpoint = CString::new(format!("tls/127.0.0.1:{port}")).unwrap();
    insert(&mut cfg, Z_CONFIG_LISTEN_KEY, &endpoint);
    insert(
        &mut cfg,
        Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
        &base64_of(cert),
    );
    insert(
        &mut cfg,
        Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY,
        &base64_of(key),
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
    assert_eq!(rc, Z_OK, "the listener opens on tls/127.0.0.1:{port}");
    session
}

/// The first event from `*cursor` on that the library wrote for a dropped handshake, for at most
/// ten seconds: its two integers.
unsafe fn dropped_handshake_event(cursor: &mut u64) -> Option<[u64; 2]> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let mut event: wz_ext_event_t = std::mem::zeroed();
        let mut args = [0u64; 4];
        assert_eq!(
            wz_ext_event_read(cursor, &mut event, args.as_mut_ptr(), args.len()),
            Z_OK
        );
        if event.kind == WZ_EXT_EVENT_RECORD {
            if event.source == WZ_EXT_EVENT_SOURCE_TLS_HANDSHAKE_DROPPED {
                assert_eq!(event.level, WZ_EXT_EVENT_LEVEL_LIBRARY);
                assert_eq!(event.arg_count, 2, "why, and the channel's code");
                return Some([args[0], args[1]]);
            }
            continue;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn a_client_that_is_not_speaking_tls_is_dropped_and_the_event_log_is_told() {
    unsafe {
        let (cert, key) = localhost_cert_key_pem();
        let port = free_port();
        let mut listener = listen(port, &cert, &key);

        let mut cursor = 0u64;
        let mut junk = TcpStream::connect(("127.0.0.1", port)).expect("the port accepts");
        junk.write_all(&[b'G'; 200]).expect("junk leaves");

        let event = dropped_handshake_event(&mut cursor)
            .expect("the event log was told of the dropped connection");
        assert_eq!(
            event[0], WZ_EXT_EVENT_TLS_DROP_OTHER,
            "a failed handshake is not a stall and not a lack of room"
        );
        assert_ne!(event[1], 0, "a failed handshake has the channel's own code");

        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
}
