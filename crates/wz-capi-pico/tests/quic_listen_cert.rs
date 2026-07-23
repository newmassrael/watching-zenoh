// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-link-quic")]

//! R311y406 — the pico `z_open(listen="quic/..")` cert-threading discriminator: the
//! C ABI now ADMITS a QUIC listen when the config carries the native
//! `Z_CONFIG_TLS_LISTEN_{CERTIFICATE,PRIVATE_KEY}_KEY` PEM paths (was rejected at bind
//! cert-absence, `drive_listen` having bound cert-free via `bind_endpoint`). The pico
//! twin of the demo's `--router`/`--peer`/`--router-hat` cert-threading (R311y405/y406);
//! zenoh feeds ONE listen-cert block to both the tls and quic acceptors, so these are
//! the same keys a `tls/` listen would use.
//!
//! Drives the exported `z_*` symbols exactly as a pico C program would. z_open(listen)
//! is non-blocking (binds + spawns the accept task + returns with zero peers), so this
//! asserts a bind-only witness (`Z_OK`) with no dialer — no network round-trip to race.
//!
//! RED reproduction (proof it binds to the cert-threading seam): revert `drive_listen`
//! to a cert-free bind (`bind_endpoint_with_config(&endpoint, &AcceptConfig::default())`)
//! -> `bind_locator` rejects the quic listen at cert-absence -> `z_open` returns
//! `Z_ERR_GENERIC` (not `Z_OK`) -> the assert below fails. NON-FLAKY: pid-unique temp
//! cert, `quic/127.0.0.1:0` OS-chosen port, no peer.

use std::ffi::CString;
use std::sync::mpsc;
use std::time::Duration;

use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY, Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
    Z_OK,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

#[test]
fn z_open_listen_quic_with_cert_config_binds() {
    // Self-signed `localhost` cert -> pid-unique temp files (the config values are
    // FILE PATHS, mirroring zenoh-pico's native listen-cert keys).
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let cert_path = dir.join(format!("wz-pico-quic-listen-cert-{pid}.pem"));
    let key_path = dir.join(format!("wz-pico-quic-listen-key-{pid}.pem"));
    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");
    let cert_c = CString::new(cert_path.to_string_lossy().into_owned()).unwrap();
    let key_c = CString::new(key_path.to_string_lossy().into_owned()).unwrap();

    let (opened_tx, opened_rx) = mpsc::channel();
    let listener = std::thread::spawn(move || unsafe {
        let endpoint = CString::new("quic/127.0.0.1:0").unwrap();
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY,
                cert_c.as_ptr()
            ),
            Z_OK
        );
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_KEY,
                key_c.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
        let _ = opened_tx.send(rc);
        // Close the (peer-less) listener: the pending accept must be cancellable.
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });

    let rc = opened_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("z_open(listen=quic/ + cert) never returned");
    listener.join().expect("listener thread panicked");

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    assert_eq!(
        rc, Z_OK,
        "z_open(listen=quic/..) with the listen-cert config must bind (R311y406); \
         a non-Z_OK means the cert was not threaded into the quic acceptor"
    );
}
