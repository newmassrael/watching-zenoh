// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "tls-mbedtls")]

//! The `tls/` link on the cooperative engine, reached through the exported `z_*` symbols as a C
//! program would reach it (step T4 of L6, `docs/capi-pico-on-coop-engine.md`): a session listens
//! on `tls/<address>` with the certificate chain and key the `Z_CONFIG_TLS_LISTEN_*` keys name, a
//! second dials it with the roots `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY` names, and what
//! each puts reaches the other. The keys are the inline base64 forms, which the stock examples use
//! and which leave no file to clean up.
//!
//! What is held: a dial that trusts the listener's certificate opens a session that carries a put
//! each way; a dial that trusts another certificate does not open.
//!
//! RED reproduction (proof it binds to the resolution and the provider): with the open's `tls`
//! left out of `HostTls::from_config` (the links built without `with_tls`), the `tls/` endpoint is
//! the stack's `Unsupported` and the first `z_open` below fails.

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_TLS_LISTEN_CERTIFICATE_BASE64_KEY,
    Z_CONFIG_TLS_LISTEN_PRIVATE_KEY_BASE64_KEY, Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::{free_port, localhost_cert_key_pem};

struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

unsafe extern "C" fn on_sample_record_keyexpr(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
    let mut view: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view) != Z_OK {
        return;
    }
    let string = z_view_string_loan(&view);
    let (data, len) = (z_string_data(string), z_string_len(string));
    if data.is_null() {
        return;
    }
    if let Ok(key) = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len)) {
        ctx.seen.lock().unwrap().insert(key.to_owned());
    }
}

unsafe extern "C" fn on_drop_set(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut SetCtx));
}

fn base64_of(pem: &str) -> CString {
    CString::new(general_purpose::STANDARD.encode(pem)).unwrap()
}

unsafe fn insert(cfg: &mut z_owned_config_t, key: u8, value: &CStr) {
    assert_eq!(
        zp_config_insert(z_config_loan_mut(cfg), key, value.as_ptr()),
        Z_OK
    );
}

/// Open the session `cfg` states, and the code the open answered.
unsafe fn open(mut cfg: z_owned_config_t) -> (z_owned_session_t, i8) {
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
    (session, rc)
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
    let (session, rc) = open(cfg);
    assert_eq!(rc, Z_OK, "the listener opens on tls/127.0.0.1:{port}");
    session
}

/// The open of a dial to `tls/127.0.0.1:port` that trusts `root`.
unsafe fn dial(port: u16, root: &str) -> (z_owned_session_t, i8) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    let endpoint = CString::new(format!("tls/127.0.0.1:{port}")).unwrap();
    insert(&mut cfg, Z_CONFIG_CONNECT_KEY, &endpoint);
    insert(
        &mut cfg,
        Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY,
        &base64_of(root),
    );
    open(cfg)
}

unsafe fn put(session: &z_owned_session_t, key: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, c"payload".as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut buf),
            std::ptr::null(),
        ),
        Z_OK
    );
}

/// A subscriber on `demo/**` of `session`, and the keys it has heard.
unsafe fn hearing(
    session: &z_owned_session_t,
) -> (Arc<Mutex<BTreeSet<String>>>, z_owned_subscriber_t) {
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(on_sample_record_keyexpr),
            Some(on_drop_set),
            ctx
        ),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    (seen, sub)
}

/// Put `key` from `from` until `seen` holds it, for at most ten seconds.
unsafe fn put_until_seen(
    from: &z_owned_session_t,
    key: &CStr,
    seen: &Arc<Mutex<BTreeSet<String>>>,
) -> bool {
    let wanted = key.to_str().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if seen.lock().unwrap().contains(wanted) {
            return true;
        }
        put(from, key);
        std::thread::sleep(Duration::from_millis(20));
    }
    seen.lock().unwrap().contains(wanted)
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

#[test]
fn a_dial_that_trusts_the_listeners_certificate_opens_a_session_that_carries_a_put_each_way() {
    unsafe {
        let (cert, key) = localhost_cert_key_pem();
        let port = free_port();
        let mut listener = listen(port, &cert, &key);
        let (heard_by_listener, mut listener_sub) = hearing(&listener);

        // The listener's own certificate is the root the dial trusts.
        let (mut client, rc) = dial(port, &cert);
        assert_eq!(rc, Z_OK, "the dial opens over tls/ to {port}");
        let (heard_by_client, mut client_sub) = hearing(&client);

        assert!(
            put_until_seen(&client, c"demo/from/client", &heard_by_listener),
            "a put of the dial reaches the listener over the secure channel"
        );
        assert!(
            put_until_seen(&listener, c"demo/from/listener", &heard_by_client),
            "a put of the listener reaches the dial over the secure channel"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut client_sub));
        z_undeclare_subscriber(z_subscriber_move(&mut listener_sub));
        close_session(&mut client);
        close_session(&mut listener);
    }
}

#[test]
fn a_dial_that_trusts_another_certificate_does_not_open() {
    unsafe {
        let (cert, key) = localhost_cert_key_pem();
        let (stranger, _) = localhost_cert_key_pem();
        assert_ne!(cert, stranger, "the fixture makes a certificate of its own");
        let port = free_port();
        let mut listener = listen(port, &cert, &key);

        let (_session, rc) = dial(port, &stranger);
        assert_ne!(
            rc, Z_OK,
            "a dial that does not trust the chain does not open"
        );

        close_session(&mut listener);
    }
}
