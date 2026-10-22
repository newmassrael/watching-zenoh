// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The link kinds zenoh-c builds by default, each carrying a put between two sessions of this
//! library, driven through the exported `z_*` symbols as a C program would.
//!
//! A hub listens on the link kind and subscribes; a client dials it and puts until the sample
//! arrives. Each kind also has a leg that must NOT open, so a pass is the link kind at work and
//! not a dial that would have succeeded over anything:
//!
//!   * `tls/`: a client that names no root certificate checks the hub's self-signed certificate
//!     against the public roots and is refused;
//!   * `ws/`: a plain `tcp/` client at the hub's port is refused, because the hub expects a
//!     WebSocket upgrade;
//!   * `unixsock-stream/`: a client at the socket path after the hub has closed is refused.

use std::ffi::{c_void, CString};
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::z_put;
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::{free_port, localhost_cert_key_pem};

/// Open with `entries` inserted as json5 values, returning the result code and the session.
unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    (rc, session)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

/// Subscribe `session` to `key`; the returned counter is how many samples it has been given.
unsafe fn count_samples(session: &z_owned_session_t, key: &str) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    hits
}

/// Publish on `key` from `publisher` every 50 ms until `hits` is not zero or `within` has passed.
unsafe fn put_until_it_arrives(
    publisher: &z_owned_session_t,
    key: &str,
    hits: &Arc<AtomicUsize>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let ke = CString::new(key).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let text = CString::new("over the link").unwrap();
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
        assert_eq!(
            z_put(
                z_session_loan(publisher),
                z_view_keyexpr_loan(&view),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    hits.load(Ordering::SeqCst) > 0
}

/// A hub's config: a peer listening on `endpoint` alone, scouting off, and what a row adds.
fn hub_entries(endpoint: &str, extra: &[(&'static str, String)]) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("mode", "\"peer\"".to_owned()),
        ("scouting/multicast/enabled", "false".to_owned()),
        ("listen/endpoints", format!("[{endpoint:?}]")),
    ];
    entries.extend(extra.iter().cloned());
    entries
}

/// A client's config: one attempt at `endpoint`, scouting off, and what a row adds.
fn client_entries(endpoint: &str, extra: &[(&'static str, String)]) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("mode", "\"client\"".to_owned()),
        ("scouting/multicast/enabled", "false".to_owned()),
        ("connect/endpoints", format!("[{endpoint:?}]")),
        ("connect/timeout_ms", "3000".to_owned()),
    ];
    entries.extend(extra.iter().cloned());
    entries
}

/// Whether a client of `client` puts a sample that `hub`, subscribed to `key`, receives.
unsafe fn client_reaches(hub: &z_owned_session_t, client: &[(&str, String)], key: &str) -> bool {
    let hits = count_samples(hub, key);
    let (rc, client) = open_with(client);
    assert_eq!(rc, Z_OK, "the client opens");
    let arrived = put_until_it_arrives(&client, key, &hits, Duration::from_secs(8));
    close_session(client);
    arrived
}

/// A file holding `text`, which a config names by its path.
fn file_of(text: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("a temp file");
    file.write_all(text.as_bytes()).expect("write");
    file
}

/// A path as the json5 string a config value is.
fn quoted(path: &std::path::Path) -> String {
    format!("{:?}", path.to_str().expect("a utf-8 path"))
}

/// A `tls/` hub presents the certificate its config names, and a client that trusts it as its
/// root reaches it; one that names no root does not. The certificate is issued to `localhost`,
/// and the client dials that name, which a `tls/` dial checks against the certificate.
#[test]
fn a_tls_hub_is_reached_by_a_client_that_trusts_its_certificate() {
    let (cert, key) = localhost_cert_key_pem();
    let (cert_file, key_file) = (file_of(&cert), file_of(&key));
    let port = free_port();
    let listen = format!("tls/127.0.0.1:{port}");
    let dial = format!("tls/localhost:{port}");
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(
            &listen,
            &[
                (
                    "transport/link/tls/listen_certificate",
                    quoted(cert_file.path()),
                ),
                (
                    "transport/link/tls/listen_private_key",
                    quoted(key_file.path()),
                ),
            ],
        ));
        assert_eq!(rc, Z_OK, "the tls hub opens");
        let trusted = client_reaches(
            &hub,
            &client_entries(
                &dial,
                &[(
                    "transport/link/tls/root_ca_certificate",
                    quoted(cert_file.path()),
                )],
            ),
            "wz/link-kinds/tls",
        );
        let (rc, untrusted) = open_with(&client_entries(&dial, &[]));
        close_session(untrusted);
        close_session(hub);
        assert!(
            trusted,
            "nothing reached the tls hub from a client trusting its certificate"
        );
        assert_ne!(
            rc, Z_OK,
            "a client that names no root trusted a self-signed certificate"
        );
    }
}

/// A `tls/` listener whose certificate path cannot be read fails the open rather than listening
/// without one.
#[test]
fn a_tls_certificate_path_that_cannot_be_read_fails_the_open() {
    let port = free_port();
    // SAFETY: a fresh config; a gravestone drops as a no-op.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(
            &format!("tls/127.0.0.1:{port}"),
            &[
                (
                    "transport/link/tls/listen_certificate",
                    "\"/nonexistent/wz-cert.pem\"".to_owned(),
                ),
                (
                    "transport/link/tls/listen_private_key",
                    "\"/nonexistent/wz-key.pem\"".to_owned(),
                ),
            ],
        ));
        close_session(hub);
        assert_ne!(
            rc, Z_OK,
            "a tls listener opened without the certificate it names"
        );
    }
}

/// A `ws/` hub is reached by a `ws/` client, and a `tcp/` client at the same port is refused:
/// the hub runs the WebSocket upgrade before the session.
#[test]
fn a_ws_hub_is_reached_by_a_ws_client_and_not_by_plain_tcp() {
    let port = free_port();
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(&format!("ws/127.0.0.1:{port}"), &[]));
        assert_eq!(rc, Z_OK, "the ws hub opens");
        let over_ws = client_reaches(
            &hub,
            &client_entries(&format!("ws/127.0.0.1:{port}"), &[]),
            "wz/link-kinds/ws",
        );
        let (rc, plain) = open_with(&client_entries(&format!("tcp/127.0.0.1:{port}"), &[]));
        close_session(plain);
        close_session(hub);
        assert!(over_ws, "nothing reached the ws hub from a ws client");
        assert_ne!(
            rc, Z_OK,
            "a plain tcp client opened a session with a ws hub"
        );
    }
}

/// A `unixsock-stream/` hub is reached at its socket path, and once it has closed, a client at
/// that path is refused.
#[cfg(unix)]
#[test]
fn a_unixsock_hub_is_reached_at_its_path_until_it_closes() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("hub.sock");
    let endpoint = format!("unixsock-stream/{}", path.to_str().expect("a utf-8 path"));
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(&endpoint, &[]));
        assert_eq!(rc, Z_OK, "the unixsock hub opens");
        let reached = client_reaches(&hub, &client_entries(&endpoint, &[]), "wz/link-kinds/unix");
        close_session(hub);
        let (rc, after) = open_with(&client_entries(&endpoint, &[]));
        close_session(after);
        assert!(reached, "nothing reached the unixsock hub at its path");
        assert_ne!(
            rc, Z_OK,
            "a client opened a session at the path of a closed hub"
        );
    }
}
