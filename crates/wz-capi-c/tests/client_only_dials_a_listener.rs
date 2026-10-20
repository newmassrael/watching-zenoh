// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The zenoh-c ABI built without the `peer` feature opens a client session to a node that
//! listens, and publishes to it and hears from it; a config that asks for a listener or a role
//! other than the client's is refused.
//!
//! Such a build cannot listen, so the node it dials is the `hold_a_listener` example of the FULL
//! build, run as a process. The two are built by two invocations (a feature set is one per
//! build), which is why the example's path is a named input:
//!
//! ```text
//! cargo build --release -p wz-capi-c --example hold_a_listener
//! WZ_CAPI_C_LISTENER_BIN=target/release/examples/hold_a_listener \
//!     cargo test --release -p wz-capi-c --no-default-features \
//!     --features scout --test client_only_dials_a_listener
//! ```
//!
//! A missing example is a failure and not a skip: a test that passes by not running would say a
//! stripped build connects when nothing has shown it.
#![cfg(not(feature = "peer"))]

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t, z_view_string_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::{z_keyexpr_as_view_string, z_sample_keyexpr};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_data, z_string_len, z_view_string_loan};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_runtime_tokio_test_support::free_port;

struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
    let mut view: z_view_string_t = std::mem::zeroed();
    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view);
    let string = z_view_string_loan(&view);
    let (data, len) = (z_string_data(string), z_string_len(string));
    if data.is_null() {
        return;
    }
    if let Ok(key) = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len)) {
        ctx.seen.lock().unwrap().insert(key.to_owned());
    }
}

/// A config with the given `(key, json5)` entries, opened; the code `z_open` returned and the
/// session it made.
unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let (key, value) = (
            CString::new(*key).unwrap(),
            CString::new(value.as_str()).unwrap(),
        );
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let code = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    (code, session)
}

fn listener_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("WZ_CAPI_C_LISTENER_BIN") {
        return path.into();
    }
    let test = std::env::current_exe().expect("the path of this test");
    let profile_dir = test
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    profile_dir.join("examples").join("hold_a_listener")
}

/// The listener process, killed when dropped, and the lines it prints.
struct Listener {
    child: Child,
    lines: Receiver<String>,
}

impl Listener {
    fn start(port: u16) -> Self {
        let binary = listener_binary();
        assert!(
            binary.is_file(),
            "{} is missing: build it with `cargo build --release -p wz-capi-c --example \
             hold_a_listener` (the full build) and name it in WZ_CAPI_C_LISTENER_BIN",
            binary.display()
        );
        let mut child = Command::new(&binary)
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the listener starts");
        let stdout = child.stdout.take().expect("a piped stdout");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let this = Self { child, lines };
        this.wait_for("READY");
        this
    }

    /// Read lines until one equals `wanted`, for at most ten seconds.
    fn wait_for(&self, wanted: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) if line == wanted => return,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("the listener never printed {wanted:?}");
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &CStr) {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut bytes, payload.as_ptr()), Z_OK);
    let mut options: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut options);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut bytes as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            &mut options,
        ),
        Z_OK
    );
}

fn off() -> (&'static str, String) {
    ("scouting/multicast/enabled", "false".to_owned())
}

#[test]
fn a_client_only_build_publishes_to_a_listener_and_hears_from_it() {
    let port = free_port();
    let listener = Listener::start(port);
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    // SAFETY: a fresh config, session and subscriber, all released before the function returns.
    unsafe {
        let (code, mut session) = open_with(&[
            off(),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ]);
        assert_eq!(
            code, Z_OK,
            "a client-only build opens a client to a listener"
        );

        let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut view, c"demo/**".as_ptr()),
            Z_OK
        );
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&view),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut heard_from_listener = false;
        while Instant::now() < deadline {
            put(&session, c"demo/from-client", c"payload");
            heard_from_listener = seen.lock().unwrap().contains("demo/from-listener");
            if heard_from_listener {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        listener.wait_for("heard demo/from-client");

        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
        z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
        assert!(
            heard_from_listener,
            "the client never heard the listener's publication"
        );
    }
}

/// A listener, a router or a peer is a role the build does not have: the open is refused before
/// any thread or socket exists, and is not run as a client it was not asked to be.
#[test]
fn a_listener_or_another_role_is_refused() {
    // SAFETY: fresh configs; a refused open leaves a gravestone to drop.
    unsafe {
        for entries in [
            vec![
                off(),
                ("listen/endpoints", "[\"tcp/127.0.0.1:0\"]".to_owned()),
            ],
            vec![
                off(),
                ("mode", "\"peer\"".to_owned()),
                ("connect/endpoints", "[\"tcp/127.0.0.1:1\"]".to_owned()),
            ],
            vec![
                off(),
                ("mode", "\"router\"".to_owned()),
                ("connect/endpoints", "[\"tcp/127.0.0.1:1\"]".to_owned()),
            ],
        ] {
            let (code, _session) = open_with(&entries);
            assert_ne!(
                code, Z_OK,
                "{entries:?} opened in a build with no peer role"
            );
        }
    }
}
