// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The build without the `peer` feature opens a client session to a node that listens, and
//! publishes to it and hears from it.
//!
//! Such a build cannot listen, so the node it dials is the `hold_a_listener` example of the
//! FULL build, run as a process. The two are built by two invocations (a feature set is one per
//! build), which is why the example's path is a named input:
//!
//! ```text
//! cargo build --release -p wz-capi-pico --example hold_a_listener
//! WZ_PICO_LISTENER_BIN=target/release/examples/hold_a_listener \
//!     cargo test --release -p wz-capi-pico --no-default-features --test client_only_dials_a_listener
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

#[cfg(not(feature = "multi-thread"))]
use wz_capi_pico::zp_read;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

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

/// The example of the full build, from `WZ_PICO_LISTENER_BIN` or beside this test's own binary.
fn listener_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("WZ_PICO_LISTENER_BIN") {
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
            "{} is missing: build it with `cargo build --release -p wz-capi-pico --example \
             hold_a_listener` (the full build) and name it in WZ_PICO_LISTENER_BIN",
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
        // Closing its standard input is how the example ends; killing is the fallback.
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
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

#[test]
fn a_client_only_build_publishes_to_a_listener_and_hears_from_it() {
    let port = free_port();
    let listener = Listener::start(port);
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    // SAFETY: a fresh config, session and subscriber, all released before the function returns.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_CONNECT_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "a client-only build opens a client session to a listener"
        );

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
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // Publish until the listener has heard it, and wait until it has been heard from. In
        // pico's single-threaded arm the program advances its session itself, with `zp_read`,
        // as pico's own single-threaded examples do: the cooperative engine reads nothing
        // between two calls, and the tokio engine, which reads on its own runtime, answers it
        // at once.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut heard_from_listener = false;
        while Instant::now() < deadline {
            #[cfg(not(feature = "multi-thread"))]
            assert_eq!(
                zp_read(z_session_loan(&session), std::ptr::null()),
                Z_OK,
                "the session is open"
            );
            put(&session, c"demo/from-client", c"payload");
            heard_from_listener = seen.lock().unwrap().contains("demo/from-listener");
            if heard_from_listener {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // And the listener reports the client's publication.
        listener.wait_for("heard demo/from-client");

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        assert!(
            heard_from_listener,
            "the client never heard the listener's publication"
        );
    }
}
