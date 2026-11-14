// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A REAL zenohd, configured as a usrpwd initiator, authenticates to a zenoh-c session whose
//! config names a dictionary, and one that holds the wrong password is refused.
//!
//! `listener_auth` proves the config reaches the session with a peer wz wrote itself, which is wz
//! agreeing with itself. This is the other direction: the credential comes from a peer wz did not
//! write (a zenohd computing its own HMAC from `transport/auth/usrpwd/{user,password}`), and the
//! verdict is the C ABI listener's, read where a C program reads it (`z_info_routers_zid`, the
//! routers it holds a link to).
//!
//! Two legs on the same listener configuration:
//!
//!   1. the right password: the zenohd becomes one of the listener's routers, which is also the
//!      control that this zenohd reaches this listener at all;
//!   2. the right password first (the control), then a zenohd whose ONLY difference is the
//!      password: it never becomes one, over a window several times what the control needed.
//!
//! And a third that makes the dictionary's effect a comparison rather than a reading of wz alone:
//! the SAME dictionary file is handed first to a zenohd listener, which must admit the right
//! password and refuse the wrong one (the positive control, read off the session that listener
//! logs), and then to the C listener, which must do the same with the same two dialers.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set `WZ_ZENOHD_BIN` or run
//! `scripts/build-zenohd.sh`). Run via Layer Z / `--ignored`. This file is in wz-capi-c for the
//! reason `redial_zenohd_interop` is: wz-capi-c is not a dependency of `wz-integration-tests`.

#![cfg(feature = "peer")]

use std::ffi::{c_void, CString};
use std::io::Write as _;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::zid::{
    z_closure_zid, z_id_t, z_info_routers_zid, z_moved_closure_zid_t, z_owned_closure_zid_t,
};
use wz_runtime_tokio_test_support::free_port;

const USER: &str = "alice";
const PASSWORD: &str = "interop-secret";
/// A password the dictionary does not hold for `USER`.
const WRONG_PASSWORD: &str = "definitely-the-wrong-password";

/// What a zenohd logs, at debug, for every session it opens
/// (`io/zenoh-transport/src/unicast/manager.rs` @ `"New transport opened between {} and {}`).
const ZENOHD_SESSION_OPENED: &str = "New transport opened between";

/// How long the control gets to become one of the listener's routers.
const ADMIT_BUDGET: Duration = Duration::from_secs(30);

/// How long a refused zenohd is watched: several times what the control has measured to need on
/// this machine, so a refusal is not a peer that was merely slow.
const REFUSE_WINDOW: Duration = Duration::from_secs(8);

fn zenohd_binary() -> PathBuf {
    if let Ok(p) = std::env::var("WZ_ZENOHD_BIN") {
        return PathBuf::from(p);
    }
    let path = wz_codegen_build::artifact("target/zenohd/zenohd")
        .canonicalize()
        .expect("target/zenohd/zenohd is missing; run scripts/build-zenohd.sh");
    assert!(path.is_file(), "{} is not a file", path.display());
    path
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A zenohd that dials `target` and authenticates as `USER` with `password`.
fn spawn_zenohd_dialling(target: u16, password: &str) -> ChildGuard {
    let own = free_port();
    let child = Command::new(zenohd_binary())
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{own}"))
        .arg("-e")
        .arg(format!("tcp/127.0.0.1:{target}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .arg("--cfg")
        .arg(format!("transport/auth/usrpwd/user:\"{USER}\""))
        .arg("--cfg")
        .arg(format!("transport/auth/usrpwd/password:\"{password}\""))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("zenohd spawns");
    let mut guard = ChildGuard(child);
    let deadline = Instant::now() + ADMIT_BUDGET;
    // Its own listener accepting means the process is up and has read its config.
    loop {
        if TcpStream::connect(("127.0.0.1", own)).is_ok() {
            return guard;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!("zenohd exited before it was up: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "zenohd was not up in {ADMIT_BUDGET:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A zenohd that listens on `port` and holds `dictionary` as its usrpwd responder dictionary, with
/// its log captured so the sessions it opens can be counted.
struct ZenohdListener {
    _guard: ChildGuard,
    log: tempfile::NamedTempFile,
}

impl ZenohdListener {
    fn spawn(port: u16, dictionary: &str) -> Self {
        let log = tempfile::NamedTempFile::new().expect("a capture file");
        // One open file description for both streams, so the two do not overwrite each other.
        let out = log.reopen().expect("open the capture for writing");
        let err = out.try_clone().expect("dup the capture");
        let child = Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .arg("--cfg")
            // Quoted and escaped, so a path with backslashes is a valid JSON5 string.
            .arg(format!(
                "transport/auth/usrpwd/dictionary_file:{dictionary:?}"
            ))
            .env("RUST_LOG", "z=debug")
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("zenohd spawns");
        let mut guard = ChildGuard(child);
        let deadline = Instant::now() + ADMIT_BUDGET;
        // Its listener accepting means the process is up and has read its config.
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Self { _guard: guard, log };
            }
            if let Ok(Some(status)) = guard.0.try_wait() {
                panic!("the zenohd listener exited before it was up: {status}");
            }
            assert!(
                Instant::now() < deadline,
                "the zenohd listener was not up in {ADMIT_BUDGET:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// How many sessions this zenohd has logged opening.
    fn sessions_opened(&self) -> usize {
        std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .matches(ZENOHD_SESSION_OPENED)
            .count()
    }

    /// Wait until this zenohd has opened more than `before` sessions, up to `budget`; whether it
    /// did.
    fn a_session_opens_past(&self, before: usize, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if self.sessions_opened() > before {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

/// A C listener whose config names a dictionary with `USER:PASSWORD`, on `port`.
unsafe fn open_listener(port: u16, dictionary: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in [
        ("scouting/multicast/enabled", String::from("false")),
        ("mode", String::from("\"router\"")),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        (
            "transport/auth/usrpwd/dictionary_file",
            // Quoted and escaped, so a path with backslashes is a valid JSON5 string.
            format!("{dictionary:?}"),
        ),
    ] {
        let k = CString::new(key).unwrap();
        let v = CString::new(value).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null(),
        ),
        Z_OK,
        "the listener opens"
    );
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

unsafe extern "C" fn count_zid(_zid: *const z_id_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

/// How many routers the session holds a link to right now.
unsafe fn routers_held(session: &z_owned_session_t) -> usize {
    let count = AtomicUsize::new(0);
    let mut closure: z_owned_closure_zid_t = std::mem::zeroed();
    z_closure_zid(
        &mut closure,
        Some(count_zid),
        None,
        (&count as *const AtomicUsize).cast_mut().cast(),
    );
    let rc = z_info_routers_zid(
        z_session_loan(session),
        (&mut closure as *mut z_owned_closure_zid_t).cast::<z_moved_closure_zid_t>(),
    );
    assert_eq!(rc, Z_OK);
    count.load(Ordering::SeqCst)
}

/// Wait until `session` holds a router, up to `budget`; whether it did.
unsafe fn a_router_arrives(session: &z_owned_session_t, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if routers_held(session) >= 1 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Wait until `session` holds no router, up to `budget`; whether it got there.
unsafe fn the_routers_go(session: &z_owned_session_t, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if routers_held(session) == 0 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn dictionary_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("a temp file");
    writeln!(file, "{USER}:{PASSWORD}").expect("write the dictionary");
    file
}

#[test]
#[ignore = "binary-dep e2e (zenohd, usrpwd initiator); Layer Z runs via --ignored"]
fn a_stock_zenohd_with_the_right_credential_becomes_a_router_of_a_c_listener() {
    let dictionary = dictionary_file();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let listener = unsafe { open_listener(port, dictionary.path().to_str().expect("utf-8")) };
    let _zenohd = spawn_zenohd_dialling(port, PASSWORD);
    // SAFETY: the listener is live.
    let admitted = unsafe { a_router_arrives(&listener, ADMIT_BUDGET) };
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        admitted,
        "a zenohd presenting the dictionary's credential never became a router of the C listener"
    );
}

#[test]
#[ignore = "binary-dep e2e (zenohd, usrpwd initiator); Layer Z runs via --ignored"]
fn a_stock_zenohd_with_the_wrong_password_never_becomes_a_router_of_a_c_listener() {
    let dictionary = dictionary_file();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let listener = unsafe { open_listener(port, dictionary.path().to_str().expect("utf-8")) };

    // The control, on this listener: the right password is admitted, so the refusal below is
    // the password and not a zenohd that cannot reach this listener.
    let good = spawn_zenohd_dialling(port, PASSWORD);
    // SAFETY: the listener is live.
    let control = unsafe { a_router_arrives(&listener, ADMIT_BUDGET) };
    drop(good);
    assert!(
        control,
        "the control (right password) never became a router, so the refusal proves nothing"
    );
    // Let the control's link go before the refused one is watched, so a router held over from it
    // is not read as the refused peer's.
    // SAFETY: the listener is live.
    let gone = unsafe { the_routers_go(&listener, ADMIT_BUDGET) };
    assert!(
        gone,
        "the control's link was still held after its zenohd was killed"
    );

    let _bad = spawn_zenohd_dialling(port, WRONG_PASSWORD);
    // SAFETY: the listener is live.
    let admitted = unsafe { a_router_arrives(&listener, REFUSE_WINDOW) };
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        !admitted,
        "a zenohd presenting the wrong password became a router of a listener that names a \
         dictionary"
    );
}

/// One dictionary FILE, handed to a zenohd listener and then to a C listener, and the same two
/// stock dialers at each: the right password and the wrong one.
///
/// The zenohd listener goes first and is the POSITIVE CONTROL: it must open a session for the
/// right password and none for the wrong one over the refusal window, or it shows no effect of
/// the dictionary and the C listener's answer would be compared with nothing. The C listener is
/// then held to the same two answers, read where a C program reads them.
#[test]
#[ignore = "binary-dep e2e (zenohd, usrpwd initiator and responder); Layer Z runs via --ignored"]
fn one_dictionary_admits_and_refuses_the_same_zenohds_at_a_zenohd_and_at_a_c_listener() {
    let dictionary = dictionary_file();
    let path = dictionary.path().to_str().expect("utf-8");

    let port = free_port();
    let upstream = ZenohdListener::spawn(port, path);
    let good = spawn_zenohd_dialling(port, PASSWORD);
    let upstream_admits = upstream.a_session_opens_past(0, ADMIT_BUDGET);
    drop(good);
    assert!(
        upstream_admits,
        "the zenohd listener opened no session for the dictionary's own credential, so this \
         zenohd cannot adjudicate the C listener's"
    );
    let before = upstream.sessions_opened();
    let bad = spawn_zenohd_dialling(port, WRONG_PASSWORD);
    let upstream_refuses = !upstream.a_session_opens_past(before, REFUSE_WINDOW);
    drop(bad);
    drop(upstream);
    assert!(
        upstream_refuses,
        "the zenohd listener opened a session for the wrong password, so it shows no effect of \
         the dictionary and cannot adjudicate the C listener's"
    );

    let port = free_port();
    // SAFETY: a fresh config and session.
    let listener = unsafe { open_listener(port, path) };
    let good = spawn_zenohd_dialling(port, PASSWORD);
    // SAFETY: the listener is live.
    let wz_admits = unsafe { a_router_arrives(&listener, ADMIT_BUDGET) };
    drop(good);
    // SAFETY: the listener is live.
    let gone = unsafe { the_routers_go(&listener, ADMIT_BUDGET) };
    let bad = spawn_zenohd_dialling(port, WRONG_PASSWORD);
    // SAFETY: the listener is live.
    let wz_refuses = !unsafe { a_router_arrives(&listener, REFUSE_WINDOW) };
    drop(bad);
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        wz_admits,
        "the zenohd listener admitted the dictionary's credential and the C listener given the \
         same file did not"
    );
    assert!(
        gone,
        "the right password's link was still held after its zenohd was killed"
    );
    assert!(
        wz_refuses,
        "the zenohd listener refused the wrong password and the C listener given the same file \
         admitted it"
    );
}
