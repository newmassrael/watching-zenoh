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
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set `WZ_ZENOHD_BIN` or run
//! `scripts/build-zenohd.sh`). Run via Layer Z / `--ignored`. This file is in wz-capi-c for the
//! reason `redial_zenohd_interop` is: wz-capi-c is not a dependency of `wz-integration-tests`.

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

/// How long the control gets to become one of the listener's routers.
const ADMIT_BUDGET: Duration = Duration::from_secs(30);

/// How long a refused zenohd is watched: several times what the control has measured to need on
/// this machine, so a refusal is not a peer that was merely slow.
const REFUSE_WINDOW: Duration = Duration::from_secs(8);

fn zenohd_binary() -> PathBuf {
    if let Ok(p) = std::env::var("WZ_ZENOHD_BIN") {
        return PathBuf::from(p);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/zenohd/zenohd")
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
            format!("\"{dictionary}\""),
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
    let gone = {
        let deadline = Instant::now() + ADMIT_BUDGET;
        loop {
            // SAFETY: the listener is live.
            if unsafe { routers_held(&listener) } == 0 {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    assert!(
        gone,
        "the control's link was still held after its zenohd was killed"
    );

    let _bad = spawn_zenohd_dialling(port, "definitely-the-wrong-password");
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
