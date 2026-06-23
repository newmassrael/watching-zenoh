// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3b-2 §5.16 — wz <-> zenohd usrpwd AUTH interop: a wz client authenticates
//! to a REAL zenohd 1.5.0 whose transport requires username/password auth, over
//! a real TCP link. The cross-impl proof for the R3b live usrpwd wiring: the
//! wz<->wz e2e (`wz-runtime-tokio/tests/usrpwd_handshake_e2e.rs`) proved the
//! send/recv wiring against wz itself; this proves the usrpwd wire format
//! (InitSyn Unit offer / InitAck Z64 nonce / OpenSyn Zbuf{user,HMAC-SHA3-256} /
//! OpenAck Unit) interoperates byte-for-byte with the canonical Rust impl — the
//! storage-A10/A12 cross-impl discipline applied to auth.
//!
//! zenohd is launched with `transport/auth/usrpwd/dictionary_file` set, which
//! per zenoh `usrpwd.rs` recv_init_syn makes auth MANDATORY: a client that does
//! not present a valid usrpwd extension is rejected at establishment. wz dials
//! IN-PROCESS via `connect_and_open_session_with_auth` + a
//! `UsrPwdMethod::initiator` dispatch (the same in-process dial shape as the
//! storage A10 interop, not the `wz-ap-demo` binary).
//!
//! Two legs:
//!   1. [`wz_authenticates_to_usrpwd_zenohd_with_correct_credentials`] — wz with
//!      the matching `(user, password)` reaches Established (the HMAC over
//!      zenohd's nonce verified on the real router).
//!   2. [`wz_rejected_by_usrpwd_zenohd_with_wrong_credentials`] — on the SAME
//!      proven-ready zenohd, a correct dial reaches Established (positive
//!      control) but a wrong-password dial does NOT. The Ok-vs-Err contrast on
//!      one router, password the only difference, is the auth-enforcement proof.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`). Run via Layer Z /
//! `--ignored`. Non-flaky by construction: the correct-creds dial retries
//! zenohd's cold-start window (the storage A10 readiness discipline), and the
//! reject leg only asserts after a positive control proved the router warm.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_integration_tests::common::{
    wait_for_tcp_accept, zenohd_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    connect_and_open_session_with_auth, DialConfig, OpenError, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::extauth_usrpwd::UsrPwdMethod;
use wz_session_core::locator::parse_any_locator;

/// The handshake-open iteration cap (matches the storage A10 interop).
const ITER_CAP: usize = 256;
const USER: &str = "testuser";
const PASSWORD: &str = "testpass";

/// Spawn a zenohd whose transport REQUIRES usrpwd auth: a credentials
/// dictionary file holding `USER:PASSWORD` is passed via
/// `--cfg transport/auth/usrpwd/dictionary_file`. Per zenoh usrpwd.rs, a
/// configured dictionary makes auth mandatory (recv_init_syn bails on a client
/// with no usrpwd ext). Blocks until the TCP listener accepts. Returns the
/// process guard plus the dictionary tempfile (kept alive — dropping it deletes
/// the file zenohd reads).
fn spawn_usrpwd_zenohd(port: u16) -> (ChildGuard, NamedTempFile) {
    let mut dict = NamedTempFile::new().expect("usrpwd credentials dictionary tempfile");
    // zenoh usrpwd dictionary format: one `user:password` (plaintext) per line.
    writeln!(dict, "{USER}:{PASSWORD}").expect("write usrpwd dictionary entry");
    dict.flush().expect("flush usrpwd dictionary");
    let dict_path = dict.path().to_path_buf();

    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        // The `--cfg KEY:VALUE` VALUE is JSON5, so the path is a quoted string.
        .arg("--cfg")
        .arg(format!(
            "transport/auth/usrpwd/dictionary_file:\"{}\"",
            dict_path.display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let guard = ChildGuard::wrap(
        "zenohd (usrpwd auth)",
        command.spawn().expect("spawn zenohd with usrpwd auth"),
    );
    assert!(
        wait_for_tcp_accept(port, Duration::from_secs(10)),
        "zenohd (usrpwd) did not start accepting on 127.0.0.1:{port} within 10s"
    );
    (guard, dict)
}

/// Build a fresh initiator-side usrpwd dispatch for `(user, password)`. Rebuilt
/// per dial: a dispatch owns mutable per-handshake method state and is consumed
/// by the open call.
fn initiator_dispatch(user: &str, password: &str) -> AuthDispatch {
    AuthDispatch::new(vec![Box::new(UsrPwdMethod::initiator(
        user.as_bytes().to_vec(),
        password.as_bytes().to_vec(),
    )) as _])
}

/// One in-process dial to zenohd authenticating with `(user, password)`. Returns
/// the open result so the caller asserts Established (Ok) or rejected (Err).
async fn dial_with_creds(
    port: u16,
    user: &str,
    password: &str,
) -> Result<OpenedSession, OpenError> {
    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("parse locator");
    connect_and_open_session_with_auth(
        locator,
        // version 0x09 / real batch_size / res 2 — a strict zenohd rejects the
        // wz<->wz fixture shape (version 0x05) at InitSyn (storage A10 note).
        zenohd_interop_session_init_params(),
        initiator_dispatch(user, password),
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
}

/// Dial with the CORRECT credentials, retrying to absorb zenohd's cold-start
/// window (the storage A10 readiness discipline: "listener up" via TCP-accept
/// precedes "handshake-ready"). Panics if Established is never reached.
async fn authenticate_until_ready(port: u16) -> OpenedSession {
    for attempt in 1..=20 {
        match dial_with_creds(port, USER, PASSWORD).await {
            Ok(opened) => return opened,
            Err(_) if attempt < 20 => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(e) => panic!(
                "wz never authenticated to the usrpwd zenohd with correct credentials: {e:?}"
            ),
        }
    }
    unreachable!("the loop returns or panics")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_authenticates_to_usrpwd_zenohd_with_correct_credentials() {
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let (mut zenohd, _dict) = spawn_usrpwd_zenohd(port);
    drop(port_res);

    // Reaching Established against a mandatory-usrpwd zenohd proves wz's usrpwd
    // wire (offer / nonce echo / HMAC-SHA3-256) verified on the canonical router.
    let _opened = authenticate_until_ready(port).await;

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_rejected_by_usrpwd_zenohd_with_wrong_credentials() {
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let (mut zenohd, _dict) = spawn_usrpwd_zenohd(port);
    drop(port_res);

    // Positive control: the correct credentials reach Established. This both
    // proves the auth path works AND warms zenohd, so the subsequent wrong-creds
    // failure is the auth reject — not a cold-start transient.
    let _ok = authenticate_until_ready(port).await;

    // The SAME proven-ready zenohd must REJECT a wrong password. The only
    // difference from the control is the password, so a failure here is the
    // usrpwd HMAC mismatch surfacing as zenohd's establishment Close. Assert the
    // failure is a PEER-CLOSE shape (zenohd closed at the auth stage), not a
    // pre-auth failure (Dial / IterationLimit) that would also be `is_err()` but
    // would NOT prove the reject reached auth -- so a wz regression that never
    // gets to the auth stage cannot pass as a "reject".
    let wrong = dial_with_creds(port, USER, "definitely-the-wrong-password").await;
    match wrong {
        Err(OpenError::Terminal | OpenError::HandshakeTimeout | OpenError::LinkLost(_)) => {}
        Ok(_) => panic!("usrpwd zenohd must reject a wrong password, but wz reached Established"),
        Err(other) => panic!(
            "wrong-password dial failed with {other:?}, not a peer-close reject \
             (Terminal/HandshakeTimeout/LinkLost) -- wz may not have reached the auth stage"
        ),
    }

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
}
