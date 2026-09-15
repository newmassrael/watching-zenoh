// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2631 — a STOCK zenoh usrpwd initiator authenticates to a wz RESPONDER, and
//! the name it authenticated as is the one wz's session holds.
//!
//! ## The direction nothing had run
//!
//! `usrpwd_zenohd_interop.rs` runs a real zenohd through this exchange, but in
//! both of its legs **wz dials**. That proves wz ENCODES an offer and an
//! `{user, hmac}` a canonical responder accepts. It says nothing about wz
//! DECODING them, and the two are not the same claim: a lenient decoder accepts
//! more than it would ever emit, so "zenohd accepts wz's bytes" and "wz accepts
//! zenoh's bytes" can each hold while the other fails.
//! `zenoh_auth_body_foreign_witness.rs` does read bytes a stock usrpwd client
//! wrote — but through the analyzer's DISSECTOR walkers, not the session kernel
//! that verifies the HMAC and records who connected.
//!
//! And the responder is where this atom's identity clause lives. Upstream
//! records the peer's username only on the ACCEPTING side
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs` @ `auth_id: osyn_out.other_auth_id,`);
//! a dialer keeps `UsrPwdId(None)`. So "the authenticated identity leaves the
//! handshake" has a cross-implementation meaning only in this direction: a peer
//! wz did not write names itself, and wz's session ends up holding that name.
//!
//! ```text
//!   zenoh_z_get --cfg transport/auth/usrpwd/{user,password}  ──►  wz accept seam
//!       (stock zenoh client, INITIATOR)                    (UsrPwdMethod responder)
//! ```
//!
//! ## Two legs, one difference
//!
//! 1. The matching password reaches Established and the session holds exactly the
//!    configured user.
//! 2. On the same responder configuration, a correct client is admitted first
//!    (the positive control, which also proves the client reaches wz at all), and
//!    then a client whose ONLY difference is the password is refused by the usrpwd
//!    method's own bad-password check. Without the control, a refusal could be a
//!    client that never finished its InitSyn for an unrelated reason.
//!
//! `#[ignore]` binary-dep e2e: needs the core zenoh `z_get` example beside
//! zenohd (`scripts/build-zenohd.sh`, or `WZ_ZENOH_CORE_EXAMPLES_DIR`).
//!
//! ⚠ Both function names carry `zenoh_zget`, and that is load-bearing, not
//! style: Layer E's `--ignored` sweep builds only the pico CLI and wz-ap-demo, so
//! a `z_get` leg it selected would die on the helper's missing-oracle assert.
//! The token skips them out of E, and Layer Z — the lane `build-zenohd.sh`
//! provisions — runs this file under a count guard (R2358's arrangement for the
//! storage-history legs). This file was first committed saying "Layer E runs via
//! --ignored"; `layer_e_oracle_scope_gate.py` refused that before any push.

use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_integration_tests::common::{zenoh_core_example_binary, ChildGuard};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_auth, DialedLink, OpenError, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::auth_dispatch::{AuthDispatch, AuthError, AuthIdentity};
use wz_session_core::extauth_usrpwd::UsrPwdMethod;

const ITER_CAP: usize = 4096;
const USER: &str = "alice";
const PASSWORD: &str = "alice-secret";
/// `z_get -o`: long enough that the client is still alive while wz reads the
/// session; the query itself is scaffolding and nothing answers it.
const GET_TIMEOUT_MS: &str = "4000";
/// How often a client that never reached wz's listener is retried. A retry is for
/// a client that did not CONNECT; a handshake result, once one arrives, is never
/// retried away.
const CONNECT_ATTEMPTS: usize = 6;

/// A stock `z_get` configured as a usrpwd initiator with `password`.
fn spawn_usrpwd_zget(endpoint: &str, password: &str) -> ChildGuard {
    let z_get = zenoh_core_example_binary("z_get");
    let mut cmd = Command::new(z_get);
    cmd.args([
        "-s",
        "demo/usrpwd-responder/**",
        "-o",
        GET_TIMEOUT_MS,
        "-m",
        "client",
        "-e",
        endpoint,
        "--no-multicast-scouting",
        "--cfg",
    ]);
    cmd.arg(format!("transport/auth/usrpwd/user:\"{USER}\""));
    cmd.arg("--cfg");
    cmd.arg(format!("transport/auth/usrpwd/password:\"{password}\""));
    ChildGuard::wrap(
        "z_get (stock zenoh, usrpwd initiator)",
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn z_get"),
    )
}

/// A wz responder whose credential table holds exactly `USER:PASSWORD`.
fn responder_dispatch() -> AuthDispatch {
    AuthDispatch::new(vec![Box::new(UsrPwdMethod::responder(
        vec![(USER.as_bytes().to_vec(), PASSWORD.as_bytes().to_vec())],
        0, // sentinel; the accept seam draws the live challenge nonce itself
    )) as _])
}

/// Accept ONE stock client presenting `password` and run the wz responder
/// handshake on it. Retries only a client that never connected; returns the
/// handshake's own result the first time there is one, plus the client guard so
/// the caller controls its lifetime.
async fn accept_one(
    listener: &TcpListener,
    endpoint: &str,
    password: &str,
) -> (Result<OpenedSession, OpenError>, ChildGuard) {
    for attempt in 1..=CONNECT_ATTEMPTS {
        let mut client = spawn_usrpwd_zget(endpoint, password);
        match tokio::time::timeout(Duration::from_secs(8), listener.accept()).await {
            Ok(Ok((stream, _peer))) => {
                let result = accept_and_open_session_with_auth(
                    DialedLink::Tcp(stream),
                    fixture_session_init_params(),
                    responder_dispatch(),
                    TokioTime::new(),
                    Some(ITER_CAP),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await;
                return (result, client);
            }
            _ => {
                let _ = client.child_mut().kill();
                let _ = client.child_mut().wait();
                eprintln!("attempt {attempt}/{CONNECT_ATTEMPTS}: z_get did not connect; retrying");
            }
        }
    }
    panic!("a stock z_get never connected to the wz responder in {CONNECT_ATTEMPTS} attempts");
}

// wz-proves: session-extauth zenoh->wz
// wz-proves: session-extauth wz->zenoh
// wz-proves: access-extauth-usrpwd zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh core example z_get, usrpwd); Layer Z runs via --ignored"]
async fn a_stock_zenoh_zget_usrpwd_client_authenticates_to_wz_and_wz_holds_its_name() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz responder");
    let endpoint = format!("tcp/{}", listener.local_addr().expect("local_addr"));

    let (result, mut client) = accept_one(&listener, &endpoint, PASSWORD).await;
    let opened = result.expect("the wz responder admits a stock client with the right password");

    // The claim is about WHO, not only that a session opened: the name wz holds is
    // the one the foreign client was configured with, decoded out of its OpenSyn.
    assert_eq!(
        opened.actions.peer_auth_id(),
        Some(AuthIdentity(USER.as_bytes().to_vec())),
        "wz's session must hold the name the stock zenoh initiator authenticated as"
    );
    assert_eq!(
        opened
            .actions
            .peer_auth_id()
            .as_ref()
            .and_then(|id| id.acl_username().map(str::to_owned)),
        Some(USER.to_owned()),
        "and it must read as that ACL username"
    );

    drop(opened);
    let _ = client.child_mut().kill();
    let _ = client.child_mut().wait();
}

// wz-proves: session-extauth zenoh->wz
// wz-proves: access-extauth-usrpwd zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh core example z_get, usrpwd); Layer Z runs via --ignored"]
async fn a_stock_zenoh_zget_usrpwd_client_with_the_wrong_password_is_refused_by_wz() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz responder");
    let endpoint = format!("tcp/{}", listener.local_addr().expect("local_addr"));

    // Positive control, on the same responder configuration.
    let (control, mut good) = accept_one(&listener, &endpoint, PASSWORD).await;
    let control = control.expect("positive control: the right password is admitted");
    drop(control);
    let _ = good.child_mut().kill();
    let _ = good.child_mut().wait();

    // The ONLY difference is the password. The refusal must be the usrpwd method
    // itself rejecting the HMAC, which the seam reports by name. MEASURED, not
    // assumed: this was first written expecting a generic `Terminal` close, and
    // the run returned `AuthRejected(Rejected("usrpwd: bad password"))` instead.
    // That is the stronger thing to pin — a client that timed out, lost its link
    // or failed its InitSyn for any other reason cannot produce it.
    let (refused, mut bad) =
        accept_one(&listener, &endpoint, "definitely-the-wrong-password").await;
    match refused {
        Err(OpenError::AuthRejected(AuthError::Rejected("usrpwd: bad password"))) => {}
        Ok(_) => panic!("wz admitted a stock client presenting the wrong password"),
        Err(other) => panic!(
            "the wrong-password handshake failed with {other:?}, not the usrpwd method's \
             bad-password rejection -- it may never have reached the auth stage"
        ),
    }
    let _ = bad.child_mut().kill();
    let _ = bad.child_mut().wait();
}
