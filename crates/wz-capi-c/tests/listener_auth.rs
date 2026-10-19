// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A listener whose config names a usrpwd dictionary ADMITS the peers that hold a user of it and
//! REFUSES every other, driven through `z_open` as a C program would.
//!
//! `transport/auth/usrpwd/dictionary_file` was read into the node's config and then went nowhere:
//! no door a program can reach built an authenticating session from it, so a node configured to
//! demand credentials started without a word and let everyone in. The legs below are the
//! behaviour a security setting has to have, and each states which side of it it is on:
//!
//!   * the right credential is admitted, so the refusals below are not a listener that admits
//!     nobody;
//!   * a wrong password is refused;
//!   * a peer that offers no authentication at all is refused (it is the case a missing check
//!     lets through, and the one an attacker tries first);
//!   * a dictionary that cannot be read fails the OPEN, where the alternative is a node that
//!     believes it is protected and is not;
//!   * a config that states pubkey keys, which this surface does not enforce yet, fails the open
//!     rather than starting unprotected.

use std::ffi::CString;
use std::io::Write as _;

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::{Z_EINVAL, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan_mut};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    connect_and_open_session, connect_and_open_session_with_auth, DialConfig, OpenError,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, free_port};
use wz_session_core::auth_dispatch::AuthDispatch;
use wz_session_core::extauth_usrpwd::UsrPwdMethod;
use wz_session_core::locator::parse_any_locator;

const USER: &str = "alice";
const PASSWORD: &str = "s3cret";
/// The iteration cap the open loops of the runtime's own tests use.
const OPEN_ITERATIONS: usize = 64;

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

/// A dictionary file with one user, in the `user:password` form upstream reads.
fn dictionary() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("a temp file");
    writeln!(file, "{USER}:{PASSWORD}").expect("write the dictionary");
    file
}

fn listener_entries(port: u16, dictionary_path: &str) -> Vec<(&'static str, String)> {
    vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        (
            "transport/auth/usrpwd/dictionary_file",
            format!("\"{dictionary_path}\""),
        ),
    ]
}

/// A peer that dials `port` offering `credential` (or no authentication at all), and what its
/// open came to.
fn dial(port: u16, credential: Option<(&str, &str)>) -> Result<(), OpenError> {
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    runtime.block_on(async {
        let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("a locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x07; 4];
        let cfg = DialConfig::default();
        let opened = match credential {
            Some((user, password)) => {
                let auth = AuthDispatch::new(vec![Box::new(UsrPwdMethod::initiator(
                    user.as_bytes().to_vec(),
                    password.as_bytes().to_vec(),
                )) as _]);
                connect_and_open_session_with_auth(
                    locator,
                    params,
                    auth,
                    &cfg,
                    TokioTime::new(),
                    Some(OPEN_ITERATIONS),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
            }
            None => {
                connect_and_open_session(
                    locator,
                    params,
                    &cfg,
                    TokioTime::new(),
                    Some(OPEN_ITERATIONS),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
            }
        };
        opened.map(|_| ())
    })
}

#[test]
fn a_listener_with_a_dictionary_admits_the_peer_that_holds_a_user_of_it() {
    let dictionary = dictionary();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe {
        open_with(&listener_entries(
            port,
            dictionary.path().to_str().expect("a utf-8 path"),
        ))
    };
    assert_eq!(rc, Z_OK, "the listener opens");
    let outcome = dial(port, Some((USER, PASSWORD)));
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        outcome.is_ok(),
        "the right credential was refused: {outcome:?}, so the refusals below prove nothing"
    );
}

#[test]
fn a_listener_with_a_dictionary_refuses_a_wrong_password() {
    let dictionary = dictionary();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe {
        open_with(&listener_entries(
            port,
            dictionary.path().to_str().expect("a utf-8 path"),
        ))
    };
    assert_eq!(rc, Z_OK);
    let outcome = dial(port, Some((USER, "not-the-password")));
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        outcome.is_err(),
        "a peer with the wrong password was admitted to a listener that names a dictionary"
    );
}

#[test]
fn a_listener_with_a_dictionary_refuses_a_peer_that_offers_no_authentication() {
    let dictionary = dictionary();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe {
        open_with(&listener_entries(
            port,
            dictionary.path().to_str().expect("a utf-8 path"),
        ))
    };
    assert_eq!(rc, Z_OK);
    let outcome = dial(port, None);
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        outcome.is_err(),
        "a peer that offered no authentication was admitted to a listener that names a dictionary"
    );
}

#[test]
fn a_dictionary_that_cannot_be_read_fails_the_open() {
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, session) =
        unsafe { open_with(&listener_entries(port, "/nonexistent/wz-usrpwd-dictionary")) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(
        rc, Z_EINVAL,
        "a node told to demand credentials from a dictionary it cannot read opened anyway"
    );
}

#[test]
fn a_config_that_states_pubkey_keys_fails_the_open_until_they_are_enforced() {
    let port = free_port();
    let entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        (
            "transport/auth/pubkey/public_key_file",
            "\"/nonexistent/pub.pem\"".to_owned(),
        ),
        (
            "transport/auth/pubkey/private_key_file",
            "\"/nonexistent/priv.pem\"".to_owned(),
        ),
    ];
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&entries) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(
        rc, Z_EINVAL,
        "a config stating pubkey authentication opened a node that does not enforce it"
    );
}

/// The count of non-router peers `session` holds a link to, which is how a C program reads
/// whether a peer was admitted.
unsafe fn peers_held(session: &z_owned_session_t) -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wz_capi_c::session::z_session_loan;
    use wz_capi_c::zid::{
        z_closure_zid, z_id_t, z_info_peers_zid, z_moved_closure_zid_t, z_owned_closure_zid_t,
    };
    unsafe extern "C" fn count(_zid: *const z_id_t, ctx: *mut std::ffi::c_void) {
        (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
    }
    let held = AtomicUsize::new(0);
    let mut closure: z_owned_closure_zid_t = std::mem::zeroed();
    z_closure_zid(
        &mut closure,
        Some(count),
        None,
        (&held as *const AtomicUsize).cast_mut().cast(),
    );
    let rc = z_info_peers_zid(
        z_session_loan(session),
        (&mut closure as *mut z_owned_closure_zid_t).cast::<z_moved_closure_zid_t>(),
    );
    assert_eq!(rc, Z_OK);
    held.load(Ordering::SeqCst)
}

/// A client config that dials `port`, stating `user` and `password` when given, and giving up
/// after three seconds rather than retrying for as long as the test runs.
fn client_entries(port: u16, credential: Option<(&str, &str)>) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"client\"".to_owned()),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ("connect/timeout_ms", "3000".to_owned()),
    ];
    if let Some((user, password)) = credential {
        entries.push(("transport/auth/usrpwd/user", format!("\"{user}\"")));
        entries.push(("transport/auth/usrpwd/password", format!("\"{password}\"")));
    }
    entries
}

/// The credentials a node's own config states are what it presents when it dials. A client whose
/// config names the right user and password reaches a listener that demands them; one whose
/// password is wrong, or that states none, does not. The first leg is the control for the other
/// two: it is what shows the listener admits a client at all.
#[test]
fn a_client_presents_the_credential_its_own_config_states() {
    let dictionary = dictionary();
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe {
        open_with(&listener_entries(
            port,
            dictionary.path().to_str().expect("a utf-8 path"),
        ))
    };
    assert_eq!(rc, Z_OK, "the listener opens");

    // SAFETY: fresh configs and sessions.
    let (rc, good) = unsafe { open_with(&client_entries(port, Some((USER, PASSWORD)))) };
    assert_eq!(
        rc, Z_OK,
        "a client stating the right user and password was not admitted"
    );
    // SAFETY: the listener is live.
    assert_eq!(
        unsafe { peers_held(&listener) },
        1,
        "the listener holds the admitted client"
    );
    // SAFETY: the client is live and owned here.
    unsafe { close_session(good) };

    // SAFETY: fresh configs and sessions.
    let (rc, bad) = unsafe { open_with(&client_entries(port, Some((USER, "not-the-password")))) };
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(bad) };
    assert_ne!(rc, Z_OK, "a client stating the wrong password was admitted");

    // SAFETY: fresh configs and sessions.
    let (rc, none) = unsafe { open_with(&client_entries(port, None)) };
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(none) };
    assert_ne!(rc, Z_OK, "a client stating no credential was admitted");

    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
}

/// A config that states only half of a credential is a mistake, and the open refuses it rather
/// than dialling with half.
#[test]
fn a_config_that_states_a_user_without_a_password_fails_the_open() {
    let port = free_port();
    let mut entries = client_entries(port, None);
    entries.push(("transport/auth/usrpwd/user", format!("\"{USER}\"")));
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&entries) };
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(session) };
    assert_eq!(rc, Z_EINVAL, "a user with no password opened a session");
}

/// A listener config that states `access_control/enabled` as `enabled`.
fn access_control_entries(port: u16, enabled: bool) -> Vec<(&'static str, String)> {
    vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ("access_control/enabled", enabled.to_string()),
    ]
}

/// Access control is a policy a node enforces on what its peers send and receive. This surface
/// does not enforce it yet (the ingress verdict has no caller on a C session's receive path), and
/// a node that starts with the policy it was configured with half applied, or not at all, is one
/// its operator believes protected. The disabled config is the control: it must still open, so
/// the refusal below is the policy and not every config that mentions the key.
#[test]
fn a_config_that_enables_access_control_fails_the_open_until_it_is_enforced() {
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, control) = unsafe { open_with(&access_control_entries(port, false)) };
    // SAFETY: the control is live and owned here.
    unsafe { close_session(control) };
    assert_eq!(
        rc, Z_OK,
        "the control (access control stated as disabled) did not open, so the refusal below \
         proves nothing"
    );

    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&access_control_entries(port, true)) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(
        rc, Z_EINVAL,
        "a config enabling access control opened a node that does not enforce it"
    );
}
