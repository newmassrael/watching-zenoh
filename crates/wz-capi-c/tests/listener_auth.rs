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
//!   * a config whose pubkey identity cannot be held fails the open rather than starting
//!     unprotected: one whose key files cannot be read, and, in a build without `auth_pubkey`,
//!     any config that states the keys at all.
//!
//! With `auth_pubkey` a node that states an RSA identity uses it on both sides, as upstream's
//! does: it presents the key to the peers it dials, and it asks a key of the peers it accepts
//! and admits none of them, because the set of peer keys a node builds from its config is empty
//! upstream (`AuthPubKey::from_config` leaves it so, and nothing in the config fills it).

use std::ffi::CString;
use std::io::Write as _;
use std::time::{Duration, Instant};

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
            // `{:?}` quotes and escapes: a Windows temp path holds backslashes, which a bare
            // JSON5 string reads as escape sequences and refuses (the insert returned -2 there).
            format!("{dictionary_path:?}"),
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
fn a_config_whose_pubkey_identity_cannot_be_held_fails_the_open() {
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
        "a config stating a pubkey identity that cannot be loaded opened a node without it"
    );
}

/// A fresh RSA identity as the two inline PEM texts a config carries, public first, and the
/// private key itself for a test that builds a method from it.
#[cfg(feature = "auth_pubkey")]
fn pubkey_identity() -> (String, String, wz_runtime_tokio::rsa::RsaPrivateKey) {
    use wz_runtime_tokio::extauth_pubkey::generate_keypair;
    use wz_runtime_tokio::rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use wz_runtime_tokio::rsa::RsaPublicKey;

    let key = generate_keypair(512).expect("a 512-bit test key");
    let public = RsaPublicKey::from(&key)
        .to_pkcs1_pem(LineEnding::LF)
        .expect("public PEM");
    let private = key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("private PEM")
        .to_string();
    (public, private, key)
}

/// The two config entries that state an identity inline. `{:?}` writes each PEM as a JSON5 string
/// with its line breaks escaped.
#[cfg(feature = "auth_pubkey")]
fn pubkey_entries(public: &str, private: &str) -> [(&'static str, String); 2] {
    [
        (
            "transport/auth/pubkey/public_key_pem",
            format!("{public:?}"),
        ),
        (
            "transport/auth/pubkey/private_key_pem",
            format!("{private:?}"),
        ),
    ]
}

/// A peer that dials `port` presenting `key` through the public-key method, and what its open
/// came to. Its own set of responder keys is disabled, so the only refusal it can meet is the
/// listener's.
#[cfg(feature = "auth_pubkey")]
fn dial_with_key(port: u16, key: wz_runtime_tokio::rsa::RsaPrivateKey) -> Result<(), OpenError> {
    use wz_runtime_tokio::extauth_pubkey::PubKeyMethod;

    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    runtime.block_on(async {
        let locator = parse_any_locator(&format!("tcp/127.0.0.1:{port}")).expect("a locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x08; 4];
        let auth = AuthDispatch::new(vec![Box::new(PubKeyMethod::initiator(key)) as _]);
        connect_and_open_session_with_auth(
            locator,
            params,
            auth,
            &DialConfig::default(),
            TokioTime::new(),
            Some(OPEN_ITERATIONS),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .map(|_| ())
    })
}

/// A listener that states a pubkey identity admits no peer, whether the peer presents a key or
/// none: the set of keys it admits is upstream's from-config one, which is empty. The control is
/// the same plain dial to a listener that states no identity, which is admitted, so the refusals
/// are the identity's and not the dialler's.
#[cfg(feature = "auth_pubkey")]
#[test]
fn a_listener_with_a_pubkey_identity_admits_no_peer_as_upstreams_does() {
    let control_port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, control) = unsafe {
        open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            (
                "listen/endpoints",
                format!("[\"tcp/127.0.0.1:{control_port}\"]"),
            ),
        ])
    };
    assert_eq!(rc, Z_OK, "the control listener opens");
    let control_outcome = dial(control_port, None);
    // SAFETY: the control is live and owned here.
    unsafe { close_session(control) };
    assert!(
        control_outcome.is_ok(),
        "a plain dial to a listener stating no identity was refused: {control_outcome:?}, so \
         the refusals below prove nothing"
    );

    let (public, private, _) = pubkey_identity();
    let port = free_port();
    let mut entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
    ];
    entries.extend(pubkey_entries(&public, &private));
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe { open_with(&entries) };
    assert_eq!(rc, Z_OK, "a listener stating a loadable identity opens");
    let (_, _, peer_key) = pubkey_identity();
    let with_a_key = dial_with_key(port, peer_key);
    let with_none = dial(port, None);
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    assert!(
        with_a_key.is_err(),
        "a listener whose admitted set is empty admitted a peer presenting a key"
    );
    assert!(
        with_none.is_err(),
        "a listener stating a pubkey identity admitted a peer that presented none"
    );
}

/// A client that states a pubkey identity presents it when it dials: a responder that admits
/// exactly that key reaches Established with it. The responder asks a key of every peer, so a
/// client that presented none would be refused and its open would fail.
#[cfg(feature = "auth_pubkey")]
#[test]
fn a_client_presents_the_pubkey_identity_its_own_config_states() {
    use wz_runtime_tokio::extauth_pubkey::{generate_keypair, PubKeyMethod};
    use wz_runtime_tokio::rsa::RsaPublicKey;
    use wz_runtime_tokio::session_open::{accept_and_open_session_with_auth, DialedLink};

    let (public, private, client_key) = pubkey_identity();
    let client_public = RsaPublicKey::from(&client_key);
    // Made before the client dials: a key's prime search takes a random time, and the client's
    // `connect/timeout_ms` bounds the whole open, so a key made after the accept could spend that
    // bound before the responder answered (a debug build on Windows did, at 3.37 s).
    let responder_key = generate_keypair(512).expect("a 512-bit responder key");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    listener
        .set_nonblocking(true)
        .expect("a listener tokio can adopt");

    let responder = std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("adopt the listener");
            let (stream, _) = listener.accept().await.expect("the client dials");
            let mut params = fixture_session_init_params();
            params.zid = vec![0x09; 4];
            let auth = AuthDispatch::new(vec![Box::new(PubKeyMethod::responder(
                responder_key,
                Some(vec![client_public]),
            )) as _]);
            accept_and_open_session_with_auth(
                DialedLink::Tcp(stream),
                params,
                auth,
                TokioTime::new(),
                Some(OPEN_ITERATIONS),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .map(|_| ())
        })
    });

    let mut entries = client_entries(port, None);
    entries.extend(pubkey_entries(&public, &private));
    // SAFETY: a fresh config and session.
    let (rc, client) = unsafe { open_with(&entries) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(client) };
    let accepted = responder.join().expect("the responder thread");
    assert_eq!(
        rc, Z_OK,
        "a client stating a pubkey identity was refused by a responder admitting that key"
    );
    assert!(
        accepted.is_ok(),
        "the responder did not reach Established with the client's key: {accepted:?}"
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
    // The client's open returns on the OpenAck, and the listener records the face only after it
    // has sent that OpenAck. Upstream's order is the same: it inserts the transport only after
    // (`io/zenoh-transport/src/unicast/manager.rs`
    // @ `transport_error!(ack.send_open_ack().await, close::reason::GENERIC);`).
    // Reading the count at once races the listener, so the read waits for it within a bound.
    let deadline = Instant::now() + Duration::from_secs(5);
    // SAFETY: the listener is live.
    while unsafe { peers_held(&listener) } == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// A listener config that states `access_control` as enabled, with `policies` verbatim.
fn access_control_entries(port: u16, policies: &str) -> Vec<(&'static str, String)> {
    vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ("access_control/enabled", "true".to_owned()),
        ("access_control/default_permission", "\"allow\"".to_owned()),
        ("access_control/policies", policies.to_owned()),
    ]
}

/// Access control a node cannot compile is not one it may start without: zenoh refuses to start
/// on a policy that names a rule or subject that does not exist, and so does this open, where
/// the alternative is a node its operator believes protected and that is not. Whether a policy
/// that DOES compile is enforced is `tests/interceptors.rs`'s claim; the control here is that it
/// opens at all, so the refusal is the policy and not every config that mentions the key.
#[test]
fn an_access_control_policy_that_cannot_be_compiled_fails_the_open() {
    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, control) = unsafe { open_with(&access_control_entries(port, "[]")) };
    // SAFETY: the control is live and owned here.
    unsafe { close_session(control) };
    assert_eq!(
        rc, Z_OK,
        "the control (access control enabled with no policy) did not open, so the refusal \
         below proves nothing"
    );

    let port = free_port();
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe {
        open_with(&access_control_entries(
            port,
            r#"[{ rules: ["no_such_rule"], subjects: ["no_such_subject"] }]"#,
        ))
    };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(
        rc, Z_EINVAL,
        "a policy naming a rule that does not exist opened a node that cannot enforce it"
    );
}
