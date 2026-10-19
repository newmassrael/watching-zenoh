// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An access-control rule scoped to a USERNAME holds for the peer that authenticated as that user
//! and for no other.
//!
//! Every other interceptor test names the subject `everyone`, which proves a rule is enforced but
//! not that it is enforced on WHOM. The authenticated username is the one subject a peer cannot
//! choose for itself, so the legs below put two users on one listener and write a rule for one:
//!
//!   * the named user's governed puts are dropped before the subscriber;
//!   * the other user's identical puts arrive, which is what separates "the rule is scoped" from
//!     "the rule hits everyone who authenticated";
//!   * flipping the name flips the outcome, so the result follows the SUBJECT and not the order the
//!     peers connected in or a fixed user;
//!   * a name that matches nobody drops nothing.
//!
//! Both sending paths are driven (`z_put` on the session and a put on a declared publisher),
//! because they are different code and a bypass on one is the defect this family looks for.

use std::ffi::{c_void, CString};
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_publisher_t, z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_owned_subscriber_t,
    z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_buf;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::{
    z_declare_publisher, z_publisher_loan, z_publisher_put, z_undeclare_publisher,
};
use wz_capi_c::put::z_put;
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

const GOVERNED: &str = "denied/data";
const FREE: &str = "allowed/data";

const ALICE: (&str, &str) = ("alice", "alice-pw");
const BOB: (&str, &str) = ("bob", "bob-pw");

#[derive(Clone, Copy, Debug)]
enum Via {
    SessionPut,
    Publisher,
}

const BOTH_PATHS: [Via; 2] = [Via::SessionPut, Via::Publisher];

unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK,
            "the config accepts {key:?}"
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

unsafe fn count_samples(
    session: &z_owned_session_t,
    key: &str,
) -> (Arc<AtomicUsize>, *mut CountCtx) {
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
    (hits, ctx)
}

/// One key a client puts on, by one of the two paths.
struct Sender<'a> {
    session: &'a z_owned_session_t,
    key: String,
    publisher: Option<z_owned_publisher_t>,
}

impl<'a> Sender<'a> {
    unsafe fn new(session: &'a z_owned_session_t, via: Via, key: &str) -> Self {
        let publisher = match via {
            Via::SessionPut => None,
            Via::Publisher => {
                let ke = CString::new(key).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                let mut publisher: z_owned_publisher_t = std::mem::zeroed();
                assert_eq!(
                    z_declare_publisher(
                        z_session_loan(session),
                        &mut publisher,
                        z_view_keyexpr_loan(&view),
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
                Some(publisher)
            }
        };
        Self {
            session,
            key: key.to_owned(),
            publisher,
        }
    }

    unsafe fn put(&self, bytes: &[u8]) {
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut payload, bytes.as_ptr(), bytes.len()),
            Z_OK
        );
        let moved = (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>();
        match &self.publisher {
            Some(publisher) => assert_eq!(
                z_publisher_put(z_publisher_loan(publisher), moved, std::ptr::null_mut()),
                Z_OK
            ),
            None => {
                let ke = CString::new(self.key.as_str()).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                assert_eq!(
                    z_put(
                        z_session_loan(self.session),
                        z_view_keyexpr_loan(&view),
                        moved,
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
            }
        }
    }
}

impl Drop for Sender<'_> {
    fn drop(&mut self) {
        if let Some(mut publisher) = self.publisher.take() {
            // SAFETY: a live publisher this value declared.
            unsafe {
                let _ = z_undeclare_publisher(
                    (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
                );
            }
        }
    }
}

/// A dictionary file holding both users, in the `user:password` form upstream reads.
fn dictionary() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("a temp file");
    writeln!(file, "{}:{}", ALICE.0, ALICE.1).expect("write the dictionary");
    writeln!(file, "{}:{}", BOB.0, BOB.1).expect("write the dictionary");
    file
}

/// A policy denying `put` on [`GOVERNED`] at ingress for the listed usernames only.
fn acl_denying_put_to(usernames: &[&str]) -> Vec<(&'static str, String)> {
    let names = usernames
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        ("access_control/enabled", "true".to_owned()),
        ("access_control/default_permission", "\"allow\"".to_owned()),
        (
            "access_control/rules",
            r#"[{ id: "deny_governed", key_exprs: ["denied/**"], messages: ["put"],
                  flows: ["ingress"], permission: "deny" }]"#
                .to_owned(),
        ),
        (
            "access_control/subjects",
            format!(r#"[{{ id: "named", usernames: [{names}] }}]"#),
        ),
        (
            "access_control/policies",
            r#"[{ rules: ["deny_governed"], subjects: ["named"] }]"#.to_owned(),
        ),
    ]
}

struct Outcome {
    governed: usize,
    free: usize,
}

/// A listener holding both users and `policy`; a client that authenticates as `who` sends a burst
/// on the governed key and then one marker on the free key.
fn run(policy: &[(&'static str, String)], who: (&str, &str), via: Via, burst: usize) -> Outcome {
    let dictionary = dictionary();
    let port = free_port();
    let mut listener_entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        (
            "transport/auth/usrpwd/dictionary_file",
            format!("{:?}", dictionary.path().to_str().expect("a utf-8 path")),
        ),
    ];
    listener_entries.extend_from_slice(policy);
    let client_entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"client\"".to_owned()),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ("transport/auth/usrpwd/user", format!("{:?}", who.0)),
        ("transport/auth/usrpwd/password", format!("{:?}", who.1)),
    ];
    // SAFETY: fresh configs and sessions, closed at the end of this function.
    unsafe {
        let (rc, listener) = open_with(&listener_entries);
        assert_eq!(
            rc, Z_OK,
            "the listener opens with its dictionary and policy"
        );
        let (governed_hits, governed_ctx) = count_samples(&listener, "denied/**");
        let (free_hits, free_ctx) = count_samples(&listener, "allowed/**");

        let (rc, client) = open_with(&client_entries);
        assert_eq!(rc, Z_OK, "{}: the client opens with its credential", who.0);
        let governed = Sender::new(&client, via, GOVERNED);
        let free = Sender::new(&client, via, FREE);

        let deadline = Instant::now() + Duration::from_secs(10);
        while free_hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            free.put(b"warm");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            free_hits.load(Ordering::SeqCst) > 0,
            "{} {via:?}: no sample on the free key ever arrived, so nothing below can be judged",
            who.0
        );
        std::thread::sleep(Duration::from_millis(200));
        governed_hits.store(0, Ordering::SeqCst);
        free_hits.store(0, Ordering::SeqCst);

        for _ in 0..burst {
            governed.put(b"payload");
            std::thread::sleep(Duration::from_millis(5));
        }
        free.put(b"marker");
        let deadline = Instant::now() + Duration::from_secs(5);
        while free_hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(400));
        let outcome = Outcome {
            governed: governed_hits.load(Ordering::SeqCst),
            free: free_hits.load(Ordering::SeqCst),
        };

        drop(governed);
        drop(free);
        close_session(client);
        close_session(listener);
        drop(Box::from_raw(governed_ctx));
        drop(Box::from_raw(free_ctx));
        outcome
    }
}

#[test]
fn a_rule_scoped_to_a_username_drops_that_users_governed_puts_on_both_paths() {
    for via in BOTH_PATHS {
        let outcome = run(&acl_denying_put_to(&["bob"]), BOB, via, 5);
        assert_eq!(outcome.governed, 0, "{via:?}: bob's governed puts arrived");
        assert_eq!(outcome.free, 1, "{via:?}: bob's marker is not governed");
    }
}

#[test]
fn the_same_rule_delivers_the_other_users_identical_puts_on_both_paths() {
    for via in BOTH_PATHS {
        let outcome = run(&acl_denying_put_to(&["bob"]), ALICE, via, 5);
        assert_eq!(
            outcome.governed, 5,
            "{via:?}: a rule for bob dropped alice's puts, so it is not scoped to a user"
        );
        assert_eq!(outcome.free, 1, "{via:?}: alice's marker arrives");
    }
}

#[test]
fn naming_the_other_user_flips_which_peer_is_dropped() {
    for via in BOTH_PATHS {
        let alice = run(&acl_denying_put_to(&["alice"]), ALICE, via, 5);
        assert_eq!(alice.governed, 0, "{via:?}: alice's governed puts arrived");
        let bob = run(&acl_denying_put_to(&["alice"]), BOB, via, 5);
        assert_eq!(
            bob.governed, 5,
            "{via:?}: bob was dropped by a rule for alice"
        );
    }
}

#[test]
fn a_username_nobody_holds_drops_nothing() {
    for via in BOTH_PATHS {
        let outcome = run(&acl_denying_put_to(&["mallory"]), BOB, via, 5);
        assert_eq!(
            outcome.governed, 5,
            "{via:?}: a rule for a user who is not connected dropped a put"
        );
    }
}
