// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A subscription is a declaration on the wire, and the policy governs declarations as it governs
//! the data: a `declare_subscriber` the policy denies is not sent (egress) or not learned
//! (ingress), so the node that would have been told never learns that the key has a subscriber.
//!
//! What a declaration changes on a wz node is its publishers' MATCHING STATUS, not the routing of
//! a put: a put is sent to every connected peer whether or not that peer declared a subscription
//! (the receiver filters), so a denied declaration cannot be observed as a put that did not
//! arrive. The matching status is what a program reads to learn "is anyone listening", and it is
//! computed from the declarations the node accepted, which is what the policy is asked about.
//!
//! The CONTROL is the same two subscriptions against nodes with no policy: both publishers match,
//! so "the governed publisher does not match" is the policy and not a harness that never
//! delivers a declaration.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_closure_sample_t, z_moved_config_t, z_moved_session_t,
    z_owned_closure_sample_t, z_owned_config_t, z_owned_liveliness_token_t, z_owned_publisher_t,
    z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::liveliness::{z_liveliness_declare_subscriber, z_liveliness_declare_token};
use wz_capi_c::matching::{z_matching_status_t, z_publisher_get_matching_status};
use wz_capi_c::publisher::{z_declare_publisher, z_publisher_loan};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

const GOVERNED: &str = "denied/data";
const FREE: &str = "allowed/data";

unsafe fn open_with(entries: &[(&str, String)]) -> z_owned_session_t {
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
    assert_eq!(rc, Z_OK, "the node opens with its policy");
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, _ctx: *mut c_void) {}

unsafe fn view(key: &CString) -> z_view_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
    view
}

unsafe fn subscribe(session: &z_owned_session_t, key: &str) -> z_owned_subscriber_t {
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut());
    let key = CString::new(key).unwrap();
    let ke = view(&key);
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&ke),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    sub
}

unsafe fn publisher(session: &z_owned_session_t, key: &str) -> z_owned_publisher_t {
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    let key = CString::new(key).unwrap();
    let ke = view(&key);
    assert_eq!(
        z_declare_publisher(
            z_session_loan(session),
            &mut publisher,
            z_view_keyexpr_loan(&ke),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    publisher
}

unsafe fn matching(publisher: &z_owned_publisher_t) -> bool {
    let mut status = z_matching_status_t { matching: false };
    assert_eq!(
        z_publisher_get_matching_status(z_publisher_loan(publisher), &mut status),
        Z_OK
    );
    status.matching
}

fn endpoint(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

/// A policy denying `declare_subscriber` on the governed key in `flow`, for every peer.
fn acl_denying_declaration(flow: &str) -> Vec<(&'static str, String)> {
    vec![
        ("access_control/enabled", "true".to_owned()),
        ("access_control/default_permission", "\"allow\"".to_owned()),
        (
            "access_control/rules",
            format!(
                r#"[{{ id: "deny_governed", key_exprs: ["denied/**"],
                      messages: ["declare_subscriber"], flows: ["{flow}"],
                      permission: "deny" }}]"#
            ),
        ),
        (
            "access_control/subjects",
            r#"[{ id: "everyone" }]"#.to_owned(),
        ),
        (
            "access_control/policies",
            r#"[{ rules: ["deny_governed"], subjects: ["everyone"] }]"#.to_owned(),
        ),
    ]
}

/// Whether the listener's publisher on each key matches, after a client subscribed to both.
struct Outcome {
    governed: bool,
    free: bool,
}

fn run(
    listener_policy: &[(&'static str, String)],
    client_policy: &[(&'static str, String)],
) -> Outcome {
    let port = free_port();
    // SAFETY: fresh configs and sessions, closed at the end of this function.
    unsafe {
        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", endpoint(port)),
        ];
        entries.extend_from_slice(listener_policy);
        let listener = open_with(&entries);
        let governed_pub = publisher(&listener, GOVERNED);
        let free_pub = publisher(&listener, FREE);

        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", endpoint(port)),
        ];
        entries.extend_from_slice(client_policy);
        let client = open_with(&entries);
        let _governed_sub = subscribe(&client, "denied/**");
        let _free_sub = subscribe(&client, "allowed/**");

        // The free subscription is the marker: once the listener has learned it, the governed
        // one (declared first, on the same link) has been delivered and judged.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !matching(&free_pub) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            matching(&free_pub),
            "the free subscription was never learned, so nothing below can be judged"
        );
        std::thread::sleep(Duration::from_millis(400));
        let outcome = Outcome {
            governed: matching(&governed_pub),
            free: matching(&free_pub),
        };

        close_session(client);
        close_session(listener);
        outcome
    }
}

struct Count(AtomicUsize);

unsafe extern "C" fn on_counted(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const Count)).0.fetch_add(1, Ordering::SeqCst);
}

/// A liveliness subscriber on `key` whose samples are counted by the returned counter.
unsafe fn watch_liveliness(
    session: &z_owned_session_t,
    key: &str,
) -> (Arc<Count>, *const Count, z_owned_subscriber_t) {
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let raw = Arc::into_raw(count.clone());
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_counted), None, raw as *mut c_void);
    let key = CString::new(key).unwrap();
    let ke = view(&key);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_liveliness_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&ke),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    (count, raw, sub)
}

unsafe fn declare_token(session: &z_owned_session_t, key: &str) -> z_owned_liveliness_token_t {
    let key = CString::new(key).unwrap();
    let ke = view(&key);
    let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
    assert_eq!(
        z_liveliness_declare_token(
            z_session_loan(session),
            &mut token,
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
        ),
        Z_OK
    );
    token
}

/// A policy denying `liveliness_token` on the governed key in `flow`, for every peer.
fn acl_denying_token(flow: &str) -> Vec<(&'static str, String)> {
    let mut policy = acl_denying_declaration(flow);
    policy[2].1 = format!(
        r#"[{{ id: "deny_governed", key_exprs: ["denied/**"],
              messages: ["liveliness_token"], flows: ["{flow}"],
              permission: "deny" }}]"#
    );
    policy
}

/// How many liveliness samples the listener saw for each key after a client declared a token on
/// both.
fn run_tokens(
    listener_policy: &[(&'static str, String)],
    client_policy: &[(&'static str, String)],
) -> Outcome2 {
    let port = free_port();
    // SAFETY: fresh configs and sessions; every raw pointer is released after both close.
    unsafe {
        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", endpoint(port)),
        ];
        entries.extend_from_slice(listener_policy);
        let listener = open_with(&entries);
        let (governed, governed_raw, _governed_sub) = watch_liveliness(&listener, "denied/**");
        let (free, free_raw, _free_sub) = watch_liveliness(&listener, "allowed/**");

        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", endpoint(port)),
        ];
        entries.extend_from_slice(client_policy);
        let client = open_with(&entries);
        let _governed_token = declare_token(&client, "denied/tok");
        let _free_token = declare_token(&client, "allowed/tok");

        let deadline = Instant::now() + Duration::from_secs(10);
        while free.0.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            free.0.load(Ordering::SeqCst) > 0,
            "the free token was never seen, so nothing below can be judged"
        );
        std::thread::sleep(Duration::from_millis(400));
        let outcome = Outcome2 {
            governed: governed.0.load(Ordering::SeqCst),
            free: free.0.load(Ordering::SeqCst),
        };

        close_session(client);
        close_session(listener);
        drop(Arc::from_raw(governed_raw));
        drop(Arc::from_raw(free_raw));
        outcome
    }
}

struct Outcome2 {
    governed: usize,
    free: usize,
}

#[test]
fn control_without_a_policy_both_tokens_are_seen() {
    let outcome = run_tokens(&[], &[]);
    assert_eq!(
        outcome.governed, 1,
        "the harness delivers the governed token"
    );
    assert_eq!(outcome.free, 1);
}

#[test]
fn a_token_denied_on_the_clients_egress_is_never_declared() {
    let outcome = run_tokens(&[], &acl_denying_token("egress"));
    assert_eq!(outcome.governed, 0, "the denied token was announced");
    assert_eq!(outcome.free, 1, "the free token is still announced");
}

#[test]
fn a_token_denied_on_the_listeners_ingress_is_never_seen() {
    let outcome = run_tokens(&acl_denying_token("ingress"), &[]);
    assert_eq!(
        outcome.governed, 0,
        "the listener saw a token its policy denies"
    );
    assert_eq!(outcome.free, 1, "the free token is still seen");
}

#[test]
fn control_without_a_policy_both_subscriptions_are_learned() {
    let outcome = run(&[], &[]);
    assert!(outcome.governed, "the harness delivers the governed key");
    assert!(outcome.free);
}

#[test]
fn a_subscription_denied_on_the_clients_egress_is_never_declared() {
    let outcome = run(&[], &acl_denying_declaration("egress"));
    assert!(
        !outcome.governed,
        "the declaration was sent, so the listener learned the subscriber its client's policy denies"
    );
    assert!(outcome.free, "the free subscription is still learned");
}

#[test]
fn a_subscription_denied_on_the_listeners_ingress_is_never_learned() {
    let outcome = run(&acl_denying_declaration("ingress"), &[]);
    assert!(
        !outcome.governed,
        "the listener learned the declaration its policy denies"
    );
    assert!(outcome.free, "the free subscription is still learned");
}
