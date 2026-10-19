// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The query half of the policy a node's config states: a `query` and a `reply` are messages an
//! access-control rule governs as much as a `put` is, in both directions.
//!
//! `tests/interceptors.rs` holds the put half. A query takes different code from a put on both
//! ends (a request is dispatched to a queryable registry, not a subscriber one, and a reply is
//! staged by the handler and sent from a drain), so a policy that held for puts says nothing about
//! these. Each leg has its control: the identical exchange against nodes with no policy, where
//! the queryable is handled and the reply arrives.
//!
//! Four legs, one per (message, flow) on a client that asks and a listener that answers:
//!
//!   * a `query` denied on the listener's INGRESS never reaches its queryable;
//!   * a `query` denied on the client's EGRESS is never sent;
//!   * a `reply` denied on the listener's EGRESS is handled and never sent;
//!   * a `reply` denied on the client's INGRESS is never delivered to the asker.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_query_t, z_loaned_reply_t, z_moved_bytes_t, z_moved_closure_query_t,
    z_moved_closure_reply_t, z_moved_config_t, z_moved_queryable_t, z_moved_session_t,
    z_owned_bytes_t, z_owned_closure_query_t, z_owned_closure_reply_t, z_owned_config_t,
    z_owned_queryable_t, z_owned_session_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::get::{z_closure_reply, z_get};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::query::{
    z_closure_query, z_declare_queryable, z_query_keyexpr, z_query_reply, z_undeclare_queryable,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_runtime_tokio_test_support::free_port;

const GOVERNED: &str = "denied/q";
const FREE: &str = "allowed/q";

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
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null(),
        ),
        Z_OK,
        "the session opens with its policy"
    );
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// A keyexpr view and the text it aliases (the view does not own it).
unsafe fn view(key: &str) -> (CString, z_view_keyexpr_t) {
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    (ke, view)
}

struct Count(AtomicUsize);

/// The queryable handler: count, then answer on the query's own key.
unsafe extern "C" fn on_query(query: *mut z_loaned_query_t, ctx: *mut c_void) {
    (*(ctx as *const Count)).0.fetch_add(1, Ordering::SeqCst);
    let body = CString::new("answer").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, body.as_ptr()) != Z_OK {
        return;
    }
    let _ = z_query_reply(
        query,
        z_query_keyexpr(query),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    );
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    (*(ctx as *const Count)).0.fetch_add(1, Ordering::SeqCst);
}

/// A queryable on `key` whose handler is counted by the returned counter.
unsafe fn queryable(
    session: &z_owned_session_t,
    key: &str,
) -> (Arc<Count>, *const Count, z_owned_queryable_t) {
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let raw = Arc::into_raw(count.clone());
    let mut closure: z_owned_closure_query_t = std::mem::zeroed();
    z_closure_query(&mut closure, Some(on_query), None, raw as *mut c_void);
    let (_text, ke) = view(key);
    let mut qbl: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut qbl,
            z_view_keyexpr_loan(&ke),
            (&mut closure as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    (count, raw, qbl)
}

/// One `z_get` on `key`, its replies counted by `replies`.
unsafe fn get(session: &z_owned_session_t, key: &str, replies: &Arc<Count>) -> *const Count {
    let raw = Arc::into_raw(replies.clone());
    let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
    z_closure_reply(&mut closure, Some(on_reply), None, raw as *mut c_void);
    let (_text, ke) = view(key);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            (&mut closure as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    raw
}

fn policy(messages: &str, flow: &str) -> Vec<(&'static str, String)> {
    vec![
        ("access_control/enabled", "true".to_owned()),
        ("access_control/default_permission", "\"allow\"".to_owned()),
        (
            "access_control/rules",
            format!(
                r#"[{{ id: "deny_governed", key_exprs: ["denied/**"], messages: ["{messages}"],
                      flows: ["{flow}"], permission: "deny" }}]"#
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

/// What the answerer handled and what the asker got, for each of the two keys.
struct Outcome {
    handled_governed: usize,
    handled_free: usize,
    replies_governed: usize,
    replies_free: usize,
}

fn run(
    listener_policy: &[(&'static str, String)],
    client_policy: &[(&'static str, String)],
) -> Outcome {
    let port = free_port();
    let endpoint = format!("[\"tcp/127.0.0.1:{port}\"]");
    // SAFETY: fresh configs and sessions; every raw pointer is released after both close.
    unsafe {
        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", endpoint.clone()),
        ];
        entries.extend_from_slice(listener_policy);
        let listener = open_with(&entries);
        let (handled_governed, raw_a, qbl_a) = queryable(&listener, "denied/**");
        let (handled_free, raw_b, qbl_b) = queryable(&listener, "allowed/**");

        let mut entries = vec![
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", endpoint),
        ];
        entries.extend_from_slice(client_policy);
        let client = open_with(&entries);

        let replies_governed = Arc::new(Count(AtomicUsize::new(0)));
        let replies_free = Arc::new(Count(AtomicUsize::new(0)));
        let mut raws = vec![raw_a, raw_b];

        // The queryable has to be known to the client first: ask the free key until it answers.
        let deadline = Instant::now() + Duration::from_secs(10);
        while replies_free.0.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            raws.push(get(&client, FREE, &replies_free));
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            replies_free.0.load(Ordering::SeqCst) > 0,
            "the free key was never answered, so nothing below can be judged"
        );
        std::thread::sleep(Duration::from_millis(300));
        for c in [
            &handled_governed,
            &handled_free,
            &replies_governed,
            &replies_free,
        ] {
            c.0.store(0, Ordering::SeqCst);
        }

        // The governed ask, then the free one as the marker: the free reply is on the same link
        // after the governed ask, so once it has come back every governed reply that was going
        // to has too.
        raws.push(get(&client, GOVERNED, &replies_governed));
        raws.push(get(&client, FREE, &replies_free));
        let deadline = Instant::now() + Duration::from_secs(5);
        while replies_free.0.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(500));
        let outcome = Outcome {
            handled_governed: handled_governed.0.load(Ordering::SeqCst),
            handled_free: handled_free.0.load(Ordering::SeqCst),
            replies_governed: replies_governed.0.load(Ordering::SeqCst),
            replies_free: replies_free.0.load(Ordering::SeqCst),
        };

        for mut qbl in [qbl_a, qbl_b] {
            z_undeclare_queryable(
                (&mut qbl as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>(),
            );
        }
        close_session(client);
        close_session(listener);
        for raw in raws {
            drop(Arc::from_raw(raw));
        }
        outcome
    }
}

#[test]
fn control_without_a_policy_the_query_is_handled_and_answered() {
    let outcome = run(&[], &[]);
    assert_eq!(
        outcome.handled_governed, 1,
        "the harness reaches the governed queryable"
    );
    assert_eq!(outcome.replies_governed, 1, "and its reply comes back");
    assert_eq!(outcome.handled_free, 1);
    assert_eq!(outcome.replies_free, 1);
}

#[test]
fn a_query_denied_on_the_listeners_ingress_never_reaches_its_queryable() {
    let outcome = run(&policy("query", "ingress"), &[]);
    assert_eq!(
        outcome.handled_governed, 0,
        "a query the listener's ingress policy denies reached its queryable"
    );
    assert_eq!(outcome.replies_governed, 0);
    assert_eq!(
        outcome.replies_free, 1,
        "the policy denied more than the key it names"
    );
}

#[test]
fn a_query_denied_on_the_clients_egress_is_never_sent() {
    let outcome = run(&[], &policy("query", "egress"));
    assert_eq!(
        outcome.handled_governed, 0,
        "a query the asker's egress policy denies was sent"
    );
    assert_eq!(outcome.replies_governed, 0);
    assert_eq!(
        outcome.replies_free, 1,
        "the policy denied more than the key it names"
    );
}

#[test]
fn a_reply_denied_on_the_listeners_egress_is_handled_and_never_sent() {
    let outcome = run(&policy("reply", "egress"), &[]);
    assert_eq!(
        outcome.handled_governed, 1,
        "the query is not what the policy denies, so it must still be handled"
    );
    assert_eq!(
        outcome.replies_governed, 0,
        "a reply the answerer's egress policy denies was sent"
    );
    assert_eq!(
        outcome.replies_free, 1,
        "the policy denied more than the key it names"
    );
}

#[test]
fn a_reply_denied_on_the_clients_ingress_is_never_delivered_to_the_asker() {
    let outcome = run(&[], &policy("reply", "ingress"));
    assert_eq!(
        outcome.handled_governed, 1,
        "the query is not what the policy denies"
    );
    assert_eq!(
        outcome.replies_governed, 0,
        "a reply the asker's ingress policy denies reached its callback"
    );
    assert_eq!(
        outcome.replies_free, 1,
        "the policy denied more than the key it names"
    );
}
