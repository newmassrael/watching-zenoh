// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session's `listen` is a SET of endpoints, driven through the exported `z_*` symbols as a C
//! program would.
//!
//! A zenoh node binds every endpoint its `listen/endpoints` states, in order. Until R3076 this
//! ABI bound the first of them and ignored the rest, so a peer that stated a tcp endpoint and a
//! second one was reachable at one of them; and a bind that failed always failed the open,
//! though `listen/exit_on_failure: false` says to skip the endpoint and go on.
//!
//! The rows where the real library is the oracle are in
//! `wz-integration-tests/tests/zenoh_c_scouting_twice_and_diff.rs`; these need none, so a lane
//! without one still reads them.

use std::ffi::{c_void, CString};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::z_put;
use wz_capi_c::result::{Z_ENETWORK, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

/// Open with `entries` inserted as json5 values, returning the result code and the session.
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

struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

/// Subscribe `session` to `key`; the returned counter is how many samples it has been given.
unsafe fn count_samples(session: &z_owned_session_t, key: &str) -> Arc<AtomicUsize> {
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
    hits
}

/// Publish on `key` from `publisher` every 50 ms until `hits` is not zero or `within` has passed.
unsafe fn put_until_it_arrives(
    publisher: &z_owned_session_t,
    key: &str,
    hits: &Arc<AtomicUsize>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let ke = CString::new(key).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let text = CString::new("reached").unwrap();
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
        assert_eq!(
            z_put(
                z_session_loan(publisher),
                z_view_keyexpr_loan(&view),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    hits.load(Ordering::SeqCst) > 0
}

/// A leaf that connects to `port` and nothing else and listens on nothing, scouting off: the
/// only thing it can reach is whatever listens at that port.
unsafe fn open_leaf(port: u16) -> z_owned_session_t {
    let (rc, leaf) = open_with(&[
        ("mode", String::from("\"peer\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("listen/endpoints", String::from("[]")),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
    ]);
    assert_eq!(rc, Z_OK, "the leaf opens");
    leaf
}

/// Whether a sample a leaf of `port` puts reaches `hub`, which subscribes to `key`.
unsafe fn leaf_reaches(hub: &z_owned_session_t, port: u16, key: &str) -> bool {
    let hits = count_samples(hub, key);
    let leaf = open_leaf(port);
    let arrived = put_until_it_arrives(&leaf, key, &hits, Duration::from_secs(8));
    close_session(leaf);
    arrived
}

/// Hold `port` on loopback, as another process would, until the returned listener is dropped.
fn hold(port: u16) -> TcpListener {
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("the port is free to take")
}

/// A hub's config: peer, scouting off, `listen` as stated, and whatever else a row adds.
fn hub_entries(listen: String, extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("mode", String::from("\"peer\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("listen/endpoints", listen),
    ];
    entries.extend(extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
    entries
}

fn endpoints(ports: &[u16]) -> String {
    let each: Vec<String> = ports
        .iter()
        .map(|port| format!("\"tcp/127.0.0.1:{port}\""))
        .collect();
    format!("[{}]", each.join(","))
}

/// A session that states two endpoints is reached at BOTH: a leaf of each port is accepted, and
/// what it puts arrives. Measured on the real library with the same shape.
#[test]
fn a_session_that_states_two_listeners_is_reached_at_both() {
    let (first, second) = (free_port(), free_port());
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(endpoints(&[first, second]), &[]));
        assert_eq!(rc, Z_OK, "the hub opens");
        let at_first = leaf_reaches(&hub, first, "wz/listen-set/first");
        let at_second = leaf_reaches(&hub, second, "wz/listen-set/second");
        close_session(hub);
        assert!(at_first, "nothing reached the hub at its first endpoint");
        assert!(
            at_second,
            "nothing reached the hub at its second endpoint: only the first was bound"
        );
    }
}

/// An endpoint that is already taken fails the open by default (`listen/exit_on_failure` is
/// `true`), though the first endpoint could be bound.
#[test]
fn an_endpoint_that_is_taken_fails_the_open_by_default() {
    let (first, second) = (free_port(), free_port());
    let _taken = hold(second);
    // SAFETY: a fresh config; no session opens.
    let (rc, _) = unsafe { open_with(&hub_entries(endpoints(&[first, second]), &[])) };
    assert_eq!(rc, Z_ENETWORK, "a taken second endpoint fails the open");
}

/// With `listen/exit_on_failure: false` the taken endpoint is skipped and the session listens on
/// the others, whichever of them it was.
#[test]
fn an_endpoint_that_is_taken_is_skipped_when_exit_on_failure_is_false() {
    let (first, second) = (free_port(), free_port());
    let off = [("listen/exit_on_failure", "false")];
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        for (taken, free, key) in [
            (second, first, "wz/listen-set/skip-second"),
            (first, second, "wz/listen-set/skip-first"),
        ] {
            let held = hold(taken);
            let (rc, hub) = open_with(&hub_entries(endpoints(&[first, second]), &off));
            assert_eq!(rc, Z_OK, "the open goes on past the taken endpoint {taken}");
            let arrived = leaf_reaches(&hub, free, key);
            close_session(hub);
            drop(held);
            assert!(arrived, "the endpoint {free} that was free is not bound");
        }
    }
}

/// With every endpoint taken and `exit_on_failure` false the session still opens, listening on
/// nothing: the real library does.
#[test]
fn a_session_whose_every_endpoint_is_taken_opens_when_exit_on_failure_is_false() {
    let (first, second) = (free_port(), free_port());
    let _taken = (hold(first), hold(second));
    // SAFETY: a fresh config and session, closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(
            endpoints(&[first, second]),
            &[("listen/exit_on_failure", "false")],
        ));
        assert_eq!(rc, Z_OK, "the open does not fail");
        close_session(hub);
    }
}

/// A `listen/endpoints` stated as a mode table binds the row of the session's own role, every
/// endpoint of it, and none of another role's.
#[test]
fn a_table_of_listeners_binds_the_row_of_the_sessions_role() {
    let (first, second, router_only) = (free_port(), free_port(), free_port());
    let table = format!(
        "{{ peer: {}, router: {} }}",
        endpoints(&[first, second]),
        endpoints(&[router_only])
    );
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let (rc, hub) = open_with(&hub_entries(table, &[]));
        assert_eq!(rc, Z_OK, "the hub opens");
        let at_first = leaf_reaches(&hub, first, "wz/listen-set/table-first");
        let at_second = leaf_reaches(&hub, second, "wz/listen-set/table-second");
        let router_row_bound = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], router_only)));
        close_session(hub);
        assert!(at_first && at_second, "a peer's row is not all bound");
        assert!(
            router_row_bound.is_err(),
            "the router's row of the table was bound by a peer"
        );
    }
}
