// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The ROLES of a session: which endpoints a config states decides whether `z_open` answers and
//! what the session does, driven through the exported `z_*` symbols as a C program would.
//!
//! The expectations were measured on the real `libzenohc.so` (see
//! `wz-integration-tests/tests/zenoh_c_open_roles_twice_and_diff.rs`, which diffs the same rows
//! against it); this file holds them where no oracle is needed, so a lane without one still
//! reads them.
//!
//! Every leg turns multicast scouting OFF, which is the half of the rows both libraries answer
//! the same way: with it on and no endpoint, the real library opens a session that finds others
//! through the group, and this ABI refuses the open instead, which the last leg states.

use std::ffi::{c_void, CString};
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

const KEYEXPR: &str = "wz/session-roles/demo";

/// The key the config stores multicast scouting under.
const SCOUTING: (&str, &str) = ("scouting/multicast/enabled", "false");

/// Open with `entries` inserted as json5 values, returning the result code and the session (in
/// its gravestone state when the code is not `Z_OK`).
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

/// A config of the given mode with scouting off, plus the endpoints stated.
fn stated(mode: &str, listen: Option<u16>, connect: Option<u16>) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        (SCOUTING.0, SCOUTING.1.to_owned()),
        ("mode", format!("\"{mode}\"")),
    ];
    if let Some(port) = listen {
        entries.push(("listen/endpoints", endpoint(port)));
    }
    if let Some(port) = connect {
        entries.push(("connect/endpoints", endpoint(port)));
    }
    entries
}

fn endpoint(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
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

/// Declare a subscriber on [`KEYEXPR`] that counts its samples. The returned context must
/// outlive `session` and be freed by the caller after it closes.
unsafe fn count_samples(session: &z_owned_session_t) -> (Arc<AtomicUsize>, *mut CountCtx) {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(KEYEXPR).unwrap();
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

unsafe fn put_once(session: &z_owned_session_t) {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let text = CString::new("roles").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
}

/// Put from `publisher` every 50 ms until a sample is counted, for up to 10 s.
unsafe fn put_until_it_arrives(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(50));
    }
    hits.load(Ordering::SeqCst) > 0
}

/// Put exactly `n` samples from `publisher`, then wait until `hits` has counted `n` (up to 5 s)
/// and for a further quiet window, so a sample that arrives twice is counted twice. Returns the
/// count.
unsafe fn put_exactly(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>, n: usize) -> usize {
    hits.store(0, Ordering::SeqCst);
    for _ in 0..n {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(20));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while hits.load(Ordering::SeqCst) < n && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(400));
    hits.load(Ordering::SeqCst)
}

/// A peer or router that states no endpoint opens, alone, and a sample it publishes reaches its
/// own subscriber. Before this a config like that was refused, though zenoh starts one.
#[test]
fn a_peer_or_router_with_no_endpoint_opens_alone_and_hears_itself() {
    for mode in ["peer", "router"] {
        // SAFETY: fresh config and session.
        let (rc, session) = unsafe { open_with(&stated(mode, None, None)) };
        assert_eq!(rc, Z_OK, "a {mode} with no endpoint opens");
        // SAFETY: the session is live; `ctx` is freed after it closes.
        let (hits, ctx) = unsafe { count_samples(&session) };
        // SAFETY: the session is live.
        assert!(
            unsafe { put_until_it_arrives(&session, &hits) },
            "a {mode} that opened alone did not deliver to its own subscriber"
        );
        // SAFETY: the session is live and owned here.
        unsafe {
            close_session(session);
            drop(Box::from_raw(ctx));
        }
    }
}

/// A client fails its open when it has nothing to dial, whether or not it states a listener:
/// zenoh's `start_client` bails once scouting is off and no peer is stated.
#[test]
fn a_client_with_nothing_to_dial_fails_its_open_listener_or_not() {
    // SAFETY: fresh configs and sessions.
    let (bare, a) = unsafe { open_with(&stated("client", None, None)) };
    let (listening, b) = unsafe { open_with(&stated("client", Some(free_port()), None)) };
    assert_eq!(bare, Z_ENETWORK, "a client with no endpoint");
    assert_eq!(listening, Z_ENETWORK, "a client with only a listener");
    // SAFETY: two gravestones, which drop as no-ops.
    unsafe {
        close_session(a);
        close_session(b);
    }
}

/// A group no other test or node on this host scouts on, so a session that scouts here meets
/// nobody it was not started to meet.
const PRIVATE_GROUP: &str = "\"224.0.0.231:7479\"";

/// With multicast scouting ON (zenoh's default) and no endpoint, a peer opens: it scouts the group
/// for the open's start window, finds nobody, and is a session alone, as the real library's is
/// (measured: `open=0` after the scouting delay). It was refused for want of scouting.
#[test]
fn a_peer_that_scouts_and_finds_nobody_opens_after_its_scouting_delay() {
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/address", String::from(PRIVATE_GROUP)),
            ("scouting/delay", String::from("300")),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(
        rc, Z_OK,
        "a peer with nothing to dial and nobody to find opens"
    );
    assert!(
        waited >= Duration::from_millis(250),
        "the open returned after {waited:?}, before its scouting delay: it did not wait for anyone"
    );
    // SAFETY: the session is live; `ctx` is freed after it closes.
    let (hits, ctx) = unsafe { count_samples(&session) };
    // SAFETY: the session is live.
    assert!(
        unsafe { put_until_it_arrives(&session, &hits) },
        "a peer alone did not deliver to its own subscriber"
    );
    // SAFETY: the session is live and owned here.
    unsafe {
        close_session(session);
        drop(Box::from_raw(ctx));
    }
}

/// A client with nothing to dial scouts for the first node it can open to, and fails its open
/// when `scouting/timeout` passes with none (measured on the real library: `-4` after the
/// timeout, 3 s by default).
#[test]
fn a_client_that_scouts_and_finds_nobody_fails_after_its_timeout() {
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("scouting/multicast/address", String::from(PRIVATE_GROUP)),
            ("scouting/timeout", String::from("400")),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(rc, Z_ENETWORK);
    assert!(
        waited >= Duration::from_millis(350) && waited < Duration::from_secs(5),
        "the search was bounded by 400 ms and the open gave up after {waited:?}"
    );
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(session) };
}

/// A client stated with a listener binds it and serves nothing on it: a sample published by a
/// peer that dialled the client never reaches the client, while the node the client dialled does.
/// The positive leg comes first so the negative one is not a subscription that never worked.
#[test]
fn a_client_listener_is_bound_and_serves_nobody() {
    let (x_port, c_port) = (free_port(), free_port());
    // SAFETY: fresh configs and sessions; `x` is the node the client dials.
    let (rc, x) = unsafe { open_with(&stated("peer", Some(x_port), None)) };
    assert_eq!(rc, Z_OK);
    let (rc, client) = unsafe { open_with(&stated("client", Some(c_port), Some(x_port))) };
    assert_eq!(rc, Z_OK, "a client stated with both opens");
    // SAFETY: the client is live; `ctx` is freed after it closes.
    let (hits, ctx) = unsafe { count_samples(&client) };
    // SAFETY: `x` is live.
    assert!(
        unsafe { put_until_it_arrives(&x, &hits) },
        "the node the client dialled never reached it, so the leg below proves nothing"
    );

    // A peer dials the CLIENT's listener, and publishes.
    let (rc, z) = unsafe { open_with(&stated("peer", None, Some(c_port))) };
    assert_eq!(rc, Z_OK);
    // Let the peer's dial settle, so a sample it publishes has a link to ride if there is one.
    std::thread::sleep(Duration::from_millis(600));
    hits.store(0, Ordering::SeqCst);
    for _ in 0..30 {
        // SAFETY: `z` is live.
        unsafe { put_once(&z) };
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a peer that dialled a client's listener reached the client: the listener served a \
         session, which the client's routing does not"
    );
    // SAFETY: the sessions are live and owned here; `ctx` is freed after its session.
    unsafe {
        close_session(z);
        close_session(client);
        close_session(x);
        drop(Box::from_raw(ctx));
    }
}

/// Two peers that each listen on their own port and dial the other's keep ONE link: a sample
/// either publishes arrives once at the other. Two faces to one node delivered every sample
/// twice (measured: 30 duplicates in six seconds); the real library keeps one transport per zid.
#[test]
fn two_peers_that_dial_each_other_keep_one_link() {
    let (port_a, port_b) = (free_port(), free_port());
    // SAFETY: fresh configs and sessions.
    let (rc, a) = unsafe { open_with(&stated("peer", Some(port_a), Some(port_b))) };
    assert_eq!(rc, Z_OK);
    let (rc, b) = unsafe { open_with(&stated("peer", Some(port_b), Some(port_a))) };
    assert_eq!(rc, Z_OK);
    // SAFETY: both sessions are live; the contexts are freed after them.
    let ((hits_a, ctx_a), (hits_b, ctx_b)) = unsafe { (count_samples(&a), count_samples(&b)) };
    // SAFETY: both sessions are live.
    unsafe {
        assert!(put_until_it_arrives(&a, &hits_b), "a never reached b");
        assert!(put_until_it_arrives(&b, &hits_a), "b never reached a");
    }
    // A refused duplicate dial retries on the connect schedule; let it come and go, so the
    // window below measures the links the two peers settled on.
    std::thread::sleep(Duration::from_millis(1500));
    // SAFETY: both sessions are live.
    let (at_b, at_a) = unsafe { (put_exactly(&a, &hits_b, 10), put_exactly(&b, &hits_a, 10)) };
    assert_eq!(at_b, 10, "ten samples from a arrived at b this many times");
    assert_eq!(at_a, 10, "ten samples from b arrived at a this many times");
    // SAFETY: both sessions are live and owned here; the contexts are freed after them.
    unsafe {
        close_session(a);
        close_session(b);
        drop(Box::from_raw(ctx_a));
        drop(Box::from_raw(ctx_b));
    }
}
