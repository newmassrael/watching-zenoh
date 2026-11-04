// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

#[cfg(feature = "router-node")]
use wz_capi_c::abi::{
    z_loaned_query_t, z_loaned_reply_t, z_moved_closure_query_t, z_moved_closure_reply_t,
    z_owned_closure_query_t, z_owned_closure_reply_t, z_owned_publisher_t, z_owned_queryable_t,
};
use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
#[cfg(feature = "router-node")]
use wz_capi_c::get::{z_closure_reply, z_get};
#[cfg(feature = "router-node")]
use wz_capi_c::keyexpr::z_keyexpr_equals;
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
#[cfg(feature = "router-node")]
use wz_capi_c::matching::{z_matching_status_t, z_publisher_get_matching_status};
#[cfg(all(feature = "router-node", not(feature = "zenoh-c-no-unstable-api")))]
use wz_capi_c::publisher::z_publisher_id;
#[cfg(feature = "router-node")]
use wz_capi_c::publisher::{
    z_declare_publisher, z_publisher_delete, z_publisher_keyexpr, z_publisher_loan,
    z_publisher_put, z_undeclare_publisher,
};
use wz_capi_c::put::z_put;
#[cfg(feature = "router-node")]
use wz_capi_c::query::{
    z_closure_query, z_declare_queryable, z_query_reply, z_undeclare_queryable,
};
#[cfg(feature = "router-node")]
use wz_capi_c::result::Z_EUNAVAILABLE;
use wz_capi_c::result::{Z_EINVAL, Z_ENETWORK, Z_OK};
#[cfg(feature = "router-node")]
use wz_capi_c::session::z_session_is_closed;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
#[cfg(feature = "router-node")]
use wz_capi_c::timestamp::{z_timestamp_new, z_timestamp_t};
#[cfg(feature = "router-node")]
use wz_capi_c::zid::z_info_zid;
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
    assert_eq!(put_rc(session), Z_OK);
}

/// What a `z_put` of one small payload answers.
unsafe fn put_rc(session: &z_owned_session_t) -> i8 {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let text = CString::new("roles").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    )
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

/// A peer or router that states no endpoint to dial opens, alone, and a sample it publishes reaches
/// its own subscriber. Before this a config like that was refused, though zenoh starts one.
///
/// What it LISTENS on is not the claim, and the two roles differ in it (R3071): a peer that says
/// nothing binds `tcp/[::]:0` and takes the kernel's port, and a router would bind the fixed
/// `tcp/[::]:7447`, a port a second router or a running daemon on the host holds. The router's row
/// STATES an empty `listen/endpoints`, which is what "nothing to listen on" means to the real
/// library and keeps this row off a port it does not own.
#[test]
fn a_peer_or_router_with_no_endpoint_opens_alone_and_hears_itself() {
    for mode in ["peer", "router"] {
        let mut config = stated(mode, None, None);
        if mode == "router" {
            config.push(("listen/endpoints", String::from("[]")));
        }
        // SAFETY: fresh config and session.
        let (rc, session) = unsafe { open_with(&config) };
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

/// A south kept apart by subregions is placed by a node, and a build without `router-node` opens
/// the registry of faces alone and holds none: the open is refused by the key, whatever the
/// role, and a document that states the preset (or no `gateway` at all) opens as before.
#[cfg(not(feature = "router-node"))]
#[test]
fn a_gateway_south_of_subregions_is_refused_and_the_preset_is_not() {
    let subregions = r#"{ south: [ { filters: [ { modes: ["peer"] } ] } ] }"#;
    for mode in ["peer", "router"] {
        let mut entries = stated(mode, Some(free_port()), None);
        entries.push(("gateway", subregions.to_owned()));
        // SAFETY: a fresh config and session.
        let (rc, session) = unsafe { open_with(&entries) };
        assert_eq!(rc, Z_EINVAL, "a {mode} that partitions its south");
        // SAFETY: a gravestone, which drops as a no-op.
        unsafe { close_session(session) };
    }
    let mut preset = stated("peer", Some(free_port()), None);
    preset.push(("gateway", r#"{ south: "auto" }"#.to_owned()));
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&preset) };
    assert_eq!(rc, Z_OK, "the preset places a remote by its role alone");
    // SAFETY: a live session this test opened.
    unsafe { close_session(session) };
}

/// A build with `router-node` opens a config that keeps its south apart as the node that places a
/// remote by it, and the handle of that session is answered where the node carries the operation
/// (the id, the closing) and by `Z_EUNAVAILABLE` where it does not yet: a `z_put` through it is
/// neither a put that vanishes nor a handle taken for one that is not there (`Z_ENULL`).
///
/// A client that is told no router scouts for one, which no node carries, so it is still refused
/// by the key; the preset opens as it did.
#[cfg(feature = "router-node")]
#[test]
fn a_gateway_south_of_subregions_opens_a_node_that_carries_little_yet() {
    let subregions = r#"{ south: [ { filters: [ { modes: ["peer"] } ] } ] }"#;
    for mode in ["peer", "router"] {
        let mut entries = stated(mode, Some(free_port()), None);
        entries.push(("gateway", subregions.to_owned()));
        // SAFETY: a fresh config and session.
        let (rc, mut session) = unsafe { open_with(&entries) };
        assert_eq!(
            rc, Z_OK,
            "a {mode} that partitions its south opens as a node"
        );
        // SAFETY: a live session this test opened, loaned for each call.
        unsafe {
            let id = z_info_zid(z_session_loan(&session));
            assert!(
                id.id.iter().any(|byte| *byte != 0),
                "the node has its own id ({mode})"
            );
            assert!(!z_session_is_closed(z_session_loan(&session)));
            // The stamp of a session's clock is one of the operations a node does not carry yet.
            let mut stamp: z_timestamp_t = std::mem::zeroed();
            assert_eq!(
                z_timestamp_new(&mut stamp, z_session_loan(&session)),
                Z_EUNAVAILABLE,
                "a node does not carry a timestamp yet ({mode})"
            );
            assert_eq!(
                z_close(z_session_loan_mut(&mut session), std::ptr::null_mut()),
                Z_OK
            );
            assert!(
                z_session_is_closed(z_session_loan(&session)),
                "closed ({mode})"
            );
            close_session(session);
        }
    }
    // A client that is told no router: it scouts for one, and no node carries that.
    let client = vec![
        ("mode", String::from("\"client\"")),
        ("gateway", subregions.to_owned()),
    ];
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&client) };
    assert_eq!(
        rc, Z_EINVAL,
        "a client that scouts and partitions its south"
    );
    // SAFETY: a gravestone, which drops as a no-op.
    unsafe { close_session(session) };
    let mut preset = stated("peer", Some(free_port()), None);
    preset.push(("gateway", r#"{ south: "auto" }"#.to_owned()));
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&preset) };
    assert_eq!(rc, Z_OK, "the preset places a remote by its role alone");
    // SAFETY: a live session this test opened.
    unsafe {
        assert_eq!(
            put_rc(&session),
            Z_OK,
            "the registry of faces carries the put"
        );
        close_session(session);
    }
}

/// A node opened through the C ABI puts and subscribes: a registry peer that dials it hears what
/// the node puts, and the node's subscriber hears what that peer puts.
#[cfg(feature = "router-node")]
#[test]
fn a_node_opened_through_the_c_abi_puts_and_subscribes() {
    let (port_node, port_peer) = (free_port(), free_port());
    let mut node_entries = stated("peer", Some(port_node), None);
    node_entries.push((
        "gateway",
        r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
    ));
    // SAFETY: fresh configs and sessions.
    let (rc, node) = unsafe { open_with(&node_entries) };
    assert_eq!(rc, Z_OK, "the node opens");
    let (rc, peer) = unsafe { open_with(&stated("peer", Some(port_peer), Some(port_node))) };
    assert_eq!(rc, Z_OK, "a registry peer dials the node");
    // SAFETY: both sessions are live; the contexts are freed after them.
    let ((hits_node, ctx_node), (hits_peer, ctx_peer)) =
        unsafe { (count_samples(&node), count_samples(&peer)) };
    // SAFETY: both sessions are live.
    unsafe {
        assert!(
            put_until_it_arrives(&node, &hits_peer),
            "what the node put never reached the peer"
        );
        assert!(
            put_until_it_arrives(&peer, &hits_node),
            "what the peer put never reached the node's subscriber"
        );
    }
    // SAFETY: both sessions are live and owned here; the contexts are freed after them.
    unsafe {
        close_session(node);
        close_session(peer);
        drop(Box::from_raw(ctx_node));
        drop(Box::from_raw(ctx_peer));
    }
}

/// A publisher declared on a node publishes as the node does: a registry peer that dials it hears
/// what the publisher puts, the publisher answers its key and an id of the node's session, a delete
/// goes out, and the publisher is let go. The matching of a publisher is not carried by the node
/// yet and says so.
#[cfg(feature = "router-node")]
#[test]
fn a_publisher_declared_on_a_node_publishes() {
    let (port_node, port_peer) = (free_port(), free_port());
    let mut node_entries = stated("peer", Some(port_node), None);
    node_entries.push((
        "gateway",
        r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
    ));
    // SAFETY: fresh configs and sessions.
    let (rc, node) = unsafe { open_with(&node_entries) };
    assert_eq!(rc, Z_OK, "the node opens");
    let (rc, peer) = unsafe { open_with(&stated("peer", Some(port_peer), Some(port_node))) };
    assert_eq!(rc, Z_OK, "a registry peer dials the node");
    // SAFETY: both sessions are live; the context is freed after them.
    let (hits_peer, ctx_peer) = unsafe { count_samples(&peer) };
    // SAFETY: the node is live.
    unsafe {
        let key = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&node),
                &mut publisher,
                z_view_keyexpr_loan(&view),
                std::ptr::null_mut(),
            ),
            Z_OK,
            "a publisher is declared on the node"
        );
        let loaned = z_publisher_loan(&publisher);
        assert!(
            z_keyexpr_equals(z_publisher_keyexpr(loaned), z_view_keyexpr_loan(&view)),
            "the publisher answers its key"
        );
        // `z_publisher_id` is unstable API, which a build may leave out.
        #[cfg(not(feature = "zenoh-c-no-unstable-api"))]
        {
            let id = z_publisher_id(loaned);
            assert_eq!(
                id.zid.id,
                z_info_zid(z_session_loan(&node)).id,
                "the publisher is an entity of the node's session"
            );
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while hits_peer.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            let text = CString::new("publisher").unwrap();
            let mut payload: z_owned_bytes_t = std::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
            assert_eq!(
                z_publisher_put(
                    loaned,
                    (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                    std::ptr::null_mut(),
                ),
                Z_OK
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            hits_peer.load(Ordering::SeqCst) > 0,
            "what the node's publisher put never reached the peer"
        );
        assert_eq!(z_publisher_delete(loaned, std::ptr::null_mut()), Z_OK);
        let mut status: z_matching_status_t = std::mem::zeroed();
        assert_eq!(
            z_publisher_get_matching_status(loaned, &mut status),
            Z_EUNAVAILABLE,
            "the matching of a publisher is not carried by the node yet"
        );
        assert_eq!(
            z_undeclare_publisher((&mut publisher as *mut z_owned_publisher_t).cast()),
            Z_OK
        );
        close_session(node);
        close_session(peer);
        drop(Box::from_raw(ctx_peer));
    }
}

/// The queryable handler of the node tests: count the query and answer it once.
#[cfg(feature = "router-node")]
unsafe extern "C" fn on_query_answer(query: *mut z_loaned_query_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    if z_view_keyexpr_from_str(&mut view, ke.as_ptr()) != Z_OK {
        return;
    }
    let body = CString::new("answer").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, body.as_ptr()) != Z_OK {
        return;
    }
    let _ = z_query_reply(
        query,
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    );
}

/// The reply handler of the node tests: count the reply.
#[cfg(feature = "router-node")]
unsafe extern "C" fn on_reply_hit(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

/// Declare a queryable on [`KEYEXPR`] that counts the queries it is handed and answers each.
#[cfg(feature = "router-node")]
unsafe fn declare_answering(
    session: &z_owned_session_t,
) -> (z_owned_queryable_t, Arc<AtomicUsize>, *mut CountCtx) {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
    let mut closure: z_owned_closure_query_t = std::mem::zeroed();
    z_closure_query(&mut closure, Some(on_query_answer), None, ctx.cast());
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut queryable,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK,
        "a queryable is declared"
    );
    (queryable, hits, ctx)
}

/// Ask [`KEYEXPR`] from `asker` until a reply has been counted (up to ten seconds), and say
/// whether one was. The context the replies are counted through is freed by the caller.
#[cfg(feature = "router-node")]
unsafe fn get_until_replied(asker: &z_owned_session_t) -> bool {
    let replies = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx {
        hits: replies.clone(),
    }));
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let deadline = Instant::now() + Duration::from_secs(10);
    while replies.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
        z_closure_reply(&mut closure, Some(on_reply_hit), None, ctx.cast());
        assert_eq!(
            z_get(
                z_session_loan(asker),
                z_view_keyexpr_loan(&view),
                std::ptr::null(),
                (&mut closure as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let replied = replies.load(Ordering::SeqCst) > 0;
    // The closure of the last get may still be held by a query under way; its context is
    // leaked rather than freed under it.
    replied
}

/// A node opened through the C ABI answers and asks: a registry peer that dials it gets a reply
/// to a `z_get` from the node's queryable, and the node's `z_get` is answered by the queryable
/// of that peer.
#[cfg(feature = "router-node")]
#[test]
fn a_node_opened_through_the_c_abi_answers_and_asks() {
    let (port_node, port_peer) = (free_port(), free_port());
    let mut node_entries = stated("peer", Some(port_node), None);
    node_entries.push((
        "gateway",
        r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
    ));
    // SAFETY: fresh configs and sessions.
    let (rc, node) = unsafe { open_with(&node_entries) };
    assert_eq!(rc, Z_OK, "the node opens");
    let (rc, peer) = unsafe { open_with(&stated("peer", Some(port_peer), Some(port_node))) };
    assert_eq!(rc, Z_OK, "a registry peer dials the node");
    // SAFETY: both sessions are live; the contexts are freed after them.
    unsafe {
        let (mut node_queryable, node_handled, node_ctx) = declare_answering(&node);
        assert!(
            get_until_replied(&peer),
            "the peer's get was never answered by the node's queryable"
        );
        assert!(node_handled.load(Ordering::SeqCst) > 0);
        // The node's own queryable is let go before the node asks, so that what answers the
        // node's get is the queryable of the peer and not its own.
        assert_eq!(
            z_undeclare_queryable((&mut node_queryable as *mut z_owned_queryable_t).cast()),
            Z_OK
        );
        let (mut peer_queryable, peer_handled, peer_ctx) = declare_answering(&peer);
        assert!(
            get_until_replied(&node),
            "the node's get was never answered by the peer's queryable"
        );
        assert!(peer_handled.load(Ordering::SeqCst) > 0);
        assert_eq!(
            z_undeclare_queryable((&mut peer_queryable as *mut z_owned_queryable_t).cast()),
            Z_OK
        );
        close_session(node);
        close_session(peer);
        drop(Box::from_raw(node_ctx));
        drop(Box::from_raw(peer_ctx));
    }
}

/// A group no other test or node on this host scouts on, so a session that scouts here meets
/// nobody it was not started to meet. ONE PER TEST: a peer answers a Scout now (R3071), so two
/// tests of this file that shared a group found each other when they ran in parallel, and the one
/// that expected to find nobody opened.
const PEER_GROUP: &str = "\"224.0.0.231:7479\"";
/// The group of the client that finds nobody; see [`PEER_GROUP`].
const CLIENT_GROUP: &str = "\"224.0.0.231:7478\"";

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
            ("scouting/multicast/address", String::from(PEER_GROUP)),
            // 1200 and not a value near zenoh's default of 500: the lower bound below is what
            // tells the key from the default, so the two have to be far enough apart that a
            // node which ignored the key cannot meet it.
            ("scouting/delay", String::from("1200")),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(
        rc, Z_OK,
        "a peer with nothing to dial and nobody to find opens"
    );
    assert!(
        waited >= Duration::from_millis(1100),
        "the open returned after {waited:?}, before its 1200 ms scouting delay (the default is \
         500 ms): it did not wait for anyone, or did not read the key"
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
            ("scouting/multicast/address", String::from(CLIENT_GROUP)),
            ("scouting/timeout", String::from("400")),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(rc, Z_ENETWORK);
    // The upper bound is the key's proof: zenoh's default is 3000 ms, so a node that ignored
    // `scouting/timeout` gives up at about 3 s and misses 1500 ms, with room either side for a
    // loaded host.
    assert!(
        waited >= Duration::from_millis(350) && waited < Duration::from_millis(1500),
        "the search was bounded by 400 ms (the default is 3000 ms) and the open gave up after \
         {waited:?}"
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
