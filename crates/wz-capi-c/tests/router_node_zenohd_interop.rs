// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A router and a peer opened through the C ABI as the node (`router-node`) forward between a
//! wz client and a REAL zenohd.
//!
//! # What is being claimed
//!
//! `session_roles` shows that a router opened by `z_open` forwards between two wz clients and
//! that a peer holding a `gateway/south` does the same; both ends are wz, so they agree with
//! themselves. Here the far side is a genuine zenohd router, which is what a program replacing a
//! zenoh node meets: the node has to be a router to it (a link between two routers carries the
//! link-state a router speaks), and a peer to it (a peer node dials its router and relays its own
//! clients).
//!
//! # The two legs, and why each delivers through the node
//!
//! Both put a wz client on each side of the node, so that a put crosses the node and zenohd and
//! no other path joins the two clients: multicast scouting is off on every node, and a client
//! dials one endpoint only.
//!
//! * the router leg: the wz router listens and dials zenohd (two routers, one link between them);
//!   client A dials the wz router, client B dials zenohd.
//! * the peer leg: the wz peer listens, keeps `gateway/south` apart for its clients, and dials
//!   zenohd as its router; client A dials the wz peer, client B dials zenohd.
//!
//! Each leg delivers a put in both directions. The control of each leg removes the link between
//! the node and zenohd and runs the same put: it must not arrive, which is what makes a delivery
//! in the leg a delivery through the node and not through some path the harness left open.
//!
//! A third leg holds the interest of a node's publisher and querier. A peer node below zenohd
//! (the same peer as above) declares a publisher and a querier, a wz client beyond zenohd then
//! declares a subscriber and a queryable, and the node's matching must say that something
//! matches. zenohd tells a peer below it a declaration only for an interest the peer holds, so
//! the node's publisher and querier each declare one; with either left out, that one never learns
//! (each measured on its own). A publisher on a key nothing subscribes to stays unmatched, and
//! nothing matches before the client declares anything. The interest is not witnessed where the
//! peer dials the node directly, which is why this leg sits below a router.
//!
//! # What is NOT claimed
//!
//! A remote the node dials and places in its own south (a node that dials into a subregion) has
//! no counterpart here: zenohd is a router, which the preset places in the north of a peer, and
//! putting it in a south needs a zenohd that is itself a gateway to compare the placement with.
//!
//! # Why this file is in wz-capi-c
//!
//! For `config_verdict_zenohd_interop`'s reason: wz-capi-c is deliberately not a dependency of
//! `wz-integration-tests`, and the C ABI is reachable only by linking it.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set `WZ_ZENOHD_BIN` or run
//! `scripts/build-zenohd.sh`). Run via Layer Z / `--ignored`.

use std::ffi::{c_void, CString};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_query_t, z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_query_t,
    z_moved_closure_sample_t, z_moved_config_t, z_moved_session_t, z_owned_bytes_t,
    z_owned_closure_query_t, z_owned_closure_sample_t, z_owned_config_t, z_owned_publisher_t,
    z_owned_querier_t, z_owned_queryable_t, z_owned_session_t, z_owned_subscriber_t,
    z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::matching::{
    z_matching_status_t, z_publisher_get_matching_status, z_querier_get_matching_status,
};
use wz_capi_c::publisher::{z_declare_publisher, z_publisher_loan};
use wz_capi_c::put::z_put;
use wz_capi_c::querier::{z_declare_querier, z_querier_loan};
use wz_capi_c::query::{z_closure_query, z_declare_queryable};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

const KEYEXPR: &str = "wz/router-node/zenohd";

/// How long zenohd gets to accept TCP after it is spawned.
const ZENOHD_UP_BUDGET: Duration = Duration::from_secs(30);

/// How long a put gets to cross the node, through zenohd or the other way.
const DELIVERY_BUDGET: Duration = Duration::from_secs(20);

/// How long a put that must NOT arrive is given before it is called absent.
const ABSENCE_WINDOW: Duration = Duration::from_secs(3);

/// Locate the reference `zenohd`, as `config_verdict_zenohd_interop` does.
fn zenohd_binary() -> PathBuf {
    if let Ok(p) = std::env::var("WZ_ZENOHD_BIN") {
        return PathBuf::from(p);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/zenohd/zenohd")
        .canonicalize()
        .expect("target/zenohd/zenohd is missing; run scripts/build-zenohd.sh");
    assert!(path.is_file(), "{} is not a file", path.display());
    path
}

/// Kills the child on drop, so a panicking test does not leave a zenohd holding the port.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A zenohd router on `port`, returned once it accepts TCP.
fn spawn_zenohd(port: u16) -> ChildGuard {
    let child = Command::new(zenohd_binary())
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("zenohd spawns");
    let mut guard = ChildGuard(child);
    let deadline = Instant::now() + ZENOHD_UP_BUDGET;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return guard;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!("zenohd exited before accepting on {port}: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "zenohd did not accept on {port} within {ZENOHD_UP_BUDGET:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Open a session with `entries` inserted as json5 values.
unsafe fn open(entries: &[(&str, String)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let k = CString::new(*key).unwrap();
        let v = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    assert_eq!(rc, Z_OK, "a session opens on {entries:?}");
    session
}

fn endpoints(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

/// A client that dials `port`.
unsafe fn open_client(port: u16) -> z_owned_session_t {
    open(&[
        ("mode", String::from("\"client\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("connect/endpoints", endpoints(port)),
        (
            "connect/retry",
            String::from("{period_init_ms: 100, period_max_ms: 200}"),
        ),
    ])
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

/// Declare a counting subscriber on [`KEYEXPR`]. The returned context must be freed by the caller
/// after `session` has closed.
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
    let text = CString::new("router-node").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    // The return code is not asserted: until the declarations have crossed, a put has nowhere to
    // go, and what this file measures is the ARRIVAL.
    let _ = z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    );
}

/// Put from `publisher` every 100 ms until a sample is counted by `hits`.
unsafe fn put_until_it_arrives(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + DELIVERY_BUDGET;
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(100));
    }
    hits.load(Ordering::SeqCst) > 0
}

/// Put from `publisher` for [`ABSENCE_WINDOW`], and say whether anything was counted by `hits`.
unsafe fn put_and_see_nothing(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + ABSENCE_WINDOW;
    while Instant::now() < deadline {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(100));
    }
    hits.load(Ordering::SeqCst) == 0
}

/// The configuration of the node under test on `own` that dials `zenohd` when it is given one.
///
/// `mode` is the role of the node, and `extra` what that role adds. Multicast scouting is off, so
/// the clients and zenohd find the node only by the endpoints they are told.
fn node_entries(
    mode: &str,
    own: u16,
    zenohd: Option<u16>,
    extra: &[(&'static str, String)],
) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("mode", format!("\"{mode}\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("listen/endpoints", endpoints(own)),
    ];
    if let Some(port) = zenohd {
        entries.push(("connect/endpoints", endpoints(port)));
    }
    entries.extend(extra.iter().cloned());
    entries
}

/// The two clients of a leg, A on the node and B on zenohd, and a put from each crossing to the
/// other. Returns whether each direction arrived.
unsafe fn cross(node_port: u16, zenohd_port: u16) -> (bool, bool) {
    let (a, b) = (open_client(node_port), open_client(zenohd_port));
    let (heard_by_a, ctx_a) = count_samples(&a);
    let (heard_by_b, ctx_b) = count_samples(&b);
    let a_to_b = put_until_it_arrives(&a, &heard_by_b);
    let b_to_a = put_until_it_arrives(&b, &heard_by_a);
    close_session(a);
    close_session(b);
    drop(Box::from_raw(ctx_a));
    drop(Box::from_raw(ctx_b));
    (a_to_b, b_to_a)
}

/// The control of a leg: the node does not dial zenohd, and a put of client A must not reach
/// client B.
unsafe fn control(node_port: u16, zenohd_port: u16) -> bool {
    let (a, b) = (open_client(node_port), open_client(zenohd_port));
    let (heard_by_b, ctx_b) = count_samples(&b);
    let nothing = put_and_see_nothing(&a, &heard_by_b);
    close_session(a);
    close_session(b);
    drop(Box::from_raw(ctx_b));
    nothing
}

#[test]
#[ignore = "binary-dep e2e (a router opened through z_open beside a real zenohd); Layer Z runs via --ignored"]
fn a_router_node_and_a_zenohd_forward_between_the_clients_of_each() {
    let (zenohd_port, node_port) = (free_port(), free_port());
    let _zenohd = spawn_zenohd(zenohd_port);

    // The control: with no link between the router and zenohd the two clients share no path.
    let control_node = free_port();
    // SAFETY: fresh sessions closed below.
    let alone = unsafe {
        let node = open(&node_entries("router", control_node, None, &[]));
        let nothing = control(control_node, zenohd_port);
        close_session(node);
        nothing
    };
    assert!(
        alone,
        "a put crossed with no link between the router and zenohd: the harness joins the \
         clients by some other path, so a delivery below proves nothing"
    );

    // SAFETY: fresh sessions closed below.
    let (a_to_b, b_to_a) = unsafe {
        let node = open(&node_entries("router", node_port, Some(zenohd_port), &[]));
        let crossed = cross(node_port, zenohd_port);
        close_session(node);
        crossed
    };
    assert!(
        a_to_b,
        "a put of the client of the wz router never reached the client of zenohd"
    );
    assert!(
        b_to_a,
        "a put of the client of zenohd never reached the client of the wz router"
    );
}

/// A queryable handler that answers nothing: the matching of a querier counts the declaration.
unsafe extern "C" fn on_query_ignored(_query: *mut z_loaned_query_t, _ctx: *mut c_void) {}

/// Declare a queryable on [`KEYEXPR`] that answers nothing.
unsafe fn declare_silent_queryable(session: &z_owned_session_t) -> z_owned_queryable_t {
    let mut closure: z_owned_closure_query_t = std::mem::zeroed();
    z_closure_query(
        &mut closure,
        Some(on_query_ignored),
        None,
        std::ptr::null_mut(),
    );
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
        Z_OK
    );
    queryable
}

/// Wait up to [`DELIVERY_BUDGET`] for `check` to hold, and say whether it did.
fn eventually(check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + DELIVERY_BUDGET;
    while !check() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}

/// Whether `check` stays false for [`ABSENCE_WINDOW`].
fn never(check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + ABSENCE_WINDOW;
    while Instant::now() < deadline {
        if check() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[test]
#[ignore = "binary-dep e2e (a peer node's matching below a real zenohd); Layer Z runs via --ignored"]
fn a_node_below_a_zenohd_learns_of_the_subscriber_and_queryable_beyond_it() {
    let (zenohd_port, node_port) = (free_port(), free_port());
    let _zenohd = spawn_zenohd(zenohd_port);
    let south = [(
        "gateway",
        String::from(r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#),
    )];
    // SAFETY: fresh sessions, closed below; the contexts outlive their sessions.
    unsafe {
        let node = open(&node_entries("peer", node_port, Some(zenohd_port), &south));
        let beyond = open_client(zenohd_port);
        let key = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
        let elsewhere = CString::new("wz/router-node/elsewhere").unwrap();
        let mut elsewhere_view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut elsewhere_view, elsewhere.as_ptr()),
            Z_OK
        );

        // The node's publisher and querier are declared BEFORE anything beyond the router holds
        // a subscriber or a queryable, so what they learn they learn from the router's interest
        // answer and its later declarations.
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        let mut apart: z_owned_publisher_t = std::mem::zeroed();
        let mut querier: z_owned_querier_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&node),
                &mut publisher,
                z_view_keyexpr_loan(&view),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&node),
                &mut apart,
                z_view_keyexpr_loan(&elsewhere_view),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        assert_eq!(
            z_declare_querier(
                z_session_loan(&node),
                &mut querier,
                z_view_keyexpr_loan(&view),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        let publisher_matches = || {
            let mut status: z_matching_status_t = std::mem::zeroed();
            assert_eq!(
                z_publisher_get_matching_status(z_publisher_loan(&publisher), &mut status),
                Z_OK
            );
            status.matching
        };
        let apart_matches = || {
            let mut status: z_matching_status_t = std::mem::zeroed();
            assert_eq!(
                z_publisher_get_matching_status(z_publisher_loan(&apart), &mut status),
                Z_OK
            );
            status.matching
        };
        let querier_matches = || {
            let mut status: z_matching_status_t = std::mem::zeroed();
            assert_eq!(
                z_querier_get_matching_status(z_querier_loan(&querier), &mut status),
                Z_OK
            );
            status.matching
        };

        // The control: nothing beyond the router holds anything yet, so nothing matches.
        assert!(
            never(|| publisher_matches() || querier_matches()),
            "the node matched before anything beyond zenohd held a subscriber or a queryable"
        );

        let (_heard, ctx) = count_samples(&beyond);
        let _queryable = declare_silent_queryable(&beyond);
        assert!(
            eventually(&publisher_matches),
            "the node's publisher never learned of the subscriber beyond zenohd"
        );
        assert!(
            eventually(&querier_matches),
            "the node's querier never learned of the queryable beyond zenohd"
        );
        assert!(
            never(&apart_matches),
            "a publisher on a key nothing subscribes to matched"
        );

        close_session(beyond);
        close_session(node);
        drop(Box::from_raw(ctx));
    }
}

#[test]
#[ignore = "binary-dep e2e (a peer node opened through z_open beside a real zenohd); Layer Z runs via --ignored"]
fn a_peer_node_that_keeps_a_south_relays_between_its_client_and_zenohd() {
    let (zenohd_port, node_port) = (free_port(), free_port());
    let _zenohd = spawn_zenohd(zenohd_port);
    // A south kept apart is what makes the C ABI open a peer as the node.
    let south = [(
        "gateway",
        String::from(r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#),
    )];

    let control_node = free_port();
    // SAFETY: fresh sessions closed below.
    let alone = unsafe {
        let node = open(&node_entries("peer", control_node, None, &south));
        let nothing = control(control_node, zenohd_port);
        close_session(node);
        nothing
    };
    assert!(
        alone,
        "a put crossed with no link between the peer and zenohd: the harness joins the \
         clients by some other path, so a delivery below proves nothing"
    );

    // SAFETY: fresh sessions closed below.
    let (a_to_b, b_to_a) = unsafe {
        let node = open(&node_entries("peer", node_port, Some(zenohd_port), &south));
        let crossed = cross(node_port, zenohd_port);
        close_session(node);
        crossed
    };
    assert!(
        a_to_b,
        "a put of the client of the wz peer never reached the client of zenohd"
    );
    assert!(
        b_to_a,
        "a put of the client of zenohd never reached the client of the wz peer"
    );
}
