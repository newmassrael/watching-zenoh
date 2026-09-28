// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2948 (F) — a zenoh-c session whose link to a REAL zenohd is lost re-dials
//! it, and its declarations reach the new router.
//!
//! # What is being claimed
//!
//! zenoh re-dials a closed session's configured endpoints
//! (`zenoh/src/net/runtime/orchestrator.rs` @
//! `.peers_connector_retry(peers, runtime.whatami() == WhatAmI::Client)`), and
//! R2948 made a wz-capi-c session do the same on its `connect/retry` schedule,
//! replaying its declarations onto the re-dialled link. The unit leg beside
//! the crate (`connect_retry_open::a_session_that_loses_its_link_redials_it`)
//! proves that against a wz listener, which is wz agreeing with itself. Here
//! the far side is a genuine zenohd router, killed and restarted on the SAME
//! port underneath two live wz sessions.
//!
//! # Why the delivery goes through the router
//!
//! Two sessions, A subscribing and B publishing, both clients of the router.
//! A put from B reaches A only if BOTH re-dialled and A's subscription was
//! declared again to the NEW router process, which has none of the old one's
//! state. So one delivery after the restart witnesses the re-dial on each side
//! and the declaration replay, with no reopen by this test.
//!
//! # Why this file is in wz-capi-c
//!
//! For `config_verdict_zenohd_interop`'s reason: wz-capi-c is deliberately not
//! a dependency of `wz-integration-tests` (its `#[no_mangle]` `z_*` symbols
//! collide with the zenoh-pico it links), and the C ABI is reachable only by
//! linking it.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`). Run via Layer Z /
//! `--ignored`.

use std::ffi::{c_void, CString};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

const KEYEXPR: &str = "wz/redial/zenohd";

/// How long zenohd gets to accept TCP after it is spawned.
const ZENOHD_UP_BUDGET: Duration = Duration::from_secs(30);

/// How long a put gets to reach the subscriber, through the router.
const DELIVERY_BUDGET: Duration = Duration::from_secs(20);

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

/// Kills the child on drop, so a panicking test does not leave a zenohd
/// holding the port.
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

/// A client session dialling `port`, re-dialling on a brisk schedule.
unsafe fn open_client(port: u16) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in [
        ("mode", String::from("\"client\"")),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        (
            "connect/retry",
            String::from("{period_init_ms: 100, period_max_ms: 200}"),
        ),
    ] {
        let k = CString::new(key).unwrap();
        let v = CString::new(value).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
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
        "the client opens against the running zenohd"
    );
    session
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

/// Declare a counting subscriber on [`KEYEXPR`]. The returned context must be
/// freed by the caller after `session` has closed.
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
    let text = CString::new("redial").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    // The return code is not asserted: between the kill and the re-dial the
    // publisher has no face, and what this leg measures is the ARRIVAL.
    let _ = z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    );
}

/// Put from `publisher` every 100 ms until a sample is counted.
unsafe fn put_until_it_arrives(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + DELIVERY_BUDGET;
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(100));
    }
    hits.load(Ordering::SeqCst) > 0
}

#[test]
#[ignore = "binary-dep e2e (zenohd restart under two wz-capi-c clients); Layer Z runs via --ignored"]
fn two_clients_redial_a_restarted_zenohd_and_deliver_again() {
    let port = free_port();
    let first = spawn_zenohd(port);

    // SAFETY: fresh sessions, closed below; `ctx` outlives its session.
    let (subscriber, publisher) = unsafe { (open_client(port), open_client(port)) };
    // SAFETY: the subscriber session is live.
    let (hits, ctx) = unsafe { count_samples(&subscriber) };

    // The control: the path works before anything is lost, so a failure after
    // the restart is about the re-dial and not about the router path.
    // SAFETY: the publisher session is live.
    assert!(
        unsafe { put_until_it_arrives(&publisher, &hits) },
        "a put through the first zenohd never arrived"
    );

    // SEVER: the router process goes away with every link and declaration it
    // held, and a FRESH one comes up on the same endpoint.
    drop(first);
    hits.store(0, Ordering::SeqCst);
    let _second = spawn_zenohd(port);

    // SAFETY: both sessions are still the ones opened above; neither was
    // reopened by this test.
    let arrived = unsafe { put_until_it_arrives(&publisher, &hits) };
    assert!(
        arrived,
        "after the restart no put arrived: a session did not re-dial, or the \
         subscription was not declared again to the new router"
    );

    // SAFETY: both sessions are live; `ctx` is freed after its session closed.
    unsafe {
        close_session(subscriber);
        close_session(publisher);
        drop(Box::from_raw(ctx));
    }
}
