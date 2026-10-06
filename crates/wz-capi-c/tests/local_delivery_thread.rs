// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Where a callback runs, driven through the exported `z_*` symbols as a C program would.
//!
//! A delivery a session makes to ITSELF (a put whose subscriber is in the same session) runs
//! inside the call that causes it, on the calling thread, as zenoh-c runs it. A delivery that
//! ARRIVES from a peer runs on the session's drive thread. The two halves are one test each, and
//! the second is the control: a callback that runs on the calling thread proves nothing if every
//! callback does.
//!
//! The real library's order for the same rows is diffed in
//! `wz-integration-tests/tests/zenoh_c_local_delivery_inline_twice_and_diff.rs`; this file holds
//! the rows where no oracle is needed, so a lane without one still reads them.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
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

const OUTER: &str = "wz/local-delivery/outer";
const INNER: &str = "wz/local-delivery/inner";
const REMOTE: &str = "wz/local-delivery/remote";

/// What a callback saw: its name and the thread it ran on, in the order they ran.
type Events = Arc<Mutex<Vec<(&'static str, ThreadId)>>>;

/// A callback's context. `puts` is the key it publishes on from inside itself, when it does.
struct Ctx {
    name: &'static str,
    events: Events,
    session: *const z_owned_session_t,
    puts: Option<&'static str>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    ctx.events
        .lock()
        .unwrap()
        .push((ctx.name, std::thread::current().id()));
    if let Some(key) = ctx.puts {
        put_once(&*ctx.session, key);
        ctx.events
            .lock()
            .unwrap()
            .push(("outer-end", std::thread::current().id()));
    }
}

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

fn stated(mode: &str, listen: Option<u16>, connect: Option<u16>) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("scouting/multicast/enabled", String::from("false")),
        ("mode", format!("\"{mode}\"")),
    ];
    if let Some(port) = listen {
        entries.push(("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")));
    }
    if let Some(port) = connect {
        entries.push(("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")));
    }
    entries
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// Subscribe to `key` with a callback that records `name` and the thread it ran on.
unsafe fn subscribe(session: &z_owned_session_t, key: &str, ctx: *mut Ctx) -> z_owned_subscriber_t {
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
    sub
}

unsafe fn put_once(session: &z_owned_session_t, key: &str) {
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let text = CString::new("x").unwrap();
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

fn new_ctx(
    name: &'static str,
    events: &Events,
    session: *const z_owned_session_t,
    puts: Option<&'static str>,
) -> *mut Ctx {
    Box::into_raw(Box::new(Ctx {
        name,
        events: events.clone(),
        session,
        puts,
    }))
}

/// A put whose subscriber is in the same session runs the callback BEFORE `z_put` returns, on the
/// thread that called it; and one made from inside a callback runs ITS callback inside the outer
/// one, between its first event and its last.
#[test]
fn a_delivery_a_session_makes_to_itself_runs_inside_the_call_on_the_calling_thread() {
    // SAFETY: a fresh config and session, owned by this test until closed below.
    let (rc, session) = unsafe { open_with(&stated("peer", None, None)) };
    assert_eq!(rc, Z_OK);
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let caller = std::thread::current().id();

    let outer = new_ctx("outer", &events, &session, Some(INNER));
    let inner = new_ctx("inner", &events, &session, None);
    // SAFETY: the session is live; the contexts are freed after it closes.
    let (_sub_outer, _sub_inner) = unsafe {
        (
            subscribe(&session, OUTER, outer),
            subscribe(&session, INNER, inner),
        )
    };

    // SAFETY: the session is live.
    unsafe { put_once(&session, OUTER) };
    // Read at once, with no wait: the callbacks have run or they have not.
    let seen = events.lock().unwrap().clone();
    let names: Vec<&str> = seen.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        ["outer", "inner", "outer-end"],
        "every callback of a delivery to this session's own subscribers must have run when the \
         put returns, the inner one inside the outer one"
    );
    assert!(
        seen.iter().all(|(_, thread)| *thread == caller),
        "a delivery a session makes to itself runs on the thread that made the call: {seen:?}"
    );

    // SAFETY: the session is live and owned here; the contexts are freed after it.
    unsafe {
        close_session(session);
        drop(Box::from_raw(outer));
        drop(Box::from_raw(inner));
    }
}

/// The control: a delivery that ARRIVES from a peer runs on the session's drive thread, not on
/// the test's, so the leg above is the policy and not "every callback runs here".
#[test]
fn a_delivery_that_arrives_from_a_peer_runs_on_the_drive_thread() {
    let port = free_port();
    // SAFETY: fresh configs and sessions.
    let (rc, listener) = unsafe { open_with(&stated("peer", Some(port), None)) };
    assert_eq!(rc, Z_OK);
    let (rc, dialler) = unsafe { open_with(&stated("peer", None, Some(port))) };
    assert_eq!(rc, Z_OK);
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let heard = new_ctx("remote", &events, &listener, None);
    // SAFETY: the listener is live; the context is freed after it closes.
    let _sub = unsafe { subscribe(&listener, REMOTE, heard) };

    let arrived = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !arrived.load(Ordering::SeqCst) && Instant::now() < deadline {
        // SAFETY: the dialler is live.
        unsafe { put_once(&dialler, REMOTE) };
        std::thread::sleep(Duration::from_millis(50));
        if !events.lock().unwrap().is_empty() {
            arrived.store(true, Ordering::SeqCst);
        }
    }
    let seen = events.lock().unwrap().clone();
    assert!(!seen.is_empty(), "the peer's put never arrived");
    let here = std::thread::current().id();
    assert!(
        seen.iter().all(|(_, thread)| *thread != here),
        "a delivery from a peer ran on the test's thread: {seen:?}"
    );

    // SAFETY: both sessions are live and owned here; the context is freed after them.
    unsafe {
        close_session(dialler);
        close_session(listener);
        drop(Box::from_raw(heard));
    }
}
