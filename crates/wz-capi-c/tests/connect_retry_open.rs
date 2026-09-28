// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! ZA-3298 — `z_open` follows `connect/timeout_ms`, `connect/exit_on_failure`
//! and `connect/retry` the way a zenoh node does, driven through the exported
//! `z_*` symbols as a C program would.
//!
//! The consumer's measurement was a driver started beside the daemon it dials:
//! dialing at once failed, dialing two seconds later worked, and the config
//! said to retry. Every leg here starts the dial BEFORE anything listens, so a
//! pass cannot be a dial that simply arrived late.
//!
//! The two client legs are a pair on purpose. The first states a budget and
//! must wait for the listener; the second states none and must NOT, because a
//! client's default is one attempt. Either alone could pass with the retry
//! applied everywhere or nowhere.

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

const KEYEXPR: &str = "wz/connect-retry/demo";

/// How long each leg lets the dial fail before a listener appears. Long
/// enough that a single immediate attempt has certainly been refused.
const LISTENER_LATE_BY: Duration = Duration::from_millis(400);

/// Open with `entries` inserted as json5 values, returning the result code and
/// the session (in its gravestone state when the code is not `Z_OK`).
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

fn endpoint(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// An owned session moved between threads. The C ABI lets any thread own a
/// session; the wrapper only tells the compiler so.
struct SendSession(z_owned_session_t);
// SAFETY: the handle is an owned heap pointer with no thread affinity; the
// drive thread behind it is the session's own.
unsafe impl Send for SendSession {}

/// Open a listener on `port` after `delay`, on its own thread, and hand it
/// back through the join handle.
fn listen_later(port: u16, delay: Duration) -> std::thread::JoinHandle<SendSession> {
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        // SAFETY: a fresh config and session, owned by this thread until returned.
        let (rc, session) = unsafe { open_with(&[("listen/endpoints", endpoint(port))]) };
        assert_eq!(rc, Z_OK, "the late listener must bind");
        SendSession(session)
    })
}

/// A client that states a budget and a schedule waits for a listener that
/// comes up after its first attempt.
#[test]
fn a_client_with_a_connect_budget_waits_for_a_late_listener() {
    let port = free_port();
    let listener = listen_later(port, LISTENER_LATE_BY);
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("connect/endpoints", endpoint(port)),
            ("connect/timeout_ms", String::from("5000")),
            (
                "connect/retry",
                String::from("{period_init_ms: 100, period_max_ms: 200}"),
            ),
        ])
    };
    let waited = started.elapsed();
    let SendSession(listen) = listener.join().expect("listener thread");
    assert_eq!(rc, Z_OK, "the retry must reach the late listener");
    assert!(
        waited >= LISTENER_LATE_BY,
        "the open returned after {waited:?}, before the listener existed: \
         it did not dial before the listener, so this leg measured nothing"
    );
    // SAFETY: both sessions are live and owned here.
    unsafe {
        close_session(session);
        close_session(listen);
    }
}

/// The control: a client that states no budget keeps upstream's client
/// default, `timeout_ms: 0`, and fails on its one attempt.
#[test]
fn a_client_without_a_connect_budget_fails_on_its_one_attempt() {
    let port = free_port();
    let listener = listen_later(port, LISTENER_LATE_BY);
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("connect/endpoints", endpoint(port)),
        ])
    };
    let waited = started.elapsed();
    let SendSession(listen) = listener.join().expect("listener thread");
    assert_eq!(rc, Z_ENETWORK, "a client's default is one attempt");
    assert!(
        waited < LISTENER_LATE_BY,
        "the one attempt took {waited:?}; it must not have waited for the listener"
    );
    // SAFETY: the failed open left a gravestone, which drops as a no-op.
    unsafe {
        close_session(session);
        close_session(listen);
    }
}

/// A stated budget is a bound: with nothing ever listening, the open gives
/// up once it is spent, and not before.
#[test]
fn a_spent_connect_budget_fails_the_open() {
    let port = free_port();
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("connect/endpoints", endpoint(port)),
            ("connect/timeout_ms", String::from("600")),
            ("connect/retry", String::from("{period_init_ms: 100}")),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(rc, Z_ENETWORK);
    assert!(
        waited >= Duration::from_millis(600) && waited < Duration::from_secs(5),
        "the budget was 600 ms and the open gave up after {waited:?}"
    );
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(session) };
}

/// A client is never released before its peer, whatever `exit_on_failure`
/// says: upstream's client connect never reads that key and fails its open
/// when no endpoint connected. (R2942 — R2936 released such a client.)
#[test]
fn a_client_that_states_exit_on_failure_false_still_fails_its_open() {
    let port = free_port();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("connect/endpoints", endpoint(port)),
            ("connect/exit_on_failure", String::from("false")),
        ])
    };
    assert_eq!(rc, Z_ENETWORK, "a client's open waits for its one peer");
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(session) };
}

/// R2950 — a PEER connects to EVERY endpoint, each as a face of its own:
/// a put from either listener reaches the peer's one subscription.
#[test]
fn a_peer_connects_to_every_endpoint() {
    let (port_a, port_b) = (free_port(), free_port());
    let SendSession(a) = listen_later(port_a, Duration::ZERO)
        .join()
        .expect("listener a");
    let SendSession(b) = listen_later(port_b, Duration::ZERO)
        .join()
        .expect("listener b");
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            (
                "connect/endpoints",
                format!("[\"tcp/127.0.0.1:{port_a}\", \"tcp/127.0.0.1:{port_b}\"]"),
            ),
        ])
    };
    assert_eq!(rc, Z_OK);
    // SAFETY: the session is live.
    let (hits, ctx) = unsafe { count_samples(&session) };
    // SAFETY: listener a is live.
    assert!(
        unsafe { put_until_it_arrives(&a, &hits) },
        "endpoint a carried nothing"
    );
    hits.store(0, Ordering::SeqCst);
    // SAFETY: listener b is live.
    assert!(
        unsafe { put_until_it_arrives(&b, &hits) },
        "endpoint b carried nothing: the peer held one face, not one per endpoint"
    );
    // SAFETY: all three sessions are live; `ctx` is freed after its session.
    unsafe {
        close_session(session);
        close_session(a);
        close_session(b);
        drop(Box::from_raw(ctx));
    }
}

/// R2950 — an endpoint's `#exit_on_failure=true` tail makes ITS failure end a
/// peer's open, over the peer's default `false`. The same endpoint without the
/// tail is stepped over and the open comes up. `timeout_ms: 0` makes each one
/// attempt, so the arm the tail picks is the whole difference.
#[test]
fn an_endpoint_exit_on_failure_tail_decides_a_peer_open() {
    let port = free_port();
    // SAFETY: fresh configs and sessions.
    let (strict, s) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            (
                "connect/endpoints",
                format!("[\"tcp/127.0.0.1:{port}#exit_on_failure=true\"]"),
            ),
            ("connect/timeout_ms", String::from("0")),
        ])
    };
    let (lenient, l) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("connect/endpoints", endpoint(port)),
            ("connect/timeout_ms", String::from("0")),
        ])
    };
    assert_eq!(
        strict, Z_ENETWORK,
        "the tail made this endpoint's failure fatal"
    );
    assert_eq!(
        lenient, Z_OK,
        "without the tail a peer steps over the failure"
    );
    // SAFETY: a gravestone and a live session, both owned here.
    unsafe {
        close_session(s);
        close_session(l);
    }
}

/// R2950 — the start window is CONFIG: `connect_scouted: false` returns the
/// open at once, and `scouting/delay` sets how long it waits otherwise.
#[test]
fn the_start_window_follows_the_config() {
    let port = free_port();
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, no_wait) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("connect/endpoints", endpoint(port)),
            (
                "open/return_conditions/connect_scouted",
                String::from("false"),
            ),
        ])
    };
    assert_eq!(rc, Z_OK);
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "connect_scouted false must not wait: {:?}",
        started.elapsed()
    );
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, long_wait) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("connect/endpoints", endpoint(port)),
            ("scouting/delay", String::from("1200")),
        ])
    };
    assert_eq!(rc, Z_OK);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1150) && waited < Duration::from_secs(4),
        "scouting/delay 1200 must set the window: {waited:?}"
    );
    // SAFETY: both sessions are live and owned here.
    unsafe {
        close_session(no_wait);
        close_session(long_wait);
    }
}

/// R2948 — a config naming no `mode` is a PEER, zenoh's default: with nothing
/// listening it opens after the start window rather than failing on one
/// attempt as a client would.
#[test]
fn a_config_without_a_mode_opens_as_a_peer() {
    let port = free_port();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe { open_with(&[("connect/endpoints", endpoint(port))]) };
    assert_eq!(
        rc, Z_OK,
        "an unnamed mode is zenoh's peer, whose open comes up anyway"
    );
    // SAFETY: the session is live and owned here.
    unsafe { close_session(session) };
}

/// R2948 — and a peer whose peer IS listening answers the open from the
/// handshake, inside the start window, not after it.
#[test]
fn a_peer_with_its_peer_up_opens_on_the_handshake() {
    let port = free_port();
    let SendSession(listen) = listen_later(port, Duration::ZERO)
        .join()
        .expect("listener thread");
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("connect/endpoints", endpoint(port)),
        ])
    };
    let waited = started.elapsed();
    assert_eq!(rc, Z_OK);
    assert!(
        waited < Duration::from_millis(450),
        "the peer was up, yet the open took {waited:?}: it waited out the window"
    );
    // SAFETY: both sessions are live and owned here.
    unsafe {
        close_session(session);
        close_session(listen);
    }
}

struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

unsafe fn put_once(session: &z_owned_session_t) {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let text = CString::new("late").unwrap();
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

/// A peer's default is `exit_on_failure: false`: upstream's open returns
/// without waiting for its peer and the connector keeps dialing behind it.
/// So the open succeeds with nothing listening, a subscription declared then
/// reaches the peer once the listener comes up, and a put from the listener
/// arrives.
#[test]
fn a_peer_opens_at_once_and_connects_behind_the_open() {
    let port = free_port();
    let started = Instant::now();
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("connect/endpoints", endpoint(port)),
            ("connect/retry", String::from("{period_init_ms: 100}")),
        ])
    };
    let opened_after = started.elapsed();
    assert_eq!(
        rc, Z_OK,
        "a peer's open does not wait for ever for its peer"
    );
    // R2948 — it waits upstream's start window (`scouting/delay`, 500 ms) for
    // the peer, then returns without it; it does not return at once, and it
    // does not wait for the dial to give up.
    assert!(
        opened_after >= Duration::from_millis(450) && opened_after < Duration::from_secs(3),
        "the open returned after {opened_after:?}; the start window is 500 ms"
    );

    // SAFETY: the session is live.
    let (hits, ctx) = unsafe { count_samples(&session) };
    let SendSession(listen) = listen_later(port, LISTENER_LATE_BY)
        .join()
        .expect("listener thread");
    // SAFETY: the listener is live.
    let arrived = unsafe { put_until_it_arrives(&listen, &hits) };
    assert!(arrived, "the peer never connected behind its open");
    // SAFETY: both sessions are live; the subscriber's callback context is
    // freed only after its session has closed.
    unsafe {
        close_session(session);
        close_session(listen);
        drop(Box::from_raw(ctx));
    }
}

/// R2948 — a session whose link is LOST re-dials, as zenoh re-dials a closed
/// session's configured endpoints: the listener goes away, a new one binds the
/// same port, and a put from the new one reaches a subscription declared
/// before the loss (`face_up` replays it onto the re-dialled link).
#[test]
fn a_session_that_loses_its_link_redials_it() {
    let port = free_port();
    let SendSession(first) = listen_later(port, Duration::ZERO)
        .join()
        .expect("listener thread");
    // SAFETY: fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("connect/endpoints", endpoint(port)),
            (
                "connect/retry",
                String::from("{period_init_ms: 100, period_max_ms: 200}"),
            ),
        ])
    };
    assert_eq!(rc, Z_OK);
    // SAFETY: the session is live.
    let (hits, ctx) = unsafe { count_samples(&session) };
    // SAFETY: the first listener is live.
    assert!(
        unsafe { put_until_it_arrives(&first, &hits) },
        "the first link never carried a put"
    );
    // SAFETY: the first listener is live and owned here.
    unsafe { close_session(first) };
    hits.store(0, Ordering::SeqCst);
    let SendSession(second) = listen_later(port, LISTENER_LATE_BY)
        .join()
        .expect("listener thread");
    // SAFETY: the second listener is live.
    let arrived = unsafe { put_until_it_arrives(&second, &hits) };
    assert!(
        arrived,
        "the session never re-dialled after its link was lost"
    );
    // SAFETY: both sessions are live; `ctx` is freed after its session closed.
    unsafe {
        close_session(session);
        close_session(second);
        drop(Box::from_raw(ctx));
    }
}

/// Declare a subscriber on [`KEYEXPR`] that counts its samples. The returned
/// context must outlive `session` and be freed by the caller after it closes.
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

/// Put from `publisher` every 50 ms until a sample is counted, for up to 10 s.
unsafe fn put_until_it_arrives(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        put_once(publisher);
        std::thread::sleep(Duration::from_millis(50));
    }
    hits.load(Ordering::SeqCst) > 0
}
