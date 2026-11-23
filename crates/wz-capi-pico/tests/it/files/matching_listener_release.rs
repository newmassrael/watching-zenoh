// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publisher's matching listener on the cooperative engine, through the exported `z_*` symbols,
//! between two peers on the loopback: the listening one publishes, the dialling one subscribes.
//!
//! - A listener declared once the publisher already matches is told so once, as it is declared.
//! - An undeclare of the listener, and the drop of the publisher that holds a background one,
//!   return only once the listener's callback running on the read task has returned and its
//!   closure's `drop(context)` has run, as zenoh-pico's do: a program frees what the callback
//!   reads the moment either returns.
//!
//! ```text
//! cargo test -p wz-capi-pico --no-default-features \
//!     --features engine-coop,peer,multi-thread --test it files::matching_listener_release::
//! ```
#![cfg(all(feature = "engine-coop", feature = "peer", feature = "multi-thread"))]

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::matching::{
    z_closure_matching_status, z_closure_matching_status_move, z_matching_listener_move,
    z_matching_status_t, z_owned_closure_matching_status_t, z_owned_matching_listener_t,
    z_publisher_declare_background_matching_listener, z_publisher_declare_matching_listener,
    z_publisher_get_matching_status, z_undeclare_matching_listener,
};
use wz_capi_pico::{
    z_close, z_closure_sample, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_publisher, z_declare_subscriber, z_loaned_sample_t, z_open,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_owned_subscriber_t,
    z_publisher_drop, z_publisher_loan, z_publisher_move, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_subscriber_move, z_undeclare_subscriber,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// How long a wait for something the peers do may take before the test fails by name.
const DEADLINE: Duration = Duration::from_secs(10);

/// How long the listener's callback holds the read task, long past the undeclare the test makes
/// while it runs.
const HOLD: Duration = Duration::from_millis(1500);

/// The key the publisher publishes on and the key the subscriber that matches it subscribes to.
const PUBLISHED: &CStr = c"release/matching/val";
const SUBSCRIBED: &CStr = c"release/matching/**";

/// What the listener's closure saw, read by the test while the callback may be running.
#[derive(Default)]
struct Probe {
    /// The callback began with a match.
    entered: AtomicBool,
    /// The callback returned.
    called: AtomicBool,
    /// The closure's `drop(context)` ran.
    dropped: AtomicBool,
}

unsafe extern "C" fn on_status_held(status: *const z_matching_status_t, ctx: *mut c_void) {
    let probe = &*(ctx as *const Probe);
    if (*status).matching {
        probe.entered.store(true, Ordering::SeqCst);
        std::thread::sleep(HOLD);
        probe.called.store(true, Ordering::SeqCst);
    }
}

unsafe extern "C" fn on_drop_late(ctx: *mut c_void) {
    let probe = &*(ctx as *const Probe);
    std::thread::sleep(Duration::from_millis(200));
    probe.dropped.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_status_logged(status: *const z_matching_status_t, ctx: *mut c_void) {
    let seen = &*(ctx as *const Mutex<Vec<bool>>);
    seen.lock().unwrap().push((*status).matching);
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, _ctx: *mut c_void) {}

unsafe fn open(key: u8, endpoint: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_MODE_KEY,
            c"peer".as_ptr()
        ),
        Z_OK
    );
    let endpoint = CString::new(endpoint).unwrap();
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "the session opens on {endpoint:?}"
    );
    session
}

/// A listening peer and a peer that dials it.
unsafe fn pair() -> (z_owned_session_t, z_owned_session_t) {
    let endpoint = format!("tcp/127.0.0.1:{}", free_port());
    let listener = open(Z_CONFIG_LISTEN_KEY, &endpoint);
    let dialler = open(Z_CONFIG_CONNECT_KEY, &endpoint);
    (listener, dialler)
}

unsafe fn publisher(session: &z_owned_session_t) -> z_owned_publisher_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, PUBLISHED.as_ptr()), Z_OK);
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    assert_eq!(
        z_declare_publisher(
            z_session_loan(session),
            &mut publisher,
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
        ),
        Z_OK
    );
    publisher
}

unsafe fn subscriber(session: &z_owned_session_t) -> z_owned_subscriber_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut()),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, SUBSCRIBED.as_ptr()), Z_OK);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    subscriber
}

/// A matching closure calling `call` with `ctx`, and `drop` with it once released.
unsafe fn closure(
    call: unsafe extern "C" fn(*const z_matching_status_t, *mut c_void),
    drop: Option<unsafe extern "C" fn(*mut c_void)>,
    ctx: *mut c_void,
) -> z_owned_closure_matching_status_t {
    let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
    assert_eq!(
        z_closure_matching_status(&mut closure, Some(call), drop, ctx),
        Z_OK
    );
    closure
}

unsafe fn matching_now(publisher: &z_owned_publisher_t) -> bool {
    let mut status = z_matching_status_t { matching: false };
    assert_eq!(
        z_publisher_get_matching_status(z_publisher_loan(publisher), &mut status),
        Z_OK
    );
    status.matching
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + DEADLINE;
    while !done() {
        assert!(Instant::now() < deadline, "{what} within {DEADLINE:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// A listener declared on a publisher that already matches is told `true`, once: the match is
/// reported as the listener registers, and nothing after it says the same again.
#[test]
fn a_listener_declared_on_a_match_is_told_once() {
    let seen: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    // SAFETY: every handle is made here and let go of once; `seen` outlives the listener, whose
    // closure has no drop of its own to run.
    unsafe {
        let (mut listener, mut dialler) = pair();
        let mut publisher = publisher(&listener);
        let mut subscriber = subscriber(&dialler);
        wait_for("the publisher to match the peer's subscriber", || {
            matching_now(&publisher)
        });

        let mut closure = closure(on_status_logged, None, Arc::as_ptr(&seen) as *mut c_void);
        let mut handle: z_owned_matching_listener_t = std::mem::zeroed();
        assert_eq!(
            z_publisher_declare_matching_listener(
                z_publisher_loan(&publisher),
                &mut handle,
                z_closure_matching_status_move(&mut closure),
            ),
            Z_OK
        );
        wait_for("the listener to be told it matches", || {
            !seen.lock().unwrap().is_empty()
        });
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(*seen.lock().unwrap(), [true], "told once, and true");

        z_undeclare_matching_listener(z_matching_listener_move(&mut handle));
        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_publisher_drop(z_publisher_move(&mut publisher));
        close(&mut dialler);
        close(&mut listener);
    }
}

/// The undeclare of a listener whose callback runs on the read task returns once the callback
/// has returned and the closure's drop has run, not while the callback still reads its context.
#[test]
fn undeclaring_a_listener_waits_for_its_running_callback_and_its_drop() {
    let probe = Arc::new(Probe::default());
    // SAFETY: every handle is made here and let go of once; `probe` outlives the closure, whose
    // drop the undeclare waits for.
    unsafe {
        let (mut listener, mut dialler) = pair();
        let mut publisher = publisher(&listener);
        let mut closure = closure(
            on_status_held,
            Some(on_drop_late),
            Arc::as_ptr(&probe) as *mut c_void,
        );
        let mut handle: z_owned_matching_listener_t = std::mem::zeroed();
        assert_eq!(
            z_publisher_declare_matching_listener(
                z_publisher_loan(&publisher),
                &mut handle,
                z_closure_matching_status_move(&mut closure),
            ),
            Z_OK
        );
        let mut subscriber = subscriber(&dialler);
        wait_for("the listener's callback to begin", || {
            probe.entered.load(Ordering::SeqCst)
        });
        assert!(
            !probe.called.load(Ordering::SeqCst),
            "CONTROL: the callback still runs as the undeclare begins"
        );

        z_undeclare_matching_listener(z_matching_listener_move(&mut handle));
        assert!(
            probe.called.load(Ordering::SeqCst),
            "the undeclare returned while the callback still ran"
        );
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "the undeclare returned before the closure's drop ran"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_publisher_drop(z_publisher_move(&mut publisher));
        close(&mut dialler);
        close(&mut listener);
    }
}

/// A background listener goes with its publisher: the publisher's drop returns once the
/// listener's running callback has returned and its closure's drop has run.
#[test]
fn dropping_a_publisher_waits_for_its_background_listeners_callback_and_its_drop() {
    let probe = Arc::new(Probe::default());
    // SAFETY: as above; the publisher's drop is what waits for the closure's drop.
    unsafe {
        let (mut listener, mut dialler) = pair();
        let mut publisher = publisher(&listener);
        let mut closure = closure(
            on_status_held,
            Some(on_drop_late),
            Arc::as_ptr(&probe) as *mut c_void,
        );
        assert_eq!(
            z_publisher_declare_background_matching_listener(
                z_publisher_loan(&publisher),
                z_closure_matching_status_move(&mut closure),
            ),
            Z_OK
        );
        let mut subscriber = subscriber(&dialler);
        wait_for("the listener's callback to begin", || {
            probe.entered.load(Ordering::SeqCst)
        });
        assert!(
            !probe.called.load(Ordering::SeqCst),
            "CONTROL: the callback still runs as the drop begins"
        );

        z_publisher_drop(z_publisher_move(&mut publisher));
        assert!(
            probe.called.load(Ordering::SeqCst),
            "the publisher's drop returned while its listener's callback still ran"
        );
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "the publisher's drop returned before the listener's drop ran"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        close(&mut dialler);
        close(&mut listener);
    }
}
