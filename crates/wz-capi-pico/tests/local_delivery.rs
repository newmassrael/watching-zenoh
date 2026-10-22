// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! pico's session-local delivery (`Z_FEATURE_LOCAL_SUBSCRIBER`, `Z_FEATURE_LOCAL_QUERYABLE`)
//! on the drop-in, with no peer at all.
//!
//! With the switches on, a session's own put reaches its own subscriber, and its own get its
//! own queryable, INSIDE the call and on the calling thread: pico's
//! `_z_session_deliver_push_locally` hands the message to `_z_handle_network_message` before
//! `z_put` returns (`vendor/zenoh-pico/src/session/loopback.c`). The localities filter both
//! ways (a subscriber's `allowed_origin`, a put's `allowed_destination`), and a publisher's
//! write filter, matching status and matching listener count the session's own subscriber
//! when its destination admits it (`vendor/zenoh-pico/src/net/filtering.c` @
//! `_z_write_filter_notify_subscriber`).
//!
//! Before this file the drop-in had neither the option fields nor the delivery: every entity
//! was `Locality::Remote` (open-debt item 914).

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::ThreadId;

use wz_capi_pico::get::{
    z_closure_reply, z_closure_reply_move, z_get, z_loaned_reply_t, z_owned_closure_reply_t,
};
use wz_capi_pico::locality::{Z_LOCALITY_ANY, Z_LOCALITY_REMOTE, Z_LOCALITY_SESSION_LOCAL};
use wz_capi_pico::matching::{
    z_closure_matching_status, z_closure_matching_status_move, z_matching_status_t,
    z_owned_closure_matching_status_t, z_publisher_declare_background_matching_listener,
    z_publisher_get_matching_status,
};
use wz_capi_pico::query::{
    z_closure_query, z_closure_query_move, z_declare_queryable, z_loaned_query_t,
    z_owned_closure_query_t, z_owned_queryable_t, z_query_keyexpr, z_query_reply, z_queryable_drop,
    z_queryable_move,
};
use wz_capi_pico::session::z_subscriber_options_t;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_closure_sample, z_closure_sample_move, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_publisher, z_declare_subscriber, z_loaned_sample_t,
    z_open, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t, z_owned_publisher_t,
    z_owned_session_t, z_owned_subscriber_t, z_publisher_drop, z_publisher_loan, z_publisher_move,
    z_publisher_options_default, z_publisher_options_t, z_put, z_put_options_default,
    z_put_options_t, z_session_drop, z_session_loan, z_session_move, z_subscriber_drop,
    z_subscriber_move, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    zp_config_insert, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// A session that listens and has no peer: what it delivers, it delivers to itself.
unsafe fn open_alone() -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            endpoint.as_ptr()
        ),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn key(text: &std::ffi::CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
    ke
}

unsafe fn payload(text: &std::ffi::CStr) -> z_owned_bytes_t {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut bytes, text.as_ptr()), Z_OK);
    bytes
}

/// What a callback saw: how many calls, and the thread of each.
#[derive(Default)]
struct Seen {
    calls: AtomicUsize,
    threads: Mutex<Vec<ThreadId>>,
}

impl Seen {
    fn record(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const Seen)).record();
}

/// A subscriber on `keyexpr` whose callbacks `seen` records, with `origin` when given.
unsafe fn subscribe(
    session: &z_owned_session_t,
    keyexpr: &std::ffi::CStr,
    seen: &'static Seen,
    origin: Option<i32>,
) -> z_owned_subscriber_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut closure,
            Some(on_sample),
            None,
            seen as *const Seen as *mut c_void
        ),
        Z_OK
    );
    let options = origin.map(|allowed_origin| z_subscriber_options_t { allowed_origin });
    let ke = key(keyexpr);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            options
                .as_ref()
                .map_or(std::ptr::null(), |options| options as *const _),
        ),
        Z_OK
    );
    subscriber
}

/// `z_put` on `keyexpr`, with `destination` when given.
unsafe fn put(session: &z_owned_session_t, keyexpr: &std::ffi::CStr, destination: Option<i32>) {
    let ke = key(keyexpr);
    let mut bytes = payload(c"local");
    let mut options: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut options);
    if let Some(destination) = destination {
        options.allowed_destination = destination;
    }
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut bytes),
            &options
        ),
        Z_OK
    );
}

#[test]
fn a_sessions_own_put_reaches_its_own_subscriber_inside_the_call() {
    unsafe {
        let mut session = open_alone();
        let seen: &'static Seen = Box::leak(Box::default());
        let mut subscriber = subscribe(&session, c"demo/local/a", seen, None);

        put(&session, c"demo/local/a", None);
        assert_eq!(
            seen.calls(),
            1,
            "the put returned before its own subscriber ran, or ran it twice"
        );
        assert_eq!(
            seen.threads.lock().unwrap().as_slice(),
            &[std::thread::current().id()],
            "the subscriber ran on another thread than the put's"
        );

        z_subscriber_drop(z_subscriber_move(&mut subscriber));
        z_session_drop(z_session_move(&mut session));
    }
}

#[test]
fn the_localities_filter_both_ways() {
    unsafe {
        let mut session = open_alone();
        let local_only: &'static Seen = Box::leak(Box::default());
        let remote_only: &'static Seen = Box::leak(Box::default());
        let mut a = subscribe(
            &session,
            c"demo/local/b",
            local_only,
            Some(Z_LOCALITY_SESSION_LOCAL),
        );
        let mut b = subscribe(
            &session,
            c"demo/local/b",
            remote_only,
            Some(Z_LOCALITY_REMOTE),
        );

        put(&session, c"demo/local/b", Some(Z_LOCALITY_ANY));
        assert_eq!(
            local_only.calls(),
            1,
            "a session-local subscriber takes its own put"
        );
        assert_eq!(remote_only.calls(), 0, "a remote-only subscriber does not");

        put(&session, c"demo/local/b", Some(Z_LOCALITY_REMOTE));
        assert_eq!(
            local_only.calls(),
            1,
            "a put whose destination is remote only reaches no subscriber of its own session"
        );

        z_subscriber_drop(z_subscriber_move(&mut a));
        z_subscriber_drop(z_subscriber_move(&mut b));
        z_session_drop(z_session_move(&mut session));
    }
}

static MATCHING: Mutex<Vec<bool>> = Mutex::new(Vec::new());

unsafe extern "C" fn on_matching(status: *const z_matching_status_t, _ctx: *mut c_void) {
    MATCHING.lock().unwrap().push((*status).matching);
}

unsafe fn declare_publisher(
    session: &z_owned_session_t,
    keyexpr: &std::ffi::CStr,
    destination: i32,
) -> z_owned_publisher_t {
    let ke = key(keyexpr);
    let mut options: z_publisher_options_t = std::mem::zeroed();
    z_publisher_options_default(&mut options);
    options.allowed_destination = destination;
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    assert_eq!(
        z_declare_publisher(
            z_session_loan(session),
            &mut publisher,
            z_view_keyexpr_loan(&ke),
            &options
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

#[test]
fn a_publishers_matching_counts_the_sessions_own_subscriber_where_its_destination_does() {
    unsafe {
        let mut session = open_alone();
        let mut counting = declare_publisher(&session, c"demo/local/m", Z_LOCALITY_ANY);
        let mut remote = declare_publisher(&session, c"demo/local/m", Z_LOCALITY_REMOTE);
        let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
        assert_eq!(
            z_closure_matching_status(&mut closure, Some(on_matching), None, std::ptr::null_mut()),
            Z_OK
        );
        assert_eq!(
            z_publisher_declare_background_matching_listener(
                z_publisher_loan(&counting),
                z_closure_matching_status_move(&mut closure)
            ),
            Z_OK
        );
        assert!(!matching(&counting), "nothing subscribes yet");

        let seen: &'static Seen = Box::leak(Box::default());
        let mut subscriber = subscribe(&session, c"demo/local/**", seen, None);
        assert!(
            matching(&counting),
            "the session's own subscriber is a match"
        );
        assert!(
            !matching(&remote),
            "and not for a publisher whose destination is remote only"
        );
        assert_eq!(
            *MATCHING.lock().unwrap(),
            vec![true],
            "the listener hears the declaration inside it"
        );

        z_subscriber_drop(z_subscriber_move(&mut subscriber));
        assert!(!matching(&counting));
        assert_eq!(*MATCHING.lock().unwrap(), vec![true, false]);

        z_publisher_drop(z_publisher_move(&mut counting));
        z_publisher_drop(z_publisher_move(&mut remote));
        z_session_drop(z_session_move(&mut session));
    }
}

unsafe extern "C" fn answer(query: *const z_loaned_query_t, ctx: *mut c_void) {
    (*(ctx as *const Seen)).record();
    let mut bytes = payload(c"answer");
    let _ = z_query_reply(
        query,
        z_query_keyexpr(query),
        z_bytes_move(&mut bytes),
        std::ptr::null(),
    );
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    (*(ctx as *const Seen)).record();
}

#[test]
fn a_sessions_own_get_reaches_its_own_queryable_inside_the_call() {
    unsafe {
        let mut session = open_alone();
        let asked: &'static Seen = Box::leak(Box::default());
        let mut closure: z_owned_closure_query_t = std::mem::zeroed();
        assert_eq!(
            z_closure_query(
                &mut closure,
                Some(answer),
                None,
                asked as *const Seen as *mut c_void
            ),
            Z_OK
        );
        let ke = key(c"demo/local/q");
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&session),
                &mut queryable,
                z_view_keyexpr_loan(&ke),
                z_closure_query_move(&mut closure),
                std::ptr::null()
            ),
            Z_OK
        );

        let replied: &'static Seen = Box::leak(Box::default());
        let mut reply: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut reply,
                Some(on_reply),
                None,
                replied as *const Seen as *mut c_void
            ),
            Z_OK
        );
        assert_eq!(
            z_get(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                c"".as_ptr(),
                z_closure_reply_move(&mut reply),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        let me = std::thread::current().id();
        assert_eq!(
            asked.calls(),
            1,
            "the get returned before its own queryable ran"
        );
        assert_eq!(asked.threads.lock().unwrap().as_slice(), &[me]);
        assert_eq!(
            replied.calls(),
            1,
            "the get returned before its own reply arrived"
        );
        assert_eq!(replied.threads.lock().unwrap().as_slice(), &[me]);

        z_queryable_drop(z_queryable_move(&mut queryable));
        z_session_drop(z_session_move(&mut session));
    }
}
