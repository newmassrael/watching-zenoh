// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publisher that leaves a put unwritten to a peer which wants nothing the key reaches must
//! write it again the moment that peer wants it.
//!
//! Between two peers a put is written to a link only when the peer has declared a subscriber the
//! key reaches (the peer pushes its declarations and ends them, so what is absent is not wanted).
//! The danger of that is not the saving but the case it must never lose: a subscriber that is
//! declared AFTER the publisher has been putting for a while. The legs below drive real sessions
//! over TCP and put continuously while the subscription appears, on both sending paths, and
//! require the first sample to arrive.
//!
//!   * the control: a subscriber that was there from the start receives (so a later silence is not
//!     a harness that delivers nothing);
//!   * a subscriber declared late starts to receive;
//!   * a subscriber that has undeclared stops receiving what is put afterwards, which is the saving
//!     working and not a loss.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_publisher_t, z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t,
    z_owned_closure_sample_t, z_owned_config_t, z_owned_publisher_t, z_owned_session_t,
    z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_buf;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::{
    z_declare_publisher, z_publisher_loan, z_publisher_put, z_undeclare_publisher,
};
use wz_capi_c::put::z_put;
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_runtime_tokio_test_support::free_port;

const KEY: &str = "mesh/data";

#[derive(Clone, Copy, Debug)]
enum Via {
    SessionPut,
    Publisher,
}

const BOTH_PATHS: [Via; 2] = [Via::SessionPut, Via::Publisher];

unsafe fn open_with(entries: &[(&str, String)]) -> z_owned_session_t {
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
    assert_eq!(rc, Z_OK, "the session opens");
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

/// A subscriber on `key`; the context is freed by the caller after the session closes.
struct Subscription {
    sub: z_owned_subscriber_t,
    hits: Arc<AtomicUsize>,
    ctx: *mut CountCtx,
}

unsafe fn subscribe(session: &z_owned_session_t, key: &str) -> Subscription {
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
    Subscription { sub, hits, ctx }
}

unsafe fn unsubscribe(mut subscription: Subscription) -> *mut CountCtx {
    let _ = z_undeclare_subscriber(
        (&mut subscription.sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
    );
    subscription.ctx
}

struct Putter<'a> {
    session: &'a z_owned_session_t,
    publisher: Option<z_owned_publisher_t>,
}

impl<'a> Putter<'a> {
    unsafe fn new(session: &'a z_owned_session_t, via: Via) -> Self {
        let publisher = match via {
            Via::SessionPut => None,
            Via::Publisher => {
                let ke = CString::new(KEY).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                let mut publisher: z_owned_publisher_t = std::mem::zeroed();
                assert_eq!(
                    z_declare_publisher(
                        z_session_loan(session),
                        &mut publisher,
                        z_view_keyexpr_loan(&view),
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
                Some(publisher)
            }
        };
        Self { session, publisher }
    }

    unsafe fn put(&self) {
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_buf(&mut payload, b"x".as_ptr(), 1), Z_OK);
        let moved = (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>();
        match &self.publisher {
            Some(publisher) => assert_eq!(
                z_publisher_put(z_publisher_loan(publisher), moved, std::ptr::null_mut()),
                Z_OK
            ),
            None => {
                let ke = CString::new(KEY).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                assert_eq!(
                    z_put(
                        z_session_loan(self.session),
                        z_view_keyexpr_loan(&view),
                        moved,
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
            }
        }
    }
}

impl Drop for Putter<'_> {
    fn drop(&mut self) {
        if let Some(mut publisher) = self.publisher.take() {
            // SAFETY: a live publisher this value declared.
            unsafe {
                let _ = z_undeclare_publisher(
                    (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
                );
            }
        }
    }
}

fn peer_entries(port: u16, listen: bool) -> Vec<(&'static str, String)> {
    let endpoint = format!("[\"tcp/127.0.0.1:{port}\"]");
    vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("scouting/gossip/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        (
            if listen {
                "listen/endpoints"
            } else {
                "connect/endpoints"
            },
            endpoint,
        ),
    ]
}

/// Put on the key every 10 ms until `hits` moves past `from` or `within` is over; whether it did.
unsafe fn put_until_received(
    putter: &Putter<'_>,
    hits: &AtomicUsize,
    from: usize,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        putter.put();
        std::thread::sleep(Duration::from_millis(10));
        if hits.load(Ordering::SeqCst) > from {
            return true;
        }
    }
    false
}

#[test]
fn control_a_subscriber_that_was_there_from_the_start_receives() {
    for via in BOTH_PATHS {
        let port = free_port();
        // SAFETY: fresh sessions, closed at the end of the leg.
        unsafe {
            let publisher = open_with(&peer_entries(port, true));
            let subscriber = open_with(&peer_entries(port, false));
            let subscription = subscribe(&subscriber, "mesh/**");
            let putter = Putter::new(&publisher, via);
            assert!(
                put_until_received(&putter, &subscription.hits, 0, Duration::from_secs(10)),
                "{via:?}: nothing ever arrived, so the legs below prove nothing"
            );
            drop(putter);
            let ctx = unsubscribe(subscription);
            close_session(subscriber);
            close_session(publisher);
            drop(Box::from_raw(ctx));
        }
    }
}

#[test]
fn a_subscriber_declared_after_the_publisher_has_been_putting_starts_to_receive() {
    for via in BOTH_PATHS {
        let port = free_port();
        // SAFETY: fresh sessions, closed at the end of the leg.
        unsafe {
            let publisher = open_with(&peer_entries(port, true));
            let subscriber = open_with(&peer_entries(port, false));
            // The peer wants something else, so a put on KEY is one it has said it does not want
            // once it has ended its declarations.
            let other = subscribe(&subscriber, "unrelated/**");
            let putter = Putter::new(&publisher, via);
            for _ in 0..100 {
                putter.put();
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(other.hits.load(Ordering::SeqCst), 0, "{via:?}: not its key");

            let wanted = subscribe(&subscriber, "mesh/**");
            assert!(
                put_until_received(&putter, &wanted.hits, 0, Duration::from_secs(10)),
                "{via:?}: a subscription declared late never received: the publisher went on \
                 leaving the put unwritten"
            );
            drop(putter);
            let ctx_wanted = unsubscribe(wanted);
            let ctx_other = unsubscribe(other);
            close_session(subscriber);
            close_session(publisher);
            drop(Box::from_raw(ctx_wanted));
            drop(Box::from_raw(ctx_other));
        }
    }
}

#[test]
fn a_subscriber_that_undeclared_receives_nothing_that_is_put_afterwards() {
    for via in BOTH_PATHS {
        let port = free_port();
        // SAFETY: fresh sessions, closed at the end of the leg.
        unsafe {
            let publisher = open_with(&peer_entries(port, true));
            let subscriber = open_with(&peer_entries(port, false));
            let keep = subscribe(&subscriber, "unrelated/**");
            let subscription = subscribe(&subscriber, "mesh/**");
            let putter = Putter::new(&publisher, via);
            assert!(
                put_until_received(&putter, &subscription.hits, 0, Duration::from_secs(10)),
                "{via:?}: the control subscriber never received"
            );
            let hits = subscription.hits.clone();
            let ctx_sub = unsubscribe(subscription);
            // The undeclaration reaches the publisher and the put stops being written; a sample
            // already on the wire may still land, so let it, then count again.
            std::thread::sleep(Duration::from_millis(500));
            let settled = hits.load(Ordering::SeqCst);
            for _ in 0..100 {
                putter.put();
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(
                hits.load(Ordering::SeqCst),
                settled,
                "{via:?}: a put reached a subscriber that had undeclared"
            );
            drop(putter);
            let ctx_keep = unsubscribe(keep);
            close_session(subscriber);
            close_session(publisher);
            drop(Box::from_raw(ctx_sub));
            drop(Box::from_raw(ctx_keep));
        }
    }
}
