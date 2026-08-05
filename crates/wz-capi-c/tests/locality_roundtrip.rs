// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y554 — `allowed_destination` / `allowed_origin` on the zenoh-c ABI,
//! driven through the exported `z_*` symbols exactly as a C program would.
//!
//! ## Why an END-TO-END leg and not only the option-resolution unit tests
//!
//! The unit tests prove the C field reaches `PublishOptions` / `QueryOptions` /
//! `SubscribeOptions`. They cannot prove the two things that actually blocked
//! this field for six rounds, because both live above that seam:
//!
//! 1. **The fan.** A zenoh-c session is one session with many peers; a wz
//!    unicast session is one peer. The C subscription is replayed onto EVERY
//!    face, so a local-capable publish handed unchanged to each face delivers
//!    one in-process `z_put` to the one C callback once PER FACE. The
//!    two-dialer leg here is the only place that shows up.
//! 2. **The thread.** `unsafe impl Sync for CClosure` rests on the C
//!    application thread never invoking the callback. These legs run `z_put`
//!    on the TEST thread while drive tasks are live, so a callback that ran
//!    inline would be running on the wrong thread — which is exactly what
//!    R311y552 measured and reverted for.
//!
//! Delivery is asserted by a bounded convergence loop, never by `z_put`'s
//! return code: a put with zero faces is `Ok(0)` and would prove nothing.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_query_t, z_loaned_reply_t, z_loaned_sample_t, z_moved_closure_query_t,
    z_moved_closure_reply_t, z_moved_queryable_t, z_moved_subscriber_t, z_owned_bytes_t,
    z_owned_closure_query_t, z_owned_closure_reply_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_queryable_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::abi::{
    z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t, z_moved_session_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::get::{z_closure_reply, z_get};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::{ZC_LOCALITY_ANY, ZC_LOCALITY_REMOTE};
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::query::{
    z_closure_query, z_declare_queryable, z_query_reply, z_undeclare_queryable,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{
    z_closure_sample, z_declare_subscriber, z_subscriber_options_t, z_undeclare_subscriber,
};

const KEYEXPR: &str = "wz/locality/demo";

/// Counts callback invocations. The COUNT is the point: a fan that delivered
/// per face would be indistinguishable from a correct one under a boolean flag.
struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample_count(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const CountCtx);
    ctx.hits.fetch_add(1, Ordering::SeqCst);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

unsafe fn open_role(port: u16, key: &str) -> z_owned_session_t {
    let key = CString::new(key).unwrap();
    let value = CString::new(format!("[\"tcp/127.0.0.1:{port}\"]")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null()
        ),
        Z_OK
    );
    session
}

unsafe fn open_listen(port: u16) -> z_owned_session_t {
    open_role(port, "listen/endpoints")
}

unsafe fn open_connect(port: u16) -> z_owned_session_t {
    open_role(port, "connect/endpoints")
}

unsafe fn declare_counting_sub(
    session: &z_owned_session_t,
    ctx: *mut c_void,
    allowed_origin: Option<i32>,
) -> z_owned_subscriber_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    // `z_closure_sample` returns void on this ABI (upstream's does too).
    z_closure_sample(&mut closure, Some(on_sample_count), None, ctx);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut opts = z_subscriber_options_t {
        allowed_origin: allowed_origin.unwrap_or(ZC_LOCALITY_ANY),
    };
    let opts_ptr = match allowed_origin {
        Some(_) => &mut opts as *mut z_subscriber_options_t,
        // NULL is what `z_sub.c` passes, and the leg that uses it is asserting
        // the DEFAULT path rather than an explicitly-configured one.
        None => std::ptr::null_mut(),
    };
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            opts_ptr,
        ),
        Z_OK
    );
    sub
}

/// Publish once with an explicit `allowed_destination`, or with NULL options.
unsafe fn put_once(session: &z_owned_session_t, allowed_destination: Option<i32>) {
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let payload_str = CString::new("hello").unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_str(&mut payload, payload_str.as_ptr()),
        Z_OK
    );
    let mut opts: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut opts);
    let opts_ptr = match allowed_destination {
        Some(v) => {
            opts.allowed_destination = v;
            &mut opts as *mut z_put_options_t
        }
        None => std::ptr::null_mut(),
    };
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            opts_ptr,
        ),
        Z_OK
    );
}

/// Wait until `hits` reaches `want`, then keep watching for the settle window
/// so an OVER-delivery is caught rather than raced past. Returns the final
/// count, so the caller asserts the number instead of a boolean.
fn settle(hits: &Arc<AtomicUsize>, want: usize, settle_for: Duration) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while hits.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(settle_for);
    hits.load(Ordering::SeqCst)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// THE leg. A listener holding TWO peer faces publishes with upstream's default
/// options (`allowed_destination = ZC_LOCALITY_ANY`) and its own C subscriber
/// fires EXACTLY ONCE.
///
/// Two claims in one number:
///
/// * **once** — not zero, which is what this ABI did before R311y554 (the
///   publish was pinned `Locality::Remote` and the field was read for layout);
/// * **once** — not twice, which is what a naive honouring would do, since the
///   subscription is replayed onto both faces and each face's session would
///   deliver its own replica.
#[test]
fn a_default_put_reaches_this_sessions_own_subscriber_exactly_once_across_two_faces() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);
        let dialer_a = open_connect(port);
        let dialer_b = open_connect(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        let mut _sub = declare_counting_sub(&listener, ctx as *mut c_void, None);

        // Let both faces come up so the fan really is two-wide; the assertion
        // below is about the count, so a one-face race would silently weaken it.
        std::thread::sleep(Duration::from_millis(300));

        put_once(&listener, None);
        let count = settle(&hits, 1, Duration::from_millis(300));
        assert_eq!(
            count, 1,
            "an Any put must reach this session's own subscriber EXACTLY once: \
             0 means the field is still dropped, >1 means the fan delivers per \
             face instead of per session"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer_a);
        close_session(dialer_b);
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// The discriminator: the same program, one field changed, and the delivery
/// stops. Without this leg the test above would also pass on a build that
/// ignored `allowed_destination` and always delivered locally.
#[test]
fn a_remote_only_put_does_not_reach_this_sessions_own_subscriber() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);
        let dialer = open_connect(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        let mut _sub = declare_counting_sub(&listener, ctx as *mut c_void, None);
        std::thread::sleep(Duration::from_millis(300));

        put_once(&listener, Some(ZC_LOCALITY_REMOTE));
        // No `want` to converge on — this asserts an ABSENCE, so it waits the
        // whole settle window. The calibration that keeps it from being vacuous
        // is the leg above: same harness, same timings, and it observes 1.
        let count = settle(&hits, 1, Duration::from_millis(500));
        assert_eq!(
            count, 0,
            "ZC_LOCALITY_REMOTE must suppress the in-process delivery"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// The RECEIVE-side half of the same axis: `z_subscriber_options_t`'s one field.
///
/// A subscriber declared `ZC_LOCALITY_REMOTE` does not fire on its own
/// session's put, even though the put itself is local-capable. The two fields
/// are independent predicates and this is the one that proves it.
#[test]
fn a_remote_origin_subscriber_ignores_its_own_sessions_put() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);
        let dialer = open_connect(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        let mut _sub =
            declare_counting_sub(&listener, ctx as *mut c_void, Some(ZC_LOCALITY_REMOTE));
        std::thread::sleep(Duration::from_millis(300));

        put_once(&listener, Some(ZC_LOCALITY_ANY));
        let count = settle(&hits, 1, Duration::from_millis(500));
        assert_eq!(
            count, 0,
            "an allowed_origin=REMOTE subscriber must not fire on a loopback \
             sample, whatever the publisher asked for"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

// --- the QUERYABLE half of the same axis ------------------------------------

/// The queryable handler: answer once with a fixed payload.
unsafe extern "C" fn on_query_reply_once(query: *mut z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const CountCtx);
    ctx.hits.fetch_add(1, Ordering::SeqCst);
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

unsafe extern "C" fn on_reply_count(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const CountCtx);
    ctx.hits.fetch_add(1, Ordering::SeqCst);
}

/// R311y554 — the queryable mirror of the publish leg, and it exercises a
/// DIFFERENT split: `issue_get` fans one wz query per face, so an `Any` get
/// handed unchanged to each face would run the one C query handler once per
/// face and answer a single `z_get` twice.
///
/// It also covers the seam no locality pin could have protected: before this
/// round `z_get`'s locality was already `Any` by default on both sides, so
/// `Session::query` ran its in-process leg — and its UNGATED
/// `drain_deferred_fires` — on the C thread, whatever the queryables' own
/// `allowed_origin` said. The count here is the visible half; the thread is the
/// half `LocalDeliveryDrain::DriveTask` fixes.
#[test]
fn an_in_process_get_reaches_this_sessions_own_queryable_exactly_once_across_two_faces() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);
        let dialer_a = open_connect(port);
        let dialer_b = open_connect(port);

        let handled = Arc::new(AtomicUsize::new(0));
        let qctx = Box::into_raw(Box::new(CountCtx {
            hits: handled.clone(),
        }));
        let mut qclosure: z_owned_closure_query_t = std::mem::zeroed();
        z_closure_query(
            &mut qclosure,
            Some(on_query_reply_once),
            None,
            qctx as *mut c_void,
        );
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut qbl: z_owned_queryable_t = std::mem::zeroed();
        // NULL options: upstream's defaults, which is `allowed_origin =
        // ZC_LOCALITY_ANY` — the value that decides whether the stock example
        // can answer its own session's get.
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&listener),
                &mut qbl,
                z_view_keyexpr_loan(&view),
                (&mut qclosure as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(300));

        let replies = Arc::new(AtomicUsize::new(0));
        let rctx = Box::into_raw(Box::new(CountCtx {
            hits: replies.clone(),
        }));
        let mut rclosure: z_owned_closure_reply_t = std::mem::zeroed();
        z_closure_reply(
            &mut rclosure,
            Some(on_reply_count),
            None,
            rctx as *mut c_void,
        );
        assert_eq!(
            z_get(
                z_session_loan(&listener),
                z_view_keyexpr_loan(&view),
                std::ptr::null(),
                (&mut rclosure as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let handled_count = settle(&handled, 1, Duration::from_millis(500));
        assert_eq!(
            handled_count, 1,
            "an in-process get must reach this session's own queryable EXACTLY \
             once: 0 means allowed_origin is still pinned Remote, >1 means the \
             get fan runs the local leg per face"
        );
        assert_eq!(
            replies.load(Ordering::SeqCst),
            1,
            "and the querier sees exactly one reply for it"
        );

        z_undeclare_queryable((&mut qbl as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>());
        close_session(dialer_a);
        close_session(dialer_b);
        close_session(listener);
        drop(Box::from_raw(qctx));
        drop(Box::from_raw(rctx));
    }
}
