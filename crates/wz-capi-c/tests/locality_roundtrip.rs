// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    Z_SAMPLE_KIND_DELETE,
};
use wz_capi_c::abi::{
    z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t, z_moved_session_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::get::{z_closure_reply, z_get, z_get_options_default, z_get_options_t};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::{ZC_LOCALITY_ANY, ZC_LOCALITY_REMOTE, ZC_LOCALITY_SESSION_LOCAL};
use wz_capi_c::put::{
    z_delete, z_delete_options_default, z_delete_options_t, z_put, z_put_options_default,
    z_put_options_t,
};
use wz_capi_c::query::{
    z_closure_query, z_declare_queryable, z_query_reply, z_undeclare_queryable,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::z_sample_kind;
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

use wz_runtime_tokio_test_support::free_port;

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

/// Counts only samples whose kind is DELETE, so an arrival that came back as a
/// Put with an empty payload advances nothing.
unsafe extern "C" fn on_sample_count_del(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    if z_sample_kind(sample) != Z_SAMPLE_KIND_DELETE {
        return;
    }
    let ctx = &*(ctx as *const CountCtx);
    ctx.hits.fetch_add(1, Ordering::SeqCst);
}

/// [`declare_counting_sub`] with the DEL-only counter and upstream's default
/// options.
unsafe fn declare_del_counting_sub(
    session: &z_owned_session_t,
    ctx: *mut c_void,
) -> z_owned_subscriber_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample_count_del), None, ctx);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
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

/// A queryable on [`KEYEXPR`] that counts its invocations and answers once,
/// with upstream's default options (`allowed_origin = ZC_LOCALITY_ANY`).
unsafe fn declare_replying_queryable(
    session: &z_owned_session_t,
    ctx: *mut c_void,
) -> z_owned_queryable_t {
    let mut closure: z_owned_closure_query_t = std::mem::zeroed();
    z_closure_query(&mut closure, Some(on_query_reply_once), None, ctx);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let mut qbl: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut qbl,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    qbl
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

        let issued = Instant::now();
        put_once(&listener, None);
        let count = settle(&hits, 1, Duration::from_millis(300));
        let latency = issued.elapsed();
        assert_eq!(
            count, 1,
            "an Any put must reach this session's own subscriber EXACTLY once: \
             0 means the field is still dropped, >1 means the fan delivers per \
             face instead of per session"
        );
        // R311y555 — AND IT MUST BE PROMPT, which is a separate claim the
        // count cannot make. Staging a fire does not make the drive loop
        // iterate; something has to wake it. Before the wake landed this leg
        // still passed, because `settle` waits up to 5 s and the delivery rode
        // the ~3333 ms keepalive tick instead — a green test that could not
        // discriminate a working hand-off from a broken one. Measured at
        // ~3.334 s then; the bound is deliberately far below one tick so a
        // regression cannot hide inside the tolerance.
        assert!(
            latency < Duration::from_millis(1500),
            "in-process delivery took {latency:?}; anything near the ~3333 ms \
             keepalive tick means the face was never woken and the fire simply \
             waited for the next scheduled iteration"
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

// --- R311y557: the FACE-INDEPENDENT local plane ------------------------------

/// THE closing leg for R311y554's named divergence, driven through the exported
/// symbols on a session that has NO peer at all.
///
/// A `z_open(listen=..)` is unblocked by the BIND, so this is not a contrived
/// configuration — it is the ordinary window every listener passes through, and
/// a client's first `z_put` can lose the same race against its own dial. zenoh-c
/// delivers here because its subscriber table is session-scope; before this
/// round wz delivered NOTHING, because the subscriber registries lived on the
/// per-face sessions and there was no face.
///
/// The latency bound is the R311y555 discipline, and it carries more here than
/// on the two-face leg: with no face there is no inbound traffic and no
/// keepalive to ride, so a plane whose drain is never woken does not deliver
/// late — it does not deliver at all, and only a bound distinguishes "the wake
/// is wired" from "the settle window was generous".
#[test]
fn a_put_on_a_session_with_no_peer_still_reaches_its_own_subscriber() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        let mut _sub = declare_counting_sub(&listener, ctx as *mut c_void, None);

        let issued = Instant::now();
        put_once(&listener, None);
        let count = settle(&hits, 1, Duration::from_millis(300));
        let latency = issued.elapsed();
        assert_eq!(
            count, 1,
            "a session with zero faces must still deliver its own put to its own \
             subscriber: 0 is the pre-R311y557 divergence from zenoh-c, >1 would \
             mean the plane and some face both took the local leg"
        );
        assert!(
            latency < Duration::from_millis(1500),
            "in-process delivery took {latency:?}; with no peer there is no \
             keepalive tick to ride, so a slow delivery means the plane's drain \
             was woken by something other than the publish"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// The discriminator for the leg above: the same faceless session, one field
/// changed, and the delivery stops.
///
/// Without it, a build whose plane simply ignored `allowed_destination` would
/// pass the positive leg. It is the faceless twin of
/// `a_remote_only_put_does_not_reach_this_sessions_own_subscriber`, and here the
/// claim is sharper — with no peer, a REMOTE-only put has nowhere at all to go,
/// so "nothing arrives" must hold for the whole settle window.
#[test]
fn a_remote_only_put_on_a_session_with_no_peer_reaches_nobody() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        let mut _sub = declare_counting_sub(&listener, ctx as *mut c_void, None);

        put_once(&listener, Some(ZC_LOCALITY_REMOTE));
        let count = settle(&hits, 1, Duration::from_millis(500));
        assert_eq!(
            count, 0,
            "a REMOTE-only put must not be delivered by the local plane"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// R311y557 — a LATE face does not disturb the local leg, and it replays the
/// caller's `allowed_origin`.
///
/// The debt ledger listed "a LATE face replaying the caller's `allowed_origin`"
/// as shipped-with-no-driver: `SubEntry` carries the field precisely so a face
/// that joins AFTER the declare re-registers with the same filter. This drives
/// exactly that order — declare on a faceless session, connect a peer, then put
/// — and asserts BOTH halves of what the late replay must not break:
///
/// * a `Remote`-origin subscriber still refuses the session's own put, which is
///   what a replay that dropped the field would get wrong;
/// * and it is still refused ONCE-for-zero rather than sometimes, i.e. the face
///   that arrived did not add a second, unfiltered registration.
#[test]
fn a_face_that_joins_after_the_declare_replays_the_callers_allowed_origin() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
        // Declared with NO face in the registry: the SSOT entry is all there is,
        // and the plane's registration is made from the same value.
        let mut _sub =
            declare_counting_sub(&listener, ctx as *mut c_void, Some(ZC_LOCALITY_REMOTE));

        // NOW the peer arrives, and `face_up` replays the entry onto it.
        let dialer = open_connect(port);
        std::thread::sleep(Duration::from_millis(300));

        put_once(&listener, Some(ZC_LOCALITY_ANY));
        let count = settle(&hits, 1, Duration::from_millis(500));
        assert_eq!(
            count, 0,
            "the late face must re-register with the caller's allowed_origin \
             (REMOTE), so this session's own put still reaches nobody"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(dialer);
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// R311y557 — `z_delete` end to end through the local plane, which the debt
/// ledger recorded as unit-tested-only.
///
/// The KIND is asserted, not merely the arrival: a Del delivered as a Put would
/// satisfy a count-only assertion and mean the opposite thing to the C
/// subscriber that receives it.
#[test]
fn a_delete_reaches_this_sessions_own_subscriber_as_a_del() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);

        let kinds = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx {
            hits: kinds.clone(),
        }));
        let mut _sub = declare_del_counting_sub(&listener, ctx as *mut c_void);

        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let mut opts: z_delete_options_t = std::mem::zeroed();
        z_delete_options_default(&mut opts);
        assert_eq!(opts.allowed_destination, ZC_LOCALITY_ANY);
        assert_eq!(
            z_delete(
                z_session_loan(&listener),
                z_view_keyexpr_loan(&view),
                &mut opts as *mut z_delete_options_t,
            ),
            Z_OK
        );

        let count = settle(&kinds, 1, Duration::from_millis(300));
        assert_eq!(
            count, 1,
            "a z_delete must reach this session's own subscriber exactly once, \
             AS A DEL — the counter only advances on Z_SAMPLE_KIND_DELETE"
        );

        z_undeclare_subscriber(
            (&mut _sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>(),
        );
        close_session(listener);
        drop(Box::from_raw(ctx));
    }
}

/// R311y557 — a SESSION_LOCAL `z_get`, the arm `issue_get` shipped with no
/// driver at all (its old `(false, false) => continue` case).
///
/// Two claims, and the second is why the leg has a peer at all: a local-only get
/// must be answered by this session's OWN queryable, and it must NOT be issued
/// on the wire — so the connected peer's queryable, registered on the same
/// keyexpr, must never see it. Without the second arm a build that simply
/// ignored SESSION_LOCAL would pass.
///
/// **What the second assertion is anchored to, measured rather than assumed.**
/// Damage-probing `issue_get`'s `if want_remote` gate off reds it (`left: 1`).
/// Damage-probing the LOCAL leg's own `Locality::SessionLocal` to `Any` does
/// NOT — and that is a property of the plane, not a weakness to paper over: the
/// plane's link is an `InertLinkDriver`, so its wire half reaches nobody by
/// construction and its locality argument is unobservable from outside. The
/// enforcement that this leg does discriminate is therefore the face-loop gate,
/// which is the one that decides whether anything is transmitted at all.
#[test]
fn a_session_local_get_is_answered_here_and_not_sent_to_the_peer() {
    let port = free_port();
    unsafe {
        let listener = open_listen(port);
        let dialer = open_connect(port);

        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);

        let here = Arc::new(AtomicUsize::new(0));
        let here_ctx = Box::into_raw(Box::new(CountCtx { hits: here.clone() }));
        let mut here_qbl = declare_replying_queryable(&listener, here_ctx as *mut c_void);

        let there = Arc::new(AtomicUsize::new(0));
        let there_ctx = Box::into_raw(Box::new(CountCtx {
            hits: there.clone(),
        }));
        let mut there_qbl = declare_replying_queryable(&dialer, there_ctx as *mut c_void);
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
        let mut gopts: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut gopts);
        gopts.allowed_destination = ZC_LOCALITY_SESSION_LOCAL;
        assert_eq!(
            z_get(
                z_session_loan(&listener),
                z_view_keyexpr_loan(&view),
                std::ptr::null(),
                (&mut rclosure as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
                &mut gopts as *mut z_get_options_t,
            ),
            Z_OK
        );

        let answered = settle(&here, 1, Duration::from_millis(500));
        assert_eq!(
            answered, 1,
            "a SESSION_LOCAL get must be answered by this session's own \
             queryable exactly once"
        );
        assert_eq!(
            there.load(Ordering::SeqCst),
            0,
            "and it must not go on the wire — the peer's queryable on the same \
             keyexpr never sees it"
        );
        assert_eq!(
            replies.load(Ordering::SeqCst),
            1,
            "the querier sees exactly the one local reply"
        );

        z_undeclare_queryable(
            (&mut here_qbl as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>(),
        );
        z_undeclare_queryable(
            (&mut there_qbl as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>(),
        );
        close_session(dialer);
        close_session(listener);
        drop(Box::from_raw(here_ctx));
        drop(Box::from_raw(there_ctx));
        drop(Box::from_raw(rctx));
    }
}
