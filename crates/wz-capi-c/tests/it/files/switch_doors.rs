// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The `wz_capi_c_*_ext` doors, driven through the exported symbols as a C program would drive
//! them, on a session that has no peer.
//!
//! The policies behind the statements (`entity-link-restriction`, `publisher-admission-retry`,
//! `multi-route-atomic-tx`, `targeted-query`) are fixed when the library is built, so this file
//! cannot turn one on. Each leg therefore states what the BUILD it runs in must answer, read from
//! the build's own policy: the refusal and the nothing-sent of a build whose policy is off (the
//! default build), and the call going through of a build that states it on. Whichever build runs
//! this file, one half is exercised, and the pure mapping of a statement to the options (both
//! halves of each policy) is held by the unit tests of `switch_doors.rs`, and the node's refusal
//! by its `node_tests`.
//!
//! What a statement of nothing does is the same in every build, and is what the first leg holds:
//! the door answers what the `z_*` function answers, and the same samples arrive.

#![cfg(all(feature = "switch-doors", feature = "peer"))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_query_t, z_loaned_reply_t, z_loaned_sample_t, z_moved_bytes_t,
    z_moved_closure_query_t, z_moved_closure_reply_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_liveliness_token_t, z_moved_publisher_t, z_moved_queryable_t, z_moved_session_t,
    z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_query_t, z_owned_closure_reply_t,
    z_owned_closure_sample_t, z_owned_config_t, z_owned_liveliness_token_t, z_owned_publisher_t,
    z_owned_queryable_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::get::z_closure_reply;
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::liveliness::{z_internal_liveliness_token_check, z_liveliness_undeclare_token};
use wz_capi_c::publisher::{
    z_internal_publisher_check, z_publisher_loan, z_publisher_put, z_undeclare_publisher,
};
use wz_capi_c::put::z_put;
use wz_capi_c::query::{
    z_closure_query, z_internal_queryable_check, z_query_reply, z_undeclare_queryable,
};
use wz_capi_c::result::{WZ_CAPI_C_E_POLICY_OFF, Z_EINVAL, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_internal_subscriber_check, z_undeclare_subscriber};
use wz_capi_c::switch_doors::*;
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::policy::SessionPolicy;

const KEYEXPR: &str = "wz/switch-doors/demo";

fn links_on() -> bool {
    SessionPolicy::from_build().entity_link_restriction
}

fn retry_on() -> bool {
    SessionPolicy::from_build().publisher_admission_retry
}

fn atomic_on() -> bool {
    SessionPolicy::from_build().multi_route_atomic_tx
}

fn target_on() -> bool {
    SessionPolicy::from_build().targeted_query
}

/// What a call that states something answers in a build whose policy for it is `on`.
fn answer_when(on: bool) -> i8 {
    if on {
        Z_OK
    } else {
        WZ_CAPI_C_E_POLICY_OFF
    }
}

/// Counts what a closure is handed and how often it is dropped.
struct Counts {
    hits: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

fn counts() -> (Arc<AtomicUsize>, Arc<AtomicUsize>, *mut Counts) {
    let hits = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(Counts {
        hits: hits.clone(),
        drops: drops.clone(),
    }));
    (hits, drops, ctx)
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .drops
        .fetch_add(1, Ordering::SeqCst);
}

/// The queryable handler: count, and answer once.
unsafe extern "C" fn on_query(query: *mut z_loaned_query_t, ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .hits
        .fetch_add(1, Ordering::SeqCst);
    let ke = CString::new(KEYEXPR).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    if z_view_keyexpr_from_str(&mut view, ke.as_ptr()) != Z_OK {
        return;
    }
    let mut payload = payload_of("answer");
    let _ = z_query_reply(
        query,
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    );
}

unsafe fn payload_of(text: &str) -> z_owned_bytes_t {
    let text = CString::new(text).unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    payload
}

/// A peer that listens on a port of its own and dials nothing: a session with no face, which
/// delivers to its own entities through the local plane.
unsafe fn open_alone() -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in [
        ("scouting/multicast/enabled", "false".to_owned()),
        (
            "listen/endpoints",
            format!("[\"tcp/127.0.0.1:{}\"]", free_port()),
        ),
    ] {
        let key = CString::new(key).unwrap();
        let value = CString::new(value).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
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

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

unsafe fn view_of(text: &CString) -> z_view_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, text.as_ptr()), Z_OK);
    view
}

/// Wait until `value` reaches `want`, then keep watching for the settle window so an extra
/// arrival is counted. Returns the final count.
fn settle(value: &Arc<AtomicUsize>, want: usize, settle_for: Duration) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    while value.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(settle_for);
    value.load(Ordering::SeqCst)
}

/// A subscriber on [`KEYEXPR`] declared through `z_declare_subscriber`, which counts.
unsafe fn count_samples(session: &z_owned_session_t, ctx: *mut Counts) -> z_owned_subscriber_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(KEYEXPR).unwrap();
    let view = view_of(&ke);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c::sub::z_declare_subscriber(
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

/// Free a closure context once its closure has been dropped, which is when the session that
/// held it lets it go. A drop that never comes leaves the context in place: freeing it under a
/// closure that still holds it would be a read of freed memory.
unsafe fn free_when_dropped(drops: &Arc<AtomicUsize>, ctx: *mut Counts) {
    if settle(drops, 1, Duration::ZERO) >= 1 {
        drop(Box::from_raw(ctx));
    }
}

unsafe fn undeclare(mut sub: z_owned_subscriber_t) {
    z_undeclare_subscriber((&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>());
}

/// One put on [`KEYEXPR`] through the door, with the statement `ext` (null for none).
unsafe fn put_ext(session: &z_owned_session_t, ext: Option<&wz_capi_c_publish_ext_t>) -> i8 {
    let ke = CString::new(KEYEXPR).unwrap();
    let view = view_of(&ke);
    let mut payload = payload_of("v");
    wz_capi_c_put_ext(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
        ext.map_or(std::ptr::null(), std::ptr::from_ref),
    )
}

/// One put on [`KEYEXPR`] through `z_put`.
unsafe fn put_plain(session: &z_owned_session_t) -> i8 {
    let ke = CString::new(KEYEXPR).unwrap();
    let view = view_of(&ke);
    let mut payload = payload_of("v");
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        std::ptr::null_mut(),
    )
}

fn publish_ext() -> wz_capi_c_publish_ext_t {
    let mut ext = wz_capi_c_publish_ext_t {
        link_mask: u64::MAX,
        attempts: u32::MAX,
        delay_ms: u32::MAX,
        all_or_none: u8::MAX,
    };
    // SAFETY: a live local.
    unsafe { wz_capi_c_publish_ext_default(&mut ext) };
    ext
}

fn query_ext() -> wz_capi_c_query_ext_t {
    // SAFETY: a zeroed local is overwritten by the default function.
    let mut ext: wz_capi_c_query_ext_t = unsafe { std::mem::zeroed() };
    // SAFETY: a live local.
    unsafe { wz_capi_c_query_ext_default(&mut ext) };
    ext
}

fn entity_ext() -> wz_capi_c_entity_ext_t {
    let mut ext = wz_capi_c_entity_ext_t {
        link_mask: u64::MAX,
    };
    // SAFETY: a live local.
    unsafe { wz_capi_c_entity_ext_default(&mut ext) };
    ext
}

/// A put that states nothing is the put `z_put` makes: the same answer and the same sample, for a
/// null statement and for the default one, in any build.
#[test]
fn a_put_stating_nothing_is_the_put_the_z_function_makes() {
    unsafe {
        let session = open_alone();
        let (hits, _drops, ctx) = counts();
        let sub = count_samples(&session, ctx);

        assert_eq!(put_plain(&session), Z_OK);
        assert_eq!(put_ext(&session, None), Z_OK, "a null statement");
        let none = publish_ext();
        assert_eq!(
            put_ext(&session, Some(&none)),
            Z_OK,
            "the default statement"
        );
        assert_eq!(
            settle(&hits, 3, Duration::from_millis(300)),
            3,
            "each of the three puts reaches the session's own subscriber once"
        );

        undeclare(sub);
        close_session(session);
        drop(Box::from_raw(ctx));
    }
}

/// A put that states something is taken only by a build whose policy for it is on, and in a build
/// whose policy is off nothing is sent: the subscriber hears none of them.
#[test]
fn a_stated_put_is_refused_while_its_policy_is_off_and_sends_nothing() {
    unsafe {
        let session = open_alone();
        let (hits, _drops, ctx) = counts();
        let sub = count_samples(&session, ctx);

        let mut links = publish_ext();
        links.link_mask = 0b1;
        let mut retry = publish_ext();
        retry.attempts = 2;
        retry.delay_ms = 10;
        let mut atomic = publish_ext();
        atomic.all_or_none = 1;
        assert_eq!(
            put_ext(&session, Some(&links)),
            answer_when(links_on()),
            "a link mask"
        );
        assert_eq!(
            put_ext(&session, Some(&retry)),
            answer_when(retry_on()),
            "a retry"
        );
        assert_eq!(
            put_ext(&session, Some(&atomic)),
            answer_when(atomic_on()),
            "an all-or-none publish"
        );
        if !links_on() && !retry_on() && !atomic_on() {
            assert_eq!(
                settle(&hits, 1, Duration::from_millis(300)),
                0,
                "a refused put sent nothing"
            );
        }

        // A retry that is no retry is refused in every build, and the policy says nothing of it.
        let mut too_many = publish_ext();
        too_many.attempts = 256;
        too_many.delay_ms = 1;
        assert_eq!(put_ext(&session, Some(&too_many)), Z_EINVAL);

        undeclare(sub);
        close_session(session);
        drop(Box::from_raw(ctx));
    }
}

/// A publisher declared with nothing stated puts as one declared by `z_declare_publisher` does,
/// and one declared with a statement is refused while its policy is off, leaving the gravestone.
#[test]
fn a_publisher_stating_nothing_puts_and_one_stating_a_retry_follows_the_policy() {
    unsafe {
        let session = open_alone();
        let (hits, _drops, ctx) = counts();
        let sub = count_samples(&session, ctx);
        let ke = CString::new(KEYEXPR).unwrap();
        let view = view_of(&ke);

        let none = publish_ext();
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            wz_capi_c_declare_publisher_ext(
                z_session_loan(&session),
                &mut publisher,
                z_view_keyexpr_loan(&view),
                std::ptr::null_mut(),
                &none
            ),
            Z_OK
        );
        let mut payload = payload_of("v");
        assert_eq!(
            z_publisher_put(
                z_publisher_loan(&publisher),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        assert_eq!(settle(&hits, 1, Duration::from_millis(300)), 1);
        z_undeclare_publisher(
            (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
        );

        let mut retry = publish_ext();
        retry.attempts = 2;
        retry.delay_ms = 10;
        let mut stated: z_owned_publisher_t = std::mem::zeroed();
        let rc = wz_capi_c_declare_publisher_ext(
            z_session_loan(&session),
            &mut stated,
            z_view_keyexpr_loan(&view),
            std::ptr::null_mut(),
            &retry,
        );
        assert_eq!(rc, answer_when(retry_on()));
        assert_eq!(
            z_internal_publisher_check(&stated),
            retry_on(),
            "a refused declaration leaves the gravestone, an accepted one a publisher"
        );
        if retry_on() {
            z_undeclare_publisher(
                (&mut stated as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
            );
        }

        undeclare(sub);
        close_session(session);
        drop(Box::from_raw(ctx));
    }
}

/// A subscriber limited to links is refused while its policy is off: the closure it was given is
/// dropped once, which is the consume-on-every-path of `z_declare_subscriber`, and the handle is
/// the gravestone. The queryable is the same, and a get stating a target too.
#[test]
fn a_refused_declaration_or_get_consumes_its_closure_and_leaves_the_gravestone() {
    unsafe {
        let session = open_alone();
        let ke = CString::new(KEYEXPR).unwrap();
        let view = view_of(&ke);

        let mut mask = entity_ext();
        mask.link_mask = 0b10;

        let (_hits, sample_drops, ctx) = counts();
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx.cast());
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        let rc = wz_capi_c_declare_subscriber_ext(
            z_session_loan(&session),
            &mut subscriber,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
            &mask,
        );
        assert_eq!(rc, answer_when(links_on()), "a limited subscriber");
        assert_eq!(z_internal_subscriber_check(&subscriber), links_on());
        if links_on() {
            undeclare(subscriber);
        } else {
            assert_eq!(
                sample_drops.load(Ordering::SeqCst),
                1,
                "a refused declaration drops the closure once"
            );
        }

        let (_hits, query_drops, qctx) = counts();
        let mut handler: z_owned_closure_query_t = std::mem::zeroed();
        z_closure_query(&mut handler, Some(on_query), Some(on_drop), qctx.cast());
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let rc = wz_capi_c_declare_queryable_ext(
            z_session_loan(&session),
            &mut queryable,
            z_view_keyexpr_loan(&view),
            (&mut handler as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
            std::ptr::null_mut(),
            &mask,
        );
        assert_eq!(rc, answer_when(links_on()), "a limited queryable");
        assert_eq!(z_internal_queryable_check(&queryable), links_on());
        if links_on() {
            z_undeclare_queryable(
                (&mut queryable as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>(),
            );
        } else {
            assert_eq!(
                query_drops.load(Ordering::SeqCst),
                1,
                "a refused declaration drops the handler once"
            );
        }

        let (_hits, reply_drops, rctx) = counts();
        let mut replies: z_owned_closure_reply_t = std::mem::zeroed();
        z_closure_reply(&mut replies, Some(on_reply), Some(on_drop), rctx.cast());
        let mut target = query_ext();
        target.has_target = 1;
        target.target.id[0] = 0xc7;
        target.target.id[1] = 0xd1;
        let rc = wz_capi_c_get_ext(
            z_session_loan(&session),
            z_view_keyexpr_loan(&view),
            std::ptr::null(),
            (&mut replies as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
            std::ptr::null_mut(),
            &target,
        );
        assert_eq!(rc, answer_when(target_on()), "a get addressed to a node");
        if !target_on() {
            assert_eq!(
                reply_drops.load(Ordering::SeqCst),
                1,
                "a refused get drops the reply closure once"
            );
        }

        close_session(session);
        // The closures of a taken declaration and get are dropped by the session that held them;
        // the contexts live until they have been.
        free_when_dropped(&sample_drops, ctx);
        free_when_dropped(&query_drops, qctx);
        free_when_dropped(&reply_drops, rctx);
    }
}

/// A queryable and a get that state nothing are the queryable and the get the `z_*` functions
/// make: the in-process get reaches the queryable and the reply comes back, for a null statement
/// and for the default one.
#[test]
fn a_queryable_and_a_get_stating_nothing_answer_as_the_z_functions_do() {
    unsafe {
        let session = open_alone();
        let ke = CString::new(KEYEXPR).unwrap();
        let view = view_of(&ke);

        let (handled, _drops, qctx) = counts();
        let mut handler: z_owned_closure_query_t = std::mem::zeroed();
        z_closure_query(&mut handler, Some(on_query), None, qctx.cast());
        let none = entity_ext();
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            wz_capi_c_declare_queryable_ext(
                z_session_loan(&session),
                &mut queryable,
                z_view_keyexpr_loan(&view),
                (&mut handler as *mut z_owned_closure_query_t).cast::<z_moved_closure_query_t>(),
                std::ptr::null_mut(),
                &none,
            ),
            Z_OK
        );

        let (replied, _drops, rctx) = counts();
        let query = query_ext();
        for ext in [std::ptr::null(), &query as *const wz_capi_c_query_ext_t] {
            let mut replies: z_owned_closure_reply_t = std::mem::zeroed();
            z_closure_reply(&mut replies, Some(on_reply), None, rctx.cast());
            assert_eq!(
                wz_capi_c_get_ext(
                    z_session_loan(&session),
                    z_view_keyexpr_loan(&view),
                    std::ptr::null(),
                    (&mut replies as *mut z_owned_closure_reply_t)
                        .cast::<z_moved_closure_reply_t>(),
                    std::ptr::null_mut(),
                    ext,
                ),
                Z_OK
            );
        }
        assert_eq!(
            settle(&handled, 2, Duration::from_millis(300)),
            2,
            "each get reaches the session's own queryable once"
        );
        assert_eq!(
            settle(&replied, 2, Duration::from_millis(300)),
            2,
            "and each gets its reply"
        );

        z_undeclare_queryable(
            (&mut queryable as *mut z_owned_queryable_t).cast::<z_moved_queryable_t>(),
        );
        close_session(session);
        drop(Box::from_raw(qctx));
        drop(Box::from_raw(rctx));
    }
}

/// A liveliness token and a liveliness subscriber that state nothing are the ones the `z_*`
/// functions declare: the session's own subscriber hears the token appear (a put) and go away (a
/// delete), for a null statement and for the default one, in any build.
#[test]
fn a_liveliness_token_and_subscriber_stating_nothing_are_the_z_functions_declarations() {
    unsafe {
        let session = open_alone();
        let ke = CString::new(KEYEXPR).unwrap();
        let view = view_of(&ke);
        let none = entity_ext();

        for ext in [std::ptr::null(), &none as *const wz_capi_c_entity_ext_t] {
            let (hits, drops, ctx) = counts();
            let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
            z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx.cast());
            let mut watcher: z_owned_subscriber_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_liveliness_declare_subscriber_ext(
                    z_session_loan(&session),
                    &mut watcher,
                    z_view_keyexpr_loan(&view),
                    (&mut closure as *mut z_owned_closure_sample_t)
                        .cast::<z_moved_closure_sample_t>(),
                    std::ptr::null_mut(),
                    ext,
                ),
                Z_OK
            );

            let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
            assert_eq!(
                wz_capi_c_liveliness_declare_token_ext(
                    z_session_loan(&session),
                    &mut token,
                    z_view_keyexpr_loan(&view),
                    std::ptr::null(),
                    ext,
                ),
                Z_OK
            );
            assert!(z_internal_liveliness_token_check(&token));
            assert_eq!(
                settle(&hits, 1, Duration::from_millis(300)),
                1,
                "the token appears once to the session's own subscriber"
            );
            z_liveliness_undeclare_token(
                (&mut token as *mut z_owned_liveliness_token_t)
                    .cast::<z_moved_liveliness_token_t>(),
            );
            assert_eq!(
                settle(&hits, 2, Duration::from_millis(300)),
                2,
                "and goes away once"
            );

            undeclare(watcher);
            free_when_dropped(&drops, ctx);
        }
        close_session(session);
    }
}

/// A liveliness token and a liveliness subscriber limited to links are refused while the policy is
/// off: nothing is declared, the closure is dropped once and the handles are the gravestone. A
/// build whose policy is on takes them, and the session's own plane, which is behind no link,
/// still hears the token.
#[test]
fn a_limited_liveliness_declaration_is_refused_while_its_policy_is_off() {
    unsafe {
        let session = open_alone();
        let ke = CString::new(KEYEXPR).unwrap();
        let view = view_of(&ke);
        let mut mask = entity_ext();
        mask.link_mask = 0b10;

        let (hits, drops, ctx) = counts();
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx.cast());
        let mut watcher: z_owned_subscriber_t = std::mem::zeroed();
        let rc = wz_capi_c_liveliness_declare_subscriber_ext(
            z_session_loan(&session),
            &mut watcher,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
            &mask,
        );
        assert_eq!(
            rc,
            answer_when(links_on()),
            "a limited liveliness subscriber"
        );
        assert_eq!(z_internal_subscriber_check(&watcher), links_on());
        if !links_on() {
            assert_eq!(
                drops.load(Ordering::SeqCst),
                1,
                "a refused declaration drops the closure once"
            );
        }

        let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
        let rc = wz_capi_c_liveliness_declare_token_ext(
            z_session_loan(&session),
            &mut token,
            z_view_keyexpr_loan(&view),
            std::ptr::null(),
            &mask,
        );
        assert_eq!(rc, answer_when(links_on()), "a limited liveliness token");
        assert_eq!(z_internal_liveliness_token_check(&token), links_on());
        if links_on() {
            assert_eq!(
                settle(&hits, 1, Duration::from_millis(300)),
                1,
                "the session's own plane is behind no link"
            );
            z_liveliness_undeclare_token(
                (&mut token as *mut z_owned_liveliness_token_t)
                    .cast::<z_moved_liveliness_token_t>(),
            );
            undeclare(watcher);
        } else {
            assert_eq!(
                hits.load(Ordering::SeqCst),
                0,
                "a refused pair declares nothing to hear"
            );
        }

        close_session(session);
        free_when_dropped(&drops, ctx);
    }
}
