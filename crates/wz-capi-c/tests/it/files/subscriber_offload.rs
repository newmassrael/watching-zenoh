// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A subscriber whose callback runs off the receive path, through the `wz_capi_c_*offload*`
//! doors, driven as a C program would drive them.
//!
//! The session is a peer with no link, so every sample is one the session puts to itself: that
//! delivery runs inside `z_put`, on the calling thread (`local_delivery_thread`), which is what a
//! plain subscriber in the same session shows here as the control. An offloaded one must not run
//! there, and must not hold the put while its callback is busy.

#![cfg(all(feature = "rx-callback-offload", feature = "peer"))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_subscriber_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::{z_bytes_copy_from_buf, z_bytes_len};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::offload::{
    wz_capi_c_declare_subscriber_offloaded, wz_capi_c_offload_options_t, wz_capi_c_offload_stats_t,
    wz_capi_c_subscriber_offload_stats, WZ_CAPI_C_OVERLOAD_BLOCK, WZ_CAPI_C_OVERLOAD_KEEP_LATEST,
    WZ_CAPI_C_OVERLOAD_REJECT,
};
use wz_capi_c::put::z_put;
use wz_capi_c::result::{ZResult, Z_EINVAL, Z_EUNAVAILABLE, Z_OK};
use wz_capi_c::sample::z_sample_payload;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{
    z_closure_sample, z_declare_subscriber, z_internal_subscriber_check, z_subscriber_loan,
    z_undeclare_subscriber,
};

/// What a callback saw and how it was told to behave. Leaked for the test's life: the library
/// may call it until the C `drop(context)` has run, which the tests wait for.
struct Ctx {
    /// The number each sample carries (its payload's length less one) and the thread it ran on.
    seen: Mutex<Vec<(usize, ThreadId)>>,
    /// The first call waits until `released` is set, so a lane fills behind it.
    hold_first: bool,
    entered: AtomicBool,
    released: AtomicBool,
    drops: AtomicUsize,
}

fn new_ctx(hold_first: bool) -> &'static Ctx {
    Box::leak(Box::new(Ctx {
        seen: Mutex::new(Vec::new()),
        hold_first,
        entered: AtomicBool::new(false),
        released: AtomicBool::new(false),
        drops: AtomicUsize::new(0),
    }))
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let n = z_bytes_len(z_sample_payload(sample)).saturating_sub(1);
    let first = {
        let mut seen = ctx.seen.lock().unwrap();
        seen.push((n, std::thread::current().id()));
        seen.len() == 1
    };
    if first && ctx.hold_first {
        ctx.entered.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ctx.released.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    (*(ctx as *const Ctx)).drops.fetch_add(1, Ordering::SeqCst);
}

unsafe fn closure_of(ctx: &'static Ctx) -> z_owned_closure_sample_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(
        &mut closure,
        Some(on_sample),
        Some(on_drop),
        ctx as *const Ctx as *mut c_void,
    );
    closure
}

unsafe fn open_peer() -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in [
        ("scouting/multicast/enabled", "false"),
        ("mode", "\"peer\""),
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
            std::ptr::null(),
        ),
        Z_OK
    );
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// Declare an offloaded subscriber on `key`; `overload` `None` passes NULL for the statement.
unsafe fn declare_offloaded(
    session: &z_owned_session_t,
    key: &str,
    ctx: &'static Ctx,
    overload: Option<u8>,
) -> (ZResult, z_owned_subscriber_t) {
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure = closure_of(ctx);
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let statement = overload.map(|overload| wz_capi_c_offload_options_t { overload });
    let rc = wz_capi_c_declare_subscriber_offloaded(
        z_session_loan(session),
        &mut sub,
        z_view_keyexpr_loan(&view),
        (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
        std::ptr::null_mut(),
        statement.as_ref().map_or(std::ptr::null(), |s| {
            s as *const wz_capi_c_offload_options_t
        }),
    );
    (rc, sub)
}

unsafe fn declare_plain(
    session: &z_owned_session_t,
    key: &str,
    ctx: &'static Ctx,
) -> z_owned_subscriber_t {
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure = closure_of(ctx);
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

/// Put sample `n` on `key`: a payload of `n + 1` bytes, so the callback reads `n` off its length.
unsafe fn put_n(session: &z_owned_session_t, key: &str, n: usize) {
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let body = vec![b'x'; n + 1];
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut payload, body.as_ptr(), body.len()),
        Z_OK
    );
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

unsafe fn stats_of(sub: &z_owned_subscriber_t) -> wz_capi_c_offload_stats_t {
    let mut out = wz_capi_c_offload_stats_t::default();
    assert_eq!(
        wz_capi_c_subscriber_offload_stats(z_subscriber_loan(sub), &mut out),
        Z_OK
    );
    out
}

unsafe fn undeclare(mut sub: z_owned_subscriber_t) {
    assert_eq!(
        z_undeclare_subscriber(
            (&mut sub as *mut z_owned_subscriber_t).cast::<z_moved_subscriber_t>()
        ),
        Z_OK
    );
}

fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

fn wait_for_entered(ctx: &Ctx) {
    assert!(
        wait_until(|| ctx.entered.load(Ordering::SeqCst)),
        "the offloaded callback never ran"
    );
}

fn numbers(ctx: &Ctx) -> Vec<usize> {
    ctx.seen.lock().unwrap().iter().map(|(n, _)| *n).collect()
}

/// The control runs inline: a plain subscriber's callback has run on this thread when `z_put`
/// returns. The offloaded one runs elsewhere, and while it is still busy with the sample the put
/// has already returned.
#[test]
fn an_offloaded_callback_runs_off_the_putting_thread_while_a_plain_one_runs_inline() {
    const KEY: &str = "wz/offload/thread";
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let plain = new_ctx(false);
    let lane = new_ctx(true);
    // SAFETY: the session is live.
    let (rc, offloaded) =
        unsafe { declare_offloaded(&session, KEY, lane, Some(WZ_CAPI_C_OVERLOAD_REJECT)) };
    assert_eq!(rc, Z_OK);
    let plain_sub = unsafe { declare_plain(&session, KEY, plain) };

    // SAFETY: the session is live.
    unsafe { put_n(&session, KEY, 0) };
    let here = std::thread::current().id();
    let plain_seen = plain.seen.lock().unwrap().clone();
    assert_eq!(
        plain_seen,
        vec![(0, here)],
        "the control runs inside the put"
    );

    // The callback waits until released, which happens only below: had it run inside the put, the
    // put would have returned only after its ten-second wait, and on this thread.
    wait_for_entered(lane);
    let lane_seen = lane.seen.lock().unwrap().clone();
    assert_eq!(lane_seen.len(), 1);
    assert_ne!(
        lane_seen[0].1, here,
        "an offloaded callback ran on the putting thread"
    );
    lane.released.store(true, Ordering::SeqCst);

    // SAFETY: both subscribers and the session are live and owned here.
    unsafe {
        undeclare(offloaded);
        undeclare(plain_sub);
        close_session(session);
    }
}

/// Under `reject`, a lane whose callback is busy with the first sample holds what its event limit
/// allows, the busy one included, refuses the rest and counts each refusal as a loss; the samples
/// it held are then delivered in the order they were put.
#[test]
fn reject_refuses_what_the_lane_cannot_hold_and_counts_it() {
    const KEY: &str = "wz/offload/reject";
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let ctx = new_ctx(true);
    // SAFETY: the session is live.
    let (rc, sub) =
        unsafe { declare_offloaded(&session, KEY, ctx, Some(WZ_CAPI_C_OVERLOAD_REJECT)) };
    assert_eq!(rc, Z_OK);
    // SAFETY: the session and the subscriber are live.
    unsafe { put_n(&session, KEY, 0) };
    wait_for_entered(ctx);
    let events = unsafe { stats_of(&sub) }.event_capacity as usize;
    assert!(events >= 1);
    let extra = 3;
    for n in 1..events + extra {
        // SAFETY: as above.
        unsafe { put_n(&session, KEY, n) };
    }
    // SAFETY: as above.
    assert!(wait_until(
        || unsafe { stats_of(&sub) }.refused_events_full == extra as u64
    ));
    let full = unsafe { stats_of(&sub) };
    assert_eq!(full.queued_events, events as u64);
    assert_eq!(full.evicted, 0);
    assert_eq!(
        full.dropped_reliable + full.dropped_best_effort,
        extra as u64
    );
    assert_eq!(full.overload, WZ_CAPI_C_OVERLOAD_REJECT);

    ctx.released.store(true, Ordering::SeqCst);
    assert!(wait_until(|| numbers(ctx).len() >= events));
    assert_eq!(numbers(ctx), (0..events).collect::<Vec<_>>());

    // SAFETY: the subscriber and the session are live and owned here.
    unsafe {
        undeclare(sub);
        close_session(session);
    }
}

/// Under `keep-latest`, each sample past a full lane takes out the newest one waiting behind the
/// busy one, so the last sample put is delivered and the ones taken out are counted.
#[test]
fn keep_latest_takes_out_the_newest_waiting_and_delivers_the_last_put() {
    const KEY: &str = "wz/offload/keep-latest";
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let ctx = new_ctx(true);
    // SAFETY: the session is live.
    let (rc, sub) =
        unsafe { declare_offloaded(&session, KEY, ctx, Some(WZ_CAPI_C_OVERLOAD_KEEP_LATEST)) };
    assert_eq!(rc, Z_OK);
    // SAFETY: the session and the subscriber are live.
    unsafe { put_n(&session, KEY, 0) };
    wait_for_entered(ctx);
    let events = unsafe { stats_of(&sub) }.event_capacity as usize;
    let extra = 3;
    let last = events + extra - 1;
    for n in 1..=last {
        // SAFETY: as above.
        unsafe { put_n(&session, KEY, n) };
    }
    // SAFETY: as above.
    assert!(wait_until(
        || unsafe { stats_of(&sub) }.evicted == extra as u64
    ));
    let full = unsafe { stats_of(&sub) };
    assert_eq!(full.refused_events_full, 0);
    assert_eq!(full.queued_events, events as u64);
    assert_eq!(full.overload, WZ_CAPI_C_OVERLOAD_KEEP_LATEST);

    ctx.released.store(true, Ordering::SeqCst);
    assert!(wait_until(|| numbers(ctx).len() >= events));
    let seen = numbers(ctx);
    assert_eq!(seen.len(), events);
    assert_eq!(seen.last(), Some(&last));
    assert_eq!(seen[..events - 1], (0..events - 1).collect::<Vec<_>>()[..]);

    // SAFETY: the subscriber and the session are live and owned here.
    unsafe {
        undeclare(sub);
        close_session(session);
    }
}

/// `block` is refused: nothing is declared, the subscriber is a gravestone and the C closure is
/// dropped once. A declaration that states nothing takes the build's policy, and is refused the
/// same way exactly when that policy is `block`.
#[test]
fn block_is_refused_and_the_callback_is_dropped_once() {
    const KEY: &str = "wz/offload/block";
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let stated = new_ctx(false);
    // SAFETY: the session is live.
    let (rc, sub) =
        unsafe { declare_offloaded(&session, KEY, stated, Some(WZ_CAPI_C_OVERLOAD_BLOCK)) };
    assert_eq!(rc, Z_EUNAVAILABLE);
    assert!(!unsafe { z_internal_subscriber_check(&sub) });
    assert_eq!(stated.drops.load(Ordering::SeqCst), 1);

    let unstated = new_ctx(false);
    // SAFETY: as above.
    let (rc, sub) = unsafe { declare_offloaded(&session, KEY, unstated, None) };
    let build_blocks = wz_session_core::policy::SubscriberOverload::default()
        == wz_session_core::policy::SubscriberOverload::Block;
    if build_blocks {
        assert_eq!(rc, Z_EUNAVAILABLE);
        assert_eq!(unstated.drops.load(Ordering::SeqCst), 1);
    } else {
        assert_eq!(rc, Z_OK);
        // SAFETY: the subscriber is live and owned here.
        unsafe { undeclare(sub) };
    }

    // SAFETY: the session is live and owned here.
    unsafe { close_session(session) };
}

/// A statement that names no answer is `Z_EINVAL`, with the closure consumed.
#[test]
fn a_value_that_names_no_answer_is_invalid() {
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let ctx = new_ctx(false);
    // SAFETY: the session is live.
    let (rc, sub) = unsafe {
        declare_offloaded(
            &session,
            "wz/offload/invalid",
            ctx,
            Some(WZ_CAPI_C_OVERLOAD_KEEP_LATEST + 1),
        )
    };
    assert_eq!(rc, Z_EINVAL);
    assert!(!unsafe { z_internal_subscriber_check(&sub) });
    assert_eq!(ctx.drops.load(Ordering::SeqCst), 1);
    // SAFETY: the session is live and owned here.
    unsafe { close_session(session) };
}

/// A subscriber declared by `z_declare_subscriber` has no lane, and its stats are refused
/// without writing the output.
#[test]
fn a_plain_subscriber_has_no_lane_to_read() {
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let ctx = new_ctx(false);
    // SAFETY: the session is live.
    let sub = unsafe { declare_plain(&session, "wz/offload/plain", ctx) };
    let mut out = wz_capi_c_offload_stats_t {
        queued_events: 77,
        ..Default::default()
    };
    // SAFETY: the subscriber is live.
    let rc = unsafe { wz_capi_c_subscriber_offload_stats(z_subscriber_loan(&sub), &mut out) };
    assert_eq!(rc, Z_EINVAL);
    assert_eq!(out.queued_events, 77);
    // SAFETY: the subscriber and the session are live and owned here.
    unsafe {
        undeclare(sub);
        close_session(session);
    }
}

/// Undeclaring an offloaded subscriber stops its lane and runs the C `drop(context)` once, after
/// which a put reaches no callback.
#[test]
fn undeclaring_stops_the_lane_and_drops_the_callback_once() {
    const KEY: &str = "wz/offload/undeclare";
    // SAFETY: a fresh session owned by this test until it is closed.
    let session = unsafe { open_peer() };
    let ctx = new_ctx(false);
    // SAFETY: the session is live.
    let (rc, sub) =
        unsafe { declare_offloaded(&session, KEY, ctx, Some(WZ_CAPI_C_OVERLOAD_REJECT)) };
    assert_eq!(rc, Z_OK);
    // SAFETY: the session and the subscriber are live.
    unsafe { put_n(&session, KEY, 4) };
    assert!(wait_until(|| numbers(ctx) == [4]));
    // SAFETY: the subscriber is live and owned here.
    unsafe { undeclare(sub) };
    assert!(wait_until(|| ctx.drops.load(Ordering::SeqCst) == 1));
    // SAFETY: the session is live.
    unsafe { put_n(&session, KEY, 5) };
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(numbers(ctx), [4]);
    assert_eq!(ctx.drops.load(Ordering::SeqCst), 1);
    // SAFETY: the session is live and owned here.
    unsafe { close_session(session) };
}
