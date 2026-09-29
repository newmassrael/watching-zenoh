// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R2964 — a payload built over the CALLER'S buffer is released when the call
//! that consumed it returns, and only after its bytes have been sent.
//!
//! ## Why this leg exists
//!
//! `pico_bytes_alias_twice_and_diff` measures the constructors against the real
//! `libzenohpico.so`: since R2964 `z_bytes_from_buf` and its siblings describe
//! the caller's buffer and run the caller's deleter when the LAST holder is
//! dropped. That comparison stops at the payload's own lifetime. What it cannot
//! reach is the consequence for a `z_put`, and the consequence is where the two
//! ways of getting this wrong live:
//!
//! * a path that reads the payload AFTER the deleter has run publishes whatever
//!   the caller's allocator left behind — and a caller's deleter is a `free`;
//! * a path that keeps the payload past the call runs the deleter late, and a
//!   program that reuses or frees its context on return reads a callback it
//!   thought was over. pico's `z_put` ends with `z_bytes_drop(payload)`
//!   (`api.c` @ `z_bytes_drop(payload);`), on the calling thread.
//!
//! ## What is measured
//!
//! The deleter here POISONS the buffer as well as counting its call, so a read
//! after release is a visible byte pattern on the subscriber rather than a
//! silent pass. `z_put` and `z_publisher_put` each assert: the deleter has not
//! run at construction, has run exactly once when the call returns, and what
//! arrived is the caller's bytes and never the poison.
//!
//! `z_publisher_put` is measured twice because R2962 gave it a write filter
//! that SENDS NOTHING while no subscriber matches, and a suppressed put must
//! still consume its payload: pico drops it unconditionally after the check.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::platform::z_bytes_from_buf;
use wz_capi_pico::{
    z_bytes_move, z_bytes_to_slice, z_close, z_closure_sample, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_publisher, z_declare_subscriber, z_loaned_bytes_t, z_loaned_sample_t,
    z_open, z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_owned_slice_t,
    z_owned_subscriber_t, z_publisher_loan, z_publisher_move, z_publisher_put, z_put,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_subscriber_move,
    z_undeclare_publisher, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The bytes the caller hands over, and the byte the deleter overwrites them
/// with. Distinct from anything a sample could legitimately carry.
const PAYLOAD: &[u8; 16] = b"PAYLOAD-ALIAS-16";
const POISON: u8 = 0xEE;

/// The caller's deleter: poison what was handed over, then count the call.
/// `context` is the counter, so each call site sees only its own release.
unsafe extern "C" fn poison_and_count(value: *mut c_void, context: *mut c_void) {
    std::ptr::write_bytes(value as *mut u8, POISON, PAYLOAD.len());
    (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

type Delivered = Arc<Mutex<Vec<Vec<u8>>>>;

struct Ctx {
    delivered: Delivered,
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let payload: *const z_loaned_bytes_t = z_sample_payload(sample);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(payload, &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let data = z_slice_data(loaned);
        let len = z_slice_len(loaned);
        if !data.is_null() {
            ctx.delivered
                .lock()
                .unwrap()
                .push(std::slice::from_raw_parts(data, len).to_vec());
        }
        z_slice_drop(z_slice_move(&mut slice));
    }
}

unsafe fn open_with(key: u8, endpoint: &std::ffi::CStr) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
        Some(session)
    } else {
        None
    }
}

/// A subscriber on `keyexpr` recording every payload it is delivered.
unsafe fn declare_recording_subscriber(
    session: &z_owned_session_t,
    keyexpr: &std::ffi::CStr,
    delivered: &Delivered,
) -> (z_owned_subscriber_t, *mut c_void) {
    let ctx = Box::into_raw(Box::new(Ctx {
        delivered: delivered.clone(),
    })) as *mut c_void;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(on_sample), None, ctx),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            wz_capi_pico::z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    (subscriber, ctx)
}

/// Build the payload over a FRESH copy of the caller's bytes, run `consume` on
/// it, and check the release around the call. Returns the buffer's address so
/// the caller can free it — the deleter poisons it and does not free it.
unsafe fn consume_over_callers_buffer(
    what: &str,
    consume: impl FnOnce(*mut wz_capi_pico::z_moved_bytes_t) -> i8,
) {
    let buffer = Box::into_raw(Box::new(*PAYLOAD));
    let released = AtomicUsize::new(0);

    let mut payload: wz_capi_pico::z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_from_buf(
            &mut payload,
            buffer as *mut u8,
            PAYLOAD.len(),
            Some(poison_and_count),
            &released as *const AtomicUsize as *mut c_void,
        ),
        Z_OK
    );
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "{what}: the deleter ran at CONSTRUCTION, before anything consumed the payload"
    );

    assert_eq!(consume(z_bytes_move(&mut payload)), Z_OK, "{what}: refused");
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "{what}: the deleter must have run exactly once by the time the call \
         returns — pico's call ends with z_bytes_drop(payload) on the calling \
         thread, and a payload kept past the call runs it late"
    );
    drop(Box::from_raw(buffer));
}

/// Retry until the peer's subscription has propagated and one sample arrived.
fn wait_for_delivery(delivered: &Delivered, mut put_once: impl FnMut()) {
    for _ in 0..250 {
        if !delivered.lock().unwrap().is_empty() {
            return;
        }
        put_once();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !delivered.lock().unwrap().is_empty(),
        "CALIBRATION FAILED: nothing crossed the wire at all, so the assertions \
         on what arrived measure nothing"
    );
}

fn assert_only_the_callers_bytes(delivered: &Delivered, what: &str) {
    let got = delivered.lock().unwrap();
    assert!(!got.is_empty(), "{what}: nothing was delivered");
    for payload in got.iter() {
        assert_eq!(
            payload.as_slice(),
            PAYLOAD,
            "{what}: the subscriber received something other than the caller's \
             bytes — a poisoned payload means the bytes were read AFTER the \
             caller's deleter had run"
        );
    }
}

/// Two sessions on loopback: a listener and a dialer.
unsafe fn connected_pair() -> (z_owned_session_t, z_owned_session_t) {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");
    for _ in 0..250 {
        if let Some(dialer) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
            return (listener, dialer);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("dialer z_open never succeeded");
}

unsafe fn close_both(mut listener: z_owned_session_t, mut dialer: z_owned_session_t) {
    z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
    z_session_drop(z_session_move(&mut dialer));
    z_close(z_session_loan_mut(&mut listener), std::ptr::null());
    z_session_drop(z_session_move(&mut listener));
}

#[test]
fn z_put_releases_the_callers_buffer_when_it_returns_and_after_sending() {
    unsafe {
        let (listener, dialer) = connected_pair();
        let delivered: Delivered = Arc::new(Mutex::new(Vec::new()));
        let (mut subscriber, ctx) =
            declare_recording_subscriber(&listener, c"demo/release/put", &delivered);

        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"demo/release/put".as_ptr()),
            Z_OK
        );
        wait_for_delivery(&delivered, || {
            consume_over_callers_buffer("z_put", |payload| {
                z_put(
                    z_session_loan(&dialer),
                    z_view_keyexpr_loan(&ke),
                    payload,
                    std::ptr::null(),
                )
            });
        });
        assert_only_the_callers_bytes(&delivered, "z_put");

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        close_both(listener, dialer);
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}

#[test]
fn z_publisher_put_releases_the_callers_buffer_whether_or_not_the_filter_sends() {
    unsafe {
        let (listener, dialer) = connected_pair();

        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"demo/release/pub".as_ptr()),
            Z_OK
        );
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&dialer),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK
        );

        // ARM 1 — NO subscriber anywhere, so the publisher's write filter is
        // ACTIVE and the put is suppressed. The payload is consumed regardless:
        // a build that returned early with the payload still held would leave
        // the caller's deleter waiting on a drop that never comes.
        consume_over_callers_buffer("z_publisher_put (suppressed by the filter)", |payload| {
            z_publisher_put(z_publisher_loan(&publisher), payload, std::ptr::null())
        });

        // ARM 2 — a subscriber appears, the filter opens, the put is SENT.
        let delivered: Delivered = Arc::new(Mutex::new(Vec::new()));
        let (mut subscriber, ctx) =
            declare_recording_subscriber(&listener, c"demo/release/pub", &delivered);
        wait_for_delivery(&delivered, || {
            consume_over_callers_buffer("z_publisher_put (sent)", |payload| {
                z_publisher_put(z_publisher_loan(&publisher), payload, std::ptr::null())
            });
        });
        assert_only_the_callers_bytes(&delivered, "z_publisher_put");

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_undeclare_publisher(z_publisher_move(&mut publisher));
        close_both(listener, dialer);
        drop(Box::from_raw(ctx as *mut Ctx));
    }
}
