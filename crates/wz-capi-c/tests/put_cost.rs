// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The instructions one `z_publisher_put` costs, for a profiler to run under.
//!
//! `valgrind --tool=callgrind --toggle-collect=z_publisher_put` of this test collects only what
//! runs inside the call and what it calls, so the receive side (the listener is in this process)
//! and the setup are not in the number. Run it twice, once with `WZ_PUT_N=0` and once with a
//! count, and divide the difference by the count: the first run is the cost of the harness around
//! the call, which `--toggle-collect` leaves out already, so it is a control that nothing else is
//! being collected.
//!
//! It exists because the send path has fast lanes whose whole value is an instruction count, and
//! a count is lost the way it is won: quietly, by a change that has nothing to do with the lane
//! (a feature turned on, a check moved). It asserts that every put arrived, which is what keeps
//! it from profiling a put that was dropped.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_publisher_t, z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_owned_subscriber_t,
    z_view_keyexpr_t,
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
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

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

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

/// A keyexpr view and the string it points at. The view ALIASES the caller's text (zenoh-c's
/// contract, kept here), so the text has to live as long as the view does: returning the view
/// alone left it pointing at a string freed on return.
unsafe fn view(key: &str) -> (CString, z_view_keyexpr_t) {
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    (ke, view)
}

unsafe fn payload(bytes: &[u8]) -> z_owned_bytes_t {
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_buf(&mut payload, bytes.as_ptr(), bytes.len()),
        Z_OK
    );
    payload
}

#[test]
#[ignore = "a profiling harness, not a check; run it under callgrind with --toggle-collect=z_publisher_put"]
fn profile_the_declared_publisher_put_loop() {
    let n: usize = std::env::var("WZ_PUT_N")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    let port = free_port();
    // SAFETY: fresh configs and sessions, closed at the end.
    unsafe {
        let listener = open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ]);
        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::into_raw(hits.clone()) as *mut c_void;
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let (_bench_text, bench) = view("bench/**");
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut sub,
                z_view_keyexpr_loan(&bench),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let client = open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ]);

        // The subscription has to be known to the client first, by a put that is NOT the
        // counted call: `z_put` on another key of the same subscription.
        let (_warm_text, warm) = view("bench/warm");
        let deadline = Instant::now() + Duration::from_secs(60);
        while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            let mut bytes = payload(b"warm");
            assert_eq!(
                z_put(
                    z_session_loan(&client),
                    z_view_keyexpr_loan(&warm),
                    (&mut bytes as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                    std::ptr::null_mut(),
                ),
                Z_OK
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            hits.load(Ordering::SeqCst) > 0,
            "the subscription never reached the client"
        );
        std::thread::sleep(Duration::from_millis(300));
        let before = hits.load(Ordering::SeqCst);

        let (_key_text, key) = view("bench/data");
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&client),
                &mut publisher,
                z_view_keyexpr_loan(&key),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let body = [7u8; 64];
        for i in 0..n {
            let mut bytes = payload(&body);
            assert_eq!(
                z_publisher_put(
                    z_publisher_loan(&publisher),
                    (&mut bytes as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                    std::ptr::null_mut(),
                ),
                Z_OK
            );
            // Let the receiver catch up every hundred puts, OUTSIDE the counted call. A sender
            // that runs ahead of a receiver (valgrind runs the threads one at a time, so under
            // it the receiver is far behind) fills the link's queue and waits for room INSIDE
            // `z_publisher_put`, and those instructions are counted: the first profile of this
            // loop read 9,150 instructions a put that way, most of them the wait.
            if (i + 1) % 100 == 0 {
                let deadline = Instant::now() + Duration::from_secs(120);
                while hits.load(Ordering::SeqCst) < before + i + 1 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        // Every put arrived: a profile of puts that were dropped is a profile of nothing.
        let deadline = Instant::now() + Duration::from_secs(120);
        while hits.load(Ordering::SeqCst) < before + n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before + n,
            "a counted put did not arrive"
        );

        let _ = z_undeclare_publisher(
            (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
        );
        close_session(client);
        close_session(listener);
        drop(Arc::from_raw(ctx as *const AtomicUsize));
    }
}
