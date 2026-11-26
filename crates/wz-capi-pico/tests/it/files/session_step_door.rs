// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zext_session_step` driven through the exported symbols as a C program drives it: a dialer
//! opened without its read task receives what a listener publishes only through its own steps,
//! a step is refused while the read task runs and steps again once it is stopped, and a closed
//! session refuses it. The tokio engine, which runs every session on a thread of its own, answers
//! the port's refusal of a step, which `wz-capi-port`'s own tests hold.

#![cfg(all(
    feature = "peer",
    feature = "multi-thread",
    not(feature = "engine-tokio")
))]

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_pico::result::{ZResult, ZEXT_ERR_READ_TASK_RUNS, Z_ERR_SESSION_CLOSED};
use wz_capi_pico::session_step::zext_session_step;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_close, z_closure_sample, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_subscriber, z_loaned_sample_t, z_open, z_open_options_default,
    z_open_options_t, z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_put,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, zp_start_read_task, zp_stop_read_task,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The C subscriber callback: count the sample.
unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

/// The C drop callback: let the count go.
unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    drop(Arc::from_raw(ctx as *const AtomicUsize));
}

/// A config of one locator under `key`.
unsafe fn config_of(key: u8, locator: &std::ffi::CStr) -> z_owned_config_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, locator.as_ptr()),
        Z_OK
    );
    cfg
}

/// One step of `session`, waiting for input at most 10 ms.
unsafe fn step(session: &z_owned_session_t) -> ZResult {
    zext_session_step(z_session_loan(session), 10)
}

/// Put `demo/a` on `session` once.
unsafe fn put_once(session: &z_owned_session_t) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/a".as_ptr()), Z_OK);
    let mut payload = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, c"cycle".as_ptr()), Z_OK);
    let _ = z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&ke),
        wz_capi_pico::z_bytes_move(&mut payload),
        std::ptr::null(),
    );
}

#[test]
fn a_session_opened_without_its_read_task_is_stepped_by_the_program() {
    let _program = crate::programs::admit();
    let port = free_port();
    let locator = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: each call is handed what the C API asks of it, as a C program hands it.
    unsafe {
        // The listener runs as the default open runs it, with its read task.
        let mut listener: z_owned_session_t = std::mem::zeroed();
        let cfg = &mut config_of(Z_CONFIG_LISTEN_KEY, &locator);
        assert_eq!(
            z_open(&mut listener, z_config_move(cfg), std::ptr::null()),
            Z_OK
        );

        // The dialer chooses the program's steps at its open.
        let mut options: z_open_options_t = std::mem::zeroed();
        z_open_options_default(&mut options);
        options.auto_start_read_task = false;
        let mut dialer: z_owned_session_t = std::mem::zeroed();
        let cfg = &mut config_of(Z_CONFIG_CONNECT_KEY, &locator);
        assert_eq!(z_open(&mut dialer, z_config_move(cfg), &options), Z_OK);

        let received = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::into_raw(received.clone()) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&dialer),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // Steps carry the declaration out and the samples in; the listener publishes until one is
        // handed over.
        let deadline = Instant::now() + Duration::from_secs(10);
        while received.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "no sample reached the stepped dialer"
            );
            put_once(&listener);
            assert_eq!(step(&dialer), Z_OK, "a session without its read task steps");
        }
        // CONTROL: without a step nothing more is handed to the dialer's subscriber.
        let before = received.load(Ordering::SeqCst);
        put_once(&listener);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            received.load(Ordering::SeqCst),
            before,
            "nothing is handed out between two steps"
        );

        assert_eq!(
            zp_start_read_task(z_session_loan_mut(&mut dialer), std::ptr::null()),
            Z_OK
        );
        assert_eq!(step(&dialer), ZEXT_ERR_READ_TASK_RUNS);
        assert_eq!(zp_stop_read_task(z_session_loan_mut(&mut dialer)), Z_OK);
        assert_eq!(
            step(&dialer),
            Z_OK,
            "the stopped task leaves the steps to the program"
        );

        wz_capi_pico::z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        assert_eq!(
            zext_session_step(z_session_loan(&dialer), 0),
            Z_ERR_SESSION_CLOSED
        );
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
    }
}
