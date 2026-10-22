// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! pico's session check (`Z_FEATURE_SESSION_CHECK`, on by default) and the single-threaded
//! entry points, on the drop-in.
//!
//! An entity that outlives its session's `z_close` (a publisher, a querier) is refused with
//! `_Z_ERR_SESSION_CLOSED` rather than answering success into a session that sends nothing;
//! the batch calls answer a null session the same way; and `zp_read`, `zp_send_keep_alive`
//! and `zp_send_join`, which pico declares for its single-threaded headers, answer `Z_OK` on
//! an open session and `_Z_ERR_SESSION_CLOSED` on a closed one.
//!
//! Before this file the publisher half answered `Z_OK` after a close (measured by reading:
//! `z_close` dropped every face and kept the session, and the put path asked nothing about
//! it), which is what open-debt item 916 recorded and asked to be measured first.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};

use wz_capi_pico::session::{
    zp_read, zp_read_options_default, zp_read_options_t, zp_send_join,
    zp_send_join_options_default, zp_send_join_options_t, zp_send_keep_alive,
    zp_send_keep_alive_options_default, zp_send_keep_alive_options_t,
};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_reply, z_closure_reply_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_declare_querier,
    z_loaned_reply_t, z_open, z_owned_bytes_t, z_owned_closure_reply_t, z_owned_config_t,
    z_owned_publisher_t, z_owned_querier_t, z_owned_session_t, z_publisher_delete,
    z_publisher_drop, z_publisher_loan, z_publisher_move, z_publisher_put, z_querier_drop,
    z_querier_get, z_querier_loan, z_querier_move, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_batch_flush, zp_batch_start, zp_batch_stop, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// pico `_Z_ERR_SESSION_CLOSED` (`utils/result.h`).
const SESSION_CLOSED: i8 = -73;

unsafe fn open_role(port: u16, key: u8) -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn payload(text: &std::ffi::CStr) -> z_owned_bytes_t {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut bytes, text.as_ptr()), Z_OK);
    bytes
}

unsafe extern "C" fn ignore_reply(_reply: *mut z_loaned_reply_t, _ctx: *mut c_void) {}

unsafe extern "C" fn count_drop(ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

#[test]
fn a_closed_session_refuses_its_publisher_and_querier() {
    unsafe {
        let port = free_port();
        let mut listener = open_role(port, Z_CONFIG_LISTEN_KEY);
        let mut dialer = open_role(port, Z_CONFIG_CONNECT_KEY);

        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"demo/check".as_ptr()),
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
        let mut querier: z_owned_querier_t = std::mem::zeroed();
        assert_eq!(
            z_declare_querier(
                z_session_loan(&dialer),
                &mut querier,
                z_view_keyexpr_loan(&ke),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        // The control: before the close, the same put succeeds.
        let mut bytes = payload(c"before");
        assert_eq!(
            z_publisher_put(
                z_publisher_loan(&publisher),
                z_bytes_move(&mut bytes),
                std::ptr::null()
            ),
            Z_OK,
            "a put on an open session must succeed, or the refusal below proves nothing"
        );

        assert_eq!(
            z_close(z_session_loan_mut(&mut dialer), std::ptr::null()),
            Z_OK
        );

        let mut bytes = payload(c"after");
        assert_eq!(
            z_publisher_put(
                z_publisher_loan(&publisher),
                z_bytes_move(&mut bytes),
                std::ptr::null()
            ),
            SESSION_CLOSED,
            "a put through a publisher whose session was closed"
        );
        assert_eq!(
            z_publisher_delete(z_publisher_loan(&publisher), std::ptr::null()),
            SESSION_CLOSED,
            "a delete through a publisher whose session was closed"
        );

        // The querier refuses and still runs the closure's drop, as pico's does.
        let drops = Box::leak(Box::new(AtomicUsize::new(0)));
        let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(ignore_reply),
                Some(count_drop),
                drops as *const AtomicUsize as *mut c_void,
            ),
            Z_OK
        );
        assert_eq!(
            z_querier_get(
                z_querier_loan(&querier),
                std::ptr::null(),
                z_closure_reply_move(&mut closure),
                std::ptr::null_mut(),
            ),
            SESSION_CLOSED,
            "a get through a querier whose session was closed"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the refused get must drop its closure"
        );

        // The single-threaded entry points answer the closed session the same way.
        let mut read = zp_read_options_t { single_read: true };
        zp_read_options_default(&mut read);
        assert!(!read.single_read);
        assert_eq!(zp_read(z_session_loan(&dialer), &read), SESSION_CLOSED);

        z_publisher_drop(z_publisher_move(&mut publisher));
        z_querier_drop(z_querier_move(&mut querier));
        z_session_drop(z_session_move(&mut dialer));
        z_session_drop(z_session_move(&mut listener));
    }
}

#[test]
fn the_single_threaded_entry_points_answer_an_open_session() {
    unsafe {
        let port = free_port();
        let mut listener = open_role(port, Z_CONFIG_LISTEN_KEY);
        let session = z_session_loan(&listener);

        let mut read = zp_read_options_t { single_read: true };
        zp_read_options_default(&mut read);
        assert!(!read.single_read, "pico's default reads the whole buffer");
        assert_eq!(zp_read(session, &read), Z_OK);
        assert_eq!(zp_read(session, std::ptr::null()), Z_OK);

        let mut keep_alive = zp_send_keep_alive_options_t { __dummy: 7 };
        zp_send_keep_alive_options_default(&mut keep_alive);
        assert_eq!(keep_alive.__dummy, 0);
        assert_eq!(zp_send_keep_alive(session, &keep_alive), Z_OK);

        let mut join = zp_send_join_options_t { __dummy: 7 };
        zp_send_join_options_default(&mut join);
        assert_eq!(join.__dummy, 0);
        assert_eq!(
            zp_send_join(session, &join),
            Z_OK,
            "upstream answers OK on a unicast transport without sending"
        );

        // A null session is a closed one to all three, and to the batch calls.
        assert_eq!(zp_read(std::ptr::null(), std::ptr::null()), SESSION_CLOSED);
        assert_eq!(
            zp_send_keep_alive(std::ptr::null(), std::ptr::null()),
            SESSION_CLOSED
        );
        assert_eq!(
            zp_send_join(std::ptr::null(), std::ptr::null()),
            SESSION_CLOSED
        );
        assert_eq!(zp_batch_start(std::ptr::null()), SESSION_CLOSED);
        assert_eq!(zp_batch_flush(std::ptr::null()), SESSION_CLOSED);
        assert_eq!(zp_batch_stop(std::ptr::null()), SESSION_CLOSED);

        z_session_drop(z_session_move(&mut listener));
    }
}
