// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` — the encoding a C program sets on
//! `z_query_reply_err_options_t` goes out with the error and surfaces on a real
//! peer's error reply, measured over TCP between two sessions.
//!
//! ## What this exists to catch
//!
//! `z_query_reply_err` took its options as an unread pointer, so a program that
//! answered a query with an error and named its encoding sent the error with none
//! (and never released the moved encoding, which pico drops:
//! `vendor/zenoh-pico/src/api/api.c` @ `z_encoding_drop(opts.encoding);`). The
//! sibling `z_query_reply` reads the same field on its Put arm, so the two
//! reply forms disagreed about one option depending on which entry point the
//! program used.
//!
//! ## The arms
//!
//! ARM 1 sets an encoding and asserts the getter reads exactly it, with the
//! moved encoding consumed. ARM 2 is the negative arm: the same queryable, an
//! error with NULL options, which arrives and carries no encoding; without it a
//! build that stamped an encoding on every error would pass ARM 1 for a reason
//! that has nothing to do with the option. ARM 3 sets a DIFFERENT encoding, so
//! the value read is the one set and not a constant.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_len, z_bytes_move, z_close, z_closure_query, z_closure_reply,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable, z_encoding_from_str,
    z_encoding_move, z_encoding_to_string, z_get, z_get_options_default, z_get_options_t,
    z_internal_encoding_check, z_loaned_query_t, z_loaned_reply_t, z_open, z_owned_config_t,
    z_owned_encoding_t, z_owned_queryable_t, z_owned_session_t, z_query_reply_err,
    z_query_reply_err_options_default, z_query_reply_err_options_t, z_reply_err,
    z_reply_err_encoding, z_reply_err_payload, z_reply_is_ok, z_session_loan, z_session_move,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// What one error reply carried: its encoding rendered as the string a C
/// program reads with `z_encoding_to_string` (None when it carried none), and
/// the length of its payload.
type Seen = (Option<String>, usize);

struct ReplyCtx {
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// Which error the queryable sends next: one arm per call.
struct QueryCtx {
    arm: Arc<Mutex<u8>>,
}

unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const ReplyCtx);
    if z_reply_is_ok(reply) {
        return;
    }
    let err = z_reply_err(reply);
    assert!(!err.is_null(), "an error reply has an error");
    let enc = z_reply_err_encoding(err);
    let encoding = if enc.is_null() {
        None
    } else {
        let mut rendered: wz_capi_pico::z_owned_string_t = std::mem::zeroed();
        assert_eq!(z_encoding_to_string(enc, &mut rendered), Z_OK);
        let loaned = wz_capi_pico::z_string_loan(&rendered);
        let text = std::str::from_utf8(std::slice::from_raw_parts(
            wz_capi_pico::z_string_data(loaned).cast::<u8>(),
            wz_capi_pico::z_string_len(loaned),
        ))
        .unwrap_or("")
        .to_owned();
        wz_capi_pico::z_string_drop(wz_capi_pico::z_string_move(&mut rendered));
        Some(text)
    };
    let payload_len = z_bytes_len(z_reply_err_payload(err));
    ctx.seen.lock().unwrap().push((encoding, payload_len));
}

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const QueryCtx);
    let mut arm = ctx.arm.lock().unwrap();
    let which = *arm;
    *arm += 1;
    drop(arm);

    let mut payload = std::mem::zeroed();
    match which {
        // ARM 1 - an encoding set; the moved encoding must be consumed.
        0 => {
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"boom".as_ptr()), Z_OK);
            let mut encoding: z_owned_encoding_t = std::mem::zeroed();
            assert_eq!(
                z_encoding_from_str(&mut encoding, c"text/plain".as_ptr()),
                Z_OK
            );
            let mut options: z_query_reply_err_options_t = std::mem::zeroed();
            z_query_reply_err_options_default(&mut options);
            options.encoding = z_encoding_move(&mut encoding).cast();
            assert_eq!(
                z_query_reply_err(query, z_bytes_move(&mut payload), &options),
                Z_OK
            );
            assert!(
                !z_internal_encoding_check(&encoding),
                "z_query_reply_err consumes the options' moved encoding, as pico's \
                 drops it"
            );
        }
        // ARM 2 - the negative arm: NULL options.
        1 => {
            assert_eq!(
                z_bytes_copy_from_str(&mut payload, c"bust!!".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_query_reply_err(query, z_bytes_move(&mut payload), std::ptr::null()),
                Z_OK
            );
        }
        // ARM 3 - a different encoding, with a schema.
        _ => {
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"kaput".as_ptr()), Z_OK);
            let mut encoding: z_owned_encoding_t = std::mem::zeroed();
            assert_eq!(
                z_encoding_from_str(&mut encoding, c"application/json;v1".as_ptr()),
                Z_OK
            );
            let mut options: z_query_reply_err_options_t = std::mem::zeroed();
            z_query_reply_err_options_default(&mut options);
            options.encoding = z_encoding_move(&mut encoding).cast();
            assert_eq!(
                z_query_reply_err(query, z_bytes_move(&mut payload), &options),
                Z_OK
            );
        }
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

/// Issue one get and wait (bounded) for `want` replies to have been recorded.
unsafe fn get_once(session: &z_owned_session_t, seen: &Arc<Mutex<Vec<Seen>>>, want: usize) {
    let ctx = Box::into_raw(Box::new(ReplyCtx { seen: seen.clone() })).cast::<c_void>();
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), None, ctx),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/err".as_ptr()), Z_OK);
    let mut options: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut options);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            wz_capi_pico::z_closure_reply_move(&mut closure),
            &mut options,
        ),
        Z_OK
    );
    for _ in 0..250 {
        if seen.lock().unwrap().len() >= want {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_encoding_of_an_error_reply_crosses_the_wire_and_null_options_leave_it_absent() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut responder = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open");

        let arm = Arc::new(Mutex::new(0u8));
        let qctx = Box::into_raw(Box::new(QueryCtx { arm: arm.clone() })).cast::<c_void>();
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let mut qclosure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut qclosure, Some(on_query), None, qctx),
            Z_OK
        );
        let mut qke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut qke, c"demo/err".as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&responder),
                &mut queryable,
                z_view_keyexpr_loan(&qke),
                wz_capi_pico::z_closure_query_move(&mut qclosure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut getter = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                getter = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut getter = getter.expect("getter z_open never succeeded");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));

        // The first get may land before the queryable declaration has propagated,
        // so retry until SOMETHING comes back - bounded, so a genuine failure
        // still fails fast.
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            *arm.lock().unwrap() = 0;
            seen.lock().unwrap().clear();
            get_once(&getter, &seen, 1);
        }
        assert!(
            !seen.lock().unwrap().is_empty(),
            "CALIBRATION FAILED: no error reply crossed the wire at all, so nothing \
             below measures the encoding option"
        );
        get_once(&getter, &seen, 2);
        get_once(&getter, &seen, 3);

        let got = seen.lock().unwrap().clone();
        assert_eq!(
            got.len(),
            3,
            "one reply per arm reached the getter; got {got:?}"
        );
        assert_eq!(
            got[0],
            (Some(String::from("text/plain")), "boom".len()),
            "an error replied with an encoding carries it"
        );
        assert_eq!(
            got[1],
            (None, "bust!!".len()),
            "an error replied with NULL options carries none: ARM 1 measured the \
             option and not something the runtime stamps on every error"
        );
        assert_eq!(
            got[2],
            (Some(String::from("application/json;v1")), "kaput".len()),
            "the encoding read is the one set, schema and all, and not a constant"
        );

        wz_capi_pico::z_undeclare_queryable(wz_capi_pico::z_queryable_move(&mut queryable));
        wz_capi_pico::z_close(
            wz_capi_pico::z_session_loan_mut(&mut getter),
            std::ptr::null(),
        );
        z_close(
            wz_capi_pico::z_session_loan_mut(&mut responder),
            std::ptr::null(),
        );
        wz_capi_pico::z_session_drop(z_session_move(&mut getter));
        wz_capi_pico::z_session_drop(z_session_move(&mut responder));
    }
}
