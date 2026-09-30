// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` — the encoding a querier is DECLARED with is the
//! default encoding of the value of every get through it, measured over TCP
//! between two sessions and read off the query a peer's queryable receives.
//!
//! ## What this exists to catch
//!
//! pico keeps the encoding in the querier (`vendor/zenoh-pico/src/net/primitives.c` @
//! `querier->_encoding = encoding == NULL ? _z_encoding_null() : _z_encoding_steal(encoding);`)
//! and a `z_querier_get` that names none of its own sends the query with it
//! (`vendor/zenoh-pico/src/api/api.c` @ `&querier->_encoding);  // it is safe to use alias`).
//! `z_querier_get_options_t` has an encoding of its own, which wins; the declared
//! one is what a program that always sends the same kind of value sets once.
//! `z_declare_querier` here never read `z_querier_options_t::encoding`, so a
//! program that declared it sent every value with none, and neither a link nor
//! a delivery shows that.
//!
//! ## The arms
//!
//! ARM 1 declares a querier with an encoding and gets without one of the get's
//! own: the queryable reads the declared encoding. ARM 2 gets with an encoding of
//! its own on the same querier: the queryable reads THAT one, so the declared
//! encoding is a default and not an override. ARM 3 is the negative arm, a
//! querier declared with NULL options: the queryable reads no encoding, which is
//! what stops ARM 1 passing for a build that stamped one on every query.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query, z_closure_reply,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_querier, z_declare_queryable,
    z_encoding_from_str, z_encoding_move, z_encoding_to_string, z_internal_encoding_check,
    z_loaned_query_t, z_loaned_reply_t, z_open, z_owned_config_t, z_owned_encoding_t,
    z_owned_querier_t, z_owned_queryable_t, z_owned_session_t, z_querier_get,
    z_querier_get_options_default, z_querier_get_options_t, z_querier_loan, z_querier_move,
    z_querier_options_default, z_querier_options_t, z_query_reply, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_undeclare_querier, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The encoding each query carried, rendered as the string a C program reads
/// with `z_encoding_to_string`, or `None` when it carried none.
type Seen = Option<String>;

struct QueryCtx {
    seen: Arc<Mutex<Vec<Seen>>>,
}

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const QueryCtx);
    let enc = wz_capi_pico::z_query_encoding(query);
    let rendered = if enc.is_null() {
        None
    } else {
        let mut out: wz_capi_pico::z_owned_string_t = std::mem::zeroed();
        assert_eq!(z_encoding_to_string(enc, &mut out), Z_OK);
        let loaned = wz_capi_pico::z_string_loan(&out);
        let text = std::str::from_utf8(std::slice::from_raw_parts(
            wz_capi_pico::z_string_data(loaned).cast::<u8>(),
            wz_capi_pico::z_string_len(loaned),
        ))
        .unwrap_or("")
        .to_owned();
        wz_capi_pico::z_string_drop(wz_capi_pico::z_string_move(&mut out));
        Some(text)
    };
    ctx.seen.lock().unwrap().push(rendered);

    // Answer, so the getter's registry closes out rather than waiting on a
    // timeout: the query's own encoding is what this fixture measures.
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qe".as_ptr()), Z_OK);
    let mut payload = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, c"ack".as_ptr()), Z_OK);
    z_query_reply(
        query,
        z_view_keyexpr_loan(&ke),
        z_bytes_move(&mut payload),
        std::ptr::null(),
    );
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, _ctx: *mut c_void) {}

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

unsafe fn declare_querier(
    session: &z_owned_session_t,
    options: *mut z_querier_options_t,
) -> z_owned_querier_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qe".as_ptr()), Z_OK);
    let mut querier: z_owned_querier_t = std::mem::zeroed();
    assert_eq!(
        z_declare_querier(
            z_session_loan(session),
            &mut querier,
            z_view_keyexpr_loan(&ke),
            options,
        ),
        Z_OK
    );
    querier
}

/// One get through `querier`, with `own_encoding` as the get's own when given.
unsafe fn get(querier: &z_owned_querier_t, own_encoding: Option<&mut z_owned_encoding_t>) {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), None, std::ptr::null_mut()),
        Z_OK
    );
    let mut options: z_querier_get_options_t = std::mem::zeroed();
    z_querier_get_options_default(&mut options);
    if let Some(own) = own_encoding {
        options.encoding = z_encoding_move(own).cast();
    }
    assert_eq!(
        z_querier_get(
            z_querier_loan(querier),
            std::ptr::null(),
            wz_capi_pico::z_closure_reply_move(&mut closure),
            &mut options,
        ),
        Z_OK
    );
}

fn wait_for(seen: &Arc<Mutex<Vec<Seen>>>, n: usize) -> Vec<Seen> {
    for _ in 0..250 {
        if seen.lock().unwrap().len() >= n {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), n, "expected {n} queries, got {got:?}");
    got
}

#[test]
fn a_querier_declared_with_an_encoding_sends_it_as_the_default_of_every_get() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut responder = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open");

        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let qctx = Box::into_raw(Box::new(QueryCtx { seen: seen.clone() })).cast::<c_void>();
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let mut qclosure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut qclosure, Some(on_query), None, qctx),
            Z_OK
        );
        let mut qke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut qke, c"demo/qe".as_ptr()), Z_OK);
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

        // A querier declared with an encoding, moved in as a C program does.
        let mut declared_encoding: z_owned_encoding_t = std::mem::zeroed();
        assert_eq!(
            z_encoding_from_str(&mut declared_encoding, c"text/plain".as_ptr()),
            Z_OK
        );
        let mut options: z_querier_options_t = std::mem::zeroed();
        z_querier_options_default(&mut options);
        options.encoding = z_encoding_move(&mut declared_encoding).cast();
        let mut declared = declare_querier(&getter, &mut options);
        assert!(
            !z_internal_encoding_check(&declared_encoding),
            "the declare must consume the options' moved encoding, as pico's steals it"
        );

        // Republish until the queryable's declaration has propagated, then forget
        // what crossed.
        for _ in 0..250 {
            if !seen.lock().unwrap().is_empty() {
                break;
            }
            get(&declared, None);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !seen.lock().unwrap().is_empty(),
            "CALIBRATION FAILED: no query reached the queryable at all, so nothing \
             below measures the declared encoding"
        );
        std::thread::sleep(Duration::from_millis(300));
        seen.lock().unwrap().clear();

        // ARM 1 - a get with no encoding of its own.
        get(&declared, None);
        // ARM 2 - a get with one, on the same querier.
        let mut own: z_owned_encoding_t = std::mem::zeroed();
        assert_eq!(
            z_encoding_from_str(&mut own, c"application/json".as_ptr()),
            Z_OK
        );
        let after_first = wait_for(&seen, 1);
        get(&declared, Some(&mut own));
        let got = wait_for(&seen, 2);
        assert_eq!(after_first[0], Some(String::from("text/plain")));
        assert_eq!(
            got[0],
            Some(String::from("text/plain")),
            "a get with no encoding of its own is sent with the querier's declared one"
        );
        assert_eq!(
            got[1],
            Some(String::from("application/json")),
            "a get's own encoding wins: the declared one is a default and not an override"
        );

        // ARM 3 - the negative arm: a querier declared with nothing.
        seen.lock().unwrap().clear();
        let mut plain = declare_querier(&getter, std::ptr::null_mut());
        get(&plain, None);
        let got = wait_for(&seen, 1);
        assert_eq!(
            got[0], None,
            "a querier declared with NULL options sends no encoding: ARM 1 measured the \
             option and not something the runtime stamps on every query"
        );

        z_undeclare_querier(z_querier_move(&mut plain));
        z_undeclare_querier(z_querier_move(&mut declared));
        wz_capi_pico::z_undeclare_queryable(wz_capi_pico::z_queryable_move(&mut queryable));
        z_close(z_session_loan_mut(&mut getter), std::ptr::null());
        z_close(z_session_loan_mut(&mut responder), std::ptr::null());
        z_session_drop(z_session_move(&mut getter));
        z_session_drop(z_session_move(&mut responder));
    }
}
