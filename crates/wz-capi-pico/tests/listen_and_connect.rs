// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A pico config that carries BOTH a `listen` and a `connect` endpoint opens one session that
//! listens AND dials.
//!
//! The real zenoh-pico accepts the pair: `_z_locators_by_config` refuses it only in a build with
//! `Z_FEATURE_UNICAST_PEER == 0`, and otherwise forces the mode to peer for any listen config and
//! goes on (`vendor/zenoh-pico/src/net/session.c` @
//! `static z_result_t _z_locators_by_config(`). This ABI refused it with `Z_ERR_INVALID` and a
//! comment calling it a follow-up, though the core has run a session that listens and dials since
//! R3067; the refusal stood for want of a witness, not of a runtime.
//!
//! The rows where the real library is the oracle are in
//! `wz-integration-tests/tests/pico_listen_and_connect_twice_and_diff.rs`; this reads wz alone,
//! through the exported `z_*` symbols as a C program would.

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_ERR_INVALID, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

unsafe extern "C" fn on_sample_record_keyexpr(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
    let ke = z_sample_keyexpr(sample);
    let mut vs: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(ke, &mut vs) == Z_OK {
        let ls = z_view_string_loan(&vs);
        let data = z_string_data(ls);
        let len = z_string_len(ls);
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data as *const u8, len);
            if let Ok(s) = std::str::from_utf8(bytes) {
                ctx.seen.lock().unwrap().insert(s.to_owned());
            }
        }
    }
}

unsafe extern "C" fn on_drop_set(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut SetCtx));
}

/// A config with the given `(key, port)` endpoints, opened. `Ok` is the session, `Err` the code
/// `z_open` returned.
unsafe fn open_with(endpoints: &[(u8, u16)]) -> Result<z_owned_session_t, i8> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, port) in endpoints {
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), *key, endpoint.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    match z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) {
        Z_OK => Ok(session),
        rc => Err(rc),
    }
}

unsafe fn put(session: &z_owned_session_t, keyexpr: &CStr, payload: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut buf),
            std::ptr::null(),
        ),
        Z_OK
    );
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// Put `key` from `from` until `seen` holds it, for at most five seconds.
unsafe fn put_until_seen(
    from: &z_owned_session_t,
    key: &CStr,
    seen: &Arc<Mutex<BTreeSet<String>>>,
) -> bool {
    let wanted = key.to_str().unwrap();
    for _ in 0..250 {
        if seen.lock().unwrap().contains(wanted) {
            return true;
        }
        put(from, key, c"payload");
        std::thread::sleep(Duration::from_millis(20));
    }
    seen.lock().unwrap().contains(wanted)
}

/// One session listens at one endpoint and dials another: it hears the peer it dialled, which is
/// a listener of its own, and the peer that dialled it. A session that did only one of the two
/// would leave one of the samples unheard.
#[test]
fn a_session_that_states_listen_and_connect_listens_and_dials() {
    let (port_listened, port_dialled) = (free_port(), free_port());
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let mut dialled = open_with(&[(Z_CONFIG_LISTEN_KEY, port_dialled)])
            .expect("the listener this session dials opens");
        let mut both = open_with(&[
            (Z_CONFIG_LISTEN_KEY, port_listened),
            (Z_CONFIG_CONNECT_KEY, port_dialled),
        ])
        .unwrap_or_else(|rc| {
            panic!("a config with listen and connect fails the open with {rc} (Z_ERR_INVALID is {Z_ERR_INVALID})")
        });

        let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample_record_keyexpr),
                Some(on_drop_set),
                ctx
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&both),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        let mut dialling_in = open_with(&[(Z_CONFIG_CONNECT_KEY, port_listened)])
            .expect("a peer dials the listener of the session that states both");

        let from_the_dialled = put_until_seen(&dialled, c"demo/from-the-dialled", &seen);
        let from_the_dialling = put_until_seen(&dialling_in, c"demo/from-the-dialling", &seen);

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialling_in);
        close_session(&mut both);
        close_session(&mut dialled);
        assert!(
            from_the_dialled,
            "nothing reached the session from the listener it dialled: it does not dial"
        );
        assert!(
            from_the_dialling,
            "nothing reached the session from the peer that dialled it: it does not listen"
        );
    }
}
