// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Every door that declares or sends a key a program hands it refuses a key not in canon form
//! with `Z_EINVAL`, the code the checked view constructor answers, through the exported `z_*`
//! symbols. Only an unchecked view can hold such a key; zenoh-pico declares and sends whatever
//! text it holds, and wz does not follow that gap. The CONTROL of each door is the same key in
//! canon form, made the same way, so a refusal is the text's and not the view's.
//!
//! ```text
//! cargo test -p wz-capi-pico --features object-pool --test it files::noncanon_keys_refused::
//! ```
#![cfg(feature = "peer")]

use std::ffi::{c_void, CStr, CString};

use wz_capi_pico::abi::z_owned_keyexpr_t;
use wz_capi_pico::result::Z_EINVAL;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_closure_sample, z_closure_sample_move, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_keyexpr, z_declare_publisher, z_declare_subscriber,
    z_delete, z_internal_keyexpr_check, z_keyexpr_drop, z_keyexpr_move, z_loaned_sample_t, z_open,
    z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t, z_owned_publisher_t,
    z_owned_session_t, z_owned_subscriber_t, z_publisher_drop, z_publisher_move, z_put,
    z_session_drop, z_session_loan, z_session_move, z_subscriber_move, z_undeclare_subscriber,
    z_view_keyexpr_from_str, z_view_keyexpr_from_str_unchecked, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, ZResult, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// Keys not in canon form, each for a cause of its own: an empty chunk, a lone `$*` chunk and a
/// `*` after `**` (key expressions canonizing would rewrite), and a trailing `/`.
const NOT_CANON: [&CStr; 4] = [
    c"canon/door//a",
    c"canon/door/$*",
    c"canon/door/**/*",
    c"canon/door/a/",
];

/// The control: a key in canon form.
const CANON: &CStr = c"canon/door/a";

/// A peer that listens on a port of its own and dials nobody.
unsafe fn open_listening() -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_MODE_KEY,
            c"peer".as_ptr()
        ),
        Z_OK
    );
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            endpoint.as_ptr()
        ),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

/// A view over `text` made without the check, as a program that asserts its key is canon makes
/// one.
unsafe fn unchecked(text: &CStr) -> z_view_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    z_view_keyexpr_from_str_unchecked(&mut view, text.as_ptr());
    view
}

/// Each key of [`NOT_CANON`], which the checked view refuses, is refused by `door` with
/// `Z_EINVAL`; the CONTROL, [`CANON`] made the same way, is taken. `door` answers its code and
/// lets go of whatever it made.
unsafe fn refuses_unless_canon(name: &str, door: impl Fn(&z_view_keyexpr_t) -> ZResult) {
    for text in NOT_CANON {
        let mut checked: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut checked, text.as_ptr()),
            Z_EINVAL,
            "{text:?}: the checked view refuses it"
        );
        assert_eq!(door(&unchecked(text)), Z_EINVAL, "{name}: {text:?}");
    }
    assert_eq!(door(&unchecked(CANON)), Z_OK, "{name}: CONTROL {CANON:?}");
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, _context: *mut c_void) {}

/// A closure that does nothing with what it is handed.
unsafe fn sample_closure() -> z_owned_closure_sample_t {
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut()),
        Z_OK
    );
    closure
}

/// A keyexpr declaration refuses a key not in canon form and leaves its destination null.
/// Turned red by `z_declare_keyexpr` reading the key without the gate.
#[test]
fn a_keyexpr_declaration_refuses_a_key_not_in_canon_form() {
    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_declare_keyexpr", |key| {
            let mut declared: z_owned_keyexpr_t = std::mem::zeroed();
            let code = z_declare_keyexpr(
                z_session_loan(&session),
                &mut declared,
                z_view_keyexpr_loan(key),
            );
            if code == Z_OK {
                z_keyexpr_drop(z_keyexpr_move(&mut declared));
            } else {
                assert!(!z_internal_keyexpr_check(&declared), "left null");
            }
            code
        });
        z_session_drop(z_session_move(&mut session));
    }
}

/// A put and a delete on a key not in canon form are refused and send nothing. Turned red by the
/// publish body reading the key without the key judgement.
#[test]
fn a_put_and_a_delete_refuse_a_key_not_in_canon_form() {
    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_put", |key| {
            let mut payload: z_owned_bytes_t = std::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"x".as_ptr()), Z_OK);
            z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(key),
                z_bytes_move(&mut payload),
                std::ptr::null(),
            )
        });
        refuses_unless_canon("z_delete", |key| {
            z_delete(
                z_session_loan(&session),
                z_view_keyexpr_loan(key),
                std::ptr::null(),
            )
        });
        z_session_drop(z_session_move(&mut session));
    }
}

/// A publisher and a subscriber on a key not in canon form are refused before anything is
/// declared. Turned red by `z_declare_publisher` reading the key without the gate.
#[test]
fn a_publisher_and_a_subscriber_refuse_a_key_not_in_canon_form() {
    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_declare_publisher", |key| {
            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            let code = z_declare_publisher(
                z_session_loan(&session),
                &mut publisher,
                z_view_keyexpr_loan(key),
                std::ptr::null(),
            );
            if code == Z_OK {
                z_publisher_drop(z_publisher_move(&mut publisher));
            }
            code
        });
        refuses_unless_canon("z_declare_subscriber", |key| {
            let mut closure = sample_closure();
            let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
            let code = z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(key),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            );
            if code == Z_OK {
                assert_eq!(
                    z_undeclare_subscriber(z_subscriber_move(&mut subscriber)),
                    Z_OK
                );
            }
            code
        });
        z_session_drop(z_session_move(&mut session));
    }
}

/// A queryable on a key not in canon form is refused before anything is declared.
#[cfg(feature = "queryable")]
#[test]
fn a_queryable_refuses_a_key_not_in_canon_form() {
    use wz_capi_pico::{
        z_closure_query, z_closure_query_move, z_declare_queryable, z_loaned_query_t,
        z_owned_closure_query_t, z_owned_queryable_t, z_queryable_move, z_undeclare_queryable,
    };

    unsafe extern "C" fn on_query(_query: *const z_loaned_query_t, _context: *mut c_void) {}

    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_declare_queryable", |key| {
            let mut closure: z_owned_closure_query_t = std::mem::zeroed();
            assert_eq!(
                z_closure_query(&mut closure, Some(on_query), None, std::ptr::null_mut()),
                Z_OK
            );
            let mut queryable: z_owned_queryable_t = std::mem::zeroed();
            let code = z_declare_queryable(
                z_session_loan(&session),
                &mut queryable,
                z_view_keyexpr_loan(key),
                z_closure_query_move(&mut closure),
                std::ptr::null(),
            );
            if code == Z_OK {
                assert_eq!(
                    z_undeclare_queryable(z_queryable_move(&mut queryable)),
                    Z_OK
                );
            }
            code
        });
        z_session_drop(z_session_move(&mut session));
    }
}

/// A get and a querier on a key not in canon form are refused and ask nothing.
#[cfg(feature = "query")]
#[test]
fn a_get_and_a_querier_refuse_a_key_not_in_canon_form() {
    use wz_capi_pico::{
        z_closure_reply, z_closure_reply_move, z_declare_querier, z_get, z_loaned_reply_t,
        z_owned_closure_reply_t, z_owned_querier_t, z_querier_move, z_undeclare_querier,
    };

    unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, _context: *mut c_void) {}

    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_get", |key| {
            let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
            assert_eq!(
                z_closure_reply(&mut closure, Some(on_reply), None, std::ptr::null_mut()),
                Z_OK
            );
            z_get(
                z_session_loan(&session),
                z_view_keyexpr_loan(key),
                std::ptr::null(),
                z_closure_reply_move(&mut closure),
                std::ptr::null_mut(),
            )
        });
        refuses_unless_canon("z_declare_querier", |key| {
            let mut querier: z_owned_querier_t = std::mem::zeroed();
            let code = z_declare_querier(
                z_session_loan(&session),
                &mut querier,
                z_view_keyexpr_loan(key),
                std::ptr::null_mut(),
            );
            if code == Z_OK {
                assert_eq!(z_undeclare_querier(z_querier_move(&mut querier)), Z_OK);
            }
            code
        });
        z_session_drop(z_session_move(&mut session));
    }
}

/// A liveliness token and a liveliness subscriber on a key not in canon form are refused before
/// anything is declared. Turned red by either door reading the key without the gate.
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_token_and_subscriber_refuse_a_key_not_in_canon_form() {
    use wz_capi_pico::liveliness::{
        z_liveliness_declare_subscriber, z_liveliness_declare_token, z_liveliness_token_drop,
        z_liveliness_token_move, z_owned_liveliness_token_t,
    };

    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        refuses_unless_canon("z_liveliness_declare_token", |key| {
            let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
            let code = z_liveliness_declare_token(
                z_session_loan(&session),
                &mut token,
                z_view_keyexpr_loan(key),
                std::ptr::null(),
            );
            if code == Z_OK {
                z_liveliness_token_drop(z_liveliness_token_move(&mut token));
            }
            code
        });
        refuses_unless_canon("z_liveliness_declare_subscriber", |key| {
            let mut closure = sample_closure();
            let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
            let code = z_liveliness_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(key),
                z_closure_sample_move(&mut closure),
                std::ptr::null_mut(),
            );
            if code == Z_OK {
                assert_eq!(
                    z_undeclare_subscriber(z_subscriber_move(&mut subscriber)),
                    Z_OK
                );
            }
            code
        });
        z_session_drop(z_session_move(&mut session));
    }
}
