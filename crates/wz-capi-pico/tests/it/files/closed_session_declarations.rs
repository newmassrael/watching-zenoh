// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a declaration asked of a closed session answers, through the exported `z_*` symbols on
//! the cooperative engine: the code zenoh-pico's own door answers there, never `Z_OK` for an
//! entity that would never be served.
//!
//! - A publisher on a key the session declared before it closed shares that declaration and is
//!   refused by its write filter with the generic error, as zenoh-pico's filter reads the
//!   Interest a closed session did not register.
//!
//! ```text
//! cargo test -p wz-capi-pico --no-default-features \
//!     --features engine-coop,peer,multi-thread \
//!     --test it files::closed_session_declarations::
//! ```
#![cfg(all(feature = "engine-coop", feature = "peer", feature = "multi-thread"))]

use std::ffi::CString;

use wz_capi_pico::abi::z_owned_keyexpr_t;
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_declare_keyexpr,
    z_declare_publisher, z_keyexpr_drop, z_keyexpr_loan, z_keyexpr_move, z_open, z_owned_config_t,
    z_owned_publisher_t, z_owned_session_t, z_publisher_drop, z_publisher_move, z_session_drop,
    z_session_loan, z_session_loan_mut, z_session_move, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_LISTEN_KEY,
    Z_CONFIG_MODE_KEY, Z_ERR_GENERIC, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

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

/// The key `text` declared on `session`.
unsafe fn declared_key(session: &z_owned_session_t, text: &std::ffi::CStr) -> z_owned_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, text.as_ptr()), Z_OK);
    let mut declared: z_owned_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_declare_keyexpr(
            z_session_loan(session),
            &mut declared,
            z_view_keyexpr_loan(&view)
        ),
        Z_OK
    );
    declared
}

/// A publisher on `declared`: the code the door answered, and the handle it left.
unsafe fn declare_publisher(
    session: &z_owned_session_t,
    declared: &z_owned_keyexpr_t,
) -> (i8, z_owned_publisher_t) {
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    let code = z_declare_publisher(
        z_session_loan(session),
        &mut publisher,
        z_keyexpr_loan(declared),
        std::ptr::null(),
    );
    (code, publisher)
}

/// A publisher on a key the session declared while open, asked once the session is closed, is
/// refused by its write filter with the generic error. The CONTROL is the same publisher declared
/// while the session is open.
#[test]
fn a_publisher_on_a_declared_key_of_a_closed_session_is_refused_by_its_filter() {
    // SAFETY: every handle is made here and let go of once.
    unsafe {
        let mut session = open_listening();
        let mut declared = declared_key(&session, c"closed/decl/pub");
        let (code, mut control) = declare_publisher(&session, &declared);
        assert_eq!(
            code, Z_OK,
            "CONTROL: the open session declares the publisher"
        );
        z_publisher_drop(z_publisher_move(&mut control));

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        let (code, _refused) = declare_publisher(&session, &declared);
        assert_eq!(code, Z_ERR_GENERIC);

        z_keyexpr_drop(z_keyexpr_move(&mut declared));
        z_session_drop(z_session_move(&mut session));
    }
}
