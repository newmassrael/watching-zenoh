// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A build without the `peer` feature is the client's, and says so at `z_open`: a config that
//! asks for a listener, or for `mode=peer`, is refused with `Z_ERR_INVALID` before any thread or
//! socket exists, and is not run as the client it was not asked to be.
//!
//! The file compiles to nothing in a build that has `peer`: there the same configs open, and
//! `listen_and_connect` and `listener_multipeer` read what they do.
#![cfg(not(feature = "peer"))]

use std::ffi::CString;

use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY,
    Z_CONFIG_MODE_KEY, Z_ERR_INVALID, Z_OK,
};

/// `z_open` over a config with the given `(key, value)` entries; the code it returned.
unsafe fn open_code(entries: &[(u8, &str)]) -> i8 {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let value = CString::new(*value).unwrap();
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), *key, value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    z_open(&mut session, z_config_move(&mut cfg), std::ptr::null())
}

#[test]
fn a_listen_endpoint_is_refused() {
    let code = unsafe { open_code(&[(Z_CONFIG_LISTEN_KEY, "tcp/127.0.0.1:0")]) };
    assert_eq!(code, Z_ERR_INVALID);
}

#[test]
fn a_listen_beside_a_connect_is_refused() {
    let code = unsafe {
        open_code(&[
            (Z_CONFIG_LISTEN_KEY, "tcp/127.0.0.1:0"),
            (Z_CONFIG_CONNECT_KEY, "tcp/127.0.0.1:1"),
        ])
    };
    assert_eq!(code, Z_ERR_INVALID);
}

#[test]
fn the_peer_mode_is_refused() {
    let code = unsafe {
        open_code(&[
            (Z_CONFIG_MODE_KEY, "peer"),
            (Z_CONFIG_CONNECT_KEY, "tcp/127.0.0.1:1"),
        ])
    };
    assert_eq!(code, Z_ERR_INVALID);
}

/// The refusal is the role's and not the endpoint's: a client that is asked to dial a port
/// nothing listens on reaches the dial and fails there, with the open's own code and not the
/// config's.
#[test]
fn a_client_dial_is_not_refused_by_the_build() {
    let code = unsafe { open_code(&[(Z_CONFIG_CONNECT_KEY, "tcp/127.0.0.1:1")]) };
    assert_ne!(code, Z_OK);
    assert_ne!(code, Z_ERR_INVALID);
}
