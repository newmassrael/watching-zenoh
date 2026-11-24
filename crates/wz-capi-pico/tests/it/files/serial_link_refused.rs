// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "peer",
    not(feature = "transport-link-serial"),
    not(feature = "engine-tokio")
))]

//! A `serial/` endpoint in a cooperative library built without `transport-link-serial`: no link
//! of the build opens one, so a session that listens on one, or dials one, does not open, as a
//! zenoh-pico build without `Z_FEATURE_LINK_SERIAL` does not. The build with the feature carries
//! the link (`serial_link_roundtrip`).
//!
//! RED reproduction: hand the open of every build the host's ttys beside its sockets
//! (`coop_host::with_serial` in `open_on_coop` without its `cfg`), and the listen below opens.

use std::ffi::CStr;

use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// What `z_open` answered for a config that states `endpoint` under `key` and nothing else.
fn open_code(key: u8, endpoint: &CStr) -> i8 {
    // SAFETY: a fresh config, moved into the open, and a session the failed open left unopened.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null())
    }
}

/// Neither role opens over a `serial/` endpoint: the listener has no link to listen on it with,
/// and the dial none to dial it with. Turned red by a build that links the serial opener whatever
/// its features.
#[test]
fn a_serial_endpoint_opens_no_session_without_the_feature() {
    for (key, role) in [
        (Z_CONFIG_LISTEN_KEY, "listen"),
        (Z_CONFIG_CONNECT_KEY, "connect"),
    ] {
        assert_ne!(
            open_code(key, c"serial//dev/ttyS0#baudrate=9600"),
            Z_OK,
            "a {role} on a serial endpoint opened in a build without serial links"
        );
    }
}
