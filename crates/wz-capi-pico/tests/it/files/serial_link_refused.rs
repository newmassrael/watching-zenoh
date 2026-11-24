// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "peer",
    not(feature = "transport-link-serial"),
    not(feature = "engine-tokio")
))]

//! A `serial/` endpoint in a cooperative library built without `transport-link-serial`: no link
//! of the build opens one, so a session that listens on one, or dials one, is refused before
//! anything is opened with `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN`, as a zenoh-pico build without
//! `Z_FEATURE_LINK_SERIAL` refuses it (`vendor/zenoh-pico/src/link/link.c` @
//! `ret = _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;`). The build with the feature carries the link
//! (`serial_link_roundtrip`).
//!
//! RED reproduction: answer `serial` as built in every build (`link_built` in
//! `src/endpoint.rs`), and the open reaches the engine, which refuses the endpoint as a link it
//! could not open, `_Z_ERR_TRANSPORT_OPEN_FAILED`.

use std::ffi::CStr;

use wz_capi_pico::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;
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

/// Neither role opens over a `serial/` endpoint, each refused as a scheme the build has no link
/// for. Turned red by a scheme judged built without its link, or by a refusal left to the engine.
#[test]
fn a_serial_endpoint_opens_no_session_without_the_feature() {
    for (key, role) in [
        (Z_CONFIG_LISTEN_KEY, "listen"),
        (Z_CONFIG_CONNECT_KEY, "connect"),
    ] {
        assert_eq!(
            open_code(key, c"serial//dev/ttyS0#baudrate=9600"),
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
            "a {role} on a serial endpoint in a build without serial links"
        );
    }
}
