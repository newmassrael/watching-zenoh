// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "peer",
    not(all(
        feature = "transport-link-unixpipe",
        any(target_os = "linux", target_os = "android")
    )),
    not(feature = "engine-tokio")
))]

//! A `unixpipe/` endpoint in a cooperative library built without `transport-link-unixpipe`, or
//! with it on a host that has no named FIFO (Windows), where the feature is inert: no link of the
//! build opens one, so a session that listens on one, or dials one, is refused before
//! anything is opened with `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN`, what zenoh-pico answers for a
//! scheme its build has no link for (`vendor/zenoh-pico/src/link/link.c` @
//! `ret = _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;`); pico has no unixpipe link in any build. The
//! build with the feature carries the link (`unixpipe_link_roundtrip`).
//!
//! RED reproduction: answer `unixpipe` as built in every build (`link_built` in
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

/// Neither role opens over a `unixpipe/` endpoint, each refused as a scheme the build has no link
/// for. Turned red by a scheme judged built without its link (the feature named on a host with no
/// named FIFO included), or by a refusal left to the engine.
#[test]
fn a_unixpipe_endpoint_opens_no_session_without_the_feature() {
    let _program = crate::programs::admit();
    for (key, role) in [
        (Z_CONFIG_LISTEN_KEY, "listen"),
        (Z_CONFIG_CONNECT_KEY, "connect"),
    ] {
        assert_eq!(
            open_code(key, c"unixpipe//tmp/wz-pipe"),
            Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
            "a {role} on a unixpipe endpoint in a build without unixpipe links"
        );
    }
}
