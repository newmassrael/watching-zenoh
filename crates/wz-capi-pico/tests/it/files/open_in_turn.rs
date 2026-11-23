// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Opening sessions of the cooperative engine through the exported `z_*` symbols, in one process,
//! as zenoh-pico's own API tests open them one test after another:
//!
//! - an endpoint with a config pico's TCP link does not read (`#iface=lo`) opens, listening and
//!   dialling, as pico's opens it;
//! - pairs of peers opened and closed in turn, more of them than the host's thread records, each
//!   open, so what a closed session took is given back.
//!
//! ```text
//! cargo test -p wz-capi-pico --no-default-features \
//!     --features engine-coop,peer,multi-thread --test it files::open_in_turn::
//! ```
#![cfg(all(feature = "engine-coop", feature = "peer", feature = "multi-thread"))]

use std::ffi::CString;

use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    ZResult, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// Pairs opened and closed in turn: each pair is two sessions with a read task each, so the
/// rounds start more threads than the host's records hold at once (`wz_host_sync::THREADS`, 64).
const ROUNDS: usize = 40;

/// Open a peer session with `endpoint` under `key`: the session, or the code `z_open` answered.
unsafe fn open(key: u8, endpoint: &str) -> Result<z_owned_session_t, ZResult> {
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
    let endpoint = CString::new(endpoint).unwrap();
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    match z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) {
        Z_OK => Ok(session),
        code => Err(code),
    }
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// A listener and a dialler whose TCP endpoints carry an interface open, as zenoh-pico's do:
/// pico's TCP link reads no `iface` key and stops reading the config there, so the locator is
/// what it listens on and dials. The CONTROL is the same pair without the config.
#[test]
fn an_interface_on_a_tcp_endpoint_opens_as_picos_does() {
    // SAFETY: each session is opened here and closed once.
    unsafe {
        for config in ["", "#iface=lo"] {
            let port = free_port();
            let endpoint = format!("tcp/127.0.0.1:{port}{config}");
            let mut listener = open(Z_CONFIG_LISTEN_KEY, &endpoint)
                .unwrap_or_else(|code| panic!("listening on {endpoint:?}: {code}"));
            let mut dialler = open(Z_CONFIG_CONNECT_KEY, &endpoint)
                .unwrap_or_else(|code| panic!("dialling {endpoint:?}: {code}"));
            close(&mut dialler);
            close(&mut listener);
        }
    }
}

/// Pairs of peers opened and closed in turn, one round after another, all open: a closed
/// session gives back its thread record, its port and its places, so the round past the host's
/// records opens as the first did.
#[test]
fn sessions_opened_and_closed_in_turn_each_open() {
    for round in 0..ROUNDS {
        let endpoint = format!("tcp/127.0.0.1:{}", free_port());
        // SAFETY: each session is opened here and closed once.
        unsafe {
            let mut listener = open(Z_CONFIG_LISTEN_KEY, &endpoint)
                .unwrap_or_else(|code| panic!("round {round}: listening: {code}"));
            let mut dialler = open(Z_CONFIG_CONNECT_KEY, &endpoint)
                .unwrap_or_else(|code| panic!("round {round}: dialling: {code}"));
            close(&mut dialler);
            close(&mut listener);
        }
    }
}
