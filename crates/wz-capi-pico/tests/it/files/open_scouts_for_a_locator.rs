// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A `z_open` whose config names no locator scouts for one, as pico's `_z_open` does
//! (`vendor/zenoh-pico/src/net/session.c` @
//! `ret = _z_locators_by_scout(config, zid, &connect_locators);`), and fails with
//! `_Z_ERR_SCOUT_NO_RESULTS` when nobody answers within the scouting budget. It used to be
//! refused at once with `Z_ERR_INVALID`, which is how upstream's own tests of the local
//! switches, opening with `z_config_default` beside a router, failed on wz.
//!
//! The answering side is upstream's own: `pico_local_delivery_upstream_tests_on_wz` opens
//! both of its sessions this way and finds a zenohd.
#![cfg(feature = "scout")]

use std::ffi::CString;
use std::time::{Duration, Instant};

use wz_capi_pico::result::Z_ERR_SCOUT_NO_RESULTS;
use wz_capi_pico::scout::{Z_CONFIG_MULTICAST_LOCATOR_KEY, Z_CONFIG_SCOUTING_TIMEOUT_KEY};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, zp_config_insert, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The scouting budget the config states.
const BUDGET: Duration = Duration::from_millis(300);

#[test]
fn an_open_with_no_locator_scouts_and_fails_when_nobody_answers() {
    // A group and port nobody else on the host scouts on, so no node can answer.
    let group = CString::new(format!("udp/224.0.0.225:{}", free_port())).unwrap();
    let budget = CString::new(BUDGET.as_millis().to_string()).unwrap();
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        for (key, value) in [
            (Z_CONFIG_MULTICAST_LOCATOR_KEY, &group),
            (Z_CONFIG_SCOUTING_TIMEOUT_KEY, &budget),
        ] {
            assert_eq!(
                zp_config_insert(z_config_loan_mut(&mut cfg), key, value.as_ptr()),
                Z_OK
            );
        }
        let mut session: z_owned_session_t = std::mem::zeroed();
        let started = Instant::now();
        let code = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
        assert_eq!(code, Z_ERR_SCOUT_NO_RESULTS);
        assert!(
            started.elapsed() >= BUDGET,
            "the open answered after {:?}, inside the {BUDGET:?} budget, so it did not scout",
            started.elapsed()
        );
    }
}
