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
//!
//! A build that scouts over one datagram socket of its stack (`scout-mcu`, the window a Zephyr
//! image scouts with, here over the host's socket on the cooperative engine) opens the same way.
#![cfg(any(feature = "scout", feature = "scout-mcu"))]

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

/// The program's time in nanoseconds, which the test sets and the library reads.
#[cfg(feature = "time-base")]
unsafe extern "C" fn program_now_ns(context: *mut std::ffi::c_void) -> u64 {
    (*(context as *const std::sync::atomic::AtomicU64)).load(std::sync::atomic::Ordering::SeqCst)
}

/// A config moved to the thread that opens it: the open consumes it there.
#[cfg(feature = "time-base")]
struct Handed(z_owned_config_t);

// SAFETY: the config is handed whole to the one thread that opens it, and nothing else uses it.
#[cfg(feature = "time-base")]
unsafe impl Send for Handed {}

#[cfg(feature = "time-base")]
impl Handed {
    /// The config, taken whole on the thread it was handed to.
    fn into_config(self) -> z_owned_config_t {
        self.0
    }
}

/// The same open from a config that names a time base the program supplies: the scouting window
/// is that time's, so it does not end while the program's time stands still, though the wall
/// clock runs three budgets past it, and it ends once that time passes the budget and the
/// program says so.
#[cfg(feature = "time-base")]
#[test]
fn an_open_on_a_time_base_scouts_for_a_budget_of_the_programs_time() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use wz_capi_pico::time_base::{
        wz_ext_config_time_base, wz_ext_owned_time_base_t, wz_ext_time_base_advanced,
        wz_ext_time_base_drop, wz_ext_time_base_loan, wz_ext_time_base_move, wz_ext_time_base_new,
        wz_ext_time_base_t,
    };

    let group = CString::new(format!("udp/224.0.0.225:{}", free_port())).unwrap();
    let budget = CString::new(BUDGET.as_millis().to_string()).unwrap();
    let time = Box::new(AtomicU64::new(0));
    unsafe {
        let mut time_base: wz_ext_owned_time_base_t = std::mem::zeroed();
        let calls = wz_ext_time_base_t {
            context: &*time as *const AtomicU64 as *mut std::ffi::c_void,
            now_ns: Some(program_now_ns),
            drop: None,
        };
        assert_eq!(wz_ext_time_base_new(&mut time_base, &calls), Z_OK);
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
        assert_eq!(
            wz_ext_config_time_base(
                z_config_loan_mut(&mut cfg),
                wz_ext_time_base_loan(&time_base)
            ),
            Z_OK
        );
        let handed = Handed(cfg);
        let opening = std::thread::spawn(move || {
            let mut cfg = handed.into_config();
            let mut session: z_owned_session_t = std::mem::zeroed();
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null())
        });

        std::thread::sleep(BUDGET * 3);
        assert!(
            !opening.is_finished(),
            "the wall clock ended a scouting window of the program's time"
        );
        let budget_ns = u64::try_from(BUDGET.as_nanos()).unwrap();
        time.store(budget_ns + 1_000_000, Ordering::SeqCst);
        assert_eq!(
            wz_ext_time_base_advanced(wz_ext_time_base_loan(&time_base)),
            Z_OK
        );
        let told = Instant::now();
        while !opening.is_finished() {
            assert!(
                told.elapsed() < Duration::from_secs(5),
                "the window did not end once the program's time passed the budget"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            opening.join().expect("the opening thread"),
            Z_ERR_SCOUT_NO_RESULTS
        );
        wz_ext_time_base_drop(wz_ext_time_base_move(&mut time_base));
    }
    drop(time);
}
