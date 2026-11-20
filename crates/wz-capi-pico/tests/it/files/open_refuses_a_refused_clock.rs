// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A pico session always has a clock of its own (its advanced publisher and `z_timestamp_new`
//! stamp with it), and the open refuses a session whose clock was refused: `UHLC_MAX_DELTA_MS`
//! stating a bound the clock does not honour fails `z_open` with
//! `_Z_ERR_CONFIG_INVALID_VALUE`, and opens nothing. Under the build's own bound the same open
//! succeeds, which is the control. Each open runs in a child process of this test binary,
//! because the variable is the process's: set in this one, it would refuse the clock of every
//! test running beside it.
#![cfg(all(feature = "peer", any(feature = "advanced", feature = "clock-source")))]

use std::ffi::CString;

use wz_capi_pico::result::{Z_ERR_CONFIG_INVALID_VALUE, Z_OK};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_internal_session_check, z_open,
    z_owned_config_t, z_owned_session_t, z_session_drop, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY,
};
use wz_runtime_tokio_test_support::free_port;

/// Set on the child process: it opens and prints what came of it.
const CHILD: &str = "WZ_CAPI_PICO_CLOCK_BOUND_CHILD";

const NAME: &str =
    "files::open_refuses_a_refused_clock::a_session_whose_clock_bound_is_refused_does_not_open";

/// A peer listening on a port of its own: what `z_open` answered, and whether a session was made.
fn open_alone() -> (i8, bool) {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
    // SAFETY: live locals, handed to the doors as they document.
    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        let code = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
        let made = z_internal_session_check(&session);
        if made {
            z_session_drop(z_session_move(&mut session));
        }
        (code, made)
    }
}

/// What the open came to in a child process whose `UHLC_MAX_DELTA_MS` is `stated`.
fn open_under(stated: &str) -> String {
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("UHLC_MAX_DELTA_MS", stated)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the open in a process of its own");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the child under `{stated}` failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("CLOCK-BOUND-OPEN "))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("the child under `{stated}` ran no open:\n{stdout}"))
}

#[test]
fn a_session_whose_clock_bound_is_refused_does_not_open() {
    if std::env::var_os(CHILD).is_some() {
        let (code, made) = open_alone();
        println!("CLOCK-BOUND-OPEN {code} {made}");
        return;
    }
    assert_eq!(
        open_under("soon"),
        format!("{Z_ERR_CONFIG_INVALID_VALUE} false"),
        "a refused clock fails the open and leaves no session"
    );
    assert_eq!(
        open_under(&wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS.to_string()),
        format!("{Z_OK} true"),
        "the control: the build's own bound, which every build allows"
    );
}
