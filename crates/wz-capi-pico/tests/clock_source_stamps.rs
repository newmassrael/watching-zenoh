// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A clock a C program registers is the clock `z_timestamp_new` stamps with
//! (`docs/observation-plane.md` M1, the `clock-source` capability).
//!
//! One test, in a process of its own, because the registry is the process's: the arms run in
//! order against it, and a second test in this binary would see what the first registered.
//!
//! * ARM 1, nothing registered: the stamp is the system clock's, as it always was.
//! * ARM 2, a clock registered: the stamp carries that clock's seconds, and two stamps made while
//!   the clock stands still still strictly increase.
//! * ARM 3, the registered clock cannot say what time it is: there is no stamp to give, and the
//!   system clock is not the fallback of a clock the program chose.
//! * ARM 4, the clock removed: the system clock again.

#![cfg(feature = "clock-source")]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};

use wz_capi_pico::clock_source::{
    wz_ext_clock_read_fn, wz_ext_clock_report, wz_ext_clock_source_register,
    wz_ext_clock_source_unregister, WZ_EXT_CLOCK_SYNC_ACQUIRED,
};
use wz_capi_pico::pubsub::{z_timestamp_new, z_timestamp_ntp64_time, z_timestamp_t};
use wz_capi_pico::result::{Z_ERR_GENERIC, Z_ERR_INVALID, Z_OK};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY,
};
use wz_runtime_tokio_test_support::free_port;

/// The seconds the registered clock reads, or 0 for a clock that is not set. Set ahead of the
/// system clock because a session's stamps never go back: a clock behind the last stamp is
/// stamped over, not followed.
static CLOCK_SECS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn read_clock(_context: *mut c_void, secs: *mut u64, nanos: *mut u32) -> i8 {
    let at = CLOCK_SECS.load(Ordering::SeqCst);
    if at == 0 {
        return -1;
    }
    *secs = at;
    *nanos = 0;
    0
}

unsafe fn open_alone() -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
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
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

/// A timestamp from the session, or the code `z_timestamp_new` refused with.
unsafe fn stamp(session: &z_owned_session_t) -> Result<u64, i8> {
    let mut ts: z_timestamp_t = std::mem::zeroed();
    match z_timestamp_new(&mut ts, z_session_loan(session)) {
        Z_OK => Ok(z_timestamp_ntp64_time(&ts)),
        code => Err(code),
    }
}

#[test]
fn a_registered_clock_is_the_clock_z_timestamp_new_stamps_with() {
    const AHEAD: u64 = 4_000_000_000;
    unsafe {
        let mut session = open_alone();

        // ARM 1
        let system = stamp(&session).expect("the system clock stamps");
        assert!(
            system >> 32 > 1_700_000_000 && system >> 32 < AHEAD,
            "the system clock's seconds, not any registered one's: {}",
            system >> 32
        );

        // ARM 2
        CLOCK_SECS.store(AHEAD, Ordering::SeqCst);
        let read: wz_ext_clock_read_fn = read_clock;
        let mut handle = 0u32;
        assert_eq!(
            wz_ext_clock_source_register(Some(read), std::ptr::null_mut(), &mut handle),
            Z_OK
        );
        let first = stamp(&session).expect("the registered clock stamps");
        let second = stamp(&session).expect("and again");
        assert_eq!(first >> 32, AHEAD, "the registered clock's seconds");
        assert!(second > first, "a clock that stands still still counts up");
        assert_eq!(wz_ext_clock_report(WZ_EXT_CLOCK_SYNC_ACQUIRED), Z_OK);

        // ARM 3
        CLOCK_SECS.store(0, Ordering::SeqCst);
        assert_eq!(
            stamp(&session),
            Err(Z_ERR_GENERIC),
            "a registered clock that cannot say the time leaves no stamp, and no fallback"
        );

        // ARM 4
        assert_eq!(wz_ext_clock_source_unregister(handle), Z_OK);
        assert_eq!(wz_ext_clock_source_unregister(handle), Z_ERR_INVALID);
        let back = stamp(&session).expect("the system clock again");
        assert!(back >> 32 > 1_700_000_000 && back >> 32 < AHEAD);

        z_session_drop(z_session_move(&mut session));
    }
}
