// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session opened through the zenoh-c ABI from a config that names a time base the program
//! supplies (`wz_capi_c_config_time_base`), driven through the exported symbols as a C program
//! would.
//!
//! The client leg is the timer this ABI's opens wait on: a connect budget with a retry schedule,
//! dialled at a port nothing listens on, so the open can end only by the budget. The program's
//! time stands still while the wall clock runs three budgets past it, and the open must not end;
//! the program then moves its time past the budget and says so, and the open must end, refused as
//! a budget that ran out is. A build whose connect wait read the system's clock would end the open
//! after one budget of the wall clock, which the first assertion reads as red.
//!
//! The node leg is the refusal: a node that forwards between its faces is not timed by a time
//! base, so its open from a config that names one is refused, and the same config without one
//! opens.

#![cfg(feature = "time-base")]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::{Z_ENETWORK, Z_OK};
use wz_capi_c::session::{z_open, z_session_drop};
use wz_capi_c::time_base::{
    wz_capi_c_config_time_base, wz_capi_c_owned_time_base_t, wz_capi_c_time_base_advanced,
    wz_capi_c_time_base_drop, wz_capi_c_time_base_loan, wz_capi_c_time_base_move,
    wz_capi_c_time_base_new, wz_capi_c_time_base_t,
};
use wz_runtime_tokio_test_support::free_port;

/// The connect budget of the client leg, in the program's time.
const BUDGET: Duration = Duration::from_millis(1000);

/// The program's time in nanoseconds, which the test sets and the library reads.
unsafe extern "C" fn program_now_ns(context: *mut c_void) -> u64 {
    // SAFETY: the test's own counter, never freed.
    unsafe { (*(context as *const AtomicU64)).load(Ordering::SeqCst) }
}

/// The program's time, starting at zero. Never freed: a thread of a session that is going may
/// still read it after the test has let go of its own reference.
fn program_time() -> &'static AtomicU64 {
    Box::leak(Box::new(AtomicU64::new(0)))
}

/// A time base over `time`.
fn time_base_over(time: &'static AtomicU64) -> wz_capi_c_owned_time_base_t {
    let calls = wz_capi_c_time_base_t {
        context: time as *const AtomicU64 as *mut c_void,
        now_ns: Some(program_now_ns),
        drop: None,
    };
    // SAFETY: a zeroed owned handle is the gravestone the door overwrites.
    let mut time_base: wz_capi_c_owned_time_base_t = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the read's context is never freed and is safe to read from any thread.
    assert_eq!(
        unsafe { wz_capi_c_time_base_new(&mut time_base, &calls) },
        Z_OK
    );
    time_base
}

/// A config with `entries` inserted as json5 values and multicast scouting off, naming
/// `time_base` when one is given.
///
/// # Safety
/// `time_base`, when given, is an owned time base that is live.
unsafe fn config_with(
    entries: &[(&str, String)],
    time_base: Option<&wz_capi_c_owned_time_base_t>,
) -> z_owned_config_t {
    // SAFETY: a zeroed owned config is the gravestone `z_config_default` overwrites.
    let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
    let off = [("scouting/multicast/enabled", String::from("false"))];
    for (key, value) in off.iter().chain(entries) {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        // SAFETY: a live config and two C strings.
        let rc = unsafe {
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr())
        };
        assert_eq!(rc, Z_OK, "{key:?}");
    }
    if let Some(time_base) = time_base {
        // SAFETY: a live config and the caller's live time base.
        let rc = unsafe {
            wz_capi_c_config_time_base(
                z_config_loan_mut(&mut cfg),
                wz_capi_c_time_base_loan(time_base),
            )
        };
        assert_eq!(rc, Z_OK);
    }
    cfg
}

/// Open `cfg`, which the open consumes, returning the result code and the session (its gravestone
/// when the code is not `Z_OK`).
fn open(mut cfg: z_owned_config_t) -> (i8, z_owned_session_t) {
    // SAFETY: a zeroed owned session is the gravestone the open overwrites; the config is live
    // and is consumed here.
    unsafe {
        let mut session: z_owned_session_t = std::mem::zeroed();
        let rc = z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null(),
        );
        (rc, session)
    }
}

/// Close and drop a session; a gravestone drops as a no-op.
fn close(mut session: z_owned_session_t) {
    // SAFETY: the session is owned here.
    unsafe {
        let _ = wz_capi_c::session::z_close(
            wz_capi_c::session::z_session_loan_mut(&mut session),
            std::ptr::null_mut(),
        );
        z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
    }
}

/// A config moved to the thread that opens it: the open consumes it there.
struct Handed(z_owned_config_t);

// SAFETY: the config is handed whole to the one thread that opens it, and nothing else uses it.
unsafe impl Send for Handed {}

impl Handed {
    /// The config, taken whole on the thread it was handed to.
    fn into_config(self) -> z_owned_config_t {
        self.0
    }
}

/// A client's connect budget on a time base is a budget of the program's time: the open does not
/// end while that time stands still, though the wall clock runs three budgets past it, and it ends
/// once the time passes the budget and the program says so, refused as a spent budget is.
#[test]
fn a_clients_connect_budget_on_a_time_base_is_a_budget_of_the_programs_time() {
    let port = free_port();
    let time = program_time();
    let mut time_base = time_base_over(time);
    let entries = [
        ("mode", String::from("\"client\"")),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ("connect/timeout_ms", BUDGET.as_millis().to_string()),
        (
            "connect/retry",
            String::from("{period_init_ms: 100, period_max_ms: 200}"),
        ),
    ];
    // SAFETY: the time base is live.
    let handed = Handed(unsafe { config_with(&entries, Some(&time_base)) });
    let opening = std::thread::spawn(move || {
        let (rc, session) = open(handed.into_config());
        close(session);
        rc
    });

    std::thread::sleep(BUDGET * 3);
    assert!(
        !opening.is_finished(),
        "the wall clock ended a connect budget of the program's time"
    );
    let budget_ns = u64::try_from(BUDGET.as_nanos()).unwrap();
    time.store(budget_ns + 1_000_000, Ordering::SeqCst);
    // SAFETY: the time base is live.
    assert_eq!(
        unsafe { wz_capi_c_time_base_advanced(wz_capi_c_time_base_loan(&time_base)) },
        Z_OK
    );
    let told = Instant::now();
    while !opening.is_finished() {
        assert!(
            told.elapsed() < Duration::from_secs(5),
            "the open did not end once the program's time passed its budget"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(opening.join().expect("the opening thread"), Z_ENETWORK);
    // SAFETY: the program's own reference, dropped once.
    unsafe { wz_capi_c_time_base_drop(wz_capi_c_time_base_move(&mut time_base)) };
}

/// A node that forwards between its faces is not timed by a time base: its open from a config that
/// names one is refused, and the same config without one opens.
#[cfg(feature = "router-node")]
#[test]
fn a_router_on_a_time_base_is_refused_and_opens_without_one() {
    use wz_capi_c::result::Z_EINVAL;

    let entries = |port: u16| {
        [
            ("mode", String::from("\"router\"")),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ]
    };
    let mut time_base = time_base_over(program_time());
    // SAFETY: the time base is live.
    let (rc, refused) = open(unsafe { config_with(&entries(free_port()), Some(&time_base)) });
    assert_eq!(rc, Z_EINVAL, "a router was opened on a time base");
    close(refused);
    // SAFETY: no time base is named.
    let (rc, router) = open(unsafe { config_with(&entries(free_port()), None) });
    assert_eq!(
        rc, Z_OK,
        "CONTROL: the same router without a time base opens"
    );
    close(router);
    // SAFETY: the program's own reference, dropped once.
    unsafe { wz_capi_c_time_base_drop(wz_capi_c_time_base_move(&mut time_base)) };
}
