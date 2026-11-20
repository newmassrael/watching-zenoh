// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A listening session of the cooperative engine opened on a time base the program supplies
//! (`wz_ext_time_base_*`) gives an inbound link the accept timeout the build states of the
//! PROGRAM's time, not of the wall clock: a client that connects and says nothing is kept for as
//! long as the program's time stands still, however long the wall clock runs, and dropped once the
//! program's time passes the bound and the program says so. `accept_timeout` is the same link
//! on the system's clock, dropped at the bound of the wall clock.
//!
//! The cooperative engine only: its accept deadline is the session's (`CoopConfig::timeouts`, on
//! the engine's clock), where the tokio engine's accept loop bounds a handshake with tokio's own
//! timer, which a time base does not reach yet.

#![cfg(all(feature = "time-base", feature = "peer", not(feature = "engine-tokio")))]

use std::ffi::{c_void, CString};
use std::io::Read;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wz_capi_pico::time_base::{
    wz_ext_config_time_base, wz_ext_owned_time_base_t, wz_ext_time_base_advanced,
    wz_ext_time_base_drop, wz_ext_time_base_loan, wz_ext_time_base_move, wz_ext_time_base_new,
    wz_ext_time_base_t,
};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::caps::PICO_ACCEPT_TIMEOUT_MS;

/// The program's time in nanoseconds, which the test sets and the library reads.
unsafe extern "C" fn now_ns(context: *mut c_void) -> u64 {
    (*(context as *const AtomicU64)).load(Ordering::SeqCst)
}

/// Whether the listener has closed `stream`: a closed link reads end-of-stream (or an error) at
/// once, an open and silent one has nothing to read when the short timeout ends.
fn closed(stream: &mut TcpStream) -> bool {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("a read timeout");
    let mut byte = [0u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

#[test]
fn a_silent_link_is_dropped_when_the_programs_time_passes_the_accept_timeout() {
    let port = free_port();
    let listen = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let bound = Duration::from_millis(PICO_ACCEPT_TIMEOUT_MS as u64);
    // The program's time, standing still until the test moves it; it outlives the session.
    let time = Box::new(AtomicU64::new(0));

    let mut time_base: wz_ext_owned_time_base_t = unsafe { std::mem::zeroed() };
    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    unsafe {
        let calls = wz_ext_time_base_t {
            context: &*time as *const AtomicU64 as *mut c_void,
            now_ns: Some(now_ns),
            drop: None,
        };
        assert_eq!(wz_ext_time_base_new(&mut time_base, &calls), Z_OK);
        let mut config: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut config), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut config),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        assert_eq!(
            wz_ext_config_time_base(
                z_config_loan_mut(&mut config),
                wz_ext_time_base_loan(&time_base)
            ),
            Z_OK
        );
        assert_eq!(
            z_open(&mut session, z_config_move(&mut config), std::ptr::null()),
            Z_OK
        );
    }

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");

    // Twice the bound of the wall clock with the program's time standing still: the link is kept.
    let kept = Instant::now() + bound * 2;
    while Instant::now() < kept {
        assert!(
            !closed(&mut stream),
            "the link was dropped while the program's time stood still, the wall clock past the \
             {bound:?} bound"
        );
    }

    // The program's time passes the bound and the program says so: the link is dropped.
    time.store(
        u64::try_from((bound + Duration::from_millis(1)).as_nanos()).unwrap(),
        Ordering::SeqCst,
    );
    assert_eq!(
        unsafe { wz_ext_time_base_advanced(wz_ext_time_base_loan(&time_base)) },
        Z_OK
    );
    let until = Instant::now() + Duration::from_secs(5);
    let mut dropped = false;
    while Instant::now() < until {
        if closed(&mut stream) {
            dropped = true;
            break;
        }
    }
    assert!(
        dropped,
        "the link was still open once the program's time passed the {bound:?} the build states"
    );

    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        wz_ext_time_base_drop(wz_ext_time_base_move(&mut time_base));
    }
    drop(time);
}
