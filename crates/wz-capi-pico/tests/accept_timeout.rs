// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A listening session of this ABI gives an inbound link as long as the build states for
//! zenoh-pico's `Z_TRANSPORT_ACCEPT_TIMEOUT` to complete its handshake, and drops it when that has
//! passed: one second by default (`vendor/zenoh-pico/CMakeLists.txt` @
//! `set(Z_TRANSPORT_ACCEPT_TIMEOUT 1000`), where the accept loop under it keeps zenoh's ten.
//!
//! The peer is a bare TCP client that connects and sends nothing, so what is observed is whether
//! the listener closed the socket, and when, and not a value the session reports of itself.

use std::ffi::CString;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan_mut, z_session_move, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::caps::PICO_ACCEPT_TIMEOUT_MS;

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
fn a_silent_link_is_dropped_at_the_accept_timeout_the_build_states() {
    let port = free_port();
    let listen = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let bound = Duration::from_millis(PICO_ACCEPT_TIMEOUT_MS as u64);

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    unsafe {
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
            z_open(&mut session, z_config_move(&mut config), std::ptr::null()),
            Z_OK
        );
    }

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");
    let connected = Instant::now();

    // Well inside the bound: nothing has been done to the link.
    std::thread::sleep(bound / 3);
    assert!(
        !closed(&mut stream),
        "the link was closed after {:?}, well inside the {bound:?} the build states",
        connected.elapsed()
    );

    // Past the bound, with the 100 ms of the observation and a margin for the loop to notice:
    // the listener has dropped it. Had the accept loop's own ten seconds been the bound, a
    // build stating one second would still hold it here.
    let until = connected + bound + Duration::from_millis(1500);
    let mut dropped = false;
    while Instant::now() < until {
        if closed(&mut stream) {
            dropped = true;
            break;
        }
    }
    assert!(
        dropped,
        "the link was still open {:?} after it connected, past the {bound:?} the build states \
         for Z_TRANSPORT_ACCEPT_TIMEOUT",
        connected.elapsed()
    );
    assert!(
        connected.elapsed() >= bound,
        "dropped after {:?}, before the {bound:?} it was given",
        connected.elapsed()
    );

    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
}
