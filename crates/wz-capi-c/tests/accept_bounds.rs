// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A listening session of this ABI bounds the handshake of an inbound link by what its config
//! states for `transport/unicast/accept_timeout`, and by zenoh's ten seconds when it states none.
//! Both are seen on a socket: the peer is a bare TCP client that connects and sends nothing, so
//! what is compared is whether the listener closed it and when, not a number the session reports.
//!
//! Before the key was read, a listener dropped every silent link after the session machine's own
//! second (zenoh-pico's bound), whatever the config said and where zenoh itself holds it for ten.

use std::ffi::CString;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan_mut};
use wz_runtime_tokio_test_support::free_port;

/// A listening session on `port`, with `entries` (key, json5 value) stated beside its endpoint.
unsafe fn listen(port: u16, entries: &[(&str, &str)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    let endpoint = format!("[\"tcp/127.0.0.1:{port}\"]");
    let mut all = vec![
        ("scouting/multicast/enabled", "false"),
        ("listen/endpoints", endpoint.as_str()),
    ];
    all.extend_from_slice(entries);
    for (k, v) in all {
        let (k, v) = (CString::new(k).unwrap(), CString::new(v).unwrap());
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null()
        ),
        Z_OK
    );
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
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

/// How long after it connected a silent link was closed, waiting at most `at_most`.
fn dropped_after(port: u16, at_most: Duration) -> Option<Duration> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");
    let connected = Instant::now();
    while connected.elapsed() < at_most {
        if closed(&mut stream) {
            return Some(connected.elapsed());
        }
    }
    None
}

#[test]
fn a_silent_link_is_dropped_when_the_stated_accept_timeout_has_passed() {
    let port = free_port();
    unsafe {
        let session = listen(port, &[("transport/unicast/accept_timeout", "400")]);
        let after = dropped_after(port, Duration::from_millis(3000));
        close_session(session);
        let after = after.expect("a link silent past the stated 400 ms was never closed");
        assert!(
            after >= Duration::from_millis(400),
            "dropped after {after:?}, before the 400 ms it was given"
        );
    }
}

/// The control, and the half that shows the bound is the key's and not a constant: with no key
/// the listener holds the same silent link for zenoh's ten seconds, past the second it used to
/// give every link.
#[test]
fn a_config_that_states_no_accept_timeout_holds_a_silent_link_for_zenohs_ten_seconds() {
    let port = free_port();
    unsafe {
        let session = listen(port, &[]);
        let after = dropped_after(port, Duration::from_millis(2000));
        close_session(session);
        assert_eq!(
            after, None,
            "a silent link was closed after {after:?}, inside zenoh's ten seconds"
        );
    }
}

/// `accept_pending`: a link that arrives while that many are mid-handshake is closed at once.
#[test]
fn a_link_past_the_stated_pending_bound_is_closed_at_once() {
    let port = free_port();
    unsafe {
        let session = listen(port, &[("transport/unicast/accept_pending", "1")]);
        let mut first = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");
        std::thread::sleep(Duration::from_millis(200));
        let mut second = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");
        std::thread::sleep(Duration::from_millis(300));
        let (first_closed, second_closed) = (closed(&mut first), closed(&mut second));
        close_session(session);
        assert!(
            !first_closed,
            "the first link, inside the bound of one, was closed"
        );
        assert!(
            second_closed,
            "the second link, past the bound of one, was not closed"
        );
    }
}
