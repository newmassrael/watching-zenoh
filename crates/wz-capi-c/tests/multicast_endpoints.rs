// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 913 — a multicast group among a zenoh-c session's endpoints to DIAL.
//!
//! zenoh's runtime refuses one in a peer's or a router's connect list and fails the open
//! (`zenoh/src/net/runtime/orchestrator.rs` @
//! `bail!("Forbidden multicast endpoint in connect list!")`); a client tries every endpoint as a
//! unicast link and fails its open when none comes up, which a group never does. Both refusals
//! happen before a socket is opened, so these legs need no multicast route and run everywhere.
//! A group in `listen/endpoints` is the joined one, and is witnessed against zenohd by
//! `zenoh_c_peer_multicast_on_wz_capi.rs` in Layer M.

use std::ffi::CString;

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::{Z_ENETWORK, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan_mut};

/// A group no test joins.
const GROUP: &str = "udp/224.0.0.227:7455";

unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    (rc, session)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// A peer that would dial `connect`, listening on nothing and scouting for nothing.
fn peer_dialling(connect: &str) -> Vec<(&'static str, String)> {
    vec![
        ("mode", "\"peer\"".to_owned()),
        ("scouting/multicast/enabled", "false".to_owned()),
        ("listen/endpoints", "[]".to_owned()),
        ("connect/endpoints", connect.to_owned()),
    ]
}

/// A unicast endpoint nothing listens on: a peer dials it in the background and opens anyway.
fn unanswered() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a port the OS gave and took back")
        .port();
    format!("tcp/127.0.0.1:{port}")
}

/// A peer told to dial a group fails its open, as zenoh's peer does, whatever else it is told
/// to dial.
///
/// # Control
///
/// The first leg is a peer told to dial an endpoint nothing answers, which opens: a peer dials
/// in the background. Without the refusal the group is dropped and the same peer opens, which
/// reds the second leg.
#[test]
fn a_peer_told_to_dial_a_group_fails_its_open() {
    let other = unanswered();
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&peer_dialling(&format!("[\"{other}\"]"))) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(
        rc, Z_OK,
        "a peer whose endpoint does not answer opens alone"
    );

    // SAFETY: a fresh config and session.
    let (rc, session) =
        unsafe { open_with(&peer_dialling(&format!("[\"{GROUP}\", \"{other}\"]"))) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(rc, Z_ENETWORK, "a peer dialling a multicast group opened");
}

/// A client tries a group as a link it never establishes: with nothing else to dial it fails its
/// open, and with an endpoint that answers it opens on that one.
///
/// # Control
///
/// Refusing a client as a peer is refused reds the second leg.
#[test]
fn a_client_dials_past_a_group() {
    let client_to = |connect: String| {
        vec![
            ("mode", "\"client\"".to_owned()),
            ("scouting/multicast/enabled", "false".to_owned()),
            ("connect/endpoints", connect),
        ]
    };
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&client_to(format!("[\"{GROUP}\"]"))) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    assert_eq!(rc, Z_ENETWORK, "a client with a group alone to dial opened");

    // A peer listening on a port of its own, which the client can reach.
    let listen = unanswered();
    let listener_entries = vec![
        ("mode", "\"peer\"".to_owned()),
        ("scouting/multicast/enabled", "false".to_owned()),
        ("listen/endpoints", format!("[\"{listen}\"]")),
    ];
    // SAFETY: a fresh config and session.
    let (rc, listener) = unsafe { open_with(&listener_entries) };
    assert_eq!(rc, Z_OK, "the listening peer opens");
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe { open_with(&client_to(format!("[\"{GROUP}\", \"{listen}\"]"))) };
    // SAFETY: a gravestone drops as a no-op, a live session closes.
    unsafe { close_session(session) };
    // SAFETY: a live session.
    unsafe { close_session(listener) };
    assert_eq!(
        rc, Z_OK,
        "a client that could reach its other endpoint did not open"
    );
}
