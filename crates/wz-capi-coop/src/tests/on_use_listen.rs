// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session whose tables take their memory at their first row (`tables-on-use`) that listens on a
//! `tcp/` port of the host, against raw connections that never speak: the host's accept of a
//! stream connection is the subject, which the simulated world's datagram ends do not have. The
//! rest of the on-use form runs in the simulated world (`tests::on_use`).

use super::Engine;

/// A session whose tables take their memory on use and that listens holds the links it takes to
/// the faces it may hold, though no table of buffers refuses a link any more (each link's buffers
/// are its own, of the heap): a connection that arrives when it holds as many faces as `max_faces`
/// admits is closed unread, the buffers its accept took let go of with it. The first connection is
/// that face, from its take on, in its handshake; the handshakes admitted are two, so only the
/// count of faces refuses the second. CONTROL: the first connection is kept, and with room for
/// another face the second is too. The bound is the face table's count, which
/// `Core::takes_a_face` asks before a link is given a face (`Core::faces_full`), and behind it
/// the index of the held faces, counted at the open to the sets the plan counts
/// (`Registry::add_face`). Turned red by a take of a face that asks neither, which gives the
/// second connection a face and keeps it open.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn an_on_use_listener_closes_a_link_past_its_faces_unread() {
    use std::io::Read;
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    use wz_capi_port::SessionDrive;

    // A listener of `max_faces` faces besides its dial role's, stepped on the test's thread, and
    // a raw connection to its port, which never speaks.
    let listening = |max_faces: usize| {
        let mut config = crate::CoopConfig {
            whatami: wz_session_core::WhatAmI::Peer,
            listen: vec!["tcp/127.0.0.1:0".to_owned()],
            max_faces,
            accept_pending: 2,
            ..super::client_config()
        };
        // Past the test: a connection that never speaks is not let go of for its silence here.
        config.timeouts.accepting_inactivity_ms = 10_000;
        let engine = super::open_with(config);
        let endpoint = engine.listening().pop().expect("one port is bound");
        let port = endpoint
            .rsplit(':')
            .next()
            .expect("an endpoint with a port")
            .to_owned();
        (engine, port)
    };
    let connect = |port: &str| {
        let stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
        stream
            .set_nonblocking(true)
            .expect("a stream whose read does not wait");
        stream
    };
    // Whether the listener closes `stream` while it is stepped for `within`: a read of the end
    // of the stream. One still open answers that the read would wait.
    let closed_within = |engine: &Engine, stream: &mut TcpStream, within: Duration| {
        let deadline = Instant::now() + within;
        let mut byte = [0u8; 1];
        while Instant::now() < deadline {
            SessionDrive::step_once(engine, 5).expect("a session without its read task steps");
            if matches!(stream.read(&mut byte), Ok(0)) {
                return true;
            }
        }
        false
    };

    let (full, port) = listening(1);
    let mut first = connect(&port);
    assert!(
        !closed_within(&full, &mut first, Duration::from_millis(200)),
        "CONTROL: the first connection is taken as the one face"
    );
    let mut over = connect(&port);
    assert!(
        closed_within(&full, &mut over, Duration::from_secs(3)),
        "the listener holds as many faces as it may, so it closes the second connection"
    );
    assert!(
        !closed_within(&full, &mut first, Duration::from_millis(100)),
        "and the face it holds stands"
    );

    let (roomy, port) = listening(2);
    let mut first = connect(&port);
    let mut kept = connect(&port);
    assert!(
        !closed_within(&roomy, &mut first, Duration::from_millis(200))
            && !closed_within(&roomy, &mut kept, Duration::from_millis(300)),
        "CONTROL: with room for another face both connections are kept"
    );
}
