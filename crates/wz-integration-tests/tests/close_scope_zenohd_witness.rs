// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y839 — what a REAL zenohd puts in the scope bit of a Close, MEASURED.
//!
//! The round that lands with this file changed wz's `FLAG_T_CLOSE_S` from a
//! literal `true` to a value derived from the link set, on the strength of a
//! claim about upstream: that zenoh 1.5.0 passes `session: false` at every
//! unicast Close construction site. That claim came from reading zenoh's source,
//! and this tree has retracted source-derived claims about upstream repeatedly
//! -- most recently R311y838, where a comment ratifying a divergence turned out
//! to have read zenoh-pico's CONSTRUCTOR and stopped one function short of the
//! cap that actually runs.
//!
//! So the bit is read off a socket a real zenohd wrote, with no zenoh source in
//! the loop.
//!
//! # The provocation, and why this one
//!
//! zenohd's accept FSM demands an InitSyn as the first transport message and
//! rejects anything else with `close::reason::INVALID`; the rejection path is a
//! `link.close(reason)`, which is the establishment-phase Close. A bare
//! KeepAlive (MID 0x04, one byte, no body) is the cheapest well-formed transport
//! message that is not an InitSyn, so it reaches the rejection without depending
//! on any field zenohd might renegotiate.
//!
//! Deliberately NOT provoked here: the whole-transport close a user triggers.
//! Reaching it needs a zenohd that has ESTABLISHED a session and is then asked
//! to close it, which is a second foreign binary's worth of harness. This
//! witness therefore covers the establishment site and says so, rather than
//! being quoted later as though it had covered all three.
//!
//! # What a failure here would mean
//!
//! Not that wz is wrong -- that the round's premise is. If a real zenohd SETS
//! the bit on an establishment close, then `close_scope_is_session` is deriving
//! the wrong value and the argument it cites has to be rebuilt from what this
//! test measured.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use wz_integration_tests::common::spawn_zenohd_on_ephemeral_tcp;
use wz_session_core::wire_const;

/// The zenoh streamed-link envelope: a 2-byte little-endian length, then the
/// transport message. Same shape wz's own TCP driver writes.
fn write_framed(stream: &mut TcpStream, payload: &[u8]) {
    let len = u16::try_from(payload.len()).expect("probe payload fits the envelope");
    stream
        .write_all(&len.to_le_bytes())
        .expect("write length prefix");
    stream.write_all(payload).expect("write payload");
    stream.flush().expect("flush probe");
}

/// Read exactly one framed transport message back.
fn read_framed(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .expect("zenohd answers the rejected handshake before closing the link");
    let mut payload = vec![0u8; u16::from_le_bytes(len) as usize];
    stream.read_exact(&mut payload).expect("read payload");
    payload
}

// wz-proves: codec-close zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd); Layer Z runs via --ignored"]
fn a_real_zenohd_clears_the_close_scope_flag_on_its_establishment_reject() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for the handshake probe's stderr")
    });

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("dial the reference router");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("bound the read");

    // A KeepAlive where zenohd's accept FSM demands an InitSyn.
    write_framed(&mut stream, &[wire_const::T_MID_KEEP_ALIVE]);

    let answer = read_framed(&mut stream);
    assert_eq!(
        answer.first().map(|h| h & 0x1F),
        Some(wire_const::T_MID_CLOSE),
        "zenohd rejects a non-InitSyn opener with a Close; got {answer:02X?}",
    );

    // The reason pins WHICH close this is: `close::reason::INVALID`, the code the
    // accept FSM attaches to "not an InitSyn". Without it a Close for some other
    // cause would satisfy the scope assertion below and read as the same witness.
    assert_eq!(
        answer.get(1).copied(),
        Some(0x02),
        "expected the INVALID rejection reason; got {answer:02X?}",
    );

    let scope_is_session = answer[0] & wire_const::FLAG_T_CLOSE_S != 0;
    assert!(
        !scope_is_session,
        "MEASURED, not read: a real zenohd's establishment Close must clear the \
         scope flag -- this is the byte wz's `close_scope_is_session` derivation \
         is built on. Got header 0x{:02X} (whole frame {answer:02X?})",
        answer[0],
    );
}
