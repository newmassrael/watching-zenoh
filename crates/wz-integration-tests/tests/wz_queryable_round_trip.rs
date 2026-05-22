// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121j-5c-e2e — wz↔wz Query/Reply round-trip integration test.
//!
//! Pairs two wz-ap-demo instances across a TCP loopback so the
//! queryable-side wiring landed across R121j-5b (QueryableRegistry,
//! QueryResponder), R121j-5c (dispatch_messages, Final scheduling),
//! R121j-5c-e2e-action (SessionLinkActions.send_response), and
//! R121j-5c-e2e-demo (wz-ap-demo --queryable/--reply/--query CLI,
//! observer fan-out) round-trips end-to-end on a real socket.
//!
//! Test flow:
//!   1. Pick a free TCP port.
//!   2. Spawn `wz-ap-demo --listen <addr> --queryable demo/** --reply
//!      hello-from-queryable` as the acceptor + queryable.
//!   3. Wait up to 5s for the acceptor's stderr to contain
//!      "listening on" — bind succeeded.
//!   4. Spawn `wz-ap-demo --connect <addr> --query demo/test` as the
//!      initiator + query emitter.
//!   5. Wait up to 5s for the initiator's stderr to contain
//!      "connected to" — dial succeeded.
//!   6. Wait up to 10s for the acceptor's stderr to contain
//!      "QUERYABLE FIRED" — the full 4-way handshake completed AND
//!      the initiator's Request(Query) reached the acceptor's
//!      QueryableRegistry through the production poll loop
//!      (drive_session_until_terminal → observer →
//!      QueryableRegistry.dispatch_iteration_event), the matching
//!      callback fired, and at least one Reply was emitted.
//!   7. Belt-and-suspenders assertions on the rid + keyexpr literal
//!      so a wire-shape regression on either side localises here.
//!   8. SIGTERM both children + surface captured stderr on any
//!      failed assertion.
//!
//! Why no inbound-Reply assertion on the initiator side: the
//! initiator's `query_task` emits one Request(Query) and exits;
//! application-side dispatch of inbound Response.Reply / ResponseFinal
//! is the R121j-6 z_get adapter scope (carry). For R121j-5c-e2e the
//! OUTBOUND Q-side path is the deliverable — that the acceptor's
//! callback fired with the matched keyexpr + rid proves the Query
//! reached the queryable through every layer (TCP → stream envelope
//! → Frame → parse_frame_payload → NetworkMessage::Request →
//! QueryableRegistry → callback). The Reply chain emitted afterwards
//! exercises send_response + send_response_final at the action layer
//! (R121j-5c-e2e-action), but the requester-side dispatch is the
//! follow-up round.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_queryable_round_trip_against_wz_initiator() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let queryable_pattern = "demo/**";
    let reply_text = "hello-from-queryable";
    let query_keyexpr = "demo/test";

    // ── wz acceptor (R121d listener + R121j-5c-e2e queryable) ─
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = Command::new(&demo)
        .arg("--listen")
        .arg(&addr)
        .arg("--queryable")
        .arg(queryable_pattern)
        .arg("--reply")
        .arg(reply_text)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --listen --queryable");

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_child.kill();
        let _ = acceptor_child.wait();
        panic!(
            "wz-ap-demo --listen --queryable did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    // R216 — acceptor bound, release the port-alloc mutex.
    drop(port_res);

    // ── wz initiator (R121f dialer + R121j-5c-e2e query emitter) ─
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = Command::new(&demo)
        .arg("--connect")
        .arg(&addr)
        .arg("--query")
        .arg(query_keyexpr)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --connect --query");

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );
    let fire_substr = "QUERYABLE FIRED";
    let fired = wait_for_substring(
        &mut acceptor_stderr_reader,
        fire_substr,
        Duration::from_secs(10),
    );

    let _ = initiator_child.kill();
    let _ = initiator_child.wait();
    let _ = acceptor_child.kill();
    let _ = acceptor_child.wait();

    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    eprintln!("--- captured wz acceptor stderr ---\n{acceptor_captured}");
    eprintln!("--- captured wz initiator stderr ---\n{initiator_captured}");

    if let Err(c) = &dialed {
        panic!(
            "wz-ap-demo --connect did not log 'connected to' within 5s — initiator \
             TCP dial against {addr} failed.\n\
             --- captured initiator stderr ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        );
    }

    let fired_text = match fired {
        Ok(c) => c,
        Err(c) => panic!(
            "wz acceptor did not log '{fire_substr}' within 10s — Query/Reply \
             round-trip regressed somewhere between Request(Query) emit \
             (initiator side) and QueryableRegistry dispatch (acceptor side).\n\
             --- captured acceptor stderr at deadline ---\n{c}\n\
             --- captured initiator stderr at deadline ---\n{initiator_captured}"
        ),
    };

    // The acceptor's queryable callback logs:
    //   "QUERYABLE FIRED pattern='demo/**' rid=1 keyexpr='demo/test' reply='hello-from-queryable'"
    // Three substring assertions on the captured stderr so a
    // regression on any of (pattern resolution, rid echo, resolved
    // keyexpr literal, configured reply payload) localises here.
    assert!(
        fired_text.contains(&format!("pattern='{queryable_pattern}'")),
        "QUERYABLE FIRED line lacks pattern='{queryable_pattern}'.\n\
         --- acceptor stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains("rid=1"),
        "QUERYABLE FIRED line lacks 'rid=1' — initiator's query_task hard-codes \
         QUERY_RID=1 and the acceptor's responder must echo the inbound \
         Request.rid verbatim.\n\
         --- acceptor stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("keyexpr='{query_keyexpr}'")),
        "QUERYABLE FIRED line lacks keyexpr='{query_keyexpr}' — wildcard pattern \
         matched but the resolved literal is missing, which would mean the \
         peer-keyexpr-table resolution drifted.\n\
         --- acceptor stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains(&format!("reply='{reply_text}'")),
        "QUERYABLE FIRED line lacks reply='{reply_text}' — the callback's \
         configured reply payload is not surfacing through the stderr trace.\n\
         --- acceptor stderr ---\n{fired_text}"
    );

    // Initiator-side trace: the query_task logs "QUERY EMITTED" once
    // it observes Established and calls send_request_query. Asserting
    // this on the captured initiator stderr proves the OUTBOUND Query
    // path actually fired (the acceptor's QUERYABLE FIRED above
    // proves the INBOUND dispatch; both sides land if the round-trip
    // completed).
    assert!(
        initiator_captured.contains("QUERY EMITTED"),
        "wz initiator stderr lacks 'QUERY EMITTED' — the query_task either \
         never observed Established or send_request_query failed.\n\
         --- initiator stderr ---\n{initiator_captured}"
    );
    assert!(
        initiator_captured.contains(&format!("keyexpr='{query_keyexpr}'")),
        "QUERY EMITTED line lacks keyexpr='{query_keyexpr}' — argv plumbing \
         from --query into send_request_query may have dropped the value.\n\
         --- initiator stderr ---\n{initiator_captured}"
    );
}
