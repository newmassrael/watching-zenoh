// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121k-5 — wz↔wz inbound DECLARE 6 sub-types round-trip test.
//!
//! Pairs two wz-ap-demo instances on TCP loopback so the
//! `RemoteSubscriberRegistry` (R121k-2), `RemoteQueryableRegistry`
//! (R121k-3), and `LivelinessRegistry` (R121k-4) wiring landed
//! through the production observer (R121k-5) round-trips for every
//! inbound Decl arm — DeclSubscriber, DeclQueryable, DeclToken —
//! end-to-end on a real socket.
//!
//! Test flow:
//!   1. Pick a free TCP port.
//!   2. Spawn acceptor: `wz-ap-demo --listen <addr> \
//!         --declare-subscriber demo/sub --declare-queryable demo/q \
//!         --declare-token demo/token`. The acceptor emits one Decl
//!      of each kind once Established. Subscriber + Queryable use
//!      hard-coded ids 1001 / 2001. Token id is auto-allocated by
//!      `SessionLinkActions::alloc_next_token_id` (R277 migration);
//!      the first call returns 0 because the per-session counter
//!      starts at 0 and uses `fetch_add(1, Relaxed)`.
//!   3. Wait up to 5s for the acceptor's stderr to contain
//!      "listening on" — bind succeeded.
//!   4. Spawn initiator: `wz-ap-demo --connect <addr> \
//!         --on-remote-subscriber-log --on-remote-queryable-log \
//!         --on-remote-liveliness-log`. The initiator installs
//!      a stderr-log callback on each of the three Remote* registries.
//!   5. Wait up to 5s for the initiator's stderr to contain
//!      "connected to" — dial succeeded.
//!   6. Wait up to 10s for the initiator's stderr to contain all three
//!      lines "REMOTE SUBSCRIBER DECLARED id=1001 keyexpr='demo/sub'",
//!      "REMOTE QUERYABLE DECLARED id=2001 keyexpr='demo/q'", and
//!      "REMOTE TOKEN DECLARED id=0 keyexpr='demo/token'" — proving
//!      the full path: TCP → stream envelope → Frame →
//!      parse_frame_payload → NetworkMessage::Declare →
//!      Remote*Registry → callback.
//!   7. Belt-and-suspenders id + keyexpr assertions so a regression
//!      on any of (id echo, keyexpr resolution, registry routing)
//!      localises here.
//!   8. SIGTERM both children + surface captured stderr on any
//!      failed assertion.
//!
//! Why this consolidated test rather than three per-kind tests:
//! the three Remote* registries share the same observer fan-out and
//! the same FramePayload.messages slice in production — exercising
//! all three in one test confirms the parallel-dispatch contract
//! (R121k-4 declare::tests::three_registries_share_a_message_stream_independently
//! at the unit level) holds end-to-end. A regression on any one
//! kind localises through the per-line assertions below.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_remote_declare_round_trip_against_wz_initiator() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let sub_keyexpr = "demo/sub";
    let q_keyexpr = "demo/q";
    let token_keyexpr = "demo/token";

    // ── wz acceptor (R121d listener + R121k-5 declare emitter) ─
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer =
        acceptor_stderr.try_clone().expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = Command::new(&demo)
        .arg("--listen")
        .arg(&addr)
        .arg("--declare-subscriber")
        .arg(sub_keyexpr)
        .arg("--declare-queryable")
        .arg(q_keyexpr)
        .arg("--declare-token")
        .arg(token_keyexpr)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --listen --declare-*");

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_child.kill();
        let _ = acceptor_child.wait();
        panic!(
            "wz-ap-demo --listen --declare-* did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    // R216 — acceptor bound, release the port-alloc mutex.
    drop(port_res);

    // ── wz initiator (R121f dialer + R121k-5 remote-log callbacks) ─
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer =
        initiator_stderr.try_clone().expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = Command::new(&demo)
        .arg("--connect")
        .arg(&addr)
        .arg("--on-remote-subscriber-log")
        .arg("--on-remote-queryable-log")
        .arg("--on-remote-liveliness-log")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --connect --on-remote-*-log");

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );

    // The three callback log lines arrive in order: subscriber →
    // queryable → token (declare_task emits in this order with a
    // 100ms inter-emit pause). Wait on the LAST one (token) so the
    // capture includes all three.
    let last_substr = "REMOTE TOKEN DECLARED";
    let last_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        last_substr,
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

    let final_text = match last_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{last_substr}' within 10s — inbound DECLARE \
             round-trip regressed somewhere between Declare emit (acceptor side) \
             and Remote*Registry dispatch (initiator side).\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr at deadline ---\n{acceptor_captured}"
        ),
    };

    // All three Decl arms must surface on the initiator side. The
    // exact line shape (id literal + keyexpr literal) catches both
    // id-echo regressions and keyexpr-resolution regressions in one
    // assertion per arm.
    assert!(
        final_text.contains(&format!(
            "REMOTE SUBSCRIBER DECLARED id=1001 keyexpr='{sub_keyexpr}'"
        )),
        "initiator stderr missing REMOTE SUBSCRIBER DECLARED line — \
         RemoteSubscriberRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );
    assert!(
        final_text.contains(&format!(
            "REMOTE QUERYABLE DECLARED id=2001 keyexpr='{q_keyexpr}'"
        )),
        "initiator stderr missing REMOTE QUERYABLE DECLARED line — \
         RemoteQueryableRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );
    // R277 — token id is no longer hard-coded; it comes from
    // `SessionLinkActions::alloc_next_token_id` (per-session
    // AtomicU64 counter that starts at 0). First call in the demo
    // returns 0. If a future round adds a token alloc earlier than
    // declare_task, this assertion will need to track that.
    assert!(
        final_text.contains(&format!(
            "REMOTE TOKEN DECLARED id=0 keyexpr='{token_keyexpr}'"
        )),
        "initiator stderr missing REMOTE TOKEN DECLARED line — \
         LivelinessRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );

    // Acceptor-side trace: the declare_task logs "DECLARED *" lines
    // once it observes Established and calls send_declare_*. Asserting
    // these on the captured acceptor stderr proves the OUTBOUND
    // Declare path actually fired (the initiator's REMOTE * DECLARED
    // lines above prove the INBOUND dispatch; both sides land if the
    // round-trip completed).
    assert!(
        acceptor_captured.contains("DECLARED SUBSCRIBER id=1001"),
        "acceptor stderr lacks 'DECLARED SUBSCRIBER id=1001' — \
         send_declare_subscriber did not fire.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );
    assert!(
        acceptor_captured.contains("DECLARED QUERYABLE id=2001"),
        "acceptor stderr lacks 'DECLARED QUERYABLE id=2001' — \
         send_declare_queryable did not fire.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );
    // R277 — token id is auto-allocated; see comment above on the
    // initiator-side assertion.
    assert!(
        acceptor_captured.contains("DECLARED TOKEN id=0"),
        "acceptor stderr lacks 'DECLARED TOKEN id=0' — \
         Session::declare_token did not fire.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );
}
