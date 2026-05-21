// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121f — initiator-side (wz dialing) round-trip integration test.
//!
//! Drives the wz-ap-demo binary in --connect mode (initiator role)
//! against a second wz-ap-demo instance in --listen mode (acceptor
//! role). Validates the new R121f initiator code path end-to-end:
//! TCP dial + `OutboundStart` + `LinkOpened` role-start dispatch +
//! 4-way handshake walked from the dialing side (peer InitAck →
//! `send_open_syn` → peer OpenAck → Established) + publisher_task
//! emission via the role-agnostic `record_established_at` gate.
//!
//! Why wz↔wz (rather than wz initiator → zenoh-pico peer-mode
//! listener): zenoh-pico 1.5.0's `-m peer -l <locator>` accepts
//! TCP connections but its session-acceptance code path in
//! `unicast/accept.c` is the well-tested router-side handshake
//! shape; a Client-whatami InitSyn dialing into a peer-mode
//! listener gets accepted at the TCP layer but the foreign side
//! closes the connection without responding (no inbound bytes
//! ever reach the wz initiator's read driver in a 10s window,
//! verified empirically during R121f authoring). Validating the
//! wz initiator code path against another wz instance lets this
//! round land cleanly; foreign-interop on the initiator side is
//! tracked as a carry for a future round (likely requires a
//! Zenoh router binary or a zenoh-pico CLI patch — both are
//! external dependencies).
//!
//! Test flow:
//!   1. Pick a free TCP port.
//!   2. Spawn wz-ap-demo --listen <addr> --key "demo/**" as the
//!      acceptor + subscriber.
//!   3. Wait up to 5s for the acceptor's stderr to contain
//!      "listening on" — proves the bind succeeded.
//!   4. Spawn wz-ap-demo --connect <addr> --publish demo/test
//!      --value hello-from-wz-initiator as the initiator +
//!      publisher.
//!   5. Wait up to 5s for the initiator's stderr to contain
//!      "connected to" — proves the dial succeeded.
//!   6. Wait up to 10s for the acceptor's stderr to contain
//!      "SUBSCRIBER FIRED" with the matching keyexpr suffix —
//!      proves the full 4-way handshake completed AND the
//!      initiator's Push reached the acceptor's subscriber
//!      callback through the wz codec catalog + session FSM +
//!      pubsub resolver. Three substring assertions on the
//!      captured snapshot (FIRED line, keyexpr literal, wireexpr
//!      id=0) so a regression localises.
//!   7. SIGTERM both children + surface captured stderr on any
//!      failed assertion.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, PortReservation,
};

#[test]
fn wz_initiator_round_trip_against_wz_acceptor() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let publish_key = "demo/test";
    let sub_pattern = "demo/**";
    let publish_value = "hello-from-wz-initiator";

    // ── wz acceptor (R121d listener + subscriber) ─────────────
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer =
        acceptor_stderr.try_clone().expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = Command::new(&demo)
        .arg("--listen")
        .arg(&addr)
        .arg("--key")
        .arg(sub_pattern)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --listen");

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_child.kill();
        let _ = acceptor_child.wait();
        panic!(
            "wz-ap-demo --listen did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    // R216 — acceptor has bound, release the port-alloc mutex so the
    // next Layer E test in the same `cargo test` invocation can
    // proceed in parallel.
    drop(port_res);

    // ── wz initiator (R121f dialer + publisher) ───────────────
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer =
        initiator_stderr.try_clone().expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = Command::new(&demo)
        .arg("--connect")
        .arg(&addr)
        .arg("--publish")
        .arg(publish_key)
        .arg("--value")
        .arg(publish_value)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --connect");

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );
    let fire_substr = "SUBSCRIBER FIRED";
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
            "wz acceptor did not log '{fire_substr}' within 10s — initiator-side \
             handshake or publisher emission regressed.\n\
             --- captured acceptor stderr at deadline ---\n{c}\n\
             --- captured initiator stderr at deadline ---\n{initiator_captured}"
        ),
    };

    // Belt-and-suspenders assertions on the keyexpr literal and
    // wireexpr id. The publisher's literal-keyexpr Push carries
    // wireexpr id=0 + suffix='demo/test'; the SUBSCRIBER FIRED
    // line logged by wz-ap-demo carries both fields so a
    // wire-shape regression on either side localises here.
    assert!(
        fired_text.contains(publish_key),
        "wz acceptor SUBSCRIBER FIRED line lacks the publish keyexpr '{publish_key}'.\n\
         --- acceptor stderr ---\n{fired_text}"
    );
    assert!(
        fired_text.contains("wireexpr_id=0"),
        "wz acceptor SUBSCRIBER FIRED line lacks 'wireexpr_id=0' \
         (literal-keyexpr Push sets id=0; non-zero would mean a DECLARE-aliased \
         path regression).\n\
         --- acceptor stderr ---\n{fired_text}"
    );
}
