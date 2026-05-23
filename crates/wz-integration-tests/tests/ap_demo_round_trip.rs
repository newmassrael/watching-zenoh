// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R121c (introduced) / R121d (stretch goal promoted to hard gate) —
// AP MVP demo round-trip integration test.
//
// Drives the wz-ap-demo binary (R121b) against an external zenoh-pico
// z_put CLI peer over real TCP. This is the first integration test
// in the workspace that proves the full session FSM + codec stack
// works against a foreign implementation — every layer3_* test in
// this crate so far has been wire-byte-compare only.
//
// Test flow:
//   1. Reserve a free TCP port via `PortReservation::pick` (R216 —
//      replaces the previous bind+drop+rebind pattern which raced
//      against concurrent tests in the same `cargo test` invocation;
//      see `wz_integration_tests::common` for the rationale).
//   2. Spawn wz-ap-demo --listen 127.0.0.1:<port> --key demo/test
//      with RUST_LOG=info; capture stderr to a tempfile.
//   3. Poll the demo's stderr until the "listening on" line appears
//      OR a 5s timeout fires. Surfaces a binding failure early
//      instead of waiting for the z_put timeout downstream. The port
//      reservation is released immediately after this confirmation.
//   4. Spawn z_put -k demo/test -v hello -e tcp/127.0.0.1:<port> -m client.
//      Inherits stdout/stderr so any zenoh-pico-side message surfaces
//      in the cargo test output for debug.
//   5. Wait up to 5s for the wz-ap-demo stderr to contain
//      "accepted peer" — proves the TCP-accept side of the bidirectional
//      split works against a real zenoh-pico client.
//   6. Wait up to 5s for the wz-ap-demo stderr to contain
//      "SUBSCRIBER FIRED" — proves the full session-FSM handshake
//      completed AND zenoh-pico's z_put successfully echoed its
//      DECLARE(KeyExpr) → Push(mapping_id) pair THROUGH the wz
//      pubsub resolver to the registered subscriber callback. This
//      was a stretch goal in R121c (handshake compat unproven);
//      R121d closed the four blockers (framing 2-byte LE vs 4-byte
//      BE; missing InboundStart dispatch; missing peer-caps
//      InitAck negotiation; missing DECLARE keyexpr-table
//      resolver) and the line now appears in steady state.
//   7. SIGTERM wz-ap-demo + flush captured stderr; surface the
//      full captured text on any failed assertion for diagnosis.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn ap_demo_round_trip_against_zenoh_pico_z_put() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    let key = "demo/test";

    let stderr_capture = tempfile::tempfile().expect("tempfile for demo stderr");
    let stderr_capture_writer = stderr_capture.try_clone().expect("dup stderr handle");
    let mut stderr_capture_reader = stderr_capture;

    let mut child = ChildGuard::wrap(
        "wz-ap-demo (--listen)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--key")
            .arg(key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_capture_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    // Wait for the binding-confirmed line; this prevents the z_put
    // spawn from racing against an unbound port.
    let bound = wait_for_substring(
        &mut stderr_capture_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n--- captured stderr ---\n{captured}"
        );
    }
    // R216 — release the port-alloc mutex now that the demo's bind
    // succeeded. Holding it through the handshake phase would
    // sequentialise Layer E's 5 tests; releasing it here keeps the
    // mutex window down to ~500 ms per test.
    drop(port_res);

    // Spawn z_put against the demo's endpoint. zenoh-pico's client
    // mode is the typical pattern for an initiator-side z_put.
    let z_put_status = Command::new(&z_put)
        .args([
            "-k",
            key,
            "-v",
            "hello-from-z_put",
            "-e",
            &endpoint,
            "-m",
            "client",
        ])
        .status();

    // Two-stage wait: first the conservative `accepted peer` line
    // (proves the TCP wire-up reached the FSM entry), then the
    // `SUBSCRIBER FIRED` hard gate (proves the FSM handshake
    // completed AND the subscriber resolver fired on a mapping-id
    // Push). Each wait has its own 5s budget so a regression
    // localizes the failure: missing `accepted peer` means TCP
    // never connected; missing `SUBSCRIBER FIRED` means the wire
    // reached the FSM but a handshake / resolver step regressed.
    let accepted_result = wait_for_substring(
        &mut stderr_capture_reader,
        "accepted peer",
        Duration::from_secs(5),
    );
    let subscriber_result = wait_for_substring(
        &mut stderr_capture_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(5),
    );

    // Tear down the demo. SIGTERM via kill(); on Unix this is SIGKILL
    // through std::process::Child — sufficient for test cleanup.
    // ChildGuard's Drop is the panic-path safety net (R305).
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();

    // Surface the full captured stderr on any failed assertion so a
    // session-FSM log line (codec error, lease expiry, etc.) is
    // visible in the cargo test output without re-running.
    let captured = read_captured(&mut stderr_capture_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{captured}");

    let accepted_captured = match accepted_result {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-ap-demo did not log 'accepted peer' within 5s after z_put connected to \
             {endpoint}\nz_put exit: {z_put_status:?}\n--- captured demo stderr at deadline ---\n{c}"
        ),
    };
    // Conservative gate's witness is the `accepted_captured` snapshot above;
    // surface it for completeness in test traces even on the success path.
    let _ = accepted_captured;

    // R121d hard gate — the subscriber must have fired against the
    // Push that referenced z_put's locally-declared mapping id. If
    // any of the four R121d blockers regresses (TCP framing, FSM
    // role start, peer-caps cap, DECLARE resolver) the line is
    // missing and the assertion below catches it.
    if let Err(c) = subscriber_result {
        panic!(
            "wz-ap-demo did not log 'SUBSCRIBER FIRED' within 5s — handshake or \
             keyexpr resolver regression against zenoh-pico's z_put initiator.\n\
             z_put exit: {z_put_status:?}\n--- captured demo stderr at deadline ---\n{c}"
        );
    }
}
