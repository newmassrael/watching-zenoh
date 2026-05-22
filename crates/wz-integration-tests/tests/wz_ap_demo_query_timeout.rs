// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R264 — wz-ap-demo --query-timeout-ms end-to-end verification.
//
// Closes the verification debt from R263. R263 wired the
// --query-timeout-ms CLI flag through ReplyConsumerSpec to the
// QUERY_RID register call's `deadline_ms` and made
// `drive_session_until_terminal`'s on_tick sweep load-bearing for
// that register site (a peer that never replies should surface
// `FINAL RECEIVED rid=1` within (timeout_ms + driver-loop-tick) of
// register time). R263 verification was in-process at the unit level
// only; this round adds the cross-process integration fixture so the
// full register-deadline -> drive_session sweep -> on_final fire
// chain is exercised at the actual process boundary.
//
// Peer pattern (chosen R264 kickoff):
//   - Acceptor `wz-ap-demo --listen <port> --key demo/timeout`
//     declares only a subscriber, no queryable. Inbound Request(Query)
//     has no matching responder, so no Response/ResponseFinal goes back
//     on the wire. (wz-ap-demo does not auto-emit a
//     "no matching queryable" ResponseFinal — Q_B / Q_E codec slots
//     are still TBD per R263 carry; the AP demo's queryable side
//     dispatches via callback only.) The Query effectively sinks at
//     the peer.
//   - Initiator `wz-ap-demo --connect <port> --query demo/timeout
//     --query-timeout-ms 500 --on-query-final-log` sends one
//     outbound Query once the session reaches Established. The
//     register call computes deadline_ms = session_clock.now + 500.
//     The drive_session on_tick sweep below fires when
//     clock.now > deadline_ms; that sweep invokes the on_final
//     callback which logs `FINAL RECEIVED rid=1` to stderr.
//
// Wall-time bounds (chosen R264 kickoff):
//   - Lower 400 ms — catches a regression where `deadline_ms` is
//     mis-registered as 0 (would fire on the first sweep tick after
//     register, ~50 ms after handshake). 400 ms is conservative
//     below the configured 500 ms timeout to absorb file-poll
//     quantisation (50 ms) and the unavoidable post-spawn /
//     pre-register window.
//   - Upper 2000 ms — catches a regression where the sweep cadence
//     stalls (e.g. lease-branch sleep growing unbounded, or on_tick
//     skipping the sweep call). Expected steady-state on a quiet
//     loopback: spawn ~50 ms + handshake ~100 ms + 500 ms timeout +
//     driver-loop-tick ~50-200 ms = ~700-850 ms. 2000 ms absorbs
//     CI-runner jitter without masking real regressions.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (2x wz-ap-demo); Layer E runs via --ignored"]
fn wz_ap_demo_query_timeout_fires_final_callback() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let connect_addr = format!("127.0.0.1:{port}");
    let key = "demo/timeout";

    // Step 1: spawn the silent acceptor (subscriber only, no
    // queryable). It will accept the initiator's TCP, complete the
    // session handshake, receive the inbound Query, and silently
    // sink it because no queryable callback is registered.
    let acceptor_stderr_capture = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr_capture
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr_capture;

    let mut acceptor = Command::new(&demo)
        .arg("--listen")
        .arg(&listen_addr)
        .arg("--key")
        .arg(key)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn acceptor wz-ap-demo");

    let acceptor_bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &acceptor_bound {
        let _ = acceptor.kill();
        let _ = acceptor.wait();
        panic!(
            "acceptor wz-ap-demo did not log 'listening on' within 5s\n\
             --- acceptor stderr ---\n{captured}"
        );
    }
    // R216 — release the port-alloc mutex now that the acceptor's
    // bind succeeded; holding it through the handshake phase would
    // sequentialise Layer E lanes.
    drop(port_res);

    // Step 2: spawn the initiator with the timeout-bearing Query.
    // `initiator_start` is the wall-clock baseline against which the
    // FINAL RECEIVED arrival is bounded.
    let initiator_stderr_capture = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr_capture
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr_capture;

    let initiator_start = Instant::now();
    let mut initiator = Command::new(&demo)
        .arg("--connect")
        .arg(&connect_addr)
        .arg("--query")
        .arg(key)
        .arg("--query-timeout-ms")
        .arg("500")
        .arg("--on-query-final-log")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn initiator wz-ap-demo");

    // Wait up to 2 s for the FINAL line. Budget breakdown:
    // spawn ~50 ms + TCP+handshake ~100 ms + 500 ms timeout +
    // driver-loop-tick ~50-200 ms + 50 ms poll quantisation.
    let final_result = wait_for_substring(
        &mut initiator_stderr_reader,
        "FINAL RECEIVED rid=1",
        Duration::from_secs(2),
    );
    let final_elapsed = initiator_start.elapsed();

    // Tear down both demos. SIGKILL through std::process::Child is
    // sufficient for test cleanup; lease will not fire on either
    // side before we reach this point.
    let _ = initiator.kill();
    let _ = initiator.wait();
    let _ = acceptor.kill();
    let _ = acceptor.wait();

    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    eprintln!("--- captured initiator wz-ap-demo stderr ---\n{initiator_captured}");
    eprintln!("--- captured acceptor wz-ap-demo stderr ---\n{acceptor_captured}");

    if let Err(c) = final_result {
        panic!(
            "initiator wz-ap-demo did not log 'FINAL RECEIVED rid=1' within 2s; \
             --query-timeout-ms=500 should have fired the ReplyRegistry on_final \
             callback via the drive_session on_tick sweep.\n\
             --- captured initiator stderr at deadline ---\n{c}"
        );
    }

    // Wall-time bounds — see file header for the rationale behind
    // the 400 ms / 2000 ms boundaries.
    assert!(
        final_elapsed >= Duration::from_millis(400),
        "FINAL fired too early ({final_elapsed:?}); deadline_ms likely misset to 0 \
         or sweep races register before clock.now >= deadline_ms"
    );
    assert!(
        final_elapsed <= Duration::from_millis(2_000),
        "FINAL fired too late ({final_elapsed:?}); sweep cadence regression \
         or driver-loop-tick stall"
    );
}
