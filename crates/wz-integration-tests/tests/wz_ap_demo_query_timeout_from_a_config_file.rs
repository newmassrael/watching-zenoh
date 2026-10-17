// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// `queries_default_timeout` read from a `--config` FILE: the topology of
// `wz_ap_demo_query_timeout.rs`, with the query's deadline stated in a stock
// zenoh document instead of `--query-timeout-ms`.
//
// What this adds over the flag-level fixture. The flag fixture proves the
// register-deadline -> sweep -> final chain from a typed `--query-timeout-ms
// 500`. The step from `queries_default_timeout` to that flag is covered only by
// argv unit tests. Here the initiator is given `--connect <addr> --query <key>
// --on-query-final-log --config <file>` and NO timeout flag, so the FINAL line
// can appear inside the same 400 ms .. 2000 ms window only if the file's value
// reached the register call. `--query` stays on the command line because the
// expansion withholds the flag from a run that has no query to bind it to.
//
// The control. The same topology and the same silent peer with a file that does
// not name the key. Without a deadline the pending entry never expires on its
// own, so the peer's silence must leave the FINAL line absent over the same 2 s
// the positive leg uses to observe it. The control first waits for the session
// to be Established, so an absence is about the deadline and not about an
// initiator that never connected.
//
// The silent peer is the flag-level fixture's: its silence lives in code it
// owns, so nothing in the build graph can talk it into answering.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    wz_e2e_silent_peer_binary, PortReservation,
};

/// The document: a 500 ms default query timeout.
const DOC_QUERY_TIMEOUT: &str = "{ queries_default_timeout: 500 }";
/// The document: names another key and leaves the query timeout unnamed.
const DOC_WITHOUT_THE_KEY: &str = "{ timestamping: { enabled: false } }";

/// What one run observed.
struct Observed {
    /// Whether the FINAL line arrived inside the 2 s window.
    final_seen: bool,
    /// Wall time from spawning the initiator to the verdict above.
    final_elapsed: Duration,
    /// The initiator's stderr at the moment of the verdict.
    initiator_stderr: String,
}

/// Spawn the silent peer and an initiator given `--config <file>` carrying
/// `document`, and report whether the FINAL line arrived.
///
/// `require_established` makes the run wait for the session to be Established
/// before the observation window opens, which the control needs and the positive
/// leg does not (its FINAL line is its own proof of a live session).
fn query_a_silent_peer_given(document: &str, require_established: bool) -> Observed {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let silent_peer = wz_e2e_silent_peer_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let mut config = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    config.write_all(document.as_bytes()).expect("write config");
    config.flush().expect("flush config");

    let acceptor_stderr_capture = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr_capture
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr_capture;

    let mut acceptor = Command::new(&silent_peer)
        .arg("--listen")
        .arg(&addr)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn wz-e2e-silent-peer");

    if let Err(captured) = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    ) {
        let _ = acceptor.kill();
        let _ = acceptor.wait();
        panic!(
            "wz-e2e-silent-peer did not log 'listening on' within 5s\n\
             --- wz-e2e-silent-peer stderr ---\n{captured}"
        );
    }
    drop(port_res);

    let initiator_stderr_capture = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr_capture
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr_capture;

    let initiator_start = Instant::now();
    let mut initiator = Command::new(&demo)
        .arg("--connect")
        .arg(&addr)
        .arg("--query")
        .arg("demo/timeout")
        .arg("--on-query-final-log")
        .arg("--config")
        .arg(config.path())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn initiator wz-ap-demo");

    if require_established {
        if let Err(c) = wait_for_substring(
            &mut initiator_stderr_reader,
            "session Established",
            Duration::from_secs(5),
        ) {
            let _ = initiator.kill();
            let _ = initiator.wait();
            let _ = acceptor.kill();
            let _ = acceptor.wait();
            panic!(
                "the initiator never reached Established within 5s, so an absent FINAL \
                 would say nothing about the deadline\n--- initiator stderr ---\n{c}"
            );
        }
    }

    let final_result = wait_for_substring(
        &mut initiator_stderr_reader,
        "FINAL RECEIVED rid=1",
        Duration::from_secs(2),
    );
    let final_elapsed = initiator_start.elapsed();

    let _ = initiator.kill();
    let _ = initiator.wait();
    let _ = acceptor.kill();
    let _ = acceptor.wait();

    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    eprintln!("--- captured initiator wz-ap-demo stderr ---\n{initiator_captured}");
    eprintln!("--- captured wz-e2e-silent-peer stderr ---\n{acceptor_captured}");

    Observed {
        final_seen: final_result.is_ok(),
        final_elapsed,
        initiator_stderr: initiator_captured,
    }
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features zenoh-config + wz-e2e-silent-peer); Layer E runs via --ignored"]
fn wz_ap_demo_query_timeout_from_a_config_file_fires_final_callback() {
    let seen = query_a_silent_peer_given(DOC_QUERY_TIMEOUT, false);

    assert!(
        seen.initiator_stderr
            .contains("\"--query-timeout-ms\", \"500\""),
        "the initiator's report of the expansion does not carry `--query-timeout-ms 500`, \
         so the file's `queries_default_timeout` never became the flag\n\
         --- initiator stderr ---\n{}",
        seen.initiator_stderr
    );
    assert!(
        seen.final_seen,
        "initiator wz-ap-demo did not log 'FINAL RECEIVED rid=1' within 2s; the file's \
         `queries_default_timeout: 500` should have fired the ReplyRegistry on_final \
         callback via the sweep task\n--- initiator stderr ---\n{}",
        seen.initiator_stderr
    );
    assert!(
        seen.final_elapsed >= Duration::from_millis(400),
        "FINAL fired too early ({:?}); the deadline was misset to 0 or the sweep raced \
         the register",
        seen.final_elapsed
    );
    assert!(
        seen.final_elapsed <= Duration::from_millis(2_000),
        "FINAL fired too late ({:?}); sweep cadence regression or driver-loop-tick stall",
        seen.final_elapsed
    );
}

/// CONTROL, key absent: no deadline reaches the register call, so the silent
/// peer leaves the pending entry open and no FINAL line appears.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features zenoh-config + wz-e2e-silent-peer); Layer E runs via --ignored"]
fn wz_ap_demo_query_without_the_timeout_key_in_a_config_file_never_fires_final() {
    let seen = query_a_silent_peer_given(DOC_WITHOUT_THE_KEY, true);

    assert!(
        !seen.initiator_stderr.contains("\"--query-timeout-ms\""),
        "a file that does not name `queries_default_timeout` expanded to \
         `--query-timeout-ms`\n--- initiator stderr ---\n{}",
        seen.initiator_stderr
    );
    assert!(
        !seen.final_seen,
        "FINAL fired after {:?} on a query whose file names no timeout; the sibling \
         leg's FINAL is therefore not attributable to the file's key\n\
         --- initiator stderr ---\n{}",
        seen.final_elapsed, seen.initiator_stderr
    );
}
