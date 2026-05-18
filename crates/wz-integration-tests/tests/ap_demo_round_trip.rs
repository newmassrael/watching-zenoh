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
//   1. Pick a free TCP port (bind+drop dance — small race window
//      but practical for MVP).
//   2. Spawn wz-ap-demo --listen 127.0.0.1:<port> --key demo/test
//      with RUST_LOG=info; capture stderr to a tempfile.
//   3. Poll the demo's stderr until the "listening on" line appears
//      OR a 5s timeout fires. Surfaces a binding failure early
//      instead of waiting for the z_put timeout downstream.
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

use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn project_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/wz-integration-tests; the
    // project root is two levels up.
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("project root resolves from CARGO_MANIFEST_DIR")
}

fn wz_ap_demo_binary() -> PathBuf {
    // cargo emits the binary at crates/target/<profile>/wz-ap-demo.
    // The profile is unknown at test-build time (debug vs release),
    // so probe both — debug first since `cargo test` defaults to it.
    let crates_dir = project_root().join("crates");
    let candidates = [
        crates_dir.join("target/debug/wz-ap-demo"),
        crates_dir.join("target/release/wz-ap-demo"),
    ];
    for c in &candidates {
        if c.is_file() {
            return c.clone();
        }
    }
    panic!(
        "wz-ap-demo binary not found in {:?}; run `cargo build -p wz-ap-demo` first",
        candidates
    );
}

fn z_put_binary() -> PathBuf {
    let path = project_root().join("target/zenoh-pico-cli/z_put");
    assert!(
        path.is_file(),
        "z_put binary missing at {}; run scripts/build-zenoh-pico-cli.sh first",
        path.display()
    );
    path
}

/// Pick a free TCP port via bind+drop. There is a small race window
/// where another process can grab the port between drop and the
/// wz-ap-demo bind; acceptable for MVP testing (CI parallelism is
/// bounded and the port range is wide enough to make collision rare).
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

/// Read the captured stderr file into a string. The wz-ap-demo child
/// writes log lines asynchronously; we read whatever is available at
/// the time of inspection.
fn read_captured(file: &mut std::fs::File) -> String {
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("read captured stderr");
    s
}

fn wait_for_substring(
    file: &mut std::fs::File,
    needle: &str,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let captured = read_captured(file);
        if captured.contains(needle) {
            return Ok(captured);
        }
        if Instant::now() >= deadline {
            return Err(captured);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn ap_demo_round_trip_against_zenoh_pico_z_put() {
    let demo = wz_ap_demo_binary();
    let z_put = z_put_binary();
    let port = pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    let key = "demo/test";

    let stderr_capture = tempfile::tempfile().expect("tempfile for demo stderr");
    let stderr_capture_writer = stderr_capture.try_clone().expect("dup stderr handle");
    let mut stderr_capture_reader = stderr_capture;

    let mut child = Command::new(&demo)
        .arg("--listen")
        .arg(&listen_addr)
        .arg("--key")
        .arg(key)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_capture_writer))
        .spawn()
        .expect("spawn wz-ap-demo");

    // Wait for the binding-confirmed line; this prevents the z_put
    // spawn from racing against an unbound port.
    let bound = wait_for_substring(
        &mut stderr_capture_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n--- captured stderr ---\n{captured}"
        );
    }

    // Spawn z_put against the demo's endpoint. zenoh-pico's client
    // mode is the typical pattern for an initiator-side z_put.
    let z_put_status = Command::new(&z_put)
        .args(["-k", key, "-v", "hello-from-z_put", "-e", &endpoint, "-m", "client"])
        .status();

    // Two-stage wait: first the conservative `accepted peer` line
    // (proves the TCP wire-up reached the FSM entry), then the
    // `SUBSCRIBER FIRED` hard gate (proves the FSM handshake
    // completed AND the subscriber resolver fired on a mapping-id
    // Push). Each wait has its own 5s budget so a regression
    // localizes the failure: missing `accepted peer` means TCP
    // never connected; missing `SUBSCRIBER FIRED` means the wire
    // reached the FSM but a handshake / resolver step regressed.
    let accepted_result =
        wait_for_substring(&mut stderr_capture_reader, "accepted peer", Duration::from_secs(5));
    let subscriber_result =
        wait_for_substring(&mut stderr_capture_reader, "SUBSCRIBER FIRED", Duration::from_secs(5));

    // Tear down the demo. SIGTERM via kill(); on Unix this is SIGKILL
    // through std::process::Child — sufficient for test cleanup.
    let _ = child.kill();
    let _ = child.wait();

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
