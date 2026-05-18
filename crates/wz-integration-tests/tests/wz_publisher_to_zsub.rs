// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121e — reverse-direction (publisher) round-trip integration test.
//!
//! Drives the wz-ap-demo binary (R121e --publish/--value mode)
//! against an external zenoh-pico `z_sub` CLI peer over real TCP.
//! Mirrors the R121c/d `ap_demo_round_trip.rs` shape but exercises
//! the outbound Push path: wz-ap-demo as acceptor + publisher,
//! z_sub as client + subscriber.
//!
//! Test flow:
//!   1. Pick a free TCP port (bind+drop dance — small race window
//!      tolerated for MVP).
//!   2. Spawn wz-ap-demo --listen 127.0.0.1:<port> --publish
//!      demo/test --value hello-from-wz with RUST_LOG=info;
//!      capture stderr to a tempfile.
//!   3. Poll the demo's stderr until the "listening on" line
//!      appears OR a 5s timeout fires. Surfaces a binding failure
//!      early instead of waiting for z_sub timeouts downstream.
//!   4. Spawn z_sub -k "demo/**" -e tcp/127.0.0.1:<port> -m client.
//!      z_sub's stdout is line-buffered via `stdbuf -oL` so the
//!      "Received" line surfaces in near-real-time (printf to a
//!      piped fd is block-buffered by default on glibc — the
//!      R121d carry memory `feedback_foreign_peer_crash_diagnosis`
//!      pinned this gotcha when it cost us an hour of dead-air).
//!      z_sub stdout is captured to a tempfile for the gate poll.
//!   5. Wait up to 10s for the z_sub stdout to contain
//!      `>> [Subscriber] Received` AND `demo/test` AND
//!      `hello-from-wz` — three substring assertions split across
//!      one captured snapshot so a regression on either the
//!      keyexpr or the payload localizes the failure surface.
//!   6. SIGTERM both children + surface the captured stderr +
//!      stdout on any failed assertion.
//!
//! This is the second integration test that drives the wz codec
//! catalog + session FSM against a foreign implementation
//! (`ap_demo_round_trip.rs` was the first). Together they cover
//! both directions of the AP MVP pub/sub round-trip — wz acceptor
//! receives Push (R121c/d) AND wz acceptor emits Push (R121e).

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

fn z_sub_binary() -> PathBuf {
    let path = project_root().join("target/zenoh-pico-cli/z_sub");
    assert!(
        path.is_file(),
        "z_sub binary missing at {}; run scripts/build-zenoh-pico-cli.sh first",
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

/// Read the captured output file into a string. The child writes
/// log/stdout lines asynchronously; we read whatever is available
/// at the time of inspection.
fn read_captured(file: &mut std::fs::File) -> String {
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("read captured output");
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
fn wz_publisher_round_trip_against_zenoh_pico_z_sub() {
    let demo = wz_ap_demo_binary();
    let z_sub = z_sub_binary();
    let port = pick_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // Publisher emits on "demo/test"; z_sub subscribes to
    // "demo/**" so the local matcher accepts. Using a wildcard
    // pattern on z_sub side proves the keyexpr-suffix path
    // round-trips through the literal-keyexpr (id=0 + suffix)
    // resolver on zenoh-pico's receive side.
    let publish_key = "demo/test";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz";

    // ── wz-ap-demo (acceptor + publisher) ────────────────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = Command::new(&demo)
        .arg("--listen")
        .arg(&listen_addr)
        .arg("--publish")
        .arg(publish_key)
        .arg("--value")
        .arg(publish_value)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(demo_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo");

    // Wait for the binding-confirmed line; this prevents the
    // z_sub spawn from racing against an unbound port.
    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.kill();
        let _ = demo_child.wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    // ── z_sub (client + subscriber) ──────────────────────────
    // `stdbuf -oL` forces line buffering on z_sub's stdout so
    // the ">> [Subscriber] Received" line surfaces in
    // near-real-time. printf to a piped fd is block-buffered
    // by default on glibc, which would otherwise hide the
    // line until z_sub exits — the test would then time out
    // before seeing the success witness. This is the same
    // gotcha pinned by the R121d carry memory
    // `feedback_foreign_peer_crash_diagnosis` (debug 5min cost
    // when stdout dropped a SEGV traceback on the same
    // mechanism).
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer =
        z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_sub)
        .args(["-k", sub_key, "-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(z_sub_stdout_writer))
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn z_sub via stdbuf");

    // Two-stage wait. First the conservative "Opening session..."
    // line — proves z_sub started and is attempting the TCP +
    // zenoh handshake. Then the hard-gate "Received" line — proves
    // the full handshake AND DECLARE subscriber emission AND
    // wz-ap-demo's Push reached z_sub AND z_sub's local matcher
    // fired the callback. Each wait has its own timeout so a
    // regression localizes the failure surface.
    let session_opening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Opening session",
        Duration::from_secs(5),
    );
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    // Tear down both children. SIGTERM via kill(); on Unix this is
    // SIGKILL through std::process::Child — sufficient for test
    // cleanup. `stdbuf` is a thin shim, so killing the demo and
    // z_sub processes is enough; the shim's own waitpid surfaces
    // via z_sub_child.wait().
    let _ = z_sub_child.kill();
    let _ = z_sub_child.wait();
    let _ = demo_child.kill();
    let _ = demo_child.wait();

    // Surface captured output on any failed assertion so a
    // session-FSM log line (codec error, lease expiry, etc.) or
    // a zenoh-pico stderr is visible in the cargo test output
    // without re-running.
    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    if let Err(c) = &session_opening {
        panic!(
            "z_sub did not log 'Opening session' within 5s — z_sub binary failed to \
             initialize. Captured z_sub stdout:\n{c}\n\
             --- captured demo stderr ---\n{demo_captured}"
        );
    }

    // Hard gate. If the line is missing, surface the full
    // captured streams + assert on each of the keyexpr + value
    // substrings independently so the failure message points
    // at the actual mismatch.
    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz-ap-demo Push did not \
             reach z_sub's subscriber callback.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured demo stderr at deadline ---\n{demo_captured}"
        ),
    };

    // Belt-and-suspenders gates on the keyexpr + value
    // substrings. The `received_substr` check already passed;
    // these surface a partial-match (e.g. wrong payload bytes
    // sneaking through, or keyexpr drift) with a localized
    // panic.
    assert!(
        received_text.contains(publish_key),
        "z_sub captured the 'Received' line but the publish keyexpr '{publish_key}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub captured the 'Received' line but the publish value '{publish_value}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
}
