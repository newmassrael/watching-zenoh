// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311or — first cross-impl interop against the zenoh-full REFERENCE router.
//!
//! Every other interop test pairs wz with zenoh-PICO (the embedded C impl).
//! This pairs wz with `zenohd` v1.5.0 — the canonical Rust router — exercised
//! through the SAME binary + harness SSOT as the pico interop suite: the wz
//! side is the production `wz-ap-demo` binary (which already announces the
//! zenoh protocol `version = 0x09` and `whatami = Client` on its `--connect`
//! initiator path — `args.rs`), zenohd is spawned as the foreign router, and
//! `ChildGuard` / `wait_for_substring` / the binary locators are the shared
//! `common` harness. No in-process dial, no per-test harness fork, no
//! version override — wz speaks the reference protocol out of the box.
//!
//! Two legs:
//!   1. `wz_client_reaches_established_against_zenohd` — wz dials zenohd and
//!      completes InitSyn/InitAck/OpenSyn/OpenAck to Established (transport
//!      wire-parity with the canonical implementation). Deterministic: the
//!      handshake does not depend on any other peer.
//!   2. `wz_publish_routes_through_zenohd_to_pico_zsub` — wz's `Put` is routed
//!      by zenohd to a zenoh-pico `z_sub` (data-plane cross-impl through the
//!      reference router). wz emits a Put burst (wz-ap-demo's publisher_task)
//!      so a Put lands after z_sub's subscription has propagated to zenohd.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z) AND binary-dep: zenohd is an external
//! 1.5.0 build (`scripts/build-zenohd.sh`), not a wz artifact, so it never
//! gates the default sweep.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wait_for_tcp_accept, wz_ap_demo_binary,
    zenoh_pico_cli_binary, zenohd_binary, ChildGuard, PortReservation,
};

/// Spawn a TCP-only zenohd router on the reserved `port` and block until its
/// listener accepts (a probe `TcpStream::connect`). `--no-multicast-scouting` +
/// `--rest-http-port none` keep it to a single unicast TCP listener.
///
/// Readiness is a TCP-accept probe, NOT a stderr-log wait: zenohd block-buffers
/// its startup logs to a non-TTY fd, so a captured-stderr `wait_for_substring`
/// races the flush and times out with an empty capture (verified). A successful
/// connect proves the listener is up — the signal the clients actually need.
fn spawn_zenohd(port: u16) -> ChildGuard {
    let guard = ChildGuard::wrap(
        "zenohd (reference router)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd"),
    );
    assert!(
        wait_for_tcp_accept(port, Duration::from_secs(10)),
        "zenohd did not start accepting on tcp/127.0.0.1:{port} within 10s"
    );
    guard
}

/// Spawn a zenoh-pico `z_sub` against zenohd and return it once its session is
/// OPEN and the subscriber DECLARED (stdout line "Declaring Subscriber on ...").
/// pico's `z_sub` is a one-shot that prints "Unable to open session!" and exits
/// if its session open transiently fails — and it does NOT self-retry. Under
/// full-run-ci load that open occasionally fails, so the orchestrator retries
/// the spawn here. This is robustness for a FOREIGN one-shot binary, not a wz
/// workaround: the wz side is deterministic (the handshake test + 20x standalone
/// pass), and a transiently-failed `z_sub` open is not a wz defect — retrying it
/// keeps the data-plane assertion zero-flake. Returns the subscribed child + its
/// stdout reader for the `Received` wait.
fn spawn_subscribed_zsub(z_sub: &Path, sub_key: &str, endpoint: &str) -> (ChildGuard, File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_sub stdout");
        let out_writer = out.try_clone().expect("dup z_sub stdout handle");
        let mut out_reader = out;
        let mut child = ChildGuard::wrap(
            "z_sub client (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_sub)
                .args(["-k", sub_key, "-e", endpoint, "-m", "client"])
                .stdout(Stdio::from(out_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn z_sub via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains("Declaring Subscriber on") {
                return (child, out_reader); // session open + subscriber declared
            }
            if cap.contains("Unable to open session") || Instant::now() >= deadline {
                break; // transient open failure / timeout -> respawn
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_sub open attempt {attempt}/{ATTEMPTS} did not subscribe; retrying");
    }
    panic!("pico z_sub failed to open a session to zenohd after {ATTEMPTS} attempts");
}

/// wz dials zenohd as a client and reaches Established — the handshake
/// interoperates with the reference router. Deterministic (no peer-timing race).
#[test]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_client_reaches_established_against_zenohd() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd"),
    );

    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s — the wz<->zenohd \
             handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// wz's Put routes through zenohd to a zenoh-pico `z_sub` — the data-plane
/// cross-impl through the reference router.
#[test]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
fn wz_publish_routes_through_zenohd_to_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let publish_key = "demo/zenohd";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-via-zenohd";

    let mut zenohd = spawn_zenohd(port);
    drop(port_res);

    // ── pico z_sub: a client of zenohd, subscribed and ready (retried past any
    //    transient one-shot open failure). Its declared subscription is the
    //    route zenohd uses to forward wz's Put.
    let (mut z_sub_child, mut z_sub_stdout_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint);

    // ── wz-ap-demo: a client of zenohd that emits a Put burst. The burst
    //    (publisher_task) covers the window for z_sub's subscription to reach
    //    zenohd; a Put landing after that propagation is routed to z_sub.
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd"),
    );

    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz's Put did not route \
             through zenohd to z_sub.\n--- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-ap-demo stderr ---\n{demo_captured}"
        ),
    };
    assert!(
        received_text.contains(publish_key),
        "z_sub received but the publish keyexpr '{publish_key}' is missing.\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub received but the publish value '{publish_value}' is missing.\n{received_text}"
    );
}
