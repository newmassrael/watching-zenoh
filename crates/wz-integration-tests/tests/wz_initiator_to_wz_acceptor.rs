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
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
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
    let acceptor_stderr_writer = acceptor_stderr
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_guard = ChildGuard::wrap(
        "wz-ap-demo acceptor (--listen)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&addr)
            .arg("--key")
            .arg(sub_pattern)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(acceptor_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen"),
    );

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        // ChildGuard's Drop will kill+wait on panic-unwind. Explicit
        // graceful shutdown stays for the cooperative-stop path; the
        // guard is the panic safety net.
        let _ = acceptor_guard.child_mut().kill();
        let _ = acceptor_guard.child_mut().wait();
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
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_guard = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect)",
        Command::new(&demo)
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
            .expect("spawn wz-ap-demo --connect"),
    );

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

    let _ = initiator_guard.child_mut().kill();
    let _ = initiator_guard.child_mut().wait();
    let _ = acceptor_guard.child_mut().kill();
    let _ = acceptor_guard.child_mut().wait();

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

    // R247 — R222 simplified the SubscriberRegistry callback API to
    // take `&Sample` carrying the *resolved* keyexpr literal; the
    // wireexpr id is no longer surfaced at the callback layer (the
    // dispatch path consumes the id during resolution and only the
    // literal reaches `wz-ap-demo`'s log line). The prior
    // `wireexpr_id=0` assertion was a stale R222 follow-up that
    // R235-hotfix masked with `#[ignore]` rather than fixed; this
    // round retires the stale token and keeps the keyexpr literal
    // assertion which still pins the dispatch wire-shape: a
    // DECLARE-aliased regression would resolve to a different
    // literal or `None`, landing visibly in the keyexpr check.
    assert!(
        fired_text.contains(publish_key),
        "wz acceptor SUBSCRIBER FIRED line lacks the publish keyexpr '{publish_key}'.\n\
         --- acceptor stderr ---\n{fired_text}"
    );
}

/// R311pw — the `--reconnect` (long-lived reconnect-supervised) Initiator
/// lifecycle round-trips end-to-end at the BINARY level. This proves the demo
/// routes `--connect --reconnect` through `open_session_with_reconnect` +
/// `ReconnectingSession::drive` (NOT the one-shot `initiate_and_open_session`
/// path) and that the full demo machinery (publisher + subscriber observer +
/// teardown) works over the supervised drive.
///
/// The reconnect-AFTER-LOSS mechanism itself — re-dial + declaration-cache
/// replay, including DNS-named re-resolution — is exhaustively proven by the
/// library `session_reconnect_e2e` suite (the supervisor's `drive` loop the
/// binary uses verbatim). THIS test is the binary-level catalog-truthfulness
/// witness: preset-ap-client declares `session-reconnect`, and the showcase
/// binary now EXERCISES it (not merely compiles it).
///
/// Positive pin: the initiator must log "reconnect-supervised session
/// Established" — the supervisor open path. A regression that silently fell
/// back to the one-shot open would instead log "connected to" (via
/// `establish_link`, which the reconnect path skips), so the substring wait
/// localises a mis-route.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_reconnect_initiator_round_trip_against_wz_acceptor() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let publish_key = "demo/test";
    let sub_pattern = "demo/**";
    let publish_value = "hello-from-reconnect-initiator";

    // ── wz acceptor (listener + subscriber) ───────────────────
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_guard = ChildGuard::wrap(
        "wz-ap-demo acceptor (--listen)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&addr)
            .arg("--key")
            .arg(sub_pattern)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(acceptor_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen"),
    );

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_guard.child_mut().kill();
        let _ = acceptor_guard.child_mut().wait();
        panic!(
            "wz-ap-demo --listen did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── wz initiator (--reconnect dialer + publisher) ─────────
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_guard = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect --reconnect)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--reconnect")
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(initiator_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --reconnect"),
    );

    // Positive pin on the SUPERVISOR open path (the reconnect lifecycle skips
    // establish_link's "connected to" log; a one-shot fallback would not emit
    // this line).
    let supervised = wait_for_substring(
        &mut initiator_stderr_reader,
        "reconnect-supervised session Established",
        Duration::from_secs(5),
    );
    let fire_substr = "SUBSCRIBER FIRED";
    let fired = wait_for_substring(
        &mut acceptor_stderr_reader,
        fire_substr,
        Duration::from_secs(10),
    );

    // R311py — tear the reconnect initiator down with SIGTERM (graceful) so it
    // runs shutdown_signal() -> the drive fork's select!-None arm ->
    // ReconnectingSession::into_teardown() -> the R292 teardown chain. A raw
    // SIGKILL (Child::kill) would bypass that entire graceful path, leaving the
    // reconnect arm's into_teardown — added in this same track — uncovered. The
    // acceptor is a one-shot session; SIGKILL is fine for it.
    graceful_terminate(initiator_guard.child_mut(), Duration::from_secs(5));
    let _ = acceptor_guard.child_mut().kill();
    let _ = acceptor_guard.child_mut().wait();

    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    eprintln!("--- captured wz acceptor stderr ---\n{acceptor_captured}");
    eprintln!("--- captured wz reconnect initiator stderr ---\n{initiator_captured}");

    if let Err(c) = &supervised {
        panic!(
            "wz-ap-demo --connect --reconnect did not log 'reconnect-supervised \
             session Established' within 5s — the reconnect lifecycle did not route \
             through open_session_with_reconnect.\n\
             --- captured initiator stderr ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        );
    }

    let fired_text = match fired {
        Ok(c) => c,
        Err(c) => panic!(
            "wz acceptor did not log '{fire_substr}' within 10s — the reconnect-\
             supervised initiator's handshake or publisher emission regressed.\n\
             --- captured acceptor stderr at deadline ---\n{c}\n\
             --- captured initiator stderr at deadline ---\n{initiator_captured}"
        ),
    };
    assert!(
        fired_text.contains(publish_key),
        "wz acceptor SUBSCRIBER FIRED line lacks the publish keyexpr '{publish_key}'.\n\
         --- acceptor stderr ---\n{fired_text}"
    );

    // R311py — pin the GRACEFUL teardown path: SIGTERM (via graceful_terminate)
    // must drive the reconnect supervisor's shutdown-cancel arm +
    // ReconnectingSession::into_teardown(). This is the only automated coverage
    // of into_teardown; a SIGKILL teardown (the prior shape) would never emit
    // this line.
    assert!(
        initiator_captured.contains("reconnect session cancelled by graceful-shutdown signal"),
        "wz-ap-demo --reconnect did not log the graceful-shutdown teardown line under SIGTERM — \
         the shutdown-cancel + into_teardown path was not exercised.\n\
         --- initiator stderr ---\n{initiator_captured}"
    );
}

/// R311py — `--reconnect` is rejected with `--listen` (an acceptor has no client
/// reopen-task model; pico Z_FEATURE_AUTO_RECONNECT is client-only). The arg
/// guard (main.rs) exits 2 BEFORE any networking. Pins the negative path that
/// the type-level unrepresentability (`Role::Initiator{reconnect}`) cannot catch
/// — the flag is parsed before the role is constructed. No sockets, deterministic.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_reconnect_with_listen_is_rejected() {
    let demo = wz_ap_demo_binary();
    let out = Command::new(&demo)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--reconnect")
        .arg("--key")
        .arg("demo/**")
        .env("RUST_LOG", "info")
        .output()
        .expect("spawn wz-ap-demo --listen --reconnect");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--listen + --reconnect must exit 2 (usage error).\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("--reconnect requires --connect"),
        "rejection stderr lacks the '--reconnect requires --connect' diagnostic.\n\
         --- stderr ---\n{stderr}"
    );
}

/// R311py — a `serial/...` `--connect` with `--reconnect` is rejected as NOT
/// reconnectable. `reconnect_endpoint` parses the locator (the serial leaf is
/// ungated, so this needs no serial backend), narrows it via
/// `ReconnectLocator::try_from`, and surfaces `OpenError::NotReconnectable`;
/// `run_demo` returns `Err` → exit 1. The rejection is at parse/narrow time,
/// BEFORE any dial — no sockets, no tty, deterministic. Pins the binary's wiring
/// of the typed `NotReconnectable` boundary (unit-tested in the library; this is
/// its end-to-end surfacing through the demo).
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_reconnect_serial_connect_is_not_reconnectable() {
    let demo = wz_ap_demo_binary();
    let out = Command::new(&demo)
        .arg("--connect")
        .arg("serial//dev/ttyUSB0#baudrate=115200")
        .arg("--reconnect")
        .arg("--publish")
        .arg("demo/x")
        .arg("--value")
        .arg("y")
        .env("RUST_LOG", "info")
        .output()
        .expect("spawn wz-ap-demo --connect serial --reconnect");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "serial --connect --reconnect must exit 1 (open error).\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("reconnect session open failed"),
        "rejection stderr lacks the 'reconnect session open failed' diagnostic \
         (expected the NotReconnectable surfacing).\n--- stderr ---\n{stderr}"
    );
}
