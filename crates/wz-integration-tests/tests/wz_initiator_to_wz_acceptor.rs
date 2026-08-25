// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    graceful_terminate, read_captured, spawn_listen_acceptor, wait_for_substring,
    wz_ap_demo_binary, ChildGuard, PortReservation,
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
    let (mut acceptor_guard, mut acceptor_stderr_reader) = spawn_listen_acceptor(
        &demo,
        &addr,
        sub_pattern,
        "wz-ap-demo acceptor (--listen)",
        tempfile::tempfile().expect("tempfile for acceptor stderr"),
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
    let (mut acceptor_guard, mut acceptor_stderr_reader) = spawn_listen_acceptor(
        &demo,
        &addr,
        sub_pattern,
        "wz-ap-demo acceptor (--listen)",
        tempfile::tempfile().expect("tempfile for acceptor stderr"),
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

/// R311q1 — the long-lived `--reconnect` Initiator RESUMES its DATA PLANE
/// against a freshly RE-SPAWNED Acceptor after a genuine process-death sever:
/// the binary-level sever-reconnect witness (carry #1). Flow: A1 (`--listen
/// --key`) accepts the initiator and fires its subscriber on the initiator's
/// Puts; A1 is SIGKILLed + fully reaped; A2 is spawned on the SAME port; the
/// reconnect supervisor re-dials, and A2 — a FRESH process — fires its
/// subscriber on a Put the initiator emits AFTER the reconnect.
///
/// The DATA-plane witness (post-reconnect Push → A2 SUBSCRIBER FIRED) is the
/// point of a long-lived `--reconnect` client: it resumes its application work
/// across the sever, not merely its control-plane declarations. It is
/// deterministic because the `--reconnect` publisher is PERIODIC (re-arms per
/// (re)Established, R311q1) — guaranteed to emit a fresh Put once the supervisor
/// re-establishes against A2, regardless of how long the reconnect takes. The
/// in-process control-plane mechanism (declaration-cache replay) is proven by
/// the library `session_reconnect_e2e`; THIS proves two real processes survive a
/// real process kill end to end.
///
/// Same-port respawn: A2 rebinds the fixed port because A1 is fully reaped
/// (`kill` + `wait`) AND the initiator tore down its half on link-loss, so
/// nothing holds the listening port — and tokio's `TcpListener::bind` sets
/// `SO_REUSEADDR` on Unix regardless (mio). `port_res` is held across the
/// A1->A2 gap so no other in-process test grabs the freed port. (Earlier rounds
/// mis-attributed this rebind to a wz-added SO_REUSEADDR "de-risk"; the
/// adversarial review in R311q1 falsified that — the rebind never depended on
/// it. See the R311q1 ledger.)
///
/// Two independent witnesses:
///   - acceptor-side: A2 (a fresh process) logs "SUBSCRIBER FIRED" for the
///     publish keyexpr → the initiator reconnected to A2 and resumed publishing.
///   - initiator-side: the graceful-teardown line reports "reconnects=1" → the
///     supervisor performed exactly one successful reopen (failed dial retries
///     do not increment the counter, so 1 is exact for a single sever).
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_reconnect_initiator_resumes_against_respawned_acceptor() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let publish_key = "demo/reconnect/resume";
    let publish_value = "post-reconnect-payload";

    // ── A1: first acceptor (subscriber on the publish keyexpr) ──
    let (mut a1_guard, mut a1_reader) = spawn_listen_acceptor(
        &demo,
        &addr,
        publish_key,
        "wz-ap-demo acceptor A1 (--listen)",
        tempfile::tempfile().expect("tempfile for A1 stderr"),
    );
    if let Err(captured) =
        wait_for_substring(&mut a1_reader, "listening on", Duration::from_secs(5))
    {
        panic!("A1 --listen did not log 'listening on' within 5s\n--- A1 stderr ---\n{captured}");
    }

    // ── initiator: long-lived reconnect supervisor + PERIODIC publisher.
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_reader = initiator_stderr;
    let mut initiator_guard = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect --reconnect --publish)",
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
            .stderr(Stdio::from(initiator_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --reconnect"),
    );

    // Positive pin on the supervisor open path (a one-shot fallback would log
    // "connected to" via establish_link, which the reconnect path skips).
    let supervised = wait_for_substring(
        &mut initiator_reader,
        "reconnect-supervised session Established",
        Duration::from_secs(5),
    );
    // A1 fires on the initiator's first Put → initial data plane proved.
    let a1_fired = wait_for_substring(&mut a1_reader, "SUBSCRIBER FIRED", Duration::from_secs(10));

    // ── SEVER: SIGKILL A1 and fully reap it. The initiator's link drops; the
    //    supervisor begins re-dialing every retry_delay_ms (1s, pico parity).
    let _ = a1_guard.child_mut().kill();
    let _ = a1_guard.child_mut().wait();

    // ── RESPAWN A2 on the SAME port. port_res is STILL held so no other
    //    in-process test grabs the freed port during the A1->A2 gap.
    let (mut a2_guard, mut a2_reader) = spawn_listen_acceptor(
        &demo,
        &addr,
        publish_key,
        "wz-ap-demo acceptor A2 (--listen respawn)",
        tempfile::tempfile().expect("tempfile for A2 stderr"),
    );
    let a2_bound = wait_for_substring(&mut a2_reader, "listening on", Duration::from_secs(5));
    // A2 owns the port now; release the reservation for other tests.
    drop(port_res);

    // A2 (a FRESH process) fires on a Put the periodic publisher emits AFTER the
    // reconnect → data-plane resumption across the sever. Generous budget: the
    // supervisor retries at 1s and the publisher re-arms each (re)Established.
    let a2_fired = wait_for_substring(&mut a2_reader, "SUBSCRIBER FIRED", Duration::from_secs(20));

    // ── teardown: graceful SIGTERM on the initiator (drives into_teardown +
    //    surfaces the reconnects counter; the periodic publisher stops on the
    //    same signal, dropping its session clone before teardown), then kill A2.
    graceful_terminate(initiator_guard.child_mut(), Duration::from_secs(5));
    let _ = a2_guard.child_mut().kill();
    let _ = a2_guard.child_mut().wait();

    let a1_captured = read_captured(&mut a1_reader);
    let a2_captured = read_captured(&mut a2_reader);
    let initiator_captured = read_captured(&mut initiator_reader);
    eprintln!("--- captured A1 stderr ---\n{a1_captured}");
    eprintln!("--- captured A2 stderr ---\n{a2_captured}");
    eprintln!("--- captured initiator stderr ---\n{initiator_captured}");

    if let Err(c) = &supervised {
        panic!(
            "initiator did not log 'reconnect-supervised session Established' within 5s — the \
             reconnect lifecycle did not route through reconnect_endpoint.\n\
             --- initiator stderr ---\n{c}\n--- A1 stderr ---\n{a1_captured}"
        );
    }
    let a1_text = match a1_fired {
        Ok(c) => c,
        Err(c) => panic!(
            "A1 did not log 'SUBSCRIBER FIRED' within 10s — the initial connect or the periodic \
             publisher's first emit regressed.\n\
             --- A1 stderr at deadline ---\n{c}\n--- initiator stderr ---\n{initiator_captured}"
        ),
    };
    assert!(
        a1_text.contains(publish_key),
        "A1 SUBSCRIBER FIRED line lacks the publish keyexpr '{publish_key}'.\n--- A1 stderr ---\n{a1_text}"
    );

    if let Err(c) = &a2_bound {
        panic!(
            "A2 --listen did not rebind '{addr}' within 5s — the fixed-port respawn failed.\n\
             --- A2 stderr ---\n{c}"
        );
    }
    let a2_text = match a2_fired {
        Ok(c) => c,
        Err(c) => panic!(
            "A2 (respawn) did not log 'SUBSCRIBER FIRED' within 20s — the supervisor did not \
             reconnect to A2 and the periodic publisher did not resume its data plane across the \
             sever.\n--- A2 stderr at deadline ---\n{c}\n--- initiator stderr ---\n{initiator_captured}"
        ),
    };
    assert!(
        a2_text.contains(publish_key),
        "A2 SUBSCRIBER FIRED line lacks the publish keyexpr '{publish_key}'.\n--- A2 stderr ---\n{a2_text}"
    );

    // Initiator-side witness: exactly one successful reopen (failed dial retries
    // do not increment the counter, so '1' is exact for a single sever).
    assert!(
        initiator_captured.contains("reconnects=1"),
        "initiator graceful-teardown line lacks 'reconnects=1' — the supervisor did not record \
         exactly one successful reopen across the sever.\n--- initiator stderr ---\n{initiator_captured}"
    );
}
