// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qa — multi-peer ROUTER e2e: `wz-ap-demo --router` binds ONCE and HOLDS N
//! concurrent peer faces (the `routing-router` catalog atom's foundation),
//! distinct from the one-shot `--listen` acceptor that serves a single peer.
//!
//! Topology: one `--router` process + two `--connect` initiators. The router's
//! accept loop brings each initiator's link to Established and holds it as a
//! *face*; both faces are alive at once (the two initiators idle as subscribers,
//! never closing), so the router's shutdown summary reports `peak 2 concurrent`
//! — the definitive "held both peers simultaneously" witness that a one-shot
//! acceptor could never produce.
//!
//! Requires the binary built with `--features routing-router` (the `--router`
//! arg is opt-in behind that feature; a default build rejects it with exit 2).
//! run-ci's Layer E builds the binary with the feature so this test rides the
//! same `--ignored` lane as the other binary-dep e2es.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router); Layer E runs via --ignored"]
fn wz_router_holds_two_concurrent_peers() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");

    // ── router: bind once, hold N peer faces (routing-router foundation) ──
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let router_writer = router_stderr.try_clone().expect("dup router stderr handle");
    let mut router_reader = router_stderr;
    let mut router_guard = ChildGuard::wrap(
        "wz-ap-demo router (--router)",
        Command::new(&demo)
            .arg("--router")
            .arg(&addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn wz-ap-demo --router"),
    );

    let bound = wait_for_substring(
        &mut router_reader,
        "router: listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = router_guard.child_mut().kill();
        let _ = router_guard.child_mut().wait();
        panic!(
            "wz-ap-demo --router did not log 'listening on' within 5s (is the binary \
             built with --features routing-router?)\n--- router stderr ---\n{captured}"
        );
    }
    // Router has bound — release the port-alloc mutex for parallel Layer E tests.
    drop(port_res);

    // ── two initiators: each dials the router and idles as a subscriber, so
    //    both faces are held by the router at the same time. ──
    let spawn_initiator = |label: &str| -> (ChildGuard, File) {
        let stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
        let writer = stderr.try_clone().expect("dup initiator stderr handle");
        let guard = ChildGuard::wrap(
            label.to_string(),
            Command::new(&demo)
                .arg("--connect")
                .arg(&addr)
                .arg("--key")
                .arg("demo/router-test")
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .expect("spawn wz-ap-demo --connect"),
        );
        (guard, stderr)
    };
    let (mut init0_guard, mut init0_reader) = spawn_initiator("wz-ap-demo initiator-0 (--connect)");
    let (mut init1_guard, mut init1_reader) = spawn_initiator("wz-ap-demo initiator-1 (--connect)");

    // Both initiators complete the TCP dial.
    let dial0 = wait_for_substring(&mut init0_reader, "connected to", Duration::from_secs(5));
    let dial1 = wait_for_substring(&mut init1_reader, "connected to", Duration::from_secs(5));

    // The router holds BOTH faces concurrently: face ids 0 and 1 each reach
    // Established (ids are assigned in accept order). Waiting for both UP lines
    // before shutdown guarantees the peak high-water mark is 2.
    let face0 = wait_for_substring(&mut router_reader, "face 0 UP", Duration::from_secs(10));
    let face1 = wait_for_substring(&mut router_reader, "face 1 UP", Duration::from_secs(10));

    // Graceful shutdown the router (SIGTERM) → it logs its accept-loop summary.
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    // Reap the initiators (the router shutdown closed their sockets).
    let _ = init0_guard.child_mut().kill();
    let _ = init0_guard.child_mut().wait();
    let _ = init1_guard.child_mut().kill();
    let _ = init1_guard.child_mut().wait();

    let init0_captured = read_captured(&mut init0_reader);
    let init1_captured = read_captured(&mut init1_reader);
    eprintln!("--- router stderr ---\n{router_captured}");
    eprintln!("--- initiator-0 stderr ---\n{init0_captured}");
    eprintln!("--- initiator-1 stderr ---\n{init1_captured}");

    // Diagnostics first (surface captured output on any failure), then assert.
    dial0.unwrap_or_else(|c| {
        panic!("initiator-0 did not log 'connected to' within 5s\n--- initiator-0 ---\n{c}\n--- router ---\n{router_captured}")
    });
    dial1.unwrap_or_else(|c| {
        panic!("initiator-1 did not log 'connected to' within 5s\n--- initiator-1 ---\n{c}\n--- router ---\n{router_captured}")
    });
    face0.unwrap_or_else(|c| {
        panic!("router did not log 'face 0 UP' within 10s\n--- router ---\n{c}")
    });
    face1.unwrap_or_else(|c| {
        panic!("router did not log 'face 1 UP' within 10s\n--- router ---\n{c}")
    });

    assert!(
        router_captured.contains("peak 2 concurrent"),
        "router summary must report peak 2 concurrent faces (held both peers at once)\n\
         --- router stderr ---\n{router_captured}"
    );
    assert!(
        router_captured.contains("served 2 peer(s)"),
        "router summary must report 2 peers served\n--- router stderr ---\n{router_captured}"
    );
}
