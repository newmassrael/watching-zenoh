// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qc — router data-plane FORWARDING e2e: `wz-ap-demo --router` (built with
//! `--features routing-routes`) forwards a Put received on one peer face to
//! another peer face that declared a matching subscriber — the `routing-routes`
//! catalog atom on top of the `routing-router` accept-and-hold foundation.
//!
//! Topology: one `--router` + a `--key` consumer + a `--publish` producer, all
//! distinct processes (no co-located loopback). The consumer declares a routed
//! subscriber on `demo/route-fwd`; the producer publishes a Put on the same
//! keyexpr. Neither peer can hear the other directly (they each hold a single
//! link to the router); the consumer firing its subscriber callback is therefore
//! a definitive witness that the ROUTER forwarded the Put across faces — a
//! property the `routing-router` hold-only foundation (which routes nothing)
//! cannot produce. The router's shutdown summary independently reports
//! `forwarded N sample(s)` with `N >= 1`.
//!
//! Requires the binary built with `--features routing-routes` (the forwarding
//! router; `--features routing-router` alone holds faces but routes nothing, so
//! the consumer would never fire). run-ci's Layer E5 builds it with the feature
//! and runs this on the `--ignored` lane.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

/// The keyexpr both peers agree on — distinct from the other router e2e's
/// `demo/router-test` so parallel Layer E runs never cross-match.
const KEYEXPR: &str = "demo/route-fwd";

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes); Layer E runs via --ignored"]
fn wz_router_forwards_put_to_a_matching_subscriber_on_another_face() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");

    // ── router: bind once, hold faces, FORWARD Puts (routing-routes) ──
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let router_writer = router_stderr.try_clone().expect("dup router stderr handle");
    let mut router_reader = router_stderr;
    let mut router_guard = ChildGuard::wrap(
        "wz-ap-demo router (--router, routing-routes)",
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
             built with --features routing-routes?)\n--- router stderr ---\n{captured}"
        );
    }
    // Router bound — release the port-alloc mutex for parallel Layer E tests.
    drop(port_res);

    // ── consumer: declare a routed subscriber and idle. The router records the
    //    subscription only when its own poll of this face yields the Declare
    //    frame — asynchronous to the consumer logging "DECLARED" — so we do NOT
    //    rely on a strict declare-before-publish ordering. What guarantees the
    //    overlap is the producer's 5-Put / 200ms burst (tasks.rs): even if the
    //    first Put loses the race to the route being recorded, a later one wins,
    //    and one forwarded Put satisfies the witnesses below. ──
    let consumer_stderr = tempfile::tempfile().expect("tempfile for consumer stderr");
    let consumer_writer = consumer_stderr
        .try_clone()
        .expect("dup consumer stderr handle");
    let mut consumer_reader = consumer_stderr;
    let mut consumer_guard = ChildGuard::wrap(
        "wz-ap-demo consumer (--key)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--key")
            .arg(KEYEXPR)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(consumer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --key"),
    );

    // The consumer reached the router (face 0) and declared its subscriber; the
    // router has held face 0 and (on its next poll) recorded the route.
    let declared = wait_for_substring(
        &mut consumer_reader,
        "DECLARED ROUTED SUBSCRIBER",
        Duration::from_secs(5),
    );
    let face0 = wait_for_substring(&mut router_reader, "face 0 UP", Duration::from_secs(10));

    // ── producer: publish a Put on the same keyexpr (a finite burst). ──
    let producer_stderr = tempfile::tempfile().expect("tempfile for producer stderr");
    let producer_writer = producer_stderr
        .try_clone()
        .expect("dup producer stderr handle");
    let mut producer_reader = producer_stderr;
    let mut producer_guard = ChildGuard::wrap(
        "wz-ap-demo producer (--publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--publish")
            .arg(KEYEXPR)
            .arg("--value")
            .arg("forwarded-payload")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(producer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --publish"),
    );

    let emitted = wait_for_substring(
        &mut producer_reader,
        "PUBLISHER EMITTED",
        Duration::from_secs(10),
    );

    // The witness: the consumer's subscriber callback fired, which can only
    // happen if the router forwarded the producer's Put across faces.
    let fired = wait_for_substring(
        &mut consumer_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    );

    // Graceful shutdown the router → it logs its accept-loop + forward summary.
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    // Reap the peers (the router shutdown closed their sockets).
    let _ = producer_guard.child_mut().kill();
    let _ = producer_guard.child_mut().wait();
    let _ = consumer_guard.child_mut().kill();
    let _ = consumer_guard.child_mut().wait();

    let consumer_captured = read_captured(&mut consumer_reader);
    let producer_captured = read_captured(&mut producer_reader);
    eprintln!("--- router stderr ---\n{router_captured}");
    eprintln!("--- consumer stderr ---\n{consumer_captured}");
    eprintln!("--- producer stderr ---\n{producer_captured}");

    // Diagnostics first (surface captured output on any failure), then assert.
    declared.unwrap_or_else(|c| {
        panic!("consumer did not log 'DECLARED ROUTED SUBSCRIBER' within 5s\n--- consumer ---\n{c}\n--- router ---\n{router_captured}")
    });
    face0.unwrap_or_else(|c| {
        panic!("router did not log 'face 0 UP' within 10s\n--- router ---\n{c}")
    });
    emitted.unwrap_or_else(|c| {
        panic!("producer did not log 'PUBLISHER EMITTED' within 10s\n--- producer ---\n{c}\n--- router ---\n{router_captured}")
    });
    let fired_log = fired.unwrap_or_else(|c| {
        panic!(
            "consumer never fired its subscriber within 10s — the router did NOT forward \
             the Put across faces\n--- consumer ---\n{c}\n--- router ---\n{router_captured}"
        )
    });

    // The fired sample must carry the agreed keyexpr (not some stray match)
    // AND the full payload — "forwarded-payload" is 17 bytes, so a forward that
    // dropped or truncated the body would fail here even though the keyexpr
    // matched (the verbatim-clone payload-survival witness the unit suite, which
    // routes on keyexpr alone, cannot give).
    assert!(
        fired_log.contains(&format!("keyexpr='{KEYEXPR}'")),
        "consumer fired on the wrong keyexpr (expected {KEYEXPR})\n--- consumer ---\n{fired_log}"
    );
    assert!(
        fired_log.contains("payload_len=17"),
        "the forwarded sample must preserve the full 17-byte payload\n--- consumer ---\n{fired_log}"
    );

    // The router's own summary independently confirms it forwarded at least one
    // sample (a non-zero count — `forwarded 0 sample(s)` would mean the consumer
    // fired off a path other than the router, which the topology forbids).
    assert!(
        router_captured.contains("forwarded ") && !router_captured.contains("forwarded 0 sample"),
        "router summary must report a non-zero forward count\n--- router stderr ---\n{router_captured}"
    );
}
