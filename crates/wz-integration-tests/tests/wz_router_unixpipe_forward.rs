// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y395 — the wz `--router` data-plane FORWARDING e2e OVER UNIXPIPE: a single
//! `wz-ap-demo --router unixpipe/<base>` (built `--features
//! routing-routes,transport-link-unixpipe`) holds TWO concurrent `--connect
//! unixpipe/<base>` clients and forwards a Put received on one client's face to the
//! other client's face, which declared a matching subscriber.
//!
//! This is the ACCEPTOR-concurrency counterpart of R311y394 (the DIALER-concurrency
//! leg, where two wz clients dialed ONE zenohd unixpipe listener): here WZ is the
//! multi-client routing LISTENER over IPC. It is the exact transport-mirror of the
//! TCP template `wz_router_forward.rs::wz_router_forwards_put_to_a_matching_
//! subscriber_on_another_face` — only tcp -> unixpipe changes, so a GREEN here
//! isolates "the unixpipe acceptor + RoutingForwarder route between two held faces"
//! as the single moving part.
//!
//! Topology: one `--router unixpipe/<base>` + a `--key` consumer + a `--publish`
//! producer, all distinct processes. The consumer declares a routed subscriber on
//! `demo/unixpipe/route-fwd`; the producer publishes a Put on the same keyexpr.
//! Neither client can hear the other directly (each holds a single unixpipe link to
//! the router); the consumer firing its subscriber callback is therefore a
//! definitive witness that the ROUTER forwarded the Put ACROSS unixpipe faces — a
//! property the `routing-router` hold-only foundation (which routes nothing) cannot
//! produce. The router's shutdown summary independently reports `forwarded N
//! sample(s)` with `N >= 1`. Both clients dial with the demo's hardwired zid
//! `0x01020304`; a wz `--router` holds two same-zid faces (unlike zenohd, whose
//! zid-uniqueness would "Terminal" the second — that was the R311y394 finding, a
//! zenohd router property, NOT a transport one), so no `--zid` is needed here (the
//! TCP template `wz_router_multi_peer.rs` proves the same-zid concurrent hold).
//!
//! RED reproductions (each proves the GREEN binds to the unixpipe cross-face route,
//! not a vehicle):
//!  - a non-matching producer keyexpr -> the consumer never fires (delivery
//!    discriminator: the route is keyed on the agreed expr, not "any Put lands");
//!  - the binary built with `routing-router` only (no `routing-routes`) -> the
//!    router installs `NoOpForwarder` and holds the two faces but routes nothing,
//!    so the consumer never fires (proves FORWARDING over unixpipe, not mere hold).
//!
//! Requires the binary built with `--features routing-routes,transport-link-unixpipe`
//! (the forwarding router + the unixpipe transport). Linux-only (the unixpipe
//! backend's `read_write` open-rendezvous). No external oracle (pure wz<->wz), so
//! run-ci gates it on a self-contained lane beside Layer E5, NOT the zenohd Layer Z.
//! Every fn name starts `wz_router_` so the default Layer E sweep's `--skip
//! wz_router` excludes it from the oracle-less arbitrary-feature run (the
//! `[[feedback_proof_that_never_runs]]` discipline: a mis-selected #[ignore] e2e
//! must never run under the wrong binary and RED the primary sweep).

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_unixpipe_request_fifo,
    wz_ap_demo_binary, ChildGuard,
};

/// The keyexpr both clients agree on — distinct from the other router e2e's
/// `demo/route-fwd` and from the dataplane suite's `demo/unixpipe/**` filter so
/// parallel Layer E runs never cross-match.
const KEYEXPR: &str = "demo/unixpipe/route-fwd";

/// A per-process-unique unixpipe base path under the temp dir; the request FIFO is
/// `<base>_uplink`. A dedicated `router-` tag keeps it disjoint from the
/// `wz_unixpipe_zenohd_dataplane` (`wz-uxp-dp-`) and `..._interop`
/// (`wz-uxp-zenohd-`) bases so parallel test binaries never share nodes.
fn unixpipe_base(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("wz-uxp-router-{tag}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Best-effort cleanup of a base's request FIFO AND every dedicated per-connection
/// sub-pipe node (`{base}_uplink`/`{base}_downlink` plus their decimal-suffixed
/// twins). The dedicated read-ends normally auto-unlink on Drop, but the test
/// SIGKILLs its children, so Drop never runs; this globs the whole
/// `{base}_uplink*`/`{base}_downlink*` family so no 0-byte FIFO inode accumulates
/// across runs. A stale node is harmless regardless — `base` embeds the pid — this
/// is temp-dir hygiene. (Mirror of `wz_unixpipe_zenohd_dataplane.rs::cleanup`.)
fn cleanup(base: &str) {
    let path = std::path::Path::new(base);
    let (dir, name) = match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => (dir.to_path_buf(), name.to_string_lossy().into_owned()),
        _ => return,
    };
    let up = format!("{name}_uplink");
    let down = format!("{name}_downlink");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            if fname.starts_with(&up) || fname.starts_with(&down) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Literal-keyexpr forwarding over unixpipe: the wz `--router unixpipe/<base>`
/// forwards a producer client's Put to the consumer client that declared a matching
/// subscriber, both connected over their own dedicated unixpipe sub-pipe pair.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes,transport-link-unixpipe); Layer E5u runs via --ignored"]
fn wz_router_forwards_a_put_between_two_unixpipe_clients() {
    let demo = wz_ap_demo_binary();
    let base = unixpipe_base("fwd");
    cleanup(&base);
    let listen = format!("unixpipe/{base}");

    // ── router: bind ONE unixpipe listener, hold N faces, FORWARD Puts
    //    (routing-routes). Unlike the TCP template there is no port to reserve; the
    //    request FIFO appearing is the acceptor's readiness signal. ──
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let router_writer = router_stderr.try_clone().expect("dup router stderr handle");
    let mut router_reader = router_stderr;
    let mut router_guard = ChildGuard::wrap(
        "wz-ap-demo router (--router unixpipe, routing-routes)",
        Command::new(&demo)
            .arg("--router")
            .arg(&listen)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn wz-ap-demo --router unixpipe"),
    );

    let bound = wait_for_substring(
        &mut router_reader,
        "router: listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = router_guard.child_mut().kill();
        let _ = router_guard.child_mut().wait();
        cleanup(&base);
        panic!(
            "wz-ap-demo --router unixpipe did not log 'listening on' within 5s (is the \
             binary built with --features routing-routes,transport-link-unixpipe?)\n\
             --- router stderr ---\n{captured}"
        );
    }
    // The request FIFO (`<base>_uplink`) must exist before a client dials it — a
    // unixpipe listener has no TCP port, so the request node appearing is the
    // race-free "ready to accept" signal (mirror of the dataplane suite).
    let fifo_ready = wait_for_unixpipe_request_fifo(&base, Duration::from_secs(5));

    // ── consumer: declare a routed subscriber over its own unixpipe link and idle.
    //    The route is recorded when the router's poll of this face yields the
    //    Declare frame (async to the consumer logging DECLARED), so we do NOT rely
    //    on strict declare-before-publish ordering — the producer's 5-Put/200ms
    //    burst guarantees at least one Put overlaps the installed route. ──
    let consumer_stderr = tempfile::tempfile().expect("tempfile for consumer stderr");
    let consumer_writer = consumer_stderr
        .try_clone()
        .expect("dup consumer stderr handle");
    let mut consumer_reader = consumer_stderr;
    let mut consumer_guard = ChildGuard::wrap(
        "wz-ap-demo consumer (--connect unixpipe --key)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&listen)
            .arg("--key")
            .arg(KEYEXPR)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(consumer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe --key"),
    );

    // The consumer reached the router over UNIXPIPE (not a silent fallback) and
    // declared its subscriber; the router held its face and (on its next poll)
    // recorded the route.
    let consumer_dialed = wait_for_substring(
        &mut consumer_reader,
        "over unixpipe transport",
        Duration::from_secs(5),
    );
    let declared = wait_for_substring(
        &mut consumer_reader,
        "DECLARED ROUTED SUBSCRIBER",
        Duration::from_secs(5),
    );
    let face0 = wait_for_substring(&mut router_reader, "face 0 UP", Duration::from_secs(10));

    // ── producer: publish a Put on the same keyexpr (a finite burst) over its OWN
    //    dedicated unixpipe sub-pipe pair (the SECOND concurrent client). ──
    let producer_stderr = tempfile::tempfile().expect("tempfile for producer stderr");
    let producer_writer = producer_stderr
        .try_clone()
        .expect("dup producer stderr handle");
    let mut producer_reader = producer_stderr;
    let mut producer_guard = ChildGuard::wrap(
        "wz-ap-demo producer (--connect unixpipe --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&listen)
            .arg("--publish")
            .arg(KEYEXPR)
            .arg("--value")
            .arg("forwarded-payload")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(producer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe --publish"),
    );

    let producer_dialed = wait_for_substring(
        &mut producer_reader,
        "over unixpipe transport",
        Duration::from_secs(5),
    );
    let emitted = wait_for_substring(
        &mut producer_reader,
        "PUBLISHER EMITTED",
        Duration::from_secs(10),
    );

    // The witness: the consumer's subscriber callback fired, which can only happen
    // if the router forwarded the producer's Put ACROSS the two unixpipe faces.
    let fired = wait_for_substring(
        &mut consumer_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    );

    // Graceful shutdown the router → it logs its accept-loop + forward summary.
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    // Reap the clients (the router shutdown closed their links).
    let _ = producer_guard.child_mut().kill();
    let _ = producer_guard.child_mut().wait();
    let _ = consumer_guard.child_mut().kill();
    let _ = consumer_guard.child_mut().wait();

    let consumer_captured = read_captured(&mut consumer_reader);
    let producer_captured = read_captured(&mut producer_reader);
    eprintln!("--- router stderr ---\n{router_captured}");
    eprintln!("--- consumer stderr ---\n{consumer_captured}");
    eprintln!("--- producer stderr ---\n{producer_captured}");

    // Best-effort FIFO hygiene (children were SIGKILLed, so Drop never ran).
    cleanup(&base);

    // Diagnostics first (surface captured output on any failure), then assert.
    assert!(
        fifo_ready,
        "the unixpipe request FIFO ({base}_uplink) never appeared within 5s — the \
         router's acceptor did not become ready\n--- router ---\n{router_captured}"
    );
    consumer_dialed.unwrap_or_else(|c| {
        panic!(
            "consumer did not reach the router 'over unixpipe transport' within 5s (a \
                non-unixpipe fallback would invalidate the crossing)\n--- consumer ---\n{c}"
        )
    });
    declared.unwrap_or_else(|c| {
        panic!("consumer did not log 'DECLARED ROUTED SUBSCRIBER' within 5s\n--- consumer ---\n{c}\n--- router ---\n{router_captured}")
    });
    face0.unwrap_or_else(|c| {
        panic!("router did not log 'face 0 UP' within 10s\n--- router ---\n{c}")
    });
    producer_dialed.unwrap_or_else(|c| {
        panic!("producer did not reach the router 'over unixpipe transport' within 5s\n--- producer ---\n{c}")
    });
    emitted.unwrap_or_else(|c| {
        panic!("producer did not log 'PUBLISHER EMITTED' within 10s\n--- producer ---\n{c}\n--- router ---\n{router_captured}")
    });
    let fired_log = fired.unwrap_or_else(|c| {
        panic!(
            "consumer never fired its subscriber within 10s — the router did NOT forward \
             the Put across the two unixpipe faces\n--- consumer ---\n{c}\n--- router ---\n{router_captured}"
        )
    });

    // The fired sample must carry the agreed keyexpr (not some stray match) AND the
    // full payload — "forwarded-payload" is 17 bytes, so a forward that dropped or
    // truncated the body over the unixpipe crossing would fail here even though the
    // keyexpr matched.
    assert!(
        fired_log.contains(&format!("keyexpr='{KEYEXPR}'")),
        "consumer fired on the wrong keyexpr (expected {KEYEXPR})\n--- consumer ---\n{fired_log}"
    );
    assert!(
        fired_log.contains("payload_len=17"),
        "the forwarded sample must preserve the full 17-byte payload across unixpipe\n--- consumer ---\n{fired_log}"
    );

    // The router's own summary independently confirms it forwarded at least one
    // sample (`forwarded 0 sample(s)` would mean the consumer fired off a path other
    // than the router, which the topology forbids).
    assert!(
        router_captured.contains("forwarded ") && !router_captured.contains("forwarded 0 sample"),
        "router summary must report a non-zero forward count\n--- router stderr ---\n{router_captured}"
    );

    // The headline this test exists to prove over the TCP E5 template: the router
    // held BOTH clients' unixpipe faces CONCURRENTLY (not serialized one-at-a-time)
    // — its shutdown summary reports the high-water face count directly. Pins the
    // ACCEPTOR-concurrency claim so a future regression that serialized clients
    // (peak 1) would RED even though a single forward still succeeded.
    assert!(
        router_captured.contains("peak 2 concurrent"),
        "router must have held TWO concurrent unixpipe faces (peak 2 concurrent)\n\
         --- router stderr ---\n{router_captured}"
    );
}
