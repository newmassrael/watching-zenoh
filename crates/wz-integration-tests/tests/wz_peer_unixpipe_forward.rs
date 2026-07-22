// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y397 — the wz `--peer` (a `WhatAmI::Peer` running the linkstate mesh
//! forwarder) binds a UNIXPIPE listener and forwards a Put across two concurrent
//! clients: the peer run-mode counterpart of R311y395 (star `--router`, test-only)
//! and R311y396 (`--router-hat`, a true Router). Like run_router_hat, run_peer
//! derived its node zid from the listen `.port()` and rendered its self dial locator
//! from the listen `.ip()`, so a non-IP unixpipe listen was rejected at bind ("a
//! unixpipe listener has no IP SocketAddr") AND run_peer had no `--zid` override at
//! all. R311y397 adds the override and makes that seam non-IP safe: the log + self
//! locator render from `local_addr_display()`, the zid uses an explicit `--zid` for
//! ANY transport, IP listeners keep the port-derived fallback (TCP byte-identical),
//! and a non-IP listen REQUIRES `--zid` (a zenoh-faithful config-id, not the demo
//! port hack).
//!
//! Topology: one `--peer unixpipe/<base> --zid 70720001` + a `--key` consumer
//! (`--zid 0a000001`) + a `--publish` producer (`--zid 0a000002`), all distinct
//! processes. The two clients carry DISTINCT `--zid`s (belt-and-suspenders across
//! the peer's face keying — always safe). Neither client can hear the other directly
//! (each holds a single unixpipe link to the peer); the consumer firing its
//! subscriber is a definitive witness that the peer forwarded the producer's Put
//! ACROSS the two unixpipe faces (`deliver_to_client_subscribers` — a peer routes
//! among its co-attached client faces, the same delivery plane the transit-push
//! interop leg exercises for a mesh-sourced Put). The peer summary independently
//! reports `peak 2 concurrent face(s)`.
//!
//! RED reproductions (each proves the GREEN binds to the unixpipe cross-face route
//! through the peer, not a vehicle):
//!  - a non-matching producer keyexpr -> the consumer never fires (delivery
//!    discriminator);
//!  - the peer spawned WITHOUT `--zid` -> the R311y397 fail-fast exits it
//!    ("non-IP transport ... pass an explicit --zid") before it ever accepts, so no
//!    client connects and the consumer never fires (proves the product-code seam is
//!    load-bearing: a non-IP peer REQUIRES an explicit zid).
//!
//! Requires the binary built with `--features routing-peer,transport-link-unixpipe`
//! (the peer run-mode + the unixpipe transport). Linux-only (the unixpipe backend's
//! `read_write` open-rendezvous). No external oracle (pure wz<->wz), so run-ci gates
//! it on a self-contained lane (Layer E6u) beside E5u/E7u. Every fn name starts
//! `wz_peer_` so the default Layer E sweep's `--skip wz_peer` excludes it from the
//! oracle-less arbitrary-feature run.

#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_unixpipe_request_fifo,
    wz_ap_demo_binary, ChildGuard,
};

/// The keyexpr both clients agree on — distinct from the star-router
/// (`demo/unixpipe/route-fwd`) and router-hat (`demo/unixpipe/rh-route-fwd`) unixpipe
/// e2es so parallel Layer E runs never cross-match.
const KEYEXPR: &str = "demo/unixpipe/peer-route-fwd";

/// A per-process-unique unixpipe base path under the temp dir; the request FIFO is
/// `<base>_uplink`. A dedicated `peer-` tag keeps it disjoint from the star-router
/// (`wz-uxp-router-`), router-hat (`wz-uxp-rh-`), dataplane (`wz-uxp-dp-`) and interop
/// (`wz-uxp-zenohd-`) bases so parallel test binaries never share nodes.
fn unixpipe_base(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("wz-uxp-peer-{tag}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Best-effort cleanup of a base's request FIFO AND every dedicated per-connection
/// sub-pipe node (`{base}_uplink`/`{base}_downlink` plus their decimal-suffixed
/// twins). The dedicated read-ends normally auto-unlink on Drop, but the test
/// SIGKILLs its children, so Drop never runs; this globs the whole
/// `{base}_uplink*`/`{base}_downlink*` family so no 0-byte FIFO inode accumulates
/// across runs. `base` embeds the pid, so a stale node never collides — temp-dir
/// hygiene. (Mirror of `wz_router_hat_unixpipe_forward.rs::cleanup`.)
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

/// The peer (`--peer`) forwards a Put across two concurrent unixpipe clients — the
/// proof that R311y397's `--zid` override + non-IP-safe zid/locator seam lets a
/// WhatAmI::Peer bind and route over IPC.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,transport-link-unixpipe); Layer E6u runs via --ignored"]
fn wz_peer_forwards_a_put_between_two_unixpipe_clients() {
    let demo = wz_ap_demo_binary();
    let base = unixpipe_base("fwd");
    cleanup(&base);
    let listen = format!("unixpipe/{base}");

    // ── peer: bind ONE unixpipe listener with an explicit --zid (REQUIRED for a
    //    non-IP listen, R311y397), hold N faces, forward across them. ──
    let peer_stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let peer_writer = peer_stderr.try_clone().expect("dup peer stderr handle");
    let mut peer_reader = peer_stderr;
    let mut peer_guard = ChildGuard::wrap(
        "wz-ap-demo peer (--peer unixpipe, --zid)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&listen)
            .arg("--zid")
            .arg("70720001")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(peer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer unixpipe"),
    );

    let bound = wait_for_substring(
        &mut peer_reader,
        "peer: listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = peer_guard.child_mut().kill();
        let _ = peer_guard.child_mut().wait();
        cleanup(&base);
        panic!(
            "wz-ap-demo --peer unixpipe did not log 'listening on' within 5s (is the \
             binary built with --features routing-peer,transport-link-unixpipe?)\n\
             --- peer stderr ---\n{captured}"
        );
    }
    let fifo_ready = wait_for_unixpipe_request_fifo(&base, Duration::from_secs(5));

    // ── consumer: declare a routed subscriber over its own unixpipe link (--zid
    //    0a000001, distinct from the producer so the peer holds two faces). ──
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
            .arg("--zid")
            .arg("0a000001")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(consumer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe --key"),
    );

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
    let face0 = wait_for_substring(&mut peer_reader, "face 0 UP", Duration::from_secs(10));

    // ── producer: publish a Put on the same keyexpr over its OWN unixpipe link
    //    (--zid 0a000002 = the SECOND concurrent client). ──
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
            .arg("--zid")
            .arg("0a000002")
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
    // The peer holds BOTH clients' faces concurrently — face 1 UP is the second
    // distinct-zid client (the acceptor-concurrency witness).
    let face1 = wait_for_substring(&mut peer_reader, "face 1 UP", Duration::from_secs(10));
    let emitted = wait_for_substring(
        &mut producer_reader,
        "PUBLISHER EMITTED",
        Duration::from_secs(10),
    );

    // The witness: the consumer's subscriber fired, which can only happen if the
    // peer forwarded the producer's Put ACROSS the two unixpipe faces.
    let fired = wait_for_substring(
        &mut consumer_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    );

    // Graceful shutdown the peer → it logs its accept-loop + forward summary.
    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let peer_captured = read_captured(&mut peer_reader);

    let _ = producer_guard.child_mut().kill();
    let _ = producer_guard.child_mut().wait();
    let _ = consumer_guard.child_mut().kill();
    let _ = consumer_guard.child_mut().wait();

    let consumer_captured = read_captured(&mut consumer_reader);
    let producer_captured = read_captured(&mut producer_reader);
    eprintln!("--- peer stderr ---\n{peer_captured}");
    eprintln!("--- consumer stderr ---\n{consumer_captured}");
    eprintln!("--- producer stderr ---\n{producer_captured}");

    cleanup(&base);

    // Diagnostics first (surface captured output on any failure), then assert.
    assert!(
        fifo_ready,
        "the unixpipe request FIFO ({base}_uplink) never appeared within 5s\n--- peer ---\n{peer_captured}"
    );
    consumer_dialed.unwrap_or_else(|c| {
        panic!("consumer did not reach the peer 'over unixpipe transport' within 5s\n--- consumer ---\n{c}")
    });
    declared.unwrap_or_else(|c| {
        panic!("consumer did not log 'DECLARED ROUTED SUBSCRIBER' within 5s\n--- consumer ---\n{c}\n--- peer ---\n{peer_captured}")
    });
    face0.unwrap_or_else(|c| panic!("peer did not log 'face 0 UP' within 10s\n--- peer ---\n{c}"));
    producer_dialed.unwrap_or_else(|c| {
        panic!("producer did not reach the peer 'over unixpipe transport' within 5s\n--- producer ---\n{c}")
    });
    face1.unwrap_or_else(|c| {
        panic!("peer did not log 'face 1 UP' (the second concurrent unixpipe client) within 10s\n--- peer ---\n{c}")
    });
    emitted.unwrap_or_else(|c| {
        panic!("producer did not log 'PUBLISHER EMITTED' within 10s\n--- producer ---\n{c}\n--- peer ---\n{peer_captured}")
    });
    let fired_log = fired.unwrap_or_else(|c| {
        panic!(
            "consumer never fired its subscriber within 10s — the peer did NOT forward \
             the Put across the two unixpipe faces\n--- consumer ---\n{c}\n--- peer ---\n{peer_captured}"
        )
    });

    assert!(
        fired_log.contains(&format!("keyexpr='{KEYEXPR}'")),
        "consumer fired on the wrong keyexpr (expected {KEYEXPR})\n--- consumer ---\n{fired_log}"
    );
    assert!(
        fired_log.contains("payload_len=17"),
        "the forwarded sample must preserve the full 17-byte payload across unixpipe\n--- consumer ---\n{fired_log}"
    );

    // The peer's own shutdown summary independently confirms it held BOTH unixpipe
    // faces concurrently (the acceptor-concurrency witness, distinct from the
    // client-side delivery proof above).
    assert!(
        peer_captured.contains("peak 2 concurrent"),
        "peer must have held TWO concurrent unixpipe faces (peak 2 concurrent)\n\
         --- peer stderr ---\n{peer_captured}"
    );
}
