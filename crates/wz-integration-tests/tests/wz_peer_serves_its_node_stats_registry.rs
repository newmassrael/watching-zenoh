// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2844 — a routing peer serves its NODE stats registry on its admin metrics
//! leg, and the registry holds the sessions its face loop holds.
//!
//! ## The property
//!
//! Upstream keeps one stats registry per runtime, filled by its transport
//! manager, and a node built with `stats` answers `@/<zid>/<whatami>/metrics`
//! with that registry's document
//! (`zenoh/src/net/runtime/adminspace.rs` @ `.encode_metrics(`). A wz peer's
//! transport manager is its face loop, which records every face into the node
//! registry; the peer host serves a snapshot of it per GET. So the client that
//! asks is itself one of the transports the answer counts.
//!
//! ## Why a wz client and not zenoh-pico
//!
//! Layer E6f's pico witness reads this leg on a build without the counters.
//! With them the document is larger than pico's reassembly bound
//! (`FRAG_MAX_SIZE 4096` in its CMake defaults; a one-transport node measured
//! 5142 bytes), and pico's `z_get` sends no selector parameters to narrow it —
//! upstream would gzip the body, and wz does not compress (the owner's
//! decision on open-debt item 677). The probe has no such bound, and it is the
//! one client here that sends parameters, which is the second thing checked.
//!
//! NO cross-impl proof marker, for the reason the storage-host probe test
//! gives: both ends are wz, so this file links no foreign implementation.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    wz_e2e_admin_probe_binary, ChildGuard, PortReservation,
};

/// How long the probe's whole script may take; the probe bounds each step
/// itself and logs it, so a timeout here is a process that never finished.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-metrics,wz/transport-stats + wz-e2e-admin-probe); Layer E6f runs via --ignored"]
fn wz_peer_serves_its_node_stats_registry_to_a_session_client() {
    let demo = wz_ap_demo_binary();
    // The peer's registry is what this leg reads, so a demo older than the
    // library it links reports the undamaged product.
    assert_demo_binary_newer_than_sources(&demo);
    let probe = wz_e2e_admin_probe_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;
    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );
    let a_captured = match wait_for_substring(
        &mut a_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!("peer A never registered its admin host within 5s\n--- A ---\n{c}");
        }
    };
    let root = a_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .and_then(|k| k.strip_suffix("/config").map(str::to_string))
        .expect("peer A logged its admin config keyexpr");
    let zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/<whatami>");
    drop(port_res);

    // ONE probe session, two GETs: the whole document, then the same leg with
    // the per-link partition switched off.
    let metrics = format!("{root}/metrics");
    let p_stderr = tempfile::tempfile().expect("tempfile for probe stderr");
    let p_writer = p_stderr.try_clone().expect("dup probe stderr handle");
    let mut p_reader = p_stderr;
    let mut p_child = ChildGuard::wrap(
        "wz-e2e-admin-probe (two metrics GETs on one session)",
        Command::new(&probe)
            .arg("--connect")
            .arg(&addr)
            .arg("--get")
            .arg(&metrics)
            .arg("--get")
            .arg(format!("{metrics}?per_link=false"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let out = match wait_for_substring(&mut p_reader, "SCRIPT COMPLETE steps=2", SCRIPT_TIMEOUT) {
        Ok(c) => c,
        Err(c) => {
            let host = read_captured(&mut a_reader);
            let _ = p_child.child_mut().kill();
            let _ = p_child.child_mut().wait();
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- A ---\n{host}");
        }
    };
    let _ = p_child.child_mut().kill();
    let _ = p_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    // The body lines of one step, prefix stripped.
    let body = |step: usize| -> Vec<&str> {
        let marker = format!("STEP {step} BODY #1 ");
        out.lines()
            .filter_map(|l| l.split_once(marker.as_str()).map(|(_, rest)| rest))
            .collect()
    };
    let whole = body(1);
    let narrowed = body(2);
    // EACH step answered exactly once, stated per step: a single check for
    // "FINAL replies=1" anywhere passed on this test's first run while the
    // second GET had answered nothing at all.
    for (step, selector) in [
        (1, metrics.clone()),
        (2, format!("{metrics}?per_link=false")),
    ] {
        assert!(
            out.contains(&format!("STEP {step} GET '{selector}' FINAL replies=1")),
            "step {step} is answered once\n--- probe ---\n{out}"
        );
    }

    // The NODE registry: the probe's own session is the one transport it holds.
    let opened = format!("zenoh_transports_opened{{local_id=\"{zid}\",local_whatami=\"peer\"}} 1");
    assert!(
        whole.contains(&opened.as_str()),
        "the peer's registry counts the one transport it holds, the probe's\n--- probe ---\n{out}"
    );
    assert!(
        whole
            .iter()
            .any(|l| l.contains("remote_zid=\"") && l.contains("disconnected=\"false\"")),
        "that transport is labelled with the peer its handshake named\n--- probe ---\n{out}"
    );
    assert_eq!(
        whole.last(),
        Some(&"# EOF"),
        "the document ends at its terminator"
    );

    // The parameter reached the HOST's registry: the per-link families are in
    // the whole document and gone from the narrowed one, and nothing else is.
    let per_link = |lines: &[&str]| lines.iter().filter(|l| l.contains("_per_link_")).count();
    assert!(
        per_link(&whole) > 0,
        "the whole document carries per-link series\n--- probe ---\n{out}"
    );
    assert_eq!(
        per_link(&narrowed),
        0,
        "per_link=false removes them\n--- probe ---\n{out}"
    );
    assert!(
        narrowed.contains(&opened.as_str()),
        "and leaves the rest of the document\n--- probe ---\n{out}"
    );
}
