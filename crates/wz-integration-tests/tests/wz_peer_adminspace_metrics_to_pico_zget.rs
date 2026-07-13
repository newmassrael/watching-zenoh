// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y275 — FOREIGN-INTEROP ADMINSPACE METRICS: a real zenoh-pico `z_get` CLI
//! reads a watching-zenoh routing peer's `@/<zid>/peer/metrics` admin leg and
//! decodes the OpenMetrics build-info body wz serves (the `zenoh_build` gauge).
//!
//! ## The gap this closes
//!
//! `adminspace-metrics` (R311y35) has been active + wz-unit-proven
//! (`declare_adminspace_metrics_get_returns_openmetrics_text`,
//! wz-runtime-tokio/src/session/tests.rs) since it was built, but it sat
//! `unproven` on the cross-impl proof axis: no foreign decoder had ever read the
//! metrics body. The y270 E6b witness (`wz_peer_adminspace_to_pico_zget`) even
//! asserts the metrics leg is ABSENT, because its binary is built WITHOUT
//! `adminspace-metrics`; this test supplies the positive foreign witness the y270
//! docstring names as a follow-up, on its OWN demo binary built WITH the feature.
//!
//! ## What the assertion binds to (the atom's own cfg-gated code)
//!
//! The demo is built `--features routing-peer,adminspace-metrics`. The metrics
//! leg is a `#[cfg(feature = "adminspace-metrics")]` branch inside
//! wz-session-core `answer_admin_query` (adminspace.rs:597-609) — the SSOT the
//! demo's `--config-queryable` host calls (runner.rs:1689) — that replies
//! `admin_metrics_key(zid,whatami)` = `@/<zid>/peer/metrics` with the body
//! `metrics_text(version)` (adminspace.rs:1016-1024), a byte-faithful copy of
//! zenoh's unconditional build-info block (adminspace.rs:714-720). With the atom
//! compiled out that branch does not exist and the leg is absent (the exact
//! counterfactual the E6b binary already runs), so the assertion cannot survive
//! the atom's code being elided.
//!
//! The GET is keyed on `@/<zid>/peer/metrics` (4 chunks); it intersects neither
//! the node root `@/<zid>/peer` (3 chunks, no wildcard) nor `@/<zid>/peer/config`
//! (different 4th chunk), so a well-formed reply set carries ONLY the metrics
//! leg — a static echo that ignored the key would not produce this key with this
//! runtime zid.
//!
//! ## Named bound (what this does NOT prove)
//!
//! Only `adminspace-metrics`, and only its v1 build-info block. wz's
//! transport-stats OpenMetrics composition (zenoh's `stats`-feature append,
//! adminspace.rs:722-730) is a documented follow-up and is not emitted here.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

// wz-proves: adminspace-metrics wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-metrics + zenoh-pico z_get CLI); Layer E6f runs via --ignored"]
fn wz_peer_adminspace_metrics_decoded_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A: hosts its adminspace (metrics leg compiled in) ──────
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

    // BARRIER (not a sleep): the admin host is registered → derive the node root
    // (`@/<zid>/peer`) and the zid. Both are runtime values the assertion keys on.
    let a_ready = wait_for_substring(
        &mut a_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    let a_captured = match a_ready {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!("peer A never registered its admin host within 5s\n--- A ---\n{c}");
        }
    };
    let config_key = a_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer A logged the admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    let zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/<whatami>");
    let metrics_key = format!("{root}/metrics");
    drop(port_res);

    // ── the FOREIGN client: pico z_get dials A and GETs the metrics leg ──
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;

    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args([
                "-k",
                &metrics_key,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(g_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    // Wait on pico's terminating Final (a positive edge) rather than on the reply,
    // so a missing reply fails the assertions below with the full transcript.
    let done = wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let out = match done {
        Ok(c) => c,
        Err(c) => {
            let _ = g_child.child_mut().kill();
            let _ = g_child.child_mut().wait();
            let a_log = read_captured(&mut a_reader);
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- A ---\n{a_log}");
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    // ── adminspace-metrics: the OpenMetrics body, decoded by pico ───
    //
    // The body is multi-line text/plain, so pico's `('key': 'value')` render spans
    // output lines; assert against the whole capture. The key carries A's live zid,
    // so a static fixture cannot satisfy it.
    assert!(
        out.contains(&format!("('{metrics_key}':")),
        "pico decoded no adminspace-metrics leg at `{metrics_key}`\n--- z_get ---\n{out}"
    );
    assert!(
        out.contains("# TYPE zenoh_build gauge"),
        "metrics body carries the zenoh_build OpenMetrics TYPE line\n--- z_get ---\n{out}"
    );
    assert!(
        out.contains("zenoh_build{version=\"") && out.contains("\"} 1"),
        "metrics body carries the zenoh_build gauge with a version label\n--- z_get ---\n{out}"
    );

    // ── the gate is real: the node record is NOT in a `{root}/metrics` reply ──
    // (the GET key does not intersect the 3-chunk root), so a reply set that
    // ignored the key could not pass the targeted assertions above.
    assert!(
        !out.contains(&format!("('{root}':")),
        "a GET on `{metrics_key}` must not return the node root record `{root}`\n--- z_get ---\n{out}"
    );
    // zid is bound above (it keys `metrics_key`); reference it so the intent is explicit.
    let _ = &zid;
}
