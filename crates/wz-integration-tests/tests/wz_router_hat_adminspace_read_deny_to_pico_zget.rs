// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y781 — FOREIGN-INTEROP ADMINSPACE READ GATE, ROUTER TIER: a real zenoh-pico
//! `z_get` CLI queries a watching-zenoh ROUTER whose `permissions.read` GET gate is
//! DENIED (`--no-admin-read`), and receives ONLY the terminating Final — neither the
//! root `local_data` legs nor the router-tier linkstate / route-successor legs.
//!
//! ## The gap this closes
//!
//! R311y780 made the admin permit a per-request read off a live config, but only on
//! the peer hosts. The router host still hardcoded `read: true` — not because the
//! gate was unhonoured (`answer_admin_query` and `answer_router_admin_query` both
//! consult `ctx.read` from whatever host passes it) but because `--router-hat`
//! parsed no permit flag and held no `WzConfig`, so there was no source to resolve.
//! The atom's residual said it plainly: "no shipping wz router applies the gate".
//! This round gives the router the same shared-`WzConfig` permit source the peer
//! host uses, and this test is the foreign witness that it denies.
//!
//! ## Why the two-router setup, and why that is not ceremony
//!
//! The positive twin (`wz_router_hat_adminspace_to_pico_zget`) federates R1 with R2
//! and waits for `routers-net converged (2 node(s))` precisely because the
//! router-tier legs are only non-trivial once a second router is in the graph: the
//! `linkstate/routers` DOT names both, and `route/successor/**` has a computed hop.
//! This test reproduces that setup EXACTLY and then asserts nothing comes back. Run
//! against one lonely router the assertion would be near-vacuous — a route-successor
//! leg that is empty anyway proves nothing about a gate. Here every leg the positive
//! test observes is present-and-suppressed, so the absence is a denial rather than
//! an emptiness.
//!
//! ## Why this is not a flaky wait-for-absence
//!
//! The test waits on pico's POSITIVE terminating edge ("Received query final
//! notification"), which only fires once the responder sent its ResponseFinal — the
//! round trip provably completed — and only then asserts no reply body preceded it.
//! A pico that never connected times out with a transcript instead of passing. R1
//! also logs `adminspace read permit = false`, asserted below, so a pass proves the
//! GATE denied rather than that some unrelated path returned nothing.
//!
//! ## The gate is real (counterfactual)
//!
//! Building the demo without `adminspace-read` makes `admin_read_permit` return
//! `true` regardless of the flag, both ctxs are permissive, the legs are served, and
//! the absence assertions below fire. The witness cannot survive the atom's code
//! being compiled out.
//!
//! ## Which binary this rides
//!
//! Layer E7g's, built `--features router-hat-router,adminspace-router-linkstate,`
//! `adminspace-read`. Cargo uplifts every feature variant of one `--bin` to a single
//! path (R311y269), so a variant is only safe inside the lane that built it.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, std::fs::File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for router stderr");
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    )
}

/// Scrape the router's admin root (`@/<zid>/router`) from its
/// `adminspace router legs hosted at @/<zid>/router/**` log line. That line fires at
/// REGISTRATION, which is independent of the read gate (the gate is per-GET, inside
/// the handler), so it is a valid barrier even on the denied build.
fn admin_root(reader: &mut std::fs::File, label: &str) -> String {
    let captured = wait_for_substring(
        reader,
        "adminspace router legs hosted at ",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| panic!("{label} never hosted its router admin legs within 5s\n{c}"));
    captured
        .lines()
        .find_map(|l| l.split_once("adminspace router legs hosted at "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .and_then(|k| k.strip_suffix("/**"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| panic!("{label} log had no scrapeable router admin root"))
}

// wz-proves: adminspace-read wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate,adminspace-read + zenoh-pico z_get CLI); Layer E7g runs via --ignored"]
fn wz_router_adminspace_read_deny_seen_by_pico_z_get() {
    // R311y783 — this fixture is squarely in the class the freshness check
    // exists for, and R311y781 landed it without one (hosted Layer C0 caught
    // that: 110 -> 111). It asserts an ABSENCE against a binary spawned from
    // whatever happens to be on disk. A demo predating R311y781 does not know
    // `--no-admin-read` in router-hat mode; if it ignores the flag rather than
    // rejecting it, the router answers the GET, the absence assertion fires,
    // and the red reads as "the read gate does not work" -- which is exactly
    // the R311y774 misdiagnosis this check was written for, on exactly this
    // shape of test. Asserted once here rather than inside `spawn_router_hat`,
    // which resolves the path twice.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let z_get = zenoh_pico_cli_binary("z_get");

    // ── R1: the router pico will query, with the READ gate DENIED ───
    let (mut r1, mut r1_log, r1_port) = spawn_router_hat(
        "router R1 (--router-hat --config-queryable --no-admin-read)",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--config-queryable",
            "--no-admin-read",
        ],
    );
    let r1_addr = format!("127.0.0.1:{r1_port}");
    let root = admin_root(&mut r1_log, "R1");

    // Prove the gate is ACTIVE and denying — not merely that pico got nothing. With
    // adminspace-read compiled out this line reads `= true` and the absence
    // assertions below then fail on the served legs.
    let permit_line = wait_for_substring(
        &mut r1_log,
        "router-hat: adminspace read permit = false",
        Duration::from_secs(5),
    );
    if let Err(c) = permit_line {
        let _ = r1.child_mut().kill();
        panic!("R1's read gate must be DENIED under --no-admin-read + adminspace-read\n--- R1 ---\n{c}");
    }

    // ── R2: a SECOND router, so the suppressed legs would be REAL ───
    let (mut r2, _r2_log, _r2_port) = spawn_router_hat(
        "router R2 (--router-hat --connect R1)",
        &["--router-hat", "127.0.0.1:0", "--connect", &r1_addr],
    );

    // The same barrier the positive twin uses: R1's routers net must hold both nodes
    // before the query, else the linkstate DOT and the successor table are trivial
    // and their absence would say nothing about the gate.
    let federated = wait_for_substring(
        &mut r1_log,
        "routers-net converged (2 node(s))",
        Duration::from_secs(10),
    );
    if let Err(c) = federated {
        let _ = r1.child_mut().kill();
        let _ = r2.child_mut().kill();
        panic!("R1's routers net never converged to 2 nodes within 10s\n--- R1 ---\n{c}");
    }

    // ── the FOREIGN client: pico z_get over the whole router subtree ─
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;
    let mut g = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args([
                "-k",
                &format!("{root}/**"),
                "-e",
                &format!("tcp/{r1_addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(g_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    let done = wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let out = match done {
        Ok(c) => c,
        Err(c) => {
            let _ = g.child_mut().kill();
            let _ = r1.child_mut().kill();
            let _ = r2.child_mut().kill();
            let r1cap = read_captured(&mut r1_log);
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- R1 ---\n{r1cap}");
        }
    };
    let _ = g.child_mut().kill();
    let _ = g.child_mut().wait();
    let _ = r1.child_mut().kill();
    let _ = r1.child_mut().wait();
    let _ = r2.child_mut().kill();
    let _ = r2.child_mut().wait();

    // ── DENY: not one reply under the router root ───────────────────
    //
    // Every admin reply pico prints is keyed `('@/<zid>/router...` (z_get.c:44).
    // The denied gate returns before emitting any, from BOTH answerers: the root
    // `local_data` leg (answer_admin_query) and the router-tier legs
    // (answer_router_admin_query). One assertion covers both because both key under
    // the same root — and the two named below are the exact legs the positive twin
    // decodes in this same two-router setup.
    assert!(
        !out.contains(&format!("('{root}")),
        "read=false must suppress every router admin reply under `{root}`; pico saw one\n--- z_get ---\n{out}"
    );
    assert!(
        !out.contains("linkstate/routers"),
        "the linkstate/routers leg must be suppressed by the read gate\n--- z_get ---\n{out}"
    );
    assert!(
        !out.contains("route/successor"),
        "the route/successor legs must be suppressed by the read gate\n--- z_get ---\n{out}"
    );
}
