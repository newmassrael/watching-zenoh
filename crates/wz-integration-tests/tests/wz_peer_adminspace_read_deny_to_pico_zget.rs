// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y276 — FOREIGN-INTEROP ADMINSPACE READ GATE: a real zenoh-pico `z_get` CLI
//! queries a watching-zenoh routing peer whose `permissions.read` GET gate is
//! DENIED (`--no-admin-read`), and receives ONLY the terminating Final — no admin
//! reply body at all.
//!
//! ## The gap this closes
//!
//! `adminspace-read` (R311y36) has been active since it was built, but its GET-gate
//! behaviour had never been witnessed by a foreign decoder: the demo host hardcoded
//! `read: true`, so no run-mode could exercise `read=false`. R311y276 adds the
//! `admin_read_permit` library resolver (the read-side mirror of `admin_write_permit`)
//! and the `--no-admin-read` flag; this test drives the denied path from pico.
//!
//! ## What the assertion binds to (the atom's own cfg-gated code)
//!
//! The demo is built `--features routing-peer,adminspace-read` and run
//! `--no-admin-read`. The read gate resolves through
//! `wz::runtime_tokio::admin_read_permit` — a `cfg(feature = "adminspace-read")`
//! site (wz-runtime-tokio/src/lib.rs) that returns `permissions.read` (false, from
//! `--no-admin-read`) under the gate and `true` with it elided. The resolved bool
//! feeds `AdminAnswerCtx::read`, which `answer_admin_query` (adminspace.rs:566-568,
//! the SSOT the `--config-queryable` host calls) consults FIRST: `if !ctx.read {
//! return; }` — every admin leg suppressed, only the dispatch SSOT's terminating
//! Final unwinds (zenoh's bare ResponseFinal on deny, adminspace.rs:462-467).
//!
//! ## Why this is not a flaky wait-for-absence
//!
//! The test waits on pico's POSITIVE terminating edge ("Received query final
//! notification"), which only fires once the responder has sent ResponseFinal — i.e.
//! the query round-trip provably completed. It then asserts no reply body preceded
//! it. A pico that never connected would time out (fail with a transcript), not pass.
//! The peer also logs "adminspace read permit = false", asserted below, so a pass
//! proves the gate DENIED — not that some unrelated path returned nothing.
//!
//! ## The gate is real (counterfactual)
//!
//! Rebuilding the demo `--features routing-peer` ALONE (adminspace-read off) makes
//! `admin_read_permit` return `true` regardless of `--no-admin-read`, the record is
//! served, and the absence assertion below fires — so the witness cannot survive the
//! atom's code being compiled out. Its positive complement is the y270 E6b test
//! (`wz_peer_adminspace_to_pico_zget`), where the same host WITHOUT the flag serves
//! the node record over the wire.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

// wz-proves: adminspace-read wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-read + zenoh-pico z_get CLI); Layer E6g runs via --ignored"]
fn wz_peer_adminspace_read_deny_seen_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A: hosts its adminspace with the READ gate DENIED ──────
    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable --no-admin-read)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .arg("--no-admin-read")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // BARRIER (not a sleep): the admin host is registered → derive the node root
    // (`@/<zid>/peer`). The registration log fires regardless of the read gate (the
    // gate is per-GET, inside the handler); it is scraped for the runtime root/zid.
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
    // Prove the gate is ACTIVE + denying (not merely that pico got nothing): with
    // adminspace-read compiled out this line would read `= true`, and the absence
    // assertion below would then fail on the served record.
    assert!(
        a_captured.contains("adminspace read permit = false"),
        "peer A's read gate must be DENIED under --no-admin-read + adminspace-read\n--- A ---\n{a_captured}"
    );
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
    drop(port_res);

    // ── the FOREIGN client: pico z_get dials A and GETs the whole root ──
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
                &format!("{root}/**"),
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

    // Wait on pico's terminating Final — the POSITIVE edge proving the query
    // round-trip completed. Only then is "no reply preceded it" a real result.
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

    // ── adminspace-read DENY: the reply set is empty (Final only) ───
    //
    // Every admin reply pico prints is keyed `('@/<zid>/peer...` (z_get.c:44). Under
    // the denied gate answer_admin_query returns before emitting any, so no such line
    // appears; only the Final (already observed) came back.
    assert!(
        !out.contains(&format!("('{root}")),
        "read=false must suppress every admin reply under `{root}`; pico saw a reply\n--- z_get ---\n{out}"
    );
}
