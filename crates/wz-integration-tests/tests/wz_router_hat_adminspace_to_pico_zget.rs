// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y273 — FOREIGN-INTEROP ROUTER ADMINSPACE: a real zenoh-pico `z_get` CLI
//! reads a watching-zenoh ROUTER's admin topology legs — the router-tier link-state
//! graph AND the computed route-successor table — across a two-router federation.
//!
//! ## The atom, and why two routers
//!
//! `adminspace-router-linkstate`'s `F=` is three legs on the router node
//! (`@/<zid>/router/**`): `linkstate/routers` + `linkstate/peers` (GraphViz DOT of
//! the two link-state nets) and `route/successor/**` (the computed
//! `(src, dst) -> next-hop` table). The successor table is rendered from the
//! ROUTERS net (zenoh `hat/router/mod.rs:910`), so it is empty on a lone router or
//! a router-with-peers — a next hop only exists once there is a SECOND router to
//! forward toward. So this drives a real federation: R1 `--router-hat`, R2
//! `--router-hat --connect R1`. With both up, all three legs carry content, and a
//! full (not partial) claim is honest — verified by probe before the round
//! (R311y273): one router alone gives non-empty DOT but an EMPTY successor table.
//!
//! ## What pico decodes, and why it is not a static echo
//!
//! One GET at `@/<R1_zid>/router/**` returns, all decoded by pico's C stack:
//! - `linkstate/routers` — `graph { ... }` naming BOTH router zids as nodes with a
//!   weighted edge between them. The test pins R1's own zid AND R2's zid as node
//!   labels, so the graph must reflect the live federation, not a template.
//! - `route/successor/**` — at least one `.../src/<s>/dst/<d>: "<next-hop>"` entry
//!   whose destination is R2's zid (R1's route toward R2). A key derived from the
//!   two runtime zids cannot be a fixture.
//!
//! ## Binding to the atom's cfg-gated code
//!
//! Every router admin leg is `#[cfg(feature = "adminspace-router-linkstate")]`
//! (wz-session-core/src/adminspace.rs — `admin_route_successor_prefix`,
//! `route_successor_entry_key`, and the RouterForwarder self-dispatch host in
//! wz-ap-demo/src/runner.rs:2482 all gate on it). The E7 binary is built WITH the
//! feature for this lane; without it the router hosts no `@/<zid>/router/**`
//! queryable at all, so pico's GET returns nothing and the test fails. That
//! counterfactual is EXECUTED, not asserted (R311y273).
//!
//! ## Which binary this rides
//!
//! Layer E7's — which R311y273 extends to build
//! `--features router-hat-router,adminspace-router-linkstate` (a superset of E7's
//! prior `router-hat-router`; the router admin legs are additive, the existing
//! wz<->wz router tests are unaffected). Cargo uplifts every feature variant of the
//! same `--bin` to one path (R311y269), so a variant is only safe inside the lane
//! that built it — this rides E7's build directly.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_on_ephemeral_port, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
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
/// `adminspace router legs hosted at @/<zid>/router/**` log line.
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

fn zid_of(root: &str) -> String {
    root.strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/router")
}

// wz-proves: adminspace-router-linkstate wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate + zenoh-pico z_get CLI); Layer E7 runs via --ignored"]
fn wz_router_adminspace_decoded_by_pico_z_get() {
    let z_get = zenoh_pico_cli_binary("z_get");

    // ── R1: the router pico will query ──────────────────────────────
    let (mut r1, mut r1_log, r1_port) = spawn_router_hat(
        "router R1 (--router-hat --config-queryable)",
        &["--router-hat", "127.0.0.1:0", "--config-queryable"],
    );
    let r1_addr = format!("127.0.0.1:{r1_port}");
    let root = admin_root(&mut r1_log, "R1");
    let r1_zid = zid_of(&root);

    // ── R2: a SECOND router, so the successor table is non-empty ────
    let (mut r2, mut r2_log, _r2_port) = spawn_router_hat(
        "router R2 (--router-hat --connect R1)",
        &["--router-hat", "127.0.0.1:0", "--connect", &r1_addr],
    );
    let r2_root = admin_root(&mut r2_log, "R2");
    let r2_zid = zid_of(&r2_root);

    // Barrier: R1 must have ingested R2 into its ROUTERS net before the query,
    // else the DOT names one node and the successor table is empty. The
    // deterministic witness is R1's own convergence log — NOT a zid-string match,
    // because wz logs faces in raw little-endian zid bytes while the admin space
    // renders zenoh-hex (byte-reversed), so `r2_zid` never appears verbatim in R1's
    // face log. "routers-net converged (2 node(s))" is the edge that means exactly
    // "the second router is in the graph the successor table is computed from".
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

    // ── pico z_get the whole router admin subtree ───────────────────
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

    // ── linkstate/routers: the DOT graph naming both routers ────────
    let routers_line = out
        .lines()
        .skip_while(|l| !l.contains(&format!("('{root}/linkstate/routers':")))
        .take(6)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !routers_line.is_empty(),
        "pico decoded no linkstate/routers leg\n--- z_get ---\n{out}"
    );
    assert!(
        routers_line.contains(&r1_zid) && routers_line.contains(&r2_zid),
        "the routers DOT graph names BOTH federated routers ({r1_zid}, {r2_zid}) — a live \
         topology, not a template\n  got: {routers_line}"
    );

    // ── route/successor/**: a computed next hop toward R2 ───────────
    let successor = out.lines().find(|l| {
        l.contains(&format!("('{root}/route/successor/")) && l.contains(&format!("/dst/{r2_zid}"))
    });
    assert!(
        successor.is_some(),
        "pico decoded no route-successor entry toward R2 ({r2_zid}) — the computed routing \
         table did not cross the wire\n--- z_get ---\n{out}"
    );
}
