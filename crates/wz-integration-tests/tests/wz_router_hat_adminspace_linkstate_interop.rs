// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y204 (§5.23 `adminspace-router-linkstate`) — the ROUTER adminspace legs
//! federated ACROSS TWO ROUTERS over real transport: a querier behind R1 GETs
//! R2's `@/<R2_zid>/router/**` admin subtree, routed issuer -> R1 -> [router mesh]
//! -> R2, self-dispatched at R2, with the replies returning back down both hops.
//! The wz analogue of zenoh's `routers_linkstate_data` / `route_successor` admin
//! handlers (`net/runtime/adminspace.rs:741-919`), proven CROSS-NODE.
//!
//! This is the load-bearing proof of the cross-node capability the user chose over
//! the direct-attach slice: R2 registers its self-hosted admin queryable at STARTUP
//! (before R1 even connects), so the ONLY way R1 can route a GET for R2's admin is
//! the RE-ADVERTISE-to-late-joiners path — `re_advertise_self_cross_tier` picking
//! up the `local_queryables` fold in `derived_cross_tier_qabls_into` when R1 joins
//! R2's routers-net tree. If that fold were missing, R1 would never learn R2's
//! admin queryable, the `learned a queryable` barrier would time out, and this test
//! would fail. So a green run proves the self-sourced-queryable mesh routing the
//! §5.21 router lacked, exercised end to end.
//!
//! Flow (mirrors `wz_router_hat_federates_a_query_across_two_routers`):
//!   1. R2 binds; R1 dials R2. Both host their admin queryable on
//!      `@/<zid>/router/**` (built with adminspace-router-linkstate).
//!   2. Scrape each router's admin root (`@/<zid>/router`) from its register log.
//!   3. Await both routers' router-tier convergence (the federation floor), then
//!      gate on R1's `learned a queryable` (R1 ingested R2's cross-mesh admin qabl
//!      advertise — the re-advertise fold under test).
//!   4. Issuer (client behind R1) GETs `@/<R2_zid>/router/**`.
//!   5. Assert the issuer received the `linkstate/routers` reply as a petgraph DOT
//!      naming BOTH routers' zenoh-hex zids (a LIVE topology render, not a static
//!      echo — R2's routers-net has both nodes), and at least one
//!      `route/successor/src/<x>/dst/<y>` reply (the successor table enumerated).
//!
//! Needs the demo built with `--features router-hat-router,adminspace-router-linkstate`
//! (Layer E7c). wz<->wz — the legs add no new wire format (a standard reply GET), so
//! no cross-impl leg is needed; the DOT node labels are petgraph-Debug of wz `Node`
//! vs zenoh `Node`, so a byte-parity wz<->zenohd DOT test could only assert
//! well-formedness (a named verification-leg deferral, not a build).

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, wait_for_substring,
    wz_ap_demo_binary, ChildGuard,
};

/// Spawn a router-hat node (`--router-hat`) — presents wire `WhatAmI::Router`.
fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for node stderr");
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    )
}

/// Spawn a client that DIALS a router (`--connect`) and gate on `connected to`.
fn spawn_session(label: &str, args: &[&str]) -> (ChildGuard, File) {
    let stderr = tempfile::tempfile().expect("tempfile for session stderr");
    let writer = stderr.try_clone().expect("dup session stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    wait_for_substring(&mut reader, "connected to", Duration::from_secs(10)).unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not connect within 10s (is the binary built with \
             --features router-hat-router,adminspace-router-linkstate?)\n--- {label} \
             stderr ---\n{c}"
        );
    });
    (guard, reader)
}

/// Scrape a router's admin root `@/<zid>/router` from its register-time log
/// `adminspace router legs hosted at @/<zid>/router/** (...)`. The zid is already
/// in zenoh `ZenohId` Display (hex) form (the router's own `zid_to_zenoh_hex`), so
/// it equals the label the DOT reply below carries — no recipe duplication.
fn scrape_admin_root(reader: &mut File, guard: &mut ChildGuard, label: &str) -> String {
    let captured = wait_for_substring(
        reader,
        "adminspace router legs hosted at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!("{label} never registered its admin router legs within 10s\n--- {label} ---\n{c}");
    });
    captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace router legs hosted at ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|key| key.strip_suffix("/**"))
                .map(|root| root.to_string())
        })
        .unwrap_or_else(|| panic!("{label} log lacked the admin queryable key\n{captured}"))
}

/// The zid chunk of `@/<zid>/router` — the 2nd `/`-segment.
fn zid_of(root: &str) -> String {
    root.split('/')
        .nth(1)
        .unwrap_or_else(|| panic!("admin root {root} has no zid chunk"))
        .to_string()
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate); Layer E7c runs via --ignored"]
fn wz_router_hat_federates_admin_linkstate_across_two_routers() {
    // R2 binds first; R1 dials R2. Both host their `@/<zid>/router/**` admin qabl.
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--connect", &addr_r2],
    );
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    // Each router's admin root (register-time log) → the two zenoh-hex zids the DOT
    // must name. Scraped BEFORE the convergence waits so the register log (which
    // fires just after `listening on`) is not skipped past.
    let r2_root = scrape_admin_root(&mut r2_reader, &mut r2_guard, "router-hat-2");
    let r1_root = scrape_admin_root(&mut r1_reader, &mut r1_guard, "router-hat-1");
    let r2_zid = zid_of(&r2_root);
    let r1_zid = zid_of(&r1_root);

    // Await BOTH routers' router-tier convergence (the federation floor) FIRST.
    for (label, reader, guard) in [
        ("router-hat-1", &mut r1_reader, &mut r1_guard),
        ("router-hat-2", &mut r2_reader, &mut r2_guard),
    ] {
        wait_for_substring(
            reader,
            "router-hat: routers-net converged (2 node(s))",
            Duration::from_secs(15),
        )
        .unwrap_or_else(|c| {
            let _ = guard.child_mut().kill();
            let _ = guard.child_mut().wait();
            panic!("{label} never federated its router tier to 2 within 15s\n--- {label} ---\n{c}");
        });
    }

    // BARRIER (the fold under test): R1 must have ingested R2's admin queryable
    // THROUGH the router mesh — R2 registered it at startup, so R1 can only learn it
    // via `re_advertise_self_cross_tier` on join (the `local_queryables` fold in
    // `derived_cross_tier_qabls_into`). Gating on R1 (the issuer's router) is
    // load-bearing: the issuer is behind R1, so R1 must know the route before the
    // one-shot GET fires.
    wait_for_substring(
        &mut r1_reader,
        "router-hat: learned a queryable",
        Duration::from_secs(15),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        let _ = r2_guard.child_mut().kill();
        let _ = r2_guard.child_mut().wait();
        panic!(
            "router-hat-1 never learned R2's admin queryable within 15s — the \
             self-hosted-queryable re-advertise fold did not federate R2 -> [router \
             mesh] -> R1, so R1 would not route the GET for R2's admin toward \
             R2\n--- router-hat-1 ---\n{c}"
        )
    });

    // The issuer (client behind R1, distinct zid) GETs R2's whole admin subtree —
    // routed issuer -> R1 -> [router mesh] -> R2, self-dispatched at R2, replied back.
    let get_key = format!("{r2_root}/**");
    let (mut iss_guard, mut iss_reader) = spawn_session(
        "issuer",
        &[
            "--connect",
            &addr_r1,
            "--query",
            &get_key,
            "--on-query-reply-log",
            "--on-query-final-log",
            "--zid",
            "0a0a0a0a",
        ],
    );

    let reply = wait_for_substring(&mut iss_reader, "REPLY RECEIVED", Duration::from_secs(15));
    let final_recv = wait_for_substring(&mut iss_reader, "FINAL RECEIVED", Duration::from_secs(10));

    graceful_terminate(iss_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    let iss_captured = read_captured(&mut iss_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");
    eprintln!("--- issuer stderr ---\n{iss_captured}");

    reply.unwrap_or_else(|c| {
        panic!(
            "issuer (behind R1) never received an admin reply within 15s — the GET \
             for R2's `@/{r2_zid}/router/**` did not route across the two routers to \
             R2's self-dispatched admin queryable\n--- issuer ---\n{c}\n--- R1 ---\n\
             {r1_captured}\n--- R2 ---\n{r2_captured}"
        )
    });

    // LIVE-CONTENT (defeats a static echo): the `linkstate/routers` reply is R2's
    // routers-net petgraph DOT, which MUST name BOTH routers' zenoh-hex zids (R2 =
    // self, R1 = the federated neighbour). A body naming only one zid would mean the
    // topology never converged; a `Node {`/struct dump would mean the fidelity fix
    // regressed.
    let linkstate_key = format!("{r2_root}/linkstate/routers");
    let linkstate_line = iss_captured
        .lines()
        .find(|l| l.contains("REPLY RECEIVED") && l.contains(&format!("keyexpr='{linkstate_key}'")))
        .unwrap_or_else(|| {
            panic!(
                "no `linkstate/routers` reply for R2 — the router linkstate leg did \
                 not answer across the mesh\n--- issuer ---\n{iss_captured}"
            )
        });
    // Assert against the PAYLOAD (the DOT body), NOT the whole line: r2_zid is in
    // the keyexpr so a whole-line `contains(&r2_zid)` would be vacuous. Both zids
    // must appear in the DOT body itself — R2 as self, R1 (a pure transit hop that
    // appears in neither the key nor the reply metadata) proving the live render.
    let dot_body = linkstate_line
        .split_once("payload=")
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("linkstate reply line lacked a payload\n{linkstate_line}"));
    assert!(
        dot_body.contains(&r2_zid) && dot_body.contains(&r1_zid),
        "the `linkstate/routers` DOT body must name BOTH routers (R2={r2_zid}, \
         R1={r1_zid}) — a live cross-node topology render.\n--- reply ---\n{linkstate_line}"
    );
    assert!(
        !dot_body.contains("Node {") && !dot_body.contains("whatami"),
        "the DOT node label must be the bare zenoh-hex zid, not wz `Node`'s struct \
         Debug\n--- reply ---\n{linkstate_line}"
    );

    // The `linkstate/peers` leg is served from R2's SEPARATE `linkstatepeers_net`
    // (not `routers_net`). R2's peer tier has ONLY self (R1 is a router, classified
    // into routers_net), so its DOT names R2 and does NOT name R1 — which is exactly
    // what guards the `peers_net_view()` -> `linkstatepeers_net` wiring: a mis-wire
    // pointing it at `routers_net` would leak R1's zid into this body.
    let peers_key = format!("{r2_root}/linkstate/peers");
    let peers_body = iss_captured
        .lines()
        .find(|l| l.contains("REPLY RECEIVED") && l.contains(&format!("keyexpr='{peers_key}'")))
        .and_then(|l| l.split_once("payload=").map(|(_, p)| p.to_string()))
        .unwrap_or_else(|| {
            panic!("no `linkstate/peers` reply for R2\n--- issuer ---\n{iss_captured}")
        });
    assert!(
        peers_body.contains("graph {")
            && peers_body.contains(&r2_zid)
            && !peers_body.contains(&r1_zid),
        "the `linkstate/peers` DOT must be R2's peer-tier net (names R2, NOT the \
         router R1) — the peers_net_view wiring guard.\n--- reply ---\n{peers_body}"
    );

    // The `route/successor` table enumerated: at least one entry keyed
    // `@/<R2>/router/route/successor/src/<x>/dst/<y>` came back (R2's routers-net has
    // 2 nodes, so it has directed successors).
    let successor_prefix = format!("{r2_root}/route/successor/src/");
    assert!(
        iss_captured
            .lines()
            .any(|l| l.contains("REPLY RECEIVED") && l.contains(&successor_prefix)),
        "no `route/successor` entry replied — the router successor table did not \
         enumerate over the mesh\n--- issuer ---\n{iss_captured}"
    );

    final_recv.unwrap_or_else(|c| {
        panic!(
            "issuer never received the ResponseFinal within 10s — the admin GET did \
             not terminate back across the router mesh\n--- issuer ---\n{c}"
        )
    });

    // Transit pins: BOTH routers routed the query (issuer -> R1 -> R2), so the admin
    // GET provably crossed the mesh (latched shutdown witnesses, race-free).
    for (label, captured) in [
        ("router-hat-1", &r1_captured),
        ("router-hat-2", &r2_captured),
    ] {
        assert!(
            captured.contains("router-hat: routed a query"),
            "{label} never routed a query — the admin GET did not transit it\n--- \
             {label} ---\n{captured}"
        );
    }
}
