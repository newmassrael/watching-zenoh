// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-PEER <-> zenohd-PEER linkstate FEDERATION interop: a wz node in PEER mode
//! (`LinkstateForwarder`, wire `WhatAmI::Peer`) forms a link-state peer mesh with
//! a REAL zenohd 1.5.0 running `mode=peer` + `routing/peer/mode=linkstate`, and
//! DECODES zenohd's `linkstatepeers_net` `LinkStateList` OAM flood over the wire.
//!
//! This closes the last cross-impl router gap: the wz-router-hat <-> zenohd-router
//! `routers_net` leg is already proven (`wz_router_hat_zenohd_interop`), but the
//! wz-linkstatepeer <-> zenoh-peer wire was untested. Both tiers share the SAME
//! `net::protocol::network::Network` codepath on zenohd's side (zenoh
//! `hat/router/mod.rs` vs `hat/linkstate_peer/mod.rs`), so wz's peer path reuses
//! the exact `LinkstateNetwork` ingest the router leg exercises — this test proves
//! the PEER-tier wire specifically.
//!
//! ## The witness discriminator (linkstate vs gossip)
//!
//! A zenohd peer emits an `OAM_LINKSTATE` `LinkStateList` on transport-up in BOTH
//! routing modes: full-linkstate (`hat/linkstate_peer`, via the shared `Network`)
//! AND the default gossip `peer_to_peer` (`hat/p2p_peer/gossip.rs`). So the weak
//! witness `"learned mesh topology"` (wz `ingested() > 0`) fires against a gossip
//! peer too — it proves only that wz decoded SOME LinkStateList, not that it
//! federated at the linkstate tier.
//!
//! The load-bearing signal is on the flood CONTENT: a full-linkstate self-entry
//! carries `links={wz}` (the reciprocal edge back to the dialer), so wz forms a
//! MUTUAL graph edge (`edge_count > 0`, witness `"confirmed reciprocal mesh
//! link"`). A gossip self-entry carries `links:false` — a node announcement with
//! no reciprocal link — so wz builds the node but NO edge (`edge_count == 0`,
//! witness absent). wz's `rebuild_edges` forms an edge only on a mutual link, so
//! the register-time `add_link` (self's outbound link only) never fabricates one;
//! the edge appears solely from ingesting zenohd's reciprocal advertisement.
//!
//! Hence the two legs:
//!   - [`wz_peer_federates_with_zenohd_at_linkstate_tier`] (positive): a
//!     linkstate zenohd → wz emits BOTH witnesses.
//!   - [`wz_peer_gossip_zenohd_yields_no_linkstate_edge`] (neuter): a default
//!     gossip zenohd → wz emits `"learned mesh topology"` but NOT the reciprocal
//!     witness (`0 edge(s)`), proving the edge witness is load-bearing and the
//!     positive proof is not a green-but-meaningless `ingested`-only pass.
//!
//! SCOPE (round 1): this proves the CONTROL-PLANE / topology tier only — that
//! wz and zenohd converge a link-state peer mesh over the wire. The DATA plane
//! (pub/sub across the wz <-> zenohd peer link: a subscriber behind one peer
//! receiving a publisher's Put routed through the other) is deferred to a
//! follow-up leg, mirroring the router-hat interop's stage order (topology leg 1,
//! data legs 2+). No assertion here reads a data-push witness.
//!
//! Requires the `wz-ap-demo` binary built with `--features routing-peer` (the
//! `--peer` arg is opt-in behind it) and a `zenohd` binary (`WZ_ZENOHD_BIN` or
//! `scripts/build-zenohd.sh`). `#[ignore]` binary-dep e2e; run via Layer Z /
//! `--ignored`. `--test-threads=1` isolates the per-leg zenohd.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_tcp_accept_alive,
    wait_for_zenohd_handshake_ready, wz_ap_demo_binary, zenohd_binary, ChildGuard, PortReservation,
    ZENOHD_TCP_ACCEPT_BUDGET,
};

/// Spawn a real zenohd in `mode=peer` on `port` and block until it is
/// HANDSHAKE-ready. `linkstate` selects the routing HAT via the wire cfg:
///   - `true`  → `--cfg mode:"peer"` + `--cfg routing/peer/mode:"linkstate"`
///     (the `hat/linkstate_peer` full-linkstate HAT — floods self with a
///     reciprocal link back to the dialer).
///   - `false` → `--cfg mode:"peer"` only, leaving zenoh's default
///     `routing/peer/mode = "peer_to_peer"` (the `hat/p2p_peer` gossip HAT —
///     floods a node-only self-announcement, no reciprocal link).
///
/// Follows the usrpwd/pubkey cfg-custom-zenohd precedent (own `Command` with
/// `--cfg` args in the test file) while reusing the shared readiness SSOT:
/// TCP-accept then `wait_for_zenohd_handshake_ready`. Unlike the auth tests, a
/// peer zenohd has no auth barrier, so the anonymous wz-Client handshake probe
/// reaches Established (routing mode governs peer-to-peer flooding, not
/// Client-transport admission). Returns the panic-safe process guard.
fn spawn_peer_zenohd(port: u16, linkstate: bool) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        // The `--cfg KEY:VALUE` VALUE is JSON5, so the string values are quoted.
        .arg("--cfg")
        .arg("mode:\"peer\"");
    if linkstate {
        command.arg("--cfg").arg("routing/peer/mode:\"linkstate\"");
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        if linkstate {
            "zenohd (linkstate peer)"
        } else {
            "zenohd (gossip peer)"
        },
        command.spawn().expect("spawn zenohd peer"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (peer): {e}");
    }
    // Close the TCP-accept-vs-handshake-ready gap with a real wz Client session
    // (the shared readiness SSOT). A linkstate/gossip peer admits a Client
    // transport regardless of routing mode, so the anonymous probe reaches
    // Established.
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    guard
}

/// Spawn `wz-ap-demo --peer 127.0.0.1:0 --connect 127.0.0.1:{port}` — a wz peer
/// that listens on an ephemeral port AND dials the zenohd peer at `port`, routing
/// stderr into a capture tempfile. Returns the panic-safe guard plus the readable
/// capture handle. Requires the binary built with `--features routing-peer`.
fn spawn_wz_peer_dialing(demo: &std::path::Path, port: u16) -> (ChildGuard, File) {
    let stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let writer = stderr.try_clone().expect("dup wz peer stderr handle");
    let guard = ChildGuard::wrap(
        "wz-ap-demo peer (--peer --connect zenohd)",
        Command::new(demo)
            .arg("--peer")
            .arg("127.0.0.1:0")
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer"),
    );
    (guard, stderr)
}

// wz-proves: routing-peer zenohd->wz partial
// wz-proves: routing-peer wz->zenohd partial
#[test]
#[ignore = "binary-dep e2e (zenohd peer + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_federates_with_zenohd_at_linkstate_tier() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();

    // zenohd in FULL-LINKSTATE peer mode (the `hat/linkstate_peer` HAT).
    let mut zenohd = spawn_peer_zenohd(port, true);

    // wz peer dials zenohd; the port reservation is held until both zenohd has
    // bound (inside spawn_peer_zenohd) and wz has been handed the dial target.
    let (mut wz_guard, mut wz_reader) = spawn_wz_peer_dialing(&demo, port);
    drop(port_res);

    // Settle on the reciprocal-link witness: wz ingested zenohd's linkstate flood
    // AND formed the mutual graph edge (the full-linkstate discriminator). This
    // is the deterministic post-ingest barrier — no dependence on the face-UP
    // timing that precedes the inbound OAM poll.
    let reciprocal = wait_for_substring(
        &mut wz_reader,
        "reciprocal mesh link confirmed",
        Duration::from_secs(15),
    );

    // Graceful-shutdown wz → it logs its peer-loop summary + the shutdown
    // witnesses the assertions read.
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz peer stderr ---\n{wz_captured}");

    // Diagnostics first, then assert.
    reciprocal.unwrap_or_else(|c| {
        panic!(
            "wz peer never confirmed a reciprocal mesh link with the linkstate zenohd \
             within 15s — the linkstatepeers_net flood did not converge into a mutual \
             edge over the wire\n--- wz peer stderr ---\n{c}"
        )
    });

    // Weak witness: wz decoded SOME zenohd LinkStateList (shared with the gossip
    // case; necessary but not sufficient for the linkstate claim).
    assert!(
        wz_captured.contains("learned mesh topology"),
        "wz peer summary must report 'learned mesh topology' — it must ingest \
         zenohd's link-state flood over the wire\n--- wz peer stderr ---\n{wz_captured}"
    );
    // Load-bearing witness: wz formed a MUTUAL edge, which ONLY a full-linkstate
    // self-entry (reciprocal `links={wz}`) produces — the wz-peer <-> zenohd-peer
    // linkstate-tier federation proof. NOTE: `edge_count > 0` uniquely names the
    // wz <-> zenohd link here ONLY because the topology has exactly two nodes (no
    // third node can contribute an unrelated edge); a future 3-node variant must
    // assert the edge ENDPOINTS, not just the count.
    assert!(
        wz_captured.contains("confirmed reciprocal mesh link"),
        "wz peer summary must report 'confirmed reciprocal mesh link' — federating \
         with a LINKSTATE zenohd peer must form a mutual graph edge (zenohd's \
         self-entry advertises a link back to wz)\n--- wz peer stderr ---\n{wz_captured}"
    );
}

// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd peer + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_gossip_zenohd_yields_no_linkstate_edge() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();

    // zenohd in DEFAULT gossip peer mode (`routing/peer/mode = "peer_to_peer"`,
    // the `hat/p2p_peer` HAT) — the neuter: it floods a node-only
    // self-announcement, NOT a reciprocal link.
    let mut zenohd = spawn_peer_zenohd(port, false);

    let (mut wz_guard, mut wz_reader) = spawn_wz_peer_dialing(&demo, port);
    drop(port_res);

    // Settle on the INGEST witness (not the reciprocal one — a gossip flood never
    // trips it): wz decoded the gossip self-announcement. This guarantees the
    // flood ARRIVED before shutdown, so the "no reciprocal edge" assertion below
    // is a genuine content distinction, not a premature-teardown false negative.
    let ingested = wait_for_substring(
        &mut wz_reader,
        "ingested neighbour link-state",
        Duration::from_secs(15),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz peer stderr ---\n{wz_captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz peer never ingested the gossip zenohd's link-state within 15s — the \
             gossip self-announcement did not arrive, so the neuter cannot \
             distinguish it from a linkstate flood\n--- wz peer stderr ---\n{c}"
        )
    });

    // The weak witness FIRES for a gossip peer too — proof that "learned mesh
    // topology" alone does NOT establish linkstate-tier federation (the
    // green-but-meaningless surface the positive test's edge witness closes).
    assert!(
        wz_captured.contains("learned mesh topology"),
        "wz peer summary must still report 'learned mesh topology' against a gossip \
         zenohd — it decoded the gossip self-announcement (the weak witness is \
         shared)\n--- wz peer stderr ---\n{wz_captured}"
    );
    // The load-bearing witness is ABSENT: a gossip self-entry carries no
    // reciprocal link, so wz forms NO mutual edge. This is what makes the
    // positive test's reciprocal witness load-bearing.
    assert!(
        !wz_captured.contains("confirmed reciprocal mesh link"),
        "wz peer must NOT report 'confirmed reciprocal mesh link' against a GOSSIP \
         zenohd — a peer_to_peer self-entry advertises no link back, so no mutual \
         edge can form; the reciprocal witness would be green-but-meaningless if it \
         fired here\n--- wz peer stderr ---\n{wz_captured}"
    );
    // Precise corroboration: the shutdown summary reports zero graph edges. The
    // needle is comma-bounded on BOTH sides ("..., 0 graph edge(s), ...") so it
    // cannot be spuriously satisfied by a multi-digit count ("10 graph edge(s)").
    assert!(
        wz_captured.contains(", 0 graph edge(s),"),
        "wz peer summary must report '0 graph edge(s)' against a gossip zenohd (node \
         learned, no mutual edge)\n--- wz peer stderr ---\n{wz_captured}"
    );
}
