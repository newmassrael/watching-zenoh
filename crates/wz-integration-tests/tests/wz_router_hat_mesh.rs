// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 ACTIVATION — the router-hat forwarder driven END TO END over real
//! transport, the first composition of the dual-mesh `RouterForwarder` (the zenoh
//! `hat/router` port) outside its own unit tests.
//!
//! The router-hat node (`--router-hat <listen>`) is the FIRST wz run-mode to
//! present a true wire `WhatAmI::Router`: connecting `--peer` nodes announce
//! `WhatAmI::Peer` and are classified into the router's `linkstatepeers_net`,
//! while a router-to-router link (ACTIVATION-4) would land in `routers_net`. Until
//! this slice the forwarder was UNIT-TESTED-ONLY (production wiring still uses
//! `RoutingForwarder` / `LinkstateForwarder`); these tests stand up the harness
//! that composes it — register / tier-classify / OAM ingest / declare
//! ingest+reflood / data route — through `accept_loop` over loopback TCP, the
//! load-bearing obligation the R311y116 session review pinned before any run-mode
//! flip.
//!
//! Two tests, STAGED so a failure localises (topology before forwarding):
//!
//! 1. `wz_router_hat_converges_with_a_peer` — the 2-node topology floor: a
//!    router-hat R + one peer P dialing it. R must ingest P's link-state and
//!    converge its PEER tier to 2 nodes (self + P), proving the Router-whatami
//!    handshake is accepted, the peer is tier-classified into `linkstatepeers_net`
//!    (not `routers_net`, which stays at 1 = self alone), and the register-time
//!    OAM bootstrap converges both directions with no third trigger. This isolates
//!    a topology failure from a forwarding failure.
//!
//! 2. `wz_router_hat_forwards_between_peers` — the 3-node STAR data path: a
//!    subscriber P1 and a publisher P2, each dialing ONLY R (no autoconnect, so
//!    they never learn each other's address — delivery CANNOT bypass the router).
//!    P1's `DeclareSubscriber` must flood P1 -> R -> P2 (so P2 learns the interest
//!    that gates its publish), and P2's Put must route P2 -> R -> P1 through the
//!    router's within-tier data route. The witnesses pin the transit: R's own
//!    `data_seen` rises (the Push crossed the router), so P1's reception is proof
//!    the router FORWARDED it, not that the peers reached each other directly.
//!
//! Requires the binary built with `--features routing-router-hat` (which pulls
//! `routing-peer` transitively, so ONE binary serves both the `--router-hat` node
//! and the `--peer` nodes). run-ci's Layer E7 builds it and runs both tests on the
//! `--ignored` lane, like the other binary-dep e2es. The test fn names carry the
//! `wz_router_hat_` prefix so the default Layer E sweep's `--skip wz_router`
//! substring excludes them from the arbitrary-feature binary run.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// Parse the bound port from a node's `listening on 127.0.0.1:<port>` log line —
/// the ephemeral-port read-back that lets the next node dial this one without a
/// reserved-port allocation. Shared by the router-hat and peer spawns (both log
/// the same `listening on 127.0.0.1:` marker).
fn listen_port(captured: &str) -> u16 {
    let marker = "listening on 127.0.0.1:";
    let rest = captured
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
}

/// Spawn a demo node on an ephemeral port and wait until it binds, then read the
/// bound port back from its listen log. `listen_marker` is the role-specific
/// prefix of the listen line (`"router-hat: listening on 127.0.0.1:"` /
/// `"peer: listening on 127.0.0.1:"`), so one spawner serves both node kinds.
fn spawn_node(label: &str, listen_marker: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for node stderr");
    let writer = stderr.try_clone().expect("dup node stderr handle");
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
    let captured = wait_for_substring(&mut reader, listen_marker, Duration::from_secs(5))
        .unwrap_or_else(|c| {
            let _ = guard.child_mut().kill();
            let _ = guard.child_mut().wait();
            panic!(
                "{label} did not bind within 5s (is the binary built with \
                 --features routing-router-hat?)\n--- {label} stderr ---\n{c}"
            );
        });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Spawn the router-hat node (`--router-hat`) — presents wire `WhatAmI::Router`.
fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    spawn_node(label, "router-hat: listening on 127.0.0.1:", args)
}

/// Spawn a `--peer` mesh node — presents wire `WhatAmI::Peer`.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    spawn_node(label, "peer: listening on 127.0.0.1:", args)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router-hat); Layer E runs via --ignored"]
fn wz_router_hat_converges_with_a_peer() {
    // The topology floor: a router-hat R + one peer P dialing it. R binds first so
    // P can dial its ephemeral port.
    let (mut r_guard, mut r_reader, p_r) =
        spawn_router_hat("router-hat", &["--router-hat", "127.0.0.1:0"]);
    let addr_r = format!("127.0.0.1:{p_r}");
    let (mut p_guard, mut p_reader, _p_p) =
        spawn_peer("peer", &["--peer", "127.0.0.1:0", "--connect", &addr_r]);

    // R must converge its PEER tier to 2 nodes (self + the connecting peer) — the
    // in-run positive-edge witness, deterministic once R ingests P's link-state
    // (the register-time OAM bootstrap). Reaching this proves: the Router-whatami
    // acceptor accepted the Peer's handshake, R classified the peer into
    // `linkstatepeers_net` (a Peer face, not a router), and both directions'
    // link-state converged over the wire with no third trigger.
    let r_converged = wait_for_substring(
        &mut r_reader,
        "router-hat: peers-net converged (2 node(s))",
        Duration::from_secs(15),
    );

    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(p_guard.child_mut(), Duration::from_secs(5));
    let r_captured = read_captured(&mut r_reader);
    let p_captured = read_captured(&mut p_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- peer stderr ---\n{p_captured}");

    r_converged.unwrap_or_else(|c| {
        panic!(
            "router-hat never converged its peer tier to 2 nodes within 15s — the \
             peer's link-state did not reach the router (Router-whatami handshake \
             rejected, tier misclassified, or the OAM bootstrap did not \
             fire)\n--- router-hat stderr ---\n{c}"
        )
    });
    // The DETERMINISTIC shutdown witness (gated on ingested > 0): R learned the
    // mesh topology over the wire. Count-free (the sibling's style — the exact
    // ingest round-count is an internal protocol detail, not a stable contract).
    assert!(
        r_captured.contains("router-hat: learned mesh topology"),
        "router-hat's shutdown witness must report it learned the mesh topology \
         (it ingested the peer's link-state)\n--- router-hat stderr ---\n{r_captured}"
    );
    // Tier classification — the deterministic shutdown peaks: the connecting node
    // was a PEER, so it landed in the PEER tier (peers-net peaked at 2 = self +
    // peer) and NOT the router tier (routers-net stayed at 1 = self alone). This
    // is what the router-hat adds over a plain peer. The peaks are high-water
    // (latched, emitted unconditionally at shutdown), so they cannot race the tick.
    assert!(
        r_captured.contains("peak routers-net 1 node(s), peak peers-net 2 node(s)"),
        "router-hat must classify the connecting peer into the PEER tier \
         (peers-net 2, routers-net 1) — a peer must not land in the router \
         tier\n--- router-hat stderr ---\n{r_captured}"
    );
    // The peer side likewise converged (it ingested the router's link-state) — the
    // handshake to a Router-whatami acceptor works from the peer's side too.
    assert!(
        p_captured.contains("learned mesh topology"),
        "peer never converged with the router-hat node — the peer could not \
         handshake/ingest a WhatAmI::Router acceptor\n--- peer stderr ---\n{p_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-router-hat); Layer E runs via --ignored"]
fn wz_router_hat_forwards_between_peers() {
    // The 3-node STAR: a subscriber P1 and a publisher P2, each dialing ONLY the
    // router R. With autoconnect off (the default), P1 and P2 never learn each
    // other's address, so any delivery MUST route through R. R binds first.
    let (mut r_guard, mut r_reader, p_r) =
        spawn_router_hat("router-hat", &["--router-hat", "127.0.0.1:0"]);
    let addr_r = format!("127.0.0.1:{p_r}");
    let (mut sub_guard, mut sub_reader, _p_sub) = spawn_peer(
        "peer-sub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_r,
            "--subscribe",
            "demo/hat",
        ],
    );
    let (mut pub_guard, mut pub_reader, _p_pub) = spawn_peer(
        "peer-pub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_r,
            "--publish",
            "demo/hat",
        ],
    );

    // The SUBSCRIBER must RECEIVE the publisher's data — but only via the router:
    // P1's `DeclareSubscriber` floods P1 -> R -> P2 (so P2's any-interest gate
    // opens), and P2's Put routes P2 -> R -> P1 through R's within-tier data
    // route. P1 has no direct link to P2, so receiving proves the full
    // router-forwarded chain over the wire. The publisher publishes every app
    // tick, so once the mesh converges delivery is self-healing (no one-shot drop
    // to race).
    let sub_data = wait_for_substring(
        &mut sub_reader,
        "received mesh data",
        Duration::from_secs(15),
    );

    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(pub_guard.child_mut(), Duration::from_secs(5));
    let r_captured = read_captured(&mut r_reader);
    let sub_captured = read_captured(&mut sub_reader);
    let pub_captured = read_captured(&mut pub_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- peer-sub stderr ---\n{sub_captured}");
    eprintln!("--- peer-pub stderr ---\n{pub_captured}");

    sub_data.unwrap_or_else(|c| {
        panic!(
            "peer-sub never logged 'received mesh data' within 15s — the \
             publisher's data did not route through the router to the subscriber \
             (the router did not forward within its peer tier)\n--- peer-sub \
             stderr ---\n{c}"
        )
    });
    // The transit pin: R's OWN data_seen rose (it counts every inbound Push before
    // routing), so the delivery went THROUGH the router — not around it (the peers
    // never knew each other's address). Without this a green subscriber-receipt
    // could not distinguish a router forward from a direct peer link.
    assert!(
        r_captured.contains("router-hat: forwarded mesh data"),
        "router-hat never forwarded a Push — the subscriber's data did not \
         transit the router, so the delivery did not exercise the router's data \
         route\n--- router-hat stderr ---\n{r_captured}"
    );
    // R's peer tier peaked at all three nodes (self + P1 + P2) — both peers
    // classified into `linkstatepeers_net`. Asserted on the DETERMINISTIC
    // shutdown-summary peak (high-water `peak_peers`, guaranteed 3 once the data
    // above flowed — delivery requires both faces registered), NOT the in-run
    // convergence trace: that positive-edge log samples whatever count the tick
    // sees, so if the two peers converge in DIFFERENT ticks it would emit
    // "(2 node(s))" then "(3 node(s))" and a test racing a specific line flakes.
    assert!(
        r_captured.contains("peak peers-net 3 node(s)"),
        "router-hat's peer tier did not peak at 3 nodes (self + both peers) — a \
         peer failed to join the peer mesh\n--- router-hat stderr ---\n{r_captured}"
    );
    // The publisher must have LEARNED the subscriber's interest (P1's declaration
    // flooded P1 -> R -> P2) before its any-interest gate would forward anything —
    // the subscription half of the routed chain, proving the router ingested and
    // re-flooded the DeclareSubscriber, not merely relayed the data.
    assert!(
        pub_captured.contains("publisher learned subscriber interest"),
        "peer-pub never learned the subscriber's interest — the DeclareSubscriber \
         did not flood through the router to the publisher\n--- peer-pub \
         stderr ---\n{pub_captured}"
    );
}
