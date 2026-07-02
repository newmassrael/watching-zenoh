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
//! Four tests, STAGED so a failure localises (topology before forwarding, single
//! router before federation):
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
//! 3. `wz_router_hat_two_routers_converge` — the FEDERATION topology floor: two
//!    router-hat nodes dialing each other, each classifying the other into
//!    `routers_net` (WhatAmI::Router both sides), converging the router tier to 2.
//!
//! 4. `wz_router_hat_federates_data_across_two_routers` — the PEER-NATIVE
//!    cross-tier federation E2E: a publisher behind R1 reaches a subscriber behind
//!    R2, routed P1 -> R1 -> [router mesh] -> R2 -> P2 (autoconnect off, so the only
//!    path is through BOTH routers). Composes over the wire the A2a
//!    cross-tier-native advertise in its PEER-NATIVE direction (R2 floods P2's
//!    peer-native sub into the router mesh so R1 attracts P1's publish) + the
//!    master-gated cross-mesh bridge. SCOPE — this is NOT the canonical R311y120
//!    black-hole (a ROUTER-NATIVE sub behind a NON-MASTER router): with 2 routers
//!    each is the sole master of its own domain (`shared_nodes` = {self}, the other
//!    router only in its `routers_net`), so no non-master / no HRW election is
//!    exercised, and `router_subs` stays empty (a router-native sub is undrivable
//!    by the OBSERVE-only demo router). The router-native direction + the
//!    non-master-attract corner stay UNIT-proven; this adds the peer-native
//!    federation + sole-master bridge E2E. The QUERY-plane E2E is likewise a NAMED
//!    follow-up — the demo has no mesh-mode query issuer and single-session query
//!    nodes collide on the hardcoded zid; the query ROUTE itself is unit-proven
//!    (route_request / forward_response, incl. 2-router HRW).
//!
//! Requires the binary built with `--features router-hat-router` (the run-mode
//! ACTIVE atom, which pulls the routing-router-hat foundation -> `routing-peer`
//! transitively, so ONE binary serves both the `--router-hat` node
//! and the `--peer` nodes). run-ci's Layer E7 builds it and runs all four tests on
//! the `--ignored` lane, like the other binary-dep e2es. The test fn names carry the
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
                 --features router-hat-router?)\n--- {label} stderr ---\n{c}"
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

/// Spawn a single-session node that DIALS a router (`--connect <router>`) — a
/// client behind the router. Unlike [`spawn_node`] it binds no listener, so it
/// waits for the `connected to` log (dial succeeded) rather than a listen marker.
/// The caller uses that gate to order the queryable's declaration ahead of the
/// issuer's one-shot query.
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
             --features router-hat-router?)\n--- {label} stderr ---\n{c}"
        );
    });
    (guard, reader)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router); Layer E runs via --ignored"]
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
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router); Layer E runs via --ignored"]
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

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router); Layer E runs via --ignored"]
fn wz_router_hat_two_routers_converge() {
    // The federation topology floor: two router-hat nodes dialing each other. R2
    // binds first; R1 dials it. Both present WhatAmI::Router, so each classifies
    // the other into `routers_net` (NOT `linkstatepeers_net`) — the router mesh.
    // This isolates a router-to-router topology failure from a federated-forwarding
    // failure (the ACTIVATION-1 staging discipline).
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    let (mut r1_guard, mut r1_reader, _p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--connect", &addr_r2],
    );

    // BOTH routers must converge their ROUTER tier to 2 (self + the other) — the
    // in-run positive-edge witness, deterministic once each ingests the other's
    // link-state. Await BOTH before terminating: R1 (the dialer) adds R2 on its
    // dial-face-up while R2 (the listener) adds R1 on accept and needs its next app
    // tick to sample the peak, so terminating on R1's convergence alone can beat
    // R2's peak sample (the observed flake). Once a router logs this positive edge
    // its `peak_routers` has reached 2, so the shutdown peak below is then latched.
    let r1_converged = wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    );
    let r2_converged = wait_for_substring(
        &mut r2_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    );

    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    r1_converged.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never converged its router tier to 2 within 15s — the two \
             routers did not federate over the router mesh\n--- router-hat-1 \
             stderr ---\n{c}"
        )
    });
    r2_converged.unwrap_or_else(|c| {
        panic!(
            "router-hat-2 never converged its router tier to 2 within 15s — the two \
             routers did not federate over the router mesh\n--- router-hat-2 \
             stderr ---\n{c}"
        )
    });
    // Deterministic shutdown peaks: BOTH routers peaked at 2 in the ROUTER tier
    // (self + the other router) and stayed at 1 in the PEER tier (the neighbour is
    // a router, not a peer — the tier classification, from the WhatAmI::Router
    // handshake on both sides).
    for (label, captured) in [
        ("router-hat-1", &r1_captured),
        ("router-hat-2", &r2_captured),
    ] {
        assert!(
            captured.contains("peak routers-net 2 node(s), peak peers-net 1 node(s)"),
            "{label} did not peak at 2 router-tier nodes / 1 peer-tier node — the \
             router federation did not converge, or the peer classified the other \
             router into the wrong tier\n--- {label} stderr ---\n{captured}"
        );
    }
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router); Layer E runs via --ignored"]
fn wz_router_hat_federates_data_across_two_routers() {
    // The PEER-NATIVE cross-tier federation E2E over real transport (the
    // load-bearing ACTIVATION obligation): a publisher behind ONE router reaches a
    // subscriber behind ANOTHER, routed P1 -> R1 -> [router mesh] -> R2 -> P2. With
    // autoconnect OFF (the default), P1 knows only R1, P2 only R2, and R1 only dials
    // R2 — so the ONLY P1->P2 path is through BOTH routers. This composes, over the
    // wire, the A2a cross-tier-native advertise in its PEER-NATIVE direction (R2
    // floods P2's peer-native subscription into the router mesh, zenoh
    // `declare_linkstatepeer_subscription` -> `register_router_subscription(self)`,
    // so R1 ATTRACTS P1's publish toward R2) and the master-gated cross-mesh bridge.
    //
    // SCOPE — this proves the PEER-NATIVE federation half, NOT the canonical
    // R311y120 black-hole. The R311y120 scenario is a peer-source Push into a
    // NON-MASTER router whose only subscriber is a ROUTER-NATIVE sub (learned via
    // the router mesh). This harness reproduces NEITHER: (a) with 2 routers each is
    // the SOLE master of its own domain (`shared_nodes` = {self}, the other router
    // being only in its `routers_net`, never its `linkstatepeers_net`), so no
    // non-master and no HRW election is exercised; (b) `router_subs` stays empty —
    // a router-native sub is only created by another router ORIGINATING a native
    // declare, which the OBSERVE-only demo router never does, so the
    // router-native -> peer-mesh advertise direction is UNDRIVABLE by this demo.
    // Both the router-native direction and the non-master-attract corner stay
    // UNIT-proven (advertise_native_cross_tier_sub / push_bridges_cross_mesh_only_
    // when_master); this E2E adds the peer-native federation + the sole-master
    // bridge over real transport. The QUERY-plane E2E is likewise a NAMED
    // follow-up — the demo has no mesh-mode query issuer, and single-session query
    // nodes collide on the hardcoded zid; the query ROUTE is unit-proven
    // (route_request / forward_response, incl. 2-router HRW).
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--connect", &addr_r2],
    );
    let addr_r1 = format!("127.0.0.1:{p_r1}");
    // The subscriber sits behind R2; the publisher behind R1.
    let (mut sub_guard, mut sub_reader, _p_sub) = spawn_peer(
        "peer-sub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_r2,
            "--subscribe",
            "demo/fed",
        ],
    );
    let (mut pub_guard, mut pub_reader, _p_pub) = spawn_peer(
        "peer-pub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_r1,
            "--publish",
            "demo/fed",
        ],
    );

    // Await BOTH routers' router-tier convergence FIRST — a positive edge that
    // latches `peak_routers >= 2`, so the shutdown "peak routers-net 2" assertion
    // below is guaranteed EXPLICITLY (not merely implied by the data-receipt
    // timing). The routers converge on the R1<->R2 dial, independent of the peers.
    for (label, reader) in [
        ("router-hat-1", &mut r1_reader),
        ("router-hat-2", &mut r2_reader),
    ] {
        wait_for_substring(
            reader,
            "router-hat: routers-net converged (2 node(s))",
            Duration::from_secs(15),
        )
        .unwrap_or_else(|c| {
            panic!(
                "{label} never federated its router tier to 2 within 15s\n--- {label} \
                 stderr ---\n{c}"
            )
        });
    }

    // The subscriber behind R2 must RECEIVE the publisher-behind-R1's data — over a
    // path it has no direct link for. The publisher republishes every app tick, so
    // once the federation converges delivery is self-healing (no one-shot drop).
    let sub_data = wait_for_substring(
        &mut sub_reader,
        "received mesh data",
        Duration::from_secs(15),
    );

    graceful_terminate(pub_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    let sub_captured = read_captured(&mut sub_reader);
    let pub_captured = read_captured(&mut pub_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");
    eprintln!("--- peer-sub stderr ---\n{sub_captured}");
    eprintln!("--- peer-pub stderr ---\n{pub_captured}");

    sub_data.unwrap_or_else(|c| {
        panic!(
            "peer-sub (behind R2) never received the publisher-behind-R1's data \
             within 15s — the federation black-hole is NOT closed (P1's Push did \
             not route through the two routers to P2)\n--- peer-sub stderr ---\n{c}"
        )
    });
    // Transit pin: BOTH routers forwarded a Push, so the delivery crossed the router
    // mesh (P1 and P2 never know each other or the far router — autoconnect off). If
    // either router had not forwarded, P2 could not have received.
    for (label, captured) in [
        ("router-hat-1", &r1_captured),
        ("router-hat-2", &r2_captured),
    ] {
        assert!(
            captured.contains("router-hat: forwarded mesh data"),
            "{label} never forwarded a Push — the federated delivery did not transit \
             it, so it did not cross the router mesh\n--- {label} stderr ---\n{captured}"
        );
        assert!(
            captured.contains("peak routers-net 2 node(s)"),
            "{label}'s router tier did not converge to 2 — the routers did not \
             federate\n--- {label} stderr ---\n{captured}"
        );
    }
    // The subscription half: P2's peer-native subscription flooded P2 -> R2 ->
    // [router mesh] -> R1 (the A2a cross-tier-native advertise) so R1's any-interest
    // gate opened and it forwarded P1's publish. Deterministic shutdown witness.
    assert!(
        pub_captured.contains("publisher learned subscriber interest"),
        "peer-pub (behind R1) never learned the subscriber's interest — the \
         cross-tier-native subscription advertise did not federate across the \
         router mesh to R1\n--- peer-pub stderr ---\n{pub_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router); Layer E runs via --ignored"]
fn wz_router_hat_routes_a_client_query_to_a_client_queryable() {
    // P4 §5.21 QUERY-plane E2E — the router's `route_request` + `forward_response`
    // composed over real transport for the FIRST time (the query twin of the
    // data-forward E2E above). A queryable CLIENT and a query-issuer CLIENT each
    // dial ONLY the router R, with DISTINCT `--zid`s so they do not collide in R's
    // mesh graph (the P4 §5.21 query-plane blocker the run-mode flip exposed). R
    // routes the issuer's `Request(Query)` to the queryable's `client_qabls` entry
    // and returns the `Reply` + `ResponseFinal` back down the querier's face. The
    // query ROUTE was UNIT-proven (route_request / forward_response, incl 2-router
    // HRW); this is the E2E composition. The queryable is spawned FIRST and its
    // `DeclareQueryable` reaches R before the issuer's one-shot query fires (the
    // spawn order + the `connected to` gate), so the query finds the queryable.
    let (mut r_guard, mut r_reader, p_r) =
        spawn_router_hat("router-hat", &["--router-hat", "127.0.0.1:0"]);
    let addr_r = format!("127.0.0.1:{p_r}");
    // The queryable client behind R (distinct zid), UP FIRST so R learns it.
    let (mut qbl_guard, mut qbl_reader) = spawn_session(
        "queryable",
        &[
            "--connect",
            &addr_r,
            "--queryable",
            "demo/**",
            "--reply",
            "value-from-router-mesh",
            "--zid",
            "0b0b0b0b",
        ],
    );
    // BARRIER (not a race): wait until R has actually INGESTED the queryable's
    // DeclareQueryable before spawning the issuer, so the issuer's one-shot query
    // cannot arrive before R knows the queryable. `spawn_session` above only gated
    // on the queryable's own TCP dial; this gates on R's routing state. R polls the
    // witness on its 250 ms app tick, so allow generous slack.
    wait_for_substring(
        &mut r_reader,
        "router-hat: learned a queryable",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = qbl_guard.child_mut().kill();
        let _ = qbl_guard.child_mut().wait();
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router never logged it learned the queryable within 10s — the \
             queryable's DeclareQueryable did not reach R\n--- router stderr ---\n{c}"
        )
    });
    // The query issuer behind R (distinct zid): its one-shot query fires on
    // Established and now provably routes THROUGH R to a queryable R already knows.
    let (mut iss_guard, mut iss_reader) = spawn_session(
        "issuer",
        &[
            "--connect",
            &addr_r,
            "--query",
            "demo/test",
            "--on-query-reply-log",
            "--on-query-final-log",
            "--zid",
            "0a0a0a0a",
        ],
    );

    let reply = wait_for_substring(&mut iss_reader, "REPLY RECEIVED", Duration::from_secs(15));
    let final_recv = wait_for_substring(&mut iss_reader, "FINAL RECEIVED", Duration::from_secs(10));

    graceful_terminate(iss_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(qbl_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));
    let r_captured = read_captured(&mut r_reader);
    let qbl_captured = read_captured(&mut qbl_reader);
    let iss_captured = read_captured(&mut iss_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- queryable stderr ---\n{qbl_captured}");
    eprintln!("--- issuer stderr ---\n{iss_captured}");

    let reply_line = reply.unwrap_or_else(|c| {
        panic!(
            "issuer never received a reply within 15s — the query did not route \
             through the router to the queryable (route_request / forward_response \
             did not compose over the wire)\n--- issuer stderr ---\n{c}\n--- \
             queryable stderr ---\n{qbl_captured}\n--- router stderr ---\n{r_captured}"
        )
    });
    assert!(
        reply_line.contains("rid=1"),
        "the routed reply must echo the query's rid=1\n--- issuer ---\n{reply_line}"
    );
    assert!(
        reply_line.contains("payload=\"value-from-router-mesh\""),
        "the queryable's configured reply payload must route back through R\n--- \
         issuer ---\n{reply_line}"
    );
    final_recv.unwrap_or_else(|c| {
        panic!(
            "issuer never received the ResponseFinal within 10s — the query \
             termination did not route back through the router\n--- issuer ---\n{c}"
        )
    });
    // Backstop: the queryable actually ANSWERED (the query reached it via R), so a
    // green reply cannot be a stale/other-run artifact.
    assert!(
        qbl_captured.contains("QUERYABLE FIRED"),
        "the queryable never fired — the routed query did not reach it through \
         R\n--- queryable stderr ---\n{qbl_captured}"
    );
}
