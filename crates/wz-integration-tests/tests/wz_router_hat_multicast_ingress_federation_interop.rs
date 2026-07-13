// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 router-multicast-faces — CROSS-IMPL validation of the wz router-hat's
//! LOOP-SAFE multicast-ingress -> mesh FEDERATION (I3c, the real-socket proof of
//! I3b's per-keyexpr Designated-Router election).
//!
//! I3b (committed R311y197) made a wz `--router-hat` federate a multicast-ingress
//! Push into the unicast linkstate mesh, loop-safe when TWO wz routers share one
//! UDP-multicast group AND are mesh-peered, via a per-keyexpr Designated-Router (DR)
//! election: `elect_router` (seedless HRW) over the on-group `whatami=Router`
//! members U self picks exactly ONE on-group router to bridge group <-> mesh. That
//! is UNIT-proven + IMPL-traced, but the JOIN-whatami -> `router_member_zids` ->
//! snapshot-diff relay -> `set_mcast_group_members` membership chain is only
//! exercised by unit tests that INJECT members directly. I3c closes both: it stands
//! the two-router-shared-group topology up over real sockets and proves the DR
//! election converges cross-process + stays loop-safe.
//!
//! Topology (four processes):
//!
//!   pico z_pub -m peer ─┐ UDP mcast 224.0.0.225:7452
//!                       ├─► R1 (--router-hat) ◄── TCP mesh ──► R2 (--router-hat)
//!                       └─►                          │
//!                          (both on the group)       │ TCP (peer mesh)
//!                                                     ▼
//!                                          P (--peer --subscribe, OFF the group,
//!                                             meshed to BOTH R1 and R2)
//!
//! R1 + R2 both `--router-hat`: each derives a DISTINCT port-based zid
//! (`0x7268 ++ ephemeral listen port`), so on the shared group neither's RX
//! self-zid gate drops the other's JOIN and the DR election has a real 2-member
//! candidate set. R2 `--connect`s R1, so they mesh-peer (both `WhatAmI::Router` ->
//! each in the other's `routers_net`). P is a `--peer` subscriber `--connect`ing
//! BOTH routers; it never joins the multicast group. A `--peer` sub receives a
//! mcast-ingress Put ONLY via the DR-gated federation path
//! (`publish_client_push_into_meshes` into the peer tier) — NOT via a router's local
//! client delivery (that is master-gated and reaches only `--key` CLIENT faces) — so
//! P firing proves FEDERATION, not the I1/I2 local-delivery path. pico `z_pub -m
//! peer` is a FOREIGN injector.
//!
//! ## What this proves — and what it does NOT (honest scope)
//!
//! - PROVES (a) the JOIN -> member-relay -> DR-election chain converges over real
//!   sockets between two wz routers (the leg the I3b unit tests inject past), and
//!   (b) it is LOOP-SAFE: EXACTLY ONE of the two routers federates the group-ingress
//!   Put into the mesh (the deterministic single-bridge witness — assertion C), so
//!   the two-router-shared-group echo zenoh's `WhatAmI::Client` "Quick hack" leaves
//!   undefended cannot occur; and (c) the federated copy reaches an OFF-group mesh
//!   subscriber (delivery — assertion D).
//! - The loop-safety is a wz-vs-wz property (two wz ROUTERS electing one DR). The
//!   pico is a `whatami=Peer` INJECTOR — it is filtered OUT of the DR candidate set
//!   (`router_member_zids` keeps only `whatami=Router`), so it does NOT participate
//!   in the election. I3c proves the wz superset stays loop-safe AROUND a foreign
//!   group publisher, NOT "cross-impl DR election."
//! - SUPERSET, not a mirror: zenoh has NO reference behavior here (its multicast is a
//!   peer-leaf "Quick hack", never two federated routers on a shared group). I3c
//!   proves a wz structural superset works, built from zenoh's own `elect_router`
//!   HRW primitive; the mcast peer stays a faithful `WhatAmI::Client` leaf.
//! - Assertion C is DETERMINISTIC (a 1-of-2 log partition), NOT a packet count —
//!   `elect_router` returns self on an EMPTY candidate set, so "exactly one
//!   federates" is satisfiable only if the membership relay populated each router's
//!   set; it proves loop-safety AND the relay wiring in one, with no timing
//!   threshold ([[feedback_no_flaky_ever]]).
//!
//! ## No-flaky discipline
//!
//! Every barrier is crossed BEFORE pico publishes: both routers join the group +
//! bind TCP, the router mesh converges (routers-net = 2), BOTH routers relay the
//! OTHER as an on-group router member (the loop-safety barrier — kills the startup
//! double-DR transient where an empty candidate set makes both self-elect DR), and
//! both routers install P's peer-native subscription. pico then `z_pub -n 30`
//! (1/s, 30 s) so no single JOIN-admission window is raced. Same-host loopback
//! multicast (`set_multicast_loop_v4(true)` + SO_REUSEADDR/REUSEPORT) carries the
//! A<->B JOIN exchange; the membership barrier converts an asymmetric-loopback
//! environment into a clean fast failure instead of a silent hang.
//!
//! Shared-group caveat: the group+port (224.0.0.225:7452) is the demo default, also
//! used by I2/S4. A STRAY `whatami=Router` beacon on it (a leaked prior-run process)
//! would enter the DR pool and could out-hash both R1 and R2 -> neither federates ->
//! assertion C fails LOUD (never a flaky pass). run-ci runs the Layer-M interop
//! tests as separate sequential `cargo test` invocations, so an in-CI collision does
//! not occur.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent (a routeless container drops the IGMP
//! join), and I3c needs it BIDIRECTIONALLY between two same-host routers, so this is
//! opt-in like the sibling multicast interop lanes (Layer M, `WZ_RUN_LAYER_M=1`).
//! Requires wz-ap-demo built `--features router-multicast-faces` AND the zenoh-pico
//! CLI (`z_pub`). The fn name carries both `wz_router` and `multicast` so the default
//! Layer-E sweep's `--skip` excludes it.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    default_route_iface, graceful_terminate, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wait_for_tcp_accept, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
const PORT: u16 = 7452;
const KEY: &str = "demo/mcast/i3c";
const VALUE: &str = "WZ-MCAST-I3C-FEDERATION";

/// Spawn a `--router-hat` node on an ephemeral port; waits for its listen marker.
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

/// Spawn a `--peer` subscriber node on an ephemeral port; waits for its listen
/// marker. A `--peer` presents `WhatAmI::Peer` and lands in each router's
/// `linkstatepeers_net`.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, std::fs::File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "peer: listening on 127.0.0.1:",
        label,
        stderr,
    )
}

/// I3c — two wz router-hats sharing one multicast group + mesh-peered federate a
/// foreign pico's group-injected Put into the mesh to an off-group subscriber,
/// loop-free: EXACTLY ONE router (the elected DR) bridges the group into the mesh.
// wz-proves: router-multicast-faces pico->wz
// wz-proves: transport-multicast pico->wz
// wz-proves: session-multicast pico->wz partial
// wz-proves: codec-join pico->wz
// wz-proves: codec-frame pico->wz
// wz-proves: codec-push pico->wz
// wz-proves: pubsub-put pico->wz
// wz-proves: keyexpr-literal pico->wz
// wz-proves: transport-link-udp pico->wz
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces + zenoh-pico z_pub); Layer M runs via --ignored"]
fn wz_router_hat_multicast_ingress_federates_loop_safe_from_pico_zpub() {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");
    let ingress_marker = format!("multicast ingress group {GROUP}:{PORT} joined");
    let converged_2 = "router-hat: routers-net converged (2 node(s))";
    let members_converged = "router-hat: on-group router members converged";

    // ── R1: joins the group + binds TCP. Binds FIRST so R2 can dial it. ──
    let (mut r1_guard, mut r1_reader, p_r1) =
        spawn_router_hat("router-hat-1", &["--router-hat", "127.0.0.1:0"]);
    let addr_r1 = format!("127.0.0.1:{p_r1}");
    if let Err(c) = wait_for_substring(&mut r1_reader, &ingress_marker, Duration::from_secs(5)) {
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        panic!(
            "router-hat-1 never logged the multicast ingress join witness \
             ({ingress_marker:?}) within 5s — the demo was likely built WITHOUT \
             `--features router-multicast-faces`\n--- router-hat-1 stderr ---\n{c}"
        );
    }

    // ── R2: joins the group + dials R1 (mesh peering). ──
    let (mut r2_guard, mut r2_reader, p_r2) = spawn_router_hat(
        "router-hat-2",
        &["--router-hat", "127.0.0.1:0", "--connect", &addr_r1],
    );
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    if let Err(c) = wait_for_substring(&mut r2_reader, &ingress_marker, Duration::from_secs(5)) {
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        let _ = r2_guard.child_mut().kill();
        let _ = r2_guard.child_mut().wait();
        panic!("router-hat-2 never joined the multicast group within 5s\n--- stderr ---\n{c}");
    }

    // Accept loops warm (P will be the first TCP client of each).
    if !wait_for_tcp_accept(p_r1, Duration::from_secs(5))
        || !wait_for_tcp_accept(p_r2, Duration::from_secs(5))
    {
        for g in [&mut r1_guard, &mut r2_guard] {
            let _ = g.child_mut().kill();
            let _ = g.child_mut().wait();
        }
        panic!("a router-hat accept loop never accepted a TCP connect within 5s");
    }

    // Barrier: the router MESH converged (each classified the other into
    // `routers_net`) — the federation floor.
    for (label, reader) in [
        ("router-hat-1", &mut r1_reader),
        ("router-hat-2", &mut r2_reader),
    ] {
        if let Err(c) = wait_for_substring(reader, converged_2, Duration::from_secs(15)) {
            let _ = r1_guard.child_mut().kill();
            let _ = r1_guard.child_mut().wait();
            let _ = r2_guard.child_mut().kill();
            let _ = r2_guard.child_mut().wait();
            panic!("{label} never converged its router tier to 2 within 15s\n--- stderr ---\n{c}");
        }
    }

    // Barrier (the LOOP-SAFETY barrier): BOTH routers relayed the OTHER as an
    // on-group ROUTER member, so each has a non-empty DR candidate set before any
    // Put — no window where an empty set makes both self-elect DR. This is also the
    // e2e witness of the JOIN->router_member_zids->relay->set chain the unit tests
    // inject past.
    for (label, reader) in [
        ("router-hat-1", &mut r1_reader),
        ("router-hat-2", &mut r2_reader),
    ] {
        if let Err(c) = wait_for_substring(reader, members_converged, Duration::from_secs(15)) {
            let _ = r1_guard.child_mut().kill();
            let _ = r1_guard.child_mut().wait();
            let _ = r2_guard.child_mut().kill();
            let _ = r2_guard.child_mut().wait();
            panic!(
                "{label} never converged its on-group router members within 15s — the \
                 A<->B group JOIN exchange did not complete (asymmetric loopback \
                 multicast?), so the DR election has no candidate set\n--- stderr ---\n{c}"
            );
        }
    }

    // ── P: an off-group `--peer` subscriber, meshed to BOTH routers so it receives
    //    the federated Put regardless of which router is elected DR. ──
    let (mut p_guard, mut p_reader, _p_p) = spawn_peer(
        "peer-sub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &format!("{addr_r1},{addr_r2}"),
            "--subscribe",
            KEY,
        ],
    );

    // Barrier: BOTH routers installed P's peer-native subscription (so whichever is
    // DR forwards the federated Put toward P).
    for (label, reader) in [
        ("router-hat-1", &mut r1_reader),
        ("router-hat-2", &mut r2_reader),
    ] {
        if let Err(c) = wait_for_substring(
            reader,
            "router-hat: learned a mesh sub",
            Duration::from_secs(15),
        ) {
            let p_cap = read_captured(&mut p_reader);
            for g in [&mut r1_guard, &mut r2_guard, &mut p_guard] {
                let _ = g.child_mut().kill();
                let _ = g.child_mut().wait();
            }
            panic!(
                "{label} never learned P's peer subscription within 15s\n--- router \
                 stderr ---\n{c}\n--- peer-sub stderr ---\n{p_cap}"
            );
        }
    }

    // ── pico z_pub (FOREIGN whatami=Peer injector): a LITERAL Put on KEY over the
    //    group, once a second for 30 s (spans many JOIN intervals). ──
    let z_pub_capture = tempfile::tempfile().expect("tempfile for z_pub capture");
    let z_pub_out = z_pub_capture.try_clone().expect("dup z_pub stdout");
    let z_pub_err = z_pub_capture.try_clone().expect("dup z_pub stderr");
    let mut z_pub_reader = z_pub_capture;
    let mut z_pub_child = ChildGuard::wrap(
        "z_pub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args([
                "-k", KEY, "-v", VALUE, "-l", &locator, "-m", "peer", "-n", "30",
            ])
            .stdout(Stdio::from(z_pub_out))
            .stderr(Stdio::from(z_pub_err))
            .spawn()
            .expect("spawn z_pub via stdbuf"),
    );

    // Success gate: P received the federated Put over the mesh (delivery). pico
    // publishes ~1/s; the 25 s budget is generous margin.
    let received = wait_for_substring(&mut p_reader, "received mesh data", Duration::from_secs(25));

    // Teardown: kill the injector + subscriber, then graceful_terminate the routers
    // so they flush their LATCHED shutdown witnesses (peak member count + the
    // federated/suppressed 1-of-2 partition).
    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();
    let _ = p_guard.child_mut().kill();
    let _ = p_guard.child_mut().wait();
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));

    let r1_cap = read_captured(&mut r1_reader);
    let r2_cap = read_captured(&mut r2_reader);
    let p_cap = read_captured(&mut p_reader);
    let z_pub_cap = read_captured(&mut z_pub_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_cap}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_cap}");
    eprintln!("--- peer-sub stderr ---\n{p_cap}");
    eprintln!("--- pico z_pub stdout ---\n{z_pub_cap}");

    // Assertion D — delivery: the federated copy reached the OFF-group subscriber.
    received.unwrap_or_else(|c| {
        panic!(
            "peer-sub never received the federated Put within 25s — the pico group \
             Put did not federate through the DR into the mesh to the off-group \
             subscriber\n--- peer-sub stderr ---\n{c}\n--- router-hat-1 ---\n{r1_cap}\n\
             --- router-hat-2 ---\n{r2_cap}\n--- pico ---\n{z_pub_cap}"
        )
    });

    // Assertion A — the two-router mesh federated (loop-safety only matters given a
    // shared group AND a mesh between the routers).
    for (label, cap) in [("router-hat-1", &r1_cap), ("router-hat-2", &r2_cap)] {
        assert!(
            cap.contains("peak routers-net 2 node(s)"),
            "{label} did not peak at 2 router-tier nodes — the routers did not \
             federate\n--- {label} stderr ---\n{cap}"
        );
    }

    // Assertion B — the JOIN -> member-relay -> DR-election chain ran e2e on both
    // routers (the unit-uncovered leg). Presence, NOT an exact count: a router may
    // list the peer's zid twice (its egress + ingress group sockets are distinct
    // src-addrs), so the peak can be 1 or 2 — either witnesses the relay ran.
    for (label, cap) in [("router-hat-1", &r1_cap), ("router-hat-2", &r2_cap)] {
        assert!(
            cap.contains("peak on-group router members"),
            "{label} never logged an on-group router member — the membership relay \
             chain did not run\n--- {label} stderr ---\n{cap}"
        );
    }

    // Assertion C — the deterministic LOOP-SAFETY proof: EXACTLY ONE router federated
    // the mcast-ingress into the mesh (the elected DR) and the OTHER suppressed it
    // (non-DR). Because `elect_router` returns self on an empty candidate set, this
    // partition is satisfiable ONLY if the membership relay fed each router the
    // other's zid — so it proves single-bridge loop-safety AND the relay wiring, with
    // no packet counting.
    let dr = "router-hat: federated a mcast-ingress push into the mesh (DR)";
    let non_dr = "router-hat: suppressed a mcast-ingress federation (not DR)";
    let r1_fed = r1_cap.contains(dr);
    let r2_fed = r2_cap.contains(dr);
    let r1_sup = r1_cap.contains(non_dr);
    let r2_sup = r2_cap.contains(non_dr);
    assert!(
        (r1_fed && r2_sup && !r1_sup && !r2_fed) || (r2_fed && r1_sup && !r2_sup && !r1_fed),
        "loop-safety violated: exactly ONE router must federate the mcast-ingress (the \
         DR) and the other suppress it. Got r1_federated={r1_fed} r1_suppressed={r1_sup} \
         r2_federated={r2_fed} r2_suppressed={r2_sup} — both federating = the \
         two-router echo-loop; neither = a pool-pollution / delivery failure.\n--- \
         router-hat-1 stderr ---\n{r1_cap}\n--- router-hat-2 stderr ---\n{r2_cap}"
    );
}
