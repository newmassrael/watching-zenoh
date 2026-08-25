// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.21 router-multicast-faces SUB PLANE (S3) — cross-impl REACHABILITY proof.
//!
//! R311y200's sub plane makes a wz `--router-hat` INGEST an on-group subscriber's
//! `DeclareSubscriber` (S1) and ADVERTISE that interest into the unicast linkstate
//! mesh as a self-sourced `DeclareSubscriber` (S2), so a MESH-side publisher (that
//! is NOT on the multicast group) routes a matching Put toward the router and it
//! reaches the on-group subscriber via the router's group egress — resolving the
//! cross-router REACHABILITY limit (a). The unit tests prove the mechanism; this
//! proves it end-to-end against a FOREIGN, unmodified zenoh-pico `z_sub`.
//!
//! ## Topology
//! ```text
//!   stock pico z_sub -m peer ── UDP mcast 224.0.0.225:7452 ──► R1 (--router-hat)
//!   (ON the group, subscribes SUB_KEY)                          (on group + mesh)
//!                                                                     ▲ TCP mesh
//!                                                                     │
//!                                       P (--peer --connect R1 --publish PUBLISH_KEY,
//!                                          OFF the group — reaches the pico ONLY via
//!                                          R1's S2 sub-advertisement)
//! ```
//!
//! ## Why this ISOLATES S2 (not the I3b egress)
//! P is a `--peer` whose `--publish` is SUBSCRIPTION-GATED: it forwards its Put ONLY
//! after it has LEARNED an interested subscriber (`forwarder.interested(key)` is
//! non-empty), logging "publisher learned subscriber interest". The ONLY subscriber
//! for `PUBLISH_KEY` is the pico z_sub ON the group — invisible to the mesh UNTIL R1
//! ingests its `DeclareSubscriber` and advertises it (S2). So P's barrier can fire
//! ONLY if S2 ran; without S2, P never forwards and the barrier times out (LOUD).
//! Then R1 (the sole on-group router ⇒ trivially its own DR) egresses the mesh-
//! sourced Put to the group and the pico z_sub fires its Received callback.
//!
//! ## Stock pico — no custom build (verified by direct read, R311y200 DESIGN)
//! `_z_register_subscriber` sends the `DeclareSubscriber` gated on
//! `_z_locality_allows_remote(allowed_origin)` (net/primitives.c:235), NOT on
//! `Z_FEATURE_MULTICAST_DECLARATIONS`; the default `z_sub` locality is
//! `z_locality_default() == Z_LOCALITY_ANY` (allows remote); and under
//! `MULTICAST_DECLARATIONS=0` the wire keyexpr is a LITERAL (session/keyexpr.c:514)
//! — directly ingestable by the wz literal-resolution path. So an unmodified
//! `z_sub -m peer` declares a literal sub over the group.
//!
//! ## No-flaky
//! Every barrier is crossed BEFORE the assertion: R1 joined the group, R1 advertised
//! the pico's sub (S1+S2 witness), and P learned R1's advertised interest (the sub-
//! gated-publish barrier). The `--peer` publishes every app tick, so the pico's
//! Received line surfaces deterministically once the (already-barriered) route is up.
//! z_sub's stdout is line-buffered via `stdbuf -oL` so the witness surfaces live.
//!
//! Requires wz-ap-demo built `--features router-multicast-faces` AND the zenoh-pico
//! CLI (`z_sub`). The fn name carries both `wz_router` and `multicast` so the default
//! test pass skips it (`#[ignore]`); run-ci Layer M runs it via `--ignored`.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    default_route_iface, read_captured, spawn_on_ephemeral_port, wait_for_substring,
    wait_for_tcp_accept, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
// The wz `--router-hat` hard-codes this data-plane group port (run_router_hat), so
// the pico z_sub joins it to be on R1's group. Shared with the I3c test; both are
// `#[ignore]` Layer-M tests run serially, so no bind contention.
const PORT: u16 = 7452;
// The pico z_sub subscribes a WILDCARD so its local matcher accepts the literal Put
// R1 egresses; R1 ingests THIS keyexpr as the group sub and advertises it, and it
// wildcard-matches P's literal PUBLISH_KEY in the mesh routing.
const SUB_KEY: &str = "demo/mcreach/**";
const PUBLISH_KEY: &str = "demo/mcreach/put";
// The fixed payload a `--peer --publish` peer emits (runner.rs); it appears in
// z_sub's `Received (... : '...')` line only if the Put reached the group byte-exact.
const PAYLOAD: &str = "wz-mesh-data";

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

/// Spawn a `--peer` node on an ephemeral port; waits for its listen marker. A
/// `--peer` presents `WhatAmI::Peer` and lands in the router's `linkstatepeers_net`.
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

/// A mesh-side (off-group) publisher reaches an on-group foreign pico `z_sub` ONLY
/// because the wz `--router-hat` ingested the pico's `DeclareSubscriber` and
/// advertised it into the unicast mesh (§5.21 sub plane, S2) — the cross-impl proof
/// of reachability limit (a).
// wz-proves: router-multicast-faces pico->wz partial
// wz-proves: router-multicast-faces wz->pico partial
// wz-proves: router-hat-router wz->pico partial
// wz-proves: declare-subscriber pico->wz partial
// wz-proves: codec-declare pico->wz partial
// wz-proves: transport-multicast pico->wz
// wz-proves: transport-multicast wz->pico
// wz-proves: session-multicast pico->wz partial
// wz-proves: session-multicast wz->pico partial
// wz-proves: codec-join pico->wz
// wz-proves: codec-join wz->pico
// wz-proves: codec-frame pico->wz
// wz-proves: codec-frame wz->pico
// wz-proves: codec-push wz->pico
// wz-proves: pubsub-put wz->pico
// wz-proves: keyexpr-literal pico->wz
// wz-proves: keyexpr-wildcard-double pico->wz partial
// wz-proves: transport-link-udp pico->wz
// wz-proves: transport-link-udp wz->pico
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces + zenoh-pico z_sub); Layer M runs via --ignored"]
fn wz_router_hat_advertises_group_sub_reaches_pico_zsub() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");
    let ingress_marker = format!("multicast ingress group {GROUP}:{PORT} joined");
    let advertised_marker = "router-hat: advertised on-group subscriber(s) into the mesh";
    let learned_interest = "peer: publisher learned subscriber interest";

    // ── R1: joins the multicast group + binds TCP for the mesh. ──
    let (mut r1_guard, mut r1_reader, p_r1) =
        spawn_router_hat("router-hat-r1", &["--router-hat", "127.0.0.1:0"]);
    let addr_r1 = format!("127.0.0.1:{p_r1}");
    if let Err(c) = wait_for_substring(&mut r1_reader, &ingress_marker, Duration::from_secs(5)) {
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        panic!(
            "router-hat-r1 never logged the multicast ingress join witness \
             ({ingress_marker:?}) within 5s — the demo was likely built WITHOUT \
             `--features router-multicast-faces`\n--- router-hat-r1 stderr ---\n{c}"
        );
    }
    if !wait_for_tcp_accept(p_r1, Duration::from_secs(5)) {
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        panic!("router-hat-r1 accept loop never accepted a TCP connect within 5s");
    }

    // ── pico z_sub (FOREIGN, unmodified): joins the group + declares SUB_KEY. ──
    // stdout+stderr → one line-buffered tempfile (combined capture for diagnosis).
    let z_sub_capture = tempfile::tempfile().expect("tempfile for z_sub capture");
    let z_sub_out = z_sub_capture.try_clone().expect("dup z_sub stdout handle");
    let z_sub_err = z_sub_capture.try_clone().expect("dup z_sub stderr handle");
    let mut z_sub_reader = z_sub_capture;
    let mut z_sub_child = ChildGuard::wrap(
        "z_sub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", SUB_KEY, "-l", &locator, "-m", "peer"])
            .stdout(Stdio::from(z_sub_out))
            .stderr(Stdio::from(z_sub_err))
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // Gate 1: z_sub joined the group + declared its subscriber (sent the
    // DeclareSubscriber over the group).
    if let Err(c) = wait_for_substring(
        &mut z_sub_reader,
        "Declaring Subscriber",
        Duration::from_secs(10),
    ) {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        panic!(
            "z_sub did not log 'Declaring Subscriber' within 10s on {locator} — \
             multicast bind/join failed?\n--- captured z_sub ---\n{c}"
        );
    }

    // Barrier (S1+S2 witness): R1 INGESTED the pico's DeclareSubscriber and
    // ADVERTISED it into the unicast mesh. This is the sub-plane readiness gate — a
    // mesh-side publisher can now route toward R1 for SUB_KEY.
    if let Err(c) = wait_for_substring(&mut r1_reader, advertised_marker, Duration::from_secs(15)) {
        let z_cap = read_captured(&mut z_sub_reader);
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        let _ = r1_guard.child_mut().kill();
        let _ = r1_guard.child_mut().wait();
        panic!(
            "router-hat-r1 never advertised the pico's on-group subscription into the \
             mesh within 15s — the sub INGEST->relay->advertise chain (S1/S2) did not \
             run\n--- router-hat-r1 stderr ---\n{c}\n--- z_sub ---\n{z_cap}"
        );
    }

    // ── P: an OFF-group `--peer` publisher, meshed to R1. Its `--publish` is
    //    subscription-gated, so it forwards ONLY after learning R1's advertised sub. ──
    let (mut p_guard, mut p_reader, _p_p) = spawn_peer(
        "mesh-pub",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_r1,
            "--publish",
            PUBLISH_KEY,
        ],
    );

    // Barrier (the S2 PROOF): P learned an interested subscriber for PUBLISH_KEY.
    // The ONLY such subscriber is the pico z_sub on the group, visible to the mesh
    // ONLY via R1's S2 advertisement — so this can fire ONLY if S2 ran. From here P
    // forwards its Put toward R1.
    if let Err(c) = wait_for_substring(&mut p_reader, learned_interest, Duration::from_secs(15)) {
        let z_cap = read_captured(&mut z_sub_reader);
        for g in [&mut p_guard, &mut z_sub_child, &mut r1_guard] {
            let _ = g.child_mut().kill();
            let _ = g.child_mut().wait();
        }
        panic!(
            "mesh publisher P never learned the on-group subscriber's interest within \
             15s — R1's S2 mesh-advertisement of the group sub did not reach P\n--- P \
             stderr ---\n{c}\n--- z_sub ---\n{z_cap}"
        );
    }

    // ── Assertion: the pico z_sub RECEIVES P's off-group Put via R1's group egress. ──
    let received = wait_for_substring(&mut z_sub_reader, PAYLOAD, Duration::from_secs(20));
    let z_cap = read_captured(&mut z_sub_reader);
    for g in [&mut p_guard, &mut z_sub_child, &mut r1_guard] {
        let _ = g.child_mut().kill();
        let _ = g.child_mut().wait();
    }
    if let Err(c) = received {
        panic!(
            "the on-group pico z_sub never received the off-group mesh publisher's Put \
             (payload {PAYLOAD:?}) within 20s — reachability (a) NOT proven\n--- z_sub \
             stdout+stderr ---\n{c}"
        );
    }
    assert!(
        z_cap.contains(">> [Subscriber] Received"),
        "z_sub logged the payload but not its Received banner — unexpected output shape\n{z_cap}"
    );
}
