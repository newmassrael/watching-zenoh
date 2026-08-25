// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 router-multicast-faces — CROSS-IMPL validation of the wz router-hat's
//! multicast INGRESS plane against a real zenoh-pico multicast publisher (I2, the
//! cross-impl proof of the ingress slice I1).
//!
//! The REVERSE direction of `wz_router_hat_multicast_pico_interop.rs` (S4, the
//! egress proof: wz publisher -> wz router -> pico z_sub). Here a FOREIGN
//! zenoh-pico `z_pub -m peer` publishes a Put over the UDP multicast group; the wz
//! `--router-hat` (built `--features router-multicast-faces`) RECEIVES it on its
//! ingress group face (`spawn_router_mcast_ingress`, the deferred `mcast_faces`
//! plane slice I1) and routes it, over TCP, to a wz UNICAST subscriber client.
//!
//! Topology (three separate processes; the wz subscriber is a UNICAST client that
//! never joins the multicast group):
//!
//!   pico `z_pub -m peer`  --UDP mcast 224.0.0.225:7452-->  wz `--router-hat`  --TCP-->  wz `--connect --key`
//!
//! The wz subscriber dials the router over TCP as a `WhatAmI::Client` and declares
//! a subscription; pico is a UDP multicast peer that never connects to the router's
//! TCP port. So the ONLY path from pico to the wz subscriber is: the router admits
//! pico's JOIN on its ingress group face, decodes pico's Push, and delivers it via
//! `route_mcast_ingress` (Client-tier local delivery) down the TCP face to the wz
//! subscriber. The wz subscriber is NOT on the multicast group, so a SUBSCRIBER
//! FIRED witness there proves specifically the router's ingress->delivery path, not
//! a co-located/loopback shortcut (there is none across two impls in three
//! processes).
//!
//! ## What this proves — and what it does NOT (honest scope)
//!
//! - PROVES: the wz router's multicast INGRESS (it JOINs the group, admits a
//!   foreign zenoh-pico peer from its JOIN beacon, and decodes its framed Push) is
//!   routed to a wz unicast subscriber — the router-multicast-faces atom's first
//!   cross-impl ingress proof.
//! - LITERAL-ONLY (matches I1): pico's `z_pub` over multicast sends LITERAL pushes
//!   (id==0). pico builds with `Z_FEATURE_MULTICAST_DECLARATIONS=0` (its CMake
//!   default; `_z_keyexpr_declare_prefix` skips the keyexpr declaration on a
//!   multicast transport, so `_z_declared_keyexpr_alias_to_wire` emits the literal
//!   suffix), so the router's literal-only ingress resolves it against an empty
//!   table without a per-peer alias plane. An aliased multicast publisher would
//!   need the deferred I3 per-peer `mcast_faces` alias tracking.
//! - Does NOT prove: the per-peer `mcast_faces` plane / mcast-peer declarations /
//!   aliased-ingress resolution (I3); mesh-federation of mcast ingress (I1 delivers
//!   to LOCAL subscribers only — mesh federation is I3); the egress plane (that is
//!   S4).
//!
//! ## No-flaky discipline
//!
//! The router JOINs the group + binds TCP FIRST; the wz subscriber then connects
//! and declares, and the publisher is spawned only after the ROUTER logs it learned
//! the client sub (`router-hat: learned a client sub`, a router-confirmed barrier —
//! the wz subscriber's DeclareSubscriber is provably installed in the router's
//! client_subs before pico publishes). pico `z_pub -n 30` then publishes once a
//! second for 30 s: the router beacons its own JOIN and admits pico's JOIN within a
//! beacon interval, and each subsequent pico Put re-delivers, so no single
//! JOIN-admission window is raced ([[feedback-no-flaky-ever]]). NOTE: the router's
//! `route_mcast_ingress` does not increment the "forwarded mesh data" counter (an
//! I2-noted witness gap), so this test gates on the wz subscriber's end-to-end
//! SUBSCRIBER FIRED, not a router-side transit log.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent (a routeless container drops the IGMP
//! join), so this is opt-in like the sibling multicast interop lanes (Layer M,
//! `WZ_RUN_LAYER_M=1` / `--layer M`), never a required gate. pico's multicast peer
//! needs an explicit `#iface=<dev>`; the test discovers the default-route interface
//! at runtime, which is the interface the router's group join selects, so both meet
//! on the same link. z_pub's stdout is line-buffered via `stdbuf -oL`.
//!
//! Requires: wz-ap-demo built with `--features router-multicast-faces` (the ingress
//! join is `#[cfg]`'d on it, `runner.rs`) AND the zenoh-pico CLI (`z_pub`). run-ci's
//! Layer M builds the demo with the feature and SKIPs if the pico CLI is absent.
//! The fn name carries BOTH `wz_router` and `multicast` so the default Layer E
//! sweep's `--skip` excludes it from the required arbitrary-feature run.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    default_route_iface, graceful_terminate, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wait_for_tcp_accept, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

// The demo's default data-plane router multicast group + port, HARDCODED in
// run_router_hat under `#[cfg(feature="router-multicast-faces")]` (both the egress
// and the ingress join). The pico locator must match it exactly.
const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
const PORT: u16 = 7452;
// Distinctive key: pico z_pub publishes this LITERAL keyexpr; the wz subscriber
// subscribes to it exactly (the router delivers on keyexpr intersection). No other
// publisher uses it, so a SUBSCRIBER FIRED on this key pins pico's Put.
const KEY: &str = "demo/mcast/ingress";
// Distinctive value (pico z_pub wraps it as `[%4d] <value>`); surfaced in the pico
// z_pub args + the diagnostic dump (the wz subscriber logs payload_len, not the
// payload, so the delivery pin is the keyexpr).
const VALUE: &str = "WZ-MCAST-INGRESS-INTEROP-I2";

/// pico `z_pub -m peer` (LITERAL) -> wz `--router-hat` ingress -> a wz unicast
/// subscriber: the wz router receives a foreign multicast peer's Put on its ingress
/// group face and routes it to a wz client subscriber — the router-multicast-faces
/// atom's first cross-impl (foreign-publisher) ingress proof.
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
fn wz_router_hat_multicast_ingress_from_pico_zpub() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");

    // ── wz router-hat: joins the multicast group (ingress) + binds a TCP port ──
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut r_guard, mut r_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--router-hat", "127.0.0.1:0"],
        "router-hat: listening on 127.0.0.1:",
        "router-hat",
        router_stderr,
    );

    // Gate 1 (build-feature-present): the router logs this only when built
    // `--features router-multicast-faces`, so a stale wrong-feature binary fails
    // fast here instead of a silent timeout. It witnesses feature-presence + the
    // ingress task spawning, NOT a successful IGMP join (the bind runs inside the
    // spawned task) — the true end-to-end join proof is the SUBSCRIBER FIRED below.
    let ingress_marker = format!("multicast ingress group {GROUP}:{PORT} joined");
    if let Err(captured) =
        wait_for_substring(&mut r_reader, &ingress_marker, Duration::from_secs(3))
    {
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat never logged the multicast ingress join witness \
             ({ingress_marker:?}) within 3s — the demo was likely built WITHOUT \
             `--features router-multicast-faces`, so the ingress group is never \
             joined\n--- router-hat stderr ---\n{captured}"
        );
    }

    // Gate 2 (accept-loop warm): the wz subscriber is the first TCP client, so gate
    // its dial on a successful TCP connect (the "listening on" log fires before the
    // accept task starts).
    if !wait_for_tcp_accept(port, Duration::from_secs(5)) {
        let r_captured = read_captured(&mut r_reader);
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat accept loop never accepted a TCP connect on 127.0.0.1:{port} \
             within 5s\n--- router-hat stderr ---\n{r_captured}"
        );
    }

    // ── wz unicast subscriber: a WhatAmI::Client of the router, subscribed to KEY.
    //    It is NOT on the multicast group — its only source is the router's ingress
    //    delivery over TCP. ──
    let sub_stderr = tempfile::tempfile().expect("tempfile for wz subscriber stderr");
    let sub_writer = sub_stderr
        .try_clone()
        .expect("dup wz subscriber stderr handle");
    let mut sub_reader = sub_stderr;
    let mut sub_child = ChildGuard::wrap(
        "wz-ap-demo (--connect wz-router --key --reconnect)".to_string(),
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            // `--key` is the R121 ROUTED client subscriber (declares
            // Declare(DeclSubscriber) so the router routes matching Pushes back +
            // logs "SUBSCRIBER FIRED" on receipt). NOT `--subscribe`, which is
            // parsed only inside the `--peer` block (peer-mesh mode) and would be
            // silently ignored by a `--connect` client.
            .arg("--key")
            .arg(KEY)
            // Long-lived: keep the subscriber session alive to RECEIVE routed
            // samples. --reconnect requires --connect (present); the node stays a
            // WhatAmI::Client, so it lands in the router's client_subs.
            .arg("--reconnect")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(sub_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect wz-router --subscribe"),
    );

    // BARRIER (not a race): wait until the ROUTER logs it installed the wz client's
    // DeclareSubscriber before spawning the publisher, so pico's Put cannot outrun
    // declare-propagation (the same router-confirmed barrier S4 / the query tests
    // use).
    wait_for_substring(
        &mut r_reader,
        "router-hat: learned a client sub",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let sub_captured = read_captured(&mut sub_reader);
        let _ = sub_child.child_mut().kill();
        let _ = sub_child.child_mut().wait();
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat never logged it learned the wz client subscription within \
             10s — the wz DeclareSubscriber did not reach the router's \
             client_subs\n--- router-hat stderr ---\n{c}\n--- wz subscriber stderr \
             ---\n{sub_captured}"
        )
    });

    // ── pico z_pub (multicast peer + publisher): publishes a LITERAL Put on KEY
    //    over the group, once a second for 30 s (spans several JOIN intervals so a
    //    missed first beacon never fails the gate). `stdbuf -oL -eL` line-buffers. ──
    let z_pub_capture = tempfile::tempfile().expect("tempfile for z_pub capture");
    let z_pub_out = z_pub_capture.try_clone().expect("dup z_pub stdout handle");
    let z_pub_err = z_pub_capture.try_clone().expect("dup z_pub stderr handle");
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

    // Success gate: the wz subscriber logs SUBSCRIBER FIRED — pico's multicast Put,
    // received on the router's ingress group face and routed over TCP to the wz
    // client subscriber. pico publishes ~1/s, so the common case is a few seconds
    // once its JOIN is admitted; the 25 s budget is generous margin.
    let received = wait_for_substring(&mut sub_reader, "SUBSCRIBER FIRED", Duration::from_secs(25));

    // Teardown: kill the publisher + subscriber directly; graceful_terminate the
    // router so it flushes latched witnesses.
    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();
    let _ = sub_child.child_mut().kill();
    let _ = sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let z_pub_captured = read_captured(&mut z_pub_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- pico z_pub stdout ---\n{z_pub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "the wz subscriber never logged 'SUBSCRIBER FIRED' within 25s — pico's \
             multicast Put did not route through the router-hat's ingress group face \
             to the wz unicast subscriber\n--- wz subscriber stderr ---\n{c}\n--- \
             router-hat stderr ---\n{r_captured}\n--- pico z_pub stdout ---\n{z_pub_captured}"
        )
    });

    // Same-line pin (strictly stronger than separate whole-buffer checks — the
    // keyexpr alone also appears in the subscriber's own DECLARE log): assert the
    // FULL SUBSCRIBER-FIRED line, binding the delivery witness + filter + delivered
    // keyexpr + kind to ONE sample. The wz subscriber is not on the multicast group,
    // so the only way this line exists is the router's ingress -> client-tier
    // delivery of pico's LITERAL mcast Push. The unique KEY rules out a stale
    // artifact. (payload_len tail omitted — pico's `[%4d] <value>` idx varies.)
    assert!(
        received_text.contains(&format!(
            "SUBSCRIBER FIRED filter='{KEY}' keyexpr='{KEY}' kind=Put"
        )),
        "the wz subscriber did not FIRE on pico's routed Put for '{KEY}' (kind=Put) — \
         the ingress delivery keyexpr/kind did not match\n--- wz subscriber stderr \
         ---\n{received_text}"
    );
}
