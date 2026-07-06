// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 router-multicast-faces — CROSS-IMPL validation of the wz router-hat's
//! multicast EGRESS plane against a real zenoh-pico multicast subscriber (S4, the
//! LAST slice of the router-multicast-faces track).
//!
//! A wz `--router-hat` built with `--features router-multicast-faces` attaches a
//! data-plane multicast group as a TX egress face (the wz analog of zenoh
//! `Router::new_transport_multicast` -> `McastMux` -> `mcast_groups`,
//! `router.rs:181`) and broadcasts EVERY routed `Push` to it, UNCONDITIONALLY —
//! outside the sub-gated fan-out (`RouterForwarder::route_push` tail,
//! `router_forward.rs:2316`, the wz analog of zenoh's flat append
//! `hat/router/pubsub.rs:1334`). This test proves that egress reaches a FOREIGN
//! zenoh-pico `z_sub -m peer` joined to the same UDP group.
//!
//! Topology (three separate processes; the ONLY shared medium between the router
//! and pico is the UDP group):
//!
//!   wz publisher  --TCP `--connect`-->  wz `--router-hat`  --UDP mcast 224.0.0.225:7452-->  pico `z_sub -m peer`
//!
//! The wz publisher dials the router over TCP as a `WhatAmI::Client`; pico is a
//! UDP multicast peer that NEVER connects to the router's TCP port and NEVER
//! declares a subscription the router can see. So the router holds ZERO matched
//! subs for the keyexpr — `deliver_to_client_subscribers` / `forward_push_tier`
//! find nothing, and the SOLE path to pico is the unconditional `mcast_groups`
//! broadcast. A z_sub witness therefore proves specifically the "egress even with
//! zero matched subs" semantics, not a co-located/loopback shortcut (there is
//! none across two impls in three processes).
//!
//! ## What this proves — and what it does NOT (honest scope)
//!
//! - PROVES: the wz router's multicast egress (a `WhatAmI::Router` JOIN beacon +
//!   framed Push, `spawn_router_mcast_egress`, `multicast_glue.rs:473`) is
//!   wire-admitted and byte-decoded by a foreign zenoh-pico multicast peer,
//!   driven by the router's `route_push` composition (not a bare
//!   `MulticastTxItem::Push` — that half is the wz<->wz loopback e2e
//!   `router_egress_helper_reaches_group_subscriber`).
//! - PROVES the y189 reliteralization (`broadcast_to_mcast_groups` re-literalizes
//!   the routed push against the resolved keyexpr, `router_forward.rs:2361-2368`):
//!   the wz publisher runs with `--declare-id`, so it DECLARES `id->keyexpr` once
//!   to the router over TCP and then emits ALIASED (id-only) pushes. pico is on a
//!   transport that never saw that `DeclKexpr`, so it holds NO alias table — the
//!   only way pico can surface the literal keyexpr `demo/router/mcast` is if the
//!   router re-literalized the push before the group broadcast. pico Receiving the
//!   literal key is the cross-impl reliteralize proof (pre-y189 it would egress an
//!   unresolvable id-only wireexpr = a group blackhole).
//! - whatami=Router is ADVERTISED but pico treats the sender GENERICALLY: pico's
//!   multicast JOIN admission (`vendor/zenoh-pico/src/transport/multicast/rx.c:371-459`)
//!   filters ONLY version / seq_num_res / req_id_res / batch_size (`rx.c:374,380-381`)
//!   and STORES `_remote_whatami` without acting on it for delivery (`rx.c:395`); a
//!   Peer-whatami egress delivers identically (proven by the sibling
//!   `wz_publisher_to_pico_multicast_zsub.rs`). So this proves the wz SIDE runs a
//!   router forward — NOT that pico distinguishes a router (the route is NOT
//!   router-DISTINCTIVE on the receiving side, mirroring the honesty note in
//!   `wz_router_hat_pico_interop.rs`).
//! - Does NOT prove: the INGRESS `mcast_faces` plane (a router consuming group
//!   ingress — the deferred milestone); router-tier linkstate federation over
//!   multicast (pico is a leaf subscriber, not a peer router joining the mesh);
//!   bidirectional (pico -> wz over the group); reverse data / query-reply /
//!   liveliness over the group.
//!
//! ## No-flaky discipline: `--reconnect`, not a barrier
//!
//! Unlike `wz_router_hat_pico_interop.rs` (which barriers on "learned a client
//! sub" before publishing), S4 has NO such barrier: pico is a multicast
//! subscriber the router NEVER learns about, and the egress drive loop is TX-only
//! with a no-op `on_event` (`multicast_glue.rs:530`), so pico's JOIN admission is
//! asynchronous and unobservable to wz. A finite publisher burst (the default
//! 5 Puts / ~800 ms, `tasks.rs:73-74`) with no retransmit would race the
//! ~100 ms-cadence JOIN-admission window and flake ([[feedback-no-flaky-ever]]).
//! The defense mirrors the sibling `wz_publisher_to_pico_multicast_zsub.rs`
//! republish-until-witness pattern at the PROCESS level: the wz publisher runs
//! long-lived with `--reconnect` (a steady ~5 Puts/sec periodic stream through
//! the router, `tasks.rs:278-305`), so once pico admits the router's JOIN the
//! NEXT Put (<=200 ms later) delivers. The test polls z_sub for the payload with
//! a generous budget and kills the processes on the witness. Do NOT "fix" a drop
//! by bumping timeouts — switch strategies at the root.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent (a container without a multicast
//! route drops the IGMP join), and the ephemeral `(UNSPECIFIED,0)` egress bind
//! succeeds regardless of routing — so a routeless env surfaces only as pico
//! never receiving, never as a bind error. Thus this is opt-in like the sibling
//! multicast interop lanes (Layer M, `WZ_RUN_LAYER_M=1` / `--layer M`), never a
//! required gate. pico's multicast peer needs an explicit `#iface=<dev>`; the
//! test discovers the default-route interface at runtime, which is the interface
//! wz's `INADDR_ANY` multicast egress selects, so both peers meet on the same
//! link. z_sub's stdout is line-buffered via `stdbuf -oL` (glibc block-buffers a
//! piped fd, hiding the Received line until exit otherwise).
//!
//! Requires: wz-ap-demo built with `--features router-multicast-faces` (the
//! mcast-attach block is `#[cfg]`'d on THAT feature, `runner.rs:2100` — a
//! `router-hat-router`-only build compiles `run_router_hat` but elides the egress
//! attach) AND the zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh`). run-ci's
//! Layer M builds the demo with the feature and SKIPs if the pico CLI is absent.
//! The fn name carries BOTH `wz_router` and `multicast` so the default Layer E
//! sweep's `--skip wz_router` / `--skip multicast` exclude it from the required
//! arbitrary-feature run (which builds a demo WITHOUT router-multicast-faces).

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    default_route_iface, graceful_terminate, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wait_for_tcp_accept, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    Z_SUB_INIT_TIMEOUT,
};

// The demo's default data-plane router multicast group + port, HARDCODED in
// `run_router_hat` under `#[cfg(feature="router-multicast-faces")]`
// (`runner.rs:2105-2106`). Distinct from the 224.0.0.224 group every other
// multicast interop test uses (scouting / pubsub-loopback / publisher-interop),
// so this lane never contends on the group+port. The port is NOT CLI-configurable
// — the pico locator must match the demo hardcode exactly.
const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
const PORT: u16 = 7452;
// Publisher keyexpr (literal); the router re-literalizes the aliased push to this
// before the group broadcast. z_sub subscribes to the wildcard so pico's local
// matcher accepts the literal keyexpr the reliteralized Push carries.
const PUBLISH_KEY: &str = "demo/router/mcast";
const SUB_KEY: &str = "demo/**";
// Non-zero expr-id: makes the wz publisher DECLARE id->keyexpr then emit ALIASED
// (id-only) pushes, so the router's reliteralize path is EXERCISED, not a no-op
// (`--declare-id 0` is the literal-keyexpr sentinel, `main.rs:507`).
const DECLARE_ID: &str = "7";
// Distinctive shell-safe payload: appears in z_sub's `Received (... : '...')`
// line only if the router's reliteralized, group-broadcast Push delivered
// byte-exact through the foreign pico multicast transport.
const PAYLOAD: &str = "WZ-ROUTER-MCAST-EGRESS-INTEROP-S4";

/// wz `--router-hat` (`--features router-multicast-faces`) routes a wz client's
/// ALIASED `Put` and broadcasts it, re-literalized, over its multicast EGRESS
/// group to a foreign zenoh-pico `z_sub -m peer` — the router-multicast-faces
/// atom's first cross-impl (foreign-subscriber) egress proof.
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces + zenoh-pico z_sub); Layer M runs via --ignored"]
fn wz_router_hat_multicast_egress_reaches_pico_zsub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");

    // ── wz router-hat: binds a TCP port + attaches the multicast egress group ──
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut r_guard, mut r_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--router-hat", "127.0.0.1:0"],
        "router-hat: listening on 127.0.0.1:",
        "router-hat",
        router_stderr,
    );

    // Gate 1 (build-feature-present + attach readiness): the router logs the
    // mcast-attach witness only when built `--features router-multicast-faces`
    // (the attach block at `runner.rs:2113` is cfg'd out otherwise). A stale
    // wrong-feature binary fails fast here with a clear message instead of a
    // silent delivery timeout. NOTE: the log fires synchronously BEFORE the async
    // egress socket bind, so it proves the feature is compiled in, not a working
    // socket — the pico Received witness below proves the working egress.
    let attach_marker = format!("multicast egress group {GROUP}:{PORT} attached");
    if let Err(captured) = wait_for_substring(&mut r_reader, &attach_marker, Duration::from_secs(3))
    {
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat never logged the multicast egress attach witness \
             ({attach_marker:?}) within 3s — the demo was likely built WITHOUT \
             `--features router-multicast-faces`, so the egress group is never \
             attached\n--- router-hat stderr ---\n{captured}"
        );
    }

    // Gate 2 (accept-loop warm): pico is a multicast peer that never dials the
    // router's TCP port, so nothing warms the accept path before the publisher —
    // the wz publisher is the FIRST TCP client and could race the accept loop
    // (the "listening on" log fires before `peer_loop` starts the accept task,
    // `runner.rs:2065` vs `:2119`). A successful TCP connect proves the accept
    // loop is live before the publisher dials.
    if !wait_for_tcp_accept(port, Duration::from_secs(5)) {
        let r_captured = read_captured(&mut r_reader);
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat accept loop never accepted a TCP connect on 127.0.0.1:{port} \
             within 5s\n--- router-hat stderr ---\n{r_captured}"
        );
    }

    // ── pico z_sub (multicast peer + subscriber) ──────────────────────────────
    // Spawned INLINE (not `spawn_subscribed_zsub`, which is `-m client -e`): a
    // multicast peer joins the group via `-m peer -l <locator>`. `stdbuf -oL -eL`
    // line-buffers so the Received witness surfaces live.
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

    // Gate 3: z_sub joined the group and declared its subscriber. Until this
    // prints, the router's egress has nothing to reach.
    if let Err(captured) = wait_for_substring(
        &mut z_sub_reader,
        "Declaring Subscriber",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "z_sub did not log 'Declaring Subscriber' within {Z_SUB_INIT_TIMEOUT:?} on \
             {locator} — multicast bind/join failed?\n--- captured z_sub ---\n{captured}"
        );
    }

    // ── wz publisher: a long-lived (`--reconnect`) ALIASED (`--declare-id`)
    //    client of the wz router that emits a steady periodic Put stream. The
    //    router routes each Put (`route_push`), re-literalizes it, and broadcasts
    //    it to the mcast group; the persistent stream self-heals past pico's
    //    JOIN-admission window (no barrier is possible — see the module doc). ──
    let mut pub_child = ChildGuard::wrap(
        "wz-ap-demo (--connect wz-router --publish --declare-id --reconnect)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(PUBLISH_KEY)
            .arg("--value")
            .arg(PAYLOAD)
            .arg("--declare-id")
            .arg(DECLARE_ID)
            .arg("--reconnect")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn wz-ap-demo --connect wz-router --publish --declare-id --reconnect"),
    );

    // Success gate: the pico subscriber RECEIVES a routed Put, egressed over the
    // multicast group by the wz router-hat. The router streams ~5 Puts/sec, so
    // the common case is sub-second once pico admits the JOIN; the 25 s budget is
    // ~125 Puts of margin against admission jitter.
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(&mut z_sub_reader, received_substr, Duration::from_secs(25));

    // Teardown: kill the publisher + z_sub directly; graceful_terminate the router
    // (SIGTERM) so it flushes its latched shutdown witnesses. With the long-lived
    // publisher the "forwarded mesh data" witness also fires in-run on the router's
    // ~250 ms app tick, but the graceful path keeps the flush deterministic.
    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{received_substr}' within 25s — wz's routed Put \
             did not egress through the router-hat's multicast group to the foreign \
             pico subscriber\n--- pico z_sub stdout ---\n{c}\n--- router-hat stderr \
             ---\n{r_captured}"
        )
    });

    // Same-line pin: pico prints the received sample as
    // `Received ('<key>': '<value>')`, so asserting the key+payload PAIR on one
    // line is strictly stronger than three whole-buffer substring checks (a green
    // "Received" banner alone cannot satisfy it, and the wildcard SUB_KEY means the
    // literal key never appears in pico's own banner). The LITERAL key here is the
    // y189 reliteralize proof: pico holds no alias table, so the only way the
    // literal `demo/router/mcast` surfaces is the router re-literalizing the
    // aliased (id-only) push before the group broadcast — a pre-y189 blackhole
    // would print no such line.
    assert!(
        received_text.contains(&format!("'{PUBLISH_KEY}': '{PAYLOAD}'")),
        "pico z_sub did not Receive the router's reliteralized Put as \
         '{PUBLISH_KEY}': '{PAYLOAD}' — either the aliased (id-only) push blackholed \
         at the group leaf (a reliteralize regression) or the routed key/payload \
         mismatched\n--- captured ---\n{received_text}"
    );

    // Transit pin: the router's OWN data counter rose (it counts every inbound
    // Push before routing, `router_forward.rs:4832`), so the Put transited THROUGH
    // `route_push` — where `broadcast_to_mcast_groups` fires unconditionally
    // (`:2317`) — not around it. The wz publisher and pico never knew each other's
    // address, so this pins the delivery to the router's egress route.
    assert!(
        r_captured.contains("router-hat: forwarded mesh data"),
        "the wz router-hat never forwarded a Push — the wz Put did not transit \
         `route_push`, so the multicast egress delivery did not exercise the router's \
         data route\n--- router-hat stderr ---\n{r_captured}"
    );
}
