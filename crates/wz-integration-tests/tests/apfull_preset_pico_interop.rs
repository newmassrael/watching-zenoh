// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y480 — the `preset-ap-full` COMPOSITION, driven against real zenoh-pico.
//!
//! ## The gap this closes
//!
//! Before this round `preset-ap-full` had no executable at all. Layer C4 ran
//! `cargo build -p wz --no-default-features --features preset-ap-full` — a
//! LIBRARY typecheck — and two separate comments in `run-ci.sh` say so in as many
//! words ("C4 builds preset-ap-full (which carries both) but is build-only and
//! clippy-free"; "preset-ap-full carries the features but is build-only").
//! `wz-ap-demo` had no `preset-ap-full` key, so `cargo build -p wz-ap-demo
//! --features preset-ap-full` answered
//!
//!     error: the package 'wz-ap-demo' does not contain this feature: preset-ap-full
//!
//! The kitchen-sink preset had therefore never been RUN, and no foreign peer had
//! ever spoken to it. Every pico proof in this crate drives a NARROW binary
//! instead — `--features routing-peer` (E6), `--features router-hat-router,time-hlc`
//! (E8t), `--features storage-backend` (E6e), and so on — so composition is the
//! one axis none of them can reach.
//!
//! ## Why composition is its own risk, not a formality
//!
//! `preset-ap-full` pulls 136 atoms into ONE binary, and among them are three the
//! inventory marks as NOT pico-faithful: `session-extqos` (reserved),
//! `session-extshm` (recorded WIRE-INCOMPATIBLE) and `transport-shm` (reserved).
//! A reserved atom is a declared cargo key with no cfg site, so the expectation is
//! that compiling it changes no wire byte — but that expectation had never been
//! tested against a real pico, because no build had ever composed them alongside
//! the live handshake. If any of the three had grown a cfg site that offered an
//! extension on InitSyn, a pico peer would refuse the session and every narrow
//! lane in this crate would still be green. Leg 1 is what makes that observable.
//!
//! ## The two legs, and which one pins the build
//!
//! * LEG 1 (`--listen` acceptor + real `z_put`) is the WIRE-INERTNESS witness: it
//!   proves the 136-feature composition still completes a zenoh-pico handshake and
//!   delivers a sample. It does NOT pin the build — the same assertion passes on
//!   the default `preset-ap-client` binary, which is exactly what
//!   `ap_demo_round_trip.rs` already runs. Stated plainly because a lane that
//!   silently built the wrong binary would pass this leg.
//!
//! * LEG 2 (`--peer` node between TWO real pico clients) is the BUILD
//!   DISCRIMINATOR. `--peer` is `cfg(feature = "routing-peer")`; a binary without
//!   it rejects the flag and exits 2 — the property
//!   `wz_peer_reject_without_feature.rs` asserts from the other side. So leg 2
//!   fails loudly against a `preset-ap-client` binary rather than passing
//!   vacuously, and it is the leg that certifies the lane built what it claims.
//!   Its delivery path is the CO-ATTACHED CLIENT egress, established by damage
//!   rather than by reading — see the fn-level comment.
//!
//! Together they are the composition proof: ONE process, two planes, three
//! foreign zenoh-pico processes, on the preset that until now only typechecked.
//!
//! ## Honest scope
//!
//! This does NOT prove the 136 atoms individually — most have no CLI surface on
//! the demo binary, and inventing one per atom would be a different (much larger)
//! round. What it proves is that composing them produces a binary that still
//! interoperates with a real foreign implementation on the planes the demo does
//! expose. The per-atom proofs remain where they already live, on their narrow
//! lanes.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

/// How long the foreign exchange gets. Generous because the lane runs under
/// full-run-ci process pressure, and `wait_for_substring` returns the instant the
/// marker appears — a wide ceiling costs a green run nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Leg 1 — the composed AP-full binary still speaks zenoh-pico's client wire.
///
/// A real `z_put` opens a session against the kitchen-sink acceptor and its
/// sample reaches the registered subscriber. The load-bearing part is not the
/// round trip itself (that is `ap_demo_round_trip.rs`'s job on the ap-client
/// binary) but that it still happens with `session-extqos` / `session-extshm` /
/// `transport-shm` compiled in — the reserved, explicitly non-pico-faithful atoms
/// the kitchen sink drags along. If one of them ever offers an ext on InitSyn,
/// pico refuses the session and this leg reds.
// wz-proves: session-unicast-accept pico->wz
// wz-proves: pubsub-put pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_preset_acceptor_round_trips_with_a_real_pico_z_put() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");
    let key = "demo/apfull";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full demo stderr");
    let (mut demo_guard, mut demo_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "127.0.0.1:0", "--key", "demo/**"],
        "listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --listen)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let put = Command::new(&z_put)
        .args([
            "-k",
            key,
            "-v",
            "hello-from-pico-to-apfull",
            "-e",
            &endpoint,
            "-m",
            "client",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn zenoh-pico z_put");
    assert!(
        put.success(),
        "the real zenoh-pico z_put exited {put:?} against the AP-full acceptor — \
         it could not complete the session handshake, which is the composition \
         failure this leg exists to catch"
    );

    let fired = wait_for_substring(&mut demo_reader, "SUBSCRIBER FIRED", EXCHANGE_TIMEOUT);
    let outcome = fired.map(|c| c.to_string());
    graceful_terminate(demo_guard.child_mut(), Duration::from_secs(5));

    let captured = match outcome {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full acceptor never logged 'SUBSCRIBER FIRED' for a real pico \
             z_put. The 136-feature composition broke a wire that every narrow \
             single-feature lane still reports green.\n--- wz-ap-demo stderr ---\n{c}"
        ),
    };
    assert!(
        captured.contains(key),
        "'SUBSCRIBER FIRED' appeared but not for {key} — the delivered sample was \
         not the one pico put\n--- wz-ap-demo stderr ---\n{captured}"
    );
}

/// Leg 2 — TWO real zenoh-pico clients interoperate THROUGH the composed AP-full
/// binary, and the leg doubles as the build discriminator.
///
/// `--peer` only exists under `cfg(feature = "routing-peer")`; a binary built
/// without it rejects the flag and exits 2 (the twin assertion in
/// `wz_peer_reject_without_feature.rs`). `spawn_on_ephemeral_port` is
/// liveness-aware, so that build fails here in ~0.1s with the child's exit status
/// named, rather than being mistaken for a slow bind. That is what stops this file
/// from certifying a lane that built the wrong binary.
///
/// The foreign edge is BOTH ends: neither publisher nor subscriber is a wz
/// process, so nothing in the exchange is wz agreeing with its own twin.
///
/// ## WHICH code this actually binds to — established by damage, not by reading
///
/// Both picos attach as CLIENTS of the one peer, so the delivery path is
/// `LinkstateForwarder::deliver_to_client_subscribers` (co-attached client
/// egress), NOT the mesh spanning-tree `forward_push`. That was MEASURED:
/// inverting the tree-forward target predicate in `forward_push` left this leg
/// GREEN, while inverting the `id == inbound` self-exclusion in
/// `deliver_to_client_subscribers` reds it. Recorded because the first wording of
/// this comment said "mesh data plane", which the damage refuted — a two-hop
/// mesh transit to a pico client is `wz_peer_transit_push_pico_interop.rs`'s
/// property, not this one's, and claiming it here would bind the claim to code
/// the leg never executes.
// wz-proves: routing-peer pico->wz partial
// wz-proves: declare-subscriber pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico CLI); Layer E9 runs via --ignored"]
fn apfull_preset_peer_forwards_between_two_real_pico_clients() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let sub_key = "demo/**";
    let pub_key = "demo/apfull/mesh";
    let payload = "APFULL-MESH-BETWEEN-TWO-PICOS";

    let stderr = tempfile::tempfile().expect("tempfile for AP-full peer stderr");
    let (mut peer_guard, mut peer_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --peer)",
        stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // Subscriber FIRST: the helper returns only once pico has opened the session
    // AND declared, so the peer has the interest before any sample is emitted.
    let (mut sub_child, mut sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint, "the AP-full peer", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // `z_pub -n 30` bursts over ~30s, so a subscription that is declared but not
    // yet installed on the peer's face costs a dropped sample, not a failed test.
    // A one-shot `z_put` here would race the interest propagation.
    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        pub_key,
        payload,
        &endpoint,
        "the AP-full peer",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    let received = wait_for_substring(&mut sub_reader, payload, EXCHANGE_TIMEOUT);
    let outcome = received.map(|c| c.to_string());

    // The peer must have ACTUALLY routed it. Without this, a direct pico<->pico
    // path (were one ever possible) would satisfy the foreign assertion above and
    // the leg would prove nothing about wz.
    //
    // POLLED, not read once. The forwarder counts the push on its own app tick, so
    // the marker trails the subscriber's delivery — a single `read_captured` here
    // raced that write and read a log that stopped at `face 1 UP`, which is how
    // this assertion first failed against a run whose foreign witness had already
    // succeeded. Polled BEFORE the children are reaped so the peer is still alive
    // to write it.
    let routed = wait_for_substring(&mut peer_reader, "received mesh data", EXCHANGE_TIMEOUT)
        .map(|c| c.to_string());

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = sub_child.child_mut().kill();
    let _ = sub_child.child_mut().wait();
    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let peer_log = read_captured(&mut peer_reader);

    let sub_out = match outcome {
        Ok(c) => c,
        Err(c) => panic!(
            "the real zenoh-pico z_sub never received '{payload}' through the \
             AP-full peer. Both endpoints are foreign, so the mesh data plane of \
             the composed preset did not forward.\n--- pico z_sub stdout ---\n{c}\
             \n--- AP-full peer stderr ---\n{peer_log}"
        ),
    };
    assert!(
        sub_out.contains(pub_key),
        "the payload arrived but not on {pub_key} — the forwarded sample carried \
         the wrong keyexpr\n--- pico z_sub stdout ---\n{sub_out}"
    );
    if let Err(c) = routed {
        panic!(
            "the pico subscriber got the sample but the AP-full peer never logged \
             'received mesh data' — the exchange did not go through wz's \
             forwarder\n--- AP-full peer stderr ---\n{c}"
        );
    }
}
