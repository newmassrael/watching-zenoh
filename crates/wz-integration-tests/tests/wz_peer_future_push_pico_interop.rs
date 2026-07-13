// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 peer — the STRONG peer-mode future-push CROSS-IMPL e2e (R311y165): the
//! peer-tier analog of router-hat leg 5
//! (`wz_router_hat_zenohd_interop.rs::wz_router_hat_pushes_a_future_subscriber_to_a_pico_publisher`),
//! now that D4 (R311y163 + R311y164) gave the wz peer a full co-attached CLIENT data
//! plane. A pico `z_pub` CLIENT of peer-A publishes BEFORE any subscriber exists; a
//! pico `z_sub` CLIENT of peer-B subscribes LATER. wz-peer-A proactively pushes the
//! future `DeclareSubscriber` (learned across the wz peer mesh from B) to z_pub,
//! DEACTIVATING its write-filter; z_pub's `Put` is then re-injected by A into the mesh
//! (D4b / C3b), transits to B, and B delivers it to the pico z_sub (D4a / C3a).
//!
//! HONESTY — the mesh (A <-> B) is wz-NATIVE `linkstatepeers_net`, already proven by
//! `wz_peer_data_forward`; this is NOT a wz-peer <-> foreign-peer linkstate federation.
//! The FOREIGN elements are the two pico CLIENT leaves: the `z_pub` whose real C11
//! write-filter deactivates on wz's pushed declare, and the `z_sub` that receives the
//! re-injected sample. So the cross-impl surface is exactly the two pico client edges;
//! the discriminator that proves the FUTURE-push path fired (not a lucky current-dump)
//! is the peer's latched `pushed a future subscriber` witness, asserted as PRIMARY. The
//! genuinely peer-cross-impl proof — wz `--peer` federating linkstate with a foreign
//! `zenohd` peer — remains a separate, un-attempted follow-up.
//!
//! Topology + ORDERING (the pub-before-sub discriminator, mirroring leg 5's spawn
//! order, no sleeps): peer-A binds; the pico z_pub dials A `-m client` and declares its
//! publisher FIRST, so its FUTURE subscriber-interest is stored on A before any sub
//! exists (its write-filter is active — an empty current dump). peer-B then dials A and
//! meshes; the pico z_sub dials B `-m client` and subscribes, which B advertises into
//! the mesh under B's zid -> A learns it -> A pushes the future declare to z_pub.
//! Unlike leg 5 (which barriers on a routers_net-converged witness BEFORE attaching
//! its clients), this leg has NO explicit A<->B convergence barrier — the peer mode
//! exposes no in-run converged witness — so convergence is absorbed by the 20 s
//! receive-wait + the pico `z_pub -n 30` burst (which outlasts the convergence +
//! future-push + re-inject chain), the same barrier-free self-healing `wz_peer_data_forward`
//! relies on. A worst-case ordering flip FAILS the future-push assertion (loud RED),
//! never false-greens it.
//!
//! Requires: wz-ap-demo built with `--features routing-peer` AND the zenoh-pico CLI
//! (`scripts/build-zenoh-pico-cli.sh` -> `target/zenoh-pico-cli/`). run-ci Layer E6
//! builds the demo and SKIPs this leg if the pico CLI is absent; it runs on the
//! `--ignored` lane like the other binary-dep e2es. The `wz_peer_` prefix keeps it out
//! of the default Layer E sweep (`--skip wz_peer`).

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

/// pico z_pub (client of peer-A, pub-before-sub) -> [wz peer A <=mesh=> wz peer B] ->
/// pico z_sub (client of peer-B): wz-peer-A pushes a future subscriber to the pico
/// publisher and re-injects its Put across the wz peer mesh to the pico subscriber —
/// the §5.21 peer's first cross-impl (foreign-client) future-push + client data proof.
// wz-proves: routing-peer wz->pico partial
// wz-proves: pubsub-put pico->wz
// wz-proves: pubsub-put wz->pico
// wz-proves: codec-push pico->wz
// wz-proves: codec-push wz->pico
// wz-proves: declare-subscriber wz->pico partial
// wz-proves: declare-subscriber pico->wz partial
// wz-proves: codec-declare wz->pico partial
// wz-proves: codec-declare pico->wz partial
// wz-proves: keyexpr-wildcard-double pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_pub/z_sub); Layer E6 runs via --ignored"]
fn wz_peer_pushes_a_future_subscriber_and_reinjects_a_pico_publish_to_a_pico_sub() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let publish_key = "demo/key";
    let sub_key = "demo/**";
    let publish_value = "hello-peer-mesh-cross-impl";

    // peer-A binds first so the pico publisher can dial it as a client.
    let a_stderr = tempfile::tempfile().expect("tempfile for peer-A stderr");
    let (mut a_guard, mut a_reader, port_a) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "peer-a",
        a_stderr,
    );
    let endpoint_a = format!("tcp/127.0.0.1:{port_a}");

    // pico z_pub: a CLIENT of peer-A that declares its publisher + starts its Put burst
    // BEFORE any subscriber exists (pub-before-sub). `spawn_publishing_zpub` returns on
    // its `Putting Data` log, by which point its FUTURE subscriber-interest has reached
    // A (a publisher-declare emits the write-filter Interest); its write-filter is
    // active, so nothing flows yet.
    let mut z_pub_child = spawn_publishing_zpub(
        &z_pub,
        publish_key,
        publish_value,
        &endpoint_a,
        "peer-a",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    // peer-B dials A and meshes (its own listen is ephemeral; it needs no read-back).
    let b_stderr = tempfile::tempfile().expect("tempfile for peer-B stderr");
    let (mut b_guard, mut b_reader, port_b) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &format!("127.0.0.1:{port_a}"),
        ],
        "peer: listening on 127.0.0.1:",
        "peer-b",
        b_stderr,
    );
    let endpoint_b = format!("tcp/127.0.0.1:{port_b}");

    // pico z_sub: a CLIENT of peer-B, subscribed and ready. B advertises this sub into
    // the mesh under B's zid; A learns it and pushes the future declare to z_pub.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint_b, "peer-B", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // The pico subscriber must RECEIVE the pico publisher's Put — routed z_pub -> A
    // -(mesh)-> B -> z_sub. This end-to-end wait absorbs the mesh convergence + the
    // future-push + the re-inject (the z_pub -n 30 burst outlasts it), so it is a
    // barrier, not a race.
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(&mut z_sub_reader, received_substr, Duration::from_secs(20));

    // Tear down: the pico one-shots are killed directly; the wz peers are
    // graceful_terminate'd (SIGTERM) so they flush their LATCHED shutdown witnesses
    // (`pushed a future subscriber` / `learned a client sub` / `received mesh data`),
    // which a SIGKILL would skip.
    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));

    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{received_substr}' within 20s — the pico publisher's \
             Put did not cross the wz peer mesh (z_pub -> A -[mesh]-> B -> z_sub)\n--- pico \
             z_sub stdout ---\n{c}\n--- peer-A stderr ---\n{a_captured}\n--- peer-B stderr \
             ---\n{b_captured}"
        )
    });
    // The routed sample must carry BOTH the publisher's keyexpr and its payload — a
    // bare "Received" could be a stale artifact; the unique payload pins THIS pico
    // publisher's Put crossing the wz peer mesh to the pico subscriber. (pico `z_pub`
    // prefixes the value with a `[   N] ` sample counter, so match the payload as a
    // SUBSTRING, exactly as leg-5 keys on `Received ('demo/key'` rather than an exact
    // value format.)
    assert!(
        received_text.contains(&format!("'{publish_key}'")) && received_text.contains(publish_value),
        "the pico subscriber received a sample, but not the '{publish_key}' Put carrying \
         '{publish_value}' — the routed key/value did not match\n--- pico z_sub stdout ---\n{received_text}"
    );
    // PRIMARY discriminator: peer-A pushed a FUTURE subscriber to the pub-before-sub
    // pico publisher. This is what proves the FUTURE-push path fired (deactivating the
    // write-filter), not a lucky sub-before-pub CURRENT dump — the peer-tier twin of
    // leg-5's `router-hat: pushed a future subscriber` gate.
    assert!(
        a_captured.contains("peer: pushed a future subscriber"),
        "peer-A never logged it pushed a future subscriber — the pub-before-sub future-push \
         path did not fire (the delivery may have ridden a sub-before-pub current dump \
         instead)\n--- peer-A stderr ---\n{a_captured}"
    );
    // Transit pin: peer-B's OWN data counter rose — the pico publisher's Put transited
    // the wz peer mesh THROUGH B (re-injected by A) before B delivered it to the pico
    // z_sub, so the delivery exercised the mesh re-inject (D4b / C3b), not a direct
    // z_pub<->z_sub path (the two pico clients never knew each other's address). This is
    // a MONOTONIC counter (unlike `client_subs_seen`, which the z_sub's pre-shutdown
    // teardown would zero), so it survives the shutdown-latched read. The z_sub receive
    // above already proves the subscribe-side C3a delivery, which requires B's
    // `client_subs` entry — so the D4a client-sub ingest is transitively proven.
    assert!(
        b_captured.contains("peer: received mesh data"),
        "peer-B never logged it received mesh data — the pico publisher's Put did not transit \
         the wz peer mesh to B, so the delivery to the pico z_sub did not exercise the C3b \
         re-inject\n--- peer-B stderr ---\n{b_captured}"
    );
}
