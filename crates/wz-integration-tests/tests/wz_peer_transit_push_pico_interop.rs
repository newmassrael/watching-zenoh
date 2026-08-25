// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 peer — the TRANSIT-source client-delivery CROSS-IMPL e2e: proves that a wz
//! peer delivers a multi-hop (transit-sourced) mesh Push to a co-attached FOREIGN pico
//! client subscriber without breaking it. This is the DATA-plane analog of the R311y179
//! query-source fix, on a 3-peer topology the 2-node sub-plane leg
//! (`wz_peer_future_push_pico_interop.rs`) cannot reach.
//!
//! THE BUG THIS PINS (fixed alongside): `deliver_to_client_subscribers` forwarded the
//! inbound Push's routing source node-id verbatim to a client subscriber. At a 3+ hop
//! TRANSIT node the inbound Push carries a NON-ZERO mesh source (the relaying peer
//! re-stamps `out_node_id`), and a real pico client's Push decoder mandatory-rejects the
//! `ext_nodeid` (id 0x03) -> transport CLOSE. Reset-to-0 for the client leaf (a client is
//! not a routing-graph node; faithful to zenoh pubsub.rs `NodeId::default`) makes the
//! delivery decode clean. WITHOUT the fix the pico z_sub's face flaps and it receives
//! nothing; WITH it the sub receives the routed data.
//!
//! HONESTY — the foreign edge is the SINGLE pico `z_sub` on the terminal peer-C; the
//! 3-peer mesh (A <- B <- C) is wz-NATIVE `linkstatepeers_net`. The publisher is a
//! wz-native `--publish` on A: the bug is on the wz->pico DELIVERY side (a client sub
//! receiving a transit-sourced Push), independent of the publisher's impl — a wz-native
//! source is sufficient to make peer-C receive a non-zero-routing-source Push.
//!
//! Topology (LINE, data flows A -> B -> C so C is 2 hops from the publisher):
//!   - peer-C (terminal, hosts the pico z_sub) binds first.
//!   - peer-B (transit) `--connect C`.
//!   - peer-A (source) `--connect B --publish demo/mesh` (subscription-filtered: it
//!     forwards only once the pico z_sub's interest has propagated C -> B -> A).
//!   - pico z_sub: CLIENT of peer-C, subscribing demo/**.
//!
//! No sleeps: the pico receive-wait (20s) absorbs the 2-hop interest propagation +
//! the continuous `--publish` tick (self-healing, like the sub-plane leg's z_pub burst).
//!
//! Requires: wz-ap-demo `--features routing-peer` + the zenoh-pico CLI. run-ci Layer E6
//! SKIPs it if the pico CLI is absent; runs on the `--ignored` lane. The `wz_peer_`
//! prefix keeps it out of the default Layer E sweep (`--skip wz_peer`).

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_subscribed_zsub,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

/// wz --publish (peer-A) -> [wz peer A -> B(transit) -> C] -> pico z_sub (client of
/// peer-C): the transit-sourced Put reaches the foreign pico subscriber 2 hops away —
/// the §5.21 peer's cross-impl proof of the transit-source client-delivery fix.
// wz-proves: routing-peer wz->pico partial
// wz-proves: pubsub-put wz->pico
// wz-proves: codec-push wz->pico
// wz-proves: declare-subscriber pico->wz partial
// wz-proves: codec-declare pico->wz partial
// wz-proves: keyexpr-wildcard-double pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_sub); Layer E6 runs via --ignored"]
fn wz_peer_delivers_a_transit_sourced_push_to_a_pico_client_sub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let publish_key = "demo/mesh";
    let sub_key = "demo/**";
    let publish_value = "wz-mesh-data"; // the wz `--publish` marker payload

    // peer-C (terminal) binds first so peer-B can dial it and the pico z_sub can attach.
    let c_stderr = tempfile::tempfile().expect("tempfile for peer-C stderr");
    let (mut c_guard, mut c_reader, port_c) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "peer-c",
        c_stderr,
    );
    let endpoint_c = format!("tcp/127.0.0.1:{port_c}");

    // peer-B (transit) dials C.
    let b_stderr = tempfile::tempfile().expect("tempfile for peer-B stderr");
    let (mut b_guard, _b_reader, port_b) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &format!("127.0.0.1:{port_c}"),
        ],
        "peer: listening on 127.0.0.1:",
        "peer-b",
        b_stderr,
    );

    // peer-A (source) dials B and publishes demo/mesh. `--publish` is
    // subscription-filtered, so nothing flows until the pico z_sub's interest reaches A.
    let a_stderr = tempfile::tempfile().expect("tempfile for peer-A stderr");
    let (mut a_guard, mut a_reader, _port_a) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &format!("127.0.0.1:{port_b}"),
            "--publish",
            publish_key,
        ],
        "peer: listening on 127.0.0.1:",
        "peer-a",
        a_stderr,
    );

    // pico z_sub: a CLIENT of the TERMINAL peer-C, subscribing demo/**. Its interest
    // propagates C -> B -> A; A then publishes, and the Put transits A -> B -> C, where
    // C delivers it to the pico z_sub carrying a (now reset-to-0) routing source.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, sub_key, &endpoint_c, "peer-C", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // The pico subscriber must RECEIVE the transit-routed Put. Pre-fix peer-C delivered
    // it carrying peer-B's non-zero routing source and the pico rejected the mandatory
    // ext_nodeid -> transport close -> nothing received. The 20s wait absorbs the 2-hop
    // interest propagation + the continuous `--publish` tick.
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(&mut z_sub_reader, received_substr, Duration::from_secs(20));

    // Teardown: kill the pico one-shot; graceful_terminate the wz peers.
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));

    let a_captured = read_captured(&mut a_reader);
    let c_captured = read_captured(&mut c_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub (client of the terminal peer-C, 2 hops from the publisher) never \
             logged '{received_substr}' within 20s — the transit-sourced Put did not reach \
             it (pre-fix: peer-C delivered a non-zero routing source and the pico rejected \
             the mandatory ext_nodeid, closing its transport)\n--- pico z_sub stdout ---\n{c}\
             \n--- peer-C stderr ---\n{c_captured}"
        )
    });
    // Pin the key AND the unique value so a stale/artifact "Received" line cannot
    // false-green.
    assert!(
        received_text.contains(&format!("'{publish_key}'"))
            && received_text.contains(publish_value),
        "the pico subscriber received a sample, but not the '{publish_key}' Put carrying \
         '{publish_value}'\n--- pico z_sub stdout ---\n{received_text}"
    );
    // Transit pin: peer-C received the Put from the mesh (2 hops from the publisher), so
    // the delivery to the pico z_sub exercised the transit (non-zero-source) client
    // delivery path — the exact path the fix corrects.
    assert!(
        c_captured.contains("peer: received mesh data"),
        "peer-C never logged it received mesh data — the Put did not transit the mesh to \
         the terminal peer, so the client delivery did not exercise the transit-source \
         path\n--- peer-C stderr ---\n{c_captured}"
    );
    // Path pin: peer-A learned the pico z_sub's interest, so the subscription propagated
    // the full 2 hops C -> B -> A and the publisher forwarded — confirming the topology
    // is the intended transit line (not a coincidental direct delivery).
    assert!(
        a_captured.contains("peer: publisher learned subscriber interest"),
        "peer-A never learned the pico z_sub's interest — the subscription did not \
         propagate C -> B -> A, so the publisher never forwarded\n--- peer-A stderr ---\n{a_captured}"
    );
}
