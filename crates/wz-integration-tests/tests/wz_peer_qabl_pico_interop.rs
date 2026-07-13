// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 peer — the client-QUERYABLE hosting CROSS-IMPL e2e (the query-plane twin
//! of `wz_peer_future_push_pico_interop.rs`), closing the deferred pico leg of the
//! R311y177 peer client-queryable hosting plane. A pico `z_queryable` CLIENT of peer-A
//! hosts `demo/**`; a pico `z_querier` CLIENT of peer-B queries `demo/key`. The Query
//! crosses the wz peer mesh (A <-> B), peer-A dispatches it to its co-attached client
//! queryable (the R311y177 hosting plane), and the reply returns the same path in
//! reverse — proving the peer query-over-mesh composition end-to-end across two foreign
//! pico edges.
//!
//! HONESTY — this is the FIRST PEER-TIER query-over-mesh cross-impl. A pico query
//! already crosses a wz backbone at the ROUTER-HAT tier
//! (`wz_router_hat_zenohd_interop.rs::wz_router_hat_and_zenohd_federate_a_pico_query_across_the_backbone`,
//! one edge on zenohd); THIS leg is the linkstatepeers_net (peer) analog with BOTH
//! edges on pico. The mesh (A <-> B) is wz-NATIVE `linkstatepeers_net`, already proven
//! by `wz_peer_data_forward`; it is NOT a wz-peer <-> foreign-peer linkstate federation
//! (that is `wz_peer_zenohd_interop`, a control-plane-only wire test). So the cross-impl
//! surface is exactly the two pico client edges: the `z_queryable` whose real C11
//! `query_handler` fires on the routed query, and the `z_querier` whose real C11
//! `reply_handler` receives the routed reply.
//!
//! Topology + ORDERING (no sleeps, deterministic barriers on in-tick positive-edge
//! witnesses):
//!   1. peer-A binds; peer-B dials A and meshes.
//!   2. Barrier: peer-A confirms the reciprocal A <-> B edge (`reciprocal mesh link
//!      confirmed`) BEFORE any client attaches, so A's later self-advertise of the
//!      client queryable floods to B (a tree child) rather than racing an unconverged
//!      graph — the non-racy peer-mesh barrier (cf. E6 load-flake lesson).
//!   3. pico z_queryable dials A `-m client` and declares `demo/**`; peer-A ingests it
//!      into `client_qabls` and self-advertises the queryable into the mesh under A's
//!      zid.
//!   4. Barrier: peer-A logs `learned a client queryable` (the IN-TICK positive-edge
//!      witness — a shutdown read of the live `client_qabls_seen()` would be zeroed by
//!      the queryable's teardown face-down, so it MUST be read mid-run).
//!   5. pico z_querier dials B `-m client` and queries `demo/key` as a self-healing
//!      `-n 30 -t 3000` get burst; peer-B's CURRENT dump (it learned A's advertised
//!      qabl off the mesh) deactivates the querier's write-filter, the Query routes
//!      B -[mesh]-> A -> the co-attached queryable, and the reply returns in reverse.
//!      The burst absorbs the A -> B advert propagation (no ordering discriminator is
//!      needed — this is the current-dump path, not a future-push).
//!
//! Requires: wz-ap-demo built with `--features routing-peer` AND the zenoh-pico CLI
//! (`scripts/build-zenoh-pico-cli.sh` -> `target/zenoh-pico-cli/`). run-ci Layer E6
//! builds the demo and SKIPs this leg if the pico CLI is absent; it runs on the
//! `--ignored` lane. The `wz_peer_` prefix keeps it out of the default Layer E sweep
//! (`--skip wz_peer`).

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_answering_zqueryable, spawn_on_ephemeral_port,
    spawn_querying_zquerier, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

/// pico z_queryable (client of peer-A, hosts demo/**) -> [wz peer A <=mesh=> wz peer B]
/// -> pico z_querier (client of peer-B, queries demo/key): the query crosses the wz
/// peer mesh to peer-A's co-attached client queryable and the reply returns — the
/// §5.21 peer's cross-impl proof of the R311y177 client-queryable HOSTING plane.
// wz-proves: routing-peer wz->pico partial
// wz-proves: codec-request pico->wz
// wz-proves: codec-request wz->pico
// wz-proves: codec-response pico->wz
// wz-proves: codec-response wz->pico
// wz-proves: declare-queryable pico->wz partial
// wz-proves: codec-declare pico->wz partial
// wz-proves: keyexpr-wildcard-double pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_queryable/z_querier); Layer E6 runs via --ignored"]
fn wz_peer_hosts_a_pico_client_queryable_across_the_mesh() {
    let demo = wz_ap_demo_binary();
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let z_querier = zenoh_pico_cli_binary("z_querier");
    let queryable_key = "demo/**";
    let query_key = "demo/key";
    // The reply payload is the pico z_queryable's `-v` value VERBATIM (no counter
    // prefix, `z_bytes_from_static_str`), so a UNIQUE value pins THIS answerer's reply
    // and a stale/artifact "Received" line cannot false-green the primary assert.
    let reply_value = "queryable-from-pico-across-the-wz-peer-mesh";

    // peer-A binds first so the pico queryable can dial it as a client.
    let a_stderr = tempfile::tempfile().expect("tempfile for peer-A stderr");
    let (mut a_guard, mut a_reader, port_a) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "peer-a",
        a_stderr,
    );
    let endpoint_a = format!("tcp/127.0.0.1:{port_a}");

    // peer-B dials A and meshes (its own listen is ephemeral; it needs no read-back for
    // the clients, but its port is used by the pico querier below).
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

    // Barrier 1 (determinism): peer-A confirms the A <-> B mutual edge BEFORE the client
    // attaches, so A's self-advertise of the client queryable floods to B (a tree child)
    // instead of racing an unconverged graph. In-tick positive-edge witness
    // (`edge_count > 0`) — the non-racy peer-mesh barrier.
    let meshed = wait_for_substring(
        &mut a_reader,
        "peer: reciprocal mesh link confirmed",
        Duration::from_secs(15),
    );

    // pico z_queryable: a CLIENT of peer-A hosting demo/** with a UNIQUE reply value.
    // peer-A ingests it into `client_qabls` and self-advertises the queryable into the
    // mesh under A's zid, so peer-B learns wz-peer-A hosts a matching queryable.
    let (mut z_qabl_guard, mut z_qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        queryable_key,
        reply_value,
        &endpoint_a,
        "peer-a",
        || tempfile::tempfile().expect("tempfile for z_queryable stdout"),
    );

    // Barrier 2 (the load-bearing witness): peer-A has INGESTED its client queryable
    // into the R311y177 hosting plane (and synchronously self-advertised it toward the
    // mesh). Gated on the IN-TICK witness — a shutdown read of the live
    // `client_qabls_seen()` would be zeroed by the queryable's teardown face-down.
    let learned = wait_for_substring(
        &mut a_reader,
        "peer: learned a client queryable",
        Duration::from_secs(10),
    );

    // pico z_querier: a CLIENT of peer-B querying demo/key as a self-healing 30-get
    // burst (-n 30 -t 3000). Its write-filter is deactivated by peer-B's CURRENT dump
    // (B learned A's advertised qabl off the mesh); the Query routes B -[mesh]-> A, A
    // dispatches it to its co-attached client queryable, and the reply returns the same
    // path in reverse. The burst absorbs the A -> B advert propagation.
    let mut z_querier_pair = learned.is_ok().then(|| {
        spawn_querying_zquerier(&z_querier, query_key, &endpoint_b, "peer-b", false, || {
            tempfile::tempfile().expect("tempfile for z_querier stdout")
        })
    });

    // The acid test: the reply from the pico z_queryable behind peer-A reaches the pico
    // z_querier behind peer-B, having crossed the wz-native peer mesh in both directions
    // (query forward, reply back).
    let received = z_querier_pair.as_mut().map(|(_, reader)| {
        wait_for_substring(reader, ">> Received ('demo/key'", Duration::from_secs(20))
    });

    // Teardown: kill the pico one-shots directly; graceful_terminate the wz peers. The
    // client-queryable witness is IN-TICK (already flushed to peer-A's stderr), so it
    // survives regardless of teardown order — graceful_terminate is for clean shutdown
    // + template symmetry, NOT to flush a latched witness.
    let z_querier_captured = if let Some((mut child, mut reader)) = z_querier_pair {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        read_captured(&mut reader)
    } else {
        String::new()
    };
    let _ = z_qabl_guard.child_mut().kill();
    let _ = z_qabl_guard.child_mut().wait();
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));

    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let z_qabl_captured = read_captured(&mut z_qabl_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- pico z_queryable stdout ---\n{z_qabl_captured}");
    eprintln!("--- pico z_querier stdout ---\n{z_querier_captured}");

    // Mesh diagnostic FIRST so a mesh-formation failure is not mis-blamed on the query
    // plane.
    meshed.unwrap_or_else(|c| {
        panic!(
            "peer-A never confirmed the reciprocal A <-> B mesh link within 15s — the two \
             wz peers did not federate, so no query could cross the mesh\n--- peer-A \
             stderr ---\n{c}"
        )
    });
    // Assert #3: peer-A hosted the pico client queryable in its client-queryable HOSTING
    // plane (R311y177). Pins that the query rode the CLIENT-queryable hosting plane under
    // test, not some other queryable path.
    learned.unwrap_or_else(|c| {
        panic!(
            "peer-A never INGESTED its client queryable within 10s (no 'learned a client \
             queryable') — the pico z_queryable's DeclareQueryable did not reach peer-A's \
             hosting plane\n--- peer-A stderr ---\n{c}"
        )
    });
    // Assert #1 (PRIMARY): the reply crossed the mesh to the pico querier. Pin BOTH the
    // query keyexpr AND the unique reply value so a stale/artifact "Received" line
    // cannot false-green.
    let received_text = received
        .expect("learned implies the querier was spawned")
        .unwrap_or_else(|c| {
            panic!(
                "pico z_querier behind peer-B never received a reply to demo/key within \
                 20s — the query/reply did not complete over the wz peer mesh (peer-A did \
                 not advertise its client queryable into the mesh, the query was not routed \
                 B -> A, the co-attached queryable was not dispatched, or the reply was lost \
                 on the return path — the z_queryable stdout above shows which)\n--- pico \
                 z_querier stdout ---\n{c}"
            )
        });
    assert!(
        received_text.contains(&format!("'{query_key}'")) && received_text.contains(reply_value),
        "the pico querier received a reply, but not the '{query_key}' reply carrying \
         '{reply_value}' — the routed key/value did not match\n--- pico z_querier stdout \
         ---\n{received_text}"
    );
    // Assert #2 (foreign-side): the query reached the REAL cross-impl answerer behind
    // peer-A. Non-redundant with the reply assert — it proves the FORWARD reach (a
    // present-but-no-reply here would localize a reverse-route fault).
    assert!(
        z_qabl_captured.contains("[Queryable handler] Received Query"),
        "pico z_queryable behind peer-A never logged 'Received Query' — the reply the \
         querier saw did not originate at the real cross-impl answerer\n--- pico \
         z_queryable stdout ---\n{z_qabl_captured}"
    );
}
