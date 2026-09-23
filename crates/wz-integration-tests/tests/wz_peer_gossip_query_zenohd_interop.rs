// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2811 — §5.21 routing-peer — the QUERY plane across a wz peer and a STOCK
//! zenohd peer, in BOTH directions, in the only peer subsystem the pin has.
//!
//! The pinned upstream has one peer HAT and it gossips: a peer announces itself
//! with no links, so neither side's topology graph ever holds an edge. R2236 gave
//! wz's gossip mode a declaration and data path, and the data legs in
//! `wz_mesh_quic_acceptor_zenohd_interop` prove it. Nothing proved the query
//! plane, and it did not work: a client of the wz peer asking for a queryable
//! behind zenohd got an immediate `ResponseFinal` and no reply, while zenohd's
//! own routing log showed it HAD propagated the queryable to wz.
//!
//! The base was the topology graph. Every route query (`next_hop`,
//! `directions_toward`, `distance_to`) walked edges, so in gossip mode each of
//! them answered "no path". R2236 had answered that for ONE caller, the
//! self-originated data route; the query route asked the same graph and kept
//! the defect. R2811 moved the answer into the graph, where upstream's rule is
//! stated once: from self a direct neighbour is its own next hop, and from any
//! other source there is none, because a peer never relays one peer's traffic
//! to another (`zenoh/src/net/routing/hat/peer/queries.rs` @
//! `if self.region() != *src_region {`).
//!
//! ## The legs
//!
//! ```text
//!   1. out:  pico z_querier --tcp--> wz peer --gossip--> zenohd peer --tcp--> pico z_queryable
//!   2. in:   pico z_querier --tcp--> zenohd peer --gossip--> wz peer --tcp--> pico z_queryable
//! ```
//!
//! Each carries a reply value unique to its leg, so a reply cannot be mistaken
//! for one from a queryable the leg did not place. The pico clients never learn
//! each other's address; only the peer link joins the two halves.
//!
//! CONTROL, measured before this file existed: with the graph's gossip arm
//! removed, leg 1 gets zero replies (the querier sees only the final) and leg 2
//! still passes, because a query that ARRIVES from a gossip neighbour is answered
//! by wz's co-attached client queryable without consulting the graph at all.
//! That asymmetry is the defect's shape, and it is why both legs are here.
//!
//! `#[ignore]` binary-dep e2e; Layer Z runs it via `--ignored` with a zenohd and
//! the zenoh-pico CLIs provisioned.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_answering_zqueryable, spawn_on_ephemeral_port,
    spawn_querying_zquerier, spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, zenohd_binary, ChildGuard,
};

const QUERY_KEY: &str = "demo/key";

fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// A wz peer in `peer-to-peer` mode listening on an ephemeral TCP port, and a
/// STOCK `mode=peer` zenohd dialing it. Returns both, wz's port, zenohd's port,
/// and wz's stderr reader, once wz has decoded zenohd's gossip announcement —
/// a wire decode, not a handshake artefact, and the event a gossip neighbour
/// actually emits.
fn spawn_gossip_pair(leg: &str) -> (ChildGuard, std::fs::File, u16, ChildGuard, u16) {
    let demo = wz_ap_demo_binary();
    let (wz, mut wz_reader, wz_port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0", "--peer-mode", "peer-to-peer"],
        "peer: listening on 127.0.0.1:",
        "wz gossip peer",
        tempfile(),
    );
    let (zenohd, zenohd_port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (gossip peer)",
        Some(&format!("tcp/127.0.0.1:{wz_port}")),
        &[],
        None,
        &["mode:\"peer\""],
    );
    if let Err(c) = wait_for_substring(
        &mut wz_reader,
        "peer: ingested neighbour link-state",
        Duration::from_secs(15),
    ) {
        panic!("[{leg}] wz never decoded zenohd's gossip announcement within 15s\n{c}");
    }
    (wz, wz_reader, wz_port, zenohd, zenohd_port)
}

/// Run one leg: a pico queryable answering `reply` on `qabl_port`, a pico
/// querier on `querier_port`, and the assertion that the querier received that
/// reply. Everything is torn down before any assertion, so a failure still
/// prints every side's log.
fn run_query_leg(leg: &str, qabl_side_is_zenohd: bool, reply: &str) {
    let (mut wz, mut wz_reader, wz_port, mut zenohd, zenohd_port) = spawn_gossip_pair(leg);
    let (qabl_port, querier_port) = if qabl_side_is_zenohd {
        (zenohd_port, wz_port)
    } else {
        (wz_port, zenohd_port)
    };
    let (mut qabl, mut qabl_reader) = spawn_answering_zqueryable(
        &zenoh_pico_cli_binary("z_queryable"),
        QUERY_KEY,
        reply,
        &format!("tcp/127.0.0.1:{qabl_port}"),
        if qabl_side_is_zenohd {
            "zenohd"
        } else {
            "wz peer"
        },
        tempfile,
    );
    let (mut querier, mut querier_reader) = spawn_querying_zquerier(
        &zenoh_pico_cli_binary("z_querier"),
        QUERY_KEY,
        &format!("tcp/127.0.0.1:{querier_port}"),
        if qabl_side_is_zenohd {
            "wz peer"
        } else {
            "zenohd"
        },
        false,
        tempfile,
    );
    let needle = format!(">> Received ('{QUERY_KEY}': '{reply}')");
    let received = wait_for_substring(&mut querier_reader, &needle, Duration::from_secs(20));

    let _ = querier.child_mut().kill();
    let _ = querier.child_mut().wait();
    let _ = qabl.child_mut().kill();
    let _ = qabl.child_mut().wait();
    graceful_terminate(wz.child_mut(), Duration::from_secs(5));
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!(
        "--- [{leg}] wz peer stderr ---\n{}",
        read_captured(&mut wz_reader)
    );
    eprintln!(
        "--- [{leg}] pico z_queryable ---\n{}",
        read_captured(&mut qabl_reader)
    );

    received.unwrap_or_else(|c| {
        panic!(
            "[{leg}] the pico querier never received '{reply}' within 20s — the query \
             did not cross the gossip peer link to the queryable, or its reply did not \
             come back\n--- pico z_querier ---\n{c}"
        )
    });
}

/// Leg 1 — the direction that was broken. A client of the WZ peer queries; the
/// queryable sits behind zenohd. wz must route the query to its gossip
/// neighbour, which the graph now answers as self's own next hop.
// wz-proves: routing-peer wz->zenohd partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenohd peer + zenoh-pico z_queryable/z_querier); Layer Z runs via --ignored"]
fn wz_peer_routes_a_client_query_to_a_queryable_behind_a_gossip_zenohd() {
    run_query_leg("out", true, "behind-zenohd");
}

/// Leg 2 — the reverse: a client of ZENOHD queries; the queryable is a client
/// of the wz peer. Kept beside leg 1 because it passed with the defect in
/// place, so it is the control that leg 1's failure was about route selection
/// and not about the pair failing to talk at all.
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenohd peer + zenoh-pico z_queryable/z_querier); Layer Z runs via --ignored"]
fn wz_peer_answers_a_gossip_zenohd_query_from_its_client_queryable() {
    run_query_leg("in", false, "behind-wz");
}
