// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2457 (open-debt item 702) — a keyexpr id space is keyed by SESSION, read
//! off a REAL two-link capture rather than a synthesised one.
//!
//! # The question this asks, which nothing else in the tree asks
//!
//! `wz_capture::agg::KeyexprSpaces` used to key its tables by the FLOW's
//! direction. That is exact while a session has one link and too tight when it
//! has two: a `DeclKexpr` goes out on whichever link was dialled first and the
//! data using the alias may go out on the second, so the declaration and the
//! reference land in different tables and neither resolves. R2457 raised the
//! unit to the session, grouped by the node pair the handshake named.
//!
//! `crate::agg`'s own tests grade that against a hand-built capture. This
//! grades it against bytes two wz peers actually wrote to a socket, which is a
//! different claim: that `wz_capture::node::NodeCensus` finds the two links of
//! a real aggregated session in a real recording, and that the grouping built
//! from it holds.
//!
//! # ⚠ WHY THIS IS A NEW CAPTURE AND NOT A LEG OF AN EXISTING ONE
//!
//! Open-debt item 702 was filed saying the bytes were already on the wire in
//! `zenoh_multilink_body_foreign_witness` — both processes run
//! `transport/unicast/max_links:2` there — and that nobody asked this question
//! of them. MEASURED this round, that is half right and the wrong half is the
//! half that mattered: the CONFIG is there and is what completes the pubkey
//! handshake that leg grades, but the CAPTURE is of ONE link. `tap_proxy`
//! accepts a single connection, `z_get` dials once, and that test asserts
//! `flows.len() == 1` in its own words — "one relayed connection is one flow".
//! `max_links: 2` is a budget, not a second dial.
//!
//! The other two multilink e2es DO establish two links —
//! `wz_peer_multilink_aggregate` has A dial B twice — and neither captures
//! anything: they read the demo's own log witnesses. So before this file there
//! was no two-link pcap in the tree at all, and the question could not be put
//! to a real capture however carefully one asked.
//!
//! # The topology, and why the tap is doubled
//!
//! `wz_peer_multilink_aggregate`'s, with the dial routed through two taps:
//!
//!   - peer B: `--peer 127.0.0.1:0 --subscribe demo/mesh --max-links 2`, the
//!     accept side, bound first.
//!   - two `tap_proxy` instances, each forwarding to B's port. One accepts one
//!     connection, which is exactly right here — two proxies, two links.
//!   - peer A: `--connect <tap1>,<tap2> --publish demo/mesh --max-links 2`. The
//!     peer-mode `--connect` list is not deduped and these are two different
//!     addresses anyway, so A dials twice and aggregates both onto one zid.
//!
//! Each recording is synthesised under its OWN port pair, so the two land in
//! the pcap as two flows — which is the whole point, and is what a real tap on
//! a real deployment would see.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::agg::UnresolvedCause;
use wz_capture::Dissection;
use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard,
};
use wz_integration_tests::wire_tap::{synthesise_packets, tap_proxy, Recording, Side};

/// The two synthesised port pairs, one per link.
///
/// DIFFERENT on both halves, and that is load-bearing: `FlowKey` is the two
/// endpoints, so two links sharing a port pair would be ONE flow in the
/// dissection and this test would grade a single-link capture while believing
/// otherwise. The numbers are arbitrary; that they differ is not.
const LINK_ONE: (u16, u16) = (40001, 7447);
const LINK_TWO: (u16, u16) = (40002, 7448);

/// Spawn a `--peer` demo on an ephemeral port and read the bound port back.
///
/// `wz_peer_multilink_aggregate`'s helper, unchanged in behaviour — the same
/// binary, the same listen-log handshake, the same failure text naming the
/// feature a missing binary would be missing.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
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
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
             --features transport-multilink?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Wait until `recording` has bytes in BOTH directions.
///
/// A one-way recording is not a handshake, and a link the census can call a
/// LINK needs an INIT from each end — see `wz_capture::node`'s module docs for
/// why one INIT proves nothing. So this is the precondition of the whole test
/// and not a convenience.
fn both_directions(recording: &Recording, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let segments = recording.lock().expect("recording lock");
        let from_dialer = segments
            .iter()
            .any(|(s, b)| *s == Side::FromDialer && !b.is_empty());
        let from_listener = segments
            .iter()
            .any(|(s, b)| *s == Side::FromListener && !b.is_empty());
        if from_dialer && from_listener {
            return true;
        }
        drop(segments);
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The `wz_peer_` PREFIX IS LOAD-BEARING and not a naming taste.
///
/// The default Layer E sweep selects every `#[ignore]`d test in this crate and
/// removes a hand-listed set of tokens, `--skip wz_peer` among them. This test
/// needs `wz-ap-demo` built `--features transport-multilink`, which that sweep
/// does not build — and a selected test whose oracle is absent PANICS rather
/// than skipping, which is the failure that ran red for six hosted runs and is
/// written up beside the sweep. The prefix is what keeps it in its own lane.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features transport-multilink); run-ci Layer E6c runs it via --ignored"]
fn wz_peer_multilink_capture_is_one_keyexpr_id_space() {
    let (mut b_guard, mut b_reader, p_b) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "demo/mesh",
            "--max-links",
            "2",
        ],
    );

    // TWO taps to B, each accepting one connection.
    let (tap_one_port, tap_one) = tap_proxy(p_b);
    let (tap_two_port, tap_two) = tap_proxy(p_b);
    let dial_both = format!("127.0.0.1:{tap_one_port},127.0.0.1:{tap_two_port}");

    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &dial_both,
            "--publish",
            "demo/mesh",
            "--max-links",
            "2",
        ],
    );

    // Sync on the AGGREGATION witnesses, exactly as
    // `wz_peer_multilink_aggregate` does and for its reason: `live links now 2`
    // is emitted only by the `LinkAggregated` event, so it is positive proof
    // that the two links became ONE session rather than two sessions forming.
    // Without it this test could pass on a capture of two independent sessions,
    // which is the thing the grouping must NOT merge.
    let a_agg = wait_for_substring(&mut a_reader, "live links now 2", Duration::from_secs(15));
    let b_agg = wait_for_substring(&mut b_reader, "live links now 2", Duration::from_secs(15));
    let b_data = wait_for_substring(&mut b_reader, "received mesh data", Duration::from_secs(15));

    let tapped_one = both_directions(&tap_one, Duration::from_secs(5));
    let tapped_two = both_directions(&tap_two, Duration::from_secs(5));

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");

    a_agg.unwrap_or_else(|c| {
        panic!(
            "peer-A never aggregated its two dials into one session (no 'live \
             links now 2'), so this capture is not of a multilink session\n\
             --- peer-A stderr ---\n{c}"
        )
    });
    b_agg.unwrap_or_else(|c| {
        panic!(
            "peer-B never aggregated the two inbound links (no 'live links now \
             2')\n--- peer-B stderr ---\n{c}"
        )
    });
    b_data.unwrap_or_else(|c| {
        panic!(
            "peer-B never received A's published data, so the aggregated \
             session carried no traffic to read\n--- peer-B stderr ---\n{c}"
        )
    });

    // ── ANTI-VACUITY, BEFORE ANY CLAIM ────────────────────────────────────
    // Two taps that recorded nothing would satisfy every assertion below over
    // an empty capture, which is this workspace's most expensive recurring
    // shape. Both must have carried a handshake in both directions.
    assert!(
        tapped_one && tapped_two,
        "both taps must have recorded both directions — link one: {tapped_one}, \
         link two: {tapped_two}. A tap that saw one direction is not a link and \
         the census will not record it as one"
    );

    let segments_one = tap_one.lock().expect("tap one lock").clone();
    let segments_two = tap_two.lock().expect("tap two lock").clone();

    // ONE pcap, TWO flows: each recording under its own port pair.
    let mut packets = synthesise_packets(&segments_one, LINK_ONE.0, LINK_ONE.1);
    packets.extend(synthesise_packets(&segments_two, LINK_TWO.0, LINK_TWO.1));
    let borrowed: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .map(|(s, f, p)| (*s, *f, p.as_slice()))
        .collect();
    let pcap = wz_capture::pcap::write(wz_capture::link::LINKTYPE_ETHERNET, &borrowed);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");

    assert_eq!(
        dissection.flows().len(),
        2,
        "two tapped links must be TWO flows — if this is 1 the port pairs \
         collided and the test would grade a single-link capture"
    );

    // ── THE CLAIM ─────────────────────────────────────────────────────────
    let census = wz_capture::node::nodes(&dissection);
    assert_eq!(
        census.nodes().len(),
        2,
        "two peers named themselves: {:?}",
        census.nodes()
    );
    assert_eq!(
        census.links().len(),
        2,
        "and BOTH links were seen handshaking, which is what makes this a \
         multilink capture rather than a single link plus noise: {:?}",
        census.links()
    );

    let grouping = wz_capture::node::SessionGrouping::of(&census);
    assert_eq!(
        grouping.sessions(),
        1,
        "the two links are ONE session — the reduction item 702 is about, here \
         derived from bytes two real peers wrote rather than from a fixture"
    );
    assert_eq!(
        grouping.grouped_lists(),
        2,
        "and BOTH flows are attributed to it, so neither falls back to a \
         per-flow id space"
    );

    let table = wz_capture::agg::aggregate(&dissection);
    // Anti-vacuity again, one layer in: a plane that walked no record could not
    // have contradicted the claim below.
    assert!(
        table.walked_records() > 0,
        "the throughput plane read no record out of this capture, so the \
         resolution claim below is over an empty set"
    );

    // THE QUESTION, asked of the real capture: with both links of the session
    // in hand, no reference may be refused for want of a SESSION. A
    // `NoSession` row here would mean the grouping failed to attribute a flow
    // this capture demonstrably holds both ends of — which is exactly the
    // defect item 702 reported, in the form its consumer met it.
    let stranded: Vec<_> = table
        .unresolved()
        .iter()
        .filter(|u| u.cause == UnresolvedCause::NoSession)
        .map(|u| (u.space, u.id, u.references))
        .collect();
    assert!(
        stranded.is_empty(),
        "every link of this session is in the capture, so no reference may be \
         unresolved for want of a session; these were: {stranded:?}. Before \
         R2457 the id space was keyed by flow and this is the list that was \
         not empty"
    );
}
