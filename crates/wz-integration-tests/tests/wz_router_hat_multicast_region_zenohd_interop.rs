// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A router's multicast group lives in its SOUTH PEER REGION, and a Put that
//! arrives on the group is a Put FROM that region. This file adjudicates
//! what follows from it against the pinned reference router, on the wire.
//!
//! ## The rule, read at the pin
//!
//! A router puts its multicast transport in the default south PEER region
//! (`zenoh/src/net/runtime/region.rs`
//! @ `WhatAmI::Router => Ok(Region::default_south(WhatAmI::Peer)),`), and a
//! unicast peer attached to that router lands in the same region
//! (`zenoh/src/net/runtime/region.rs`
//! @ `(WhatAmI::Router, WhatAmI::Peer | WhatAmI::Client) | (WhatAmI::Peer, WhatAmI::Client) => {`).
//! The hat that serves that region relays to its own faces only what came from
//! ANOTHER region (`zenoh/src/net/routing/hat/peer/pubsub.rs`
//! @ `if ctx.subs.is_some() && self.region() != *src_region {`). So a Put a
//! group member publishes is NOT relayed by the router to a unicast peer that
//! subscribed to it: the two are peers of one region and reach each other
//! over their own links, which is what the group is. A client of the router
//! sits in a different region, and receives it.
//!
//! Until this round wz routed a group Put as if a CLIENT had sent it, which
//! re-injected it into the router's peer region too, so a unicast peer
//! received a Put that the reference router withholds.
//!
//! ## Topology
//!
//! ```text
//!   pico z_pub -m peer ──(udp multicast group)──► ROUTER ◄── pico z_sub -m client   (C)
//!                                                    ▲
//!                                                    └────── wz --peer --subscribe   (P)
//! ```
//!
//! ROUTER is zenohd in the calibration leg and a wz `--router-hat` in the claim
//! leg, with the same group on the same interface and the same two
//! subscribers. P is a unicast peer that is NOT on the group.
//!
//! ## Why the absence is not a timing guess
//!
//! P's subscription is proved live BEFORE the group publisher starts: a
//! unicast pico client publishes the same key and P must receive it (a client
//! region differs from P's, so the router relays it). The client publisher is
//! then stopped and P's push count is read as the baseline. After that the
//! group publisher runs, and the assertion waits for C to RECEIVE a group
//! Put, so the router has demonstrably routed one, and then for three more
//! seconds. P's count must still equal the baseline. A wz router that
//! re-injects into the peer region moves P's count at the same instant it
//! moves C's.
//!
//! The calibration leg runs the same code against zenohd. If zenohd moved P's
//! count the claim leg would be asserting something the reference does not
//! do, and that leg would be wrong rather than the router.
//!
//! ## Environment (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment dependent, so this is opt-in like the
//! sibling multicast lanes. Needs `zenohd`, the zenoh-pico CLI and a
//! `wz-ap-demo` built with `router-multicast-faces`.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, default_route_iface, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_publishing_zpub, spawn_subscribed_zsub, wait_for_substring,
    wait_for_tcp_accept_alive, wait_for_zenohd_handshake_ready, wz_ap_demo_binary,
    zenoh_pico_cli_binary, zenohd_binary, ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 231);
const KEY: &str = "demo/mc/region";
const CONTROL_VALUE: &str = "FROM-A-UNICAST-CLIENT";
const GROUP_VALUE: &str = "FROM-THE-MULTICAST-GROUP";
/// How long C may take to receive the first group Put: a multicast member is
/// admitted on its first JOIN, which zenoh sends every 2.5 s.
const GROUP_RECEIVE_BUDGET: Duration = Duration::from_secs(30);
/// Time given to a Put that is going to reach P after C received it. Both are
/// routed from the same arrival, so this is margin for a slow second hop, not
/// a wait for something that might be late by seconds.
const SETTLE_AFTER_C: Duration = Duration::from_secs(3);

fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// What one run of the topology measured.
struct Outcome {
    /// P's push count after the unicast control, before any group Put.
    peer_baseline: usize,
    /// P's push count after C received a group Put and the settle time passed.
    peer_after_group: usize,
    /// Whether C received a group Put (the proof the router routed one).
    client_saw_group_put: bool,
    /// Every capture, for the failure message.
    diagnostics: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Router {
    Zenohd,
    Wz,
}

/// The last `(N push(es))` a wz peer logged: its count of received pushes.
fn last_push_count(captured: &str) -> usize {
    captured
        .lines()
        .rev()
        .find_map(|line| {
            let tail = line.split_once("received mesh data (")?.1;
            tail.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

fn run_topology(router: Router, port: u16) -> Outcome {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{port}#iface={iface}");

    // ── ROUTER, with the group attached. ──
    let tcp_reservation = PortReservation::pick();
    let (router_guard, mut router_reader, endpoint): (ChildGuard, Option<std::fs::File>, String) =
        match router {
            Router::Zenohd => {
                let tcp_port = tcp_reservation.port();
                let mut guard = ChildGuard::wrap(
                    "zenohd (reference router)",
                    Command::new(zenohd_binary())
                        .args(["-l", &format!("tcp/127.0.0.1:{tcp_port}"), "-l", &locator])
                        .args(["--no-multicast-scouting", "--rest-http-port", "none"])
                        // A multicast member is admitted only when its Join names the
                        // batch size this node expects, and zenohd expects the UDP
                        // link's 8192 while the pico CLI announces its own multicast
                        // batch of 2048 (`BATCH_MULTICAST_SIZE` in the vendored build
                        // config). zenohd logs `Ignoring Join ... Unsupported Batch
                        // Size: 2048. Expected: 8192.` and routes nothing. The wz
                        // router takes whatever the Join says, so this is set on
                        // zenohd only, to make the pico publisher a member of ITS group.
                        .args(["--cfg", "transport/link/tx/batch_size:2048"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .expect("spawn zenohd"),
                );
                if let Err(e) =
                    wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
                {
                    panic!("zenohd (reference router): {e}");
                }
                wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{tcp_port}"), tempfile);
                (guard, None, format!("tcp/127.0.0.1:{tcp_port}"))
            }
            Router::Wz => {
                let demo = wz_ap_demo_binary();
                assert_demo_binary_newer_than_sources(&demo);
                let (mut guard, mut reader, tcp_port) = spawn_on_ephemeral_port(
                    &demo,
                    &[
                        "--router-hat",
                        "127.0.0.1:0",
                        "--multicast-locator",
                        &locator,
                    ],
                    "router-hat: listening on 127.0.0.1:",
                    "router-hat",
                    tempfile(),
                );
                let joined = format!("multicast group {GROUP}:{port} joined");
                if let Err(c) = wait_for_substring(&mut reader, &joined, Duration::from_secs(5)) {
                    let _ = guard.child_mut().kill();
                    let _ = guard.child_mut().wait();
                    panic!(
                        "the wz router never joined the group within 5s -- the demo was \
                         likely built without `router-multicast-faces`\n--- stderr ---\n{c}"
                    );
                }
                (guard, Some(reader), format!("tcp/127.0.0.1:{tcp_port}"))
            }
        };
    drop(tcp_reservation);
    let dial = endpoint.trim_start_matches("tcp/").to_string();

    // ── C: a client subscriber (a different region from the group's). ──
    let (c_guard, mut c_reader) =
        spawn_subscribed_zsub(&z_sub, KEY, &endpoint, "the router", tempfile);

    // ── P: a unicast PEER subscriber that is not on the group. ──
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (mut p_guard, mut p_reader, _p_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &dial,
            "--subscribe",
            KEY,
        ],
        "peer: listening on 127.0.0.1:",
        "peer-sub",
        tempfile(),
    );

    // ── Control: P's subscription is live, proved by a client's Put. ──
    let control = spawn_publishing_zpub(
        &z_pub,
        KEY,
        CONTROL_VALUE,
        &endpoint,
        "the router",
        tempfile,
    );
    let p_got_control =
        wait_for_substring(&mut p_reader, "received mesh data", Duration::from_secs(20));
    let mut control = control;
    let _ = control.child_mut().kill();
    let _ = control.child_mut().wait();
    // Let what the stopped publisher already sent drain before the baseline.
    std::thread::sleep(Duration::from_millis(2500));
    let peer_baseline = last_push_count(&read_captured(&mut p_reader));

    // ── The group publisher: a foreign multicast member (whatami peer). ──
    let group_capture = tempfile();
    let group_out = group_capture.try_clone().expect("dup z_pub stdout");
    let group_err = group_capture.try_clone().expect("dup z_pub stderr");
    let mut group_reader = group_capture;
    let mut group_pub = ChildGuard::wrap(
        "z_pub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args([
                "-k",
                KEY,
                "-v",
                GROUP_VALUE,
                "-l",
                &locator,
                "-m",
                "peer",
                "-n",
                "40",
            ])
            .stdout(Stdio::from(group_out))
            .stderr(Stdio::from(group_err))
            .spawn()
            .expect("spawn the group z_pub via stdbuf"),
    );

    // pico prints the value after a `[   n] ` counter, so match the value alone; the
    // control's value is a different string, so a control Put cannot satisfy this.
    let c_saw = wait_for_substring(&mut c_reader, GROUP_VALUE, GROUP_RECEIVE_BUDGET);
    if c_saw.is_ok() {
        std::thread::sleep(SETTLE_AFTER_C);
    }
    let peer_after_group = last_push_count(&read_captured(&mut p_reader));

    let _ = group_pub.child_mut().kill();
    let _ = group_pub.child_mut().wait();
    let _ = p_guard.child_mut().kill();
    let _ = p_guard.child_mut().wait();
    drop(c_guard);
    let mut router_guard = router_guard;
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));

    let mut diagnostics = String::new();
    if let Some(r) = router_reader.as_mut() {
        diagnostics.push_str(&format!("--- router stderr ---\n{}\n", read_captured(r)));
    }
    diagnostics.push_str(&format!(
        "--- peer-sub stderr ---\n{}\n--- client z_sub ---\n{}\n--- group z_pub ---\n{}\n",
        read_captured(&mut p_reader),
        read_captured(&mut c_reader),
        read_captured(&mut group_reader),
    ));
    assert!(
        p_got_control.is_ok(),
        "the control never reached P, so P's subscription was not live and the absence \
         below would prove nothing\n{diagnostics}"
    );
    Outcome {
        peer_baseline,
        peer_after_group,
        client_saw_group_put: c_saw.is_ok(),
        diagnostics,
    }
}

fn assert_group_put_stays_out_of_the_peer_region(who: &str, o: &Outcome) {
    assert!(
        o.client_saw_group_put,
        "{who}: the client never received a group Put, so the router routed none and the \
         peer's silence proves nothing\n{}",
        o.diagnostics
    );
    assert!(
        o.peer_baseline >= 1,
        "{who}: the baseline is empty, the control did not count\n{}",
        o.diagnostics
    );
    assert_eq!(
        o.peer_after_group, o.peer_baseline,
        "{who}: a unicast peer in the router's peer region received a Put that came from \
         the router's multicast group (baseline {}, after {}); the router withholds it, \
         because the group and the peer are one region\n{}",
        o.peer_baseline, o.peer_after_group, o.diagnostics
    );
}

/// The calibration: the reference router withholds the group Put from P.
// wz-proves: none -- harness entry; calibrates the leg below against zenohd, which
// is the adjudicator of what a router does with a group Put and a unicast peer.
#[test]
#[ignore = "binary-dep multicast e2e (zenohd + zenoh-pico + wz-ap-demo); Layer M runs via --ignored"]
fn zenohd_router_keeps_a_multicast_put_out_of_its_peer_region_multicast() {
    let outcome = run_topology(Router::Zenohd, 17761);
    assert_group_put_stays_out_of_the_peer_region("zenohd", &outcome);
}

/// The claim: a wz router does the same.
// wz-proves: router-multicast-faces zenohd->wz partial
#[test]
#[ignore = "binary-dep multicast e2e (zenohd + zenoh-pico + wz-ap-demo --features router-multicast-faces); Layer M runs via --ignored"]
fn wz_router_hat_keeps_a_multicast_put_out_of_its_peer_region_multicast() {
    let outcome = run_topology(Router::Wz, 17762);
    assert_group_put_stays_out_of_the_peer_region("wz router-hat", &outcome);
}
