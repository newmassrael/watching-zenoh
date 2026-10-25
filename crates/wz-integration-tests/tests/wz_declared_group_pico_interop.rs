// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that is a MEMBER OF A MULTICAST GROUP, against zenoh-pico's
//! multicast peers: it joins, is admitted by them and admits them, puts a document on the group for
//! them, and keeps what they put.
//!
//! The node is `slot-group` (`deploy/nodes/slot-group.toml`): a fixed-memory process with no
//! allocator that dials nothing, joins `udp/224.0.0.224:7490`, puts an eight-byte document on
//! `lab/group/beat` every 200 ms and keeps the latest sample on `lab/group/in`. The file Layer M
//! runs is the one the entry packaged (`wz_package.py --node slot-group`), so what is proven is the
//! artifact whose manifest was verified.
//!
//! The peers are zenoh-pico's own examples, which share no code with wz: `z_sub` and `z_pub` as
//! multicast peers (`-m peer -l udp/<group>:<port>#iface=<dev>`). A group has no handshake, so
//! admission is the JOIN beacon each side hears and accepts, and a peer that rejects the other's
//! parameters (the sequence-number resolution and the batch must agree) hears nothing of it. Three
//! legs:
//!
//! - the node's puts reach a pico subscriber, byte for byte and more than once, so its JOIN was
//!   admitted and its Frames decode; a pico subscriber of another key hears none of them, so what
//!   arrived is the node's table and not an echo of the group;
//! - a pico publisher's puts reach the node's subscription, which keeps the latest of them, so the
//!   node admitted pico's JOIN and decoded its Frames; a put on a key the node does not subscribe
//!   to is kept by nothing;
//! - the node counts its members: none until pico joins, one while pico is there and none again
//!   once pico has left (its lease runs out, since the CLI says no Close when it is stopped).
//!
//! Multicast needs a route on the host: the legs run on the interface the default route uses, as
//! pico's `#iface=` names it and as the node's own join (the kernel's routing) picks it, so both meet
//! on the one link. The environment decides, so the legs run on the opt-in Layer M, one at a time
//! (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_GROUP`) and the pico CLI
//! (`scripts/build-zenoh-pico-cli.sh`). The file's `zenohd` token is absent on purpose: Layer E's
//! sweep must not run it, and `--ignored` is what keeps it off.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    default_route_iface, graceful_terminate, read_captured, wait_for_substring,
    zenoh_pico_cli_binary, ChildGuard, ZENOH_MULTICAST_GROUP,
};

// The node says every change of its group; the leg waits for the join.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-GROUP {} joins={} refused={} members={}" for "joins=1"

/// The port of the group, as the node's declaration states it.
const PORT: u16 = 7490;
/// The key the node puts on, and the one it keeps.
const BEAT: &str = "lab/group/beat";
const KEPT: &str = "lab/group/in";
/// What the node puts: eight bytes of `x`, as its declaration states.
const DOCUMENT: &str = "xxxxxxxx";
/// What pico's `z_pub` puts: it wraps the value as `[%4d] <value>`, so the tail survives intact.
const VALUE: &str = "WZ-GROUP-IN-VALUE";
/// How long a leg may wait for the group to carry something.
const BUDGET: Duration = Duration::from_secs(30);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_GROUP").expect(
        "WZ_DECLARED_NODE_GROUP names the packaged slot-group (Layer M builds it with \
         `wz_package.py --node slot-group`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

/// The locator pico peers join, on the default route's interface.
fn locator() -> String {
    format!(
        "udp/{ZENOH_MULTICAST_GROUP}:{PORT}#iface={}",
        default_route_iface()
    )
}

/// The node, with its output captured. It joins on its first round.
fn start_node() -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("a capture for the node");
    let node = ChildGuard::wrap(
        "slot-group (declared node)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(node_binary())
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the node"),
    );
    wait_for_substring(&mut out.try_clone().expect("dup"), "joins=1", BUDGET)
        .unwrap_or_else(|why| panic!("the node never joined its group: {why:?}"));
    (node, out)
}

/// A pico peer of the group: `z_sub` of `key`, or `z_pub` of `key` with `value`. Its output is
/// captured, and it is returned once it has said what it says when it is up.
fn start_pico(program: &str, key: &str, value: Option<&str>, up: &str) -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("a capture for the peer");
    let mut command = Command::new("stdbuf");
    command
        .args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary(program))
        .args(["-k", key, "-l", &locator(), "-m", "peer"]);
    if let Some(value) = value {
        command.args(["-v", value]);
    }
    let peer = ChildGuard::wrap(
        "pico multicast peer",
        command
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the pico peer"),
    );
    wait_for_substring(
        &mut out.try_clone().expect("dup"),
        up,
        Duration::from_secs(10),
    )
    .unwrap_or_else(|why| panic!("the pico peer never said `{up}`: {why:?}"));
    (peer, out)
}

fn read(capture: &File) -> String {
    read_captured(&mut capture.try_clone().expect("dup capture"))
}

/// How many times `needle` is in what `capture` has so far.
fn count(capture: &File, needle: &str) -> usize {
    read(capture).matches(needle).count()
}

/// Wait until `done` holds of what `capture` has so far, or `BUDGET` runs out and say what was.
fn wait_until(what: &str, capture: &File, done: impl Fn(&str) -> bool) {
    let until = Instant::now() + BUDGET;
    loop {
        let seen = read(capture);
        if done(&seen) {
            return;
        }
        assert!(
            Instant::now() < until,
            "{what} did not happen within {BUDGET:?}\n--- seen ---\n{seen}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `members=` the node last said, or none.
fn members(node: &File) -> Option<u32> {
    read(node)
        .lines()
        .filter(|line| line.starts_with("HOST-WZ-GROUP "))
        .filter_map(|line| line.rsplit_once("members=")?.1.trim().parse().ok())
        .next_back()
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its group is the slot profile's own plane over the shared group drive, and the catalog's multicast atoms name the heap runtime's
#[test]
#[ignore = "environment-dependent multicast e2e (the packaged slot-group, which Layer M makes, + the pico CLI); runs via --ignored"]
fn pico_multicast_subscriber_hears_the_nodes_puts_and_only_on_its_key() {
    let (mut node, node_out) = start_node();
    let (mut hears, hears_out) = start_pico("z_sub", BEAT, None, "Declaring Subscriber");
    let (mut other, other_out) =
        start_pico("z_sub", "lab/group/other", None, "Declaring Subscriber");

    let received = format!("Received ('{BEAT}': '{DOCUMENT}')");
    wait_until(
        "pico receiving the node's document three times",
        &hears_out,
        |seen| seen.matches(&received).count() >= 3,
    );
    // The node was admitted: it counts pico among its members.
    wait_until("the node admitting a member", &node_out, |seen| {
        seen.contains("members=1") || seen.contains("members=2")
    });
    // A pico subscriber of another key heard nothing of it, over the same group in the same time.
    assert_eq!(
        count(&other_out, "Received ("),
        0,
        "a subscriber of another key was told what was put on {BEAT}\n{}",
        read(&other_out)
    );
    for peer in [&mut hears, &mut other] {
        let _ = peer.child_mut().kill();
        let _ = peer.child_mut().wait();
    }
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}

// wz-proves: none -- the same node, for the same reason: its subscription over the group has no catalog atom
#[test]
#[ignore = "environment-dependent multicast e2e (the packaged slot-group, which Layer M makes, + the pico CLI); runs via --ignored"]
fn the_node_keeps_the_latest_sample_a_pico_multicast_publisher_puts() {
    let (mut node, node_out) = start_node();
    let (mut publisher, _publisher_out) =
        start_pico("z_pub", KEPT, Some(VALUE), "Declaring publisher");
    // A put on a key the node does not subscribe to, from a second pico peer on the same group.
    let (mut stranger, _stranger_out) = start_pico(
        "z_pub",
        "lab/group/not-mine",
        Some("NOT-FOR-THE-NODE"),
        "Declaring publisher",
    );

    let value_hex = hex(VALUE);
    wait_until(
        "the node keeping a sample of pico's put",
        &node_out,
        |seen| {
            seen.lines().any(|line| {
                line.starts_with(&format!("HOST-WZ-SAMPLE {KEPT} put "))
                    && line.contains(&value_hex)
            })
        },
    );
    // It keeps the LATEST: the sequence of the cell grows with every put, and each line is the
    // payload pico wrapped, so a later one is a later sample and not the first said again.
    wait_until("a second sample", &node_out, |seen| {
        seen.contains(" seq=2 ")
    });
    // And only that key: nothing the stranger put is in any sample the node says.
    std::thread::sleep(Duration::from_millis(1_500));
    let said = read(&node_out);
    assert!(
        !said.contains("lab/group/not-mine"),
        "the node kept a sample of a key it does not subscribe to\n{said}"
    );
    assert!(
        !said.contains(&hex("NOT-FOR-THE-NODE")),
        "what a stranger put reached the node's cell\n{said}"
    );
    for peer in [&mut publisher, &mut stranger] {
        let _ = peer.child_mut().kill();
        let _ = peer.child_mut().wait();
    }
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}

// wz-proves: none -- the same node, for the same reason: its view of the group's members has no catalog atom
#[test]
#[ignore = "environment-dependent multicast e2e (the packaged slot-group, which Layer M makes, + the pico CLI); runs via --ignored"]
fn the_node_counts_its_members_as_pico_joins_and_its_lease_runs_out() {
    let (mut node, node_out) = start_node();
    // Nobody else is on the group: the node has joined and has admitted no one.
    assert_eq!(members(&node_out), Some(0), "{}", read(&node_out));

    let (mut peer, _peer_out) =
        start_pico("z_pub", "lab/group/count", Some("x"), "Declaring publisher");
    wait_until("the node admitting pico", &node_out, |seen| {
        seen.contains("members=1")
    });
    assert_eq!(members(&node_out), Some(1), "{}", read(&node_out));

    // Pico goes without a Close: its lease, which its JOIN advertised, is what ends the membership.
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    wait_until("the node forgetting pico", &node_out, |seen| {
        seen.rsplit_once("members=")
            .is_some_and(|(_, tail)| tail.trim_start().starts_with('0'))
    });
    assert_eq!(members(&node_out), Some(0), "{}", read(&node_out));
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}
