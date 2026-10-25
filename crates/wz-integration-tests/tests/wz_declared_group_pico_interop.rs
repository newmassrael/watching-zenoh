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
//!   once pico has left (its lease runs out, since the CLI says no Close when it is stopped);
//! - a put longer than the batch, which pico cuts into a Fragment chain, is put back together and
//!   kept (the whole length is said, the cell keeps what it holds), one that fits a frame is kept
//!   the same way, and one longer than the reassembly slot (4,096 bytes) is dropped whole.
//!
//! Multicast needs a route on the host: the legs run on the interface the default route uses, as
//! pico's `#iface=` names it and as the node's own join (the kernel's routing) picks it, so both meet
//! on the one link. The environment decides, so the legs run on the opt-in Layer M, one at a time
//! (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_GROUP`) and the pico CLI
//! (`scripts/build-zenoh-pico-cli.sh`). Every test fn here carries `multicast` in its name, which
//! is the token Layer E's `--ignored` sweep skips by: a leg named without it is selected by that
//! sweep, which has no packaged node, and fails on the missing variable (hosted run 40163531279).

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    default_route_iface, graceful_terminate, read_captured, wait_for_substring,
    zenoh_pico_cli_binary, ChildGuard, ZENOH_MULTICAST_GROUP,
};

// The node says every change of its group; the leg waits for the join.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-GROUP {} joins={} refused={} turned_away={} members={}" for "joins=1"

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

/// The `turned_away=` the node last said, or none.
fn turned_away(node: &File) -> Option<u32> {
    read(node)
        .lines()
        .filter(|line| line.starts_with("HOST-WZ-GROUP "))
        .filter_map(|line| {
            let tail = line.split_once("turned_away=")?.1;
            tail.split_whitespace().next()?.parse().ok()
        })
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
fn the_multicast_node_keeps_the_latest_sample_a_pico_publisher_puts() {
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
fn the_multicast_node_counts_its_members_as_pico_joins_and_its_lease_runs_out() {
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

/// How many members the node's table has rows for, as its declaration states.
const MEMBER_ROWS: usize = 8;

// wz-proves: none -- the same node, for the same reason: its view of the group's members has no catalog atom
#[test]
#[ignore = "environment-dependent multicast e2e (the packaged slot-group, which Layer M makes, + the pico CLI); runs via --ignored"]
fn the_multicast_node_says_its_member_table_is_full_when_it_turns_a_peer_away() {
    let (mut node, node_out) = start_node();
    // As many pico peers as the table has rows: every one is admitted and nobody is turned away.
    let mut peers = Vec::new();
    for at in 0..MEMBER_ROWS {
        let key = format!("lab/group/full/{at}");
        peers.push(start_pico("z_pub", &key, Some("x"), "Declaring publisher"));
    }
    let rows = MEMBER_ROWS.to_string();
    wait_until(
        "the node admitting every peer its table has a row for",
        &node_out,
        |seen| seen.contains(&format!("members={rows}")),
    );
    assert_eq!(
        members(&node_out),
        Some(MEMBER_ROWS as u32),
        "{}",
        read(&node_out)
    );
    assert_eq!(
        turned_away(&node_out),
        Some(0),
        "a peer for each row is nobody turned away\n{}",
        read(&node_out)
    );

    // One more than the table holds: its JOIN finds no row, the node says so, and the table does not
    // grow.
    peers.push(start_pico(
        "z_pub",
        "lab/group/full/over",
        Some("x"),
        "Declaring publisher",
    ));
    wait_until(
        "the node counting the peer it had no row for",
        &node_out,
        |_| turned_away(&node_out).is_some_and(|turned| turned >= 1),
    );
    assert_eq!(
        members(&node_out),
        Some(MEMBER_ROWS as u32),
        "a peer past the table is not a member\n{}",
        read(&node_out)
    );
    drop(peers);
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}

/// One put of `bytes` bytes of `fill` on `KEPT`, from a pico peer of its own that joins the group,
/// puts once and leaves (its lease, not a Close, ends its membership). `z_put` takes the whole value
/// as the payload, where `z_pub` cuts it to 255 bytes, so this is how a put longer than the batch is
/// made.
fn put_once(bytes: usize, fill: char) {
    let value = fill.to_string().repeat(bytes);
    let output = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary("z_put"))
        .args(["-k", KEPT, "-v", &value, "-l", &locator(), "-m", "peer"])
        .output_bounded()
        .expect("run z_put");
    assert!(
        output.status.success(),
        "z_put failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Put `bytes` bytes of `fill` until the node says a sample of that whole length, trying a few
/// peers (a first put can precede the node's admission of its JOIN); whether it said one by then.
fn put_until_kept(node: &File, bytes: usize, fill: char) -> bool {
    let line = format!("HOST-WZ-SAMPLE {KEPT} put len={bytes} ");
    for _ in 0..3 {
        put_once(bytes, fill);
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if read(node).contains(&line) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    false
}

// wz-proves: none -- the same node, for the same reason: reassembly on the group has no catalog atom for the fixed-memory profile
#[test]
#[ignore = "environment-dependent multicast e2e (the packaged slot-group, which Layer M makes, + the pico CLI); runs via --ignored"]
fn the_multicast_node_reassembles_a_put_pico_cuts_into_fragments_and_drops_one_too_long() {
    let (mut node, node_out) = start_node();

    // A put that fits one frame arrives whole and is kept: the cell holds 64 bytes of it and the
    // line says the 1,000 it was. (Pico cuts at the link's MTU, about 1,470 bytes, before it cuts at
    // the batch of 2,048, so a put a little over a thousand is the last that is not a chain.)
    assert!(
        put_until_kept(&node_out, 1_000, 'A'),
        "a put that fits one frame was not kept\n{}",
        read(&node_out)
    );
    // A put of 3,000 bytes is past the batch, so pico sends it as a Fragment chain, and the node puts
    // it back together: the same line, with the whole length.
    assert!(
        put_until_kept(&node_out, 3_000, 'B'),
        "a put pico fragmented was not reassembled\n{}",
        read(&node_out)
    );
    let said = read(&node_out);
    assert!(
        said.lines().any(|line| line
            .starts_with(&format!("HOST-WZ-SAMPLE {KEPT} put len=3000 kept=64 "))
            && line.contains(&hex(&"B".repeat(64)))),
        "the reassembled put is not the bytes pico put\n{said}"
    );
    // A put past the reassembly slot (4,096 bytes) is dropped whole: nothing of it is kept, and the
    // node still takes the next put, so the drop did not wedge the chain table.
    put_once(5_000, 'C');
    put_once(5_000, 'C');
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !read(&node_out).contains("len=5000"),
        "a put longer than the reassembly slot was kept\n{}",
        read(&node_out)
    );
    assert!(
        put_until_kept(&node_out, 2_500, 'D'),
        "the node stopped taking puts after a chain it dropped\n{}",
        read(&node_out)
    );
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}
