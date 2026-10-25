// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that LISTENS, against stock zenoh clients: it takes the
//! connections that arrive, answers their queries, holds as many sessions as it declared and no more,
//! and gives a row back when a session ends or never begins.
//!
//! The node is `slot-server` (`deploy/nodes/slot-server.toml`): a fixed-memory process with no
//! allocator that dials nothing, listens on `tcp/127.0.0.1:17475`, holds two sessions at once
//! (`accepts = 2`) and answers `lab/server/small` (16 bytes) and `lab/server/large` (256 bytes). The
//! file Layer Z runs is the one the entry packaged (`wz_package.py --node slot-server`), so what is
//! proven is the artifact whose manifest was verified.
//!
//! The peers are upstream's own examples, which share no code with wz: `z_get` and `z_pub` as clients
//! of the node. A stock client refuses another client, so a reply at all is the node presenting itself
//! as a peer. Three legs:
//!
//! - a stock `z_get` is answered with each document, byte for byte, and gets no reply for a key the
//!   node does not serve, so the answer is the node's table and not an echo;
//! - two stock clients hold the node's two sessions; a third is refused (its connection is closed,
//!   which a client reports as a failed open, well inside the handshake deadline); one holder leaves,
//!   the node says its session was lost, and the next client is served in the row it left;
//! - two connections that say nothing are closed at the handshake deadline, which frees both rows:
//!   the next client is served at once.
//!
//! The locator is fixed in the node (`tcp/127.0.0.1:17475`), so the legs run one at a time
//! (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_SERVER`) and the stock examples
//! (`scripts/build-zenohd.sh`). Runs on the `--ignored` lane; the file's `zenohd` token keeps Layer
//! E's sweep off it.

use std::fs::File;
use std::io::Read;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_tcp_accept_alive,
    zenoh_core_example_binary, ChildGuard,
};

// The node says it listens once the port is bound.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-LISTEN {LISTEN}" for "HOST-WZ-LISTEN tcp/127.0.0.1:17475"

/// The port the node listens on, as its declaration states it.
const PORT: u16 = 17475;
/// What the node prints once its port is bound.
const LISTENING: &str = "HOST-WZ-LISTEN tcp/127.0.0.1:17475";
/// What the node prints when a session establishes.
const ESTABLISHED: &str = "slot-server: session established";
/// What the node prints when a session ends.
const LOST: &str = "slot-server: session lost";
/// The documents the node answers with, as its declaration states them: (key, bytes).
const SMALL: (&str, usize) = ("lab/server/small", 16);
const LARGE: (&str, usize) = ("lab/server/large", 256);
/// How long the node may take to start listening, to establish, and to notice a session is gone.
const BUDGET: Duration = Duration::from_secs(30);
/// A refused connection is closed at once; a client that was not refused has until the handshake
/// deadline (a second) to be, so a failed open that takes longer than this was not a refusal.
const REFUSAL_WITHIN: Duration = Duration::from_millis(800);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_SERVER").expect(
        "WZ_DECLARED_NODE_SERVER names the packaged slot-server (Layer Z builds it with \
         `wz_package.py --node slot-server`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

fn endpoint() -> String {
    format!("tcp/127.0.0.1:{PORT}")
}

/// The node, with its output captured, once it listens.
fn start_node() -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("a capture for the node");
    let mut node = ChildGuard::wrap(
        "slot-server (declared node)",
        Command::new(node_binary())
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the node"),
    );
    wait_for_substring(&mut out.try_clone().expect("dup"), LISTENING, BUDGET)
        .unwrap_or_else(|why| panic!("the node never said it listens: {why:?}"));
    wait_for_tcp_accept_alive(node.child_mut(), PORT, BUDGET)
        .unwrap_or_else(|why| panic!("the node's port never took a connection: {why:?}"));
    (node, out)
}

/// What a stock `z_get` of `key` came to: whether it opened a session, what it printed, how long it
/// took.
struct Asked {
    opened: bool,
    replies: Vec<(String, String)>,
    took: Duration,
    text: String,
}

/// Ask the node for `key` as a stock client.
fn ask(key: &str) -> Asked {
    let began = Instant::now();
    let output = Command::new(zenoh_core_example_binary("z_get"))
        .args(["-s", key, "-o", "3000", "-m", "client", "-e"])
        .arg(endpoint())
        .arg("--no-multicast-scouting")
        .output_bounded()
        .expect("run z_get");
    let took = began.elapsed();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let replies = text
        .lines()
        .filter_map(|line| line.strip_prefix(">> Received ('")?.strip_suffix("')"))
        .filter_map(|body| body.split_once("': '"))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    Asked {
        opened: output.status.success(),
        replies,
        took,
        text,
    }
}

/// A stock client that holds a session to the node open until it is stopped: a publisher, once its
/// first put has gone out, which it makes only on an open session, so the node's session with it is
/// established by then.
fn hold_session() -> ChildGuard {
    let out = tempfile::tempfile().expect("a capture for the holder");
    let holder = ChildGuard::wrap(
        "z_pub (stock client holding a session)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_core_example_binary("z_pub"))
            .args(["-k", "lab/hold/beat", "-m", "client", "-e"])
            .arg(endpoint())
            .arg("--no-multicast-scouting")
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn z_pub"),
    );
    wait_for_substring(&mut out.try_clone().expect("dup"), "Putting Data", BUDGET)
        .unwrap_or_else(|why| panic!("the holder never opened its session: {why:?}"));
    holder
}

/// How many times `needle` is in what `capture` has so far.
fn count(capture: &File, needle: &str) -> usize {
    read_captured(&mut capture.try_clone().expect("dup capture"))
        .matches(needle)
        .count()
}

/// Wait until `needle` has been said `times` times, or `BUDGET` runs out and say what was.
fn wait_for_count(capture: &File, needle: &str, times: usize) {
    let until = Instant::now() + BUDGET;
    while count(capture, needle) < times {
        assert!(
            Instant::now() < until,
            "`{needle}` was not said {times} time(s) within {BUDGET:?}\n--- node ---\n{}",
            read_captured(&mut capture.try_clone().expect("dup capture"))
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its listener and its accepted sessions are the slot profile's own, and the catalog's accept atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the packaged slot-server, which Layer Z makes, + the stock z_get); runs via --ignored"]
fn zenohd_stock_client_gets_the_documents_of_the_listening_node() {
    let (mut node, node_out) = start_node();

    for (key, bytes) in [SMALL, LARGE] {
        let asked = ask(key);
        assert!(
            asked.opened,
            "z_get did not open a session:\n{}",
            asked.text
        );
        assert_eq!(
            asked.replies,
            vec![(key.to_owned(), "x".repeat(bytes))],
            "the document of {key}\n{}",
            asked.text
        );
    }
    // A key the node does not serve gets no reply: the node's table is what answered.
    let none = ask("lab/server/none");
    assert!(none.opened, "z_get did not open a session:\n{}", none.text);
    assert!(
        none.replies.is_empty(),
        "a reply for a key nobody serves: {:?}",
        none.replies
    );
    // Every client was a session of its own, and every one ended.
    wait_for_count(&node_out, ESTABLISHED, 3);
    wait_for_count(&node_out, LOST, 3);
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}

// wz-proves: none -- the same node, for the same reason: the table of accepted sessions has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-server, which Layer Z makes, + the stock z_get and z_pub); runs via --ignored"]
fn zenohd_listening_node_holds_two_sessions_refuses_a_third_and_reuses_a_freed_row() {
    let (mut node, node_out) = start_node();

    let mut first = hold_session();
    let mut second = hold_session();
    assert_eq!(
        count(&node_out, ESTABLISHED),
        1,
        "the node says a session established when it first holds one, and not for each"
    );

    // Both rows are taken: a third client's connection is accepted and closed, which it reports as
    // a failed open, at once and not at the handshake deadline.
    let refused = ask(SMALL.0);
    assert!(
        !refused.opened && refused.replies.is_empty(),
        "a third client was served by a node that holds two sessions:\n{}",
        refused.text
    );
    assert!(
        refused.took < REFUSAL_WITHIN + Duration::from_secs(1),
        "the refusal took {:?}: the connection was held, not closed\n{}",
        refused.took,
        refused.text
    );
    assert_eq!(
        count(&node_out, LOST),
        0,
        "a session was lost to a refusal: the refused client was never one"
    );

    // One holder leaves and the next client is served in the row it left: the node notices the Close
    // within a few of its rounds, so a client that comes at once may still meet the full table and
    // is let try again.
    graceful_terminate(first.child_mut(), Duration::from_secs(5));
    let until = Instant::now() + BUDGET;
    let served = loop {
        let asked = ask(LARGE.0);
        if asked.opened || Instant::now() > until {
            break asked;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(served.opened, "no row came back:\n{}", served.text);
    assert_eq!(
        served.replies,
        vec![(LARGE.0.to_owned(), "x".repeat(LARGE.1))],
        "{}",
        served.text
    );

    // The holder that stayed was never disturbed: the node has not lost its last session. It does
    // when that one goes.
    assert!(
        second
            .child_mut()
            .try_wait()
            .expect("poll the holder")
            .is_none(),
        "the holder that stayed ended"
    );
    assert_eq!(
        count(&node_out, LOST),
        0,
        "a session was lost while the second holder still held its own"
    );
    graceful_terminate(second.child_mut(), Duration::from_secs(5));
    wait_for_count(&node_out, LOST, 1);
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}

// wz-proves: none -- the same node, for the same reason: the handshake deadline of an accepted session has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-server, which Layer Z makes, + the stock z_get); runs via --ignored"]
fn zenohd_listening_node_frees_the_rows_of_connections_that_say_nothing() {
    let (mut node, _node_out) = start_node();

    // Two connections that send no InitSyn take both rows until the handshake deadline.
    let mut silent: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(("127.0.0.1", PORT)).expect("a connection"))
        .collect();
    for stream in &mut silent {
        stream
            .set_read_timeout(Some(BUDGET))
            .expect("a read timeout");
        // The node closes the connection when the deadline passes: a read of nothing.
        let mut byte = [0u8; 1];
        let got = stream
            .read(&mut byte)
            .expect("the node closed the connection");
        assert_eq!(
            got, 0,
            "the node said something to a client that said nothing"
        );
    }
    // Both rows are free again.
    let asked = ask(SMALL.0);
    assert!(asked.opened, "no row came back:\n{}", asked.text);
    assert_eq!(
        asked.replies,
        vec![(SMALL.0.to_owned(), "x".repeat(SMALL.1))],
        "{}",
        asked.text
    );
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
}
