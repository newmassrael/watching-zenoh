// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that says it is ALIVE, against the reference router and stock
//! watchers: the tokens it declares, that the router keeps them as long as the session lasts, and that
//! they come back with the next session.
//!
//! The node is `slot-beacon` (`deploy/nodes/slot-beacon.toml`): a fixed-memory process with no
//! allocator that dials one router and declares four liveliness tokens (`lab/alive/a` to `lab/alive/d`)
//! and a queryable on every session. The file Layer Z runs is the one the entry packaged
//! (`wz_package.py --node slot-beacon`), so what is proven is the artifact whose manifest was verified.
//!
//! The two peers are upstream's own examples, which share no code with wz: `z_sub_liveliness`, a client
//! of the router that says when a token appears and when it is dropped, and `z_get_liveliness`, which
//! asks the router for the tokens alive now. Two legs:
//!
//! - the watcher sees the four tokens appear when the node's session is established, in turns (the
//!   node is declared with the `declaration-sync-pacing` policy, two declarations a turn and half a
//!   second between turns, so a router that holds some of them and not all is seen, and the last comes
//!   about a second after the first), and nothing else;
//!   `z_get_liveliness` lists exactly those four on the pattern that covers them, exactly one on a key
//!   that names one, and none on a key nothing declared, so the answer is the router's table and not an
//!   echo; the node is stopped, and the watcher sees the four dropped and the table is empty, which is
//!   the router dropping a token with its session;
//! - the node is started again: the watcher sees the four appear a second time, and the query lists
//!   them again, so the tokens come back with the next session.
//!
//! The locator is fixed in the node (`tcp/127.0.0.1:17474`), so the router listens there and the legs
//! run one at a time (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_BEACON`), the reference zenohd and the stock examples
//! (`scripts/build-zenohd.sh`). Runs on the `--ignored` lane; the file's `zenohd` token keeps Layer
//! E's sweep off it.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_tcp_accept_alive,
    zenoh_core_example_binary, zenohd_binary, ChildGuard,
};

// The watcher's ready line is upstream's, from its own example.
// barrier-origin: zenohd "Declaring Liveliness Subscriber" -- `examples/examples/z_sub_liveliness.rs` @ `Declaring Liveliness Subscriber`

/// The router the node dials, as its declaration states it.
const ROUTER_PORT: u16 = 17474;
/// What the node prints once its session is up.
const ESTABLISHED: &str = "slot-beacon: session established";
/// What the stock watcher prints once it has declared its subscriber.
const WATCHER_READY: &str = "Declaring Liveliness Subscriber";
/// The tokens the node declares, as its declaration states them.
const KEYS: [&str; 4] = ["lab/alive/a", "lab/alive/b", "lab/alive/c", "lab/alive/d"];
/// How long the node may take to establish, and the router to tell the watcher.
const BUDGET: Duration = Duration::from_secs(30);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_BEACON").expect(
        "WZ_DECLARED_NODE_BEACON names the packaged slot-beacon (Layer Z builds it with \
         `wz_package.py --node slot-beacon`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

fn endpoint() -> String {
    format!("tcp/127.0.0.1:{ROUTER_PORT}")
}

/// What the watcher says of a token that appeared.
fn appeared(key: &str) -> String {
    format!("New alive token ('{key}')")
}

/// What the watcher says of a token that was dropped.
fn dropped(key: &str) -> String {
    format!("Dropped token ('{key}')")
}

/// How many times `needle` is in `capture`.
fn count(capture: &File, needle: &str) -> usize {
    read_captured(&mut capture.try_clone().expect("dup capture"))
        .matches(needle)
        .count()
}

/// Wait until `done` holds of what `capture` has so far, or `BUDGET` runs out and say why.
fn wait_until(
    what: &str,
    capture: &File,
    report: impl Fn() -> String,
    done: impl Fn(&str) -> bool,
) {
    let until = Instant::now() + BUDGET;
    loop {
        if done(&read_captured(
            &mut capture.try_clone().expect("dup capture"),
        )) {
            return;
        }
        assert!(
            Instant::now() < until,
            "{what} did not happen within {BUDGET:?}\n{}",
            report()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A router that listens where the node dials.
fn start_router() -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("a capture for the router");
    let mut router = ChildGuard::wrap(
        "zenohd (reference router)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(endpoint())
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn zenohd"),
    );
    wait_for_tcp_accept_alive(router.child_mut(), ROUTER_PORT, BUDGET)
        .unwrap_or_else(|why| panic!("zenohd never listened: {why}"));
    (router, out)
}

/// The stock watcher of tokens under `lab/alive/**`, a client of the router, once it has declared.
/// Retried on a transient open failure, which is a flake and not a finding.
fn start_watcher() -> (ChildGuard, File) {
    let binary = zenoh_core_example_binary("z_sub_liveliness");
    for attempt in 1..=6 {
        let out = tempfile::tempfile().expect("a capture for the watcher");
        let mut watcher = ChildGuard::wrap(
            "z_sub_liveliness (stock zenoh)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&binary)
                .args(["-k", "lab/alive/**", "-m", "client", "-e"])
                .arg(endpoint())
                .arg("--no-multicast-scouting")
                .stdout(Stdio::from(out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn z_sub_liveliness"),
        );
        let mut reader = out.try_clone().expect("dup capture");
        if wait_for_substring(&mut reader, WATCHER_READY, Duration::from_secs(10)).is_ok() {
            return (watcher, out);
        }
        let _ = watcher.child_mut().kill();
        let _ = watcher.child_mut().wait();
        eprintln!("z_sub_liveliness open attempt {attempt}/6 did not declare; retrying");
    }
    panic!("the stock watcher never declared its subscriber");
}

/// The node, with its output captured, dialling the router.
fn start_node() -> (ChildGuard, File) {
    let out = tempfile::tempfile().expect("a capture for the node");
    let node = ChildGuard::wrap(
        "slot-beacon (declared node)",
        Command::new(node_binary())
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the node"),
    );
    (node, out)
}

/// What the stock `z_get_liveliness` lists as alive under `key` now: the keys it printed.
fn alive(key: &str) -> Vec<String> {
    let output = Command::new(zenoh_core_example_binary("z_get_liveliness"))
        .args(["-k", key, "-o", "3000", "-m", "client", "-e"])
        .arg(endpoint())
        .arg("--no-multicast-scouting")
        .output_bounded()
        .expect("run z_get_liveliness");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut keys: Vec<String> = text
        .lines()
        .filter_map(|line| line.strip_prefix(">> Alive token ('")?.strip_suffix("')"))
        .map(str::to_owned)
        .collect();
    keys.sort();
    assert!(
        output.status.success(),
        "z_get_liveliness failed: {}\n{text}",
        String::from_utf8_lossy(&output.stderr)
    );
    keys
}

/// Everything a failing run has to say, in one block.
struct Run {
    node: File,
    watcher: File,
    router: File,
}

impl Run {
    fn report(&self) -> String {
        let read = |file: &File| read_captured(&mut file.try_clone().expect("dup capture"));
        format!(
            "--- node ---\n{}\n--- watcher ---\n{}\n--- zenohd ---\n{}",
            read(&self.node),
            read(&self.watcher),
            read(&self.router)
        )
    }
}

fn expected() -> Vec<String> {
    KEYS.iter().map(|k| (*k).to_owned()).collect()
}

/// How long the node's replay of its declarations is held back between its turns, as its
/// declaration states it (`DECLARATION_SYNC_INTERVAL_MS`), and how many turns the five declarations
/// of a session (a document and four tokens, two to a turn) take: the first and the last token are
/// two intervals apart.
const REPLAY_SPAN_FLOOR: Duration = Duration::from_millis(800);

/// How the four tokens reach the watcher: how long from the first of them to the last, and whether
/// some look at the watcher found some of them and not yet all. A node that tells its declarations in
/// one go has both at nothing; one that tells them in turns shows a router that holds a part.
fn tokens_arrive(run: &Run) -> (Duration, bool) {
    let until = Instant::now() + BUDGET;
    let mut first: Option<Instant> = None;
    let mut partial = false;
    loop {
        let seen = read_captured(&mut run.watcher.try_clone().expect("dup capture"));
        let held = KEYS.iter().filter(|k| seen.contains(&appeared(k))).count();
        if held > 0 && first.is_none() {
            first = Some(Instant::now());
        }
        if held == KEYS.len() {
            return (first.map_or(Duration::ZERO, |at| at.elapsed()), partial);
        }
        partial |= held > 0;
        assert!(
            Instant::now() < until,
            "the four tokens appearing did not happen within {BUDGET:?}\n{}",
            run.report()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its token is the slot profile's own declaration (wz_session_core::lent_control::declare_token), and the catalog's liveliness atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the packaged slot-beacon, which Layer Z makes, + zenohd and the stock liveliness examples); runs via --ignored"]
fn zenohd_sees_the_four_tokens_appear_and_drop_with_the_nodes_session() {
    let (_router, router_out) = start_router();
    let (_watcher, watcher_out) = start_watcher();
    let (mut node, node_out) = start_node();
    let run = Run {
        node: node_out,
        watcher: watcher_out,
        router: router_out,
    };

    // The four tokens appear, in turns: the router holds some of them before it holds all, and the
    // last comes two intervals after the first. The node is built with the pacing policy on, and
    // this is how the binary shows it.
    let (span, partial) = tokens_arrive(&run);
    assert!(
        partial,
        "a router that held some of the tokens and not all was never seen: the node told its \
         declarations in one go\n{}",
        run.report()
    );
    assert!(
        span >= REPLAY_SPAN_FLOOR,
        "the four tokens arrived within {span:?}, less than the {REPLAY_SPAN_FLOOR:?} the node's \
         turns are apart\n{}",
        run.report()
    );
    // Each appears once, and nothing else does.
    assert!(
        wait_for_substring(&mut run.node.try_clone().expect("dup"), ESTABLISHED, BUDGET).is_ok(),
        "the node did not say its session was established\n{}",
        run.report()
    );
    for key in KEYS {
        assert_eq!(
            count(&run.watcher, &appeared(key)),
            1,
            "{key} appeared once\n{}",
            run.report()
        );
    }
    assert_eq!(
        count(&run.watcher, "New alive token"),
        4,
        "a token appeared that the node did not declare\n{}",
        run.report()
    );

    // The router's table: the four on the pattern, one on a key, none on a key nothing declared.
    assert_eq!(alive("lab/alive/**"), expected(), "{}", run.report());
    assert_eq!(
        alive("lab/alive/b"),
        vec!["lab/alive/b".to_owned()],
        "{}",
        run.report()
    );
    assert!(alive("lab/other/**").is_empty(), "{}", run.report());

    // The node goes: the four are dropped and the table is empty.
    graceful_terminate(node.child_mut(), Duration::from_secs(5));
    wait_until(
        "the four tokens being dropped",
        &run.watcher,
        || run.report(),
        |seen| KEYS.iter().all(|k| seen.contains(&dropped(k))),
    );
    assert!(
        alive("lab/alive/**").is_empty(),
        "a token outlived its session\n{}",
        run.report()
    );
}

// wz-proves: none -- the same node, for the same reason: the token of the fixed-memory profile has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-beacon, which Layer Z makes, + zenohd and the stock liveliness examples); runs via --ignored"]
fn zenohd_a_restarted_node_declares_its_tokens_again_with_the_next_session() {
    let (_router, router_out) = start_router();
    let (_watcher, watcher_out) = start_watcher();
    let (mut first, first_out) = start_node();
    let run = Run {
        node: first_out,
        watcher: watcher_out,
        router: router_out,
    };
    wait_until(
        "the four tokens appearing",
        &run.watcher,
        || run.report(),
        |seen| KEYS.iter().all(|k| seen.contains(&appeared(k))),
    );

    // The node goes and a node comes up in its place: the four are dropped and then appear again.
    graceful_terminate(first.child_mut(), Duration::from_secs(5));
    wait_until(
        "the four tokens being dropped",
        &run.watcher,
        || run.report(),
        |seen| KEYS.iter().all(|k| seen.contains(&dropped(k))),
    );
    let (mut second, _second_out) = start_node();
    wait_until(
        "the four tokens appearing again",
        &run.watcher,
        || run.report(),
        |seen| KEYS.iter().all(|k| seen.matches(&appeared(k)).count() >= 2),
    );
    assert_eq!(alive("lab/alive/**"), expected(), "{}", run.report());
    graceful_terminate(second.child_mut(), Duration::from_secs(5));
}
