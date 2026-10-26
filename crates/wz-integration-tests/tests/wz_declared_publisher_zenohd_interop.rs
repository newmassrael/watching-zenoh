// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that PUBLISHES, against the reference router: the document it
//! puts, how often, and that it starts again with the next session.
//!
//! The node is `slot-reporter` (`deploy/nodes/slot-reporter.toml`): a fixed-memory process with no
//! allocator that dials one router and, while the session is established, puts an eight-byte
//! document on `lab/out/beat` every 200 ms. The file Layer Z runs is the one the entry packaged
//! (`wz_package.py --node slot-reporter`), so what is proven is the artifact whose manifest was
//! verified.
//!
//! The router is zenohd 1.10.1 with its REST plugin, and the plugin's SSE stream is the subscriber:
//! a peer the node shares no code with decodes each put and renders it. Two legs:
//!
//! - the stream shows the declared document, eight bytes, again and again, and the time between two
//!   puts is the period and not a flood or a stall (the bounds are loose, a REST stream adds its
//!   own jitter, and tight enough that a node that sent on every event of the session or on a
//!   period of seconds fails);
//! - the second publisher's stream, declared at a rate with a body made for each put by the
//!   `counter` fill (`wz_workload`, played without an allocator), shows eight bytes that are the
//!   put's sequence number, each one more than the last (none lost, none repeated), at the rate;
//! - the router is stopped and started again: the node says its session was lost, dials the new
//!   router, and the puts start again at once with the next session.
//!
//! The locator is fixed in the node (`tcp/127.0.0.1:17472`), so the router listens there and the
//! legs run one at a time (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_REPORTER`), the reference zenohd and its REST
//! plugin (`scripts/build-zenohd.sh`). Runs on the `--ignored` lane; the file's `zenohd` token
//! keeps Layer E's sweep off it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    graceful_terminate, read_captured, rest_plugin, wait_for_substring, zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::free_port;

// The node is a deploy crate, which the barrier gate does not read as a producer: the lines it
// prints are declared here, each for the needle the tests wait for.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-PUBLISHED {} sent={} refused={} late_max_ms={}" for "HOST-WZ-PUBLISHED lab/out/beat sent="
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-PUBLISHED {} sent={} refused={} late_max_ms={}" for "HOST-WZ-PUBLISHED lab/out/count sent="

/// The router the node dials, as its declaration states it.
const ROUTER_PORT: u16 = 17472;
/// What the node prints once its session is up, and when it is lost.
const ESTABLISHED: &str = "slot-reporter: session established";
const LOST: &str = "slot-reporter: session lost";
/// The eight bytes of `x` the declaration puts, as the REST plugin renders a payload: the sample
/// carries no encoding of its own, so the plugin takes it as `zenoh/bytes` and writes base64.
const VALUE: &str = "eHh4eHh4eHg=";
/// The declared period.
const PERIOD: Duration = Duration::from_millis(200);
/// The gap of the counted stream: twenty puts a second.
const COUNT_GAP: Duration = Duration::from_millis(50);
/// How long the node may take to establish, and the router to learn it.
const ESTABLISH_BUDGET: Duration = Duration::from_secs(30);
/// How long a run of puts may take to come.
const PUTS_BUDGET: Duration = Duration::from_secs(20);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_REPORTER").expect(
        "WZ_DECLARED_NODE_REPORTER names the packaged slot-reporter (Layer Z builds it with \
         `wz_package.py --node slot-reporter`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

/// A router with the REST plugin on `rest_port`, listening where the node dials.
fn start_router(rest_port: u16) -> (ChildGuard, std::fs::File) {
    let plugin = rest_plugin();
    assert!(
        plugin.is_file(),
        "the REST plugin cdylib must exist at {}",
        plugin.display()
    );
    let out = tempfile::tempfile().expect("a capture for the router");
    let router = ChildGuard::wrap(
        "zenohd (reference router, REST plugin)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{ROUTER_PORT}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .arg("--cfg")
            .arg(format!("plugins/rest/http_port:\"{rest_port}\""))
            .arg("--cfg")
            .arg("plugins/rest/__required__:true")
            .stdout(Stdio::from(out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn zenohd"),
    );
    (router, out)
}

fn wait_for_rest(addr: SocketAddr, what: &str) {
    let until = Instant::now() + ESTABLISH_BUDGET;
    while Instant::now() < until {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the REST plugin never listened\n{what}");
}

/// The router's SSE stream of one key: each `PUT` event it renders, with the moment it arrived.
struct Sse {
    stream: TcpStream,
    pending: String,
    event: Option<String>,
}

impl Sse {
    fn open(addr: SocketAddr, key: &str) -> Self {
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect SSE");
        stream
            .write_all(
                format!("GET /{key} HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n")
                    .as_bytes(),
            )
            .expect("write the SSE request");
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("read timeout");
        Self {
            stream,
            pending: String::new(),
            event: None,
        }
    }

    /// The next `count` puts the stream shows, as (arrival, data), or fewer when `budget` runs out.
    fn puts(&mut self, count: usize, budget: Duration) -> Vec<(Instant, String)> {
        let until = Instant::now() + budget;
        let mut seen = Vec::new();
        let mut chunk = [0u8; 4096];
        while seen.len() < count && Instant::now() < until {
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => self.pending.push_str(&String::from_utf8_lossy(&chunk[..n])),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("read the SSE stream: {e}"),
            }
            while let Some(end) = self.pending.find('\n') {
                let line = self.pending[..end].trim().to_owned();
                self.pending.drain(..=end);
                if let Some(name) = line.strip_prefix("event:") {
                    self.event = Some(name.trim().to_owned());
                } else if let Some(data) = line.strip_prefix("data:") {
                    if self.event.as_deref() == Some("PUT") {
                        seen.push((Instant::now(), data.trim().to_owned()));
                    }
                }
            }
        }
        seen
    }
}

/// The node and a router, with the node's output captured.
struct Fixture {
    node_out: std::fs::File,
    router_out: std::fs::File,
    node: ChildGuard,
    router: ChildGuard,
    rest: SocketAddr,
}

impl Fixture {
    fn start() -> Self {
        let mut node_out = tempfile::tempfile().expect("a capture for the node");
        let node = ChildGuard::wrap(
            "slot-reporter (declared node)",
            Command::new(node_binary())
                .stdout(Stdio::from(node_out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(node_out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn the node"),
        );
        let rest_port = free_port();
        let (router, router_out) = start_router(rest_port);
        let fixture = Self {
            node_out: node_out.try_clone().expect("dup capture"),
            router_out,
            node,
            router,
            rest: format!("127.0.0.1:{rest_port}")
                .parse()
                .expect("an address"),
        };
        if wait_for_substring(&mut node_out, ESTABLISHED, ESTABLISH_BUDGET).is_err() {
            panic!(
                "the node established no session within {ESTABLISH_BUDGET:?}\n{}",
                fixture.report()
            );
        }
        wait_for_rest(fixture.rest, &fixture.report());
        fixture
    }

    fn report(&self) -> String {
        let (mut node, mut router) = (
            self.node_out.try_clone().expect("dup"),
            self.router_out.try_clone().expect("dup"),
        );
        format!(
            "--- node ---\n{}\n--- zenohd ---\n{}",
            read_captured(&mut node),
            read_captured(&mut router)
        )
    }

    fn node_says(&self, needle: &str, budget: Duration) -> bool {
        let mut capture = self.node_out.try_clone().expect("dup");
        wait_for_substring(&mut capture, needle, budget).is_ok()
    }

    fn finish(mut self) {
        graceful_terminate(self.node.child_mut(), Duration::from_secs(5));
        graceful_terminate(self.router.child_mut(), Duration::from_secs(5));
    }
}

/// The puts of one run are all the declared document, and the time between two is the period.
fn assert_cadence(puts: &[(Instant, String)], wanted: usize, report: &str) {
    assert!(
        puts.len() >= wanted,
        "the stream showed {} put(s) in {PUTS_BUDGET:?}, not {wanted}\n{report}",
        puts.len()
    );
    for (_, data) in puts {
        assert!(
            data.contains(VALUE),
            "a put is not the declared document ({VALUE}): {data}\n{report}"
        );
    }
    for pair in puts.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            gap >= PERIOD / 2 && gap <= PERIOD * 4,
            "two puts are {gap:?} apart, the period is {PERIOD:?}\n{report}"
        );
    }
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its publisher is the slot profile's own seam (wz_session_mcu::slot_publisher), and the catalog's pubsub atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the packaged slot-reporter, which Layer Z makes, + zenohd and its REST plugin); runs via --ignored"]
fn zenohd_sees_the_declared_document_on_the_declared_period() {
    let fx = Fixture::start();
    let mut sse = Sse::open(fx.rest, "lab/out/beat");
    let puts = sse.puts(6, PUTS_BUDGET);
    assert_cadence(&puts, 6, &fx.report());
    assert!(
        fx.node_says(
            "HOST-WZ-PUBLISHED lab/out/beat sent=",
            Duration::from_secs(5)
        ),
        "the node did not say what it published\n{}",
        fx.report()
    );
    fx.finish();
}

/// The sequence number a put of the counted stream carries: the `value` the REST plugin renders,
/// base64 of eight bytes, read little-endian. `None` for anything else.
fn sequence_of(data: &str) -> Option<u64> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let start = data.find("\"value\":\"")? + "\"value\":\"".len();
    let text = &data[start..start + data[start..].find('"')?];
    let mut bits = Vec::new();
    for c in text.trim_end_matches('=').bytes() {
        let six = ALPHABET.iter().position(|&a| a == c)?;
        bits.extend((0..6).rev().map(|at| (six >> at) & 1));
    }
    let bytes: Vec<u8> = bits
        .chunks_exact(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &bit| acc << 1 | bit as u8))
        .collect();
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

// wz-proves: none -- the same node, for the same reason: the publisher of the fixed-memory profile has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-reporter, which Layer Z makes, + zenohd and its REST plugin); runs via --ignored"]
fn zenohd_sees_the_made_stream_in_order_at_its_rate() {
    let fx = Fixture::start();
    let mut sse = Sse::open(fx.rest, "lab/out/count");
    let puts = sse.puts(20, PUTS_BUDGET);
    let report = fx.report();
    assert!(
        puts.len() >= 20,
        "the stream showed {} put(s) in {PUTS_BUDGET:?}, not 20\n{report}",
        puts.len()
    );
    let sequence: Vec<u64> = puts
        .iter()
        .map(|(_, data)| {
            sequence_of(data)
                .unwrap_or_else(|| panic!("a put is not eight counted bytes: {data}\n{report}"))
        })
        .collect();
    for pair in sequence.windows(2) {
        assert_eq!(
            pair[1],
            pair[0] + 1,
            "the counted stream skipped or repeated a put: {sequence:?}\n{report}"
        );
    }
    // Nineteen gaps of 50 ms: a node that flooded, or that put one a period of the clock's
    // rounding, is far outside a factor of two either way.
    let span = puts[puts.len() - 1].0.duration_since(puts[0].0);
    assert!(
        span >= COUNT_GAP * 19 / 2 && span <= COUNT_GAP * 19 * 2,
        "twenty puts took {span:?}, the rate gives {:?}\n{report}",
        COUNT_GAP * 19
    );
    assert!(
        fx.node_says(
            "HOST-WZ-PUBLISHED lab/out/count sent=",
            Duration::from_secs(5)
        ),
        "the node did not say what it published\n{report}"
    );
    fx.finish();
}

// wz-proves: none -- the same node, for the same reason: the publisher of the fixed-memory profile has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-reporter, which Layer Z makes, + zenohd and its REST plugin); runs via --ignored"]
fn zenohd_restarted_the_publisher_starts_again_with_the_next_session() {
    let mut fx = Fixture::start();
    let mut sse = Sse::open(fx.rest, "lab/out/beat");
    assert_cadence(&sse.puts(3, PUTS_BUDGET), 3, &fx.report());

    // The router goes away: the node says its session is lost.
    graceful_terminate(fx.router.child_mut(), Duration::from_secs(5));
    assert!(
        fx.node_says(LOST, ESTABLISH_BUDGET),
        "the node did not notice its router had gone\n{}",
        fx.report()
    );

    // A router comes up where the node dials: the node dials it, and puts at once.
    let rest_port = free_port();
    let (router, router_out) = start_router(rest_port);
    fx.router = router;
    fx.router_out = router_out;
    fx.rest = format!("127.0.0.1:{rest_port}")
        .parse()
        .expect("an address");
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let mut capture = fx.node_out.try_clone().expect("dup");
        if read_captured(&mut capture).matches(ESTABLISHED).count() >= 2 {
            break;
        }
        assert!(
            Instant::now() < until,
            "the node never established a second session\n{}",
            fx.report()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    wait_for_rest(fx.rest, &fx.report());
    let mut again = Sse::open(fx.rest, "lab/out/beat");
    assert_cadence(&again.puts(3, PUTS_BUDGET), 3, &fx.report());
    fx.finish();
}
