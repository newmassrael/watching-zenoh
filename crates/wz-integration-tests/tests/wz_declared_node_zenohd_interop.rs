// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration, against the reference router: what a declared subscription
//! keeps, and what a queryable that answers from it says.
//!
//! The node is `slot-recorder` (`deploy/nodes/slot-recorder.toml`): a fixed-memory process with no
//! allocator that dials one router, subscribes to `lab/in/temp` (keeping the latest 64 bytes of a
//! payload) and answers a query under the same key from what it kept. The file Layer Z runs is
//! the one the entry packaged (`wz_package.py --node slot-recorder`), not a build of this test's
//! own, so what is proven is the artifact whose manifest was verified.
//!
//! The router is zenohd 1.10.1 with its REST plugin, and the REST plugin is the other end of both
//! directions: an HTTP PUT is a sample the reference router routes to the node's subscription, and
//! an HTTP GET is a query it routes to the node's queryable. Nothing of wz is on that side, so the
//! node is judged by a peer it shares no code with. The node's own console is the witness of what
//! it kept (`HOST-WZ-SAMPLE <key> put len= kept= seq= hex=` for a put, `HOST-WZ-SAMPLE <key> del
//! seq=` for a delete).
//!
//! The locator is fixed in the node (`tcp/127.0.0.1:17471`), so the router listens there and the
//! legs run one at a time (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_RECORDER`), the reference zenohd and its REST
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

// The node is a deploy crate, which the barrier gate does not read as a producer: the two lines it
// prints are declared here, each for the needle the tests wait for.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-SAMPLE {} put len={} kept={} seq={} hex={}" for "hex="
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-SAMPLE {} del seq={}" for "lab/in/temp del seq="

/// The router the node dials, as its declaration states it.
const ROUTER_PORT: u16 = 17471;
/// What the node prints once its session is up.
const ESTABLISHED: &str = "slot-recorder: session established";
/// How long the node may take to establish and the router to learn its declarations.
const ESTABLISH_BUDGET: Duration = Duration::from_secs(30);
/// How long a sample that must NOT be kept is watched for.
const ABSENCE_WINDOW: Duration = Duration::from_secs(3);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_RECORDER").expect(
        "WZ_DECLARED_NODE_RECORDER names the packaged slot-recorder (Layer Z builds it with \
         `wz_package.py --node slot-recorder`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

/// One HTTP request to the router's REST plugin, answered `(status, body)`. `Connection: close` is
/// load-bearing, not hygiene: the plugin's server keeps a persistent connection otherwise and a
/// read to the end never returns.
fn http(addr: SocketAddr, method: &str, key: &str, body: &[u8]) -> (u16, String) {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect REST");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    let head = format!(
        "{method} /{key} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a header terminator");
    let status = std::str::from_utf8(&raw[..split])
        .expect("ascii head")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("a status code");
    (
        status,
        String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    )
}

/// The router with its REST plugin, and the node dialling it, both with their output captured.
struct Fixture {
    rest: SocketAddr,
    node_out: std::fs::File,
    router_out: std::fs::File,
    node: ChildGuard,
    router: ChildGuard,
}

impl Fixture {
    /// Start the node (which redials until the router is up) and the router, and wait for the
    /// session.
    fn start() -> Self {
        let plugin = rest_plugin();
        assert!(
            plugin.is_file(),
            "the REST plugin cdylib must exist at {}",
            plugin.display()
        );
        let rest_port = free_port();
        let mut node_out = tempfile::tempfile().expect("a capture for the node");
        let node = ChildGuard::wrap(
            "slot-recorder (declared node)",
            Command::new(node_binary())
                .stdout(Stdio::from(node_out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(node_out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn the node"),
        );
        let router_out = tempfile::tempfile().expect("a capture for the router");
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
                .stdout(Stdio::from(router_out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(router_out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn zenohd"),
        );
        let fixture = Self {
            rest: format!("127.0.0.1:{rest_port}")
                .parse()
                .expect("an address"),
            node_out: node_out.try_clone().expect("dup capture"),
            router_out,
            node,
            router,
        };
        if wait_for_substring(&mut node_out, ESTABLISHED, ESTABLISH_BUDGET).is_err() {
            panic!(
                "the node established no session within {ESTABLISH_BUDGET:?}\n{}",
                fixture.report()
            );
        }
        fixture.wait_for_rest();
        fixture
    }

    fn wait_for_rest(&self) {
        let until = Instant::now() + ESTABLISH_BUDGET;
        while Instant::now() < until {
            if TcpStream::connect_timeout(&self.rest, Duration::from_millis(200)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("the REST plugin never listened\n{}", self.report());
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

    /// Put `body` on `key` until the node reports a sample whose payload is `hex` (the router may
    /// not yet hold the node's subscription when the session has just come up, and a put it
    /// routes nowhere is lost). Returns the node's output when it appears.
    fn put_until_kept(&mut self, key: &str, body: &[u8], hex: &str) -> String {
        let needle = format!("hex={hex}");
        let until = Instant::now() + ESTABLISH_BUDGET;
        loop {
            let (status, _) = http(self.rest, "PUT", key, body);
            assert!(status < 300, "the REST plugin refused a PUT: {status}");
            let mut capture = self.node_out.try_clone().expect("dup");
            if let Ok(seen) = wait_for_substring(&mut capture, &needle, Duration::from_millis(500))
            {
                return seen;
            }
            assert!(
                Instant::now() < until,
                "the node kept nothing of a put on {key} within {ESTABLISH_BUDGET:?}\n{}",
                self.report()
            );
        }
    }

    fn finish(mut self) {
        graceful_terminate(self.node.child_mut(), Duration::from_secs(5));
        graceful_terminate(self.router.child_mut(), Duration::from_secs(5));
    }
}

/// The sample lines the node printed, newest last.
fn sample_lines(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|l| l.starts_with("HOST-WZ-SAMPLE "))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A payload as the REST plugin renders it in a reply: the reply carries no encoding of its own, so
/// the plugin takes it as `zenoh/bytes` and writes the value as standard base64.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (at, b)| acc | (u32::from(*b) << (16 - 8 * at)));
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(char::from(
                    ALPHABET[((word >> (18 - 6 * at)) & 63) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its subscription and answer are the slot profile's own seam (wz_session_mcu::latest), and the catalog's pubsub and query atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the packaged slot-recorder, which Layer Z makes, + zenohd and its REST plugin); runs via --ignored"]
fn zenohd_put_is_kept_and_a_query_is_answered_from_the_latest() {
    let mut fx = Fixture::start();

    // A put the reference router routes to the node's declared subscription is kept: its key, its
    // length and its bytes are on the node's console.
    let seen = fx.put_until_kept("lab/in/temp", b"21.5", &hex(b"21.5"));
    let line = *sample_lines(&seen)
        .iter()
        .rev()
        .find(|l| l.contains(&hex(b"21.5")))
        .expect("the line that matched");
    assert!(
        line.starts_with("HOST-WZ-SAMPLE lab/in/temp put len=4 kept=4 seq="),
        "the kept sample is not the one put: {line}\n{}",
        fx.report()
    );

    // A query the router routes to the node's queryable is answered from that sample.
    let (status, body) = http(fx.rest, "GET", "lab/in/temp", b"");
    assert_eq!(status, 200, "the query failed: {body}\n{}", fx.report());
    assert!(
        body.contains(&base64(b"21.5")),
        "the queryable did not answer with the sample it kept: {body}\n{}",
        fx.report()
    );

    // The next sample replaces it, and the answer follows: the control of the answer above, which
    // could otherwise be a value the node had from anywhere.
    fx.put_until_kept("lab/in/temp", b"22.5", &hex(b"22.5"));
    let (_, body) = http(fx.rest, "GET", "lab/in/temp", b"");
    assert!(
        body.contains(&base64(b"22.5")) && !body.contains(&base64(b"21.5")),
        "the answer is not the latest sample: {body}\n{}",
        fx.report()
    );
    fx.finish();
}

// wz-proves: none -- the same node, for the same reason: the cells of the fixed-memory profile have no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-recorder, which Layer Z makes, + zenohd and its REST plugin); runs via --ignored"]
fn zenohd_other_key_is_not_kept_a_long_payload_is_cut_and_a_delete_empties_the_answer() {
    let mut fx = Fixture::start();
    // The node is subscribed and the router knows it: the first sample proves both.
    fx.put_until_kept("lab/in/temp", b"warm", &hex(b"warm"));

    // A key the node did not subscribe to is not kept: the node's console shows no such sample.
    let (status, _) = http(fx.rest, "PUT", "lab/in/other", b"zzz");
    assert!(status < 300, "the REST plugin refused a PUT: {status}");
    std::thread::sleep(ABSENCE_WINDOW);
    let mut capture = fx.node_out.try_clone().expect("dup");
    let output = read_captured(&mut capture);
    assert!(
        !output.contains(&hex(b"zzz")) && !output.contains("lab/in/other"),
        "the node kept a sample of a key it did not subscribe to\n{}",
        fx.report()
    );

    // A payload over the 64 bytes the declaration asked to keep is cut there, and the node says how
    // long it was.
    let long = vec![b'a'; 100];
    let seen = fx.put_until_kept("lab/in/temp", &long, &hex(&long[..64]));
    assert!(
        sample_lines(&seen)
            .iter()
            .any(|l| l.contains("len=100 kept=64 ")),
        "a payload over the subscription's capacity was not cut to it\n{}",
        fx.report()
    );
    let (_, body) = http(fx.rest, "GET", "lab/in/temp", b"");
    assert!(
        body.contains(&base64(&long[..64])) && !body.contains(&base64(&long[..65])),
        "the answer is not the 64 bytes the node kept: {body}\n{}",
        fx.report()
    );

    // A delete is kept as a delete, and a delete is not a value to answer with.
    let (status, _) = http(fx.rest, "DELETE", "lab/in/temp", b"");
    assert!(status < 300, "the REST plugin refused a DELETE: {status}");
    let mut capture = fx.node_out.try_clone().expect("dup");
    let seen = wait_for_substring(&mut capture, "lab/in/temp del seq=", ESTABLISH_BUDGET)
        .unwrap_or_else(|_| panic!("the node did not report the delete\n{}", fx.report()));
    assert!(!sample_lines(&seen).is_empty());
    let (_, body) = http(fx.rest, "GET", "lab/in/temp", b"");
    assert!(
        !body.contains(&base64(&long[..64])),
        "a deleted key was still answered with its last value: {body}\n{}",
        fx.report()
    );
    fx.finish();
}
