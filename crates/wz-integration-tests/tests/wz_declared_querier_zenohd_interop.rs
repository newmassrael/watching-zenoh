// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that ASKS, against the reference router and a stock responder:
//! the reply it keeps, that it keeps it when nothing answers, and that it asks again with the next
//! session.
//!
//! The node is `slot-asker` (`deploy/nodes/slot-asker.toml`): a fixed-memory process with no
//! allocator that dials one router and, while the session is established, asks `lab/ask/val` every
//! 500 ms, keeps the latest reply (up to 32 bytes) and answers a query under the same key from it.
//! The file Layer Z runs is the one the entry packaged (`wz_package.py --node slot-asker`), so what
//! is proven is the artifact whose manifest was verified.
//!
//! The responder is the stock `zenoh_z_queryable` example, a client of the router, and the router
//! is zenohd 1.10.1 with its REST plugin: peers the node shares no code with answer its queries and
//! ask its own. Two legs:
//!
//! - the stock responder answers, and the node says it kept the reply (its key, length and bytes
//!   are on the node's console); the responder is stopped, and the node, which keeps asking, ends
//!   each query without a reply and keeps the cell as it was, so a query the router routes to the
//!   node's queryable (the only one left) is answered from what it kept; another responder with
//!   another value replaces the cell, and the answer follows;
//! - the router is stopped and started again: the node says its session was lost, dials the new
//!   router, and asks again with the next session, so a responder of the new router is heard.
//!
//! The locator is fixed in the node (`tcp/127.0.0.1:17473`), so the router listens there and the
//! legs run one at a time (`--test-threads=1`).
//!
//! Requires the packaged node (`WZ_DECLARED_NODE_ASKER`), the reference zenohd, its REST plugin and
//! the stock examples (`scripts/build-zenohd.sh`). Runs on the `--ignored` lane; the file's `zenohd`
//! token keeps Layer E's sweep off it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    graceful_terminate, read_captured, rest_plugin, wait_for_substring, zenoh_core_example_binary,
    zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::free_port;

// The node is a deploy crate, which the barrier gate does not read as a producer: the lines it
// prints are declared here, each for the needle the tests wait for. The line of a cell, whose
// `hex=` the tests also wait for, is declared by `wz_declared_node_zenohd_interop.rs` for the crate.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-ASKED {} asked={} replies={} errors={} finals={} timeouts={} refused={}" for "HOST-WZ-ASKED lab/ask/val asked="

/// The router the node dials, as its declaration states it.
const ROUTER_PORT: u16 = 17473;
/// What the node prints once its session is up, and when it is lost.
const ESTABLISHED: &str = "slot-asker: session established";
const LOST: &str = "slot-asker: session lost";
/// What the stock responder prints once it has declared its queryable.
const RESPONDER_READY: &str = "Declaring Queryable on";
/// The key the node asks and answers under.
const KEY: &str = "lab/ask/val";
/// The two values the stock responder answers with, both under the 32 bytes the node keeps.
const FIRST: &[u8] = b"value-from-stock-zenoh";
const SECOND: &[u8] = b"second-value-zenoh";
/// How long the node may take to establish, and the router to learn it.
const ESTABLISH_BUDGET: Duration = Duration::from_secs(30);

fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_DECLARED_NODE_ASKER").expect(
        "WZ_DECLARED_NODE_ASKER names the packaged slot-asker (Layer Z builds it with \
         `wz_package.py --node slot-asker`)",
    ));
    assert!(path.is_file(), "no node at {}", path.display());
    path
}

/// One HTTP request to the router's REST plugin, answered `(status, body)`. `Connection: close` is
/// load-bearing: the plugin's server keeps a persistent connection otherwise and a read to the end
/// never returns.
fn http(addr: SocketAddr, method: &str, key: &str) -> (u16, String) {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect REST");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream
        .write_all(
            format!("{method} /{key} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .expect("write the request");
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

/// What the node's last `HOST-WZ-ASKED` line says: (asked, replies, finals).
fn last_asked(output: &str) -> Option<(u32, u32, u32)> {
    let line = output
        .lines()
        .rev()
        .find(|l| l.starts_with(&format!("HOST-WZ-ASKED {KEY} ")))?;
    let field = |name: &str| -> Option<u32> {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(name)?.parse().ok())
    };
    Some((field("asked=")?, field("replies=")?, field("finals=")?))
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

/// The stock responder, a client of the router, answering `payload` under the key the node asks.
/// Returns once it has declared; it is retried on a transient open failure, which is a flake and
/// not a finding.
fn start_responder(payload: &[u8]) -> ChildGuard {
    let binary = zenoh_core_example_binary("z_queryable");
    for attempt in 1..=6 {
        let out = tempfile::tempfile().expect("a capture for the responder");
        let mut reader = out.try_clone().expect("dup capture");
        let mut responder = ChildGuard::wrap(
            "z_queryable (stock zenoh)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&binary)
                .args(["-k", KEY, "-p"])
                .arg(String::from_utf8_lossy(payload).into_owned())
                .args(["-m", "client", "-e"])
                .arg(format!("tcp/127.0.0.1:{ROUTER_PORT}"))
                .arg("--no-multicast-scouting")
                .stdout(Stdio::from(out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(out))
                .spawn()
                .expect("spawn z_queryable"),
        );
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if read_captured(&mut reader).contains(RESPONDER_READY) {
                return responder;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = responder.child_mut().kill();
        let _ = responder.child_mut().wait();
        eprintln!("z_queryable open attempt {attempt}/6 did not declare; retrying");
    }
    panic!("the stock responder never declared its queryable");
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
            "slot-asker (declared node)",
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

    fn output(&self) -> String {
        read_captured(&mut self.node_out.try_clone().expect("dup"))
    }

    fn report(&self) -> String {
        let mut router = self.router_out.try_clone().expect("dup");
        format!(
            "--- node ---\n{}\n--- zenohd ---\n{}",
            self.output(),
            read_captured(&mut router)
        )
    }

    /// Wait until the node says it kept `value` as the reply to its query: a `HOST-WZ-REPLY` line,
    /// not a subscription's.
    fn wait_for_reply(&self, value: &[u8]) -> String {
        let mut capture = self.node_out.try_clone().expect("dup");
        let seen = wait_for_substring(
            &mut capture,
            &format!("hex={}", hex(value)),
            ESTABLISH_BUDGET,
        )
        .unwrap_or_else(|_| panic!("the node kept no reply of {value:?}\n{}", self.report()));
        let line = seen
            .lines()
            .find(|l| l.contains(&hex(value)))
            .expect("the line that matched");
        assert!(
            line.starts_with(&format!(
                "HOST-WZ-REPLY {KEY} put len={n} kept={n} seq=",
                n = value.len()
            )),
            "what the node kept is not the reply to its query: {line}\n{}",
            self.report()
        );
        seen
    }

    fn finish(mut self) {
        graceful_terminate(self.node.child_mut(), Duration::from_secs(5));
        graceful_terminate(self.router.child_mut(), Duration::from_secs(5));
    }
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its querier is the slot profile's own seam (wz_session_mcu::slot_querier), and the catalog's query atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the packaged slot-asker, which Layer Z makes, + zenohd, its REST plugin and the stock examples); runs via --ignored"]
fn zenohd_asker_keeps_a_reply_and_answers_from_it_when_the_responder_is_gone() {
    let fx = Fixture::start();
    let mut responder = start_responder(FIRST);
    fx.wait_for_reply(FIRST);
    assert!(
        wait_for_substring(
            &mut fx.node_out.try_clone().expect("dup"),
            "HOST-WZ-ASKED lab/ask/val asked=",
            Duration::from_secs(5)
        )
        .is_ok(),
        "the node did not say what it asked\n{}",
        fx.report()
    );

    // The responder goes: the node keeps asking, each query ends with its final and no reply, and
    // the cell is as it was.
    graceful_terminate(responder.child_mut(), Duration::from_secs(5));
    let (_, replies, finals) = last_asked(&fx.output()).expect("an asked line");
    std::thread::sleep(Duration::from_millis(2_500));
    let (_, replies_later, finals_later) = last_asked(&fx.output()).expect("an asked line");
    assert!(
        finals_later >= finals + 3,
        "the node did not keep asking: {finals} finals, then {finals_later}\n{}",
        fx.report()
    );
    assert_eq!(
        replies_later,
        replies,
        "a query nobody answers was counted as answered\n{}",
        fx.report()
    );

    // The only queryable left that answers under the key is the node's own, from what it kept.
    let (status, body) = http(fx.rest, "GET", KEY);
    assert_eq!(status, 200, "the query failed: {body}\n{}", fx.report());
    assert!(
        body.contains(&base64(FIRST)),
        "the node did not answer from the reply it kept: {body}\n{}",
        fx.report()
    );

    // Another responder with another value replaces what the node keeps, and the answer follows.
    let mut second = start_responder(SECOND);
    fx.wait_for_reply(SECOND);
    graceful_terminate(second.child_mut(), Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(1_000));
    let (_, body) = http(fx.rest, "GET", KEY);
    assert!(
        body.contains(&base64(SECOND)) && !body.contains(&base64(FIRST)),
        "the answer is not the latest reply: {body}\n{}",
        fx.report()
    );
    fx.finish();
}

// wz-proves: none -- the same node, for the same reason: the querier of the fixed-memory profile has no catalog atom
#[test]
#[ignore = "binary-dep e2e (the packaged slot-asker, which Layer Z makes, + zenohd, its REST plugin and the stock examples); runs via --ignored"]
fn zenohd_restarted_the_asker_asks_again_with_the_next_session() {
    let mut fx = Fixture::start();
    let mut responder = start_responder(FIRST);
    fx.wait_for_reply(FIRST);

    // The router goes away, and with it the responder's session: the node says its is lost.
    graceful_terminate(fx.router.child_mut(), Duration::from_secs(5));
    graceful_terminate(responder.child_mut(), Duration::from_secs(5));
    assert!(
        wait_for_substring(
            &mut fx.node_out.try_clone().expect("dup"),
            LOST,
            ESTABLISH_BUDGET
        )
        .is_ok(),
        "the node did not notice its router had gone\n{}",
        fx.report()
    );
    let (asked_before, _, _) = last_asked(&fx.output()).expect("an asked line");

    // A router comes up where the node dials, with a responder of another value: the node dials it
    // and asks again, and hears it.
    let rest_port = free_port();
    let (router, router_out) = start_router(rest_port);
    fx.router = router;
    fx.router_out = router_out;
    fx.rest = format!("127.0.0.1:{rest_port}")
        .parse()
        .expect("an address");
    let mut second = start_responder(SECOND);
    fx.wait_for_reply(SECOND);
    let (asked_after, _, _) = last_asked(&fx.output()).expect("an asked line");
    assert!(
        asked_after > asked_before,
        "the node asked no more after the router came back: {asked_before}, then {asked_after}\n{}",
        fx.report()
    );
    assert!(
        fx.output().matches(ESTABLISHED).count() >= 2,
        "the node never established a second session\n{}",
        fx.report()
    );
    graceful_terminate(second.child_mut(), Duration::from_secs(5));
    fx.finish();
}
