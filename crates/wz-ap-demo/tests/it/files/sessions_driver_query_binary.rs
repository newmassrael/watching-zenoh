// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `query`, `forward` and `pull` roles of a `--sessions` driver, each over a
//! real loopback link between two processes.
//!
//! One node listens and the other dials it. Every role that sends is held
//! (`after_ms`) after the link opens: the listener declares its subscriber and
//! queryable only once the client is accepted, so a sample or a question issued at
//! that instant reaches a peer whose declaration has not arrived and is lost
//! without an error. What each test asserts is what the OTHER node received.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);

/// A running demo and the lines it writes to stderr.
struct Node {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Node {
    fn spawn(args: &[&str]) -> Node {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the demo binary runs");
        let stderr = child.stderr.take().expect("stderr was piped");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Node {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Read lines until `done` holds over everything read so far, or panic with
    /// the transcript at the deadline.
    fn wait_until(&mut self, what: &str, done: impl Fn(&[String]) -> bool) {
        let until = Instant::now() + DEADLINE;
        while !done(&self.seen) {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => panic!(
                    "never saw {what}\n--- transcript ---\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// The first line, already read or read now, that contains `needle`.
    fn expect_line(&mut self, needle: &str) -> String {
        self.wait_until(&format!("{needle:?}"), |seen| {
            seen.iter().any(|l| l.contains(needle))
        });
        self.seen
            .iter()
            .find(|l| l.contains(needle))
            .cloned()
            .expect("wait_until returned with the line present")
    }

    /// Read until at least `n` lines contain `needle`.
    fn expect_lines(&mut self, needle: &str, n: usize) {
        self.wait_until(&format!("{n} lines with {needle:?}"), |seen| {
            seen.iter().filter(|l| l.contains(needle)).count() >= n
        });
    }

    /// How many lines read so far contain `needle`.
    fn count(&self, needle: &str) -> usize {
        self.seen.iter().filter(|l| l.contains(needle)).count()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A directory of this test's own, removed with it.
struct Dir(PathBuf);

impl Dir {
    fn new(case: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "wz-ap-demo-sessions-driver-query-{case}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("a directory of this test's own");
        Dir(path)
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("the document is written");
        path.display().to_string()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The address a listening session printed in its READY line.
fn listening_on(ready: &str) -> String {
    let addr = ready
        .rsplit("listening on ")
        .next()
        .expect("a READY line names its address");
    format!("tcp/{addr}")
}

/// A listener written as `driver` and its address, once it is ready.
fn listen(dir: &Dir, zid: &str, driver: &str) -> (Node, String) {
    let doc = dir.write(
        "listener.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "inbound", mode: "peer", transport: "unicast", zid: "{zid}",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  driver: [ {driver} ] }} ] }}"#
        ),
    );
    let mut node = Node::spawn(&["--sessions", &doc]);
    let ready = node.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);
    (node, addr)
}

/// A client that dials `addr` and runs `driver`.
fn dial(dir: &Dir, zid: &str, addr: &str, driver: &str) -> Node {
    let doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "out", mode: "client", transport: "unicast", zid: "{zid}",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [ {driver} ] }} ] }}"#
        ),
    );
    Node::spawn(&["--sessions", &doc])
}

/// A declared querier asks twice, and the queryable on the other node answers: the
/// client reads replies and a final for each question, and the listener says what
/// it answered.
#[test]
fn a_declared_querier_asks_through_its_handle_and_the_peer_answers() {
    let dir = Dir::new("query");
    let (mut listener, addr) = listen(
        &dir,
        "dd11",
        r#"{ role: "answer", key: "demo/q", reply: "pong" }"#,
    );
    let mut client = dial(
        &dir,
        "dd12",
        &addr,
        r#"{ role: "query", key: "demo/q", period_ms: 300, count: 2, timeout_ms: 5000,
             after_ms: 1500 }"#,
    );

    client.expect_line("DRIVER query declared key=demo/q");
    client.expect_line("DRIVER query asked key=demo/q n=1");
    client.expect_line("DRIVER query asked key=demo/q n=2");
    client.expect_line("DRIVER query reply key=demo/q kind=Put bytes=4");
    client.expect_line("DRIVER query final n=1");
    client.expect_line("DRIVER query final n=2");
    client.expect_line("DRIVER query done key=demo/q count=2");
    assert_eq!(client.count("DRIVER query asked"), 2);

    // The answer came from the other process.
    listener.expect_line("DRIVER answer replied key=demo/q bytes=4");
}

/// A closed loop (`think_ms`): each question is asked after the final of the one before it,
/// which is what an asker that waits for its answer does, and every final is seen.
#[test]
fn a_closed_loop_asks_each_question_after_the_last_ones_final() {
    let dir = Dir::new("query-closed");
    let (_listener, addr) = listen(
        &dir,
        "dd21",
        r#"{ role: "answer", key: "demo/c", reply: "pong" }"#,
    );
    let mut client = dial(
        &dir,
        "dd22",
        &addr,
        r#"{ role: "query", key: "demo/c", think_ms: 0, count: 3, timeout_ms: 5000,
             after_ms: 1500 }"#,
    );
    client.expect_line("DRIVER query done key=demo/c count=3");
    assert_eq!(
        client.count("DRIVER query lost final"),
        0,
        "{}",
        client.seen.join("\n")
    );
    let order: Vec<&String> = client
        .seen
        .iter()
        .filter(|l| l.contains("DRIVER query asked key=demo/c") || l.contains("DRIVER query final"))
        .collect();
    let shape: Vec<String> = order
        .iter()
        .map(|l| {
            l.rsplit("DRIVER query ")
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        shape,
        [
            "asked key=demo/c n=1",
            "final n=1",
            "asked key=demo/c n=2",
            "final n=2",
            "asked key=demo/c n=3",
            "final n=3",
        ],
        "{}",
        client.seen.join("\n")
    );
}

/// A forwarder on one node republishes what the other node puts and deletes, and
/// the other node's subscriber on the `to` key receives them: a put arrives as a
/// put and a delete as a delete. The samples that feed the forwarder come from the
/// listener over the link, so the test needs no local loopback delivery.
#[test]
fn a_forwarder_republishes_puts_and_deletes_on_its_target_key() {
    let dir = Dir::new("forward");
    let (mut listener, addr) = listen(
        &dir,
        "dd21",
        r#"{ role: "subscribe", key: "b/x" },
           { role: "put", key: "a/1", payload: "abc", after_ms: 1500 },
           { role: "delete", key: "a/1", after_ms: 1800 }"#,
    );
    let mut client = dial(
        &dir,
        "dd22",
        &addr,
        r#"{ role: "forward", key: "a/**", to: "b/x" }"#,
    );

    client.expect_line("DRIVER forward declared key=a/** to=b/x");
    listener.expect_line("DRIVER subscribe sample key=b/x kind=Put bytes=3");
    listener.expect_line("DRIVER subscribe sample key=b/x kind=Del bytes=0");
    // The listener's own subscriber is on `b/x` alone: nothing it saw is the put
    // on `a/1` itself.
    assert_eq!(listener.count("DRIVER subscribe sample key=a/1"), 0);
    client.expect_line("DRIVER forward forwarded from=a/1 to=b/x kind=Put bytes=3");
    client.expect_line("DRIVER forward forwarded from=a/1 to=b/x kind=Del bytes=0");
}

/// A buffered subscriber drains on its own period: every sample the client puts is
/// printed once, and the `pulled` counts add up to the puts. The queue holds fewer
/// samples than are put, so the session waits at its drain between pulls instead
/// of dropping the surplus.
#[test]
fn a_pulled_subscriber_prints_every_sample_and_the_counts_add_up() {
    const PUTS: usize = 6;
    let dir = Dir::new("pull");
    let (mut listener, addr) = listen(
        &dir,
        "dd31",
        r#"{ role: "pull", key: "p/**", period_ms: 100, capacity: 4 }"#,
    );
    let mut client = dial(
        &dir,
        "dd32",
        &addr,
        r#"{ role: "publish", key: "p/x", payload: "hi", period_ms: 10, count: 6,
             after_ms: 1500 }"#,
    );

    listener.expect_line("DRIVER pull declared key=p/** capacity=4");
    listener.expect_lines("DRIVER pull sample key=p/x kind=Put bytes=2", PUTS);
    client.expect_line("DRIVER publish done key=p/x count=6");

    // A `pulled` line precedes the samples it counts, so every sample read has its
    // count read too.
    let pulled: usize = listener
        .seen
        .iter()
        .filter_map(|l| l.split("DRIVER pull pulled n=").nth(1))
        .map(|n| n.trim().parse::<usize>().expect("a count"))
        .sum();
    assert_eq!(pulled, PUTS, "{}", listener.seen.join("\n"));
    assert_eq!(
        listener.count("DRIVER pull sample key=p/x kind=Put bytes=2"),
        PUTS
    );
}
