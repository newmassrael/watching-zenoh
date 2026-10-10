// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 900 — `--sessions <file>` reaches the process: a document is
//! refused by its key paths before anything starts, and a passed one starts
//! every session it lists in ONE process, each with its own READY line, its own
//! end and its own close.
//!
//! Unicast only, so it needs no foreign binary and no multicast delivery: the
//! client-plus-group shape against a stock zenohd is
//! `wz-integration-tests/tests/wz_ap_demo_sessions_client_and_group_zenohd.rs`.
//!
//! The fault leg is the shape the consumer asked about. Node B holds two
//! sessions: `to_a`, a client dialled to node A, and `inbound`, a listener.
//! Killing A is a fault of `to_a`'s alone: `to_a` ends, and `inbound` goes on
//! accepting. The existing single-session `--connect` mode is one of
//! `inbound`'s clients, unchanged.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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

    /// The first line, already read or read now, that contains `needle`; or a
    /// panic with everything read so far. Already-read lines count because the
    /// sessions run concurrently and print in either order.
    fn expect_line(&mut self, needle: &str) -> String {
        if let Some(line) = self.seen.iter().find(|l| l.contains(needle)) {
            return line.clone();
        }
        let until = Instant::now() + DEADLINE;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => panic!(
                    "never saw {needle:?}\n--- transcript ---\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Every line written so far and until the process exits; its status.
    fn finish(&mut self, within: Duration) -> (ExitStatus, String) {
        let until = Instant::now() + within;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                break status;
            }
            assert!(
                Instant::now() < until,
                "the node did not exit\n--- transcript ---\n{}",
                self.seen.join("\n")
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        // The reader thread ends with the pipe; drain what it already has.
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(line);
        }
        (status, self.seen.join("\n"))
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill {signal} failed");
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
        let path =
            std::env::temp_dir().join(format!("wz-ap-demo-sessions-{case}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("a directory of this test's own");
        Dir(path)
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path: PathBuf = self.0.join(name);
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

fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// A document the rules refuse starts nothing, and every refusal names its key
/// as a dotted path: here two unicast sessions inheriting one zid, a group
/// endpoint with `auto` for an interface, and a per-session limit an AP cannot
/// apply.
#[test]
fn a_refused_document_names_every_key_and_starts_nothing() {
    let dir = Dir::new("refused");
    let path = dir.write(
        "refused.json5",
        r#"{
            zid: "a1b2c3d4",
            sessions: [
                { name: "to_router", mode: "client", transport: "unicast",
                  connect: { endpoints: ["tcp/127.0.0.1:7447"] }, limits: { tx_queue: 4 } },
                { name: "listener", mode: "peer", transport: "unicast",
                  listen: { endpoints: ["tcp/127.0.0.1:0"] } },
                { name: "group", mode: "peer", transport: "multicast",
                  group: { endpoint: "udp/224.0.0.224:7446#iface=auto" } },
            ],
        }"#,
    );
    let mut node = Node::spawn(&["--sessions", &path]);
    let (status, transcript) = node.finish(DEADLINE);
    assert_eq!(status.code(), Some(2), "{transcript}");
    for key in [
        "sessions[0].limits: ",
        "sessions[1].zid: sessions[1] (`listener`) and sessions[0] (`to_router`)",
        "sessions[2].group.endpoint: `auto` is not a word",
    ] {
        assert!(
            transcript.contains(&format!("--sessions {path}: {key}")),
            "missing {key:?}\n--- transcript ---\n{transcript}"
        );
    }
    assert!(
        !transcript.contains("wz-ap-demo session "),
        "a refused document started a session\n--- transcript ---\n{transcript}"
    );
}

/// `--sessions` takes nothing beside it, so no existing flag changes meaning
/// under it; and a document that cannot be read is refused by its path.
#[test]
fn the_flag_stands_alone_and_an_unreadable_file_is_refused() {
    let dir = Dir::new("alone");
    let path = dir.write(
        "one.json5",
        r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
                           connect: { endpoints: ["tcp/127.0.0.1:7447"] } } ] }"#,
    );
    let mut node = Node::spawn(&["--sessions", &path, "--key", "demo/**"]);
    let (status, transcript) = node.finish(DEADLINE);
    assert_eq!(status.code(), Some(2), "{transcript}");
    assert!(
        transcript.contains("takes no other argument (also given: --key demo/**)"),
        "{transcript}"
    );

    let missing = dir.0.join("absent.json5").display().to_string();
    assert!(!exists(&missing));
    let mut node = Node::spawn(&["--sessions", &missing]);
    let (status, transcript) = node.finish(DEADLINE);
    assert_eq!(status.code(), Some(2), "{transcript}");
    assert!(
        transcript.contains(&format!("--sessions: cannot read {missing}")),
        "{transcript}"
    );
}

/// A session that never opens fails ALONE: its sibling still comes up and
/// serves, and the process reports the failure only in its exit status, after
/// the sibling has closed.
#[test]
fn a_session_that_fails_to_open_leaves_its_sibling_serving() {
    let dir = Dir::new("fails");
    let nothing = format!(
        "tcp/127.0.0.1:{}",
        wz_runtime_tokio_test_support::free_port()
    );
    let doc = dir.write(
        "fails.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "nowhere", mode: "client", transport: "unicast", zid: "ee01",
                   connect: {{ endpoints: ["{nothing}"] }} }},
                {{ name: "inbound", mode: "peer", transport: "unicast", zid: "ee02",
                   listen: {{ endpoints: ["tcp/127.0.0.1:0"] }} }} ] }}"#
        ),
    );
    let mut node = Node::spawn(&["--sessions", &doc]);
    node.expect_line("wz-ap-demo session nowhere: failed: no endpoint opened");
    let addr = listening_on(&node.expect_line("wz-ap-demo session inbound: READY"));
    let mut client = Node::spawn(&["--connect", &addr, "--key", "demo/**", "--zid", "ff01"]);
    client.expect_line("session Established; entering steady state");
    node.expect_line("wz-ap-demo session inbound: accepted ff01");
    node.signal("-TERM");
    let (status, transcript) = node.finish(DEADLINE);
    assert_eq!(status.code(), Some(1), "{transcript}");
    assert!(
        transcript.contains("wz-ap-demo session inbound: closed"),
        "{transcript}"
    );
}

/// Two sessions in one process, each READY on its own, a fault of one that the
/// other survives, and a per-session close on SIGTERM.
#[test]
fn two_sessions_in_one_process_are_ready_end_and_close_each_on_their_own() {
    let dir = Dir::new("two");

    // Node A — one listening session, the peer node B's client dials.
    let a_doc = dir.write(
        "a.json5",
        r#"{ sessions: [ { name: "inbound_a", mode: "peer", transport: "unicast", zid: "aa01",
                           listen: { endpoints: ["tcp/127.0.0.1:0"] } } ] }"#,
    );
    let mut a = Node::spawn(&["--sessions", &a_doc]);
    let a_addr = listening_on(&a.expect_line("wz-ap-demo session inbound_a: READY"));

    // Node B — the subject: a client session to A and a listening session.
    let b_doc = dir.write(
        "b.json5",
        &format!(
            r#"{{ zid: "bb01",
                  sessions: [
                    {{ name: "to_a", mode: "client", transport: "unicast",
                       connect: {{ endpoints: ["{a_addr}"] }} }},
                    {{ name: "inbound", mode: "peer", transport: "unicast", zid: "bb02",
                       listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                       accept: {{ max_sessions: 2 }} }},
                  ] }}"#
        ),
    );
    let mut b = Node::spawn(&["--sessions", &b_doc]);
    b.expect_line("wz-ap-demo session to_a: starting client unicast zid bb01");
    b.expect_line("wz-ap-demo session inbound: starting peer unicast zid bb02");
    let ready_to_a = b.expect_line("wz-ap-demo session to_a: READY client unicast");
    assert!(ready_to_a.ends_with("peer aa01"), "{ready_to_a}");
    let b_addr = listening_on(&b.expect_line("wz-ap-demo session inbound: READY"));
    a.expect_line("wz-ap-demo session inbound_a: accepted bb01");

    // The existing single-session client, unchanged, is one of B's peers.
    let mut c = Node::spawn(&["--connect", &b_addr, "--key", "demo/**", "--zid", "cc01"]);
    c.expect_line("session Established; entering steady state");
    b.expect_line("wz-ap-demo session inbound: accepted cc01");

    // The fault: A dies. It is `to_a`'s alone.
    a.signal("-KILL");
    b.expect_line("wz-ap-demo session to_a: ended");
    // `inbound` still serves: it accepts a client that arrives after.
    let mut d = Node::spawn(&["--connect", &b_addr, "--key", "demo/**", "--zid", "dd01"]);
    d.expect_line("session Established; entering steady state");
    b.expect_line("wz-ap-demo session inbound: accepted dd01");

    // A per-session close: B is told to stop, and each live session closes.
    b.signal("-TERM");
    let (status, transcript) = b.finish(DEADLINE);
    assert!(status.success(), "{transcript}");
    // The listener closes once, and so does each session it accepted.
    for line in [
        "wz-ap-demo session inbound: closed",
        "wz-ap-demo session inbound: accepted cc01 closed",
        "wz-ap-demo session inbound: accepted dd01 closed",
    ] {
        let count = transcript.lines().filter(|l| *l == line).count();
        assert_eq!(count, 1, "{line:?} x{count}\n{transcript}");
    }
    assert!(
        !transcript.contains("wz-ap-demo session to_a: closed"),
        "to_a had already ended and cannot close again\n{transcript}"
    );
    assert!(
        transcript.contains("wz-ap-demo sessions: all 2 session(s) ended"),
        "{transcript}"
    );
    // The closes reached the wire: each client of B sees its session end.
    for client in [&mut c, &mut d] {
        let (_, transcript) = client.finish(DEADLINE);
        assert!(
            !transcript.contains("panicked"),
            "a client of B panicked\n{transcript}"
        );
    }
}
