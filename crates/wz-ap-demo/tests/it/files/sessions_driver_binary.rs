// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `driver` key of a `--sessions` session reaches the process: the roles a
//! document names run on the session it names, over a real link, and say what
//! they did in the lines a harness waits on.
//!
//! One node listens and holds a subscriber and a queryable; a second dials it and
//! publishes, puts, deletes and asks. Everything is on loopback unicast, so no
//! foreign binary and no multicast are needed. A refused driver starts nothing.

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

    /// The first line, already read or read now, that contains `needle`; or a
    /// panic with everything read so far.
    fn expect_line(&mut self, needle: &str) -> String {
        self.expect_line_within(needle, DEADLINE)
    }

    /// [`Node::expect_line`] with a deadline of its own.
    fn expect_line_within(&mut self, needle: &str, within: Duration) -> String {
        if let Some(line) = self.seen.iter().find(|l| l.contains(needle)) {
            return line.clone();
        }
        let until = Instant::now() + within;
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

    /// How many lines read so far contain `needle`.
    fn count(&self, needle: &str) -> usize {
        self.seen.iter().filter(|l| l.contains(needle)).count()
    }

    /// Every line written until the process exits, and its exit code.
    fn finish(&mut self) -> (Option<i32>, String) {
        let until = Instant::now() + DEADLINE;
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
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(line);
        }
        (status.code(), self.seen.join("\n"))
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
            "wz-ap-demo-sessions-driver-{case}-{}",
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

/// A listener that holds a subscriber and a queryable, and a client that
/// publishes, puts, deletes and asks: each role says what it did, and what the
/// listener received is what the client sent.
#[test]
fn the_roles_of_two_sessions_meet_over_a_real_link() {
    let dir = Dir::new("meet");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "inbound", mode: "peer", transport: "unicast", zid: "dd01",
              listen: { endpoints: ["tcp/127.0.0.1:0"] },
              driver: [
                { role: "subscribe", key: "demo/in/**" },
                { role: "answer", key: "demo/q", reply: "pong" },
              ] } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);

    // Every client role is held (`after_ms`) after the link opens. The listener declares its
    // subscriber and queryable only once the client is accepted, so a put, a delete or a
    // question issued at that instant reaches a peer whose declaration the client has not heard
    // yet and is lost, with no error. The hosted run that showed it printed `get asked` and
    // `get final` and no `get reply`; the next run, with only the get held, lost the put and the
    // delete. The delete is held longest so it follows the put it deletes.
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "out", mode: "client", transport: "unicast", zid: "dd02",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [
                    {{ role: "publish", key: "demo/in/tick", payload: "hi", period_ms: 20, count: 3, after_ms: 1000 }},
                    {{ role: "put", key: "demo/in/once", payload: "abc", after_ms: 1000 }},
                    {{ role: "delete", key: "demo/in/once", after_ms: 1300 }},
                    {{ role: "get", key: "demo/q", timeout_ms: 5000, after_ms: 1000 }},
                  ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);

    // The client's roles each say what they did.
    client.expect_line("DRIVER publish done key=demo/in/tick count=3");
    assert_eq!(
        client.count("DRIVER publish sent key=demo/in/tick bytes=2"),
        3
    );
    client.expect_line("DRIVER put sent key=demo/in/once bytes=3");
    client.expect_line("DRIVER delete sent key=demo/in/once bytes=0");
    client.expect_line("DRIVER get reply key=demo/q");
    client.expect_line("DRIVER get final");

    // And the listener received what was sent, and answered what was asked.
    listener.expect_line("DRIVER subscribe sample key=demo/in/once kind=Del bytes=0");
    listener.expect_line("DRIVER subscribe sample key=demo/in/once kind=Put bytes=3");
    listener.expect_line("DRIVER answer replied key=demo/q bytes=4");
    let ticks = {
        // The three publishes may still be arriving; wait for the last.
        let mut n = 0;
        let until = Instant::now() + DEADLINE;
        while n < 3 && Instant::now() < until {
            listener.expect_line("DRIVER subscribe sample key=demo/in/tick kind=Put bytes=2");
            n = listener.count("DRIVER subscribe sample key=demo/in/tick kind=Put bytes=2");
            std::thread::sleep(Duration::from_millis(50));
            while let Ok(line) = listener.lines.try_recv() {
                listener.seen.push(line);
            }
        }
        n
    };
    assert_eq!(ticks, 3, "{}", listener.seen.join("\n"));
}

/// The workload a driver plays (`wz-workload`) reaches a peer: a stream at a rate written as a
/// decimal with a made payload, and a replay of hex and text samples with a mutation, each counted
/// on the listener at the length it was sent with.
#[test]
fn a_rate_stream_and_a_replay_reach_the_listener() {
    let dir = Dir::new("workload");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "inbound", mode: "peer", transport: "unicast", zid: "dd11",
              listen: { endpoints: ["tcp/127.0.0.1:0"] },
              driver: [ { role: "subscribe", key: "demo/w/**" } ] } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "out", mode: "client", transport: "unicast", zid: "dd12",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [
                    {{ role: "publish", key: "demo/w/tick", rate_per_s: 50, payload_bytes: 16,
                      fill: "counter", count: 4, after_ms: 1000 }},
                    {{ role: "replay", gap_ms: 50, after_ms: 1000, samples: [
                        {{ key: "demo/w/a", hex: "00ff10" }},
                        {{ key: "demo/w/b", text: "beta", mutation: {{ kind: "flip_bit", at_bit: 0 }} }},
                        {{ key: "demo/w/c", text: "gamma", mutation: {{ kind: "truncate", keep: 2 }} }},
                    ] }},
                  ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);
    client.expect_line("DRIVER publish done key=demo/w/tick count=4 late_max_us=");
    assert_eq!(
        client.count("DRIVER publish sent key=demo/w/tick bytes=16"),
        4
    );
    client.expect_line("DRIVER replay plan emissions=3 total_ms=100");
    client.expect_line("DRIVER replay emission 1 delay_ms=50 source=declared mutated=true");
    client.expect_line("DRIVER replay done emissions=3");
    listener.expect_line("DRIVER subscribe sample key=demo/w/a kind=Put bytes=3");
    listener.expect_line("DRIVER subscribe sample key=demo/w/b kind=Put bytes=4");
    listener.expect_line("DRIVER subscribe sample key=demo/w/c kind=Put bytes=2");
    let ticks = {
        let mut n = 0;
        let until = Instant::now() + DEADLINE;
        while n < 4 && Instant::now() < until {
            listener.expect_line("DRIVER subscribe sample key=demo/w/tick kind=Put bytes=16");
            n = listener.count("DRIVER subscribe sample key=demo/w/tick kind=Put bytes=16");
            std::thread::sleep(Duration::from_millis(50));
            while let Ok(line) = listener.lines.try_recv() {
                listener.seen.push(line);
            }
        }
        n
    };
    assert_eq!(ticks, 4, "{}", listener.seen.join("\n"));
}

/// The arrival processes of a stream reach the listener in full: a Poisson stream from a seed and a
/// stream of bursts, each its count of sends at its length: a short Poisson gap the timer cannot
/// hit is sent late, never dropped, so the count is the plan's.
#[test]
fn a_poisson_and_a_burst_stream_reach_the_listener() {
    let dir = Dir::new("arrivals");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "inbound", mode: "peer", transport: "unicast", zid: "dd31",
              listen: { endpoints: ["tcp/127.0.0.1:0"] },
              driver: [ { role: "subscribe", key: "demo/a/**" } ] } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "out", mode: "client", transport: "unicast", zid: "dd32",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [
                    {{ role: "publish", key: "demo/a/poisson", rate_per_s: 50, arrivals: "poisson",
                      arrival_seed: 7, payload_bytes: 8, count: 5, after_ms: 1000 }},
                    {{ role: "publish", key: "demo/a/burst", period_ms: 100, arrivals: "burst",
                      burst: 3, payload: "b", count: 6, after_ms: 1000 }},
                  ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);
    client.expect_line("DRIVER publish done key=demo/a/poisson count=5 late_max_us=");
    client.expect_line("DRIVER publish done key=demo/a/burst count=6 late_max_us=");
    for (key, bytes, n) in [("demo/a/poisson", 8, 5), ("demo/a/burst", 1, 6)] {
        let needle = format!("DRIVER subscribe sample key={key} kind=Put bytes={bytes}");
        let until = Instant::now() + DEADLINE;
        while listener.count(&needle) < n && Instant::now() < until {
            listener.expect_line(&needle);
            std::thread::sleep(Duration::from_millis(50));
            while let Ok(line) = listener.lines.try_recv() {
                listener.seen.push(line);
            }
        }
        assert_eq!(listener.count(&needle), n, "{}", listener.seen.join("\n"));
    }
}

/// `--driver-vocabulary` prints the role table as JSON: every role, with the keys the reader
/// judges, and exits 0 without starting anything.
#[test]
fn the_driver_vocabulary_is_the_role_table() {
    let out = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .arg("--driver-vocabulary")
        .output()
        .expect("the demo binary runs");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).expect("utf-8");
    for needle in [
        "\"schema\":1",
        "\"role\":\"publish\"",
        "\"name\":\"rate_per_s\",\"kind\":\"decimal\"",
        "\"name\":\"fill\",\"kind\":{\"word\":[\"zero\",\"counter\",\"seeded\"]}",
        "\"role\":\"replay\"",
        "\"name\":\"max_gap_ms\",\"kind\":\"integer-or-null\",\"required\":false,\"default\":10000",
        "\"every_role\":[{\"name\":\"after_ms\"",
    ] {
        assert!(text.contains(needle), "{needle} is not in\n{text}");
    }
}

/// A driver the rules refuse starts nothing: every refusal names its key path
/// and the exit is 2, and a deploy document, which has no `driver`, is judged as
/// it always was.
#[test]
fn a_refused_driver_starts_nothing_and_names_its_key() {
    let dir = Dir::new("refused");
    let path = dir.write(
        "refused.json5",
        r#"{ sessions: [
            { name: "out", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447"] },
              driver: [
                { role: "teleport", key: "demo/t" },
                { role: "publish", key: "demo/p", payload: "x" },
                { role: "delete", key: "demo/u", payload: "x" },
              ] } ] }"#,
    );
    let mut node = Node::spawn(&["--check-sessions", &path]);
    let (code, transcript) = node.finish();
    assert_eq!(code, Some(2), "{transcript}");
    for key in [
        "sessions[0].driver[0].role: required: publish, put, delete, subscribe, get, answer, \
         query, scout, advanced_publish, advanced_subscribe, liveliness_token, \
         liveliness_subscribe, liveliness_get, pull, group_member, group_view, forward or replay",
        "sessions[0].driver[1].period_ms: give exactly one of period_ms and rate_per_s",
        "sessions[0].driver[2].payload: not a key of the `delete` role",
    ] {
        assert!(
            transcript.contains(&format!("--check-sessions {path}: {key}")),
            "missing {key:?}\n--- transcript ---\n{transcript}"
        );
    }
    assert!(
        !transcript.contains("wz-ap-demo session "),
        "a refused document started a session\n{transcript}"
    );
}

/// `--check-sessions` accepts a document whose driver is well formed, and starts
/// nothing: the verdict a harness asks for before it asks for the traffic.
#[test]
fn a_well_formed_driver_is_accepted_by_the_check() {
    let dir = Dir::new("accepted");
    let path = dir.write(
        "ok.json5",
        r#"{ sessions: [
            { name: "out", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447"] },
              driver: [ { role: "put", key: "demo/p", payload: "x" } ] } ] }"#,
    );
    let mut node = Node::spawn(&["--check-sessions", &path]);
    let (code, transcript) = node.finish();
    assert_eq!(code, Some(0), "{transcript}");
    assert!(
        !transcript.contains("DRIVER"),
        "the check ran a role\n{transcript}"
    );
}

/// Suspend or resume a process by signal.
fn signal(pid: u32, which: &str) {
    let status = Command::new("kill")
        .args([&format!("-{which}"), &pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success(), "kill -{which} {pid}");
}

/// A question to a peer that never answers ends at its own deadline: the session
/// sweeps what has timed out, as the one-shot run modes do. The peer is suspended,
/// so its session stays open and says nothing; without the sweep the question
/// would wait for ever, and the lease (ten seconds) is far past the five this
/// waits.
#[test]
fn a_question_to_a_silent_peer_ends_at_its_deadline() {
    let dir = Dir::new("silent");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "inbound", mode: "peer", transport: "unicast", zid: "dd03",
              listen: { endpoints: ["tcp/127.0.0.1:0"] } } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "out", mode: "client", transport: "unicast", zid: "dd04",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [ {{ role: "get", key: "demo/q", timeout_ms: 600, after_ms: 1000 }} ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);
    // The client is Established when it says READY; suspending the listener any
    // earlier (its own `accepted` line comes first) strands the handshake.
    client.expect_line("READY client unicast connected");
    signal(listener.child.id(), "STOP");

    client.expect_line("DRIVER get asked key=demo/q");
    client.expect_line_within("DRIVER get final", Duration::from_secs(5));
    // What ends the question is the timeout the session itself delivers, one error
    // reply, as upstream's does; a reply of any other kind would be the peer's.
    let replies: Vec<&String> = client
        .seen
        .iter()
        .filter(|l| l.contains("DRIVER get reply"))
        .collect();
    assert!(
        replies.len() == 1 && replies[0].contains("kind=Err"),
        "expected the timeout error reply alone, got {replies:?}\n{}",
        client.seen.join("\n")
    );
    signal(listener.child.id(), "CONT");
}
