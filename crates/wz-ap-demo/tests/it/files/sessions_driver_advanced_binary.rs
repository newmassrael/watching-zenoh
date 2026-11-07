// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The advanced roles of a `--sessions` driver reach the process: a listener
//! that publishes into a cache, a client that joins after the puts and asks for
//! history, and the document rules that bind the subscriber's recovery keys.
//!
//! Both sides are `wz-ap-demo --sessions` processes over loopback unicast, so no
//! foreign binary is needed. The wire carries the proof: the samples the client
//! prints were put before it declared anything, so only the cache can have
//! delivered them.

#![cfg(all(unix, feature = "advanced"))]

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

    /// Read lines until `needle` has been seen `times` times in all, or panic
    /// with everything read so far.
    fn expect_lines(&mut self, needle: &str, times: usize) {
        let until = Instant::now() + DEADLINE;
        while self.count(needle) < times {
            let left = until.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => panic!(
                    "saw {:?} {} time(s), wanted {times}\n--- transcript ---\n{}",
                    needle,
                    self.count(needle),
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// The first line, already read or read now, that contains `needle`.
    fn expect_line(&mut self, needle: &str) -> String {
        self.expect_lines(needle, 1);
        self.seen
            .iter()
            .find(|l| l.contains(needle))
            .expect("counted above")
            .clone()
    }

    /// How many lines read so far contain `needle`.
    fn count(&self, needle: &str) -> usize {
        self.seen.iter().filter(|l| l.contains(needle)).count()
    }

    /// Read until the node has been quiet for a moment, so a count that must
    /// not grow is read after what would have grown it had time to arrive.
    fn settle(&mut self) {
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(line);
        }
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
            "wz-ap-demo-sessions-driver-advanced-{case}-{}",
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

/// A listener publishes five samples into a cache three deep as soon as a client
/// is accepted; the client declares its advanced subscriber long after, asking
/// for three samples of history, and prints exactly the three the cache kept.
#[test]
fn a_late_subscriber_is_given_the_cached_history() {
    let dir = Dir::new("history");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "source", mode: "peer", transport: "unicast", zid: "ad01",
              listen: { endpoints: ["tcp/127.0.0.1:0"] },
              driver: [
                { role: "advanced_publish", key: "demo/adv/tick", payload: "hi",
                  period_ms: 10, count: 5, cache: 3 },
              ] } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);

    // The hold keeps the subscriber from declaring until the puts are over and the
    // listener's cache declaration has reached the client: a history query sent
    // earlier finds no cache to ask, and a live sample would be counted as history.
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "sink", mode: "client", transport: "unicast", zid: "ad02",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [
                    {{ role: "advanced_subscribe", key: "demo/adv/tick", history: 3,
                       after_ms: 1500 }},
                  ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);

    listener.expect_line("DRIVER advanced_publish declared key=demo/adv/tick cache=3");
    listener.expect_line("DRIVER advanced_publish done key=demo/adv/tick count=5");
    assert_eq!(
        listener.count("DRIVER advanced_publish sent key=demo/adv/tick bytes=2"),
        5,
        "{}",
        listener.seen.join("\n")
    );

    client.expect_line(
        "DRIVER advanced_subscribe declared key=demo/adv/tick history=3 recovery=none",
    );
    let sample = "DRIVER advanced_subscribe sample key=demo/adv/tick kind=Put bytes=2";
    client.expect_lines(sample, 3);
    client.settle();
    assert_eq!(
        client.count(sample),
        3,
        "the cache keeps three of the five\n{}",
        client.seen.join("\n")
    );
}

/// The keys that bind the subscriber's recovery are judged by the rules, before
/// anything starts: each refusal names its key path and the exit is 2; the same
/// keys, well formed, are accepted.
#[test]
fn the_recovery_keys_are_refused_by_path_and_accepted_when_whole() {
    let dir = Dir::new("rules");
    let refused = dir.write(
        "refused.json5",
        r#"{ sessions: [
            { name: "sink", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447"] },
              driver: [
                { role: "advanced_subscribe", key: "demo/a", recovery: "periodic" },
                { role: "advanced_subscribe", key: "demo/a", recovery: "samples",
                  periodic_ms: 100 },
                { role: "advanced_subscribe", key: "demo/a", periodic_ms: 100 },
                { role: "advanced_subscribe", key: "demo/a", recovery: "periodic",
                  periodic_ms: 3600001 },
                { role: "advanced_publish", key: "demo/a", payload: "x", period_ms: 10,
                  history: 3 },
              ] } ] }"#,
    );
    let mut node = Node::spawn(&["--check-sessions", &refused]);
    let (code, transcript) = node.finish();
    assert_eq!(code, Some(2), "{transcript}");
    for key in [
        "sessions[0].driver[0].periodic_ms: required when recovery is periodic: the period \
         of the re-ask, in milliseconds",
        "sessions[0].driver[1].periodic_ms: only meaningful when recovery is periodic",
        "sessions[0].driver[2].periodic_ms: only meaningful when recovery is periodic",
        "sessions[0].driver[3].periodic_ms: 3600001 ms exceeds the 3600000 ms ceiling; a \
         period no run will reach reports the trigger as armed while it never fires",
        "sessions[0].driver[4].history: not a key of the `advanced_publish` role",
    ] {
        assert!(
            transcript.contains(&format!("--check-sessions {refused}: {key}")),
            "missing {key:?}\n--- transcript ---\n{transcript}"
        );
    }
    assert!(
        !transcript.contains("wz-ap-demo session "),
        "a refused document started a session\n{transcript}"
    );

    let accepted = dir.write(
        "ok.json5",
        r#"{ sessions: [
            { name: "sink", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447"] },
              driver: [
                { role: "advanced_subscribe", key: "demo/a", history: 2, history_age_ms: 500,
                  recovery: "periodic", periodic_ms: 250 },
                { role: "advanced_publish", key: "demo/a", payload: "x", period_ms: 10,
                  cache: 4, heartbeat_ms: 100 },
              ] } ] }"#,
    );
    let mut node = Node::spawn(&["--check-sessions", &accepted]);
    let (code, transcript) = node.finish();
    assert_eq!(code, Some(0), "{transcript}");
}
