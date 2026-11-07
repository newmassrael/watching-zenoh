// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The group roles of a `--sessions` driver reach the process: one node holds a
//! `group_view`, a second dials it and holds a `group_member` of the same group,
//! and what the first prints is what crossed the link.
//!
//! The proof is on the viewer's side: it prints the member's join as an event
//! and reaches the size only the member's arrival gives it, so the member's own
//! line is not what is graded. Everything is on loopback unicast. A refused
//! rule across keys starts nothing.

#![cfg(all(unix, feature = "group"))]

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
            "wz-ap-demo-sessions-driver-group-{case}-{}",
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

/// A listener holds a `group_view` that waits for two members; a client joins
/// the same group as a `group_member`. The viewer reports the member's join and
/// the view it makes.
#[test]
fn a_viewer_sees_the_member_another_session_joins() {
    let dir = Dir::new("meet");
    let listener_doc = dir.write(
        "listener.json5",
        r#"{ sessions: [
            { name: "viewer", mode: "peer", transport: "unicast", zid: "ee01",
              listen: { endpoints: ["tcp/127.0.0.1:0"] },
              driver: [
                { role: "group_view", group: "drv/g", member_id: "viewer", size: 2, timeout_ms: 15000 },
              ] } ] }"#,
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);

    // The member is held (`after_ms`) after the link opens: the viewer declares
    // its group subscriber and queryable only once it has accepted the client,
    // so a join announced at that instant reaches a peer whose subscriber the
    // client has not heard of yet, and is lost with no error.
    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "joiner", mode: "client", transport: "unicast", zid: "ee02",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [
                    {{ role: "group_member", group: "drv/g", member_id: "member-b", lease_ms: 60000, after_ms: 1000 }},
                  ] }} ] }}"#
        ),
    );
    let _client = Node::spawn(&["--sessions", &client_doc]);

    listener.expect_line("DRIVER group_view joined group=drv/g member=viewer");
    listener.expect_line("DRIVER group_view event kind=Join member=member-b");
    listener.expect_line("DRIVER group_view view size=2 members=member-b,viewer");
    listener.expect_line("DRIVER group_view view reached size=2");
}

/// A `timeout_ms` with no `size` to wait for is refused at the timeout's key
/// path, the exit is 2, and nothing is started.
#[test]
fn a_timeout_without_a_size_is_refused_naming_its_key() {
    let dir = Dir::new("refused");
    let path = dir.write(
        "refused.json5",
        r#"{ sessions: [
            { name: "viewer", mode: "client", transport: "unicast",
              connect: { endpoints: ["tcp/127.0.0.1:7447"] },
              driver: [
                { role: "group_view", group: "drv/g", timeout_ms: 500 },
              ] } ] }"#,
    );
    let mut node = Node::spawn(&["--check-sessions", &path]);
    let (code, transcript) = node.finish();
    assert_eq!(code, Some(2), "{transcript}");
    assert!(
        transcript.contains(&format!(
            "--check-sessions {path}: sessions[0].driver[0].timeout_ms: is the wait for `size`"
        )),
        "the refusal does not name the key\n--- transcript ---\n{transcript}"
    );
    assert!(
        !transcript.contains("wz-ap-demo session "),
        "a refused document started a session\n{transcript}"
    );
}
