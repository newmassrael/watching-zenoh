// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `scout` driver role of a `--sessions` session asks a real multicast group
//! and reports the Hello of a node that answers on it.
//!
//! One process holds a listening peer session that answers Scouts on a group of
//! this file's own; a second holds a client session, dialled to the first only so
//! that its driver runs, and a `scout` role on the same group. The client's role
//! must print the peer's zid, as a peer, in a `hello` line.
//!
//! The group and port are this file's own and differ from the other scouting
//! tests: the kernel delivers a datagram to every wildcard-bound socket on the
//! port whichever group it carried, so two tests on one port would answer each
//! other's Scouts.

#![cfg(all(unix, feature = "scouting-active", feature = "scouting-responder"))]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);

/// The group of this test, off the default so concurrent runs do not collide.
const GROUP: &str = "224.0.0.241:17480";

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
            "wz-ap-demo-sessions-driver-scout-{case}-{}",
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

/// A listening peer answers Scouts on the group; a client's `scout` role asks the
/// group and prints that peer, with its zid, its role and the address it
/// listens on, and ends its window with a count.
#[test]
#[ignore = "binary-dep e2e: needs a multicast route; runs via --ignored"]
fn the_scout_role_reports_the_hello_of_a_listening_peer() {
    let dir = Dir::new("peer");
    let listener_doc = dir.write(
        "listener.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "found", mode: "peer", transport: "unicast", zid: "7e01",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  scouting: {{ multicast: {{ listen: true, address: "{GROUP}" }} }} }} ] }}"#
        ),
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let ready = listener.expect_line("READY peer unicast listening on");
    let addr = listening_on(&ready);
    // The READY line comes before the responder joins the group: a Scout sent
    // earlier would be lost, and nothing sends it again.
    listener.expect_line("SCOUT RESPONDER answering as peer");

    let client_doc = dir.write(
        "client.json5",
        &format!(
            r#"{{ sessions: [
                {{ name: "asker", mode: "client", transport: "unicast", zid: "7e02",
                  connect: {{ endpoints: ["{addr}"] }},
                  driver: [ {{ role: "scout", address: "{GROUP}", timeout_ms: 3000 }} ] }} ] }}"#
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);

    client.expect_line(&format!(
        "DRIVER scout started what=router,peer group={GROUP}"
    ));
    let hello = client.expect_line("DRIVER scout hello zid=7e01 whatami=peer");
    assert!(
        hello.ends_with(&format!("locators={addr}")),
        "the Hello names the address the peer listens on: {hello}"
    );
    let done = client.expect_line("DRIVER scout done hellos=");
    let count: usize = done
        .rsplit("hellos=")
        .next()
        .and_then(|n| n.trim().parse().ok())
        .expect("done names a count");
    assert!(count >= 1, "{done}");
}
