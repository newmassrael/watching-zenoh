// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness roles of a `--sessions` driver reach the wire: a token one
//! process holds is seen by the liveliness subscriber and the liveliness get of
//! another, and its going away is seen too.
//!
//! One node listens, the other dials it, both over loopback unicast, so no
//! foreign binary is needed. What is asserted is what the OTHER process prints,
//! never the line a role prints about its own call.

#![cfg(all(unix, feature = "preset-ap-client"))]

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

    /// Where in the lines read so far the first one containing `needle` is; the
    /// line must have been waited for already.
    fn position(&self, needle: &str) -> usize {
        self.seen
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| {
                panic!(
                    "{needle:?} was not read\n--- transcript ---\n{}",
                    self.seen.join("\n")
                )
            })
    }

    /// Every line written until the process exits.
    fn finish(&mut self) -> String {
        let until = Instant::now() + DEADLINE;
        loop {
            if self.child.try_wait().expect("wait").is_some() {
                break;
            }
            assert!(
                Instant::now() < until,
                "the node did not exit\n--- transcript ---\n{}",
                self.seen.join("\n")
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }

    /// Ask the process to stop the way an operator does: its sessions close.
    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill -TERM failed");
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
            "wz-ap-demo-sessions-driver-liveliness-{case}-{}",
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

/// A document of one listening session that carries `driver`.
fn listener_document(driver: &str) -> String {
    format!(
        r#"{{ sessions: [
            {{ name: "inbound", mode: "peer", transport: "unicast", zid: "ee01",
              listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
              driver: [ {driver} ] }} ] }}"#
    )
}

/// A document of one client session, dialled to `addr`, that carries `driver`.
fn client_document(addr: &str, driver: &str) -> String {
    format!(
        r#"{{ sessions: [
            {{ name: "out", mode: "client", transport: "unicast", zid: "ee02",
              connect: {{ endpoints: ["{addr}"] }},
              driver: [ {driver} ] }} ] }}"#
    )
}

/// A client that holds a token is seen by the listener's liveliness subscriber
/// as soon as the token is declared, and the same subscriber sees it go away when
/// the client process is stopped.
#[test]
fn a_token_is_seen_to_appear_and_to_go_away_by_a_liveliness_subscriber() {
    let dir = Dir::new("appear");
    let listener_doc = dir.write(
        "listener.json5",
        &listener_document(r#"{ role: "liveliness_subscribe", key: "demo/alive/**" }"#),
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let addr = listening_on(&listener.expect_line("READY peer unicast listening on"));

    // The listener declares its subscriber only once it has accepted the client, so
    // a token declared at that instant would reach a subscriber that is not there
    // yet and be missed without any error. The hold leaves it the time.
    let client_doc = dir.write(
        "client.json5",
        &client_document(
            &addr,
            r#"{ role: "liveliness_token", key: "demo/alive/a", after_ms: 1000 }"#,
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);

    listener.expect_line("DRIVER liveliness_subscribe declared key=demo/alive/** history=false");
    listener.expect_line("DRIVER liveliness_subscribe sample key=demo/alive/a kind=Put");
    assert!(
        !listener
            .seen
            .iter()
            .any(|l| l.contains("sample key=demo/alive/a kind=Del")),
        "the token went away before the client was stopped\n{}",
        listener.seen.join("\n")
    );

    client.terminate();
    listener.expect_line("DRIVER liveliness_subscribe sample key=demo/alive/a kind=Del");
    assert!(
        listener.position("sample key=demo/alive/a kind=Put")
            < listener.position("sample key=demo/alive/a kind=Del"),
        "{}",
        listener.seen.join("\n")
    );
    let transcript = client.finish();
    assert!(!transcript.contains("panicked"), "{transcript}");
}

/// A subscriber that asks for history sees a token that was declared before the
/// subscriber existed: the client declares its token the moment its session is
/// up, and the listener's subscriber is held back well past that.
#[test]
fn a_subscriber_with_history_sees_a_token_that_was_alive_before_it() {
    let dir = Dir::new("history");
    let listener_doc = dir.write(
        "listener.json5",
        &listener_document(
            r#"{ role: "liveliness_subscribe", key: "demo/alive/**", history: true, after_ms: 1500 }"#,
        ),
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let addr = listening_on(&listener.expect_line("READY peer unicast listening on"));

    let client_doc = dir.write(
        "client.json5",
        &client_document(
            &addr,
            r#"{ role: "liveliness_token", key: "demo/alive/h" }"#,
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);
    client.expect_line("DRIVER liveliness_token declared key=demo/alive/h");

    listener.expect_line("DRIVER liveliness_subscribe declared key=demo/alive/** history=true");
    listener.expect_line("DRIVER liveliness_subscribe sample key=demo/alive/h kind=Put");
}

/// A client that asks which tokens are alive is answered with the token the
/// listener holds, and the answer ends.
#[test]
fn a_liveliness_get_is_answered_with_the_token_the_listener_holds() {
    let dir = Dir::new("get");
    let listener_doc = dir.write(
        "listener.json5",
        &listener_document(r#"{ role: "liveliness_token", key: "demo/alive/g" }"#),
    );
    let mut listener = Node::spawn(&["--sessions", &listener_doc]);
    let addr = listening_on(&listener.expect_line("READY peer unicast listening on"));

    // The token is declared once the listener has accepted the client, and a
    // question asked before that is answered with an empty set; the hold gives the
    // declaration the time.
    let client_doc = dir.write(
        "client.json5",
        &client_document(
            &addr,
            r#"{ role: "liveliness_get", key: "demo/alive/*", timeout_ms: 5000, after_ms: 1000 }"#,
        ),
    );
    let mut client = Node::spawn(&["--sessions", &client_doc]);

    client.expect_line("DRIVER liveliness_get asked key=demo/alive/*");
    client.expect_line("DRIVER liveliness_get reply key=demo/alive/g");
    client.expect_line("DRIVER liveliness_get final");
    assert!(
        client.position("DRIVER liveliness_get reply key=demo/alive/g")
            < client.position("DRIVER liveliness_get final"),
        "the answer ended before the token was reported\n{}",
        client.seen.join("\n")
    );
    listener.expect_line("DRIVER liveliness_token declared key=demo/alive/g");
}
