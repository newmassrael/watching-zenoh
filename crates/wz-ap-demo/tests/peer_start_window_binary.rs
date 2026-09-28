// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2951 — a `--peer` holds its application back for its dialled peers, up to
//! `scouting/delay`, as upstream's `start_peer` holds its open back under
//! `open/return_conditions/connect_scouted`.
//!
//! The demo announces the moment it lets the application start
//! (`START WINDOW met` / `START WINDOW passed`), and these legs read it:
//!
//! - a dial target that never answers: the window PASSES, and not before the
//!   configured delay;
//! - a dial target that is up: the window is MET, well inside a long delay;
//! - a peer that only dials IN: the window still PASSES, because upstream's
//!   start conditions count this node's own dials and an accepted face is not
//!   one. This is the leg `Face::dialed` exists for.

#![cfg(feature = "routing-peer")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);
const MET: &str = "START WINDOW met";
const PASSED: &str = "START WINDOW passed";

struct Node {
    child: Child,
    lines: Receiver<String>,
}

impl Node {
    fn spawn(args: &[String]) -> Node {
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
        Node { child, lines }
    }

    /// The first line containing either needle, and when it arrived, or `None`
    /// with every line read.
    fn first_of(&self, needles: &[&str]) -> (Option<(String, Instant)>, Vec<String>) {
        let mut seen = Vec::new();
        let until = Instant::now() + DEADLINE;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return (None, seen);
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = needles.iter().any(|n| line.contains(n));
                    seen.push(line.clone());
                    if hit {
                        return (Some((line, Instant::now())), seen);
                    }
                }
                Err(RecvTimeoutError::Disconnected) | Err(RecvTimeoutError::Timeout) => {
                    return (None, seen)
                }
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

fn argv(items: &[&str]) -> Vec<String> {
    items
        .iter()
        .map(|s| String::from(*s))
        .chain(["--subscribe".to_string(), "demo/**".to_string()])
        .collect()
}

fn locator(port: u16) -> String {
    format!("tcp/127.0.0.1:{port}")
}

#[test]
fn a_peer_whose_target_never_answers_starts_when_the_window_passes() {
    let dead = wz_runtime_tokio_test_support::refusing_port();
    let target = format!("tcp/{}", dead.addr());
    let listen = locator(wz_runtime_tokio_test_support::free_port());
    let started = Instant::now();
    let node = Node::spawn(&argv(&[
        "--peer",
        &listen,
        "--connect",
        &target,
        "--scouting-delay",
        "1200",
    ]));
    let (hit, seen) = node.first_of(&[MET, PASSED]);
    let (line, at) = hit.unwrap_or_else(|| {
        panic!(
            "no START WINDOW line\n--- transcript ---\n{}",
            seen.join("\n")
        )
    });
    assert!(line.contains(PASSED), "nothing answered, yet: {line}");
    assert!(
        at.duration_since(started) >= Duration::from_millis(1100),
        "the application started {:?} in, before the 1200 ms window",
        at.duration_since(started)
    );
}

#[test]
fn a_peer_whose_target_is_up_starts_as_soon_as_it_connects() {
    let port_b = wz_runtime_tokio_test_support::free_port();
    let _b = Node::spawn(&argv(&["--peer", &locator(port_b)]));
    std::thread::sleep(Duration::from_millis(300));
    let listen_a = locator(wz_runtime_tokio_test_support::free_port());
    let started = Instant::now();
    let a = Node::spawn(&argv(&[
        "--peer",
        &listen_a,
        "--connect",
        &locator(port_b),
        "--scouting-delay",
        "8000",
    ]));
    let (hit, seen) = a.first_of(&[MET, PASSED]);
    let (line, at) = hit.unwrap_or_else(|| {
        panic!(
            "no START WINDOW line\n--- transcript ---\n{}",
            seen.join("\n")
        )
    });
    assert!(line.contains(MET), "its one target was up: {line}");
    assert!(
        at.duration_since(started) < Duration::from_secs(6),
        "a connected peer must not wait out an 8 s window: {:?}",
        at.duration_since(started)
    );
}

#[test]
fn an_inbound_peer_does_not_meet_the_window() {
    let dead = wz_runtime_tokio_test_support::refusing_port();
    let target = format!("tcp/{}", dead.addr());
    let port_a = wz_runtime_tokio_test_support::free_port();
    let started = Instant::now();
    let a = Node::spawn(&argv(&[
        "--peer",
        &locator(port_a),
        "--connect",
        &target,
        "--scouting-delay",
        "2500",
    ]));
    std::thread::sleep(Duration::from_millis(300));
    // C dials IN to A; A's own dial still has nowhere to go.
    let _c = Node::spawn(&argv(&[
        "--peer",
        &locator(wz_runtime_tokio_test_support::free_port()),
        "--connect",
        &locator(port_a),
    ]));
    let (hit, seen) = a.first_of(&[MET, PASSED]);
    let (line, at) = hit.unwrap_or_else(|| {
        panic!(
            "no START WINDOW line\n--- transcript ---\n{}",
            seen.join("\n")
        )
    });
    assert!(
        line.contains(PASSED),
        "an ACCEPTED face met the window, which upstream's start conditions do \
         not count: {line}"
    );
    assert!(at.duration_since(started) >= Duration::from_millis(2400));
}
