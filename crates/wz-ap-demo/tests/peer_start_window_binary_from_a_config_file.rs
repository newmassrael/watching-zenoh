// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `open/return_conditions/connect_scouted` read from a `--config` FILE: the
//! start window `peer_start_window_binary.rs` reads off a typed
//! `--scouting-delay`, now driven by a stock zenoh document.
//!
//! ## What is observed, and why it is not a START WINDOW line
//!
//! With `connect_scouted: false` the peer has NO window: the application starts
//! on its first tick and the demo prints neither `START WINDOW met` nor
//! `START WINDOW passed`, because those lines announce the moment a window
//! closes and there is none. The observable is therefore the application's first
//! act, `declared subscriber`, and what stands before it in the transcript:
//!
//! - the file says `connect_scouted: false` over an 8 s `scouting/delay`: the
//!   subscriber is declared with no START WINDOW line before it and well inside
//!   the delay, against a dial target that never answers;
//! - the control, a file that states a 1.2 s `scouting/delay` and no
//!   `connect_scouted`: the window PASSES, its line stands before the
//!   declaration, and not before the delay.
//!
//! The ordering is read off the transcript rather than a stopwatch, so a loaded
//! machine cannot move the verdict; the elapsed-time bounds only separate an 8 s
//! hold from a prompt start.

#![cfg(all(feature = "routing-peer", feature = "zenoh-config"))]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(20);
const WINDOW_LINE: &str = "START WINDOW";
const PASSED: &str = "START WINDOW passed";
const DECLARED: &str = "peer: declared subscriber demo/**";

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

    /// Every line up to and including the first one containing `needle`, and
    /// when that one arrived; `None` for the time when it never did.
    fn until(&self, needle: &str) -> (Option<Instant>, Vec<String>) {
        let mut seen = Vec::new();
        let until = Instant::now() + DEADLINE;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return (None, seen);
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = line.contains(needle);
                    seen.push(line);
                    if hit {
                        return (Some(Instant::now()), seen);
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

/// A directory of this test's own, removed on the way out.
struct Fixture {
    dir: std::path::PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("wz-start-window-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory for this case");
        Fixture { dir }
    }

    fn write(&self, name: &str, source: &str) -> std::path::PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, source).expect("the fixture file");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `--peer <free port> --connect <a target that refuses> --subscribe demo/**
/// --config <path>`: the file supplies the window keys and nothing else.
fn argv_over_a_dead_target(config: &std::path::Path, target: &str) -> Vec<String> {
    let listen = format!(
        "tcp/127.0.0.1:{}",
        wz_runtime_tokio_test_support::free_port()
    );
    let config_arg = config.display().to_string();
    let items: [&str; 8] = [
        "--peer",
        listen.as_str(),
        "--connect",
        target,
        "--subscribe",
        "demo/**",
        "--config",
        config_arg.as_str(),
    ];
    items.iter().map(|s| String::from(*s)).collect()
}

#[test]
fn a_config_file_saying_connect_scouted_false_starts_the_application_without_a_window() {
    let fixture = Fixture::new("scouted-false");
    let dead = wz_runtime_tokio_test_support::refusing_port();
    let target = format!("tcp/{}", dead.addr());
    let path = fixture.write(
        "z.json5",
        r#"{ scouting: { delay: 8000 },
             open: { return_conditions: { connect_scouted: false } } }"#,
    );
    let started = Instant::now();
    let node = Node::spawn(&argv_over_a_dead_target(&path, &target));

    let (at, seen) = node.until(DECLARED);
    let at = at.unwrap_or_else(|| {
        panic!(
            "the application never declared its subscriber\n--- transcript ---\n{}",
            seen.join("\n")
        )
    });
    let transcript = seen.join("\n");
    assert!(
        transcript.contains("\"--connect-scouted\", \"false\""),
        "the file's `connect_scouted: false` never reached `--connect-scouted`\n\
         --- transcript ---\n{transcript}"
    );
    assert!(
        !transcript.contains(WINDOW_LINE),
        "a START WINDOW line stands before the first application act, so the peer held \
         its application back although the file says it does not wait for its peers\n\
         --- transcript ---\n{transcript}"
    );
    assert!(
        at.duration_since(started) < Duration::from_secs(6),
        "the application started {:?} in; an 8 s `scouting/delay` was waited out although \
         `connect_scouted` is false\n--- transcript ---\n{transcript}",
        at.duration_since(started)
    );
}

#[test]
fn a_config_file_without_connect_scouted_holds_the_application_for_the_window() {
    let fixture = Fixture::new("scouted-unnamed");
    let dead = wz_runtime_tokio_test_support::refusing_port();
    let target = format!("tcp/{}", dead.addr());
    let path = fixture.write("z.json5", r#"{ scouting: { delay: 1200 } }"#);
    let started = Instant::now();
    let node = Node::spawn(&argv_over_a_dead_target(&path, &target));

    let (at, seen) = node.until(DECLARED);
    let at = at.unwrap_or_else(|| {
        panic!(
            "the application never declared its subscriber\n--- transcript ---\n{}",
            seen.join("\n")
        )
    });
    let transcript = seen.join("\n");
    assert!(
        !transcript.contains("\"--connect-scouted\""),
        "a file that does not name `connect_scouted` expanded to `--connect-scouted`\n\
         --- transcript ---\n{transcript}"
    );
    let passed_at = seen
        .iter()
        .position(|l| l.contains(PASSED))
        .unwrap_or_else(|| {
            panic!(
                "nothing answered and no window was waived, yet no `{PASSED}` line stands \
                 before the application's first act\n--- transcript ---\n{transcript}"
            )
        });
    assert!(
        passed_at + 1 < seen.len(),
        "the window line must stand BEFORE the declaration\n--- transcript ---\n{transcript}"
    );
    assert!(
        at.duration_since(started) >= Duration::from_millis(1100),
        "the application started {:?} in, before the file's 1200 ms window",
        at.duration_since(started)
    );
}
