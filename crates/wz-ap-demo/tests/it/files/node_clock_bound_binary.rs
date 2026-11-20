// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A run whose node clock was refused exits with the clock's reason.
//!
//! `UHLC_MAX_DELTA_MS` stating a bound the node clock does not honour (here `soon`, which is no
//! number of milliseconds) leaves a node that was to stamp without its clock. Each run mode that
//! builds one, a one-shot `--connect` client, a `--peer` and a `--router-hat`, refuses to go on:
//! it exits with status 1 and writes the reason, which names the variable and the value, as
//! upstream's node does not start on such a value. The control of each is the same run with the
//! variable unset, which reaches the line the run writes after its clock is built.
//!
//! The variable is set on the demo process alone, so no other test sees it.
#![cfg(feature = "time-hlc")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How long a run gets to write its line or exit. Only a failing leg pays it.
const DEADLINE: Duration = Duration::from_secs(20);

/// The stated bound the clock refuses.
const REFUSED: &str = "soon";

/// A running demo and the lines it writes to stderr.
struct Node {
    child: Child,
    lines: Receiver<String>,
}

impl Node {
    /// Start the demo with `args`, its `UHLC_MAX_DELTA_MS` set to `bound` when one is given.
    fn spawn(args: &[String], bound: Option<&str>) -> Node {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
        command
            .args(args)
            // The lines this file waits for are written at `info`.
            .env("RUST_LOG", "info")
            .env_remove("UHLC_MAX_DELTA_MS")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(bound) = bound {
            command.env("UHLC_MAX_DELTA_MS", bound);
        }
        let mut child = command.spawn().expect("the demo binary runs");
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

    /// Read lines until one contains `needle`, the node's stderr closes, or [`DEADLINE`]
    /// passes. Whether it was seen, and every line read.
    fn watch_for(&self, needle: &str) -> (bool, Vec<String>) {
        let mut seen = Vec::new();
        let until = Instant::now() + DEADLINE;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return (false, seen);
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = line.contains(needle);
                    seen.push(line);
                    if hit {
                        return (true, seen);
                    }
                }
                Err(RecvTimeoutError::Disconnected) | Err(RecvTimeoutError::Timeout) => {
                    return (false, seen)
                }
            }
        }
    }

    /// Wait for the node to exit within [`DEADLINE`].
    fn exit_status(&mut self) -> Option<ExitStatus> {
        let until = Instant::now() + DEADLINE;
        while Instant::now() < until {
            if let Some(status) = self.child.try_wait().expect("the demo can be waited on") {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

/// A loopback locator nothing listens on yet.
fn locator() -> String {
    format!(
        "tcp/127.0.0.1:{}",
        wz_runtime_tokio_test_support::free_port()
    )
}

/// The run `setup` gives (its argv, and a node it needs kept up while it runs, a listener for a
/// client) exits under the refused bound with status 1 and the clock's reason, before it writes
/// `after_clock`; with the variable unset it writes `after_clock`. Each half has a setup of its
/// own, so neither meets what the other left.
fn assert_refused_then_controlled(
    case: &str,
    setup: impl Fn() -> (Vec<String>, Option<Node>),
    after_clock: &str,
) {
    let (run, _helper) = setup();
    let mut refused = Node::spawn(&run, Some(REFUSED));
    let (reached, seen) = refused.watch_for("UHLC_MAX_DELTA_MS");
    let transcript = seen.join("\n");
    assert!(
        reached && transcript.contains(REFUSED),
        "{case}: no reason naming the variable and `{REFUSED}`.\n--- transcript ---\n{transcript}"
    );
    assert!(
        !transcript.contains(after_clock),
        "{case}: the run went on past its clock.\n--- transcript ---\n{transcript}"
    );
    let status = refused.exit_status();
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(1),
        "{case}: the refused run did not exit with status 1.\n--- transcript ---\n{transcript}"
    );

    let (run, _helper) = setup();
    let control = Node::spawn(&run, None);
    let (reached, seen) = control.watch_for(after_clock);
    assert!(
        reached,
        "{case}: with the variable unset the run never wrote `{after_clock}`.\n\
         --- transcript ---\n{}",
        seen.join("\n")
    );
}

/// A one-shot client that stamps (`--timestamping true` for its role) builds its clock once its
/// session is established, with a listener of its own that runs with the variable unset.
#[test]
fn a_client_whose_stated_clock_bound_is_refused_exits_with_the_reason() {
    assert_refused_then_controlled(
        "--connect",
        || {
            let locator = locator();
            let listener = Node::spawn(&argv(&["--listen", &locator, "--key", "demo/**"]), None);
            let run = argv(&[
                "--connect",
                &locator,
                "--connect-timeout",
                "10000",
                "--connect-retry",
                "100,200,2",
                "--key",
                "demo/**",
                "--timestamping",
                "true",
            ]);
            (run, Some(listener))
        },
        "driving session FSM",
    );
}

/// A peer that stamps builds its clock in its forwarder, after its listener is bound.
#[cfg(feature = "routing-peer")]
#[test]
fn a_peer_whose_stated_clock_bound_is_refused_exits_with_the_reason() {
    assert_refused_then_controlled(
        "--peer",
        || {
            let run = argv(&[
                "--peer",
                &locator(),
                "--subscribe",
                "demo/**",
                "--timestamping",
                "true",
            ]);
            (run, None)
        },
        "ADVERTISED SELF LOCATOR",
    );
}

/// A router stamps by zenoh's shipped map, so it builds its clock with nothing stated.
#[cfg(feature = "router-hat-router")]
#[test]
fn a_router_whose_stated_clock_bound_is_refused_exits_with_the_reason() {
    assert_refused_then_controlled(
        "--router-hat",
        || (argv(&["--router-hat", &locator()]), None),
        "ADVERTISED SELF LOCATOR",
    );
}
