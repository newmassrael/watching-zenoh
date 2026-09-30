// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A one-shot `--connect` client runs upstream's client startup
//! connect phase: `connect/timeout_ms` decides whether it re-dials, and
//! `connect/retry` paces it.
//!
//! The consumer's case is a lab that starts a client beside the router it
//! dials, and a config generator that therefore writes `timeout_ms: -1` into
//! client documents. Before this, the demo reported the key withheld and the
//! client dialled once and exited.
//!
//! Every leg starts the client BEFORE anything listens, so an Established
//! session can only come from a re-dial. The control is the same client with no
//! budget: upstream's client default is one attempt, and that must not move.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How long a client gets to reach Established once its listener is up.
/// Generous against a loaded build machine; only a failing leg pays it.
const DEADLINE: Duration = Duration::from_secs(20);

/// How long the listener is started after the client. Long enough that the
/// client's first attempt has certainly been refused.
const LISTENER_LATE_BY: Duration = Duration::from_millis(600);

const ESTABLISHED: &str = "session Established; entering steady state";
const RE_DIAL: &str = "wz-ap-demo: connect attempt ";

/// A running demo and the lines it writes to stderr.
struct Node {
    child: Child,
    lines: Receiver<String>,
}

impl Node {
    fn spawn(args: &[String]) -> Node {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
            .args(args)
            // Pinned, as the other binary legs pin it: the logger defaults to
            // `info` only when RUST_LOG is unset.
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

    /// Read lines until one contains `needle`, the node exits, or `deadline`
    /// passes. Returns whether it was seen, and every line read.
    fn watch_for(&self, needle: &str, deadline: Duration) -> (bool, Vec<String>) {
        let mut seen = Vec::new();
        let until = Instant::now() + deadline;
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
        .chain(["--key".to_string(), "demo/**".to_string()])
        .collect()
}

/// A loopback locator nothing listens on yet.
fn late_locator() -> String {
    format!(
        "tcp/127.0.0.1:{}",
        wz_runtime_tokio_test_support::free_port()
    )
}

/// Start `client`, then a listener on `locator` after [`LISTENER_LATE_BY`],
/// and require the client to reach Established by re-dialing.
fn assert_client_waits_for_the_listener(case: &str, client: &[String], locator: &str) {
    let client_node = Node::spawn(client);
    std::thread::sleep(LISTENER_LATE_BY);
    let _listener = Node::spawn(&argv(&["--listen", locator]));
    let (established, seen) = client_node.watch_for(ESTABLISHED, DEADLINE);
    let transcript = seen.join("\n");
    assert!(
        established,
        "{case}: the client never reached Established.\nargv = {client:?}\n\
         --- transcript ---\n{transcript}"
    );
    assert!(
        transcript.contains(RE_DIAL),
        "{case}: the client reached Established without re-dialing, so it did \
         not dial before the listener and this leg measured nothing.\n\
         --- transcript ---\n{transcript}"
    );
}

/// From the command line: `--connect-timeout` with `--connect-retry`.
#[test]
fn a_typed_connect_budget_makes_a_client_wait_for_its_router() {
    let locator = late_locator();
    assert_client_waits_for_the_listener(
        "--connect-timeout",
        &argv(&[
            "--connect",
            &locator,
            "--connect-timeout",
            "10000",
            "--connect-retry",
            "100,200,2",
        ]),
        &locator,
    );
}

/// The control: no budget is upstream's client default, one attempt. The node
/// fails its open and exits without re-dialing.
#[test]
fn a_client_without_a_connect_budget_dials_once() {
    let locator = late_locator();
    let client = argv(&["--connect", &locator]);
    let node = Node::spawn(&client);
    let (re_dialed, seen) = node.watch_for(RE_DIAL, Duration::from_secs(5));
    let transcript = seen.join("\n");
    assert!(
        !re_dialed,
        "a client with no connect budget re-dialed.\n--- transcript ---\n{transcript}"
    );
    assert!(
        !transcript.contains(ESTABLISHED),
        "nothing listens, yet the client reports Established.\n--- transcript ---\n{transcript}"
    );
}

/// A client DOCUMENT that asks for no application work is a whole
/// node, as zenohd runs it: it connects and holds its session. Spawned WITHOUT
/// [`argv`], whose `--key` is exactly what hid this — every other leg here
/// names an action, so the demo's no-action refusal was never reached.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_client_document_with_no_action_flag_is_a_whole_node() {
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let locator = late_locator();
    let dir = Dir(std::env::temp_dir().join(format!(
        "wz-ap-demo-bare-client-document-{}",
        std::process::id()
    )));
    std::fs::create_dir_all(&dir.0).expect("a directory of this test's own");
    let path = dir.0.join("client.json5");
    std::fs::write(
        &path,
        format!(
            r#"{{ mode: "client",
                  connect: {{ endpoints: ["{locator}"], timeout_ms: -1,
                              retry: {{ period_init_ms: 100, period_max_ms: 200 }} }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#
        ),
    )
    .expect("the config file is written");
    let client = vec![String::from("--config"), path.display().to_string()];
    let client_node = Node::spawn(&client);
    std::thread::sleep(LISTENER_LATE_BY);
    let _listener = Node::spawn(&argv(&["--listen", &locator]));
    let (established, seen) = client_node.watch_for(ESTABLISHED, DEADLINE);
    assert!(
        established,
        "a client document with no action flag must still stand as a node\n\
         --- transcript ---\n{}",
        seen.join("\n")
    );
}

/// From a FILE — the consumer's own case: a client document carrying
/// `connect/timeout_ms: -1`.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_client_document_with_an_unbounded_budget_waits_for_its_router() {
    /// Removes the test's directory on the way out, including a failing one.
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let locator = late_locator();
    let dir = Dir(std::env::temp_dir().join(format!(
        "wz-ap-demo-client-connect-phase-{}",
        std::process::id()
    )));
    std::fs::create_dir_all(&dir.0).expect("a directory of this test's own");
    let path = dir.0.join("client.json5");
    std::fs::write(
        &path,
        format!(
            r#"{{ mode: "client",
                  connect: {{ endpoints: ["{locator}"], timeout_ms: -1,
                              retry: {{ period_init_ms: 100, period_max_ms: 200 }} }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#
        ),
    )
    .expect("the config file is written");
    assert_client_waits_for_the_listener(
        "--config with connect/timeout_ms: -1",
        &argv(&["--config", &path.display().to_string()]),
        &locator,
    );
}
