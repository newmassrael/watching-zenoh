// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "zenoh-config",
    feature = "routing-peer",
    feature = "router-hat-router",
))]

//! R2099 (open-debt item 512) — a node handed a config document whose
//! `listen/endpoints` names TWO addresses binds BOTH of them, and ACCEPTS on
//! both.
//!
//! ## What item 512 was
//!
//! Measured at R2091b: `{ mode: "router", listen: { endpoints:
//! ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"] } }` expanded to `--router-hat
//! tcp/127.0.0.1:0`, the node logged one `listening on`, the second address
//! appeared nowhere — and the report still said `APPLIED [… "listen/endpoints"
//! …]`. Not the lie item 508's gate catches (that one is "the key never reached
//! a flag"): the key DID reach its flag, carrying one of its two members. Item
//! 220's axis, one layer in.
//!
//! ## Why a process test
//!
//! A unit test over the expansion sees that both members reach the argv, and
//! one does (`args::stock_config_tests`). Nothing below `main` can see whether
//! the NODE bound them: a run-mode host still binding `listen[0]` passes every
//! such unit test, which is item 479's class and exactly the shape 512 took. So
//! the witness is the process — run the binary against a real document and read
//! its REAL stderr.
//!
//! ## Why it opens a session rather than reading the log
//!
//! Three strengths were available, and the weakest two are not enough:
//!
//! * the node LOGS two bind lines — a host that logged both and bound one would
//!   pass;
//! * a TCP `connect` to the second address SUCCEEDS — the kernel completes a
//!   handshake into the listen backlog whether or not anything ever calls
//!   `accept`, so this cannot see a loop that accepts on the first listener
//!   only;
//! * a wz node DIALS the second address and the listener reports `face … UP` —
//!   that requires the bind, the accept fan-in
//!   (`accept_loop::accept_any`) and the session open, and it is the one used.
//!
//! ## Both BINDING run-modes, from one table
//!
//! `mode: "peer"` and `mode: "router"` reach DIFFERENT hosts —
//! `runner::run_peer_until` and `runner::run_router_hat_until` — which is how
//! item 512's sibling defects have gone: R2095 found the two mesh arms wired
//! separately and measured separately. One table asks both, and every arm is
//! collected rather than asserted where it is read, so an early failure does
//! not leave the later ones UNMEASURED and reported as passing.
//!
//! ## Why `127.0.0.1` and `127.0.0.2`
//!
//! The register's own measurement used exactly this pair, and the whole
//! `127.0.0.0/8` is loopback on Linux, so both bind on any machine that can run
//! this suite. Port `0` on both: the node resolves each to a real ephemeral
//! port and prints it, which is what makes the dial-back possible at all — a
//! hardcoded port would be a second thing that can fail.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// The two addresses every arm's document names, in document order.
const ENDPOINTS: [&str; 2] = ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"];

/// How long a node gets to bind both addresses, and how long the listener gets
/// to report the dialled face. Generous against a loaded build machine; every
/// wait returns as soon as its line arrives, so the budget is paid only by a
/// FAILING arm.
const DEADLINE: Duration = Duration::from_secs(20);

/// The line `runner::bind_all_endpoints` writes per BOUND address. Pinned as a
/// literal so a round that renames it reds this test instead of silently
/// matching nothing — an absent message and a node that never bound look
/// identical to a `contains` (R2077).
const BOUND: &str = "BOUND LISTEN ENDPOINT";

/// The listener's report that an inbound link reached Established. This is the
/// assertion that needs the accept fan-in, not just the bind.
const FACE_UP: &str = "UP (peer ";

/// A directory of this test's own, removed on the way out.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("wz-listen-list-{}-{case}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a temp directory for this case");
        Fixture { dir }
    }

    fn write(&self, name: &str, source: &str) -> PathBuf {
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

/// A spawned node, its stderr streaming into a channel, killed and reaped on
/// the way out.
///
/// The demo's binding run-modes run until a signal, so every arm MUST kill its
/// child — a leaked node holds its ports and the next arm's bind fails for a
/// reason that has nothing to do with the code under test.
struct Node {
    child: Child,
    lines: Receiver<String>,
    /// Every line read so far, so a failure message can show the whole
    /// transcript rather than the one line that did not arrive.
    seen: Vec<String>,
}

impl Node {
    /// Start the demo against `path`, streaming its stderr.
    ///
    /// The reader runs on its own thread because a node that binds nothing
    /// writes nothing, and a blocking read on this thread would hang the suite
    /// rather than fail it.
    fn start(path: &Path) -> Node {
        let mut child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
            .arg("--config")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the demo binary runs");
        let stderr = child.stderr.take().expect("stderr was piped");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                // A closed receiver means the arm is over; stop reading rather
                // than spinning on a dead channel.
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Node {
            child,
            lines: rx,
            seen: Vec::new(),
        }
    }

    /// Read until `want` lines containing `needle` have been seen, or the
    /// deadline passes. Returns whether the count was reached.
    ///
    /// EVERY line is retained, not only the matching ones: the `--config`
    /// report rides this same stream, and a later question about it must not be
    /// answered "the node printed nothing".
    fn wait_for(&mut self, needle: &str, want: usize) -> bool {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if self.seen.iter().filter(|l| l.contains(needle)).count() >= want {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => self.seen.push(line),
                Err(RecvTimeoutError::Timeout) => return false,
                // The node died: drain nothing further, but let the caller
                // decide — its transcript is what explains why.
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
    }

    fn transcript(&self) -> String {
        self.seen.join("\n")
    }

    /// The `host:port` each `BOUND LISTEN ENDPOINT` line reports, in the order
    /// the node bound them.
    ///
    /// Read out of the line rather than assumed, because the document asked for
    /// port `0` and only the node knows what it got — which is the same reason
    /// the line carries the RESOLVED display in the first place.
    fn bound_addresses(&self) -> Vec<SocketAddr> {
        self.seen
            .iter()
            .filter(|l| l.contains(BOUND))
            .filter_map(|l| {
                // `... BOUND LISTEN ENDPOINT 1/2 127.0.0.1:41234 (from tcp/...)`
                let tail = l.split(BOUND).nth(1)?;
                let mut words = tail.split_whitespace();
                let _index = words.next()?;
                words.next()?.parse::<SocketAddr>().ok()
            })
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A spawned dialler, killed and reaped on the way out.
///
/// KILLED rather than waited for, and that is a correction: the first cut of
/// this file called `Command::output()`, which waits for the child to EXIT. A
/// `--key`-only initiator against a live mesh node does not exit — it holds the
/// session — so the arm hung instead of failing, and the hang looked like a slow
/// test rather than a wrong assumption. What the arm needs from the dialler is
/// that it OPENED, and the listener is what reports that.
struct Dialer {
    child: Child,
}

impl Drop for Dialer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Dial `addr` with a one-shot wz initiator.
///
/// The DIALLER is the demo itself rather than a bare `TcpStream`, and that is
/// the point of the whole arm: a raw connect is completed by the kernel's
/// listen backlog whether or not the node ever calls `accept`, so it cannot
/// tell a two-listener accept loop from a one-listener one. A session open can.
fn dial(addr: &SocketAddr) -> Dialer {
    let child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .arg("--connect")
        .arg(format!("tcp/{addr}"))
        // The demo refuses an initiator with nothing to do, so the arm gives it
        // the smallest thing there is: one declared keyexpr. What happens to the
        // declaration is not the claim — the claim is that the listener saw a
        // face come up on the address it was dialled at.
        .arg("--key")
        .arg("wz/item512/multi-bind")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the demo binary runs");
    Dialer { child }
}

/// Every arm: the `mode` the document names. Both are BINDING modes with
/// separate hosts (`run_peer_until` / `run_router_hat_until`), which is the
/// whole reason for a table — item 512 lived in a `listen.first()` that each
/// host wrote for itself.
const MODES: &[&str] = &["peer", "router"];

#[test]
fn a_node_accepts_on_every_endpoint_its_config_lists() {
    let fixture = Fixture::new("bind-all");
    // Collected, not asserted where read: an arm that panics mid-table leaves
    // every later arm UNMEASURED, and unmeasured must not read as passed.
    let mut failures: Vec<String> = Vec::new();
    let mut arms = 0usize;

    for mode in MODES {
        arms += 1;
        let doc = format!(
            r#"{{ mode: "{mode}", listen: {{ endpoints: ["{}", "{}"] }} }}"#,
            ENDPOINTS[0], ENDPOINTS[1]
        );
        let path = fixture.write(&format!("{mode}.json5"), &doc);
        let mut node = Node::start(&path);
        node.wait_for(BOUND, ENDPOINTS.len());
        let bound = node.bound_addresses();

        if bound.len() != ENDPOINTS.len() {
            failures.push(format!(
                "mode {mode:?}: the document named {} listen endpoints and the node \
                 announced {} bound.\n--- stderr ---\n{}",
                ENDPOINTS.len(),
                bound.len(),
                node.transcript(),
            ));
            continue;
        }

        // Both bound addresses must be DISTINCT: two `:0` binds that resolved to
        // one port would mean the second line described the first socket.
        if bound[0] == bound[1] {
            failures.push(format!(
                "mode {mode:?}: both bind lines name {}, so one socket is being \
                 reported twice.\n--- stderr ---\n{}",
                bound[0],
                node.transcript(),
            ));
            continue;
        }

        // THE assertion: a session opened against the endpoint item 512 dropped.
        // The LAST one, deliberately — the defect kept `listen[0]` working, so
        // an arm that dialled the first address would have been green
        // throughout the life of the bug.
        let last = bound[bound.len() - 1];
        let dialer = dial(&last);
        if !node.wait_for(FACE_UP, 1) {
            failures.push(format!(
                "mode {mode:?}: dialled endpoint {}/{} at {last} and the node never \
                 reported a face UP.\n--- node stderr ---\n{}",
                ENDPOINTS.len(),
                ENDPOINTS.len(),
                node.transcript(),
            ));
        }
        drop(dialer);
    }

    assert_eq!(arms, MODES.len(), "every run-mode arm was attempted");
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The REPORT half of item 512, on the same binary and in the same run as the
/// binds: a listen list the node took in full is reported APPLIED, and the run
/// that says so is the run that bound every member.
///
/// Kept in this file rather than beside the unit tests because the claim is
/// about what the BINARY prints — `main` decides where the report goes, and
/// item 479's class is what a unit test over the expansion would leave open.
#[test]
fn the_report_calls_the_listen_list_applied_only_when_the_node_took_all_of_it() {
    let fixture = Fixture::new("report");
    let doc = format!(
        r#"{{ mode: "peer", listen: {{ endpoints: ["{}", "{}"] }} }}"#,
        ENDPOINTS[0], ENDPOINTS[1]
    );
    let path = fixture.write("peer.json5", &doc);
    let mut node = Node::start(&path);
    node.wait_for(BOUND, ENDPOINTS.len());
    let transcript = node.transcript();

    let applied = node
        .seen
        .iter()
        .find(|l| l.contains("APPLIED"))
        .unwrap_or_else(|| panic!("the run reports what it applied\n--- stderr ---\n{transcript}"));
    assert!(
        applied.contains("listen/endpoints"),
        "both endpoints reached the node, so the key is applied: {applied}"
    );
    assert_eq!(
        node.bound_addresses().len(),
        ENDPOINTS.len(),
        "the run that reported APPLIED bound every endpoint\n--- stderr ---\n{transcript}"
    );
}
