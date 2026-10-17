// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `routing/interests/timeout` read from a `--config` FILE: the frozen-upstream
//! arm of `wz_peer_interest_pending_gc_pico_interop.rs`, with the brokered
//! interest's timeout stated in a stock zenoh document instead of
//! `--interest-timeout`.
//!
//! ## What this adds over the flag-level arm
//!
//! The flag arm proves the GC deadline follows `--interest-timeout`. The step
//! from `routing.interests.timeout` to that flag is covered by argv unit tests
//! only. Here the broker is given `--peer 127.0.0.1:0 --connect <upstream>
//! --config <file>` and no timeout flag, so a foreign `z_get_liveliness` returns
//! inside the window below only if the FILE'S millisecond value reached the
//! forwarder's deadline.
//!
//! ## The control
//!
//! The same topology and the same frozen upstream, with a file that does not name
//! the key. The forwarder's own default is 10 s, so the foreign client must still
//! be waiting at the budget (8 s, under both the default deadline and the session
//! lease) and the GC must not yet have reaped anything. A broker that ignored the
//! file would behave as the control in both legs; one that applied it to everything
//! would return early in the control.
//!
//! The bounds are the flag-level file's: pico has no timeout of its own for a
//! current interest (the note in the flag-level file's header, which cites the
//! pico source), so its process exit is the wire observable, a frozen upstream
//! cannot answer, and the lease cannot expire in under 10 s.
//!
//! Requires: wz-ap-demo built with `--features routing-peer,routing-interest-pending-gc,zenoh-config`
//! and the zenoh-pico CLI. Layer E6's lane owns that build.

use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedStatus as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, listen_port, read_captured,
    wait_for_exit, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// The keyexpr pico solicits. RESTRICTED (a literal prefix + `**`), because the
/// broker deliberately declines to propagate a match-all interest.
const GET_KEYEXPR: &str = "group1/**";

/// The document: a brokered interest's GC deadline of 2.5 s.
const DOC_INTEREST_TIMEOUT: &str = "{ routing: { interests: { timeout: 2500 } } }";
/// The document: names another key and leaves the interest timeout unnamed.
const DOC_WITHOUT_THE_KEY: &str = "{ timestamping: { enabled: false } }";

/// The GC deadline `DOC_INTEREST_TIMEOUT` states, in milliseconds.
const INTEREST_TIMEOUT_MS: u64 = 2500;

/// Upper bound on the frozen arm. Below the 10 s lease and the 10 s default
/// deadline by a wide margin, so a pass cannot have come from either.
const FROZEN_ARM_BUDGET: Duration = Duration::from_secs(8);

/// Lower bound on the frozen arm. A frozen process cannot answer, so nothing can
/// terminate the client before the GC deadline.
const FROZEN_ARM_FLOOR: Duration = Duration::from_millis(1_500);

/// A `--peer` demo on an ephemeral port, optionally dialing `connect` and
/// optionally given a `--config` document.
struct Peer {
    guard: ChildGuard,
    stderr: File,
    port: u16,
    /// Kept so the document outlives the process that read it.
    _config: Option<tempfile::NamedTempFile>,
}

fn spawn_peer(label: &str, connect: Option<u16>, document: Option<&str>) -> Peer {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;

    let config = document.map(|text| {
        let mut file = tempfile::Builder::new()
            .suffix(".json5")
            .tempfile()
            .expect("config tempfile");
        file.write_all(text.as_bytes()).expect("write config");
        file.flush().expect("flush config");
        file
    });

    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let mut cmd = Command::new(demo);
    cmd.args(["--peer", "127.0.0.1:0"]);
    let dial;
    if let Some(port) = connect {
        dial = format!("127.0.0.1:{port}");
        cmd.args(["--connect", &dial]);
    }
    if let Some(file) = &config {
        cmd.arg("--config").arg(file.path());
    }
    let mut guard = ChildGuard::wrap(
        format!("interest-broker peer {label}"),
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer"),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "wz-ap-demo did not bind a peer listener within 5s (is the binary built with \
             --features routing-peer,routing-interest-pending-gc,zenoh-config?)\n\
             --- peer {label} stderr ---\n{c}"
        );
    });
    // Every feature-set lane writes the SAME artifact path, so a stale binary from
    // a neighbouring lane is the standing hazard; the demo prints its own closure.
    assert!(
        captured.contains("routing-interest-pending-gc"),
        "peer {label} was built WITHOUT routing-interest-pending-gc — this lane would \
         measure the wrong binary.\n--- BUILD FEATURES line ---\n{captured}"
    );
    let port = listen_port(&captured);
    Peer {
        guard,
        stderr: reader,
        port,
        _config: config,
    }
}

impl Peer {
    fn signal(&mut self, sig: &str) {
        let pid = self.guard.child_mut().id().to_string();
        let status = Command::new("kill")
            .arg(sig)
            .arg(&pid)
            .status_bounded()
            .expect("kill(1) is available");
        assert!(status.success(), "kill {sig} {pid} failed");
    }

    /// Terminate the demo and return everything it logged.
    fn finish(mut self) -> String {
        graceful_terminate(self.guard.child_mut(), Duration::from_secs(5));
        read_captured(&mut self.stderr)
    }
}

/// Run `z_get_liveliness` against `port` and return `(exited_within_budget,
/// elapsed, captured)`. A pico that never returns is KILLED at the budget; that
/// timeout is the negative observable and is reported.
fn run_pico_get(port: u16, budget: Duration) -> (bool, Duration, String) {
    let stdout = tempfile::tempfile().expect("tempfile for pico stdout");
    let writer = stdout.try_clone().expect("dup pico stdout handle");
    let mut reader = stdout;
    // The clock starts at SPAWN: pico's own banner is block-buffered on a
    // redirected stdout and would read ~0 for every arm.
    let started = Instant::now();
    let mut guard = ChildGuard::wrap(
        "z_get_liveliness".to_string(),
        Command::new(zenoh_pico_cli_binary("z_get_liveliness"))
            .args([
                "-k",
                GET_KEYEXPR,
                "-m",
                "client",
                "-e",
                &format!("tcp/127.0.0.1:{port}"),
            ])
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr handle")))
            .stdout(Stdio::from(writer))
            .spawn()
            .expect("spawn zenoh-pico z_get_liveliness"),
    );
    let exited = wait_for_exit(guard.child_mut(), budget).is_ok();
    let elapsed = started.elapsed();
    if !exited {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
    }
    (exited, elapsed, read_captured(&mut reader))
}

/// Parse the `reaped by the GC` count out of the demo's own broker witness line.
fn gc_reaped(captured: &str) -> u64 {
    let line = captured
        .lines()
        .find(|l| l.contains("peer: interest broker;"))
        .unwrap_or_else(|| {
            panic!(
                "the broker witness line is absent — the peer was not built with the atom's \
                 feature.\n--- peer stderr ---\n{captured}"
            )
        });
    let (before, _) = line
        .rsplit_once(" reaped by the GC")
        .expect("the witness line ends with the GC count");
    before
        .rsplit(", ")
        .next()
        .expect("a count precedes `reaped by the GC`")
        .trim()
        .parse()
        .expect("the GC count is a number")
}

/// Start an upstream peer and a broker peer given `document`, freeze the upstream
/// AFTER the mesh face is up, and run one foreign liveliness get against the
/// broker. Returns what the foreign client did and what the broker logged.
fn freeze_the_upstream_and_ask(document: &str) -> (bool, Duration, String, String) {
    let mut upstream = spawn_peer("upstream", None, None);
    let mut broker = spawn_peer("broker", Some(upstream.port), Some(document));
    // The mesh face must exist BEFORE the upstream is frozen, else there is no
    // upstream to propagate to and this degrades into an inline answer.
    let mesh = wait_for_substring(&mut broker.stderr, "face 0 UP", Duration::from_secs(10))
        .unwrap_or_else(|c| panic!("the broker never linked to its upstream\n{c}"));
    assert!(
        mesh.contains("whatami Some(Peer)"),
        "the upstream face must be a PEER face — a client face is a leaf and is never \
         brokered to.\n{mesh}"
    );

    upstream.signal("-STOP");
    let (exited, elapsed, pico_out) = run_pico_get(broker.port, FROZEN_ARM_BUDGET);
    upstream.signal("-CONT");

    let broker_log = broker.finish();
    let _ = upstream.finish();
    (exited, elapsed, pico_out, broker_log)
}

/// A `--config` file stating `routing.interests.timeout: 2500` makes the broker's
/// GC finalize the foreign client inside the window, with exactly one entry
/// reaped.
// wz-proves: none -- the DOCUMENT -> flag half of the flag-level frozen arm in
// wz_peer_interest_pending_gc_pico_interop.rs, which carries the atom claim; pico only
// reads the broker's decision.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,routing-interest-pending-gc,zenoh-config + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_gc_terminates_a_pico_liveliness_get_at_the_timeout_a_config_file_states() {
    let (exited, elapsed, pico_out, broker_log) = freeze_the_upstream_and_ask(DOC_INTEREST_TIMEOUT);

    assert!(
        broker_log.contains("\"--interest-timeout\""),
        "the broker's report of the expansion does not name `--interest-timeout`, so the \
         file's `routing.interests.timeout` never became the flag\n--- broker stderr ---\n{broker_log}"
    );
    assert!(
        exited,
        "z_get_liveliness never returned within {FROZEN_ARM_BUDGET:?}: the file's \
         {INTEREST_TIMEOUT_MS}ms deadline did not reach the GC, so the foreign client \
         waited out the 10s default. pico has no timeout of its own.\n--- \
         z_get_liveliness stdout ---\n{pico_out}\n--- broker stderr ---\n{broker_log}"
    );
    assert!(
        elapsed >= FROZEN_ARM_FLOOR,
        "z_get_liveliness returned in {elapsed:?}, sooner than the {INTEREST_TIMEOUT_MS}ms \
         GC deadline — the interest was answered INLINE, so this leg proves nothing.\n\
         --- broker stderr ---\n{broker_log}"
    );
    assert_eq!(
        gc_reaped(&broker_log),
        1,
        "the GC must have reaped exactly the one propagated interest.\n\
         --- broker stderr ---\n{broker_log}"
    );
}

/// CONTROL, key absent: the same frozen upstream and a file that leaves
/// `routing.interests.timeout` unnamed keep the forwarder's 10 s default, so the
/// foreign client is still waiting at the 8 s budget and nothing was reaped.
// wz-proves: none -- the key-absent control of the leg above; it shows the early
// return is caused by the file's key and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,routing-interest-pending-gc,zenoh-config + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_keeps_a_pico_liveliness_get_pending_when_a_config_file_omits_the_timeout() {
    let (exited, elapsed, pico_out, broker_log) = freeze_the_upstream_and_ask(DOC_WITHOUT_THE_KEY);

    assert!(
        !broker_log.contains("\"--interest-timeout\""),
        "a file that does not name `routing.interests.timeout` expanded to \
         `--interest-timeout`\n--- broker stderr ---\n{broker_log}"
    );
    assert!(
        !exited,
        "z_get_liveliness returned after {elapsed:?} with the default 10s deadline and a \
         frozen upstream — the interest was not held by the pending table, so the \
         sibling leg's early return is not attributable to the file's key.\n--- \
         z_get_liveliness stdout ---\n{pico_out}\n--- broker stderr ---\n{broker_log}"
    );
    assert_eq!(
        gc_reaped(&broker_log),
        0,
        "the 10s default deadline had not passed, so the GC must have reaped NOTHING.\n\
         --- broker stderr ---\n{broker_log}"
    );
}
