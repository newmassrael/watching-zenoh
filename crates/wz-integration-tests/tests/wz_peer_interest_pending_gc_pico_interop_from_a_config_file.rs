// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `routing/interests/timeout` read from a `--config` FILE, on a peer that brokers no
//! interest (item 751 step 7b, `docs/peer-region-hats.md` sections 10 and 12a).
//!
//! This file was the document-to-flag half of `wz_peer_interest_pending_gc_pico_interop.rs`:
//! the brokered interest's deadline stated in a stock zenoh document instead of
//! `--interest-timeout`, and a frozen upstream that the deadline had to outlast. The
//! region-hat peer has no pending interest for a deadline to bound, so the key has nothing
//! to reach, and what the file can still show is two things:
//!
//! - A document naming the key does NOT stop the peer, and is reported read-and-not-applied
//!   with the build as the reason, never expanded into a `--interest-timeout` the peer
//!   refuses. The foreign client's current interest is answered promptly, the upstream
//!   frozen as before.
//! - The control: a document that does not name the key changes nothing about that, and
//!   is not reported.
//!
//! Requires: wz-ap-demo built with `--features routing-peer,zenoh-config` and the zenoh-pico
//! CLI. Layer E6's lane owns that build.

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

/// The document: the interest deadline the retired broker would have honoured, 2.5 s.
const DOC_INTEREST_TIMEOUT: &str = "{ routing: { interests: { timeout: 2500 } } }";
/// The document: names another key and leaves the interest timeout unnamed.
const DOC_WITHOUT_THE_KEY: &str = "{ timestamping: { enabled: false } }";

/// Upper bound on the arm, under the 10 s lease so a return cannot come from the face-down
/// path.
const ARM_BUDGET: Duration = Duration::from_secs(8);

/// How soon the foreign client must be answered: well under the 2.5 s the retired broker's
/// deadline named.
const PROMPT: Duration = Duration::from_millis(1_500);

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
        format!("region-hat peer {label}"),
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
             --features routing-peer,zenoh-config?)\n\
             --- peer {label} stderr ---\n{c}"
        );
    });
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
fn ask_with_the_upstream_frozen(document: &str) -> (bool, Duration, String, String) {
    let mut upstream = spawn_peer("upstream", None, None);
    let mut peer = spawn_peer("peer", Some(upstream.port), Some(document));
    // The mesh face exists BEFORE the upstream is frozen, so the peer has an upstream that
    // answers nothing, the case the retired broker had to time out.
    let mesh = wait_for_substring(&mut peer.stderr, "face 0 UP", Duration::from_secs(10))
        .unwrap_or_else(|c| panic!("the peer never linked to its upstream\n{c}"));
    assert!(
        mesh.contains("whatami Some(Peer)"),
        "the upstream face must be a PEER face.\n{mesh}"
    );

    upstream.signal("-STOP");
    let (exited, elapsed, pico_out) = run_pico_get(peer.port, ARM_BUDGET);
    upstream.signal("-CONT");

    let peer_log = peer.finish();
    let _ = upstream.finish();
    (exited, elapsed, pico_out, peer_log)
}

/// A `--config` file stating `routing.interests.timeout: 2500` does not stop the peer, is
/// reported as read and not applied, and the foreign client is answered promptly with the
/// upstream frozen.
// wz-proves: none -- the DOCUMENT half of the frozen arm in
// wz_peer_interest_pending_gc_pico_interop.rs; it shows a document naming the retired key is
// reported and does not wedge the peer, and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,zenoh-config + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_reports_a_config_files_interest_timeout_as_not_applied_and_answers_promptly() {
    let (exited, elapsed, pico_out, peer_log) = ask_with_the_upstream_frozen(DOC_INTEREST_TIMEOUT);

    assert!(
        !peer_log.contains("\"--interest-timeout\""),
        "the file's `routing.interests.timeout` was expanded into `--interest-timeout`, which \
         the peer refuses.\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        peer_log.contains("routing/interests/timeout"),
        "the peer does not say it read `routing/interests/timeout` and applied nothing.\n\
         --- peer stderr ---\n{peer_log}"
    );
    assert!(
        exited,
        "z_get_liveliness never returned within {ARM_BUDGET:?} against a frozen upstream.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed < PROMPT,
        "z_get_liveliness took {elapsed:?}: the peer waited on its upstream.\n\
         --- peer stderr ---\n{peer_log}"
    );
}

/// CONTROL, key absent: a file that leaves `routing.interests.timeout` unnamed is not
/// reported for it, and the answer is as prompt.
// wz-proves: none -- the key-absent control of the leg above; it shows the report is caused
// by the file's key and claims no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,zenoh-config + zenoh-pico z_get_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_without_the_interest_timeout_key_reports_nothing_and_answers_promptly() {
    let (exited, elapsed, pico_out, peer_log) = ask_with_the_upstream_frozen(DOC_WITHOUT_THE_KEY);

    assert!(
        !peer_log.contains("routing/interests/timeout"),
        "a file that does not name `routing.interests.timeout` was reported for it.\n\
         --- peer stderr ---\n{peer_log}"
    );
    assert!(
        exited,
        "z_get_liveliness never returned within {ARM_BUDGET:?} against a frozen upstream.\n\
         --- z_get_liveliness stdout ---\n{pico_out}\n--- peer stderr ---\n{peer_log}"
    );
    assert!(
        elapsed < PROMPT,
        "z_get_liveliness took {elapsed:?}.\n--- peer stderr ---\n{peer_log}"
    );
}
