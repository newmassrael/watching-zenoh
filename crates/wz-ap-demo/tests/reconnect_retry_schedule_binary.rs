// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2158 (open-debt item 230) — the re-dial schedule a CLIENT is configured
//! with is the one its `--reconnect` supervisor is handed.
//!
//! ## What item 230 was, and what it got wrong
//!
//! Measured at R311y849 and true until this round: `connect/retry` reached the
//! `--peer` and `--router-hat` arms and nothing else, so the client reconnect
//! supervisor took `ReconnectPolicy::default()` and had ZERO config input. The
//! item recorded that, and then recorded a VERDICT that does not follow — that
//! wiring the key here would be a divergence decision, because this supervisor's
//! parity target is pico's constant delay while `connect/retry` is zenoh's
//! exponential backoff.
//!
//! Both premises hold; the conclusion does not. Pico's constant is a POINT in
//! zenoh's parameter space, not a rival schedule — `RetryPolicy::constant(1000)`
//! is `{ period_init_ms: 1000, period_max_ms: 0, period_increase_factor: 1.0 }`,
//! the three fields of upstream's `ConnectionRetryConf`. So the surface is
//! zenoh's, the DEFAULT stays pico's, and nothing is traded. The refutation is
//! pinned as code in `runner::client_reconnect_schedule_tests`; what is pinned
//! HERE is the half no unit test can reach.
//!
//! ## Why a process test
//!
//! Three joints separate a config file from a re-dial, and only the last one is
//! new. That the file parses into a `RetryPolicy` is `zenoh_config`'s own unit
//! tests; that the policy becomes `--connect-retry <spec>` under the right
//! precondition is `args::stock_config_tests`; that
//! `Option<RetryPolicy> -> ReconnectPolicy` keeps pico's default is
//! `runner::client_reconnect_schedule_tests`. EVERY ONE OF THOSE PASSES with
//! `run_demo` still handing the supervisor `ReconnectPolicy::default()`, which
//! is exactly the state item 230 found and is open-debt item 479's class: a
//! seam proven on both sides and never joined. Only running the binary shows
//! the argv reaching the call.
//!
//! ## Why a REFUSED dial is the right shape
//!
//! `open_session_with_reconnect` dials once and returns `Err` if that fails —
//! the schedule governs re-dials after an ESTABLISHED link is lost, not the
//! first attempt. So this cannot count attempts the way
//! `wz_reads_a_stock_zenohd_config`'s LEG 5 counts them for `--peer`. What it
//! reads instead is the line the demo emits BEFORE it dials, naming the
//! resolved schedule and its SOURCE. That line is not a test affordance:
//! `parse_connect_retry`'s own doc names its absence as the failure mode —
//! "the node runs, dials, reconnects, and paces itself by a cadence the
//! operator did not ask for and no log line contradicts".
//!
//! Nothing listens on the port, deliberately: providing a listener would need a
//! second node and would prove nothing more, since the announce precedes the
//! dial either way.
//!
//! ## The residue, stated rather than hidden
//!
//! The announce and the `reconnect_endpoint` call read ONE binding on adjacent
//! lines, so every natural way of removing the wiring moves both. A deliberate
//! edit that kept the announce and passed a different value to the supervisor
//! would pass this leg; short of a newtype only the supervisor could accept,
//! no instrument here rules that out, and a newtype for a demo's own concern
//! would be a library signature bent to a test.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How long a node gets to announce its schedule. Generous against a loaded
/// build machine; the wait returns as soon as the line arrives, so only a
/// FAILING arm pays it.
const DEADLINE: Duration = Duration::from_secs(20);

/// The three numbers every configured arm asks for. Deliberately unlike each
/// other and unlike BOTH defaults: with `init == max`, or a factor of 2 against
/// a power-of-two ceiling, a swapped pair still reads plausibly.
const SPEC: &str = "250,9000,1.5";

/// What the demo must announce for [`SPEC`].
const CONFIGURED: &str = "RECONNECT SCHEDULE init=250ms max=9000ms factor=1.5 source=connect/retry";

/// What it must announce when nothing configured one: pico's literal 1s re-arm,
/// flat forever. zenoh's default would read `init=1000ms max=4000ms factor=2`,
/// which SHARES its first wait with this — hence the whole line, not the init.
const PICO_DEFAULT: &str = "RECONNECT SCHEDULE init=1000ms max=0ms factor=1 source=pico-default";

/// A TCP port with nothing on it: bound to learn the number, then released.
///
/// The window between the release and the demo's dial is not a correctness
/// risk here — a dial that unexpectedly SUCCEEDED would still have announced
/// the schedule first, which is the only thing read.
fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port to learn and release");
    listener
        .local_addr()
        .expect("the bound address is readable")
        .port()
}

/// A directory of this test's own, removed on the way out.
///
/// `cfg`-ed on the set of its consumers — the two `--config` arms — rather than
/// `allow(dead_code)`d, which is this crate's rule for exactly this shape: an
/// allow would keep compiling after the last caller went away.
#[cfg(feature = "zenoh-config")]
struct Fixture {
    dir: std::path::PathBuf,
}

#[cfg(feature = "zenoh-config")]
impl Fixture {
    fn new(case: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("wz-reconnect-retry-{}-{case}", std::process::id()));
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

#[cfg(feature = "zenoh-config")]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run the demo with `args`, and return the schedule line it announced together
/// with the whole transcript.
///
/// The stderr reader runs on its own thread: a node that announces nothing
/// writes nothing, and a blocking read on this thread would HANG the suite
/// rather than fail it. The child is killed if the deadline passes, so a
/// regression that never reaches the announce cannot leave a process behind.
fn announced_schedule(args: &[String]) -> (Option<String>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .args(args)
        // Pinned rather than inherited: the demo's logger defaults to `info`
        // only when RUST_LOG is unset, and a developer running the suite with
        // `RUST_LOG=warn` would otherwise see this leg fail for their shell's
        // reason rather than the code's.
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the demo binary runs");
    let stderr = child.stderr.take().expect("stderr was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    // EVERY line is retained, not only the matching one: a failure message that
    // shows the whole transcript is what separates "the node never announced"
    // from "the node refused the argv".
    let mut seen: Vec<String> = Vec::new();
    let mut found: Option<String> = None;
    let deadline = Instant::now() + DEADLINE;
    while found.is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(line) => {
                if line.contains("RECONNECT SCHEDULE") {
                    found = Some(line.clone());
                }
                seen.push(line);
            }
            // The node exited. Everything it wrote is already in `seen`, and an
            // absent announce is the failure the caller reports.
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    (found, seen.join("\n"))
}

/// Assert the demo announced exactly `want`, quoting the transcript otherwise.
fn assert_announced(case: &str, args: &[String], want: &str) {
    let (line, transcript) = announced_schedule(args);
    let line = line.unwrap_or_else(|| {
        panic!(
            "{case}: the node announced no schedule at all.\nargv = {args:?}\n\
             --- transcript ---\n{transcript}"
        )
    });
    assert!(
        line.ends_with(want),
        "{case}: the supervisor was handed a schedule nobody asked for.\n\
         argv     = {args:?}\n\
         expected = {want}\n\
         announced= {line}\n--- transcript ---\n{transcript}"
    );
}

/// The demo refuses an invocation that asks for no application behaviour at
/// all ("at least one of --key / --publish / ..."), and it refuses it BEFORE the
/// session role runs — so every arm here carries a subscriber keyexpr. A
/// subscriber rather than a publisher because it needs no `--value` partner:
/// the fewer words in the argv, the fewer ways an arm can fail for a reason
/// that is not the schedule.
fn argv(items: &[&str]) -> Vec<String> {
    items
        .iter()
        .map(|s| String::from(*s))
        .chain(["--key".to_string(), "demo/**".to_string()])
        .collect()
}

/// ① from the command line — `--connect-retry` reaches the supervisor.
///
/// The argv half runs in EVERY build, which is why it is here rather than only
/// behind `zenoh-config`: `pre-push` runs the changed crate's tests at default
/// features, so the wiring this round added is watched before the push and not
/// only by a hosted lane.
#[test]
fn a_typed_schedule_reaches_the_reconnect_supervisor() {
    let target = format!("tcp/127.0.0.1:{}", dead_port());
    assert_announced(
        "typed --connect-retry",
        &argv(&["--connect", &target, "--reconnect", "--connect-retry", SPEC]),
        CONFIGURED,
    );
}

/// ② from the command line — no flag leaves pico's constant in place.
///
/// The control for the case above, and the one a "unify the two defaults" round
/// would break first.
#[test]
fn an_untyped_schedule_leaves_the_supervisor_on_picos_constant() {
    let target = format!("tcp/127.0.0.1:{}", dead_port());
    assert_announced(
        "no --connect-retry",
        &argv(&["--connect", &target, "--reconnect"]),
        PICO_DEFAULT,
    );
}

/// ① from a FILE — the invocation item 230 is actually about.
///
/// `wz-ap-demo --config their.json5 --reconnect`: the document supplies the
/// role, the dial and the schedule; the operator types only the lifecycle. That
/// is the whole chain — JSON5 leaf, expansion, parser, supervisor — in one
/// process, and every joint in it was provable separately while the last one
/// was missing.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_config_file_schedule_reaches_the_reconnect_supervisor() {
    let fixture = Fixture::new("configured");
    let path = fixture.write(
        "z.json5",
        &format!(
            r#"{{ mode: "client",
                  connect: {{ endpoints: ["tcp/127.0.0.1:{}"],
                             retry: {{ period_init_ms: 250, period_max_ms: 9000,
                                      period_increase_factor: 1.5 }} }} }}"#,
            dead_port()
        ),
    );
    assert_announced(
        "--config with connect/retry",
        &argv(&["--config", &path.display().to_string(), "--reconnect"]),
        CONFIGURED,
    );
}

/// ② from a FILE — the SAME document with the block deleted.
///
/// Two runs of one binary differing in one block. If the announce does not move
/// between this arm and the one above, the file reached nothing whatever the
/// config report says — the discipline
/// `the_retry_schedule_a_stock_zenohd_config_carries_is_the_one_the_node_runs`
/// established for the `--peer` arm, asked of the client one.
#[cfg(feature = "zenoh-config")]
#[test]
fn a_config_file_without_the_block_leaves_picos_constant() {
    let fixture = Fixture::new("default");
    let path = fixture.write(
        "z.json5",
        &format!(
            r#"{{ mode: "client",
                  connect: {{ endpoints: ["tcp/127.0.0.1:{}"] }} }}"#,
            dead_port()
        ),
    );
    assert_announced(
        "--config without connect/retry",
        &argv(&["--config", &path.display().to_string(), "--reconnect"]),
        PICO_DEFAULT,
    );
}
