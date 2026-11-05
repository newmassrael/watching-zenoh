// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` -- the wz C ABI dials a REAL zenoh-pico node that LISTENS, whichever
//! engine runs the ABI.
//!
//! `pico_dials_a_wz_listener.rs` is the other direction: upstream's CLI dials a wz listener.
//! Here the roles are turned. The counterparty is upstream's own CLI run as `-m peer -l
//! tcp/127.0.0.1:<port>` (`scripts/build-zenoh-pico-cli.sh`), parked on pico's accept task, and the
//! program that dials it is the `dial_a_listener` example of `wz-capi-pico`, run as a process. The
//! same example is built once for each engine (the tokio engine, and the cooperative engine of
//! `docs/capi-pico-on-coop-engine.md`), so one file is the foreign-listener witness of both:
//! nothing in it names an engine, and `WZ_PICO_DIALER_BIN` says which binary is the subject.
//!
//! The dial role is the cooperative engine's first (L1 and L2), and until this file it had been
//! held only against the tokio listener and against itself. A real pico is what reads the
//! `InitSyn` the cooperative link layer writes (its whatami, its lease, its patch extension) and
//! what writes the `InitAck` and `OpenAck` the cooperative handshake has to accept.
//!
//! A missing dialer binary or a missing CLI is a hard FAIL and not a skip: a test that passes by
//! not running would say the dial role works against a foreign listener when nothing has shown it.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// How long a foreign exchange gets: generous, because the lane runs under process pressure, and
/// every wait returns the instant what it waits for is there.
const EXCHANGE: Duration = Duration::from_secs(20);

/// pico's own banner once its session is open and its declaration is made: every CLI used here
/// prints it after it has bound its `listen` endpoint and started its accept task.
const PARKED: &str = "Press CTRL-C to quit";

/// The `dial_a_listener` example of the build under test, which Layer C1co builds once for each
/// engine and names in `WZ_PICO_DIALER_BIN`. Layer E's sweep builds no such example, so the
/// tests that call this carry `wz_dialer` in their names and are skipped there
/// (`scripts/lib/layer_e_oracle_scope_gate.py` lists this helper).
fn wz_dialer_binary() -> PathBuf {
    let binary: PathBuf = std::env::var("WZ_PICO_DIALER_BIN")
        .expect(
            "WZ_PICO_DIALER_BIN names the `dial_a_listener` example of the build under test \
             (`cargo build -p wz-capi-pico --example dial_a_listener`)",
        )
        .into();
    assert!(
        binary.is_file(),
        "{} is missing: build the example and name it in WZ_PICO_DIALER_BIN",
        binary.display()
    );
    binary
}

/// A foreign pico CLI parked on a `listen` endpoint, and what it printed.
struct ForeignListener {
    child: ChildGuard,
    output: File,
    endpoint: String,
}

impl ForeignListener {
    /// Start `cli` (`z_sub`, `z_pub` or `z_queryable`) in peer mode listening on a port of its
    /// own, with `args` after the listen endpoint, and return once it is parked on the accept
    /// task. The port is held until then, so no other test of the lane takes it between the pick
    /// and pico's bind.
    fn start(cli: &str, args: &[&str]) -> Self {
        let binary = zenoh_pico_cli_binary(cli);
        let reservation = PortReservation::pick();
        let endpoint = format!("tcp/127.0.0.1:{}", reservation.port());
        let output = tempfile::tempfile().expect("a tempfile for a pico CLI's output");
        let writer = output.try_clone().expect("dup the CLI's stdout handle");
        // `stdbuf` line-buffers: printf to a file is block-buffered on glibc, which would hide the
        // banner until the CLI exits.
        let child = ChildGuard::wrap(
            format!("{cli} peer-listen (zenoh-pico)"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&binary)
                .args(["-m", "peer", "-l", &endpoint])
                .args(args)
                .stdout(Stdio::from(writer))
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn the pico CLI via stdbuf"),
        );
        let mut this = Self {
            child,
            output,
            endpoint,
        };
        if let Err(captured) = wait_for_substring(&mut this.output, PARKED, Duration::from_secs(5))
        {
            panic!(
                "{cli} did not park on {} within 5s -- the bind failed or the session never \
                 opened.\n--- captured stdout ---\n{captured}",
                this.endpoint
            );
        }
        // pico owns the port now.
        drop(reservation);
        this
    }

    /// Wait for the CLI to print `needle`; the panic carries what it did print.
    fn printed(&mut self, needle: &str, what: &str) -> String {
        wait_for_substring(&mut self.output, needle, EXCHANGE)
            .unwrap_or_else(|captured| panic!("{what}; the foreign listener printed:\n{captured}"))
    }
}

impl Drop for ForeignListener {
    fn drop(&mut self) {
        let _ = self.child.child_mut().kill();
        let _ = self.child.child_mut().wait();
    }
}

/// The wz ABI's dialer process, ended when dropped, and the lines it prints.
struct Dialer {
    child: Child,
    lines: Receiver<String>,
}

impl Dialer {
    /// Start the dialer on `endpoint` and return once its session is open.
    fn start(endpoint: &str) -> Self {
        let mut child = Command::new(wz_dialer_binary())
            .arg(endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the dialer starts");
        let stdout = child.stdout.take().expect("a piped stdout");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let this = Self { child, lines };
        this.wait_for(|line| line == "READY");
        this
    }

    /// Read lines until one satisfies `wanted`, for at most [`EXCHANGE`].
    fn wait_for(&self, wanted: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + EXCHANGE;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) if wanted(&line) => return,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("the dialer never printed what the test waits for");
    }

    /// Have the dialer ask a query on `key`.
    fn ask(&mut self, key: &str) {
        let stdin = self.child.stdin.as_mut().expect("a piped stdin");
        writeln!(stdin, "get {key}").expect("the dialer reads its input");
        stdin.flush().expect("the dialer reads its input");
    }
}

impl Drop for Dialer {
    fn drop(&mut self) {
        // Closing its standard input is how the example ends; killing is the fallback.
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What a wz session publishes after it dials a pico listener reaches the listener's subscriber.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "runs the wz dialer against upstream's z_sub; run by run-ci Layer C1co"]
fn a_wz_dialer_publishes_to_a_zenoh_pico_listener() {
    let mut listener = ForeignListener::start("z_sub", &["-k", "demo/**"]);
    let _dialer = Dialer::start(&listener.endpoint);
    // The dialer publishes every 50 ms, so a put sent before the listener's face had installed
    // the subscriber's interest costs a sample and not the test.
    // The key is the one the dialer fixture of this test publishes (`dial_a_listener`, an example
    // and so not a producer the gate reads), and the test names it to z_sub as well.
    // barrier-origin: test-payload "'demo/from-dialer'"
    listener.printed(
        "'demo/from-dialer'",
        "z_sub never received what the wz dialer published",
    );
}

/// What a pico listener publishes reaches the subscriber of a wz session that dialled it.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "runs the wz dialer against upstream's z_pub; run by run-ci Layer C1co"]
fn a_wz_dialer_hears_a_zenoh_pico_listener() {
    let listener = ForeignListener::start("z_pub", &["-k", "demo/foreign/pub", "-v", "from-pico"]);
    let dialer = Dialer::start(&listener.endpoint);
    // z_pub puts once a second.
    dialer.wait_for(|line| line == "heard demo/foreign/pub");
    // The listener's own view: it did not stop at the handshake.
    let mut output = listener.output.try_clone().expect("dup the CLI's output");
    assert!(
        read_captured(&mut output).contains("Putting Data"),
        "z_pub never put"
    );
}

/// A query a wz session asks of a pico listener is answered by the listener's queryable and ends
/// with the listener's Final.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "runs the wz dialer against upstream's z_queryable; run by run-ci Layer C1co"]
fn a_wz_dialer_get_is_answered_by_a_zenoh_pico_listener() {
    let mut listener = ForeignListener::start(
        "z_queryable",
        &["-k", "demo/foreign/queryable", "-v", "answered"],
    );
    let mut dialer = Dialer::start(&listener.endpoint);
    dialer.ask("demo/foreign/queryable");
    dialer.wait_for(|line| line == "reply answered");
    dialer.wait_for(|line| line == "done demo/foreign/queryable");
    listener.printed(
        "Received Query 'demo/foreign/queryable'",
        "the listener's queryable never saw the dialer's query",
    );
}
