// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` -- the REAL zenoh-pico dials a listener of the wz C ABI, whichever
//! engine runs it.
//!
//! The listener is the `hold_a_listener` example of `wz-capi-pico`, run as a process: it listens
//! on `tcp/127.0.0.1:<port>`, subscribes to `demo/**`, publishes `demo/from-listener` every 50 ms
//! and answers a query on `demo/listener/**` with `listened`. The same example is built once for
//! each engine (the tokio engine's accept loop, and the cooperative engine's acceptor of
//! `docs/capi-pico-on-coop-engine.md` step L3 and L4), so one file is the foreign-peer witness of
//! both: nothing in it names an engine, and `WZ_PICO_LISTENER_BIN` says which binary is the
//! subject.
//!
//! The counterparty is upstream's own CLI (`scripts/build-zenoh-pico-cli.sh`): `z_pub` publishes
//! to the listener, `z_sub` hears what the listener publishes, `z_get` is answered by the
//! listener's queryable. Each is a handshake the listener ANSWERS, which is the half of the
//! protocol a wz-authored client cannot witness: the cooperative acceptor's cookie, lease and
//! patch extension were each written against the codec, and a real pico is what reads them.
//!
//! A missing listener binary or a missing CLI is a hard FAIL and not a skip: a test that passes
//! by not running would say the listener serves a foreign peer when nothing has shown it.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    read_captured, spawn_publishing_zpub, spawn_subscribed_zsub, wait_for_substring,
    zenoh_pico_cli_binary,
};
use wz_runtime_tokio_test_support::free_port;

/// How long a foreign exchange gets: generous, because the lane runs under process pressure, and
/// every wait returns the instant what it waits for is there.
const EXCHANGE: Duration = Duration::from_secs(20);

/// The listener process, ended when dropped, and the lines it prints.
struct Listener {
    child: Child,
    lines: Receiver<String>,
    endpoint: String,
}

impl Listener {
    fn start() -> Self {
        let binary: PathBuf = std::env::var("WZ_PICO_LISTENER_BIN")
            .expect(
                "WZ_PICO_LISTENER_BIN names the `hold_a_listener` example of the build under test \
                 (`cargo build -p wz-capi-pico --example hold_a_listener`)",
            )
            .into();
        assert!(
            binary.is_file(),
            "{} is missing: build the example and name it in WZ_PICO_LISTENER_BIN",
            binary.display()
        );
        let port = free_port();
        let mut child = Command::new(&binary)
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the listener starts");
        let stdout = child.stdout.take().expect("a piped stdout");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let this = Self {
            child,
            lines,
            endpoint: format!("tcp/127.0.0.1:{port}"),
        };
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
        panic!("the listener never printed what the test waits for");
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Closing its standard input is how the example ends; killing is the fallback.
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stdout_file() -> File {
    tempfile::tempfile().expect("a tempfile for a pico CLI's output")
}

/// A pico publisher that dials the listener is heard by the listener's subscriber.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "runs upstream's z_pub against a built listener; run by run-ci Layer C1co"]
fn a_zenoh_pico_publisher_reaches_a_wz_listener() {
    let listener = Listener::start();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let mut publisher = spawn_publishing_zpub(
        &z_pub,
        "demo/foreign/pub",
        "from-pico",
        &listener.endpoint,
        "the wz listener",
        stdout_file,
    );
    listener.wait_for(|line| line == "heard demo/foreign/pub");
    let _ = publisher.child_mut().kill();
    let _ = publisher.child_mut().wait();
}

/// A pico subscriber that dials the listener hears what the listener publishes.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "runs upstream's z_sub against a built listener; run by run-ci Layer C1co"]
fn a_zenoh_pico_subscriber_hears_a_wz_listener() {
    let listener = Listener::start();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (mut subscriber, mut output) = spawn_subscribed_zsub(
        &z_sub,
        "demo/from-listener",
        &listener.endpoint,
        "the wz listener",
        stdout_file,
    );
    // The listener publishes every 50 ms, so a subscription that is declared and not yet
    // installed on the listener's face costs a sample and not the test.
    // The key is the one the listener fixture of this test publishes (`hold_a_listener`, an
    // example and so not a producer the gate reads), and the test names it to z_sub as well.
    // barrier-origin: test-payload "demo/from-listener"
    wait_for_substring(&mut output, "demo/from-listener", EXCHANGE).unwrap_or_else(|captured| {
        panic!("z_sub never heard the listener; it printed:\n{captured}")
    });
    let _ = subscriber.child_mut().kill();
    let _ = subscriber.child_mut().wait();
}

/// A pico get that dials the listener is answered by the listener's queryable and ends with the
/// listener's Final.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "runs upstream's z_get against a built listener; run by run-ci Layer C1co"]
fn a_zenoh_pico_get_is_answered_by_a_wz_listener() {
    let listener = Listener::start();
    let z_get = zenoh_pico_cli_binary("z_get");
    let mut output = stdout_file();
    let mut asking = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_get)
        .args([
            "-k",
            "demo/listener/foreign",
            "-e",
            &listener.endpoint,
            "-m",
            "client",
        ])
        .stdout(Stdio::from(output.try_clone().expect("dup stdout handle")))
        .stderr(Stdio::from(output.try_clone().expect("dup stderr handle")))
        .spawn()
        .expect("spawn z_get via stdbuf");
    let captured = wait_for_substring(&mut output, "Received query final notification", EXCHANGE)
        .unwrap_or_else(|captured| {
            let _ = asking.kill();
            panic!("z_get was never told the query had ended; it printed:\n{captured}")
        });
    let _ = asking.kill();
    let _ = asking.wait();
    assert!(
        captured.contains("'demo/listener/foreign': 'listened'"),
        "the listener's queryable did not answer; z_get printed:\n{captured}\n{}",
        read_captured(&mut output)
    );
}
