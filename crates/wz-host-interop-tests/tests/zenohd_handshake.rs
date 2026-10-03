// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The first router interop test a macOS or Windows host owes: the wz demo dials a
//! stock `zenohd` as a client and reaches Established.
//!
//! It is the host-portable twin of `wz_client_reaches_established_against_zenohd`
//! in `wz_integration_tests`' router file, which asserts the same fact and cannot be
//! compiled on a host, because the file's other tests need the pico C library. This
//! one needs only the router, the demo and the harness library, all of which build
//! on a host. It is deliberately the same assertion: the question a host leg asks is
//! whether the handshake interoperates THERE, and a second, different assertion
//! would answer a different question.
//!
//! The two are not meant to stay twins. When this has run green twice on each host
//! as an observation, the right move is to take the test out of the corpus file and
//! let this one carry the fact on every host, with the count the corpus lane guards
//! lowered in the same commit. Until then the duplication costs one short test and
//! keeps the corpus lane's count, and so its guard, exactly as it was.
//!
//! Opt-in (`#[ignore]`) and binary-dependent: the router is named with
//! `WZ_ZENOHD_BIN` and the demo is the one `cargo build -p wz-ap-demo` produced.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

#[test]
#[ignore = "binary-dep e2e (zenohd router); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_on_this_host() {
    let demo = wz_ap_demo_binary();
    // The port is DISCOVERED from the router's own announcement, as in the corpus:
    // naming one in advance is what lets another process hold it.
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg("handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect zenohd"),
    );

    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s: the wz<->zenohd \
             handshake did not interoperate on this host.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}
