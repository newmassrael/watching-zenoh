// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The demo's peer mode does not depend on the host's default stack.
//!
//! A process's first thread has a stack the host chose: 8 MiB on Linux and macOS,
//! 1 MiB on Windows. `--peer` polls its whole mesh future there, and an
//! unoptimised build spends 255 KB of it before the first subscriber is declared
//! (measured on Linux), more on Windows, where the first hosted run of the
//! interop crate's data rows saw `thread 'main' has overflowed its stack`. The
//! demo now runs its work on a thread of its own, sized by the demo
//! (`DEMO_STACK_BYTES`), so the first thread's stack no longer matters.
//!
//! The leg starts the peer under a first-thread stack of 256 KiB, a budget that
//! the pre-fix demo overflows (it exited 134 with that message) and that the
//! first thread alone is far inside now. It is a Unix leg because the limit is
//! `ulimit -s`; Windows has no equivalent for a child, so the interop crate's data
//! rows are that host's witness.

#![cfg(all(unix, feature = "routing-peer"))]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The first thread's stack, in KiB, the leg runs the demo under.
const FIRST_THREAD_KIB: &str = "256";
const DEADLINE: Duration = Duration::from_secs(20);

/// Starts `argv` under `ulimit -s <kib>`, with stdout and stderr piped.
fn under_stack_limit(kib: &str, argv: &[&str]) -> std::process::Child {
    let mut cmd = Command::new("sh");
    // `$1` is the limit and the rest is the command, so nothing is spliced into the script.
    cmd.arg("-c")
        .arg(r#"ulimit -s "$1" && shift && exec "$@""#)
        .arg("sh")
        .arg(kib)
        .args(argv)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().expect("sh runs")
}

#[test]
fn the_limit_the_leg_sets_is_the_limit_the_child_sees() {
    // The control: the knob reaches the child. Without it a green leg below would
    // say nothing about the stack the demo ran under.
    let mut child = under_stack_limit(FIRST_THREAD_KIB, &["sh", "-c", "ulimit -s"]);
    let mut out = String::new();
    std::io::Read::read_to_string(child.stdout.as_mut().expect("stdout"), &mut out).expect("read");
    child.wait().expect("sh ends");
    assert_eq!(
        out.trim(),
        FIRST_THREAD_KIB,
        "the child's stack limit is not the one the leg set, so the leg below proves nothing"
    );
}

#[test]
fn a_peer_declares_its_subscriber_under_a_small_first_thread_stack() {
    let mut child = under_stack_limit(
        FIRST_THREAD_KIB,
        &[
            env!("CARGO_BIN_EXE_wz-ap-demo"),
            "--peer",
            "127.0.0.1:0",
            "--connect",
            // A port nobody serves: the peer retries in the background, and the
            // subscriber is declared without a session.
            "127.0.0.1:9",
            "--subscribe",
            "demo/stack-budget",
        ],
    );
    let stderr = child.stderr.take().expect("stderr was piped");
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    let mut seen = Vec::new();
    let mut declared = false;
    while let Ok(line) = lines.recv_timeout(DEADLINE) {
        let hit = line.contains("declared subscriber");
        seen.push(line);
        if hit {
            declared = true;
            break;
        }
    }
    let _ = child.kill();
    let status = child.wait().expect("the demo ends");
    assert!(
        declared,
        "the peer never declared its subscriber under a {FIRST_THREAD_KIB} KiB first-thread stack \
         (exit: {status:?}).\n--- stderr ---\n{}",
        seen.join("\n")
    );
    assert!(
        !seen.iter().any(|l| l.contains("overflowed its stack")),
        "the demo overflowed a stack:\n{}",
        seen.join("\n")
    );
}
