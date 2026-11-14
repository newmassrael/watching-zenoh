// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// `--client-node` at the binary: a client that listens as well as it dials, as upstream's client
// binds its listen endpoints before it connects to its router (`zenoh/src/net/runtime/
// orchestrator.rs` @ `async fn start_client(&self) -> ZResult<()> {`).
//
// The run mode is chosen in `main`, so only argv -> process witnesses it. The refusals are read
// while the arguments are, so they open no socket. The bind arm dials a port nothing listens on
// and is ended by the test once it has logged its bound listener.

#![cfg(feature = "routing-peer")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    cmd.args(args);
    cmd.output().expect("the demo binary runs")
}

/// A client node with no router to dial is refused, by name: upstream's client with nothing to
/// dial and no scouting does not start.
#[test]
fn a_client_node_without_a_router_to_dial_is_refused() {
    let out = run(&["--client-node", "tcp/127.0.0.1:0"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "--- stderr ---\n{stderr}");
    assert!(
        stderr.contains("--client-node dials its router; name it with --connect"),
        "--- stderr ---\n{stderr}"
    );
}

/// One node holds one role: a peer and a client node at once is refused, by name.
#[test]
fn a_peer_and_a_client_node_at_once_are_refused() {
    let out = run(&[
        "--peer",
        "tcp/127.0.0.1:0",
        "--client-node",
        "tcp/127.0.0.1:0",
        "--connect",
        "tcp/127.0.0.1:1",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "--- stderr ---\n{stderr}");
    assert!(
        stderr.contains("--peer and --client-node are two roles of one node"),
        "--- stderr ---\n{stderr}"
    );
}

/// A client node binds its listen endpoint as well as dialling its router: the run mode that a
/// client document naming both selects, where the one-shot client bound nothing.
#[test]
fn a_client_node_binds_its_listen_endpoint() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a port")
        .port();
    let router = format!("tcp/127.0.0.1:{closed}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"))
        .args(["--client-node", "tcp/127.0.0.1:0", "--connect", &router])
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the demo binary runs");
    // Read on a thread of its own, each line sent as it comes, so a log that fills the pipe
    // never holds the child and the test waits only for the line it needs.
    let pipe = child.stderr.take().expect("stderr is piped");
    let (lines, logged) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = String::new();
    let bound = loop {
        match logged.recv_timeout(Duration::from_secs(30)) {
            Ok(line) => {
                let found = line.contains("client-node: BOUND LISTEN ENDPOINT");
                seen.push_str(&line);
                seen.push('\n');
                if found {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    drop(logged);
    let _ = reader.join();
    assert!(bound, "the client node binds its listen endpoint\n{seen}");
}
