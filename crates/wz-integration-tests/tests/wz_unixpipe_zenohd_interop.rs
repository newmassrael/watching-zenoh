// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y392 — wz <-> zenohd cross-impl interop over a UNIXPIPE (named-FIFO) link.
//!
//! The named-FIFO sibling of the tcp/ws/tls zenohd interop suite. It proves wz's
//! MULTI-CLIENT, zenoh-wire-compatible unixpipe transport (the invitation
//! handshake + per-connection dedicated sub-pipe pair, `unixpipe_pipeline`)
//! genuinely interoperates with the canonical `zenohd`'s `UnicastPipeListener` /
//! `UnicastPipeClient`, in BOTH directions — the ultimate wire-parity check for
//! the multi-client acceptor + the flock-based rendezvous.
//!
//!   Leg a — wz DIALS zenohd: zenohd listens on `unixpipe/<base>`
//!     (its `UnicastPipeListener`), wz-ap-demo `--connect unixpipe/<base>` runs the
//!     CLIENT invitation protocol, completes InitSyn/InitAck/OpenSyn/OpenAck to
//!     Established. Proves wz's dialer speaks zenoh's listener protocol.
//!   Leg b — zenohd DIALS wz: wz-ap-demo `--listen unixpipe/<base>` binds the
//!     MULTI-CLIENT acceptor, zenohd `-e unixpipe/<base>` (its `UnicastPipeClient`)
//!     invites, wz accepts + reaches Established. Proves wz's acceptor holds the
//!     flock a zenoh client probes and re-creates the dedicated uplink node.
//!
//! `#[ignore]` (binary-dep e2e): needs a UNIXPIPE-ENABLED zenohd at
//! `target/zenohd-unixpipe/zenohd` (stock zenohd omits `transport_unixpipe`; build
//! with `ZENOHD_UNIXPIPE=1 ZENOHD_ALLOW_CLONE=1 scripts/build-zenohd.sh`) AND a
//! `wz-ap-demo` compiled with `transport-link-unixpipe`. Both must run as the SAME
//! uid (wz `mkfifo`s the request node 0o600; run-ci Layer Z provisions both).
//! Linux-only (the unixpipe backend's `read_write` open-rendezvous).

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    wait_for_substring, wz_ap_demo_binary, zenohd_unixpipe_binary, ChildGuard,
};

/// A per-process-unique unixpipe base path under the temp dir; the request FIFO is
/// `<base>_uplink`. Distinct suffix per leg so parallel legs never share nodes.
fn unixpipe_base(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("wz-uxp-zenohd-{tag}-{}", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// Poll until the request FIFO node exists (a listener has bound) or the deadline
/// passes. The unixpipe analogue of `wait_for_tcp_accept_alive` — a unixpipe
/// listener has no TCP port, so readiness is the `<base>_uplink` node appearing.
fn wait_for_request_fifo(base: &str, timeout: Duration) -> bool {
    let node = format!("{base}_uplink");
    let deadline = Instant::now() + timeout;
    loop {
        if Path::new(&node).exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Best-effort cleanup of a base's request FIFO (dedicated per-connection nodes
/// auto-unlink via their read-end drop; a stale node is harmless — the next bind
/// tolerates it).
fn cleanup(base: &str) {
    let _ = std::fs::remove_file(format!("{base}_uplink"));
    let _ = std::fs::remove_file(format!("{base}_downlink"));
}

/// Leg a — wz DIALS zenohd over unixpipe and reaches Established (wz's client
/// invitation protocol vs zenohd's `UnicastPipeListener`).
// wz-proves: transport-link-unixpipe wz->zenohd
// wz-proves: session-unicast-open wz->zenohd
#[test]
#[ignore = "binary-dep: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe]"]
fn wz_client_reaches_established_against_zenohd_over_unixpipe() {
    let base = unixpipe_base("a");
    cleanup(&base);
    let endpoint = format!("unixpipe/{base}");

    // zenohd LISTENS on unixpipe (its UnicastPipeListener owns the request FIFO).
    let mut zenohd = ChildGuard::wrap(
        "zenohd (unixpipe listener)",
        Command::new(zenohd_unixpipe_binary())
            .arg("-l")
            .arg(&endpoint)
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd unixpipe listener"),
    );
    assert!(
        wait_for_request_fifo(&base, Duration::from_secs(15)),
        "zenohd did not create the unixpipe request FIFO {base}_uplink within 15s"
    );

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut demo_reader = demo_stderr;
    let mut demo = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd unixpipe)",
        Command::new(wz_ap_demo_binary())
            .arg("--connect")
            .arg(&endpoint)
            .arg("--publish")
            .arg("demo/unixpipe")
            .arg("--value")
            .arg("handshake-probe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect unixpipe"),
    );

    let established = wait_for_substring(
        &mut demo_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = demo.child_mut().kill();
    let _ = demo.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    cleanup(&base);

    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s — the wz->zenohd \
             unixpipe handshake regressed.\n--- captured wz-ap-demo stderr ---\n{c}"
        );
    }
}

/// Leg b — zenohd DIALS wz over unixpipe and wz reaches Established (zenohd's
/// `UnicastPipeClient` vs wz's MULTI-CLIENT acceptor; exercises the flock the wz
/// listener holds on the dedicated uplink reader that a zenoh client probes).
// wz-proves: transport-link-unixpipe zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep: needs target/zenohd-unixpipe/zenohd + wz-ap-demo[+transport-link-unixpipe]"]
fn wz_acceptor_reaches_established_from_zenohd_over_unixpipe() {
    let base = unixpipe_base("b");
    cleanup(&base);
    let endpoint = format!("unixpipe/{base}");

    // wz-ap-demo LISTENS on unixpipe (the multi-client acceptor owns the request
    // FIFO); a `--key` subscriber keeps it in steady state after Established.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let wz_stderr_writer = wz_stderr.try_clone().expect("dup wz stderr");
    let mut wz_reader = wz_stderr;
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--listen unixpipe)",
        Command::new(wz_ap_demo_binary())
            .arg("--listen")
            .arg(&endpoint)
            .arg("--key")
            .arg("demo/unixpipe")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen unixpipe"),
    );
    // Readiness: the wz acceptor logs the bound listen line + creates the request
    // FIFO before any peer dials.
    let listening = wait_for_substring(&mut wz_reader, "(unixpipe)", Duration::from_secs(10));
    assert!(
        listening.is_ok() && wait_for_request_fifo(&base, Duration::from_secs(5)),
        "wz-ap-demo did not bind the unixpipe listener within 10s:\n{}",
        listening.err().unwrap_or_default()
    );

    // zenohd DIALS the wz unixpipe listener (also listens on an ephemeral tcp port,
    // harmless — zenohd needs at least one listener to boot its runtime cleanly).
    let mut zenohd = ChildGuard::wrap(
        "zenohd (unixpipe dialer)",
        Command::new(zenohd_unixpipe_binary())
            .arg("-e")
            .arg(&endpoint)
            .arg("-l")
            .arg("tcp/127.0.0.1:0")
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd unixpipe dialer"),
    );

    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    cleanup(&base);

    if let Err(c) = &established {
        panic!(
            "wz-ap-demo acceptor did not log 'session Established' within 10s — the \
             zenohd->wz unixpipe handshake regressed.\n--- captured wz stderr ---\n{c}"
        );
    }
}
