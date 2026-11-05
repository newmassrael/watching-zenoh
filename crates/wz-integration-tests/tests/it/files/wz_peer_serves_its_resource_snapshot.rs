// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A running wz peer that serves its admin space (`--config-queryable`) serves its resource
//! snapshot (`docs/observation-plane.md` M4) at `wz/@/<zid>/snapshot`, outside upstream's admin
//! space and behind the same admin read permit, as a router does
//! (`wz_router_hat_serves_its_resource_snapshot`).
//!
//! - **It is served.** A wz session GETs the key and the one reply is the snapshot's JSON, taken
//!   by the node's own task, with the platform's readings where the host could take them.
//! - **It is gated like every admin leg.** With the read permit denied the same GET gets the
//!   terminating Final alone.
//!
//! Both ends are wz, so this file links no foreign implementation and carries no cross-impl
//! marker. The peer is built with `adminspace-read`, which is what makes the permit the flag's
//! value and not a constant `true`; without it the denial below would fail and not pass vacuously.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    wz_e2e_admin_probe_binary, ChildGuard, PortReservation,
};

/// How long the probe's whole script may take; it bounds each step itself.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// A peer with `--config-queryable` and `extra` flags, its address, and the key its snapshot is
/// hosted at, scraped from the line it logs at registration.
fn spawn_peer(label: &str, extra: &[&str]) -> (ChildGuard, std::fs::File, String, String) {
    let port = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port.port());
    let stderr = tempfile::tempfile().expect("tempfile for the peer's stderr");
    let writer = stderr.try_clone().expect("dup the peer's stderr handle");
    let mut reader = stderr;
    let mut child = ChildGuard::wrap(
        label,
        Command::new(wz_ap_demo_binary())
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .args(extra)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer"),
    );
    drop(port);
    let captured = match wait_for_substring(
        &mut reader,
        "resource snapshot hosted at ",
        Duration::from_secs(10),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("{label} never hosted its resource snapshot within 10s\n{c}");
        }
    };
    let key = captured
        .lines()
        .find_map(|l| l.split_once("resource snapshot hosted at "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{label} log had no scrapeable snapshot key"));
    (child, reader, addr, key)
}

/// One probe session GETting `key`; its transcript.
fn probe(peer: &mut ChildGuard, log: &mut std::fs::File, addr: &str, key: &str) -> String {
    let p_stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let p_writer = p_stderr.try_clone().expect("dup the probe's stderr handle");
    let mut p_reader = p_stderr;
    let mut child = ChildGuard::wrap(
        "wz-e2e-admin-probe",
        Command::new(wz_e2e_admin_probe_binary())
            .arg("--connect")
            .arg(addr)
            .arg("--get")
            .arg(key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let out = match wait_for_substring(&mut p_reader, "SCRIPT COMPLETE steps=1", SCRIPT_TIMEOUT) {
        Ok(c) => c,
        Err(c) => {
            let host = read_captured(log);
            let _ = child.child_mut().kill();
            let _ = peer.child_mut().kill();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- peer ---\n{host}");
        }
    };
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    out
}

fn stop(mut peer: ChildGuard) {
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-read,resource-snapshot + wz-e2e-admin-probe); Layer E6f runs via --ignored"]
fn wz_peer_serves_its_resource_snapshot_to_a_session_client() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut peer, mut log, addr, key) = spawn_peer("wz-ap-demo peer serving its snapshot", &[]);
    let out = probe(&mut peer, &mut log, &addr, &key);
    stop(peer);
    let reply = format!("STEP 1 GET reply #1 keyexpr='{key}'");
    assert!(
        out.contains(&reply),
        "the snapshot is served under its key\n--- probe ---\n{out}"
    );
    let body = out
        .lines()
        .find_map(|l| l.split_once("STEP 1 BODY #1 ").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("no body in step 1\n--- probe ---\n{out}"));
    for fact in ["{\"version\":1,", "\"heap\":null,", "\"resource-snapshot\""] {
        assert!(body.contains(fact), "the snapshot lacks {fact}\n{body}");
    }
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-read,resource-snapshot + wz-e2e-admin-probe); Layer E6f runs via --ignored"]
fn wz_peer_answers_no_snapshot_when_admin_read_is_denied() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut peer, mut log, addr, key) = spawn_peer(
        "wz-ap-demo peer with the admin read permit denied",
        &["--no-admin-read"],
    );
    // The permit is the flag's value only with `adminspace-read` built in; say so before
    // trusting an absence.
    if let Err(c) = wait_for_substring(
        &mut log,
        "peer: adminspace read permit = false",
        Duration::from_secs(5),
    ) {
        stop(peer);
        panic!("the read permit must be denied under --no-admin-read + adminspace-read\n{c}");
    }
    let out = probe(&mut peer, &mut log, &addr, &key);
    stop(peer);
    assert!(
        out.contains(&format!("STEP 1 GET '{key}' FINAL replies=0")),
        "a denied read answers with the terminating Final alone\n--- probe ---\n{out}"
    );
}
