// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A running wz router that has joined a multicast group counts what the group delivers in its
//! resource snapshot (`docs/observation-plane.md` M4), not only what its unicast sessions receive.
//!
//! ## The property
//!
//! The snapshot's `messages` is the node's receive count. The unicast sessions feed it through the
//! session's own meter, and a joined group feeds it through the meter of the group's face
//! (`RouterMcastGroup::messages`, read by the router's `messages_view`). The library witnesses
//! count each in isolation; this leg reads the join the router process makes of them.
//!
//! A router is started with a group (`--multicast-locator`, on `lo`, so it needs no NIC and no
//! namespace) and asked for its snapshot after a fixed wait, alone and then with a second router
//! in the same group. The second beacons every 100 ms, so over the wait it delivers a few dozen
//! messages to the first and nothing else differs between the two runs: the first router's count
//! must rise by a margin that a late or a missed sample cannot make.
//!
//! The snapshot a GET reads is the one taken before the probe connected, so the count is the
//! group's alone (the router hears its own beacons on `lo`, which the first run is the witness
//! of). Measured on a build host, three runs alike: 20 alone, 39 with a second member, and 0 and 0
//! with the router's group readers left unregistered, which is the control that the count is the
//! group's and that this leg fails without them.
//!
//! Both ends are wz, so this file links no foreign implementation and carries no cross-impl
//! marker.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, wz_e2e_admin_probe_binary, ChildGuard,
};

/// How long the probe's whole script may take; it bounds each step itself.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The group, and a port no other Layer M leg binds.
const GROUP: &str = "udp/224.0.0.224:7478#iface=lo";

/// How long a router runs before its snapshot is asked for: the second router has started, its
/// beacons (every 100 ms) have been arriving, and the snapshot a GET reads is taken once a period
/// (a second), so the wait spans at least two samples after the beacons began.
const WAIT: Duration = Duration::from_millis(2_600);

/// How many more messages a router with a second member must have counted than a router alone.
/// The second member sends about twenty in the wait (19 more were counted in each of three runs),
/// so the margin is well under what the beacons give and well over a sample taken a beacon early
/// or late.
const MARGIN: u64 = 8;

/// A router in `GROUP`, and the key its snapshot is hosted at (scraped from the line it logs at
/// registration), with its stderr.
fn spawn_router(label: &str) -> (ChildGuard, std::fs::File, u16, String) {
    let stderr = tempfile::tempfile().expect("tempfile for the router's stderr");
    let (router, mut log, port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &["--router-hat", "127.0.0.1:0", "--multicast-locator", GROUP],
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    );
    let captured = wait_for_substring(
        &mut log,
        "resource snapshot hosted at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| panic!("{label} never hosted its resource snapshot within 10s\n{c}"));
    let key = captured
        .lines()
        .find_map(|l| l.split_once("resource snapshot hosted at "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{label} log had no scrapeable snapshot key"));
    (router, log, port, key)
}

/// A member of the group that only beacons: a router the first one is not connected to.
fn spawn_member(label: &str) -> ChildGuard {
    let stderr = tempfile::tempfile().expect("tempfile for the member's stderr");
    let (member, _log, _port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &["--router-hat", "127.0.0.1:0", "--multicast-locator", GROUP],
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    );
    member
}

/// One GET of `key` through a fresh session to `port`: the body of its reply.
fn snapshot(router: &mut ChildGuard, log: &mut std::fs::File, port: u16, key: &str) -> String {
    let p_stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let p_writer = p_stderr.try_clone().expect("dup the probe's stderr handle");
    let mut p_reader = p_stderr;
    let mut child = ChildGuard::wrap(
        "wz-e2e-admin-probe",
        Command::new(wz_e2e_admin_probe_binary())
            .args(["--connect", &format!("127.0.0.1:{port}"), "--get", key])
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
            let _ = router.child_mut().kill();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- router ---\n{host}");
        }
    };
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    out.lines()
        .find_map(|l| {
            l.split_once("STEP 1 BODY #1 ")
                .map(|(_, rest)| rest.to_string())
        })
        .unwrap_or_else(|| panic!("no body in the probe's step 1\n--- probe ---\n{out}"))
}

/// The unsigned number after `"name":` in a JSON document written by the snapshot, which has no
/// nesting that repeats a name.
fn number_of(json: &str, name: &str) -> Option<u64> {
    let key = format!("\"{name}\":");
    let at = json.find(&key)? + key.len();
    let digits: String = json[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn stop(mut child: ChildGuard) {
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
}

/// What a router in `GROUP` has counted after [`WAIT`], with or without a second member.
fn messages_counted(label: &str, with_member: bool) -> u64 {
    let (mut router, mut log, port, key) = spawn_router(label);
    let member = with_member.then(|| spawn_member("the second member of the group"));
    std::thread::sleep(WAIT);
    let body = snapshot(&mut router, &mut log, port, &key);
    stop(router);
    if let Some(member) = member {
        stop(member);
    }
    number_of(&body, "messages").unwrap_or_else(|| panic!("the snapshot has no count\n{body}"))
}

#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces,locator-iface,adminspace-router-linkstate,adminspace-read,resource-snapshot + wz-e2e-admin-probe) on lo; Layer M runs via --ignored"]
fn wz_router_hat_counts_its_multicast_group_in_its_snapshot() {
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let alone = messages_counted("a router alone in its group", false);
    let together = messages_counted("a router with a second member in its group", true);
    println!("messages counted: {alone} alone, {together} with a second member");
    assert!(
        together >= alone + MARGIN,
        "a second member's beacons are in the router's count: {together} with it, {alone} alone"
    );
}
