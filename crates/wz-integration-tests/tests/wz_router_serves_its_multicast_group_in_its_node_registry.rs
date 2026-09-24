// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2854 — a running wz router serves its MULTICAST group transport on its
//! admin metrics leg, beside the unicast session that asks.
//!
//! ## The property
//!
//! Upstream keeps one stats registry per runtime and registers a multicast
//! transport in it under its group locator
//! (`io/zenoh-transport/src/multicast/transport.rs` @ `.multicast_transport_stats(config.link.link.get_dst().to_string());`);
//! a node built with `stats` answers `@/<zid>/<whatami>/metrics` with that
//! registry's document (`zenoh/src/net/runtime/adminspace.rs` @ `.encode_metrics(`).
//!
//! R2852 wired the pieces separately: the router's group face records into the
//! node registry it is handed, witnessed at the library level, and the router
//! host hands the face the same registry its admin handler reads, which was
//! only a code read. This leg reads the join itself: a router process joins a
//! group, a wz session GETs the router's metrics, and the document must hold
//! the group as one opened transport, with the router's own beacons counted
//! as sent on it.
//!
//! `lo` carries the group (`#iface=lo`), so the beacons have a route on every
//! Linux runner and the leg needs no NIC and no namespace.
//!
//! NO cross-impl proof marker: both ends are wz, so this file links no foreign
//! implementation.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    wz_e2e_admin_probe_binary, ChildGuard, PortReservation,
};

/// How long the probe's whole script may take; the probe bounds each step
/// itself and logs it, so a timeout here is a process that never finished.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The group, and a port no other Layer M leg binds.
const GROUP: &str = "224.0.0.224";
const GROUP_PORT: u16 = 7458;

/// The one sample of `family` whose labels include every one of `labels`.
fn sample(lines: &[&str], family: &str, labels: &[&str]) -> u64 {
    let found: Vec<&&str> = lines
        .iter()
        .filter(|line| line.starts_with(&format!("{family}{{")))
        .filter(|line| labels.iter().all(|l| line.contains(l)))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "`{family}` with {labels:?} must be written exactly once:\n{}",
        lines.join("\n")
    );
    let value = found[0].rsplit(' ').next().expect("a sample has a value");
    value
        .parse::<f64>()
        .unwrap_or_else(|e| panic!("`{value}` is not a number: {e}")) as u64
}

#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces,locator-iface,adminspace-router-linkstate,adminspace-metrics,wz/transport-stats + wz-e2e-admin-probe) on lo; Layer M runs via --ignored"]
fn wz_router_serves_its_multicast_group_in_its_node_registry() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let probe = wz_e2e_admin_probe_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());
    let locator = format!("udp/{GROUP}:{GROUP_PORT}#iface=lo");

    let r_stderr = tempfile::tempfile().expect("tempfile for the router's stderr");
    let r_writer = r_stderr
        .try_clone()
        .expect("dup the router's stderr handle");
    let mut r_reader = r_stderr;
    let mut router = ChildGuard::wrap(
        "wz-ap-demo router-hat with a multicast group and its admin legs",
        Command::new(&demo)
            .args(["--router-hat", &addr, "--multicast-locator", &locator])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(r_writer))
            .spawn()
            .expect("spawn the router"),
    );
    let captured = match wait_for_substring(
        &mut r_reader,
        "adminspace router legs hosted at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = router.child_mut().kill();
            let _ = router.child_mut().wait();
            panic!("the router never hosted its admin legs within 5s\n--- router ---\n{c}");
        }
    };
    let root = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace router legs hosted at ")
                .map(|(_, rest)| rest.split_whitespace().next().unwrap_or("").to_string())
        })
        .and_then(|k| k.strip_suffix("/**").map(str::to_string))
        .expect("the router logged its admin queryable key");
    let zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/<whatami>");
    drop(port_res);
    // The group face binds and beacons on its own task after the admin legs
    // are hosted; give it a few beacon intervals (100 ms each) to count.
    std::thread::sleep(Duration::from_millis(600));

    let metrics = format!("{root}/metrics");
    let p_stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let p_writer = p_stderr.try_clone().expect("dup the probe's stderr handle");
    let mut p_reader = p_stderr;
    let mut p_child = ChildGuard::wrap(
        "wz-e2e-admin-probe (one metrics GET)",
        Command::new(&probe)
            .args(["--connect", &addr, "--get", &metrics])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let out = match wait_for_substring(&mut p_reader, "SCRIPT COMPLETE steps=1", SCRIPT_TIMEOUT) {
        Ok(c) => c,
        Err(c) => {
            let host = read_captured(&mut r_reader);
            let _ = p_child.child_mut().kill();
            let _ = p_child.child_mut().wait();
            let _ = router.child_mut().kill();
            let _ = router.child_mut().wait();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- router ---\n{host}");
        }
    };
    let _ = p_child.child_mut().kill();
    let _ = p_child.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();

    assert!(
        out.contains(&format!("STEP 1 GET '{metrics}' FINAL replies=1")),
        "the metrics GET is answered once\n--- probe ---\n{out}"
    );
    let body: Vec<&str> = out
        .lines()
        .filter_map(|l| l.split_once("STEP 1 BODY #1 ").map(|(_, rest)| rest))
        .collect();

    // TWO opened transports: the probe's unicast session and the group. The
    // group's members, had any joined, would be partitions, not transports.
    let head = format!("local_id=\"{zid}\",local_whatami=\"router\"");
    assert_eq!(
        sample(&body, "zenoh_transports_opened", &[head.as_str()]),
        2,
        "the router's registry holds the probe's session AND its group"
    );
    let group = format!("remote_group=\"udp/{GROUP}:{GROUP_PORT}\"");
    assert!(
        sample(
            &body,
            "zenoh_tx_transport_message_per_transport_total",
            &[group.as_str(), "remote_zid=\"\"", "disconnected=\"false\""]
        ) > 0,
        "the router's beacons are counted as sent on its group\n--- probe ---\n{out}"
    );
    assert_eq!(
        body.last(),
        Some(&"# EOF"),
        "the document ends at its terminator"
    );
}
