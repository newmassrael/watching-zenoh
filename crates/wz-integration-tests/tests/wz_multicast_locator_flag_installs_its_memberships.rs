// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2588 — a running wz router, told `--multicast-locator
//! udp/<group>:<port>#iface=lo;join=<extra>`, holds kernel memberships for BOTH
//! groups on the named interface, in either address family.
//!
//! # What this closes, and what it deliberately does not
//!
//! `transport-link-udp` already has foreign witnesses of `#join=` (a pico peer
//! in a network namespace, at the library level) and of `#ttl=` (zenohd on the
//! wire, through this same run-mode flag). Two things were left:
//!
//! - `#join=` had no PROCESS-level leg. The flag's value travels through the
//!   demo's parser, `McastGroupOptions`, and the ingress spawner before it
//!   reaches a socket, and the `ttl` leg only exercises the egress half of that
//!   path. Joins are an ingress-only key.
//! - No leg drove an IPv6 group through a running process. R2584 built the v6
//!   constructor and lifted the demo's refusal, and both were witnessed only
//!   below the process.
//!
//! The observable is the kernel's own membership table (`/proc/net/igmp` and
//! `/proc/net/igmp6`), not a socket option read back through wz. It is not a
//! foreign implementation, so the claim below is `none`. The foreign witnesses
//! of what a membership DOES live in the files named above.
//!
//! `lo` is the interface for both families. It accepts memberships for either
//! (it is the kernel's default for neither `224.0.0.0/4` nor `ff02::/16`, so a
//! lost pin shows up as a membership elsewhere), and it exists on every Linux
//! runner, so this leg needs no NIC and no namespace.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, multicast_memberships, read_captured, wz_ap_demo_binary,
    ChildGuard,
};

/// Start a router with `locator` and wait until `lo` holds every group in
/// `want`, or the budget runs out. Returns what `lo` held at the end and the
/// router's own output.
fn memberships_while_running(locator: &str, want: &[IpAddr]) -> (Vec<IpAddr>, String) {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let capture = tempfile::tempfile().expect("tempfile for the router's output");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let _router = ChildGuard::wrap(
        "wz-ap-demo router-hat with a multicast locator",
        Command::new(&demo)
            .args([
                "--router-hat",
                "127.0.0.1:0",
                "--multicast-locator",
                locator,
            ])
            .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
            .stderr(Stdio::from(capture))
            .spawn()
            .expect("spawn the router"),
    );
    // The ingress face binds and joins on its own task after the log line that
    // announces it, so the table is polled rather than read once.
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut held = multicast_memberships("lo");
    while !want.iter().all(|g| held.contains(g)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        held = multicast_memberships("lo");
    }
    (held, read_captured(&mut log))
}

// No proof claim, and not by omission: the membership is read from the kernel's
// table, which is independent of wz's code but is not a foreign implementation.
// The cross-impl audit (A4-3) refuses any claim line, `none` included, in a file
// that spawns nothing foreign. The foreign witnesses of `#join=` and `#ttl=` are
// the namespace legs this file's header names.
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo router-multicast-faces, locator-iface) on lo; \
            Layer M runs via --ignored"]
fn multicast_locator_flag_joins_its_own_and_extra_groups_on_the_named_interface() {
    for (label, own, extra) in [
        ("IPv4", "239.255.73.50", "239.255.73.51"),
        ("IPv6", "ff02::7a7a:4e30", "ff02::7a7a:4e31"),
    ] {
        let own_ip: IpAddr = own.parse().expect("own group");
        let extra_ip: IpAddr = extra.parse().expect("extra group");
        // Both groups must be absent BEFORE the router starts, or their presence
        // afterwards says nothing about this router.
        let before = multicast_memberships("lo");
        assert!(
            !before.contains(&own_ip) && !before.contains(&extra_ip),
            "{label}: lo already holds {own} or {extra} before the router starts: {before:?}"
        );
        let host = match own_ip {
            IpAddr::V4(_) => own.to_string(),
            IpAddr::V6(_) => format!("[{own}]"),
        };
        let locator = format!("udp/{host}:7491#iface=lo;join={extra}");
        let (held, log) = memberships_while_running(&locator, &[own_ip, extra_ip]);
        assert!(
            held.contains(&own_ip) && held.contains(&extra_ip),
            "{label}: a router given {locator} must hold memberships for BOTH {own} and \
             {extra} on lo; lo held {held:?}\n--- router output ---\n{log}"
        );
    }
}
