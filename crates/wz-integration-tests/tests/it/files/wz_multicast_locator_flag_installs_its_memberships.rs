// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2588 — a running wz router, told `--multicast-locator
//! udp/<group>:<port>#iface=<device>;join=<extra>`, holds kernel memberships for
//! BOTH groups on the named interface, in either address family.
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
//! IPv4 runs on `lo`: the kernel takes a membership there and a datagram can be
//! sent from it, and `lo` is the kernel's default for no group, so a lost pin shows
//! up as a membership elsewhere. IPv6 cannot run on `lo`. The kernel gives `lo` no
//! `IFF_MULTICAST` and so no `ff00::/8` route, a send to a group by way of `lo` is
//! refused with `ENETUNREACH`, and the router's group face, which treats a failed
//! write as a lost link, drops its socket and with it the membership the test is
//! reading. (Measured on a hosted runner and on a build host: `lo` holds only
//! `ff02::1` and `ff01::1`, with `<LOOPBACK,UP,LOWER_UP>` and no multicast route; the
//! original form of this test, which named `lo` for both families, failed on that
//! build host with the same panic and the same `ENETUNREACH` as on the runner.)
//! So the IPv6 arm names a non-loopback interface that is up, has `IFF_MULTICAST` and
//! holds an IPv6 address, as the other IPv6 multicast leg of Layer M does, and a host
//! with none PANICS here rather than skipping, since a skipped arm proves nothing.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, multicast_memberships, read_captured, wz_ap_demo_binary,
    ChildGuard,
};

/// A non-loopback interface that is up, can carry multicast (`IFF_MULTICAST`) and
/// holds an IPv6 address, from the kernel's own tables (`/proc/net/if_inet6` and
/// sysfs). Sorted so a host with several answers the same way each run.
fn ipv6_multicast_interface() -> String {
    // `IFF_UP` and `IFF_MULTICAST` from `<net/if.h>`; sysfs prints the flags in hex. They do not
    // carry `IFF_RUNNING` (sysfs shows the device's own flags, and `0x1003` is an interface that
    // is running as well as one that is not), so the carrier is read from its own file: an
    // interface that is up with no carrier (a docker bridge with no container on it sorts first on
    // a build machine) is one wz refuses to bind a multicast socket on, as upstream's
    // `is_running` filter does, so it is no interface to name here.
    const IFF_UP: u32 = 0x1;
    const IFF_MULTICAST: u32 = 0x1000;
    let table = std::fs::read_to_string("/proc/net/if_inet6")
        .expect("read /proc/net/if_inet6 (a Linux host with IPv6)");
    let mut names: Vec<String> = table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(5).map(str::to_owned))
        .filter(|name| name != "lo")
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .find(|name| {
            let has_carrier = || {
                // A device that is not up refuses the read, and one without a carrier says `0`.
                std::fs::read_to_string(format!("/sys/class/net/{name}/carrier"))
                    .is_ok_and(|s| s.trim() == "1")
            };
            std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
                .ok()
                .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                .is_some_and(|flags| flags & IFF_UP != 0 && flags & IFF_MULTICAST != 0)
                && has_carrier()
        })
        .expect(
            "a non-loopback interface that is up, has a carrier, has IFF_MULTICAST and holds \
             an IPv6 address; this test cannot run without one",
        )
}

/// Start a router with `locator` and wait until `device` holds every group in
/// `want`, or the budget runs out. Returns what `device` held at the end and the
/// router's own output.
fn memberships_while_running(
    locator: &str,
    want: &[IpAddr],
    device: &str,
) -> (Vec<IpAddr>, String) {
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
    let mut held = multicast_memberships(device);
    while !want.iter().all(|g| held.contains(g)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        held = multicast_memberships(device);
    }
    (held, read_captured(&mut log))
}

// No proof claim, and not by omission: the membership is read from the kernel's
// table, which is independent of wz's code but is not a foreign implementation.
// The cross-impl audit (A4-3) refuses any claim line, `none` included, in a file
// that spawns nothing foreign. The foreign witnesses of `#join=` and `#ttl=` are
// the namespace legs this file's header names.
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo router-multicast-faces, locator-iface) on lo \
            for IPv4 and on a multicast-capable NIC for IPv6; Layer M runs via --ignored"]
fn multicast_locator_flag_joins_its_own_and_extra_groups_on_the_named_interface() {
    for (label, own, extra, device) in [
        ("IPv4", "239.255.73.50", "239.255.73.51", "lo".to_owned()),
        (
            "IPv6",
            "ff02::7a7a:4e30",
            "ff02::7a7a:4e31",
            ipv6_multicast_interface(),
        ),
    ] {
        let own_ip: IpAddr = own.parse().expect("own group");
        let extra_ip: IpAddr = extra.parse().expect("extra group");
        // Both groups must be absent BEFORE the router starts, or their presence
        // afterwards says nothing about this router.
        let before = multicast_memberships(&device);
        assert!(
            !before.contains(&own_ip) && !before.contains(&extra_ip),
            "{label}: {device} already holds {own} or {extra} before the router starts: \
             {before:?}"
        );
        let host = match own_ip {
            IpAddr::V4(_) => own.to_string(),
            IpAddr::V6(_) => format!("[{own}]"),
        };
        let locator = format!("udp/{host}:7491#iface={device};join={extra}");
        let (held, log) = memberships_while_running(&locator, &[own_ip, extra_ip], &device);
        assert!(
            held.contains(&own_ip) && held.contains(&extra_ip),
            "{label}: a router given {locator} must hold memberships for BOTH {own} and \
             {extra} on {device}; {device} held {held:?}\n--- router output ---\n{log}"
        );
    }
}
