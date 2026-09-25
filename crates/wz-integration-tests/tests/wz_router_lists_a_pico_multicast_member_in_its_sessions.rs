// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2859 — a running wz router lists a foreign zenoh-pico MULTICAST member in
//! its adminspace `sessions[]`, as a row of upstream's multicast shape.
//!
//! ## The property
//!
//! Upstream's `local_data` walks every unicast transport and then every peer of
//! every multicast transport, writing the second kind of row with four keys,
//! `group, links, peer, whatami`
//! (`zenoh/src/net/runtime/adminspace.rs` @ `let transport_multicast_peer_to_json =`).
//! The member's one link runs from the node's own locator on the group to the
//! address the member's datagrams come from
//! (`io/zenoh-transport/src/multicast/transport.rs` @ `link.dst = p.locator.clone();`).
//!
//! The library side is witnessed in-process (the answerer's bytes, the
//! dispatcher's member view, the drive loop keeping it). What only a running
//! process can show is the router host's wiring: that the face the router
//! joins the group with is the one its admin handler reads. So this leg joins a
//! real group with a real foreign member and reads the answer.
//!
//! ## Red first, inside the leg
//!
//! The same GET is made twice. Before the pico member starts, the router has no
//! member (its own beacons loop back and are dropped by the self-zid gate), so
//! the answer carries NO multicast row; after the member's JOIN, exactly one.
//! A router that never lists members fails the second GET, and a router that
//! lists something whatever the group holds (its own beacon, say) fails the
//! first.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Needs wz-ap-demo built with `router-multicast-faces` and
//! `adminspace-router-linkstate`, the admin probe, and the pico CLI; the group
//! rides the default-route interface, as the ingress leg's does.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, default_route_iface, read_captured, wait_for_substring,
    wz_ap_demo_binary, wz_e2e_admin_probe_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// How long the probe's whole script may take; the probe bounds each step
/// itself and logs it, so a timeout here is a process that never finished.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The group, and a port no other multicast leg binds.
const GROUP: &str = "224.0.0.224";
const GROUP_PORT: u16 = 7476;

/// One root GET of the router's adminspace, returning the `local_data` body.
fn get_local_data(
    probe: &std::path::Path,
    addr: &str,
    root: &str,
    router_reader: &mut std::fs::File,
) -> String {
    let p_stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let p_writer = p_stderr.try_clone().expect("dup the probe's stderr handle");
    let mut p_reader = p_stderr;
    let mut p_child = ChildGuard::wrap(
        "wz-e2e-admin-probe (one root GET)",
        Command::new(probe)
            .args(["--connect", addr, "--get", root])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let out = match wait_for_substring(&mut p_reader, "SCRIPT COMPLETE steps=1", SCRIPT_TIMEOUT) {
        Ok(c) => c,
        Err(c) => {
            let host = read_captured(router_reader);
            let _ = p_child.child_mut().kill();
            let _ = p_child.child_mut().wait();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- router ---\n{host}");
        }
    };
    let _ = p_child.child_mut().kill();
    let _ = p_child.child_mut().wait();
    assert!(
        out.contains(&format!("STEP 1 GET '{root}' FINAL replies=1")),
        "the root GET is answered once\n--- probe ---\n{out}"
    );
    out.lines()
        .find_map(|l| {
            l.split_once("STEP 1 BODY #1 ")
                .map(|(_, rest)| rest.to_string())
        })
        .unwrap_or_else(|| panic!("the root GET carried a body\n--- probe ---\n{out}"))
}

/// The multicast rows of a `local_data` body: every object that opens with
/// the `group` key, which only that kind of row carries and which sorts first
/// in it. Each is cut at the end of its LAST key, `whatami`, whose string value
/// is followed by the row's closing `}` (a link object inside the row closes
/// with `"}` too, so the cut is anchored on the key, not on the brace).
fn multicast_rows(body: &str) -> Vec<&str> {
    body.match_indices(r#"{"group":"#)
        .map(|(at, _)| {
            let rest = &body[at..];
            let key = rest
                .find(r#","whatami":""#)
                .expect("a multicast row carries whatami");
            let value = key + r#","whatami":""#.len();
            let close = rest[value..]
                .find(r#""}"#)
                .expect("the whatami value closes the row");
            &rest[..value + close + 2]
        })
        .collect()
}

// wz-proves: adminspace-core pico->wz partial
#[test]
#[ignore = "binary-dep multicast e2e (wz-ap-demo --features router-multicast-faces,locator-iface,adminspace-router-linkstate + wz-e2e-admin-probe + zenoh-pico z_pub); Layer M runs via --ignored"]
fn wz_router_lists_a_pico_multicast_member_in_its_sessions() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let probe = wz_e2e_admin_probe_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{GROUP_PORT}#iface={iface}");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

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
    drop(port_res);
    // The group face binds and beacons on its own task after the admin legs
    // are hosted; give its own beacons time to loop back, so the first GET
    // would see them if they were (wrongly) admitted.
    std::thread::sleep(Duration::from_millis(600));

    let before = get_local_data(&probe, &addr, &root, &mut r_reader);
    assert!(
        multicast_rows(&before).is_empty(),
        "with no member on the group the router lists no multicast row\n{before}"
    );

    // The foreign member: pico as a multicast peer, beaconing its JOIN on the
    // group while it publishes (once a second, for longer than this leg runs).
    let z_pub_capture = tempfile::tempfile().expect("tempfile for z_pub capture");
    let z_pub_out = z_pub_capture.try_clone().expect("dup z_pub stdout handle");
    let z_pub_err = z_pub_capture.try_clone().expect("dup z_pub stderr handle");
    let mut z_pub_reader = z_pub_capture;
    let pico_locator = format!("udp/{GROUP}:{GROUP_PORT}#iface={iface}");
    let mut z_pub_child = ChildGuard::wrap(
        "z_pub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args([
                "-k",
                "demo/mcast/member",
                "-v",
                "WZ-MCAST-MEMBER-R2859",
                "-l",
                &pico_locator,
                "-m",
                "peer",
                "-n",
                "30",
            ])
            .stdout(Stdio::from(z_pub_out))
            .stderr(Stdio::from(z_pub_err))
            .spawn()
            .expect("spawn z_pub via stdbuf"),
    );

    // pico beacons its JOIN on open and then on its join interval; poll the
    // router until the member is listed rather than guessing one wait.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let after = loop {
        let body = get_local_data(&probe, &addr, &root, &mut r_reader);
        if !multicast_rows(&body).is_empty() || std::time::Instant::now() >= deadline {
            break body;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let pico_out = read_captured(&mut z_pub_reader);

    let rows = multicast_rows(&after);
    assert_eq!(
        rows.len(),
        1,
        "the one pico member is one multicast row\n{after}\n--- pico ---\n{pico_out}"
    );
    let row = rows[0];
    let group = format!(r#"{{"group":"udp/{GROUP}:{GROUP_PORT}","links":[{{"dst":"udp/"#);
    assert!(
        row.starts_with(&group),
        "the row opens with the group and the member's one link\n{row}"
    );
    assert!(
        row.ends_with(r#""whatami":"peer"}"#),
        "pico joined as a peer, and the row closes on that role\n{row}"
    );
    for absent in [r#""region":"#, r#""shm":"#, r#""weight":"#] {
        assert!(
            !row.contains(absent),
            "a multicast row carries none of the unicast row's {absent}\n{row}"
        );
    }
    // The link's two ends: the member's address, then this router's locator on
    // the group. They must differ, or the router listed its own beacon.
    let dst = row
        .split_once(r#""dst":""#)
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(v, _)| v)
        .expect("the link has a dst");
    let src = row
        .split_once(r#""src":""#)
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(v, _)| v)
        .expect("the link has a src");
    assert_ne!(dst, src, "the member is not the router itself\n{row}");
    // The router's end names an address, as upstream's does: its multicast
    // link fills an unspecified send address from the interface. The first run
    // of this leg read `udp/0.0.0.0:<port>` here, which is how R2859 found that
    // wz bound its sending socket to the wildcard.
    let src_ip = src
        .strip_prefix("udp/")
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip())
        .unwrap_or_else(|| panic!("the link's src is a udp socket address\n{row}"));
    assert!(
        !src_ip.is_unspecified(),
        "the router's end of the link is an interface address, not the wildcard\n{row}"
    );
    let peer = row
        .split_once(r#""peer":""#)
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(v, _)| v)
        .expect("the row names its peer");
    assert!(!peer.is_empty(), "the member's zid is written\n{row}");
}
