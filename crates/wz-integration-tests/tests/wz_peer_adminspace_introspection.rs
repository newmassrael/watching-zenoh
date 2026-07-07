// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y203 (§5.23 `adminspace-introspection-handlers`) — a routing peer answers
//! its OWN admin `@/<zid>/peer/subscriber/**` GET over the wire with the LIVE list
//! of its declared subscribers, the wz analogue of zenoh's `subscribers_data`
//! handler (`net/runtime/adminspace.rs:781`).
//!
//! This defeats the "compiled handler fed an empty list" blackhole: the reply key
//! carries the ACTUAL declared keyexpr (`demo/data`) AND the body is the zenoh
//! `Sources` struct listing A as the declaring peer — so a green reply cannot be a
//! static echo; it proves the admin view enumerated A's live `forwarder.subscriptions()`
//! snapshot.
//!
//! Flow (mirrors `wz_peer_adminspace_config`):
//!   1. Peer A: `--peer <addr> --config-queryable --subscribe demo/data`. A hosts a
//!      forwarder-local admin queryable on `@/<A_zid>/peer/**` AND declares a
//!      subscriber `demo/data`; the app-tick re-snapshots the subscriber into the
//!      admin introspection buffer the same tick it declares it.
//!   2. Scrape A's `adminspace config GET at @/<zid>/peer/config` log → derive the
//!      node root, then GATE on A's `declared subscriber demo/data` log (a barrier,
//!      not a sleep — it guarantees the introspection buffer already holds the sub).
//!   3. Client B: `--connect <addr> --query @/<A_zid>/peer/subscriber/** ...`. B's
//!      z_get self-dispatches on A to the admin handler, which replies one entry per
//!      declared subscriber whose entity key intersects.
//!   4. Assert B logs `REPLY RECEIVED` keyed `@/<zid>/peer/subscriber/demo/data`
//!      (the LIVE keyexpr) with body `{"routers":[],"peers":["<A_zid>"],"clients":[]}`
//!      (the zenoh `Sources` struct — the SAME body both admin handlers serialize).
//!
//! Needs the demo built with `--features routing-peer,adminspace-introspection-handlers`
//! (Layer E6b). wz<->wz loopback — the introspection adds no wire format, so no
//! cross-impl leg is needed.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-introspection-handlers); Layer E6b runs via --ignored"]
fn wz_peer_admin_subscriber_introspection_over_the_wire() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A: hosts its adminspace + declares a subscriber ────────
    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable --subscribe demo/data)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .arg("--subscribe")
            .arg("demo/data")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // Scrape A's admin config key → derive the node root (`@/<zid>/peer`).
    let a_ready = wait_for_substring(
        &mut a_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    let a_captured = match a_ready {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!("peer A never registered its admin host within 5s\n--- A ---\n{c}");
        }
    };
    let config_key = a_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer A logged the admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    let subscriber_get = format!("{root}/subscriber/**");
    let expected_reply_key = format!("{root}/subscriber/demo/data");

    // BARRIER (not a sleep): A declared the subscriber, and the SAME app-tick
    // re-snapshotted the introspection buffer — so once this log appears, a query
    // that arrives at A will find the sub in the admin view.
    let declared = wait_for_substring(
        &mut a_reader,
        "declared subscriber demo/data",
        Duration::from_secs(10),
    );
    if let Err(c) = declared {
        let _ = a_child.child_mut().kill();
        let _ = a_child.child_mut().wait();
        panic!("peer A never declared its subscriber within 10s\n--- A ---\n{c}");
    }
    drop(port_res);

    // ── client B: GET the subscriber introspection over the wire ────
    let b_stderr = tempfile::tempfile().expect("tempfile for client B stderr");
    let b_writer = b_stderr.try_clone().expect("dup client B stderr handle");
    let mut b_reader = b_stderr;

    let mut b_child = ChildGuard::wrap(
        "wz-ap-demo client B (--connect --query subscriber/** )",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--query")
            .arg(&subscriber_get)
            .arg("--on-query-reply-log")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(b_writer))
            .spawn()
            .expect("spawn wz-ap-demo client B"),
    );

    let dialed = wait_for_substring(&mut b_reader, "connected to", Duration::from_secs(5));
    let reply_recv = wait_for_substring(&mut b_reader, "REPLY RECEIVED", Duration::from_secs(10));

    let _ = b_child.child_mut().kill();
    let _ = b_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    let a_final = read_captured(&mut a_reader);
    let b_final = read_captured(&mut b_reader);
    eprintln!("--- peer A stderr ---\n{a_final}");
    eprintln!("--- client B stderr ---\n{b_final}");

    if let Err(c) = &dialed {
        panic!("client B never dialed A within 5s\n--- B ---\n{c}\n--- A ---\n{a_final}");
    }
    let reply = match reply_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "client B never received a subscriber-introspection reply within 10s — the \
             admin `subscriber/**` GET did not enumerate A's live subscriber over the \
             wire.\n--- B ---\n{c}\n--- A ---\n{a_final}"
        ),
    };

    // The LIVE-content assertion (defeats a static echo): the reply is keyed by A's
    // ACTUAL declared subscriber keyexpr, which only a live enumeration of
    // `forwarder.subscriptions()` could produce.
    assert!(
        reply.contains(&format!("keyexpr='{expected_reply_key}'")),
        "REPLY RECEIVED lacks keyexpr='{expected_reply_key}' — the admin subscriber \
         introspection did not list A's live declared subscriber.\n--- B ---\n{reply}"
    );
    // A's zid = the 2nd chunk of `@/<zid>/peer` — the peer that declared demo/data.
    let a_zid = root
        .split('/')
        .nth(1)
        .expect("root has a zid chunk")
        .to_string();
    // zenoh serializes the SAME `Sources` struct for the admin body of BOTH kinds — for
    // A's own subscriber it is `{"routers":[],"peers":["<A_zid>"],"clients":[]}` (the
    // reply log debug-escapes the quotes, so they appear backslash-escaped). This pins
    // the exact body shape + content (A as the declaring peer), not just a bare `null`.
    assert!(
        reply.contains(r#"body=Put"#)
            && reply.contains(&format!(r#"\"peers\":[\"{a_zid}\"]"#))
            && reply.contains(r#"\"routers\":[]"#)
            && reply.contains(r#"\"clients\":[]"#),
        "the subscriber introspection reply body must be the zenoh Sources struct \
         {{routers:[],peers:[{a_zid}],clients:[]}}, not `null`.\n--- B ---\n{reply}"
    );
}
