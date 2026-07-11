// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y237 (§5.23 `adminspace-plugins-handlers`) — a routing peer answers its OWN
//! admin `@/<zid>/peer/plugins/**` GET over the wire with its compiled-in plugin
//! registry, the wz-native superset of zenoh's `plugins_data` handler
//! (`net/runtime/adminspace.rs:922`).
//!
//! wz has NO dlopen plugin-manager (the §5.22 plugin family is reserved); a wz
//! "plugin" is a COMPILED-IN composable subsystem with a zenoh-plugin analogue.
//! Peer A is built with `storage-backend`, so `compiled_plugins` reports
//! `storage_manager` (the wz mirror of `zenoh-plugin-storage-manager`, state
//! `Loaded`). The reply body is the zenoh `PluginStatusRec` — a green reply cannot
//! be a static echo: the key carries the ACTUAL plugin id AND the body carries the
//! `state`/`path` a live registry enumeration produces.
//!
//! Flow (mirrors `wz_peer_adminspace_introspection`):
//!   1. Peer A: `--peer <addr> --config-queryable`. A hosts a forwarder-local admin
//!      queryable on `@/<A_zid>/peer/**`; its `compiled_plugins` reports the static
//!      subsystem registry (available from the first GET — no declare barrier, the
//!      plugin list is compile-time, unlike the per-tick subscriber snapshot).
//!   2. Scrape A's `adminspace config GET at @/<zid>/peer/config` log → derive the
//!      node root, then build `@/<zid>/peer/plugins/**`.
//!   3. Client B: `--connect <addr> --query @/<A_zid>/peer/plugins/** ...`. B's
//!      z_get self-dispatches on A to the admin handler, which replies one entry per
//!      compiled plugin whose entity key intersects.
//!   4. Assert B logs `REPLY RECEIVED` keyed `@/<zid>/peer/plugins/storage_manager`
//!      (the LIVE plugin id) with a `PluginStatusRec` body carrying
//!      `"state":"Loaded"` + `"path":"__static__"` (the wz-native static marker).
//!
//! Needs the demo built with
//! `--features routing-peer,adminspace-plugins-handlers,storage-backend` (Layer E6e).
//! wz<->wz loopback — the plugins legs add no wire format, so no cross-impl leg is
//! needed.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-plugins-handlers,storage-backend); Layer E6e runs via --ignored"]
fn wz_peer_admin_plugins_introspection_over_the_wire() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A: hosts its adminspace with a compiled plugin registry ────
    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // Scrape A's admin config key → derive the node root (`@/<zid>/peer`). This log
    // also proves A's admin host is registered; the plugin registry is compile-time,
    // so it is populated from the first GET (no `declared subscriber` barrier needed).
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
    let plugins_get = format!("{root}/plugins/**");
    let expected_reply_key = format!("{root}/plugins/storage_manager");
    drop(port_res);

    // ── client B: GET the plugins introspection over the wire ───────────
    let b_stderr = tempfile::tempfile().expect("tempfile for client B stderr");
    let b_writer = b_stderr.try_clone().expect("dup client B stderr handle");
    let mut b_reader = b_stderr;

    let mut b_child = ChildGuard::wrap(
        "wz-ap-demo client B (--connect --query plugins/** )",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--query")
            .arg(&plugins_get)
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
            "client B never received a plugins-introspection reply within 10s — the \
             admin `plugins/**` GET did not enumerate A's compiled plugin registry over \
             the wire.\n--- B ---\n{c}\n--- A ---\n{a_final}"
        ),
    };

    // The LIVE-content assertion (defeats a static echo): the reply is keyed by A's
    // ACTUAL compiled plugin id, which only a real `compiled_plugins()` enumeration
    // could produce.
    assert!(
        reply.contains(&format!("keyexpr='{expected_reply_key}'")),
        "REPLY RECEIVED lacks keyexpr='{expected_reply_key}' — the admin plugins \
         introspection did not list A's compiled storage_manager subsystem.\n--- B ---\n{reply}"
    );
    // The zenoh `PluginStatusRec` body for a wz static subsystem (the reply log
    // debug-escapes the quotes, so they appear backslash-escaped). This pins the
    // exact shape + content (id/name = storage_manager, state = Loaded, the wz-native
    // `__static__` path marker), not just a bare key match.
    assert!(
        reply.contains(r#"body=Put"#)
            && reply.contains(r#"\"id\":\"storage_manager\""#)
            && reply.contains(r#"\"state\":\"Loaded\""#)
            && reply.contains(r#"\"path\":\"__static__\""#),
        "the plugins introspection reply body must be the zenoh PluginStatusRec for the \
         static storage_manager subsystem (id/state/path), not a bare echo.\n--- B ---\n{reply}"
    );
}
