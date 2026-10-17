// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `adminspace/permissions/read` (with `adminspace/enabled`) read from a
//! `--config` FILE: the topology `wz_peer_adminspace_read_deny_to_pico_zget.rs`
//! drives with `--config-queryable --no-admin-read`, with both stated in a stock
//! zenoh document instead.
//!
//! ## What this adds over the flag-level leg
//!
//! The flag leg proves the denied GET gate from typed words. The step from the
//! `adminspace` block to those words is covered by argv unit tests that never
//! start a node. Here the peer is given ONLY `--peer <addr> --config <file>`, so
//! the admin host that answers pico exists because the FILE'S `enabled: true`
//! expanded to `--config-queryable`, and the gate that denies exists because the
//! FILE'S `permissions.read: false` expanded to `--no-admin-read`.
//!
//! ## The control
//!
//! Same topology, same pico query, a file that names `adminspace.enabled` and not
//! the read permission. The host is still there, so the control is served: pico
//! decodes a reply under the node root. A file whose `read` key was ignored would
//! pass the control and fail the deny leg, and a host that never came up would
//! fail the control and not merely look denied.
//!
//! Requires: wz-ap-demo built with `--features routing-peer,adminspace-read,zenoh-config`
//! and the zenoh-pico CLI. Layer E6g's lane owns that build.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// The document: admin host on, read permission denied.
const DOC_READ_DENIED: &str = "{ adminspace: { enabled: true, permissions: { read: false } } }";
/// The document: admin host on, the read permission not named.
const DOC_READ_UNNAMED: &str = "{ adminspace: { enabled: true } }";

/// What one run observed.
struct Observed {
    /// The peer's stderr up to the admin host's registration line.
    peer_log: String,
    /// What pico printed up to the terminating Final.
    z_get_out: String,
    /// The node's admin root, `@/<zid>/peer`.
    root: String,
}

/// Start `--peer <addr> --config <file>` (nothing else), GET the whole admin
/// root from a real pico `z_get`, and return what both ends said.
fn query_the_admin_root_of_a_peer_given(document: &str) -> Observed {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(document.as_bytes()).expect("write config");
    file.flush().expect("flush config");

    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config <file>)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config")
            .arg(file.path())
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // BARRIER (not a sleep): the admin host registered. It exists only if the
    // file's `adminspace.enabled` reached `--config-queryable`.
    let a_captured = match wait_for_substring(
        &mut a_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!(
                "peer A never registered its admin host within 5s, so the file's \
                 `adminspace.enabled` did not reach `--config-queryable`\n--- A ---\n{c}"
            );
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
    drop(port_res);

    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;

    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args([
                "-k",
                &format!("{root}/**"),
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::from(g_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    // The terminating Final is the positive edge that the round trip completed,
    // so an absence of replies before it is a result and not a timeout.
    let out = match wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = g_child.child_mut().kill();
            let _ = g_child.child_mut().wait();
            let a_log = read_captured(&mut a_reader);
            panic!(
                "pico z_get never saw the terminating Final within 15s\n--- z_get \
                 ---\n{c}\n--- A ---\n{a_log}"
            );
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    Observed {
        peer_log: a_captured,
        z_get_out: out,
        root,
    }
}

/// A `--config` file with `adminspace.permissions.read: false` makes the peer
/// answer a pico `z_get` with the terminating Final alone.
// wz-proves: none -- the DOCUMENT -> flag half of a flag-level proof that lives in
// wz_peer_adminspace_read_deny_to_pico_zget.rs; pico only reads the peer's decision, so
// no atom is witnessed beyond what that file already claims.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-read,zenoh-config + zenoh-pico z_get CLI); Layer E6g runs via --ignored"]
fn wz_peer_adminspace_read_denied_by_a_config_file_seen_by_pico_z_get() {
    let seen = query_the_admin_root_of_a_peer_given(DOC_READ_DENIED);

    assert!(
        seen.peer_log.contains("\"--no-admin-read\""),
        "the peer's report of the expansion does not name `--no-admin-read`, so the \
         file's `permissions.read: false` never became the flag\n--- A ---\n{}",
        seen.peer_log
    );
    assert!(
        seen.peer_log.contains("adminspace read permit = false"),
        "the peer's read gate must be DENIED by the file's `permissions.read: false`\n\
         --- A ---\n{}",
        seen.peer_log
    );
    assert!(
        !seen.z_get_out.contains(&format!("('{}", seen.root)),
        "`permissions.read: false` in the file must suppress every admin reply under \
         `{}`; pico saw a reply\n--- z_get ---\n{}",
        seen.root,
        seen.z_get_out
    );
}

/// CONTROL, read permission not named: the same file shape with only
/// `enabled: true` leaves the gate open, and pico decodes a reply under the node
/// root. Without it the deny leg's silence could be a host that never answered.
// wz-proves: none -- the key-absent control of the deny leg above; it asserts the
// admin host's existing served path, which the flag-level files already witness.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-read,zenoh-config + zenoh-pico z_get CLI); Layer E6g runs via --ignored"]
fn wz_peer_adminspace_without_the_read_key_in_a_config_file_serves_pico_z_get() {
    let seen = query_the_admin_root_of_a_peer_given(DOC_READ_UNNAMED);

    assert!(
        !seen.peer_log.contains("\"--no-admin-read\""),
        "a file that does not name `permissions.read` expanded to `--no-admin-read`\n\
         --- A ---\n{}",
        seen.peer_log
    );
    assert!(
        seen.peer_log.contains("adminspace read permit = true"),
        "a file that does not name `permissions.read` must leave the gate open\n\
         --- A ---\n{}",
        seen.peer_log
    );
    assert!(
        seen.z_get_out.contains(&format!("('{}", seen.root)),
        "the admin host given `enabled: true` alone must answer pico under `{}`; no \
         reply arrived, so the deny leg's silence proves nothing\n--- z_get ---\n{}",
        seen.root,
        seen.z_get_out
    );
}
