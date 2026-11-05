// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `adminspace/permissions/write` read from a `--config` FILE: the topology
//! `wz_peer_adminspace_write_from_pico_zput.rs` drives with `--config-writable`
//! and `--config-write-permit`, with the permission stated in a stock zenoh
//! document instead.
//!
//! ## What this adds over the flag-level legs
//!
//! zenoh states the write permission as ONE key, `adminspace.permissions.write`;
//! wz splits it into hosting the write subscriber and permitting the write, and
//! the expansion maps the one key onto both flags. That mapping is covered by an
//! argv unit test only. In the GRANT leg below the peer is given no admin flag at
//! all (`--peer <addr> --subscribe mesh/data --config <file>`), so a pico `z_put`
//! reconfigures it only if the file's single key produced BOTH the host and the
//! permit.
//!
//! ## The controls
//!
//! A permit can only be refused by a node that hosts the write subscriber, and a
//! document cannot ask for the host without the permit. The two DENY controls
//! therefore type `--config-writable` on the command line (the host) and let the
//! file say the permission is not granted: once by NOT NAMING the key, once by
//! stating it `false`. Both must reach the gate's own rejection line, so a
//! missing apply is attributed to the permission and not to a dead host.
//!
//! Requires: wz-ap-demo built with `--features routing-peer,adminspace-write,zenoh-config`
//! and the zenoh-pico CLI. Layer E6's lane owns that build.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// The document: the write permission granted.
const DOC_WRITE_GRANTED: &str = "{ adminspace: { permissions: { write: true } } }";
/// The document: an adminspace block that does not name the write permission.
const DOC_WRITE_UNNAMED: &str = "{ adminspace: { permissions: { read: true } } }";
/// The document: the write permission stated at upstream's shipped default.
const DOC_WRITE_FALSE: &str = "{ adminspace: { permissions: { write: false } } }";

/// Spawn peer A on `--peer <addr> --subscribe mesh/data [--config-writable]
/// --config <file>`, scrape its admin root, and return the child, its stderr
/// reader, the `@/<zid>/peer` root, the address and the config tempfile (kept
/// alive for the child's lifetime).
fn spawn_write_host_from_document(
    document: &str,
    host_typed_on_the_command_line: bool,
) -> (
    ChildGuard,
    std::fs::File,
    String,
    String,
    tempfile::NamedTempFile,
) {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(document.as_bytes()).expect("write config");
    file.flush().expect("flush config");

    let stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let writer = stderr.try_clone().expect("dup peer A stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(&demo);
    cmd.arg("--peer")
        .arg(&addr)
        .arg("--subscribe")
        .arg("mesh/data");
    if host_typed_on_the_command_line {
        cmd.arg("--config-writable");
    }
    cmd.arg("--config").arg(file.path());
    let mut child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config <file>)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer A"),
    );

    // The write host announces its keyexpr; that log is the barrier proving the
    // write subscriber is registered before pico's Put can race it.
    let ready = wait_for_substring(
        &mut reader,
        "adminspace config WRITE at ",
        Duration::from_secs(5),
    );
    let captured = match ready {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait_bounded();
            panic!("peer A never registered its config-write host within 5s\n--- A ---\n{c}");
        }
    };
    let write_key = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer A logged the admin config-write keyexpr");
    let root = write_key
        .strip_suffix("/config/**")
        .expect("write key ends with /config/**")
        .to_string();
    drop(port_res);
    (child, reader, root, addr, file)
}

/// Drive pico's `z_put` CLI at A's `.../config/acl-deny`, carrying the keyexpr to
/// deny. pico ENCODES the Put; wz decodes it.
fn pico_put_acl_deny(root: &str, addr: &str) {
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(&z_put)
            .args([
                "-k",
                &format!("{root}/config/acl-deny"),
                "-v",
                "mesh/data",
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_put"),
    );
    let _ = child.child_mut().wait_bounded();
}

/// Run one DENY control: the host is typed, the file does not grant the write.
fn assert_a_pico_write_is_rejected_given(document: &str) {
    let (mut a_child, mut a_reader, root, addr, _config) =
        spawn_write_host_from_document(document, true);
    pico_put_acl_deny(&root, &addr);

    let denied = wait_for_substring(
        &mut a_reader,
        "config-write DENIED (adminspace.permissions.write=false",
        Duration::from_secs(15),
    );
    let out = match denied {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait_bounded();
            panic!(
                "peer A never rejected the config write within 15s on the document \
                 {document} -- that document does not grant `permissions.write`, so the \
                 gate must fire\n--- A ---\n{c}"
            );
        }
    };
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait_bounded();

    assert!(
        out.contains(&format!("ignored {root}/config/acl-deny")),
        "the rejection names the exact key pico's z_put addressed\n--- A ---\n{out}"
    );
    assert!(
        !out.contains("\"--config-write-permit\""),
        "a document that does not grant the write expanded to `--config-write-permit`\n\
         --- A ---\n{out}"
    );
    let tail = read_captured(&mut a_reader);
    let all = format!("{out}{tail}");
    assert!(
        !all.contains("config reconfigured"),
        "a DENIED config write must not also reconfigure the forwarder\n--- A ---\n{all}"
    );
}

/// GRANT: `adminspace.permissions.write: true` in the file is the only thing
/// that makes the peer host the write subscriber AND permit the write, and a real
/// pico `z_put` is applied.
// wz-proves: none -- the DOCUMENT -> flags half of the flag-level grant arm in
// wz_peer_adminspace_write_from_pico_zput.rs, which itself claims no atom; pico only
// encodes the Put the file's key made acceptable.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write,zenoh-config + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_admin_config_write_applied_from_pico_z_put_given_a_config_file_grant() {
    let (mut a_child, mut a_reader, root, addr, _config) =
        spawn_write_host_from_document(DOC_WRITE_GRANTED, false);
    pico_put_acl_deny(&root, &addr);

    let applied = wait_for_substring(
        &mut a_reader,
        "config reconfigured — now denying mesh/data",
        Duration::from_secs(15),
    );
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait_bounded();
    match applied {
        Ok(c) => {
            assert!(
                c.contains("\"--config-writable\"") && c.contains("\"--config-write-permit\""),
                "the peer's report of the expansion must name both flags the one \
                 `permissions.write` key stands for\n--- A ---\n{c}"
            );
        }
        Err(c) => panic!(
            "peer A never applied the config write pico PUT within 15s -- the file's \
             `permissions.write: true` did not make the peer both host and permit the \
             write\n--- A ---\n{c}"
        ),
    }
}

/// DENY control, key not named: an adminspace block without `write` leaves the
/// gate closed even though the host is typed.
// wz-proves: none -- the key-absent control of the grant leg above; it asserts the
// permissions.write gate the flag-level file already witnesses over the wire.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write,zenoh-config + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_admin_config_write_denied_from_pico_z_put_when_a_config_file_omits_the_key() {
    assert_a_pico_write_is_rejected_given(DOC_WRITE_UNNAMED);
}

/// DENY control, key stated `false`: upstream's shipped default is the behaviour
/// the node already has, so the file must not open the gate.
// wz-proves: none -- the stated-default control of the grant leg above; it asserts the
// permissions.write gate the flag-level file already witnesses over the wire.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write,zenoh-config + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_admin_config_write_denied_from_pico_z_put_when_a_config_file_states_false() {
    assert_a_pico_write_is_rejected_given(DOC_WRITE_FALSE);
}
