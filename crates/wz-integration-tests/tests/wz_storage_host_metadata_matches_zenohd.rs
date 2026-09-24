// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.23 `adminspace-core` — the `metadata` a node's config states is served in
//! its `local_data` with the SAME BYTES a real zenohd serves for the same value.
//!
//! # Why a byte comparison against a running zenohd
//!
//! Upstream does not serve the value the way the operator wrote it. The config
//! is read by `json5` into a `serde_json::Value` and written back by
//! `serde_json`, so object keys come out sorted, `1.50` comes out `1.5`, and an
//! exponent gains its sign. wz reproduces that pipeline by hand
//! (`Json5Value::to_upstream_value_json_text`), and its unit test grades it
//! against the two crates themselves. This leg grades the WHOLE path instead:
//! one config value, handed to a stock zenohd with `--cfg` and to a wz storage
//! host through a `--config` FILE, read back from each by the same foreign
//! client. A reply that differed in one byte would be two nodes describing
//! themselves differently to anything that compares them.
//!
//! The value is built to make every rewrite visible: keys out of order at two
//! depths, a float with a trailing zero, one wide enough to need an exponent,
//! an escape, and a `null`. A path that kept the source text, or sorted only
//! the top level, differs here.
//!
//! # Which host, and why one is enough here
//!
//! The storage host, because it is the host a `--config` file and a pico client
//! both reach with no other process in between. The other two hosts read the
//! value off the same `WzConfig` field through the same answerer, which the
//! crate-level tests pin; what only a running pair can show is that the file,
//! the expansion, the flag, the config and the reply agree end to end.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs,
    wait_for_substring, wait_for_zenohd_handshake_ready, wz_ap_demo_binary, zenoh_pico_cli_binary,
    zenohd_binary, ChildGuard, PortReservation,
};

/// The value both nodes are configured with, as an operator would write it.
const METADATA: &str = r#"{ zeta: 1, name: 'strawberry', floor: 1.50,
    nested: { b: [1e30, "tab\there"], a: null }, location: "Penny Lane" }"#;

/// What upstream serves for [`METADATA`], written out so a failure names the
/// expected bytes rather than only a mismatch between two replies.
const SERVED: &str = r#"{"floor":1.5,"location":"Penny Lane","name":"strawberry","nested":{"a":null,"b":[1e+30,"tab\there"]},"zeta":1}"#;

/// A one-shot pico `z_get` on `keyexpr`, captured up to its terminating Final.
fn pico_get_output(z_get: &Path, keyexpr: &str, endpoint: &str) -> String {
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;
    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args(["-k", keyexpr, "-e", endpoint, "-m", "client"])
            .stdout(Stdio::from(g_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    let done = wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    match done {
        Ok(c) => c,
        Err(c) => {
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}")
        }
    }
}

/// The `metadata` value inside the one `local_data` reply pico decoded.
///
/// Taken as the BYTES between the field's key and the next top-level key.
/// Upstream's keys are sorted, so `metadata` is always followed by `plugins`,
/// and reading the raw span rather than a parsed value is the point: a parse
/// would forgive exactly the key order and number spelling this leg exists to
/// compare.
fn served_metadata(out: &str) -> String {
    let body = out
        .lines()
        .find_map(|l| {
            let (_, rest) = l.split_once("('@/")?;
            let (_, body) = rest.split_once("': '")?;
            body.rsplit_once('\'').map(|(body, _)| body.to_string())
        })
        .unwrap_or_else(|| panic!("no local_data reply was decoded\n--- z_get ---\n{out}"));
    let (_, from_metadata) = body
        .split_once("\"metadata\":")
        .unwrap_or_else(|| panic!("the reply carries no metadata field: {body}"));
    let (value, _) = from_metadata
        .split_once(",\"plugins\":")
        .unwrap_or_else(|| panic!("metadata is not followed by plugins: {body}"));
    value.to_string()
}

// wz-proves: adminspace-core pico->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features adminspace-config-hotreload,zenoh-config + zenoh-pico z_get); Layer E6h runs via --ignored"]
fn wz_storage_host_serves_its_config_metadata_as_zenohd_does() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_get = zenoh_pico_cli_binary("z_get");

    // ── the reference: a stock zenohd holding the same value ────────────
    let cfg = format!("metadata:{METADATA}");
    let (mut zenohd, zenohd_port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (metadata reference)",
        None,
        &[],
        None,
        &[cfg.as_str()],
    );
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{zenohd_port}"), || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let reference = pico_get_output(
        &z_get,
        "@/*/router",
        &format!("tcp/127.0.0.1:{zenohd_port}"),
    );
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let reference = served_metadata(&reference);

    // ── the subject: a wz storage host started on a FILE ─────────────────
    let mut file = tempfile::NamedTempFile::new().expect("tempfile for the wz config");
    write!(file, "{{ metadata: {METADATA} }}").expect("write the wz config");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());
    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut h_reader = h_stderr;
    let mut host = ChildGuard::wrap(
        "wz-ap-demo --storage-host --config (adminspace-config-hotreload,zenoh-config)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .arg("--config")
            .arg(file.path())
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );
    let ready = match wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = host.child_mut().kill();
            let _ = host.child_mut().wait();
            panic!("storage host never became ready within 5s\n--- host ---\n{c}");
        }
    };
    let root = ready
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, r)| r.trim().to_string())
        })
        .and_then(|k| k.strip_suffix("/config").map(str::to_string))
        .expect("storage host logged its admin config keyexpr");
    drop(port_res);
    let subject = pico_get_output(&z_get, &root, &format!("tcp/{addr}"));
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();
    let subject = served_metadata(&subject);

    // The reference first, so a zenohd that stopped serving what this file says
    // it serves is reported as that, not as a wz defect.
    assert_eq!(
        reference, SERVED,
        "a stock zenohd no longer serves this value the way this leg states"
    );
    assert_eq!(
        subject, reference,
        "the same config value, served by a wz node and by a zenohd, differs"
    );
}
