// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2787 (§5.23 `adminspace-config-hotreload`) — a stock zenoh-pico client
//! drives the storage manager's DECLARATIVE document on a wz `--storage-host`,
//! over the wire, the way an operator drives a zenohd's: by writing config keys
//! below `@/<zid>/peer/config/plugins/storage_manager/`.
//!
//! ## What each step witnesses
//!
//! 1. A PUT of one storage's declaration STARTS the plugin (the notification
//!    plane: the document appeared) and hosts the storage on the `memory`
//!    volume a started plugin always has — read back by the foreign client
//!    through the status sub-tree, and by writing to and reading from the
//!    storage itself.
//! 2. A PUT of ONE FIELD of that declaration is merged into the document, and
//!    the storage is re-created under the new key expression (the validator:
//!    old and new documents diffed, the difference applied).
//! 3. A PUT naming a volume nobody declared is REFUSED by the running plugin,
//!    and changes nothing: the storage from step 2 is still there, and the
//!    refused one never appears.
//! 4. A PUT emptying `storages` removes the storage (the diff's delete).
//! 5. A PUT of the whole section as `{}` STOPS the plugin.
//!
//! Every step is a PUT because the only foreign write client this tree
//! provisions is pico's `z_put`; upstream's DELETE of the same keys takes the
//! same route in wz (`WzConfig::remove_by_key_with`) and is witnessed below
//! the wire by `plugins_section_writes_pass_the_validator_then_notify_once`.
//!
//! ## Positive edges only
//!
//! Every wait is on a line that MUST appear: the host's own verdict for each
//! write (written, or refused), pico's `Received query final notification`.
//!
//! ## Which binary this rides
//!
//! Layer E6h's SECOND build, `wz-ap-demo --features
//! adminspace-config-hotreload,zenoh-config`: the storage host applies a
//! config-key write only with `zenoh-config`, and the first build lacks it.
//! Cargo uplifts every feature variant of `wz-ap-demo` to one path, so this
//! test is only safe inside the lane that built it, after its first test.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// A one-shot pico `z_get` on `keyexpr`, captured up to its terminating Final.
fn pico_get_output(z_get: &Path, keyexpr: &str, addr: &str) -> String {
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;
    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args(["-k", keyexpr, "-e", &format!("tcp/{addr}"), "-m", "client"])
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

/// The pico-decoded reply body at `key`, if one came back.
fn pico_body_at(out: &str, key: &str) -> Option<String> {
    let marker = format!("('{key}': '");
    out.lines().find_map(|l| {
        let (_, rest) = l.split_once(&marker)?;
        rest.rsplit_once('\'').map(|(body, _)| body.to_string())
    })
}

/// A one-shot pico `z_put` of `value` at `key`.
fn pico_put(z_put: &Path, key: &str, value: &str, addr: &str) {
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(z_put)
            .args([
                "-k",
                key,
                "-v",
                value,
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
    let _ = child.child_mut().wait();
}

/// Wait for the host's verdict line, or fail naming the step.
fn host_says(host: &mut ChildGuard, log: &mut std::fs::File, line: &str, step: &str) {
    if let Err(c) = wait_for_substring(log, line, Duration::from_secs(15)) {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("step {step}: the host never said `{line}` within 15s\n--- host ---\n{c}");
    }
}

// wz-proves: adminspace-config-hotreload pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,zenoh-config + zenoh-pico z_get/z_put CLIs); Layer E6h runs via --ignored"]
fn wz_storage_host_plugins_section_drives_the_storage_manager_via_pico() {
    let demo = wz_ap_demo_binary();
    // The host must be the binary this lane just built with `zenoh-config`: a
    // stale one would refuse every `plugins/...` write as a key it cannot
    // apply, and the refusal would read as the step's failure.
    assert_demo_binary_newer_than_sources(&demo);
    let z_get = zenoh_pico_cli_binary("z_get");
    let z_put = zenoh_pico_cli_binary("z_put");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut h_reader = h_stderr;
    let mut host = ChildGuard::wrap(
        "wz-ap-demo --storage-host (adminspace-config-hotreload,zenoh-config)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .arg("--config-write-permit")
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

    let sm = format!("{root}/config/plugins/storage_manager");
    let status = format!("{root}/status/plugins/storage_manager");

    // ── (1) the document appears: the plugin starts and hosts the storage ──
    pico_put(
        &z_put,
        &format!("{sm}/storages/demo"),
        r#"{"key_expr":"demo/**","volume":"memory"}"#,
        &addr,
    );
    host_says(
        &mut host,
        &mut h_reader,
        "plugins config key plugins/storage_manager/storages/demo written over the wire — \
         storage_manager plugin running",
        "1",
    );
    let out = pico_get_output(&z_get, &format!("{status}/**"), &addr);
    assert_eq!(
        pico_body_at(&out, &format!("{status}/storages/demo")).as_deref(),
        Some(r#"{"key_expr":"demo/**","volume":"memory"}"#),
        "the declared storage is hosted as declared\n--- z_get ---\n{out}"
    );
    assert!(
        pico_body_at(&out, &format!("{status}/volumes/memory")).is_some(),
        "a started plugin has its `memory` volume\n--- z_get ---\n{out}"
    );
    // And it is a STORAGE, not only a status leaf: what a client writes under
    // its key expression is what a later client reads back.
    pico_put(&z_put, "demo/a", "stored-by-pico", &addr);
    let data = pico_get_output(&z_get, "demo/**", &addr);
    assert_eq!(
        pico_body_at(&data, "demo/a").as_deref(),
        Some("stored-by-pico"),
        "the declared storage captures and answers\n--- z_get ---\n{data}"
    );

    // ── (2) one FIELD of the declaration: merged, diffed, re-created ──
    pico_put(
        &z_put,
        &format!("{sm}/storages/demo/key_expr"),
        r#""demo/x/**""#,
        &addr,
    );
    host_says(
        &mut host,
        &mut h_reader,
        "plugins config key plugins/storage_manager/storages/demo/key_expr written over the \
         wire — storage_manager plugin running",
        "2",
    );
    let out = pico_get_output(&z_get, &format!("{status}/**"), &addr);
    assert_eq!(
        pico_body_at(&out, &format!("{status}/storages/demo")).as_deref(),
        Some(r#"{"key_expr":"demo/x/**","volume":"memory"}"#),
        "the storage now owns the merged key expression\n--- z_get ---\n{out}"
    );

    // ── (3) a declaration the running plugin cannot apply: refused, nothing moves ──
    pico_put(
        &z_put,
        &format!("{sm}/storages/bad"),
        r#"{"key_expr":"bad/**","volume":"nope"}"#,
        &addr,
    );
    host_says(
        &mut host,
        &mut h_reader,
        "plugins config key plugins/storage_manager/storages/bad refused, nothing changed",
        "3",
    );
    let out = pico_get_output(&z_get, &format!("{status}/**"), &addr);
    assert_eq!(
        pico_body_at(&out, &format!("{status}/storages/bad")),
        None,
        "the refused storage never appears\n--- z_get ---\n{out}"
    );
    assert!(
        pico_body_at(&out, &format!("{status}/storages/demo")).is_some(),
        "and the refusal touched nothing that was there\n--- z_get ---\n{out}"
    );

    // ── (4) `storages` emptied: the diff deletes the storage ──
    pico_put(&z_put, &format!("{sm}/storages"), "{}", &addr);
    host_says(
        &mut host,
        &mut h_reader,
        "plugins config key plugins/storage_manager/storages written over the wire — \
         storage_manager plugin running",
        "4",
    );
    let out = pico_get_output(&z_get, &format!("{root}/plugins/**"), &addr);
    assert!(
        out.lines()
            .any(|l| l.contains(r#""id":"storage_manager""#) && l.contains(r#""state":"Loaded""#)),
        "no storage is live, so storage_manager reports Loaded\n--- z_get ---\n{out}"
    );

    // ── (5) the whole section emptied: the plugin stops ──
    pico_put(&z_put, &format!("{root}/config/plugins"), "{}", &addr);
    host_says(
        &mut host,
        &mut h_reader,
        "plugins config key plugins written over the wire — storage_manager plugin not running",
        "5",
    );

    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();
    let _ = read_captured(&mut h_reader);
}
