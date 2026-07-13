// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y277 — FOREIGN-INTEROP CONFIG-HOTRELOAD: a stock zenoh-pico client drives
//! watching-zenoh's `adminspace-config-hotreload` storage lifecycle END-TO-END over
//! the wire. A pico `z_put` `@/<zid>/peer/config/storage-add demo:demo/**` live-spawns
//! a `RuntimeStorageManager` storage on the wz `--storage-host`; a subsequent pico
//! `z_get` `@/<zid>/peer/plugins/**` then decodes `storage_manager` state `Started`
//! (`Loaded` before); a `storage-del demo` reverses it back to `Loaded`.
//!
//! ## What binds the claim (and why it is NOT a bool flip)
//!
//! `adminspace-config-hotreload`'s `F=` is the config-diff-driven storage lifecycle:
//! the `storage-add`/`storage-del` decode (wz-session-core `parse_admin_config_write`),
//! the APPLY via `RuntimeStorageManager::add_storage` / `remove_storage`, AND the
//! DYNAMIC plugin registry (`compiled_plugins_dyn`) reflecting `storage_manager`
//! `Started` when a storage is LIVE. The host's GET handler reads
//! `compiled_plugins_dyn(&version, storage_started)`, and `storage_started` tracks
//! `!manager.is_empty()` — set only by a REAL `add_storage`/`remove_storage`, never a
//! bare bool. A `Started` reply therefore cannot appear without a live
//! manager-hosted storage; the state flip is the wz-encoded reply pico decodes, so
//! the claim rides the plugins GET arm (`wz->pico`). pico is ALSO the encoder of the
//! `storage-add`/`storage-del` PUT (the `pico->wz` config-write half), but the atom
//! is witnessed by the STATE it produces, not the PUT that triggers it.
//!
//! ## The "zombie storage" bound (NAMED — do not over-read this witness)
//!
//! A stock pico `z_put` and `z_get` are SEPARATE one-shot processes, so the wz host
//! multi-accepts a fresh per-client Session each. A storage is spawned on the
//! TRANSIENT z_put client Session; when that pico process exits and the Session is
//! dropped, the hosted `StorageService` SURVIVES (the manager is hoisted; the service
//! holds `Arc` clones of the dropped Session's observer/actions, and dead-link
//! undeclare emits are swallowed). So the storage is STATE-OBSERVABLE across the
//! session boundary — it keeps the manager non-empty, which is what this
//! plugins-STATE witness reads — but it is a ZOMBIE: it does NOT serve data across
//! the connection boundary. This test asserts ONLY the reported state
//! (`Loaded`->`Started`->`Loaded`); it makes no claim that the zombie storage answers
//! cross-connection data gets.
//!
//! ## Positive edges only
//!
//! Every wait is on a log/notification that MUST appear: the host's readiness line,
//! the host's `spawned live storage`/`despawned` lines (the storage-apply barriers,
//! waited on AFTER the driving z_put exits), and pico's `Received query final
//! notification`. No arm waits for the absence of a line.
//!
//! ## Which binary this rides
//!
//! Layer E6h's — it builds `wz-ap-demo --features adminspace-config-hotreload` (the
//! ONLY lane with the `--storage-host` mode compiled in) and drives this test. The
//! `wz_storage_host_` fn prefix keeps the default Layer E sweep's `--skip wz_peer` /
//! `--skip wz_router` from touching it; the `--ignored` gate keeps it out of the
//! host-only unit runs. Cargo uplifts every feature variant of `wz-ap-demo` to one
//! path (R311y269), so this variant is only safe inside the lane that built it.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// Run a fresh one-shot pico `z_get` on `<root>/plugins/**` and return its stdout
/// (captured up to the terminating `Received query final notification`). Each call
/// is a SEPARATE pico process opening its own session — the reason the wz host
/// multi-accepts.
fn pico_get_plugins_output(z_get: &Path, root: &str, addr: &str) -> String {
    let g_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let g_writer = g_stdout.try_clone().expect("dup z_get stdout handle");
    let mut g_reader = g_stdout;

    let mut g_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args([
                "-k",
                &format!("{root}/plugins/**"),
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

    let done = wait_for_substring(
        &mut g_reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let out = match done {
        Ok(c) => c,
        Err(c) => {
            let _ = g_child.child_mut().kill();
            let _ = g_child.child_mut().wait();
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}");
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    out
}

/// Assert the pico-decoded `<root>/plugins/storage_manager` record carries the
/// expected `storage_manager` state. `when` names the phase for the failure message.
fn assert_plugins_state(out: &str, root: &str, expected_state: &str, when: &str) {
    let key = format!("{root}/plugins/storage_manager");
    let line = out
        .lines()
        .find(|l| l.contains(&format!("('{key}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no plugins leg at `{key}` ({when})\n--- z_get ---\n{out}")
        });
    assert!(
        line.contains(r#""id":"storage_manager""#)
            && line.contains(&format!(r#""state":"{expected_state}""#)),
        "storage_manager must report state `{expected_state}` ({when})\n  got: {line}"
    );
}

/// Drive a one-shot pico `z_put` at `key` carrying `value`. pico ENCODES the config
/// write (keyexpr + payload + push body); wz's config-write subscriber decodes it.
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

// wz-proves: adminspace-config-hotreload wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload + zenoh-pico z_get/z_put CLIs); Layer E6h runs via --ignored"]
fn wz_storage_host_config_hotreload_state_flip_via_pico() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let z_put = zenoh_pico_cli_binary("z_put");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── the wz storage host: multi-accepts per-client Sessions, hosts the admin GET
    //    + config-write subscriber, applies storage-add/-del via RuntimeStorageManager.
    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut h_reader = h_stderr;

    let mut h_child = ChildGuard::wrap(
        "wz-ap-demo --storage-host (adminspace-config-hotreload)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );

    let ready = wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    let captured = match ready {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("storage host never became ready within 5s\n--- host ---\n{c}");
        }
    };
    let config_key = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("storage host logged the admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    drop(port_res);

    // ── (1) BEFORE any storage-add: storage_manager is Loaded (compiled, not live) ──
    let out_before = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_before, &root, "Loaded", "before storage-add");

    // ── (2) pico z_put storage-add: wz calls RuntimeStorageManager::add_storage ──
    pico_put(
        &z_put,
        &format!("{root}/config/storage-add"),
        "demo:demo/**",
        &addr,
    );
    // BARRIER: the host's REAL add_storage apply (waited after the z_put exits — a
    // positive edge, the apply happens on the host as it drains the config-write).
    let spawned = wait_for_substring(
        &mut h_reader,
        "spawned live storage 'demo' — storage_manager Started",
        Duration::from_secs(15),
    );
    if let Err(c) = spawned {
        let _ = h_child.child_mut().kill();
        let _ = h_child.child_mut().wait();
        panic!(
            "storage host never applied the pico storage-add within 15s — the \
             config-hotreload add_storage did not run on a pico-encoded PUT\n--- host ---\n{c}"
        );
    }

    // ── (3) AFTER storage-add: storage_manager flips to Started ──
    let out_added = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_added, &root, "Started", "after storage-add");

    // ── (4) pico z_put storage-del: wz calls RuntimeStorageManager::remove_storage ──
    pico_put(&z_put, &format!("{root}/config/storage-del"), "demo", &addr);
    let despawned = wait_for_substring(
        &mut h_reader,
        "despawned 'demo' — storage_manager Loaded",
        Duration::from_secs(15),
    );
    if let Err(c) = despawned {
        let _ = h_child.child_mut().kill();
        let _ = h_child.child_mut().wait();
        panic!(
            "storage host never applied the pico storage-del within 15s — the \
             config-hotreload remove_storage did not run on a pico-encoded PUT\n--- host ---\n{c}"
        );
    }

    // ── (5) AFTER storage-del: storage_manager reverts to Loaded ──
    let out_removed = pico_get_plugins_output(&z_get, &root, &addr);
    assert_plugins_state(&out_removed, &root, "Loaded", "after storage-del");

    let _ = h_child.child_mut().kill();
    let _ = h_child.child_mut().wait();
    // Surface the host log on a post-mortem failure hunt (unused on the green path).
    let _ = read_captured(&mut h_reader);
}
