// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y271 — FOREIGN-INTEROP ADMINSPACE PLUGINS: a real zenoh-pico `z_get` CLI
//! reads wz's `@/<zid>/peer/plugins/**` admin leg and decodes the compiled-subsystem
//! record wz serves there — the `storage_manager` entry, `path: "__static__"`.
//!
//! ## What is claimed, and why it is PARTIAL
//!
//! `adminspace-plugins-handlers` has three surfaces in its `F=`: the `plugins/**`
//! legs (B), the `status/plugins/**` legs (C), and the `plugins` field of the
//! `local_data` node record. This test witnesses **only B**, and the claim is
//! graded `partial` accordingly rather than fused into a full one:
//!
//! - **B — witnessed.** pico decodes
//!   `@/<zid>/peer/plugins/storage_manager` carrying the real registry record
//!   (`name`/`id`/`version`/`state: "Loaded"`/`path: "__static__"` — the
//!   superset marker for wz's compiled-subsystem registry, which is NOT a dlopen
//!   PluginsManager; the §5.22 plugin family stays reserved).
//! - **C + the local_data field — NOT witnessed, for a faithful reason.** Both
//!   report *started* plugins (wz mirrors zenoh's `plugins_status`, which replies
//!   each STARTED plugin's `path()`). This binary compiles `storage-backend` in,
//!   so `storage_manager` is `Loaded`, but nothing STARTS it — no storage is
//!   configured — so C replies nothing and the node record's `plugins` field is
//!   `{}`. That is correct behaviour, not a gap; it is simply unproven here.
//!   Witnessing it needs a LIVE storage, which is `adminspace-config-hotreload`
//!   territory (a follow-up round that would upgrade this claim to full).
//!
//! ## Why the witness is neither an empty-container tautology nor storage's doing
//!
//! Both failure modes were RUN, not reasoned about:
//!
//! - EXECUTED COUNTERFACTUAL on the atom. Rebuild this demo
//!   `--features routing-peer,storage-backend` — the subsystem still compiled in,
//!   only `adminspace-plugins-handlers` removed — and the test FAILS: pico's GET
//!   returns no `plugins/**` leg at all. The witness therefore binds to the ATOM's
//!   code, not to storage-backend's presence.
//! - NOT `{} == {}`. Probing the feature ON but WITHOUT `storage-backend` answers
//!   the same GET with nothing (an empty registry: no compiled subsystem to
//!   report), and a demo without the feature reports `"plugins":null` in its node
//!   record (pinned by `wz_peer_adminspace_to_pico_zget`). The body asserted below
//!   is non-empty and subsystem-specific — the failure mode that graded
//!   `codec-keep-alive` full on `vec![] == vec![]` cannot reach it.
//!
//! ## Which binary this rides
//!
//! Layer E6e's — it already builds exactly the set this needs
//! (`routing-peer,adminspace-plugins-handlers,storage-backend`) for its wz<->wz
//! twin `wz_peer_adminspace_plugins`, so the cross-impl half rides the same lane
//! and the same binary, exactly as R311y270 did for E6b. That matters because
//! cargo keys a binary's final path on (target dir, profile, bin name) ONLY —
//! every feature variant of `wz-ap-demo` uplifts to the SAME
//! `crates/target/debug/wz-ap-demo` (R311y269) — so a variant is only ever safe
//! to use inside the lane that built it, which is the convention every E6* lane
//! already follows (build, then test, self-contained).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

// wz-proves: adminspace-plugins-handlers wz->pico partial

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-plugins-handlers,storage-backend + zenoh-pico z_get CLI); Layer E6e runs via --ignored"]
fn wz_peer_admin_plugins_decoded_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A: hosts its adminspace with the plugins legs compiled in ──
    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable, plugins+storage-backend)",
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
    drop(port_res);

    // ── the FOREIGN client: pico z_get on the plugins legs ──────────
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
            let a_log = read_captured(&mut a_reader);
            panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- A ---\n{a_log}");
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    // ── the compiled-subsystem record, decoded by pico ──────────────
    let key = format!("{root}/plugins/storage_manager");
    let line = out
        .lines()
        .find(|l| l.contains(&format!("('{key}':")))
        .unwrap_or_else(|| panic!("pico decoded no plugins leg at `{key}`\n--- z_get ---\n{out}"));
    assert!(
        line.contains(r#""id":"storage_manager""#) && line.contains(r#""state":"Loaded""#),
        "the plugins record identifies the compiled storage_manager subsystem and its state\n  got: {line}"
    );
    assert!(
        line.contains(r#""path":"__static__""#),
        "the plugins record carries wz's __static__ marker — the superset signal that this \
         registry is the compiled-subsystem set, NOT a dlopen PluginsManager (§5.22 stays \
         reserved)\n  got: {line}"
    );
}
