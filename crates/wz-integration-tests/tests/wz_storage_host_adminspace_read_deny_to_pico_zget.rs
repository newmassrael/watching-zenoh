// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y812 — FOREIGN-INTEROP ADMINSPACE READ GATE, STORAGE-HOST TIER: a real
//! zenoh-pico `z_get` CLI queries a watching-zenoh `--storage-host` whose
//! `permissions.read` GET gate is DENIED (`--no-admin-read`), and receives ONLY the
//! terminating Final — no admin reply body at all.
//!
//! ## The gap this closes
//!
//! `adminspace-read`'s residual named exactly one thing still open after R311y781:
//! the `--storage-host` admin host hardcoded `read: true`. It was the last shipping
//! wz run-mode the gate could not reach — R311y780 gave the peer hosts a live permit
//! source and R311y781 gave the router-hat one, and this closes the third. The
//! host's answerer is bespoke (its plugins leg is `compiled_plugins_dyn` over the
//! live `storage_started`, plus any dlopen'd records), so it does not go through
//! `Session::declare_adminspace`; what it now shares with the other two is the
//! source, not the declare.
//!
//! ## What the assertion binds to (the atom's own cfg-gated code)
//!
//! The demo is built `--features adminspace-config-hotreload` — the only build that
//! compiles the `--storage-host` run-mode — and run `--no-admin-read`. The permit
//! resolves through `wz::runtime_tokio::admin_read_permit`, a
//! `cfg(feature = "adminspace-read")` site, off the host's shared live `WzConfig`
//! ON EVERY GET rather than from a bool captured at setup. The resolved value feeds
//! `AdminAnswerCtx::read`, which `answer_admin_query` consults FIRST: every admin
//! leg is suppressed and only the dispatch SSOT's terminating Final unwinds
//! (zenoh's bare ResponseFinal on deny, `net/runtime/adminspace.rs:462-467`).
//!
//! ## Why this is not a flaky wait-for-absence
//!
//! The test waits on pico's POSITIVE terminating edge ("Received query final
//! notification"), which only fires once the responder has sent ResponseFinal — the
//! query round-trip provably completed. It then asserts no reply body preceded it. A
//! pico that never connected would time out with a transcript, not pass. The host
//! also logs `adminspace read permit = false`, asserted below, so a pass proves the
//! gate DENIED rather than that some unrelated path returned nothing.
//!
//! ## The gate is real (counterfactual)
//!
//! `adminspace-config-hotreload` does not imply `adminspace-read`; building the demo
//! without the latter makes `admin_read_permit` return `true` regardless of the flag,
//! the record is served, and the absence assertion below fires — so the witness
//! cannot survive the atom's code being compiled out. Its positive complement is the
//! Layer E6h test (`wz_storage_host_config_hotreload_pico`), where the same run-mode
//! WITHOUT the flag serves its plugins leg over the wire to the same foreign client.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

// wz-proves: adminspace-read wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,adminspace-read + zenoh-pico z_get CLI); Layer E6i runs via --ignored"]
fn wz_storage_host_adminspace_read_deny_seen_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    // This fixture drives a flag the storage-host run-mode gained THIS round, and a
    // demo older than the sources would not parse it — it would serve its admin
    // surface as before while the run looked like a configuration the test chose.
    // The permit-log assertion below would catch that, but only after the reader has
    // spent the failure on the wrong hypothesis.
    assert_demo_binary_newer_than_sources(&demo);
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── the storage host: serves its adminspace with the READ gate DENIED ──
    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut h_reader = h_stderr;

    let mut h_child = ChildGuard::wrap(
        "wz-ap-demo storage host (--storage-host --no-admin-read)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .arg("--no-admin-read")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );

    // BARRIER (not a sleep): the host's dedicated readiness line, emitted after bind
    // and after every admin key is computed → derive the node root (`@/<zid>/peer`).
    // It fires regardless of the read gate, which is per-GET inside the handler.
    let h_ready = wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    let h_captured = match h_ready {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("storage host never registered its admin host within 5s\n--- host ---\n{c}");
        }
    };
    // Prove the gate is ACTIVE + denying, not merely that pico got nothing: with
    // adminspace-read compiled out this line reads `= true`, and the absence
    // assertion below would then fail on the served record.
    assert!(
        h_captured.contains("adminspace read permit = false"),
        "the storage host's read gate must be DENIED under --no-admin-read + \
         adminspace-read\n--- host ---\n{h_captured}"
    );
    let config_key = h_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("the storage host logged its admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    drop(port_res);

    // ── the FOREIGN client: pico z_get dials the host and GETs the whole root ──
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

    // Wait on pico's terminating Final — the POSITIVE edge proving the query
    // round-trip completed. Only then is "no reply preceded it" a real result.
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
            let h_log = read_captured(&mut h_reader);
            panic!(
                "pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n\
                 --- host ---\n{h_log}"
            );
        }
    };
    let _ = g_child.child_mut().kill();
    let _ = g_child.child_mut().wait();
    let _ = h_child.child_mut().kill();
    let _ = h_child.child_mut().wait();

    // ── adminspace-read DENY: the reply set is empty (Final only) ───
    //
    // Every admin reply pico prints is keyed `('@/<zid>/peer...` (z_get.c:44). Under
    // the denied gate `answer_admin_query` returns before emitting any, so no such
    // line appears; only the Final (already observed) came back. This host's surface
    // includes the `plugins` leg the E6h positive twin reads, so a gate that leaked
    // only that leg would still be caught here.
    assert!(
        !out.contains(&format!("('{root}")),
        "read=false must suppress every admin reply under `{root}`; pico saw a \
         reply\n--- z_get ---\n{out}"
    );
}
