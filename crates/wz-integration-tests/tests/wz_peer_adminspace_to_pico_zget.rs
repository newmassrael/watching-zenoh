// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y270 — FOREIGN-INTEROP ADMINSPACE: a real zenoh-pico `z_get` CLI queries a
//! watching-zenoh routing peer's admin space and decodes BOTH admin bodies wz
//! serves — the `adminspace-core` node record and the
//! `adminspace-introspection-handlers` per-entity view — in one GET.
//!
//! ## The gap this closes
//!
//! §5.23 adminspace was entirely wz<->wz until now: Layer E6b's existing
//! `wz_peer_adminspace_introspection` drives peer A's admin host from a *wz*
//! client, so every §5.23 atom sat at `unproven` on the cross-impl proof axis
//! (scripts/audit-crossimpl-proof.sh) — the admin bodies had never been read by a
//! foreign decoder. They add no new wire *format* (an admin GET is an ordinary
//! Query and the replies ordinary Put bodies), which is why no cross-impl leg was
//! written; but "no new format" is an argument about the envelope, not about the
//! KEYS and BODIES, and those are exactly what a foreign client has to agree with
//! for the admin space to be usable from one. This test supplies that witness.
//!
//! ## What each assertion binds to (the atom's own cfg-gated code)
//!
//! The demo is built `--features routing-peer,adminspace-introspection-handlers`,
//! and that feature COMPOSES `adminspace-core`
//! (crates/wz-runtime-tokio/Cargo.toml: `adminspace-introspection-handlers =
//! ["adminspace-core", ...]`), so this binary carries the cfg sites of both atoms
//! — `Session::declare_adminspace` + the local_data builder for core, the
//! `answer_admin_query` per-entity legs + `LinkstateForwarder::subscriptions()`
//! for introspection. Both claims below name a body only that code can produce:
//!
//! - `adminspace-core` — the node record at the root key `@/<zid>/peer`, whose
//!   `F=` is precisely this JSON (zid / version / locators / sessions / plugins).
//!   The assertion pins `"zid":"<A_zid>"` AND `"locators":["tcp/<the actual bound
//!   addr>"]`, so it cannot pass on a static echo: the locator is the port this
//!   test reserved at runtime.
//! - `adminspace-introspection-handlers` — the per-entity subscriber leg, keyed
//!   `@/<zid>/peer/subscriber/demo/data` (the LIVE declared keyexpr, not a
//!   template) with the zenoh `Sources` body `{"routers":[],"peers":["<A_zid>"],
//!   "clients":[]}`. Same discriminator as the wz<->wz E6b test, now read by
//!   pico's C decoder.
//!
//! ## Why the gate is real — and the two atoms are NOT equally bound
//!
//! The claims below rest on different strengths of evidence, and conflating them
//! is how a proof axis rots, so they are stated apart:
//!
//! - `adminspace-introspection-handlers` — EXECUTED COUNTERFACTUAL. Rebuilding the
//!   demo `--features routing-peer` ALONE (introspection off) and re-running this
//!   test makes it FAIL: pico's reply set still carries the node record and the
//!   config leg, but the `@/<zid>/peer/subscriber/**` leg is gone and the
//!   assertion below fires. The witness therefore cannot survive the atom's code
//!   being compiled out. (Verified R311y270, not asserted from the source.)
//!   `adminspace-metrics` is likewise absent from this binary's features and its
//!   leg is absent from the reply set — the third assertion pins that, so a reply
//!   set that ignored the cfg gates could not pass.
//! - `adminspace-core` — SOURCE-READ BINDING, no counterfactual build EXISTS. The
//!   demo's `routing-peer` hard-pulls `wz/adminspace-core`
//!   (crates/wz-ap-demo/Cargo.toml:179 — a routing peer hosts its own admin
//!   space), so there is no `--peer` binary with the atom off to run against. The
//!   binding is instead structural and total: the ENTIRE `wz_session_core::
//!   adminspace` module — which is where the `local_data` JSON body this test
//!   decodes is built — is `#[cfg(feature = "adminspace-core")]`
//!   (crates/wz-session-core/src/lib.rs:492). With the atom off the module does
//!   not exist and the body cannot be produced. That is a strong binding, but it
//!   is READ, not RUN, and it is graded accordingly.
//!
//! ## Named bound (what this does NOT prove)
//!
//! Only the two atoms above. `adminspace-metrics` / `-plugins-handlers` / `-read`
//! / `-write` need a demo built with THEIR features, and cargo uplifts every
//! feature variant of the same `--bin` to the same path (R311y269), so a second
//! variant needs its own build+run step or its own target dir — a follow-up round,
//! not a silent second claim here.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

// wz-proves: adminspace-core wz->pico
// wz-proves: adminspace-introspection-handlers wz->pico

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-introspection-handlers + zenoh-pico z_get CLI); Layer E6b runs via --ignored"]
fn wz_peer_adminspace_decoded_by_pico_z_get() {
    let demo = wz_ap_demo_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
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

    // Scrape A's admin config key → derive the node root (`@/<zid>/peer`) and the
    // zid. Both are runtime values; every assertion below is keyed on them.
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
    let zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/<whatami>");

    // BARRIER (not a sleep): A declared the subscriber, and the SAME app-tick
    // re-snapshotted the introspection buffer — so a query arriving after this
    // log finds the subscriber in the admin view.
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

    // ── the FOREIGN client: zenoh-pico's z_get dials A and GETs the whole root ──
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

    // pico prints the terminating Final as its own line; waiting on THAT (rather
    // than on the replies) means a missing reply fails the assertions below with
    // the full transcript, instead of timing out with no diagnosis.
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

    // ── adminspace-core: the node record, decoded by pico ───────────
    //
    // Keyed at the bare root. The locator is the port THIS test reserved, so a
    // static fixture cannot satisfy it.
    let core_line = out
        .lines()
        .find(|l| l.contains(&format!("('{root}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no adminspace-core node record at `{root}`\n--- z_get ---\n{out}")
        });
    assert!(
        core_line.contains(&format!(r#""zid":"{zid}""#)),
        "adminspace-core record carries A's live zid\n  got: {core_line}"
    );
    assert!(
        core_line.contains(&format!(r#""locators":["tcp/{addr}"]"#)),
        "adminspace-core record carries A's ACTUAL bound locator (not a template)\n  got: {core_line}"
    );
    assert!(
        core_line.contains(r#""version":"#) && core_line.contains(r#""sessions":"#),
        "adminspace-core record carries the version + sessions fields of its F=\n  got: {core_line}"
    );

    // ── adminspace-introspection-handlers: the live per-entity view ─
    let sub_key = format!("{root}/subscriber/demo/data");
    let sub_line = out
        .lines()
        .find(|l| l.contains(&format!("('{sub_key}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no per-entity subscriber leg at `{sub_key}`\n--- z_get ---\n{out}")
        });
    assert!(
        sub_line.contains(&format!(
            r#"{{"routers":[],"peers":["{zid}"],"clients":[]}}"#
        )),
        "subscriber leg carries the zenoh Sources body naming A as the source peer\n  got: {sub_line}"
    );

    // ── the gate is real: metrics is NOT in this binary's features ──
    assert!(
        !out.contains(&format!("('{root}/metrics'")),
        "adminspace-metrics is not compiled into this binary, so its leg must be \
         absent — a reply set that ignores the cfg gates would prove nothing\n--- z_get ---\n{out}"
    );
}
