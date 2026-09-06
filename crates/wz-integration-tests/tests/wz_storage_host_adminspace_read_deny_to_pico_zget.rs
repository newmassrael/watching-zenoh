// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// R2374 — one one-shot pico `z_get` over `keyexpr`, returning what it decoded up
/// to its terminating Final.
///
/// A SEPARATE pico process per call, which is what the storage host multi-accepts
/// for; it is also what makes the flip below a real observation rather than one
/// connection's cached view.
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

    // The POSITIVE terminating edge: it fires only once the responder sent
    // ResponseFinal, so "nothing preceded it" is a result rather than a timeout.
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

/// R2374 — one one-shot pico `z_put`. pico ENCODES the config write; wz's
/// config-write subscriber decodes it through `parse_admin_config_write`.
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

/// Whether pico decoded any admin reply under `root`. pico prints one
/// `('<key>': '<payload>')` line per reply, so this reads the key literal rather
/// than a payload substring that could occur elsewhere.
fn pico_replied_under(out: &str, root: &str) -> bool {
    out.contains(&format!("('{root}"))
}

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

/// R2374 (§5.23 `adminspace-read`) — THE READ PERMIT IS RE-READ PER GET, WITNESSED
/// FROM OFF THE PROCESS: a foreign pico client GRANTS, REVOKES and RE-GRANTS this
/// host's `permissions.read` over the wire, and each of its own `z_get`s sees the
/// permit that was in force when it asked.
///
/// ## The residual this closes, and why it needed a new sub-key
///
/// `adminspace-read`'s last residual after R311y812 read: "the PER-GET resolve has
/// no witness HERE: nothing on this host's wire mutates its permissions, so the
/// live-ness is structural parity with the peer/router-hat hosts, whose R311y780
/// test covers the mechanism." That is exactly right, and it is why a test could
/// not be written: R311y780's witness drives
/// `Session::declare_adminspace_with_permissions_source`, and this host does not go
/// through that declare — its answerer is bespoke because its plugins leg is a
/// DYNAMIC registry. So the library test covers a mechanism this host does not use,
/// and everything else was an argument from shape.
///
/// What made the witness possible is a capability wz was missing rather than a test
/// wz had not written. Upstream's config is a json5 document and its admin PUT
/// routes any pointer into the live `Config`, so an upstream node CAN be told to
/// change `adminspace/permissions/read` by a client; wz's typed intents had no such
/// key. `AdminConfigWrite::AdminReadPermit` adds it, which both closes that
/// divergence and puts the permit somewhere an outside observer can move it.
///
/// ## What makes this a resolve witness and not a restart witness
///
/// One host PROCESS, one `Arc<Mutex<WzConfig>>`, three GETs and two PUTs against it.
/// The permit is never passed to the handler; the handler pulls it from that
/// instance on every request. A host that captured the permit at setup would answer
/// all three GETs the same way, and a host that re-read it only at connection setup
/// would still answer all three the same way, because each `z_get` is its own
/// connection either way — what separates them is that the PUT between them moved
/// the shared slice.
///
/// ## Why RE-GRANT and not just revoke
///
/// A revoke-only test passes against a host that latches to deny — a plausible bug
/// in a `set_admin_permissions` that ORs rather than assigns, and a much worse one
/// than never denying, because it locks an operator out of their own node with no
/// way back over the wire. The third GET is what refuses it.
///
/// ## Positive edges only
///
/// Every wait is on a line that MUST appear: the host's readiness line, the host's
/// own `read permit set to <v> over the wire` line after each PUT, and pico's
/// terminating Final. Nothing waits for an absence.
// wz-proves: adminspace-read pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,adminspace-read,adminspace-write + zenoh-pico z_get/z_put CLIs); Layer E6i runs via --ignored"]
fn wz_storage_host_adminspace_read_permit_flips_over_the_wire() {
    let demo = wz_ap_demo_binary();
    // This drives `--config-write-permit` on a run-mode that gained it THIS round;
    // an older binary would ignore the flag, deny every write, and the failure would
    // read as "the permit never moved" rather than "the binary is stale".
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

    // No `--no-admin-read`: this host STARTS permissive, and the wire takes it away.
    // `--config-write-permit` is what lets the wire do so at all — without it the
    // twin test below shows the same PUT refused.
    let mut h_child = ChildGuard::wrap(
        "wz-ap-demo storage host (--storage-host --config-write-permit)",
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

    let h_captured = match wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("storage host never registered its admin host within 5s\n--- host ---\n{c}");
        }
    };
    // Both gates are ACTIVE and in the state this test needs. Asserted rather than
    // assumed: with `adminspace-read` compiled out the first line reads `= true`
    // whatever the flag says, and the revoke below would then prove nothing.
    assert!(
        h_captured.contains("adminspace read permit = true"),
        "this host must START permissive\n--- host ---\n{h_captured}"
    );
    assert!(
        h_captured.contains("adminspace write permit = true"),
        "--config-write-permit must grant the write gate; without it the PUTs below \
         are refused and the read permit never moves\n--- host ---\n{h_captured}"
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

    // ── GRANTED: the population. Without this the two absences below would be
    //    satisfied by a host that answers nothing at all. ──
    let granted = pico_get_output(&z_get, &format!("{root}/**"), &addr);
    assert!(
        pico_replied_under(&granted, &root),
        "the permissive host must serve its admin surface, or the revoke below is \
         asserted against nothing\n--- z_get ---\n{granted}"
    );

    // ── REVOKE over the wire, then GET again ──
    pico_put(
        &z_put,
        &config_key_write(&root, "admin-read"),
        "false",
        &addr,
    );
    let after_revoke = match wait_for_substring(
        &mut h_reader,
        "adminspace read permit set to false over the wire",
        Duration::from_secs(10),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("the host never applied the admin-read revoke\n--- host ---\n{c}");
        }
    };
    let _ = after_revoke;
    let revoked = pico_get_output(&z_get, &format!("{root}/**"), &addr);
    assert!(
        !pico_replied_under(&revoked, &root),
        "a GET issued AFTER the wire revoked the permit must be denied; the handler \
         is still using a permit from before\n--- z_get ---\n{revoked}"
    );

    // ── RE-GRANT over the wire, then GET again ──
    pico_put(
        &z_put,
        &config_key_write(&root, "admin-read"),
        "true",
        &addr,
    );
    if let Err(c) = wait_for_substring(
        &mut h_reader,
        "adminspace read permit set to true over the wire",
        Duration::from_secs(10),
    ) {
        let _ = h_child.child_mut().kill();
        let _ = h_child.child_mut().wait();
        panic!("the host never applied the admin-read re-grant\n--- host ---\n{c}");
    }
    let regranted = pico_get_output(&z_get, &format!("{root}/**"), &addr);
    let _ = h_child.child_mut().kill();
    let _ = h_child.child_mut().wait();
    assert!(
        pico_replied_under(&regranted, &root),
        "the permit must come BACK; a gate that latches to deny locks an operator \
         out of their own node with no way back over the wire\n--- z_get ---\n{regranted}"
    );
}

/// R2374 (§5.23 `adminspace-write`) — THE WRITE GATE NOW GOVERNS THIS RUN-MODE: the
/// same PUT the test above uses is REFUSED on a host started without
/// `--config-write-permit`, and the read permit does not move.
///
/// ## The residual this closes
///
/// It is the one `adminspace-read`'s reason carried while saying "and it is not a
/// host": this host's config-WRITE subscriber passed a hardcoded `true` and
/// consulted no `admin_write_permit`, so `permissions.write` had one shipping
/// run-mode outside it. That clause was recorded under the READ atom because that is
/// where it was noticed, and the code it names is the write gate's.
///
/// ## The discriminator is the ABSENCE OF A CHANGE, made observable
///
/// Asserting only "no `set to false` line appeared" would pass against a host whose
/// PUT never arrived. So the GET afterwards is the real assertion: the host is still
/// SERVING, which is what the permit being unchanged looks like from outside. And
/// the host's own DENIED line is asserted, so a pass cannot come from a PUT that was
/// lost on the way.
// wz-proves: adminspace-write pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,adminspace-read,adminspace-write + zenoh-pico z_get/z_put CLIs); Layer E6i runs via --ignored"]
fn wz_storage_host_refuses_a_config_write_without_the_permit() {
    let demo = wz_ap_demo_binary();
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

    // NO `--config-write-permit`: default-DENY, which is zenoh's `PermissionsConf`.
    let mut h_child = ChildGuard::wrap(
        "wz-ap-demo storage host (--storage-host, no write permit)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );

    let h_captured = match wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("storage host never registered its admin host within 5s\n--- host ---\n{c}");
        }
    };
    assert!(
        h_captured.contains("adminspace write permit = false"),
        "absent --config-write-permit the write gate must DENY by default, the way \
         zenoh's PermissionsConf does\n--- host ---\n{h_captured}"
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

    pico_put(
        &z_put,
        &config_key_write(&root, "admin-read"),
        "false",
        &addr,
    );
    // The host's OWN refusal line, so a pass cannot come from a PUT that never
    // arrived. zenoh logs an error on a denied config write (`adminspace.rs:397`).
    if let Err(c) = wait_for_substring(&mut h_reader, "config-write on ", Duration::from_secs(10)) {
        let _ = h_child.child_mut().kill();
        let _ = h_child.child_mut().wait();
        panic!("the host never reported the denied config-write\n--- host ---\n{c}");
    }
    let h_log = read_captured(&mut h_reader);
    assert!(
        !h_log.contains("read permit set to"),
        "a REFUSED write must not move the read permit\n--- host ---\n{h_log}"
    );

    // And from outside: the host is still serving, which is what "the permit did not
    // move" looks like to a client.
    let after = pico_get_output(&z_get, &format!("{root}/**"), &addr);
    let _ = h_child.child_mut().kill();
    let _ = h_child.child_mut().wait();
    assert!(
        pico_replied_under(&after, &root),
        "the refused write must leave the read permit where it was\n--- z_get ---\n{after}"
    );
}

/// The `@/<zid>/<whatami>/config/<sub-key>` a config-WRITE PUT lands on, built from
/// the node root the host logged rather than re-derived here.
fn config_key_write(root: &str, subkey: &str) -> String {
    format!("{root}/config/{subkey}")
}
