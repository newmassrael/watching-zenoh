// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y489 — the ADMINSPACE plane COMPOSED, on the AP-full binary, witnessed by
//! a real zenoh-pico in both directions: `z_get` reads every admin leg wz serves
//! in ONE query, and `z_put` reconfigures the node and then OBSERVES its own write
//! through a second `z_get`.
//!
//! ## The gap this closes, and why it is composition rather than coverage
//!
//! Each §5.23 atom already had a pico witness — y270 for core + introspection,
//! y237 for plugins, y275 for metrics, y276 for the read gate, y51 for the write
//! gate. What none of them had, and could not have, is the atoms TOGETHER. Cargo
//! uplifts every feature variant of the same `--bin` to one path, so each of those
//! lanes builds a narrow feature set of its own, and they actively assert the
//! others are OFF: y270's test ends by asserting `.../metrics` is ABSENT from the
//! reply set, which is what makes ITS gate argument work and what makes it
//! structurally unable to also be the metrics witness.
//!
//! So the plane had six proofs of six parts and none of the whole. That is exactly
//! the question `preset-ap-full` exists to answer — the same one Layer E9 answers
//! for the transport/query plane and E11 for advanced pub/sub — and until this
//! round it could not be asked at all, because the preset OMITTED seven of the
//! eight adminspace atoms (see the R311y489 note in `crates/wz/Cargo.toml`).
//!
//! The omission was half-present, which is what made it incoherent rather than
//! merely partial: `routing-peer` has hard-pulled `adminspace-core` since the
//! preset existed, so an AP-full node already answered `@/<zid>/peer` with its
//! node record while every leg that makes that record worth querying — the
//! per-entity view, metrics, plugins, both permission gates, hot-reload — was
//! compiled out. A node that answers its own identity and nothing else is not an
//! admin space.
//!
//! ## THE BUILD DISCRIMINATOR (read this before diagnosing a failure here)
//!
//! `crates/target/debug/wz-ap-demo` is ONE path that many feature sets are written
//! over, and mistaking which one is present has already cost three misdiagnoses in
//! this tree (R311y482). Every leg below therefore asserts the demo's own
//! `BUILD FEATURES = [...]` line BEFORE it waits on any wire marker, so a wrong
//! binary fails in milliseconds naming the feature list rather than timing out and
//! reading like a wz defect.
//!
//! Since R311y489 that line is GENERATED from the manifest rather than hand-listed,
//! which is why these legs can assert `preset-ap-full` itself — the preset key is
//! in the report now, so "which binary is this" is answerable directly instead of
//! being inferred from which atoms happen to appear.
//!
//! ## What each leg binds to (the atoms' own cfg-gated code)
//!
//! - **`apfull_adminspace_plane_decoded_by_a_real_pico_z_get`** — `adminspace-core`
//!   (the `@/<zid>/peer` node record, keyed on the port THIS test reserved and on
//!   the live session list, which at GET time contains pico's own client session),
//!   `-introspection-handlers` (the per-entity `subscriber/demo/data` leg carrying
//!   the zenoh `Sources` body), `-metrics` (the OpenMetrics `zenoh_build` gauge),
//!   `-plugins-handlers` (the `plugins/storage_manager` record at `state=Loaded`).
//!   All four in one reply set from one process — the assertion y270 could not make.
//! - **`apfull_adminspace_read_gate_denies_every_leg_to_a_real_pico_z_get`** —
//!   `adminspace-read`. The SAME binary, `--no-admin-read`: pico receives only the
//!   terminating Final. This is what keeps leg 1 from being a "gates are ignored"
//!   pass: the four bodies leg 1 requires present are here required absent, from
//!   one build, decided by a runtime flag that resolves through the atom's
//!   `admin_read_permit` cfg site.
//! - **`apfull_adminspace_write_applied_and_observed_by_a_real_pico`** — the
//!   composition of the read and write hosts in ONE node, which no lane had: pico
//!   GETs `acl_deny:[]`, PUTs `acl-deny=mesh/data`, and GETs again to see its own
//!   write reflected as `acl_deny:["mesh/data"]` PLUS the expanded ingress/egress
//!   ACL rules. Every observation is made by the foreign decoder.
//! - **`apfull_adminspace_write_gate_refuses_an_unpermitted_pico_put`** —
//!   `adminspace-write`. Same topology WITHOUT `--config-write-permit`: pico's own
//!   follow-up GET still reads `acl_deny:[]`. Stricter than y51's witness, which
//!   reads wz's rejection out of wz's log; here the refusal is observed on the
//!   wire, by the implementation that attempted the write.
//!
//! The last two are a PAIR and neither is dropped: without the permit arm showing
//! the write CAN land through this exact path, the deny arm's "it did not land"
//! is equally consistent with the write plumbing being broken.
//!
//! ## R311y491 — the named bound is CLOSED, by driving the run-modes
//!
//! R311y489 shipped this file with `adminspace-config-hotreload` and
//! `-router-linkstate` listed as compiled-in but unclaimed, because both live in
//! run-modes the four legs above never enter: hot-reload's host is
//! `--storage-host`, and the linkstate render is inside `run_router_hat`. That
//! was an accurate bound and a poor stopping point — the gap was a run-mode not
//! being driven, so what closes it is driving the run-mode, not asserting harder
//! on `--peer`. Both are now legs, on the SAME AP-full binary and with no second
//! build (`routing-token-tables` already pulls `router-hat-router`):
//!
//! - **`apfull_router_hat_linkstate_decoded_by_a_real_pico_z_get`** —
//!   `adminspace-router-linkstate`. TWO AP-full `--router-hat` nodes, so the
//!   graph has an edge; pico decodes the routers-net render naming both live
//!   zids and a successor entry keyed on the second router as destination. One
//!   router would render a one-node graph and an empty table, which any build
//!   produces.
//! - **`apfull_storage_host_hotreload_state_flip_seen_by_a_real_pico`** —
//!   `adminspace-config-hotreload`. pico reads `storage_manager` `Loaded`, PUTs
//!   a storage-add, reads `Started`, PUTs a storage-del, reads `Loaded` again.
//!   A single reading could be a constant; the round trip in BOTH directions
//!   cannot, and every observation is the foreign decoder's.
//!
//! What is still not claimed here is the rest of §5.22 — the `plugin-*` family
//! (dynamic loading, ABI compat, lifecycle) is neither in this preset nor
//! implemented as a dlopen manager; `storage_manager` is a compiled-in
//! subsystem. That bound is real and is not closed by these legs.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// Fail NOW, naming the feature list, if the binary at the shared demo path is not
/// the AP-full one this file needs.
///
/// Reads the demo's OWN report rather than trusting the cargo invocation, which
/// lives in a shell script one directory away and writes a path other feature sets
/// also write to. `preset-ap-full` is asserted directly because R311y489 made the
/// report manifest-generated, so the preset key appears in it; the adminspace keys
/// are asserted beside it so a future preset that dropped the plane fails here
/// rather than at a wire marker.
fn assert_apfull_adminspace_was_built(captured: &str, role: &str) {
    let line = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_else(|| {
            panic!(
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line, so \
                 which feature set this binary carries is unknown and no assertion \
                 below means anything\n--- captured ---\n{captured}"
            )
        });
    for needed in [
        "preset-ap-full",
        "adminspace-metrics",
        "adminspace-plugins-handlers",
        "adminspace-introspection-handlers",
        "adminspace-read",
        "adminspace-write",
        // R311y491 — the two the preset carried but no leg reached until the
        // router-hat and storage-host legs below. Required by EVERY leg, not just
        // theirs: the claim this file makes is that the preset carries the whole
        // plane, so a build missing either is the wrong binary for any of them.
        "adminspace-config-hotreload",
        "adminspace-router-linkstate",
    ] {
        assert!(
            line.contains(&format!(" {needed} ")) || line.contains(&format!("[{needed} ")),
            "the wz-ap-demo ({role}) was built WITHOUT `{needed}`, so the admin leg \
             this file asserts on is compiled out. Build it with \
             `--no-default-features --features preset-ap-full` from a tree that \
             carries the R311y489 preset change.\n{line}"
        );
    }
}

/// Spawn an AP-full `--peer` admin host and return it once every admin
/// registration it will make has been logged.
///
/// The returned `root` is the node's admin root (`@/<zid>/<whatami>`), scraped at
/// runtime — every assertion in this file is keyed on it and on the reserved port,
/// so no leg can pass against a static fixture.
///
/// The barrier is `declared subscriber <ke>`, and that choice is load-bearing
/// rather than incidental: the host logs `read permit` -> `config GET` ->
/// `config WRITE` -> `declared subscriber` in that order, so the LAST of them
/// proves all the earlier registrations completed. Waiting on the subscriber also
/// means the same app-tick has re-snapshotted the introspection buffer, so a query
/// arriving after this point finds the subscriber in the admin view — the fixture
/// owns its precondition instead of sleeping past it.
/// Spawn the AP-full demo with `args`, assert its build BEFORE any wire wait,
/// then return it once `ready` has been logged, together with the union of both
/// captures.
///
/// THE BUILD CHECK RUNS FIRST, and that ordering is the whole point rather than a
/// detail. The demo emits its banner ahead of every mode branch, so it is
/// readable in milliseconds; asserting it only in the readiness wait's `Err` arm
/// would still report the right cause but would spend the full timeout per leg to
/// do it (MEASURED: 60s across four legs, versus 0.1s here).
///
/// The two captures are CONCATENATED because the banner read returns the instant
/// its needle appears, which can be before or after the lines a caller wants to
/// scrape — so the caller reads the union rather than guessing which.
fn spawn_apfull(args: &[&str], ready: &str, role: &str) -> (ChildGuard, std::fs::File, String) {
    let stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let writer = stderr.try_clone().expect("dup demo stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(wz_ap_demo_binary());
    for a in args {
        cmd.arg(a);
    }
    cmd.env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer));

    let mut child = ChildGuard::wrap(
        format!("wz-ap-demo AP-full ({role})"),
        cmd.spawn().expect("spawn wz-ap-demo AP-full"),
    );

    let banner = match wait_for_substring(&mut reader, "BUILD FEATURES = [", Duration::from_secs(5))
    {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("the wz-ap-demo ({role}) never printed its BUILD FEATURES line within 5s, so which feature set this binary carries is unknown\n--- {role} ---\n{c}");
        }
    };
    assert_apfull_adminspace_was_built(&banner, role);

    let tail = match wait_for_substring(&mut reader, ready, Duration::from_secs(15)) {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("the AP-full demo ({role}) never logged `{ready}` within 15s\n--- {role} ---\n{banner}{c}");
        }
    };
    (child, reader, format!("{banner}{tail}"))
}

/// Scrape `needle`'s value off a captured log line.
fn scrape(captured: &str, needle: &str, role: &str) -> String {
    captured
        .lines()
        .find_map(|l| {
            l.split_once(needle)
                .map(|(_, rest)| rest.trim().to_string())
        })
        .unwrap_or_else(|| {
            panic!("the AP-full demo ({role}) never logged `{needle}`\n--- {role} ---\n{captured}")
        })
}

fn spawn_admin_host(
    extra: &[&str],
    subscribe: &str,
    role: &str,
) -> (ChildGuard, std::fs::File, String, String, String) {
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let mut args: Vec<&str> = vec!["--peer", &addr, "--config-queryable"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--subscribe", subscribe]);

    let ready = format!("declared subscriber {subscribe}");
    let (child, reader, captured) = spawn_apfull(&args, &ready, role);

    let config_key = scrape(&captured, "adminspace config GET at ", role);
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    let zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/<whatami>");

    drop(port_res);
    (child, reader, root, zid, addr)
}

/// Run pico's `z_get` on `keyexpr` against `addr` and return its transcript,
/// captured up to the terminating Final.
///
/// `stdbuf -oL` is not optional: pico's CLI block-buffers a non-TTY stdout, so
/// without it the `Received` lines sit in libc's buffer until exit and a delivered
/// reply reads as a missing one. Waiting on the Final rather than on a reply means
/// a MISSING reply fails the caller's assertion with a full transcript instead of
/// timing out with no diagnosis.
fn pico_get(keyexpr: &str, addr: &str) -> Result<String, String> {
    let z_get = zenoh_pico_cli_binary("z_get");
    let stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let writer = stdout.try_clone().expect("dup z_get stdout handle");
    let mut reader = stdout;

    let mut child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-k", keyexpr, "-e", &format!("tcp/{addr}"), "-m", "client"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    let done = wait_for_substring(
        &mut reader,
        "Received query final notification",
        Duration::from_secs(15),
    );
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    done
}

/// Drive pico's `z_put` at an admin config leaf. pico ENCODES the write; wz
/// decodes it.
fn pico_put_key(key: &str, value: &str, addr: &str) {
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(&z_put)
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

/// The BODY pico decoded for `key`, which is NOT the header line.
///
/// pico prints one reply as `>> Received PUT ('<key>': '<body>')`, and two of the
/// bodies this file reads are MULTI-LINE — the OpenMetrics text and the routers
/// linkstate DOT. A `lines().find(...)` therefore sees only `graph {` and an
/// assertion scoped to it fails against a perfectly correct render, which is
/// exactly how the first draft of the linkstate leg failed. The body runs from
/// the header to pico's next `>> ` line, so that is the slice returned.
fn reply_body(transcript: &str, key: &str, when: &str) -> String {
    let marker = format!("('{key}': ");
    let start = transcript.find(&marker).unwrap_or_else(|| {
        panic!("pico decoded no reply at `{key}` {when}\n--- z_get ---\n{transcript}")
    });
    let rest = &transcript[start + marker.len()..];
    let end = rest.find("\n>> ").unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Pull the `acl_deny` array out of the admin `config` body pico decoded.
///
/// Returned as the raw slice rather than parsed, so the assertion messages show
/// exactly what the foreign decoder read off the wire.
fn acl_deny_of(transcript: &str, root: &str) -> String {
    let line = transcript
        .lines()
        .find(|l| l.contains(&format!("('{root}/config':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no admin `config` body at `{root}/config`\n--- z_get ---\n{transcript}")
        });
    let start = line.find(r#""acl_deny":["#).unwrap_or_else(|| {
        panic!("the admin config body carries no acl_deny field\n  got: {line}")
    });
    let rest = &line[start..];
    let end = rest
        .find(']')
        .unwrap_or_else(|| panic!("acl_deny is unterminated\n  got: {line}"));
    rest[..=end].to_string()
}

// wz-proves: adminspace-core wz->pico
// wz-proves: adminspace-introspection-handlers wz->pico
// wz-proves: adminspace-metrics wz->pico
// PARTIAL, and the grading is measured rather than inherited. The atom has three
// surfaces in its `F=`: the `plugins/**` legs, the `status/plugins/**` legs, and
// the `plugins` field of the `local_data` node record. This leg witnesses only the
// first, exactly as R311y237's narrower test does — and for the same faithful
// reason, re-measured here on the AP-full binary: `storage_manager` is compiled in
// and therefore `Loaded`, but nothing STARTS it (no storage is configured), so the
// status legs reply nothing and the node record carries `"plugins":{}`. Dropping
// the `partial` here would have moved the A4 count 106/38/16 -> 107/37/16 on a
// witness that covers no more surface than the claim it sits beside.
// wz-proves: adminspace-plugins-handlers wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get CLI); Layer E12 runs via --ignored"]
fn apfull_adminspace_plane_decoded_by_a_real_pico_z_get() {
    let (mut host, mut host_log, root, zid, addr) = spawn_admin_host(&[], "demo/data", "read");

    let out = pico_get(&format!("{root}/**"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    // ── adminspace-core — the node record ───────────────────────────
    //
    // Keyed at the bare root. The locator is the port THIS test reserved and the
    // session list is the live one, so neither can be satisfied by a static echo.
    let core = out
        .lines()
        .find(|l| l.contains(&format!("('{root}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no adminspace-core node record at `{root}`\n--- z_get ---\n{out}")
        });
    assert!(
        core.contains(&format!(r#""zid":"{zid}""#))
            && core.contains(&format!(r#""locators":["tcp/{addr}"]"#)),
        "the node record carries this host's live zid AND its ACTUAL bound locator\n  got: {core}"
    );
    assert!(
        core.contains(r#""whatami":"client""#),
        "the node record's `sessions` names the FOREIGN pico session that is asking \
         — the record is rendered from live state, not from configuration\n  got: {core}"
    );

    // ── adminspace-introspection-handlers — the per-entity view ─────
    let sub_key = format!("{root}/subscriber/demo/data");
    let sub = out
        .lines()
        .find(|l| l.contains(&format!("('{sub_key}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no per-entity subscriber leg at `{sub_key}`\n--- z_get ---\n{out}")
        });
    assert!(
        sub.contains(&format!(
            r#"{{"routers":[],"peers":["{zid}"],"clients":[]}}"#
        )),
        "the subscriber leg carries the zenoh Sources body naming this host as the \
         source peer\n  got: {sub}"
    );

    // ── adminspace-metrics — THE COMPOSITION DELTA ──────────────────
    //
    // y270's witness ends by asserting this leg is ABSENT, which is what makes its
    // own cfg-gate argument work. Requiring it PRESENT here, from one process that
    // also served the two legs above, is the claim no existing lane can make. The
    // body spans several lines (OpenMetrics is newline-delimited), so the gauge is
    // matched against the whole transcript rather than the header line.
    let metrics = reply_body(&out, &format!("{root}/metrics"), "in the composed GET");
    assert!(
        metrics.contains("zenoh_build{version="),
        "the metrics leg carries the OpenMetrics zenoh_build gauge — scoped to that \
         leg's own BODY, not to the transcript, so another leg cannot satisfy it\n  got: {metrics}"
    );

    // ── adminspace-plugins-handlers — the compiled-in registry ──────
    let plugins_key = format!("{root}/plugins/storage_manager");
    let plugins = out
        .lines()
        .find(|l| l.contains(&format!("('{plugins_key}':")))
        .unwrap_or_else(|| {
            panic!("pico decoded no plugins leg at `{plugins_key}` — the AP-full binary carries storage-backend, so storage_manager must be reported\n--- z_get ---\n{out}")
        });
    assert!(
        plugins.contains(r#""state":"Loaded""#) && plugins.contains(r#""path":"__static__""#),
        "the plugins leg reports the statically compiled storage_manager as Loaded\n  got: {plugins}"
    );
}

// wz-proves: adminspace-read wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get CLI); Layer E12 runs via --ignored"]
fn apfull_adminspace_read_gate_denies_every_leg_to_a_real_pico_z_get() {
    let (mut host, mut host_log, root, _zid, addr) =
        spawn_admin_host(&["--no-admin-read"], "demo/data", "read-deny");

    // The gate's own resolution, from the host that resolved it — so a pass proves
    // the read was DENIED rather than that some unrelated path stayed quiet.
    let permit = read_captured(&mut host_log);
    assert!(
        permit.contains("adminspace read permit = false"),
        "the AP-full host must resolve `permissions.read` to false under \
         --no-admin-read\n--- host ---\n{permit}"
    );

    let out = pico_get(&format!("{root}/**"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    // Not a wait-for-absence: the transcript above is captured up to pico's
    // POSITIVE terminating edge, so the round-trip provably completed. Every leg
    // the first test requires PRESENT is required absent here, from the same build.
    for suppressed in [
        root.clone(),
        format!("{root}/config"),
        format!("{root}/metrics"),
        format!("{root}/subscriber/demo/data"),
        format!("{root}/plugins/storage_manager"),
    ] {
        assert!(
            !out.contains(&format!("('{suppressed}':")),
            "the read gate must suppress EVERY admin leg, but pico decoded \
             `{suppressed}`\n--- z_get ---\n{out}"
        );
    }
}

// wz-proves: none -- the GRANT arm, and it claims no atom for the reason R311y51's
// own grant arm does not: an un-gated write path applies anyway, so this leg passes
// with adminspace-write compiled OUT. What it adds over that precedent is the
// COMPOSITION (one AP-full node hosting the read and write admin hosts at once,
// with the foreign client reading back its own write), which is a property of the
// preset rather than of any single atom. It is also not a config-mutate-runtime
// witness: the body pico reads back is the STORED WzConfig rendered to JSON, and
// reconfigure_interceptors stores unconditionally -- only the sink re-drive is
// cfg-gated, and nothing here observes the re-drive.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get/z_put CLI); Layer E12 runs via --ignored"]
fn apfull_adminspace_write_applied_and_observed_by_a_real_pico() {
    let (mut host, mut host_log, root, _zid, addr) = spawn_admin_host(
        &["--config-writable", "--config-write-permit"],
        "mesh/data",
        "write-permit",
    );

    let before = pico_get(&format!("{root}/config"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (before) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    assert_eq!(
        acl_deny_of(&before, &root),
        r#""acl_deny":[]"#,
        "the host starts with an empty deny list, so the second GET's content is \
         attributable to pico's write and not to a preloaded config"
    );

    pico_put_key(&format!("{root}/config/acl-deny"), "mesh/data", &addr);

    // The host's own apply edge — the barrier that makes the second GET's timing
    // owned rather than slept.
    let applied = wait_for_substring(
        &mut host_log,
        "config reconfigured — now denying mesh/data",
        Duration::from_secs(15),
    );
    if let Err(c) = applied {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("the AP-full host never applied pico's config write within 15s\n--- host ---\n{c}");
    }

    let after = pico_get(&format!("{root}/config"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (after) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    // THE COMPOSITION CLAIM: the foreign implementation reads back its own write.
    assert_eq!(
        acl_deny_of(&after, &root),
        r#""acl_deny":["mesh/data"]"#,
        "pico must read back the deny entry IT wrote — read and write hosted by \
         one AP-full node\n--- z_get ---\n{after}"
    );
    // And the write reached the ACL model, not merely the deny list it was spelled
    // in: the stored entry expands to the ingress/egress rule pair.
    let config_line = after
        .lines()
        .find(|l| l.contains(&format!("('{root}/config':")))
        .expect("the config body was located by acl_deny_of above");
    assert!(
        config_line.contains(r#""flow":"ingress""#)
            && config_line.contains(r#""flow":"egress""#)
            && config_line.contains(r#""permission":"deny""#),
        "the written deny entry expands into the ingress+egress ACL rule pair\n  got: {config_line}"
    );
}

// wz-proves: adminspace-write pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get/z_put CLI); Layer E12 runs via --ignored"]
fn apfull_adminspace_write_gate_refuses_an_unpermitted_pico_put() {
    // Same topology as the permit arm MINUS --config-write-permit. The pair is what
    // makes this leg mean anything: alone, "the write did not land" is equally
    // consistent with the write path being broken.
    let (mut host, mut host_log, root, _zid, addr) =
        spawn_admin_host(&["--config-writable"], "mesh/data", "write-deny");

    let before = pico_get(&format!("{root}/config"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (before) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    assert_eq!(acl_deny_of(&before, &root), r#""acl_deny":[]"#);

    pico_put_key(&format!("{root}/config/acl-deny"), "mesh/data", &addr);

    // POSITIVE edge: the gate's OWN rejection, naming the key pico addressed, so
    // the follow-up GET is sequenced against the refusal rather than a sleep.
    let denied = wait_for_substring(
        &mut host_log,
        "config-write DENIED (adminspace.permissions.write=false",
        Duration::from_secs(15),
    );
    let host_out = match denied {
        Ok(c) => c,
        Err(c) => {
            let _ = host.child_mut().kill();
            let _ = host.child_mut().wait();
            panic!("the permissions.write gate never fired on pico's Put within 15s\n--- host ---\n{c}");
        }
    };
    assert!(
        host_out.contains(&format!("ignored {root}/config/acl-deny")),
        "the rejection names the exact key pico's z_put addressed\n--- host ---\n{host_out}"
    );

    let after = pico_get(&format!("{root}/config"), &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (after) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();

    // Observed ON THE WIRE by the implementation that attempted the write — a
    // stricter witness than reading wz's refusal out of wz's own log.
    assert_eq!(
        acl_deny_of(&after, &root),
        r#""acl_deny":[]"#,
        "an un-permitted write must not be visible to the foreign client that \
         attempted it\n--- z_get ---\n{after}"
    );
}

// wz-proves: adminspace-router-linkstate wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get CLI); Layer E12 runs via --ignored"]
fn apfull_router_hat_linkstate_decoded_by_a_real_pico_z_get() {
    // R311y491 — the atom the R311y489 "Named bound" listed as compiled-in but
    // unexercised. Its render lives inside `run_router_hat`, a DIFFERENT run-mode
    // from the `--peer` the other legs drive, so no amount of `--peer` traffic
    // reaches it; what closes the gap is driving the run-mode, not asserting
    // harder. The AP-full binary already carries it — `routing-token-tables`
    // pulls `router-hat-router` — so this needs no second build.
    let (mut r1, mut r1_log, r1_cap) = spawn_apfull(
        &["--router-hat", "127.0.0.1:0", "--config-queryable"],
        "adminspace router legs hosted at ",
        "router-hat R1",
    );
    let r1_addr = format!(
        "127.0.0.1:{}",
        scrape(
            &r1_cap,
            "router-hat: listening on 127.0.0.1:",
            "router-hat R1"
        )
        .trim_end_matches(';')
        .split(';')
        .next()
        .expect("the listening line carries a port")
    );
    let root = scrape(
        &r1_cap,
        "adminspace router legs hosted at ",
        "router-hat R1",
    )
    .split_whitespace()
    .next()
    .and_then(|k| k.strip_suffix("/**"))
    .expect("the router admin root ends /**")
    .to_string();
    let r1_zid = root
        .strip_prefix("@/")
        .and_then(|r| r.split_once('/'))
        .map(|(z, _)| z.to_string())
        .expect("admin root is @/<zid>/router");

    // A SECOND router, so the linkstate graph has an edge and the successor table
    // is non-empty. One router renders a one-node DOT and an empty table, which
    // every build produces — the leg would pass on a node that computes nothing.
    let (mut r2, mut r2_log, r2_cap) = spawn_apfull(
        &["--router-hat", "127.0.0.1:0", "--connect", &r1_addr],
        "adminspace router legs hosted at ",
        "router-hat R2",
    );
    let r2_zid = scrape(
        &r2_cap,
        "adminspace router legs hosted at ",
        "router-hat R2",
    )
    .split_whitespace()
    .next()
    .and_then(|k| k.strip_suffix("/**"))
    .and_then(|r| r.strip_prefix("@/"))
    .and_then(|r| r.split_once('/'))
    .map(|(z, _)| z.to_string())
    .expect("R2 admin root is @/<zid>/router");

    // BARRIER, not a sleep: R1's own convergence edge. Asserted on R1's log rather
    // than on a zid string match, because wz logs faces in raw little-endian zid
    // bytes while the admin space renders zenoh-hex (byte-reversed), so `r2_zid`
    // never appears verbatim in R1's face log.
    if let Err(c) = wait_for_substring(
        &mut r1_log,
        "routers-net converged (2 node(s))",
        Duration::from_secs(15),
    ) {
        let _ = r1.child_mut().kill();
        let _ = r2.child_mut().kill();
        panic!("R1's routers net never converged to 2 nodes within 15s\n--- R1 ---\n{c}");
    }

    let out = pico_get(&format!("{root}/**"), &r1_addr).unwrap_or_else(|c| {
        let a = read_captured(&mut r1_log);
        let b = read_captured(&mut r2_log);
        panic!("pico z_get never saw the terminating Final within 15s\n--- z_get ---\n{c}\n--- R1 ---\n{a}\n--- R2 ---\n{b}")
    });
    let _ = r1.child_mut().kill();
    let _ = r1.child_mut().wait();
    let _ = r2.child_mut().kill();
    let _ = r2.child_mut().wait();

    // The routers-net DOT, naming BOTH live zids — runtime values, so no static
    // fixture satisfies it.
    let linkstate = reply_body(
        &out,
        &format!("{root}/linkstate/routers"),
        "in the router GET",
    );
    assert!(
        linkstate.contains(&r1_zid) && linkstate.contains(&r2_zid),
        "the routers-net render names both live routers — a one-node graph would \
         mean the second never entered it\n  got: {linkstate}"
    );

    // And the computed successor table, keyed on R2 as a destination.
    assert!(
        out.lines()
            .any(|l| l.contains(&format!("('{root}/route/successor/"))
                && l.contains(&format!("/dst/{r2_zid}"))),
        "the successor table carries a route whose destination is R2 — the graph \
         is computed over, not merely rendered\n--- z_get ---\n{out}"
    );
}

// wz-proves: adminspace-config-hotreload wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_get/z_put CLI); Layer E12 runs via --ignored"]
fn apfull_storage_host_hotreload_state_flip_seen_by_a_real_pico() {
    // R311y491 — the OTHER atom the R311y489 "Named bound" listed. Like the
    // router-hat leg above it is a run-mode gap, not a coverage one: the
    // hot-reload host is `--storage-host`, which `--peer` never becomes.
    //
    // The witness is a STATE FLIP the foreign client observes twice, in opposite
    // directions: pico reads storage_manager `Loaded`, PUTs a storage-add, reads
    // `Started`, PUTs a storage-del, reads `Loaded` again. A single reading could
    // be a constant; the round trip cannot.
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());
    let (mut host, mut host_log, captured) = spawn_apfull(
        &["--storage-host", &addr],
        "adminspace config GET at ",
        "storage-host",
    );
    let root = scrape(&captured, "adminspace config GET at ", "storage-host")
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    drop(port_res);

    let plugins_key = format!("{root}/plugins/storage_manager");
    let state_of = |transcript: &str, when: &str| -> String {
        let line = transcript
            .lines()
            .find(|l| l.contains(&format!("('{plugins_key}':")))
            .unwrap_or_else(|| {
                panic!("pico decoded no plugins leg at `{plugins_key}` {when}\n--- z_get ---\n{transcript}")
            });
        let at = line.find(r#""state":""#).unwrap_or_else(|| {
            panic!("the plugins record carries no state field {when}\n  got: {line}")
        });
        let rest = &line[at + r#""state":""#.len()..];
        rest[..rest.find('"').expect("state is quoted")].to_string()
    };

    let before = pico_get(&plugins_key, &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (before) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    assert_eq!(
        state_of(&before, "before storage-add"),
        "Loaded",
        "the subsystem starts compiled-but-not-live, so the flip below is \
         attributable to pico's write"
    );

    pico_put_key(&format!("{root}/config/storage-add"), "demo:demo/**", &addr);
    if let Err(c) = wait_for_substring(
        &mut host_log,
        "spawned live storage 'demo' — storage_manager Started",
        Duration::from_secs(15),
    ) {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("the AP-full storage host never applied pico's storage-add within 15s\n--- host ---\n{c}");
    }

    let added = pico_get(&plugins_key, &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (after add) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    assert_eq!(
        state_of(&added, "after storage-add"),
        "Started",
        "the foreign client must observe the subsystem go live on its own write"
    );

    pico_put_key(&format!("{root}/config/storage-del"), "demo", &addr);
    if let Err(c) = wait_for_substring(
        &mut host_log,
        "despawned 'demo' — storage_manager Loaded",
        Duration::from_secs(15),
    ) {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait();
        panic!("the AP-full storage host never applied pico's storage-del within 15s\n--- host ---\n{c}");
    }

    let removed = pico_get(&plugins_key, &addr).unwrap_or_else(|c| {
        let h = read_captured(&mut host_log);
        panic!("pico z_get (after del) never saw the terminating Final\n--- z_get ---\n{c}\n--- host ---\n{h}")
    });
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait();
    assert_eq!(
        state_of(&removed, "after storage-del"),
        "Loaded",
        "and back down again — the state TRACKS the config rather than latching"
    );
}
