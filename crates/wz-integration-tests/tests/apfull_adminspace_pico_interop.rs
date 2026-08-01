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
//! ## Named bound (what this does NOT prove)
//!
//! `adminspace-config-hotreload` and `adminspace-router-linkstate` are compiled
//! into this binary and are NOT claimed here. Hot-reload's demo run-mode is the
//! storage host, not `--peer`; linkstate's render lives inside `run_router_hat`,
//! a different run-mode from the `--peer` these legs drive. Compiling an atom in
//! is not exercising it, and a claim per compiled feature is how a proof axis
//! rots.

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
fn spawn_admin_host(
    extra: &[&str],
    subscribe: &str,
    role: &str,
) -> (ChildGuard, std::fs::File, String, String, String) {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;

    let mut cmd = Command::new(&demo);
    cmd.arg("--peer").arg(&addr).arg("--config-queryable");
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg("--subscribe")
        .arg(subscribe)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer));

    let mut child = ChildGuard::wrap(
        format!("wz-ap-demo AP-full admin host ({role})"),
        cmd.spawn().expect("spawn wz-ap-demo AP-full admin host"),
    );

    // THE BUILD CHECK RUNS FIRST, and that ordering is the whole point rather than
    // a detail. The demo emits this line ahead of every mode branch, so it is
    // readable in milliseconds; asserting it only in the registration wait's Err
    // arm would still report the right cause but would spend the full timeout per
    // leg to do it (MEASURED: 60s across the four legs, versus 0.1s here).
    let banner = match wait_for_substring(&mut reader, "BUILD FEATURES = [", Duration::from_secs(5))
    {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("the wz-ap-demo ({role}) never printed its BUILD FEATURES line within 5s, so which feature set this binary carries is unknown\n--- host ---\n{c}");
        }
    };
    assert_apfull_adminspace_was_built(&banner, role);

    let ready = wait_for_substring(
        &mut reader,
        &format!("declared subscriber {subscribe}"),
        Duration::from_secs(15),
    );
    let tail = match ready {
        Ok(c) => c,
        Err(c) => {
            let _ = child.child_mut().kill();
            let _ = child.child_mut().wait();
            panic!("the AP-full admin host ({role}) never finished registering within 15s\n--- host ---\n{banner}{c}");
        }
    };
    // The registration lines may land in EITHER capture (the banner read returns as
    // soon as its needle appears, which can be before or after them), so the scrape
    // below reads the union rather than assuming which.
    let captured = format!("{banner}{tail}");

    let config_key = captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .unwrap_or_else(|| {
            panic!("the AP-full admin host ({role}) never logged its admin config keyexpr\n--- host ---\n{captured}")
        });
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

/// Drive pico's `z_put` at the admin config leaf. pico ENCODES the write; wz
/// decodes it.
fn pico_put_acl_deny(root: &str, addr: &str, value: &str) {
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut child = ChildGuard::wrap(
        "z_put client (zenoh-pico)",
        Command::new(&z_put)
            .args([
                "-k",
                &format!("{root}/config/acl-deny"),
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
    assert!(
        out.contains(&format!("('{root}/metrics':")),
        "pico decoded no metrics leg at `{root}/metrics` — the AP-full binary \
         carries adminspace-metrics, so its absence means the composed host \
         dropped a leg\n--- z_get ---\n{out}"
    );
    assert!(
        out.contains("zenoh_build{version="),
        "the metrics leg carries the OpenMetrics zenoh_build gauge\n--- z_get ---\n{out}"
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

    pico_put_acl_deny(&root, &addr, "mesh/data");

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

    pico_put_acl_deny(&root, &addr, "mesh/data");

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
