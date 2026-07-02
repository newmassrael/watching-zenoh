// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y48 (§5.23 Phase 3b) — a remote PUT to a routing peer's config-WRITE
//! subscriber RECONFIGURES its live forwarder over the wire: the ACL verdict
//! FLIPS from admit to drop.
//!
//! This is the §5.23 adminspace-WRITE payoff and the close of the R311y45
//! read-at-open caveat: y45 proved the config GET reads the forwarder-bound
//! WzConfig but the served fields were handshake-fixed, so a GET could not
//! OBSERVE a runtime change. Here a remote PUT DRIVES a runtime change and the
//! data plane WITNESSES it — reconfigure becomes wire-OBSERVABLE.
//!
//! Topology (both the `--features routing-peer` binary, ephemeral ports read back
//! from each peer's listen log):
//!   - peer A: `--peer 127.0.0.1:0 --subscribe mesh/data --config-writable` — the
//!     SUBSCRIBER + config-write HOST. A declares interest in `mesh/data` (so B
//!     forwards it here) AND hosts a config-write subscriber on
//!     `@/<A_zid>/peer/config/**` (R311y46 Push-plane self-dispatch).
//!   - peer B: `--peer 127.0.0.1:0 --connect <A> --publish mesh/data
//!     --put-key <A_config_write_key> --put-payload mesh/data` — dials A, PUBLISHES
//!     `mesh/data` each tick AND PUTs A's `.../config/acl-deny` carrying the
//!     keyexpr to deny (`mesh/data`).
//!
//! Flow: A admits B's `mesh/data` (`received mesh data` rises) until B's
//! config-write PUT routes to A; A's handler stashes the deny keyexpr and A's
//! app-tick reconfigures the LIVE forwarder (the Phase-1 `InterceptorSink` drive,
//! `config reconfigured — now denying mesh/data`); the next `mesh/data` from B is
//! then DENIED at A's ingress ACL (`interceptor dropped` rises). "Forwarded, then
//! DROPPED" — the live verdict flipped because of a PUT over real TCP.
//!
//! The witnesses are DETERMINISTIC positive edges (never a flaky wait-for-absence):
//! A's `config reconfigured` (the PUT was received + applied) and A's `interceptor
//! dropped` (a live message was dropped by the new ACL) — both emitted in-run AND,
//! state-derived, at A's shutdown summary, so the PASS gate is the post-shutdown
//! capture, not a racy in-run log.
//!
//! Requires the binary built with `--features routing-peer` (which pulls
//! `wz/config-mutate-runtime` so the reconfigure actually re-drives the forwarder;
//! without it the write would store but never apply). run-ci's Layer E6 builds it,
//! so this rides the same `--ignored` lane as the other binary-dep e2es.
//!
//! R311y51 — Layer E6 now builds the binary with `adminspace-write` too, so the
//! `permissions.write` GATE (default-deny, zenoh `PermissionsConf` write:false) is
//! compiled in. The two APPLY tests above grant it with `--config-write-permit`;
//! [`wz_peer_config_write_denied_without_permit_holds_the_verdict`] omits it to
//! witness the gate REJECTING a write (the live verdict does NOT flip) — the
//! negative twin proving the permit is the control.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard,
};

/// The data keyexpr B publishes and (via the config-write PUT) A is told to deny.
const DATA_KEY: &str = "mesh/data";

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Returns the guard, its stderr reader,
/// and the captured-so-far log (the caller may scrape more markers from it).
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16, String) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
             --features routing-peer?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port, captured)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_config_write_acl_deny_flips_the_live_verdict_over_the_wire() {
    // A (the SUBSCRIBER + config-write host) binds first so B can dial it. A logs
    // `adminspace config WRITE at @/<zid>/peer/config/**` once registered — scrape
    // the exact key so B can PUT A's `.../config/acl-deny` without deriving A's
    // port-derived zid.
    let (mut a_guard, mut a_reader, p_a, a_listen_log) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            DATA_KEY,
            "--config-writable",
            // R311y51 — the E6 binary is built with `adminspace-write`, so the
            // permissions.write gate is default-deny; GRANT it here (this test
            // proves the APPLY path). The deny path is the dedicated test below.
            "--config-write-permit",
        ],
    );
    let addr_a = format!("127.0.0.1:{p_a}");

    // The listen-log capture may already carry the WRITE-at line; otherwise read on
    // until it appears.
    let write_log = if a_listen_log.contains("adminspace config WRITE at ") {
        a_listen_log
    } else {
        wait_for_substring(
            &mut a_reader,
            "adminspace config WRITE at ",
            Duration::from_secs(5),
        )
        .unwrap_or_else(|c| {
            let _ = a_guard.child_mut().kill();
            let _ = a_guard.child_mut().wait();
            panic!(
                "peer-A did not log 'adminspace config WRITE at' within 5s — the \
                 --config-writable subscriber did not register.\n\
                 --- peer-A stderr ---\n{c}"
            );
        })
    };
    // `@/<zid>/peer/config/**` -> the PUT target `@/<zid>/peer/config/acl-deny`.
    let write_key = write_log
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer-A logged the admin config-write keyexpr");
    let config_base = write_key
        .strip_suffix("/**")
        .unwrap_or_else(|| panic!("config-write key lacks the /** pattern suffix: {write_key}"));
    assert!(
        config_base.starts_with("@/") && config_base.ends_with("/peer/config"),
        "scraped config-write base has the @/<zid>/peer/config shape: {config_base}"
    );
    let put_key = format!("{config_base}/acl-deny");

    // B (the PUBLISHER + config WRITER): dials A, publishes mesh/data each tick AND
    // PUTs A's `.../config/acl-deny` carrying `mesh/data` (the keyexpr to deny).
    let (mut b_guard, mut b_reader, _p_b, _b_listen_log) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_a,
            "--publish",
            DATA_KEY,
            "--put-key",
            &put_key,
            "--put-payload",
            DATA_KEY,
        ],
    );

    // Primary sync: wait until A has DROPPED a message — the terminal proof the
    // runtime reconfigure flipped the live verdict. The demo logs `interceptor
    // dropped` in-run on the first rise AND, state-derived, at shutdown; this wait
    // only lets the whole lifecycle run (interest converge, data admit, config-write
    // route + reconfigure, deny). The PASS gate is the post-shutdown capture below.
    let dropped_sync = wait_for_substring(
        &mut a_reader,
        "interceptor dropped",
        Duration::from_secs(20),
    );

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");

    // Diagnostics printed; now assert against the DETERMINISTIC post-shutdown state.
    dropped_sync.unwrap_or_else(|c| {
        panic!(
            "peer-A never logged 'interceptor dropped' within 20s — the remote \
             config-write PUT did not reconfigure A's forwarder to deny {DATA_KEY} \
             (the live verdict did not flip).\n--- peer-A stderr at deadline ---\n{c}\n\
             --- peer-B stderr ---\n{b_captured}"
        )
    });

    // (1) The config-write PUT was RECEIVED and APPLIED: A reconfigured its live
    // forwarder to deny the keyexpr carried in the PUT payload. The headline — a
    // remote PUT drove a runtime config change over the wire.
    assert!(
        a_captured.contains(&format!("config reconfigured — now denying {DATA_KEY}")),
        "peer-A never logged the config reconfigure — the remote PUT to {put_key} did \
         not reach A's config-write handler and drive reconfigure_interceptors.\n\
         --- peer-A stderr ---\n{a_captured}"
    );

    // (2) The new ACL DROPPED a live message: the verdict flipped from admit to
    // drop on the data plane. A deterministic positive edge (the demo logs this
    // only when interceptor_dropped > 0).
    assert!(
        a_captured.contains("interceptor dropped"),
        "peer-A's forwarder dropped nothing — the reconfigure did not take effect on \
         the LIVE forwarder (config-mutate-runtime not driving?).\n\
         --- peer-A stderr ---\n{a_captured}"
    );

    // (3) "Forwarded, THEN dropped": A admitted B's mesh/data at some point. The
    // deny denies ALL mesh/data, so any admission (a non-zero `received mesh data`)
    // necessarily PRECEDED the deny taking effect — after the deny, mesh/data is
    // dropped, not received. A drop alone would not prove a FLIP (A could have
    // denied from the start); a drop PLUS a prior admission does.
    assert!(
        a_captured.contains("received mesh data"),
        "peer-A never admitted any mesh/data — cannot prove the verdict FLIPPED \
         (admit -> drop) rather than denying from the start.\n\
         --- peer-A stderr ---\n{a_captured}"
    );

    // Causal order (RELIABLE, not log-cadence-sensitive): the reconfigure logs
    // BEFORE the first drop, because a drop can only happen AFTER the new deny ACL
    // is installed (which IS the reconfigure). This is the "PUT -> reconfigure ->
    // deny" chain in order. (We do NOT assert received-before-reconfigure: the
    // `received mesh data (N)` log is emitted on the 250 ms app-tick and can lag the
    // actual ingest past the reconfigure log — a logging-cadence artifact, not a
    // semantic one. The admission itself is proven by (3); its timing relative to
    // the deny is proven by the deny dropping all mesh/data thereafter.)
    let reconfig_at = a_captured
        .find("config reconfigured")
        .expect("reconfigure substring present (asserted above)");
    let dropped_at = a_captured
        .find("interceptor dropped")
        .expect("interceptor-dropped substring present (asserted above)");
    assert!(
        reconfig_at < dropped_at,
        "peer-A dropped a message before it reconfigured — the drop must FOLLOW the \
         config-write deny install (PUT -> reconfigure -> deny).\n\
         --- peer-A stderr ---\n{a_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_config_write_acl_deny_is_get_observable_over_the_wire() {
    // R311y50 — the READ-path twin of the test above: a remote PUT reconfigures A's
    // ACL, and a remote GET of A's `@/<A>/peer/config` then OBSERVES the new
    // `acl_deny` over the wire (the y49 GET-observable claim, end-to-end rather than
    // by composition). A hosts BOTH surfaces off ONE shared WzConfig, so this also
    // proves the §5.23 combined node directly — closing the y42 two-instance gap
    // against any future Rc-decoupling regression.
    //
    // Topology: A (peer, `--config-queryable --config-writable`) hosts the config
    // GET + the config-write subscriber. B (peer, `--connect A`) PUTs A's
    // `config/acl-deny=mesh/data`. C (connect client) GETs A's config AFTER A has
    // reconfigured. Deterministic: C is spawned only once A logs `config
    // reconfigured`, so C's single GET sees the post-reconfigure state; the FLIP is
    // witnessed against A's startup `acl_deny:[]` baseline.

    let (mut a_guard, mut a_reader, p_a, _a_listen_log) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--config-queryable",
            "--config-writable",
            // R311y51 — grant the default-deny permissions.write gate (the E6
            // binary is built with `adminspace-write`); this test proves APPLY.
            "--config-write-permit",
        ],
    );
    let addr_a = format!("127.0.0.1:{p_a}");

    // Wait until A registers the config-write subscriber (logged AFTER the config
    // GET registration in run_peer, so this guarantees both surfaces are up). The
    // capture also carries A's startup `config (read-at-open)` line = the baseline.
    let a_write_log = wait_for_substring(
        &mut a_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = a_guard.child_mut().kill();
        let _ = a_guard.child_mut().wait();
        panic!("peer-A did not register --config-writable within 5s.\n--- peer-A ---\n{c}");
    });
    // The open BASELINE (before any PUT): A's read-at-open config log shows an
    // empty deny list. This is the "before" half of the observable flip.
    assert!(
        a_write_log.contains(r#""acl_deny":[]"#),
        "peer-A's startup config did not show the empty acl_deny baseline.\n\
         --- peer-A ---\n{a_write_log}"
    );
    let write_key = a_write_log
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer-A logged the config-write keyexpr");
    let config_key = write_key
        .strip_suffix("/**")
        .unwrap_or_else(|| panic!("config-write key lacks /**: {write_key}"))
        .to_string();
    let put_key = format!("{config_key}/acl-deny");

    // B (peer): dials A and PUTs A's config/acl-deny carrying mesh/data each tick.
    let (mut b_guard, mut b_reader, _p_b, _b_log) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_a,
            "--put-key",
            &put_key,
            "--put-payload",
            DATA_KEY,
        ],
    );

    // Gate: A must have reconfigured from B's PUT before C queries — so C's GET sees
    // the FLIPPED state, deterministically (not racing the reconfigure).
    let reconfigured = wait_for_substring(
        &mut a_reader,
        &format!("config reconfigured — now denying {DATA_KEY}"),
        Duration::from_secs(20),
    );
    if let Err(c) = &reconfigured {
        let a = read_captured(&mut a_reader);
        let b = read_captured(&mut b_reader);
        graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
        graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
        panic!(
            "peer-A never reconfigured from B's config-write PUT within 20s.\n\
             --- A at deadline ---\n{c}\n--- A ---\n{a}\n--- B ---\n{b}"
        );
    }

    // C (connect client): GET A's config AFTER the reconfigure; the reply must carry
    // the FLIPPED acl_deny.
    let c_stderr = tempfile::tempfile().expect("tempfile for client C stderr");
    let c_writer = c_stderr.try_clone().expect("dup client C stderr handle");
    let mut c_reader = c_stderr;
    let mut c_guard = ChildGuard::wrap(
        "client-C (--connect --query --on-query-reply-log)".to_string(),
        Command::new(wz_ap_demo_binary())
            .arg("--connect")
            .arg(&addr_a)
            .arg("--query")
            .arg(&config_key)
            .arg("--on-query-reply-log")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(c_writer))
            .spawn()
            .expect("spawn client-C"),
    );
    let reply = wait_for_substring(&mut c_reader, "REPLY RECEIVED", Duration::from_secs(10));

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let _ = c_guard.child_mut().kill();
    let _ = c_guard.child_mut().wait();
    let a_final = read_captured(&mut a_reader);
    let c_final = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_final}");
    eprintln!("--- client-C stderr ---\n{c_final}");

    let reply = reply.unwrap_or_else(|c| {
        panic!(
            "client-C did not log 'REPLY RECEIVED' within 10s — the config GET after the \
             reconfigure did not answer over the wire.\n--- C at deadline ---\n{c}\n\
             --- A ---\n{a_final}"
        )
    });
    // The AFTER half of the flip: A's GET now serves acl_deny=[mesh/data] — the same
    // deny the remote PUT drove, observed over the wire on the read path. The demo's
    // reply log debug-escapes the JSON (e.g. \"acl_deny\":[\"mesh/data\"]).
    assert!(
        reply.contains(r#"\"acl_deny\":[\"mesh/data\"]"#),
        "client-C's GET reply did not carry the FLIPPED acl_deny=[mesh/data] — the \
         remote PUT's reconfigure is not GET-observable over the wire.\n--- C ---\n{reply}"
    );
    assert!(
        reply.contains(r#"\"acl_default\":\"allow\""#),
        "client-C's GET reply lacks acl_default=allow (the base verdict).\n--- C ---\n{reply}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,adminspace-write); Layer E runs via --ignored"]
fn wz_peer_config_write_denied_without_permit_holds_the_verdict() {
    // R311y51 — the §5.23 adminspace-write GATE proof, the negative twin of
    // `..flips_the_live_verdict..`. A HOSTS the config-write subscriber
    // (`--config-writable`) but does NOT grant the write permission (no
    // `--config-write-permit`). The E6 binary is built with `adminspace-write`, so
    // A's `permissions.write` gate is default-deny and B's config-write PUT is
    // REJECTED: A logs `config-write DENIED`, NEVER reconfigures, NEVER drops, and
    // keeps admitting B's mesh/data. The verdict does NOT flip — the permit is the
    // control.
    //
    // Determinism: `config-write DENIED` is the positive witness the PUT routed AND
    // the gate engaged (a non-denied write would log `config reconfigured` instead;
    // for a fixed write=false the two are mutually exclusive). The absence asserts
    // on the post-shutdown capture are belt-and-suspenders, not the primary gate.

    let (mut a_guard, mut a_reader, p_a, a_listen_log) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            DATA_KEY,
            "--config-writable",
            // NB: no `--config-write-permit` — the gate must DENY.
        ],
    );
    let addr_a = format!("127.0.0.1:{p_a}");

    let write_log = if a_listen_log.contains("adminspace config WRITE at ") {
        a_listen_log
    } else {
        wait_for_substring(
            &mut a_reader,
            "adminspace config WRITE at ",
            Duration::from_secs(5),
        )
        .unwrap_or_else(|c| {
            let _ = a_guard.child_mut().kill();
            let _ = a_guard.child_mut().wait();
            panic!(
                "peer-A did not register --config-writable within 5s.\n\
                 --- peer-A stderr ---\n{c}"
            );
        })
    };
    let write_key = write_log
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer-A logged the admin config-write keyexpr");
    let config_base = write_key
        .strip_suffix("/**")
        .unwrap_or_else(|| panic!("config-write key lacks the /** pattern suffix: {write_key}"));
    let put_key = format!("{config_base}/acl-deny");

    // B dials A, publishes mesh/data each tick AND PUTs A's config/acl-deny=mesh/data.
    let (mut b_guard, mut b_reader, _p_b, _b_listen_log) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_a,
            "--publish",
            DATA_KEY,
            "--put-key",
            &put_key,
            "--put-payload",
            DATA_KEY,
        ],
    );

    // Primary sync: A must have RECEIVED + DENIED the config-write PUT (the gate
    // engaged). This proves the PUT routed all the way to A's handler and was
    // rejected — a non-denied write would have logged `config reconfigured`.
    let denied_sync = wait_for_substring(
        &mut a_reader,
        "config-write DENIED",
        Duration::from_secs(20),
    );

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");

    denied_sync.unwrap_or_else(|c| {
        panic!(
            "peer-A never logged 'config-write DENIED' within 20s — B's config-write \
             PUT to {put_key} did not reach A's gated handler (or the gate did not \
             engage).\n--- peer-A stderr at deadline ---\n{c}\n\
             --- peer-B stderr ---\n{b_captured}"
        )
    });

    // (1) The gate ENGAGED: the PUT was received and rejected by permissions.write.
    assert!(
        a_captured.contains("config-write DENIED"),
        "peer-A did not log the permission deny.\n--- peer-A stderr ---\n{a_captured}"
    );
    // (2) NO reconfigure: a denied write never reaches reconfigure_interceptors.
    assert!(
        !a_captured.contains("config reconfigured"),
        "peer-A RECONFIGURED despite the deny — the adminspace-write gate did not \
         hold (a config-write PUT applied without --config-write-permit).\n\
         --- peer-A stderr ---\n{a_captured}"
    );
    // (3) NO drop: the live verdict never flipped, so no mesh/data was dropped.
    assert!(
        !a_captured.contains("interceptor dropped"),
        "peer-A DROPPED a message — the verdict flipped despite the deny (the gate \
         failed to block the reconfigure).\n--- peer-A stderr ---\n{a_captured}"
    );
    // (4) Data kept flowing: A admitted B's mesh/data (the verdict stayed allow).
    assert!(
        a_captured.contains("received mesh data"),
        "peer-A never admitted any mesh/data — cannot show the verdict stayed at \
         allow under the deny.\n--- peer-A stderr ---\n{a_captured}"
    );
}
