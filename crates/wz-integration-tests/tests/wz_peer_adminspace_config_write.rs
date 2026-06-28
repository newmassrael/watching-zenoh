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

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// The data keyexpr B publishes and (via the config-write PUT) A is told to deny.
const DATA_KEY: &str = "mesh/data";

/// Parse the bound port from a peer's `listening on 127.0.0.1:<port>` log line —
/// the ephemeral-port read-back that lets the next peer dial this one without a
/// reserved-port allocation.
fn listen_port(captured: &str) -> u16 {
    let marker = "listening on 127.0.0.1:";
    let rest = captured
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
}

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
