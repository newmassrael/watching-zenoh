// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! P4 §5.21 `router-connect-reconcile` (R311y202, slice 1) — the runtime dynamic
//! connect-list reconcile driven END TO END over real transport, the wz port of
//! zenoh's `update_peers` (`net/runtime/orchestrator.rs:413`): a router-hat that
//! learns a NEW connect endpoint at runtime dials it and federates, without the
//! endpoint ever appearing on the startup `--connect` list.
//!
//! FOUR tests split across two binaries (the feature-on and feature-off binaries
//! never share a build — the negative lane rebuilds the no-reconcile binary right
//! before it, so neither clobbers the other):
//!
//! 1. `wz_router_hat_reconcile_dials_new_endpoint` (POSITIVE, feature ON) — a
//!    router-hat R1 spawned with NO `--connect` but a `--connect-after
//!    <ms>:<R2>` affordance. R1 comes up isolated (router tier = 1 = self alone),
//!    then at the deadline the operator affordance fires the reconcile channel and
//!    R1 dials R2 at RUNTIME, converging its router tier to 2. Because R1 has no
//!    static connect target, the ONLY path to R2 is the reconcile — a converged
//!    router tier is proof the runtime-added endpoint was dialed and established.
//!    The `--connect-after fired` log pins that the federation came from the
//!    reconcile, not a startup dial.
//!
//! 2. `wz_router_hat_reconcile_dedups_already_dialed` (POSITIVE, feature ON) — the
//!    address dedup: R1 with a STATIC `--connect <R2>` AND a `--connect-after`
//!    listing the SAME R2 holds exactly ONE face to R2 (peak 1 concurrent), proving
//!    the reconcile did not re-dial an endpoint already being dialed. A broken dedup
//!    would seat a second face (peak 2).
//!
//! 3. `wz_router_hat_reconnect_redials_dropped_peer` (POSITIVE, feature ON) — the
//!    slice-2 peer auto-reconnect: a dropped-but-still-desired configured peer is
//!    re-dialed on the face drop.
//!
//! 4. `wz_router_hat_reconcile_requires_feature` (NEGATIVE, feature OFF) — the SAME
//!    `--connect-after` flag on a `router-hat-router` binary built WITHOUT
//!    `router-connect-reconcile` is inert: the run mode warns it is ignoring the
//!    flag and never reconciles. This keeps the catalog claim and the binary in
//!    lockstep (the `#[cfg(feature = "router-connect-reconcile")]` sites in
//!    `run_router_hat` + `main.rs` are what make the atom truthfully active).
//!
//! Cross-impl is NOT needed for this atom: the reconcile introduces no new wire
//! format — the runtime dial reuses the already-cross-impl-proven session-open
//! handshake — so a wz<->wz loopback exercises the whole new control path. The test
//! fns carry the `wz_router_hat_` prefix so the default Layer E sweep's `--skip
//! wz_router` excludes them from the arbitrary-feature binary run (Layer E7b runs
//! them via `--ignored` against their own binaries).

use std::fs::File;
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// Spawn a `--router-hat` node (presents wire `WhatAmI::Router`). Mirrors the
/// `wz_router_hat_mesh` harness — owns the tempfile the dev-dep-restricted lib
/// helper cannot allocate, and gates on the router-hat listen marker.
fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for node stderr");
    // R2394 — the demo is this fixture's SUBJECT, not a readiness probe: both
    // tests read a verdict out of the router's own behaviour, so a demo built
    // before the connect-add arms landed would read as "wz does not honour a
    // wire connect-add" and send the diagnosis to the routing layer for a defect
    // that is in the build. R2393 added these two fixtures without the check and
    // the binary-freshness lint went 232 -> 234; the repair the lint prescribes
    // for that direction is the call, not a higher number.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    )
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile); Layer E7b runs via --ignored"]
fn wz_router_hat_reconcile_dials_new_endpoint() {
    // R2 binds first so R1's runtime reconcile has a live target to dial. R2 hosts
    // no connect list of its own — it only accepts R1's later inbound dial.
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");

    // R1 comes up with NO `--connect` (isolated: router tier = 1 = self), plus a
    // `--connect-after 600:<R2>` affordance that fires a runtime reconcile ~600 ms
    // after startup. Since R1 never has R2 on its static connect list, a converged
    // router tier can ONLY come from the reconcile dial.
    let connect_after = format!("600:{addr_r2}");
    let (mut r1_guard, mut r1_reader, _p_r1) = spawn_router_hat(
        "router-hat-1",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--connect-after",
            &connect_after,
        ],
    );

    // The reconcile FIRE (deterministic operator-affordance log) followed by R1's
    // router tier converging to 2 — the runtime-added endpoint was dialed and the
    // R1<->R2 Router/Router handshake established. Await the convergence (the
    // load-bearing edge); the fire log is asserted from the capture below.
    let r1_converged = wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    );

    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    r1_converged.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never converged its router tier to 2 within 15s — the \
             runtime connect-list reconcile did not dial R2 (R1 has no static \
             --connect, so the only path to R2 is the --connect-after reconcile; a \
             stuck router tier means the reconcile channel never dialed the \
             newly-listed endpoint)\n--- router-hat-1 stderr ---\n{c}"
        )
    });
    // Pin that the federation came from the RECONCILE, not a startup dial: R1 must
    // log the operator-affordance fire. Without this a green convergence could not
    // distinguish the reconcile path from an (absent) static dial.
    assert!(
        r1_captured.contains("--connect-after fired; reconciling connect-list"),
        "router-hat-1 never logged the --connect-after reconcile fire — the \
         convergence did not come through the runtime reconcile path\n--- \
         router-hat-1 stderr ---\n{r1_captured}"
    );
    // Deterministic shutdown peak: R1's router tier peaked at 2 (self + the
    // reconcile-dialed R2). Latched high-water, emitted unconditionally at shutdown,
    // so it cannot race the app tick.
    assert!(
        r1_captured.contains("peak routers-net 2 node(s)"),
        "router-hat-1's router tier did not peak at 2 nodes — the runtime-dialed R2 \
         did not join the router mesh\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
    // R2's side confirms the inbound dial arrived and was classified Router (it had
    // no connect list of its own, so its router tier rose only because R1 dialed in).
    assert!(
        r2_captured.contains("peak routers-net 2 node(s)"),
        "router-hat-2 never saw the reconcile-dialed inbound face converge its \
         router tier to 2 — R1's runtime dial did not reach R2\n--- router-hat-2 \
         stderr ---\n{r2_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile); Layer E7b runs via --ignored"]
fn wz_router_hat_reconcile_dedups_already_dialed() {
    // The ADDRESS dedup: a reconcile that lists an endpoint ALREADY being dialed must
    // not INITIATE a second dial to it. R1 statically `--connect`s R2 (seeding R2 into
    // the dial-address index) AND `--connect-after`s the SAME R2 at runtime. The proof
    // is R1's shutdown-summary DIAL COUNT staying at 1: the reconcile skipped R2. The
    // peak-face count would NOT prove this — a re-dialed R2 is caught post-handshake by
    // the RouterForwarder's zid dedup (dedups_faces_by_zid, router_forward.rs:5080), so
    // the peak stays 1 either way. `summary.dialed` increments at the dial-PUSH, before
    // the zid dedup runs, so it is the observable that isolates the address dedup: a
    // broken dedup pushes a second dial (dialed 2) even though the face is later dropped.
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    let connect_after = format!("600:{addr_r2}");
    let (mut r1_guard, mut r1_reader, _p_r1) = spawn_router_hat(
        "router-hat-1",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--connect",
            &addr_r2,
            "--connect-after",
            &connect_after,
        ],
    );

    // Federate (the static dial), then let the reconcile fire listing R2 again. Gate
    // on the fire so the dedup path has provably run before the shutdown read.
    wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    )
    .unwrap_or_else(|c| panic!("router-hat-1 never federated with R2 within 15s\n--- r1 ---\n{c}"));
    let fired = wait_for_substring(
        &mut r1_reader,
        "--connect-after fired; reconciling connect-list",
        Duration::from_secs(15),
    );

    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    fired.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never fired the --connect-after reconcile within 15s — the \
             dedup path did not run\n--- r1 ---\n{c}"
        )
    });
    // The dedup proof: R1 initiated exactly ONE dial (the static R2). The reconcile
    // listing R2 again did NOT push a second dial. A broken address dedup would show
    // "dialed 2" in the latched shutdown summary.
    assert!(
        r1_captured.contains("dialed 1,"),
        "router-hat-1 initiated more than one dial — the reconcile re-dialed an \
         already-dialed endpoint (address dedup broke)\n--- r1 ---\n{r1_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile); Layer E7b runs via --ignored"]
fn wz_router_hat_reconnect_redials_dropped_peer() {
    // Slice 2 — peer AUTO-RECONNECT (the wz port of zenoh's `closed_session`
    // Peer/Router re-dial, `orchestrator.rs:1210`): a router-hat R1 with a STATIC
    // `--connect <R2>` federates with R2, then R2 is killed. R1's face to R2 drops,
    // and because R2 is still in R1's desired connect-set, R1 SCHEDULES a re-dial
    // (retry-until-success). We prove the re-dial FIRES on the drop — the new
    // behaviour; the re-dial itself reuses the slice-1-proven `dial_face` path, so a
    // live target would be reconnected (not re-proven here to keep the test robust:
    // restarting R2 on the same ephemeral port is racy, and the attempt-on-drop is
    // the mechanism this slice adds).
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");
    let (mut r1_guard, mut r1_reader, _p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--connect", &addr_r2],
    );

    // First establish the federation: R1's router tier converges to 2 (the static
    // dial to R2 succeeded and R2 is in R1's desired set). This orders the drop
    // AFTER a real face exists to drop.
    wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    )
    .unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never federated with R2 within 15s — the static dial did \
             not establish, so there is no face to drop\n--- router-hat-1 stderr \
             ---\n{c}"
        )
    });

    // Kill R2. R1's face to R2 drops; R2 is still desired (it is on R1's --connect
    // list), so R1 must schedule a re-dial.
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));

    // The re-dial FIRE for R2's address — the deterministic peer-auto-reconnect
    // witness (logged the moment the drop is observed, before the backoff sleep).
    let redialed = wait_for_substring(
        &mut r1_reader,
        &format!("reconcile: re-dialing desired peer {addr_r2}"),
        Duration::from_secs(15),
    );

    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");

    redialed.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never re-dialed the dropped-but-still-desired peer R2 \
             within 15s — the peer auto-reconnect did not fire on the face drop (a \
             dropped configured peer must be re-dialed, zenoh closed_session \
             behaviour)\n--- router-hat-1 stderr ---\n{c}"
        )
    });
}

#[test]
#[ignore = "binary-dep e2e (DEFAULT router-hat-router build, no router-connect-reconcile); Layer E7b runs via --ignored"]
fn wz_router_hat_reconcile_requires_feature() {
    // The NEGATIVE lockstep counterpart: a `router-hat-router` binary built WITHOUT
    // `router-connect-reconcile` must treat `--connect-after` as inert — warn that
    // it is ignoring the flag, and NOT reconcile. A bogus target is fine: the flag
    // is dropped before any dial, so it is never contacted.
    let (mut r_guard, mut r_reader, _p_r) = spawn_router_hat(
        "router-hat",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--connect-after",
            "100:127.0.0.1:1",
        ],
    );

    // The inert-flag warning is a deterministic STARTUP line (printed before the
    // run mode's listen marker the spawn gated on), so it is already in the capture.
    let warned = wait_for_substring(
        &mut r_reader,
        "--connect-after requires the `router-connect-reconcile` feature",
        Duration::from_secs(10),
    );

    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));
    let r_captured = read_captured(&mut r_reader);
    eprintln!("--- router-hat stderr ---\n{r_captured}");

    warned.unwrap_or_else(|c| {
        panic!(
            "a router-hat built WITHOUT router-connect-reconcile must warn that it \
             is ignoring --connect-after (the feature-gate lockstep) — the warning \
             never appeared, so the flag is silently accepted without the \
             feature\n--- router-hat stderr ---\n{c}"
        )
    });
    // Belt-and-suspenders: the inert build must NOT log a reconcile fire (the
    // #[cfg]-gated fire path is compiled out).
    assert!(
        !r_captured.contains("--connect-after fired"),
        "a build without router-connect-reconcile must not fire a reconcile — the \
         feature gate is not eliding the fire path\n--- router-hat stderr ---\n{r_captured}"
    );
}

// ── R2393 — the connect list told over the WIRE, not from the CLI ──────────────
//
// The atom's last live residual was that the runtime connect-list reconcile had
// exactly ONE producer, the one-shot `--connect-after` timer, where upstream
// re-enters `update_peers` whenever a live node's config changes. R2393 added the
// second producer: a `RouterForwarder`-hosted config-WRITE subscriber that decodes
// `.../config/connect-add <endpoint>` and feeds the same `ReconcileSender`.
//
// THESE TESTS EXIST BECAUSE THAT FEATURE SHIPPED BROKEN AND NOTHING NOTICED.
// `82fd09b2` wired the handler with the subscription PATTERN where the STRIP PREFIX
// belongs, so every PUT decoded `NotAWrite` — an arm that is silent by design — and
// it built the router-hat's admin permissions with `..Default::default()`, whose
// `write` is `false`, so the gate could not be opened by any flag even once the
// prefix was right. Both defects are invisible to every unit test in the tree: the
// decoder's tests pass the prefix as a `const` literal, and no test had ever driven
// this host's write path. A lane is the only instrument that could have caught it,
// and there was none.
//
// The pair is a positive/negative twin on the SAME binary, so the permit is the only
// variable: with `--config-write-permit` the wire PUT federates R1 to R2, without it
// R1 stays isolated and says the write was denied.
//
// CONTAINMENT — why the deny arm is not vacuous. `admin_write_permit` reads
// `permissions.write` only under the `adminspace-write` cfg; with that feature
// compiled OUT it returns a constant `true` (`wz-runtime-tokio/src/lib.rs:459-463`),
// so every write would be APPLIED and a deny test would be asserting against a node
// that permits everything. Layer E7b2 therefore NAMES `adminspace-write` in its
// build, and the deny arm passing is itself the evidence that it is compiled in and
// load-bearing: were it absent, the PUT would federate and this test would fail on
// the missing deny rather than pass quietly.

/// Spawn a `--peer` writer that dials `addr` and PUTs `put_key` once per app tick.
/// The writer is a peer rather than a router-hat because `--put-key` is a `PeerOpts`
/// affordance — the router-hat run-mode parses no put flags.
fn spawn_config_writer(
    label: &str,
    addr: &str,
    put_key: &str,
    payload: &str,
) -> (ChildGuard, File) {
    let stderr = tempfile::tempfile().expect("tempfile for writer stderr");
    let (guard, reader, _port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            addr,
            // `--publish` is REQUIRED for `--put-key` to fire, and that is not
            // obvious: the put drive sits inside the publisher's tick branch
            // (`runner.rs`, `if let Some(key) = publish_key`), so a writer given
            // only `--put-key` connects, logs nothing, and PUTs nothing — which is
            // exactly what the first cut of this test observed. The key published
            // here is inert: nothing subscribes to it.
            "--publish",
            "r2393/writer/tick",
            "--put-key",
            put_key,
            "--put-payload",
            payload,
        ],
        "peer: listening on 127.0.0.1:",
        label,
        stderr,
    );
    (guard, reader)
}

/// R2655 — the DELETE twin of [`spawn_config_writer`]: a peer that publishes a
/// Del on the config-write key rather than a Put.
///
/// `--del-key` is the tick driver, NOT `--delete`. The first cut of this helper
/// used `--delete <keyexpr>`, which is the demo's legacy burst-publisher MODE:
/// it is mutually exclusive with `--publish`, never reaches `run_peer_until`'s
/// app tick, and produced a run in which the deleter formed a mesh link and sent
/// nothing at all. `--del-key` rides the same tick as `--put-key`, which is what
/// a config write is.
fn spawn_config_deleter(label: &str, addr: &str, del_key: &str) -> (ChildGuard, File) {
    let stderr = tempfile::tempfile().expect("tempfile for deleter stderr");
    let (guard, reader, _port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            addr,
            // `--publish` is REQUIRED for the tick drivers to fire, exactly as
            // it is for `--put-key`: the drive sits inside the publisher's tick
            // branch. The key published here is inert.
            "--publish",
            "r2655/deleter/tick",
            "--del-key",
            del_key,
        ],
        "peer: listening on 127.0.0.1:",
        label,
        stderr,
    );
    (guard, reader)
}

/// Read R1's advertised config-WRITE key out of its log and return the BASE
/// `@/<zid>/router/config` that every intent hangs off.
///
/// Scraped rather than derived: the zid is assigned at startup, so deriving it in
/// the test would duplicate the demo's own zid policy and could drift from it. The
/// `/**` suffix assertion is what makes the strip safe.
///
/// R2649 — split out of `connect_add_key` when a SECOND intent needed the same
/// base. The scrape is not a convenience: the two asserts are what stop a silently
/// reshaped key from producing a PUT target that decodes `NotAWrite`, an arm that
/// is quiet by design and was one of the three defects this lane exists for. Two
/// copies of a safety check are two things that can drift apart, so there is one.
fn config_write_base(write_log: &str) -> String {
    let write_key = write_log
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config WRITE at ")
                .map(|(_, rest)| rest.split_whitespace().next().unwrap_or("").to_string())
        })
        .expect("router-hat logged its admin config-write keyexpr");
    let base = write_key
        .strip_suffix("/**")
        .unwrap_or_else(|| panic!("config-write key lacks the /** pattern suffix: {write_key}"));
    assert!(
        base.starts_with("@/") && base.ends_with("/router/config"),
        "scraped config-write base has the @/<zid>/router/config shape: {base}"
    );
    String::from(base)
}

/// The concrete PUT target `@/<zid>/router/config/connect-add`.
fn connect_add_key(write_log: &str) -> String {
    format!("{}/connect-add", config_write_base(write_log))
}

/// R2649 — the PUT target for a runtime config-KEY write, which is the base plus
/// the upstream config key path itself. Unlike `connect-add` this is not a wz
/// spelling: `AdminConfigWrite::SetKey` carries the key as DATA, so the wire form
/// is the very key `HONOURED_CONFIG_KEYS` names.
fn config_key_write_key(write_log: &str, config_key: &str) -> String {
    format!("{}/{config_key}", config_write_base(write_log))
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile,adminspace-router-linkstate,routing-peer); Layer E7b2 runs via --ignored"]
fn wz_router_hat_connect_add_over_the_wire_dials_the_new_endpoint() {
    // R2 binds first so there is a live target to dial.
    let (mut r2_guard, mut r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");

    // R1: NO `--connect` and NO `--connect-after`. The ONLY path to R2 is a wire
    // write, so a converged router tier can come from nothing else. The permit is
    // GRANTED here; the twin below omits it.
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--config-write-permit"],
    );
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    let write_log = wait_for_substring(
        &mut r1_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        let _ = r2_guard.child_mut().kill();
        panic!(
            "router-hat-1 never logged 'adminspace config WRITE at' — it did not \
             register the config-write subscriber, so no wire write can reach \
             it.\n--- router-hat-1 stderr ---\n{c}"
        )
    });
    let put_key = connect_add_key(&write_log);

    // The payload is an IP LOCATOR (`tcp/...`), not the bare `host:port` the CLI
    // takes: this handler is a sync closure and parses without the CLI path's async
    // resolver, which is written down where it diverges.
    let (mut w_guard, mut w_reader) = spawn_config_writer(
        "config-writer",
        &addr_r1,
        &put_key,
        &format!("tcp/{addr_r2}"),
    );

    // The load-bearing edge: R1's router tier converges to 2. Nothing but the wire
    // write could have dialed R2.
    let converged = wait_for_substring(
        &mut r1_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(20),
    );

    graceful_terminate(w_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let r2_captured = read_captured(&mut r2_reader);
    let w_captured = read_captured(&mut w_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- router-hat-2 stderr ---\n{r2_captured}");
    eprintln!("--- config-writer stderr ---\n{w_captured}");

    converged.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never converged its router tier to 2 within 20s — the \
             config-write PUT to {put_key} did not reach the reconcile channel. R1 \
             has no --connect and no --connect-after, so the WIRE write is the only \
             path to R2. A silent failure here is the shape R2393 shipped: a \
             mismatched strip prefix decodes every PUT as NotAWrite, whose arm logs \
             nothing.\n--- router-hat-1 stderr at deadline ---\n{c}\n\
             --- config-writer stderr ---\n{w_captured}"
        )
    });

    // The apply log names the reconcile explicitly, so the convergence is attributed
    // to the connect-add rather than to any other dial path.
    assert!(
        r1_captured.contains("config-write connect-add reconciled"),
        "router-hat-1 converged but never logged the connect-add apply — the \
         federation did not come from the wire write.\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
    // And the write was not denied. Asserted on `DENIED` ALONE: the first cut wrote
    // `!contains("config-write on") || !contains("DENIED")`, which is `!(A && B)` —
    // it passes whenever either half is missing, so a capture holding a deny line
    // with either wording drifted would satisfy it. The deny is one line carrying
    // both, so the single check is both clearer and strictly stronger.
    assert!(
        !r1_captured.contains("DENIED"),
        "router-hat-1 logged a DENIED config write while holding \
         --config-write-permit\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile,adminspace-router-linkstate,routing-peer); Layer E7b2 runs via --ignored"]
fn wz_router_hat_connect_add_is_denied_without_the_write_permit() {
    // The NEGATIVE twin, and the control that makes the positive test mean
    // something: identical binary, identical topology, identical PUT — the ONLY
    // difference is the absent `--config-write-permit`. Without this arm the
    // positive test could pass on a node that permits every write unconditionally,
    // which is exactly the state the router-hat was in before R2393 gave it a flag
    // (it permitted NOTHING, and nothing could tell).
    // R2's own log is not read in this arm — the claim is about R1 refusing, and R2
    // is only here so the endpoint the denied write names is genuinely dialable. If
    // R2 were absent, a non-convergence would be explained by "nothing to dial"
    // rather than by the deny, and the assertion would prove nothing.
    let (mut r2_guard, _r2_reader, p_r2) =
        spawn_router_hat("router-hat-2", &["--router-hat", "127.0.0.1:0"]);
    let addr_r2 = format!("127.0.0.1:{p_r2}");

    let (mut r1_guard, mut r1_reader, p_r1) =
        spawn_router_hat("router-hat-1", &["--router-hat", "127.0.0.1:0"]);
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    let write_log = wait_for_substring(
        &mut r1_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        let _ = r2_guard.child_mut().kill();
        panic!(
            "router-hat-1 never logged 'adminspace config WRITE at' — the subscriber \
             must be HOSTED regardless of the permit (host and permit are orthogonal, \
             as they are on the peer host).\n--- router-hat-1 stderr ---\n{c}"
        )
    });
    let put_key = connect_add_key(&write_log);

    let (mut w_guard, mut w_reader) = spawn_config_writer(
        "config-writer",
        &addr_r1,
        &put_key,
        &format!("tcp/{addr_r2}"),
    );

    // A DENY is a POSITIVE edge here — the demo logs the refusal at error — so this
    // is not a wait-for-absence. The convergence assertion below is what the deny
    // implies, checked against the post-shutdown capture rather than by waiting.
    let denied = wait_for_substring(&mut r1_reader, "config-write on", Duration::from_secs(20));

    graceful_terminate(w_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r2_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let w_captured = read_captured(&mut w_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- config-writer stderr ---\n{w_captured}");

    denied.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never logged the config-write DENY within 20s — without \
             --config-write-permit the write gate must refuse the PUT and say so \
             (zenoh logs a denied write at error, adminspace.rs:397).\n\
             --- router-hat-1 stderr at deadline ---\n{c}\n\
             --- config-writer stderr ---\n{w_captured}"
        )
    });
    assert!(
        r1_captured.contains("DENIED"),
        "the deny line must name the refusal\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
    // The refusal is LOAD-BEARING: no dial happened.
    assert!(
        !r1_captured.contains("config-write connect-add reconciled"),
        "a DENIED write must not reach the reconcile channel\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
    assert!(
        !r1_captured.contains("routers-net converged (2 node(s))"),
        "a router whose config write was denied must NOT federate with the endpoint \
         the denied write named — the permit is not load-bearing if it does\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
}

// ─── R2649 — the runtime config-KEY write, over the wire ────────────────────────
//
// The second intent this host serves, and the first that is not a wz spelling:
// `AdminConfigWrite::SetKey` carries the config key as DATA, so the PUT target is
// the upstream key itself and the payload is its JSON5 value.
//
// WHY A LANE AND NOT A UNIT TEST, which is the same answer this file's header
// already gives for connect-add: the path from a decoded intent to the live value
// runs through a handler stored INSIDE the forwarder, a slot it stashes into, and
// an app-tick drain that owns the sink. None of that is reachable from a unit test,
// and the library seam on either side of it is already covered — `ingest_for_key`
// -> `reconfigure_router_link_weights` -> sink is pinned by
// `a_wire_value_for_the_weights_key_reaches_the_sink_through_the_front_end`.
// What no test could see until this one is whether a real PUT reaches that stash.
//
// WHAT THE APPLIED LINE PROVES, because it is weaker-looking than it is:
// `reconfigure_router_link_weights` returns `Ok(sink.set_router_link_weights(..))`
// under `config-mutate-runtime`, and the drain logs "applied" ONLY on `Ok`. So the
// line is not "the drain ran" — it is "the sink was driven with the parsed rows".
// The rows' CONTENT is the library test's job; reaching the sink is this one's.
//
// The pair is a positive/negative twin on ONE binary, permit as the only variable,
// exactly as the connect-add pair above. No R2: applying a weight needs no live
// destination, so the fixture is two processes rather than three.

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile,adminspace-router-linkstate,routing-peer,adminspace-write,router-config-mutate,pubsub-delete); Layer E7b2 runs via --ignored"]
fn wz_router_hat_config_key_write_applies_a_link_weight_over_the_wire() {
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--config-write-permit"],
    );
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    let write_log = wait_for_substring(
        &mut r1_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        panic!(
            "router-hat-1 never logged 'adminspace config WRITE at' — it did not \
             register the config-write subscriber, so no wire write can reach \
             it.\n--- router-hat-1 stderr ---\n{c}"
        )
    });
    let put_key = config_key_write_key(&write_log, "routing/router/linkstate/transport_weights");

    // The value spelling is the reader's own, not this test's invention: the SHAPE
    // const in `transport_weights_of` says `{ dst_zid: "<hex zid>", weight: <1..=65535> }`.
    // The destination need not exist — a weight is a statement about a link, and
    // installing it is what is under test, not routing to it.
    let (mut w_guard, mut w_reader) = spawn_config_writer(
        "config-writer",
        &addr_r1,
        &put_key,
        r#"[{ dst_zid: "aa", weight: 7 }]"#,
    );

    // R2655 — the line moved with the plane. The drain used to be typed to this
    // one slice and said so ("applied N link weight(s)"); it now writes any key
    // whose slice this host has a sink for, through `set_by_key_with`, so it
    // names the KEY instead of the slice's units. The discriminator is the same:
    // this line is written only when the write returned `Ok`, which is only when
    // the value was stored AND the sink was driven.
    let applied = wait_for_substring(
        &mut r1_reader,
        "config-write wrote routing/router/linkstate/transport_weights at runtime",
        Duration::from_secs(20),
    );

    // R2650 — settle long enough for the writer to re-deliver the SAME value
    // several times. `--put-key` fires once per 250ms app tick, so ~6 more PUTs
    // land in this window, and the apply is idempotent only if none of them
    // reaches the sink again. The fixture GENERATES the repeat rather than the
    // assertion merely hoping for its absence, which is what makes the count
    // below a real discriminator instead of a wait-for-nothing.
    std::thread::sleep(Duration::from_millis(1500));

    graceful_terminate(w_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let w_captured = read_captured(&mut w_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- config-writer stderr ---\n{w_captured}");

    applied.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never logged that it WROTE the link-weight key within \
             20s. That line is written only when `set_by_key_with` returns Ok, \
             which is only when the value was stored and the sink was driven — so \
             its absence means the PUT never reached the queue, the drain never \
             ran, or the write was refused.\n\
             --- router-hat-1 stderr at deadline ---\n{c}\n\
             --- config-writer stderr ---\n{w_captured}"
        )
    });
    // The two halves, named separately: the handler QUEUED and the drain WROTE.
    // A run that logged only the first would mean the queue filled and nothing
    // drained it.
    //
    // ⚠ R2655 — the handler's line says "queued", not "accepted", and the change
    // is not cosmetic: the handler no longer parses or decides servability, so
    // an acceptance is not a thing it can report any more. Both judgements moved
    // into the one function the drain calls.
    assert!(
        r1_captured
            .contains("config-write routing/router/linkstate/transport_weights queued for apply"),
        "the handler must report the intent it queued, not only the apply\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
    assert!(
        !r1_captured.contains("transport_weights refused"),
        "a well-formed single row must not be refused by the write gate\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
    // R2650 — EXACTLY once, over a window in which the same value arrived many
    // times. An unchanged config must not re-drive the sink: the drain compares
    // each queued intent against the last one APPLIED for that key and skips a
    // repeat.
    let applies = r1_captured.matches("config-write wrote").count();
    assert_eq!(
        applies, 1,
        "the same value re-delivered every tick must be applied ONCE — {applies} \
         applies means the drain re-drives the sink for a configuration that \
         never changed\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile,adminspace-router-linkstate,routing-peer,adminspace-write,router-config-mutate,pubsub-delete); Layer E7b2 runs via --ignored"]
fn wz_router_hat_config_key_write_is_denied_without_the_write_permit() {
    // Same binary, same PUT, no `--config-write-permit`. The deny is a POSITIVE
    // edge (the demo logs the refusal at error), so this is not a wait-for-absence.
    let (mut r1_guard, mut r1_reader, p_r1) =
        spawn_router_hat("router-hat-1", &["--router-hat", "127.0.0.1:0"]);
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    let write_log = wait_for_substring(
        &mut r1_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        panic!(
            "router-hat-1 never logged 'adminspace config WRITE at'\n\
             --- router-hat-1 stderr ---\n{c}"
        )
    });
    let put_key = config_key_write_key(&write_log, "routing/router/linkstate/transport_weights");

    let (mut w_guard, mut w_reader) = spawn_config_writer(
        "config-writer",
        &addr_r1,
        &put_key,
        r#"[{ dst_zid: "aa", weight: 7 }]"#,
    );

    let denied = wait_for_substring(&mut r1_reader, "config-write on", Duration::from_secs(20));

    graceful_terminate(w_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let w_captured = read_captured(&mut w_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- config-writer stderr ---\n{w_captured}");

    denied.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never logged the config-write DENY within 20s\n\
             --- router-hat-1 stderr at deadline ---\n{c}\n\
             --- config-writer stderr ---\n{w_captured}"
        )
    });
    assert!(
        r1_captured.contains("DENIED"),
        "the deny line must name the refusal\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
    // The refusal is LOAD-BEARING: the gate runs BEFORE the key is even looked up,
    // so neither the stash nor the drain may report anything.
    assert!(
        !r1_captured.contains("queued for apply"),
        "a DENIED write must not reach the intent slot\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
    assert!(
        !r1_captured.contains("config-write wrote"),
        "a DENIED write must never be applied — the permit is not load-bearing if \
         it is\n--- router-hat-1 stderr ---\n{r1_captured}"
    );
}

/// R2655 — the DELETE half over the WIRE, which this host could not do before.
///
/// Until this round the router host's write handler had no `RemoveKey` arm: a
/// wire delete decoded and fell through to "intent decoded but not applied".
/// The two halves of upstream's ONE write gate are one gate here now, so the
/// delete goes through the same queue, the same drain and the same
/// `ConfigSinks` — and restores the key to its schema default, which for this
/// one is no weights at all.
///
/// ⚠ IT WRITES FIRST AND DELETES AFTER, in one run, because a delete that
/// restores a default is indistinguishable from a no-op against a node that
/// never held a value. The PUT is what makes the DEL observable.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,router-connect-reconcile,adminspace-router-linkstate,routing-peer,adminspace-write,router-config-mutate,pubsub-delete); Layer E7b2 runs via --ignored"]
fn wz_router_hat_config_key_delete_restores_the_default_over_the_wire() {
    let (mut r1_guard, mut r1_reader, p_r1) = spawn_router_hat(
        "router-hat-1",
        &["--router-hat", "127.0.0.1:0", "--config-write-permit"],
    );
    let addr_r1 = format!("127.0.0.1:{p_r1}");

    let write_log = wait_for_substring(
        &mut r1_reader,
        "adminspace config WRITE at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = r1_guard.child_mut().kill();
        panic!(
            "router-hat-1 never logged 'adminspace config WRITE at'\n\
             --- router-hat-1 stderr ---\n{c}"
        )
    });
    let put_key = config_key_write_key(&write_log, "routing/router/linkstate/transport_weights");

    let (mut w_guard, mut w_reader) = spawn_config_writer(
        "config-writer",
        &addr_r1,
        &put_key,
        r#"[{ dst_zid: "aa", weight: 7 }]"#,
    );
    let wrote = wait_for_substring(
        &mut r1_reader,
        "config-write wrote routing/router/linkstate/transport_weights at runtime",
        Duration::from_secs(20),
    );
    // The writer is stopped BEFORE the delete is sent: it re-publishes its PUT
    // every tick, and a live PUT racing the DEL would leave which one won up to
    // scheduling rather than to the gate.
    graceful_terminate(w_guard.child_mut(), Duration::from_secs(5));

    let (mut d_guard, mut d_reader) = spawn_config_deleter("config-deleter", &addr_r1, &put_key);
    let deleted = wait_for_substring(
        &mut r1_reader,
        "config-write deleted routing/router/linkstate/transport_weights at runtime",
        Duration::from_secs(20),
    );

    graceful_terminate(d_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(r1_guard.child_mut(), Duration::from_secs(5));
    let r1_captured = read_captured(&mut r1_reader);
    let w_captured = read_captured(&mut w_reader);
    let d_captured = read_captured(&mut d_reader);
    eprintln!("--- router-hat-1 stderr ---\n{r1_captured}");
    eprintln!("--- config-writer stderr ---\n{w_captured}");
    eprintln!("--- config-deleter stderr ---\n{d_captured}");

    wrote.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never wrote the weight, so the DELETE below would have \
             had nothing to restore\n--- router-hat-1 stderr at deadline ---\n{c}"
        )
    });
    deleted.unwrap_or_else(|c| {
        panic!(
            "router-hat-1 never logged that it DELETED the key within 20s. That \
             line is written only when `remove_by_key_with` returns Ok, so its \
             absence means the DEL never reached the queue, the handler has no \
             RemoveKey arm, or the delete was refused.\n\
             --- router-hat-1 stderr at deadline ---\n{c}\n\
             --- config-deleter stderr ---\n{d_captured}"
        )
    });
    assert!(
        r1_captured.contains(
            "config-write routing/router/linkstate/transport_weights delete queued for apply"
        ),
        "the handler must report the DELETE it queued — a run without this line \
         means the intent never decoded as a RemoveKey\n\
         --- router-hat-1 stderr ---\n{r1_captured}"
    );
}
