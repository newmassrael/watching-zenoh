// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    graceful_terminate, read_captured, spawn_on_ephemeral_port, wait_for_substring,
    wz_ap_demo_binary, ChildGuard,
};

/// Spawn a `--router-hat` node (presents wire `WhatAmI::Router`). Mirrors the
/// `wz_router_hat_mesh` harness — owns the tempfile the dev-dep-restricted lib
/// helper cannot allocate, and gates on the router-hat listen marker.
fn spawn_router_hat(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for node stderr");
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
