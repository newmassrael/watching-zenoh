// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer E — R300 outbound DECLARE-side keyexpr gate.
//!
//! Verifies that the wz-ap-demo binary rejects R299-documented
//! SIGABRT-prone keyexprs at argv parse time, before any wire bytes
//! are produced and before the session-FSM is even constructed. The
//! reject path is the eager mirror of the runtime gate in
//! `SessionLinkActions::send_declare_*` (R300 NARROW scope).
//!
//! ## What this fixture proves
//!
//! * Three MEASURED bug #3 family inputs (`**/c/*`, `**/c/**`,
//!   `**/a/b/*`) are rejected with exit code 2 and a diagnostic stderr
//!   line. R311y544 replaced `**/foo/*` here — the gate no longer
//!   refuses it, because a real zenoh-pico does not abort on it.
//! * The reject path runs at argv parse — no `--connect`
//!   completion required (the fixture uses a deliberately
//!   unreachable connect target so the binary never reaches the
//!   driver loop).
//! * The gate fires uniformly across the DECLARE-side CLI flags that
//!   carry an outbound keyexpr (`--key`, `--queryable`,
//!   `--declare-token`). R311oy — `--key` / `--queryable` (the routed
//!   `Session::declare_subscriber` / `declare_queryable` that R311ou /
//!   R311ow wired into the same eager gate) replaced the retired
//!   low-level `--declare-subscriber` / `--declare-queryable` hooks.
//!
//! ## Why a separate e2e file (not just a unit test)
//!
//! The R300 gate is covered exhaustively at unit-test level
//! (`wz-runtime-tokio::keyexpr_canon::tests` + `session_glue::tests`).
//! This Layer E fixture pins the END-TO-END plumbing: argv parse →
//! `check_outbound_keyexpr_pico_safe` → exit code → stderr line.
//! A regression that bypasses the argv gate (e.g. a refactor that
//! moves declare-spec construction before the validation loop) would
//! pass unit tests but fail this fixture, surfacing the integration
//! gap.

use std::process::{Command, Stdio};

use wz_integration_tests::common::wz_ap_demo_binary;

/// Run wz-ap-demo with a deliberately unreachable `--connect`
/// target. The R300 argv-gate fires before any connect attempt, so
/// the binary exits with code 2 (gate reject) before reaching the
/// driver loop — keeping the test fast and free of peer
/// dependencies.
fn run_demo_with_declare_flag(flag: &str, keyexpr: &str) -> (Option<i32>, String) {
    let demo = wz_ap_demo_binary();
    let output = Command::new(&demo)
        .args(["--connect", "127.0.0.1:1", flag, keyexpr])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn wz-ap-demo");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// R311oy — `--queryable` requires a paired `--reply`, and the demo validates
/// that pairing BEFORE the R300 argv gate runs; pass a dummy reply so the bad
/// keyexpr reaches the gate. The queryable keyexpr only enters the eager gate
/// when `queryable_spec` is `Some` (both `--queryable` and `--reply` present),
/// so the reply is mandatory to exercise the gate via this flag.
fn run_demo_queryable_gate(keyexpr: &str) -> (Option<i32>, String) {
    let demo = wz_ap_demo_binary();
    let output = Command::new(&demo)
        .args([
            "--connect",
            "127.0.0.1:1",
            "--queryable",
            keyexpr,
            "--reply",
            "x",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn wz-ap-demo");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo argv-only); Layer E runs via --ignored"]
fn r300_argv_gate_rejects_bug_three_via_key() {
    // R311oy — `--key` (routed subscriber declare) carries an outbound keyexpr
    // into the eager gate, replacing the retired `--declare-subscriber`.
    // R311y544 — `**/foo/*` left this list: it is not in the abort
    // family (a real pico canonizes it to itself, measured by
    // `layer3_keyexpr_canon::canon_pico_abort_family_is_single_byte_chunks_only_measured`),
    // so the gate correctly ACCEPTS it now and it can no longer stand
    // for a reject. `**/c/**` replaces it and widens the coverage to a
    // `**` closer.
    for pattern in ["**/c/*", "**/c/**", "**/a/b/*"] {
        let (exit, stderr) = run_demo_with_declare_flag("--key", pattern);
        assert_eq!(
            exit,
            Some(2),
            "pattern={pattern}: expected exit 2 (R300 argv reject), \
             got {exit:?}\n--- stderr ---\n{stderr}"
        );
        assert!(
            stderr.contains("rejected by R300 outbound DECLARE gate"),
            "pattern={pattern}: missing R300 reject log\n--- stderr ---\n{stderr}"
        );
        assert!(
            stderr.contains(pattern),
            "pattern={pattern}: offending keyexpr not surfaced in \
             diagnostic\n--- stderr ---\n{stderr}"
        );
    }
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo argv-only); Layer E runs via --ignored"]
fn r300_argv_gate_rejects_bug_three_via_queryable() {
    // R311oy — `--queryable` (routed queryable declare) replaced the retired
    // `--declare-queryable`; the eager gate names the `--queryable` flag.
    let (exit, stderr) = run_demo_queryable_gate("**/c/*");
    assert_eq!(
        exit,
        Some(2),
        "expected exit 2 (R300 argv reject), got {exit:?}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("--queryable"),
        "stderr must name the offending flag\nstderr={stderr}"
    );
    assert!(
        stderr.contains("**/c/*"),
        "stderr must name the offending keyexpr\nstderr={stderr}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo argv-only); Layer E runs via --ignored"]
fn r300_argv_gate_rejects_bug_three_via_declare_token() {
    let (exit, stderr) = run_demo_with_declare_flag("--declare-token", "**/c/*");
    assert_eq!(
        exit,
        Some(2),
        "expected exit 2 (R300 argv reject), got {exit:?}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("--declare-token"),
        "stderr must name the offending flag\nstderr={stderr}"
    );
    assert!(
        stderr.contains("**/c/*"),
        "stderr must name the offending keyexpr\nstderr={stderr}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo argv-only); Layer E runs via --ignored"]
fn r300_argv_gate_rejects_non_canonical_keyexpr() {
    // Grammar-violation arm of `OutboundKeyexprError::NotCanonical`
    // — empty chunk in this case. The same argv path catches the
    // structural reject in addition to the bug #3 family. R311oy — via
    // `--key` (the retired `--declare-subscriber` hook's replacement).
    let (exit, stderr) = run_demo_with_declare_flag("--key", "home//temp");
    assert_eq!(
        exit,
        Some(2),
        "expected exit 2 for empty-chunk reject, got {exit:?}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("rejected by R300 outbound DECLARE gate"),
        "missing R300 reject log\nstderr={stderr}"
    );
    assert!(
        stderr.contains("home//temp"),
        "stderr must name the offending keyexpr\nstderr={stderr}"
    );
}
