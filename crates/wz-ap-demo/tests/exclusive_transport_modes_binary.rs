// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R2087 (open-debt item 506) — the qos x lowlatency exclusivity reaches the
// BINARY.
//
// ## Why a process test and not a unit test
//
// Wiring `--qos` into `initiator_offer` made that function fallible, and a unit
// test over it would pass whether or not `main` ever consults the rule. That is
// open-debt item 479's class, and R2072 paid for it once already: a verdict a
// shipping surface never asks is not a verdict. So the seam witnessed here is
// argv -> exit status, and only running the binary witnesses it.
//
// ## Why the control arms are half the test
//
// Every arm below exits 2, so the exit STATUS cannot tell them apart — the
// message must, which is R2077's lesson stated as a fixture. A rejection that
// fired on `--qos` alone, or on `--lowlatency` alone, would be a demo that
// refuses two configurations zenoh runs happily; a rejection that never fired
// would be one that picks a winner behind the operator's back. The single-flag
// arms are what separate those from the pair.
//
// ## Why it is feature-independent
//
// `--qos` on a build without `transport-qos` is INERT — the offer builder drops
// the mode. The command line is contradictory either way, though, and answering
// a contradiction with a running session is worse than refusing it, so the rule
// is not compiled out. This file therefore carries no feature gate and runs in
// the crate's default build, which is also the build `pre-push` runs.
//
// Deterministic by construction: no role flag is given, so no socket is opened,
// nothing is dialled and no clock is read. That the pair is reported even
// though the command line names no role is itself the ordering proof — the
// refusal lands before the role parse, and therefore before any dial.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    cmd.args(args);
    cmd.output().expect("the demo binary runs")
}

/// The diagnostic the pair must produce, and the two single flags must not.
const PAIR_REFUSED: &str = "--qos and --lowlatency are mutually exclusive";

/// The pair is refused; each flag ALONE is not refused for that reason.
///
/// Stated as one test so neither half can be read without the other, the same
/// shape `check_topology_binary`'s verdict pair uses.
#[test]
fn the_binary_refuses_qos_with_lowlatency_and_neither_flag_alone() {
    let pair = run(&["--qos", "--lowlatency"]);
    let stderr = String::from_utf8_lossy(&pair.stderr);
    assert_eq!(
        pair.status.code(),
        Some(2),
        "--qos --lowlatency must exit 2 (usage error).\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(PAIR_REFUSED),
        "the pair was refused without naming the pair, so the operator cannot \
         tell which flag to drop.\n--- stderr ---\n{stderr}"
    );

    // ── CONTROL ────────────────────────────────────────────────────────
    // Both of these ALSO exit 2 (no role flag), which is why the assertion is
    // on the message: a rule that fired on either flag alone would be invisible
    // to an exit-status check.
    for alone in [["--qos"], ["--lowlatency"]] {
        let out = run(&alone);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains(PAIR_REFUSED),
            "{alone:?} alone is a configuration zenoh runs, and this build \
             refused it as the exclusive pair.\n--- stderr ---\n{stderr}"
        );
        assert!(
            stderr.contains("exactly one of --listen / --connect is required"),
            "{alone:?} alone should reach the role parse and be refused THERE; \
             stopping earlier would mean the mode rule is still swallowing \
             it.\n--- stderr ---\n{stderr}"
        );
    }
}

/// The refusal survives a real role, and lands before the dial.
///
/// The arm above proves the rule runs before the role parse; this one proves
/// the role parse does not somehow overtake it. `tcp/127.0.0.1:1` is never
/// dialled — a demo that reached the dial would report a refused connection and
/// exit 1, so the exit status here is load-bearing rather than incidental.
#[test]
fn the_refusal_precedes_the_dial_a_role_would_have_started() {
    let out = run(&[
        "--connect",
        "tcp/127.0.0.1:1",
        "--qos",
        "--lowlatency",
        "--key",
        "demo/exclusive",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the pair must be refused as a usage error (2), not surfaced as an open \
         failure (1) after a dial.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(PAIR_REFUSED),
        "the refusal lost its diagnostic once a role was on the command \
         line.\n--- stderr ---\n{stderr}"
    );
}
