// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "routing-peer",
    feature = "transport-lowlatency",
))]

//! R2095 (open-debt item 513, its residual) — a capability the AGGREGATED mesh
//! dial cannot put on the wire is REFUSED at the command line, not dropped.
//!
//! ## What made the guard necessary
//!
//! R2095 wired `peer_loop`'s single-link dial to a whole `SessionOffer`, which
//! is what item 513 asked for. The AGGREGATING dial (`--max-links > 1`) is a
//! different entrypoint — `initiate_and_open_session_with_multilink`, which
//! takes `(pref, qos, band)` and stages no offer — so after that wiring the same
//! flag reaches the wire on one path and nothing on the other. Before R2095 it
//! reached nothing on BOTH, so the silence was at least uniform; a divergence
//! that depends on `--max-links` is the shape an operator cannot see.
//!
//! R311y506 met this exact shape with `--qos-band --max-links > 1` and answered
//! it by refusing the pair and naming the residual. This is the same answer for
//! the three capabilities R2095 added.
//!
//! ## Why a process test
//!
//! The rule is `argv -> exit status`. `capabilities_the_multilink_path_drops` is
//! a pure function and a unit test over it would pass whether or not `main` ever
//! consults it — open-debt item 479's class, which R2072 paid for once already.
//!
//! ## The controls are in the same test, and they are the harder half
//!
//! Every arm here fails somehow, so the exit STATUS cannot tell them apart: the
//! MESSAGE must (R2077). Two controls sit beside the refusal:
//!
//! * the SAME flag with `--max-links 1`, which is the configuration R2095 made
//!   work — a guard that fired there would refuse what this round just built;
//! * `--qos` with `--max-links 2`, which is the one capability the aggregation
//!   path DOES carry (`FaceSources.qos` -> `set_qos_offer` inside the
//!   `_with_multilink` entrypoints) — a guard that fired there would break the
//!   combination that path exists for.
//!
//! ## Why `tcp/192.0.2.1:9` is the listen address
//!
//! A `--peer` that binds successfully runs until a signal, so a control arm has
//! to reach a deterministic failure INSTEAD of the guard. `192.0.2.1` is
//! RFC 5737 TEST-NET-1: it is assigned to no interface anywhere, so `bind`
//! returns immediately and does so on every machine. A port number would not
//! give that — an ephemeral port succeeds and a privileged one depends on who
//! is running the test.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    cmd.args(args);
    cmd.output().expect("the demo binary runs")
}

/// RFC 5737 TEST-NET-1 — assigned to no interface, so a bind here fails fast
/// and identically everywhere. See the module doc.
const UNBINDABLE: &str = "tcp/192.0.2.1:9";

/// The fragment the refusal must produce, and the controls must not.
const DROPPED: &str = "cannot be offered with --max-links > 1";

/// What a control arm that got PAST the guard says instead: the bind of
/// [`UNBINDABLE`] failing. Asserting it is what separates "the guard did not
/// fire" from "the run never reached the guard" — two states an absent message
/// reports identically.
const REACHED_THE_BIND: &str = "Cannot assign requested address";

#[test]
fn the_binary_refuses_a_capability_the_aggregated_dial_would_drop() {
    let refused = run(&["--peer", UNBINDABLE, "--max-links", "2", "--lowlatency"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "the combination must be refused as a usage error (2), not surfaced \
         later as a bind failure.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(DROPPED) && stderr.contains("--lowlatency"),
        "the refusal must NAME the flag to drop; without it the operator is \
         told only that something is wrong.\n--- stderr ---\n{stderr}"
    );

    // ── CONTROL 1 ──────────────────────────────────────────────────────
    // The same flag on a SINGLE link is exactly what R2095 wired. A guard that
    // fired here would refuse the thing this round built.
    let single = run(&["--peer", UNBINDABLE, "--max-links", "1", "--lowlatency"]);
    let stderr = String::from_utf8_lossy(&single.stderr);
    assert!(
        !stderr.contains(DROPPED),
        "--lowlatency on a single-link peer is offered on the wire since R2095, \
         and this build refused it.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(REACHED_THE_BIND),
        "the single-link arm must have reached the BIND and failed THERE; \
         anything else means the run stopped earlier and the absent refusal \
         message proves nothing.\n--- stderr ---\n{stderr}"
    );

    // ── CONTROL 2 ──────────────────────────────────────────────────────
    // `--qos` is the one capability the aggregation path carries by its own
    // route, so it is deliberately absent from the dropped set.
    let qos = run(&["--peer", UNBINDABLE, "--max-links", "2", "--qos"]);
    let stderr = String::from_utf8_lossy(&qos.stderr);
    assert!(
        !stderr.contains(DROPPED),
        "--qos IS carried on the aggregated path (FaceSources.qos), so refusing \
         it breaks the combination that path exists for.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(REACHED_THE_BIND),
        "the qos arm must have reached the BIND too — an arm that stopped \
         earlier for some other reason would report a missing refusal it never \
         had the chance to hit.\n--- stderr ---\n{stderr}"
    );
}
