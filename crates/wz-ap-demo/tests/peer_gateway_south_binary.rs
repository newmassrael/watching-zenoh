// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// Item 751, step 7d -- `--gateway-south` reaches a PEER at the binary.
//
// ## Why a process test
//
// The flag is read in `main`, and the rule that refuses it on a run mode that
// cannot hold a partition is a line of `main` too. A unit test over the parser
// passes whether or not `main` consults it for a peer, which is what `--peer`
// did until this step: it answered the flag with a refusal. Only argv -> exit
// status witnesses the change.
//
// ## Why the arms are a pair
//
// Both arms exit 2, so the status cannot tell them apart; the message does. A
// run mode with no partition must be told that THIS is the reason, and a peer
// must reach the flag's own parse, which is where a malformed value is
// refused. A peer that was still refused by the mode rule would never get as
// far as the value, so the second arm separates "accepted" from "refused by the
// mode".
//
// Deterministic: the first arm names no role and the second is refused while
// the arguments are read, so no socket is opened and nothing is dialled.

#![cfg(all(feature = "routing-peer", feature = "zenoh-config"))]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-ap-demo"));
    cmd.args(args);
    cmd.output().expect("the demo binary runs")
}

/// The mode rule's diagnostic: the flag is held by the router hat and the peer.
const MODE_REFUSED: &str = "--gateway-south requires --router-hat or --peer";

/// A run mode that holds no partition refuses the flag, and says why.
#[test]
fn a_run_mode_without_a_partition_refuses_the_flag_by_name() {
    let out = run(&[
        "--listen",
        "tcp/127.0.0.1:0",
        "--gateway-south",
        r#""auto""#,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a node that cannot hold the partition must not run on `auto` while the operator asked \
         for another.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(MODE_REFUSED),
        "the refusal must name the modes that do hold one.\n--- stderr ---\n{stderr}"
    );
}

/// A peer is NOT refused by the mode rule: it reaches the value's own parse, which refuses a
/// partition that is no `gateway/south` document.
#[test]
fn a_peer_reaches_the_flags_own_parse() {
    let out = run(&[
        "--peer",
        "tcp/127.0.0.1:0",
        "--gateway-south",
        r#"{ "not": "a partition" }"#,
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a malformed partition is a usage error, not a node that runs on `auto`.\n--- stderr \
         ---\n{stderr}"
    );
    assert!(
        !stderr.contains(MODE_REFUSED),
        "--peer was still refused by the mode rule.\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("--gateway-south "),
        "the value's own parse must name the flag it refused.\n--- stderr ---\n{stderr}"
    );
}
