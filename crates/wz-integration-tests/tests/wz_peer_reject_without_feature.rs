// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qg — catalog-truthfulness gate for the `routing-peer` feature: a
//! `wz-ap-demo` built WITHOUT `routing-peer` must REJECT `--peer` (exit 2 + a
//! message naming the feature), not silently no-op. This keeps the feature claim
//! and the binary in lockstep — the `#[cfg(not(feature = "routing-peer"))]`
//! interception in `main.rs` is the cfg site that makes "mesh topology" a
//! truthful catalog atom.
//!
//! Distinct from `wz_peer_mesh` (the positive e2e), which needs the
//! `--features routing-peer` binary: this NEGATIVE test needs the DEFAULT binary,
//! so it rides its own self-contained run-ci lane that builds the default binary
//! immediately before running it — the two never share a binary build.

use std::process::Command;

use wz_integration_tests::common::wz_ap_demo_binary;

#[test]
#[ignore = "binary-dep e2e (DEFAULT wz-ap-demo build); Layer E runs via --ignored"]
fn wz_peer_without_feature_rejects_with_exit_2() {
    let demo = wz_ap_demo_binary();
    // `--peer` carries a value so `parse_pair` matches it (the reject arm runs
    // before any bind, so the address is never used — any string is fine).
    let output = Command::new(&demo)
        .arg("--peer")
        .arg("127.0.0.1:0")
        .output()
        .expect("spawn wz-ap-demo --peer");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a default (no routing-peer) build must reject --peer with exit 2\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("requires the `routing-peer` feature"),
        "the reject message must name the missing feature\n--- stderr ---\n{stderr}"
    );
}
