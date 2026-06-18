// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qa — catalog-truthfulness gate for the `routing-router` feature: a
//! `wz-ap-demo` built WITHOUT `routing-router` must REJECT `--router` (exit 2 +
//! a message naming the feature), not silently no-op. This keeps the feature
//! claim and the binary in lockstep — the `#[cfg(not(feature = "routing-router"))]`
//! interception in `main.rs` is the cfg site that makes "router topology" a
//! truthful catalog atom.
//!
//! Distinct from `wz_router_multi_peer` (the positive e2e), which needs the
//! `--features routing-router` binary: this NEGATIVE test needs the DEFAULT
//! binary, so it rides its own self-contained run-ci lane (Layer E4) that builds
//! the default binary immediately before running it — the two never share a
//! binary build, so neither can clobber the other.

use std::process::Command;

use wz_integration_tests::common::wz_ap_demo_binary;

#[test]
#[ignore = "binary-dep e2e (DEFAULT wz-ap-demo build); Layer E4 runs via --ignored"]
fn wz_router_without_feature_rejects_with_exit_2() {
    let demo = wz_ap_demo_binary();
    // `--router` carries a value so `parse_pair` matches it (the reject arm runs
    // before any bind, so the address is never used — any string is fine).
    let output = Command::new(&demo)
        .arg("--router")
        .arg("127.0.0.1:0")
        .output()
        .expect("spawn wz-ap-demo --router");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a default (no routing-router) build must reject --router with exit 2\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("requires the `routing-router` feature"),
        "the reject message must name the missing feature\n--- stderr ---\n{stderr}"
    );
}
