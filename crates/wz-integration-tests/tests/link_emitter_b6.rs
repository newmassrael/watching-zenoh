// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R63 — SCE B6 link-kind C11 emitter audit. Replaces the SCE B6
// validation that the deleted `wz-runtime-lwip` crate's compile-
// time codegen step performed, but reframes it as a focused Layer 3
// emit-output check instead of a host-build skeleton crate.
//
// What this test proves:
//
//   1. `sce-codegen generate --language c11` against
//      `sources/links/lwip_udp_scout.scxml` emits a single .h
//      output file (the per-link wrapper header).
//   2. The emit contains the load-bearing tokens from the B6
//      contract:
//        - the `#include "sce/forge/link.h"` pull-in of the
//          forge-runtime C contract
//        - the `_link_t` typedef composing a `sce_forge_link_t`
//          driver handle
//        - the LINK_CLASS / FRAMER_REF / BACKPRESSURE macros
//          round-tripping the SCXML's <sce:link-class> /
//          <sce:framer ref="..."/> / <sce:backpressure> bodies.
//
// What this test does NOT prove (vs. the deleted wz-runtime-lwip
// crate):
//
//   - The emit does NOT compile into a real lwIP runtime here.
//     The host-build skeleton in wz-runtime-lwip was likewise NOP
//     (no actual `udp_recv` / `udp_sendto` wired), so removing
//     the cc-compile step loses no production-grade behaviour —
//     only an audit artefact. Phase W's MCU cross-compile will
//     re-introduce a compiled lwIP runtime crate with real
//     driver code, and this Layer 3 test stays as the
//     codegen-side gate next to it.
//
// Skip behaviour: if `vendor/sce/target/release/sce-codegen` is
// not built (developer ran `cargo test` on a fresh clone), the
// test prints a remediation hint and short-circuits with a
// pass-with-warning. R63 keeps the test in the always-run set
// because `scripts/build-sce.sh` is the documented bootstrap;
// the local-only skip is for first-clone ergonomics, not for
// CI (CI runs the bootstrap before `cargo test`).

use std::path::PathBuf;
use std::process::Command;

fn sce_codegen_bin() -> PathBuf {
    // CARGO_MANIFEST_DIR points at `crates/wz-integration-tests/`.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../vendor/sce/target/release/sce-codegen")
}

fn sce_workspace() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../vendor/sce")
}

fn link_scxml() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../sources/links/lwip_udp_scout.scxml")
}

#[test]
fn r63_sce_b6_link_emitter_emits_expected_c11_shape() {
    let bin = sce_codegen_bin();
    if !bin.exists() {
        eprintln!(
            "skip: sce-codegen binary missing at {}; run scripts/build-sce.sh from the workspace root.",
            bin.display()
        );
        return;
    }

    let out_dir = tempfile::tempdir().expect("create tempdir");
    let status = Command::new(&bin)
        .arg("--workspace-root")
        .arg(sce_workspace())
        .arg("generate")
        .arg("--language")
        .arg("c11")
        .arg("--output-dir")
        .arg(out_dir.path())
        .arg(link_scxml())
        .output()
        .expect("invoke sce-codegen");

    assert!(
        status.status.success(),
        "sce-codegen failed (exit {:?}):\nstderr: {}",
        status.status,
        String::from_utf8_lossy(&status.stderr)
    );

    // Exactly one .h file in the output (the per-link wrapper).
    let entries: Vec<_> = std::fs::read_dir(out_dir.path())
        .expect("read_dir tempdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("h"))
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one .h emit");

    let emit_path = entries[0].path();
    let emit = std::fs::read_to_string(&emit_path).expect("read emit");

    // Load-bearing tokens from the B6 contract.
    let must_contain = [
        // pulls in the forge-runtime C contract
        r#"#include "sce/forge/link.h""#,
        // per-deploy wrapper composes the driver handle
        "lwip_udp_scout_link_t",
        "sce_forge_link_t driver;",
        // round-tripped SCXML body values
        r#"#define LWIP_UDP_SCOUT_LINK_CLASS "udp""#,
        r#"#define LWIP_UDP_SCOUT_LINK_FRAMER_REF "frame""#,
        r#"#define LWIP_UDP_SCOUT_LINK_BACKPRESSURE "drop""#,
        // 4 inline fns the wrapper exposes
        "lwip_udp_scout_link_init",
        "lwip_udp_scout_link_rx",
        "lwip_udp_scout_link_tx",
        "lwip_udp_scout_link_poll",
    ];
    for token in must_contain {
        assert!(
            emit.contains(token),
            "B6 emit missing load-bearing token `{token}`; full emit:\n{emit}"
        );
    }
}
