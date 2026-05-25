// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R63 — SCE B6 link-kind C11 emitter audit. Replaces the SCE B6
// validation that the deleted `wz-runtime-lwip` crate's compile-
// time codegen step performed, but reframes it as a focused Layer 3
// emit-output check instead of a host-build skeleton crate.
//
// R311ah — extends the audit to the session-layer sibling
// (sources/links/lwip_udp_session.scxml). Phase W landing of
// wz-runtime-lwip will compile both wrappers; this Layer 3 gate
// pins the codegen contract for both SCXMLs ahead of that landing.
//
// What this test proves:
//
//   1. `sce-codegen generate --language c11` against a `link`-kind
//      SCXML emits a single .h output file (the per-link wrapper
//      header).
//   2. The emit contains the load-bearing tokens from the B6
//      contract:
//        - the `#include "sce/forge/link.h"` pull-in of the
//          forge-runtime C contract
//        - the `<name>_link_t` typedef composing a `sce_forge_link_t`
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
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../vendor/sce/target/release/sce-codegen")
}

fn sce_workspace() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("../../vendor/sce")
}

fn link_scxml(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join(format!("../../sources/links/{name}.scxml"))
}

fn emit_link_c11(scxml_name: &str) -> Option<String> {
    let bin = sce_codegen_bin();
    if !bin.exists() {
        eprintln!(
            "skip: sce-codegen binary missing at {}; run scripts/build-sce.sh from the workspace root.",
            bin.display()
        );
        return None;
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
        .arg(link_scxml(scxml_name))
        .output()
        .expect("invoke sce-codegen");

    assert!(
        status.status.success(),
        "sce-codegen failed for {scxml_name} (exit {:?}):\nstderr: {}",
        status.status,
        String::from_utf8_lossy(&status.stderr)
    );

    let entries: Vec<_> = std::fs::read_dir(out_dir.path())
        .expect("read_dir tempdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("h"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one .h emit for {scxml_name}"
    );

    Some(std::fs::read_to_string(entries[0].path()).expect("read emit"))
}

fn assert_b6_tokens(emit: &str, tokens: &[&str]) {
    for token in tokens {
        assert!(
            emit.contains(token),
            "B6 emit missing load-bearing token `{token}`; full emit:\n{emit}"
        );
    }
}

#[test]
fn r63_sce_b6_link_emitter_emits_expected_c11_shape() {
    let Some(emit) = emit_link_c11("lwip_udp_scout") else {
        return;
    };

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
    assert_b6_tokens(&emit, &must_contain);
}

// R311ah — mirror gate for the session-layer link. Same B6-α
// contract, different SCXML body values: session uses `block`
// backpressure (reliability-bearing per session-fsm sec 6
// Reliability::Reliable baseline) where scout uses `drop`
// (best-effort scouting). Framer ref is `frame` (the zenoh
// transport frame codec wrapping session-fsm sec 6 outbound 3:
// init / open / close bodies) where scout uses `scout`.
#[test]
fn r311ah_sce_b6_link_emitter_emits_expected_session_c11_shape() {
    let Some(emit) = emit_link_c11("lwip_udp_session") else {
        return;
    };

    let must_contain = [
        r#"#include "sce/forge/link.h""#,
        "lwip_udp_session_link_t",
        "sce_forge_link_t driver;",
        r#"#define LWIP_UDP_SESSION_LINK_CLASS "udp""#,
        r#"#define LWIP_UDP_SESSION_LINK_FRAMER_REF "frame""#,
        r#"#define LWIP_UDP_SESSION_LINK_BACKPRESSURE "block""#,
        "lwip_udp_session_link_init",
        "lwip_udp_session_link_rx",
        "lwip_udp_session_link_tx",
        "lwip_udp_session_link_poll",
    ];
    assert_b6_tokens(&emit, &must_contain);
}
