// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// R63 — SCE B6 link-kind C11 emitter audit. Replaces the SCE B6
// validation that the deleted `wz-runtime-coop` crate's compile-
// time codegen step performed, but reframes it as a focused Layer 3
// emit-output check instead of a host-build skeleton crate.
//
// R311ah — extends the audit to the session-layer sibling
// (sources/links/lwip_udp_session.scxml). Phase W landing of
// wz-runtime-coop will compile both wrappers; this Layer 3 gate
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
// What this test does NOT prove (vs. the deleted wz-runtime-coop
// crate):
//
//   - The emit does NOT compile into a real lwIP runtime here.
//     The host-build skeleton in wz-runtime-coop was likewise NOP
//     (no actual `udp_recv` / `udp_sendto` wired), so removing
//     the cc-compile step loses no production-grade behaviour —
//     only an audit artefact. Phase W's MCU cross-compile will
//     re-introduce a compiled lwIP runtime crate with real
//     driver code, and this Layer 3 test stays as the
//     codegen-side gate next to it.
//
// Where it runs. R63 kept these two tests in the always-run set on the
// sentence "CI runs the bootstrap before `cargo test`". That was a
// sentence, not a mechanism: the job that runs Layer C1 (`cargo test
// --workspace`) builds no sce-codegen, so there they printed a skip and
// passed, and no lane named them -- they have not run in any hosted job
// since the jobs were split. They are `#[ignore]`d now and owned by Layer
// B, which runs in the job that builds `vendor/sce/target/release/sce-codegen`
// and arms `WZ_SCE_ORACLE_REQUIRE` on its step. `scripts/run-ci.sh` selects
// them with `--ignored` and a count guard, and Layer E's sweep skips them by
// the `sce_b6` token in their names (they need no pico CLI and no demo).
//
// Skip behaviour is kept as the second line behind that lane's own
// `sce_codegen_ensure`: with the oracle absent a local `--ignored` run prints
// a remediation hint and passes, and `skip_or_fail` turns the same absence into
// a failure wherever `WZ_SCE_ORACLE_REQUIRE` is set.

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

/// The skip, or a FAILURE when the job that provisions sce-codegen declared it
/// required. `WZ_SCE_ORACLE_REQUIRE` is the variable `verify-codegen.sh` already
/// reads for the same oracle, so one switch means one thing across both consumers.
/// Open-debt item 776: without a door a skip and a pass are the same line of
/// output.
fn skip_or_fail(why: &str) -> Option<String> {
    if std::env::var("WZ_SCE_ORACLE_REQUIRE").is_ok_and(|v| !v.is_empty()) {
        panic!(
            "{why}; WZ_SCE_ORACLE_REQUIRE is set, so the job that provisions the oracle did not"
        );
    }
    eprintln!("skip: {why}; set WZ_SCE_ORACLE_REQUIRE=1 to make this a failure");
    None
}

fn emit_link_c11(scxml_name: &str) -> Option<String> {
    let bin = sce_codegen_bin();
    if !bin.exists() {
        return skip_or_fail(&format!(
            "sce-codegen binary missing at {}; run scripts/build-sce.sh from the workspace root",
            bin.display()
        ));
    }

    // ABSENT may skip; FOREIGN may not. The two are not the same answer, and
    // the existence test above cannot tell them apart. A binary built from
    // another vendor/sce revision emits confidently from that revision's
    // templates, so this test would compare wz's link SCXML against an SCE it
    // is not pinned to and report the difference as a wz defect — the shape
    // R311y774 walked into with a stale demo binary and R311y776 had to
    // retract. Refuse, and name the one command that repairs it: a test cannot
    // rebuild the toolchain it is testing with.
    match wz_codegen_build::sce_codegen_provenance(&sce_workspace()) {
        wz_codegen_build::Provenance::Matches => {}
        // Unverifiable is the first-clone / tarball case the skip above serves;
        // it is not evidence of a foreign binary, so it stays a skip.
        v @ wz_codegen_build::Provenance::Unverifiable => return skip_or_fail(&v.explain()),
        v => panic!("{}", v.explain()),
    }

    let out_dir = tempfile::tempdir().expect("create tempdir");
    let status = Command::new(&bin)
        // R311y756 — the FOURTH site that spawns sce-codegen and therefore the
        // fourth that had to name its resource directories. `--workspace-root`
        // does not carry the Jinja2 templates or the XSD schemas; those resolve
        // against wherever the binary believes it lives, which is a fact about
        // the machine. On a build host this test died with `Cannot find Jinja2
        // templates` while passing here — the shape this workspace calls "a gate
        // verified here may not run there".
        .env(
            "SCE_TEMPLATE_DIR",
            std::env::var_os("SCE_TEMPLATE_DIR").unwrap_or_else(|| {
                sce_workspace()
                    .join("tools")
                    .join("codegen")
                    .join("templates")
                    .into_os_string()
            }),
        )
        .env(
            "SCE_SCHEMAS_DIR",
            std::env::var_os("SCE_SCHEMAS_DIR")
                .unwrap_or_else(|| sce_workspace().join("schemas").into_os_string()),
        )
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
#[ignore = "binary-dep e2e (vendor/sce sce-codegen built by scripts/build-sce.sh); Layer B runs via --ignored"]
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
#[ignore = "binary-dep e2e (vendor/sce sce-codegen built by scripts/build-sce.sh); Layer B runs via --ignored"]
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
