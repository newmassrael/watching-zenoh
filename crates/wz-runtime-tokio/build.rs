// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-runtime-tokio build.rs — R54 entry. Codegens the statechart-kind
// SCXML at `sources/session/session_fsm_unicast.scxml` into
// `$OUT_DIR/session_fsm_unicast_sm.rs`.
//
// Pipeline choice. `sce_build::compile_forge_with_imports` is the
// in-process API for forge-kind SCXMLs (codec / link / algorithm /
// etc.). Statechart-kind SCXMLs route through a different pipeline
// internally (SCXMLParser + analyzer + generator chain) and the
// `sce-codegen generate` CLI command is the public entry that wires
// the chain — `sce_build` does not yet expose an equivalent
// in-process API for the statechart path. The build script therefore
// shells out to the vendored binary, supplying `--workspace-root` so
// the §6.2.6 template-hash anchor embeds the real hash (R53 closure).
//
// The binary must exist at `vendor/sce/target/release/sce-codegen`;
// see `scripts/build-sce.sh`. We fail-fast with a clear remedy when
// it is missing instead of trying to invoke `cargo build` recursively
// from inside the build script (which deadlocks on nested cargo locks
// when the wz workspace is itself in a `cargo build`).

use std::path::{Path, PathBuf};
use std::process::Command;

const STATECHARTS: &[&str] = &["session_fsm_unicast"];

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );

    let resource_dir = manifest_dir
        .join("../../sources/session")
        .canonicalize()
        .expect("canonicalize sources/session");

    let sce_workspace = manifest_dir
        .join("../../vendor/sce")
        .canonicalize()
        .expect("canonicalize vendor/sce");

    let sce_codegen = sce_workspace.join("target/release/sce-codegen");
    if !sce_codegen.exists() {
        panic!(
            "sce-codegen binary not found at {}\n\
             run `scripts/build-sce.sh` from the wz workspace root \
             to build it (vendor pin: see vendor/sce HEAD).",
            sce_codegen.display()
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", resource_dir.display());
    // Rerun when the binary itself is rebuilt — covers `git -C vendor/sce
    // checkout <new-pin>` + `scripts/build-sce.sh` rebuilds during a
    // round where the wz crate sources did not otherwise change.
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    for stem in STATECHARTS {
        emit_one(stem, &resource_dir, &out_dir, &sce_codegen, &sce_workspace);
    }
}

fn emit_one(
    stem: &str,
    resource_dir: &Path,
    out_dir: &Path,
    sce_codegen: &Path,
    sce_workspace: &Path,
) {
    let scxml_path = resource_dir.join(format!("{stem}.scxml"));

    let status = Command::new(sce_codegen)
        .arg("--workspace-root")
        .arg(sce_workspace)
        .arg("generate")
        .arg("--language")
        .arg("rust")
        .arg("--output-dir")
        .arg(out_dir)
        .arg(&scxml_path)
        .status()
        .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

    if !status.success() {
        panic!("sce-codegen generate failed for {stem} (exit {status:?})");
    }

    // R40 carry strip extended for statechart emit — SCE codegen emits
    // a full block of `#![allow(...)]` lints + `#![doc = "SCE-MAP:..."]`
    // marker at file head. None of those inner attributes are legal
    // once the file is `include!()`'d into a module scope. The lib.rs
    // wrapping module restores the lint allows as OUTER attributes
    // attached to `pub mod session_fsm_unicast { ... }`; the SCE-MAP
    // inner is information-redundant with the adjacent `// SCE-MAP:`
    // line as documented in wz-codecs/build.rs.
    let emit_path = out_dir.join(format!("{stem}_sm.rs"));
    let original = std::fs::read_to_string(&emit_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", emit_path.display()));
    let stripped = original
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            // Both `#![...]` attr-style inner forms AND `//!` inner doc
            // comments are illegal at item position inside a `mod` block.
            // The build script strips both; lib.rs restores the lint
            // suppressions as outer attributes on the wrapping module.
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&emit_path, &stripped)
        .unwrap_or_else(|e| panic!("write {}: {e}", emit_path.display()));
}
