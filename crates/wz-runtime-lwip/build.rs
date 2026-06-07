// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-runtime-lwip build.rs — codegens the MCU reassembly buffer-pool.
//!
//! R311in carry[3] — the MCU sibling of `wz-runtime-tokio/build.rs`. The
//! lwIP (MCU / bare-metal) host's reassembly slot-pool dims + runtime
//! knobs are sourced from `sources/network/reassembly_pool_mcu.scxml`
//! (an `sce:kind="buffer-pool"` document, the SSOT) and consumed by the
//! no-alloc `reassembly_rx` seam. SCE owns the buffer-pool schema +
//! codegen; this script invokes `sce-codegen` exactly as the AP profile
//! does (same emit_one shape, same `{stem}.rs` buffer-pool output, same
//! `generated_tests` strip). The build script runs on the HOST, so it
//! invokes the host sce-codegen binary regardless of the crate's MCU
//! cross-compile target.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Elidable: a build without `reassembly` neither invokes sce-codegen
    // nor includes the emitted module (the wrapper in lib.rs is gated on
    // the same feature).
    if std::env::var("CARGO_FEATURE_REASSEMBLY").is_err() {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );

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
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    let resource_dir = manifest_dir
        .join("../../sources/network")
        .canonicalize()
        .expect("canonicalize sources/network");
    println!("cargo:rerun-if-changed={}", resource_dir.display());

    emit_buffer_pool(
        "reassembly_pool_mcu",
        &resource_dir,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
}

/// Invoke sce-codegen for one `sce:kind="buffer-pool"` document, then
/// post-process the emit for `include!`'ing into a module scope.
///
/// Identical to `wz-runtime-tokio/build.rs::emit_buffer_pool` (see there
/// for the two-transform rationale): strip the file-head `#![...]` inner
/// attributes, and strip the trailing SCE-pool-API `generated_tests`
/// module (it constructs the pool inline and exercises the §5.E DMA pool
/// API the wz dispatcher does not use). The buffer-pool kind emits
/// `{stem}.rs` (not the statechart `{stem}_sm.rs`).
fn emit_buffer_pool(
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
        // Allocator-free emit: the MCU profile is #![no_std]; the
        // buffer-pool template uses only `core::` types under this flag.
        .arg("--no-std")
        .arg("--output-dir")
        .arg(out_dir)
        .arg(&scxml_path)
        .status()
        .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

    if !status.success() {
        panic!("sce-codegen generate failed for {stem} (exit {status:?})");
    }

    let emit_path = out_dir.join(format!("{stem}.rs"));
    let original = std::fs::read_to_string(&emit_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", emit_path.display()));

    let lines: Vec<&str> = original.lines().collect();

    // Cut the trailing `#[cfg(test)] mod generated_tests { ... }` block
    // (the last block in the template) from its leading attribute onward.
    let end = match lines
        .iter()
        .position(|l| l.trim_start().starts_with("mod generated_tests"))
    {
        Some(i) => {
            let mut start = i;
            while start > 0 && lines[start - 1].trim_start().starts_with("#[") {
                start -= 1;
            }
            start
        }
        None => lines.len(),
    };

    // Strip inner attributes / inner doc comments (illegal once
    // `include!`'d mid-module; lib.rs restores the lint allows as outer
    // attributes on the wrapping module).
    let stripped = lines[..end]
        .iter()
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&emit_path, &stripped)
        .unwrap_or_else(|e| panic!("write {}: {e}", emit_path.display()));
}
