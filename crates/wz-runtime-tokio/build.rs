// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-runtime-tokio build.rs — codegens the AP reassembly buffer-pool.
//!
//! R311in — the tokio (AP / Linux) host's reassembly slot-pool
//! dimensions + runtime knobs are sourced from
//! `sources/network/reassembly_pool_ap.scxml` (an `sce:kind="buffer-pool"`
//! document, the SSOT) rather than hand-transcribed into
//! `session_glue.rs`. SCE owns the buffer-pool schema + codegen; its
//! `sce-codegen` emits the spec-anchored `SLOT_COUNT` / `SLOT_SIZE` /
//! `MAX_FRAGMENTS_PER_MESSAGE` / `REASSEMBLY_TIMEOUT_MS` / `PER_PEER_QUOTA`
//! constants the host `ReassemblyDispatcher` consumes (see the scxml
//! header for the SSOT rationale).
//!
//! The AP profile owns its deploy policy here; the MCU profile mirrors
//! this with `wz-runtime-lwip/build.rs` codegen'ing `reassembly_pool_mcu`
//! — wz-session-core stays profile-agnostic (the generic dispatcher
//! mechanism only). The sce-codegen invocation mirrors
//! `wz-session-core/build.rs::emit_one`; the lone deltas are the
//! buffer-pool output filename (`{stem}.rs`, not the statechart
//! `{stem}_sm.rs`) and the trailing `generated_tests` strip (see
//! `emit_buffer_pool`).

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
        "reassembly_pool_ap",
        &resource_dir,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
}

/// Invoke sce-codegen for one `sce:kind="buffer-pool"` document, then
/// post-process the emit for `include!`'ing into a module scope.
///
/// Two transforms (both mirror the spirit of
/// `wz-session-core/build.rs::emit_one`):
///   1. Strip the file-head `#![...]` inner attributes / `//!` inner doc
///      comments — illegal once `include!`'d mid-module; lib.rs restores
///      the lint allows as outer attributes on the wrapping module.
///   2. Strip the trailing `#[cfg(test)] mod generated_tests { ... }`.
///      That module exercises SCE's §5.E DMA slot-pool API (which the
///      AP host does not use — it drives its own `ReassemblyDispatcher`)
///      and constructs the pool inline (`[[u8; SLOT_SIZE]; SLOT_COUNT]`
///      = ~2 MiB at AP dims), which would overflow a default test-thread
///      stack. SCE's own CI covers those tests; the wz suite tests the
///      dispatcher, not SCE's emitted pool API.
///
/// Unlike statechart kinds (`{stem}_sm.rs`), the buffer-pool kind emits
/// `{stem}.rs`.
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
        // Allocator-free emit: the buffer-pool template uses only
        // `core::` types under this flag, so the same emit serves a
        // future no_std consumer (and stays symmetric with the MCU
        // profile's `reassembly_pool_mcu` codegen).
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

    // Transform 2: find the trailing `mod generated_tests` and cut from
    // its leading `#[cfg(test)]` attribute onward (the module is the last
    // block in the template, so this also drops everything after it).
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

    // Transform 1: strip inner attributes / inner doc comments.
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
