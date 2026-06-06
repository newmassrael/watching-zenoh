// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-session-core build.rs — codegens the reassembly slot statechart.
//!
//! `sources/network/reassembly_slot.scxml` is the first `network/`-kind
//! statechart and the first SCE-generated statechart hosted in
//! wz-session-core (the AP/MCU-shared core crate). It is fully
//! script-engine-free: every effect is a `<sce:action>` native host-trait
//! call and every guard is a typed `_event.data` comparison, so the
//! emitted `ReassemblySlotPolicy<A>` carries no `IScriptEngine` and
//! compiles `#![no_std]` (proven by the sce-rust-runtime no_std CI lane).
//!
//! Unlike `wz-runtime-tokio/build.rs`, there is no script-name audit:
//! `<sce:action>` binds to the generated `ReassemblySlotActions` trait,
//! whose implementation is checked at compile time by the Rust type
//! system — an unimplemented action cannot link, so the build-script
//! grep that the Lua-bound FSMs need is unnecessary here.
//!
//! Codegen is gated on the `reassembly` feature (the module is elidable):
//! a build without the feature neither invokes sce-codegen nor includes
//! the emitted module.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Elidable: only codegen when the reassembly feature is active.
    if std::env::var("CARGO_FEATURE_REASSEMBLY").is_err() {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );

    let resource_dir = manifest_dir
        .join("../../sources/network")
        .canonicalize()
        .expect("canonicalize sources/network");

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

    println!("cargo:rerun-if-changed={}", resource_dir.display());
    // Rerun when the binary itself is rebuilt — covers a vendor/sce pin
    // bump + scripts/build-sce.sh rebuild during a round where the crate
    // sources did not otherwise change.
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    // The statechart imports fragment_chunk_schema.scxml (an event-schema
    // kind) via a relative `<sce:import>`; sce-codegen resolves it from
    // resource_dir, so only the statechart stem is emitted.
    emit_one(
        "reassembly_slot",
        &resource_dir,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
}

/// Invoke sce-codegen for one statechart stem and strip the file-head
/// inner attributes / inner doc comments that are illegal once the emit
/// is `include!`'d into a module scope (lib.rs restores the lint
/// suppressions as outer attributes on the wrapping module). Mirrors
/// `wz-runtime-tokio/build.rs::emit_one`.
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
        // Allocator-free emit (RFC §5.J.2): core::time::Duration, the
        // runtime's heapless SceString / StateChain aliases, NoOpHal, and
        // elision of the invoke / script-engine machinery. The slot FSM is
        // engine-free and flat (no parallel states), so it falls in the
        // supported no_std class and compiles for bare-metal targets; the
        // same emit also serves the AP profile (the aliases resolve to std
        // types under a std sce-rust-runtime). Without this, the emit pulls
        // ::std::vec::Vec / String / StdHal and will not build the no_std
        // wz-session-core crate.
        .arg("--no-std")
        .arg("--output-dir")
        .arg(out_dir)
        .arg(&scxml_path)
        .status()
        .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

    if !status.success() {
        panic!("sce-codegen generate failed for {stem} (exit {status:?})");
    }

    let emit_path = out_dir.join(format!("{stem}_sm.rs"));
    let original = std::fs::read_to_string(&emit_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", emit_path.display()));
    let stripped = original
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&emit_path, &stripped)
        .unwrap_or_else(|e| panic!("write {}: {e}", emit_path.display()));
}
