// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared build-script helper for watching-zenoh SCE codegen.
//!
//! R311in — one source for the two things every codegen build script
//! does: locate the vendored `sce-codegen` binary, and post-process its
//! emit so the generated file can be `include!`'d into a module scope.
//!
//! Two emit kinds:
//! - [`Codegen::emit_statechart`] — `sce:kind="statechart"` →
//!   `$OUT_DIR/{stem}_sm.rs`; strips the file-head `#![...]` inner
//!   attributes / `//!` inner doc comments (illegal mid-module; the
//!   consuming `pub mod` restores the lint allows as outer attributes).
//! - [`Codegen::emit_buffer_pool`] — `sce:kind="buffer-pool"` →
//!   `$OUT_DIR/{stem}.rs` (note: NOT `_sm.rs`); strips the inner
//!   attributes AND the trailing `#[cfg(test)] mod generated_tests`
//!   block (it constructs the pool inline — a multi-MiB stack allocation
//!   at large dims — and exercises SCE's §5.E DMA-pool API the wz
//!   dispatcher does not use; SCE's own CI covers those tests).
//!
//! The strip transforms are byte-identical to the per-build-script logic
//! they replace, so regenerated emits are unchanged.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the vendored `sce-codegen` binary under `sce_workspace`
/// (`<sce_workspace>/target/release/sce-codegen[.exe]`), accounting for the
/// host executable suffix (`std::env::consts::EXE_SUFFIX` = `.exe` on Windows,
/// empty on Unix). Panics with the `build-sce.sh` directive if absent.
///
/// R311y20 — the SINGLE source of the sce-codegen binary path for EVERY wz
/// build script. The statechart [`Codegen::from_manifest`] AND the switchboard
/// `--emit-ast` build scripts (`wz-ap-demo-app`, `wz-switchboard-example`,
/// `deploy/mcu-noheap-probe`) all route through here, so the `EXE_SUFFIX` rule
/// — and any future path/lookup change — lives in one place rather than five
/// hand-copied blocks (R311y17 fixed only this crate's copy; the other three
/// still hardcoded the suffix-less path and would panic on Windows). Callers
/// emit their own `cargo:rerun-if-changed` on the returned path.
pub fn locate_sce_codegen(sce_workspace: &Path) -> PathBuf {
    let bin = sce_workspace
        .join("target/release")
        .join(format!("sce-codegen{}", std::env::consts::EXE_SUFFIX));
    if !bin.exists() {
        panic!(
            "sce-codegen binary not found at {}\n\
             run `scripts/build-sce.sh` from the wz workspace root to build it \
             (vendor pin: see vendor/sce HEAD).",
            bin.display()
        );
    }
    bin
}

/// A located `sce-codegen` binary + its SCE workspace root, ready to
/// drive one or more emits into `$OUT_DIR`.
pub struct Codegen {
    sce_codegen: PathBuf,
    sce_workspace: PathBuf,
}

impl Codegen {
    /// Locate the vendored `sce-codegen` from a crate's manifest dir
    /// (`<manifest>/../../vendor/sce/target/release/sce-codegen`),
    /// panicking with the `build-sce.sh` directive if absent. Emits the
    /// binary's `rerun-if-changed` so a vendor/sce pin bump + rebuild
    /// re-triggers codegen even when the crate sources are unchanged.
    pub fn from_manifest(manifest_dir: &Path) -> Self {
        let sce_workspace = manifest_dir
            .join("../../vendor/sce")
            .canonicalize()
            .expect("canonicalize vendor/sce");

        let sce_codegen = locate_sce_codegen(&sce_workspace);
        println!("cargo:rerun-if-changed={}", sce_codegen.display());

        Self {
            sce_codegen,
            sce_workspace,
        }
    }

    /// Codegen one `sce:kind="statechart"` document into
    /// `$OUT_DIR/{stem}_sm.rs`, stripping inner attributes / inner doc
    /// comments. `resource_dir` is the directory holding `{stem}.scxml`
    /// (plus any `<sce:import>` siblings sce-codegen resolves relatively).
    pub fn emit_statechart(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        self.run_generate(stem, resource_dir, out_dir);
        let emit_path = out_dir.join(format!("{stem}_sm.rs"));
        let original = read(&emit_path);
        let stripped = strip_inner_attrs(original.lines());
        write(&emit_path, &stripped);
    }

    /// Codegen one `sce:kind="buffer-pool"` document into
    /// `$OUT_DIR/{stem}.rs`, stripping inner attributes AND the trailing
    /// `generated_tests` module (see the module docs for why).
    pub fn emit_buffer_pool(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        self.run_generate(stem, resource_dir, out_dir);
        let emit_path = out_dir.join(format!("{stem}.rs"));
        let original = read(&emit_path);
        let lines: Vec<&str> = original.lines().collect();
        let end = cut_generated_tests(&lines);
        let stripped = strip_inner_attrs(lines[..end].iter().copied());
        write(&emit_path, &stripped);
    }

    /// Allocator-free emit (`--no-std`): the buffer-pool / statechart
    /// templates use only `core::` types under this flag, so one emit
    /// serves both the std (AP) and heapless (MCU) runtimes.
    fn run_generate(&self, stem: &str, resource_dir: &Path, out_dir: &Path) {
        let scxml_path = resource_dir.join(format!("{stem}.scxml"));
        let status = Command::new(&self.sce_codegen)
            .arg("--workspace-root")
            .arg(&self.sce_workspace)
            .arg("generate")
            .arg("--language")
            .arg("rust")
            .arg("--no-std")
            .arg("--output-dir")
            .arg(out_dir)
            .arg(&scxml_path)
            .status()
            .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

        if !status.success() {
            panic!("sce-codegen generate failed for {stem} (exit {status:?})");
        }
    }
}

/// Drop the trailing `#[cfg(test)] mod generated_tests { ... }` block —
/// returns the line index to truncate at (the block is the last in the
/// template, so this also drops everything after it). Cuts from the
/// leading `#[...]` attribute(s) above the `mod generated_tests` line.
fn cut_generated_tests(lines: &[&str]) -> usize {
    match lines
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
    }
}

/// Strip file-head `#![...]` inner attributes and `//!` inner doc
/// comments — illegal once the emit is `include!`'d mid-module.
fn strip_inner_attrs<'a>(lines: impl Iterator<Item = &'a str>) -> String {
    lines
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()))
}
