// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-noheap-probe build.rs.
//
// Two responsibilities:
//
//  1. Places `memory.x` into OUT_DIR so cortex-m-rt's bundled `link.x`
//     can `INCLUDE memory.x` during the final link. cortex-m-rt's own
//     build.rs adds `OUT_DIR` to `rustc-link-search` if its
//     `cortex-m-rt` rlib is being linked; our `cargo:rustc-link-search`
//     directive here is symmetric defence-in-depth so a manual cargo
//     invocation that disables build-script propagation still finds
//     memory.x.
//
//  2. (ⓓ) Orchestrates the switchboard VALUE path for the thermostat
//     machine — the no_std / allocator-free mirror of
//     wz-switchboard-example's build.rs:
//       a. sce-codegen `-l rust --no-std --emit-ast` over each source doc
//          (thermostat.scxml -> thermostat_sm.rs + AST;
//          temp_reading_schema.scxml -> AST;
//          temp_reading_codec.scxml -> temp_reading_codec.rs + AST);
//       b. wz-switchboard-codegen over wz-switchboard.yaml + the three
//          ASTs -> dispatch_switchboard.rs.
//     main.rs `include!`s the machine + codec + dispatch into `#![no_std]`
//     modules. The CRITICAL difference from the example is `--no-std`, so
//     SCE emits an allocator-free `Engine<ThermostatPolicy>` (no
//     `session_id`/`invoke_id`/`child_session_id` String fields — SCE pin
//     aea1a7b50+), and the codec is compiled without its `alloc` feature
//     so only the `SceCursor` decode path links. A clean link in a binary
//     with no `#[global_allocator]` is the whole-program proof that
//     wire-decode -> typed-inject is heap-free.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_switchboard_codegen::{
    generate, parse_codec_facts, parse_event_schema_facts, parse_machine_facts, GenInput,
};
use wz_switchboard_schema::SwitchboardSpec;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // R311bm-m0: thumbv6m-none-eabi (Cortex-M0/M0+, e.g. QEMU
    // `microbit` / nrf51822) needs a 16 KB RAM + 256 KB FLASH
    // memory map instead of the mps2 family's 4 MB / 4 MB. Pick
    // the matching file by inspecting cargo's `TARGET` env var.
    //
    // The crate-root variant files are named `memory-mps2.x` and
    // `memory-microbit.x` — never `memory.x` at the crate root —
    // because rust-lld resolves `INCLUDE memory.x` in `link.x`
    // by checking the link script's source directory (which on
    // cortex-m-rt 0.7 paths back to this crate's manifest dir)
    // BEFORE walking `-L` search paths. A `memory.x` at the
    // crate root shadows the OUT_DIR copy and silently feeds
    // the wrong layout to the linker (verified empirically:
    // `_stack_start` stayed at the mps2 4 MB value even when
    // OUT_DIR contained the 16 KB microbit file). Renaming the
    // crate-root file forces the linker to resolve INCLUDE only
    // against the per-target OUT_DIR copy this build.rs emits.
    let target = env::var("TARGET").expect("TARGET set by cargo");
    let memory_x: &[u8] = if target == "thumbv6m-none-eabi" {
        include_bytes!("memory-microbit.x")
    } else {
        include_bytes!("memory-mps2.x")
    };
    fs::write(out_dir.join("memory.x"), memory_x).expect("write memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    // R311bf: pass `-Tlink.x` here in addition to the same flag
    // in `.cargo/config.toml`. Cargo's `.cargo/config.toml` lookup
    // walks from CWD, not from the manifest dir, so a `cargo build
    // --manifest-path deploy/mcu-qemu-demo/Cargo.toml` invoked
    // from the workspace root (e.g. scripts/run-ci.sh Layer Q.1)
    // does NOT see the per-crate config and silently produces an
    // empty ELF. Emitting the directive from build.rs makes the
    // link-arg cwd-invariant; the config.toml entry remains for
    // `cargo run` ergonomics inside the crate dir.
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-mps2.x");
    println!("cargo:rerun-if-changed=memory-microbit.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");

    // ── (ⓓ) switchboard value-path codegen ──────────────────────────────
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    let sources = manifest_dir.join("sources");
    let sidecar = manifest_dir.join("wz-switchboard.yaml");

    let sce_workspace = manifest_dir
        .join("../../vendor/sce")
        .canonicalize()
        .expect("canonicalize vendor/sce");
    let sce_codegen = sce_workspace.join("target/release/sce-codegen");
    if !sce_codegen.exists() {
        panic!(
            "sce-codegen binary not found at {}\n\
             run `scripts/build-sce.sh` from the wz workspace root to build it.",
            sce_codegen.display()
        );
    }

    println!("cargo:rerun-if-changed={}", sources.display());
    println!("cargo:rerun-if-changed={}", sidecar.display());
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    // 1. Codegen each source doc (--no-std); collect the emitted forge-ast JSON.
    let machine_ast = emit(
        "thermostat",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    let schema_ast = emit(
        "temp_reading_schema",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    let codec_ast = emit(
        "temp_reading_codec",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );

    // The machine + codec Rust is `include!`d into a `mod`, so strip the
    // file-head inner attributes (`#![no_std]` / `#![allow(...)]` / `//!`)
    // that are illegal at item position (same transform as the example).
    strip_inner_attrs(&out_dir.join("thermostat_sm.rs"));
    strip_inner_attrs(&out_dir.join("temp_reading_codec.rs"));

    // 2. Parse the facts and the sidecar, then run the pure generator.
    let facts = parse_machine_facts(&read(&machine_ast)).expect("parse machine facts");
    let schema = parse_event_schema_facts(&read(&schema_ast)).expect("parse event-schema facts");
    let codec =
        parse_codec_facts(&read(&codec_ast), "temp_reading_codec").expect("parse codec facts");

    let spec: SwitchboardSpec =
        serde_yaml_ng::from_str(&read(&sidecar)).expect("parse wz-switchboard.yaml");

    let dispatch = generate(&GenInput {
        spec: &spec,
        facts: &facts,
        schemas: &[schema],
        codecs: &[codec],
        machine_module: "thermostat",
    })
    .expect("generate switchboard dispatch");

    fs::write(out_dir.join("dispatch_switchboard.rs"), dispatch)
        .expect("write dispatch_switchboard.rs");
}

/// Run `sce-codegen generate -l rust --no-std --emit-ast` for `<stem>.scxml`;
/// return the emitted forge-ast JSON path. Panics on a codegen failure (a
/// malformed source is a build error, never a silent skip).
fn emit(stem: &str, sources: &Path, out_dir: &Path, bin: &Path, workspace: &Path) -> PathBuf {
    let scxml = sources.join(format!("{stem}.scxml"));
    let ast = out_dir.join(format!("{stem}.ast.json"));
    let status = Command::new(bin)
        .arg("--workspace-root")
        .arg(workspace)
        .arg("generate")
        .arg("--language")
        .arg("rust")
        .arg("--no-std")
        .arg("--emit-ast")
        .arg(&ast)
        .arg("--output-dir")
        .arg(out_dir)
        .arg(&scxml)
        .status()
        .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));
    if !status.success() {
        panic!("sce-codegen generate failed for {stem} (exit {status:?})");
    }
    ast
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Strip `#![...]` inner attributes and `//!` inner doc comments from a
/// generated file's head so it can be `include!`d inside a `mod` block.
fn strip_inner_attrs(path: &Path) {
    let original = read(path);
    let stripped = original
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, &stripped).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
