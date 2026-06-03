// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-switchboard-example build.rs — gc-3c.
//
// Orchestrates the switchboard value path end to end:
//   1. sce-codegen over each source doc (-l rust + --emit-ast):
//      - sensor_monitor.scxml  -> sensor_monitor_sm.rs  + AST (the machine,
//        with BOTH EventSchema imports resolved -> SensorMonitorInject seam,
//        SensorMonitor{TempUpdate,HumidityUpdate}Payload, typed_inject_events)
//      - temp_update_schema.scxml     -> AST (the temp_update field list)
//      - temp_payload.scxml    -> temp_payload.rs       + AST (the temp codec)
//      - humidity_update_schema.scxml -> AST (the humidity_update field list)
//      - humidity_payload.scxml -> humidity_payload.rs  + AST (the humidity codec)
//   2. wz-switchboard-codegen over wz-switchboard.yaml + the five ASTs ->
//      dispatch_switchboard.rs (the closed typed dispatch, one schema<->codec
//      join per value event).
// lib.rs `include!`s the machine + both codecs + dispatch. The shell-out to the
// sce-codegen BINARY mirrors wz-runtime-tokio/build.rs (the documented public
// codegen path); the pin lives in the vendor/sce submodule.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_switchboard_codegen::{
    generate, parse_codec_facts, parse_event_schema_facts, parse_machine_facts, GenInput,
};
use wz_switchboard_schema::SwitchboardSpec;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
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

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", sources.display());
    println!("cargo:rerun-if-changed={}", sidecar.display());
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    // 1. Codegen each source doc; collect the emitted forge-ast JSON.
    let machine_ast = emit(
        "sensor_monitor",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    let schema_ast = emit(
        "temp_update_schema",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    let codec_ast = emit(
        "temp_payload",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    // Multi-event carry: a SECOND value event's EventSchema + wire codec. The
    // generator resolves a separate schema<->codec join for `humidity_update`.
    let humidity_schema_ast = emit(
        "humidity_update_schema",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );
    let humidity_codec_ast = emit(
        "humidity_payload",
        &sources,
        &out_dir,
        &sce_codegen,
        &sce_workspace,
    );

    // The machine + codecs' Rust is `include!`d into a `mod`, so strip the
    // file-head inner attributes (`#![allow(...)]` / `//!`) that are illegal
    // at item position (same transform as wz-runtime-tokio/build.rs).
    strip_inner_attrs(&out_dir.join("sensor_monitor_sm.rs"));
    strip_inner_attrs(&out_dir.join("temp_payload.rs"));
    strip_inner_attrs(&out_dir.join("humidity_payload.rs"));

    // 2. Parse the facts and the sidecar, then run the pure generator. Both
    // value events' schemas + codecs are supplied; the generator looks each up
    // by event_name / codec name per binding.
    let facts = parse_machine_facts(&read(&machine_ast)).expect("parse machine facts");
    let schema = parse_event_schema_facts(&read(&schema_ast)).expect("parse event-schema facts");
    let codec = parse_codec_facts(&read(&codec_ast), "temp_payload").expect("parse codec facts");
    let humidity_schema = parse_event_schema_facts(&read(&humidity_schema_ast))
        .expect("parse humidity event-schema facts");
    let humidity_codec = parse_codec_facts(&read(&humidity_codec_ast), "humidity_payload")
        .expect("parse humidity codec facts");

    let spec: SwitchboardSpec =
        serde_yaml_ng::from_str(&read(&sidecar)).expect("parse wz-switchboard.yaml");

    let dispatch = generate(&GenInput {
        spec: &spec,
        facts: &facts,
        schemas: &[schema, humidity_schema],
        codecs: &[codec, humidity_codec],
        machine_module: "sensor_monitor",
    })
    .expect("generate switchboard dispatch");

    std::fs::write(out_dir.join("dispatch_switchboard.rs"), dispatch)
        .expect("write dispatch_switchboard.rs");
}

/// Run `sce-codegen generate -l rust --emit-ast` for `<stem>.scxml`; return
/// the emitted forge-ast JSON path. Panics on a codegen failure (a malformed
/// source is a build error, never a silent skip).
fn emit(stem: &str, sources: &Path, out_dir: &Path, bin: &Path, workspace: &Path) -> PathBuf {
    let scxml = sources.join(format!("{stem}.scxml"));
    let ast = out_dir.join(format!("{stem}.ast.json"));
    let status = Command::new(bin)
        .arg("--workspace-root")
        .arg(workspace)
        .arg("generate")
        .arg("--language")
        .arg("rust")
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
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
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
    std::fs::write(path, &stripped).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
